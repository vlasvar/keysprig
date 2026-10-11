import { createClient } from "@supabase/supabase-js";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { z } from "zod";
import { authorize, encrypt, decrypt } from "./security";
import { withDeadline, readLimited } from "./http";
import { feedback } from "./feedback";
import { createSetupLink, keySetup } from "./key-setup";
import { validatePolicy, validateCall, proxyCall, ProxyFailure } from "./proxy";
interface Env {
  SUPABASE_URL: string;
  SUPABASE_ANON_KEY: string;
  SUPABASE_SERVICE_ROLE_KEY: string;
  VAULT_ROOT_KEY: string;
  ASSETS: { fetch(request: Request): Promise<Response> };
}
const json = (data: unknown, status = 200) =>
  Response.json(data, {
    status,
    headers: {
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    },
  });
const notFound = () =>
  new Response("Not found", {
    status: 404,
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    },
  });
const publicPages = new Set([
  "/",
  "/privacy",
  "/privacy/",
  "/terms",
  "/terms/",
  "/cookies",
  "/cookies/",
]);
const staticAsset =
  /\.(?:js|mjs|cjs|css|map|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|otf|eot|txt|xml|json|webmanifest|wasm)$/i;
const uuid = (s: unknown): s is string =>
  typeof s === "string" &&
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(s);
function permissionInput(keys: unknown, expires: unknown) {
  if (
    !Array.isArray(keys) ||
    keys.length > 100 ||
    keys.some((k) => !uuid(k)) ||
    typeof expires !== "string"
  )
    throw Error("Invalid permissions");
  const time = Date.parse(expires);
  if (
    !Number.isFinite(time) ||
    time <= Date.now() ||
    time > Date.now() + 30 * 86400000
  )
    throw Error("Invalid expiry");
  return {
    keys: [...new Set<string>(keys)],
    expires: new Date(time).toISOString(),
  };
}
const jwks = new Map<string, ReturnType<typeof createRemoteJWKSet>>();
async function invitationHash(value: string) {
  return Array.from(
    new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)),
    ),
    (n) => n.toString(16).padStart(2, "0"),
  ).join("");
}
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (
      url.pathname === "/.well-known/oauth-protected-resource" ||
      url.pathname === "/.well-known/oauth-protected-resource/mcp"
    )
      return json({
        resource: url.origin + "/mcp",
        authorization_servers: [env.SUPABASE_URL + "/auth/v1"],
        bearer_methods_supported: ["header"],
      });
    if (url.pathname.startsWith("/.well-known/")) return notFound();
    if (!url.pathname.startsWith("/api/") && url.pathname !== "/mcp") {
      const response = await env.ASSETS.fetch(request);
      const html = Boolean(
        response.headers.get("Content-Type")?.includes("text/html"),
      );
      const missingAsset =
        (staticAsset.test(url.pathname) ||
          url.pathname.startsWith("/assets/")) &&
        (html || response.status === 404);
      if (missingAsset) return notFound();
      const authCallback =
        url.searchParams.has("code") ||
        url.searchParams.has("recovery") ||
        url.searchParams.has("authorization_id") ||
        url.searchParams.has("error");
      if (html && (!publicPages.has(url.pathname) || authCallback)) {
        const privatePage = new Response(response.body, response);
        privatePage.headers.set("X-Robots-Tag", "noindex, nofollow");
        return privatePage;
      }
      return response;
    }
    if (
      !env.SUPABASE_URL ||
      !env.SUPABASE_SERVICE_ROLE_KEY ||
      !env.VAULT_ROOT_KEY
    )
      return json({ error: "Vault service setup is incomplete." }, 503);
    try {
      if (url.pathname === "/api/invitations/redeem") {
        if (request.method !== "POST")
          return json({ error: "Not found." }, 404);
        if (request.headers.get("Origin") !== url.origin)
          return json({ error: "Invalid request origin." }, 403);
        const { code, email } = JSON.parse(
          await readLimited(request.body, 2048),
        );
        if (
          typeof code !== "string" ||
          !/^[A-Za-z0-9_-]{43}$/.test(code) ||
          typeof email !== "string" ||
          email.length > 254 ||
          !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
        )
          return json({ error: "Invalid invitation or email." }, 400);
        const db = createClient(
          env.SUPABASE_URL,
          env.SUPABASE_SERVICE_ROLE_KEY,
          { auth: { persistSession: false, autoRefreshToken: false } },
        );
        const { data, error } = await db.rpc("vault_claim_invitation", {
          p_hash: await invitationHash(code),
          p_email: email.trim().toLowerCase(),
          p_ip_hash: await invitationHash(
            env.VAULT_ROOT_KEY +
              ":" +
              (request.headers.get("CF-Connecting-IP") || "unknown"),
          ),
        });
        if (error) throw Error("Invitation operation failed");
        if (data === "limited")
          return json(
            { error: "Too many attempts. Try again in ten minutes." },
            429,
          );
        if (data !== "ok")
          return json(
            { error: "Invitation is invalid, expired or already used." },
            400,
          );
        return json({ ok: true });
      }
      const token = request.headers
        .get("Authorization")
        ?.match(/^Bearer (\S+)$/)?.[1];
      if (!token)
        return new Response(null, {
          status: 401,
          headers: {
            "WWW-Authenticate": `Bearer resource_metadata="${url.origin}/.well-known/oauth-protected-resource/mcp"`,
          },
        });
      const issuer = env.SUPABASE_URL + "/auth/v1";
      if (!jwks.has(issuer))
        jwks.set(
          issuer,
          createRemoteJWKSet(new URL(issuer + "/.well-known/jwks.json")),
        );
      let identity: ReturnType<typeof authorize>;
      try {
        const { payload } = await jwtVerify(token, jwks.get(issuer)!, {
          issuer,
          audience: "authenticated",
          algorithms: ["ES256", "RS256"],
        });
        identity = authorize(
          payload,
          url.pathname === "/mcp" ? "agent" : "human",
        );
      } catch {
        return new Response(
          JSON.stringify({ error: "Invalid session or client token." }),
          {
            status: 401,
            headers: {
              "Content-Type": "application/json",
              "Cache-Control": "no-store",
              "WWW-Authenticate": `Bearer error="invalid_token", resource_metadata="${url.origin}/.well-known/oauth-protected-resource/mcp"`,
            },
          },
        );
      }
      const db = createClient(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY, {
        auth: { persistSession: false, autoRefreshToken: false },
      });
      const checked = async <T extends { error: unknown }>(
        result: PromiseLike<T>,
      ) => {
        const r = await result;
        if (r.error) throw Error("Database operation failed");
        return r;
      };
      const event = async (action: string, key_name?: string) => {
        await checked(
          db
            .from("vault_events")
            .insert({ owner_id: identity.owner, action, key_name }),
        );
      };
      if (url.pathname === "/mcp") {
        const grant = await checked(
          db
            .from("vault_agents")
            .select("id")
            .eq("owner_id", identity.owner)
            .eq("oauth_client_id", identity.client!)
            .is("revoked_at", null)
            .maybeSingle(),
        );
        if (!grant.data)
          return json({ error: "Client disconnected or not approved." }, 403);
        const grantId = grant.data.id;
        const server = new McpServer(
          {
            name: "KeySprig",
            version: "0.1.0",
            websiteUrl: url.origin,
            icons: [
              {
                src: url.origin + "/keysprig-icon.svg",
                mimeType: "image/svg+xml",
              },
            ],
          },
          {
            instructions:
              "KeySprig is connected at https://keysprig.xyz/mcp. When a user asks to add an AgentMail API key, call setup_key with provider agentmail and present its secure setup_url. Do not search old chats, guess a setup URL or request the secret in chat. The retired workers.dev address is unavailable. For a request to add an unspecified API key, ask which service first. After private setup, use call_api with key_name agentmail. Access still requires the user's approval on the setup page.",
          },
        );
        server.registerTool(
          "setup_key",
          {
            title: "Connect AgentMail privately",
            annotations: { readOnlyHint: true, openWorldHint: false },
            description:
              "Start private API key setup for this connected agent. For AgentMail, return a secure KeySprig link with technical settings prefilled. Ask the user to open it, paste the key privately and approve access. Never ask for or accept API keys in chat or tool arguments. This link grants no access by itself and expires in 15 minutes.",
            inputSchema: { provider: z.enum(["agentmail"]) },
          },
          async () => ({
            content: [
              {
                type: "text" as const,
                text: JSON.stringify({
                  setup_url: await createSetupLink(
                    env.VAULT_ROOT_KEY,
                    url.origin,
                    identity.owner,
                    grantId,
                  ),
                  instructions:
                    "Open this KeySprig link. Sign in if needed, paste your AgentMail key there and approve access. Never paste it in chat. After saving, use call_api with key_name agentmail. The link expires in 15 minutes.",
                }),
              },
            ],
          }),
        );
        server.registerTool(
          "call_api",
          {
            description:
              "Use an approved named key to call its trusted HTTPS destinations. The server injects authentication; never ask for keys in chat. For a missing AgentMail key, use setup_key to open private one-field setup. Other keys and permissions can be configured privately in the dashboard. Returns bounded response text with known secret representations scrubbed.",
            inputSchema: {
              key_name: z.string().regex(/^[a-z][a-z0-9_-]{0,39}$/),
              method: z.enum([
                "GET",
                "HEAD",
                "POST",
                "PUT",
                "PATCH",
                "DELETE",
                "OPTIONS",
              ]),
              url: z.string().max(4096),
              headers: z.record(z.string(), z.string()).optional(),
              body: z.string().max(65536).optional(),
            },
          },
          async (input) => {
            let eventId: string | undefined;
            let auditDestination: string | undefined;
            let admittedCall = false;
            let stage = "key policy";
            try {
              const record = await checked(
                db
                  .from("vault_keys")
                  .select("*")
                  .eq("owner_id", identity.owner)
                  .eq("name", input.key_name)
                  .maybeSingle(),
              );
              if (!record.data) throw Error("Access denied");
              const policy = validatePolicy(record.data);
              const { target } = validateCall(policy, input);
              auditDestination = target.hostname;
              stage = "permission or rate limit";
              const admitted = await checked(
                db.rpc("vault_begin_call", {
                  p_owner: identity.owner,
                  p_agent: grantId,
                  p_key_name: input.key_name,
                  p_destination: target.hostname,
                  p_method: input.method,
                }),
              );
              if (!admitted.data || admitted.data.denied)
                throw Error("Access denied or rate limited");
              admittedCall = true;
              const current = admitted.data;
              eventId = current.event_id;
              stage = "key decryption";
              const secret = await decrypt(
                env.VAULT_ROOT_KEY,
                `${identity.owner}/${current.id}/${current.key_version}`,
                current,
              );
              stage = "outbound request";
              const result = await proxyCall(
                validatePolicy(current),
                secret,
                input,
              );
              stage = "completion audit";
              const finished = await checked(
                db.rpc("vault_finish_call", {
                  p_owner: identity.owner,
                  p_agent: grantId,
                  p_event: eventId,
                  p_outcome: result.status < 400 ? "success" : "upstream_error",
                }),
              );
              eventId = undefined;
              if (finished.data !== true) throw Error("Access revoked");
              return {
                content: [
                  { type: "text" as const, text: JSON.stringify(result) },
                ],
              };
            } catch (error) {
              const safeReasons = [
                "Destination lookup failed",
                "Private destination rejected",
                "Redirect rejected",
                "Response too large",
                "Body too large",
                "Invalid authentication value",
              ];
              if (error instanceof Error && safeReasons.includes(error.message))
                stage = error.message;
              if (error instanceof ProxyFailure) stage = error.stage;
              if (eventId) {
                try {
                  await checked(
                    db.rpc("vault_finish_call", {
                      p_owner: identity.owner,
                      p_agent: grantId,
                      p_event: eventId,
                      p_outcome: "failed",
                    }),
                  );
                } catch {
                  /* No result escapes if audit storage is unavailable. */
                }
              }
              if (!eventId && !admittedCall) {
                try {
                  await checked(
                    db.from("vault_events").insert({
                      owner_id: identity.owner,
                      agent_id: grantId,
                      key_name: input.key_name,
                      destination: auditDestination,
                      method: input.method,
                      action: "api.call",
                      outcome: "denied",
                    }),
                  );
                } catch {
                  /* Fail closed, no upstream response. */
                }
              }
              return {
                isError: true,
                content: [
                  {
                    type: "text" as const,
                    text: `Call denied or failed at ${stage}. Check key policy, approval, expiry and rate limit in the dashboard.`,
                  },
                ],
              };
            }
          },
        );
        const transport = new WebStandardStreamableHTTPServerTransport({
          sessionIdGenerator: undefined,
          enableJsonResponse: true,
        });
        await server.connect(transport);
        if (request.method === "POST") {
          const body = await readLimited(request.body, 100000);
          request = new Request(request.url, {
            method: request.method,
            headers: request.headers,
            body,
          });
        }
        return transport.handleRequest(request);
      }
      if (
        request.method !== "GET" &&
        request.headers.get("Origin") !== url.origin
      )
        return json({ error: "Invalid request origin." }, 403);
      if (url.pathname === "/api/feedback")
        return feedback(request, db, identity.owner);
      if (url.pathname === "/api/key-setup")
        return keySetup(request, db, env.VAULT_ROOT_KEY, identity.owner);
      const invitationId = url.pathname.match(
        /^\/api\/invitations\/([0-9a-f-]+)$/,
      )?.[1];
      if (
        url.pathname === "/api/invitations" ||
        (invitationId && uuid(invitationId))
      ) {
        const admin = await checked(
          db
            .from("vault_admins")
            .select("user_id")
            .eq("user_id", identity.owner)
            .maybeSingle(),
        );
        if (!admin.data)
          return json({ error: "Only the owner can manage invitations." }, 403);
        if (request.method === "DELETE" && invitationId) {
          await checked(
            db
              .from("vault_invitations")
              .update({
                revoked_at: new Date().toISOString(),
                claimed_email: null,
                claimed_until: null,
              })
              .eq("id", invitationId)
              .is("used_at", null),
          );
          return json({ ok: true });
        }
        if (request.method === "GET" && !invitationId) {
          const result = await checked(
            db
              .from("vault_invitations")
              .select(
                "id,created_at,expires_at,used_at,revoked_at,claimed_until",
              )
              .order("created_at", { ascending: false })
              .limit(100),
          );
          return json({
            invitations: result.data?.map((row) => ({
              id: row.id,
              created_at: row.created_at,
              expires_at: row.expires_at,
              used_at: row.used_at,
              revoked_at: row.revoked_at,
              claimed: Boolean(
                row.claimed_until && Date.parse(row.claimed_until) > Date.now(),
              ),
            })),
          });
        }
        if (request.method === "POST" && !invitationId) {
          const code = btoa(
            String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))),
          )
            .replace(/\+/g, "-")
            .replace(/\//g, "_")
            .replace(/=+$/g, "");
          const result = await checked(
            db.rpc("vault_create_invitation", {
              p_owner: identity.owner,
              p_hash: await invitationHash(code),
            }),
          );
          if (result.data?.error === "full")
            return json(
              { error: "Invitation allocation is full." },
              409,
            );
          if (!result.data?.expires_at)
            return json({ error: "Unable to create an invitation." }, 403);
          return json({ code, expires_at: result.data.expires_at }, 201);
        }
        return json({ error: "Not found." }, 404);
      }
      if (request.method === "POST" && url.pathname === "/api/consent") {
        const input = await readLimited(request.body, 10000);
        const { authorization_id, key_ids, expires_at } = JSON.parse(input);
        const permission = permissionInput(key_ids, expires_at);
        if (
          typeof authorization_id !== "string" ||
          !/^[a-zA-Z0-9_-]{1,200}$/.test(authorization_id)
        )
          return json({ error: "Invalid authorization." }, 400);
        // Read the pending authorization directly from Auth; never trust a submitted client ID.
        const details = await withDeadline(async (signal) => {
          const response = await fetch(
            `${issuer}/oauth/authorizations/${authorization_id}`,
            {
              headers: {
                apikey: env.SUPABASE_ANON_KEY,
                Authorization: `Bearer ${token}`,
              },
              redirect: "manual",
              signal,
            },
          );
          if (!response.ok) throw Error("Authorization unavailable");
          return JSON.parse(await readLimited(response.body, 16384)) as {
            user?: { id: string };
            client?: { id: string; name: string };
          };
        });
        if (
          details.user?.id !== identity.owner ||
          !details.client?.id ||
          !details.client.name
        )
          return json(
            { error: "This authorization does not belong to your account." },
            403,
          );
        const ownedKeys = await checked(
          db
            .from("vault_keys")
            .select("id")
            .eq("owner_id", identity.owner)
            .in("id", permission.keys),
        );
        if ((ownedKeys.data ?? []).length !== permission.keys.length)
          return json({ error: "Invalid key selection." }, 400);
        await checked(
          db.rpc("vault_approve_client", {
            p_owner: identity.owner,
            p_client: details.client.id,
            p_label: details.client.name,
            p_keys: permission.keys,
            p_expires: permission.expires,
          }),
        );
        await event("client.approved");
        return json({ ok: true });
      }
      if (request.method === "GET" && url.pathname === "/api/keys") {
        const r = await checked(
          db
            .from("vault_keys")
            .select(
              "id,name,created_at,allowed_hosts,auth_header,auth_prefix,allowed_methods,rate_limit_per_minute",
            )
            .eq("owner_id", identity.owner)
            .order("created_at", { ascending: false }),
        );
        return json({ keys: r.data });
      }
      if (request.method === "POST" && url.pathname === "/api/keys") {
        if (Number(request.headers.get("content-length") || 0) > 20000)
          return json({ error: "Key is too large." }, 413);
        const text = await readLimited(request.body, 20000);
        const body = JSON.parse(text);
        if (
          !/^[a-z][a-z0-9_-]{0,39}$/.test(body.name) ||
          typeof body.value !== "string" ||
          !body.value ||
          body.value.length > 16000
        )
          return json({ error: "Use a valid key name and value." }, 400);
        const policy = validatePolicy(body);
        const id = crypto.randomUUID();
        const sealed = await encrypt(
          env.VAULT_ROOT_KEY,
          `${identity.owner}/${id}/1`,
          body.value,
        );
        await checked(
          db.from("vault_keys").insert({
            id,
            owner_id: identity.owner,
            name: body.name,
            ...sealed,
            key_version: 1,
            ...policy,
          }),
        );
        await event("key.created", body.name);
        return json({ id }, 201);
      }
      const keyId = url.pathname.match(/^\/api\/keys\/([0-9a-f-]{36})$/)?.[1];
      if (keyId && request.method === "DELETE") {
        await checked(
          db
            .from("vault_keys")
            .delete()
            .eq("owner_id", identity.owner)
            .eq("id", keyId),
        );
        await event("key.deleted");
        return json({ ok: true });
      }
      if (
        request.method === "POST" &&
        url.pathname === "/api/agents/disconnect-all"
      ) {
        const grants = await checked(
          db
            .from("vault_agents")
            .select("oauth_client_id")
            .eq("owner_id", identity.owner),
        );
        await checked(
          db
            .from("vault_agents")
            .update({ revoked_at: new Date().toISOString() })
            .eq("owner_id", identity.owner),
        );
        await event("clients.disconnected_for_recovery");
        try {
          for (const grant of grants.data ?? []) {
            await withDeadline(async (signal) => {
              const target = new URL(issuer + "/user/oauth/grants");
              target.searchParams.set("client_id", grant.oauth_client_id);
              const response = await fetch(target, {
                method: "DELETE",
                redirect: "manual",
                headers: {
                  apikey: env.SUPABASE_ANON_KEY,
                  Authorization: `Bearer ${token}`,
                },
                signal,
              });
              if (!response.ok) throw Error("Consent cleanup failed");
            });
          }
        } catch {
          return json(
            {
              error:
                "Vault access is blocked for all clients. Consent cleanup failed; retry the password update.",
            },
            503,
          );
        }
        return json({ ok: true });
      }
      if (request.method === "DELETE" && url.pathname === "/api/account") {
        const grants = await checked(
          db
            .from("vault_agents")
            .select("oauth_client_id")
            .eq("owner_id", identity.owner),
        );
        await checked(
          db
            .from("vault_agents")
            .update({ revoked_at: new Date().toISOString() })
            .eq("owner_id", identity.owner),
        );
        for (const grant of grants.data ?? []) {
          try {
            await withDeadline(async (signal) => {
              const target = new URL(issuer + "/user/oauth/grants");
              target.searchParams.set("client_id", grant.oauth_client_id);
              const response = await fetch(target, {
                method: "DELETE",
                redirect: "manual",
                headers: {
                  apikey: env.SUPABASE_ANON_KEY,
                  Authorization: `Bearer ${token}`,
                },
                signal,
              });
              if (!response.ok) throw Error("Consent cleanup failed");
            });
          } catch {
            /* Revoke locally and continue; the auth user is about to be deleted. */
          }
        }
        await checked(
          db.from("vault_rate_limits").delete().eq("owner_id", identity.owner),
        );
        await checked(
          db.from("vault_permissions").delete().eq("owner_id", identity.owner),
        );
        await checked(
          db.from("vault_events").delete().eq("owner_id", identity.owner),
        );
        await checked(
          db.from("vault_keys").delete().eq("owner_id", identity.owner),
        );
        await checked(
          db.from("vault_agents").delete().eq("owner_id", identity.owner),
        );
        await checked(
          db
            .from("vault_invitations")
            .update({ used_by: null })
            .eq("used_by", identity.owner),
        );
        await checked(
          db
            .from("vault_invitations")
            .update({
              revoked_at: new Date().toISOString(),
              claimed_email: null,
              claimed_until: null,
            })
            .eq("created_by", identity.owner)
            .is("used_at", null),
        );
        const removed = await db.auth.admin.deleteUser(identity.owner);
        if (removed.error) throw Error("Database operation failed");
        return json({ ok: true });
      }
      if (request.method === "GET" && url.pathname === "/api/agents") {
        const r = await checked(
          db
            .from("vault_agents")
            .select("id,label,created_at")
            .eq("owner_id", identity.owner)
            .is("revoked_at", null),
        );
        return json({ agents: r.data });
      }
      const agentId = url.pathname.match(
        /^\/api\/agents\/([0-9a-f-]{36})$/,
      )?.[1];
      if (agentId && request.method === "DELETE") {
        const agent = await checked(
          db
            .from("vault_agents")
            .select("oauth_client_id")
            .eq("owner_id", identity.owner)
            .eq("id", agentId)
            .maybeSingle(),
        );
        if (!agent.data) return json({ ok: true });
        const oauthClientId = agent.data.oauth_client_id;
        // Deny vault access first, even if Auth cleanup is unavailable.
        await checked(
          db
            .from("vault_agents")
            .update({ revoked_at: new Date().toISOString() })
            .eq("owner_id", identity.owner)
            .eq("id", agentId),
        );
        await event("client.disconnected");
        try {
          await withDeadline(async (signal) => {
            const target = new URL(issuer + "/user/oauth/grants");
            target.searchParams.set("client_id", oauthClientId);
            const response = await fetch(target, {
              method: "DELETE",
              redirect: "manual",
              headers: {
                apikey: env.SUPABASE_ANON_KEY,
                Authorization: `Bearer ${token}`,
              },
              signal,
            });
            if (!response.ok) throw Error("Consent cleanup failed");
          });
        } catch {
          return json(
            {
              error:
                "Vault access is blocked. OAuth consent cleanup failed; retry disconnect before reconnecting.",
            },
            503,
          );
        }
        return json({ ok: true });
      }
      if (request.method === "GET" && url.pathname === "/api/permissions") {
        const r = await checked(
          db
            .from("vault_permissions")
            .select("id,agent_id,key_id,expires_at,revoked_at")
            .eq("owner_id", identity.owner)
            .is("revoked_at", null),
        );
        return json({ permissions: r.data });
      }
      if (request.method === "POST" && url.pathname === "/api/permissions") {
        const input = JSON.parse(await readLimited(request.body, 10000));
        const permission = permissionInput(input.key_ids, input.expires_at);
        if (!uuid(input.agent_id))
          return json({ error: "Invalid agent." }, 400);
        await checked(
          db.rpc("vault_set_permissions", {
            p_owner: identity.owner,
            p_agent: input.agent_id,
            p_keys: permission.keys,
            p_expires: permission.expires,
          }),
        );
        return json({ ok: true });
      }
      const permissionId = url.pathname.match(
        /^\/api\/permissions\/([0-9a-f-]{36})$/,
      )?.[1];
      if (permissionId && request.method === "DELETE") {
        await checked(
          db
            .from("vault_permissions")
            .update({ revoked_at: new Date().toISOString() })
            .eq("owner_id", identity.owner)
            .eq("id", permissionId),
        );
        await event("permission.revoked");
        return json({ ok: true });
      }
      if (request.method === "GET" && url.pathname === "/api/activity") {
        const r = await checked(
          db
            .from("vault_events")
            .select(
              "id,action,key_name,agent_id,destination,method,outcome,created_at",
            )
            .eq("owner_id", identity.owner)
            .order("created_at", { ascending: false })
            .limit(100),
        );
        return json({ events: r.data });
      }
      return json({ error: "Not found." }, 404);
    } catch (error) {
      console.warn(
        "vault_request_failed",
        error instanceof Error ? error.name : "Unknown",
      );
      return json({ error: "Unable to complete the request." }, 400);
    }
  },
};
