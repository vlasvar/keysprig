import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair, exportJWK, SignJWT } from "jose";
import worker from "../worker/index";
import { decrypt, encrypt } from "../worker/security";

const owner = "11111111-1111-4111-8111-111111111111";
type Call = { url: URL; method: string; body?: unknown };

// Exercise real token verification and the actual Worker request handler. Only
// remote JWKS and database HTTP calls are simulated, with no real credentials.
test("Worker authentication, owner isolation and secret boundaries", async (t) => {
  const originalFetch = globalThis.fetch;
  const { privateKey, publicKey } = await generateKeyPair("ES256");
  const jwk = {
    ...(await exportJWK(publicKey)),
    kid: "test-signing-key",
    alg: "ES256",
    use: "sig",
  };
  const issuer = "https://worker-tests.supabase.co/auth/v1";
  const calls: Call[] = [];
  let cleanupFails = false;
  const cleanupClients: string[] = [];
  const deletedAuthUsers: string[] = [];
  let databaseReply: (call: Call) => Response = () => Response.json([]);
  let providerReply: (request: Request) => Response = () => {
    throw Error("Unexpected provider request");
  };
  globalThis.fetch = async (input, init) => {
    const request = input instanceof Request ? input : new Request(input, init);
    const url = new URL(request.url);
    if (url.href === issuer + "/.well-known/jwks.json")
      return Response.json({ keys: [jwk] });
    if (url.href.startsWith(issuer + "/user/oauth/grants")) {
      assert.equal(request.method, "DELETE");
      cleanupClients.push(url.searchParams.get("client_id")!);
      return new Response(null, { status: cleanupFails ? 503 : 204 });
    }
    if (url.pathname.startsWith("/auth/v1/admin/users/")) {
      assert.equal(request.method, "DELETE");
      deletedAuthUsers.push(url.pathname.split("/").pop()!);
      return Response.json({ id: url.pathname.split("/").pop() });
    }
    if (url.origin === "https://api.example.com") return providerReply(request);
    if (url.origin === "https://cloudflare-dns.com") return Response.json({Status:0,Answer:url.searchParams.get("type") === "A" ? [{type:1,data:"93.184.216.34"}] : []});
    if (
      url.origin !== "https://worker-tests.supabase.co" ||
      !url.pathname.startsWith("/rest/v1/")
    )
      throw Error("Unexpected remote request");
    const text = await request.text();
    const call = {
      url,
      method: request.method,
      body: text ? JSON.parse(text) : undefined,
    };
    calls.push(call);
    return databaseReply(call);
  };
  const env = {
    SUPABASE_URL: "https://worker-tests.supabase.co",
    SUPABASE_ANON_KEY: "test-publishable",
    SUPABASE_SERVICE_ROLE_KEY: "test-service-role",
    VAULT_ROOT_KEY: Buffer.alloc(32, 7).toString("base64"),
    ASSETS: { fetch: async () => new Response("assets") },
  };
  const token = async (client?: string, extra: Record<string, unknown> = {}) =>
    new SignJWT({
      role: "authenticated",
      ...(client ? { client_id: client } : {}),
      ...extra,
    })
      .setProtectedHeader({ alg: "ES256", kid: jwk.kid })
      .setSubject(owner)
      .setIssuer(issuer)
      .setAudience("authenticated")
      .setExpirationTime("5m")
      .sign(privateKey);
  const request = async (
    path: string,
    options: {
      token?: string;
      method?: string;
      body?: unknown;
      origin?: string;
    } = {},
  ) =>
    worker.fetch(
      new Request("https://vault.example" + path, {
        method: options.method ?? "GET",
        headers: {
          ...(options.token
            ? { Authorization: "Bearer " + options.token }
            : {}),
          ...(options.origin ? { Origin: options.origin } : {}),
          "Content-Type": "application/json",
          Accept: "application/json, text/event-stream",
          "MCP-Protocol-Version": "2025-03-26",
        },
        ...(options.body !== undefined
          ? { body: JSON.stringify(options.body) }
          : {}),
      }),
      env,
    );
  try {
    await t.test("Invitation management requires an admin and returns raw codes once without storing them",async()=>{
      databaseReply=()=>new Response(null,{status:204});
      assert.equal((await request("/api/invitations",{token:await token()})).status,403);
      let storedHash="";
      databaseReply=call=>{
        if (call.url.pathname === "/rest/v1/vault_admins") return Response.json({user_id:owner});
        assert.equal(call.url.pathname,"/rest/v1/rpc/vault_create_invitation");
        const input=call.body as {p_owner:string;p_hash:string};
        assert.equal(input.p_owner,owner);
        storedHash=input.p_hash;
        return Response.json({expires_at:new Date(Date.now()+86400000).toISOString()});
      };
      const response=await request("/api/invitations",{token:await token(),method:"POST",origin:"https://vault.example"});
      assert.equal(response.status,201);
      const body=await response.json() as {code:string};
      assert.match(body.code,/^[A-Za-z0-9_-]{43}$/);
      assert.match(storedHash,/^[0-9a-f]{64}$/);
      assert.notEqual(body.code,storedHash);
      databaseReply=call=>call.url.pathname === "/rest/v1/vault_admins" ? Response.json({user_id:owner}):Response.json({error:"full"});
      assert.equal((await request("/api/invitations",{token:await token(),method:"POST",origin:"https://vault.example"})).status,409);
      databaseReply=()=>Response.json([]);
    });
    await t.test(
      "missing authentication returns discovery challenge without querying storage",
      async () => {
        calls.length = 0;
        const response = await request("/api/keys");
        assert.equal(response.status, 401);
        assert.match(
          response.headers.get("WWW-Authenticate") ?? "",
          /oauth-protected-resource\/mcp/,
        );
        assert.equal(calls.length, 0);
      },
    );
    await t.test(
      "OAuth client token cannot use human dashboard API",
      async () => {
        calls.length = 0;
        const response = await request("/api/keys", {
          token: await token("cursor-client"),
        });
        assert.ok(response.status >= 400);
        assert.equal(calls.length, 0);
      },
    );
    await t.test(
      "invalid issuer and expired JWTs never reach storage",
      async () => {
        calls.length = 0;
        const expired = await new SignJWT({ role: "authenticated" })
          .setProtectedHeader({ alg: "ES256", kid: jwk.kid })
          .setSubject(owner)
          .setIssuer(issuer)
          .setAudience("authenticated")
          .setExpirationTime(1)
          .sign(privateKey);
        const wrongIssuer = await new SignJWT({ role: "authenticated" })
          .setProtectedHeader({ alg: "ES256", kid: jwk.kid })
          .setSubject(owner)
          .setIssuer("https://attacker.example")
          .setAudience("authenticated")
          .setExpirationTime("5m")
          .sign(privateKey);
        for (const value of [expired, wrongIssuer])
          assert.ok(
            (await request("/api/keys", { token: value })).status >= 400,
          );
        assert.equal(calls.length, 0);
      },
    );
    await t.test(
      "key listing constrains owner and requests metadata only",
      async () => {
        calls.length = 0;
        databaseReply = (call) => {
          assert.equal(call.url.pathname, "/rest/v1/vault_keys");
          assert.equal(call.url.searchParams.get("owner_id"), "eq." + owner);
          assert.equal(
            call.url.searchParams.get("select"),
            "id,name,created_at,allowed_hosts,auth_header,auth_prefix,allowed_methods,rate_limit_per_minute",
          );
          return Response.json([
            {
              id: "key-id",
              name: "test_key",
              created_at: "2026-10-10T00:00:00Z",
            },
          ]);
        };
        const response = await request("/api/keys", { token: await token() });
        assert.equal(response.status, 200);
        const payload = await response.json();
        assert.deepEqual(Object.keys(payload.keys[0]).sort(), [
          "created_at",
          "id",
          "name",
        ]);
        assert.equal(calls.length, 1);
      },
    );
    await t.test("foreign and missing origins cannot mutate keys", async () => {
      calls.length = 0;
      for (const origin of ["https://attacker.example", undefined]) {
        const response = await request("/api/keys", {
          token: await token(),
          method: "POST",
          origin,
          body: { name: "test_key", value: "dummy-secret" },
        });
        assert.equal(response.status, 403);
      }
      assert.equal(calls.length, 0);
    });
    await t.test(
      "key creation encrypts before persistence and ignores submitted owner",
      async () => {
        calls.length = 0;
        databaseReply = () => new Response(null, { status: 201 });
        const secret = "dummy-secret-never-in-database";
        const response = await request("/api/keys", {
          token: await token(),
          method: "POST",
          origin: "https://vault.example",
          body: {
            allowed_hosts:["api.example.com"],auth_header:"Authorization",auth_prefix:"Bearer ",allowed_methods:["GET"],rate_limit_per_minute:10,
            name: "test_key",
            value: secret,
            owner_id: "attacker-owner",
          },
        });
        assert.equal(response.status, 201);
        const saved = calls.find(
          (call) => call.url.pathname === "/rest/v1/vault_keys",
        )?.body as {
          id: string;
          owner_id: string;
          ciphertext: string;
          nonce: string;
          key_version: number;
        };
        assert.ok(saved);
        assert.equal(saved.owner_id, owner);
        assert.equal(JSON.stringify(calls).includes(secret), false);
        assert.equal(
          await decrypt(env.VAULT_ROOT_KEY, `${owner}/${saved.id}/1`, saved),
          secret,
        );
        await assert.rejects(
          decrypt(env.VAULT_ROOT_KEY, `other-owner/${saved.id}/1`, saved),
        );
        const text = await response.text();
        assert.equal(text.includes(secret), false);
        assert.equal(text.includes(saved.ciphertext), false);
      },
    );
    await t.test(
      "disconnected MCP client is rejected before tool execution",
      async () => {
        calls.length = 0;
        databaseReply = (call) => {
          assert.equal(call.url.pathname, "/rest/v1/vault_agents");
          assert.equal(call.url.searchParams.get("owner_id"), "eq." + owner);
          assert.equal(
            call.url.searchParams.get("oauth_client_id"),
            "eq.cursor-client",
          );
          assert.equal(call.url.searchParams.get("revoked_at"), "is.null");
          return new Response(null, { status: 200 });
        };
        const response = await request("/mcp", {
          token: await token("cursor-client"),
          method: "POST",
          body: { jsonrpc: "2.0", id: 1, method: "tools/list" },
        });
        assert.equal(response.status, 403);
        assert.equal(calls.length, 1);
        assert.deepEqual(await response.json(), {
          error: "Client disconnected or not approved.",
        });
      },
    );
    await t.test("generic MCP discovery, atomic permission checks, redaction and revocation", async () => {
      const secret = "dummy-provider-secret";
      const keyId = "22222222-2222-4222-8222-222222222222";
      const encrypted = await encrypt(env.VAULT_ROOT_KEY, `${owner}/${keyId}/1`, secret);
      const policy = {allowed_hosts:["api.example.com"],auth_header:"Authorization",auth_prefix:"Bearer ",allowed_methods:["GET"],rate_limit_per_minute:10};
      let revoked = false, permitted = true, finishPermitted = true, auditFails = false, providerCalls = 0;
      databaseReply = call => {
        if(call.url.pathname.endsWith("vault_agents")) return Response.json(revoked ? null : {id:"agent-id"});
        if(call.url.pathname.endsWith("vault_keys")) return Response.json({id:keyId,name:"test_key",key_version:1,...encrypted,...policy});
        if(call.url.pathname.endsWith("vault_begin_call")) {
          assert.equal((call.body as any).p_owner, owner);
          assert.equal((call.body as any).p_destination, "api.example.com");
          return permitted ? Response.json({id:keyId,key_name:"test_key",key_version:1,event_id:"event-id",...encrypted,...policy}) : Response.json({message:"Permission denied"},{status:403});
        }
        if(call.url.pathname.endsWith("vault_finish_call")) {
          assert.equal((call.body as any).p_owner, owner);
          assert.equal(JSON.stringify(call.body).includes(secret),false);
          return auditFails ? Response.json({message:"Unavailable"},{status:503}) : Response.json(finishPermitted);
        }
        throw Error("Unexpected database operation");
      };
      providerReply = remote => {
        providerCalls++;
        assert.equal(remote.url,"https://api.example.com/check?q=private-query");
        assert.equal(remote.headers.get("Authorization"),"Bearer "+secret);
        assert.equal(remote.redirect,"manual");
        return Response.json({echo:secret,ok:true});
      };
      const agentToken=await token("cursor-client");
      const rpc=(method:string,params?:unknown)=>request("/mcp",{token:agentToken,method:"POST",body:{jsonrpc:"2.0",id:1,method,params}});
      const tools=(await (await rpc("tools/list")).json()).result.tools;
      assert.deepEqual(
        tools.map((tool: any) => tool.name),
        ["setup_key", "call_api"],
      );
      const setupResult = (
        await (
          await rpc("tools/call", {
            name: "setup_key",
            arguments: { provider: "agentmail" },
          })
        ).json()
      ).result;
      const setupUrl = JSON.parse(setupResult.content[0].text).setup_url;
      assert.equal(new URL(setupUrl).pathname, "/setup-key");
      assert.ok(!setupUrl.includes(owner));
      assert.equal(providerCalls, 0, "Setup never contacts the provider");
      const input={name:"call_api",arguments:{key_name:"test_key",method:"GET",url:"https://api.example.com/check?q=private-query"}};
      const invoked=(await (await rpc("tools/call",input)).json()).result;
      assert.ok(!invoked.isError);
      assert.equal(JSON.stringify(invoked).includes(secret),false);
      assert.equal(providerCalls,1);
      finishPermitted=false;
      const revokedDuringCall=(await (await rpc("tools/call",input)).json()).result;
      assert.equal(revokedDuringCall.isError,true);
      assert.equal(JSON.stringify(revokedDuringCall).includes("ok"),false);
      assert.equal(providerCalls,2);
      finishPermitted=true;
      auditFails=true;
      assert.equal((await (await rpc("tools/call",input)).json()).result.isError,true);
      assert.equal(providerCalls,3);
      auditFails=false;
      permitted=false;
      assert.equal((await (await rpc("tools/call",input)).json()).result.isError,true);
      assert.equal(providerCalls,3);
      revoked=true;
      assert.equal((await rpc("tools/call",input)).status,403);
      assert.equal(providerCalls,3);
    });
    await t.test(
      "password recovery revokes only the owner and fails closed on consent cleanup",
      async () => {
        let revoked = false;
        databaseReply = (call) => {
          if (call.url.pathname.endsWith("vault_events")) {
            assert.equal((call.body as any).owner_id, owner);
            return Response.json([]);
          }
          assert.equal(call.url.searchParams.get("owner_id"), "eq." + owner);
          if (call.method === "PATCH") {
            assert.ok((call.body as any).revoked_at);
            revoked = true;
            return Response.json([]);
          }
          if (call.url.searchParams.get("select") === "oauth_client_id")
            return Response.json([{ oauth_client_id: "recovery-client" }]);
          return Response.json(revoked ? null : { id: "grant" });
        };
        cleanupFails = true;
        const failed = await request("/api/agents/disconnect-all", {
          token: await token(),
          method: "POST",
          origin: "https://vault.example",
        });
        assert.equal(failed.status, 503);
        assert.equal(revoked, true);
        const denied = await request("/mcp", {
          token: await token("recovery-client"),
          method: "POST",
          body: {
            jsonrpc: "2.0",
            id: 1,
            method: "initialize",
            params: {
              protocolVersion: "2025-03-26",
              capabilities: {},
              clientInfo: { name: "test", version: "1" },
            },
          },
        });
        assert.equal(denied.status, 403);
        cleanupFails = false;
        const retried = await request("/api/agents/disconnect-all", {
          token: await token(),
          method: "POST",
          origin: "https://vault.example",
        });
        assert.equal(retried.status, 200);
        assert.deepEqual(cleanupClients, [
          "recovery-client",
          "recovery-client",
        ]);
      },
    );
    await t.test("empty allowed_methods is rejected when creating a key", async () => {
      calls.length = 0;
      const response = await request("/api/keys", {
        token: await token(),
        method: "POST",
        origin: "https://vault.example",
        body: {
          allowed_hosts: ["api.example.com"],
          auth_header: "Authorization",
          auth_prefix: "Bearer ",
          allowed_methods: [],
          rate_limit_per_minute: 10,
          name: "test_key",
          value: "dummy-secret",
        },
      });
      assert.ok(response.status >= 400);
      assert.equal(calls.length, 0);
    });
    await t.test(
      "account deletion requires a human session and removes owner data",
      async () => {
        calls.length = 0;
        deletedAuthUsers.length = 0;
        const agentDenied = await request("/api/account", {
          token: await token("cursor-client"),
          method: "DELETE",
          origin: "https://vault.example",
        });
        assert.ok(agentDenied.status >= 400);
        assert.equal(calls.length, 0);
        assert.equal(deletedAuthUsers.length, 0);

        const tables: string[] = [];
        databaseReply = (call) => {
          tables.push(`${call.method} ${call.url.pathname}`);
          if (call.url.searchParams.get("owner_id"))
            assert.equal(call.url.searchParams.get("owner_id"), "eq." + owner);
          if (
            call.url.pathname.endsWith("vault_agents") &&
            call.method === "GET"
          )
            return Response.json([{ oauth_client_id: "doomed-client" }]);
          return Response.json([]);
        };
        const response = await request("/api/account", {
          token: await token(),
          method: "DELETE",
          origin: "https://vault.example",
        });
        assert.equal(response.status, 200);
        assert.ok(tables.some((row) => row.includes("vault_keys") && row.startsWith("DELETE")));
        assert.ok(tables.some((row) => row.includes("vault_permissions") && row.startsWith("DELETE")));
        assert.ok(tables.some((row) => row.includes("vault_agents") && row.startsWith("DELETE")));
        assert.ok(tables.some((row) => row.includes("vault_events") && row.startsWith("DELETE")));
        assert.ok(tables.some((row) => row.includes("vault_rate_limits") && row.startsWith("DELETE")));
        assert.deepEqual(deletedAuthUsers, [owner]);
        assert.ok(cleanupClients.includes("doomed-client"));
      },
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("unknown well-known and missing assets return 404 instead of SPA HTML", async () => {
  const env = {
    SUPABASE_URL: "https://worker-tests.supabase.co",
    SUPABASE_ANON_KEY: "test-publishable",
    SUPABASE_SERVICE_ROLE_KEY: "test-service-role",
    VAULT_ROOT_KEY: Buffer.alloc(32, 7).toString("base64"),
    ASSETS: {
      fetch: async (request: Request) => {
        const path = new URL(request.url).pathname;
        if (path === "/assets/cached.js")
          return new Response(null, { status: 304, headers: { ETag: '"cached"' } });
        if (path === "/assets/app.js")
          return new Response("ok", {
            headers: { "Content-Type": "text/javascript" },
          });
        return new Response("<html>spa</html>", {
          headers: { "Content-Type": "text/html" },
        });
      },
    },
  };
  const get = (path: string) =>
    worker.fetch(new Request("https://vault.example" + path), env);
  const unknown = await get("/.well-known/unknown");
  assert.equal(unknown.status, 404);
  assert.equal((await unknown.text()).includes("<html>"), false);
  assert.equal((await get("/.well-known/oauth-protected-resource")).status, 200);
  assert.equal((await get("/missing.js")).status, 404);
  assert.equal((await get("/assets/nope.js")).status, 404);
  assert.equal((await get("/assets/app.js")).status, 200);
  const cached = await get("/assets/cached.js");
  assert.equal(cached.status, 304);
  assert.equal(cached.headers.get("ETag"), '"cached"');
  const spa = await get("/app");
  assert.equal(spa.status, 200);
  assert.match(await spa.text(), /spa/);
  assert.equal((await get("/privacy")).status, 200);
  assert.equal((await get("/privacy")).headers.get("X-Robots-Tag"), null);
  const app = await get("/app");
  assert.equal(app.headers.get("X-Robots-Tag"), "noindex, nofollow");
});
