import type { SupabaseClient } from "@supabase/supabase-js";
import { encrypt, decrypt } from "./security";
import { readLimited } from "./http";

const context = "keysprig/key-setup/v1";
type Intent = {
  id: string;
  owner: string;
  agent: string;
  provider: "agentmail";
  expires: number;
};
const encode = (s: string) =>
  s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
const decode = (s: string) => atob(s.replace(/-/g, "+").replace(/_/g, "/"));
const response = (body: unknown, status = 200) =>
  Response.json(body, { status, headers: { "Cache-Control": "no-store" } });

export function agentMailPolicy(access: unknown) {
  if (access !== "read" && access !== "send") throw Error("Invalid access");
  return {
    name: "agentmail",
    allowed_hosts: ["api.agentmail.to"],
    auth_header: "Authorization",
    auth_prefix: "Bearer ",
    allowed_methods: access === "read" ? ["GET"] : ["GET", "POST"],
    rate_limit_per_minute: 10,
  };
}

export async function createSetupLink(
  root: string,
  origin: string,
  owner: string,
  agent: string,
) {
  const intent: Intent = {
    id: crypto.randomUUID(),
    owner,
    agent,
    provider: "agentmail",
    expires: Date.now() + 15 * 60000,
  };
  const sealed = await encrypt(root, context, JSON.stringify(intent));
  // The fragment never reaches HTTP access logs. This is an intent, not authentication.
  return `${origin}/setup-key#${encode(sealed.nonce)}.${encode(sealed.ciphertext)}`;
}

export async function readIntent(
  root: string,
  token: unknown,
  owner: string,
): Promise<Intent> {
  if (
    typeof token !== "string" ||
    token.length > 2000 ||
    !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token)
  )
    throw Error("Invalid setup");
  const [nonce, ciphertext] = token.split(".").map((s) => btoa(decode(s)));
  const intent = JSON.parse(
    await decrypt(root, context, { nonce, ciphertext }),
  ) as Intent;
  if (
    intent.owner !== owner ||
    intent.provider !== "agentmail" ||
    intent.expires <= Date.now() ||
    intent.expires > Date.now() + 15 * 60000
  )
    throw Error("Invalid setup");
  return intent;
}

export async function keySetup(
  request: Request,
  db: SupabaseClient,
  root: string,
  owner: string,
) {
  if (request.method !== "POST") return response({ error: "Not found." }, 404);
  const body = JSON.parse(await readLimited(request.body, 20000));
  let intent: Intent;
  try {
    intent = await readIntent(root, body.setup, owner);
  } catch {
    return response(
      {
        error:
          "This setup link is invalid or expired, or belongs to a different account. Ask your agent for a new link.",
      },
      403,
    );
  }
  const agent = await db
    .from("vault_agents")
    .select("id,label")
    .eq("id", intent.agent)
    .eq("owner_id", owner)
    .is("revoked_at", null)
    .maybeSingle();
  if (agent.error) throw Error("Database operation failed");
  if (!agent.data)
    return response(
      {
        error:
          "This agent is disconnected. Connect it again before adding a key.",
      },
      403,
    );
  const used = await db
    .from("vault_key_setup_completions")
    .select("request_id")
    .eq("request_id", intent.id)
    .maybeSingle();
  if (used.error) throw Error("Database operation failed");
  if (used.data)
    return response({ error: "This setup link has already been used." }, 409);
  if (body.action === "details")
    return response({
      provider: "AgentMail",
      agent: agent.data.label,
      host: "api.agentmail.to",
    });
  if (
    body.action !== "save" ||
    typeof body.value !== "string" ||
    !body.value.trim() ||
    body.value.length > 16000 ||
    /[\r\n]/.test(body.value) ||
    ![1, 7, 30].includes(body.days)
  )
    return response(
      { error: "Enter a valid API key and access duration." },
      400,
    );
  const policy = agentMailPolicy(body.access);
  const id = crypto.randomUUID();
  const sealed = await encrypt(root, `${owner}/${id}/1`, body.value.trim());
  const result = await db.rpc("vault_complete_key_setup", {
    p_owner: owner,
    p_agent: intent.agent,
    p_request: intent.id,
    p_id: id,
    p_ciphertext: sealed.ciphertext,
    p_nonce: sealed.nonce,
    p_methods: policy.allowed_methods,
    p_days: body.days,
  });
  if (result.error)
    return response(
      {
        error:
          "Unable to save. The link may be used, the agent disconnected, or an agentmail key already exists. Existing keys are never overwritten.",
      },
      409,
    );
  return response({ ok: true, key_name: policy.name }, 201);
}
