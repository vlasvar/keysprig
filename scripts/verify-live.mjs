// Opt-in integration check against the configured development Supabase project.
// Creates only temporary, confirmed .invalid users; sends no registration email.
import fs from "node:fs";
import assert from "node:assert/strict";
import crypto from "node:crypto";
const config = Object.fromEntries(
  fs
    .readFileSync(".dev.vars", "utf8")
    .split("\n")
    .filter(Boolean)
    .map((line) => {
      const i = line.indexOf("=");
      return [line.slice(0, i), JSON.parse(line.slice(i + 1))];
    }),
);
const base = process.env.VAULT_TEST_URL || "http://127.0.0.1:3417";
const users = [];
const clients = [];
const backupPath = `artifacts/restore-drill-${crypto.randomUUID()}.json`;
const adminHeaders = {
  apikey: config.SUPABASE_SERVICE_ROLE_KEY,
  Authorization: "Bearer " + config.SUPABASE_SERVICE_ROLE_KEY,
  "Content-Type": "application/json",
};
const api = async (path, token, method = "GET", body) =>
  fetch(base + path, {
    method,
    headers: {
      Authorization: "Bearer " + token,
      Origin: base,
      "Content-Type": "application/json",
      ...(path === "/mcp" ? {Accept:"application/json, text/event-stream"} : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
async function account() {
  const email = `integration-${crypto.randomUUID()}@vault-test.invalid`,
    password = crypto.randomBytes(32).toString("base64url");
  const created = await fetch(config.SUPABASE_URL + "/auth/v1/admin/users", {
    method: "POST",
    headers: {
      apikey: config.SUPABASE_SERVICE_ROLE_KEY,
      Authorization: "Bearer " + config.SUPABASE_SERVICE_ROLE_KEY,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ email, password, email_confirm: true }),
  });
  assert.equal(created.status, 200, "Temporary user creation");
  const user = await created.json();
  users.push(user.id);
  const signed = await fetch(
    config.SUPABASE_URL + "/auth/v1/token?grant_type=password",
    {
      method: "POST",
      headers: {
        apikey: config.SUPABASE_ANON_KEY,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ email, password }),
    },
  );
  assert.equal(signed.status, 200, "Password authentication");
  return { id: user.id, token: (await signed.json()).access_token };
}
try {
  const a = await account(),
    b = await account();
  const secret = "dummy-live-" + crypto.randomUUID();
  const added = await api("/api/keys", a.token, "POST", {
    name: "integration_key",
    value: secret,
    owner_id: b.id,
    allowed_hosts:["httpbin.org"],auth_header:"X-Api-Key",auth_prefix:"",allowed_methods:["GET"],rate_limit_per_minute:30,
  });
  assert.equal(added.status, 201, "Key creation");
  const { id } = await added.json();
  const snapshotResponse = await fetch(
    config.SUPABASE_URL +
      `/rest/v1/vault_keys?id=eq.${id}&owner_id=eq.${a.id}&select=*`,
    { headers: adminHeaders },
  );
  assert.equal(snapshotResponse.status, 200);
  const snapshot = await snapshotResponse.json();
  assert.equal(snapshot.length, 1);
  assert.ok(!JSON.stringify(snapshot).includes(secret));
  fs.mkdirSync("artifacts", { recursive: true });
  fs.writeFileSync(backupPath, JSON.stringify(snapshot), { flag: "wx" });
  const listed = await api("/api/keys", a.token);
  assert.equal(listed.status, 200);
  const body = await listed.json();
  assert.equal(body.keys.length, 1);
  assert.equal(body.keys[0].id, id);
  assert.ok(!JSON.stringify(body).includes(secret));
  for (const field of ["id","name","created_at","allowed_hosts","auth_header"]) assert.ok(field in body.keys[0]);
  assert.ok(!("ciphertext" in body.keys[0]) && !("nonce" in body.keys[0]));
  assert.equal(
    (await (await api("/api/keys", b.token)).json()).keys.length,
    0,
    "Another owner sees no keys",
  );
  assert.equal((await api("/api/keys/" + id, b.token, "DELETE")).status, 200);
  assert.equal(
    (await (await api("/api/keys", a.token)).json()).keys.length,
    1,
    "Cross-owner deletion has no effect",
  );
  const direct = await fetch(
    config.SUPABASE_URL + "/rest/v1/vault_keys?select=*",
    {
      headers: {
        apikey: config.SUPABASE_ANON_KEY,
        Authorization: "Bearer " + a.token,
      },
    },
  );
  assert.ok(
    direct.status === 401 || direct.status === 403,
    "Data API ciphertext denied",
  );
  const noOrigin = await fetch(base + "/api/keys", {
    method: "POST",
    headers: {
      Authorization: "Bearer " + a.token,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ name: "blocked", value: secret }),
  });
  assert.equal(noOrigin.status, 403);
  assert.equal(
    (
      await api("/mcp", a.token, "POST", {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/list",
      })
    ).status,
    401,
    "Human token cannot use MCP",
  );
  const authHeaders = {
    apikey: config.SUPABASE_ANON_KEY,
    Authorization: "Bearer " + a.token,
    "Content-Type": "application/json",
  };
  const discovery = await (
    await fetch(
      config.SUPABASE_URL + "/.well-known/oauth-authorization-server/auth/v1",
    )
  ).json();
  const registration = await fetch(discovery.registration_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_name: "Vault integration test",
      redirect_uris: ["http://127.0.0.1:3430/callback"],
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
    }),
  });
  assert.equal(registration.status, 201, "OAuth dynamic registration");
  const client = await registration.json();
  clients.push(client.client_id);
  const verifier = crypto.randomBytes(32).toString("base64url"),
    challenge = crypto
      .createHash("sha256")
      .update(verifier)
      .digest("base64url");
  const authorizeUrl = new URL(discovery.authorization_endpoint);
  for (const [k, v] of Object.entries({
    client_id: client.client_id,
    redirect_uri: "http://127.0.0.1:3430/callback",
    response_type: "code",
    scope: "openid",
    state: "integration-state",
    code_challenge: challenge,
    code_challenge_method: "S256",
  }))
    authorizeUrl.searchParams.set(k, v);
  const authorization = await fetch(authorizeUrl, { redirect: "manual" });
  assert.equal(authorization.status, 302, "OAuth authorization redirect");
  const location = new URL(authorization.headers.get("location"));
  const authorization_id = location.searchParams.get("authorization_id");
  assert.ok(authorization_id, "Pending authorization id");
  const detailsResponse = await fetch(
    config.SUPABASE_URL + "/auth/v1/oauth/authorizations/" + authorization_id,
    { headers: authHeaders },
  );
  const details = await detailsResponse.json();
  console.log(
    "Consent schema check",
    JSON.stringify({
      idFormatValid: /^[a-zA-Z0-9_-]{1,200}$/.test(authorization_id),
      status: detailsResponse.status,
      fields: Object.keys(details),
      clientFields: Object.keys(details.client || {}),
      userMatches: details.user?.id === a.id,
      clientNamePresent: !!details.client?.name,
    }),
  );
  const consent = await api("/api/consent", a.token, "POST", {
    authorization_id,key_ids:[],expires_at:new Date(Date.now()+3600000).toISOString(),
  });
  assert.equal(consent.status, 200, "Vault consent verification");
  const approved = await fetch(
    config.SUPABASE_URL +
      "/auth/v1/oauth/authorizations/" +
      authorization_id +
      "/consent",
    {
      method: "POST",
      headers: authHeaders,
      body: JSON.stringify({ action: "approve" }),
    },
  );
  assert.equal(approved.status, 200);
  const code = new URL((await approved.json()).redirect_url).searchParams.get(
    "code",
  );
  assert.ok(code);
  const exchange = await fetch(discovery.token_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: client.client_id,
      redirect_uri: "http://127.0.0.1:3430/callback",
      code,
      code_verifier: verifier,
    }),
  });
  assert.equal(exchange.status, 200, "PKCE exchange");
  const agentToken = (await exchange.json()).access_token;
  assert.ok(agentToken);
  const initialize = await fetch(base + "/mcp", {
    method: "POST",
    headers: {
      Authorization: "Bearer " + agentToken,
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-03-26",
        capabilities: {},
        clientInfo: { name: "integration", version: "1" },
      },
    }),
  });
  assert.equal(initialize.status, 200, "Authenticated MCP initialization");
  const agentList = await (await api("/api/agents", a.token)).json();
  assert.equal(agentList.agents.length, 1);
  assert.equal((await (await api("/api/permissions",a.token)).json()).permissions.length,0,"Connect with zero key access");
  const deniedBeforeApproval = (await (await api("/mcp",agentToken,"POST",{jsonrpc:"2.0",id:14,method:"tools/call",params:{name:"call_api",arguments:{key_name:"integration_key",method:"GET",url:"https://httpbin.org/get"}}})).json()).result;
  assert.equal(deniedBeforeApproval.isError,true,"Connected client cannot use unapproved keys");
  assert.equal((await api("/api/permissions",a.token,"POST",{agent_id:agentList.agents[0].id,key_ids:[id],expires_at:new Date(Date.now()+3600000).toISOString()})).status,200,"Explicit human approval after connection");
  const setupRPC = {
    jsonrpc: "2.0",
    id: 15,
    method: "tools/call",
    params: { name: "setup_key", arguments: { provider: "agentmail" } },
  };
  const setupResult = (
    await (await api("/mcp", agentToken, "POST", setupRPC)).json()
  ).result;
  assert.ok(!setupResult.isError, "Chat setup tool available");
  const setupURL = new URL(JSON.parse(setupResult.content[0].text).setup_url);
  assert.equal(setupURL.pathname, "/setup-key");
  assert.equal(setupURL.search, "");
  const setup = setupURL.hash.slice(1);
  const setupDetails = { setup, action: "details" };
  assert.equal(
    (await api("/api/key-setup", b.token, "POST", setupDetails)).status,
    403,
    "Other owner cannot open setup",
  );
  assert.equal(
    (await api("/api/key-setup", agentToken, "POST", setupDetails)).status,
    401,
    "Agent cannot submit private setup",
  );
  assert.equal(
    (await api("/api/key-setup", a.token, "POST", setupDetails)).status,
    200,
    "Human reviews setup",
  );
  const setupSecret = "dummy-agentmail-" + crypto.randomUUID();
  const setupSave = {
    setup,
    action: "save",
    value: setupSecret,
    access: "read",
    days: 7,
    allowed_hosts: ["evil.example"],
    allowed_methods: ["DELETE"],
  };
  assert.equal(
    (await api("/api/key-setup", a.token, "POST", setupSave)).status,
    201,
    "Private save and approval",
  );
  assert.equal(
    (await api("/api/key-setup", a.token, "POST", setupSave)).status,
    409,
    "Single-use link cannot replay",
  );
  const setupKeys = await (await api("/api/keys", a.token)).json();
  const setupKey = setupKeys.keys.find((k) => k.name === "agentmail");
  assert.deepEqual(setupKey.allowed_hosts, ["api.agentmail.to"]);
  assert.deepEqual(setupKey.allowed_methods, ["GET"]);
  assert.ok(
    !JSON.stringify(setupKeys).includes(setupSecret),
    "Saved secret absent from metadata",
  );
  const setupPermissions = await (
    await api("/api/permissions", a.token)
  ).json();
  assert.ok(
    setupPermissions.permissions.some(
      (p) => p.key_id === setupKey.id && p.agent_id === agentList.agents[0].id,
    ),
    "Setup approves only requesting agent",
  );
  assert.ok(
    setupPermissions.permissions.some((p) => p.key_id === id),
    "Setup preserves prior permissions",
  );
  console.log(
    "Private chat setup: owner binding, secret isolation, single-use, preset policy and additive approval passed",
  );
  const call = {jsonrpc:"2.0",id:3,method:"tools/call",params:{name:"call_api",arguments:{key_name:"integration_key",method:"GET",url:"https://httpbin.org/get"}}};
  const invoked=await api("/mcp",agentToken,"POST",call);
  assert.equal(invoked.status,200);
  const callResult=(await invoked.json()).result;
  assert.ok(!callResult.isError,"Harmless generic outbound call: " + (callResult.isError ? callResult.content?.[0]?.text : ""));
  assert.ok(!JSON.stringify(callResult).includes(secret),"Echoed credential scrubbed");
  for (const argumentsOverride of [{method:"DELETE"},{headers:{"X-Api-Key":"override"}}]) {
    const blocked=await api("/mcp",agentToken,"POST",{...call,params:{...call.params,arguments:{...call.params.arguments,...argumentsOverride}}});
    assert.equal((await blocked.json()).result.isError,true,"Method and auth-header policy enforced");
  }
  for (const url of ["https://127.0.0.1/","https://httpbin.org.attacker.com/","http://httpbin.org/"]) {
    const blocked=await api("/mcp",agentToken,"POST",{...call,params:{...call.params,arguments:{...call.params.arguments,url}}});
    assert.equal((await blocked.json()).result.isError,true,"Malicious destination denied");
  }
  const admissions=await Promise.all(Array.from({length:35},async()=> {
    const result=await fetch(config.SUPABASE_URL+"/rest/v1/rpc/vault_begin_call",{method:"POST",headers:adminHeaders,body:JSON.stringify({p_owner:a.id,p_agent:agentList.agents[0].id,p_key_name:"integration_key",p_destination:"httpbin.org",p_method:"GET"})});
    assert.equal(result.status,200,"Concurrent atomic admission");
    return (await result.json()).denied===true;
  }));
  // One real call already consumed a slot. SQL counters serialize across clients.
  assert.equal(admissions.filter(denied=>!denied).length,29,"Exactly remaining rate slots admitted concurrently");
  assert.equal(admissions.filter(Boolean).length,6,"Excess concurrent requests denied");
  console.log("PASS: generic outbound call, echo scrubbing, destination/method/header restrictions and concurrent per-agent/key rate limit.");
  const permissions=await api("/api/permissions",a.token,"POST",{agent_id:agentList.agents[0].id,key_ids:[],expires_at:new Date(Date.now()+3600000).toISOString()});
  assert.equal(permissions.status,200);
  assert.equal((await (await api("/mcp",agentToken,"POST",call)).json()).result.isError,true,"Revoked key permission blocks existing token");
  const recoveryCheck = process.env.VERIFY_RECOVERY === "1";
  assert.equal(
    (
      await api(
        recoveryCheck
          ? "/api/agents/disconnect-all"
          : "/api/agents/" + agentList.agents[0].id,
        a.token,
        recoveryCheck ? "POST" : "DELETE",
      )
    ).status,
    200,
  );
  assert.equal(
    (
      await api("/mcp", agentToken, "POST", {
        jsonrpc: "2.0",
        id: 2,
        method: "tools/list",
      })
    ).status,
    403,
    "Existing OAuth token blocked after disconnect",
  );
  const reconnect = await fetch(authorizeUrl, { redirect: "manual" });
  assert.equal(reconnect.status, 302);
  const freshId = new URL(reconnect.headers.get("location")).searchParams.get(
    "authorization_id",
  );
  assert.ok(freshId);
  const reconnectDetails = await (
    await fetch(
      config.SUPABASE_URL + "/auth/v1/oauth/authorizations/" + freshId,
      { headers: authHeaders },
    )
  ).json();
  assert.ok(
    reconnectDetails.authorization_id,
    "Reconnect requires fresh explicit consent",
  );
  assert.equal((await api("/api/keys/" + id, a.token, "DELETE")).status, 200);
  assert.equal((await api("/api/keys/" + setupKey.id, a.token, "DELETE")).status, 200);
  assert.equal((await api("/api/key-setup",a.token,"POST",setupSave)).status,403,"Disconnected agent cannot reuse setup");
  assert.equal((await (await api("/api/keys", a.token)).json()).keys.length, 0);
  // Restore ciphertext only. Never restore OAuth grants from a stale snapshot.
  const restored = JSON.parse(fs.readFileSync(backupPath, "utf8"));
  const restoredResponse = await fetch(
    config.SUPABASE_URL + "/rest/v1/vault_keys",
    {
      method: "POST",
      headers: adminHeaders,
      body: JSON.stringify(restored),
    },
  );
  assert.equal(restoredResponse.status, 201);
  assert.equal((await (await api("/api/keys", a.token)).json()).keys.length, 1);
  const ciphertext = Buffer.from(restored[0].ciphertext, "base64");
  const open = (root) => {
    const decipher = crypto.createDecipheriv(
      "aes-256-gcm",
      root,
      Buffer.from(restored[0].nonce, "base64"),
    );
    decipher.setAAD(Buffer.from(`${a.id}/${id}/1`));
    decipher.setAuthTag(ciphertext.subarray(-16));
    return Buffer.concat([
      decipher.update(ciphertext.subarray(0, -16)),
      decipher.final(),
    ]).toString();
  };
  assert.equal(open(Buffer.from(config.VAULT_ROOT_KEY, "base64")), secret);
  assert.throws(
    () => open(crypto.randomBytes(32)),
    "Lost/wrong root cannot decrypt restored ciphertext",
  );
  assert.equal(
    (
      await api("/mcp", agentToken, "POST", {
        jsonrpc: "2.0",
        id: 3,
        method: "tools/list",
      })
    ).status,
    403,
    "Ciphertext restore does not resurrect revoked client access",
  );
  assert.equal((await api("/api/keys/" + id, a.token, "DELETE")).status, 200);
  console.log(
    "PASS: temporary ciphertext backup/restore, correct-root decryption, wrong-root rejection, revoked token remains blocked.",
  );
  console.log(
    "PASS: live password auth, encrypted key lifecycle, two-owner isolation, Data API denial, origin enforcement, OAuth PKCE/consent, MCP initialize, existing-token revocation.",
  );
  if (recoveryCheck)
    console.log(
      "PASS: recovery revocation blocks an existing real OAuth token and removes Supabase consent.",
    );
} finally {
  if (fs.existsSync(backupPath)) fs.unlinkSync(backupPath);
  for (const id of clients) {
    const removed = await fetch(
      config.SUPABASE_URL + "/auth/v1/admin/oauth/clients/" + id,
      {
        method: "DELETE",
        headers: {
          apikey: config.SUPABASE_SERVICE_ROLE_KEY,
          Authorization: "Bearer " + config.SUPABASE_SERVICE_ROLE_KEY,
        },
      },
    );
    assert.ok(removed.ok, "Temporary OAuth client cleanup");
  }
  for (const id of users) {
    const removed = await fetch(
      config.SUPABASE_URL + "/auth/v1/admin/users/" + id,
      {
        method: "DELETE",
        headers: {
          apikey: config.SUPABASE_SERVICE_ROLE_KEY,
          Authorization: "Bearer " + config.SUPABASE_SERVICE_ROLE_KEY,
        },
      },
    );
    assert.equal(removed.status, 200, "Temporary account cleanup");
  }
  console.log("Temporary integration accounts removed.");
}
