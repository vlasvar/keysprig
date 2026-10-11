// Opt-in live checks. Creates disposable .invalid users and removes them afterward.
import fs from "node:fs";
import crypto from "node:crypto";
import assert from "node:assert/strict";
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
const admin = {
  apikey: config.SUPABASE_SERVICE_ROLE_KEY,
  Authorization: `Bearer ${config.SUPABASE_SERVICE_ROLE_KEY}`,
  "Content-Type": "application/json",
};
const anon = {
  apikey: config.SUPABASE_ANON_KEY,
  "Content-Type": "application/json",
};
const email = `beta-proof-${crypto.randomUUID()}@vault-test.invalid`,
  password = crypto.randomBytes(32).toString("base64url");
let user, invitation;
const request = (path, token, method = "GET", body) =>
  fetch(base + path, {
    method,
    headers: {
      "Content-Type": "application/json",
      Origin: base,
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
try {
  const denied = await fetch(config.SUPABASE_URL + "/auth/v1/signup", {
    method: "POST",
    headers: anon,
    body: JSON.stringify({ email, password, data: { provider: "google" } }),
  });
  assert.equal(denied.ok, false);
  assert.match((await denied.json()).msg || "", /invitation/);
  console.log("Direct signup and user-metadata provider spoofing blocked.");
  const created = await fetch(config.SUPABASE_URL + "/auth/v1/admin/users", {
    method: "POST",
    headers: admin,
    body: JSON.stringify({ email, password, email_confirm: true }),
  });
  const creation = await created.json();
  assert.equal(created.ok, true);
  user = creation.id;
  const signed = await fetch(
    config.SUPABASE_URL + "/auth/v1/token?grant_type=password",
    {
      method: "POST",
      headers: anon,
      body: JSON.stringify({ email, password }),
    },
  );
  const session = await signed.json();
  assert.ok(session.access_token);
  assert.equal(
    (await request("/api/invitations", session.access_token)).status,
    403,
  );
  assert.equal(
    (await request("/api/feedback", session.access_token)).status,
    403,
  );
  for (let i = 0; i < 3; i++)
    assert.equal(
      (
        await request("/api/feedback", session.access_token, "POST", {
          category: "Other",
          message: "Disposable beta verification",
        })
      ).status,
      201,
    );
  assert.equal(
    (
      await request("/api/feedback", session.access_token, "POST", {
        category: "Other",
        message: "Disposable beta verification",
      })
    ).status,
    429,
  );
  console.log(
    "Existing sign-in, owner restrictions and feedback persistence/rate limit passed.",
  );
  const code = crypto.randomBytes(32).toString("base64url"),
    hash = crypto.createHash("sha256").update(code).digest("hex");
  const inserted = await fetch(
    config.SUPABASE_URL + "/rest/v1/vault_invitations",
    {
      method: "POST",
      headers: { ...admin, Prefer: "return=representation" },
      body: JSON.stringify({
        code_hash: hash,
        created_by: user,
        expires_at: new Date(Date.now() + 3600000).toISOString(),
      }),
    },
  );
  const rows = await inserted.json();
  assert.equal(inserted.ok, true);
  invitation = rows[0].id;
  const pendingEmail = `claim-${crypto.randomUUID()}@vault-test.invalid`;
  assert.equal(
    (
      await request("/api/invitations/redeem", null, "POST", {
        code,
        email: pendingEmail,
      })
    ).status,
    200,
  );
  assert.equal(
    (
      await request("/api/invitations/redeem", null, "POST", {
        code,
        email: "other@vault-test.invalid",
      })
    ).status,
    400,
  );
  assert.equal(
    (
      await request("/api/invitations/redeem", null, "POST", {
        code: "bad",
        email: pendingEmail,
      })
    ).status,
    400,
  );
  assert.equal(
    (
      await fetch(base + "/api/invitations/redeem", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Origin: "https://evil.example",
        },
        body: JSON.stringify({ code, email: pendingEmail }),
      })
    ).status,
    403,
  );
  const direct = await fetch(
    config.SUPABASE_URL + "/rest/v1/vault_invitations",
    { headers: anon },
  );
  assert.equal(direct.ok, false);
  console.log(
    "Invitation claim, email binding, cross-origin rejection and direct-table denial passed.",
  );
  const logout = await request("/api/account", session.access_token, "DELETE");
  assert.equal(logout.status, 200);
  const remaining = await fetch(
    config.SUPABASE_URL + `/rest/v1/vault_feedback?owner_id=eq.${user}`,
    { headers: admin },
  );
  assert.deepEqual(await remaining.json(), []);
  user = undefined;
  console.log("Account deletion removes beta feedback.");
} finally {
  if (invitation)
    await fetch(
      config.SUPABASE_URL + `/rest/v1/vault_invitations?id=eq.${invitation}`,
      { method: "DELETE", headers: admin },
    );
  if (user)
    await fetch(config.SUPABASE_URL + `/auth/v1/admin/users/${user}`, {
      method: "DELETE",
      headers: admin,
    });
}
