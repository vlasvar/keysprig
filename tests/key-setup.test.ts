import assert from "node:assert/strict";
import test from "node:test";
import {
  agentMailPolicy,
  createSetupLink,
  readIntent,
  keySetup,
} from "../worker/key-setup";
const root = btoa("a".repeat(32));

test("setup links hide identity, require the matching owner and reject tampering and expiry", async () => {
  const link = await createSetupLink(
    root,
    "https://keysprig.xyz",
    "private-owner",
    "agent-id",
  );
  const url = new URL(link);
  assert.equal(url.pathname, "/setup-key");
  assert.equal(url.search, "");
  assert.ok(!link.includes("private-owner") && !link.includes("agent-id"));
  const token = url.hash.slice(1);
  assert.equal(
    (await readIntent(root, token, "private-owner")).agent,
    "agent-id",
  );
  await assert.rejects(readIntent(root, token, "other-owner"));
  await assert.rejects(
    readIntent(root, token.slice(0, -5) + "AAAAA", "private-owner"),
  );
  await assert.rejects(
    readIntent(btoa("b".repeat(32)), token, "private-owner"),
  );
  const now = Date.now;
  Date.now = () => now() + 16 * 60000;
  try {
    await assert.rejects(readIntent(root, token, "private-owner"));
  } finally {
    Date.now = now;
  }
});
test("provider policy is server fixed, read-only by choice and rejects arbitrary access", () => {
  assert.deepEqual(agentMailPolicy("read").allowed_methods, ["GET"]);
  assert.deepEqual(agentMailPolicy("send").allowed_methods, ["GET", "POST"]);
  assert.equal(agentMailPolicy("read").auth_prefix, "Bearer ");
  assert.throws(() => agentMailPolicy("DELETE"));
});
test("private setup rejects disconnected agents and never echoes submitted secrets", async () => {
  const setup = new URL(
    await createSetupLink(root, "https://keysprig.xyz", "owner", "agent"),
  ).hash.slice(1);
  const db = {
    from: () => ({
      select: () => ({
        eq: () => ({
          eq: () => ({
            is: () => ({
              maybeSingle: async () => ({ data: null, error: null }),
            }),
          }),
        }),
      }),
    }),
  };
  const r = await keySetup(
    new Request("https://keysprig.xyz/api/key-setup", {
      method: "POST",
      body: JSON.stringify({ setup, action: "save", value: "never-echo-this" }),
    }),
    db as any,
    root,
    "owner",
  );
  assert.equal(r.status, 403);
  assert.ok(!(await r.text()).includes("never-echo-this"));
});
