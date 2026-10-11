import { test } from "node:test";
import assert from "node:assert/strict";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { encrypt, decrypt, authorize } from "../worker/security";
import { withDeadline, readLimited } from "../worker/http";
import Legal from "../web/Legal";
test("remote calls abort on deadline and streamed bodies are bounded", async () => {
  await assert.rejects(
    withDeadline(
      (signal) =>
        new Promise((_resolve, reject) =>
          signal.addEventListener("abort", () => reject(Error("aborted"))),
        ),
      10,
    ),
  );
  assert.equal(await readLimited(new Response("small").body!, 5), "small");
  await assert.rejects(readLimited(new Response("too large").body!, 5));
});
test("ciphertext cannot be moved between owners or records", async () => {
  const root = btoa(
    String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))),
  );
  const record = await encrypt(root, "alice/key/1", "private-value");
  assert.equal(await decrypt(root, "alice/key/1", record), "private-value");
  assert.ok(!record.ciphertext.includes("private-value"));
  await assert.rejects(decrypt(root, "bob/key/1", record));
  await assert.rejects(decrypt(root, "alice/other/1", record));
});
test("human sessions and OAuth clients have distinct access boundaries", () => {
  assert.equal(
    authorize({ sub: "alice", role: "authenticated" }, "human").owner,
    "alice",
  );
  assert.throws(() =>
    authorize(
      { sub: "alice", role: "authenticated", client_id: "client" },
      "human",
    ),
  );
  assert.throws(() =>
    authorize({ sub: "alice", role: "authenticated" }, "agent"),
  );
  assert.throws(() =>
    authorize({ sub: "alice", role: "service_role" }, "human"),
  );
  assert.equal(
    authorize(
      { sub: "alice", role: "authenticated", client_id: "client" },
      "agent",
    ).client,
    "client",
  );
});
test("legal pages describe stored data and omit personal identifiers", () => {
  const html = (["privacy", "terms", "cookies"] as const)
    .map((page) => renderToStaticMarkup(React.createElement(Legal, { page })))
    .join("\n");
  assert.doesNotMatch(html, /[a-z0-9._%+-]+@(gmail|icloud)\.com/i);
  assert.match(html, /privacy@keysprig\.xyz/);
  assert.doesNotMatch(html, /TODO/);
  assert.match(html, /KeySprig team/);
  assert.match(html, /Hellenic/);
  assert.match(html, /AgentMail/);
  assert.match(html, /localStorage/);
  assert.match(html, /Created by the/);
  assert.match(html, /aislop\.gr/);
});
