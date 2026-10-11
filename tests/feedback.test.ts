import assert from "node:assert/strict";
import test from "node:test";
import { feedback, validateFeedback } from "../worker/feedback";

test("feedback validates category and size before database submission", () => {
  assert.equal(validateFeedback({ category: "Bug", message: " " }), null);
  assert.equal(validateFeedback({ category: "unexpected", message: "Hello" }), null);
  assert.equal(validateFeedback({ category: "Idea", message: "a".repeat(4001) }), null);
  assert.deepEqual(validateFeedback({ category: "Other", message: "  Hello  " }), { category: "Other", message: "Hello" });
});
test("feedback limit produces a safe response without reflecting submitted content", async () => {
  const response = await feedback(new Request("https://keysprig.xyz/api/feedback", { method: "POST", body: JSON.stringify({ category: "Bug", message: "private test content" }) }), { rpc: async () => ({ data: false, error: null }) } as any, "owner");
  assert.equal(response.status, 429);
  assert.ok(!(await response.text()).includes("private test content"));
});
test("feedback review denies a non-admin", async () => {
  const db = { from: () => ({ select: () => ({ eq: () => ({ maybeSingle: async () => ({ data: null, error: null }) }) }) }) };
  assert.equal((await feedback(new Request("https://keysprig.xyz/api/feedback"), db as any, "owner")).status, 403);
});
