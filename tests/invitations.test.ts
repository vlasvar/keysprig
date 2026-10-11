import { test } from "node:test";
import assert from "node:assert/strict";
import worker from "../worker/index";

test("Invitation claims reject cross-origin and malformed requests, hash identifiers, and honor persistent limits",async () => {
  const oldFetch=globalThis.fetch;
  const env={SUPABASE_URL:"https://invites.supabase.co",SUPABASE_ANON_KEY:"unused",SUPABASE_SERVICE_ROLE_KEY:"unused",VAULT_ROOT_KEY:"private-test-root",ASSETS:{fetch:async()=>new Response("unused")}};
  let result="ok";
  let calls=0;
  globalThis.fetch=async (input,init)=>{
    calls++;
    const req=input instanceof Request?input:new Request(input,init);
    assert.equal(new URL(req.url).pathname,"/rest/v1/rpc/vault_claim_invitation");
    const data=await req.json() as Record<string,string>;
    assert.match(data.p_hash,/^[0-9a-f]{64}$/);
    assert.match(data.p_ip_hash,/^[0-9a-f]{64}$/);
    assert.equal(data.p_email,"test@example.com");
    assert.ok(!JSON.stringify(data).includes("203.0.113.10"));
    assert.ok(!JSON.stringify(data).includes("private-test-root"));
    return Response.json(result);
  };
  const send=(code:string,origin="https://keysprig.xyz")=>worker.fetch(new Request("https://keysprig.xyz/api/invitations/redeem",{method:"POST",headers:{Origin:origin,"Content-Type":"application/json","CF-Connecting-IP":"203.0.113.10"},body:JSON.stringify({code,email:"TEST@example.com"})}),env);
  try {
    assert.equal((await send("a".repeat(43),"https://attacker.example")).status,403);
    assert.equal((await send("short")).status,400);
    assert.equal(calls,0);
    assert.equal((await send("a".repeat(43))).status,200);
    result="invalid";
    assert.equal((await send("a".repeat(43))).status,400);
    result="limited";
    assert.equal((await send("a".repeat(43))).status,429);
  } finally {globalThis.fetch=oldFetch;}
});
