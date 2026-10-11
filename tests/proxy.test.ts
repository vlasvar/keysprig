import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validatePolicy, validateTarget, prepareHeaders, scrubSecrets, publicAddress, proxyCall, validateCall } from '../worker/proxy';

const policy = validatePolicy({allowed_hosts:['api.example.com'],auth_header:'X-Api-Key',auth_prefix:'',allowed_methods:['GET','POST'],rate_limit_per_minute:10});
test('exact HTTPS destination policy rejects malicious target syntax', () => {
  assert.equal(validateTarget('https://api.example.com/check',policy.allowed_hosts).hostname,'api.example.com');
  for(const url of ['http://api.example.com','https://api.example.com:444','https://user:pass@api.example.com','https://api.example.com.attacker.com','https://attacker.com@api.example.com','https://api.example.com./','https://127.0.0.1','https://[::1]','https://2130706433','https://api.example.com/#fragment','https://api.example.com\\@attacker.com']) assert.throws(()=>validateTarget(url,policy.allowed_hosts),url);
  for(const hostname of ['localhost','metadata.google.internal','*.example.com','API.example.com','192.168.1.1','api.local']) assert.throws(()=>validatePolicy({...policy,allowed_hosts:[hostname]}),hostname);
  assert.throws(()=>validatePolicy({...policy,auth_header:'Host'}));
  assert.throws(()=>validatePolicy({...policy,auth_prefix:'Bearer\r\nInjected: true'}));
});
test('caller cannot override authentication, routing, cookies or framing', () => {
  for(const name of ['x-api-key','Authorization','Proxy-Authorization','Cookie','Host','Content-Length','Transfer-Encoding','X-Forwarded-Host','CF-Connecting-IP','X-HTTP-Method-Override','Forwarded','Connection']) assert.throws(()=>prepareHeaders({[name]:'attacker'},policy.auth_header),name);
  assert.throws(()=>prepareHeaders({'Accept':'ok\r\nX-Evil: true'},policy.auth_header));
  assert.throws(()=>prepareHeaders({'Accept':'x'.repeat(8193)},policy.auth_header));
  assert.equal(prepareHeaders({'Accept':'application/json'},policy.auth_header).get('Accept'),'application/json');
});
test('public address validation rejects private, metadata, mapped and reserved ranges', () => {
  for(const address of ['0.0.0.0','10.0.0.1','127.0.0.1','169.254.169.254','172.16.0.1','192.168.1.1','100.64.0.1','192.0.2.1','198.51.100.1','203.0.113.1','198.18.0.1','224.0.0.1','::','::1','fc00::1','fe80::1','::ffff:127.0.0.1','2001:db8::1','2002:7f00:1::','3fff::1']) assert.equal(publicAddress(address),false,address);
  for(const address of ['93.184.216.34','1.1.1.1','2606:4700:4700::1111']) assert.equal(publicAddress(address),true,address);
});
test('known secret encodings are redacted without exposing upstream headers', () => {
  const secret='fake/key +value';
  const representations=[secret,encodeURIComponent(secret),encodeURIComponent(encodeURIComponent(secret)),JSON.stringify(secret).slice(1,-1),Buffer.from(secret).toString('base64'),Buffer.from(secret).toString('base64url'),Buffer.from(secret).toString('hex')];
  for(const representation of representations) assert.equal(scrubSecrets(representation,secret),'[REDACTED]');
});
test('allowed_methods must contain at least one method; empty never means all', () => {
  const base = {allowed_hosts:['api.example.com'],auth_header:'Authorization',auth_prefix:'Bearer ',rate_limit_per_minute:10};
  assert.throws(() => validatePolicy({...base, allowed_methods: []}));
  assert.throws(() => validatePolicy({...base}));
  assert.throws(() => validatePolicy({...base, allowed_methods: undefined}));
  assert.deepEqual(validatePolicy({...base, allowed_methods: ['GET']}).allowed_methods, ['GET']);
  const empty = {...policy, allowed_methods: []};
  assert.throws(() => validateCall(empty, {method:'GET', url:'https://api.example.com/check'}));
  assert.throws(() => validateCall(empty, {method:'POST', url:'https://api.example.com/check'}));
});
test('proxy injects server authentication, rejects redirects, DNS failures and oversized payloads', async () => {
  let remoteCalls=0;
  let reply=()=>new Response('fake-secret',{headers:{'X-Secret':'fake-secret'}});
  let answers:any[]=[{type:1,data:'93.184.216.34'}];
  const fetcher:typeof fetch=async (input,init)=> {
    const url=new URL(String(input));
    if(url.hostname==='cloudflare-dns.com') {
      assert.equal(init?.redirect,'manual','Workers supports manual redirect rejection');
      return Response.json({Status:0,Answer:answers});
    }
    remoteCalls++;
    assert.equal(new Headers(init?.headers).get('X-Api-Key'),'fake-secret');
    assert.equal(init?.redirect,'manual');
    return reply();
  };
  const input={method:'GET',url:'https://api.example.com/check'};
  assert.deepEqual(await proxyCall(policy,'fake-secret',input,fetcher),{status:200,body:'[REDACTED]'});
  reply=()=>new Response(null,{status:302,headers:{Location:'https://attacker.com'}});
  await assert.rejects(proxyCall(policy,'fake-secret',input,fetcher),/Redirect/);
  reply=()=>new Response('x'.repeat(262145));
  await assert.rejects(proxyCall(policy,'fake-secret',input,fetcher));
  reply=()=>new Response('small',{headers:{'Content-Length':'262145'}});
  await assert.rejects(proxyCall(policy,'fake-secret',input,fetcher));
  const before=remoteCalls;
  answers=[{type:1,data:'169.254.169.254'}];
  await assert.rejects(proxyCall(policy,'fake-secret',input,fetcher));
  assert.equal(remoteCalls,before);
  answers=[];
  await assert.rejects(proxyCall(policy,'fake-secret',input,fetcher));
  assert.equal(remoteCalls,before);
  await assert.rejects(proxyCall(policy,'fake-secret',{...input,method:'DELETE'},fetcher));
  await assert.rejects(proxyCall(policy,'fake-secret',{...input,method:'POST',body:'x'.repeat(65537)},fetcher));
  await assert.rejects(proxyCall(policy,'fake-secret',{...input,body:'get body'},fetcher));
  assert.equal(remoteCalls,before);
});
