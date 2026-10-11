import { isIP } from 'node:net';
import { readLimited, withDeadline } from './http';

export class ProxyFailure extends Error {
  constructor(public readonly stage: string) { super('Outbound request failed'); }
}

export interface Policy {
  allowed_hosts: string[];
  auth_header: string;
  auth_prefix: string;
  allowed_methods: string[];
  rate_limit_per_minute: number;
}
const methods = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'];
const forbidden = /^(authorization|proxy-authorization|cookie|set-cookie|host|connection|content-length|transfer-encoding|te|trailer|upgrade|expect|forwarded|via|origin|referer|accept-encoding|x-forwarded-.*|cf-.*|sec-.*|proxy-.*|x-http-method.*|x-original-.*|x-rewrite-.*)$/i;
function host(value: unknown): string {
  if (typeof value !== 'string' || value !== value.toLowerCase() || value.length > 253 || !value.includes('.') || isIP(value) || !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(value) || /\.(localhost|local|internal|lan|home|test|invalid|example|onion)$/.test(value) || value === 'localhost' || value === 'metadata.google.internal') throw Error('Invalid destination hostname');
  return value;
}
export function validatePolicy(input: any): Policy {
  if (!Array.isArray(input.allowed_hosts) || input.allowed_hosts.length < 1 || input.allowed_hosts.length > 10) throw Error('Choose 1 to 10 destination hosts');
  const allowed_hosts = [...new Set<string>(input.allowed_hosts.map(host))];
  if (typeof input.auth_header !== 'string' || !/^[A-Za-z][A-Za-z0-9-]{0,63}$/.test(input.auth_header) || (forbidden.test(input.auth_header) && input.auth_header.toLowerCase() !== 'authorization')) throw Error('Invalid authentication header');
  const auth_prefix = input.auth_prefix ?? '';
  if (typeof auth_prefix !== 'string' || auth_prefix.length > 40 || /[^\x20-\x7e]/.test(auth_prefix)) throw Error('Invalid authentication prefix');
  const allowed_methods = input.allowed_methods;
  if (!Array.isArray(allowed_methods) || allowed_methods.length < 1 || allowed_methods.some((m: unknown) => typeof m !== 'string' || !methods.includes(m)) || allowed_methods.length > methods.length) throw Error('Allowed methods must include at least one method');
  const rate_limit_per_minute = input.rate_limit_per_minute ?? 30;
  if (!Number.isInteger(rate_limit_per_minute) || rate_limit_per_minute < 1 || rate_limit_per_minute > 120) throw Error('Rate must be 1 to 120 per minute');
  return { allowed_hosts, auth_header: input.auth_header, auth_prefix, allowed_methods: [...new Set<string>(allowed_methods)], rate_limit_per_minute };
}
export function validateTarget(value: string, allowedHosts: string[]): URL {
  if (typeof value !== 'string' || value.length > 4096 || /[\x00-\x20\x7f\\]/.test(value)) throw Error('Invalid URL');
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.port || url.username || url.password || url.hash || !allowedHosts.includes(host(url.hostname))) throw Error('Destination is not allowed');
  return url;
}
export function prepareHeaders(input: Record<string, string> = {}, authHeader: string): Headers {
  if (!input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).length > 30) throw Error('Invalid headers');
  const headers = new Headers();
  let size = 0;
  for (const [name, value] of Object.entries(input)) {
    if (typeof value !== 'string' || !/^[A-Za-z][A-Za-z0-9-]{0,63}$/.test(name) || forbidden.test(name) || name.toLowerCase() === authHeader.toLowerCase() || /[\r\n\x00]/.test(value)) throw Error('Header override is not allowed');
    size += name.length + value.length;
    if (size > 8192) throw Error('Headers too large');
    headers.set(name, value);
  }
  return headers;
}
export function publicAddress(address: string): boolean {
  if (isIP(address) === 4) {
    const [a,b,c] = address.split('.').map(Number);
    return !(a===0 || a===10 || a===127 || a>=224 || (a===100 && b>=64 && b<=127) || (a===169 && b===254) || (a===172 && b>=16 && b<=31) || (a===192 && (b===168 || b===0 || (b===88 && c===99))) || (a===198 && (b===18 || b===19 || (b===51 && c===100))) || (a===203 && b===0 && c===113));
  }
  // Fail closed outside global unicast; reject mapped, translation, docs, transition and reserved ranges.
  if (isIP(address) !== 6 || !/^[23][0-9a-f]{3}:/i.test(address)) return false;
  const parts = address.toLowerCase().split(':');
  const first = parseInt(parts[0],16), second = parseInt(parts[1] || '0',16);
  return !(first === 0x2002 || first === 0x3fff || (first === 0x2001 && (second < 0x200 || second === 0xdb8)));
}
export function scrubSecrets(text: string, secret: string): string {
  const utf8 = new TextEncoder().encode(secret);
  const encoded = btoa(Array.from(utf8, b => String.fromCharCode(b)).join(''));
  const representations = [secret, encodeURIComponent(secret), encodeURIComponent(encodeURIComponent(secret)), JSON.stringify(secret).slice(1,-1), encoded, encoded.replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''), Array.from(utf8,b=>b.toString(16).padStart(2,'0')).join(''), Array.from(secret,c=>'\\u'+c.charCodeAt(0).toString(16).padStart(4,'0')).join('')];
  representations.push(encodeURIComponent(secret).replace(/%[0-9A-F]{2}/g, s=>s.toLowerCase()), Array.from(utf8,b=>b.toString(16).padStart(2,'0')).join('').toUpperCase());
  for (const value of [...new Set(representations)].sort((a,b)=>b.length-a.length)) if (value) text = text.split(value).join('[REDACTED]');
  return text;
}
export interface ProxyInput { key_name?: string; method: string; url: string; headers?: Record<string,string>; body?: string }
export function validateCall(policy: Policy, input: ProxyInput) {
  const target = validateTarget(input.url, policy.allowed_hosts);
  if (!methods.includes(input.method) || !policy.allowed_methods.includes(input.method)) throw Error('Method is not allowed');
  if (input.body !== undefined && (typeof input.body !== 'string' || new TextEncoder().encode(input.body).length > 65536 || ['GET','HEAD'].includes(input.method))) throw Error('Invalid request body');
  return {target, headers: prepareHeaders(input.headers, policy.auth_header)};
}
export async function proxyCall(policy: Policy, secret: string, input: ProxyInput, fetcher: typeof fetch = fetch) {
  const {target,headers} = validateCall(policy,input);
  if (!secret || /[\r\n\x00]/.test(secret)) throw Error('Invalid authentication value');
  return withDeadline(async signal => {
    let stage = 'DNS request';
    try {
    let addressCount = 0;
    for (const type of ['A','AAAA']) {
      stage = 'DNS request';
      const dns = await fetcher('https://cloudflare-dns.com/dns-query?name='+encodeURIComponent(target.hostname)+'&type='+type,{headers:{Accept:'application/dns-json'},redirect:'manual',signal});
      if (!dns.ok) throw Error('Destination lookup failed');
      stage = 'DNS response parsing';
      const result = JSON.parse(await readLimited(dns.body,16384));
      if (result.Status !== 0 || !Array.isArray(result.Answer ?? [])) throw Error('Destination lookup failed');
      const answers = (result.Answer ?? []).filter((a:any)=>a.type===1 || a.type===28);
      if (answers.some((a:any)=>!publicAddress(a.data))) throw Error('Private destination rejected');
      addressCount += answers.length;
    }
    if (!addressCount) throw Error('Destination lookup failed');
    stage = 'authentication header';
    headers.set(policy.auth_header,policy.auth_prefix+secret);
    stage = 'HTTPS request';
    const response = await fetcher(target.href,{method:input.method,headers,body:input.body,redirect:'manual',signal});
    if (response.status>=300 && response.status<400) { await response.body?.cancel(); throw Error('Redirect rejected'); }
    if (Number(response.headers.get('content-length')??0)>262144) { await response.body?.cancel(); throw Error('Response too large'); }
    stage = 'response reading';
    const text = await readLimited(response.body,262144);
    stage = 'response scrubbing';
    return { status: response.status, body: scrubSecrets(text,secret) };
    } catch (error) {
      if (error instanceof Error && ['Destination lookup failed','Private destination rejected','Redirect rejected','Response too large','Body too large'].includes(error.message)) throw error;
      throw new ProxyFailure(stage);
    }
  },10000);
}
