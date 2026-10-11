# Hosted v1 outbound security decision

Reviewed 2026-10-10. This records the agreed target scope; it does not certify
that the generic proxy or its controls have been implemented.

## Keep the hosted vault on Workers

Cloudflare documents private-network access through explicit Workers VPC
bindings and Cloudflare Tunnel, Mesh, or WAN connectivity:

- https://developers.cloudflare.com/workers-vpc/
- https://developers.cloudflare.com/workers-vpc/configuration/vpc-networks/
- https://developers.cloudflare.com/workers-vpc/api/

The current `wrangler.jsonc` has no VPC, service, Hyperdrive, or other private
network bindings. The hosted Worker does not run on the user's machine or in
the user's home/company network. Consequently, DNS rebinding cannot create a
route into those networks through the configured application. This is an
architectural inference from the documented connectivity model and inspected
configuration, not a claim that every Workers HTTP destination is safe.

The TCP socket documentation explicitly excludes localhost and private network
IPs, but that statement is about `connect()`, not a documented guarantee for
all HTTP `fetch()` behavior:
https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/

Workers fetch uses Cloudflare DNS and does not expose a general arbitrary-host
IP-pinning control. `resolveOverride` is limited to hosts within the applicable
zone. A separate DNS check followed by fetch must never be described as pinned:

- https://developers.cloudflare.com/workers/platform/known-issues/
- https://developers.cloudflare.com/workers/runtime-apis/request/

Hosted v1 therefore accepts unpinned Workers egress under the no-private-network
connectivity boundary. This does not establish absence of every possible
Cloudflare-internal destination. If strict transport-level public-IP enforcement
is required, use a transport that can pin and verify the connection; do not
silently substitute a DNS precheck. Reassess before adding any private-network
bindings or changing the runtime.

## Required generic proxy controls

- No raw-secret MCP tool or export in v1; decrypt only for authenticated use.
- Human-set exact destination hostnames and authentication header per key.
- HTTPS on port 443 only; reject URL credentials, IP literals, local/internal
  names, redirects, and caller-controlled authentication/routing headers.
- Public DNS validation can reject obvious private/reserved answers as defense
  in depth, but is not pinning and must not be represented as rebinding-proof.
- Optional human-selected allowed methods per key, enforced before sending.
- Atomic shared rate limits per owner/agent/key; no per-isolate counters.
- Per-key approval, expiring grants, and rechecking revocation at use time.
- Bounded request/response sizes and request duration. Fail closed on policy,
  authorization, rate-limit, or audit-storage failure.
- Scrub known secret representations from returned content. Return no upstream
  response headers by default. Do not claim arbitrary transformed-secret removal.
- Audit owner, agent, key identifier/name, destination host, method, outcome, and
  time; never secret, request/response bodies, headers, or full URLs with queries.
- Disable infrastructure tracing of outbound sensitive requests unless verified
  to exclude sensitive headers, bodies, and URL queries.

Allowed hosts are trusted recipients of the key. Host restrictions and method
restrictions are not endpoint/action authorization or provider spending caps.

## Local or private-network deployment

Before enabling generic calls locally or inside a private network, implement
real pinning: resolve, reject nonpublic/reserved addresses, select a validated
address, connect to that exact address, retain the original HTTPS hostname for
SNI and certificate verification, and do not follow redirects. No second lookup
may choose a different address. Test rebinding, IPv4/IPv6, redirect, revocation,
and concurrent rate-limit behavior before enabling the transport.
