# Testing

Run `npm run typecheck`, `npm test` and `npm run build` without live secrets. Tests use synthetic accounts and dummy keys.

For opt-in integration checks, use your own test Supabase project, private .dev.vars and a compiled local Worker. `npm run verify:live` creates disposable confirmed .invalid users and an OAuth client, exercises isolation, private setup, encrypted storage, generic calls and revocation, and removes test accounts. Set VAULT_TEST_URL only when deliberately targeting a deployed test instance. Do not use production users or unrestricted provider keys.

For browser checks, `npm run verify:browser` uses an installed Chrome and disposable accounts. Review the script's requirements first. `scripts/verify-beta.mjs` checks the invitation hook and feedback limits.

Manual acceptance: sign in, connect with zero key access, add a dummy/restricted key through private setup, approve only intended access, make a harmless read, confirm no secret is returned, revoke and verify denial, submit feedback, and test account deletion only on a disposable account. Check desktop/mobile layouts and legal links. For email features, separately verify real delivery using an inbox you control.
