# Deployment checklist

- Configure your own Cloudflare account, Supabase project and public origin; keep privileged bindings outside source control.
- Apply migrations and bootstrap an administrator before enabling the invitation hook.
- Verify Google identity login, OAuth PKCE, empty-vault connection and private key setup in your selected MCP client.
- Keep a protected off-device encryption-root backup and database/Auth backup. Exercise restore; a temporary-key decryption test does not prove full disaster recovery.
- Verify provider permissions/spending limits, server rate limits, revocation, account deletion and owner isolation.
- Verify TLS, custom-domain redirects, authentication return paths and actual email delivery where offered.
- Replace example legal/contact/operator information with accurate details for your deployment. Necessary-storage UI is not a compliance certification.
- Keep request-body/header logging disabled. Do not expose private network bindings without revisiting outbound security.
- Promote only the features and availability actually verified. Hosted billing and pricing require their own implementation and acceptance checks.
