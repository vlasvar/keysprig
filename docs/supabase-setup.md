# Configure your own Supabase project

Keep all credentials private. Only the project URL and public anon/publishable key belong in `.env.local`; never use a VITE_ prefix for a service-role key or encryption root.

1. Create a Supabase project and fill in `.env.local` and `.dev.vars` from the examples. VAULT_ROOT_KEY must encode 32 cryptographically random bytes in base64. Generate it locally, store it privately and back it up separately from the database. Losing the root makes encrypted keys unrecoverable.
2. Apply every SQL file under supabase/migrations in filename order. The public source has no preconfigured owner account. Table privileges intentionally deny browser users direct access to vault data.
3. Configure Google sign-in with a Google OAuth web client. Use the exact callback displayed by Supabase (`https://<project-ref>.supabase.co/auth/v1/callback`). Save its secret only in Supabase. Use identity scopes and enable VITE_GOOGLE_AUTH_ENABLED after configuration.
4. Set Auth Site URL to your instance. Allow its sign-in, consent and `/setup-key` return paths; include explicit local development origins only while needed.
5. Enable Supabase's OAuth server with authorization path `/oauth/consent` and dynamic client registration for compatible remote MCP clients. Confirm the client can complete authorization-code PKCE. MCP requires an OAuth client token; a human dashboard token is deliberately rejected.
6. Bootstrap an administrator before enabling invitation-only registration: create and verify your first account, then add that account's UUID to public.vault_admins through the SQL editor. Do not paste a personal account UUID into source control.
7. Enable the Before User Created hook `pg-functions://postgres/public/vault_before_user_created`. It requires a valid invitation claim and the actual Google provider on new accounts. Existing users can still sign in; new email/password registration is not supported by this hook.
8. Create invitations from the administrator's Settings screen. Invitation limits are installation settings, not public marketing copy. Set public.vault_installation_settings.invitation_limit to a positive integer if a cap is wanted; NULL leaves it uncapped. Claims remain single-use and expire.
9. Configure production SMTP if password recovery is offered for existing password accounts. Test actual delivery and recovery; Google users do not need a separate vault password.

Run the checks in testing.md with dummy credentials. Before exposing your instance, replace the included hosted branding/contact/legal URLs with your own accurate operator details and verify your provider's current OAuth requirements.
