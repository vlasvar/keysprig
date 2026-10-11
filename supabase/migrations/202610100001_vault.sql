-- All vault access goes through the authenticated Worker. Never expose the
-- service-role credential to the browser or MCP client.
begin;

create table public.vault_keys (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  name text not null check (char_length(name) between 1 and 100 and name = btrim(name)),
  ciphertext text not null check (char_length(ciphertext) > 0),
  nonce text not null check (char_length(nonce) > 0),
  key_version integer not null default 1 check (key_version > 0),
  created_at timestamptz not null default now(),
  unique (owner_id, name)
);

create table public.vault_agents (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  oauth_client_id text not null check (char_length(oauth_client_id) between 1 and 512),
  label text not null check (char_length(label) between 1 and 100),
  revoked_at timestamptz,
  created_at timestamptz not null default now(),
  unique (owner_id, oauth_client_id)
);

create table public.vault_events (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  action text not null check (char_length(action) between 1 and 100),
  key_name text check (key_name is null or char_length(key_name) between 1 and 100),
  created_at timestamptz not null default now()
);

create index vault_events_owner_created_idx on public.vault_events (owner_id, created_at desc);

alter table public.vault_keys enable row level security;
alter table public.vault_agents enable row level security;
alter table public.vault_events enable row level security;

-- Owner policies are defense in depth if privileges are intentionally changed
-- later. They do not protect requests executed using service_role (BYPASSRLS).
create policy vault_keys_owner on public.vault_keys for all to authenticated
  using ((select auth.uid()) = owner_id) with check ((select auth.uid()) = owner_id);
create policy vault_agents_owner on public.vault_agents for all to authenticated
  using ((select auth.uid()) = owner_id) with check ((select auth.uid()) = owner_id);
create policy vault_events_owner on public.vault_events for all to authenticated
  using ((select auth.uid()) = owner_id) with check ((select auth.uid()) = owner_id);

-- Explicitly override Supabase public-schema default table privileges. An
-- authenticated Data API request must not read ciphertext or mutate grants.
revoke all on table public.vault_keys, public.vault_agents, public.vault_events
  from public, anon, authenticated;
grant select, insert, update, delete on table public.vault_keys, public.vault_agents, public.vault_events
  to service_role;

comment on table public.vault_keys is 'Encrypted values only; Worker validates token and owner before every service-role query. No browser Data API access.';
comment on table public.vault_agents is 'Worker-managed consent and revocation; OAuth client_id comes from a verified token, never a display name.';
comment on table public.vault_events is 'Secret-free audit metadata; no values, tokens, provider bodies, or plaintext in action/key_name.';

commit;
