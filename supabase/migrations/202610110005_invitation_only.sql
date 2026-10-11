begin;
create table public.vault_admins (
  user_id uuid primary key references auth.users(id) on delete cascade
);
create table public.vault_invitations (
  id uuid primary key default gen_random_uuid(),
  code_hash text not null unique check (code_hash ~ '^[0-9a-f]{64}$'),
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  claimed_email text,
  claimed_until timestamptz,
  used_at timestamptz,
  revoked_at timestamptz,
  -- The hook runs before auth.users insertion, so this cannot be a foreign key.
  used_by uuid
);
create table public.vault_invitation_attempts (
  ip_hash text primary key check (ip_hash ~ '^[0-9a-f]{64}$'),
  window_start timestamptz not null,
  attempts integer not null
);
alter table public.vault_admins enable row level security;
alter table public.vault_invitations enable row level security;
alter table public.vault_invitation_attempts enable row level security;
revoke all on public.vault_admins,public.vault_invitations,public.vault_invitation_attempts from public,anon,authenticated;
grant all on public.vault_admins,public.vault_invitations,public.vault_invitation_attempts to service_role;

create table public.vault_installation_settings (
  singleton boolean primary key default true check (singleton),
  invitation_limit integer check (invitation_limit > 0)
);
insert into public.vault_installation_settings(singleton,invitation_limit) values(true,null);
alter table public.vault_installation_settings enable row level security;
revoke all on public.vault_installation_settings from public,anon,authenticated;
grant select,update on public.vault_installation_settings to service_role;

create function public.vault_create_invitation(p_owner uuid,p_hash text)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare expiry timestamptz := now()+interval '7 days'; seat_limit integer;
begin
  -- Serialize the total-seat cap across all administrators.
  perform pg_catalog.pg_advisory_xact_lock(792811005);
  if not exists(select 1 from public.vault_admins where user_id=p_owner) then return jsonb_build_object('error','forbidden'); end if;
  select invitation_limit into seat_limit from public.vault_installation_settings where singleton=true;
  if seat_limit is not null and (select count(*) from public.vault_invitations where used_at is not null or (revoked_at is null and expires_at > now())) >= seat_limit then
    return jsonb_build_object('error','full');
  end if;
  insert into public.vault_invitations(code_hash,created_by,expires_at) values(p_hash,p_owner,expiry);
  return jsonb_build_object('expires_at',expiry);
end;
$$;
revoke all on function public.vault_create_invitation(uuid,text) from public,anon,authenticated;
grant execute on function public.vault_create_invitation(uuid,text) to service_role;

create function public.vault_claim_invitation(p_hash text,p_email text,p_ip_hash text)
returns text language plpgsql security definer set search_path = '' as $$
declare count_attempts integer;
begin
  -- Persist the limiter, including failed claims; serialize concurrent attempts.
  delete from public.vault_invitation_attempts where window_start < now()-interval '1 day';
  insert into public.vault_invitation_attempts(ip_hash,window_start,attempts)
  values(p_ip_hash,now(),1)
  on conflict(ip_hash) do update set
    attempts=case when public.vault_invitation_attempts.window_start < now()-interval '10 minutes' then 1 else public.vault_invitation_attempts.attempts+1 end,
    window_start=case when public.vault_invitation_attempts.window_start < now()-interval '10 minutes' then now() else public.vault_invitation_attempts.window_start end
  returning attempts into count_attempts;
  if count_attempts > 10 then return 'limited'; end if;
  update public.vault_invitations set claimed_email=null,claimed_until=null where claimed_until < now();
  if exists(select 1 from auth.users where lower(email)=lower(trim(p_email))) then return 'invalid'; end if;
  update public.vault_invitations set claimed_email=lower(trim(p_email)),claimed_until=now()+interval '30 minutes'
  where code_hash=p_hash and used_at is null and revoked_at is null and expires_at > now()
    and (claimed_until is null or claimed_until < now() or claimed_email=lower(trim(p_email)));
  if found then return 'ok'; end if;
  return 'invalid';
end;
$$;
revoke all on function public.vault_claim_invitation(text,text,text) from public,anon,authenticated;
grant execute on function public.vault_claim_invitation(text,text,text) to service_role;

-- Enable this function as the Supabase Before User Created hook. Checking the
-- verified provider email here also prevents direct OAuth/API signup bypasses.
create function public.vault_before_user_created(event jsonb)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare selected_id uuid;
begin
  if event->'user'->'app_metadata'->>'provider' is distinct from 'google' then
    return jsonb_build_object('error',jsonb_build_object('http_code',403,'message','New accounts require a KeySprig invitation and Google sign-in.'));
  end if;
  select id into selected_id from public.vault_invitations
    where used_at is null and revoked_at is null and expires_at > now() and claimed_until > now()
      and claimed_email=lower(trim(event->'user'->>'email'))
    order by created_at limit 1 for update skip locked;
  if selected_id is null then
    return jsonb_build_object('error',jsonb_build_object('http_code',403,'message','Enter a valid KeySprig invitation before creating an account.'));
  end if;
  update public.vault_invitations set used_at=now(),used_by=(event->'user'->>'id')::uuid,claimed_email=null,claimed_until=null where id=selected_id;
  return '{}'::jsonb;
end;
$$;
revoke all on function public.vault_before_user_created(jsonb) from public,anon,authenticated,service_role;
grant usage on schema public to supabase_auth_admin;
grant execute on function public.vault_before_user_created(jsonb) to supabase_auth_admin;
commit;
