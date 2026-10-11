begin;
create table public.vault_key_setup_completions (
  request_id uuid primary key,
  owner_id uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);
alter table public.vault_key_setup_completions enable row level security;
revoke all on public.vault_key_setup_completions from public,anon,authenticated;
grant select,insert,delete on public.vault_key_setup_completions to service_role;

create function public.vault_complete_key_setup(p_owner uuid,p_agent uuid,p_request uuid,p_id uuid,p_ciphertext text,p_nonce text,p_methods text[],p_days integer)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if p_days not in (1,7,30) or not (p_methods = array['GET']::text[] or p_methods = array['GET','POST']::text[]) then raise exception 'Invalid policy'; end if;
  perform 1 from public.vault_agents where id=p_agent and owner_id=p_owner and revoked_at is null for update;
  if not found then raise exception 'Invalid agent'; end if;
  -- Single-use receipt, encrypted key, approval and audit commit together.
  insert into public.vault_key_setup_completions(request_id,owner_id) values(p_request,p_owner);
  insert into public.vault_keys(id,owner_id,name,ciphertext,nonce,key_version,allowed_hosts,auth_header,auth_prefix,allowed_methods,rate_limit_per_minute)
  values(p_id,p_owner,'agentmail',p_ciphertext,p_nonce,1,array['api.agentmail.to'],'Authorization','Bearer ',p_methods,10);
  insert into public.vault_permissions(owner_id,agent_id,key_id,expires_at)
  values(p_owner,p_agent,p_id,now()+make_interval(days=>p_days));
  insert into public.vault_events(owner_id,agent_id,key_id,key_name,action,outcome)
  values(p_owner,p_agent,p_id,'agentmail','key.setup','approved');
end $$;
revoke all on function public.vault_complete_key_setup(uuid,uuid,uuid,uuid,text,text,text[],integer) from public,anon,authenticated;
grant execute on function public.vault_complete_key_setup(uuid,uuid,uuid,uuid,text,text,text[],integer) to service_role;
commit;
