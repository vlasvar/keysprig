begin;
alter table public.vault_keys
  add column allowed_hosts text[] not null default '{}',
  add column auth_header text not null default 'Authorization',
  add column auth_prefix text not null default 'Bearer ',
  add column allowed_methods text[] not null default '{}',
  add column rate_limit_per_minute integer not null default 30 check (rate_limit_per_minute between 1 and 120);
-- Old keys have no allowed destinations and remain unusable until replaced.
alter table public.vault_events
  add column agent_id uuid,
  add column key_id uuid,
  add column destination text,
  add column method text,
  add column outcome text;
create table public.vault_permissions (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  agent_id uuid not null references public.vault_agents(id) on delete cascade,
  key_id uuid not null references public.vault_keys(id) on delete cascade,
  expires_at timestamptz not null,
  revoked_at timestamptz,
  unique(agent_id,key_id)
);
create table public.vault_rate_limits (
  owner_id uuid not null references auth.users(id) on delete cascade,
  agent_id uuid not null references public.vault_agents(id) on delete cascade,
  key_id uuid not null references public.vault_keys(id) on delete cascade,
  window_start timestamptz not null,
  count integer not null,
  primary key(agent_id,key_id)
);
alter table public.vault_permissions enable row level security;
alter table public.vault_rate_limits enable row level security;
revoke all on public.vault_permissions,public.vault_rate_limits from public,anon,authenticated;
grant select,insert,update,delete on public.vault_permissions,public.vault_rate_limits to service_role;

create function public.vault_set_permissions(p_owner uuid,p_agent uuid,p_keys uuid[],p_expires timestamptz)
returns void language plpgsql security definer set search_path = '' as $$
declare v_key uuid;
begin
  if p_expires <= now() or p_expires > now()+interval '30 days' or cardinality(p_keys)>100 then raise exception 'Invalid permission'; end if;
  perform 1 from public.vault_agents where id=p_agent and owner_id=p_owner and revoked_at is null for update;
  if not found then raise exception 'Invalid agent'; end if;
  foreach v_key in array p_keys loop
    perform 1 from public.vault_keys where id=v_key and owner_id=p_owner;
    if not found then raise exception 'Invalid key'; end if;
  end loop;
  update public.vault_permissions set revoked_at=now() where agent_id=p_agent and owner_id=p_owner;
  foreach v_key in array p_keys loop
    insert into public.vault_permissions(owner_id,agent_id,key_id,expires_at,revoked_at)
    values(p_owner,p_agent,v_key,p_expires,null)
    on conflict(agent_id,key_id) do update set expires_at=excluded.expires_at,revoked_at=null;
  end loop;
  insert into public.vault_events(owner_id,agent_id,action,outcome) values(p_owner,p_agent,'permissions.updated','approved');
end $$;

create function public.vault_begin_call(p_owner uuid,p_agent uuid,p_key_name text,p_destination text,p_method text)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare k public.vault_keys; v_count integer; v_event uuid;
begin
  -- Serialize admission with disconnect and grant changes for this agent.
  perform 1 from public.vault_agents where id=p_agent and owner_id=p_owner and revoked_at is null for update;
  if not found then raise exception 'Access denied'; end if;
  select * into k from public.vault_keys where owner_id=p_owner and name=p_key_name for share;
  if not found then raise exception 'Access denied'; end if;
  perform 1 from public.vault_permissions where owner_id=p_owner and agent_id=p_agent and key_id=k.id and revoked_at is null and expires_at>now() for share;
  if not found or not(p_destination=any(k.allowed_hosts)) or (cardinality(k.allowed_methods)>0 and not(p_method=any(k.allowed_methods))) then raise exception 'Access denied'; end if;
  insert into public.vault_rate_limits(owner_id,agent_id,key_id,window_start,count)
  values(p_owner,p_agent,k.id,date_trunc('minute',now()),1)
  on conflict(agent_id,key_id) do update set
    count=case when public.vault_rate_limits.window_start=excluded.window_start then public.vault_rate_limits.count+1 else 1 end,
    window_start=excluded.window_start
  returning count into v_count;
  insert into public.vault_events(owner_id,agent_id,key_id,key_name,destination,method,action,outcome)
  values(p_owner,p_agent,k.id,k.name,p_destination,p_method,'api.call',case when v_count>k.rate_limit_per_minute then 'rate_limited' else 'started' end)
  returning id into v_event;
  if v_count>k.rate_limit_per_minute then return jsonb_build_object('denied',true); end if;
  return to_jsonb(k) || jsonb_build_object('event_id',v_event);
end $$;

create function public.vault_finish_call(p_owner uuid,p_agent uuid,p_event uuid,p_outcome text)
returns boolean language plpgsql security definer set search_path = '' as $$
declare v_allowed boolean;
begin
  if p_outcome not in ('success','upstream_error','failed') then raise exception 'Invalid outcome'; end if;
  select exists(select 1 from public.vault_events e join public.vault_agents a on a.id=e.agent_id join public.vault_permissions g on g.agent_id=a.id and g.key_id=e.key_id
    where e.id=p_event and e.owner_id=p_owner and a.id=p_agent and a.owner_id=p_owner and a.revoked_at is null and g.owner_id=p_owner and g.revoked_at is null and g.expires_at>now()) into v_allowed;
  update public.vault_events set outcome=case when v_allowed then p_outcome else 'revoked' end where id=p_event and owner_id=p_owner and agent_id=p_agent;
  if not found then raise exception 'Audit unavailable'; end if;
  return v_allowed;
end $$;
revoke all on function public.vault_set_permissions(uuid,uuid,uuid[],timestamptz),public.vault_begin_call(uuid,uuid,text,text,text),public.vault_finish_call(uuid,uuid,uuid,text) from public,anon,authenticated;
grant execute on function public.vault_set_permissions(uuid,uuid,uuid[],timestamptz),public.vault_begin_call(uuid,uuid,text,text,text),public.vault_finish_call(uuid,uuid,uuid,text) to service_role;
commit;
