-- Empty allowed_methods must never mean "all methods". Require at least one.
begin;
update public.vault_keys
  set allowed_methods = array['GET']
  where cardinality(allowed_methods) = 0;
alter table public.vault_keys
  alter column allowed_methods set default array['GET'];
alter table public.vault_keys
  add constraint vault_keys_allowed_methods_required
  check (cardinality(allowed_methods) >= 1 and cardinality(allowed_methods) <= 7);

create or replace function public.vault_begin_call(p_owner uuid,p_agent uuid,p_key_name text,p_destination text,p_method text)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare k public.vault_keys; v_count integer; v_event uuid;
begin
  -- Serialize admission with disconnect and grant changes for this agent.
  perform 1 from public.vault_agents where id=p_agent and owner_id=p_owner and revoked_at is null for update;
  if not found then raise exception 'Access denied'; end if;
  select * into k from public.vault_keys where owner_id=p_owner and name=p_key_name for share;
  if not found then raise exception 'Access denied'; end if;
  perform 1 from public.vault_permissions where owner_id=p_owner and agent_id=p_agent and key_id=k.id and revoked_at is null and expires_at>now() for share;
  if not found or not(p_destination=any(k.allowed_hosts)) or cardinality(k.allowed_methods) < 1 or not(p_method=any(k.allowed_methods)) then raise exception 'Access denied'; end if;
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
revoke all on function public.vault_begin_call(uuid,uuid,text,text,text) from public,anon,authenticated;
grant execute on function public.vault_begin_call(uuid,uuid,text,text,text) to service_role;
commit;
