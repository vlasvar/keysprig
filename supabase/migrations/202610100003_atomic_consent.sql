begin;
create function public.vault_approve_client(p_owner uuid,p_client text,p_label text,p_keys uuid[],p_expires timestamptz)
returns uuid language plpgsql security definer set search_path = '' as $$
declare v_agent uuid;
begin
  insert into public.vault_agents(owner_id,oauth_client_id,label,revoked_at)
  values(p_owner,p_client,left(p_label,100),null)
  on conflict(owner_id,oauth_client_id) do update set label=excluded.label,revoked_at=null
  returning id into v_agent;
  perform public.vault_set_permissions(p_owner,v_agent,p_keys,p_expires);
  return v_agent;
end $$;
revoke all on function public.vault_approve_client(uuid,text,text,uuid[],timestamptz) from public,anon,authenticated;
grant execute on function public.vault_approve_client(uuid,text,text,uuid[],timestamptz) to service_role;
commit;
