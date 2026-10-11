begin;
create table public.vault_feedback (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  category text not null check (category in ('Bug', 'Idea', 'Other')),
  message text not null check (char_length(btrim(message)) between 1 and 4000),
  created_at timestamptz not null default now()
);
create index vault_feedback_owner_created on public.vault_feedback(owner_id, created_at desc);
alter table public.vault_feedback enable row level security;
revoke all on public.vault_feedback from public, anon, authenticated;
grant select, insert, delete on public.vault_feedback to service_role;

create function public.vault_submit_feedback(p_owner uuid, p_category text, p_message text)
returns boolean language plpgsql security definer set search_path = '' as $$
begin
  -- Serialize submissions for this owner, so parallel requests cannot bypass the limit.
  perform pg_advisory_xact_lock(hashtextextended('feedback:' || p_owner::text, 0));
  if (select count(*) from public.vault_feedback where owner_id = p_owner and created_at > now() - interval '1 hour') >= 3 then
    return false;
  end if;
  insert into public.vault_feedback(owner_id, category, message) values (p_owner, p_category, btrim(p_message));
  return true;
end;
$$;
revoke all on function public.vault_submit_feedback(uuid, text, text) from public, anon, authenticated;
grant execute on function public.vault_submit_feedback(uuid, text, text) to service_role;
comment on table public.vault_feedback is 'Beta feedback shared with the team; not an encrypted secret store. Deleted with the submitting account.';
commit;
