-- "How she sees it": Tohar opens a client's page as a short, read-only preview.

alter table public.coaching_sessions add column if not exists preview boolean not null default false;

create or replace function public.coaching_admin_preview(p_session text, p_client uuid) returns text
language plpgsql volatile security definer set search_path = public, extensions as $$
declare v_token text;
begin
  perform public.coaching_require_admin(p_session);
  insert into public.coaching_sessions (role, client_id, preview, expires_at)
  values ('client', p_client, true, now() + interval '1 hour')
  returning token into v_token;
  return v_token;
end $$;

-- a preview may look, never send
create or replace function public.coaching_me_submit(
  p_session text, p_meeting uuid, p_goals jsonb, p_progress text, p_stuck text, p_note text) returns uuid
language plpgsql volatile security definer set search_path = public as $$
declare v_client uuid; v_id uuid;
begin
  select client_id into v_client from public.coaching_session_role(p_session) where role = 'client';
  if v_client is null or not exists (select 1 from public.coaching_meetings where id = p_meeting and client_id = v_client)
     or exists (select 1 from public.coaching_sessions where token = p_session and preview) then
    raise exception 'not allowed';
  end if;
  if jsonb_typeof(p_goals) <> 'array' or jsonb_array_length(p_goals) > 30 then raise exception 'bad goals'; end if;
  if (select count(*) from public.coaching_updates where client_id = v_client and created_at > now() - interval '1 minute') >= 5 then
    raise exception 'too many';
  end if;
  insert into public.coaching_updates (meeting_id, client_id, goals, progress, stuck, note)
  values (p_meeting, v_client, p_goals, left(coalesce(p_progress, ''), 5000), left(coalesce(p_stuck, ''), 5000), left(coalesce(p_note, ''), 5000))
  returning id into v_id;
  return v_id;
end $$;

revoke execute on function public.coaching_admin_preview(text, uuid) from public, authenticated;
grant execute on function public.coaching_admin_preview(text, uuid) to anon;
