-- Entrance with name + short code for everyone (Tohar and clients), no email.
-- All reads and writes go through the security-definer functions below; anon never touches tables.

create extension if not exists pgcrypto;

-- the email-based owner column stays, but is no longer required (rows are written by the functions below)
alter table public.coaching_clients alter column owner drop not null;
alter table public.coaching_clients alter column owner drop default;
alter table public.coaching_clients add column if not exists code text not null default lpad((floor(random() * 10000))::int::text, 4, '0');

create table if not exists public.coaching_admin (
  id          int primary key default 1 check (id = 1),
  name        text not null default '',
  code_hash   text,
  setup_hash  text            -- one-time setup link, cleared once Tohar picks her code
);

create table if not exists public.coaching_sessions (
  token       text primary key default encode(gen_random_bytes(24), 'hex'),
  role        text not null check (role in ('admin', 'client')),
  client_id   uuid references public.coaching_clients(id) on delete cascade,
  expires_at  timestamptz not null default now() + interval '60 days'
);

create table if not exists public.coaching_login_fails (
  name_key  text not null,
  at        timestamptz not null default now()
);
create index if not exists coaching_login_fails_idx on public.coaching_login_fails(name_key, at);

create table if not exists public.coaching_files (
  meeting_id  uuid primary key references public.coaching_meetings(id) on delete cascade,
  name        text not null,
  mime        text not null,
  data        bytea not null,
  created_at  timestamptz not null default now()
);

alter table public.coaching_admin       enable row level security;
alter table public.coaching_sessions    enable row level security;
alter table public.coaching_login_fails enable row level security;
alter table public.coaching_files       enable row level security;
revoke all on public.coaching_clients, public.coaching_meetings, public.coaching_updates,
              public.coaching_admin, public.coaching_sessions, public.coaching_login_fails, public.coaching_files
  from anon, authenticated;

-- ---------- helpers (not callable from the browser) ----------
create or replace function public.coaching_norm(t text) returns text
language sql immutable as $$ select lower(regexp_replace(btrim(coalesce(t, '')), '\s+', ' ', 'g')) $$;

create or replace function public.coaching_session_role(p_session text, out role text, out client_id uuid)
language sql stable security definer set search_path = public as $$
  select s.role, s.client_id from public.coaching_sessions s
   where s.token = p_session and s.expires_at > now();
$$;

create or replace function public.coaching_require_admin(p_session text) returns void
language plpgsql stable security definer set search_path = public as $$
begin
  if (select role from public.coaching_session_role(p_session)) is distinct from 'admin' then
    raise exception 'not allowed';
  end if;
end $$;

create or replace function public.coaching_new_code() returns text
language sql volatile as $$ select lpad((floor(random() * 10000))::int::text, 4, '0') $$;

-- ---------- entrance ----------
create or replace function public.coaching_login(p_name text, p_code text) returns jsonb
language plpgsql volatile security definer set search_path = public as $$
declare k text := public.coaching_norm(p_name); a public.coaching_admin; v_client uuid; v_token text;
begin
  -- brakes against guessing codes: per name, and overall
  if (select count(*) from public.coaching_login_fails where name_key = k and at > now() - interval '15 minutes') >= 5
     or (select count(*) from public.coaching_login_fails where at > now() - interval '15 minutes') >= 60 then
    return jsonb_build_object('error', 'locked');
  end if;

  select * into a from public.coaching_admin where id = 1;
  if a.code_hash is not null and k = public.coaching_norm(a.name) and crypt(coalesce(p_code, ''), a.code_hash) = a.code_hash then
    insert into public.coaching_sessions (role) values ('admin') returning token into v_token;
    return jsonb_build_object('role', 'admin', 'session', v_token, 'name', a.name);
  end if;

  select c.id into v_client from public.coaching_clients c
   where public.coaching_norm(c.name) = k and c.code = btrim(coalesce(p_code, '')) and k <> '' limit 1;
  if v_client is not null then
    insert into public.coaching_sessions (role, client_id) values ('client', v_client) returning token into v_token;
    return jsonb_build_object('role', 'client', 'session', v_token);
  end if;

  -- returned, not raised: an exception would roll back the recorded failure
  insert into public.coaching_login_fails (name_key) values (k);
  delete from public.coaching_login_fails where at < now() - interval '1 day';
  return jsonb_build_object('error', 'bad login');
end $$;

create or replace function public.coaching_logout(p_session text) returns void
language sql volatile security definer set search_path = public as $$
  delete from public.coaching_sessions where token = p_session;
$$;

-- one-time: Tohar picks her name and code from the setup link
create or replace function public.coaching_admin_setup(p_setup text, p_name text, p_code text) returns jsonb
language plpgsql volatile security definer set search_path = public as $$
declare a public.coaching_admin; v_token text;
begin
  select * into a from public.coaching_admin where id = 1;
  if a.setup_hash is null or crypt(coalesce(p_setup, ''), a.setup_hash) <> a.setup_hash then raise exception 'bad setup'; end if;
  if length(btrim(coalesce(p_name, ''))) < 2 or coalesce(p_code, '') !~ '^[0-9]{4,8}$' then raise exception 'bad input'; end if;
  update public.coaching_admin set name = btrim(p_name), code_hash = crypt(p_code, gen_salt('bf')), setup_hash = null where id = 1;
  insert into public.coaching_sessions (role) values ('admin') returning token into v_token;
  return jsonb_build_object('role', 'admin', 'session', v_token, 'name', btrim(p_name));
end $$;

-- ---------- client side ----------
create or replace function public.coaching_me_view(p_session text) returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare v_client uuid;
begin
  select client_id into v_client from public.coaching_session_role(p_session) where role = 'client';
  if v_client is null then raise exception 'not allowed'; end if;
  return (
    select jsonb_build_object(
      'name', c.name, 'goal', c.goal,
      'meetings', coalesce((
        select jsonb_agg(jsonb_build_object(
          'id', m.id, 'n', m.n, 'date', m.date, 'goals', m.goals, 'note', m.note,
          'file', (select jsonb_build_object('name', f.name, 'mime', f.mime) from public.coaching_files f where f.meeting_id = m.id),
          'update', (select jsonb_build_object('goals', u.goals, 'progress', u.progress, 'stuck', u.stuck, 'note', u.note, 'created_at', u.created_at)
                     from public.coaching_updates u where u.meeting_id = m.id order by u.created_at desc limit 1)
        ) order by m.n)
        from public.coaching_meetings m where m.client_id = c.id), '[]'::jsonb))
    from public.coaching_clients c where c.id = v_client);
end $$;

create or replace function public.coaching_me_submit(
  p_session text, p_meeting uuid, p_goals jsonb, p_progress text, p_stuck text, p_note text) returns uuid
language plpgsql volatile security definer set search_path = public as $$
declare v_client uuid; v_id uuid;
begin
  select client_id into v_client from public.coaching_session_role(p_session) where role = 'client';
  if v_client is null or not exists (select 1 from public.coaching_meetings where id = p_meeting and client_id = v_client) then
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

-- the summary file, for whoever may see this meeting (its client, or Tohar)
create or replace function public.coaching_file(p_session text, p_meeting uuid) returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare s record;
begin
  select * into s from public.coaching_session_role(p_session);
  if s.role is null
     or (s.role = 'client' and not exists (select 1 from public.coaching_meetings where id = p_meeting and client_id = s.client_id)) then
    raise exception 'not allowed';
  end if;
  return (select jsonb_build_object('name', f.name, 'mime', f.mime, 'data', encode(f.data, 'base64'))
            from public.coaching_files f where f.meeting_id = p_meeting);
end $$;

-- ---------- Tohar's side ----------
create or replace function public.coaching_admin_list(p_session text) returns jsonb
language plpgsql stable security definer set search_path = public as $$
begin
  perform public.coaching_require_admin(p_session);
  return coalesce((
    select jsonb_agg(jsonb_build_object(
      'id', c.id, 'name', c.name, 'business', c.business,
      'last_n', (select max(n) from public.coaching_meetings m where m.client_id = c.id),
      'last_date', (select m.date from public.coaching_meetings m where m.client_id = c.id order by n desc limit 1),
      'unseen', (select count(*) from public.coaching_updates u where u.client_id = c.id and not u.seen)
    ) order by c.created_at desc)
    from public.coaching_clients c), '[]'::jsonb);
end $$;

create or replace function public.coaching_admin_client(p_session text, p_client uuid) returns jsonb
language plpgsql stable security definer set search_path = public as $$
begin
  perform public.coaching_require_admin(p_session);
  return (select jsonb_build_object(
    'client', jsonb_build_object('id', c.id, 'name', c.name, 'business', c.business, 'goal', c.goal, 'code', c.code),
    'meetings', coalesce((select jsonb_agg(jsonb_build_object(
        'id', m.id, 'n', m.n, 'date', m.date, 'goals', m.goals, 'note', m.note,
        'file', (select jsonb_build_object('name', f.name, 'mime', f.mime) from public.coaching_files f where f.meeting_id = m.id)
      ) order by m.n) from public.coaching_meetings m where m.client_id = c.id), '[]'::jsonb),
    'updates', coalesce((select jsonb_agg(to_jsonb(u) order by u.created_at desc)
      from public.coaching_updates u where u.client_id = c.id), '[]'::jsonb))
    from public.coaching_clients c where c.id = p_client);
end $$;

create or replace function public.coaching_admin_save_client(p_session text, p_client uuid, p_name text, p_business text, p_goal text) returns jsonb
language plpgsql volatile security definer set search_path = public as $$
declare v_id uuid := p_client; v_code text;
begin
  perform public.coaching_require_admin(p_session);
  if v_id is null then
    insert into public.coaching_clients (name, business, goal, code)
    values (left(coalesce(p_name, ''), 200), left(coalesce(p_business, ''), 200), left(coalesce(p_goal, ''), 2000), public.coaching_new_code())
    returning id, code into v_id, v_code;
  else
    update public.coaching_clients set name = left(coalesce(p_name, ''), 200), business = left(coalesce(p_business, ''), 200), goal = left(coalesce(p_goal, ''), 2000)
     where id = v_id returning code into v_code;
  end if;
  return jsonb_build_object('id', v_id, 'code', v_code);
end $$;

create or replace function public.coaching_admin_new_code(p_session text, p_client uuid) returns text
language plpgsql volatile security definer set search_path = public as $$
declare v_code text := public.coaching_new_code();
begin
  perform public.coaching_require_admin(p_session);
  update public.coaching_clients set code = v_code where id = p_client;
  delete from public.coaching_sessions where client_id = p_client;   -- old code stops working everywhere
  return v_code;
end $$;

create or replace function public.coaching_admin_delete_client(p_session text, p_client uuid) returns void
language plpgsql volatile security definer set search_path = public as $$
begin
  perform public.coaching_require_admin(p_session);
  delete from public.coaching_clients where id = p_client;
end $$;

create or replace function public.coaching_admin_add_meeting(p_session text, p_client uuid) returns uuid
language plpgsql volatile security definer set search_path = public as $$
declare prev public.coaching_meetings; v_id uuid;
begin
  perform public.coaching_require_admin(p_session);
  select * into prev from public.coaching_meetings where client_id = p_client order by n desc limit 1;
  insert into public.coaching_meetings (client_id, n, goals)
  values (p_client, coalesce(prev.n, 0) + 1, coalesce(prev.goals, '[]'::jsonb))   -- goals carry over
  returning id into v_id;
  return v_id;
end $$;

create or replace function public.coaching_admin_save_meeting(p_session text, p_meeting uuid, p_date date, p_goals jsonb, p_note text) returns void
language plpgsql volatile security definer set search_path = public as $$
begin
  perform public.coaching_require_admin(p_session);
  if jsonb_typeof(p_goals) <> 'array' or jsonb_array_length(p_goals) > 30 then raise exception 'bad goals'; end if;
  update public.coaching_meetings set date = coalesce(p_date, date), goals = p_goals, note = left(coalesce(p_note, ''), 5000)
   where id = p_meeting;
end $$;

create or replace function public.coaching_admin_delete_meeting(p_session text, p_meeting uuid) returns void
language plpgsql volatile security definer set search_path = public as $$
begin
  perform public.coaching_require_admin(p_session);
  delete from public.coaching_meetings where id = p_meeting;
end $$;

create or replace function public.coaching_admin_set_file(p_session text, p_meeting uuid, p_name text, p_mime text, p_data text) returns void
language plpgsql volatile security definer set search_path = public as $$
declare v bytea;
begin
  perform public.coaching_require_admin(p_session);
  if p_mime !~ '^(application/pdf|image/(png|jpeg|webp))$' then raise exception 'bad type'; end if;
  v := decode(p_data, 'base64');
  if octet_length(v) > 10 * 1024 * 1024 then raise exception 'too big'; end if;
  insert into public.coaching_files (meeting_id, name, mime, data) values (p_meeting, left(p_name, 200), p_mime, v)
  on conflict (meeting_id) do update set name = excluded.name, mime = excluded.mime, data = excluded.data, created_at = now();
end $$;

create or replace function public.coaching_admin_mark_seen(p_session text, p_meeting uuid) returns void
language plpgsql volatile security definer set search_path = public as $$
begin
  perform public.coaching_require_admin(p_session);
  update public.coaching_updates set seen = true where meeting_id = p_meeting and not seen;
end $$;

-- the old token-link functions from 001 stay in place but nobody may call them anymore
revoke execute on function
  public.coaching_client_view(text),
  public.coaching_client_submit(text, uuid, jsonb, text, text, text)
from public, anon, authenticated;

-- helpers are internal only; the entry points below are what the browser may call
revoke execute on function
  public.coaching_norm(text),
  public.coaching_session_role(text),
  public.coaching_require_admin(text),
  public.coaching_new_code()
from public, anon, authenticated;
grant execute on function
  public.coaching_login(text, text),
  public.coaching_logout(text),
  public.coaching_admin_setup(text, text, text),
  public.coaching_me_view(text),
  public.coaching_me_submit(text, uuid, jsonb, text, text, text),
  public.coaching_file(text, uuid),
  public.coaching_admin_list(text),
  public.coaching_admin_client(text, uuid),
  public.coaching_admin_save_client(text, uuid, text, text, text),
  public.coaching_admin_new_code(text, uuid),
  public.coaching_admin_delete_client(text, uuid),
  public.coaching_admin_add_meeting(text, uuid),
  public.coaching_admin_save_meeting(text, uuid, date, jsonb, text),
  public.coaching_admin_delete_meeting(text, uuid),
  public.coaching_admin_set_file(text, uuid, text, text, text),
  public.coaching_admin_mark_seen(text, uuid)
to anon;

insert into public.coaching_admin (id) values (1) on conflict (id) do nothing;

-- crypt()/gen_salt() live in the extensions schema on Supabase
alter function public.coaching_login(text, text) set search_path = public, extensions;
alter function public.coaching_admin_setup(text, text, text) set search_path = public, extensions;
