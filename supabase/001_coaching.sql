-- Coaching follow-up: Tohar manages clients and meetings (signed in),
-- each client reaches only her own file through a secret link token.

create extension if not exists pgcrypto;

create table if not exists public.coaching_clients (
  id          uuid primary key default gen_random_uuid(),
  owner       uuid not null default auth.uid() references auth.users(id) on delete cascade,
  name        text not null default '',
  business    text not null default '',
  goal        text not null default '',
  token       text not null unique default encode(gen_random_bytes(16), 'hex'),
  created_at  timestamptz not null default now()
);

create table if not exists public.coaching_meetings (
  id            uuid primary key default gen_random_uuid(),
  client_id     uuid not null references public.coaching_clients(id) on delete cascade,
  n             int  not null,
  date          date not null default current_date,
  summary_path  text,
  summary_name  text,
  goals         jsonb not null default '[]'::jsonb,   -- [{ "text": "..." }], set by Tohar
  note          text  not null default '',             -- a message from Tohar to the client
  created_at    timestamptz not null default now()
);

create table if not exists public.coaching_updates (
  id          uuid primary key default gen_random_uuid(),
  meeting_id  uuid not null references public.coaching_meetings(id) on delete cascade,
  client_id   uuid not null references public.coaching_clients(id) on delete cascade,
  goals       jsonb not null default '[]'::jsonb,     -- [{ "text": "...", "state": "todo|doing|done" }]
  progress    text not null default '',
  stuck       text not null default '',
  note        text not null default '',
  seen        boolean not null default false,
  created_at  timestamptz not null default now()
);

create index if not exists coaching_meetings_client_idx on public.coaching_meetings(client_id);
create index if not exists coaching_updates_meeting_idx on public.coaching_updates(meeting_id, created_at desc);

alter table public.coaching_clients  enable row level security;
alter table public.coaching_meetings enable row level security;
alter table public.coaching_updates  enable row level security;

-- Tohar (the signed-in owner) sees and edits only her own rows. anon has no policy, so no direct access.
drop policy if exists coaching_clients_owner on public.coaching_clients;
create policy coaching_clients_owner on public.coaching_clients
  for all to authenticated using (owner = auth.uid()) with check (owner = auth.uid());

drop policy if exists coaching_meetings_owner on public.coaching_meetings;
create policy coaching_meetings_owner on public.coaching_meetings
  for all to authenticated
  using (exists (select 1 from public.coaching_clients c where c.id = client_id and c.owner = auth.uid()))
  with check (exists (select 1 from public.coaching_clients c where c.id = client_id and c.owner = auth.uid()));

drop policy if exists coaching_updates_owner on public.coaching_updates;
create policy coaching_updates_owner on public.coaching_updates
  for all to authenticated
  using (exists (select 1 from public.coaching_clients c where c.id = client_id and c.owner = auth.uid()))
  with check (exists (select 1 from public.coaching_clients c where c.id = client_id and c.owner = auth.uid()));

revoke all on public.coaching_clients, public.coaching_meetings, public.coaching_updates from anon;

-- Client side: read her own file by token
create or replace function public.coaching_client_view(p_token text)
returns jsonb language sql stable security definer set search_path = public as $$
  select jsonb_build_object(
    'name', c.name,
    'goal', c.goal,
    'meetings', coalesce((
      select jsonb_agg(jsonb_build_object(
        'id', m.id, 'n', m.n, 'date', m.date,
        'summary_path', m.summary_path, 'summary_name', m.summary_name,
        'goals', m.goals, 'note', m.note,
        'update', (select jsonb_build_object('goals', u.goals, 'progress', u.progress, 'stuck', u.stuck, 'note', u.note, 'created_at', u.created_at)
                   from public.coaching_updates u where u.meeting_id = m.id order by u.created_at desc limit 1)
      ) order by m.n)
      from public.coaching_meetings m where m.client_id = c.id), '[]'::jsonb)
  )
  from public.coaching_clients c
  where length(p_token) = 32 and c.token = p_token;
$$;

-- Client side: send an update for one meeting
create or replace function public.coaching_client_submit(
  p_token text, p_meeting uuid, p_goals jsonb, p_progress text, p_stuck text, p_note text)
returns uuid language plpgsql security definer set search_path = public as $$
declare v_client uuid; v_id uuid;
begin
  select c.id into v_client
    from public.coaching_clients c join public.coaching_meetings m on m.client_id = c.id
   where length(p_token) = 32 and c.token = p_token and m.id = p_meeting;
  if v_client is null then raise exception 'not found'; end if;
  if jsonb_typeof(p_goals) <> 'array' or jsonb_array_length(p_goals) > 30 then raise exception 'bad goals'; end if;
  -- a light brake against repeated submits
  if (select count(*) from public.coaching_updates where client_id = v_client and created_at > now() - interval '1 minute') >= 5 then
    raise exception 'too many';
  end if;
  insert into public.coaching_updates (meeting_id, client_id, goals, progress, stuck, note)
  values (p_meeting, v_client, p_goals, left(coalesce(p_progress, ''), 5000), left(coalesce(p_stuck, ''), 5000), left(coalesce(p_note, ''), 5000))
  returning id into v_id;
  return v_id;
end $$;

revoke all on function public.coaching_client_view(text) from public;
revoke all on function public.coaching_client_submit(text, uuid, jsonb, text, text, text) from public;
grant execute on function public.coaching_client_view(text) to anon, authenticated;
grant execute on function public.coaching_client_submit(text, uuid, jsonb, text, text, text) to anon, authenticated;

-- Meeting summary PDFs: public bucket with unguessable paths (random folder per file).
-- Only signed-in Tohar can upload or delete; anon cannot list the bucket.
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('coaching-summaries', 'coaching-summaries', true, 20971520,
        array['application/pdf', 'image/png', 'image/jpeg', 'image/webp'])
on conflict (id) do nothing;

drop policy if exists coaching_summaries_owner on storage.objects;
create policy coaching_summaries_owner on storage.objects
  for all to authenticated
  using (bucket_id = 'coaching-summaries' and owner = auth.uid())
  with check (bucket_id = 'coaching-summaries');
