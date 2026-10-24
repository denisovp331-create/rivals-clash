-- RIVALS CLASH shared tournament database
-- Run in Supabase SQL Editor once, after creating a Supabase project.
create extension if not exists pgcrypto;

create table if not exists public.teams (
  id uuid primary key default gen_random_uuid(),
  name text not null unique,
  logo text not null default '✦',
  captain text not null default '',
  description text not null default '',
  eliminated boolean not null default false,
  created_at timestamptz not null default now()
);

create table if not exists public.matches (
  id uuid primary key default gen_random_uuid(),
  team_a uuid not null references public.teams(id) on delete restrict,
  team_b uuid not null references public.teams(id) on delete restrict,
  score_a integer not null,
  score_b integer not null,
  played_at timestamptz not null default now(),
  constraint different_teams check (team_a <> team_b),
  constraint valid_rivals_score check (
    (score_a = 5 and score_b between 0 and 4) or
    (score_b = 5 and score_a between 0 and 4)
  )
);

create index if not exists matches_played_at_idx on public.matches (played_at desc);
create index if not exists matches_team_a_idx on public.matches (team_a);
create index if not exists matches_team_b_idx on public.matches (team_b);

-- Standings are derived from match records, so points cannot drift out of sync.
create or replace view public.standings
with (security_invoker = true) as
select
  t.id,
  t.name,
  t.logo,
  t.captain,
  t.description,
  t.eliminated,
  count(m.id) filter (
    where (m.team_a = t.id and m.score_a = 5) or
          (m.team_b = t.id and m.score_b = 5)
  )::integer as wins,
  count(m.id) filter (
    where (m.team_a = t.id and m.score_a < 5) or
          (m.team_b = t.id and m.score_b < 5)
  )::integer as losses,
  (count(m.id) filter (
    where (m.team_a = t.id and m.score_a = 5) or
          (m.team_b = t.id and m.score_b = 5)
  ) * 10)::integer as points
from public.teams t
left join public.matches m on m.team_a = t.id or m.team_b = t.id
group by t.id, t.name, t.logo, t.captain, t.description, t.eliminated;

alter table public.teams enable row level security;
alter table public.matches enable row level security;

drop policy if exists "Public can view teams" on public.teams;
create policy "Public can view teams"
  on public.teams for select using (true);

drop policy if exists "Admins manage teams" on public.teams;
create policy "Admins manage teams"
  on public.teams for all to authenticated
  using ((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin')
  with check ((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');

drop policy if exists "Public can view matches" on public.matches;
create policy "Public can view matches"
  on public.matches for select using (true);

drop policy if exists "Admins manage matches" on public.matches;
create policy "Admins manage matches"
  on public.matches for all to authenticated
  using ((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin')
  with check ((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');

grant select on public.teams, public.matches, public.standings to anon, authenticated;
grant insert, update, delete on public.teams, public.matches to authenticated;
