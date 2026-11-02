-- Run this in Supabase SQL Editor for the Pepe Rescue Challenge leaderboard.
-- Anonymous sign-ins must also be enabled in Authentication > Providers.

create table if not exists public.rescue_scores (
  user_id uuid primary key references auth.users(id) on delete cascade,
  nickname text not null check (char_length(btrim(nickname)) between 2 and 20),
  best_time_ms integer not null check (best_time_ms between 1 and 3600000),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint nickname_no_control_chars check (nickname !~ '[[:cntrl:]]')
);

alter table public.rescue_scores enable row level security;
revoke all on table public.rescue_scores from anon, authenticated;
grant select (nickname, best_time_ms, updated_at) on public.rescue_scores to anon, authenticated;

drop policy if exists "Anyone can read rescue scores" on public.rescue_scores;
create policy "Anyone can read rescue scores"
  on public.rescue_scores for select
  to anon, authenticated
  using (true);

create or replace function public.submit_rescue_score(p_nickname text, p_time_ms integer)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  current_user_id uuid := auth.uid();
  is_anonymous boolean := coalesce((auth.jwt() ->> 'is_anonymous')::boolean, false);
  clean_nickname text := btrim(p_nickname);
begin
  if current_user_id is null or not is_anonymous then
    raise exception 'Anonymous sign-in required';
  end if;
  if clean_nickname is null or char_length(clean_nickname) not between 2 and 20 or clean_nickname ~ '[[:cntrl:]]' then
    raise exception 'Nickname must be 2–20 characters and contain no control characters';
  end if;
  if p_time_ms is null or p_time_ms not between 1 and 3600000 then
    raise exception 'Time is outside the allowed range';
  end if;

  insert into public.rescue_scores (user_id, nickname, best_time_ms)
  values (current_user_id, clean_nickname, p_time_ms)
  on conflict (user_id) do update
    set nickname = excluded.nickname,
        best_time_ms = least(public.rescue_scores.best_time_ms, excluded.best_time_ms),
        updated_at = now();
end;
$$;

revoke all on function public.submit_rescue_score(text, integer) from public, anon;
grant execute on function public.submit_rescue_score(text, integer) to authenticated;

