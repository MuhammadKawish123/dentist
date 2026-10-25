-- =====================================================================
--  Dr. Ella Golrang website - Supabase setup (appointments + single admin)
--  Supabase Dashboard -> SQL Editor -> New query -> paste ALL -> Run
--
--  After running this, create your admin account IMMEDIATELY from the
--  website footer -> Admin Login / Sign Up. The first account created
--  becomes the one and only admin; every later signup is blocked.
-- =====================================================================

-- 1) APPOINTMENTS TABLE --------------------------------------------------
create table if not exists public.appointments (
  id              bigint generated always as identity primary key,
  created_at      timestamptz not null default now(),
  full_name       text not null,
  email           text not null,
  phone           text not null,
  service         text not null,
  preferred_date  date not null,
  preferred_time  time not null,
  best_time_to_reach text,                         -- Morning / Afternoon / Evening
  message         text,
  status          text not null default 'new'     -- new / confirmed / completed / cancelled
);
-- If the table already existed before, this adds the new column safely (run it once):
alter table public.appointments add column if not exists best_time_to_reach text;

alter table public.appointments enable row level security;

-- 2) ADMINS TABLE + HELPERS ---------------------------------------------
create table if not exists public.admins (
  user_id     uuid primary key references auth.users(id) on delete cascade,
  email       text,
  created_at  timestamptz not null default now()
);
alter table public.admins enable row level security;

create or replace function public.is_admin()
returns boolean language sql security definer stable set search_path = ''
as $$ select exists (select 1 from public.admins where user_id = auth.uid()); $$;

-- lets the login page know whether the one-time signup should still be offered
create or replace function public.admin_exists()
returns boolean language sql security definer stable set search_path = ''
as $$ select exists (select 1 from auth.users); $$;
grant execute on function public.admin_exists() to anon, authenticated;

-- 3) ONE ADMIN ONLY (blocks every signup after the first) ---------------
create or replace function public.enforce_single_admin()
returns trigger language plpgsql security definer set search_path = ''
as $$
begin
  if exists (select 1 from auth.users) then
    raise exception 'ADMIN_ALREADY_EXISTS';
  end if;
  return new;
end;
$$;

drop trigger if exists only_one_admin on auth.users;
create trigger only_one_admin
  before insert on auth.users
  for each row execute function public.enforce_single_admin();

create or replace function public.register_admin()
returns trigger language plpgsql security definer set search_path = ''
as $$
begin
  insert into public.admins (user_id, email) values (new.id, new.email);
  return new;
end;
$$;

drop trigger if exists register_first_admin on auth.users;
create trigger register_first_admin
  after insert on auth.users
  for each row execute function public.register_admin();

-- 4) ACCESS RULES (Row Level Security) ----------------------------------
-- Website visitors: can ONLY add a new appointment. Cannot read/change/delete anything.
drop policy if exists "Public can create appointments" on public.appointments;
create policy "Public can create appointments"
  on public.appointments for insert to anon, authenticated
  with check (true);

-- Only the admin can read, update status, or delete appointments.
drop policy if exists "Admin can read appointments"   on public.appointments;
drop policy if exists "Admin can update appointments" on public.appointments;
drop policy if exists "Admin can delete appointments" on public.appointments;
create policy "Admin can read appointments"
  on public.appointments for select to authenticated using (public.is_admin());
create policy "Admin can update appointments"
  on public.appointments for update to authenticated using (public.is_admin()) with check (public.is_admin());
create policy "Admin can delete appointments"
  on public.appointments for delete to authenticated using (public.is_admin());

drop policy if exists "Admin can see own admin row" on public.admins;
create policy "Admin can see own admin row"
  on public.admins for select to authenticated using (user_id = auth.uid());
