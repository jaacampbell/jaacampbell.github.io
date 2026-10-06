-- JO₵YN Creator OS — initial Supabase schema
-- Apply only after connecting a dedicated Supabase project.

create extension if not exists pgcrypto;

create table if not exists public.workspaces (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  name text not null,
  slug text not null unique,
  type text not null default 'creator',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.brand_profiles (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null unique references public.workspaces(id) on delete cascade,
  display_name text not null,
  handle text,
  bio text,
  voice jsonb not null default '{}'::jsonb,
  social_links jsonb not null default '[]'::jsonb,
  updated_at timestamptz not null default now()
);

create table if not exists public.projects (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces(id) on delete cascade,
  type text not null check (type in ('single','album','event','campaign_project','other')),
  title text not null,
  status text not null default 'planning',
  release_date date,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.campaigns (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces(id) on delete cascade,
  project_id uuid references public.projects(id) on delete set null,
  title text not null,
  objective text,
  status text not null default 'planning',
  starts_at timestamptz,
  ends_at timestamptz,
  progress integer not null default 0 check (progress between 0 and 100),
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.content_items (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces(id) on delete cascade,
  project_id uuid references public.projects(id) on delete set null,
  campaign_id uuid references public.campaigns(id) on delete set null,
  parent_content_id uuid references public.content_items(id) on delete set null,
  title text not null,
  state text not null default 'idea',
  format text,
  platforms text[] not null default '{}',
  body jsonb not null default '{}'::jsonb,
  scheduled_for timestamptz,
  published_at timestamptz,
  performance jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.tasks (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces(id) on delete cascade,
  project_id uuid references public.projects(id) on delete cascade,
  campaign_id uuid references public.campaigns(id) on delete cascade,
  content_id uuid references public.content_items(id) on delete cascade,
  title text not null,
  status text not null default 'open',
  due_at timestamptz,
  priority text not null default 'normal',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.media_assets (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces(id) on delete cascade,
  project_id uuid references public.projects(id) on delete set null,
  campaign_id uuid references public.campaigns(id) on delete set null,
  storage_path text not null,
  file_name text not null,
  mime_type text,
  kind text,
  width integer,
  height integer,
  duration_seconds numeric,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists public.link_hubs (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null unique references public.workspaces(id) on delete cascade,
  slug text not null unique,
  status text not null default 'draft' check (status in ('draft','published')),
  theme jsonb not null default '{}'::jsonb,
  published_at timestamptz,
  updated_at timestamptz not null default now()
);

create table if not exists public.link_blocks (
  id uuid primary key default gen_random_uuid(),
  link_hub_id uuid not null references public.link_hubs(id) on delete cascade,
  type text not null,
  position integer not null default 0,
  visible boolean not null default true,
  starts_at timestamptz,
  ends_at timestamptz,
  content jsonb not null default '{}'::jsonb,
  analytics_enabled boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.ai_threads (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces(id) on delete cascade,
  context_type text,
  context_id uuid,
  title text,
  messages jsonb not null default '[]'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.workspaces enable row level security;
alter table public.brand_profiles enable row level security;
alter table public.projects enable row level security;
alter table public.campaigns enable row level security;
alter table public.content_items enable row level security;
alter table public.tasks enable row level security;
alter table public.media_assets enable row level security;
alter table public.link_hubs enable row level security;
alter table public.link_blocks enable row level security;
alter table public.ai_threads enable row level security;

create or replace function public.owns_workspace(target_workspace uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.workspaces w
    where w.id = target_workspace and w.owner_id = auth.uid()
  );
$$;

create policy "owners_manage_workspaces" on public.workspaces
for all using (owner_id = auth.uid()) with check (owner_id = auth.uid());

create policy "owners_manage_brand_profiles" on public.brand_profiles
for all using (public.owns_workspace(workspace_id)) with check (public.owns_workspace(workspace_id));

create policy "owners_manage_projects" on public.projects
for all using (public.owns_workspace(workspace_id)) with check (public.owns_workspace(workspace_id));

create policy "owners_manage_campaigns" on public.campaigns
for all using (public.owns_workspace(workspace_id)) with check (public.owns_workspace(workspace_id));

create policy "owners_manage_content" on public.content_items
for all using (public.owns_workspace(workspace_id)) with check (public.owns_workspace(workspace_id));

create policy "owners_manage_tasks" on public.tasks
for all using (public.owns_workspace(workspace_id)) with check (public.owns_workspace(workspace_id));

create policy "owners_manage_media" on public.media_assets
for all using (public.owns_workspace(workspace_id)) with check (public.owns_workspace(workspace_id));

create policy "owners_manage_link_hubs" on public.link_hubs
for all using (public.owns_workspace(workspace_id)) with check (public.owns_workspace(workspace_id));

create policy "public_read_published_link_hubs" on public.link_hubs
for select using (status = 'published');

create policy "owners_manage_link_blocks" on public.link_blocks
for all using (
  exists (
    select 1 from public.link_hubs h
    where h.id = link_hub_id and public.owns_workspace(h.workspace_id)
  )
) with check (
  exists (
    select 1 from public.link_hubs h
    where h.id = link_hub_id and public.owns_workspace(h.workspace_id)
  )
);

create policy "public_read_visible_blocks" on public.link_blocks
for select using (
  visible = true and
  (starts_at is null or starts_at <= now()) and
  (ends_at is null or ends_at >= now()) and
  exists (select 1 from public.link_hubs h where h.id = link_hub_id and h.status = 'published')
);

create policy "owners_manage_ai_threads" on public.ai_threads
for all using (public.owns_workspace(workspace_id)) with check (public.owns_workspace(workspace_id));

-- Storage bucket recommendation:
-- bucket: creator-media
-- authenticated owner uploads only
-- public delivery should use signed URLs or a separate public derivatives strategy.
