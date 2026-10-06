# Backend connection plan

The browser prototype currently runs on GitHub Pages and now includes a shared local data adapter.

## What already works without a backend

- Private OS state persists in localStorage.
- Link Hub Manager can publish configuration to the public hub on the same origin/browser.
- Public-hub interactions write local analytics events.
- The private Analytics view can read those events.

This is intentionally an MVP bridge, not the final database.

## Supabase production path

A migration is prepared at:

supabase/0001_creator_os.sql

It defines:

- workspaces
- brand_profiles
- projects
- campaigns
- content_items
- tasks
- media_assets
- link_hubs
- link_blocks
- ai_threads
- row-level security

The current Supabase connector was not authorized when this build was attempted, so the migration has NOT been applied to a live project.

When Supabase access is restored:

1. Use a dedicated project for the Creator OS.
2. Apply the migration.
3. Add a creator-media storage bucket.
4. Configure authentication for the private OS.
5. Replace localStorage methods in data-layer.js with Supabase CRUD while keeping the same interface.
6. Keep public-hub reads limited to published Link Hub rows.
7. Track public analytics through a server-side/edge endpoint rather than allowing unrestricted anonymous database inserts.

Do not place service-role credentials in browser JavaScript.
