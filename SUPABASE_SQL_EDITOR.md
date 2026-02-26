# Supabase SQL Editor Setup

Use this script in the Supabase SQL Editor to create the table needed by this app.

```sql
create extension if not exists pgcrypto;

create table if not exists public.files (
  id uuid primary key default gen_random_uuid(),
  path text not null,
  original_name text not null,
  password text,
  created_at timestamptz not null default now()
);

create index if not exists files_created_at_idx
  on public.files (created_at desc);
```

After running it, keep `SUPABASE_FILES_TABLE=files` (or leave it unset) in `.env`.
