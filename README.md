# File Sharing Server

Simple Node.js + Express file sharing server with:
- Optional password-based encrypted file storage
- One-time download links (burn after first successful download)
- Supabase (Postgres)-backed file metadata

## Setup
1. Install dependencies:
   ```bash
   npm install
   ```
2. In Supabase SQL Editor, run the script in:
   `SUPABASE_SQL_EDITOR.md`
3. Configure `.env` (copy from `.env.example`):
   ```env
   SUPABASE_URL=https://YOUR_PROJECT_REF.supabase.co
   SUPABASE_SERVICE_ROLE_KEY=YOUR_SUPABASE_SERVICE_ROLE_KEY
   SUPABASE_FILES_TABLE=files
   PORT=3000
   PORT_RETRIES=10
   ```
4. Replace placeholders with real Supabase values.
5. Start:
   ```bash
   npm run dev
   ```
