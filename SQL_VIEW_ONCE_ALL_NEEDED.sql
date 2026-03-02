-- SQL Playbook - View-Once Mode (All Needed)
-- Run sections as needed.

-- =========================================================
-- 1) CORE MIGRATION (REQUIRED)
-- =========================================================

ALTER TABLE public.files
ADD COLUMN IF NOT EXISTS mode VARCHAR(20) DEFAULT 'download';

ALTER TABLE public.files
ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP WITH TIME ZONE;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'files_mode_check'
  ) THEN
    ALTER TABLE public.files
    ADD CONSTRAINT files_mode_check
    CHECK (mode IN ('download', 'view-once'));
  END IF;
END$$;

-- =========================================================
-- 2) PERFORMANCE INDEXES (RECOMMENDED)
-- =========================================================

CREATE INDEX IF NOT EXISTS idx_files_expires_at
ON public.files (expires_at)
WHERE expires_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_files_mode_expires_at
ON public.files (mode, expires_at)
WHERE expires_at IS NOT NULL;

-- =========================================================
-- 3) OPTIONAL OBSERVABILITY COLUMNS
-- =========================================================

ALTER TABLE public.files
ADD COLUMN IF NOT EXISTS viewed_at TIMESTAMP WITH TIME ZONE;

ALTER TABLE public.files
ADD COLUMN IF NOT EXISTS burned_at TIMESTAMP WITH TIME ZONE;

-- =========================================================
-- 4) VALIDATION QUERIES (RUN AFTER MIGRATION)
-- =========================================================

SELECT column_name, data_type, column_default
FROM information_schema.columns
WHERE table_schema = 'public'
  AND table_name = 'files'
  AND column_name IN ('mode', 'expires_at', 'viewed_at', 'burned_at')
ORDER BY column_name;

SELECT conname, pg_get_constraintdef(oid)
FROM pg_constraint
WHERE conname = 'files_mode_check';

SELECT indexname, indexdef
FROM pg_indexes
WHERE schemaname = 'public'
  AND tablename = 'files'
  AND indexname IN ('idx_files_expires_at', 'idx_files_mode_expires_at');

-- =========================================================
-- 5) BACKFILL EXISTING ROWS (OPTIONAL)
-- =========================================================

UPDATE public.files
SET mode = 'download'
WHERE mode IS NULL;

-- =========================================================
-- 6) CLEANUP QUERIES
-- =========================================================

SELECT id, path, mode, expires_at
FROM public.files
WHERE expires_at IS NOT NULL
  AND expires_at <= NOW();

DELETE FROM public.files
WHERE expires_at IS NOT NULL
  AND expires_at <= NOW();

CREATE OR REPLACE FUNCTION public.cleanup_expired_view_once_files()
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
  deleted_count INTEGER;
BEGIN
  DELETE FROM public.files
  WHERE mode = 'view-once'
    AND expires_at IS NOT NULL
    AND expires_at <= NOW();

  GET DIAGNOSTICS deleted_count = ROW_COUNT;
  RETURN deleted_count;
END;
$$;

SELECT public.cleanup_expired_view_once_files();

-- =========================================================
-- 7) SCHEDULER SETUP (OPTIONAL, pg_cron)
-- =========================================================

CREATE EXTENSION IF NOT EXISTS pg_cron;

SELECT cron.schedule(
  'cleanup-expired-view-once-files',
  '*/5 * * * *',
  $$SELECT public.cleanup_expired_view_once_files();$$
);

SELECT jobid, jobname, schedule, command
FROM cron.job
ORDER BY jobid;

-- Safe unschedule
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'cleanup-expired-view-once-files') THEN
    PERFORM cron.unschedule('cleanup-expired-view-once-files');
  END IF;
END$$;

-- =========================================================
-- 8) REPORTING QUERIES
-- =========================================================

SELECT mode, COUNT(*) AS total
FROM public.files
GROUP BY mode
ORDER BY mode;

SELECT COUNT(*) AS active_view_once
FROM public.files
WHERE mode = 'view-once'
  AND expires_at IS NOT NULL
  AND expires_at > NOW();

SELECT COUNT(*) AS expired_pending_cleanup
FROM public.files
WHERE mode = 'view-once'
  AND expires_at IS NOT NULL
  AND expires_at <= NOW();

-- =========================================================
-- 9) ROLLBACK SQL (DESTRUCTIVE)
-- =========================================================

-- Safe unschedule
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'cleanup-expired-view-once-files') THEN
    PERFORM cron.unschedule('cleanup-expired-view-once-files');
  END IF;
END$$;

DROP FUNCTION IF EXISTS public.cleanup_expired_view_once_files();

DROP INDEX IF EXISTS public.idx_files_mode_expires_at;
DROP INDEX IF EXISTS public.idx_files_expires_at;

ALTER TABLE public.files
DROP CONSTRAINT IF EXISTS files_mode_check;

ALTER TABLE public.files DROP COLUMN IF EXISTS burned_at;
ALTER TABLE public.files DROP COLUMN IF EXISTS viewed_at;
ALTER TABLE public.files DROP COLUMN IF EXISTS expires_at;
ALTER TABLE public.files DROP COLUMN IF EXISTS mode;
