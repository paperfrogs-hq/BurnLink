-- ── BurnLink CLI backend table + atomic burn RPC ────────────────────────────
-- The CLI uploads zero-knowledge ciphertexts via /api/cli/upload and downloads
-- them via /api/cli/object/:id. We store:
--   • the ciphertext blob in R2 under `cli/<id>`
--   • a row in `cli_files` keyed by a 12-char base64url id (NOT a UUID)
--   • expiry + burn-after-read flags
-- Burn uses the same atomic-RPC pattern as the existing `burn_file()` to
-- eliminate TOCTOU races between SELECT and DELETE.

CREATE TABLE IF NOT EXISTS cli_files (
  id              TEXT PRIMARY KEY,
  path            TEXT NOT NULL,
  original_name   TEXT,
  expires_at      TIMESTAMPTZ,
  burn_after_read BOOLEAN NOT NULL DEFAULT TRUE,
  license_tier    TEXT NOT NULL DEFAULT 'STD',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS cli_files_expires_at_idx
  ON cli_files (expires_at);

-- Atomic burn: returns the row if it existed and was not expired, otherwise
-- returns no rows. The DELETE only happens after the SELECT in one statement,
-- so concurrent callers race cleanly — exactly one wins.
CREATE OR REPLACE FUNCTION burn_cli_file(cli_id TEXT)
RETURNS SETOF cli_files
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  RETURN QUERY
  DELETE FROM cli_files
  WHERE id = cli_id
    AND (expires_at IS NULL OR expires_at > NOW())
  RETURNING *;
END;
$$;

-- RLS: the anon key has no access. The service_role key bypasses RLS.
ALTER TABLE cli_files ENABLE ROW LEVEL SECURITY;