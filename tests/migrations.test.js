const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { quoteSqlIdentifier, runMigrationFile } = require("../run-migrations");

test("migration table names are restricted and quoted", () => {
  assert.equal(quoteSqlIdentifier("custom_files"), '"custom_files"');
  assert.throws(() => quoteSqlIdentifier('files; DROP TABLE users'), /simple SQL identifier/);
});

test("migration execution fails on SQL errors", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "burnlink-migration-test-"));
  const migrationPath = path.join(directory, "001_failure.sql");
  fs.writeFileSync(migrationPath, "SELECT 1;");
  const supabase = {
    rpc: async () => ({ error: { message: "permission denied" } }),
  };

  try {
    await assert.rejects(
      runMigrationFile(supabase, migrationPath),
      /001_failure\.sql statement 1 failed: permission denied/
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
