const test = require("node:test");
const assert = require("node:assert/strict");

require("dotenv").config({ override: true });
const r2 = require("../lib/r2");
const supabase = require("../lib/supabase");

const active = "2026-01-01/11111111-1111-4111-8111-111111111111-active.txt";
const orphan = "2026-01-01/22222222-2222-4222-8222-222222222222-orphan.txt";
const recent = "2026-01-02/33333333-3333-4333-8333-333333333333-recent.txt";
const now = new Date("2026-01-02T12:00:00Z").getTime();
const deleted = [];
let dbError = false;
let pageSize = 4;
let cursorStorage = null;

const listed = [
  { Key: active, LastModified: new Date("2026-01-01T00:00:00Z") },
  { Key: orphan, LastModified: new Date("2026-01-01T00:00:00Z") },
  { Key: recent, LastModified: new Date("2026-01-02T11:00:00Z") },
  { Key: "cli/something", LastModified: new Date("2026-01-01T00:00:00Z") },
];
r2.listStoragePage = async (startAfter = "") => {
  const remaining = listed.filter(object => object.Key > startAfter);
  return { objects: remaining.slice(0, pageSize), isTruncated: remaining.length > pageSize };
};
r2.removeFromStorage = async path => deleted.push(path);
r2.uploadToStorage = async (_path, bytes) => { cursorStorage = bytes.toString(); };
r2.downloadFromStorage = async () => {
  if (cursorStorage === null) throw Object.assign(new Error("missing cursor"), { name: "NoSuchKey" });
  return Buffer.from(cursorStorage);
};
supabase.from = table => ({
  select: () => ({
    in: async () => dbError
      ? { data: null, error: { message: "Database unavailable" } }
      : { data: table === "cli_files" ? [{ path: "cli/ABCDEFGHIJKL" }] : [{ path: active }], error: null },
  }),
});

const { reapOrphanedFiles } = require("../lib/reap-orphaned-files");

test("sweep deletes only old objects without an active database row", async () => {
  const preview = await reapOrphanedFiles({ now });
  assert.deepEqual(preview, { scanned: 4, candidates: 1, deleted: 0, complete: true });
  assert.deepEqual(deleted, []);

  const result = await reapOrphanedFiles({ now, dryRun: false });
  assert.deepEqual(result, { scanned: 4, candidates: 1, deleted: 1, complete: true });
  assert.deepEqual(deleted, [orphan]);
});

test("database failure stops the sweep without deleting objects", async () => {
  deleted.length = 0;
  dbError = true;
  await assert.rejects(reapOrphanedFiles({ now, dryRun: false }), /Cannot check active files/);
  assert.deepEqual(deleted, []);
  dbError = false;
});

test("sweep covers orphaned CLI objects without removing active CLI files", async () => {
  listed.push(
    { Key: "cli/ABCDEFGHIJKL", LastModified: new Date("2026-01-01T00:00:00Z") },
    { Key: "cli/MNOPQRSTUVWX", LastModified: new Date("2026-01-01T00:00:00Z") }
  );
  pageSize = 6;
  deleted.length = 0;
  try {
    const result = await reapOrphanedFiles({ now, dryRun: false });
    assert.equal(result.scanned, 6);
    assert.equal(result.deleted, 2);
    assert.deepEqual(deleted, [orphan, "cli/MNOPQRSTUVWX"]);
  } finally {
    listed.length = 4;
    pageSize = 4;
  }
});

test("scheduled sweeps persist progress and eventually scan the full bucket", async () => {
  pageSize = 2;
  cursorStorage = null;
  deleted.length = 0;
  try {
    const first = await reapOrphanedFiles({ now, dryRun: false, maxPages: 1, persistCursor: true });
    assert.equal(first.complete, false);
    assert.equal(first.scanned, 2);
    assert.equal(cursorStorage, orphan);

    const second = await reapOrphanedFiles({ now, dryRun: false, maxPages: 1, persistCursor: true });
    assert.equal(second.complete, true);
    assert.equal(second.scanned, 2);
    assert.equal(cursorStorage, "");
    assert.deepEqual(deleted, [orphan]);
  } finally {
    pageSize = 4;
    cursorStorage = null;
  }
});
