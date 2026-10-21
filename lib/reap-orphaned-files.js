const supabase = require("./supabase");
const { listStoragePage, uploadToStorage, downloadFromStorage, removeFromStorage } = require("./r2");
const { validators } = require("./security");

const GRACE_MS = 24 * 60 * 60 * 1000;
const BATCH_SIZE = 50;
const CURSOR_KEY = "maintenance/orphan-sweep-cursor";
const CLI_PATH_RE = /^cli\/[A-Za-z0-9_-]{12}$/;

async function reapOrphanedFiles({ dryRun = true, now = Date.now(), maxPages = Infinity, persistCursor = false } = {}) {
  const table = process.env.SUPABASE_FILES_TABLE || "files";
  const result = { scanned: 0, candidates: 0, deleted: 0, complete: false };
  let batch = [];
  let cursor = "";
  if (persistCursor) {
    try {
      cursor = (await downloadFromStorage(CURSOR_KEY)).toString();
    } catch (error) {
      if (error?.name !== "NoSuchKey" && error?.$metadata?.httpStatusCode !== 404) throw error;
    }
  }

  async function processBatch() {
    if (!batch.length) return;
    const paths = batch;
    batch = [];
    const active = new Set();
    for (const [tableName, candidates] of [
      [table, paths.filter(path => validators.isValidStoragePath(path))],
      ["cli_files", paths.filter(path => CLI_PATH_RE.test(path))],
    ]) {
      if (!candidates.length) continue;
      const { data, error } = await supabase.from(tableName).select("path").in("path", candidates);
      if (error) throw new Error(`Cannot check active files: ${error.message}`);
      for (const row of data || []) active.add(row.path);
    }
    for (const path of paths) {
      if (active.has(path)) continue;
      result.candidates++;
      if (dryRun) continue;
      await removeFromStorage(path);
      result.deleted++;
    }
  }

  for (let pageNumber = 0; pageNumber < maxPages; pageNumber++) {
    const page = await listStoragePage(cursor);
    if (page.isTruncated && !page.objects.length) throw new Error("Storage listing made no progress");
    for (const object of page.objects) {
      result.scanned++;
      const path = object.Key;
      const modified = new Date(object.LastModified).getTime();
      if ((!validators.isValidStoragePath(path) && !CLI_PATH_RE.test(path)) ||
          !Number.isFinite(modified) || now - modified < GRACE_MS) continue;
      batch.push(path);
      if (batch.length >= BATCH_SIZE) await processBatch();
    }
    await processBatch();
    cursor = page.objects.at(-1)?.Key || "";
    result.complete = !page.isTruncated;
    if (persistCursor) await uploadToStorage(CURSOR_KEY, Buffer.from(result.complete ? "" : cursor));
    if (result.complete) break;
  }
  return result;
}

module.exports = { reapOrphanedFiles };
