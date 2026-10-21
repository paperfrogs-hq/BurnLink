const { reapOrphanedFiles } = require("../../lib/reap-orphaned-files");

exports.handler = async () => {
  const result = await reapOrphanedFiles({ dryRun: false, maxPages: 4, persistCursor: true });
  console.log("Orphan cleanup:", result);
  return { statusCode: 204 };
};
