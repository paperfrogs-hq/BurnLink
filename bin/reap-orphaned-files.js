#!/usr/bin/env node
require("dotenv").config();
const { reapOrphanedFiles } = require("../lib/reap-orphaned-files");

reapOrphanedFiles({ dryRun: !process.argv.includes("--delete") })
  .then(result => console.log(JSON.stringify(result)))
  .catch(error => {
    console.error("Orphan cleanup failed:", error);
    process.exitCode = 1;
  });
