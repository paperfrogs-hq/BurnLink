const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const {
  createAnalytics,
  hashVisitorId,
  isValidVisitorId,
} = require("../lib/analytics");

function createSupabaseMock() {
  const calls = [];
  return {
    calls,
    from(table) {
      return {
        upsert(values, options) {
          calls.push({ type: "upsert", table, values, options });
          return Promise.resolve({ error: null });
        },
        insert(values) {
          calls.push({ type: "insert", table, values });
          return Promise.resolve({ error: null });
        },
        delete() {
          return {
            eq(column, value) {
              calls.push({ type: "delete", table, column, value });
              return Promise.resolve({ error: null });
            },
          };
        },
      };
    },
  };
}

test("visitor IDs are validated and hashed before storage", () => {
  const visitorId = "a".repeat(64);

  assert.equal(isValidVisitorId(visitorId), true);
  assert.equal(isValidVisitorId("not-a-random-id"), false);
  assert.equal(
    hashVisitorId(visitorId),
    crypto.createHash("sha256").update(visitorId).digest("hex")
  );
  assert.equal(hashVisitorId("invalid"), null);
});

test("analytics stores monthly unique visitors and event totals", async () => {
  const supabase = createSupabaseMock();
  const analytics = createAnalytics(supabase, () => new Date("2026-03-27T18:00:00Z"));
  const visitorId = "b".repeat(64);
  const visitorHash = hashVisitorId(visitorId);

  await analytics.recordVisit(visitorId);
  await analytics.recordEvent(visitorId, "completed_upload", 3);

  assert.deepEqual(supabase.calls, [
    {
      type: "upsert",
      table: "burnlink_analytics_visitors",
      values: { visitor_hash: visitorHash, month_start: "2026-03-01" },
      options: { onConflict: "visitor_hash,month_start", ignoreDuplicates: true },
    },
    {
      type: "insert",
      table: "burnlink_analytics_events",
      values: {
        visitor_hash: visitorHash,
        event_type: "completed_upload",
        event_date: "2026-03-27",
        quantity: 3,
      },
    },
  ]);
});

test("analytics rejects invalid event values and deletes all visitor records", async () => {
  const supabase = createSupabaseMock();
  const analytics = createAnalytics(supabase);
  const visitorId = "c".repeat(64);

  await assert.rejects(
    analytics.recordEvent(visitorId, "file_name", 1),
    /Invalid analytics event type/
  );
  await assert.rejects(
    analytics.recordEvent(visitorId, "completed_upload", 101),
    /Invalid analytics event quantity/
  );

  await analytics.forgetVisitor(visitorId);
  assert.deepEqual(
    supabase.calls.map(({ type, table, column, value }) => ({ type, table, column, value })),
    [
      {
        type: "delete",
        table: "burnlink_analytics_events",
        column: "visitor_hash",
        value: hashVisitorId(visitorId),
      },
      {
        type: "delete",
        table: "burnlink_analytics_visitors",
        column: "visitor_hash",
        value: hashVisitorId(visitorId),
      },
    ]
  );
});
