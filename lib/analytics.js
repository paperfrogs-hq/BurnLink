const crypto = require("crypto");

const VISITORS_TABLE = "burnlink_analytics_visitors";
const EVENTS_TABLE = "burnlink_analytics_events";
const VISITOR_ID_RE = /^[a-f0-9]{64}$/i;
const EVENT_TYPES = new Set(["completed_upload", "successful_download"]);

function isValidVisitorId(visitorId) {
  return typeof visitorId === "string" && VISITOR_ID_RE.test(visitorId);
}

function hashVisitorId(visitorId) {
  if (!isValidVisitorId(visitorId)) return null;
  return crypto.createHash("sha256").update(visitorId.toLowerCase()).digest("hex");
}

function utcDate(date) {
  return date.toISOString().slice(0, 10);
}

function utcMonthStart(date) {
  return `${date.toISOString().slice(0, 7)}-01`;
}

function createAnalytics(supabase, clock = () => new Date()) {
  async function recordVisit(visitorId) {
    const visitorHash = hashVisitorId(visitorId);
    if (!visitorHash) return false;

    const { error } = await supabase.from(VISITORS_TABLE).upsert(
      {
        visitor_hash: visitorHash,
        month_start: utcMonthStart(clock()),
      },
      {
        onConflict: "visitor_hash,month_start",
        ignoreDuplicates: true,
      }
    );

    if (error) throw new Error(`Failed to record analytics visit: ${error.message}`);
    return true;
  }

  async function recordEvent(visitorId, eventType, quantity = 1) {
    const visitorHash = hashVisitorId(visitorId);
    if (!visitorHash) return false;
    if (!EVENT_TYPES.has(eventType)) throw new Error("Invalid analytics event type.");
    if (!Number.isSafeInteger(quantity) || quantity < 1 || quantity > 100) {
      throw new Error("Invalid analytics event quantity.");
    }

    const { error } = await supabase.from(EVENTS_TABLE).insert({
      visitor_hash: visitorHash,
      event_type: eventType,
      event_date: utcDate(clock()),
      quantity,
    });

    if (error) throw new Error(`Failed to record analytics event: ${error.message}`);
    return true;
  }

  async function forgetVisitor(visitorId) {
    const visitorHash = hashVisitorId(visitorId);
    if (!visitorHash) return false;

    for (const table of [EVENTS_TABLE, VISITORS_TABLE]) {
      const { error } = await supabase
        .from(table)
        .delete()
        .eq("visitor_hash", visitorHash);
      if (error) throw new Error(`Failed to delete analytics data: ${error.message}`);
    }

    return true;
  }

  return { recordVisit, recordEvent, forgetVisitor };
}

module.exports = {
  createAnalytics,
  hashVisitorId,
  isValidVisitorId,
};
