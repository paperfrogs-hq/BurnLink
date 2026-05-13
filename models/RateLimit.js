
const supabase = require("../lib/supabase");

const RL_TABLE = process.env.SUPABASE_RL_TABLE || "rate_limits";

/**
 * Check whether `key` is within the rate limit window, then increment.
 *
 * @param {string}  key         Unique bucket key (e.g. "1.2.3.4:/file/:id/raw")
 * @param {number}  maxRequests Maximum allowed requests per window
 * @param {number}  windowMs    Window duration in milliseconds
 * @returns {{ allowed: boolean, retryAfter?: number }}
 */
async function checkAndIncrement(key, maxRequests, windowMs) {
  const now = Date.now();

  // ── 1. Read the current window entry ─────────────────────────────────────
  const { data, error: fetchError } = await supabase
    .from(RL_TABLE)
    .select("count, reset_at")
    .eq("key", key)
    .maybeSingle();

  if (fetchError) {
    // Fail open — a DB error should not block legitimate traffic
    console.warn("[rl] Supabase read error:", fetchError.message);
    return { allowed: true };
  }

  const resetAtMs = data ? new Date(data.reset_at).getTime() : 0;

  // ── 2. Expired or new window: reset to count=1 ────────────────────────────
  if (!data || now > resetAtMs) {
    const { error: upsertError } = await supabase.from(RL_TABLE).upsert(
      {
        key,
        count: 1,
        reset_at: new Date(now + windowMs).toISOString(),
      },
      { onConflict: "key" }
    );

    if (upsertError) {
      console.warn("[rl] Supabase upsert error:", upsertError.message);
    }

    return { allowed: true };
  }

  // ── 3. Within the window — check limit ────────────────────────────────────
  if (data.count >= maxRequests) {
    return {
      allowed: false,
      retryAfter: Math.ceil((resetAtMs - now) / 1000),
    };
  }

  // ── 4. Increment count ────────────────────────────────────────────────────
  const { error: incrError } = await supabase
    .from(RL_TABLE)
    .update({ count: data.count + 1 })
    .eq("key", key)
    // Only update if the window hasn't expired between our read and write
    .gt("reset_at", new Date(now).toISOString());

  if (incrError) {
    console.warn("[rl] Supabase increment error:", incrError.message);
  }

  return { allowed: true };
}

/**
 * Express middleware factory — mirrors the API of the in-memory rateLimit().
 *
 * Usage:
 *   app.post("/file/:id/raw", dbRateLimit(20, 60_000), handler);
 *
 * @param {number} maxRequests
 * @param {number} windowMs
 */
function dbRateLimit(maxRequests, windowMs) {
  return async (req, res, next) => {
    try {
      // ── Same IP resolution as in-memory rateLimit() ──────────────────────
      const fwdRaw = (req.headers["x-forwarded-for"] || "").trim();
      const fwdParts = fwdRaw.split(",").map((s) => s.trim()).filter(Boolean);
      const ip =
        (fwdParts.length === 1 ? fwdParts[0] : null) ||
        req.socket?.remoteAddress ||
        "unknown";

      // Strip UUIDs so all /file/*/raw share one bucket per IP
      const routeKey = req.path.replace(
        /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi,
        ":id"
      );
      const key = `${ip}:${routeKey}`;

      const { allowed, retryAfter } = await checkAndIncrement(key, maxRequests, windowMs);

      if (!allowed) {
        res.setHeader("Retry-After", String(retryAfter));
        const wantsJson =
          req.method === "POST" ||
          req.path.includes("/raw") ||
          req.path.includes("/burn");
        return wantsJson
          ? res.status(429).json({ error: "Too many requests. Please slow down." })
          : res.status(429).send("Too many requests.");
      }

      return next();
    } catch (err) {
      // Fail open — unexpected errors must not gate legitimate requests
      console.error("[rl] Unexpected error in dbRateLimit:", err.message);
      return next();
    }
  };
}

module.exports = { dbRateLimit };
