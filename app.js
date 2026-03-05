require("dotenv").config({ override: true });

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const express = require("express");
const multer = require("multer");
const File = require("./models/File");
const { dbRateLimit } = require("./models/RateLimit");
const supabase = require("./lib/supabase");

const { uploadToStorage, downloadFromStorage, streamFromStorage, removeFromStorage, getPresignedPutUrl, getPresignedGetUrl, getFirstBytes } = require("./lib/r2");

const app = express();
app.disable("x-powered-by");
const canonicalBaseUrl = process.env.CANONICAL_BASE_URL || "https://burnlink.page";
const MAX_UPLOAD_BYTES = 1 * 1024 * 1024 * 1024; // 1 GB hard cap
const configuredMaxUploadBytes = Number(process.env.MAX_UPLOAD_BYTES || MAX_UPLOAD_BYTES);
const hasAppUploadLimit =
  Number.isFinite(configuredMaxUploadBytes) && configuredMaxUploadBytes > 0;
const PASSWORD_MAX_ATTEMPTS = 3;
const PASSWORD_LOCK_MINUTES = 10;
const enforceCanonicalRedirect = process.env.ENFORCE_CANONICAL_REDIRECT === "true";
const TURNSTILE_SITE_KEY = process.env.TURNSTILE_SITE_KEY || "";
const r2CspOrigin = process.env.R2_ACCOUNT_ID
  ? `https://*.r2.cloudflarestorage.com`
  : null;

// Secret used to sign one-time R2 cleanup tokens.
// Falls back to the R2 secret key so no extra env var is required.
const CLEANUP_SECRET = process.env.CLEANUP_TOKEN_SECRET || process.env.R2_SECRET_ACCESS_KEY || "burnlink-cleanup-v1";
const GATEWAY_SECRET = process.env.GATEWAY_COOKIE_SECRET || CLEANUP_SECRET;
const GATEWAY_COOKIE = "_bl_gw";
const GATEWAY_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

function signGatewayCookie() {
  const ts = Date.now().toString();
  const sig = crypto.createHmac("sha256", GATEWAY_SECRET).update(ts).digest("hex");
  return `${ts}.${sig}`;
}

function isGatewayCookieValid(value) {
  if (!value || typeof value !== "string") return false;
  const dot = value.lastIndexOf(".");
  if (dot === -1) return false;
  const ts = value.slice(0, dot);
  const sig = value.slice(dot + 1);
  let expected;
  try {
    expected = crypto.createHmac("sha256", GATEWAY_SECRET).update(ts).digest("hex");
    if (sig.length !== expected.length) return false;
    if (!crypto.timingSafeEqual(Buffer.from(sig, "hex"), Buffer.from(expected, "hex"))) return false;
  } catch {
    return false;
  }
  const age = Date.now() - Number(ts);
  return age >= 0 && age < GATEWAY_TTL_MS;
}

function makeCleanupToken(storagePath) {
  return crypto.createHmac("sha256", CLEANUP_SECRET).update(storagePath).digest("hex");
}

// ── Fix 6: Preview/link-preview bot detection ─────────────────────────────
// Known bots that auto-fetch shared URLs (link previews). Receiving one of
// these must NOT trigger a burn — return a neutral preview page instead.
const PREVIEW_BOT_AGENTS = [
  'WhatsApp', 'Slackbot', 'TelegramBot', 'facebookexternalhit',
  'Twitterbot', 'LinkedInBot', 'Discordbot', 'Iframely',
  'bot', 'crawl', 'spider', 'preview', 'fetch',
];

function isPreviewBot(userAgent = '') {
  const ua = userAgent.toLowerCase();
  return PREVIEW_BOT_AGENTS.some(bot => ua.includes(bot.toLowerCase()));
}

const PREVIEW_RESPONSE_HTML = `<!DOCTYPE html>
<html>
<head>
  <meta property="og:title" content="BurnLink \u2014 Secure File">
  <meta property="og:description" content="A secure, encrypted one-time file. Open the link to decrypt and download.">
  <meta name="robots" content="noindex,nofollow">
</head>
<body></body>
</html>`;


async function verifyTurnstile(token, remoteip) {
  const secret = process.env.TURNSTILE_SECRET_KEY;
  if (!secret) return true; // skip if env var not configured
  if (!token) return false;
  try {
    const resp = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ secret, response: token, remoteip }),
    });
    const data = await resp.json();
    return data.success === true;
  } catch {
    return false;
  }
}

let canonicalUrl = null;
try {
  canonicalUrl = new URL(canonicalBaseUrl);
} catch (error) {
  canonicalUrl = null;
}

const uploadConfig = {
  storage: multer.memoryStorage(),
};

if (hasAppUploadLimit) {
  uploadConfig.limits = { fileSize: configuredMaxUploadBytes };
}

const upload = multer(uploadConfig);

function buildStoragePath(originalName) {
  const safeName = (originalName || "file").replace(/[^\w.\-]+/g, "_");
  return `${new Date().toISOString().slice(0, 10)}/${crypto.randomUUID()}-${safeName}`;
}

// uploadToStorage, downloadFromStorage, removeFromStorage are imported from lib/r2.js

async function sendOneTimeEncryptedFile(res, file) {
  // Fix 1 — Atomic burn via Supabase RPC.
  // The burn_file() function does the expiry check AND the DELETE in a single
  // SQL statement, eliminating the TOCTOU window that a separate
  // SELECT-then-DELETE pattern has. Only one concurrent caller wins;
  // any race loser (or an already-burned / expired link) gets 410.
  // Never reveal *why* the link is unavailable — all failure cases return the
  // same status and body.
  const { data: burnData, error: burnError } = await supabase.rpc('burn_file', {
    file_id: file.id,
  });
  if (burnError || !burnData || burnData.length === 0) {
    return res.status(410).render("not-found");
  }

  // Return a short-lived presigned GET URL so the browser downloads directly
  // from R2. The Netlify function only handles this tiny JSON response
  // (~500ms) regardless of file size — no more 26s timeout kills.
  // A signed cleanup token lets the client tell us when to delete the R2 object.
  const PRESIGN_TTL = 5 * 60; // 5 minutes
  let downloadUrl;
  try {
    downloadUrl = await getPresignedGetUrl(file.path, PRESIGN_TTL);
  } catch (err) {
    await removeFromStorage(file.path).catch(() => {});
    throw err;
  }

  return res.json({
    downloadUrl,
    fileName: file.originalName,
    storagePath: file.path,
    cleanupToken: makeCleanupToken(file.path),
  });
}

function getActiveLock(file) {
  if (!file.lockedUntil) return null;
  const lockedUntilMs = new Date(file.lockedUntil).getTime();
  if (!Number.isFinite(lockedUntilMs)) return null;
  if (lockedUntilMs <= Date.now()) return null;
  return lockedUntilMs;
}

function resolveViewsDirectory() {
  const candidates = [
    path.join(process.cwd(), "views"),
    path.join(__dirname, "views"),
    path.join(__dirname, "..", "views"),
    path.join(__dirname, "..", "..", "views"),
    "/var/task/views",
    "/var/task/src/views",
  ];

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }

  return path.join(process.cwd(), "views");
}

function isLocalHost(hostname) {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1";
}

// ── Bot scanner fast-reject ────────────────────────────────────────────────
// Drop known exploit/WordPress/scanner probes before any other logic runs.
const BOT_SCAN_EXACT = new Set([
  "/wp-login.php", "/wp-login", "/xmlrpc.php", "/admin", "/administrator",
  "/getcmd", "/console", "/manager",
  "/.well-known/traffic-advice",
  "/wp-includes/wlwmanifest.xml",
]);
const BOT_SCAN_SUFFIX = [
  "/wp-includes/wlwmanifest.xml",
  "/wp-admin", "/wp-login.php", "/xmlrpc.php",
];
const BOT_SCAN_PREFIX = [
  "/php", "/cgi-bin", "/boaform", "/GponForm", "/owa/",
];
app.use((req, res, next) => {
  const p = req.path.toLowerCase();
  if (
    BOT_SCAN_EXACT.has(p) ||
    BOT_SCAN_SUFFIX.some(s => p.endsWith(s)) ||
    BOT_SCAN_PREFIX.some(s => p.startsWith(s))
  ) {
    return res.status(404).end();
  }
  next();
});

// Strict body size limits — prevent oversized request attacks
app.use(express.urlencoded({ extended: true, limit: "16kb" }));
app.use(express.json({ limit: "16kb" }));
app.set("view engine", "ejs");
app.set("views", resolveViewsDirectory());

// Serve static files from public directory
function resolvePublicDirectory() {
  const candidates = [
    path.join(process.cwd(), "public"),
    path.join(__dirname, "public"),
    path.join(__dirname, "..", "public"),
    path.join(__dirname, "..", "..", "public"),
    "/var/task/public",
    "/var/task/src/public",
  ];

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }

  return path.join(process.cwd(), "public");
}

app.use(express.static(resolvePublicDirectory()));

// ── Security headers + CSP nonce ───────────────────────────────────────────
app.use((req, res, next) => {
  const nonce = crypto.randomBytes(16).toString("base64");
  res.locals.cspNonce = nonce;

  res.locals.turnstileSiteKey = TURNSTILE_SITE_KEY;
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
  res.setHeader("X-XSS-Protection", "0"); // disabled — CSP is the correct defence
  // Fix 3: Prevent cross-origin opener from accessing window.opener (key theft)
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader("Content-Security-Policy", [
    "default-src 'none'",
    `script-src 'self' 'nonce-${nonce}' https://cloud.umami.is https://challenges.cloudflare.com`,
    "style-src 'unsafe-inline'",
    "img-src 'self' blob: data: https://api.producthunt.com",
    "media-src 'self' blob:",
    "font-src 'self'",
    `connect-src 'self' https://cloud.umami.is https://challenges.cloudflare.com${r2CspOrigin ? " " + r2CspOrigin : ""}`,
    "frame-src blob: https://challenges.cloudflare.com",
    "form-action 'self'",
    "base-uri 'self'",
    "object-src 'none'",
  ].join("; "));

  if (req.secure || req.headers["x-forwarded-proto"] === "https") {
    res.setHeader("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");
  }

  next();
});

// ── In-memory rate limiter (no external package needed) ────────────────────
const _rlMap = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of _rlMap) {
    if (now > v.resetAt) _rlMap.delete(k);
  }
}, 60_000).unref();

function rateLimit(maxRequests, windowMs) {
  // Skip rate limiting in local development
  if (process.env.NODE_ENV !== "production" && process.env.ENABLE_RATE_LIMIT !== "true") {
    return (req, res, next) => next();
  }
  return (req, res, next) => {
    // Trust X-Forwarded-For ONLY if it looks like a single valid IP
    // An attacker can spoof multi-value headers like "1.2.3.4, 5.6.7.8"
    // We only trust it when there is exactly one value (set by a real proxy)
    const fwdRaw = (req.headers["x-forwarded-for"] || "").trim();
    const fwdParts = fwdRaw.split(",").map(s => s.trim()).filter(Boolean);
    const ip =
      (fwdParts.length === 1 ? fwdParts[0] : null) ||
      req.socket?.remoteAddress ||
      "unknown";

    // Rate limit key is per-IP + per-ROUTE (not per file UUID)
    // Strip UUIDs from path so all /file/*/raw share one bucket per IP
    const routeKey = req.path.replace(
      /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi,
      ":id"
    );
    const key = ip + ":" + routeKey;
    const now = Date.now();
    const entry = _rlMap.get(key);
    if (!entry || now > entry.resetAt) {
      _rlMap.set(key, { count: 1, resetAt: now + windowMs });
      return next();
    }
    if (entry.count >= maxRequests) {
      res.setHeader("Retry-After", String(Math.ceil((entry.resetAt - now) / 1000)));
      const isApi = req.path.startsWith("/api") || req.path.includes("/raw") || req.path.includes("/burn");
      return isApi
        ? res.status(429).json({ error: "Too many requests. Please slow down." })
        : res.status(429).send("Too many requests.");
    }
    entry.count++;
    return next();
  };
}

// ── UUID format validation — blocks DB lookup on garbage IDs ───────────────
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
app.param("id", (req, res, next, id) => {
  if (!UUID_RE.test(id)) {
    const wantsJson = req.method === "POST" || req.path.endsWith("/raw") || req.path.endsWith("/burn");
    return wantsJson
      ? res.status(404).json({ error: "Not found." })
      : res.status(404).render("not-found");
  }
  next();
});

app.use((req, res, next) => {
  if (!canonicalUrl || !enforceCanonicalRedirect) {
    return next();
  }

  const forwardedHost = (req.headers["x-forwarded-host"] || "").split(",")[0].trim();
  const requestHost = (forwardedHost || req.get("host") || "").toLowerCase();
  const requestHostname = requestHost.split(":")[0];
  const canonicalHostname = canonicalUrl.hostname.toLowerCase();

  if (!requestHostname || isLocalHost(requestHostname) || requestHostname === canonicalHostname) {
    return next();
  }

  return res.redirect(301, `${canonicalUrl.origin}${req.originalUrl}`);
});

// ── Turnstile gateway — verify humans before accessing any page ────────────
app.use((req, res, next) => {
  // Exempt: gateway page, verify endpoint, health, well-known, static assets
  const exempt = ["/gateway", "/api/gateway-verify", "/health", "/.well-known"];
  if (exempt.some(p => req.path === p || req.path.startsWith(p + "/"))) return next();
  if (/\.\w{1,6}$/.test(req.path)) return next(); // static files

  const raw = req.headers.cookie || "";
  const cookieEntry = raw.split(";").map(s => s.trim()).find(s => s.startsWith(GATEWAY_COOKIE + "="));
  const cookieVal = cookieEntry ? cookieEntry.slice(GATEWAY_COOKIE.length + 1) : null;

  if (isGatewayCookieValid(cookieVal)) return next();

  // Validate and sanitize next param to prevent open redirect
  const next_ = encodeURIComponent(req.originalUrl.startsWith("/") ? req.originalUrl : "/");
  return res.redirect(`/gateway?next=${next_}`);
});

app.get("/gateway", (req, res) => {
  const next_ = (req.query.next || "/").toString();
  // Only allow relative paths
  const returnTo = next_.startsWith("/") && !next_.startsWith("//") ? next_ : "/";
  res.render("gateway", { returnTo, cspNonce: res.locals.cspNonce, turnstileSiteKey: res.locals.turnstileSiteKey });
});

app.post("/api/gateway-verify", async (req, res) => {
  const token = req.body["cf-turnstile-response"];
  const fwdRaw = (req.headers["x-forwarded-for"] || "").trim();
  const userIp = fwdRaw.split(",")[0].trim() || req.socket?.remoteAddress;

  const ok = await verifyTurnstile(token, userIp);
  if (!ok) {
    return res.status(403).json({ error: "Verification failed. Please try again." });
  }

  const cookieVal = signGatewayCookie();
  const isSecure = req.secure || req.headers["x-forwarded-proto"] === "https";
  res.setHeader("Set-Cookie", [
    `${GATEWAY_COOKIE}=${cookieVal}`,
    "HttpOnly",
    isSecure ? "Secure" : "",
    "SameSite=Lax",
    `Max-Age=${GATEWAY_TTL_MS / 1000}`,
    "Path=/",
  ].filter(Boolean).join("; "));

  const returnTo = (req.body.returnTo || "/").toString();
  const safeReturn = returnTo.startsWith("/") && !returnTo.startsWith("//") ? returnTo : "/";
  return res.json({ ok: true, redirect: safeReturn });
});

app.get("/", (req, res) => {
  const error = req.query.error || null;
  res.render("index", { fileLink: null, error });
});

app.get("/about", (req, res) => {
  res.render("about");
});

app.get("/security-policy", (req, res) => {
  res.render("security-policy");
});

app.get("/hall-of-fame", (req, res) => {
  res.render("hall-of-fame");
});

// ── Responsible disclosure policy ─────────────────────────────────────────
app.get("/.well-known/security.txt", (req, res) => {
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.send([
    "Contact: mailto:hello@paperfrogs.dev",
    "Expires: 2027-01-01T00:00:00.000Z",
    "Preferred-Languages: en",
    "Canonical: https://burnlink.page/.well-known/security.txt",
    "Policy: https://burnlink.page/security-policy",
    "",
    "# Scope: *.burnlink.page",
    "# In-scope: client-side crypto flaws, one-time link bypass, IDOR, auth bypass",
    "# Please report vulnerabilities responsibly before public disclosure.",
  ].join("\n"));
});

app.get("/health", async (req, res) => {
  // Require a secret token to access internal health details
  const healthToken = process.env.HEALTH_TOKEN || "";
  const providedToken = (req.headers["authorization"] || "").replace(/^Bearer\s+/i, "");

  const authed = healthToken.length > 0 && providedToken === healthToken;

  try {
    const { error } = await supabase.from(process.env.SUPABASE_FILES_TABLE || "files").select("id").limit(1);
    const dbOk = !error;
    if (authed) {
      return res.json({ status: "ok", db: dbOk ? "ok" : "fail: " + error.message });
    }
    return res.json({ status: dbOk ? "ok" : "degraded" });
  } catch (e) {
    return res.status(503).json({ status: "error" });
  }
});

// ── Phase 2: presign + commit (direct browser → R2 upload, no Netlify 6MB cap) ──

// Validates storagePath format to prevent path traversal on commit
const STORAGE_PATH_RE = /^\d{4}-\d{2}-\d{2}\/[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}-[\w.\-]+$/i;
const LINK_KEY_RE = /^[A-Za-z0-9_-]{43,88}$/; // base64url-encoded AES-256 key (32 bytes = 43 chars)

// Step 1 — browser asks for a signed PUT URL
// Fix 4: Use DB-backed rate limiter so limits survive serverless cold starts
app.get("/api/presign", dbRateLimit(30, 10 * 60 * 1000), async (req, res) => {
  try {
    const filesize = Number(req.query.filesize || 0);
    if (filesize > MAX_UPLOAD_BYTES) {
      return res.status(413).json({ error: "File too large. Maximum upload size is 1 GB." });
    }
    const rawName = (req.query.filename || "file").toString().trim().slice(0, 255);
    const storagePath = buildStoragePath(rawName);
    const uploadUrl = await getPresignedPutUrl(storagePath, 900); // 15 min
    return res.json({ uploadUrl, storagePath });
  } catch (err) {
    console.error("Presign error:", err.message);
    return res.status(500).json({ error: "Could not generate upload URL." });
  }
});

// Step 2 — browser calls this after it finishes the direct PUT to R2
// Fix 4: Use DB-backed rate limiter so limits survive serverless cold starts
app.post("/api/commit", dbRateLimit(30, 10 * 60 * 1000), async (req, res) => {
  const { storagePath, originalName, mode: rawMode, password: rawPassword, linkKey: rawLinkKey, "cf-turnstile-response": turnstileToken } = req.body;

  const fwdRaw = (req.headers["x-forwarded-for"] || "").trim();
  const userIp = fwdRaw.split(",")[0].trim() || req.socket?.remoteAddress;
  const turnstileOk = await verifyTurnstile(turnstileToken, userIp);
  if (!turnstileOk) {
    return res.status(403).json({ error: "Bot verification failed. Please try again." });
  }

  if (!storagePath || !STORAGE_PATH_RE.test(storagePath)) {
    return res.status(400).json({ error: "Invalid storage path." });
  }

  if (rawLinkKey && !LINK_KEY_RE.test(rawLinkKey)) {
    return res.status(400).json({ error: "Invalid link key." });
  }

  const originalNameClean = (originalName || "file").toString().trim().slice(0, 255);
  const mode = (rawMode === "view-once" || rawMode === "download") ? rawMode : "download";

  // Verify the file actually landed in R2 and validate FSE1 magic header
  let firstBytes;
  try {
    firstBytes = await getFirstBytes(storagePath, 4);
  } catch (err) {
    return res.status(400).json({ error: "Upload not found in storage. Please try uploading again." });
  }

  if (
    firstBytes.length < 4 ||
    firstBytes[0] !== 70 ||
    firstBytes[1] !== 83 ||
    firstBytes[2] !== 69 ||
    firstBytes[3] !== 49
  ) {
    await removeFromStorage(storagePath).catch(() => {});
    return res.status(400).json({ error: "Invalid payload. File must be encrypted client-side before upload." });
  }

  try {
    const file = await File.createFile({
      path: storagePath,
      originalName: originalNameClean,
      password: rawPassword?.trim() || undefined,
      mode,
      linkKey: rawLinkKey || null,
    });

    const shareBaseUrl = canonicalUrl
      ? canonicalUrl.origin
      : `${req.protocol}://${req.get("host")}`;

    return res.status(201).json({ id: file.id, baseUrl: shareBaseUrl });
  } catch (err) {
    console.error("Commit error:", err.message);
    await removeFromStorage(storagePath).catch(() => {});
    return res.status(500).json({ error: "Upload failed. Please try again." });
  }
});

// Called by the browser after it finishes downloading the encrypted file from R2.
// Validates the HMAC cleanup token (signed with CLEANUP_SECRET) then deletes
// the R2 object immediately. This is a fast operation — no size/timeout risk.
app.post("/api/r2-cleanup", rateLimit(60, 60 * 1000), async (req, res) => {
  const { storagePath, cleanupToken } = req.body;
  if (!storagePath || !STORAGE_PATH_RE.test(storagePath) || !cleanupToken) {
    return res.status(400).json({ ok: false, error: "Invalid request." });
  }
  const expected = makeCleanupToken(storagePath);
  // Constant-time comparison; wrap in try-catch in case token isn't valid hex
  let tokenValid = false;
  try {
    tokenValid =
      cleanupToken.length === expected.length &&
      crypto.timingSafeEqual(Buffer.from(cleanupToken, "hex"), Buffer.from(expected, "hex"));
  } catch (_) {
    tokenValid = false;
  }
  if (!tokenValid) {
    return res.status(403).json({ ok: false, error: "Invalid token." });
  }
  await removeFromStorage(storagePath).catch(() => {});
  return res.json({ ok: true });
});

// Fix 4: Use DB-backed rate limiter so limits survive serverless cold starts
app.post("/api/upload", dbRateLimit(10, 10 * 60 * 1000), upload.single("file"), async (req, res) => {
  let storagePath = null;

  try {
    if (!req.file) {
      return res.status(400).json({
        error: "Please choose a file to upload.",
      });
    }

    const originalName = (req.body.originalName?.trim() || req.file.originalname || "file").slice(0, 255);
    const rawPassword = req.body.password?.trim() || "";
    // Whitelist mode — reject anything not in the allowed set
    const rawMode = req.body.mode?.trim() || "";
    const mode = (rawMode === "view-once" || rawMode === "download") ? rawMode : "download";
    const payload = req.file.buffer;

    if (
      payload.length < 8 ||
      payload[0] !== 70 ||
      payload[1] !== 83 ||
      payload[2] !== 69 ||
      payload[3] !== 49
    ) {
      return res.status(400).json({
        error: "Invalid payload. File must be encrypted client-side before upload.",
      });
    }

    storagePath = buildStoragePath(originalName);
    await uploadToStorage(storagePath, payload);

    const file = await File.createFile({
      path: storagePath,
      originalName,
      password: rawPassword || undefined,
      mode,
    });

    const shareBaseUrl = canonicalUrl
      ? canonicalUrl.origin
      : `${req.protocol}://${req.get("host")}`;

    return res.status(201).json({
      id: file.id,
      baseUrl: shareBaseUrl,
    });
  } catch (error) {
    if (storagePath) {
      await removeFromStorage(storagePath);
    }

    const errMsg = error?.message || String(error);
    console.error("Upload error details:", errMsg);

    return res.status(500).json({
      error: "Upload failed. Please try again.",
    });
  }
});

app.post("/upload", upload.single("file"), (req, res) => {
  return res.redirect("/?error=JavaScript+is+required+for+encrypted+uploads.+Please+enable+JavaScript+and+try+again.");
});

// ── /s/:id — new short share URL ────────────────────────────────────────
app.get("/s/:id", async (req, res) => {
  try {
    const file = await File.findById(req.params.id);
    if (!file) return res.status(404).render("not-found");
    return res.render("password", {
      error: null,
      fileId: file.id,
      requiresPassword: Boolean(file.password),
      mode: file.mode || "download",
      linkKey: file.linkKey || null,
    });
  } catch (error) {
    return res.status(400).render("not-found");
  }
});

app.get("/s/:id/raw", rateLimit(15, 60 * 1000), async (req, res) => {
  // Fix 6: Known link-preview bots must not trigger a burn.
  // They receive a neutral HTML preview and the file is left intact.
  if (isPreviewBot(req.headers["user-agent"] || "")) {
    return res.status(200).set("Content-Type", "text/html").send(PREVIEW_RESPONSE_HTML);
  }
  try {
    const file = await File.findById(req.params.id);
    if (!file) return res.status(404).render("not-found");
    if (file.password) return res.status(401).json({ error: "Password required." });
    return sendOneTimeEncryptedFile(res, file);
  } catch (error) {
    return res.status(400).json({ error: "Failed to download file." });
  }
});

app.post("/s/:id/raw", dbRateLimit(20, 60 * 1000), async (req, res) => {
  try {
    const file = await File.findById(req.params.id);
    if (!file) return res.status(404).json({ error: "File not found." });
    if (!file.password) return sendOneTimeEncryptedFile(res, file);
    const activeLockUntilMs = getActiveLock(file);
    if (activeLockUntilMs) {
      const remainingMinutes = Math.ceil((activeLockUntilMs - Date.now()) / 60000);
      return res.status(423).json({ error: `File is locked. Try again in ${remainingMinutes} minute(s).` });
    }
    const submittedPassword = req.body.password || "";
    const passwordOk = await File.comparePassword(file, submittedPassword);
    if (!passwordOk) {
      const nextFailedAttempts = (file.failedAttempts || 0) + 1;
      if (nextFailedAttempts >= PASSWORD_MAX_ATTEMPTS) {
        const lockUntil = new Date(Date.now() + PASSWORD_LOCK_MINUTES * 60 * 1000).toISOString();
        await File.updateLockState(file.id, 0, lockUntil);
        return res.status(423).json({ error: `Too many wrong passwords. File locked for ${PASSWORD_LOCK_MINUTES} minutes.` });
      }
      await File.updateLockState(file.id, nextFailedAttempts, null);
      const remaining = PASSWORD_MAX_ATTEMPTS - nextFailedAttempts;
      return res.status(401).json({ error: `Wrong password. ${remaining} attempt(s) left before lock.` });
    }
    await File.updateLockState(file.id, 0, null);
    return sendOneTimeEncryptedFile(res, file);
  } catch (error) {
    return res.status(400).json({ error: "Failed to verify password." });
  }
});

app.post("/s/:id/burn", rateLimit(10, 60 * 1000), async (req, res) => {
  const id = req.params.id;
  const referer = req.headers["referer"] || req.headers["origin"] || "";
  const host = (req.headers["x-forwarded-host"] || req.headers["host"] || "").split(":")[0];
  if (referer && !referer.includes(host)) return res.status(403).json({ ok: false, error: "Forbidden." });
  try {
    const file = await File.findById(id);
    if (!file) return res.json({ ok: true, alreadyGone: true });
    await File.deleteById(file.id);
    await removeFromStorage(file.path);
    console.log(`[burn] Completed id=${id}`);
    return res.json({ ok: true });
  } catch (error) {
    console.error(`[burn] ERROR for id=${id}:`, error.message);
    return res.status(500).json({ ok: false, error: "Burn failed." });
  }
});

// ── /file/:id — kept for backward compatibility, redirects to /s/:id ──────
app.get("/file/:id", async (req, res) => {
  try {
    const file = await File.findById(req.params.id);
    if (!file) return res.status(404).render("not-found");
    return res.redirect(301, `/s/${req.params.id}`);
  } catch (error) {
    return res.status(400).render("not-found");
  }
});

app.get("/file/:id/raw", rateLimit(15, 60 * 1000), async (req, res) => {
  // Fix 6: Same bot guard as /s/:id/raw — never burn on a preview-bot GET.
  if (isPreviewBot(req.headers["user-agent"] || "")) {
    return res.status(200).set("Content-Type", "text/html").send(PREVIEW_RESPONSE_HTML);
  }
  try {
    const file = await File.findById(req.params.id);

    if (!file) {
      return res.status(404).render("not-found");
    }

    if (file.password) {
      return res.status(401).json({
        error: "Password required.",
      });
    }

    return sendOneTimeEncryptedFile(res, file);
  } catch (error) {
    return res.status(400).json({ error: "Failed to download file." });
  }
});

app.post("/file/:id/raw", dbRateLimit(20, 60 * 1000), async (req, res) => {
  try {
    const file = await File.findById(req.params.id);

    if (!file) {
      return res.status(404).json({ error: "File not found." });
    }

    if (!file.password) {
      return sendOneTimeEncryptedFile(res, file);
    }

    const activeLockUntilMs = getActiveLock(file);
    if (activeLockUntilMs) {
      const remainingMinutes = Math.ceil((activeLockUntilMs - Date.now()) / 60000);
      return res.status(423).json({
        error: `File is locked. Try again in ${remainingMinutes} minute(s).`,
      });
    }

    const submittedPassword = req.body.password || "";
    const passwordOk = await File.comparePassword(file, submittedPassword);
    if (!passwordOk) {
      const nextFailedAttempts = (file.failedAttempts || 0) + 1;

      if (nextFailedAttempts >= PASSWORD_MAX_ATTEMPTS) {
        const lockUntil = new Date(
          Date.now() + PASSWORD_LOCK_MINUTES * 60 * 1000
        ).toISOString();
        await File.updateLockState(file.id, 0, lockUntil);

        return res.status(423).json({
          error: `Too many wrong passwords. File locked for ${PASSWORD_LOCK_MINUTES} minutes.`,
        });
      }

      await File.updateLockState(file.id, nextFailedAttempts, null);
      const remaining = PASSWORD_MAX_ATTEMPTS - nextFailedAttempts;
      return res.status(401).json({
        error: `Wrong password. ${remaining} attempt(s) left before lock.`,
      });
    }

    await File.updateLockState(file.id, 0, null);
    return sendOneTimeEncryptedFile(res, file);
  } catch (error) {
    return res.status(400).json({
      error: "Failed to verify password.",
    });
  }
});

// Explicit burn endpoint — called by client when view-once timer expires or user closes
// Requires the file's own UUID as proof of possession (unguessable, 122 bits entropy)
// Additional protection: checks the Referer header is same-origin
app.post("/file/:id/burn", rateLimit(10, 60 * 1000), async (req, res) => {
  const id = req.params.id;

  // Block cross-origin burn requests (basic CSRF protection)
  const referer = req.headers["referer"] || req.headers["origin"] || "";
  const host = (req.headers["x-forwarded-host"] || req.headers["host"] || "").split(":")[0];
  if (referer && !referer.includes(host)) {
    return res.status(403).json({ ok: false, error: "Forbidden." });
  }

  console.log(`[burn] Request received for file id=${id}`);
  try {
    const file = await File.findById(id);
    if (!file) {
      console.log(`[burn] File not found id=${id} — already deleted, treating as success`);
      return res.json({ ok: true, alreadyGone: true });
    }
    await File.deleteById(file.id);
    await removeFromStorage(file.path);
    console.log(`[burn] Completed id=${id}`);
    return res.json({ ok: true });
  } catch (error) {
    console.error(`[burn] ERROR for id=${id}:`, error.message);
    return res.status(500).json({ ok: false, error: "Burn failed." });
  }
});

app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError && error.code === "LIMIT_FILE_SIZE") {
    const maxMb = Math.floor(configuredMaxUploadBytes / 1024 / 1024);
    return res.status(413).render("index", {
      fileLink: null,
      error: `File is too large. Max size is ${maxMb}MB.`,
    });
  }

  return next(error);
});

module.exports = app;
