require("dotenv").config({ override: true });

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const express = require("express");
const multer = require("multer");
const QRCode = require("qrcode");
const { Jimp } = require("jimp");
const File = require("./models/File");
const { dbRateLimit } = require("./models/RateLimit");
const supabase = require("./lib/supabase");
const { getComparisonBySlug, getComparisonPages } = require("./lib/comparisons");
const {
  versioningPolicy,
  currentRelease,
  changelogEntries,
  roadmapColumns,
} = require("./lib/product-updates");
const {
  getHelmetConfig,
  cspMiddleware,
  cspReportHandler,
  validators,
  validateEnvironment,
  requestIdMiddleware,
  securityLog,
} = require("./lib/security");

const { uploadToStorage, downloadFromStorage, streamFromStorage, removeFromStorage, getPresignedPutUrl, getPresignedGetUrl, getFirstBytes } = require("./lib/r2");

// Validate environment on startup
validateEnvironment();

const app = express();
app.disable("x-powered-by");

// Security headers via helmet
app.use(getHelmetConfig());

// Request ID tracking for audit trails
app.use(requestIdMiddleware);
const canonicalBaseUrl = process.env.CANONICAL_BASE_URL || "https://burnlink.page";
const MAX_UPLOAD_BYTES = 1 * 1024 * 1024 * 1024; // 1 GB hard cap
const configuredMaxUploadBytes = Number(process.env.MAX_UPLOAD_BYTES || MAX_UPLOAD_BYTES);
const hasAppUploadLimit =
  Number.isFinite(configuredMaxUploadBytes) && configuredMaxUploadBytes > 0;
const PASSWORD_MAX_ATTEMPTS = 3;
const PASSWORD_LOCK_MINUTES = 10;
const PASSWORD_MIN_LENGTH = 4;
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

function passwordHasWhitespace(password) {
  return typeof password === "string" && /\s/.test(password);
}

function isValidPassword(password) {
  return validators.validatePassword(password);
}

// ── CSRF Token Protection ──────────────────────────────────────────────────
// Simple in-memory CSRF token store with automatic cleanup
const csrfTokens = new Map();

function generateCsrfToken() {
  const token = crypto.randomBytes(32).toString('hex');
  csrfTokens.set(token, Date.now());
  return token;
}

function validateCsrfToken(token) {
  if (!token || typeof token !== 'string') return false;
  const exists = csrfTokens.has(token);
  if (exists) {
    csrfTokens.delete(token); // One-time use
  }
  return exists;
}

// Clean up old tokens every 10 minutes
setInterval(() => {
  const tenMinutesAgo = Date.now() - (10 * 60 * 1000);
  for (const [token, timestamp] of csrfTokens.entries()) {
    if (timestamp < tenMinutesAgo) {
      csrfTokens.delete(token);
    }
  }
  // Warn if too many accumulated (potential issue)
  if (csrfTokens.size > 100000) {
    console.warn(`[SECURITY] High number of CSRF tokens in memory: ${csrfTokens.size}`);
  }
}, 10 * 60 * 1000);

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

async function sendOneTimeEncryptedFile(res, file, bundleFiles = null) {

  // If bundleFiles is provided, burn all files in the bundle
  const filesToBurn = bundleFiles || [file];

  // Fix 1 — Atomic burn via Supabase RPC.
  // The burn_file() function does the expiry check AND the DELETE in a single
  // SQL statement, eliminating the TOCTOU window that a separate
  // SELECT-then-DELETE pattern has. Only one concurrent caller wins;
  // any race loser (or an already-burned / expired link) gets 410.
  // Never reveal *why* the link is unavailable — all failure cases return the
  // same status and body.
  const burnPromises = filesToBurn.map(f =>
    supabase.rpc('burn_file', { file_id: f.id })
  );
  const burnResults = await Promise.all(burnPromises);

  // Check if any burn succeeded (at least the first one)
  const mainBurnData = burnResults[0].data;
  if (burnResults[0].error || !mainBurnData || mainBurnData.length === 0) {
    return res.status(410).render("not-found");
  }

  // Return presigned GET URLs for all files in the bundle
  const PRESIGN_TTL = 5 * 60; // 5 minutes
  const downloadUrls = [];

  try {
    for (const f of filesToBurn) {
      const downloadUrl = await getPresignedGetUrl(f.path, PRESIGN_TTL);
      downloadUrls.push({
        downloadUrl,
        fileName: f.originalName,
        storagePath: f.path,
        cleanupToken: makeCleanupToken(f.path),
      });
    }
  } catch (err) {
    // Clean up any already-burned files
    for (const f of filesToBurn) {
      await removeFromStorage(f.path).catch(() => {});
    }
    throw err;
  }

  // Return single file format for backwards compatibility, or array for bundles
  if (filesToBurn.length === 1) {
    return res.json(downloadUrls[0]);
  } else {
    return res.json({
      files: downloadUrls,
      bundleSize: filesToBurn.length,
    });
  }
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

function getShareBaseUrl(req) {
  const isNetlify = process.env.NETLIFY === "true";
  const canonicalHostname = canonicalUrl?.hostname?.toLowerCase();
  const canonicalIsLocal = canonicalHostname ? isLocalHost(canonicalHostname) : false;

  if (canonicalUrl && (!isNetlify || !canonicalIsLocal)) {
    return canonicalUrl.origin;
  }

  const forwardedProto = (req.headers["x-forwarded-proto"] || "").split(",")[0].trim().toLowerCase();
  const forwardedHost = (req.headers["x-forwarded-host"] || "").split(",")[0].trim();
  const requestHost = forwardedHost || req.get("host") || "";
  const requestHostname = requestHost.split(":")[0].toLowerCase();
  const protocol = forwardedProto || req.protocol || "https";

  if (requestHostname && !isLocalHost(requestHostname)) {
    return `${protocol}://${requestHost}`;
  }

  return "https://burnlink.page";
}

function getPublicSiteUrl(req) {
  const canonicalHostname = canonicalUrl?.hostname?.toLowerCase();
  if (canonicalUrl && canonicalHostname && !isLocalHost(canonicalHostname)) {
    return canonicalUrl.origin;
  }

  const forwardedProto = (req.headers["x-forwarded-proto"] || "").split(",")[0].trim().toLowerCase();
  const forwardedHost = (req.headers["x-forwarded-host"] || "").split(",")[0].trim();
  const requestHost = forwardedHost || req.get("host") || "";
  const requestHostname = requestHost.split(":")[0].toLowerCase();
  const protocol = forwardedProto || req.protocol || "https";

  if (requestHostname && !isLocalHost(requestHostname)) {
    return `${protocol}://${requestHost}`;
  }

  return "https://burnlink.page";
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

// Enhanced CSP middleware with nonce support
app.use(cspMiddleware);

// Add Turnstile site key to locals
app.use((req, res, next) => {
  res.locals.turnstileSiteKey = TURNSTILE_SITE_KEY;
  next();
});

// CSP violation reporting endpoint
app.post("/api/csp-report", express.json({ type: "application/csp-report" }), cspReportHandler);

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
app.param("id", (req, res, next, id) => {
  if (!validators.isValidUUID(id)) {
    securityLog.log("INVALID_UUID_FORMAT", {
      path: req.path,
      providedId: id.substring(0, 20),
      requestId: req.id,
    });
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

app.get("/gateway", (req, res) => {
  // Gateway view removed. Route disabled.
  res.status(404).send("Gateway page has been removed.");
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

// GET /api/csrf-token - Generate CSRF token for client-side requests
app.get("/api/csrf-token", (req, res) => {
  if (process.env.CSRF_TOKENS_ENABLED !== 'true') {
    return res.status(404).json({ error: 'CSRF tokens disabled' });
  }
  const token = generateCsrfToken();
  res.json({ token });
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

app.get("/changelog", (req, res) => {
  const publicBaseUrl = getPublicSiteUrl(req);
  res.render("changelog", {
    canonicalUrl: `${publicBaseUrl}/changelog`,
    versioningPolicy,
    currentRelease,
    changelogEntries,
  });
});

app.get("/roadmap", (req, res) => {
  const publicBaseUrl = getPublicSiteUrl(req);
  res.render("roadmap", {
    canonicalUrl: `${publicBaseUrl}/roadmap`,
    versioningPolicy,
    currentRelease,
    roadmapColumns,
  });
});

app.get("/comparisons/:slug", (req, res) => {
  const comparison = getComparisonBySlug(req.params.slug);
  if (!comparison) {
    return res.status(404).render("not-found");
  }

  const comparisonPages = getComparisonPages();
  const footerComparisonLinks = comparisonPages.map((page) => ({
    href: `/comparisons/${page.slug}`,
    label: `BurnLink vs ${page.competitor}`,
  }));
  const relatedComparisons = comparisonPages.filter(
    (page) => page.slug !== comparison.slug
  );
  const publicBaseUrl = getPublicSiteUrl(req);

  return res.render("comparison", {
    comparison,
    canonicalUrl: `${publicBaseUrl}/comparisons/${comparison.slug}`,
    relatedComparisons,
    footerComparisonLinks,
  });
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

// Security events endpoint (requires authentication)
app.get("/api/security-events", async (req, res) => {
  const healthToken = process.env.HEALTH_TOKEN || "";
  const providedToken = (req.headers["authorization"] || "").replace(/^Bearer\s+/i, "");

  if (!healthToken || providedToken !== healthToken) {
    securityLog.log("UNAUTHORIZED_SECURITY_EVENTS_ACCESS", {
      ip: req.ip,
      path: req.path,
    });
    return res.status(403).json({ error: "Unauthorized" });
  }

  const count = Math.min(Number(req.query.count || 100), 1000);
  const events = securityLog.getEvents(count);
  res.json({ events, total: events.length });
});

// ── QR Code generation endpoint ────────────────────────────────────────────
app.get("/api/qr/:id", rateLimit(30, 60 * 1000), async (req, res) => {
  try {
    const file = await File.findById(req.params.id);
    if (!file) {
      return res.status(404).json({ error: "File not found." });
    }

    const shareBaseUrl = getShareBaseUrl(req);
    const shareUrl = `${shareBaseUrl}/s/${req.params.id}`;

    // Generate QR code as buffer
    const qrBuffer = await QRCode.toBuffer(shareUrl, {
      errorCorrectionLevel: "H",
      type: "image/png",
      width: 300,
      margin: 2,
      color: {
        dark: "#000000",
        light: "#ffffff",
      },
    });

    // Load QR code image with Jimp
    let qrImage = await Jimp.read(qrBuffer);

    // Try to load and overlay logo
    try {
      const logoPath = path.join(path.dirname(__filename), "public", "logo1.png");
      if (fs.existsSync(logoPath)) {
        const logo = await Jimp.read(logoPath);

        // Calculate logo size (about 25% of QR code)
        const qrSize = qrImage.width;
        const logoSize = Math.floor(qrSize * 0.25);

        // Resize logo
        logo.resize({ w: logoSize, h: logoSize });

        // Calculate center position
        const logoX = Math.floor((qrSize - logoSize) / 2);
        const logoY = Math.floor((qrSize - logoSize) / 2);

        // Composite logo directly on QR (transparent background)
        qrImage.composite(logo, logoX, logoY);
      }
    } catch (logoErr) {
      console.warn("Could not overlay logo:", logoErr.message);
      // Continue without logo if there's an error
    }

    // Convert to data URL
    const qrDataUrl = await qrImage.getBase64("image/png");

    return res.json({ qrDataUrl, shareUrl });
  } catch (error) {
    console.error("QR generation error:", error.message);
    return res.status(500).json({ error: "Failed to generate QR code." });
  }
});


// ── Phase 2: presign + commit (direct browser → R2 upload, no Netlify 6MB cap) ──

// Validates storagePath format to prevent path traversal on commit

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
  const { "cf-turnstile-response": turnstileToken } = req.body;
  
  // Determine if batch or single-file mode
  const isBatchMode = Array.isArray(req.body.files);
  const filesToProcess = isBatchMode ? req.body.files : [{
    storagePath: req.body.storagePath,
    originalName: req.body.originalName,
    mode: req.body.mode,
    password: req.body.password,
    linkKey: req.body.linkKey,
  }];

  if (!Array.isArray(filesToProcess) || filesToProcess.length === 0) {
    return res.status(400).json({ error: "No files to process." });
  }

  if (filesToProcess.length > 100) {
    return res.status(400).json({ error: "Too many files. Maximum 100 files per batch." });
  }

  // Early validation for all files (synchronous, fast)
  for (let i = 0; i < filesToProcess.length; i++) {
    const file = filesToProcess[i];
    const { storagePath, originalName, mode: rawMode, password: rawPassword, linkKey: rawLinkKey } = file;

    if (!storagePath || !validators.isValidStoragePath(storagePath)) {
      securityLog.log("INVALID_STORAGE_PATH", {
        path: req.path,
        requestId: req.id,
        fileIndex: i,
      });
      return res.status(400).json({ error: `Invalid storage path at file ${i + 1}.` });
    }

    if (rawLinkKey && !validators.isValidLinkKey(rawLinkKey)) {
      securityLog.log("INVALID_LINK_KEY", {
        path: req.path,
        requestId: req.id,
        fileIndex: i,
      });
      return res.status(400).json({ error: `Invalid link key at file ${i + 1}.` });
    }

    if (rawPassword && !isValidPassword(rawPassword)) {
      return res.status(400).json({ error: `Invalid password at file ${i + 1}. Must be 4-255 characters without spaces.` });
    }
  }

  // Turnstile token check (once for batch)
  if (process.env.TURNSTILE_SECRET_KEY && !turnstileToken) {
    return res.status(400).json({ error: "Bot verification failed. Please try again." });
  }

  try {
    // Verify Turnstile once (if configured)
    const turnstileOk = process.env.TURNSTILE_SECRET_KEY 
      ? await verifyTurnstile(turnstileToken, req.socket?.remoteAddress)
      : true;

    if (process.env.TURNSTILE_SECRET_KEY && !turnstileOk) {
      return res.status(403).json({ error: "Bot verification failed. Please try again." });
    }

    // Generate bundle_id for batch uploads (multiple files share same bundle_id)
    const bundleId = isBatchMode && filesToProcess.length > 1 ? crypto.randomUUID() : null;

    // Process all files in parallel
    const fileCreationPromises = filesToProcess.map(async (file, idx) => {
      const { storagePath, originalName, mode: rawMode, password: rawPassword, linkKey: rawLinkKey } = file;
      
      const originalNameClean = (originalName || "file").toString().trim().slice(0, 255);
      const mode = (rawMode === "view-once" || rawMode === "download") ? rawMode : "download";

      try {
        // Verify file exists and has valid FSE1 magic header + create DB record in parallel
        const [firstBytes, fileRecord] = await Promise.all([
          getFirstBytes(storagePath, 4),
          File.createFile({
            path: storagePath,
            originalName: originalNameClean,
            password: rawPassword || undefined,
            mode,
            linkKey: rawLinkKey || null,
            bundleId: bundleId,
          }),
        ]);

        // Validate FSE1 magic header
        if (
          firstBytes.length < 4 ||
          firstBytes[0] !== 70 ||
          firstBytes[1] !== 83 ||
          firstBytes[2] !== 69 ||
          firstBytes[3] !== 49
        ) {
          await removeFromStorage(storagePath).catch(() => {});
          throw new Error(`Invalid payload at file ${idx + 1}. File must be encrypted client-side before upload.`);
        }

        securityLog.log("FILE_CREATED", {
          fileId: fileRecord.id,
          bundleId: bundleId,
          ip: req.ip,
          mode,
          hasPassword: Boolean(rawPassword),
          hasLinkKey: Boolean(rawLinkKey),
          requestId: req.id,
          fileIndex: idx,
          batchMode: isBatchMode,
        });

        return fileRecord.id;
      } catch (err) {
        console.error(`File creation error at index ${idx}:`, err.message);
        await removeFromStorage(file.storagePath).catch(() => {});
        throw new Error(`Failed to process file ${idx + 1}: ${err.message}`);
      }
    });

    const fileIds = await Promise.all(fileCreationPromises);

    const shareBaseUrl = getShareBaseUrl(req);
    
    // Return single ID for backwards compatibility, or array of IDs for batch
    if (isBatchMode) {
      return res.status(201).json({ ids: fileIds, baseUrl: shareBaseUrl, bundleId: bundleId });
    } else {
      return res.status(201).json({ id: fileIds[0], baseUrl: shareBaseUrl });
    }
  } catch (err) {
    console.error("Commit error:", err.message);
    
    if (err.message && err.message.includes("NoSuchKey")) {
      return res.status(400).json({ error: "One or more files not found in storage. Please try uploading again." });
    }
    
    return res.status(500).json({ error: err.message || "Upload failed. Please try again." });
  }
});

// Called by the browser after it finishes downloading the encrypted file from R2.
// Validates the HMAC cleanup token (signed with CLEANUP_SECRET) then deletes
// the R2 object immediately. This is a fast operation — no size/timeout risk.
app.post("/api/r2-cleanup", rateLimit(60, 60 * 1000), async (req, res) => {
  const { storagePath, cleanupToken } = req.body;
  if (!storagePath || !validators.isValidStoragePath(storagePath) || !cleanupToken) {
    securityLog.log("INVALID_CLEANUP_REQUEST", {
      path: req.path,
      requestId: req.id,
    });
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
    // Early validation (fast, synchronous)
    if (!req.file) {
      return res.status(400).json({
        error: "Please choose a file to upload.",
      });
    }

    const originalName = (req.body.originalName?.trim() || req.file.originalname || "file").slice(0, 255);
    const rawPassword = (req.body.password || "").toString();
    if (rawPassword && !isValidPassword(rawPassword)) {
      securityLog.log("INVALID_PASSWORD_FORMAT", {
        path: req.path,
        requestId: req.id,
      });
      return res.status(400).json({ error: "Invalid password. Must be 4-255 characters without spaces." });
    }

    // Whitelist mode — reject anything not in the allowed set
    const rawMode = req.body.mode?.trim() || "";
    const mode = (rawMode === "view-once" || rawMode === "download") ? rawMode : "download";
    const payload = req.file.buffer;

    // Validate payload magic header (synchronous)
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
    const turnstileToken = (req.body["cf-turnstile-response"] || "").toString();

    // Parallelize: Turnstile verification + R2 upload + DB file creation
    // These are all independent I/O operations
    const [turnstileOk, , file] = await Promise.all([
      // 1. Verify Turnstile (if configured)
      process.env.TURNSTILE_SECRET_KEY
        ? (turnstileToken ? verifyTurnstile(turnstileToken, req.socket?.remoteAddress) : Promise.resolve(false))
        : Promise.resolve(true),
      
      // 2. Upload to R2
      uploadToStorage(storagePath, payload),
      
      // 3. Create file record in DB (happens in parallel with Turnstile & upload)
      File.createFile({
        path: storagePath,
        originalName,
        password: rawPassword || undefined,
        mode,
      }),
    ]);

    // Check Turnstile result
    if (process.env.TURNSTILE_SECRET_KEY) {
      if (!turnstileToken) {
        await removeFromStorage(storagePath).catch(() => {});
        return res.status(400).json({ error: "Bot verification failed. Please try again." });
      }
      if (!turnstileOk) {
        await removeFromStorage(storagePath).catch(() => {});
        return res.status(403).json({ error: "Bot verification failed. Please try again." });
      }
    }

    securityLog.log("FILE_CREATED", {
      fileId: file.id,
      ip: req.ip,
      mode,
      hasPassword: Boolean(rawPassword),
      requestId: req.id,
    });

    const shareBaseUrl = getShareBaseUrl(req);

    return res.status(201).json({
      id: file.id,
      baseUrl: shareBaseUrl,
    });
  } catch (error) {
    if (storagePath) {
      await removeFromStorage(storagePath).catch(() => {});
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
    
    // If file is part of a bundle, fetch all files in the bundle
    let bundleFiles = [file];
    if (file.bundleId) {
      bundleFiles = await File.findByBundleId(file.bundleId);
    }
    
    return res.render("password", {
      error: null,
      fileId: file.id,
      bundleId: file.bundleId || null,
      bundleFiles: bundleFiles,
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
    // If no password, check for bundle and pass all files
    let bundleFiles = null;
    if (file.bundleId) {
      bundleFiles = await File.findByBundleId(file.bundleId);
    }
    return sendOneTimeEncryptedFile(res, file, bundleFiles);
  } catch (error) {
    return res.status(400).json({ error: "Failed to download file." });
  }
});

app.post("/s/:id/raw", dbRateLimit(20, 60 * 1000), csrfProtectionMiddleware, async (req, res) => {
  try {
    const file = await File.findById(req.params.id);
    if (!file) return res.status(404).json({ error: "File not found." });
    if (!file.password) {
      // If no password, check for bundle and pass all files
      let bundleFiles = null;
      if (file.bundleId) {
        bundleFiles = await File.findByBundleId(file.bundleId);
      }
      return sendOneTimeEncryptedFile(res, file, bundleFiles);
    }
    const activeLockUntilMs = getActiveLock(file);
    if (activeLockUntilMs) {
      const remainingMinutes = Math.ceil((activeLockUntilMs - Date.now()) / 60000);
      securityLog.log("FILE_ACCESS_LOCKED", {
        fileId: file.id,
        ip: req.ip,
        requestId: req.id,
      });
      return res.status(423).json({ error: `File is locked. Try again in ${remainingMinutes} minute(s).` });
    }
    const submittedPassword = req.body.password || "";
    const passwordOk = await File.comparePassword(file, submittedPassword);
    if (!passwordOk) {
      const nextFailedAttempts = (file.failedAttempts || 0) + 1;
      if (nextFailedAttempts >= PASSWORD_MAX_ATTEMPTS) {
        const lockUntil = new Date(Date.now() + PASSWORD_LOCK_MINUTES * 60 * 1000).toISOString();
        await File.updateLockState(file.id, 0, lockUntil);
        securityLog.log("FILE_PASSWORD_LOCK", {
          fileId: file.id,
          ip: req.ip,
          attempts: nextFailedAttempts,
          requestId: req.id,
        });
        return res.status(423).json({ error: `Too many wrong passwords. File locked for ${PASSWORD_LOCK_MINUTES} minutes.` });
      }
      await File.updateLockState(file.id, nextFailedAttempts, null);
      securityLog.log("FILE_PASSWORD_WRONG", {
        fileId: file.id,
        ip: req.ip,
        attempts: nextFailedAttempts,
        requestId: req.id,
      });
      const remaining = PASSWORD_MAX_ATTEMPTS - nextFailedAttempts;
      return res.status(401).json({ error: `Wrong password. ${remaining} attempt(s) left before lock.` });
    }
    await File.updateLockState(file.id, 0, null);
    securityLog.log("FILE_PASSWORD_SUCCESS", {
      fileId: file.id,
      ip: req.ip,
      requestId: req.id,
    });
    // If password-protected, check for bundle and pass all files
    let bundleFiles = null;
    if (file.bundleId) {
      bundleFiles = await File.findByBundleId(file.bundleId);
    }
    return sendOneTimeEncryptedFile(res, file, bundleFiles);
  } catch (error) {
    return res.status(400).json({ error: "Failed to verify password." });
  }
});

app.post("/s/:id/burn", rateLimit(10, 60 * 1000), async (req, res) => {
  const id = req.params.id;
  const referer = req.headers["referer"] || req.headers["origin"] || "";
  const host = (req.headers["x-forwarded-host"] || req.headers["host"] || "").split(":")[0];
  if (referer && !referer.includes(host)) {
    securityLog.log("BURN_CSRF_REJECTION", {
      fileId: id,
      ip: req.ip,
      referer,
      host,
      requestId: req.id,
    });
    return res.status(403).json({ ok: false, error: "Forbidden." });
  }
  try {
    const file = await File.findById(id);
    if (!file) return res.json({ ok: true, alreadyGone: true });
    await File.deleteById(file.id);
    await removeFromStorage(file.path);
    securityLog.log("FILE_BURNED", {
      fileId: id,
      ip: req.ip,
      requestId: req.id,
    });
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

// Middleware to validate CSRF tokens on password submissions
function csrfProtectionMiddleware(req, res, next) {
  if (process.env.CSRF_TOKENS_ENABLED === 'true' && req.body && req.body.password) {
    const token = req.body.csrfToken || req.headers['x-csrf-token'];
    if (!validateCsrfToken(token)) {
      securityLog.log('CSRF_TOKEN_INVALID', {
        endpoint: req.path,
        ip: req.ip,
        requestId: req.id,
      });
      return res.status(403).json({ error: 'Invalid or missing CSRF token' });
    }
  }
  next();
}

app.post("/file/:id/raw", dbRateLimit(20, 60 * 1000), csrfProtectionMiddleware, async (req, res) => {
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
      securityLog.log("FILE_ACCESS_LOCKED", {
        fileId: file.id,
        ip: req.ip,
        requestId: req.id,
      });
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
        securityLog.log("FILE_PASSWORD_LOCK", {
          fileId: file.id,
          ip: req.ip,
          attempts: nextFailedAttempts,
          requestId: req.id,
        });
        return res.status(423).json({
          error: `Too many wrong passwords. File locked for ${PASSWORD_LOCK_MINUTES} minutes.`,
        });
      }

      await File.updateLockState(file.id, nextFailedAttempts, null);
      securityLog.log("FILE_PASSWORD_WRONG", {
        fileId: file.id,
        ip: req.ip,
        attempts: nextFailedAttempts,
        requestId: req.id,
      });
      const remaining = PASSWORD_MAX_ATTEMPTS - nextFailedAttempts;
      return res.status(401).json({
        error: `Wrong password. ${remaining} attempt(s) left before lock.`,
      });
    }

    await File.updateLockState(file.id, 0, null);
    securityLog.log("FILE_PASSWORD_SUCCESS", {
      fileId: file.id,
      ip: req.ip,
      requestId: req.id,
    });
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
    securityLog.log("BURN_CSRF_REJECTION", {
      fileId: id,
      ip: req.ip,
      referer,
      host,
      requestId: req.id,
    });
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
    securityLog.log("FILE_BURNED", {
      fileId: id,
      ip: req.ip,
      requestId: req.id,
    });
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
