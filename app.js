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
const r2CspOrigin = process.env.R2_ACCOUNT_ID
  ? `https://*.r2.cloudflarestorage.com`
  : null;

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
  // Check if view-once file has expired
  if (file.mode === "view-once" && file.expiresAt) {
    const expiresAt = new Date(file.expiresAt);
    if (!isNaN(expiresAt) && expiresAt <= new Date()) {
      await File.deleteById(file.id);
      await removeFromStorage(file.path);
      return res.status(410).render("not-found");
    }
  }

  // Atomically claim this file by deleting the DB record FIRST.
  // This prevents a race condition where two concurrent requests both
  // retrieve and serve the same encrypted payload.
  // The first caller gets deleted=true and proceeds; any concurrent
  // caller gets deleted=false and receives 410 without touching storage.
  const deleted = await File.deleteById(file.id);
  if (!deleted) {
    return res.status(410).render("not-found");
  }

  // Stream directly from R2 to the client — never buffer the whole file in
  // memory. This avoids heap exhaustion on large files and means the first
  // bytes reach the client almost immediately.
  let bodyStream, contentLength;
  try {
    ({ stream: bodyStream, contentLength } = await streamFromStorage(file.path));
  } catch (storageError) {
    // DB record is already gone; clean up storage best-effort then re-throw.
    await removeFromStorage(file.path).catch(() => {});
    throw storageError;
  }

  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
  res.setHeader("X-File-Name", encodeURIComponent(file.originalName));
  res.setHeader("Content-Type", "application/octet-stream");
  if (contentLength) {
    res.setHeader("Content-Length", contentLength);
  }

  // Pipe stream to client. Delete from R2 immediately when done —
  // whether the transfer completed normally or the client disconnected.
  // Guard flag prevents the double-delete if both events fire.
  bodyStream.pipe(res);
  let r2Cleaned = false;
  const cleanupR2 = () => {
    if (r2Cleaned) return;
    r2Cleaned = true;
    removeFromStorage(file.path).catch(() => {});
  };
  res.on("finish", cleanupR2); // stream fully sent
  res.on("close", cleanupR2);  // client disconnected early
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

  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
  res.setHeader("X-XSS-Protection", "0"); // disabled — CSP is the correct defence
  res.setHeader("Content-Security-Policy", [
    "default-src 'none'",
    `script-src 'self' 'nonce-${nonce}' https://cloud.umami.is`,
    "style-src 'unsafe-inline'",
    "img-src 'self' blob: data: https://api.producthunt.com",
    "media-src 'self' blob:",
    "font-src 'self'",
    `connect-src 'self' https://cloud.umami.is${r2CspOrigin ? " " + r2CspOrigin : ""}`,
    "frame-src blob:",
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

// Step 1 — browser asks for a signed PUT URL
app.get("/api/presign", rateLimit(30, 10 * 60 * 1000), async (req, res) => {
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
app.post("/api/commit", rateLimit(30, 10 * 60 * 1000), async (req, res) => {
  const { storagePath, originalName, mode: rawMode, password: rawPassword } = req.body;

  if (!storagePath || !STORAGE_PATH_RE.test(storagePath)) {
    return res.status(400).json({ error: "Invalid storage path." });
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

app.post("/api/upload", rateLimit(10, 10 * 60 * 1000), upload.single("file"), async (req, res) => {
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
    });
  } catch (error) {
    return res.status(400).render("not-found");
  }
});

app.get("/s/:id/raw", rateLimit(15, 60 * 1000), async (req, res) => {
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
