require("dotenv").config({ override: true });

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const express = require("express");
const multer = require("multer");
const File = require("./models/File");
const supabase = require("./lib/supabase");

const app = express();
app.disable("x-powered-by");
const storageBucket = process.env.SUPABASE_STORAGE_BUCKET || "files";
const canonicalBaseUrl = process.env.CANONICAL_BASE_URL || "https://burnlink.page";
const configuredMaxUploadBytes = Number(process.env.MAX_UPLOAD_BYTES || 0);
const hasAppUploadLimit =
  Number.isFinite(configuredMaxUploadBytes) && configuredMaxUploadBytes > 0;
const PASSWORD_MAX_ATTEMPTS = 3;
const PASSWORD_LOCK_MINUTES = 10;
const enforceCanonicalRedirect = process.env.ENFORCE_CANONICAL_REDIRECT === "true";

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

async function uploadToStorage(storagePath, buffer) {
  const { error } = await supabase.storage
    .from(storageBucket)
    .upload(storagePath, buffer, {
      contentType: "application/octet-stream",
      upsert: false,
    });

  if (error) {
    throw new Error(`Storage upload failed: ${error.message}`);
  }
}

async function downloadFromStorage(storagePath) {
  const { data, error } = await supabase.storage
    .from(storageBucket)
    .download(storagePath);

  if (error) {
    throw new Error(`Storage download failed: ${error.message}`);
  }

  const arrayBuffer = await data.arrayBuffer();
  return Buffer.from(arrayBuffer);
}

async function removeFromStorage(storagePath) {
  if (!storagePath) return;

  const { error } = await supabase.storage
    .from(storageBucket)
    .remove([storagePath]);

  if (error && !/not found/i.test(error.message)) {
    console.error(`Storage delete failed for ${storagePath}:`, error.message);
  }
}

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

  // Only retrieve bytes AFTER the DB record is atomically claimed.
  let storedBuffer;
  try {
    storedBuffer = await downloadFromStorage(file.path);
  } catch (storageError) {
    // DB record is already gone; clean up storage best-effort then re-throw.
    await removeFromStorage(file.path).catch(() => {});
    throw storageError;
  }
  await removeFromStorage(file.path);

  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
  res.setHeader("X-File-Name", encodeURIComponent(file.originalName));
  res.setHeader("Content-Type", "application/octet-stream");
  return res.send(storedBuffer);
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
    "connect-src 'self' https://cloud.umami.is",
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

// ── Responsible disclosure policy ─────────────────────────────────────────
app.get("/.well-known/security.txt", (req, res) => {
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.send([
    "Contact: mailto:security@burnlink.page",
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

app.get("/file/:id", async (req, res) => {
  try {
    const file = await File.findById(req.params.id);

    if (!file) {
      return res.status(404).render("not-found");
    }

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

app.post("/file/:id/raw", rateLimit(20, 60 * 1000), async (req, res) => {
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
    console.log(`[burn] Found file id=${id} path=${file.path} mode=${file.mode}`);
    await File.deleteById(file.id);
    console.log(`[burn] DB record deleted id=${id}`);
    await removeFromStorage(file.path);
    console.log(`[burn] Storage deleted path=${file.path}`);
    return res.json({ ok: true });
  } catch (error) {
    console.error(`[burn] ERROR for id=${id}:`, error.message, error.stack);
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
