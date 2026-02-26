require("dotenv").config();

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const express = require("express");
const multer = require("multer");
const File = require("./models/File");
const supabase = require("./lib/supabase");

const app = express();
const storageBucket = process.env.SUPABASE_STORAGE_BUCKET || "files";
const canonicalBaseUrl = process.env.CANONICAL_BASE_URL || "https://burnlink.page";
const configuredMaxUploadBytes = Number(process.env.MAX_UPLOAD_BYTES || 0);
const hasAppUploadLimit =
  Number.isFinite(configuredMaxUploadBytes) && configuredMaxUploadBytes > 0;
const PASSWORD_MAX_ATTEMPTS = 3;
const PASSWORD_LOCK_MINUTES = 10;
const enforceCanonicalRedirect = process.env.ENFORCE_CANONICAL_REDIRECT !== "false";

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
  const storedBuffer = await downloadFromStorage(file.path);

  // Burn the link before sending data so the URL cannot be reused.
  const deleted = await File.deleteById(file.id);
  if (!deleted) {
    return res.status(410).render("not-found");
  }

  await removeFromStorage(file.path);
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

app.use(express.urlencoded({ extended: true }));
app.set("view engine", "ejs");
app.set("views", resolveViewsDirectory());

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
  res.render("index", { fileLink: null, error: null });
});

app.post("/api/upload", upload.single("file"), async (req, res) => {
  let storagePath = null;

  try {
    if (!req.file) {
      return res.status(400).render("index", {
        fileLink: null,
        error: "Please choose a file to upload.",
      });
    }

    const originalName = req.body.originalName?.trim() || req.file.originalname || "file";
    const rawPassword = req.body.password?.trim() || "";
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

    return res.status(500).json({
      error: "Upload failed. Please try again.",
    });
  }
});

app.post("/upload", upload.single("file"), (req, res) => {
  return res.status(400).render("index", {
    fileLink: null,
    error: "This app requires JavaScript for end-to-end encryption uploads.",
  });
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
    });
  } catch (error) {
    return res.status(400).render("not-found");
  }
});

app.get("/file/:id/raw", async (req, res) => {
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

app.post("/file/:id/raw", async (req, res) => {
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
