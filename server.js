require("dotenv").config();

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { promisify } = require("util");
const express = require("express");
const multer = require("multer");
const File = require("./models/File");

const app = express();
const uploadDirectory = path.join(__dirname, "uploads");
const upload = multer({ dest: uploadDirectory });
const pbkdf2Async = promisify(crypto.pbkdf2);

const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const KEY_LENGTH = 32;
const PBKDF2_ITERATIONS = 210000;
const PBKDF2_DIGEST = "sha256";

if (!process.env.SUPABASE_URL) {
  throw new Error("SUPABASE_URL is missing in .env");
}

if (!process.env.SUPABASE_SERVICE_ROLE_KEY) {
  throw new Error("SUPABASE_SERVICE_ROLE_KEY is missing in .env");
}

if (!process.env.PORT) {
  throw new Error("PORT is missing in .env");
}

if (!fs.existsSync(uploadDirectory)) {
  fs.mkdirSync(uploadDirectory, { recursive: true });
}

async function removeFileIfExists(filePath) {
  try {
    await fs.promises.unlink(filePath);
  } catch (error) {
    if (error.code !== "ENOENT") {
      console.error(`Failed to remove file ${filePath}:`, error.message);
    }
  }
}

async function encryptFileAtPath(filePath, password) {
  const plainBuffer = await fs.promises.readFile(filePath);
  const salt = crypto.randomBytes(SALT_LENGTH);
  const iv = crypto.randomBytes(IV_LENGTH);
  const key = await pbkdf2Async(
    password,
    salt,
    PBKDF2_ITERATIONS,
    KEY_LENGTH,
    PBKDF2_DIGEST
  );

  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encryptedBuffer = Buffer.concat([
    cipher.update(plainBuffer),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();

  // payload format: [salt][iv][authTag][ciphertext]
  const payload = Buffer.concat([salt, iv, authTag, encryptedBuffer]);
  await fs.promises.writeFile(filePath, payload);
}

async function decryptFileAtPath(filePath, password) {
  const payload = await fs.promises.readFile(filePath);
  const headerLength = SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH;

  if (payload.length <= headerLength) {
    throw new Error("Encrypted payload is invalid.");
  }

  const salt = payload.subarray(0, SALT_LENGTH);
  const iv = payload.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
  const authTag = payload.subarray(
    SALT_LENGTH + IV_LENGTH,
    SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH
  );
  const ciphertext = payload.subarray(headerLength);

  const key = await pbkdf2Async(
    password,
    salt,
    PBKDF2_ITERATIONS,
    KEY_LENGTH,
    PBKDF2_DIGEST
  );
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(authTag);

  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

app.use(express.urlencoded({ extended: true }));
app.set("view engine", "ejs");

app.get("/", (req, res) => {
  res.render("index", { fileLink: null, error: null });
});

app.post("/upload", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).render("index", {
        fileLink: null,
        error: "Please choose a file to upload.",
      });
    }

    const rawPassword = req.body.password?.trim() || "";

    if (rawPassword) {
      await encryptFileAtPath(req.file.path, rawPassword);
    }

    const file = await File.createFile({
      path: req.file.path,
      originalName: req.file.originalname,
      password: rawPassword || undefined,
    });

    const fileLink = `${req.protocol}://${req.get("host")}/file/${file.id}`;

    return res.render("index", { fileLink, error: null });
  } catch (error) {
    if (req.file?.path) {
      await removeFileIfExists(req.file.path);
    }

    return res.status(500).render("index", {
      fileLink: null,
      error: "Upload failed. Please try again.",
    });
  }
});

app.get("/file/:id", async (req, res) => {
  try {
    const file = await File.findById(req.params.id);

    if (!file) {
      return res.status(404).render("not-found");
    }

    if (file.password) {
      return res.render("password", { error: null });
    }

    // Legacy fallback for old non-encrypted records.
    const deleted = await File.deleteById(file.id);
    if (!deleted) {
      return res.status(404).render("not-found");
    }

    return res.download(file.path, file.originalName, async () => {
      await removeFileIfExists(file.path);
    });
  } catch (error) {
    return res.status(400).render("not-found");
  }
});

app.post("/file/:id", async (req, res) => {
  try {
    const file = await File.findById(req.params.id);

    if (!file) {
      return res.status(404).render("not-found");
    }

    if (!file.password) {
      const deleted = await File.deleteById(file.id);
      if (!deleted) {
        return res.status(404).render("not-found");
      }

      return res.download(file.path, file.originalName, async () => {
        await removeFileIfExists(file.path);
      });
    }

    const submittedPassword = req.body.password || "";
    const passwordOk = await File.comparePassword(file, submittedPassword);
    if (!passwordOk) {
      return res.status(401).render("password", {
        error: "Wrong password. Try again.",
      });
    }

    const decryptedBuffer = await decryptFileAtPath(file.path, submittedPassword);

    // Burn the link before sending data so the URL cannot be reused.
    const deleted = await File.deleteById(file.id);
    if (!deleted) {
      return res.status(410).render("not-found");
    }

    await removeFileIfExists(file.path);

    res.attachment(file.originalName);
    res.setHeader("Content-Type", "application/octet-stream");
    return res.send(decryptedBuffer);
  } catch (error) {
    if (error.message && error.message.includes("authenticate")) {
      return res.status(401).render("password", {
        error: "Wrong password. Try again.",
      });
    }

    return res.status(400).render("not-found");
  }
});

const preferredPort = Number(process.env.PORT) || 3000;
const maxPortRetries = Number(process.env.PORT_RETRIES || 10);

function startServer(port, retriesLeft) {
  const server = app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
  });

  server.on("error", (error) => {
    if (error.code === "EADDRINUSE" && retriesLeft > 0) {
      const nextPort = port + 1;
      console.warn(
        `Port ${port} is busy. Retrying on port ${nextPort} (${retriesLeft} retries left)...`
      );
      startServer(nextPort, retriesLeft - 1);
      return;
    }

    console.error("Failed to start server:", error.message);
    process.exit(1);
  });
}

startServer(preferredPort, maxPortRetries);
