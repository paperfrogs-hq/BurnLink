const { S3Client, PutObjectCommand, GetObjectCommand, HeadObjectCommand, DeleteObjectCommand, ListObjectsV2Command } = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");

const requiredVars = ["R2_ACCOUNT_ID", "R2_ACCESS_KEY_ID", "R2_SECRET_ACCESS_KEY", "R2_BUCKET_NAME"];
for (const v of requiredVars) {
  if (!process.env[v]) {
    throw new Error(`Missing required env var: ${v}`);
  }
}

const r2 = new S3Client({
  region: "auto",
  endpoint: `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
  credentials: {
    accessKeyId: process.env.R2_ACCESS_KEY_ID,
    secretAccessKey: process.env.R2_SECRET_ACCESS_KEY,
  },
  requestChecksumCalculation: "WHEN_REQUIRED",
  responseChecksumValidation: "WHEN_REQUIRED",
});

const bucket = process.env.R2_BUCKET_NAME;

async function uploadToStorage(storagePath, buffer) {
  await r2.send(
    new PutObjectCommand({
      Bucket: bucket,
      Key: storagePath,
      Body: buffer,
      ContentType: "application/octet-stream",
    })
  );
}

async function downloadFromStorage(storagePath) {
  const response = await r2.send(
    new GetObjectCommand({
      Bucket: bucket,
      Key: storagePath,
    })
  );

  // Stream the body into a Buffer
  const chunks = [];
  for await (const chunk of response.Body) {
    chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
  }
  return Buffer.concat(chunks);
}

async function removeFromStorage(storagePath) {
  if (!storagePath) return;
  try {
    await r2.send(
      new DeleteObjectCommand({
        Bucket: bucket,
        Key: storagePath,
      })
    );
  } catch (err) {
    if (err?.name !== "NoSuchKey") throw err;
  }
}

// Returns a presigned PUT URL the browser can use to upload directly to R2
async function getPresignedPutUrl(storagePath, expiresIn = 900) {
  const command = new PutObjectCommand({
    Bucket: bucket,
    Key: storagePath,
    // No ContentType here — avoids a CORS preflight on the browser PUT
  });
  return getSignedUrl(r2, command, { expiresIn });
}

// Streams an object from R2 — avoids buffering large files in memory.
// Returns { stream, contentLength } where stream is a Node.js Readable.
async function streamFromStorage(storagePath) {
  const response = await r2.send(
    new GetObjectCommand({
      Bucket: bucket,
      Key: storagePath,
    })
  );
  return { stream: response.Body, contentLength: response.ContentLength };
}

async function getStorageSize(storagePath) {
  const response = await r2.send(new HeadObjectCommand({ Bucket: bucket, Key: storagePath }));
  return response.ContentLength;
}

async function listStoragePage(startAfter = "", maxKeys = 250) {
  const page = await r2.send(new ListObjectsV2Command({
    Bucket: bucket,
    StartAfter: startAfter || undefined,
    MaxKeys: maxKeys,
  }));
  return { objects: page.Contents || [], isTruncated: Boolean(page.IsTruncated) };
}

// Fetches only the first `byteCount` bytes of an object (used to validate FSE1 header)
async function getFirstBytes(storagePath, byteCount = 4) {
  const response = await r2.send(
    new GetObjectCommand({
      Bucket: bucket,
      Key: storagePath,
      Range: `bytes=0-${byteCount - 1}`,
    })
  );
  const chunks = [];
  for await (const chunk of response.Body) {
    chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
  }
  return Buffer.concat(chunks);
}

module.exports = { uploadToStorage, downloadFromStorage, streamFromStorage, getStorageSize, listStoragePage, removeFromStorage, getPresignedPutUrl, getFirstBytes };
