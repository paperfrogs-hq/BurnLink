const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const { Readable } = require("node:stream");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const crypto = require("node:crypto");

require("dotenv").config({ override: true });
const storage = require("../lib/r2");
const File = require("../models/File");
const supabase = require("../lib/supabase");

const objects = new Map();
const rows = new Map();
const cliRows = new Map();
const events = [];
let deleteFailure = false;
let stalledPath = null;
let failedBurnId = null;
let deletionGate = null;

storage.streamFromStorage = async (key) => {
  const value = objects.get(key);
  if (!value) throw new Error("NoSuchKey");
  events.push(`open:${key}`);
  if (key === stalledPath) {
    const stream = new Readable({
      read() {
        if (!this.sent) {
          this.sent = true;
          this.push(value.subarray(0, 2));
        }
      },
    });
    return { stream, contentLength: value.length };
  }
  return { stream: Readable.from([value.subarray(0, 2), value.subarray(2)]), contentLength: value.length };
};
storage.getStorageSize = async key => objects.get(key)?.length;
storage.downloadFromStorage = async key => {
  const value = objects.get(key);
  if (!value) throw new Error("NoSuchKey");
  return value;
};
storage.removeFromStorage = async (key) => {
  events.push(`delete:${key}`);
  if (deletionGate?.path === key) {
    deletionGate.started();
    await deletionGate.permit;
  }
  if (deleteFailure) throw new Error("R2 unavailable");
  objects.delete(key);
};
File.findById = async (id) => rows.get(id) || null;
File.findByBundleId = async (id) => [...rows.values()].filter(row => row.bundleId === id);
supabase.from = () => ({
  select: () => ({ eq: () => ({ maybeSingle: async () => ({ data: null, error: null }) }) }),
  upsert: async () => ({ error: null }),
});
supabase.rpc = async (name, params) => {
  if (name === "burn_cli_file") {
    const row = cliRows.get(params.cli_id);
    if (!row) return { data: [], error: null };
    if (row.burn_after_read) cliRows.delete(params.cli_id);
    return { data: [row], error: null };
  }
  const id = params.file_id;
  if (id === failedBurnId) return { data: [], error: null };
  const row = rows.get(id);
  if (!row) return { data: [], error: null };
  rows.delete(id);
  events.push(`burn:${row.path}`);
  return { data: [row], error: null };
};

const app = require("../app");
const serverless = require("serverless-http");
let server;
let port;

test.before(async () => {
  server = http.createServer(app);
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  port = server.address().port;
});

test.after(async () => {
  await new Promise(resolve => server.close(resolve));
});

async function request(path, method = "GET", headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ hostname: "127.0.0.1", port, path, method, headers }, res => {
      const chunks = [];
      res.on("data", chunk => chunks.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
      res.on("error", reject);
    });
    req.on("error", reject);
    req.end();
  });
}

const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
process.env.BURNLINK_ISSUER_PUB = publicKey.export({ type: "spki", format: "pem" });
const checksum = crypto.createHash("sha256").update("STD:AAAA-BBBB").digest("hex").toUpperCase().slice(0, 4);
const licenseBody = `BURNLINK-STD-AAAA-BBBB-${checksum}`;
const license = `${licenseBody}.${crypto.sign(null, Buffer.from(licenseBody), privateKey).toString("base64url")}`;

function parseTransfer(body) {
  const length = body.readUInt32BE(0);
  const metadata = JSON.parse(body.subarray(4, 4 + length).toString());
  let offset = 4 + length;
  return metadata.files.map(file => {
    const payload = body.subarray(offset, offset + file.size);
    offset += file.size;
    return { name: file.fileName, payload };
  });
}

function parseInBrowser(bytes) {
  const template = fs.readFileSync(path.join(__dirname, "../views/password.ejs"), "utf8");
  const start = template.indexOf("function parseOneTimeTransfer(bytes)");
  const end = template.indexOf("async function streamWithProgress", start);
  assert.ok(start >= 0 && end > start);
  const context = { TextDecoder, DataView, Number, JSON };
  vm.runInNewContext(template.slice(start, end), context);
  return context.parseOneTimeTransfer(new Uint8Array(bytes));
}

test("one-time read deletes R2 on the server and exposes no reusable URL", async () => {
  const id = "fa1391f1-847e-4535-bf09-ec6474bfdafd";
  const path = "2026-10-22/fa1391f1-847e-4535-bf09-ec6474bfdafd-secret.txt";
  rows.set(id, { id, path, originalName: "secret.txt" });
  objects.set(path, Buffer.from("encrypted-bytes"));

  const first = await request(`/s/${id}/raw`);
  assert.equal(first.status, 200);
  assert.equal(first.headers["cache-control"], "no-store");
  assert.deepEqual(parseTransfer(first.body).map(f => [f.name, f.payload.toString()]), [["secret.txt", "encrypted-bytes"]]);
  assert.equal(Buffer.from(parseInBrowser(first.body)[0].payload).toString(), "encrypted-bytes");
  assert.equal(objects.has(path), false);
  assert.ok(events.indexOf(`open:${path}`) < events.indexOf(`burn:${path}`));
  assert.ok(events.indexOf(`burn:${path}`) < events.indexOf(`delete:${path}`));
  assert.doesNotMatch(first.body.toString(), /downloadUrl|cleanupToken|r2\.cloudflarestorage\.com/);

  const second = await request(`/s/${id}/raw`);
  assert.equal(second.status, 404);
  assert.equal((await request("/api/r2-cleanup", "POST")).status, 404);
});

test("concurrent readers cannot both receive a one-time payload", async () => {
  const id = "a370e343-c1f9-4dbc-bd10-ece5cc85c92d";
  const path = `2026-10-22/${id}-race.txt`;
  rows.set(id, { id, path, originalName: "race.txt" });
  objects.set(path, Buffer.from("race-ciphertext"));
  const responses = await Promise.all([
    request(`/s/${id}/raw`),
    request(`/s/${id}/raw`),
  ]);
  assert.equal(responses.filter(response => response.status === 200).length, 1);
  assert.ok(responses.some(response => response.status === 404 || response.status === 410));
  assert.equal(objects.has(path), false);
  assert.equal(events.filter(event => event === `delete:${path}`).length, 1);
});

test("bundle read deletes every object and returns every encrypted payload", async () => {
  const bundleId = "e73806a9-282d-4a06-964b-43aedf8e7059";
  const ids = ["75425399-0103-4707-8173-4a1847ecb485", "d48b670d-b8ce-47bc-8afc-9dbd96b53ad7"];
  ids.forEach((id, index) => {
    const path = `2026-10-22/${id}-file${index}.txt`;
    rows.set(id, { id, path, originalName: `file${index}.txt`, bundleId });
    objects.set(path, Buffer.from(`cipher${index}`));
  });

  const response = await request(`/s/${ids[0]}/raw`);
  assert.equal(response.status, 200);
  assert.deepEqual(parseTransfer(response.body).map(f => [f.name, f.payload.toString()]), [
    ["file0.txt", "cipher0"], ["file1.txt", "cipher1"],
  ]);
  assert.deepEqual(Array.from(parseInBrowser(response.body), f => Buffer.from(f.payload).toString()), ["cipher0", "cipher1"]);
  for (const id of ids) assert.equal([...objects.keys()].some(key => key.includes(id)), false);
});

test("legacy raw routes burn every bundle member", async () => {
  for (const method of ["GET", "POST"]) {
    const bundleId = crypto.randomUUID();
    const ids = [crypto.randomUUID(), crypto.randomUUID()];
    const paths = ids.map((id, index) => `2026-10-22/${id}-legacy${index}.txt`);
    ids.forEach((id, index) => {
      rows.set(id, { id, path: paths[index], originalName: `legacy${index}.txt`, bundleId });
      objects.set(paths[index], Buffer.from(`legacy-cipher${index}`));
    });

    const response = await request(`/file/${ids[0]}/raw`, method);
    assert.equal(response.status, 200);
    assert.deepEqual(parseTransfer(response.body).map(f => f.payload.toString()),
      ["legacy-cipher0", "legacy-cipher1"]);
    for (const id of ids) assert.equal(rows.has(id), false);
    for (const path of paths) assert.equal(objects.has(path), false);
    assert.equal((await request(`/s/${ids[1]}/raw`)).status, 404);
  }
});

test("explicit burn routes delete the complete bundle", async () => {
  for (const route of ["s", "file"]) {
    const bundleId = crypto.randomUUID();
    const ids = [crypto.randomUUID(), crypto.randomUUID()];
    const paths = ids.map((id, index) => `2026-10-22/${id}-burn${index}.txt`);
    ids.forEach((id, index) => {
      rows.set(id, { id, path: paths[index], originalName: `burn${index}.txt`, bundleId });
      objects.set(paths[index], Buffer.from(`burn-cipher${index}`));
    });

    const response = await request(`/${route}/${ids[0]}/burn`, "POST");
    assert.equal(response.status, 200);
    for (const id of ids) assert.equal(rows.has(id), false);
    for (const path of paths) assert.equal(objects.has(path), false);
  }
});

test("R2 deletion failure prevents a complete transfer", async () => {
  const id = "cd64c98e-c051-41a6-9c55-f76a87016cf6";
  const path = `2026-10-22/${id}-failure.txt`;
  rows.set(id, { id, path, originalName: "failure.txt" });
  objects.set(path, Buffer.from("encrypted-payload"));
  deleteFailure = true;
  await assert.rejects(request(`/s/${id}/raw`));
  deleteFailure = false;
  assert.equal(objects.has(path), true);
});

test("a complete payload is withheld until R2 deletion succeeds", async () => {
  const id = "b5afcb23-d0b7-4ec4-ac95-8a309437d781";
  const path = `2026-10-22/${id}-gated.txt`;
  rows.set(id, { id, path, originalName: "gated.txt" });
  objects.set(path, Buffer.from("encrypted-payload"));
  let startDeletion;
  let releaseDeletion;
  const started = new Promise(resolve => { startDeletion = resolve; });
  const permit = new Promise(resolve => { releaseDeletion = resolve; });
  deletionGate = { path, started: startDeletion, permit };
  let received = 0;
  const expected = 4 + Buffer.byteLength(JSON.stringify({
    files: [{ fileName: "gated.txt", size: Buffer.byteLength("encrypted-payload") }],
  })) + Buffer.byteLength("encrypted-payload");
  let completed = false;
  try {
    const transfer = new Promise((resolve, reject) => {
      const req = http.get({ hostname: "127.0.0.1", port, path: `/s/${id}/raw` }, res => {
        res.on("data", chunk => { received += chunk.length; });
        res.on("end", () => { completed = true; resolve(); });
        res.on("error", reject);
      });
      req.on("error", reject);
    });
    await started;
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(objects.has(path), true);
    assert.equal(completed, false);
    assert.ok(received < expected);
    releaseDeletion();
    await transfer;
    assert.equal(objects.has(path), false);
    assert.ok(received > 0);
  } finally {
    releaseDeletion();
    deletionGate = null;
  }
});

test("unreadable storage object does not burn the database link", async () => {
  const id = "eb3c7c47-df1d-4fe5-87d2-d3ae64c373b0";
  const path = `2026-10-22/${id}-missing.txt`;
  rows.set(id, { id, path, originalName: "missing.txt" });
  const response = await request(`/s/${id}/raw`);
  assert.equal(response.status, 500);
  assert.equal(rows.has(id), true);
  assert.equal(events.includes(`burn:${path}`), false);
});

test("partial bundle burn releases no content and deletes only rows it burned", async () => {
  const bundleId = "74434535-d540-48bd-bb4b-012283642d3a";
  const ids = ["d2160bc4-5c13-417c-bc9d-b3895e83fb1b", "45445729-801a-4511-a9cd-16c054c6dbeb"];
  const paths = ids.map((id, i) => `2026-10-22/${id}-partial${i}.txt`);
  ids.forEach((id, i) => {
    rows.set(id, { id, path: paths[i], originalName: `partial${i}.txt`, bundleId });
    objects.set(paths[i], Buffer.from(`cipher${i}`));
  });
  failedBurnId = ids[1];
  try {
    const response = await request(`/s/${ids[0]}/raw`);
    assert.equal(response.status, 410);
    assert.equal(objects.has(paths[0]), false);
    assert.equal(objects.has(paths[1]), true);
  } finally {
    failedBurnId = null;
  }
});

test("Netlify size guard keeps an oversized one-time link intact", async () => {
  const id = "92d0f657-99f9-46ea-9e19-650f5d2a1947";
  const path = `2026-10-22/${id}-large.txt`;
  rows.set(id, { id, path, originalName: "large.txt" });
  objects.set(path, Buffer.alloc(4 * 1024 * 1024 + 1));
  process.env.NETLIFY = "true";
  try {
    const response = await request(`/s/${id}/raw`);
    assert.equal(response.status, 413);
    assert.equal(rows.has(id), true);
    assert.equal(objects.has(path), true);
  } finally {
    delete process.env.NETLIFY;
  }
});

test("client disconnect still triggers server-side object deletion", async () => {
  const id = "6044da2b-eb12-4735-b19e-8df541f7291c";
  const path = `2026-10-22/${id}-abort.txt`;
  rows.set(id, { id, path, originalName: "abort.txt" });
  objects.set(path, Buffer.from("encrypted-payload"));
  stalledPath = path;
  try {
    await new Promise((resolve, reject) => {
      const req = http.get({ hostname: "127.0.0.1", port, path: `/s/${id}/raw` }, res => {
        res.once("data", () => res.destroy());
        res.once("close", resolve);
      });
      req.once("error", reject);
    });
    await new Promise(resolve => setTimeout(resolve, 10));
    assert.equal(objects.has(path), false);
  } finally {
    stalledPath = null;
  }
});

test("serverless adapter completes a small secure transfer", async () => {
  const id = "9d4be49a-df9b-456d-82a7-733083fa1246";
  const path = `2026-10-22/${id}-small.txt`;
  rows.set(id, { id, path, originalName: "small.txt" });
  objects.set(path, Buffer.from("ciphertext"));
  const handler = serverless(app);
  process.env.NETLIFY = "true";
  let timeout;
  try {
    const response = await Promise.race([
      handler({ httpMethod: "GET", path: `/s/${id}/raw`, headers: {}, requestContext: {} }, {}),
      new Promise((_, reject) => {
        timeout = setTimeout(() => reject(new Error("serverless transfer timed out")), 1000);
      }),
    ]);
    assert.equal(response.statusCode, 200);
    const body = Buffer.from(response.body, response.isBase64Encoded ? "base64" : "utf8");
    assert.equal(parseTransfer(body)[0].payload.toString(), "ciphertext");
    assert.equal(objects.has(path), false);
  } finally {
    clearTimeout(timeout);
    delete process.env.NETLIFY;
  }
});

test("serverless adapter fails closed when R2 deletion fails", async () => {
  const id = "640ed22d-40dc-4796-8f83-bb2af2661d45";
  const path = `2026-10-22/${id}-delete-failure.txt`;
  rows.set(id, { id, path, originalName: "delete-failure.txt" });
  objects.set(path, Buffer.from("secret-ciphertext"));
  deleteFailure = true;
  process.env.NETLIFY = "true";
  try {
    const response = await serverless(app)(
      { httpMethod: "GET", path: `/s/${id}/raw`, headers: {}, requestContext: {} },
      {}
    );
    assert.equal(response.statusCode, 500);
    assert.doesNotMatch(response.body, /secret-ciphertext/);
    assert.equal(objects.has(path), true);
  } finally {
    deleteFailure = false;
    delete process.env.NETLIFY;
  }
});

test("CLI one-time read removes its R2 object; repeatable CLI read retains it", async () => {
  const headers = { "x-license-key": license };
  const oneTimeId = "ABCDEFGHIJKL";
  const repeatableId = "MNOPQRSTUVWX";
  const oneTimePath = `cli/${oneTimeId}`;
  const repeatablePath = `cli/${repeatableId}`;
  cliRows.set(oneTimeId, { path: oneTimePath, original_name: "once.txt", burn_after_read: true });
  cliRows.set(repeatableId, { path: repeatablePath, original_name: "again.txt", burn_after_read: false });
  objects.set(oneTimePath, Buffer.from("once-ciphertext"));
  objects.set(repeatablePath, Buffer.from("repeatable-ciphertext"));

  const first = await request(`/api/cli/object/${oneTimeId}`, "GET", headers);
  assert.equal(first.status, 200);
  assert.equal(Buffer.from(JSON.parse(first.body.toString()).payload, "base64url").toString(), "once-ciphertext");
  assert.equal(objects.has(oneTimePath), false);
  assert.equal((await request(`/api/cli/object/${oneTimeId}`, "GET", headers)).status, 404);

  assert.equal((await request(`/api/cli/object/${repeatableId}`, "GET", headers)).status, 200);
  assert.equal((await request(`/api/cli/object/${repeatableId}`, "GET", headers)).status, 200);
  assert.equal(objects.has(repeatablePath), true);
});

test("CLI deletion failure never returns the one-time payload", async () => {
  const id = "ZYXWVUTSRQPO";
  const path = `cli/${id}`;
  cliRows.set(id, { path, original_name: "failed.txt", burn_after_read: true });
  objects.set(path, Buffer.from("secret-cli-ciphertext"));
  deleteFailure = true;
  try {
    const response = await request(`/api/cli/object/${id}`, "GET", { "x-license-key": license });
    assert.equal(response.status, 500);
    assert.doesNotMatch(response.body.toString(), /secret-cli-ciphertext/);
    assert.equal(objects.has(path), true);
  } finally {
    deleteFailure = false;
  }
});
