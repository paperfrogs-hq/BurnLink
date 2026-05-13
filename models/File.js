const bcrypt = require("bcryptjs");
const supabase = require("../lib/supabase");
const { validators } = require("../lib/security");

const filesTable = process.env.SUPABASE_FILES_TABLE || "files";
const PASSWORD_MIN_LENGTH = 4;

function mapRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    path: row.path,
    originalName: row.original_name,
    password: row.password,
    failedAttempts: row.failed_attempts || 0,
    lockedUntil: row.locked_until || null,
    mode: row.mode || "download",
    expiresAt: row.expires_at || null,
    linkKey: row.link_key || null,
    bundleId: row.bundle_id || null,
  };
}

async function createFile({ 
  path, 
  originalName, 
  password, 
  mode = "download", 
  linkKey = null,
  bundleId = null,
}) {
  // Validate inputs
  if (!path || typeof path !== "string") {
    throw new Error("Invalid path");
  }
  if (!validators.isValidStoragePath(path)) {
    throw new Error("Path must be in format YYYY-MM-DD/UUID-filename");
  }

  if (originalName && typeof originalName !== "string") {
    throw new Error("Invalid originalName");
  }



  if (password) {
    if (typeof password !== "string") {
      throw new Error("Invalid password");
    }
    if (password.length < PASSWORD_MIN_LENGTH) {
      throw new Error(`Password must be at least ${PASSWORD_MIN_LENGTH} characters`);
    }
    if (password.length > 255) {
      throw new Error("Password too long");
    }
    if (/\s/.test(password)) {
      throw new Error("Password cannot contain spaces");
    }
  }

  if (mode && !["download", "view-once"].includes(mode)) {
    throw new Error("Invalid mode: must be 'download' or 'view-once'");
  }

  if (linkKey && !validators.isValidLinkKey(linkKey)) {
    throw new Error("Invalid link key");
  }

  const hashedPassword = password ? await bcrypt.hash(password, 10) : null;

  const { data, error } = await supabase
    .from(filesTable)
    .insert({
      path,
      original_name: originalName,
      password: hashedPassword,
      failed_attempts: 0,
      locked_until: null,
      mode,
      expires_at: null,
      link_key: linkKey || null,
      bundle_id: bundleId || null,
    })
    .select("*")
    .single();

  if (error) {
    throw new Error(error.message);
  }

  return mapRow(data);
}

async function findFileById(id) {
  const { data, error } = await supabase
    .from(filesTable)
    .select("*")
    .eq("id", id)
    .maybeSingle();

  if (error) {
    throw new Error(error.message);
  }

  return mapRow(data);
}

async function findFilesByBundleId(bundleId) {
  const { data, error } = await supabase
    .from(filesTable)
    .select("*")
    .eq("bundle_id", bundleId)
    .order("created_at", { ascending: true });

  if (error) {
    throw new Error(error.message);
  }

  return data ? data.map(mapRow) : [];
}

async function updateLockState(id, failedAttempts, lockedUntil) {
  const { error } = await supabase
    .from(filesTable)
    .update({
      failed_attempts: failedAttempts,
      locked_until: lockedUntil,
    })
    .eq("id", id);

  if (error) {
    throw new Error(error.message);
  }
}

async function deleteFileById(id) {
  const { data, error } = await supabase
    .from(filesTable)
    .delete()
    .eq("id", id)
    .select("id")
    .maybeSingle();

  if (error) {
    throw new Error(error.message);
  }

  return Boolean(data);
}

function comparePassword(file, password) {
  return bcrypt.compare(password, file.password);
}

module.exports = {
  createFile,
  findById: findFileById,
  findByBundleId: findFilesByBundleId,
  deleteById: deleteFileById,
  updateLockState,
  comparePassword,
};
