const bcrypt = require("bcrypt");
const { createClient } = require("@supabase/supabase-js");

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const filesTable = process.env.SUPABASE_FILES_TABLE || "files";

if (!supabaseUrl) {
  throw new Error("SUPABASE_URL is missing in .env");
}

if (!supabaseKey) {
  throw new Error("SUPABASE_SERVICE_ROLE_KEY is missing in .env");
}

if (supabaseUrl.includes("YOUR_PROJECT_REF")) {
  throw new Error("SUPABASE_URL is still a placeholder. Set your real project URL.");
}

if (supabaseKey.includes("YOUR_SUPABASE_SERVICE_ROLE_KEY")) {
  throw new Error(
    "SUPABASE_SERVICE_ROLE_KEY is still a placeholder. Set your real service role key."
  );
}

const supabase = createClient(supabaseUrl, supabaseKey);

function mapRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    path: row.path,
    originalName: row.original_name,
    password: row.password,
  };
}

async function createFile({ path, originalName, password }) {
  const hashedPassword = password ? await bcrypt.hash(password, 10) : null;

  const { data, error } = await supabase
    .from(filesTable)
    .insert({
      path,
      original_name: originalName,
      password: hashedPassword,
    })
    .select("id, path, original_name, password")
    .single();

  if (error) {
    throw new Error(error.message);
  }

  return mapRow(data);
}

async function findFileById(id) {
  const { data, error } = await supabase
    .from(filesTable)
    .select("id, path, original_name, password")
    .eq("id", id)
    .maybeSingle();

  if (error) {
    throw new Error(error.message);
  }

  return mapRow(data);
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
  deleteById: deleteFileById,
  comparePassword,
};
