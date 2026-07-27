// Plaintext waitlist model. Server sees email/name/role and stores them in
// Supabase. The user opted in by submitting the form on /download.

const supabase = require("../lib/supabase");

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MAX_NAME = 200;
const MAX_ROLE = 200;

function sanitizeText(v, max) {
  if (typeof v !== "string") return null;
  const t = v.trim().slice(0, max);
  return t.length ? t : null;
}

function normalizeEmail(v) {
  if (typeof v !== "string") return null;
  const t = v.trim().toLowerCase().slice(0, 320);
  return EMAIL_RE.test(t) ? t : null;
}

async function addSignup({ email, name, role, ip, userAgent } = {}) {
  const safeEmail = normalizeEmail(email);
  if (!safeEmail) {
    const err = new Error("Invalid email.");
    err.code = "INVALID_EMAIL";
    throw err;
  }
  const safeName = sanitizeText(name, MAX_NAME);
  const safeRole = sanitizeText(role, MAX_ROLE);

  const { data, error } = await supabase
    .from("waitlist_signups")
    .insert({
      email: safeEmail,
      name: safeName,
      role: safeRole,
      ip: ip || null,
      user_agent: (userAgent || "").slice(0, 500) || null,
      status: "confirmed",
      confirmed_at: new Date().toISOString(),
    })
    .select("id, email, name, role, created_at")
    .single();

  if (error) throw error;
  return data;
}

// Find an existing signup (used to detect duplicates and answer the user
// with "you've already joined" without exposing anyone else's row).
async function findByEmail(email) {
  const safeEmail = normalizeEmail(email);
  if (!safeEmail) return null;
  const { data, error } = await supabase
    .from("waitlist_signups")
    .select("id, email, name, role, created_at")
    .ilike("email", safeEmail)
    .maybeSingle();
  if (error) throw error;
  return data || null;
}

async function countSignups() {
  const { count, error } = await supabase
    .from("waitlist_signups")
    .select("id", { count: "exact", head: true });
  if (error) {
    console.warn("[waitlist] count error:", error.message);
    return null;
  }
  return count;
}

module.exports = { addSignup, findByEmail, countSignups };
