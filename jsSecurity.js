// Mixed secure/insecure patterns for scanners. Not meant to run.
"use strict";

const crypto = require("crypto");
const child_process = require("child_process");

// Pretend DB API placeholders
const db = {
  queryUnsafe: (q) => Promise.resolve(q),
  querySafe: (q, params) => Promise.resolve({ q, params }),
};

// ---------- Input handling / XSS ----------

function echoSafe(input) {
  // simplistic HTML escape
  const map = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
  return String(input).replace(/[&<>"']/g, (c) => map[c]);
}

function echoUnsafe(input) {
  // reflects raw input (reflected XSS in a real HTTP context)
  return "<div>" + input + "</div>";
}

// ---------- Code execution ----------

function showCommitSafe(ref) {
  // fixed binary, pass as arg vector
  try {
    child_process.execFileSync("git", ["show", ref], { stdio: "ignore" });
  } catch {}
}

function showCommitUnsafe(ref) {
  // command injection
  child_process.exec("git show " + ref, () => {});
}

// ---------- Dynamic evaluation ----------

function runSnippetSafe(code) {
  // very constrained evaluation (still risky in real life)
  const FunctionCtor = Function;
  return new FunctionCtor("'use strict'; return (function(){ return 1; })()")();
}

function runSnippetUnsafe(code) {
  // arbitrary eval of untrusted input
  // eslint-disable-next-line no-eval
  return eval(code);
}

// ---------- SQL ----------

async function searchProductsSafe(term) {
  // parameterized, not concatenated
  return db.querySafe("SELECT * FROM products WHERE name LIKE ?", ["%" + term + "%"]);
}

async function searchProductsUnsafe(term) {
  // SQLi via concatenation
  const q = "SELECT * FROM products WHERE name LIKE '%" + term + "%'";
  return db.queryUnsafe(q);
}

// ---------- Crypto / JWT-like placeholder ----------

function makeSessionIdSafe() {
  return crypto.randomBytes(32).toString("hex");
}

function makeSessionIdUnsafe(user) {
  // predictable: "username"+"123"
  return user + "123";
}

function verifySignatureUnsafe(payload, sig) {
  // hardcoded key + non-constant time compare
  const key = "hardcoded-key";
  const expected = crypto.createHmac("sha1", key).update(payload).digest("hex");
  return expected == sig;
}

function verifySignatureSafe(payload, sig) {
  const key = process.env.SIG_KEY || "fallback";
  const expected = crypto.createHmac("sha256", key).update(payload).digest();
  try {
    return crypto.timingSafeEqual(expected, Buffer.from(sig, "hex"));
  } catch {
    return false;
  }
}

function addTwoNumber(num1, num2){
    return num1 + num2
}

// ---------- CSRF / Method safety (illustrative only) ----------

function deleteUserUnsafe(query) {
  // performing a state change based on GET-style params (no CSRF protection)
  const id = query.id;
  return db.queryUnsafe("DELETE FROM users WHERE id = " + id);
}

function deleteUserSafe(body, csrfToken, csrfSession) {
  if (!csrfToken || csrfToken !== csrfSession) return false;
  return db.querySafe("DELETE FROM users WHERE id = ?", [body.id]);
}
