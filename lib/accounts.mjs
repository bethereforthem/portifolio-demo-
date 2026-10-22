// File-based account store for ThickBing Lin Cyber.
// No database: users, sessions, reset tokens and subscribers live in JSON files
// under .data/ (gitignored, never served). Passwords are scrypt-hashed with a
// per-user random salt — plaintext passwords are never stored or logged.
import { randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const DATA_DIR = join(ROOT, ".data");

const USERS_FILE = join(DATA_DIR, "users.json");
const SESSIONS_FILE = join(DATA_DIR, "sessions.json");
const RESETS_FILE = join(DATA_DIR, "reset-tokens.json");
const SUBSCRIBERS_FILE = join(DATA_DIR, "subscribers.json");

mkdirSync(DATA_DIR, { recursive: true });

function readJson(path, fallback) {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    return fallback;
  }
}

function writeJson(path, value) {
  writeFileSync(path, JSON.stringify(value, null, 2), { mode: 0o600 });
}

// --- Password hashing (scrypt) -------------------------------------------

const SCRYPT_KEYLEN = 64;

function hashPassword(password) {
  const salt = randomBytes(16).toString("hex");
  const hash = scryptSync(password, salt, SCRYPT_KEYLEN).toString("hex");
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, hash] = String(stored).split(":");
  if (!salt || !hash) return false;
  const candidate = scryptSync(password, salt, SCRYPT_KEYLEN);
  const expected = Buffer.from(hash, "hex");
  return candidate.length === expected.length && timingSafeEqual(candidate, expected);
}

export function isStrongPassword(password) {
  return typeof password === "string" && password.length >= 8;
}

export function normalizeEmail(email) {
  return String(email ?? "").trim().toLowerCase();
}

// --- Users ----------------------------------------------------------------

export function findUser(email) {
  const users = readJson(USERS_FILE, {});
  return users[normalizeEmail(email)] ?? null;
}

export function createUser({ name, email, phone, org, service, password }) {
  const key = normalizeEmail(email);
  const users = readJson(USERS_FILE, {});
  if (users[key]) return { created: false, reason: "exists" };
  users[key] = {
    name: String(name).trim(),
    email: key,
    phone: String(phone).trim(),
    org: String(org).trim(),
    service: String(service),
    passwordHash: hashPassword(password),
    createdAt: new Date().toISOString(),
  };
  writeJson(USERS_FILE, users);
  return { created: true, user: publicUser(users[key]) };
}

export function setPassword(email, password) {
  const users = readJson(USERS_FILE, {});
  const key = normalizeEmail(email);
  if (!users[key]) return false;
  users[key].passwordHash = hashPassword(password);
  users[key].passwordChangedAt = new Date().toISOString();
  writeJson(USERS_FILE, users);
  return true;
}

export function publicUser(user) {
  if (!user) return null;
  const { passwordHash, ...safe } = user;
  return safe;
}

export function authenticate(email, password) {
  const users = readJson(USERS_FILE, {});
  const user = users[normalizeEmail(email)];
  if (!user) return null;
  return verifyPassword(password, user.passwordHash) ? user : null;
}

// --- Sessions (server-side, HttpOnly cookie) ------------------------------

export function createSession(email) {
  const token = randomBytes(32).toString("hex");
  const sessions = readJson(SESSIONS_FILE, {});
  sessions[token] = {
    email: normalizeEmail(email),
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(), // 7 days
  };
  writeJson(SESSIONS_FILE, sessions);
  return token;
}

export function getSessionUser(token) {
  if (!token) return null;
  const sessions = readJson(SESSIONS_FILE, {});
  const session = sessions[token];
  if (!session) return null;
  if (new Date(session.expiresAt).getTime() < Date.now()) {
    delete sessions[token];
    writeJson(SESSIONS_FILE, sessions);
    return null;
  }
  const users = readJson(USERS_FILE, {});
  return publicUser(users[session.email]);
}

export function destroySession(token) {
  if (!token) return;
  const sessions = readJson(SESSIONS_FILE, {});
  delete sessions[token];
  writeJson(SESSIONS_FILE, sessions);
}

// --- Password-reset tokens (single use, 30 min) ---------------------------

export function createResetToken(email) {
  const token = randomBytes(24).toString("hex");
  const resets = readJson(RESETS_FILE, {});
  resets[token] = {
    email: normalizeEmail(email),
    used: false,
    expiresAt: new Date(Date.now() + 30 * 60 * 1000).toISOString(),
  };
  writeJson(RESETS_FILE, resets);
  return token;
}

export function consumeResetToken(token) {
  if (!token) return null;
  const resets = readJson(RESETS_FILE, {});
  const entry = resets[token];
  if (!entry || entry.used || new Date(entry.expiresAt).getTime() < Date.now()) {
    return null;
  }
  entry.used = true; // single use
  writeJson(RESETS_FILE, resets);
  return entry.email;
}

// --- Newsletter subscribers ------------------------------------------------

export function addSubscriber(email) {
  const key = normalizeEmail(email);
  const list = readJson(SUBSCRIBERS_FILE, []);
  if (!list.includes(key)) {
    list.push(key);
    writeJson(SUBSCRIBERS_FILE, list);
    return true;
  }
  return false;
}

// --- Login throttling (in-memory, best effort) ----------------------------

const attempts = new Map(); // key -> { count, resetAt }

export function isThrottled(key, max = 8, windowMs = 10 * 60 * 1000) {
  const now = Date.now();
  const entry = attempts.get(key);
  if (!entry || entry.resetAt < now) {
    attempts.set(key, { count: 1, resetAt: now + windowMs });
    return false;
  }
  entry.count += 1;
  return entry.count > max;
}

export function clearAttempts(key) {
  attempts.delete(key);
}
