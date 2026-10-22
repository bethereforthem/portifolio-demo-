// Server for the ThickBing Lin Cyber site.
// Serves the HTML pages and exposes server-only routes:
//   - GET  /api/threat-search?q=...      Exa threat-intel search
//   - POST /api/signup | /api/login | /api/logout | GET /api/me
//   - POST /api/forgot-password | /api/reset-password
//   - POST /api/newsletter
// Accounts live in local JSON files (.data/), passwords are scrypt-hashed,
// reset emails go out through Gmail SMTP using credentials from .env.
import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { extname, join, normalize, sep } from "node:path";
import { fileURLToPath } from "node:url";

import { searchThreatIntel, ThreatSearchError } from "./lib/exa-search.mjs";
import {
  addSubscriber,
  authenticate,
  clearAttempts,
  createResetToken,
  createSession,
  createUser,
  consumeResetToken,
  destroySession,
  findUser,
  getSessionUser,
  isStrongPassword,
  isThrottled,
  normalizeEmail,
  publicUser,
  setPassword,
} from "./lib/accounts.mjs";
import { isValidEmail, sendPasswordResetEmail } from "./lib/mailer.mjs";

const ROOT = fileURLToPath(new URL(".", import.meta.url));
const PORT = Number(process.env.PORT) || 3000;

// Load a local .env file when present so `npm start` picks up EXA_API_KEY
// and the Gmail SMTP credentials used for password-reset emails.
try {
  process.loadEnvFile(join(ROOT, ".env"));
} catch {
  // No local env file: rely on the real environment.
}

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".webp": "image/webp",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".mp4": "video/mp4",
};

// Only these top-level entries are public; server code, manifests and env files are not served.
const PUBLIC_ENTRIES = new Set([
  "index.html",
  "login.html",
  "signup.html",
  "forgot-password.html",
  "reset-password.html",
  "dashboard.html",
  "photos",
]);

const SESSION_COOKIE = "tb_session";
const MAX_BODY_BYTES = 64 * 1024; // 64 KB is plenty for auth payloads

function sendJson(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
  });
  res.end(body);
}

function parseCookies(req) {
  const header = req.headers.cookie;
  const jar = {};
  if (!header) return jar;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    const key = part.slice(0, eq).trim();
    if (key) jar[key] = part.slice(eq + 1).trim();
  }
  return jar;
}

function sessionToken(req) {
  return parseCookies(req)[SESSION_COOKIE] ?? null;
}

function setSessionCookie(res, token) {
  // HttpOnly: JavaScript cannot read the session token.
  // SameSite=Lax: blocks cross-site POSTs while keeping normal navigation.
  res.setHeader(
    "set-cookie",
    `${SESSION_COOKIE}=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${7 * 24 * 60 * 60}`,
  );
}

function clearSessionCookie(res) {
  res.setHeader("set-cookie", `${SESSION_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`);
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error("payload too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      try {
        const raw = Buffer.concat(chunks).toString("utf8");
        resolve(raw ? JSON.parse(raw) : {});
      } catch {
        reject(new Error("invalid json"));
      }
    });
    req.on("error", reject);
  });
}

function clientIp(req) {
  return req.socket.remoteAddress ?? "unknown";
}

function resolveStaticPath(pathname) {
  const relative = decodeURIComponent(pathname === "/" ? "/index.html" : pathname);
  const clean = normalize(relative).replace(/^([/\\])+/, "");
  if (!clean || clean.includes("..")) return null;

  const segments = clean.split(/[/\\]/);
  if (!PUBLIC_ENTRIES.has(segments[0])) return null;
  if (segments.some((segment) => segment.startsWith("."))) return null;
  if (segments.length > 1 && !["photos"].includes(segments[0])) return null;

  const filePath = join(ROOT, ...segments);
  if (!filePath.startsWith(ROOT.endsWith(sep) ? ROOT : ROOT + sep)) return null;
  return filePath;
}

async function serveStatic(res, pathname, method) {
  const filePath = resolveStaticPath(pathname);
  if (!filePath) {
    res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
    res.end("Not found");
    return;
  }

  try {
    const info = await stat(filePath);
    if (!info.isFile()) throw new Error("not a file");
    const body = await readFile(filePath);
    res.writeHead(200, {
      "content-type": MIME_TYPES[extname(filePath).toLowerCase()] ?? "application/octet-stream",
      "content-length": body.length,
    });
    res.end(method === "HEAD" ? undefined : body);
  } catch {
    res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
    res.end("Not found");
  }
}

async function handleThreatSearch(res, searchParams) {
  try {
    const { query, results, searchedAt } = await searchThreatIntel(searchParams.get("q"));
    sendJson(res, 200, { query, results, searchedAt });
  } catch (error) {
    const status = error instanceof ThreatSearchError ? error.status : 500;
    const message =
      error instanceof ThreatSearchError
        ? error.message
        : "Threat search failed unexpectedly. Please try again.";
    if (!(error instanceof ThreatSearchError)) console.error("[threat-search]", error);
    sendJson(res, status, { error: message });
  }
}

// --- Auth routes ----------------------------------------------------------

async function handleSignup(req, res) {
  let body;
  try {
    body = await readJsonBody(req);
  } catch {
    return sendJson(res, 400, { error: "Invalid request body." });
  }

  const name = String(body.fullName ?? "").trim();
  const email = normalizeEmail(body.email);
  const phone = String(body.phone ?? "").trim();
  const org = String(body.org ?? "").trim();
  const service = String(body.service ?? "").trim();
  const password = String(body.password ?? "");
  const confirm = String(body.confirm ?? "");

  if (name.length < 2) return sendJson(res, 400, { error: "Please enter your full name." });
  if (!isValidEmail(email)) return sendJson(res, 400, { error: "Please enter a valid email address." });
  if (phone.length < 6) return sendJson(res, 400, { error: "Please enter your phone number." });
  if (org.length < 2) return sendJson(res, 400, { error: "Please enter your organization." });
  if (!service) return sendJson(res, 400, { error: "Please choose a service." });
  if (!isStrongPassword(password)) {
    return sendJson(res, 400, { error: "Password must be at least 8 characters." });
  }
  if (password !== confirm) return sendJson(res, 400, { error: "Passwords do not match." });

  const result = createUser({ name, email, phone, org, service, password });
  if (!result.created) {
    return sendJson(res, 409, {
      error: "An account with this email already exists. Try logging in instead.",
    });
  }

  const token = createSession(email);
  setSessionCookie(res, token);
  console.log(`[auth] account created: ${email}`);
  sendJson(res, 201, { ok: true, user: result.user });
}

async function handleLogin(req, res) {
  let body;
  try {
    body = await readJsonBody(req);
  } catch {
    return sendJson(res, 400, { error: "Invalid request body." });
  }

  const email = normalizeEmail(body.email);
  const password = String(body.password ?? "");
  if (!isValidEmail(email) || !password) {
    return sendJson(res, 400, { error: "Enter your email and password." });
  }

  const throttleKey = `${clientIp(req)}|${email}`;
  if (isThrottled(throttleKey)) {
    return sendJson(res, 429, {
      error: "Too many login attempts. Please wait a few minutes and try again.",
    });
  }

  const user = authenticate(email, password);
  if (!user) {
    return sendJson(res, 401, { error: "Invalid email or password." });
  }

  clearAttempts(throttleKey);
  const token = createSession(email);
  setSessionCookie(res, token);
  console.log(`[auth] login: ${email}`);
  sendJson(res, 200, { ok: true, user: publicUser(user) });
}

async function handleLogout(req, res) {
  destroySession(sessionToken(req));
  clearSessionCookie(res);
  sendJson(res, 200, { ok: true });
}

async function handleMe(req, res) {
  const user = getSessionUser(sessionToken(req));
  if (!user) return sendJson(res, 401, { error: "Not signed in." });
  sendJson(res, 200, { user });
}

async function handleForgotPassword(req, res) {
  let body;
  try {
    body = await readJsonBody(req);
  } catch {
    return sendJson(res, 400, { error: "Invalid request body." });
  }

  const email = normalizeEmail(body.email);
  if (!isValidEmail(email)) {
    return sendJson(res, 400, { error: "Please enter a valid email address." });
  }

  const throttleKey = `${clientIp(req)}|forgot|${email}`;
  if (isThrottled(throttleKey, 5, 15 * 60 * 1000)) {
    return sendJson(res, 429, {
      error: "Too many reset requests. Please wait a few minutes and try again.",
    });
  }

  const user = findUser(email);
  // Always answer success so the endpoint cannot be used to probe which
  // emails are registered — but only send an email when the account exists.
  if (user) {
    const token = createResetToken(email);
    const host = req.headers.host ?? `localhost:${PORT}`;
    const proto = req.socket.encrypted ? "https" : "http";
    const resetUrl = `${proto}://${host}/reset-password.html?token=${token}`;
    try {
      await sendPasswordResetEmail({ to: email, resetUrl, name: user.name });
      console.log(`[auth] reset email sent to ${email}`);
    } catch (error) {
      console.error("[auth] failed to send reset email:", error.message);
      return sendJson(res, 502, {
        error: "We could not send the reset email right now. Please try again later.",
      });
    }
  } else {
    console.log(`[auth] reset requested for unknown address (ignored): ${email}`);
  }
  sendJson(res, 200, { ok: true });
}

async function handleResetPassword(req, res) {
  let body;
  try {
    body = await readJsonBody(req);
  } catch {
    return sendJson(res, 400, { error: "Invalid request body." });
  }

  const token = String(body.token ?? "");
  const password = String(body.password ?? "");
  const confirm = String(body.confirm ?? "");

  if (!isStrongPassword(password)) {
    return sendJson(res, 400, { error: "Password must be at least 8 characters." });
  }
  if (password !== confirm) return sendJson(res, 400, { error: "Passwords do not match." });

  const email = consumeResetToken(token);
  if (!email) {
    return sendJson(res, 400, {
      error: "This reset link is invalid or has expired. Please request a new one.",
    });
  }

  setPassword(email, password);
  console.log(`[auth] password reset completed for ${email}`);
  sendJson(res, 200, { ok: true });
}

async function handleNewsletter(req, res) {
  let body;
  try {
    body = await readJsonBody(req);
  } catch {
    return sendJson(res, 400, { error: "Invalid request body." });
  }
  const email = normalizeEmail(body.email);
  if (!isValidEmail(email)) {
    return sendJson(res, 400, { error: "Please enter a valid email address." });
  }
  const added = addSubscriber(email);
  sendJson(res, 200, { ok: true, already: !added });
}

const POST_ROUTES = {
  "/api/signup": handleSignup,
  "/api/login": handleLogin,
  "/api/logout": handleLogout,
  "/api/forgot-password": handleForgotPassword,
  "/api/reset-password": handleResetPassword,
  "/api/newsletter": handleNewsletter,
};

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);

  if (url.pathname === "/api/threat-search") {
    if (req.method !== "GET") {
      res.writeHead(405, { "content-type": "application/json; charset=utf-8", allow: "GET" });
      res.end(JSON.stringify({ error: "Use GET for threat search." }));
      return;
    }
    await handleThreatSearch(res, url.searchParams);
    return;
  }

  if (url.pathname === "/api/me") {
    if (req.method !== "GET") {
      res.writeHead(405, { "content-type": "application/json; charset=utf-8", allow: "GET" });
      res.end(JSON.stringify({ error: "Use GET for session info." }));
      return;
    }
    await handleMe(req, res);
    return;
  }

  const postHandler = POST_ROUTES[url.pathname];
  if (postHandler) {
    if (req.method !== "POST") {
      res.writeHead(405, { "content-type": "application/json; charset=utf-8", allow: "POST" });
      res.end(JSON.stringify({ error: "Use POST for this route." }));
      return;
    }
    await postHandler(req, res);
    return;
  }

  // The dashboard is members-only: without a valid session, send them to login.
  if (url.pathname === "/dashboard.html") {
    const user = getSessionUser(sessionToken(req));
    if (!user) {
      res.writeHead(302, { location: "/login.html?next=dashboard", "cache-control": "no-store" });
      res.end();
      return;
    }
  }

  if (req.method === "GET" || req.method === "HEAD") {
    await serveStatic(res, url.pathname, req.method);
    return;
  }

  res.writeHead(405, { "content-type": "text/plain; charset=utf-8", allow: "GET, HEAD" });
  res.end("Method not allowed");
});

server.listen(PORT, () => {
  console.log(`ThickBing Lin Cyber site running at http://localhost:${PORT}`);
  if (!process.env.EXA_API_KEY) {
    console.warn("EXA_API_KEY is not set — the threat-intel search will report a configuration error.");
  }
  if (!process.env.GMAIL_USER || !process.env.GMAIL_APP_PASSWORD) {
    console.warn("GMAIL_USER / GMAIL_APP_PASSWORD not set — password-reset emails will be unavailable.");
  }
});
