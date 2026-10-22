// Small static server for the ThickBing Lin Cyber site.
// It serves the existing HTML pages and exposes one server-only route,
// GET /api/threat-search?q=..., which searches the web through Exa.
import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { extname, join, normalize, sep } from "node:path";
import { fileURLToPath } from "node:url";

import { searchThreatIntel, ThreatSearchError } from "./lib/exa-search.mjs";

const ROOT = fileURLToPath(new URL(".", import.meta.url));
const PORT = Number(process.env.PORT) || 3000;

// Load a local .env file when present so `npm start` picks up EXA_API_KEY.
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
  "photos",
]);

function sendJson(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
  });
  res.end(body);
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
});
