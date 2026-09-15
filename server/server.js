import "./env.js";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import express from "express";
import cors from "cors";
import { WebSocketServer } from "ws";

import * as db from "./db.js";
import authRoutes from "./routes/auth.js";
import sourceRoutes from "./routes/sources.js";
import dataRoutes from "./routes/data.js";
import adminRoutes from "./routes/admin.js";
import { resolveToken } from "./middleware/auth.js";
import { startUdpIngestListener, startTcpIngestListener } from "./ingest.js";

// `npm run dev` passes --dev: the dashboard is compiled on the fly by Vite
// with hot reload. `npm start` serves the production build from dist/.
const IS_DEV = process.argv.includes("--dev");
const ROOT = path.resolve(import.meta.dirname, "..");
const PLACEHOLDER_SECRET = "change_this_to_a_long_random_string";

if (!process.env.JWT_SECRET) {
  console.error("Missing JWT_SECRET - copy .env.example to .env (or set it in your host's environment). Exiting.");
  process.exit(1);
}
if (process.env.JWT_SECRET === PLACEHOLDER_SECRET || process.env.JWT_SECRET.length < 32) {
  const msg = "JWT_SECRET is the example value or shorter than 32 characters. Generate one with: node -e \"console.log(require('crypto').randomBytes(48).toString('hex'))\"";
  if (!IS_DEV) {
    console.error(`${msg}. Refusing to start in production.`);
    process.exit(1);
  }
  console.warn(`Warning: ${msg}`);
}

const app = express();
app.disable("x-powered-by");

// Behind a reverse proxy / PaaS load balancer (Nginx, Render, Railway...)
// this makes req.ip the real client IP, which rate limits rely on. Never set
// it when clients connect directly, or they could fake their IP.
if (process.env.TRUST_PROXY) {
  const v = process.env.TRUST_PROXY;
  app.set("trust proxy", /^\d+$/.test(v) ? Number(v) : v === "true" ? true : v);
}

// The dashboard is served from this same server, so CORS is only needed if
// you deliberately host it on a different domain.
if (process.env.CORS_ORIGIN) {
  const origins = process.env.CORS_ORIGIN.split(",").map((o) => o.trim());
  app.use(cors({ origin: origins.includes("*") ? "*" : origins }));
}

// Content Security Policy for the built dashboard: only this server's own
// scripts may run, which blunts any XSS that could steal a login token.
// ('unsafe-inline' styles are needed for React's style attributes and the
// dashboard's small <style> block.) Skipped in dev, where Vite injects inline
// scripts for hot reload.
const CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join("; ");

app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  if (!IS_DEV) {
    res.setHeader("Content-Security-Policy", CSP);
    if (req.secure) res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }
  next();
});

// API responses carry account data and tokens - never let browsers or proxies cache them.
app.use("/api", (req, res, next) => {
  res.setHeader("Cache-Control", "no-store");
  next();
});
app.use(express.json({ limit: "20kb" }));

const HTTP_PORT = process.env.PORT || 4000;
// The dev server only listens on this machine: Vite's dev middleware exposes
// project source files and isn't meant to face a network.
const HOST = process.env.HOST || (IS_DEV ? "127.0.0.1" : undefined);
const INGEST_UDP_PORT = process.env.INGEST_PORT || 5514;
const INGEST_TCP_PORT = process.env.INGEST_TCP_PORT || 5515;

app.get("/api/health", (req, res) => res.json({ status: "ok" }));

// Public, non-sensitive settings the dashboard needs before sign-in.
app.get("/api/config", (req, res) => {
  res.json({
    registrationOpen: process.env.ALLOW_REGISTRATION !== "false" || db.userCount() === 0,
    ingest: { udpPort: Number(INGEST_UDP_PORT), tcpPort: Number(INGEST_TCP_PORT) },
  });
});

app.use("/api/auth", authRoutes);
app.use("/api/sources", sourceRoutes);
app.use("/api/admin", adminRoutes);
app.use("/api", dataRoutes);
app.use("/api", (req, res) => res.status(404).json({ error: "Not found" }));

const server = http.createServer(app);

// ---- dashboard ----
if (IS_DEV) {
  // Vite runs inside this server as middleware, so one command and one port
  // give you the API plus the dashboard with hot module reloading.
  const { createServer } = await import("vite");
  const vite = await createServer({
    root: ROOT,
    appType: "spa",
    server: { middlewareMode: true, ws: { server } },
  });
  app.use(vite.middlewares);
} else {
  // Any non-API GET falls back to index.html so client-side views survive a refresh.
  const DIST = path.resolve(process.env.FRONTEND_DIST || path.join(ROOT, "dist"));
  const INDEX_HTML = path.join(DIST, "index.html");
  if (fs.existsSync(INDEX_HTML)) {
    app.use(express.static(DIST, { index: false, maxAge: "1h", dotfiles: "ignore" }));
    app.get("*", (req, res) => {
      res.setHeader("Cache-Control", "no-cache");
      res.sendFile(INDEX_HTML);
    });
  } else {
    console.warn(`Dashboard build not found at ${DIST} - run "npm run build" first (or use "npm run dev"). API still available.`);
  }
}

// Express recognizes error handlers by their four parameters, so _next must stay.
app.use((err, req, res, _next) => {
  if (err.type === "entity.parse.failed") {
    return res.status(400).json({ error: "Invalid JSON body" });
  }
  if (err.type === "entity.too.large") {
    return res.status(413).json({ error: "Request body too large" });
  }
  console.error(err);
  res.status(500).json({ error: "Internal server error" });
});

// ---- live feed ----
// Pushes new logs/alerts to the dashboard the instant they're ingested.
// Clients must authenticate with their JWT as the first message, only receive
// events for sources they're allowed to see, and are disconnected as soon as
// their session expires or is revoked.
const MAX_WS_CLIENTS = 1000;
const AUTH_TIMEOUT_MS = 10 * 1000;
const HEARTBEAT_MS = 30 * 1000;

const wss = new WebSocketServer({ noServer: true, maxPayload: 4 * 1024 });

server.on("upgrade", (req, socket, head) => {
  const { pathname } = new URL(req.url, "http://localhost");
  if (pathname === "/ws") {
    if (wss.clients.size >= MAX_WS_CLIENTS) {
      socket.end("HTTP/1.1 503 Service Unavailable\r\n\r\n");
      return;
    }
    wss.handleUpgrade(req, socket, head, (ws) => wss.emit("connection", ws, req));
  } else if (!IS_DEV) {
    socket.destroy();
  }
  // in dev, any other upgrade is Vite's hot-reload socket, which handles itself
});

// Returns the user if this socket's session is still valid, otherwise null.
function sessionUser(ws) {
  const user = db.findUserById(ws.userId);
  if (!user) return null;
  if ((user.status || "active") === "suspended") return null;
  if ((user.tokenVersion || 0) !== ws.tokenVersion) return null;
  if (Date.now() >= ws.expiresAt) return null;
  return user;
}

wss.on("connection", (ws) => {
  ws.userId = null;
  ws.isAlive = true;
  const authTimer = setTimeout(() => {
    if (!ws.userId) ws.close(4001, "Authentication required");
  }, AUTH_TIMEOUT_MS);

  ws.on("pong", () => {
    ws.isAlive = true;
  });

  ws.on("message", (raw) => {
    if (ws.userId) return; // authenticated clients have nothing else to send
    let msg;
    try {
      msg = JSON.parse(raw.toString());
    } catch {
      ws.close(4000, "Invalid message");
      return;
    }
    clearTimeout(authTimer);
    const result = msg && msg.type === "auth" ? resolveToken(msg.token) : { error: "Authentication required" };
    if (!result.user) {
      ws.close(4001, "Authentication failed");
      return;
    }
    ws.userId = result.user.id;
    ws.tokenVersion = result.tokenVersion;
    ws.expiresAt = result.expiresAt;
    ws.send(JSON.stringify({ type: "ready" }));
  });

  ws.on("close", () => clearTimeout(authTimer));
  ws.on("error", () => {});
});

// Drops dead connections and sessions that expired or were revoked while open.
const heartbeat = setInterval(() => {
  wss.clients.forEach((ws) => {
    if (!ws.isAlive) return ws.terminate();
    if (ws.userId && !sessionUser(ws)) return ws.close(4001, "Session ended");
    ws.isAlive = false;
    ws.ping();
  });
}, HEARTBEAT_MS);
heartbeat.unref();

function broadcast(event) {
  const payload = JSON.stringify(event);
  const sourceIp = event.data && event.data.sourceIp;

  wss.clients.forEach((client) => {
    if (client.readyState !== client.OPEN || !client.userId) return;
    const user = sessionUser(client);
    if (!user) {
      client.close(4001, "Session ended");
      return;
    }
    const scope = db.visibleIpsFor(user);
    if (scope && !scope.has(sourceIp)) return;
    client.send(payload);
  });
}

server.listen(HTTP_PORT, HOST, () => {
  console.log(`NocaSIEM ${IS_DEV ? "dev server (hot reload on)" : "running"} at http://localhost:${HTTP_PORT}`);
});

startUdpIngestListener({ port: INGEST_UDP_PORT, onEvent: broadcast });
startTcpIngestListener({ port: INGEST_TCP_PORT, onEvent: broadcast });

// Write any batched log data before exiting.
function shutdown() {
  try {
    db.flush();
  } finally {
    process.exit(0);
  }
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
process.on("exit", () => db.flush());
