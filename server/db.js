// Lightweight JSON-file data store.
// This keeps the project dependency-free (no native DB bindings to compile),
// which makes it easy to run anywhere. Swap this module out for a real
// database (Postgres, MySQL, SQLite) later without touching the routes -
// they only ever call the functions exported here.

import fs from "node:fs";
import path from "node:path";

// Point DATA_FILE at a persistent disk/volume when deploying - many hosts
// wipe the app directory on every redeploy.
const DATA_FILE = path.resolve(process.env.DATA_FILE || path.join(import.meta.dirname, "..", "data.json"));

const EMPTY_STATE = {
  users: [],
  sources: [],
  alerts: [],
  logs: [],
  auditLog: [],
};

function load() {
  if (!fs.existsSync(DATA_FILE)) {
    fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
    fs.writeFileSync(DATA_FILE, JSON.stringify(EMPTY_STATE, null, 2));
  }
  const raw = fs.readFileSync(DATA_FILE, "utf8");
  try {
    return JSON.parse(raw);
  } catch (err) {
    console.error("data.json is corrupted, resetting to empty state:", err);
    fs.writeFileSync(DATA_FILE, JSON.stringify(EMPTY_STATE, null, 2));
    return { ...EMPTY_STATE };
  }
}

// Write to a temp file then rename, so a crash mid-write can never leave
// a half-written (corrupted) data.json behind.
function save(state) {
  const tmp = `${DATA_FILE}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(state, null, 2));
  fs.renameSync(tmp, DATA_FILE);
}

let state = load();

function nextId(collection) {
  return collection.length ? Math.max(...collection.map((r) => r.id)) + 1 : 1;
}

// ---- users ----
function findUserByEmail(email) {
  return state.users.find((u) => u.email.toLowerCase() === email.toLowerCase());
}

function findUserById(id) {
  return state.users.find((u) => u.id === id);
}

function createUser({ username, email, passwordHash, role }) {
  const user = {
    id: nextId(state.users),
    username,
    email,
    passwordHash,
    role: role || "user",
    status: "active",
    lastLoginAt: null,
    createdAt: new Date().toISOString(),
  };
  state.users.push(user);
  save(state);
  return user;
}

function userCount() {
  return state.users.length;
}

function recordLogin(id) {
  const user = state.users.find((u) => u.id === id);
  if (!user) return null;
  user.lastLoginAt = new Date().toISOString();
  save(state);
  return user;
}

// ---- admin: user management (never exposes passwordHash) ----
function listAllUsers() {
  return state.users.map((u) => ({
    id: u.id,
    username: u.username,
    email: u.email,
    role: u.role || "user",
    status: u.status || "active",
    createdAt: u.createdAt,
    lastLoginAt: u.lastLoginAt || null,
    sourceCount: state.sources.filter((s) => s.userId === u.id).length,
  }));
}

function countAdmins() {
  return state.users.filter((u) => (u.role || "user") === "admin").length;
}

function updateUserRole(id, role) {
  const user = state.users.find((u) => u.id === id);
  if (!user) return null;
  user.role = role;
  save(state);
  return user;
}

function updateUserStatus(id, status) {
  const user = state.users.find((u) => u.id === id);
  if (!user) return null;
  user.status = status;
  save(state);
  return user;
}

function deleteUserAccount(id) {
  const before = state.users.length;
  state.users = state.users.filter((u) => u.id !== id);
  state.sources = state.sources.filter((s) => s.userId !== id);
  save(state);
  return state.users.length < before;
}

function listAllAuditLog(limit = 100) {
  return (state.auditLog || [])
    .slice(-limit)
    .reverse()
    .map((entry) => {
      const u = state.users.find((x) => x.id === entry.userId);
      return { ...entry, username: u ? u.username : `User #${entry.userId}` };
    });
}

function updateUser(id, { username, email }) {
  const user = state.users.find((u) => u.id === id);
  if (!user) return null;
  if (username) user.username = username;
  if (email) user.email = email;
  save(state);
  return user;
}

function updateUserPassword(id, passwordHash) {
  const user = state.users.find((u) => u.id === id);
  if (!user) return null;
  user.passwordHash = passwordHash;
  save(state);
  return user;
}

// ---- audit log ----
function addAuditLog({ userId, action, detail }) {
  if (!state.auditLog) state.auditLog = [];
  const entry = {
    id: nextId(state.auditLog),
    userId,
    action,
    detail,
    createdAt: new Date().toISOString(),
  };
  state.auditLog.push(entry);
  if (state.auditLog.length > 500) state.auditLog = state.auditLog.slice(-500);
  save(state);
  return entry;
}

function listAuditLog(userId, limit = 20) {
  return (state.auditLog || [])
    .filter((e) => e.userId === userId)
    .slice(-limit)
    .reverse();
}

// ---- visibility ----
// Returns null when the user may see everything (admins), otherwise the Set
// of source IPs they registered - logs/alerts are filtered down to those.
function visibleIpsFor(user) {
  if (!user) return new Set();
  if ((user.role || "user") === "admin") return null;
  return new Set(state.sources.filter((s) => s.userId === user.id).map((s) => s.ip));
}

function inScope(rows, ips) {
  return ips ? rows.filter((r) => ips.has(r.sourceIp)) : rows;
}

// ---- log sources ----
function listSources(userId) {
  return state.sources.filter((s) => s.userId === userId);
}

function createSource(userId, { name, ip, port, protocol }) {
  const source = {
    id: nextId(state.sources),
    userId,
    name,
    ip,
    port,
    protocol,
    status: "pending",
    lastSeen: null,
    createdAt: new Date().toISOString(),
  };
  state.sources.push(source);
  save(state);
  return source;
}

function deleteSource(userId, sourceId) {
  const before = state.sources.length;
  state.sources = state.sources.filter((s) => !(s.id === sourceId && s.userId === userId));
  save(state);
  return state.sources.length < before;
}

// Called by the ingest listener whenever a datagram arrives, so the
// Settings page can show "last seen" / active status per source.
function markSourceSeen(ip) {
  const matches = state.sources.filter((s) => s.ip === ip);
  if (!matches.length) return [];
  const now = new Date().toISOString();
  matches.forEach((s) => {
    s.status = "active";
    s.lastSeen = now;
  });
  save(state);
  return matches;
}

// ---- logs & alerts ----
function addLog({ sourceIp, message }) {
  const entry = {
    id: nextId(state.logs),
    sourceIp,
    message,
    createdAt: new Date().toISOString(),
  };
  state.logs.push(entry);
  if (state.logs.length > 2000) state.logs = state.logs.slice(-2000);
  save(state);
  return entry;
}

function addAlert({ sourceIp, severity, type, message }) {
  const alert = {
    id: nextId(state.alerts),
    sourceIp,
    severity,
    type,
    message,
    status: "Open",
    createdAt: new Date().toISOString(),
  };
  state.alerts.push(alert);
  if (state.alerts.length > 1000) state.alerts = state.alerts.slice(-1000);
  save(state);
  return alert;
}

function listLogs(limit = 100, ips = null) {
  return inScope(state.logs, ips).slice(-limit).reverse();
}

function listAlerts(limit = 100, ips = null) {
  return inScope(state.alerts, ips).slice(-limit).reverse();
}

function updateAlertStatus(id, status, ips = null) {
  const alert = inScope(state.alerts, ips).find((a) => a.id === id);
  if (!alert) return null;
  alert.status = status;
  save(state);
  return alert;
}

const HOUR_MS = 60 * 60 * 1000;

function getStats(ips = null) {
  const now = Date.now();
  const last24h = now - 24 * HOUR_MS;
  const recentLogs = inScope(state.logs, ips).filter((l) => new Date(l.createdAt).getTime() >= last24h);
  const recentAlerts = inScope(state.alerts, ips).filter((a) => new Date(a.createdAt).getTime() >= last24h);

  // 24 hourly buckets, oldest first, ending with the current hour.
  const currentHour = Math.floor(now / HOUR_MS) * HOUR_MS;
  const volume = Array.from({ length: 24 }, (_, i) => ({
    start: new Date(currentHour - (23 - i) * HOUR_MS).toISOString(),
    events: 0,
  }));
  const ipCounts = new Map();
  let lastMinute = 0;
  recentLogs.forEach((l) => {
    const t = new Date(l.createdAt).getTime();
    const idx = 23 - Math.floor((currentHour - Math.floor(t / HOUR_MS) * HOUR_MS) / HOUR_MS);
    if (idx >= 0 && idx < 24) volume[idx].events += 1;
    if (now - t < 60 * 1000) lastMinute += 1;
    ipCounts.set(l.sourceIp, (ipCounts.get(l.sourceIp) || 0) + 1);
  });

  return {
    totalEvents: recentLogs.length,
    activeAlerts: recentAlerts.filter((a) => a.status !== "Resolved").length,
    criticalIncidents: recentAlerts.filter((a) => a.severity === "Critical" && a.status !== "Resolved").length,
    eventsPerSecond: Math.round((lastMinute / 60) * 10) / 10,
    severityBreakdown: ["Critical", "High", "Medium", "Low"].map((sev) => ({
      name: sev,
      value: recentAlerts.filter((a) => a.severity === sev).length,
    })),
    volume,
    topSources: [...ipCounts.entries()]
      .map(([ip, count]) => ({ ip, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5),
  };
}

export {
  findUserByEmail,
  findUserById,
  createUser,
  userCount,
  recordLogin,
  listAllUsers,
  countAdmins,
  updateUserRole,
  updateUserStatus,
  deleteUserAccount,
  listAllAuditLog,
  updateUser,
  updateUserPassword,
  addAuditLog,
  listAuditLog,
  listSources,
  createSource,
  deleteSource,
  visibleIpsFor,
  markSourceSeen,
  addLog,
  addAlert,
  listLogs,
  listAlerts,
  updateAlertStatus,
  getStats,
};
