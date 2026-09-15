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

const COLLECTIONS = ["users", "sources", "alerts", "logs", "auditLog"];

function emptyState() {
  return { users: [], sources: [], alerts: [], logs: [], auditLog: [], counters: {} };
}

function load() {
  fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
  let parsed = emptyState();
  if (fs.existsSync(DATA_FILE)) {
    try {
      parsed = { ...emptyState(), ...JSON.parse(fs.readFileSync(DATA_FILE, "utf8")) };
    } catch (err) {
      // Keep the damaged file for recovery instead of silently wiping every account.
      const backup = `${DATA_FILE}.corrupt-${Date.now()}`;
      fs.renameSync(DATA_FILE, backup);
      console.error(`Data file was unreadable (${err.message}). Moved it to ${backup} and started empty.`);
      parsed = emptyState();
    }
  }

  // Ids come from counters that only ever go up. Reusing a deleted user's id
  // would let that user's old login token act as whoever got the id next.
  parsed.counters = parsed.counters || {};
  for (const name of COLLECTIONS) {
    if (!Array.isArray(parsed[name])) parsed[name] = [];
    const maxId = parsed[name].reduce((m, r) => Math.max(m, Number(r.id) || 0), 0);
    parsed.counters[name] = Math.max(Number(parsed.counters[name]) || 0, maxId);
  }
  return parsed;
}

const state = load();

// ---- persistence ----
let saveTimer = null;

// Write to a temp file then rename, so a crash mid-write can never leave a
// half-written data file behind. Mode 600: only the server's OS user can read
// password hashes and logs.
function writeNow() {
  if (saveTimer) {
    clearTimeout(saveTimer);
    saveTimer = null;
  }
  const tmp = `${DATA_FILE}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(state, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, DATA_FILE);
  try {
    fs.chmodSync(DATA_FILE, 0o600);
  } catch {
    // not supported on every filesystem (e.g. Windows) - best effort
  }
}

// Account and security changes are written immediately.
function save() {
  writeNow();
}

// High-volume ingest writes are batched (at most once per second) so a flood
// of log lines can't pin the server rewriting the file thousands of times.
function saveSoon() {
  if (!saveTimer) saveTimer = setTimeout(writeNow, 1000);
}

// Called on shutdown so batched log writes aren't lost.
function flush() {
  if (saveTimer) writeNow();
}

writeNow();

function nextId(collection) {
  state.counters[collection] += 1;
  return state.counters[collection];
}

// ---- users ----
function findUserByEmail(email) {
  const needle = String(email).trim().toLowerCase();
  return state.users.find((u) => u.email.toLowerCase() === needle);
}

function findUserById(id) {
  return state.users.find((u) => u.id === id);
}

function createUser({ username, email, passwordHash, role }) {
  const user = {
    id: nextId("users"),
    username,
    email: email.toLowerCase(),
    passwordHash,
    role: role || "user",
    status: "active",
    tokenVersion: 0,
    lastLoginAt: null,
    createdAt: new Date().toISOString(),
  };
  state.users.push(user);
  save();
  return user;
}

function userCount() {
  return state.users.length;
}

function recordLogin(id) {
  const user = findUserById(id);
  if (!user) return null;
  user.lastLoginAt = new Date().toISOString();
  save();
  return user;
}

// Invalidates every login token issued to this user so far.
function revokeSessions(user) {
  user.tokenVersion = (user.tokenVersion || 0) + 1;
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
  const user = findUserById(id);
  if (!user) return null;
  user.role = role;
  save();
  return user;
}

function updateUserStatus(id, status) {
  const user = findUserById(id);
  if (!user) return null;
  if (status === "suspended" && user.status !== "suspended") revokeSessions(user);
  user.status = status;
  save();
  return user;
}

function deleteUserAccount(id) {
  const before = state.users.length;
  state.users = state.users.filter((u) => u.id !== id);
  state.sources = state.sources.filter((s) => s.userId !== id);
  save();
  return state.users.length < before;
}

function listAllAuditLog(limit = 100) {
  return state.auditLog
    .slice(-limit)
    .reverse()
    .map((entry) => {
      const u = findUserById(entry.userId);
      return { ...entry, username: u ? u.username : `User #${entry.userId}` };
    });
}

function updateUser(id, { username, email }) {
  const user = findUserById(id);
  if (!user) return null;
  if (username) user.username = username;
  if (email) user.email = email.toLowerCase();
  save();
  return user;
}

// Changing the password signs out every other session.
function updateUserPassword(id, passwordHash) {
  const user = findUserById(id);
  if (!user) return null;
  user.passwordHash = passwordHash;
  revokeSessions(user);
  save();
  return user;
}

// ---- audit log ----
function addAuditLog({ userId, action, detail }) {
  const entry = {
    id: nextId("auditLog"),
    userId,
    action,
    detail,
    createdAt: new Date().toISOString(),
  };
  state.auditLog.push(entry);
  if (state.auditLog.length > 500) state.auditLog = state.auditLog.slice(-500);
  save();
  return entry;
}

function listAuditLog(userId, limit = 20) {
  return state.auditLog
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

function findSourceByIp(ip) {
  return state.sources.find((s) => s.ip === ip);
}

function isRegisteredIp(ip) {
  return state.sources.some((s) => s.ip === ip);
}

function createSource(userId, { name, ip, port, protocol }) {
  const source = {
    id: nextId("sources"),
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
  save();
  return source;
}

function deleteSource(userId, sourceId) {
  const before = state.sources.length;
  state.sources = state.sources.filter((s) => !(s.id === sourceId && s.userId === userId));
  save();
  return state.sources.length < before;
}

// Called by the ingest listener whenever a line arrives, so the Settings
// page can show "last seen" / active status per source.
function markSourceSeen(ip) {
  const matches = state.sources.filter((s) => s.ip === ip);
  if (!matches.length) return [];
  const now = new Date().toISOString();
  matches.forEach((s) => {
    s.status = "active";
    s.lastSeen = now;
  });
  saveSoon();
  return matches;
}

// ---- logs & alerts ----
function addLog({ sourceIp, message }) {
  const entry = {
    id: nextId("logs"),
    sourceIp,
    message,
    createdAt: new Date().toISOString(),
  };
  state.logs.push(entry);
  if (state.logs.length > 2000) state.logs = state.logs.slice(-2000);
  saveSoon();
  return entry;
}

function addAlert({ sourceIp, severity, type, message }) {
  const alert = {
    id: nextId("alerts"),
    sourceIp,
    severity,
    type,
    message,
    status: "Open",
    createdAt: new Date().toISOString(),
  };
  state.alerts.push(alert);
  if (state.alerts.length > 1000) state.alerts = state.alerts.slice(-1000);
  saveSoon();
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
  save();
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
  flush,
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
  findSourceByIp,
  isRegisteredIp,
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
