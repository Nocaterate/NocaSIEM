// SQLite data store (Node's built-in node:sqlite, no extra dependency).
//
// All routes and the ingest pipeline go through the functions exported here,
// so the storage engine can be swapped without touching them. Every query
// uses bound parameters - user input is never concatenated into SQL.

import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { describeTechniques } from "./engine/mitre.js";

const ROOT = path.resolve(import.meta.dirname, "..");
const DB_FILE = path.resolve(process.env.DB_FILE || path.join(ROOT, "nocasiem.db"));
const LEGACY_JSON = path.resolve(process.env.DATA_FILE || path.join(ROOT, "data.json"));

const DAY_MS = 24 * 60 * 60 * 1000;
const HOUR_MS = 60 * 60 * 1000;

fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
const db = new DatabaseSync(DB_FILE);
try {
  fs.chmodSync(DB_FILE, 0o600); // only the server's OS user can read hashes and logs
} catch {
  // not supported on every filesystem (e.g. Windows) - best effort
}

db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA synchronous = NORMAL;
  PRAGMA foreign_keys = ON;
  PRAGMA busy_timeout = 5000;

  CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);

  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    status TEXT NOT NULL DEFAULT 'active',
    token_version INTEGER NOT NULL DEFAULT 0,
    last_login_at TEXT,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    ip TEXT NOT NULL UNIQUE,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    last_seen TEXT,
    created_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS sources_user ON sources(user_id);

  CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    detail TEXT,
    created_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS audit_user ON audit_log(user_id, id);

  CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    message TEXT NOT NULL,
    host TEXT,
    program TEXT,
    decoder TEXT,
    event_action TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    user_name TEXT,
    fields TEXT NOT NULL DEFAULT '{}',
    rule_ids TEXT NOT NULL DEFAULT '[]'
  );
  CREATE INDEX IF NOT EXISTS logs_created ON logs(created_at);
  CREATE INDEX IF NOT EXISTS logs_source ON logs(source_ip, id);
  CREATE INDEX IF NOT EXISTS logs_src_ip ON logs(src_ip);
  CREATE INDEX IF NOT EXISTS logs_decoder ON logs(decoder);

  CREATE VIRTUAL TABLE IF NOT EXISTS logs_fts USING fts5(message, content='logs', content_rowid='id');
  CREATE TRIGGER IF NOT EXISTS logs_ai AFTER INSERT ON logs BEGIN
    INSERT INTO logs_fts(rowid, message) VALUES (new.id, new.message);
  END;
  CREATE TRIGGER IF NOT EXISTS logs_ad AFTER DELETE ON logs BEGIN
    INSERT INTO logs_fts(logs_fts, rowid, message) VALUES ('delete', old.id, old.message);
  END;

  CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    log_id INTEGER REFERENCES logs(id) ON DELETE SET NULL,
    source_ip TEXT NOT NULL,
    rule_id INTEGER,
    level INTEGER NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    rule_groups TEXT NOT NULL DEFAULT '[]',
    mitre TEXT NOT NULL DEFAULT '[]',
    src_ip TEXT,
    user_name TEXT,
    message TEXT,
    fields TEXT NOT NULL DEFAULT '{}',
    fired_times INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'Open'
  );
  CREATE INDEX IF NOT EXISTS alerts_created ON alerts(created_at);
  CREATE INDEX IF NOT EXISTS alerts_source ON alerts(source_ip, id);
  CREATE INDEX IF NOT EXISTS alerts_rule ON alerts(rule_id);
  CREATE INDEX IF NOT EXISTS alerts_src_ip ON alerts(src_ip);
  CREATE INDEX IF NOT EXISTS alerts_status ON alerts(status);
`);

const stmtCache = new Map();
function q(sql) {
  let s = stmtCache.get(sql);
  if (!s) {
    s = db.prepare(sql);
    stmtCache.set(sql, s);
  }
  return s;
}

function transaction(fn) {
  db.exec("BEGIN");
  try {
    const result = fn();
    db.exec("COMMIT");
    return result;
  } catch (err) {
    db.exec("ROLLBACK");
    throw err;
  }
}

function parseJson(text, fallback) {
  try {
    return JSON.parse(text);
  } catch {
    return fallback;
  }
}

const now = () => new Date().toISOString();

// ------------------------------------------------------------------ users --

function mapUser(r) {
  if (!r) return undefined;
  return {
    id: r.id,
    username: r.username,
    email: r.email,
    passwordHash: r.password_hash,
    role: r.role,
    status: r.status,
    tokenVersion: r.token_version,
    lastLoginAt: r.last_login_at,
    createdAt: r.created_at,
  };
}

function findUserByEmail(email) {
  return mapUser(q("SELECT * FROM users WHERE email = ? COLLATE NOCASE").get(String(email).trim()));
}

function findUserById(id) {
  return mapUser(q("SELECT * FROM users WHERE id = ?").get(id));
}

function createUser({ username, email, passwordHash, role }) {
  const r = q("INSERT INTO users (username, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)").run(username, email.toLowerCase(), passwordHash, role || "user", now());
  return findUserById(Number(r.lastInsertRowid));
}

function userCount() {
  return q("SELECT count(*) AS c FROM users").get().c;
}

function recordLogin(id) {
  q("UPDATE users SET last_login_at = ? WHERE id = ?").run(now(), id);
  return findUserById(id);
}

function listAllUsers() {
  return q(`SELECT u.*, (SELECT count(*) FROM sources s WHERE s.user_id = u.id) AS source_count FROM users u ORDER BY u.id`)
    .all()
    .map((r) => {
      const u = mapUser(r);
      return { id: u.id, username: u.username, email: u.email, role: u.role, status: u.status, createdAt: u.createdAt, lastLoginAt: u.lastLoginAt, sourceCount: r.source_count };
    });
}

function countAdmins() {
  return q("SELECT count(*) AS c FROM users WHERE role = 'admin'").get().c;
}

function updateUserRole(id, role) {
  q("UPDATE users SET role = ? WHERE id = ?").run(role, id);
  return findUserById(id);
}

// Suspending bumps the token version, which revokes every existing session.
function updateUserStatus(id, status) {
  const user = findUserById(id);
  if (!user) return undefined;
  const bump = status === "suspended" && user.status !== "suspended" ? 1 : 0;
  q("UPDATE users SET status = ?, token_version = token_version + ? WHERE id = ?").run(status, bump, id);
  return findUserById(id);
}

function deleteUserAccount(id) {
  return q("DELETE FROM users WHERE id = ?").run(id).changes > 0; // sources cascade
}

function updateUser(id, { username, email }) {
  if (username) q("UPDATE users SET username = ? WHERE id = ?").run(username, id);
  if (email) q("UPDATE users SET email = ? WHERE id = ?").run(email.toLowerCase(), id);
  return findUserById(id);
}

// Changing the password signs out every other session.
function updateUserPassword(id, passwordHash) {
  q("UPDATE users SET password_hash = ?, token_version = token_version + 1 WHERE id = ?").run(passwordHash, id);
  return findUserById(id);
}

// -------------------------------------------------------------- audit log --

function addAuditLog({ userId, action, detail }) {
  const createdAt = now();
  const r = q("INSERT INTO audit_log (user_id, action, detail, created_at) VALUES (?, ?, ?, ?)").run(userId ?? null, action, detail ?? null, createdAt);
  return { id: Number(r.lastInsertRowid), userId, action, detail, createdAt };
}

function mapAudit(r) {
  return { id: r.id, userId: r.user_id, action: r.action, detail: r.detail, createdAt: r.created_at };
}

function listAuditLog(userId, limit = 20) {
  return q("SELECT * FROM audit_log WHERE user_id = ? ORDER BY id DESC LIMIT ?").all(userId, limit).map(mapAudit);
}

function listAllAuditLog(limit = 100) {
  return q(`SELECT a.*, u.username FROM audit_log a LEFT JOIN users u ON u.id = a.user_id ORDER BY a.id DESC LIMIT ?`)
    .all(limit)
    .map((r) => ({ ...mapAudit(r), username: r.username || `User #${r.user_id}` }));
}

// ---------------------------------------------------------------- sources --

function mapSource(r) {
  return r && { id: r.id, userId: r.user_id, name: r.name, ip: r.ip, port: r.port, protocol: r.protocol, status: r.status, lastSeen: r.last_seen, createdAt: r.created_at };
}

function listSources(userId) {
  return q("SELECT * FROM sources WHERE user_id = ? ORDER BY id").all(userId).map(mapSource);
}

function findSourceByIp(ip) {
  return mapSource(q("SELECT * FROM sources WHERE ip = ?").get(ip));
}

function isRegisteredIp(ip) {
  return !!q("SELECT 1 FROM sources WHERE ip = ?").get(ip);
}

function createSource(userId, { name, ip, port, protocol }) {
  const r = q("INSERT INTO sources (user_id, name, ip, port, protocol, created_at) VALUES (?, ?, ?, ?, ?, ?)").run(userId, name, ip, port, protocol, now());
  return mapSource(q("SELECT * FROM sources WHERE id = ?").get(Number(r.lastInsertRowid)));
}

function deleteSource(userId, sourceId) {
  return q("DELETE FROM sources WHERE id = ? AND user_id = ?").run(sourceId, userId).changes > 0;
}

// Updates "last seen" at most every 10 seconds per source to avoid a write per line.
function markSourceSeen(ip) {
  const ts = now();
  q("UPDATE sources SET status = 'active', last_seen = ? WHERE ip = ? AND (last_seen IS NULL OR last_seen < ?)").run(ts, ip, new Date(Date.now() - 10000).toISOString());
}

// ------------------------------------------------------------- visibility --

// null = sees everything (admin); otherwise the Set of the user's source IPs.
function visibleIpsFor(user) {
  if (!user) return new Set();
  if (user.role === "admin") return null;
  return new Set(q("SELECT ip FROM sources WHERE user_id = ?").all(user.id).map((r) => r.ip));
}

// Scope clause for logs/alerts: $scope is null for admins, else a user id.
const SCOPE = "($scope IS NULL OR source_ip IN (SELECT ip FROM sources WHERE user_id = $scope))";

// ------------------------------------------------------------ logs/alerts --

function mapLog(r) {
  return (
    r && {
      id: r.id,
      createdAt: r.created_at,
      sourceIp: r.source_ip,
      message: r.message,
      host: r.host,
      program: r.program,
      decoder: r.decoder,
      action: r.event_action,
      srcIp: r.src_ip,
      dstIp: r.dst_ip,
      srcPort: r.src_port,
      dstPort: r.dst_port,
      user: r.user_name,
      fields: parseJson(r.fields, {}),
      ruleIds: parseJson(r.rule_ids, []),
    }
  );
}

function mapAlert(r) {
  if (!r) return undefined;
  const mitreIds = parseJson(r.mitre, []);
  return {
    id: r.id,
    createdAt: r.created_at,
    logId: r.log_id,
    sourceIp: r.source_ip,
    ruleId: r.rule_id,
    level: r.level,
    severity: r.severity,
    title: r.title,
    type: r.title,
    groups: parseJson(r.rule_groups, []),
    mitre: describeTechniques(mitreIds),
    srcIp: r.src_ip,
    user: r.user_name,
    message: r.message,
    fields: parseJson(r.fields, {}),
    firedTimes: r.fired_times,
    status: r.status,
  };
}

function toInt(v) {
  return typeof v === "number" && Number.isFinite(v) ? Math.trunc(v) : null;
}

function addLog({ sourceIp, message, decoded, matchedRules = [] }) {
  const f = decoded?.fields || {};
  const createdAt = now();
  const r = q(`INSERT INTO logs (created_at, source_ip, message, host, program, decoder, event_action, src_ip, dst_ip, src_port, dst_port, user_name, fields, rule_ids)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
    createdAt,
    sourceIp,
    message,
    decoded?.host ?? null,
    decoded?.program ?? null,
    decoded?.decoder ?? null,
    f.action ?? null,
    f.srcip ?? null,
    f.dstip ?? null,
    toInt(f.srcport),
    toInt(f.dstport),
    f.user ?? null,
    JSON.stringify(f),
    JSON.stringify(matchedRules)
  );
  return mapLog(q("SELECT * FROM logs WHERE id = ?").get(Number(r.lastInsertRowid)));
}

function addAlert({ logId, sourceIp, message, fields = {}, alert }) {
  const r = q(`INSERT INTO alerts (created_at, log_id, source_ip, rule_id, level, severity, title, rule_groups, mitre, src_ip, user_name, message, fields, fired_times)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
    now(),
    logId ?? null,
    sourceIp,
    alert.ruleId ?? null,
    alert.level,
    alert.severity,
    alert.title,
    JSON.stringify(alert.groups || []),
    JSON.stringify(alert.mitre || []),
    alert.srcIp ?? null,
    alert.user ?? null,
    message ?? null,
    JSON.stringify(fields),
    alert.firedTimes || 1
  );
  return mapAlert(q("SELECT * FROM alerts WHERE id = ?").get(Number(r.lastInsertRowid)));
}

// Turns free text into a safe FTS5 query: every word becomes a quoted term
// (so FTS operators typed by a user are treated as plain text).
function ftsQuery(text) {
  const terms = String(text).match(/[\p{L}\p{N}_.:@\-/]+/gu) || [];
  return terms
    .slice(0, 12)
    .map((t) => `"${t.replace(/"/g, "")}"`)
    .join(" ");
}

function likeEscape(text) {
  return `%${String(text).replace(/[\\%_]/g, (c) => `\\${c}`)}%`;
}

// filters: q, sourceIp, srcIp, user, decoder, action, from, to, before, limit
function searchLogs(filters, scopeUserId) {
  const where = [SCOPE];
  const params = { $scope: scopeUserId ?? null, $limit: filters.limit };
  if (filters.q) {
    const fts = ftsQuery(filters.q);
    if (fts) {
      where.push("id IN (SELECT rowid FROM logs_fts WHERE logs_fts MATCH $fts)");
      params.$fts = fts;
    }
  }
  if (filters.sourceIp) {
    where.push("source_ip = $sourceIp");
    params.$sourceIp = filters.sourceIp;
  }
  if (filters.srcIp) {
    where.push("src_ip = $srcIp");
    params.$srcIp = filters.srcIp;
  }
  if (filters.user) {
    where.push("user_name = $user COLLATE NOCASE");
    params.$user = filters.user;
  }
  if (filters.decoder) {
    where.push("decoder = $decoder");
    params.$decoder = filters.decoder;
  }
  if (filters.action) {
    where.push("event_action = $action");
    params.$action = filters.action;
  }
  if (filters.from) {
    where.push("created_at >= $from");
    params.$from = filters.from;
  }
  if (filters.to) {
    where.push("created_at <= $to");
    params.$to = filters.to;
  }
  if (filters.before) {
    where.push("id < $before");
    params.$before = filters.before;
  }
  const rows = db.prepare(`SELECT * FROM logs WHERE ${where.join(" AND ")} ORDER BY id DESC LIMIT $limit`).all(params);
  return rows.map(mapLog);
}

// filters: q, severity[], status, ruleId, mitre, srcIp, sourceIp, user, levelMin, from, to, before, limit
function searchAlerts(filters, scopeUserId) {
  const where = [SCOPE];
  const params = { $scope: scopeUserId ?? null, $limit: filters.limit };
  if (filters.q) {
    where.push("(title LIKE $q ESCAPE '\\' OR message LIKE $q ESCAPE '\\')");
    params.$q = likeEscape(filters.q);
  }
  if (filters.severity?.length) {
    where.push("severity IN (SELECT value FROM json_each($severity))");
    params.$severity = JSON.stringify(filters.severity);
  }
  if (filters.status) {
    where.push("status = $status");
    params.$status = filters.status;
  }
  if (filters.ruleId) {
    where.push("rule_id = $ruleId");
    params.$ruleId = filters.ruleId;
  }
  if (filters.mitre) {
    where.push("EXISTS (SELECT 1 FROM json_each(alerts.mitre) WHERE value = $mitre)");
    params.$mitre = filters.mitre;
  }
  if (filters.srcIp) {
    where.push("src_ip = $srcIp");
    params.$srcIp = filters.srcIp;
  }
  if (filters.sourceIp) {
    where.push("source_ip = $sourceIp");
    params.$sourceIp = filters.sourceIp;
  }
  if (filters.user) {
    where.push("user_name = $user COLLATE NOCASE");
    params.$user = filters.user;
  }
  if (filters.levelMin) {
    where.push("level >= $levelMin");
    params.$levelMin = filters.levelMin;
  }
  if (filters.from) {
    where.push("created_at >= $from");
    params.$from = filters.from;
  }
  if (filters.to) {
    where.push("created_at <= $to");
    params.$to = filters.to;
  }
  if (filters.before) {
    where.push("id < $before");
    params.$before = filters.before;
  }
  const rows = db.prepare(`SELECT * FROM alerts WHERE ${where.join(" AND ")} ORDER BY id DESC LIMIT $limit`).all(params);
  return rows.map(mapAlert);
}

function listLogs(limit = 100, scopeUserId = null) {
  return searchLogs({ limit }, scopeUserId);
}

function listAlerts(limit = 100, scopeUserId = null) {
  return searchAlerts({ limit }, scopeUserId);
}

function getLog(id, scopeUserId) {
  return mapLog(q(`SELECT * FROM logs WHERE id = $id AND ${SCOPE}`).get({ $id: id, $scope: scopeUserId ?? null }));
}

function getAlert(id, scopeUserId) {
  return mapAlert(q(`SELECT * FROM alerts WHERE id = $id AND ${SCOPE}`).get({ $id: id, $scope: scopeUserId ?? null }));
}

// Other alerts involving the same attacker IP (or the same device when the
// alert has no attacker IP) in the 24 hours around it.
function relatedAlerts(alert, scopeUserId, limit = 10) {
  const t = new Date(alert.createdAt).getTime();
  const params = { $id: alert.id, $scope: scopeUserId ?? null, $from: new Date(t - DAY_MS).toISOString(), $to: new Date(t + DAY_MS).toISOString(), $limit: limit };
  let match;
  if (alert.srcIp) {
    match = "src_ip = $ip";
    params.$ip = alert.srcIp;
  } else {
    match = "source_ip = $ip";
    params.$ip = alert.sourceIp;
  }
  return q(`SELECT * FROM alerts WHERE id != $id AND ${match} AND created_at BETWEEN $from AND $to AND ${SCOPE} ORDER BY id DESC LIMIT $limit`)
    .all(params)
    .map(mapAlert);
}

function updateAlertStatus(id, status, scopeUserId = null) {
  const r = q(`UPDATE alerts SET status = $status WHERE id = $id AND ${SCOPE}`).run({ $status: status, $id: id, $scope: scopeUserId ?? null });
  return r.changes > 0 ? getAlert(id, scopeUserId) : undefined;
}

function getStats(scopeUserId = null) {
  const nowMs = Date.now();
  const p = { $scope: scopeUserId ?? null, $since: new Date(nowMs - DAY_MS).toISOString() };

  const totalEvents = q(`SELECT count(*) AS c FROM logs WHERE created_at >= $since AND ${SCOPE}`).get(p).c;
  const lastMinute = q(`SELECT count(*) AS c FROM logs WHERE created_at >= $since AND ${SCOPE}`).get({ ...p, $since: new Date(nowMs - 60000).toISOString() }).c;

  // 24 hourly buckets (UTC hours), oldest first, ending with the current hour.
  const currentHour = Math.floor(nowMs / HOUR_MS) * HOUR_MS;
  const hourly = new Map(
    q(`SELECT substr(created_at, 1, 13) AS h, count(*) AS c FROM logs WHERE created_at >= $from AND ${SCOPE} GROUP BY h`)
      .all({ $scope: p.$scope, $from: new Date(currentHour - 23 * HOUR_MS).toISOString() })
      .map((r) => [r.h, r.c])
  );
  const volume = Array.from({ length: 24 }, (_, i) => {
    const start = new Date(currentHour - (23 - i) * HOUR_MS).toISOString();
    return { start, events: hourly.get(start.slice(0, 13)) || 0 };
  });

  const severityRows = q(`SELECT severity, count(*) AS c FROM alerts WHERE created_at >= $since AND ${SCOPE} GROUP BY severity`).all(p);
  const alertCounts = q(`SELECT
      sum(CASE WHEN status != 'Resolved' THEN 1 ELSE 0 END) AS active,
      sum(CASE WHEN status != 'Resolved' AND severity = 'Critical' THEN 1 ELSE 0 END) AS critical
    FROM alerts WHERE created_at >= $since AND ${SCOPE}`).get(p);

  const topSources = q(`SELECT source_ip AS ip, count(*) AS count FROM logs WHERE created_at >= $since AND ${SCOPE} GROUP BY source_ip ORDER BY count DESC LIMIT 5`).all(p).map((r) => ({ ip: r.ip, count: r.count }));

  const topAttackers = q(`SELECT src_ip AS ip, count(*) AS count, max(level) AS maxLevel FROM alerts
      WHERE created_at >= $since AND src_ip IS NOT NULL AND ${SCOPE} GROUP BY src_ip ORDER BY maxLevel DESC, count DESC LIMIT 5`)
    .all(p)
    .map((r) => ({ ip: r.ip, count: r.count, maxLevel: r.maxLevel }));

  const techniqueRows = q(`SELECT j.value AS id, count(*) AS count FROM alerts, json_each(alerts.mitre) AS j
      WHERE alerts.created_at >= $since AND ${SCOPE.replace(/source_ip/g, "alerts.source_ip")} GROUP BY j.value ORDER BY count DESC LIMIT 6`).all(p);
  const described = describeTechniques(techniqueRows.map((r) => r.id));
  const topTechniques = techniqueRows.map((r, i) => ({ ...described[i], count: r.count }));

  return {
    totalEvents,
    activeAlerts: alertCounts.active || 0,
    criticalIncidents: alertCounts.critical || 0,
    eventsPerSecond: Math.round((lastMinute / 60) * 10) / 10,
    severityBreakdown: ["Critical", "High", "Medium", "Low"].map((name) => ({ name, value: severityRows.find((r) => r.severity === name)?.c || 0 })),
    volume,
    topSources,
    topAttackers,
    topTechniques,
  };
}

// -------------------------------------------------------------- retention --

function retentionDays(name, fallback) {
  const n = Number(process.env[name]);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

// Deletes old rows in batches so a big cleanup never blocks the server for long.
function pruneOld() {
  const logCutoff = new Date(Date.now() - retentionDays("LOG_RETENTION_DAYS", 90) * DAY_MS).toISOString();
  const alertCutoff = new Date(Date.now() - retentionDays("ALERT_RETENTION_DAYS", 365) * DAY_MS).toISOString();
  let removed = 0;
  for (const [table, cutoff] of [["alerts", alertCutoff], ["logs", logCutoff]]) {
    let changes;
    do {
      changes = q(`DELETE FROM ${table} WHERE id IN (SELECT id FROM ${table} WHERE created_at < ? LIMIT 5000)`).run(cutoff).changes;
      removed += changes;
    } while (changes === 5000);
  }
  q("DELETE FROM audit_log WHERE id <= (SELECT id FROM audit_log ORDER BY id DESC LIMIT 1 OFFSET 10000)").run();
  return removed;
}

// Checkpoints the write-ahead log on shutdown.
function flush() {
  try {
    db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
  } catch {
    // database may already be closed
  }
}

// ------------------------------------------------- import old data.json --

// Earlier versions stored everything in data.json. Import it once into
// SQLite (keeping ids, so existing sessions stay valid), then rename the file.
function importLegacyJson() {
  if (!fs.existsSync(LEGACY_JSON) || userCount() > 0) return;
  let data;
  try {
    data = JSON.parse(fs.readFileSync(LEGACY_JSON, "utf8"));
  } catch (err) {
    console.error(`Couldn't read ${LEGACY_JSON} for import: ${err.message}`);
    return;
  }
  const levelFor = { Critical: 12, High: 10, Medium: 7, Low: 5 };

  transaction(() => {
    for (const u of data.users || []) {
      q("INSERT INTO users (id, username, email, password_hash, role, status, token_version, last_login_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)").run(
        u.id, u.username, String(u.email).toLowerCase(), u.passwordHash, u.role || "user", u.status || "active", u.tokenVersion || 0, u.lastLoginAt || null, u.createdAt || now()
      );
    }
    for (const s of data.sources || []) {
      q("INSERT OR IGNORE INTO sources (id, user_id, name, ip, port, protocol, status, last_seen, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)").run(
        s.id, s.userId, s.name, s.ip, s.port, s.protocol, s.status || "pending", s.lastSeen || null, s.createdAt || now()
      );
    }
    for (const a of data.auditLog || []) {
      q("INSERT INTO audit_log (id, user_id, action, detail, created_at) VALUES (?, ?, ?, ?, ?)").run(a.id, a.userId ?? null, a.action, a.detail ?? null, a.createdAt || now());
    }
    for (const l of data.logs || []) {
      q("INSERT INTO logs (created_at, source_ip, message, decoder) VALUES (?, ?, ?, 'legacy')").run(l.createdAt || now(), l.sourceIp, l.message);
    }
    for (const a of data.alerts || []) {
      q("INSERT INTO alerts (created_at, source_ip, level, severity, title, message, status) VALUES (?, ?, ?, ?, ?, ?, ?)").run(
        a.createdAt || now(), a.sourceIp, levelFor[a.severity] || 5, a.severity || "Low", a.type || "Legacy alert", a.message ?? null, a.status || "Open"
      );
    }
    // Never hand out an id the old store already used.
    const counters = data.counters || {};
    for (const [table, key] of [["users", "users"], ["sources", "sources"], ["audit_log", "auditLog"]]) {
      const seq = Number(counters[key]) || 0;
      if (q("UPDATE sqlite_sequence SET seq = max(seq, ?) WHERE name = ?").run(seq, table).changes === 0 && seq > 0) {
        q("INSERT INTO sqlite_sequence (name, seq) VALUES (?, ?)").run(table, seq);
      }
    }
    q("INSERT OR REPLACE INTO meta (key, value) VALUES ('legacy_import', ?)").run(`${LEGACY_JSON} at ${now()}`);
  });

  const renamed = `${LEGACY_JSON}.imported`;
  fs.renameSync(LEGACY_JSON, renamed);
  console.log(`Imported ${data.users?.length || 0} users and ${data.sources?.length || 0} sources from ${path.basename(LEGACY_JSON)} into ${path.basename(DB_FILE)}. The old file was renamed to ${path.basename(renamed)} - delete it once you've checked everything works.`);
}

importLegacyJson();
pruneOld();
setInterval(pruneOld, HOUR_MS).unref();

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
  searchLogs,
  searchAlerts,
  listLogs,
  listAlerts,
  getLog,
  getAlert,
  relatedAlerts,
  updateAlertStatus,
  getStats,
  pruneOld,
};
