import express from "express";
import * as db from "../db.js";
import { requireAuth } from "../middleware/auth.js";
import { clampLimit, parseId } from "../utils/validate.js";
import { listRules } from "../engine/index.js";

const router = express.Router();
router.use(requireAuth);

const SEVERITIES = ["Critical", "High", "Medium", "Low"];
const STATUSES = ["Open", "Investigating", "Resolved"];

// Admins see every log/alert (scope null); everyone else only sees traffic
// from the source IPs they've registered themselves (scope = their user id).
function scopeFor(req) {
  const user = db.findUserById(req.userId);
  return user && user.role === "admin" ? null : req.userId;
}

function text(value, max = 200) {
  return typeof value === "string" && value.trim() && value.length <= max ? value.trim() : undefined;
}

function isoDate(value) {
  if (typeof value !== "string" || value.length > 40) return undefined;
  const t = Date.parse(value);
  return Number.isNaN(t) ? undefined : new Date(t).toISOString();
}

function nextCursor(rows, limit) {
  return rows.length === limit ? rows[rows.length - 1].id : null;
}

router.get("/stats", (req, res) => {
  res.json(db.getStats(scopeFor(req)));
});

router.get("/rules", (req, res) => {
  res.json({ rules: listRules() });
});

router.get("/alerts", (req, res) => {
  const qs = req.query;
  const limit = clampLimit(qs.limit, 50, 500);
  const levelMin = Number(qs.levelMin);
  const filters = {
    limit,
    q: text(qs.q),
    severity: typeof qs.severity === "string" ? qs.severity.split(",").filter((s) => SEVERITIES.includes(s)) : undefined,
    status: STATUSES.includes(qs.status) ? qs.status : undefined,
    ruleId: parseId(qs.ruleId) || undefined,
    mitre: typeof qs.mitre === "string" && /^T\d{4}(\.\d{3})?$/.test(qs.mitre) ? qs.mitre : undefined,
    srcIp: text(qs.srcIp, 45),
    sourceIp: text(qs.sourceIp, 45),
    user: text(qs.user, 100),
    levelMin: Number.isInteger(levelMin) && levelMin > 0 && levelMin <= 15 ? levelMin : undefined,
    from: isoDate(qs.from),
    to: isoDate(qs.to),
    before: parseId(qs.before) || undefined,
  };
  const alerts = db.searchAlerts(filters, scopeFor(req));
  res.json({ alerts, nextCursor: nextCursor(alerts, limit) });
});

router.get("/alerts/:id", (req, res) => {
  const scope = scopeFor(req);
  const id = parseId(req.params.id);
  const alert = id && db.getAlert(id, scope);
  if (!alert) return res.status(404).json({ error: "Alert not found" });
  res.json({
    alert,
    log: alert.logId ? db.getLog(alert.logId, scope) || null : null,
    related: db.relatedAlerts(alert, scope),
    rule: listRules().find((r) => r.id === alert.ruleId) || null,
  });
});

router.patch("/alerts/:id", (req, res) => {
  const { status } = req.body || {};
  if (!STATUSES.includes(status)) {
    return res.status(400).json({ error: "status must be Open, Investigating or Resolved" });
  }
  const id = parseId(req.params.id);
  const alert = id && db.updateAlertStatus(id, status, scopeFor(req));
  if (!alert) return res.status(404).json({ error: "Alert not found" });
  res.json({ alert });
});

router.get("/logs", (req, res) => {
  const qs = req.query;
  const limit = clampLimit(qs.limit, 100, 500);
  const filters = {
    limit,
    q: text(qs.q),
    sourceIp: text(qs.sourceIp, 45),
    srcIp: text(qs.srcIp, 45),
    user: text(qs.user, 100),
    decoder: text(qs.decoder, 40),
    action: text(qs.action, 60),
    from: isoDate(qs.from),
    to: isoDate(qs.to),
    before: parseId(qs.before) || undefined,
  };
  const logs = db.searchLogs(filters, scopeFor(req));
  res.json({ logs, nextCursor: nextCursor(logs, limit) });
});

router.get("/logs/:id", (req, res) => {
  const id = parseId(req.params.id);
  const log = id && db.getLog(id, scopeFor(req));
  if (!log) return res.status(404).json({ error: "Log not found" });
  res.json({ log });
});

router.get("/audit-log", (req, res) => {
  res.json({ auditLog: db.listAuditLog(req.userId, clampLimit(req.query.limit, 20, 100)) });
});

export default router;
