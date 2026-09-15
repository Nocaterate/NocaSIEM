import express from "express";
import * as db from "../db.js";
import { requireAuth } from "../middleware/auth.js";
import { clampLimit, parseId } from "../utils/validate.js";

const router = express.Router();
router.use(requireAuth);

// Admins see every log/alert; everyone else only sees traffic from the
// source IPs they've registered themselves.
function scopeFor(req) {
  return db.visibleIpsFor(db.findUserById(req.userId));
}

router.get("/stats", (req, res) => {
  res.json(db.getStats(scopeFor(req)));
});

router.get("/alerts", (req, res) => {
  res.json({ alerts: db.listAlerts(clampLimit(req.query.limit, 50, 500), scopeFor(req)) });
});

router.patch("/alerts/:id", (req, res) => {
  const { status } = req.body || {};
  if (!["Open", "Investigating", "Resolved"].includes(status)) {
    return res.status(400).json({ error: "status must be Open, Investigating or Resolved" });
  }
  const id = parseId(req.params.id);
  const alert = id && db.updateAlertStatus(id, status, scopeFor(req));
  if (!alert) return res.status(404).json({ error: "Alert not found" });
  res.json({ alert });
});

router.get("/logs", (req, res) => {
  res.json({ logs: db.listLogs(clampLimit(req.query.limit, 100, 500), scopeFor(req)) });
});

router.get("/audit-log", (req, res) => {
  res.json({ auditLog: db.listAuditLog(req.userId, clampLimit(req.query.limit, 20, 100)) });
});

export default router;
