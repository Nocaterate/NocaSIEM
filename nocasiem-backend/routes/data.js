const express = require("express");
const db = require("../db");
const { requireAuth } = require("../middleware/auth");

const router = express.Router();
router.use(requireAuth);

router.get("/stats", (req, res) => {
  res.json(db.getStats());
});

router.get("/alerts", (req, res) => {
  const limit = Number(req.query.limit) || 50;
  res.json({ alerts: db.listAlerts(limit) });
});

router.patch("/alerts/:id", (req, res) => {
  const { status } = req.body || {};
  if (!["Open", "Investigating", "Resolved"].includes(status)) {
    return res.status(400).json({ error: "status must be Open, Investigating or Resolved" });
  }
  const alert = db.updateAlertStatus(Number(req.params.id), status);
  if (!alert) return res.status(404).json({ error: "Alert not found" });
  res.json({ alert });
});

router.get("/logs", (req, res) => {
  const limit = Number(req.query.limit) || 100;
  res.json({ logs: db.listLogs(limit) });
});

router.get("/audit-log", (req, res) => {
  const limit = Number(req.query.limit) || 20;
  res.json({ auditLog: db.listAuditLog(req.userId, limit) });
});

module.exports = router;
