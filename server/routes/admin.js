import express from "express";
import * as db from "../db.js";
import { requireAuth } from "../middleware/auth.js";
import { requireAdmin } from "../middleware/requireAdmin.js";

const router = express.Router();
router.use(requireAuth, requireAdmin);

// Never returns passwordHash or any credential material - by design.
// Passwords are one-way bcrypt hashes; nobody, including admins, can
// recover the original password. Use "suspend" or delete the account
// instead of trying to view/reset credentials directly.
router.get("/users", (req, res) => {
  res.json({ users: db.listAllUsers() });
});

router.patch("/users/:id/role", (req, res) => {
  const { role } = req.body || {};
  if (!["admin", "user"].includes(role)) {
    return res.status(400).json({ error: "role must be 'admin' or 'user'" });
  }
  const targetId = Number(req.params.id);
  const target = db.findUserById(targetId);
  if (!target) return res.status(404).json({ error: "User not found" });

  if (role === "user" && (target.role || "user") === "admin" && db.countAdmins() <= 1) {
    return res.status(400).json({ error: "Can't demote the last remaining admin" });
  }

  const updated = db.updateUserRole(targetId, role);
  db.addAuditLog({ userId: req.userId, action: "admin_role_change", detail: `Set ${updated.username} to ${role}` });
  res.json({ user: { id: updated.id, username: updated.username, email: updated.email, role: updated.role, status: updated.status } });
});

router.patch("/users/:id/status", (req, res) => {
  const { status } = req.body || {};
  if (!["active", "suspended"].includes(status)) {
    return res.status(400).json({ error: "status must be 'active' or 'suspended'" });
  }
  const targetId = Number(req.params.id);
  if (targetId === req.userId && status === "suspended") {
    return res.status(400).json({ error: "You can't suspend your own account" });
  }
  const updated = db.updateUserStatus(targetId, status);
  if (!updated) return res.status(404).json({ error: "User not found" });

  db.addAuditLog({ userId: req.userId, action: "admin_status_change", detail: `Set ${updated.username} to ${status}` });
  res.json({ user: { id: updated.id, username: updated.username, email: updated.email, role: updated.role, status: updated.status } });
});

router.delete("/users/:id", (req, res) => {
  const targetId = Number(req.params.id);
  if (targetId === req.userId) {
    return res.status(400).json({ error: "You can't delete your own account" });
  }
  const target = db.findUserById(targetId);
  if (!target) return res.status(404).json({ error: "User not found" });
  if ((target.role || "user") === "admin" && db.countAdmins() <= 1) {
    return res.status(400).json({ error: "Can't delete the last remaining admin" });
  }

  db.deleteUserAccount(targetId);
  db.addAuditLog({ userId: req.userId, action: "admin_user_deleted", detail: `Deleted ${target.username}` });
  res.status(204).end();
});

// Org-wide activity feed - unlike GET /api/audit-log (your own activity
// only), this shows every user's actions for admin oversight.
router.get("/audit-log", (req, res) => {
  const limit = Number(req.query.limit) || 100;
  res.json({ auditLog: db.listAllAuditLog(limit) });
});

export default router;
