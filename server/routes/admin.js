import express from "express";
import * as db from "../db.js";
import { requireAuth } from "../middleware/auth.js";
import { requireAdmin } from "../middleware/requireAdmin.js";
import { clampLimit, parseId } from "../utils/validate.js";

const router = express.Router();
router.use(requireAuth, requireAdmin);

function safeUser(u) {
  return { id: u.id, username: u.username, email: u.email, role: u.role, status: u.status };
}

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
  const targetId = parseId(req.params.id);
  const target = targetId && db.findUserById(targetId);
  if (!target) return res.status(404).json({ error: "User not found" });

  if (role === "user" && (target.role || "user") === "admin" && db.countAdmins() <= 1) {
    return res.status(400).json({ error: "Can't demote the last remaining admin" });
  }

  const updated = db.updateUserRole(targetId, role);
  db.addAuditLog({ userId: req.userId, action: "admin_role_change", detail: `Set ${updated.username} to ${role}` });
  res.json({ user: safeUser(updated) });
});

router.patch("/users/:id/status", (req, res) => {
  const { status } = req.body || {};
  if (!["active", "suspended"].includes(status)) {
    return res.status(400).json({ error: "status must be 'active' or 'suspended'" });
  }
  const targetId = parseId(req.params.id);
  if (!targetId) return res.status(404).json({ error: "User not found" });
  if (targetId === req.userId && status === "suspended") {
    return res.status(400).json({ error: "You can't suspend your own account" });
  }
  // Suspending also revokes the user's existing sessions (see db.updateUserStatus).
  const updated = db.updateUserStatus(targetId, status);
  if (!updated) return res.status(404).json({ error: "User not found" });

  db.addAuditLog({ userId: req.userId, action: "admin_status_change", detail: `Set ${updated.username} to ${status}` });
  res.json({ user: safeUser(updated) });
});

router.delete("/users/:id", (req, res) => {
  const targetId = parseId(req.params.id);
  if (targetId === req.userId) {
    return res.status(400).json({ error: "You can't delete your own account" });
  }
  const target = targetId && db.findUserById(targetId);
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
  res.json({ auditLog: db.listAllAuditLog(clampLimit(req.query.limit, 100, 500)) });
});

export default router;
