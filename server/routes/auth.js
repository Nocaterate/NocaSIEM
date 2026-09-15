import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import * as db from "../db.js";
import * as loginAttempts from "../utils/loginAttempts.js";
import { requireAuth } from "../middleware/auth.js";

const router = express.Router();

function issueToken(user) {
  return jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: "7d" });
}

function publicUser(user) {
  return {
    id: user.id,
    username: user.username,
    email: user.email,
    role: user.role || "user",
    status: user.status || "active",
    lastLoginAt: user.lastLoginAt || null,
    createdAt: user.createdAt,
  };
}

router.post("/register", async (req, res) => {
  const { username, email, password } = req.body || {};

  // Set ALLOW_REGISTRATION=false once your own admin account exists, so
  // strangers can't sign up on a public instance. The very first account
  // can always be created, otherwise nobody could ever get in.
  if (process.env.ALLOW_REGISTRATION === "false" && db.userCount() > 0) {
    return res.status(403).json({ error: "Sign-up is disabled on this instance. Ask an administrator for access." });
  }
  if (typeof username !== "string" || typeof email !== "string" || typeof password !== "string" || !username.trim() || !email || !password) {
    return res.status(400).json({ error: "username, email and password are required" });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: "Please provide a valid email address" });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: "Password must be at least 8 characters" });
  }
  if (db.findUserByEmail(email)) {
    return res.status(409).json({ error: "An account with this email already exists" });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const role = db.userCount() === 0 ? "admin" : "user"; // first account bootstraps as admin
  const user = db.createUser({ username: username.trim(), email: email.trim(), passwordHash, role });
  db.addAuditLog({ userId: user.id, action: "register", detail: role === "admin" ? "Account created (first user - admin)" : "Account created" });
  const token = issueToken(user);

  res.status(201).json({ token, user: publicUser(user) });
});

router.post("/login", async (req, res) => {
  const { email, password } = req.body || {};
  const ip = req.ip;

  if (typeof email !== "string" || typeof password !== "string" || !email || !password) {
    return res.status(400).json({ error: "email and password are required" });
  }

  if (loginAttempts.isLocked(ip, email)) {
    const waitSec = Math.ceil(loginAttempts.remainingLockMs(ip, email) / 1000);
    return res.status(429).json({ error: `Too many failed attempts. Try again in ${waitSec}s.` });
  }

  const user = db.findUserByEmail(email);
  if (!user) {
    loginAttempts.registerFailure(ip, email);
    return res.status(401).json({ error: "Invalid email or password" });
  }

  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) {
    loginAttempts.registerFailure(ip, email);
    return res.status(401).json({ error: "Invalid email or password" });
  }

  if ((user.status || "active") === "suspended") {
    return res.status(403).json({ error: "This account has been suspended. Contact an administrator.", code: "ACCOUNT_SUSPENDED" });
  }

  loginAttempts.clear(ip, email);
  db.recordLogin(user.id);
  db.addAuditLog({ userId: user.id, action: "login", detail: `Signed in from ${ip}` });
  const token = issueToken(user);
  res.json({ token, user: publicUser(user) });
});

router.get("/me", requireAuth, (req, res) => {
  const user = db.findUserById(req.userId);
  if (!user) return res.status(404).json({ error: "User not found" });
  res.json({ user: publicUser(user) });
});

router.patch("/me", requireAuth, (req, res) => {
  const { username, email } = req.body || {};
  const user = db.findUserById(req.userId);
  if (!user) return res.status(404).json({ error: "User not found" });

  if (username !== undefined && !username.trim()) {
    return res.status(400).json({ error: "Username cannot be empty" });
  }
  if (email !== undefined) {
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: "Please provide a valid email address" });
    }
    const existing = db.findUserByEmail(email);
    if (existing && existing.id !== user.id) {
      return res.status(409).json({ error: "Email already in use by another account" });
    }
  }

  const updated = db.updateUser(req.userId, { username, email });
  db.addAuditLog({ userId: req.userId, action: "profile_update", detail: "Updated profile information" });
  res.json({ user: publicUser(updated) });
});

router.patch("/password", requireAuth, async (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: "currentPassword and newPassword are required" });
  }
  if (newPassword.length < 8) {
    return res.status(400).json({ error: "New password must be at least 8 characters" });
  }

  const user = db.findUserById(req.userId);
  if (!user) return res.status(404).json({ error: "User not found" });

  const valid = await bcrypt.compare(currentPassword, user.passwordHash);
  // 400, not 401: the session itself is fine, and the dashboard treats 401 as "signed out".
  if (!valid) return res.status(400).json({ error: "Current password is incorrect" });

  const passwordHash = await bcrypt.hash(newPassword, 10);
  db.updateUserPassword(req.userId, passwordHash);
  db.addAuditLog({ userId: req.userId, action: "password_change", detail: "Password changed" });
  res.json({ ok: true });
});

export default router;
