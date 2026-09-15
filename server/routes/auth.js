import express from "express";
import bcrypt from "bcryptjs";
import * as db from "../db.js";
import * as loginAttempts from "../utils/loginAttempts.js";
import { requireAuth, issueToken } from "../middleware/auth.js";
import { rateLimit } from "../utils/rateLimit.js";
import { LIMITS, isNonEmptyString, isValidEmail, normalizeEmail, passwordProblem } from "../utils/validate.js";

const router = express.Router();

const BCRYPT_ROUNDS = 10;

// Logins for unknown emails still run a bcrypt comparison against this hash,
// so response timing can't reveal which emails have accounts.
const DUMMY_HASH = bcrypt.hashSync("nocasiem-timing-equalizer", BCRYPT_ROUNDS);

// Caps password-guessing and bcrypt CPU load per client IP, on top of the
// per-account lockout in utils/loginAttempts.js.
const authLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 30,
  message: "Too many attempts from your network. Try again in a few minutes.",
});
const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  message: "Too many sign-ups from your network. Try again later.",
});

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

function registrationClosed() {
  return process.env.ALLOW_REGISTRATION === "false" && db.userCount() > 0;
}

// On a fresh public deployment the first account becomes admin. Setting
// ADMIN_EMAIL means only that address can claim it, so nobody can race you.
function bootstrapBlocked(email) {
  if (db.userCount() > 0 || !process.env.ADMIN_EMAIL) return false;
  return normalizeEmail(email) !== normalizeEmail(process.env.ADMIN_EMAIL);
}

router.post("/register", registerLimiter, async (req, res) => {
  const { username, email, password } = req.body || {};

  if (registrationClosed()) {
    return res.status(403).json({ error: "Sign-up is disabled on this instance. Ask an administrator for access." });
  }
  if (!isNonEmptyString(username, LIMITS.username)) {
    return res.status(400).json({ error: `Username is required (at most ${LIMITS.username} characters)` });
  }
  if (!isValidEmail(email)) {
    return res.status(400).json({ error: "Please provide a valid email address" });
  }
  const pwProblem = passwordProblem(password);
  if (pwProblem) return res.status(400).json({ error: pwProblem });
  if (bootstrapBlocked(email)) {
    return res.status(403).json({ error: "This instance hasn't been set up yet. Only the configured administrator can create the first account." });
  }
  if (db.findUserByEmail(email)) {
    return res.status(409).json({ error: "An account with this email already exists" });
  }

  const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);

  // Re-check after the slow hash: another sign-up may have finished meanwhile.
  if (registrationClosed() || bootstrapBlocked(email)) {
    return res.status(403).json({ error: "Sign-up is disabled on this instance. Ask an administrator for access." });
  }
  if (db.findUserByEmail(email)) {
    return res.status(409).json({ error: "An account with this email already exists" });
  }

  const role = db.userCount() === 0 ? "admin" : "user"; // first account bootstraps as admin
  const user = db.createUser({ username: username.trim(), email: normalizeEmail(email), passwordHash, role });
  db.addAuditLog({ userId: user.id, action: "register", detail: role === "admin" ? "Account created (first user - admin)" : "Account created" });

  res.status(201).json({ token: issueToken(user), user: publicUser(user) });
});

router.post("/login", authLimiter, async (req, res) => {
  const { email, password } = req.body || {};
  const ip = req.ip;

  if (typeof email !== "string" || typeof password !== "string" || !email || !password || email.length > LIMITS.email || password.length > 1024) {
    return res.status(400).json({ error: "email and password are required" });
  }

  const waitMs = loginAttempts.lockRemainingMs(ip, email);
  if (waitMs > 0) {
    return res.status(429).json({ error: `Too many failed attempts. Try again in ${Math.ceil(waitMs / 1000)}s.`, code: "RATE_LIMITED" });
  }

  const user = db.findUserByEmail(email);
  const valid = await bcrypt.compare(password, user ? user.passwordHash : DUMMY_HASH);
  if (!user || !valid) {
    loginAttempts.registerFailure(ip, email);
    return res.status(401).json({ error: "Invalid email or password" });
  }

  if ((user.status || "active") === "suspended") {
    return res.status(403).json({ error: "This account has been suspended. Contact an administrator.", code: "ACCOUNT_SUSPENDED" });
  }

  loginAttempts.clear(ip, email);
  db.recordLogin(user.id);
  db.addAuditLog({ userId: user.id, action: "login", detail: `Signed in from ${ip}` });
  res.json({ token: issueToken(user), user: publicUser(user) });
});

router.get("/me", requireAuth, (req, res) => {
  const user = db.findUserById(req.userId);
  if (!user) return res.status(404).json({ error: "User not found" });
  res.json({ user: publicUser(user) });
});

router.patch("/me", requireAuth, authLimiter, async (req, res) => {
  const { username, email, currentPassword } = req.body || {};
  const user = db.findUserById(req.userId);
  if (!user) return res.status(404).json({ error: "User not found" });

  const changes = {};
  if (username !== undefined) {
    if (!isNonEmptyString(username, LIMITS.username)) {
      return res.status(400).json({ error: `Username cannot be empty (at most ${LIMITS.username} characters)` });
    }
    changes.username = username.trim();
  }

  if (email !== undefined) {
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: "Please provide a valid email address" });
    }
    const normalized = normalizeEmail(email);
    if (normalized !== user.email.toLowerCase()) {
      // The email is the sign-in name, so changing it needs the password -
      // otherwise a stolen session could lock the real owner out.
      const ok = typeof currentPassword === "string" && currentPassword.length <= 1024 && (await bcrypt.compare(currentPassword, user.passwordHash));
      if (!ok) {
        return res.status(400).json({ error: "Enter your current password to change your email.", code: "PASSWORD_REQUIRED" });
      }
      const existing = db.findUserByEmail(normalized);
      if (existing && existing.id !== user.id) {
        return res.status(409).json({ error: "Email already in use by another account" });
      }
      changes.email = normalized;
    }
  }

  const updated = db.updateUser(req.userId, changes);
  if (!updated) return res.status(404).json({ error: "User not found" });
  db.addAuditLog({ userId: req.userId, action: "profile_update", detail: changes.email ? "Updated profile and email" : "Updated profile information" });
  res.json({ user: publicUser(updated) });
});

router.patch("/password", requireAuth, authLimiter, async (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (typeof currentPassword !== "string" || !currentPassword || currentPassword.length > 1024) {
    return res.status(400).json({ error: "currentPassword and newPassword are required" });
  }
  const pwProblem = passwordProblem(newPassword);
  if (pwProblem) return res.status(400).json({ error: `New ${pwProblem.charAt(0).toLowerCase()}${pwProblem.slice(1)}` });

  const user = db.findUserById(req.userId);
  if (!user) return res.status(404).json({ error: "User not found" });

  const valid = await bcrypt.compare(currentPassword, user.passwordHash);
  // 400, not 401: the session itself is fine, and the dashboard treats 401 as "signed out".
  if (!valid) return res.status(400).json({ error: "Current password is incorrect" });

  const passwordHash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
  const updated = db.updateUserPassword(req.userId, passwordHash);
  if (!updated) return res.status(404).json({ error: "User not found" });
  db.addAuditLog({ userId: req.userId, action: "password_change", detail: "Password changed (other sessions signed out)" });

  // Every older token is now invalid; hand this session a fresh one.
  res.json({ ok: true, token: issueToken(updated) });
});

export default router;
