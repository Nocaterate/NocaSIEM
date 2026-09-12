// In-memory brute-force protection for /api/auth/login.
// Tracks failed attempts per (client IP + email) pair inside a sliding
// window and temporarily locks that pair out after too many failures -
// this protects the SIEM's own login from being brute-forced, which
// matters since this product's whole job is detecting exactly that kind
// of attack against *other* systems.

const WINDOW_MS = 10 * 60 * 1000; // 10 minutes
const MAX_ATTEMPTS = 5;

const attempts = new Map();

function key(ip, email) {
  return `${ip}:${email.toLowerCase()}`;
}

function prune(rec) {
  return rec && Date.now() - rec.firstAttempt < WINDOW_MS ? rec : null;
}

function isLocked(ip, email) {
  const rec = prune(attempts.get(key(ip, email)));
  return !!rec && rec.count >= MAX_ATTEMPTS;
}

function registerFailure(ip, email) {
  const k = key(ip, email);
  const rec = prune(attempts.get(k));
  if (rec) {
    rec.count += 1;
    attempts.set(k, rec);
  } else {
    attempts.set(k, { count: 1, firstAttempt: Date.now() });
  }
}

function clear(ip, email) {
  attempts.delete(key(ip, email));
}

function remainingLockMs(ip, email) {
  const rec = prune(attempts.get(key(ip, email)));
  if (!rec) return 0;
  return Math.max(0, WINDOW_MS - (Date.now() - rec.firstAttempt));
}

module.exports = { isLocked, registerFailure, clear, remainingLockMs, MAX_ATTEMPTS };
