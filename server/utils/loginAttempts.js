// In-memory brute-force protection for /api/auth/login.
// Failed attempts are counted inside a sliding window both per (client IP +
// email) and per client IP across all emails, so an attacker can neither
// hammer one account nor spray many accounts from the same address. This
// matters since this product's whole job is detecting exactly that kind of
// attack against *other* systems.

const WINDOW_MS = 10 * 60 * 1000; // 10 minutes
const MAX_PER_ACCOUNT = 5; // failures per IP + email
const MAX_PER_IP = 20; // failures per IP, any email
const MAX_KEYS = 50000;

const attempts = new Map();

function keysFor(ip, email) {
  return { account: `acct:${ip}:${email.toLowerCase()}`, ip: `ip:${ip}` };
}

function current(key, now) {
  const rec = attempts.get(key);
  if (!rec) return null;
  if (now - rec.firstAttempt >= WINDOW_MS) {
    attempts.delete(key);
    return null;
  }
  return rec;
}

function prune(now = Date.now()) {
  for (const [key, rec] of attempts) {
    if (now - rec.firstAttempt >= WINDOW_MS) attempts.delete(key);
  }
}

// Milliseconds until this IP/email may try again; 0 when not locked.
function lockRemainingMs(ip, email) {
  const now = Date.now();
  const keys = keysFor(ip, email);
  let wait = 0;
  const acct = current(keys.account, now);
  if (acct && acct.count >= MAX_PER_ACCOUNT) wait = Math.max(wait, WINDOW_MS - (now - acct.firstAttempt));
  const byIp = current(keys.ip, now);
  if (byIp && byIp.count >= MAX_PER_IP) wait = Math.max(wait, WINDOW_MS - (now - byIp.firstAttempt));
  return wait;
}

function registerFailure(ip, email) {
  const now = Date.now();
  for (const key of Object.values(keysFor(ip, email))) {
    const rec = current(key, now);
    if (rec) {
      rec.count += 1;
    } else {
      if (attempts.size >= MAX_KEYS) prune(now);
      attempts.set(key, { count: 1, firstAttempt: now });
    }
  }
}

// A successful login clears that account's counter; the per-IP counter keeps
// running so one valid login can't be used to reset a password-spraying run.
function clear(ip, email) {
  attempts.delete(keysFor(ip, email).account);
}

setInterval(prune, WINDOW_MS).unref();

export { lockRemainingMs, registerFailure, clear, MAX_PER_ACCOUNT, MAX_PER_IP };
