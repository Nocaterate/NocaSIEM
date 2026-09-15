// Small in-memory fixed-window rate limiter. State lives in this process,
// which matches how NocaSIEM runs (a single Node server).

export function createLimiter({ windowMs, max, maxKeys = 50000 }) {
  const hits = new Map();

  function prune(now = Date.now()) {
    for (const [key, rec] of hits) {
      if (now - rec.start >= windowMs) hits.delete(key);
    }
  }

  function take(key) {
    const now = Date.now();
    let rec = hits.get(key);
    if (!rec || now - rec.start >= windowMs) {
      if (!rec && hits.size >= maxKeys) {
        prune(now);
        // Still full: refuse rather than let a flood of distinct keys grow memory forever.
        if (hits.size >= maxKeys) return { allowed: false, retryAfterMs: windowMs };
      }
      rec = { start: now, count: 0 };
      hits.set(key, rec);
    }
    rec.count += 1;
    return { allowed: rec.count <= max, retryAfterMs: windowMs - (now - rec.start) };
  }

  setInterval(prune, windowMs).unref();
  return { take };
}

// Express middleware version. `key` defaults to the client IP (make sure
// TRUST_PROXY is set correctly when running behind a proxy).
export function rateLimit({ windowMs, max, key = (req) => req.ip, message = "Too many requests. Please slow down." }) {
  const limiter = createLimiter({ windowMs, max });
  return (req, res, next) => {
    const { allowed, retryAfterMs } = limiter.take(key(req));
    if (allowed) return next();
    res.setHeader("Retry-After", String(Math.ceil(retryAfterMs / 1000)));
    res.status(429).json({ error: message, code: "RATE_LIMITED" });
  };
}
