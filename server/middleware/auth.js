import jwt from "jsonwebtoken";
import * as db from "../db.js";

const TOKEN_TTL = "7d";

// `tv` (token version) lets the server revoke every token for a user at once:
// it's bumped on password change and suspension.
function issueToken(user) {
  return jwt.sign({ userId: user.id, tv: user.tokenVersion || 0 }, process.env.JWT_SECRET, {
    algorithm: "HS256",
    expiresIn: TOKEN_TTL,
  });
}

// Shared by the HTTP middleware and the WebSocket handshake so both apply
// the exact same rules. Returns { user, tokenVersion, expiresAt } or
// { status, code, error }.
function resolveToken(token) {
  if (!token || typeof token !== "string" || token.length > 2048) {
    return { status: 401, code: "AUTH_REQUIRED", error: "Missing or invalid Authorization header" };
  }

  let payload;
  try {
    // Pin the algorithm so a token signed any other way is always rejected.
    payload = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ["HS256"] });
  } catch {
    return { status: 401, code: "AUTH_INVALID", error: "Invalid or expired token" };
  }

  const user = db.findUserById(payload.userId);
  if (!user) {
    return { status: 401, code: "AUTH_INVALID", error: "Account no longer exists" };
  }
  // Checked before the token version so a suspended user sees why they were signed out.
  if ((user.status || "active") === "suspended") {
    return { status: 403, code: "ACCOUNT_SUSPENDED", error: "This account has been suspended. Contact an administrator." };
  }
  if ((payload.tv || 0) !== (user.tokenVersion || 0)) {
    return { status: 401, code: "AUTH_INVALID", error: "Your session has ended. Please sign in again." };
  }
  return { user, tokenVersion: payload.tv || 0, expiresAt: payload.exp * 1000 };
}

function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;

  const result = resolveToken(token);
  if (!result.user) {
    return res.status(result.status).json({ error: result.error, code: result.code });
  }
  req.userId = result.user.id;
  next();
}

export { requireAuth, resolveToken, issueToken };
