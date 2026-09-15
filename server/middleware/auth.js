import jwt from "jsonwebtoken";
import * as db from "../db.js";

// Shared by the HTTP middleware and the WebSocket handshake so both apply
// the exact same rules. Returns { user } or { status, code, error }.
function resolveToken(token) {
  if (!token || typeof token !== "string") {
    return { status: 401, code: "AUTH_REQUIRED", error: "Missing or invalid Authorization header" };
  }

  let payload;
  try {
    payload = jwt.verify(token, process.env.JWT_SECRET);
  } catch {
    return { status: 401, code: "AUTH_INVALID", error: "Invalid or expired token" };
  }

  const user = db.findUserById(payload.userId);
  if (!user) {
    return { status: 401, code: "AUTH_INVALID", error: "Account no longer exists" };
  }
  if ((user.status || "active") === "suspended") {
    return { status: 403, code: "ACCOUNT_SUSPENDED", error: "This account has been suspended. Contact an administrator." };
  }
  return { user };
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

export { requireAuth, resolveToken };
