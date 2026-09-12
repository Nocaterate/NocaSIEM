const jwt = require("jsonwebtoken");
const db = require("../db");

function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;

  if (!token) {
    return res.status(401).json({ error: "Missing or invalid Authorization header" });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    const user = db.findUserById(payload.userId);
    if (!user) {
      return res.status(401).json({ error: "Account no longer exists" });
    }
    if ((user.status || "active") === "suspended") {
      return res.status(403).json({ error: "This account has been suspended. Contact an administrator." });
    }
    req.userId = payload.userId;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

module.exports = { requireAuth };
