import * as db from "../db.js";

function requireAdmin(req, res, next) {
  const user = db.findUserById(req.userId);
  if (!user || (user.role || "user") !== "admin") {
    return res.status(403).json({ error: "Admin access required" });
  }
  next();
}

export { requireAdmin };
