import express from "express";
import net from "node:net";
import * as db from "../db.js";
import { requireAuth } from "../middleware/auth.js";
import { rateLimit } from "../utils/rateLimit.js";
import { LIMITS, isNonEmptyString, isIPv4, parseId, probeTargetProblem } from "../utils/validate.js";

const router = express.Router();
router.use(requireAuth);

const testLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  key: (req) => `user:${req.userId}`,
  message: "Too many connectivity tests. Wait a minute and try again.",
});

router.get("/", (req, res) => {
  res.json({ sources: db.listSources(req.userId) });
});

router.post("/", (req, res) => {
  const { name, ip, port, protocol = "UDP" } = req.body || {};

  if (!isNonEmptyString(name, LIMITS.sourceName)) {
    return res.status(400).json({ error: `name is required (at most ${LIMITS.sourceName} characters)` });
  }
  if (!isIPv4(ip)) {
    return res.status(400).json({ error: "ip must be a valid IPv4 address (e.g. 10.0.0.5)" });
  }
  const portNum = Number(port);
  if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) {
    return res.status(400).json({ error: "port must be an integer between 1 and 65535" });
  }
  const proto = typeof protocol === "string" ? protocol.toUpperCase() : "";
  if (!["UDP", "TCP"].includes(proto)) {
    return res.status(400).json({ error: "protocol must be UDP or TCP" });
  }

  // Each IP belongs to one account. Otherwise anyone could register another
  // user's device IP and read that device's logs.
  const existing = db.findSourceByIp(ip);
  if (existing) {
    return res.status(409).json({
      error: existing.userId === req.userId ? "You've already registered this IP address." : "This IP address is already registered by another account.",
    });
  }
  if (db.listSources(req.userId).length >= LIMITS.sourcesPerUser) {
    return res.status(400).json({ error: `You can register at most ${LIMITS.sourcesPerUser} sources.` });
  }

  const source = db.createSource(req.userId, { name: name.trim(), ip, port: portNum, protocol: proto });
  db.addAuditLog({ userId: req.userId, action: "source_added", detail: `${source.name} (${ip}:${portNum}/${proto})` });
  res.status(201).json({ source });
});

router.delete("/:id", (req, res) => {
  const id = parseId(req.params.id);
  const target = id && db.listSources(req.userId).find((s) => s.id === id);
  if (!target) return res.status(404).json({ error: "Source not found" });
  db.deleteSource(req.userId, id);
  db.addAuditLog({ userId: req.userId, action: "source_removed", detail: `${target.name} (${target.ip}:${target.port})` });
  res.status(204).end();
});

// Actively checks whether the registered IP:port is reachable.
// For TCP sources this is a real TCP handshake test. UDP is connectionless,
// so there's no reliable way to "connect" to it - we say so explicitly
// instead of returning a misleading pass/fail.
router.post("/:id/test", testLimiter, (req, res) => {
  const id = parseId(req.params.id);
  const source = id && db.listSources(req.userId).find((s) => s.id === id);
  if (!source) return res.status(404).json({ error: "Source not found" });

  if (source.protocol === "UDP") {
    return res.json({
      reachable: null,
      reason: "UDP is connectionless - reachability can't be actively tested. Status will switch to Active once it starts sending logs.",
    });
  }

  const user = db.findUserById(req.userId);
  const blocked = probeTargetProblem(source.ip, user && user.role === "admin");
  if (blocked) return res.json({ reachable: null, reason: blocked });

  const socket = new net.Socket();
  const start = Date.now();
  let settled = false;

  const finish = (payload) => {
    if (settled) return;
    settled = true;
    socket.destroy();
    res.json(payload);
  };

  socket.setTimeout(2000);
  socket.once("connect", () => finish({ reachable: true, latencyMs: Date.now() - start }));
  socket.once("timeout", () => finish({ reachable: false, reason: "Connection timed out" }));
  socket.once("error", (err) => finish({ reachable: false, reason: err.code || "Connection failed" }));

  // source.ip is a validated literal IPv4 address, so no DNS lookup happens here.
  socket.connect({ port: source.port, host: source.ip, family: 4 });
});

export default router;
