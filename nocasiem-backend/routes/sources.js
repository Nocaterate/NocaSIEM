const express = require("express");
const net = require("net");
const db = require("../db");
const { requireAuth } = require("../middleware/auth");

const router = express.Router();
router.use(requireAuth);

const IP_REGEX = /^((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)$/;

router.get("/", (req, res) => {
  res.json({ sources: db.listSources(req.userId) });
});

router.post("/", (req, res) => {
  const { name, ip, port, protocol } = req.body || {};

  if (!name || !ip || !port) {
    return res.status(400).json({ error: "name, ip and port are required" });
  }
  if (!IP_REGEX.test(ip)) {
    return res.status(400).json({ error: "ip must be a valid IPv4 address" });
  }
  const portNum = Number(port);
  if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) {
    return res.status(400).json({ error: "port must be an integer between 1 and 65535" });
  }

  const source = db.createSource(req.userId, {
    name,
    ip,
    port: portNum,
    protocol: (protocol || "UDP").toUpperCase(),
  });
  db.addAuditLog({ userId: req.userId, action: "source_added", detail: `${name} (${ip}:${portNum}/${source.protocol})` });
  res.status(201).json({ source });
});

router.delete("/:id", (req, res) => {
  const sources = db.listSources(req.userId);
  const target = sources.find((s) => s.id === Number(req.params.id));
  const ok = db.deleteSource(req.userId, Number(req.params.id));
  if (!ok) return res.status(404).json({ error: "Source not found" });
  if (target) {
    db.addAuditLog({ userId: req.userId, action: "source_removed", detail: `${target.name} (${target.ip}:${target.port})` });
  }
  res.status(204).end();
});

// Actively checks whether the registered IP:port is reachable.
// For TCP sources this is a real TCP handshake test. UDP is connectionless,
// so there's no reliable way to "connect" to it - we say so explicitly
// instead of returning a misleading pass/fail.
router.post("/:id/test", (req, res) => {
  const source = db.listSources(req.userId).find((s) => s.id === Number(req.params.id));
  if (!source) return res.status(404).json({ error: "Source not found" });

  if (source.protocol === "UDP") {
    return res.json({
      reachable: null,
      reason: "UDP is connectionless - reachability can't be actively tested. Status will switch to Active once it starts sending logs.",
    });
  }

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
  socket.once("error", (err) => finish({ reachable: false, reason: err.code || err.message }));

  socket.connect(source.port, source.ip);
});

module.exports = router;
