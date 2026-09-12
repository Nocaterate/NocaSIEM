const dgram = require("dgram");
const net = require("net");
const db = require("./db");
const { classify } = require("./utils/rules");

// Shared handling for a single incoming log line, regardless of whether
// it arrived over UDP or TCP.
function processLine(message, sourceIp, onEvent) {
  const trimmed = message.trim();
  if (!trimmed) return;

  db.markSourceSeen(sourceIp);

  const logEntry = db.addLog({ sourceIp, message: trimmed });
  onEvent({ type: "log", data: logEntry });

  const match = classify(trimmed, sourceIp);
  if (match) {
    const alert = db.addAlert({ sourceIp, ...match, message: trimmed });
    onEvent({ type: "alert", data: alert });
  }
}

// UDP listener - one collector port, every UDP source points here.
function startUdpIngestListener({ port, onEvent }) {
  const socket = dgram.createSocket("udp4");

  socket.on("message", (msg, rinfo) => {
    processLine(msg.toString("utf8"), rinfo.address, onEvent);
  });
  socket.on("error", (err) => console.error("UDP ingest listener error:", err));
  socket.bind(port, () => console.log(`Syslog ingest listener bound on UDP port ${port}`));

  return socket;
}

// TCP listener - for sources configured with protocol "TCP". Log lines
// are newline-delimited, same as standard syslog-over-TCP.
function startTcpIngestListener({ port, onEvent }) {
  const server = net.createServer((socket) => {
    const sourceIp = (socket.remoteAddress || "").replace(/^::ffff:/, "");
    let buffer = "";

    socket.on("data", (chunk) => {
      buffer += chunk.toString("utf8");
      let idx;
      while ((idx = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, idx);
        buffer = buffer.slice(idx + 1);
        processLine(line, sourceIp, onEvent);
      }
    });
    socket.on("error", () => {});
  });

  server.on("error", (err) => console.error("TCP ingest listener error:", err));
  server.listen(port, () => console.log(`Syslog ingest listener bound on TCP port ${port}`));

  return server;
}

module.exports = { startUdpIngestListener, startTcpIngestListener };
