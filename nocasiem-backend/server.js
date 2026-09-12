require("dotenv").config();
const http = require("http");
const express = require("express");
const cors = require("cors");
const { WebSocketServer } = require("ws");

const authRoutes = require("./routes/auth");
const sourceRoutes = require("./routes/sources");
const dataRoutes = require("./routes/data");
const adminRoutes = require("./routes/admin");
const { startUdpIngestListener, startTcpIngestListener } = require("./ingest");

if (!process.env.JWT_SECRET) {
  console.error("Missing JWT_SECRET in .env - copy .env.example to .env and set one. Exiting.");
  process.exit(1);
}

const app = express();
app.use(cors({ origin: process.env.CORS_ORIGIN || "*" }));
app.use(express.json());

app.get("/api/health", (req, res) => res.json({ status: "ok" }));
app.use("/api/auth", authRoutes);
app.use("/api/sources", sourceRoutes);
app.use("/api/admin", adminRoutes);
app.use("/api", dataRoutes);

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: "Internal server error" });
});

const server = http.createServer(app);

// WebSocket server: pushes new logs/alerts to the dashboard the instant
// they're ingested, instead of the frontend having to poll for them.
const wss = new WebSocketServer({ server, path: "/ws" });

function broadcast(event) {
  const payload = JSON.stringify(event);
  wss.clients.forEach((client) => {
    if (client.readyState === client.OPEN) client.send(payload);
  });
}

wss.on("connection", (ws) => {
  ws.send(JSON.stringify({ type: "connected" }));
});

const HTTP_PORT = process.env.PORT || 4000;
const INGEST_UDP_PORT = process.env.INGEST_PORT || 5514;
const INGEST_TCP_PORT = process.env.INGEST_TCP_PORT || 5515;

server.listen(HTTP_PORT, () => {
  console.log(`NocaSIEM API listening on http://localhost:${HTTP_PORT}`);
  console.log(`WebSocket live feed on ws://localhost:${HTTP_PORT}/ws`);
});

startUdpIngestListener({ port: INGEST_UDP_PORT, onEvent: broadcast });
startTcpIngestListener({ port: INGEST_TCP_PORT, onEvent: broadcast });
