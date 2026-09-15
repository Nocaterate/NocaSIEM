// Sends sample syslog lines to NocaSIEM's UDP ingest port so you can check
// that logs and alerts show up on the dashboard.
//
//   npm run test-log                      sample mix of normal + suspicious events
//   npm run test-log -- --brute-force     6 failed logins -> escalates to Critical
//   npm run test-log -- --host 192.168.1.20
//
// Lines sent from this PC arrive from 127.0.0.1, so register a source with
// IP 127.0.0.1 in Settings first (unregistered IPs are ignored).

import "../server/env.js";
import dgram from "node:dgram";

const args = process.argv.slice(2);
const hostIndex = args.indexOf("--host");
const host = hostIndex >= 0 ? args[hostIndex + 1] : "127.0.0.1";
const port = Number(process.env.INGEST_PORT) || 5514;

const SAMPLE = [
  "sshd[2211]: Accepted publickey for alice from 192.168.1.50 port 50522",
  "sshd[2212]: Failed password for root from 203.0.113.7 port 41122",
  "kernel: firewall DROPPED IN=eth0 SRC=198.51.100.23 DST=192.168.1.1 PROTO=TCP DPT=23",
  "ids: Port scan detected from 198.51.100.23 (nmap)",
  "av: Malware signature match Trojan.Generic in C:\\Users\\Public\\invoice.exe",
  "cron[3100]: (backup) CMD (/usr/local/bin/nightly-backup.sh)",
];

const BRUTE_FORCE = Array.from({ length: 6 }, (_, i) => `sshd[40${i}]: Failed password for admin from 203.0.113.99 port ${51000 + i}`);

const lines = args.includes("--brute-force") ? BRUTE_FORCE : SAMPLE;
const socket = dgram.createSocket("udp4");

for (const line of lines) {
  await new Promise((resolve, reject) => socket.send(line, port, host, (err) => (err ? reject(err) : resolve())));
  console.log(`sent -> ${host}:${port}  ${line}`);
}
socket.close();
console.log(`\nDone. If nothing appears on the dashboard, check that a source with this PC's IP (127.0.0.1 when testing locally) is registered in Settings.`);
