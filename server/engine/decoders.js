// Log decoders: turn a raw syslog line into structured fields.
//
// Step 1 parses the syslog header (RFC 3164, RFC 5424, ISO-timestamp and
// MikroTik styles) to find the host, program and message body. Step 2 runs a
// program-specific decoder over the body to extract fields such as the
// attacker IP (srcip), user, action and ports. Rules then match on those
// fields instead of guessing from raw text.
//
// Every regex here is anchored and avoids nested quantifiers, and input lines
// are capped in ingest.js, so hostile log lines can't cause catastrophic
// backtracking.

const IPV4 = "(?:\\d{1,3}\\.){3}\\d{1,3}";
const IP_ANY = `(${IPV4}|[0-9a-fA-F:]{2,39})`;

// ---------------------------------------------------------------- header --

const RFC5424 = /^(?:<(\d{1,3})>)?1 (\S+) (\S+) (\S+) (\S+) (\S+) (-|\[[^\]]*\](?:\[[^\]]*\])*) ?(.*)$/s;
const RFC3164 = /^(?:<(\d{1,3})>)?([A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}) (\S+) (.*)$/s;
const ISO_HEADER = /^(?:<(\d{1,3})>)?(\d{4}-\d{2}-\d{2}T\S+) (\S+) (.*)$/s;
const PRI_ONLY = /^<(\d{1,3})>(.*)$/s;
const TAG = /^([A-Za-z0-9_\-./]{1,64})(?:\[(\d{1,10})\])?: ?(.*)$/s;
const MIKROTIK_TOPICS = /^([a-z]+(?:,[a-z]+)+) (.*)$/s;

function splitPri(pri) {
  if (pri === undefined) return {};
  const n = Number(pri);
  return { facility: Math.floor(n / 8), syslogSeverity: n % 8 };
}

function parseHeader(line) {
  let m;
  if ((m = RFC5424.exec(line))) {
    return { ...splitPri(m[1]), timestamp: m[2], host: nil(m[3]), program: nil(m[4]), pid: nil(m[5]), body: m[8] };
  }
  let rest = line;
  let header = {};
  if ((m = RFC3164.exec(line)) || (m = ISO_HEADER.exec(line))) {
    header = { ...splitPri(m[1]), timestamp: m[2], host: m[3] };
    rest = m[4];
  } else if ((m = PRI_ONLY.exec(line))) {
    header = splitPri(m[1]);
    rest = m[2];
  }
  if ((m = MIKROTIK_TOPICS.exec(rest))) {
    return { ...header, program: "mikrotik", topics: m[1].split(","), body: m[2] };
  }
  if ((m = TAG.exec(rest))) {
    return { ...header, program: m[1], pid: m[2], body: m[3] };
  }
  return { ...header, body: rest };
}

function nil(v) {
  return v === "-" ? undefined : v;
}

// -------------------------------------------------------------- decoders --

// Each decoder: { name, programs (optional), test (optional), rules: [[regex, fn]] }
// or a custom decode(body, header) function returning fields or null.

function matchList(body, list) {
  for (const [re, build] of list) {
    const m = re.exec(body);
    if (m) return build(m);
  }
  return null;
}

const SSHD = [
  [new RegExp(`^Failed (password|publickey|none|keyboard-interactive/pam) for (invalid user )?(\\S+) from ${IP_ANY} port (\\d+)`), (m) => ({ action: "ssh_failed_auth", authMethod: m[1], invalidUser: !!m[2], user: m[3], srcip: m[4], srcport: +m[5] })],
  [new RegExp(`^Accepted (\\S+) for (\\S+) from ${IP_ANY} port (\\d+)`), (m) => ({ action: "ssh_login_success", authMethod: m[1], user: m[2], srcip: m[3], srcport: +m[4] })],
  [new RegExp(`^Invalid user (\\S*) from ${IP_ANY}(?: port (\\d+))?`), (m) => ({ action: "ssh_invalid_user", invalidUser: true, user: m[1], srcip: m[2], srcport: m[3] ? +m[3] : undefined })],
  [new RegExp(`^(?:error: )?maximum authentication attempts exceeded for (invalid user )?(\\S+) from ${IP_ANY} port (\\d+)`), (m) => ({ action: "ssh_max_attempts", invalidUser: !!m[1], user: m[2], srcip: m[3], srcport: +m[4] })],
  [new RegExp(`^pam_unix\\(sshd:auth\\): authentication failure;.*rhost=${IP_ANY}(?:\\s+user=(\\S+))?`), (m) => ({ action: "ssh_failed_auth", authMethod: "pam", srcip: m[1], user: m[2] })],
  [new RegExp(`^Did not receive identification string from ${IP_ANY}`), (m) => ({ action: "ssh_probe", srcip: m[1] })],
  [new RegExp(`^(?:error: )?kex_exchange_identification: .*?(?:from ${IP_ANY})?$`), (m) => ({ action: "ssh_probe", srcip: m[1] })],
  [new RegExp(`^banner exchange: Connection from ${IP_ANY} port (\\d+): invalid format`), (m) => ({ action: "ssh_probe", srcip: m[1], srcport: +m[2] })],
  [new RegExp(`^Disconnected from (?:invalid |authenticating )?user (\\S+) ${IP_ANY} port (\\d+) \\[preauth\\]`), (m) => ({ action: "ssh_preauth_disconnect", user: m[1], srcip: m[2], srcport: +m[3] })],
];

const SUDO = [
  [/^\s*(\S+) : user NOT in sudoers ; .*?USER=(\S+) ; COMMAND=(.*)$/, (m) => ({ action: "sudo_not_allowed", user: m[1], dstuser: m[2], command: m[3] })],
  [/^\s*(\S+) : (\d+) incorrect password attempts? ; .*?USER=(\S+) ; COMMAND=(.*)$/, (m) => ({ action: "sudo_auth_failure", user: m[1], attempts: +m[2], dstuser: m[3], command: m[4] })],
  [/^\s*(\S+) : TTY=\S+ ; PWD=.*? ; USER=(\S+) ; COMMAND=(.*)$/, (m) => ({ action: "sudo_command", user: m[1], dstuser: m[2], command: m[3] })],
  [/^pam_unix\(sudo:auth\): authentication failure;.*?ruser=(\S*).*?user=(\S+)/, (m) => ({ action: "sudo_auth_failure", user: m[1] || m[2] })],
];

const SU = [
  [/^FAILED SU \(to (\S+)\) (\S+) on (\S+)/, (m) => ({ action: "su_failure", dstuser: m[1], user: m[2] })],
  [/^pam_unix\(su(?:-l)?:auth\): authentication failure;.*?ruser=(\S*).*?user=(\S+)/, (m) => ({ action: "su_failure", user: m[1], dstuser: m[2] })],
  [/^\(to (\S+)\) (\S+) on (\S+)/, (m) => ({ action: "su_success", dstuser: m[1], user: m[2] })],
];

const ACCOUNTS = [
  [/^new user: name=([^,]+), UID=(\d+)/, (m) => ({ action: "user_created", dstuser: m[1], uid: +m[2] })],
  [/^add '([^']+)' to (?:shadow )?group '([^']+)'/, (m) => ({ action: "user_added_to_group", dstuser: m[1], group: m[2] })],
  [/^user (\S+) added by (\S+) to group (\S+)/, (m) => ({ action: "user_added_to_group", dstuser: m[1], user: m[2], group: m[3] })],
  [/^pam_unix\((?:passwd|chpasswd):chauthtok\): password changed for (\S+)/, (m) => ({ action: "password_changed", dstuser: m[1] })],
  [/^password for '([^']+)' changed by '([^']+)'/, (m) => ({ action: "password_changed", dstuser: m[1], user: m[2] })],
  [/^delete user '([^']+)'/, (m) => ({ action: "user_deleted", dstuser: m[1] })],
  [/^new group: name=([^,]+)/, (m) => ({ action: "group_created", group: m[1] })],
];

// iptables / ufw / most Linux-based routers: "[UFW BLOCK] IN=eth0 SRC=... DST=... PROTO=TCP SPT=.. DPT=.."
function decodeKernelFirewall(body) {
  if (!/\bSRC=/.test(body) || !/\bDST=/.test(body)) return null;
  const kv = {};
  for (const m of body.matchAll(/\b([A-Z]{2,5})=(\S*)/g)) kv[m[1]] = m[2];
  const verdict = /\[UFW (?:LIMIT )?(BLOCK|ALLOW|AUDIT)\]/.exec(body) || /\b(DROP(?:PED)?|REJECT(?:ED)?|BLOCK(?:ED)?|DENY|DENIED|ACCEPT(?:ED)?|ALLOW(?:ED)?)\b/i.exec(body);
  return {
    action: verdict ? normalizeVerdict(verdict[1]) : "logged",
    srcip: kv.SRC,
    dstip: kv.DST,
    protocol: kv.PROTO,
    srcport: kv.SPT ? +kv.SPT : undefined,
    dstport: kv.DPT ? +kv.DPT : undefined,
    inInterface: kv.IN || undefined,
  };
}

function normalizeVerdict(word) {
  return /^(drop|reject|block|deny)/i.test(word) ? "blocked" : /^(accept|allow|pass)/i.test(word) ? "allowed" : "logged";
}

// pfSense / OPNsense filterlog CSV
function decodeFilterlog(body) {
  const f = body.split(",");
  if (f.length < 20) return null;
  const base = { action: normalizeVerdict(f[6]), direction: f[7], inInterface: f[4] };
  if (f[8] === "4") {
    return { ...base, protocol: f[16]?.toUpperCase(), srcip: f[18], dstip: f[19], srcport: toPort(f[20]), dstport: toPort(f[21]) };
  }
  if (f[8] === "6") {
    return { ...base, protocol: f[12]?.toUpperCase(), srcip: f[15], dstip: f[16], srcport: toPort(f[17]), dstport: toPort(f[18]) };
  }
  return null;
}

function toPort(v) {
  const n = Number(v);
  return Number.isInteger(n) && n > 0 && n < 65536 ? n : undefined;
}

// MikroTik RouterOS: "firewall,info input: in:ether1 out:(unknown 0), ... proto TCP (SYN), 1.2.3.4:5678->5.6.7.8:22, len 60"
const MIKROTIK_ACCOUNT = [
  [new RegExp(`login failure for user (\\S+) from ${IP_ANY} via (\\S+)`), (m) => ({ action: "router_login_failure", user: m[1], srcip: m[2], service: m[3] })],
  [new RegExp(`user (\\S+) logged in from ${IP_ANY} via (\\S+)`), (m) => ({ action: "router_login_success", user: m[1], srcip: m[2], service: m[3] })],
  [new RegExp(`user (\\S+) logged out from ${IP_ANY} via (\\S+)`), (m) => ({ action: "router_logout", user: m[1], srcip: m[2], service: m[3] })],
];

function decodeMikrotik(body, header) {
  const account = matchList(body, MIKROTIK_ACCOUNT);
  if (account) return account;
  if (!header.topics?.includes("firewall")) return null;
  const m = /proto (\w+)(?: \([^)]*\))?, (\d{1,3}(?:\.\d{1,3}){3}):(\d+)->(\d{1,3}(?:\.\d{1,3}){3}):(\d+)/.exec(body);
  if (!m) return null;
  return {
    action: /\b(drop|reject|block|deny)/i.test(body) ? "blocked" : "logged",
    protocol: m[1].toUpperCase(),
    srcip: m[2],
    srcport: +m[3],
    dstip: m[4],
    dstport: +m[5],
    chain: /^(?:\S+ )?(\w+):/.exec(body)?.[1],
  };
}

// Apache / Nginx combined access log
const ACCESS_LOG = new RegExp(`^${IP_ANY} \\S+ (\\S+) \\[([^\\]]+)\\] "([A-Z]{3,10}) (\\S+)(?: HTTP/[\\d.]+)?" (\\d{3}) (\\d+|-)(?: "([^"]*)" "([^"]*)")?`);

function decodeAccessLog(body) {
  const m = ACCESS_LOG.exec(body);
  if (!m) return null;
  return {
    action: "web_request",
    srcip: m[1],
    user: m[2] === "-" ? undefined : m[2],
    method: m[4],
    url: m[5],
    urlDecoded: safeDecode(m[5]),
    status: +m[6],
    bytes: m[7] === "-" ? 0 : +m[7],
    referer: m[8],
    userAgent: m[9],
  };
}

function safeDecode(s) {
  try {
    return decodeURIComponent(s.replace(/\+/g, " "));
  } catch {
    return s;
  }
}

// Windows events forwarded as JSON (e.g. NXLog `to_json()`).
function pick(obj, ...keys) {
  for (const k of keys) {
    const v = obj[k];
    if (v !== undefined && v !== null && v !== "" && v !== "-") return String(v);
  }
  return undefined;
}

function cleanIp(v) {
  if (!v || v === "-" || v === "::1" || v === "127.0.0.1") return undefined;
  return v.replace(/^::ffff:/, "");
}

function decodeWindows(obj) {
  const idRaw = pick(obj, "EventID", "EventId", "event_id", "eventId");
  if (!idRaw || !/^\d+$/.test(idRaw)) return null;
  const eventId = Number(idRaw);
  const fields = {
    action: `win_${eventId}`,
    eventId,
    channel: pick(obj, "Channel", "channel"),
    provider: pick(obj, "SourceName", "ProviderName", "Provider"),
    winHost: pick(obj, "Hostname", "Computer", "hostname"),
    user: pick(obj, "TargetUserName", "UserName"),
    subjectUser: pick(obj, "SubjectUserName"),
    srcip: cleanIp(pick(obj, "IpAddress", "SourceAddress", "ClientAddress")),
    srcport: toPort(pick(obj, "IpPort")),
    logonType: pick(obj, "LogonType") ? Number(pick(obj, "LogonType")) : undefined,
    workstation: pick(obj, "WorkstationName"),
    process: pick(obj, "NewProcessName", "ProcessName", "Image"),
    command: pick(obj, "CommandLine"),
    parentProcess: pick(obj, "ParentProcessName"),
    script: pick(obj, "ScriptBlockText")?.slice(0, 4000),
    service: pick(obj, "ServiceName"),
    imagePath: pick(obj, "ImagePath", "ServiceFileName"),
    task: pick(obj, "TaskName"),
    threat: pick(obj, "Threat Name", "ThreatName"),
    status: pick(obj, "Status", "FailureReason"),
  };
  // Group-membership events: TargetUserName is the group, MemberName the member.
  if ([4728, 4732, 4756].includes(eventId)) {
    fields.group = fields.user;
    fields.dstuser = pick(obj, "MemberName", "MemberSid");
    fields.user = fields.subjectUser;
  }
  if (eventId === 4720 || eventId === 4726) {
    fields.dstuser = fields.user;
    fields.user = fields.subjectUser;
  }
  return fields;
}

function decodeJsonBody(body) {
  const start = body.indexOf("{");
  if (start < 0 || start > 64 || !body.trimEnd().endsWith("}")) return null;
  let obj;
  try {
    obj = JSON.parse(body.slice(start));
  } catch {
    return null;
  }
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) return null;
  const win = decodeWindows(obj);
  if (win) return { decoder: "windows", fields: win };
  // Other JSON logs: keep simple top-level values, map common names.
  const fields = {};
  for (const [k, v] of Object.entries(obj).slice(0, 40)) {
    if (["string", "number", "boolean"].includes(typeof v)) fields[k] = typeof v === "string" ? v.slice(0, 500) : v;
  }
  fields.srcip = cleanIp(pick(obj, "srcip", "src_ip", "source_ip", "client_ip", "ip"));
  fields.user = pick(obj, "user", "username", "user_name");
  return { decoder: "json", fields };
}

// Fallback for anything else: grab "from <ip>" / "src=<ip>" and "user=<name>".
function decodeGeneric(body) {
  const fields = {};
  const ip = new RegExp(`(?:\\bfrom|\\bsrc(?:ip)?[=:]|\\bclient[=:]|\\brhost=)\\s*${IP_ANY}`, "i").exec(body);
  if (ip) fields.srcip = ip[1];
  const user = /\b(?:user(?:name)?)[=:]\s*"?([\w.@\\-]{1,64})/i.exec(body) || /\bfor (?:invalid user )?([\w.@\\-]{1,64}) from\b/i.exec(body);
  if (user) fields.user = user[1];
  return fields;
}

const PROGRAM_DECODERS = [
  { name: "sshd", programs: ["sshd", "sshd-session"], decode: (b) => matchList(b, SSHD) },
  { name: "sudo", programs: ["sudo"], decode: (b) => matchList(b, SUDO) },
  { name: "su", programs: ["su"], decode: (b) => matchList(b, SU) },
  { name: "accounts", programs: ["useradd", "userdel", "usermod", "groupadd", "gpasswd", "passwd", "chpasswd"], decode: (b) => matchList(b, ACCOUNTS) },
  { name: "pfsense", programs: ["filterlog"], decode: decodeFilterlog },
  { name: "mikrotik", programs: ["mikrotik"], decode: decodeMikrotik },
  { name: "firewall", programs: ["kernel", "ufw", "iptables"], decode: decodeKernelFirewall },
];

// Decodes one sanitized log line. Always returns an object; `decoder` tells
// which decoder understood it ("generic" when none did).
export function decode(line) {
  const header = parseHeader(line);
  const body = header.body ?? line;
  const program = header.program?.toLowerCase();
  const base = {
    host: header.host,
    program: header.program,
    pid: header.pid ? Number(header.pid) || undefined : undefined,
    facility: header.facility,
    syslogSeverity: header.syslogSeverity,
    body,
  };

  const json = decodeJsonBody(body);
  if (json) return { ...base, decoder: json.decoder, fields: compact(json.fields) };

  for (const d of PROGRAM_DECODERS) {
    if (!d.programs.includes(program)) continue;
    const fields = d.decode(body, header);
    if (fields) return { ...base, decoder: d.name, fields: compact(fields) };
  }

  // Content-based decoders for lines without a recognizable program tag.
  const access = decodeAccessLog(body);
  if (access) return { ...base, decoder: "web-access", fields: compact(access) };
  const fw = decodeKernelFirewall(body);
  if (fw) return { ...base, decoder: "firewall", fields: compact(fw) };
  for (const [name, list] of [["sshd", SSHD], ["sudo", SUDO]]) {
    const fields = matchList(body, list);
    if (fields) return { ...base, decoder: name, fields: compact(fields) };
  }

  return { ...base, decoder: "generic", fields: compact(decodeGeneric(body)) };
}

function compact(obj) {
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    if (v !== undefined && v !== null && v !== "" && !(typeof v === "number" && Number.isNaN(v))) out[k] = v;
  }
  return out;
}
