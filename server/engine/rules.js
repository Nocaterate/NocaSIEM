// Built-in detection rules, modelled on Wazuh's ruleset.
//
// Levels (0-15) follow Wazuh's scale:
//   0-3  informational (stored and used for correlation, no alert by default)
//   4-6  Low   7-9 Medium   10-12 High   13-15 Critical
//
// Rule kinds:
//   Atomic       conditions on a single event:
//                  decoder, action (string or list), field: { name: value | list | RegExp | fn }, pattern (RegExp on the message body)
//   Frequency    fires when rules in `ifGroup` / `ifRule` matched `frequency` times within `timeframe`
//                seconds for the same device and `same` fields (optionally counting `distinct` values)
//   Sequence     atomic conditions plus `after`: the event only matches if `after.group` matched
//                at least `after.count` times for the same key within `after.timeframe` seconds
//
// Optional `ignore: seconds` on an atomic rule raises at most one alert per attacker IP in that
// window (repeats still count toward correlation rules).
//
// To add your own rule, append an object below with a unique id (use 100000+ for custom rules).

const SENSITIVE_PORTS = [21, 22, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 27017];

export function isPublicIp(ip) {
  if (!ip || typeof ip !== "string") return false;
  if (ip.includes(":")) return !/^(fe80|fc|fd|::1$)/i.test(ip);
  const [a, b] = ip.split(".").map(Number);
  if (a === 10 || a === 127 || a === 0 || a >= 224) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 169 && b === 254) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  return true;
}

const PRIV_GROUP_LINUX = /^(sudo|wheel|admin|root|adm|docker|lxd)$/i;
const PRIV_GROUP_WINDOWS = /^(administrators|domain admins|enterprise admins|schema admins|remote desktop users)$/i;

const SQLI = /(\bunion\b.{0,40}\bselect\b|\bselect\b.{0,40}\bfrom\b|'\s{0,5}or\s{0,5}'?\d+'?\s{0,5}=\s{0,5}'?\d|\bor\s+1\s*=\s*1\b|\bsleep\(\s*\d+\s*\)|\bbenchmark\(|information_schema|;\s*drop\s+table)/i;
const TRAVERSAL = /(\.\.\/|\.\.\\|%2e%2e|\/etc\/passwd|\/etc\/shadow|win\.ini|boot\.ini)/i;
const XSS = /(<script|javascript:|onerror\s*=|onload\s*=|document\.cookie|<svg\b[^>]{0,40}\bon\w+=)/i;
const CMD_INJECTION = /((;|\||`|\$\()\s*(wget|curl|bash|sh|nc|ncat|powershell|cmd\.exe|python|perl)\b|\bcmd=|\bexec=|c99\.php|r57\.php|\/bin\/sh\b)/i;
const SCANNER_UA = /(sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|wpscan|nuclei|acunetix|nessus|openvas|ffuf|feroxbuster|hydra)/i;
const SENSITIVE_FILES = /\/(\.env\b|\.git\/|\.aws\/|wp-config\.php|phpmyadmin|\.htpasswd|server-status|actuator\/env)/i;

const SUSPICIOUS_POWERSHELL = /(invoke-mimikatz|downloadstring|downloadfile|invoke-expression|\biex\b|frombase64string|-enc(?:odedcommand)?\s|net\.webclient|add-mppreference\s+-exclusion|set-mppreference\s+-disablerealtimemonitoring)/i;
const SUSPICIOUS_PROCESS = /(mimikatz|procdump.{0,40}lsass|vssadmin(?:\.exe)?\s+delete\s+shadows|wmic(?:\.exe)?\s+shadowcopy\s+delete|wevtutil(?:\.exe)?\s+cl\b|certutil(?:\.exe)?.{0,40}-urlcache|bcdedit.{0,40}recoveryenabled\s+no|comsvcs.{0,40}minidump|reg(?:\.exe)?\s+save\s+hk(?:lm|ey_local_machine)\\(?:sam|security))/i;

const urlField = (re) => (_v, f) => re.test(f.urlDecoded || "") || re.test(f.url || "");

export const RULES = [
  // ------------------------------------------------------------ SSH (Linux)
  { id: 5700, level: 3, description: "SSH login succeeded", decoder: "sshd", action: "ssh_login_success", groups: ["sshd", "authentication_success"], mitre: ["T1078"] },
  { id: 5701, level: 5, description: "SSH authentication failed", decoder: "sshd", action: "ssh_failed_auth", groups: ["sshd", "authentication_failed"], mitre: ["T1110.001"] },
  { id: 5702, level: 5, description: "SSH login attempt with a non-existent user", decoder: "sshd", action: "ssh_invalid_user", groups: ["sshd", "authentication_failed", "invalid_login"], mitre: ["T1110.001"] },
  { id: 5703, level: 7, description: "SSH authentication failed for root", decoder: "sshd", action: "ssh_failed_auth", field: { user: "root" }, groups: ["sshd", "authentication_failed"], mitre: ["T1110.001"] },
  { id: 5704, level: 6, description: "SSH maximum authentication attempts exceeded", decoder: "sshd", action: "ssh_max_attempts", groups: ["sshd", "authentication_failed"], mitre: ["T1110"] },
  { id: 5705, level: 3, description: "SSH connection probe without a login attempt", decoder: "sshd", action: "ssh_probe", groups: ["sshd", "recon"], mitre: ["T1046"] },
  { id: 5706, level: 10, description: "SSH brute force: 8+ failed logins from the same IP in 2 minutes", ifRule: [5701, 5702, 5703, 5704], frequency: 8, timeframe: 120, same: ["srcip"], groups: ["sshd", "brute_force"], mitre: ["T1110"] },
  { id: 5707, level: 10, description: "SSH password spraying: failed logins for 5+ different users from the same IP in 5 minutes", ifRule: [5701, 5702, 5703], frequency: 5, distinct: "user", timeframe: 300, same: ["srcip"], groups: ["sshd", "brute_force"], mitre: ["T1110.003"] },
  { id: 5708, level: 13, description: "SSH login succeeded after repeated failures from the same IP (possible compromise)", decoder: "sshd", action: "ssh_login_success", after: { group: "authentication_failed", count: 5, timeframe: 600, same: ["srcip"] }, groups: ["sshd", "authentication_success", "compromise"], mitre: ["T1110", "T1078"] },
  { id: 5709, level: 9, description: "Direct SSH login as root", decoder: "sshd", action: "ssh_login_success", field: { user: "root" }, groups: ["sshd", "authentication_success"], mitre: ["T1078.003"] },

  // ----------------------------------------------------------- sudo / su
  { id: 5401, level: 3, description: "Command run with sudo", decoder: "sudo", action: "sudo_command", groups: ["sudo"], mitre: ["T1548.003"] },
  { id: 5402, level: 5, description: "sudo authentication failed", decoder: "sudo", action: "sudo_auth_failure", groups: ["sudo", "authentication_failed"], mitre: ["T1548.003"] },
  { id: 5403, level: 8, description: "Root shell opened with sudo", decoder: "sudo", action: "sudo_command", field: { dstuser: "root", command: /(^|\/)(bash|sh|zsh|su)(\s+-?\w*)?$/ }, groups: ["sudo", "privilege_escalation"], mitre: ["T1548.003"] },
  { id: 5404, level: 9, description: "User not in sudoers tried to run a command as another user", decoder: "sudo", action: "sudo_not_allowed", groups: ["sudo", "privilege_escalation"], mitre: ["T1548.003"] },
  { id: 5405, level: 5, description: "su authentication failed", decoder: "su", action: "su_failure", groups: ["su", "authentication_failed"], mitre: ["T1548"] },
  { id: 5406, level: 10, description: "Repeated sudo/su failures by the same user in 5 minutes", ifRule: [5402, 5405], frequency: 5, timeframe: 300, same: ["user"], groups: ["privilege_escalation", "brute_force"], mitre: ["T1548"] },

  // ------------------------------------------------ Linux account changes
  { id: 5901, level: 8, description: "New Linux user account created", decoder: "accounts", action: "user_created", groups: ["account_changed"], mitre: ["T1136.001"] },
  { id: 5902, level: 12, description: "Linux user created with UID 0 (root privileges)", decoder: "accounts", action: "user_created", field: { uid: 0 }, groups: ["account_changed", "privilege_escalation"], mitre: ["T1136.001"] },
  { id: 5903, level: 10, description: "User added to a privileged Linux group", decoder: "accounts", action: "user_added_to_group", field: { group: PRIV_GROUP_LINUX }, groups: ["account_changed", "privilege_escalation"], mitre: ["T1098"] },
  { id: 5904, level: 4, description: "Linux user added to a group", decoder: "accounts", action: "user_added_to_group", groups: ["account_changed"], mitre: ["T1098"] },
  { id: 5905, level: 6, description: "Linux user password changed", decoder: "accounts", action: "password_changed", groups: ["account_changed"], mitre: ["T1098"] },
  { id: 5906, level: 6, description: "Linux user account deleted", decoder: "accounts", action: "user_deleted", groups: ["account_changed"], mitre: ["T1531"] },

  // ---------------------------------------------------- firewall / router
  { id: 4100, level: 0, description: "Firewall event", decoder: ["firewall", "pfsense", "mikrotik"], field: { dstport: (v) => v !== undefined }, groups: ["firewall"] },
  { id: 4101, level: 2, description: "Firewall blocked a connection", decoder: ["firewall", "pfsense", "mikrotik"], action: "blocked", groups: ["firewall", "firewall_drop"] },
  { id: 4102, level: 3, description: "Firewall blocked an external connection to a sensitive port", decoder: ["firewall", "pfsense", "mikrotik"], action: "blocked", field: { dstport: SENSITIVE_PORTS, srcip: isPublicIp }, groups: ["firewall", "firewall_drop", "recon"], mitre: ["T1046"] },
  { id: 4103, level: 10, description: "Port scan: connections to 15+ different ports from the same IP in 1 minute", ifRule: [4100], frequency: 15, distinct: "dstport", timeframe: 60, same: ["srcip"], groups: ["firewall", "recon"], mitre: ["T1046"] },
  { id: 4104, level: 8, description: "Flood: 100+ blocked connections from the same IP in 1 minute", ifRule: [4101, 4102], frequency: 100, timeframe: 60, same: ["srcip"], groups: ["firewall", "dos"], mitre: ["T1498"] },
  { id: 4105, level: 6, description: "Firewall allowed an external connection to a remote-access port", decoder: ["firewall", "pfsense", "mikrotik"], action: "allowed", field: { dstport: [22, 23, 3389, 5900, 5985, 5986], srcip: isPublicIp }, groups: ["firewall", "remote_access"], mitre: ["T1133"] },
  { id: 4201, level: 5, description: "Router login failed", decoder: "mikrotik", action: "router_login_failure", groups: ["router", "authentication_failed"], mitre: ["T1110.001"] },
  { id: 4202, level: 3, description: "Router login succeeded", decoder: "mikrotik", action: "router_login_success", groups: ["router", "authentication_success"], mitre: ["T1078"] },
  { id: 4203, level: 10, description: "Router brute force: 6+ failed logins from the same IP in 2 minutes", ifRule: [4201], frequency: 6, timeframe: 120, same: ["srcip"], groups: ["router", "brute_force"], mitre: ["T1110"] },
  { id: 4204, level: 13, description: "Router login succeeded after repeated failures (possible compromise)", decoder: "mikrotik", action: "router_login_success", after: { group: "authentication_failed", count: 4, timeframe: 600, same: ["srcip"] }, groups: ["router", "compromise"], mitre: ["T1110", "T1078"] },

  // --------------------------------------------------------------- web
  { id: 31100, level: 0, description: "Web request returned a client error", decoder: "web-access", field: { status: (v) => v >= 400 && v < 500 }, groups: ["web", "web_error"] },
  { id: 31101, level: 7, description: "SQL injection attempt", decoder: "web-access", field: { url: urlField(SQLI) }, groups: ["web", "web_attack"], mitre: ["T1190"] },
  { id: 31102, level: 7, description: "Path traversal attempt", decoder: "web-access", field: { url: urlField(TRAVERSAL) }, groups: ["web", "web_attack"], mitre: ["T1190"] },
  { id: 31103, level: 6, description: "Cross-site scripting (XSS) attempt", decoder: "web-access", field: { url: urlField(XSS) }, groups: ["web", "web_attack"], mitre: ["T1190"] },
  { id: 31104, level: 10, description: "Command injection or web shell access attempt", decoder: "web-access", field: { url: urlField(CMD_INJECTION) }, groups: ["web", "web_attack"], mitre: ["T1505.003", "T1059"] },
  { id: 31105, level: 6, description: "Request from a known vulnerability scanner", decoder: "web-access", field: { userAgent: SCANNER_UA }, ignore: 600, groups: ["web", "recon"], mitre: ["T1595.002"] },
  { id: 31106, level: 5, description: "Attempt to access a sensitive file or admin panel", decoder: "web-access", field: { url: urlField(SENSITIVE_FILES) }, ignore: 300, groups: ["web", "recon"], mitre: ["T1595.003"] },
  { id: 31107, level: 10, description: "Directory brute force: 20+ client errors from the same IP in 1 minute", ifRule: [31100], frequency: 20, timeframe: 60, same: ["srcip"], groups: ["web", "recon"], mitre: ["T1595.003"] },
  { id: 31108, level: 12, description: "Sustained web attack: 5+ attack requests from the same IP in 5 minutes", ifRule: [31101, 31102, 31103, 31104], frequency: 5, timeframe: 300, same: ["srcip"], groups: ["web", "web_attack"], mitre: ["T1190"] },

  // ------------------------------------------------------------ Windows
  { id: 60101, level: 3, description: "Windows logon succeeded", decoder: "windows", field: { eventId: 4624 }, groups: ["windows", "authentication_success"], mitre: ["T1078"] },
  { id: 60102, level: 5, description: "Windows logon failed", decoder: "windows", field: { eventId: 4625 }, groups: ["windows", "authentication_failed"], mitre: ["T1110.001"] },
  { id: 60103, level: 10, description: "Windows brute force: 8+ failed logons from the same IP in 2 minutes", ifRule: [60102], frequency: 8, timeframe: 120, same: ["srcip"], groups: ["windows", "brute_force"], mitre: ["T1110"] },
  { id: 60104, level: 10, description: "Windows password spraying: failed logons for 5+ different accounts from the same IP in 5 minutes", ifRule: [60102], frequency: 5, distinct: "user", timeframe: 300, same: ["srcip"], groups: ["windows", "brute_force"], mitre: ["T1110.003"] },
  { id: 60105, level: 13, description: "Windows logon succeeded after repeated failures from the same IP (possible compromise)", decoder: "windows", field: { eventId: 4624 }, after: { group: "authentication_failed", count: 5, timeframe: 600, same: ["srcip"] }, groups: ["windows", "compromise"], mitre: ["T1110", "T1078"] },
  { id: 60106, level: 8, description: "Remote Desktop logon from a public IP address", decoder: "windows", field: { eventId: 4624, logonType: 10, srcip: isPublicIp }, groups: ["windows", "remote_access"], mitre: ["T1133", "T1021.001"] },
  { id: 60107, level: 9, description: "Windows account locked out", decoder: "windows", field: { eventId: 4740 }, groups: ["windows", "authentication_failed"], mitre: ["T1110"] },
  { id: 60108, level: 8, description: "Windows user account created", decoder: "windows", field: { eventId: 4720 }, groups: ["windows", "account_changed"], mitre: ["T1136.001"] },
  { id: 60109, level: 12, description: "User added to a privileged Windows group", decoder: "windows", field: { eventId: [4728, 4732, 4756], group: PRIV_GROUP_WINDOWS }, groups: ["windows", "account_changed", "privilege_escalation"], mitre: ["T1098"] },
  { id: 60110, level: 13, description: "Windows Security event log was cleared", decoder: "windows", field: { eventId: 1102 }, groups: ["windows", "defense_evasion"], mitre: ["T1070.001"] },
  { id: 60111, level: 10, description: "New Windows service installed", decoder: "windows", field: { eventId: [7045, 4697] }, groups: ["windows", "persistence"], mitre: ["T1543.003"] },
  { id: 60112, level: 7, description: "Scheduled task created", decoder: "windows", field: { eventId: 4698 }, groups: ["windows", "persistence"], mitre: ["T1053.005"] },
  { id: 60113, level: 12, description: "Suspicious PowerShell script (download, encoded or credential-theft commands)", decoder: "windows", field: { eventId: 4104, script: SUSPICIOUS_POWERSHELL }, groups: ["windows", "execution"], mitre: ["T1059.001"] },
  { id: 60114, level: 12, description: "Suspicious process: credential dumping, shadow copy deletion or log tampering", decoder: "windows", field: { eventId: 4688, command: SUSPICIOUS_PROCESS }, groups: ["windows", "execution"], mitre: ["T1003", "T1490", "T1105"] },
  { id: 60115, level: 12, description: "Microsoft Defender detected malware", decoder: "windows", field: { eventId: [1116, 1117] }, groups: ["windows", "malware"], mitre: ["T1204.002"] },
  { id: 60116, level: 12, description: "Microsoft Defender real-time protection was disabled", decoder: "windows", field: { eventId: [5001, 5010, 5012] }, groups: ["windows", "defense_evasion"], mitre: ["T1562.001"] },

  // ------------------------------- generic keywords (undecoded log lines)
  { id: 1001, level: 12, description: "Malware keyword in log", decoder: ["generic", "json"], pattern: /\b(malware|ransomware|trojan|backdoor|rootkit)\b/i, groups: ["malware"], mitre: ["T1204.002"] },
  { id: 1002, level: 10, description: "Privilege escalation keyword in log", decoder: ["generic", "json"], pattern: /(privilege escalation|root access|unauthorized access)/i, groups: ["privilege_escalation"], mitre: ["T1068"] },
  { id: 1003, level: 5, description: "Authentication failure keyword in log", decoder: ["generic", "json"], pattern: /(authentication fail|failed password|login fail|brute.?force|invalid password)/i, groups: ["authentication_failed"], mitre: ["T1110"] },
  { id: 1004, level: 8, description: "Port scan keyword in log", decoder: ["generic", "json"], pattern: /(port scan|\bnmap\b|masscan)/i, groups: ["recon"], mitre: ["T1046"] },
  { id: 1005, level: 8, description: "DNS tunneling keyword in log", decoder: ["generic", "json"], pattern: /dns tunnel/i, groups: ["exfiltration"], mitre: ["T1071.004"] },
  { id: 1006, level: 6, description: "Data exfiltration keyword in log", decoder: ["generic", "json"], pattern: /(unusual outbound|data exfil)/i, groups: ["exfiltration"], mitre: ["T1041"] },
  { id: 1007, level: 2, description: "Denied/blocked keyword in log", decoder: ["generic", "json"], pattern: /\b(denied|blocked|dropped)\b/i, groups: ["firewall_drop"] },
  { id: 1008, level: 10, description: "Repeated authentication failures from the same source in 2 minutes", ifRule: [1003], frequency: 5, timeframe: 120, same: ["srcip"], groups: ["brute_force"], mitre: ["T1110"] },
];
