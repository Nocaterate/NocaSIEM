// Keyword-based detection engine with a lightweight correlation layer.
// Every incoming log line is checked against these patterns in order;
// the first match decides the alert's base severity and type. On top of
// that, repeated matches of the *same* rule from the *same* source IP
// within a short window get escalated - this is the same basic idea
// real SIEMs use to turn "one failed login" into "this is a brute-force
// attack in progress".

const RULES = [
  { pattern: /malware|ransomware|trojan|exploit/i, severity: "Critical", type: "Malware signature match" },
  { pattern: /unauthorized|privilege escalation|root access/i, severity: "Critical", type: "Privilege escalation" },
  { pattern: /brute.?force|failed password|authentication failure/i, severity: "High", type: "Brute force attempt" },
  { pattern: /port scan|nmap|masscan/i, severity: "High", type: "Port scan detected" },
  { pattern: /dns tunnel/i, severity: "High", type: "DNS tunneling suspected" },
  { pattern: /denied|blocked|dropped/i, severity: "Medium", type: "Firewall rule violation" },
  { pattern: /unusual outbound|data exfil/i, severity: "Medium", type: "Unusual outbound traffic" },
];

const CORRELATION_WINDOW_MS = 2 * 60 * 1000; // 2 minutes
const CORRELATION_THRESHOLD = 5; // this many matches of the same rule from the same IP = escalate

const recentMatches = new Map(); // key: `${sourceIp}|${ruleType}` -> array of timestamps

function recordAndCount(sourceIp, ruleType) {
  const key = `${sourceIp}|${ruleType}`;
  const now = Date.now();
  const timestamps = (recentMatches.get(key) || []).filter((ts) => now - ts < CORRELATION_WINDOW_MS);
  timestamps.push(now);
  recentMatches.set(key, timestamps);
  return timestamps.length;
}

// Returns { severity, type } if the message should be raised as an alert,
// or null if it should just be stored as a plain log line.
function classify(message, sourceIp) {
  for (const rule of RULES) {
    if (rule.pattern.test(message)) {
      const count = recordAndCount(sourceIp, rule.type);
      if (count >= CORRELATION_THRESHOLD && rule.severity !== "Critical") {
        return { severity: "Critical", type: `${rule.type} (${count}x in 2 min - escalated)` };
      }
      return { severity: rule.severity, type: rule.type };
    }
  }
  return null;
}

export { classify };
