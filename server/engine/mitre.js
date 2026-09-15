// MITRE ATT&CK techniques referenced by the built-in rules.
// https://attack.mitre.org/techniques/enterprise/

export const MITRE = {
  "T1003": { name: "OS Credential Dumping", tactic: "Credential Access" },
  "T1003.001": { name: "LSASS Memory", tactic: "Credential Access" },
  "T1021.001": { name: "Remote Desktop Protocol", tactic: "Lateral Movement" },
  "T1041": { name: "Exfiltration Over C2 Channel", tactic: "Exfiltration" },
  "T1046": { name: "Network Service Discovery", tactic: "Discovery" },
  "T1053.005": { name: "Scheduled Task", tactic: "Execution" },
  "T1059": { name: "Command and Scripting Interpreter", tactic: "Execution" },
  "T1059.001": { name: "PowerShell", tactic: "Execution" },
  "T1068": { name: "Exploitation for Privilege Escalation", tactic: "Privilege Escalation" },
  "T1070.001": { name: "Clear Windows Event Logs", tactic: "Defense Evasion" },
  "T1071.004": { name: "Application Layer Protocol: DNS", tactic: "Command and Control" },
  "T1078": { name: "Valid Accounts", tactic: "Initial Access" },
  "T1078.003": { name: "Local Accounts", tactic: "Initial Access" },
  "T1098": { name: "Account Manipulation", tactic: "Persistence" },
  "T1105": { name: "Ingress Tool Transfer", tactic: "Command and Control" },
  "T1110": { name: "Brute Force", tactic: "Credential Access" },
  "T1110.001": { name: "Password Guessing", tactic: "Credential Access" },
  "T1110.003": { name: "Password Spraying", tactic: "Credential Access" },
  "T1133": { name: "External Remote Services", tactic: "Initial Access" },
  "T1136.001": { name: "Create Account: Local Account", tactic: "Persistence" },
  "T1190": { name: "Exploit Public-Facing Application", tactic: "Initial Access" },
  "T1204.002": { name: "User Execution: Malicious File", tactic: "Execution" },
  "T1490": { name: "Inhibit System Recovery", tactic: "Impact" },
  "T1498": { name: "Network Denial of Service", tactic: "Impact" },
  "T1505.003": { name: "Web Shell", tactic: "Persistence" },
  "T1531": { name: "Account Access Removal", tactic: "Impact" },
  "T1543.003": { name: "Windows Service", tactic: "Persistence" },
  "T1548": { name: "Abuse Elevation Control Mechanism", tactic: "Privilege Escalation" },
  "T1548.003": { name: "Sudo and Sudo Caching", tactic: "Privilege Escalation" },
  "T1562.001": { name: "Impair Defenses: Disable or Modify Tools", tactic: "Defense Evasion" },
  "T1595.002": { name: "Vulnerability Scanning", tactic: "Reconnaissance" },
  "T1595.003": { name: "Wordlist Scanning", tactic: "Reconnaissance" },
};

export function describeTechniques(ids = []) {
  return ids.map((id) => ({ id, ...(MITRE[id] || { name: id, tactic: "Unknown" }) }));
}
