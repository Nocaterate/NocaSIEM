// Input validation shared by the API routes.

export const LIMITS = {
  username: 50,
  email: 254,
  sourceName: 100,
  passwordMinChars: 8,
  // bcrypt only uses the first 72 bytes of a password, so anything longer
  // would be silently truncated - reject it instead.
  passwordMaxBytes: 72,
  sourcesPerUser: 200,
};

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Strict dotted-quad with no leading zeros. "010.0.0.1" is rejected because
// some resolvers read leading-zero octets as octal and would connect to a
// different address than the one that was validated.
const IPV4_RE = /^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;

export function isNonEmptyString(value, maxLength) {
  return typeof value === "string" && value.trim().length > 0 && value.length <= maxLength;
}

export function isValidEmail(email) {
  return typeof email === "string" && email.length <= LIMITS.email && EMAIL_RE.test(email.trim());
}

export function normalizeEmail(email) {
  return email.trim().toLowerCase();
}

export function passwordProblem(password) {
  if (typeof password !== "string" || password.length < LIMITS.passwordMinChars) {
    return `Password must be at least ${LIMITS.passwordMinChars} characters`;
  }
  if (Buffer.byteLength(password, "utf8") > LIMITS.passwordMaxBytes) {
    return `Password must be at most ${LIMITS.passwordMaxBytes} bytes (about ${LIMITS.passwordMaxBytes} characters)`;
  }
  return null;
}

export function parseId(value) {
  const id = Number(value);
  return Number.isSafeInteger(id) && id > 0 ? id : null;
}

export function clampLimit(value, fallback, max) {
  const n = Math.floor(Number(value));
  if (!Number.isFinite(n) || n < 1) return fallback;
  return Math.min(n, max);
}

export function isIPv4(ip) {
  return typeof ip === "string" && IPV4_RE.test(ip);
}

function ipToInt(ip) {
  return ip.split(".").reduce((n, octet) => n * 256 + Number(octet), 0);
}

function inRange(ip, [base, bits]) {
  const size = 2 ** (32 - bits);
  return Math.floor(ipToInt(ip) / size) === Math.floor(ipToInt(base) / size);
}

// The server itself, cloud metadata endpoints and non-unicast space.
const NEVER_PROBE = [
  ["0.0.0.0", 8],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4],
];

const PRIVATE = [
  ["10.0.0.0", 8],
  ["172.16.0.0", 12],
  ["192.168.0.0", 16],
  ["100.64.0.0", 10],
];

// The source connectivity test makes the *server* open a TCP connection, so
// without limits any user could use it to scan the server's own ports or the
// internal network behind it (SSRF). Returns a reason string when blocked.
export function probeTargetProblem(ip, isAdmin) {
  if (!isIPv4(ip)) return "Invalid IP address.";
  if (NEVER_PROBE.some((range) => inRange(ip, range))) {
    return "Loopback, link-local, multicast and reserved addresses can't be tested from the server.";
  }
  if (!isAdmin && PRIVATE.some((range) => inRange(ip, range))) {
    return "Only administrators can test private network addresses.";
  }
  return null;
}
