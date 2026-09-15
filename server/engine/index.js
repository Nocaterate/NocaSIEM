// Detection engine: decodes a log line, evaluates every rule, keeps the
// sliding windows needed for correlation, and picks the alert to raise.

import { decode } from "./decoders.js";
import { RULES } from "./rules.js";
import { describeTechniques } from "./mitre.js";

const MAX_WINDOW_KEYS = 100000;

// ------------------------------------------------------------ rule setup --

const seenIds = new Set();
for (const rule of RULES) {
  if (!Number.isInteger(rule.id) || seenIds.has(rule.id)) throw new Error(`Rule id ${rule.id} is missing or duplicated`);
  if (!Number.isInteger(rule.level) || rule.level < 0 || rule.level > 15) throw new Error(`Rule ${rule.id} needs a level between 0 and 15`);
  seenIds.add(rule.id);
}

const ATOMIC_RULES = RULES.filter((r) => !r.frequency);
const FREQUENCY_RULES = RULES.filter((r) => r.frequency);
// Every (group, same-fields) combination used by a sequence rule, so group
// matches can be counted under exactly the key those rules look up.
const SEQUENCE_KEYS = [];
for (const r of RULES) {
  if (!r.after) continue;
  const same = r.after.same || [];
  const existing = SEQUENCE_KEYS.find((k) => k.group === r.after.group && k.same.join() === same.join());
  if (existing) existing.timeframe = Math.max(existing.timeframe, r.after.timeframe);
  else SEQUENCE_KEYS.push({ group: r.after.group, same, timeframe: r.after.timeframe });
}

export function severityForLevel(level) {
  if (level >= 13) return "Critical";
  if (level >= 10) return "High";
  if (level >= 7) return "Medium";
  return "Low";
}

function alertMinLevel() {
  const n = Number(process.env.ALERT_MIN_LEVEL);
  return Number.isInteger(n) && n >= 0 && n <= 15 ? n : 4;
}

// ------------------------------------------------------------- matching --

function listIncludes(expected, value) {
  return Array.isArray(expected) ? expected.includes(value) : expected === value;
}

function fieldMatches(expected, value, fields) {
  if (typeof expected === "function") return !!expected(value, fields);
  if (expected instanceof RegExp) return (typeof value === "string" || typeof value === "number") && expected.test(String(value));
  if (Array.isArray(expected)) return expected.includes(value);
  return value === expected;
}

function atomicMatch(rule, event) {
  if (!rule.decoder && !rule.action && !rule.field && !rule.pattern) return false;
  if (rule.decoder && !listIncludes(rule.decoder, event.decoder)) return false;
  if (rule.action && !listIncludes(rule.action, event.fields.action)) return false;
  if (rule.field) {
    for (const [name, expected] of Object.entries(rule.field)) {
      if (!fieldMatches(expected, event.fields[name], event.fields)) return false;
    }
  }
  if (rule.pattern && !rule.pattern.test(event.body)) return false;
  return true;
}

// ---------------------------------------------------------- correlation --

const windows = new Map(); // key -> { times: number[], distinct: Map, expires }
const cooldowns = new Map(); // key -> expiry timestamp

function windowKey(prefix, sourceIp, same, fields) {
  return `${prefix}|${sourceIp}|${same.map((f) => fields[f] ?? "").join("|")}`;
}

function getWindow(key) {
  let w = windows.get(key);
  if (!w) {
    if (windows.size >= MAX_WINDOW_KEYS) pruneWindows(Date.now());
    w = { times: [], distinct: new Map(), expires: 0 };
    windows.set(key, w);
  }
  return w;
}

function record(key, timeframeSec, now, distinctValue, cap) {
  const w = getWindow(key);
  const cutoff = now - timeframeSec * 1000;
  w.times = w.times.filter((t) => t > cutoff);
  w.times.push(now);
  if (w.times.length > cap) w.times.splice(0, w.times.length - cap);
  if (distinctValue !== undefined) {
    for (const [v, t] of w.distinct) if (t <= cutoff) w.distinct.delete(v);
    w.distinct.set(distinctValue, now);
  }
  w.expires = now + timeframeSec * 1000;
  return w;
}

function countWithin(key, timeframeSec, now) {
  const w = windows.get(key);
  if (!w) return 0;
  const cutoff = now - timeframeSec * 1000;
  return w.times.filter((t) => t > cutoff).length;
}

function inCooldown(key, now) {
  const until = cooldowns.get(key);
  return until !== undefined && until > now;
}

function pruneWindows(now) {
  for (const [k, w] of windows) if (w.expires <= now) windows.delete(k);
  for (const [k, until] of cooldowns) if (until <= now) cooldowns.delete(k);
}

setInterval(() => pruneWindows(Date.now()), 60 * 1000).unref();

export function resetCorrelation() {
  windows.clear();
  cooldowns.clear();
}

// -------------------------------------------------------------- analyze --

// Returns { decoded, matchedRules, rule, alert }. `alert` is null when no
// matched rule reaches ALERT_MIN_LEVEL (default 4).
export function analyze(line, sourceIp, now = Date.now()) {
  const decoded = decode(line);
  const { fields } = decoded;
  const matched = [];

  for (const rule of ATOMIC_RULES) {
    if (!atomicMatch(rule, decoded)) continue;
    if (rule.after) {
      const key = windowKey(`g:${rule.after.group}`, sourceIp, rule.after.same || [], fields);
      if (countWithin(key, rule.after.timeframe, now) < rule.after.count) continue;
      const cdKey = windowKey(`c:${rule.id}`, sourceIp, rule.after.same || [], fields);
      if (inCooldown(cdKey, now)) continue;
      cooldowns.set(cdKey, now + rule.after.timeframe * 1000);
    }
    // `ignore`: raise at most one alert per `ignore` seconds for the same
    // source (like Wazuh's ignore option). Suppressed matches still count
    // toward correlation rules, they just don't create another alert.
    if (rule.ignore) {
      const igKey = windowKey(`i:${rule.id}`, sourceIp, ["srcip"], fields);
      if (inCooldown(igKey, now)) {
        matched.push({ rule, suppressed: true });
        continue;
      }
      cooldowns.set(igKey, now + rule.ignore * 1000);
    }
    matched.push({ rule });
  }

  // Count group matches for sequence rules (after evaluating them, so an
  // event never counts toward its own precondition).
  const matchedGroups = new Set(matched.flatMap((m) => m.rule.groups || []));
  for (const sk of SEQUENCE_KEYS) {
    if (matchedGroups.has(sk.group)) {
      record(windowKey(`g:${sk.group}`, sourceIp, sk.same, fields), sk.timeframe, now, undefined, 1000);
    }
  }

  const matchedIds = new Set(matched.map((m) => m.rule.id));
  for (const rule of FREQUENCY_RULES) {
    const triggered = (rule.ifRule && rule.ifRule.some((id) => matchedIds.has(id))) || (rule.ifGroup && matchedGroups.has(rule.ifGroup));
    if (!triggered) continue;
    const same = rule.same || [];
    const key = windowKey(`f:${rule.id}`, sourceIp, same, fields);
    const distinctValue = rule.distinct ? fields[rule.distinct] : undefined;
    if (rule.distinct && distinctValue === undefined) continue;
    const w = record(key, rule.timeframe, now, distinctValue, rule.frequency * 2);
    const count = rule.distinct ? w.distinct.size : w.times.length;
    if (count < rule.frequency) continue;
    const cdKey = windowKey(`c:${rule.id}`, sourceIp, same, fields);
    if (inCooldown(cdKey, now)) continue;
    cooldowns.set(cdKey, now + rule.timeframe * 1000);
    matched.push({ rule, firedTimes: count });
  }

  // Highest level wins; on a tie, correlation rules (evaluated later) win.
  let best = null;
  for (const m of matched) if (!m.suppressed && (!best || m.rule.level >= best.rule.level)) best = m;

  const alert =
    best && best.rule.level >= alertMinLevel()
      ? {
          ruleId: best.rule.id,
          level: best.rule.level,
          severity: severityForLevel(best.rule.level),
          title: best.rule.description,
          groups: best.rule.groups || [],
          mitre: best.rule.mitre || [],
          srcIp: fields.srcip,
          user: fields.user,
          firedTimes: best.firedTimes || 1,
        }
      : null;

  return { decoded, matchedRules: matched.map((m) => m.rule.id), rule: best?.rule || null, alert };
}

// Rule catalogue for the API / UI.
export function listRules() {
  return RULES.map((r) => ({
    id: r.id,
    level: r.level,
    severity: severityForLevel(r.level),
    description: r.description,
    groups: r.groups || [],
    mitre: describeTechniques(r.mitre),
    kind: r.frequency ? "frequency" : r.after ? "sequence" : "atomic",
    frequency: r.frequency,
    timeframe: r.timeframe || r.after?.timeframe,
    same: r.same || r.after?.same,
    distinct: r.distinct,
  }));
}

export function getRule(id) {
  return RULES.find((r) => r.id === id) || null;
}
