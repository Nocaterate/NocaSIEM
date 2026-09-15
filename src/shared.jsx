// Design tokens, helpers and small components shared by every view.

/* ---------------------------------- tokens --------------------------------- */

export const NAVY_DEEP = "#071B3F";
export const NAVY_MID = "#123B7D";
export const HEADER_BLUE = "#2F6FE4";
export const AMBER = "#FFC63D";

export function getTheme(mode) {
  if (mode === "dark") {
    return {
      bg: "#0B1220",
      panel: "#121B2E",
      border: "rgba(255,255,255,0.08)",
      ink: "#F3F6FC",
      slate: "#8B95A9",
      blueBright: "#5B8DFF",
      crimson: "#FF5F72",
      orange: "#FFA05C",
      green: "#3EE0A0",
    };
  }
  return {
    bg: "#F3F6FC",
    panel: "#FFFFFF",
    border: "#E3E9F3",
    ink: "#0E1F3D",
    slate: "#5B6B84",
    blueBright: "#2F6FE4",
    crimson: "#F1495B",
    orange: "#FF8A3D",
    green: "#2FBF87",
  };
}

export const SEVERITIES = ["Critical", "High", "Medium", "Low"];

// Same mapping as the server's rule engine (Wazuh-style levels 0-15).
export function severityForLevel(level) {
  if (level >= 13) return "Critical";
  if (level >= 10) return "High";
  if (level >= 7) return "Medium";
  return "Low";
}

export const SEV_STYLE = {
  Critical: { bg: "#FDEBEC", text: "#D6273A", dot: "#F1495B" },
  High: { bg: "#FFF1E5", text: "#C2600F", dot: "#FF8A3D" },
  Medium: { bg: "#FFF8E1", text: "#9A7B0A", dot: "#FFC63D" },
  Low: { bg: "#EAF7F1", text: "#1F8F63", dot: "#2FBF87" },
};

export const STATUS_STYLE = {
  Open: { bg: "#FDEBEC", text: "#D6273A" },
  Investigating: { bg: "#FFF1E5", text: "#C2600F" },
  Resolved: { bg: "#EAF7F1", text: "#1F8F63" },
};

export const FONT_SANS = "'Inter', ui-sans-serif, system-ui, -apple-system, 'Segoe UI', sans-serif";
export const FONT_MONO = "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace";

/* --------------------------------- helpers --------------------------------- */

export function timeLabel(d) {
  return d.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function dateTimeLabel(iso) {
  return new Date(iso).toLocaleString("en-US", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function initials(name) {
  if (!name) return "U";
  return name.trim().split(/\s+/).map((w) => w[0]).slice(0, 2).join("").toUpperCase();
}

export function fieldStyle(T) {
  return { backgroundColor: T.bg, border: `1px solid ${T.border}`, color: T.ink };
}

// Builds a query string from an object, skipping empty values.
export function queryString(params) {
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== "") qs.set(k, String(v));
  }
  const s = qs.toString();
  return s ? `?${s}` : "";
}

// The dashboard is served by the backend itself, so every call is same-origin.
export async function apiRequest(path, { method = "GET", token, body } = {}) {
  const res = await fetch(path, {
    method,
    headers: {
      ...(body ? { "Content-Type": "application/json" } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(data.error || `Request failed (${res.status})`);
    err.status = res.status;
    err.code = data.code;
    throw err;
  }
  return data;
}

/* -------------------------------- components -------------------------------- */

export function SeverityBadge({ severity }) {
  const s = SEV_STYLE[severity] || SEV_STYLE.Low;
  return (
    <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium whitespace-nowrap" style={{ backgroundColor: s.bg, color: s.text, fontFamily: FONT_SANS }}>
      <span style={{ width: 6, height: 6, borderRadius: 9999, backgroundColor: s.dot }} />
      {severity}
    </span>
  );
}

export function StatusSelect({ status, onChange }) {
  const s = STATUS_STYLE[status] || STATUS_STYLE.Open;
  return (
    <select
      value={status}
      onChange={(e) => onChange(e.target.value)}
      onClick={(e) => e.stopPropagation()}
      className="px-1.5 py-0.5 rounded text-xs font-medium outline-none cursor-pointer"
      style={{ backgroundColor: s.bg, color: s.text, fontFamily: FONT_SANS, border: "none" }}
      aria-label="Alert status"
    >
      {Object.keys(STATUS_STYLE).map((k) => (
        <option key={k} value={k}>{k}</option>
      ))}
    </select>
  );
}

export function Card({ T, className = "", style, children }) {
  return (
    <div className={`rounded-lg ${className}`} style={{ backgroundColor: T.panel, border: `1px solid ${T.border}`, ...style }}>
      {children}
    </div>
  );
}

export function MitreTags({ techniques = [], T, onSelect }) {
  if (!techniques.length) return <span className="text-xs" style={{ color: T.slate }}>{"—"}</span>;
  return (
    <div className="flex flex-wrap gap-1">
      {techniques.map((t) => (
        <button
          key={t.id}
          type="button"
          onClick={onSelect ? (e) => (e.stopPropagation(), onSelect(t.id)) : undefined}
          title={`${t.name} (${t.tactic})`}
          className="px-1.5 py-0.5 rounded text-[11px] font-medium whitespace-nowrap"
          style={{ backgroundColor: T.bg, color: T.ink, border: `1px solid ${T.border}`, fontFamily: FONT_MONO, cursor: onSelect ? "pointer" : "default" }}
        >
          {t.id}
        </button>
      ))}
    </div>
  );
}

export function ErrorNote({ children }) {
  if (!children) return null;
  return (
    <div className="text-xs px-3 py-2 rounded-md" style={{ backgroundColor: "#FDEBEC", color: "#D6273A" }}>
      {children}
    </div>
  );
}
