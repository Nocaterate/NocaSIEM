import React, { useState, useEffect, useRef, useMemo } from "react";
import {
  AreaChart,
  Area,
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from "recharts";
import {
  Shield,
  Bell,
  Server,
  Globe,
  TrendingUp,
  TrendingDown,
  AlertTriangle,
  Activity,
  Zap,
  Sun,
  Moon,
  LogOut,
  User as UserIcon,
  Settings as SettingsIcon,
  LayoutDashboard,
  Eye,
  EyeOff,
  Plus,
  Trash2,
  Radio,
  Wifi,
  WifiOff,
  Users,
  ShieldCheck,
} from "lucide-react";

/* ---------------------------------- tokens --------------------------------- */

const NAVY_DEEP = "#071B3F";
const NAVY_MID = "#123B7D";
const HEADER_BLUE = "#2F6FE4";
const AMBER = "#FFC63D";

function getTheme(mode) {
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

const SEV_STYLE = {
  Critical: { bg: "#FDEBEC", text: "#D6273A", dot: "#F1495B" },
  High: { bg: "#FFF1E5", text: "#C2600F", dot: "#FF8A3D" },
  Medium: { bg: "#FFF8E1", text: "#9A7B0A", dot: "#FFC63D" },
  Low: { bg: "#EAF7F1", text: "#1F8F63", dot: "#2FBF87" },
};

const STATUS_STYLE = {
  Open: { bg: "#FDEBEC", text: "#D6273A" },
  Investigating: { bg: "#FFF1E5", text: "#C2600F" },
  Resolved: { bg: "#EAF7F1", text: "#1F8F63" },
};

const FONT_SANS =
  "'Inter', ui-sans-serif, system-ui, -apple-system, 'Segoe UI', sans-serif";
const FONT_MONO =
  "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace";

/* --------------------------------- helpers --------------------------------- */

const rand = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;

const randomIp = () =>
  `${rand(10, 223)}.${rand(0, 255)}.${rand(0, 255)}.${rand(1, 254)}`;

const EVENT_TYPES = [
  "Brute force attempt",
  "Malware signature match",
  "Unusual outbound traffic",
  "Privilege escalation",
  "Port scan detected",
  "Failed login spike",
  "DNS tunneling suspected",
  "Firewall rule violation",
];

function weightedSeverity() {
  const r = Math.random();
  if (r < 0.1) return "Critical";
  if (r < 0.35) return "High";
  if (r < 0.7) return "Medium";
  return "Low";
}

let alertCounter = 1000;
function makeAlert() {
  alertCounter += 1;
  return {
    id: alertCounter,
    time: new Date(),
    severity: weightedSeverity(),
    sourceIp: randomIp(),
    type: EVENT_TYPES[rand(0, EVENT_TYPES.length - 1)],
    status: ["Open", "Investigating", "Resolved"][rand(0, 2)],
  };
}

function timeLabel(d) {
  return d.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function initialVolume() {
  const out = [];
  let v = 120;
  for (let h = 0; h < 24; h++) {
    v = Math.max(30, Math.min(260, v + rand(-25, 25)));
    out.push({ time: `${String(h).padStart(2, "0")}:00`, events: v });
  }
  return out;
}

const LOG_VERBS = [
  "AUTH_FAIL",
  "CONN_ACCEPT",
  "RULE_MATCH",
  "PKT_DROP",
  "SESSION_START",
  "SIG_HIT",
  "DNS_QUERY",
  "FILE_MODIFIED",
];

function makeLogLine() {
  const ts = timeLabel(new Date());
  const verb = LOG_VERBS[rand(0, LOG_VERBS.length - 1)];
  const ip = randomIp();
  const port = rand(20, 65000);
  return `${ts}  ${verb.padEnd(14, " ")} src=${ip}:${port}`;
}

function initials(name) {
  if (!name) return "U";
  return name.trim().split(/\s+/).map((w) => w[0]).slice(0, 2).join("").toUpperCase();
}

async function apiRequest(baseUrl, path, { method = "GET", token, body } = {}) {
  const res = await fetch(`${baseUrl}${path}`, {
    method,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}

/* ------------------------------- animated wave ------------------------------ */

function AnimatedWave() {
  const seg =
    "M0,60 C150,10 150,110 300,60 C450,10 450,110 600,60 " +
    "C750,10 750,110 900,60 C1050,10 1050,110 1200,60 " +
    "C1350,10 1350,110 1500,60 C1650,10 1650,110 1800,60 " +
    "C1950,10 1950,110 2100,60 C2250,10 2250,110 2400,60";
  return (
    <div style={{ position: "relative", width: "100%", height: 44, overflow: "hidden" }}>
      <svg
        className="wave-track"
        viewBox="0 0 4800 120"
        preserveAspectRatio="none"
        style={{ position: "absolute", top: 0, left: 0, width: "200%", height: "100%" }}
      >
        <path d={seg} fill="none" stroke={AMBER} strokeWidth="18" strokeLinecap="round" opacity="0.22" />
        <path d={seg} fill="none" stroke={AMBER} strokeWidth="5" strokeLinecap="round" />
        <path d={seg} fill="none" stroke={AMBER} strokeWidth="18" strokeLinecap="round" opacity="0.22" transform="translate(2400,0)" />
        <path d={seg} fill="none" stroke={AMBER} strokeWidth="5" strokeLinecap="round" transform="translate(2400,0)" />
      </svg>
    </div>
  );
}

/* --------------------------------- sub UI ----------------------------------- */

function KpiCard({ icon: Icon, label, value, delta, accent, T }) {
  const up = delta >= 0;
  return (
    <div
      className="flex flex-col gap-2 p-4 sm:p-5 rounded-lg"
      style={{
        backgroundColor: T.panel,
        borderTop: `1px solid ${T.border}`,
        borderRight: `1px solid ${T.border}`,
        borderBottom: `1px solid ${T.border}`,
        borderLeft: `3px solid ${accent}`,
      }}
    >
      <div className="flex items-center justify-between">
        <span className="text-xs" style={{ color: T.slate, fontFamily: FONT_SANS }}>{label}</span>
        <Icon size={16} color={accent} />
      </div>
      <div className="flex items-end justify-between">
        <span className="text-2xl font-semibold" style={{ color: T.ink, fontFamily: FONT_SANS }}>{value}</span>
        <span className="flex items-center gap-1 text-xs font-medium" style={{ color: up ? T.green : T.crimson, fontFamily: FONT_SANS }}>
          {up ? <TrendingUp size={13} /> : <TrendingDown size={13} />}
          {Math.abs(delta)}%
        </span>
      </div>
    </div>
  );
}

function SeverityBadge({ severity }) {
  const s = SEV_STYLE[severity] || SEV_STYLE.Low;
  return (
    <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium" style={{ backgroundColor: s.bg, color: s.text, fontFamily: FONT_SANS }}>
      <span style={{ width: 6, height: 6, borderRadius: 9999, backgroundColor: s.dot }} />
      {severity}
    </span>
  );
}

function StatusBadge({ status }) {
  const s = STATUS_STYLE[status] || STATUS_STYLE.Open;
  return (
    <span className="inline-block px-2 py-0.5 rounded text-xs font-medium" style={{ backgroundColor: s.bg, color: s.text, fontFamily: FONT_SANS }}>
      {status}
    </span>
  );
}

function ThemeToggle({ theme, onChange }) {
  return (
    <button
      onClick={() => onChange(theme === "dark" ? "light" : "dark")}
      className="flex items-center justify-center rounded-md"
      style={{ width: 30, height: 30, backgroundColor: "rgba(255,255,255,0.1)" }}
      aria-label="Toggle dark mode"
    >
      {theme === "dark" ? <Sun size={15} color="#fff" /> : <Moon size={15} color="#fff" />}
    </button>
  );
}

function ConnectionBadge({ connected }) {
  return (
    <div
      className="hidden sm:flex items-center gap-1.5 text-xs px-2 py-1 rounded-md"
      style={{ backgroundColor: "rgba(255,255,255,0.08)", color: connected ? "#3EE0A0" : "rgba(255,255,255,0.6)" }}
    >
      {connected ? <Wifi size={13} /> : <WifiOff size={13} />}
      {connected ? "Live" : "Demo mode"}
    </div>
  );
}

function NavTabs({ view, setView, isAdmin }) {
  const items = [
    { key: "dashboard", label: "Dashboard", icon: LayoutDashboard },
    { key: "profile", label: "Profile", icon: UserIcon },
    { key: "settings", label: "Settings", icon: SettingsIcon },
    ...(isAdmin ? [{ key: "admin", label: "Admin", icon: Users }] : []),
  ];
  return (
    <div className="flex items-center gap-1">
      {items.map(({ key, label, icon: Icon }) => {
        const active = view === key;
        return (
          <button
            key={key}
            onClick={() => setView(key)}
            className="flex items-center gap-1.5 px-2.5 sm:px-3 py-1.5 rounded-md text-xs font-medium"
            style={{ backgroundColor: active ? "rgba(255,255,255,0.14)" : "transparent", color: active ? "#FFFFFF" : "rgba(255,255,255,0.6)" }}
          >
            <Icon size={14} />
            <span className="hidden sm:inline">{label}</span>
          </button>
        );
      })}
    </div>
  );
}

/* --------------------------------- auth screen ------------------------------ */

function AuthScreen({ mode, onModeChange, onSubmit, loading, error, onDemo, T }) {
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);

  function handleSubmit(e) {
    e.preventDefault();
    onSubmit({ username, email, password });
  }

  const inputStyle = { backgroundColor: T.bg, border: `1px solid ${T.border}`, color: T.ink };

  return (
    <div style={{ minHeight: "100vh", backgroundColor: T.bg, fontFamily: FONT_SANS }} className="flex items-center justify-center px-4">
      <div style={{ width: 380, maxWidth: "100%", backgroundColor: T.panel, border: `1px solid ${T.border}` }} className="rounded-lg p-6 sm:p-8">
        <div className="flex items-center gap-2 mb-1">
          <Shield size={20} color={AMBER} />
          <span style={{ color: T.ink }} className="text-base font-semibold">NocaSIEM</span>
        </div>
        <p style={{ color: T.slate }} className="text-xs mb-6">Security operations center</p>

        <div className="flex mb-5 rounded-md overflow-hidden" style={{ border: `1px solid ${T.border}` }}>
          <button type="button" onClick={() => onModeChange("signin")} className="flex-1 text-sm py-2" style={{ backgroundColor: mode === "signin" ? T.bg : "transparent", color: mode === "signin" ? T.ink : T.slate, fontWeight: mode === "signin" ? 600 : 400 }}>
            Sign in
          </button>
          <button type="button" onClick={() => onModeChange("signup")} className="flex-1 text-sm py-2" style={{ backgroundColor: mode === "signup" ? T.bg : "transparent", color: mode === "signup" ? T.ink : T.slate, fontWeight: mode === "signup" ? 600 : 400 }}>
            Sign up
          </button>
        </div>

        <form onSubmit={handleSubmit} className="flex flex-col gap-3">
          {mode === "signup" && (
            <label className="flex flex-col gap-1">
              <span className="text-xs" style={{ color: T.slate }}>Username</span>
              <input value={username} onChange={(e) => setUsername(e.target.value)} required className="px-3 py-2 rounded-md text-sm outline-none" style={inputStyle} />
            </label>
          )}
          <label className="flex flex-col gap-1">
            <span className="text-xs" style={{ color: T.slate }}>Email</span>
            <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required className="px-3 py-2 rounded-md text-sm outline-none" style={inputStyle} />
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-xs" style={{ color: T.slate }}>Password</span>
            <div className="relative">
              <input type={showPassword ? "text" : "password"} value={password} onChange={(e) => setPassword(e.target.value)} required minLength={8} className="px-3 py-2 pr-9 rounded-md text-sm outline-none w-full" style={inputStyle} />
              <button type="button" onClick={() => setShowPassword((s) => !s)} className="absolute right-2.5 top-1/2 -translate-y-1/2" style={{ color: T.slate }}>
                {showPassword ? <EyeOff size={15} /> : <Eye size={15} />}
              </button>
            </div>
          </label>

          {error && (
            <div className="text-xs px-3 py-2 rounded-md" style={{ backgroundColor: "#FDEBEC", color: "#D6273A" }}>
              {error}
            </div>
          )}

          <button type="submit" disabled={loading} className="mt-1 py-2 rounded-md text-sm font-medium text-white" style={{ backgroundColor: T.blueBright, opacity: loading ? 0.7 : 1 }}>
            {loading ? "Please wait\u2026" : mode === "signin" ? "Sign in" : "Create account"}
          </button>
        </form>

        <button onClick={onDemo} className="w-full mt-4 text-xs text-center underline" style={{ color: T.slate }}>
          Continue in demo mode without connecting a backend
        </button>
      </div>
    </div>
  );
}

/* -------------------------------- profile view ------------------------------- */

const ACTION_LABELS = {
  login: "Signed in",
  register: "Account created",
  profile_update: "Profile updated",
  password_change: "Password changed",
  source_added: "Log source added",
  source_removed: "Log source removed",
};

function ProfileView({ user, T, onLogout, theme, onThemeChange, onUpdateProfile, onChangePassword, auditLog, connected }) {
  const joined = user.createdAt
    ? new Date(user.createdAt).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" })
    : "\u2014";

  const fieldStyle = { backgroundColor: T.bg, border: `1px solid ${T.border}`, color: T.ink };

  const [editing, setEditing] = useState(false);
  const [username, setUsername] = useState(user.username);
  const [email, setEmail] = useState(user.email);
  const [profileError, setProfileError] = useState("");
  const [profileSaving, setProfileSaving] = useState(false);

  const [showPasswordForm, setShowPasswordForm] = useState(false);
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [passwordError, setPasswordError] = useState("");
  const [passwordSuccess, setPasswordSuccess] = useState("");
  const [passwordSaving, setPasswordSaving] = useState(false);

  async function handleSaveProfile() {
    setProfileError("");
    setProfileSaving(true);
    try {
      await onUpdateProfile({ username, email });
      setEditing(false);
    } catch (err) {
      setProfileError(err.message);
    } finally {
      setProfileSaving(false);
    }
  }

  async function handleSavePassword(e) {
    e.preventDefault();
    setPasswordError("");
    setPasswordSuccess("");
    if (newPassword.length < 8) {
      setPasswordError("New password must be at least 8 characters.");
      return;
    }
    setPasswordSaving(true);
    try {
      await onChangePassword({ currentPassword, newPassword });
      setPasswordSuccess("Password updated.");
      setCurrentPassword("");
      setNewPassword("");
    } catch (err) {
      setPasswordError(err.message);
    } finally {
      setPasswordSaving(false);
    }
  }

  return (
    <div className="px-5 sm:px-8 py-8 max-w-[640px] mx-auto flex flex-col gap-5">
      <div className="rounded-lg p-6 flex items-center gap-4" style={{ backgroundColor: T.panel, border: `1px solid ${T.border}` }}>
        <div className="flex items-center justify-center rounded-full text-lg font-semibold text-white shrink-0" style={{ width: 56, height: 56, backgroundColor: T.blueBright }}>
          {initials(user.username)}
        </div>
        {!editing ? (
          <div className="flex-1 flex items-center justify-between gap-3">
            <div>
              <div className="text-base font-semibold" style={{ color: T.ink }}>{user.username}</div>
              <div className="text-sm" style={{ color: T.slate }}>{user.email}</div>
            </div>
            <button onClick={() => { setUsername(user.username); setEmail(user.email); setEditing(true); }} className="text-xs font-medium px-3 py-1.5 rounded-md" style={{ border: `1px solid ${T.border}`, color: T.ink }}>
              Edit
            </button>
          </div>
        ) : (
          <div className="flex-1 flex flex-col gap-2">
            <input value={username} onChange={(e) => setUsername(e.target.value)} className="px-2.5 py-1.5 rounded-md text-sm outline-none" style={fieldStyle} placeholder="Username" />
            <input value={email} onChange={(e) => setEmail(e.target.value)} type="email" className="px-2.5 py-1.5 rounded-md text-sm outline-none" style={fieldStyle} placeholder="Email" />
          </div>
        )}
      </div>

      {editing && (
        <div className="flex flex-col gap-2 -mt-3">
          {profileError && (
            <div className="text-xs px-3 py-2 rounded-md" style={{ backgroundColor: "#FDEBEC", color: "#D6273A" }}>{profileError}</div>
          )}
          <div className="flex gap-2 justify-end">
            <button onClick={() => setEditing(false)} className="text-xs font-medium px-3 py-1.5 rounded-md" style={{ border: `1px solid ${T.border}`, color: T.slate }}>Cancel</button>
            <button onClick={handleSaveProfile} disabled={profileSaving} className="text-xs font-medium px-3 py-1.5 rounded-md text-white" style={{ backgroundColor: T.blueBright, opacity: profileSaving ? 0.7 : 1 }}>
              {profileSaving ? "Saving\u2026" : "Save changes"}
            </button>
          </div>
        </div>
      )}

      <div className="rounded-lg p-5 flex flex-col gap-4" style={{ backgroundColor: T.panel, border: `1px solid ${T.border}` }}>
        <div className="flex items-center justify-between text-sm">
          <span style={{ color: T.slate }}>Member since</span>
          <span style={{ color: T.ink }}>{joined}</span>
        </div>
        <div className="flex items-center justify-between text-sm">
          <span style={{ color: T.slate }}>Role</span>
          <span style={{ color: T.ink }}>Administrator</span>
        </div>
        <div className="flex items-center justify-between text-sm">
          <span style={{ color: T.slate }}>Appearance</span>
          <div className="flex items-center gap-2">
            <button onClick={() => onThemeChange("light")} className="px-2.5 py-1 rounded-md text-xs" style={{ backgroundColor: theme === "light" ? T.blueBright : "transparent", color: theme === "light" ? "#fff" : T.slate, border: `1px solid ${T.border}` }}>
              Light
            </button>
            <button onClick={() => onThemeChange("dark")} className="px-2.5 py-1 rounded-md text-xs" style={{ backgroundColor: theme === "dark" ? T.blueBright : "transparent", color: theme === "dark" ? "#fff" : T.slate, border: `1px solid ${T.border}` }}>
              Dark
            </button>
          </div>
        </div>
      </div>

      <div className="rounded-lg p-5 flex flex-col gap-3" style={{ backgroundColor: T.panel, border: `1px solid ${T.border}` }}>
        <button onClick={() => setShowPasswordForm((s) => !s)} className="flex items-center justify-between text-sm font-semibold" style={{ color: T.ink }}>
          Change password
          <span className="text-xs font-normal" style={{ color: T.slate }}>{showPasswordForm ? "Hide" : "Show"}</span>
        </button>
        {showPasswordForm && (
          <form onSubmit={handleSavePassword} className="flex flex-col gap-2 pt-1">
            {!connected && (
              <div className="text-xs px-3 py-2 rounded-md" style={{ backgroundColor: T.bg, color: T.slate }}>
                You're in demo mode, so this won't be saved anywhere \u2014 connect a real backend in Settings first.
              </div>
            )}
            <input type="password" value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)} placeholder="Current password" required className="px-2.5 py-2 rounded-md text-sm outline-none" style={fieldStyle} />
            <input type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} placeholder="New password (min. 8 characters)" required minLength={8} className="px-2.5 py-2 rounded-md text-sm outline-none" style={fieldStyle} />
            {passwordError && <div className="text-xs px-3 py-2 rounded-md" style={{ backgroundColor: "#FDEBEC", color: "#D6273A" }}>{passwordError}</div>}
            {passwordSuccess && <div className="text-xs px-3 py-2 rounded-md" style={{ backgroundColor: "#EAF7F1", color: "#1F8F63" }}>{passwordSuccess}</div>}
            <button type="submit" disabled={passwordSaving} className="py-2 rounded-md text-sm font-medium text-white" style={{ backgroundColor: T.blueBright, opacity: passwordSaving ? 0.7 : 1 }}>
              {passwordSaving ? "Updating\u2026" : "Update password"}
            </button>
          </form>
        )}
      </div>

      {connected && auditLog.length > 0 && (
        <div className="rounded-lg p-5 flex flex-col gap-3" style={{ backgroundColor: T.panel, border: `1px solid ${T.border}` }}>
          <span className="text-sm font-semibold" style={{ color: T.ink }}>Recent account activity</span>
          <div className="flex flex-col">
            {auditLog.map((entry) => (
              <div key={entry.id} className="flex items-center justify-between py-2 text-xs" style={{ borderTop: `1px solid ${T.border}` }}>
                <div>
                  <div style={{ color: T.ink }}>{ACTION_LABELS[entry.action] || entry.action}</div>
                  <div style={{ color: T.slate }}>{entry.detail}</div>
                </div>
                <span style={{ color: T.slate }}>{new Date(entry.createdAt).toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" })}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <button onClick={onLogout} className="flex items-center justify-center gap-2 py-2.5 rounded-lg text-sm font-medium" style={{ backgroundColor: "#FDEBEC", color: "#D6273A" }}>
        <LogOut size={15} /> Log out
      </button>
    </div>
  );
}

/* -------------------------------- settings view ------------------------------ */

function SourceTestResult({ result, T }) {
  if (!result) return null;
  if (result.reachable === true) {
    return <span className="text-xs" style={{ color: T.green }}>Reachable ({result.latencyMs}ms)</span>;
  }
  if (result.reachable === false) {
    return <span className="text-xs" style={{ color: T.crimson }}>Unreachable \u2014 {result.reason}</span>;
  }
  return <span className="text-xs" style={{ color: T.slate }}>{result.reason}</span>;
}

function SettingsView({ T, apiBaseUrl, setApiBaseUrl, onTestConnection, checkingConnection, backendConnected, sources, sourceForm, setSourceForm, onAdd, onDelete, onTestSource, sourceError }) {
  const fieldStyle = { backgroundColor: T.bg, border: `1px solid ${T.border}`, color: T.ink };
  const [testResults, setTestResults] = useState({});
  const [testingId, setTestingId] = useState(null);

  async function handleTestSource(id) {
    setTestingId(id);
    const result = await onTestSource(id);
    setTestResults((prev) => ({ ...prev, [id]: result }));
    setTestingId(null);
  }

  return (
    <div className="px-5 sm:px-8 py-8 max-w-[760px] mx-auto flex flex-col gap-6">
      <div className="rounded-lg p-5 flex flex-col gap-3" style={{ backgroundColor: T.panel, border: `1px solid ${T.border}` }}>
        <span className="text-sm font-semibold" style={{ color: T.ink }}>Backend connection</span>
        <p className="text-xs" style={{ color: T.slate }}>
          Point this dashboard at your NocaSIEM backend to receive real alerts and logs instead of demo data.
        </p>
        <div className="flex flex-col sm:flex-row gap-2">
          <input
            value={apiBaseUrl}
            onChange={(e) => setApiBaseUrl(e.target.value)}
            placeholder="http://localhost:4000"
            className="flex-1 px-3 py-2 rounded-md text-sm outline-none"
            style={{ ...fieldStyle, fontFamily: FONT_MONO }}
          />
          <button onClick={onTestConnection} disabled={checkingConnection} className="px-4 py-2 rounded-md text-sm font-medium text-white shrink-0" style={{ backgroundColor: T.blueBright, opacity: checkingConnection ? 0.7 : 1 }}>
            {checkingConnection ? "Testing\u2026" : "Test connection"}
          </button>
        </div>
        <div className="flex items-center gap-1.5 text-xs" style={{ color: backendConnected ? T.green : T.slate }}>
          {backendConnected ? <Wifi size={13} /> : <WifiOff size={13} />}
          {backendConnected ? "Connected \u2014 showing live data" : "Not connected \u2014 dashboard is showing demo data"}
        </div>
      </div>

      <div className="rounded-lg p-5 flex flex-col gap-4" style={{ backgroundColor: T.panel, border: `1px solid ${T.border}` }}>
        <div>
          <span className="text-sm font-semibold" style={{ color: T.ink }}>Log sources</span>
          <p className="text-xs mt-1" style={{ color: T.slate }}>
            Register the devices that will send logs here, then point each device's syslog forwarder at your backend's ingest port.
          </p>
        </div>

        <form onSubmit={onAdd} className="grid grid-cols-2 sm:grid-cols-4 gap-2 items-end">
          <label className="flex flex-col gap-1 col-span-2 sm:col-span-1">
            <span className="text-xs" style={{ color: T.slate }}>Name</span>
            <input value={sourceForm.name} onChange={(e) => setSourceForm((f) => ({ ...f, name: e.target.value }))} placeholder="Office firewall" className="px-2.5 py-2 rounded-md text-sm outline-none" style={fieldStyle} />
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-xs" style={{ color: T.slate }}>IP address</span>
            <input value={sourceForm.ip} onChange={(e) => setSourceForm((f) => ({ ...f, ip: e.target.value }))} placeholder="10.0.0.5" className="px-2.5 py-2 rounded-md text-sm outline-none" style={{ ...fieldStyle, fontFamily: FONT_MONO }} />
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-xs" style={{ color: T.slate }}>Port</span>
            <input value={sourceForm.port} onChange={(e) => setSourceForm((f) => ({ ...f, port: e.target.value }))} placeholder="514" className="px-2.5 py-2 rounded-md text-sm outline-none" style={{ ...fieldStyle, fontFamily: FONT_MONO }} />
          </label>
          <div className="flex gap-2">
            <select value={sourceForm.protocol} onChange={(e) => setSourceForm((f) => ({ ...f, protocol: e.target.value }))} className="px-2 py-2 rounded-md text-sm outline-none flex-1" style={fieldStyle}>
              <option value="UDP">UDP</option>
              <option value="TCP">TCP</option>
            </select>
            <button type="submit" className="flex items-center justify-center rounded-md text-white shrink-0" style={{ width: 36, backgroundColor: T.blueBright }} aria-label="Add source">
              <Plus size={16} />
            </button>
          </div>
        </form>

        {sourceError && (
          <div className="text-xs px-3 py-2 rounded-md" style={{ backgroundColor: "#FDEBEC", color: "#D6273A" }}>
            {sourceError}
          </div>
        )}

        <div className="flex flex-col">
          {sources.length === 0 && (
            <div className="text-xs py-4 text-center" style={{ color: T.slate }}>
              No sources yet \u2014 add one above to start receiving logs.
            </div>
          )}
          {sources.map((s) => (
            <div key={s.id} className="flex items-center justify-between py-3" style={{ borderTop: `1px solid ${T.border}` }}>
              <div className="flex flex-col">
                <span className="text-sm font-medium" style={{ color: T.ink }}>{s.name}</span>
                <span className="text-xs" style={{ color: T.slate, fontFamily: FONT_MONO }}>{s.ip}:{s.port} \u00b7 {s.protocol}</span>
              </div>
              <div className="flex items-center gap-3">
                <SourceTestResult result={testResults[s.id]} T={T} />
                <span className="flex items-center gap-1 text-xs" style={{ color: s.status === "active" ? T.green : T.slate }}>
                  <Radio size={12} /> {s.status === "active" ? "Active" : "Pending"}
                </span>
                <button onClick={() => handleTestSource(s.id)} disabled={testingId === s.id} className="text-xs font-medium px-2 py-1 rounded-md" style={{ border: `1px solid ${T.border}`, color: T.ink, opacity: testingId === s.id ? 0.6 : 1 }}>
                  {testingId === s.id ? "Testing\u2026" : "Test"}
                </button>
                <button onClick={() => onDelete(s.id)} style={{ color: T.crimson }} aria-label="Delete source">
                  <Trash2 size={15} />
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

/* --------------------------------- admin panel ------------------------------- */

function AdminPanel({ T, users, loading, error, currentUserId, onChangeRole, onChangeStatus, onDelete, onRefresh }) {
  const [confirmDeleteId, setConfirmDeleteId] = useState(null);

  return (
    <div className="px-5 sm:px-8 py-8 max-w-[920px] mx-auto flex flex-col gap-5">
      <div className="flex items-start justify-between gap-3">
        <div>
          <span className="text-sm font-semibold" style={{ color: T.ink }}>Admin panel</span>
          <p className="text-xs mt-1" style={{ color: T.slate }}>
            Manage every account on this NocaSIEM instance. Passwords are never shown here \u2014 they're one-way hashed and can't be recovered by anyone, including admins.
          </p>
        </div>
        <button onClick={onRefresh} className="text-xs font-medium px-3 py-1.5 rounded-md shrink-0" style={{ border: `1px solid ${T.border}`, color: T.ink }}>
          Refresh
        </button>
      </div>

      {error && <div className="text-xs px-3 py-2 rounded-md" style={{ backgroundColor: "#FDEBEC", color: "#D6273A" }}>{error}</div>}

      <div className="rounded-lg overflow-hidden" style={{ backgroundColor: T.panel, border: `1px solid ${T.border}` }}>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr style={{ borderBottom: `1px solid ${T.border}` }}>
                {["User", "Role", "Status", "Joined", "Last login", "Sources", ""].map((h) => (
                  <th key={h} className="text-left font-medium px-4 py-2 whitespace-nowrap" style={{ color: T.slate, fontSize: 12 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {users.map((u) => {
                const isSelf = u.id === currentUserId;
                return (
                  <tr key={u.id} style={{ borderBottom: `1px solid ${T.border}` }}>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <div className="flex items-center justify-center rounded-full text-xs font-semibold text-white shrink-0" style={{ width: 26, height: 26, backgroundColor: T.blueBright }}>
                          {initials(u.username)}
                        </div>
                        <div>
                          <div style={{ color: T.ink }}>
                            {u.username}
                            {isSelf && <span className="text-xs ml-1" style={{ color: T.slate }}>(you)</span>}
                          </div>
                          <div className="text-xs" style={{ color: T.slate }}>{u.email}</div>
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium" style={{ backgroundColor: u.role === "admin" ? "#EAF7F1" : "transparent", color: u.role === "admin" ? "#1F8F63" : T.slate, border: u.role === "admin" ? "none" : `1px solid ${T.border}` }}>
                        {u.role === "admin" && <ShieldCheck size={12} />} {u.role}
                      </span>
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <span className="text-xs font-medium" style={{ color: u.status === "suspended" ? T.crimson : T.green }}>{u.status}</span>
                    </td>
                    <td className="px-4 py-3 text-xs whitespace-nowrap" style={{ color: T.slate }}>
                      {new Date(u.createdAt).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })}
                    </td>
                    <td className="px-4 py-3 text-xs whitespace-nowrap" style={{ color: T.slate }}>
                      {u.lastLoginAt ? new Date(u.lastLoginAt).toLocaleDateString("en-US", { month: "short", day: "numeric" }) : "Never"}
                    </td>
                    <td className="px-4 py-3 text-xs" style={{ color: T.ink }}>{u.sourceCount}</td>
                    <td className="px-4 py-3">
                      {!isSelf && (
                        <div className="flex items-center gap-2 justify-end whitespace-nowrap">
                          <button onClick={() => onChangeRole(u.id, u.role === "admin" ? "user" : "admin")} className="text-xs px-2 py-1 rounded-md" style={{ border: `1px solid ${T.border}`, color: T.ink }}>
                            {u.role === "admin" ? "Demote" : "Promote"}
                          </button>
                          <button onClick={() => onChangeStatus(u.id, u.status === "suspended" ? "active" : "suspended")} className="text-xs px-2 py-1 rounded-md" style={{ border: `1px solid ${T.border}`, color: u.status === "suspended" ? T.green : T.orange }}>
                            {u.status === "suspended" ? "Reactivate" : "Suspend"}
                          </button>
                          {confirmDeleteId === u.id ? (
                            <>
                              <button onClick={() => { onDelete(u.id); setConfirmDeleteId(null); }} className="text-xs px-2 py-1 rounded-md text-white" style={{ backgroundColor: T.crimson }}>
                                Confirm
                              </button>
                              <button onClick={() => setConfirmDeleteId(null)} className="text-xs px-2 py-1 rounded-md" style={{ color: T.slate }}>
                                Cancel
                              </button>
                            </>
                          ) : (
                            <button onClick={() => setConfirmDeleteId(u.id)} style={{ color: T.crimson }} aria-label="Delete user">
                              <Trash2 size={15} />
                            </button>
                          )}
                        </div>
                      )}
                    </td>
                  </tr>
                );
              })}
              {!loading && users.length === 0 && (
                <tr><td colSpan={7} className="text-center text-xs py-6" style={{ color: T.slate }}>No users found.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

/* ---------------------------------- main ------------------------------------ */

export default function NocaSIEM() {
  const [theme, setTheme] = useState("light");
  const T = getTheme(theme);

  const [authMode, setAuthMode] = useState("signin");
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(null);
  const [authError, setAuthError] = useState("");
  const [authLoading, setAuthLoading] = useState(false);

  const [apiBaseUrl, setApiBaseUrl] = useState("http://localhost:4000");
  const [backendConnected, setBackendConnected] = useState(false);
  const [checkingConnection, setCheckingConnection] = useState(false);

  const [view, setView] = useState("dashboard");

  const [sources, setSources] = useState([]);
  const [auditLog, setAuditLog] = useState([]);
  const [sourceForm, setSourceForm] = useState({ name: "", ip: "", port: "", protocol: "UDP" });
  const [sourceError, setSourceError] = useState("");

  const [volume, setVolume] = useState(initialVolume());
  const [alerts, setAlerts] = useState(() => Array.from({ length: 7 }, makeAlert));
  const [logs, setLogs] = useState(() => Array.from({ length: 10 }, makeLogLine));
  const [totalEvents, setTotalEvents] = useState(1284302);
  const [eps, setEps] = useState(38);
  const logRef = useRef(null);

  async function handleAuthSubmit(fields) {
    setAuthError("");
    setAuthLoading(true);
    try {
      const path = authMode === "signin" ? "/api/auth/login" : "/api/auth/register";
      const body =
        authMode === "signin"
          ? { email: fields.email, password: fields.password }
          : { username: fields.username, email: fields.email, password: fields.password };
      const data = await apiRequest(apiBaseUrl, path, { method: "POST", body });
      setUser(data.user);
      setToken(data.token);
      setBackendConnected(true);
    } catch (err) {
      setAuthError(err.message || "Couldn't reach the backend. Check the URL in Settings, or continue in demo mode.");
    } finally {
      setAuthLoading(false);
    }
  }

  function handleDemoMode() {
    setUser({ username: "Demo User", email: "demo@nocasiem.io", createdAt: new Date().toISOString() });
    setToken(null);
    setBackendConnected(false);
  }

  function handleLogout() {
    setUser(null);
    setToken(null);
    setView("dashboard");
    setSources([]);
  }

  async function handleUpdateProfile(fields) {
    if (token) {
      const data = await apiRequest(apiBaseUrl, "/api/auth/me", { method: "PATCH", token, body: fields });
      setUser(data.user);
    } else {
      setUser((prev) => ({ ...prev, ...fields }));
    }
  }

  async function handleChangePassword(fields) {
    if (!token) {
      throw new Error("Password changes aren't available in demo mode. Connect a real backend in Settings first.");
    }
    await apiRequest(apiBaseUrl, "/api/auth/password", { method: "PATCH", token, body: fields });
  }

  async function handleTestSource(id) {
    if (!token) {
      return { reachable: null, reason: "Connect a backend in Settings to test connectivity." };
    }
    try {
      return await apiRequest(apiBaseUrl, `/api/sources/${id}/test`, { method: "POST", token });
    } catch (err) {
      return { reachable: false, reason: err.message };
    }
  }

  async function handleTestConnection() {
    setCheckingConnection(true);
    try {
      await apiRequest(apiBaseUrl, "/api/health");
      setBackendConnected(true);
    } catch {
      setBackendConnected(false);
    }
    setCheckingConnection(false);
  }

  async function handleAddSource(e) {
    e.preventDefault();
    setSourceError("");
    const { name, ip, port, protocol } = sourceForm;
    if (!name || !ip || !port) {
      setSourceError("Please fill in name, IP address and port.");
      return;
    }
    if (token) {
      try {
        const data = await apiRequest(apiBaseUrl, "/api/sources", { method: "POST", token, body: { name, ip, port: Number(port), protocol } });
        setSources((prev) => [...prev, data.source]);
        setSourceForm({ name: "", ip: "", port: "", protocol: "UDP" });
      } catch (err) {
        setSourceError(err.message);
      }
    } else {
      setSources((prev) => [...prev, { id: Date.now(), name, ip, port: Number(port), protocol, status: "pending", lastSeen: null }]);
      setSourceForm({ name: "", ip: "", port: "", protocol: "UDP" });
    }
  }

  async function handleDeleteSource(id) {
    if (token) {
      try {
        await apiRequest(apiBaseUrl, `/api/sources/${id}`, { method: "DELETE", token });
      } catch {
        // ignore - still remove locally below
      }
    }
    setSources((prev) => prev.filter((s) => s.id !== id));
  }

  // Data lifecycle: when a real backend session exists, poll it for live
  // data. Otherwise (demo mode) simulate a live feed locally so the
  // dashboard is fully explorable without any backend running.
  useEffect(() => {
    if (!user) return;

    if (token) {
      let cancelled = false;
      async function poll() {
        try {
          const [statsData, alertsData, logsData, sourcesData, auditData] = await Promise.all([
            apiRequest(apiBaseUrl, "/api/stats", { token }),
            apiRequest(apiBaseUrl, "/api/alerts?limit=7", { token }),
            apiRequest(apiBaseUrl, "/api/logs?limit=40", { token }),
            apiRequest(apiBaseUrl, "/api/sources", { token }),
            apiRequest(apiBaseUrl, "/api/audit-log?limit=10", { token }),
          ]);
          if (cancelled) return;
          setBackendConnected(true);
          setTotalEvents(statsData.totalEvents);
          setAlerts(alertsData.alerts.map((a) => ({ ...a, time: new Date(a.createdAt) })));
          setLogs(logsData.logs.slice().reverse().map((l) => `${timeLabel(new Date(l.createdAt))}  ${l.message}`));
          setSources(sourcesData.sources);
          setAuditLog(auditData.auditLog);
        } catch {
          if (!cancelled) setBackendConnected(false);
        }
      }
      poll();
      const t = setInterval(poll, 3000);
      const epsTimer = setInterval(() => setEps(rand(22, 64)), 4000);
      return () => {
        cancelled = true;
        clearInterval(t);
        clearInterval(epsTimer);
      };
    }

    const t1 = setInterval(() => {
      setAlerts((prev) => [makeAlert(), ...prev].slice(0, 7));
    }, 3400);
    const t2 = setInterval(() => {
      setLogs((prev) => [...prev, makeLogLine()].slice(-40));
    }, 1500);
    const t3 = setInterval(() => {
      setVolume((prev) => {
        const last = prev[prev.length - 1].events;
        const next = Math.max(30, Math.min(260, last + rand(-30, 30)));
        const nextHour = (parseInt(prev[prev.length - 1].time) + 1) % 24;
        return [...prev.slice(1), { time: `${String(nextHour).padStart(2, "0")}:00`, events: next }];
      });
      setTotalEvents((v) => v + rand(80, 400));
      setEps(rand(22, 64));
    }, 4000);

    return () => {
      clearInterval(t1);
      clearInterval(t2);
      clearInterval(t3);
    };
  }, [user, token, apiBaseUrl]);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [logs]);

  const severityCounts = ["Critical", "High", "Medium", "Low"].map((name) => ({
    name,
    value: alerts.filter((a) => a.severity === name).length || 0,
    color: SEV_STYLE[name].dot,
  }));

  const topIps = useMemo(() => {
    const counts = {};
    alerts.forEach((a) => {
      counts[a.sourceIp] = (counts[a.sourceIp] || 0) + 1;
    });
    const arr = Object.entries(counts).map(([ip, n]) => ({ ip, n }));
    while (arr.length < 5) arr.push({ ip: randomIp(), n: rand(1, 4) });
    return arr.sort((a, b) => b.n - a.n).slice(0, 5);
  }, [alerts]);

  const criticalCount = alerts.filter((a) => a.severity === "Critical").length;
  const activeCount = alerts.filter((a) => a.status !== "Resolved").length;
  const maxIp = Math.max(...topIps.map((i) => i.n), 1);

  const globalStyles = (
    <style>{`
      @keyframes waveScroll { from { transform: translateX(0); } to { transform: translateX(-50%); } }
      .wave-track { animation: waveScroll 13s linear infinite; }
      @keyframes pulseDot { 0%, 100% { opacity: 1; } 50% { opacity: 0.35; } }
      .pulse-dot { animation: pulseDot 1.8s ease-in-out infinite; }
      @keyframes logIn { from { opacity: 0; transform: translateY(3px); } to { opacity: 1; transform: translateY(0); } }
      .log-line { animation: logIn 0.25s ease-out; }
      ::-webkit-scrollbar { width: 8px; height: 8px; }
      ::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.15); border-radius: 8px; }
    `}</style>
  );

  if (!user) {
    return (
      <>
        {globalStyles}
        <AuthScreen mode={authMode} onModeChange={setAuthMode} onSubmit={handleAuthSubmit} loading={authLoading} error={authError} onDemo={handleDemoMode} T={T} />
      </>
    );
  }

  return (
    <div style={{ backgroundColor: T.bg, minHeight: "100%", fontFamily: FONT_SANS }}>
      {globalStyles}

      {/* header */}
      <div style={{ position: "relative", overflow: "hidden", background: `linear-gradient(120deg, ${NAVY_DEEP} 0%, ${NAVY_MID} 55%, ${HEADER_BLUE} 120%)` }}>
        <div style={{ position: "absolute", top: -80, right: -60, width: 320, height: 320, borderRadius: "50%", background: "radial-gradient(circle, rgba(255,255,255,0.10) 0%, rgba(255,255,255,0) 70%)" }} />
        <div className="relative flex items-center justify-between px-5 sm:px-8 pt-5 pb-6 gap-3">
          <div className="flex items-center gap-3 shrink-0">
            <div className="flex items-center justify-center rounded-md" style={{ width: 34, height: 34, backgroundColor: "rgba(255,255,255,0.1)" }}>
              <Shield size={18} color={AMBER} />
            </div>
            <div className="hidden xs:block">
              <div className="text-white text-sm font-semibold tracking-wide">NocaSIEM</div>
              <div className="text-xs" style={{ color: "rgba(255,255,255,0.55)" }}>Security operations center</div>
            </div>
          </div>

          <NavTabs view={view} setView={setView} />

          <div className="flex items-center gap-2 sm:gap-3 shrink-0">
            <ThemeToggle theme={theme} onChange={setTheme} />
            <ConnectionBadge connected={backendConnected} />
            <div className="relative">
              <Bell size={17} color="rgba(255,255,255,0.85)" />
              <span className="absolute -top-1.5 -right-1.5 flex items-center justify-center text-[10px] font-semibold text-white rounded-full" style={{ width: 15, height: 15, backgroundColor: T.crimson }}>
                {activeCount}
              </span>
            </div>
            <button onClick={() => setView("profile")} className="flex items-center justify-center rounded-full text-xs font-semibold text-white" style={{ width: 30, height: 30, backgroundColor: "rgba(255,255,255,0.15)" }} aria-label="Open profile">
              {initials(user.username)}
            </button>
          </div>
        </div>
        <AnimatedWave />
      </div>

      {/* views */}
      {view === "dashboard" && (
        <div className="px-5 sm:px-8 py-6 flex flex-col gap-6 max-w-[1400px] mx-auto">
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <KpiCard T={T} icon={Activity} label="Total events (24h)" value={totalEvents.toLocaleString("en-US")} delta={8} accent={T.blueBright} />
            <KpiCard T={T} icon={AlertTriangle} label="Active alerts" value={activeCount} delta={-4} accent={T.orange} />
            <KpiCard T={T} icon={Shield} label="Critical incidents" value={criticalCount} delta={criticalCount > 1 ? 12 : -6} accent={T.crimson} />
            <KpiCard T={T} icon={Zap} label="Events / second" value={eps} delta={5} accent={T.green} />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="lg:col-span-2 rounded-lg p-4 sm:p-5" style={{ backgroundColor: T.panel, border: `1px solid ${T.border}` }}>
              <div className="flex items-center justify-between mb-3">
                <span className="text-sm font-semibold" style={{ color: T.ink }}>Event volume</span>
                <span className="text-xs" style={{ color: T.slate }}>Last 24 hours</span>
              </div>
              <ResponsiveContainer width="100%" height={230}>
                <AreaChart data={volume} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="eventGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor={T.blueBright} stopOpacity={0.35} />
                      <stop offset="100%" stopColor={T.blueBright} stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke={T.border} vertical={false} />
                  <XAxis dataKey="time" tick={{ fontSize: 11, fill: T.slate }} axisLine={false} tickLine={false} interval={3} />
                  <YAxis tick={{ fontSize: 11, fill: T.slate }} axisLine={false} tickLine={false} width={34} />
                  <Tooltip contentStyle={{ fontSize: 12, borderRadius: 8, border: `1px solid ${T.border}` }} />
                  <Area type="monotone" dataKey="events" stroke={T.blueBright} strokeWidth={2} fill="url(#eventGradient)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>

            <div className="rounded-lg p-4 sm:p-5" style={{ backgroundColor: T.panel, border: `1px solid ${T.border}` }}>
              <span className="text-sm font-semibold" style={{ color: T.ink }}>Severity distribution</span>
              <ResponsiveContainer width="100%" height={170}>
                <PieChart>
                  <Pie data={severityCounts} dataKey="value" nameKey="name" innerRadius={48} outerRadius={72} paddingAngle={3} strokeWidth={0}>
                    {severityCounts.map((entry, i) => (
                      <Cell key={i} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ fontSize: 12, borderRadius: 8, border: `1px solid ${T.border}` }} />
                </PieChart>
              </ResponsiveContainer>
              <div className="grid grid-cols-2 gap-2 mt-1">
                {severityCounts.map((s) => (
                  <div key={s.name} className="flex items-center gap-1.5 text-xs" style={{ color: T.slate }}>
                    <span style={{ width: 7, height: 7, borderRadius: 9999, backgroundColor: s.color }} />
                    {s.name} ({s.value})
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="lg:col-span-2 rounded-lg overflow-hidden" style={{ backgroundColor: T.panel, border: `1px solid ${T.border}` }}>
              <div className="flex items-center justify-between px-4 sm:px-5 pt-4 pb-3">
                <span className="text-sm font-semibold" style={{ color: T.ink }}>Recent alerts</span>
                <span className="text-xs" style={{ color: T.slate }}>Auto-refreshing</span>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr style={{ borderTop: `1px solid ${T.border}`, borderBottom: `1px solid ${T.border}` }}>
                      {["Time", "Severity", "Source IP", "Event type", "Status"].map((h) => (
                        <th key={h} className="text-left font-medium px-4 sm:px-5 py-2" style={{ color: T.slate, fontSize: 12 }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {alerts.map((a) => (
                      <tr key={a.id} style={{ borderBottom: `1px solid ${T.border}` }}>
                        <td className="px-4 sm:px-5 py-2.5" style={{ color: T.slate, fontFamily: FONT_MONO, fontSize: 12 }}>{timeLabel(a.time)}</td>
                        <td className="px-4 sm:px-5 py-2.5"><SeverityBadge severity={a.severity} /></td>
                        <td className="px-4 sm:px-5 py-2.5" style={{ fontFamily: FONT_MONO, fontSize: 12.5, color: T.ink }}>{a.sourceIp}</td>
                        <td className="px-4 sm:px-5 py-2.5" style={{ color: T.ink }}>{a.type}</td>
                        <td className="px-4 sm:px-5 py-2.5"><StatusBadge status={a.status} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="rounded-lg overflow-hidden flex flex-col" style={{ backgroundColor: NAVY_DEEP }}>
              <div className="flex items-center gap-2 px-4 py-3" style={{ borderBottom: "1px solid rgba(255,255,255,0.08)" }}>
                <Server size={14} color={AMBER} />
                <span className="text-xs font-medium text-white">Live log stream</span>
              </div>
              <div ref={logRef} className="flex-1 overflow-y-auto px-4 py-3" style={{ height: 260, fontFamily: FONT_MONO, fontSize: 11.5 }}>
                {logs.map((l, i) => (
                  <div key={i} className="log-line" style={{ color: "rgba(255,255,255,0.7)", marginBottom: 4, whiteSpace: "pre" }}>{l}</div>
                ))}
              </div>
            </div>
          </div>

          <div className="rounded-lg p-4 sm:p-5" style={{ backgroundColor: T.panel, border: `1px solid ${T.border}` }}>
            <div className="flex items-center gap-2 mb-4">
              <Globe size={15} color={T.blueBright} />
              <span className="text-sm font-semibold" style={{ color: T.ink }}>Top source IPs</span>
            </div>
            <div className="flex flex-col gap-3">
              {topIps.map((row) => (
                <div key={row.ip} className="flex items-center gap-3">
                  <span style={{ fontFamily: FONT_MONO, fontSize: 12.5, color: T.ink, width: 130 }}>{row.ip}</span>
                  <div className="flex-1 rounded-full overflow-hidden" style={{ height: 7, backgroundColor: T.bg }}>
                    <div style={{ width: `${(row.n / maxIp) * 100}%`, height: "100%", backgroundColor: T.blueBright, borderRadius: 9999 }} />
                  </div>
                  <span className="text-xs w-16 text-right" style={{ color: T.slate }}>{row.n} events</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {view === "profile" && (
        <ProfileView
          user={user}
          T={T}
          onLogout={handleLogout}
          theme={theme}
          onThemeChange={setTheme}
          onUpdateProfile={handleUpdateProfile}
          onChangePassword={handleChangePassword}
          auditLog={auditLog}
          connected={backendConnected}
        />
      )}

      {view === "settings" && (
        <SettingsView
          T={T}
          apiBaseUrl={apiBaseUrl}
          setApiBaseUrl={setApiBaseUrl}
          onTestConnection={handleTestConnection}
          checkingConnection={checkingConnection}
          backendConnected={backendConnected}
          sources={sources}
          sourceForm={sourceForm}
          setSourceForm={setSourceForm}
          onAdd={handleAddSource}
          onDelete={handleDeleteSource}
          onTestSource={handleTestSource}
          sourceError={sourceError}
        />
      )}
    </div>
  );
}
