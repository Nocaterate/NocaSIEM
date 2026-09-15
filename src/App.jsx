import { useState, useEffect, useRef, useMemo, useCallback } from "react";
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

function timeLabel(d) {
  return d.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function initials(name) {
  if (!name) return "U";
  return name.trim().split(/\s+/).map((w) => w[0]).slice(0, 2).join("").toUpperCase();
}

// The dashboard is served by the backend itself, so every call is same-origin
// (in development Vite proxies /api and /ws to the backend).
async function apiRequest(path, { method = "GET", token, body } = {}) {
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

function KpiCard({ icon: Icon, label, value, hint, accent, T }) {
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
        {hint && <span className="text-xs" style={{ color: T.slate, fontFamily: FONT_SANS }}>{hint}</span>}
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

function StatusSelect({ status, onChange }) {
  const s = STATUS_STYLE[status] || STATUS_STYLE.Open;
  return (
    <select
      value={status}
      onChange={(e) => onChange(e.target.value)}
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
      {connected ? "Live" : "Reconnecting\u2026"}
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

function AuthScreen({ mode, onModeChange, registrationOpen, onSubmit, loading, error, T }) {
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

        {registrationOpen && (
        <div className="flex mb-5 rounded-md overflow-hidden" style={{ border: `1px solid ${T.border}` }}>
          <button type="button" onClick={() => onModeChange("signin")} className="flex-1 text-sm py-2" style={{ backgroundColor: mode === "signin" ? T.bg : "transparent", color: mode === "signin" ? T.ink : T.slate, fontWeight: mode === "signin" ? 600 : 400 }}>
            Sign in
          </button>
          <button type="button" onClick={() => onModeChange("signup")} className="flex-1 text-sm py-2" style={{ backgroundColor: mode === "signup" ? T.bg : "transparent", color: mode === "signup" ? T.ink : T.slate, fontWeight: mode === "signup" ? 600 : 400 }}>
            Sign up
          </button>
        </div>
        )}

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

        {!registrationOpen && (
          <p className="mt-4 text-xs text-center" style={{ color: T.slate }}>
            Sign-up is closed on this instance. Ask an administrator for an account.
          </p>
        )}
      </div>
    </div>
  );
}

/* -------------------------------- profile view ------------------------------- */

const ACTION_LABELS = {
  login: "Signed in",
  admin_role_change: "Changed a user's role",
  admin_status_change: "Changed a user's status",
  admin_user_deleted: "Deleted a user",
  register: "Account created",
  profile_update: "Profile updated",
  password_change: "Password changed",
  source_added: "Log source added",
  source_removed: "Log source removed",
};

function ProfileView({ user, T, onLogout, theme, onThemeChange, onUpdateProfile, onChangePassword, auditLog }) {
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
          <span style={{ color: T.ink }}>{user.role === "admin" ? "Administrator" : "Analyst"}</span>
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

      {auditLog.length > 0 && (
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
    return <span className="text-xs" style={{ color: T.crimson }}>Unreachable — {result.reason}</span>;
  }
  return <span className="text-xs" style={{ color: T.slate }}>{result.reason}</span>;
}

function SettingsView({ T, ingest, sources, sourceForm, setSourceForm, onAdd, onDelete, onTestSource, sourceError }) {
  const fieldStyle = { backgroundColor: T.bg, border: `1px solid ${T.border}`, color: T.ink };
  const [testResults, setTestResults] = useState({});
  const [testingId, setTestingId] = useState(null);

  async function handleTestSource(id) {
    setTestingId(id);
    const result = await onTestSource(id);
    setTestResults((prev) => ({ ...prev, [id]: result }));
    setTestingId(null);
  }

  const host = window.location.hostname;

  return (
    <div className="px-5 sm:px-8 py-8 max-w-[760px] mx-auto flex flex-col gap-6">
      <div className="rounded-lg p-5 flex flex-col gap-3" style={{ backgroundColor: T.panel, border: `1px solid ${T.border}` }}>
        <span className="text-sm font-semibold" style={{ color: T.ink }}>Where to send logs</span>
        <p className="text-xs" style={{ color: T.slate }}>
          Configure each device's syslog forwarder to send to this server. Incoming traffic is matched to your sources by the device's IP address.
        </p>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          {[
            { label: "UDP syslog", port: ingest?.udpPort },
            { label: "TCP syslog", port: ingest?.tcpPort },
          ].map((row) => (
            <div key={row.label} className="flex items-center justify-between px-3 py-2 rounded-md text-sm" style={{ backgroundColor: T.bg, border: `1px solid ${T.border}` }}>
              <span className="text-xs" style={{ color: T.slate }}>{row.label}</span>
              <span style={{ color: T.ink, fontFamily: FONT_MONO, fontSize: 12.5 }}>{row.port ? `${host}:${row.port}` : "\u2014"}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="rounded-lg p-5 flex flex-col gap-4" style={{ backgroundColor: T.panel, border: `1px solid ${T.border}` }}>
        <div>
          <span className="text-sm font-semibold" style={{ color: T.ink }}>Log sources</span>
          <p className="text-xs mt-1" style={{ color: T.slate }}>
            Register the devices that will send logs here. You'll only see events from IPs you've registered.
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
              No sources yet — add one above to start receiving logs.
            </div>
          )}
          {sources.map((s) => (
            <div key={s.id} className="flex items-center justify-between py-3" style={{ borderTop: `1px solid ${T.border}` }}>
              <div className="flex flex-col">
                <span className="text-sm font-medium" style={{ color: T.ink }}>{s.name}</span>
                <span className="text-xs" style={{ color: T.slate, fontFamily: FONT_MONO }}>{s.ip}:{s.port} · {s.protocol}</span>
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
            Manage every account on this NocaSIEM instance. Passwords are never shown here — they're one-way hashed and can't be recovered by anyone, including admins.
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
              {loading && users.length === 0 && (
                <tr><td colSpan={7} className="text-center text-xs py-6" style={{ color: T.slate }}>Loading users…</td></tr>
              )}
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

const TOKEN_KEY = "nocasiem.token";
const THEME_KEY = "nocasiem.theme";

const EMPTY_STATS = {
  totalEvents: 0,
  activeAlerts: 0,
  criticalIncidents: 0,
  eventsPerSecond: 0,
  severityBreakdown: [],
  volume: [],
  topSources: [],
};

function readStorage(key) {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

function writeStorage(key, value) {
  try {
    if (value == null) localStorage.removeItem(key);
    else localStorage.setItem(key, value);
  } catch {
    // storage unavailable (e.g. private mode) - the session just won't persist
  }
}

function hourLabel(iso) {
  return new Date(iso).toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", hour12: false });
}

export default function NocaSIEM() {
  const [theme, setThemeState] = useState(() => (readStorage(THEME_KEY) === "dark" ? "dark" : "light"));
  const T = getTheme(theme);
  const setTheme = (next) => {
    setThemeState(next);
    writeStorage(THEME_KEY, next);
  };

  const [config, setConfig] = useState({ registrationOpen: true, ingest: null });

  const [authMode, setAuthMode] = useState("signin");
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(() => readStorage(TOKEN_KEY));
  const [restoring, setRestoring] = useState(() => !!readStorage(TOKEN_KEY));
  const [authError, setAuthError] = useState("");
  const [authLoading, setAuthLoading] = useState(false);

  const [connected, setConnected] = useState(false);
  const [view, setView] = useState("dashboard");

  const [sources, setSources] = useState([]);
  const [auditLog, setAuditLog] = useState([]);
  const [sourceForm, setSourceForm] = useState({ name: "", ip: "", port: "", protocol: "UDP" });
  const [sourceError, setSourceError] = useState("");

  const [stats, setStats] = useState(EMPTY_STATS);
  const [alerts, setAlerts] = useState([]);
  const [logs, setLogs] = useState([]);
  const logRef = useRef(null);

  const [adminUsers, setAdminUsers] = useState([]);
  const [adminLoading, setAdminLoading] = useState(false);
  const [adminError, setAdminError] = useState("");

  const isAdmin = user?.role === "admin";

  const handleLogout = useCallback(() => {
    writeStorage(TOKEN_KEY, null);
    setToken(null);
    setUser(null);
    setView("dashboard");
    setSources([]);
    setAuditLog([]);
    setAlerts([]);
    setLogs([]);
    setStats(EMPTY_STATS);
    setAdminUsers([]);
    setConnected(false);
  }, []);

  // Every authenticated call goes through here, so an expired token or a
  // suspended account signs the user out instead of leaving a broken UI.
  const authed = useCallback(
    async (path, opts = {}) => {
      try {
        return await apiRequest(path, { ...opts, token });
      } catch (err) {
        if (err.status === 401 || err.code === "ACCOUNT_SUSPENDED") {
          handleLogout();
          setAuthError(err.message);
        }
        throw err;
      }
    },
    [token, handleLogout]
  );

  useEffect(() => {
    apiRequest("/api/config").then(setConfig).catch(() => {});
  }, []);

  // Restore a saved session on page load.
  useEffect(() => {
    if (!token || user) {
      setRestoring(false);
      return;
    }
    let cancelled = false;
    apiRequest("/api/auth/me", { token })
      .then((data) => {
        if (!cancelled) setUser(data.user);
      })
      .catch((err) => {
        if (cancelled) return;
        if (err.status) handleLogout();
        else setAuthError("Couldn't reach the server. Please try again.");
      })
      .finally(() => {
        if (!cancelled) setRestoring(false);
      });
    return () => {
      cancelled = true;
    };
  }, [token, user, handleLogout]);

  async function handleAuthSubmit(fields) {
    setAuthError("");
    setAuthLoading(true);
    try {
      const path = authMode === "signin" ? "/api/auth/login" : "/api/auth/register";
      const body =
        authMode === "signin"
          ? { email: fields.email, password: fields.password }
          : { username: fields.username, email: fields.email, password: fields.password };
      const data = await apiRequest(path, { method: "POST", body });
      writeStorage(TOKEN_KEY, data.token);
      setToken(data.token);
      setUser(data.user);
      setView("dashboard");
      if (authMode === "signup") apiRequest("/api/config").then(setConfig).catch(() => {});
    } catch (err) {
      setAuthError(err.status ? err.message : "Couldn't reach the server. Please try again.");
    } finally {
      setAuthLoading(false);
    }
  }

  async function handleUpdateProfile(fields) {
    const data = await authed("/api/auth/me", { method: "PATCH", body: fields });
    setUser(data.user);
  }

  async function handleChangePassword(fields) {
    await authed("/api/auth/password", { method: "PATCH", body: fields });
  }

  async function handleTestSource(id) {
    try {
      return await authed(`/api/sources/${id}/test`, { method: "POST" });
    } catch (err) {
      return { reachable: false, reason: err.message };
    }
  }

  async function handleAddSource(e) {
    e.preventDefault();
    setSourceError("");
    const { name, ip, port, protocol } = sourceForm;
    if (!name || !ip || !port) {
      setSourceError("Please fill in name, IP address and port.");
      return;
    }
    try {
      const data = await authed("/api/sources", { method: "POST", body: { name, ip, port: Number(port), protocol } });
      setSources((prev) => [...prev, data.source]);
      setSourceForm({ name: "", ip: "", port: "", protocol: "UDP" });
    } catch (err) {
      setSourceError(err.message);
    }
  }

  async function handleDeleteSource(id) {
    setSourceError("");
    try {
      await authed(`/api/sources/${id}`, { method: "DELETE" });
      setSources((prev) => prev.filter((s) => s.id !== id));
    } catch (err) {
      setSourceError(err.message);
    }
  }

  async function handleAlertStatus(id, status) {
    setAlerts((prev) => prev.map((a) => (a.id === id ? { ...a, status } : a)));
    try {
      await authed(`/api/alerts/${id}`, { method: "PATCH", body: { status } });
    } finally {
      refresh();
    }
  }

  const refresh = useCallback(async () => {
    if (!token) return;
    try {
      const [statsData, alertsData, logsData, sourcesData, auditData] = await Promise.all([
        authed("/api/stats"),
        authed("/api/alerts?limit=7"),
        authed("/api/logs?limit=40"),
        authed("/api/sources"),
        authed("/api/audit-log?limit=10"),
      ]);
      setStats(statsData);
      setAlerts(alertsData.alerts);
      setLogs(logsData.logs.slice().reverse());
      setSources(sourcesData.sources);
      setAuditLog(auditData.auditLog);
    } catch {
      // transient network error - the next poll or live event retries
    }
  }, [token, authed]);

  // Live data: an initial fetch, a WebSocket that signals new logs/alerts the
  // moment they're ingested, and a slow poll as a safety net.
  const userId = user?.id;
  useEffect(() => {
    if (!userId || !token) return;

    let cancelled = false;
    let ws;
    let retryTimer;
    let refreshTimer;

    refresh();
    const poll = setInterval(refresh, 15000);

    // Coalesce bursts of events (e.g. a port scan) into a single refetch.
    function scheduleRefresh() {
      if (refreshTimer) return;
      refreshTimer = setTimeout(() => {
        refreshTimer = null;
        refresh();
      }, 500);
    }

    function connect() {
      const proto = window.location.protocol === "https:" ? "wss" : "ws";
      ws = new WebSocket(`${proto}://${window.location.host}/ws`);
      ws.onopen = () => ws.send(JSON.stringify({ type: "auth", token }));
      ws.onmessage = (e) => {
        let msg;
        try {
          msg = JSON.parse(e.data);
        } catch {
          return;
        }
        if (msg.type === "ready") setConnected(true);
        else if (msg.type === "log" || msg.type === "alert") scheduleRefresh();
      };
      ws.onclose = () => {
        setConnected(false);
        if (!cancelled) retryTimer = setTimeout(connect, 3000);
      };
    }
    connect();

    return () => {
      cancelled = true;
      clearInterval(poll);
      clearTimeout(retryTimer);
      clearTimeout(refreshTimer);
      if (ws) ws.close();
    };
  }, [userId, token, refresh]);

  const loadAdminUsers = useCallback(async () => {
    setAdminLoading(true);
    setAdminError("");
    try {
      const data = await authed("/api/admin/users");
      setAdminUsers(data.users);
    } catch (err) {
      setAdminError(err.message);
    } finally {
      setAdminLoading(false);
    }
  }, [authed]);

  useEffect(() => {
    if (view === "admin" && isAdmin) loadAdminUsers();
  }, [view, isAdmin, loadAdminUsers]);

  async function runAdminAction(action) {
    setAdminError("");
    try {
      await action();
      await loadAdminUsers();
    } catch (err) {
      setAdminError(err.message);
    }
  }

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [logs]);

  const severityCounts = ["Critical", "High", "Medium", "Low"].map((name) => ({
    name,
    value: stats.severityBreakdown.find((s) => s.name === name)?.value || 0,
    color: SEV_STYLE[name].dot,
  }));
  const severityTotal = severityCounts.reduce((sum, s) => sum + s.value, 0);

  const volume = useMemo(() => stats.volume.map((v) => ({ time: hourLabel(v.start), events: v.events })), [stats.volume]);
  const topIps = stats.topSources;
  const maxIp = Math.max(...topIps.map((i) => i.count), 1);

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
      body { background-color: ${T.bg}; }
    `}</style>
  );

  if (restoring) {
    return (
      <div style={{ minHeight: "100vh", backgroundColor: T.bg, color: T.slate, fontFamily: FONT_SANS }} className="flex items-center justify-center gap-2 text-sm">
        {globalStyles}
        <Shield size={18} color={AMBER} /> Loading NocaSIEM{"…"}
      </div>
    );
  }

  if (!user) {
    return (
      <>
        {globalStyles}
        <AuthScreen
          mode={config.registrationOpen ? authMode : "signin"}
          onModeChange={(m) => {
            setAuthMode(m);
            setAuthError("");
          }}
          registrationOpen={config.registrationOpen}
          onSubmit={handleAuthSubmit}
          loading={authLoading}
          error={authError}
          T={T}
        />
      </>
    );
  }

  return (
    <div style={{ backgroundColor: T.bg, minHeight: "100vh", fontFamily: FONT_SANS }}>
      {globalStyles}

      {/* header */}
      <div style={{ position: "relative", overflow: "hidden", background: `linear-gradient(120deg, ${NAVY_DEEP} 0%, ${NAVY_MID} 55%, ${HEADER_BLUE} 120%)` }}>
        <div style={{ position: "absolute", top: -80, right: -60, width: 320, height: 320, borderRadius: "50%", background: "radial-gradient(circle, rgba(255,255,255,0.10) 0%, rgba(255,255,255,0) 70%)" }} />
        <div className="relative flex items-center justify-between px-5 sm:px-8 pt-5 pb-6 gap-3">
          <div className="flex items-center gap-3 shrink-0">
            <div className="flex items-center justify-center rounded-md" style={{ width: 34, height: 34, backgroundColor: "rgba(255,255,255,0.1)" }}>
              <Shield size={18} color={AMBER} />
            </div>
            <div className="hidden md:block">
              <div className="text-white text-sm font-semibold tracking-wide">NocaSIEM</div>
              <div className="text-xs" style={{ color: "rgba(255,255,255,0.55)" }}>Security operations center</div>
            </div>
          </div>

          <NavTabs view={view} setView={setView} isAdmin={isAdmin} />

          <div className="flex items-center gap-2 sm:gap-3 shrink-0">
            <ThemeToggle theme={theme} onChange={setTheme} />
            <ConnectionBadge connected={connected} />
            <button onClick={() => setView("dashboard")} className="relative" aria-label={`${stats.activeAlerts} active alerts`}>
              <Bell size={17} color="rgba(255,255,255,0.85)" />
              {stats.activeAlerts > 0 && (
                <span className="absolute -top-1.5 -right-2 flex items-center justify-center text-[10px] font-semibold text-white rounded-full px-1" style={{ minWidth: 15, height: 15, backgroundColor: T.crimson }}>
                  {stats.activeAlerts > 99 ? "99+" : stats.activeAlerts}
                </span>
              )}
            </button>
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
          {sources.length === 0 && !isAdmin && (
            <div className="rounded-lg px-4 py-3 text-sm flex flex-col sm:flex-row sm:items-center justify-between gap-2" style={{ backgroundColor: T.panel, border: `1px solid ${T.border}`, color: T.ink }}>
              <span>No log sources yet. Register a device to start seeing its events here.</span>
              <button onClick={() => setView("settings")} className="text-xs font-medium px-3 py-1.5 rounded-md text-white self-start sm:self-auto" style={{ backgroundColor: T.blueBright }}>
                Add a log source
              </button>
            </div>
          )}

          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <KpiCard T={T} icon={Activity} label="Total events (24h)" value={stats.totalEvents.toLocaleString("en-US")} accent={T.blueBright} />
            <KpiCard T={T} icon={AlertTriangle} label="Active alerts" value={stats.activeAlerts} accent={T.orange} />
            <KpiCard T={T} icon={Shield} label="Critical incidents" value={stats.criticalIncidents} accent={T.crimson} />
            <KpiCard T={T} icon={Zap} label="Events / second" value={stats.eventsPerSecond} hint="last minute" accent={T.green} />
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
                  <YAxis tick={{ fontSize: 11, fill: T.slate }} axisLine={false} tickLine={false} width={34} allowDecimals={false} />
                  <Tooltip contentStyle={{ fontSize: 12, borderRadius: 8, border: `1px solid ${T.border}` }} />
                  <Area type="monotone" dataKey="events" stroke={T.blueBright} strokeWidth={2} fill="url(#eventGradient)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>

            <div className="rounded-lg p-4 sm:p-5" style={{ backgroundColor: T.panel, border: `1px solid ${T.border}` }}>
              <span className="text-sm font-semibold" style={{ color: T.ink }}>Severity distribution</span>
              {severityTotal === 0 ? (
                <div className="flex items-center justify-center text-xs text-center" style={{ height: 170, color: T.slate }}>
                  No alerts in the last 24 hours
                </div>
              ) : (
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
              )}
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
                <span className="text-xs" style={{ color: T.slate }}>{connected ? "Live" : "Auto-refreshing"}</span>
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
                      <tr key={a.id} style={{ borderBottom: `1px solid ${T.border}` }} title={a.message}>
                        <td className="px-4 sm:px-5 py-2.5 whitespace-nowrap" style={{ color: T.slate, fontFamily: FONT_MONO, fontSize: 12 }}>{timeLabel(new Date(a.createdAt))}</td>
                        <td className="px-4 sm:px-5 py-2.5"><SeverityBadge severity={a.severity} /></td>
                        <td className="px-4 sm:px-5 py-2.5" style={{ fontFamily: FONT_MONO, fontSize: 12.5, color: T.ink }}>{a.sourceIp}</td>
                        <td className="px-4 sm:px-5 py-2.5" style={{ color: T.ink }}>{a.type}</td>
                        <td className="px-4 sm:px-5 py-2.5"><StatusSelect status={a.status} onChange={(s) => handleAlertStatus(a.id, s)} /></td>
                      </tr>
                    ))}
                    {alerts.length === 0 && (
                      <tr>
                        <td colSpan={5} className="text-center text-xs py-8" style={{ color: T.slate }}>
                          No alerts yet. Alerts appear here when incoming logs match a detection rule.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="rounded-lg overflow-hidden flex flex-col" style={{ backgroundColor: NAVY_DEEP }}>
              <div className="flex items-center gap-2 px-4 py-3" style={{ borderBottom: "1px solid rgba(255,255,255,0.08)" }}>
                <Server size={14} color={AMBER} />
                <span className="text-xs font-medium text-white">Live log stream</span>
                {connected && <span className="pulse-dot ml-auto" style={{ width: 7, height: 7, borderRadius: 9999, backgroundColor: "#3EE0A0" }} />}
              </div>
              <div ref={logRef} className="flex-1 overflow-auto px-4 py-3" style={{ height: 260, fontFamily: FONT_MONO, fontSize: 11.5 }}>
                {logs.length === 0 && (
                  <div style={{ color: "rgba(255,255,255,0.5)", whiteSpace: "normal" }}>
                    Waiting for logs{"…"}
                    {config.ingest && ` Send syslog to ${window.location.hostname} on UDP ${config.ingest.udpPort} or TCP ${config.ingest.tcpPort}.`}
                  </div>
                )}
                {logs.map((l) => (
                  <div key={l.id} className="log-line" style={{ color: "rgba(255,255,255,0.7)", marginBottom: 4, whiteSpace: "pre" }}>
                    {`${timeLabel(new Date(l.createdAt))}  ${l.sourceIp.padEnd(15, " ")}  ${l.message}`}
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="rounded-lg p-4 sm:p-5" style={{ backgroundColor: T.panel, border: `1px solid ${T.border}` }}>
            <div className="flex items-center gap-2 mb-4">
              <Globe size={15} color={T.blueBright} />
              <span className="text-sm font-semibold" style={{ color: T.ink }}>Top source IPs</span>
              <span className="text-xs ml-auto" style={{ color: T.slate }}>Last 24 hours</span>
            </div>
            <div className="flex flex-col gap-3">
              {topIps.length === 0 && (
                <div className="text-xs text-center py-2" style={{ color: T.slate }}>No events received yet.</div>
              )}
              {topIps.map((row) => (
                <div key={row.ip} className="flex items-center gap-3">
                  <span style={{ fontFamily: FONT_MONO, fontSize: 12.5, color: T.ink, width: 130 }}>{row.ip}</span>
                  <div className="flex-1 rounded-full overflow-hidden" style={{ height: 7, backgroundColor: T.bg }}>
                    <div style={{ width: `${(row.count / maxIp) * 100}%`, height: "100%", backgroundColor: T.blueBright, borderRadius: 9999 }} />
                  </div>
                  <span className="text-xs w-20 text-right" style={{ color: T.slate }}>{row.count.toLocaleString("en-US")} events</span>
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
        />
      )}

      {view === "settings" && (
        <SettingsView
          T={T}
          ingest={config.ingest}
          sources={sources}
          sourceForm={sourceForm}
          setSourceForm={setSourceForm}
          onAdd={handleAddSource}
          onDelete={handleDeleteSource}
          onTestSource={handleTestSource}
          sourceError={sourceError}
        />
      )}

      {view === "admin" && isAdmin && (
        <AdminPanel
          T={T}
          users={adminUsers}
          loading={adminLoading}
          error={adminError}
          currentUserId={user.id}
          onChangeRole={(id, role) => runAdminAction(() => authed(`/api/admin/users/${id}/role`, { method: "PATCH", body: { role } }))}
          onChangeStatus={(id, status) => runAdminAction(() => authed(`/api/admin/users/${id}/status`, { method: "PATCH", body: { status } }))}
          onDelete={(id) => runAdminAction(() => authed(`/api/admin/users/${id}`, { method: "DELETE" }))}
          onRefresh={loadAdminUsers}
        />
      )}
    </div>
  );
}
