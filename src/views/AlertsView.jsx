import { useCallback, useEffect, useState } from "react";
import { Search, RotateCcw } from "lucide-react";
import { Card, ErrorNote, FONT_MONO, MitreTags, SEVERITIES, SeverityBadge, StatusSelect, dateTimeLabel, fieldStyle, queryString } from "../shared.jsx";

const PAGE = 50;
const EMPTY = { q: "", severity: "", status: "", srcIp: "", mitre: "", ruleId: "" };

// Filterable alert list. Clicking a row opens the alert detail panel;
// clicking an attacker IP or MITRE technique filters by it.
export default function AlertsView({ T, authed, refreshKey, filters: externalFilters, onOpenAlert, onStatusChange }) {
  const [draft, setDraft] = useState({ ...EMPTY, ...externalFilters });
  const [filters, setFilters] = useState({ ...EMPTY, ...externalFilters });
  const [alerts, setAlerts] = useState([]);
  const [cursor, setCursor] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!externalFilters) return;
    const next = { ...EMPTY, ...externalFilters };
    setDraft(next);
    setFilters(next);
  }, [externalFilters]);

  const load = useCallback(
    async (before) => {
      setLoading(true);
      setError("");
      try {
        const data = await authed(`/api/alerts${queryString({ ...filters, limit: PAGE, before })}`);
        setAlerts((prev) => (before ? [...prev, ...data.alerts] : data.alerts));
        setCursor(data.nextCursor);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    },
    [authed, filters]
  );

  // Reload the first page when filters change or new alerts arrive.
  useEffect(() => {
    load();
  }, [load, refreshKey]);

  const apply = (patch) => {
    const next = { ...filters, ...patch };
    setDraft(next);
    setFilters(next);
  };

  async function changeStatus(id, status) {
    setAlerts((prev) => prev.map((a) => (a.id === id ? { ...a, status } : a)));
    await onStatusChange(id, status);
  }

  const input = { ...fieldStyle(T) };
  const active = Object.values(filters).some(Boolean);

  return (
    <div className="px-5 sm:px-8 py-6 max-w-[1400px] mx-auto flex flex-col gap-4">
      <div>
        <div className="text-base font-semibold" style={{ color: T.ink }}>Alerts</div>
        <div className="text-xs" style={{ color: T.slate }}>Everything the detection rules flagged. Click an alert for the full story.</div>
      </div>

      <Card T={T} className="p-3">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            setFilters(draft);
          }}
          className="grid grid-cols-2 md:grid-cols-6 gap-2 items-end"
        >
          <label className="flex flex-col gap-1 col-span-2">
            <span className="text-xs" style={{ color: T.slate }}>Search title or log text</span>
            <input value={draft.q} onChange={(e) => setDraft({ ...draft, q: e.target.value })} placeholder="e.g. brute force" maxLength={200} className="px-2.5 py-1.5 rounded-md text-sm outline-none" style={input} />
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-xs" style={{ color: T.slate }}>Severity</span>
            <select value={draft.severity} onChange={(e) => apply({ severity: e.target.value })} className="px-2 py-1.5 rounded-md text-sm outline-none" style={input}>
              <option value="">All</option>
              {SEVERITIES.map((s) => <option key={s}>{s}</option>)}
            </select>
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-xs" style={{ color: T.slate }}>Status</span>
            <select value={draft.status} onChange={(e) => apply({ status: e.target.value })} className="px-2 py-1.5 rounded-md text-sm outline-none" style={input}>
              <option value="">All</option>
              <option>Open</option>
              <option>Investigating</option>
              <option>Resolved</option>
            </select>
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-xs" style={{ color: T.slate }}>Attacker IP</span>
            <input value={draft.srcIp} onChange={(e) => setDraft({ ...draft, srcIp: e.target.value })} placeholder="203.0.113.7" maxLength={45} className="px-2.5 py-1.5 rounded-md text-sm outline-none" style={{ ...input, fontFamily: FONT_MONO }} />
          </label>
          <div className="flex gap-2">
            <button type="submit" className="flex-1 flex items-center justify-center gap-1 px-3 py-1.5 rounded-md text-sm font-medium text-white" style={{ backgroundColor: T.blueBright }}>
              <Search size={14} /> Search
            </button>
            {active && (
              <button type="button" onClick={() => (setDraft(EMPTY), setFilters(EMPTY))} className="px-2 rounded-md" style={{ border: `1px solid ${T.border}`, color: T.slate }} aria-label="Clear filters" title="Clear filters">
                <RotateCcw size={14} />
              </button>
            )}
          </div>
        </form>
        {(filters.mitre || filters.ruleId) && (
          <div className="flex gap-2 mt-2 text-xs" style={{ color: T.slate }}>
            {filters.mitre && <span>Technique: <b style={{ color: T.ink }}>{filters.mitre}</b></span>}
            {filters.ruleId && <span>Rule: <b style={{ color: T.ink }}>#{filters.ruleId}</b></span>}
          </div>
        )}
      </Card>

      <ErrorNote>{error}</ErrorNote>

      <Card T={T} className="overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr style={{ borderBottom: `1px solid ${T.border}` }}>
                {["Time", "Severity", "Alert", "Attacker IP", "User", "Device", "MITRE", "Status"].map((h) => (
                  <th key={h} className="text-left font-medium px-3 py-2 whitespace-nowrap" style={{ color: T.slate, fontSize: 12 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {alerts.map((a) => (
                <tr key={a.id} onClick={() => onOpenAlert(a.id)} className="cursor-pointer" style={{ borderBottom: `1px solid ${T.border}` }}>
                  <td className="px-3 py-2 whitespace-nowrap text-xs" style={{ color: T.slate, fontFamily: FONT_MONO }}>{dateTimeLabel(a.createdAt)}</td>
                  <td className="px-3 py-2">
                    <div className="flex items-center gap-1.5">
                      <SeverityBadge severity={a.severity} />
                      <span className="text-[11px]" style={{ color: T.slate }}>L{a.level}</span>
                    </div>
                  </td>
                  <td className="px-3 py-2 min-w-[220px]" style={{ color: T.ink }}>
                    {a.title}
                    {a.firedTimes > 1 && <span className="text-xs ml-1" style={{ color: T.slate }}>({a.firedTimes}x)</span>}
                  </td>
                  <td className="px-3 py-2 whitespace-nowrap">
                    {a.srcIp ? (
                      <button onClick={(e) => (e.stopPropagation(), apply({ srcIp: a.srcIp }))} className="text-xs" style={{ color: T.blueBright, fontFamily: FONT_MONO }}>{a.srcIp}</button>
                    ) : (
                      <span style={{ color: T.slate }}>{"—"}</span>
                    )}
                  </td>
                  <td className="px-3 py-2 text-xs" style={{ color: T.ink }}>{a.user || "—"}</td>
                  <td className="px-3 py-2 text-xs whitespace-nowrap" style={{ color: T.slate, fontFamily: FONT_MONO }}>{a.sourceIp}</td>
                  <td className="px-3 py-2"><MitreTags techniques={a.mitre} T={T} onSelect={(id) => apply({ mitre: id })} /></td>
                  <td className="px-3 py-2"><StatusSelect status={a.status} onChange={(s) => changeStatus(a.id, s)} /></td>
                </tr>
              ))}
              {!loading && alerts.length === 0 && (
                <tr>
                  <td colSpan={8} className="text-center text-xs py-10" style={{ color: T.slate }}>
                    {active ? "No alerts match these filters." : "No alerts yet. Try `npm run test-log -- --scenario all` to simulate attacks."}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        {(cursor || loading) && (
          <div className="flex justify-center p-3" style={{ borderTop: `1px solid ${T.border}` }}>
            <button onClick={() => load(cursor)} disabled={loading} className="text-xs font-medium px-3 py-1.5 rounded-md" style={{ border: `1px solid ${T.border}`, color: T.ink, opacity: loading ? 0.6 : 1 }}>
              {loading ? "Loading…" : "Load older alerts"}
            </button>
          </div>
        )}
      </Card>
    </div>
  );
}
