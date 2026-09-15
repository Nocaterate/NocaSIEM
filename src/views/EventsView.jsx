import { useCallback, useEffect, useState } from "react";
import { Search, RotateCcw } from "lucide-react";
import { Card, ErrorNote, FONT_MONO, dateTimeLabel, fieldStyle, queryString } from "../shared.jsx";

const PAGE = 100;
const DECODERS = ["sshd", "sudo", "su", "accounts", "firewall", "pfsense", "mikrotik", "web-access", "windows", "json", "generic", "legacy"];
const RANGES = [
  { label: "Last hour", ms: 60 * 60 * 1000 },
  { label: "Last 24 hours", ms: 24 * 60 * 60 * 1000 },
  { label: "Last 7 days", ms: 7 * 24 * 60 * 60 * 1000 },
  { label: "Last 30 days", ms: 30 * 24 * 60 * 60 * 1000 },
  { label: "All time", ms: 0 },
];
const EMPTY = { q: "", srcIp: "", user: "", decoder: "", sourceIp: "", range: "Last 24 hours" };

// Log search: full-text search plus field filters over every stored log line.
export default function EventsView({ T, authed, refreshKey }) {
  const [draft, setDraft] = useState(EMPTY);
  const [filters, setFilters] = useState(EMPTY);
  const [logs, setLogs] = useState([]);
  const [cursor, setCursor] = useState(null);
  const [expanded, setExpanded] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const load = useCallback(
    async (before) => {
      setLoading(true);
      setError("");
      const range = RANGES.find((r) => r.label === filters.range);
      const from = range && range.ms ? new Date(Date.now() - range.ms).toISOString() : undefined;
      const { range: _range, ...rest } = filters;
      try {
        const data = await authed(`/api/logs${queryString({ ...rest, from, limit: PAGE, before })}`);
        setLogs((prev) => (before ? [...prev, ...data.logs] : data.logs));
        setCursor(data.nextCursor);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    },
    [authed, filters]
  );

  useEffect(() => {
    load();
  }, [load, refreshKey]);

  const apply = (patch) => {
    const next = { ...filters, ...patch };
    setDraft(next);
    setFilters(next);
  };

  const input = fieldStyle(T);
  const active = JSON.stringify(filters) !== JSON.stringify(EMPTY);

  return (
    <div className="px-5 sm:px-8 py-6 max-w-[1400px] mx-auto flex flex-col gap-4">
      <div>
        <div className="text-base font-semibold" style={{ color: T.ink }}>Events</div>
        <div className="text-xs" style={{ color: T.slate }}>Search every log line received, with the fields NocaSIEM extracted from it.</div>
      </div>

      <Card T={T} className="p-3">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            setFilters(draft);
          }}
          className="grid grid-cols-2 md:grid-cols-7 gap-2 items-end"
        >
          <label className="flex flex-col gap-1 col-span-2">
            <span className="text-xs" style={{ color: T.slate }}>Search log text</span>
            <input value={draft.q} onChange={(e) => setDraft({ ...draft, q: e.target.value })} placeholder="e.g. failed password root" maxLength={200} className="px-2.5 py-1.5 rounded-md text-sm outline-none" style={input} />
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-xs" style={{ color: T.slate }}>Attacker / source IP</span>
            <input value={draft.srcIp} onChange={(e) => setDraft({ ...draft, srcIp: e.target.value })} maxLength={45} className="px-2.5 py-1.5 rounded-md text-sm outline-none" style={{ ...input, fontFamily: FONT_MONO }} />
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-xs" style={{ color: T.slate }}>User</span>
            <input value={draft.user} onChange={(e) => setDraft({ ...draft, user: e.target.value })} maxLength={100} className="px-2.5 py-1.5 rounded-md text-sm outline-none" style={input} />
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-xs" style={{ color: T.slate }}>Log type</span>
            <select value={draft.decoder} onChange={(e) => apply({ decoder: e.target.value })} className="px-2 py-1.5 rounded-md text-sm outline-none" style={input}>
              <option value="">All</option>
              {DECODERS.map((d) => <option key={d}>{d}</option>)}
            </select>
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-xs" style={{ color: T.slate }}>Time</span>
            <select value={draft.range} onChange={(e) => apply({ range: e.target.value })} className="px-2 py-1.5 rounded-md text-sm outline-none" style={input}>
              {RANGES.map((r) => <option key={r.label}>{r.label}</option>)}
            </select>
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
      </Card>

      <ErrorNote>{error}</ErrorNote>

      <Card T={T} className="overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr style={{ borderBottom: `1px solid ${T.border}` }}>
                {["Time", "Device", "Type", "Attacker IP", "User", "Action", "Message"].map((h) => (
                  <th key={h} className="text-left font-medium px-3 py-2 whitespace-nowrap" style={{ color: T.slate, fontSize: 12 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {logs.map((l) => {
                const open = expanded === l.id;
                return [
                  <tr key={l.id} onClick={() => setExpanded(open ? null : l.id)} className="cursor-pointer" style={{ borderBottom: `1px solid ${T.border}` }}>
                    <td className="px-3 py-2 whitespace-nowrap text-xs" style={{ color: T.slate, fontFamily: FONT_MONO }}>{dateTimeLabel(l.createdAt)}</td>
                    <td className="px-3 py-2 whitespace-nowrap text-xs" style={{ color: T.slate, fontFamily: FONT_MONO }}>{l.sourceIp}</td>
                    <td className="px-3 py-2 whitespace-nowrap text-xs" style={{ color: T.ink }}>{l.decoder || "—"}</td>
                    <td className="px-3 py-2 whitespace-nowrap">
                      {l.srcIp ? (
                        <button onClick={(e) => (e.stopPropagation(), apply({ srcIp: l.srcIp }))} className="text-xs" style={{ color: T.blueBright, fontFamily: FONT_MONO }}>{l.srcIp}</button>
                      ) : (
                        <span style={{ color: T.slate }}>{"—"}</span>
                      )}
                    </td>
                    <td className="px-3 py-2 text-xs" style={{ color: T.ink }}>{l.user || "—"}</td>
                    <td className="px-3 py-2 text-xs whitespace-nowrap" style={{ color: T.ink }}>{l.action || "—"}</td>
                    <td className="px-3 py-2 text-xs max-w-[520px] truncate" style={{ color: T.ink, fontFamily: FONT_MONO }}>{l.message}</td>
                  </tr>,
                  open && (
                    <tr key={`${l.id}-detail`} style={{ borderBottom: `1px solid ${T.border}`, backgroundColor: T.bg }}>
                      <td colSpan={7} className="px-3 py-3">
                        <pre className="text-xs whitespace-pre-wrap break-all mb-2" style={{ color: T.ink, fontFamily: FONT_MONO }}>{l.message}</pre>
                        <div className="text-xs mb-1" style={{ color: T.slate }}>
                          Program: {l.program || "—"} {"·"} Host: {l.host || "—"} {"·"} Matched rules: {l.ruleIds.length ? l.ruleIds.map((id) => `#${id}`).join(", ") : "none"}
                        </div>
                        {Object.keys(l.fields).length > 0 && (
                          <pre className="text-xs whitespace-pre-wrap break-all" style={{ color: T.ink, fontFamily: FONT_MONO }}>{JSON.stringify(l.fields, null, 2)}</pre>
                        )}
                      </td>
                    </tr>
                  ),
                ];
              })}
              {!loading && logs.length === 0 && (
                <tr>
                  <td colSpan={7} className="text-center text-xs py-10" style={{ color: T.slate }}>
                    {active ? "No log lines match these filters." : "No logs yet."}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        {(cursor || loading) && (
          <div className="flex justify-center p-3" style={{ borderTop: `1px solid ${T.border}` }}>
            <button onClick={() => load(cursor)} disabled={loading} className="text-xs font-medium px-3 py-1.5 rounded-md" style={{ border: `1px solid ${T.border}`, color: T.ink, opacity: loading ? 0.6 : 1 }}>
              {loading ? "Loading…" : "Load older events"}
            </button>
          </div>
        )}
      </Card>
    </div>
  );
}
