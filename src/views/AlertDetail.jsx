import { useEffect, useState } from "react";
import { X, ExternalLink, Filter } from "lucide-react";
import { FONT_MONO, SeverityBadge, StatusSelect, MitreTags, ErrorNote, dateTimeLabel } from "../shared.jsx";

function mitreUrl(id) {
  return `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`;
}

function Row({ label, children, T }) {
  return (
    <div className="flex flex-col sm:flex-row sm:items-start gap-0.5 sm:gap-3 py-2" style={{ borderTop: `1px solid ${T.border}` }}>
      <span className="text-xs sm:w-32 shrink-0" style={{ color: T.slate }}>{label}</span>
      <div className="text-sm min-w-0 break-words" style={{ color: T.ink }}>{children}</div>
    </div>
  );
}

// Slide-over panel with everything known about one alert: the rule that
// fired, MITRE ATT&CK techniques, extracted fields, the raw log line and
// other alerts involving the same attacker.
export default function AlertDetail({ T, alertId, authed, onClose, onStatusChange, onFilter }) {
  const [currentId, setCurrentId] = useState(alertId);
  const [data, setData] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => setCurrentId(alertId), [alertId]);

  useEffect(() => {
    let cancelled = false;
    setData(null);
    setError("");
    authed(`/api/alerts/${currentId}`)
      .then((d) => !cancelled && setData(d))
      .catch((err) => !cancelled && setError(err.message));
    return () => {
      cancelled = true;
    };
  }, [currentId, authed]);

  useEffect(() => {
    const onKey = (e) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  async function changeStatus(status) {
    setData((d) => ({ ...d, alert: { ...d.alert, status } }));
    await onStatusChange(currentId, status);
  }

  const a = data?.alert;
  const rule = data?.rule;
  const fields = a ? Object.entries(a.fields || {}).filter(([k]) => !["urlDecoded"].includes(k)) : [];

  return (
    <div className="fixed inset-0 z-50 flex justify-end" style={{ backgroundColor: "rgba(7,27,63,0.45)" }} onClick={onClose}>
      <div className="h-full w-full sm:w-[560px] overflow-y-auto p-5 sm:p-6 flex flex-col gap-4" style={{ backgroundColor: T.panel }} onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="text-xs mb-1" style={{ color: T.slate }}>Alert #{currentId}</div>
            <div className="text-base font-semibold" style={{ color: T.ink }}>{a ? a.title : "Loading…"}</div>
          </div>
          <button onClick={onClose} className="shrink-0 p-1 rounded-md" style={{ color: T.slate }} aria-label="Close">
            <X size={18} />
          </button>
        </div>

        <ErrorNote>{error}</ErrorNote>

        {a && (
          <>
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={a.severity} />
              <span className="text-xs px-2 py-0.5 rounded" style={{ border: `1px solid ${T.border}`, color: T.slate }}>Level {a.level}</span>
              <StatusSelect status={a.status} onChange={changeStatus} />
              {a.firedTimes > 1 && <span className="text-xs" style={{ color: T.slate }}>{a.firedTimes} matching events</span>}
            </div>

            <div>
              <Row label="Time" T={T}>{dateTimeLabel(a.createdAt)}</Row>
              <Row label="Attacker IP" T={T}>
                {a.srcIp ? (
                  <span className="flex items-center gap-2 flex-wrap">
                    <span style={{ fontFamily: FONT_MONO }}>{a.srcIp}</span>
                    <button onClick={() => onFilter({ srcIp: a.srcIp })} className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-md" style={{ border: `1px solid ${T.border}`, color: T.blueBright }}>
                      <Filter size={11} /> All alerts from this IP
                    </button>
                  </span>
                ) : (
                  "—"
                )}
              </Row>
              <Row label="User" T={T}>{a.user || "—"}</Row>
              <Row label="Device" T={T}><span style={{ fontFamily: FONT_MONO }}>{a.sourceIp}</span></Row>
              <Row label="Rule" T={T}>
                {rule ? (
                  <div>
                    <div>#{rule.id} {"·"} {rule.description}</div>
                    {rule.kind !== "atomic" && (
                      <div className="text-xs mt-0.5" style={{ color: T.slate }}>
                        {rule.kind === "frequency"
                          ? `Correlation: ${rule.frequency}${rule.distinct ? ` different ${rule.distinct} values` : " events"} within ${rule.timeframe}s, grouped by ${(rule.same || []).join(", ") || "device"}`
                          : `Sequence: follows repeated related events within ${rule.timeframe}s`}
                      </div>
                    )}
                    <div className="text-xs mt-0.5" style={{ color: T.slate }}>Groups: {rule.groups.join(", ")}</div>
                  </div>
                ) : (
                  a.ruleId ? `#${a.ruleId}` : "Legacy alert"
                )}
              </Row>
              <Row label="MITRE ATT&CK" T={T}>
                {a.mitre.length === 0
                  ? "—"
                  : a.mitre.map((t) => (
                      <div key={t.id} className="flex items-center gap-2 flex-wrap mb-1">
                        <MitreTags techniques={[t]} T={T} onSelect={(id) => onFilter({ mitre: id })} />
                        <span>{t.name}</span>
                        <span className="text-xs" style={{ color: T.slate }}>{t.tactic}</span>
                        <a href={mitreUrl(t.id)} target="_blank" rel="noopener noreferrer" style={{ color: T.blueBright }} aria-label={`Open ${t.id} on attack.mitre.org`}>
                          <ExternalLink size={12} />
                        </a>
                      </div>
                    ))}
              </Row>
            </div>

            {fields.length > 0 && (
              <div>
                <div className="text-sm font-semibold mb-1" style={{ color: T.ink }}>Extracted fields</div>
                <div className="rounded-md overflow-hidden" style={{ border: `1px solid ${T.border}` }}>
                  {fields.map(([k, v]) => (
                    <div key={k} className="flex gap-3 px-3 py-1.5 text-xs" style={{ borderTop: `1px solid ${T.border}` }}>
                      <span className="w-28 shrink-0" style={{ color: T.slate, fontFamily: FONT_MONO }}>{k}</span>
                      <span className="min-w-0 break-all" style={{ color: T.ink, fontFamily: FONT_MONO }}>{String(v)}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div>
              <div className="text-sm font-semibold mb-1" style={{ color: T.ink }}>Raw log</div>
              <pre className="text-xs p-3 rounded-md overflow-x-auto whitespace-pre-wrap break-all" style={{ backgroundColor: T.bg, color: T.ink, fontFamily: FONT_MONO, border: `1px solid ${T.border}` }}>
                {data.log?.message || a.message || "—"}
              </pre>
            </div>

            <div>
              <div className="text-sm font-semibold mb-1" style={{ color: T.ink }}>
                Related alerts <span className="text-xs font-normal" style={{ color: T.slate }}>same {a.srcIp ? "attacker IP" : "device"}, {"±"}24h</span>
              </div>
              {data.related.length === 0 ? (
                <div className="text-xs" style={{ color: T.slate }}>None</div>
              ) : (
                <div className="flex flex-col">
                  {data.related.map((r) => (
                    <button key={r.id} onClick={() => setCurrentId(r.id)} className="flex items-center justify-between gap-3 py-2 text-left" style={{ borderTop: `1px solid ${T.border}` }}>
                      <span className="flex items-center gap-2 min-w-0">
                        <SeverityBadge severity={r.severity} />
                        <span className="text-sm truncate" style={{ color: T.ink }}>{r.title}</span>
                      </span>
                      <span className="text-xs shrink-0" style={{ color: T.slate }}>{dateTimeLabel(r.createdAt)}</span>
                    </button>
                  ))}
                </div>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  );
}
