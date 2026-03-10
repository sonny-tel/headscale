import { useState, useEffect, useCallback, useRef } from "react";
import { listAuditEvents, listConsoleLogs, type AuditEvent, type ConsoleLogEntry } from "../api";

// ─── Tab types ────────────────────────────────────────────────────────────────
type Tab = "audit" | "console";

// ─── Audit Log constants ─────────────────────────────────────────────────────
const EVENT_LABELS: Record<string, { label: string; color: string }> = {
  "user.created": { label: "User Created", color: "var(--color-success)" },
  "user.deleted": { label: "User Deleted", color: "var(--color-danger)" },
  "user.renamed": { label: "User Renamed", color: "var(--color-primary)" },
  "user.login": { label: "Login", color: "var(--color-primary)" },
  "node.approved": { label: "Node Approved", color: "var(--color-success)" },
  "node.deleted": { label: "Node Deleted", color: "var(--color-danger)" },
  "node.expired": { label: "Node Expired", color: "var(--color-warning)" },
  "node.renamed": { label: "Node Renamed", color: "var(--color-primary)" },
  "node.tags_changed": { label: "Tags Changed", color: "var(--color-primary)" },
  "policy.updated": { label: "Policy Updated", color: "var(--color-warning)" },
  "apikey.created": { label: "API Key Created", color: "var(--color-primary)" },
};

function getEventStyle(eventType: string) {
  return EVENT_LABELS[eventType] || { label: eventType, color: "var(--color-text-secondary)" };
}

function timeAgo(dateStr: string): string {
  const now = Date.now();
  const then = new Date(dateStr).getTime();
  const diff = now - then;
  const seconds = Math.floor(diff / 1000);
  if (seconds < 60) return "just now";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  return new Date(dateStr).toLocaleDateString();
}

const PAGE_SIZE = 50;

// ─── Audit Tab ────────────────────────────────────────────────────────────────
function AuditTab() {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [filter, setFilter] = useState("");
  const [offset, setOffset] = useState(0);

  const fetchEvents = useCallback(async () => {
    try {
      setLoading(true);
      const resp = await listAuditEvents({
        event_type: filter || undefined,
        limit: PAGE_SIZE,
        offset,
      });
      setEvents(resp.events ?? []);
      setTotal(resp.total ?? 0);
      setError("");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, [filter, offset]);

  useEffect(() => { fetchEvents(); }, [fetchEvents]);

  const eventTypes = Object.keys(EVENT_LABELS);
  const totalPages = Math.ceil(total / PAGE_SIZE);
  const currentPage = Math.floor(offset / PAGE_SIZE) + 1;

  return (
    <div>
      <div className="flex items-center justify-between" style={{ marginBottom: "0.75rem" }}>
        <p className="text-sm" style={{ color: "var(--color-text-secondary)" }}>
          {total} event{total !== 1 ? "s" : ""}
        </p>
        <div className="flex gap-2">
          <select
            value={filter}
            onChange={(e) => { setFilter(e.target.value); setOffset(0); }}
            style={{
              padding: "0.375rem 0.625rem",
              background: "var(--color-surface)",
              border: "1px solid var(--color-border)",
              borderRadius: "var(--radius)",
              color: "var(--color-text)",
              fontSize: "0.8125rem",
            }}
          >
            <option value="">All events</option>
            {eventTypes.map((t) => (
              <option key={t} value={t}>{EVENT_LABELS[t].label}</option>
            ))}
          </select>
          <button className="btn outline sm" onClick={fetchEvents}>Refresh</button>
        </div>
      </div>

      {error && (
        <div style={{
          padding: "0.5rem 0.75rem",
          marginBottom: "0.75rem",
          borderRadius: "var(--radius)",
          fontSize: "0.8125rem",
          background: "var(--color-danger-subtle)",
          color: "var(--color-danger)",
          border: "1px solid var(--color-danger)",
        }}>{error}</div>
      )}

      {loading && events.length === 0 ? (
        <div style={{ padding: "3rem", display: "flex", justifyContent: "center" }}>
          <span className="spinner" />
        </div>
      ) : events.length === 0 ? (
        <div style={{ padding: "3rem", textAlign: "center", color: "var(--color-text-tertiary)", fontSize: "0.875rem" }}>
          No events recorded yet. Actions like creating users, approving machines, and changing policies will appear here.
        </div>
      ) : (
        <>
          <div style={{ display: "flex", flexDirection: "column", gap: "1px" }}>
            {events.map((event) => {
              const style = getEventStyle(event.event_type);
              return (
                <div key={event.id} style={{
                  display: "flex", alignItems: "center", gap: "0.75rem",
                  padding: "0.625rem 0.75rem",
                  background: "var(--color-surface)", borderRadius: "var(--radius)",
                  fontSize: "0.8125rem",
                }}>
                  <span style={{
                    flexShrink: 0, padding: "0.125rem 0.5rem", borderRadius: "9999px",
                    fontSize: "0.6875rem", fontWeight: 500,
                    background: `color-mix(in srgb, ${style.color} 15%, transparent)`,
                    color: style.color, minWidth: 90, textAlign: "center",
                  }}>{style.label}</span>
                  <span style={{ flex: 1, minWidth: 0 }}>
                    {event.target_name && <span style={{ fontWeight: 500 }}>{event.target_name}</span>}
                    {event.details && <span style={{ color: "var(--color-text-secondary)", marginLeft: event.target_name ? "0.5rem" : 0 }}>{event.details}</span>}
                    {!event.target_name && !event.details && <span style={{ color: "var(--color-text-tertiary)" }}>&mdash;</span>}
                  </span>
                  {event.actor && event.actor !== "api" && (
                    <span className="text-sm" style={{ color: "var(--color-text-secondary)", flexShrink: 0 }}>by {event.actor}</span>
                  )}
                  <span className="text-sm" title={new Date(event.timestamp).toLocaleString()} style={{
                    color: "var(--color-text-tertiary)", flexShrink: 0, minWidth: 60, textAlign: "right",
                  }}>{timeAgo(event.timestamp)}</span>
                </div>
              );
            })}
          </div>
          {totalPages > 1 && (
            <div className="flex items-center justify-between" style={{ marginTop: "0.75rem" }}>
              <span className="text-sm" style={{ color: "var(--color-text-secondary)" }}>Page {currentPage} of {totalPages}</span>
              <div className="flex gap-2">
                <button className="btn outline sm" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}>Previous</button>
                <button className="btn outline sm" disabled={currentPage >= totalPages} onClick={() => setOffset(offset + PAGE_SIZE)}>Next</button>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

// ─── Console Tab ──────────────────────────────────────────────────────────────
function ConsoleTab() {
  const [entries, setEntries] = useState<ConsoleLogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [autoScroll, setAutoScroll] = useState(true);
  const [paused, setPaused] = useState(false);
  const [levelFilter, setLevelFilter] = useState<string>("all");
  const scrollRef = useRef<HTMLDivElement>(null);
  const intervalRef = useRef<ReturnType<typeof setInterval>>(undefined);

  const fetchLogs = useCallback(async () => {
    try {
      const resp = await listConsoleLogs(500);
      setEntries(resp.entries ?? []);
    } catch {
      // Silently ignore polling errors
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchLogs();
    if (!paused) {
      intervalRef.current = setInterval(fetchLogs, 3000);
    }
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [fetchLogs, paused]);

  useEffect(() => {
    if (autoScroll && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [entries, autoScroll]);

  function stripAnsi(str: string): string {
    return str.replace(/\x1b\[[0-9;]*m/g, "").replace(/\r?\n$/, "");
  }

  function getLogLevel(msg: string): string {
    const cleaned = stripAnsi(msg);
    if (cleaned.includes(" ERR ") || cleaned.includes(" FTL ") || cleaned.includes(" PNC ")) return "error";
    if (cleaned.includes(" WRN ")) return "warn";
    if (cleaned.includes(" DBG ") || cleaned.includes(" TRC ")) return "debug";
    return "info";
  }

  const levelColors: Record<string, string> = {
    error: "var(--color-log-error)",
    warn: "var(--color-log-warn)",
    debug: "var(--color-log-debug)",
    info: "var(--color-log-info)",
  };

  const filteredEntries = levelFilter === "all"
    ? entries
    : entries.filter((e) => getLogLevel(e.message) === levelFilter);

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "calc(100vh - 200px)" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "0.5rem", gap: "0.75rem" }}>
        <p className="text-sm" style={{ color: "var(--color-text-secondary)", whiteSpace: "nowrap", margin: 0 }}>
          Live headscale process output{" "}
          {!paused && <span style={{ color: "var(--color-success)" }}>&bull; streaming</span>}
        </p>
        <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", flexShrink: 0 }}>
          <div style={{ display: "inline-flex", borderRadius: "var(--radius)", border: "1px solid var(--color-border)", overflow: "hidden" }}>
            {[
              { value: "all", label: "All" },
              { value: "error", label: "ERR" },
              { value: "warn", label: "WRN" },
              { value: "info", label: "INF" },
              { value: "debug", label: "DBG" },
            ].map((o) => (
              <button
                key={o.value}
                onClick={() => setLevelFilter(o.value)}
                style={{
                  background: levelFilter === o.value ? "var(--color-surface-2)" : "transparent",
                  color: levelFilter === o.value ? "var(--color-text-primary)" : "var(--color-text-secondary)",
                  border: "none",
                  padding: "0.2rem 0.5rem",
                  fontSize: "0.6875rem",
                  cursor: "pointer",
                  fontFamily: "inherit",
                  borderRight: "1px solid var(--color-border)",
                }}
              >
                {o.label}
              </button>
            ))}
          </div>
          <label style={{ display: "flex", alignItems: "center", gap: "0.375rem", color: "var(--color-text-secondary)", cursor: "pointer", fontSize: "0.75rem", whiteSpace: "nowrap" }}>
            <input type="checkbox" checked={autoScroll} onChange={(e) => setAutoScroll(e.target.checked)} style={{ margin: 0, width: "13px", height: "13px", accentColor: "var(--color-primary)" }} />
            Auto-scroll
          </label>
          <button className="btn outline sm" style={{ padding: "0.2rem 0.5rem", fontSize: "0.6875rem", lineHeight: 1.3, whiteSpace: "nowrap" }} onClick={() => setPaused(p => !p)}>
            {paused ? "Resume" : "Pause"}
          </button>
        </div>
      </div>

      {loading ? (
        <div style={{ flex: 1, display: "flex", justifyContent: "center", alignItems: "center" }}>
          <span className="spinner" />
        </div>
      ) : (
        <div
          ref={scrollRef}
          style={{
            flex: 1, overflow: "auto",
            background: "var(--color-console-bg)", borderRadius: "var(--radius)",
            border: "1px solid var(--color-border)",
            fontFamily: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace",
            fontSize: "0.75rem", lineHeight: 1.6,
            padding: "0.5rem",
          }}
        >
          {filteredEntries.length === 0 ? (
            <div style={{ color: "var(--color-console-empty)", padding: "2rem", textAlign: "center" }}>
              {entries.length === 0 ? "No log output captured yet." : "No entries match the selected level."}
            </div>
          ) : filteredEntries.map((entry, i) => {
            const level = getLogLevel(entry.message);
            return (
              <div key={i} style={{ color: levelColors[level], whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
                {stripAnsi(entry.message)}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ─── Tab definitions ──────────────────────────────────────────────────────────
const TABS: { key: Tab; label: string; icon: React.ReactNode }[] = [
  {
    key: "audit",
    label: "Audit Log",
    icon: (
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      </svg>
    ),
  },
  {
    key: "console",
    label: "Console",
    icon: (
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <polyline points="4 17 10 11 4 5" />
        <line x1="12" y1="19" x2="20" y2="19" />
      </svg>
    ),
  },
];

// ─── Main Page ────────────────────────────────────────────────────────────────
export function LogsPage() {
  const initialTab = (TABS.find(t => t.key === window.location.hash.replace(/^#/, ""))?.key ?? "audit") as Tab;
  const [tab, setTab] = useState<Tab>(initialTab);

  const switchTab = (key: Tab) => {
    setTab(key);
    window.history.replaceState(null, "", `#${key}`);
  };

  return (
    <div>
      <div style={{ marginBottom: "1rem" }}>
        <h2 style={{ fontSize: "1.125rem", fontWeight: 600, marginBottom: "0.75rem" }}>Logs</h2>
        <div className="flex gap-2" style={{
          borderBottom: "1px solid var(--color-border)",
          paddingBottom: 0,
        }}>
          {TABS.map((t) => (
            <button
              key={t.key}
              onClick={() => switchTab(t.key)}
              className="flex items-center"
              style={{
                gap: "0.375rem",
                padding: "0.5rem 0.875rem",
                fontSize: "0.8125rem",
                fontWeight: 500,
                color: tab === t.key ? "var(--color-primary)" : "var(--color-text-secondary)",
                background: "none",
                border: "none",
                borderBottom: tab === t.key ? "2px solid var(--color-primary)" : "2px solid transparent",
                cursor: "pointer",
                marginBottom: "-1px",
                transition: "color 0.15s, border-color 0.15s",
              }}
            >
              {t.icon}
              {t.label}
            </button>
          ))}
        </div>
      </div>

      {tab === "audit" && <AuditTab />}
      {tab === "console" && <ConsoleTab />}
    </div>
  );
}
