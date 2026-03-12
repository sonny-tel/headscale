import { useState, useEffect, useCallback } from "react";
import {
  getDebugOverview,
  getDebugNodeStore,
  getDebugRoutes,
  getDebugDERP,
  getDebugConfig,
  getDebugPolicy,
  getDebugFilter,
  seedDebugData,
  purgeDebugData,
  purgeSeededData,
} from "../api";

// ─── Tab types ────────────────────────────────────────────────────────────────
type Tab = "overview" | "nodestore" | "routes" | "derp" | "config" | "policy" | "filter" | "seed";

const TABS: { key: Tab; label: string; icon: React.ReactNode }[] = [
  {
    key: "overview",
    label: "Overview",
    icon: (
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="12" cy="12" r="10" />
        <line x1="12" y1="16" x2="12" y2="12" />
        <line x1="12" y1="8" x2="12.01" y2="8" />
      </svg>
    ),
  },
  {
    key: "nodestore",
    label: "Peer Map",
    icon: (
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <rect x="2" y="2" width="20" height="8" rx="2" ry="2" />
        <rect x="2" y="14" width="20" height="8" rx="2" ry="2" />
        <line x1="6" y1="6" x2="6.01" y2="6" />
        <line x1="6" y1="18" x2="6.01" y2="18" />
      </svg>
    ),
  },
  {
    key: "routes",
    label: "Routes",
    icon: (
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="12" cy="12" r="2" />
        <path d="M16.24 7.76a6 6 0 0 1 0 8.49m-8.48-.01a6 6 0 0 1 0-8.49m11.31-2.82a10 10 0 0 1 0 14.14m-14.14 0a10 10 0 0 1 0-14.14" />
      </svg>
    ),
  },
  {
    key: "derp",
    label: "DERP",
    icon: (
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <polygon points="12 2 2 7 12 12 22 7 12 2" />
        <polyline points="2 17 12 22 22 17" />
        <polyline points="2 12 12 17 22 12" />
      </svg>
    ),
  },
  {
    key: "config",
    label: "Config",
    icon: (
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="12" cy="12" r="3" />
        <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" />
      </svg>
    ),
  },
  {
    key: "policy",
    label: "Policy",
    icon: (
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
        <polyline points="14 2 14 8 20 8" />
        <line x1="16" y1="13" x2="8" y2="13" />
        <line x1="16" y1="17" x2="8" y2="17" />
        <polyline points="10 9 9 9 8 9" />
      </svg>
    ),
  },
  {
    key: "filter",
    label: "Filter",
    icon: (
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3" />
      </svg>
    ),
  },
  {
    key: "seed",
    label: "Seed Data",
    icon: (
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" />
        <polyline points="3.27 6.96 12 12.01 20.73 6.96" />
        <line x1="12" y1="22.08" x2="12" y2="12" />
      </svg>
    ),
  },
];

// ─── JSON Viewer ──────────────────────────────────────────────────────────────
function JsonViewer({ data, loading, error, onRefresh }: {
  data: unknown;
  loading: boolean;
  error: string;
  onRefresh: () => void;
}) {
  const [collapsed, setCollapsed] = useState(false);
  const [search, setSearch] = useState("");
  const formatted = JSON.stringify(data, null, 2);
  const lines = formatted.split("\n");
  const filtered = search
    ? lines.filter((l) => l.toLowerCase().includes(search.toLowerCase()))
    : lines;

  return (
    <div>
      <div className="flex items-center gap-2" style={{ marginBottom: "0.75rem" }}>
        <button
          onClick={onRefresh}
          disabled={loading}
          style={{
            padding: "0.375rem 0.75rem",
            fontSize: "0.75rem",
            fontWeight: 500,
            background: "var(--color-bg-subtle)",
            color: "var(--color-text-secondary)",
            border: "1px solid var(--color-border)",
            borderRadius: "0.375rem",
            cursor: loading ? "not-allowed" : "pointer",
          }}
        >
          {loading ? "Loading..." : "Refresh"}
        </button>
        <input
          type="text"
          placeholder="Search JSON..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{
            padding: "0.375rem 0.625rem",
            fontSize: "0.75rem",
            background: "var(--color-bg-input)",
            color: "var(--color-text)",
            border: "1px solid var(--color-border)",
            borderRadius: "0.375rem",
            flex: 1,
            maxWidth: "20rem",
          }}
        />
        <button
          onClick={() => setCollapsed(!collapsed)}
          style={{
            padding: "0.375rem 0.75rem",
            fontSize: "0.75rem",
            fontWeight: 500,
            background: "none",
            color: "var(--color-text-secondary)",
            border: "1px solid var(--color-border)",
            borderRadius: "0.375rem",
            cursor: "pointer",
          }}
        >
          {collapsed ? "Expand" : "Collapse"}
        </button>
        <span style={{ fontSize: "0.6875rem", color: "var(--color-text-secondary)" }}>
          {lines.length} lines
        </span>
      </div>
      {error && (
        <div style={{
          padding: "0.75rem",
          marginBottom: "0.75rem",
          background: "var(--color-danger-bg, rgba(220,38,38,0.1))",
          color: "var(--color-danger)",
          borderRadius: "0.375rem",
          fontSize: "0.8125rem",
        }}>
          {error}
        </div>
      )}
      {collapsed ? (
        <pre style={{
          padding: "1rem",
          background: "var(--color-bg-subtle)",
          border: "1px solid var(--color-border)",
          borderRadius: "0.5rem",
          overflow: "auto",
          maxHeight: "70vh",
          fontSize: "0.75rem",
          lineHeight: 1.5,
          color: "var(--color-text)",
          margin: 0,
        }}>
          {JSON.stringify(data)}
        </pre>
      ) : (
        <pre style={{
          padding: "1rem",
          background: "var(--color-bg-subtle)",
          border: "1px solid var(--color-border)",
          borderRadius: "0.5rem",
          overflow: "auto",
          maxHeight: "70vh",
          fontSize: "0.75rem",
          lineHeight: 1.5,
          color: "var(--color-text)",
          margin: 0,
        }}>
          {filtered.join("\n")}
        </pre>
      )}
    </div>
  );
}

// ─── Text Viewer (for policy HuJSON) ──────────────────────────────────────────
function TextViewer({ data, loading, error, onRefresh }: {
  data: string;
  loading: boolean;
  error: string;
  onRefresh: () => void;
}) {
  return (
    <div>
      <div className="flex items-center gap-2" style={{ marginBottom: "0.75rem" }}>
        <button
          onClick={onRefresh}
          disabled={loading}
          style={{
            padding: "0.375rem 0.75rem",
            fontSize: "0.75rem",
            fontWeight: 500,
            background: "var(--color-bg-subtle)",
            color: "var(--color-text-secondary)",
            border: "1px solid var(--color-border)",
            borderRadius: "0.375rem",
            cursor: loading ? "not-allowed" : "pointer",
          }}
        >
          {loading ? "Loading..." : "Refresh"}
        </button>
      </div>
      {error && (
        <div style={{
          padding: "0.75rem",
          marginBottom: "0.75rem",
          background: "var(--color-danger-bg, rgba(220,38,38,0.1))",
          color: "var(--color-danger)",
          borderRadius: "0.375rem",
          fontSize: "0.8125rem",
        }}>
          {error}
        </div>
      )}
      <pre style={{
        padding: "1rem",
        background: "var(--color-bg-subtle)",
        border: "1px solid var(--color-border)",
        borderRadius: "0.5rem",
        overflow: "auto",
        maxHeight: "70vh",
        fontSize: "0.75rem",
        lineHeight: 1.5,
        color: "var(--color-text)",
        margin: 0,
        whiteSpace: "pre-wrap",
      }}>
        {data || "(empty)"}
      </pre>
    </div>
  );
}

// ─── Overview Tab ─────────────────────────────────────────────────────────────
function OverviewTab() {
  const [data, setData] = useState<Record<string, unknown> | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const fetch_ = useCallback(async () => {
    try {
      setLoading(true);
      setData(await getDebugOverview());
      setError("");
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetch_(); }, [fetch_]);

  if (!data && loading) return <p style={{ color: "var(--color-text-secondary)", fontSize: "0.8125rem" }}>Loading...</p>;
  return <JsonViewer data={data} loading={loading} error={error} onRefresh={fetch_} />;
}

// ─── Generic JSON endpoint tab ────────────────────────────────────────────────
function JsonEndpointTab({ fetcher }: { fetcher: () => Promise<unknown> }) {
  const [data, setData] = useState<unknown>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const fetch_ = useCallback(async () => {
    try {
      setLoading(true);
      setData(await fetcher());
      setError("");
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [fetcher]);

  useEffect(() => { fetch_(); }, [fetch_]);

  if (!data && loading) return <p style={{ color: "var(--color-text-secondary)", fontSize: "0.8125rem" }}>Loading...</p>;
  return <JsonViewer data={data} loading={loading} error={error} onRefresh={fetch_} />;
}

// ─── Policy Tab (text) ────────────────────────────────────────────────────────
function PolicyTab() {
  const [data, setData] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const fetch_ = useCallback(async () => {
    try {
      setLoading(true);
      setData(await getDebugPolicy());
      setError("");
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetch_(); }, [fetch_]);

  if (!data && loading) return <p style={{ color: "var(--color-text-secondary)", fontSize: "0.8125rem" }}>Loading...</p>;
  return <TextViewer data={data} loading={loading} error={error} onRefresh={fetch_} />;
}

// ─── Styled Number Stepper ────────────────────────────────────────────────────
function NumberStepper({ value, onChange, min, max, label }: {
  value: number;
  onChange: (v: number) => void;
  min: number;
  max: number;
  label: string;
}) {
  const clamp = (v: number) => Math.max(min, Math.min(max, v));
  const btnStyle: React.CSSProperties = {
    width: "1.75rem",
    height: "1.75rem",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontSize: "0.875rem",
    fontWeight: 600,
    background: "var(--color-bg-subtle)",
    color: "var(--color-text-secondary)",
    border: "1px solid var(--color-border)",
    cursor: "pointer",
    lineHeight: 1,
    padding: 0,
  };
  return (
    <label style={{ fontSize: "0.8125rem", color: "var(--color-text-secondary)", display: "flex", alignItems: "center", gap: "0.5rem" }}>
      {label}
      <span style={{ display: "inline-flex", borderRadius: "0.375rem", overflow: "hidden", border: "1px solid var(--color-border)" }}>
        <button type="button" onClick={() => onChange(clamp(value - 1))} disabled={value <= min} style={{ ...btnStyle, borderRight: "none", borderTopLeftRadius: "0.375rem", borderBottomLeftRadius: "0.375rem", opacity: value <= min ? 0.4 : 1 }}>−</button>
        <input
          type="text"
          inputMode="numeric"
          value={value}
          onChange={(e) => { const n = parseInt(e.target.value, 10); if (!isNaN(n)) onChange(clamp(n)); }}
          style={{
            width: "2.75rem",
            textAlign: "center",
            padding: "0.25rem 0",
            fontSize: "0.8125rem",
            fontWeight: 500,
            background: "var(--color-bg-input)",
            color: "var(--color-text)",
            border: "none",
            borderTop: "1px solid var(--color-border)",
            borderBottom: "1px solid var(--color-border)",
            outline: "none",
          }}
        />
        <button type="button" onClick={() => onChange(clamp(value + 1))} disabled={value >= max} style={{ ...btnStyle, borderLeft: "none", borderTopRightRadius: "0.375rem", borderBottomRightRadius: "0.375rem", opacity: value >= max ? 0.4 : 1 }}>+</button>
      </span>
    </label>
  );
}

// ─── Seed Data Tab ────────────────────────────────────────────────────────────
function SeedTab() {
  const [userCount, setUserCount] = useState(3);
  const [nodeCount, setNodeCount] = useState(5);
  const [deviceExitCount, setDeviceExitCount] = useState(2);
  const [vpnExitCount, setVpnExitCount] = useState(3);
  const [seedLoading, setSeedLoading] = useState(false);
  const [purgeLoading, setPurgeLoading] = useState(false);
  const [purgeSeededLoading, setPurgeSeededLoading] = useState(false);
  const [result, setResult] = useState<string | null>(null);
  const [error, setError] = useState("");

  const handleSeed = async () => {
    try {
      setSeedLoading(true);
      setError("");
      const res = await seedDebugData(userCount, nodeCount, deviceExitCount, vpnExitCount);
      const parts = [`${res.users.length} users`, `${res.nodes.length} nodes`];
      if (res.deviceExitNodes?.length) parts.push(`${res.deviceExitNodes.length} device exit nodes`);
      if (res.vpnExitNodes?.length) parts.push(`${res.vpnExitNodes.length} VPN exit nodes`);
      setResult(`Created ${parts.join(", ")}`);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSeedLoading(false);
    }
  };

  const handlePurgeSeeded = async () => {
    if (!confirm("This will remove only debug-seeded nodes and users. Continue?")) return;
    try {
      setPurgeSeededLoading(true);
      setError("");
      const res = await purgeSeededData();
      setResult(`Cleared ${res.nodes} seeded nodes and ${res.users} seeded users`);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setPurgeSeededLoading(false);
    }
  };

  const handlePurge = async () => {
    if (!confirm("This will delete ALL nodes and users (including real data). Are you sure?")) return;
    try {
      setPurgeLoading(true);
      setError("");
      const res = await purgeDebugData();
      setResult(`Purged ${res.nodes} nodes and ${res.users} users`);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setPurgeLoading(false);
    }
  };

  const busy = seedLoading || purgeLoading || purgeSeededLoading;

  return (
    <div>
      <p style={{ color: "var(--color-text-secondary)", fontSize: "0.8125rem", marginBottom: "1rem" }}>
        Generate fake users, nodes, and exit nodes for testing. Device exits are regular devices sharing their connection; VPN exits are location-based relay servers. Seeded data is tracked and can be selectively removed.
      </p>

      <div className="flex items-center gap-3" style={{ marginBottom: "1rem", flexWrap: "wrap" }}>
        <NumberStepper label="Users" value={userCount} onChange={setUserCount} min={1} max={20} />
        <NumberStepper label="Nodes" value={nodeCount} onChange={setNodeCount} min={1} max={50} />
        <NumberStepper label="Device Exits" value={deviceExitCount} onChange={setDeviceExitCount} min={0} max={10} />
        <NumberStepper label="VPN Exits" value={vpnExitCount} onChange={setVpnExitCount} min={0} max={10} />
      </div>

      <div className="flex items-center gap-2" style={{ marginBottom: "1rem", flexWrap: "wrap" }}>
        <button
          onClick={handleSeed}
          disabled={busy}
          style={{
            padding: "0.5rem 1rem",
            fontSize: "0.8125rem",
            fontWeight: 500,
            background: "var(--color-primary)",
            color: "#fff",
            border: "none",
            borderRadius: "0.375rem",
            cursor: busy ? "not-allowed" : "pointer",
            opacity: busy ? 0.6 : 1,
          }}
        >
          {seedLoading ? "Seeding..." : "Seed Data"}
        </button>
        <button
          onClick={handlePurgeSeeded}
          disabled={busy}
          style={{
            padding: "0.5rem 1rem",
            fontSize: "0.8125rem",
            fontWeight: 500,
            background: "var(--color-warning, #f59e0b)",
            color: "#fff",
            border: "none",
            borderRadius: "0.375rem",
            cursor: busy ? "not-allowed" : "pointer",
            opacity: busy ? 0.6 : 1,
          }}
        >
          {purgeSeededLoading ? "Clearing..." : "Clear Seeded Data"}
        </button>
        <button
          onClick={handlePurge}
          disabled={busy}
          style={{
            padding: "0.5rem 1rem",
            fontSize: "0.8125rem",
            fontWeight: 500,
            background: "var(--color-danger, #dc2626)",
            color: "#fff",
            border: "none",
            borderRadius: "0.375rem",
            cursor: busy ? "not-allowed" : "pointer",
            opacity: busy ? 0.6 : 1,
          }}
        >
          {purgeLoading ? "Purging..." : "Purge All Data"}
        </button>
      </div>

      {error && (
        <div style={{
          padding: "0.75rem",
          marginBottom: "0.75rem",
          background: "var(--color-danger-bg, rgba(220,38,38,0.1))",
          color: "var(--color-danger)",
          borderRadius: "0.375rem",
          fontSize: "0.8125rem",
        }}>
          {error}
        </div>
      )}

      {result && (
        <div style={{
          padding: "0.75rem",
          background: "var(--color-success-bg, rgba(34,197,94,0.1))",
          color: "var(--color-success, #16a34a)",
          borderRadius: "0.375rem",
          fontSize: "0.8125rem",
        }}>
          {result}
        </div>
      )}
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────
export function DebugPage() {
  const initialTab = (TABS.find(t => t.key === window.location.hash.replace(/^#/, ""))?.key ?? "overview") as Tab;
  const [tab, setTab] = useState<Tab>(initialTab);

  const switchTab = (key: Tab) => {
    setTab(key);
    window.history.replaceState(null, "", `#${key}`);
  };

  return (
    <div>
      <div style={{ marginBottom: "1rem" }}>
        <h2 style={{ fontSize: "1.125rem", fontWeight: 600, marginBottom: "0.75rem" }}>Debug</h2>
        <div className="flex gap-2" style={{
          borderBottom: "1px solid var(--color-border)",
          paddingBottom: 0,
          overflowX: "auto",
          scrollbarWidth: "none",
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
                whiteSpace: "nowrap",
              }}
            >
              {t.icon}
              {t.label}
            </button>
          ))}
        </div>
      </div>

      {tab === "overview" && <OverviewTab />}
      {tab === "nodestore" && <JsonEndpointTab fetcher={getDebugNodeStore} />}
      {tab === "routes" && <JsonEndpointTab fetcher={getDebugRoutes} />}
      {tab === "derp" && <JsonEndpointTab fetcher={getDebugDERP} />}
      {tab === "config" && <JsonEndpointTab fetcher={getDebugConfig} />}
      {tab === "policy" && <PolicyTab />}
      {tab === "filter" && <JsonEndpointTab fetcher={getDebugFilter} />}
      {tab === "seed" && <SeedTab />}
    </div>
  );
}
