import { useState, useEffect, useCallback } from "react";
import { listNodes, type Node } from "../api";
import { useAuth } from "../auth";

function timeAgo(dateStr: string): string {
  if (!dateStr) return "never";
  const seconds = Math.floor(
    (Date.now() - new Date(dateStr).getTime()) / 1000,
  );
  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

function isExpired(node: Node): boolean {
  if (!node.expiry) return false;
  const exp = new Date(node.expiry);
  if (exp.getFullYear() < 2) return false;
  return exp < new Date();
}

function formatOS(os?: string): string {
  if (!os) return "";
  const map: Record<string, string> = {
    linux: "Linux",
    windows: "Windows",
    macOS: "macOS",
    iOS: "iOS",
    android: "Android",
    freebsd: "FreeBSD",
    openbsd: "OpenBSD",
  };
  return map[os] || os;
}

function osIcon(os?: string) {
  const color = "var(--color-text-tertiary)";
  switch (os) {
    case "linux":
      return (
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="10" /><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20" /><path d="M2 12h20" />
        </svg>
      );
    case "windows":
      return (
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
          <rect x="3" y="3" width="18" height="18" rx="2" /><line x1="3" y1="12" x2="21" y2="12" /><line x1="12" y1="3" x2="12" y2="21" />
        </svg>
      );
    case "iOS":
    case "macOS":
      return (
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
          <rect x="5" y="2" width="14" height="20" rx="3" /><line x1="12" y1="18" x2="12.01" y2="18" />
        </svg>
      );
    case "android":
      return (
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
          <rect x="5" y="2" width="14" height="20" rx="3" /><line x1="12" y1="18" x2="12.01" y2="18" />
        </svg>
      );
    default:
      return (
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
          <rect x="2" y="3" width="20" height="14" rx="2" ry="2" /><line x1="8" y1="21" x2="16" y2="21" /><line x1="12" y1="17" x2="12" y2="21" />
        </svg>
      );
  }
}

function DeviceCard({ node }: { node: Node }) {
  const expired = isExpired(node);
  const [copied, setCopied] = useState<string | null>(null);

  function copyIP(ip: string) {
    navigator.clipboard.writeText(ip);
    setCopied(ip);
    setTimeout(() => setCopied(null), 1500);
  }

  return (
    <div
      className="card"
      style={{
        padding: "1rem 1.25rem",
        display: "flex",
        flexDirection: "column",
        gap: "0.75rem",
      }}
    >
      {/* Top row: status + name + OS icon */}
      <div className="flex items-center gap-3">
        <span
          className={`status-dot ${node.online ? "online" : "offline"}`}
          style={{ flexShrink: 0 }}
        />
        <div style={{ flex: 1, minWidth: 0 }}>
          <div className="flex items-center gap-2">
            <span style={{ fontWeight: 600, fontSize: "0.9375rem" }}>
              {node.given_name || node.name}
            </span>
            {expired ? (
              <span className="badge expired" style={{ fontSize: "0.6875rem" }}>
                Expired
              </span>
            ) : (
              <span
                className={`badge ${node.online ? "online" : "offline"}`}
                style={{ fontSize: "0.6875rem" }}
              >
                {node.online ? "Connected" : "Disconnected"}
              </span>
            )}
          </div>
          {node.os && (
            <span
              className="text-xs"
              style={{ color: "var(--color-text-tertiary)" }}
            >
              {formatOS(node.os)}
              {node.os_version ? ` ${node.os_version}` : ""}
              {node.device_model ? ` · ${node.device_model}` : ""}
            </span>
          )}
        </div>
        {osIcon(node.os)}
      </div>

      {/* IP addresses */}
      <div style={{ display: "flex", flexWrap: "wrap", gap: "0.375rem" }}>
        {(node.ip_addresses || []).map((ip) => (
          <button
            key={ip}
            onClick={() => copyIP(ip)}
            title={copied === ip ? "Copied!" : "Click to copy"}
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 4,
              padding: "0.2rem 0.5rem",
              borderRadius: "var(--radius)",
              border: "1px solid var(--color-border)",
              background: "var(--color-bg)",
              color: "var(--color-primary)",
              fontSize: "0.8rem",
              fontFamily: "var(--font-mono, monospace)",
              cursor: "pointer",
            }}
          >
            {ip}
            {copied === ip && (
              <svg
                width="12"
                height="12"
                viewBox="0 0 24 24"
                fill="none"
                stroke="var(--color-success)"
                strokeWidth="2"
              >
                <polyline points="20 6 9 17 4 12" />
              </svg>
            )}
          </button>
        ))}
      </div>

      {/* Tags */}
      {(node.tags || []).length > 0 && (
        <div style={{ display: "flex", flexWrap: "wrap", gap: "0.25rem" }}>
          {(node.tags || []).map(
            (tag) => (
              <span key={tag} className="badge tag">
                {tag}
              </span>
            ),
          )}
        </div>
      )}

      {/* Bottom row: last seen + version */}
      <div
        className="flex items-center justify-between"
        style={{ borderTop: "1px solid var(--color-border)", paddingTop: "0.5rem" }}
      >
        <span className="text-xs" style={{ color: "var(--color-text-tertiary)" }}>
          Last seen {timeAgo(node.last_seen)}
        </span>
        {node.client_version && (
          <span className="text-xs" style={{ color: "var(--color-text-tertiary)" }}>
            v{node.client_version}
          </span>
        )}
      </div>
    </div>
  );
}

export function MyDevicesPage() {
  const { user } = useAuth();
  const [nodes, setNodes] = useState<Node[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const fetchData = useCallback(async () => {
    try {
      const all = await listNodes();
      // Filter to only show nodes owned by the current user
      const mine = all.filter(
        (n) => n.user && user && n.user.name === user.name,
      );
      setNodes(mine);
      setError("");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, [user]);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, [fetchData]);

  const online = nodes.filter((n) => n.online).length;

  if (loading) {
    return (
      <div
        className="flex items-center justify-between"
        style={{ padding: "3rem", justifyContent: "center" }}
      >
        <span className="spinner" />
      </div>
    );
  }

  return (
    <div>
      <div
        className="flex items-center justify-between"
        style={{ marginBottom: "1.25rem" }}
      >
        <div>
          <h2>My Devices</h2>
          <p className="text-sm" style={{ marginTop: 2 }}>
            {nodes.length} device{nodes.length !== 1 ? "s" : ""} &middot;{" "}
            {online} online
          </p>
        </div>
        <button className="outline" onClick={fetchData}>
          <svg
            width="14"
            height="14"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <polyline points="23 4 23 10 17 10" />
            <polyline points="1 20 1 14 7 14" />
            <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
          </svg>
          Refresh
        </button>
      </div>

      {error && (
        <div className="alert error" style={{ marginBottom: "1rem" }}>
          {error}
        </div>
      )}

      {nodes.length === 0 ? (
        <div className="card">
          <div className="empty-state">
            <svg
              width="40"
              height="40"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
            >
              <rect x="2" y="3" width="20" height="14" rx="2" ry="2" />
              <line x1="8" y1="21" x2="16" y2="21" />
              <line x1="12" y1="17" x2="12" y2="21" />
            </svg>
            <h3>No devices</h3>
            <p>
              Connect a device using{" "}
              <code>
                tailscale up --login-server {window.location.origin}
              </code>
            </p>
          </div>
        </div>
      ) : (
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fill, minmax(340px, 1fr))",
            gap: "0.75rem",
          }}
        >
          {nodes.map((node) => (
            <DeviceCard key={node.id} node={node} />
          ))}
        </div>
      )}
    </div>
  );
}
