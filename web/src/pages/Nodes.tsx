import { useState, useEffect, useCallback } from "react";
import {
  listNodes,
  deleteNode,
  expireNode,
  renameNode,
  type Node,
} from "../api";
import { useAuth } from "../auth";
import { getPermissions } from "../permissions";
import ConfirmModal from "../ConfirmModal";

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
  // Treat year 0001 (Go zero time) as no expiry
  if (exp.getFullYear() < 2) return false;
  return exp < new Date();
}

function truncateKey(key: string): string {
  if (!key) return "—";
  // Show prefix (e.g. "mkey:") + first 8 chars + "…"
  const colonIdx = key.indexOf(":");
  if (colonIdx >= 0 && key.length > colonIdx + 9) {
    return key.slice(0, colonIdx + 9) + "…";
  }
  return key.length > 16 ? key.slice(0, 16) + "…" : key;
}

function formatRegisterMethod(method: string): string {
  if (!method) return "—";
  const map: Record<string, string> = {
    REGISTER_METHOD_CLI: "CLI",
    REGISTER_METHOD_AUTH_KEY: "Auth Key",
    REGISTER_METHOD_OIDC: "OIDC",
  };
  return map[method] || method.replace("REGISTER_METHOD_", "");
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

function DetailRow({
  label,
  value,
  copyable,
  fullValue,
  valueColor,
}: {
  label: string;
  value: string;
  copyable?: boolean;
  fullValue?: string;
  valueColor?: string;
}) {
  const [copied, setCopied] = useState(false);

  const handleCopy = (e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(fullValue || value);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="detail-row">
      <span className="detail-row-label">{label}</span>
      <span className="detail-row-value" style={valueColor ? { color: valueColor } : undefined}>
        <code style={{ fontSize: "0.8rem", background: "none", padding: 0 }}>{value}</code>
        {copyable && (
          <button
            className="copy-btn"
            onClick={handleCopy}
            title={copied ? "Copied!" : "Copy to clipboard"}
          >
            {copied ? (
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="var(--color-success)" strokeWidth="2"><polyline points="20 6 9 17 4 12" /></svg>
            ) : (
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="9" y="9" width="13" height="13" rx="2" /><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" /></svg>
            )}
          </button>
        )}
      </span>
    </div>
  );
}

function NodeRow({
  node,
  onRefresh,
  canWrite,
}: {
  node: Node;
  onRefresh: () => void;
  canWrite: boolean;
}) {
  const [expanded, setExpanded] = useState(false);
  const [renaming, setRenaming] = useState(false);
  const [newName, setNewName] = useState(node.given_name || node.name);
  const [showRemoveConfirm, setShowRemoveConfirm] = useState(false);
  const expired = isExpired(node);

  async function handleRename() {
    if (!newName.trim() || newName === (node.given_name || node.name)) {
      setRenaming(false);
      return;
    }
    try {
      await renameNode(node.id, newName.trim());
      setRenaming(false);
      onRefresh();
    } catch {
      /* ignore */
    }
  }

  const tags = [
    ...(node.forced_tags || []),
    ...(node.valid_tags || []),
  ];

  return (
    <>
      <tr
        onClick={() => setExpanded(!expanded)}
        style={{ cursor: "pointer" }}
      >
        <td>
          <div className="flex items-center gap-3">
            <span
              className={`status-dot ${node.online ? "online" : "offline"}`}
            />
            <div>
              {renaming ? (
                <input
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  onBlur={handleRename}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") handleRename();
                    if (e.key === "Escape") setRenaming(false);
                  }}
                  onClick={(e) => e.stopPropagation()}
                  autoFocus
                  style={{ width: 180, padding: "0.125rem 0.375rem" }}
                />
              ) : (
                <span style={{ fontWeight: 500 }}>
                  {node.given_name || node.name}
                </span>
              )}
              {tags.length > 0 && (
                <div className="flex gap-1" style={{ marginTop: 2 }}>
                  {tags.slice(0, 3).map((tag) => (
                    <span key={tag} className="badge tag">
                      {tag}
                    </span>
                  ))}
                  {tags.length > 3 && (
                    <span className="text-xs text-tertiary">
                      +{tags.length - 3}
                    </span>
                  )}
                </div>
              )}
            </div>
          </div>
        </td>
        <td>
          <div className="flex-col gap-1">
            {(node.ip_addresses || []).map((ip) => (
              <code key={ip} className="text-sm" style={{ color: "var(--color-text-secondary)" }}>
                {ip}
              </code>
            ))}
          </div>
        </td>
        <td className="text-sm">{node.user?.name || "—"}</td>
        <td className="text-sm text-secondary">
          {formatOS(node.os)}
        </td>
        <td className="text-sm text-secondary">
          {node.client_version || "—"}
        </td>
        <td>
          {expired ? (
            <span className="badge expired">Expired</span>
          ) : (
            <span className={`badge ${node.online ? "online" : "offline"}`}>
              {node.online ? "Connected" : "Disconnected"}
            </span>
          )}
        </td>
        <td className="text-sm text-secondary">
          {timeAgo(node.last_seen)}
        </td>
        <td>
          <svg
            width="16"
            height="16"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            style={{
              transform: expanded ? "rotate(180deg)" : "rotate(0)",
              transition: "transform var(--transition)",
              color: "var(--color-text-tertiary)",
            }}
          >
            <polyline points="6 9 12 15 18 9" />
          </svg>
        </td>
      </tr>

      {expanded && (
        <tr>
          <td
            colSpan={8}
            style={{
              background: "var(--color-bg)",
              padding: "1.25rem 1.5rem",
            }}
          >
            {/* Header bar */}
            <div className="flex items-center justify-between" style={{ marginBottom: "1.25rem" }}>
              <div className="flex items-center gap-3">
                <h3 style={{ fontSize: "1rem", fontWeight: 600, margin: 0 }}>
                  {node.given_name || node.name}
                </h3>
                <span className={`badge ${node.online ? "online" : "offline"}`} style={{ fontSize: "0.7rem" }}>
                  {node.online ? "Connected" : "Disconnected"}
                </span>
                {expired && <span className="badge expired" style={{ fontSize: "0.7rem" }}>Expired</span>}
                {node.is_jailed && <span className="badge expired" style={{ fontSize: "0.7rem" }}>Jailed</span>}
              </div>
              <div className="flex gap-2">
                {canWrite && <button className="outline sm" onClick={(e) => { e.stopPropagation(); setRenaming(true); }}>Rename</button>}
                {canWrite && <button className="outline sm" onClick={async (e) => { e.stopPropagation(); await expireNode(node.id); onRefresh(); }}>Expire</button>}
                {canWrite && <button className="danger sm" onClick={(e) => { e.stopPropagation(); setShowRemoveConfirm(true); }}>Remove</button>}
              </div>
            </div>

            {/* Managed by + Status */}
            <div className="flex gap-4" style={{ marginBottom: "1.25rem" }}>
              {tags.length > 0 && (
                <div>
                  <div className="detail-label">Managed by</div>
                  <div className="flex gap-1" style={{ flexWrap: "wrap" }}>
                    {tags.map((tag) => <span key={tag} className="badge tag">{tag}</span>)}
                  </div>
                </div>
              )}
              <div>
                <div className="detail-label">Status</div>
                <span className="text-sm">
                  {expired ? "Expired" : node.expiry ? `Expires ${new Date(node.expiry).toLocaleDateString()}` : "Expiry disabled"}
                </span>
              </div>
              <div>
                <div className="detail-label">Owner</div>
                <span className="text-sm">{node.user?.name || "—"}</span>
              </div>
            </div>

            {/* Subnet Routes */}
            {((node.subnet_routes && node.subnet_routes.length > 0) ||
              (node.approved_routes && node.approved_routes.length > 0) ||
              (node.available_routes && node.available_routes.length > 0)) && (
              <div className="detail-section">
                <h4 className="detail-section-title">Subnet Routes</h4>
                <p className="text-xs text-secondary" style={{ marginBottom: "0.5rem" }}>
                  Subnets this machine exposes to the network.
                </p>
                <div className="flex gap-2" style={{ flexWrap: "wrap" }}>
                  {(node.subnet_routes || []).map((r) => (
                    <span key={r} className="badge tag">{r}</span>
                  ))}
                  {(node.approved_routes || []).map((r) => (
                    <span key={`a-${r}`} className="badge tag" style={{ borderColor: "var(--color-success)" }}>{r} ✓</span>
                  ))}
                  {(node.available_routes || []).filter(r => !(node.approved_routes || []).includes(r) && !(node.subnet_routes || []).includes(r)).map((r) => (
                    <span key={`v-${r}`} className="badge tag" style={{ opacity: 0.5 }}>{r} (pending)</span>
                  ))}
                </div>
              </div>
            )}

            {/* Machine Details + Addresses — two column layout */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1.5rem" }}>
              {/* Left: Machine Details */}
              <div className="detail-section">
                <h4 className="detail-section-title">Machine Details</h4>
                <div className="detail-grid">
                  <DetailRow label="Machine name" value={node.name} copyable />
                  <DetailRow label="Hostname" value={node.given_name || node.name} copyable />
                  <DetailRow label="ID" value={node.id} copyable />
                  <DetailRow label="Machine key" value={truncateKey(node.machine_key)} copyable fullValue={node.machine_key} />
                  <DetailRow label="Node key" value={truncateKey(node.node_key)} copyable fullValue={node.node_key} />
                  <DetailRow label="Disco key" value={truncateKey(node.disco_key)} copyable fullValue={node.disco_key} />
                  <DetailRow label="Created" value={node.created_at ? new Date(node.created_at).toLocaleString() : "—"} />
                  <DetailRow label="Last seen" value={node.last_seen ? `${timeAgo(node.last_seen)} — ${new Date(node.last_seen).toLocaleString()}` : "—"} />
                  <DetailRow label="Key expiry" value={node.expiry && new Date(node.expiry).getFullYear() > 1 ? new Date(node.expiry).toLocaleString() : "No expiry"} />
                  <DetailRow label="Register method" value={formatRegisterMethod(node.register_method)} />
                  <DetailRow label="Tailscale version" value={node.client_version || "—"} />
                  <DetailRow label="OS" value={node.os ? `${formatOS(node.os)}${node.os_version ? " " + node.os_version : ""}` : "—"} />
                  {node.is_wireguard_only && <DetailRow label="WireGuard only" value="Yes" />}
                </div>
              </div>

              {/* Right: Addresses */}
              <div className="detail-section">
                <h4 className="detail-section-title">Addresses</h4>
                <div className="detail-grid">
                  {(node.ip_addresses || []).map((ip, i) => (
                    <DetailRow
                      key={ip}
                      label={ip.includes(":") ? "Tailscale IPv6" : `Tailscale IPv4${i > 1 ? ` (${i + 1})` : ""}`}
                      value={ip}
                      copyable
                      valueColor="var(--color-primary)"
                    />
                  ))}
                  <DetailRow label="Short domain" value={node.given_name || node.name} copyable />
                  {node.fqdn && <DetailRow label="FQDN" value={node.fqdn} copyable />}
                </div>

                {/* Endpoints */}
                {(node.endpoints || []).length > 0 && (
                  <>
                    <div className="detail-label" style={{ marginTop: "0.75rem" }}>Endpoints</div>
                    <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                      {node.endpoints.map((ep) => (
                        <code key={ep} className="text-xs" style={{ color: "var(--color-text-secondary)" }}>{ep}</code>
                      ))}
                    </div>
                  </>
                )}

                {/* Location */}
                {(node.location_country || node.location_city) && (
                  <>
                    <div className="detail-label" style={{ marginTop: "0.75rem" }}>Location</div>
                    <span className="text-sm">
                      {[node.location_city, node.location_country].filter(Boolean).join(", ")}
                      {node.location_country_code && ` (${node.location_country_code})`}
                    </span>
                  </>
                )}
              </div>
            </div>
          </td>
        </tr>
      )}
      <ConfirmModal
        open={showRemoveConfirm}
        title="Remove machine"
        message={`Remove "${node.given_name || node.name}" permanently? This cannot be undone.`}
        confirmLabel="Remove"
        destructive
        onConfirm={async () => { setShowRemoveConfirm(false); await deleteNode(node.id); onRefresh(); }}
        onCancel={() => setShowRemoveConfirm(false)}
      />
    </>
  );
}

export function NodesPage() {
  const { user } = useAuth();
  const perms = getPermissions(user?.role);
  const [nodes, setNodes] = useState<Node[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const fetchData = useCallback(async () => {
    try {
      const n = await listNodes();
      setNodes(n);
      setError("");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, [fetchData]);

  const online = nodes.filter((n) => n.online).length;

  if (loading) {
    return (
      <div className="flex items-center justify-between" style={{ padding: "3rem", justifyContent: "center" }}>
        <span className="spinner" />
      </div>
    );
  }

  return (
    <div>
      <div
        className="flex items-center justify-between"
        style={{ marginBottom: "1rem" }}
      >
        <div>
          <h2>Machines</h2>
          <p className="text-sm" style={{ marginTop: 2 }}>
            {nodes.length} machine{nodes.length !== 1 ? "s" : ""} &middot;{" "}
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

      <div className="card" style={{ padding: 0 }}>
        {nodes.length === 0 ? (
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
            <h3>No machines</h3>
            <p>
              Connect a device using{" "}
              <code>tailscale up --login-server {window.location.origin}</code>
            </p>
          </div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table>
              <thead>
                <tr>
                  <th>Machine</th>
                  <th>Address</th>
                  <th>User</th>
                  <th>OS</th>
                  <th>Version</th>
                  <th>Status</th>
                  <th>Last Seen</th>
                  <th style={{ width: 32 }} />
                </tr>
              </thead>
              <tbody>
                {nodes.map((node) => (
                  <NodeRow
                    key={node.id}
                    node={node}
                    onRefresh={fetchData}
                    canWrite={perms.canWriteMachines}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
