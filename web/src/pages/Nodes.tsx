import { useState, useEffect, useCallback, useMemo } from "react";
import {
  listNodes,
  deleteNode,
  expireNode,
  renameNode,
  setApprovedRoutes,
  listPendingRegistrations,
  approvePendingRegistration,
  rejectPendingRegistration,
  type Node,
  type PendingRegistration,
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
  const [routeLoading, setRouteLoading] = useState(false);
  const expired = isExpired(node);

  // Classify routes
  const approvedRoutes = node.approved_routes || [];
  const availableRoutes = node.available_routes || [];
  const subnetRoutes = node.subnet_routes || [];
  // Exit routes are 0.0.0.0/0 and ::/0
  const isExitRoute = (r: string) => r === "0.0.0.0/0" || r === "::/0";
  const advertisedExitRoutes = availableRoutes.filter(isExitRoute);
  const approvedExitRoutes = approvedRoutes.filter(isExitRoute);
  const hasExitNode = advertisedExitRoutes.length > 0;
  const exitNodeApproved = approvedExitRoutes.length >= 2; // both v4+v6
  // Subnet (non-exit) routes
  const advertisedSubnets = availableRoutes.filter(r => !isExitRoute(r));
  const approvedSubnets = approvedRoutes.filter(r => !isExitRoute(r));
  const pendingSubnets = advertisedSubnets.filter(r => !approvedSubnets.includes(r));
  const hasRoutes = advertisedSubnets.length > 0 || hasExitNode;

  async function handleApproveRoute(route: string) {
    setRouteLoading(true);
    try {
      const newRoutes = [...approvedRoutes, route];
      await setApprovedRoutes(node.id, newRoutes);
      onRefresh();
    } finally {
      setRouteLoading(false);
    }
  }

  async function handleRejectRoute(route: string) {
    setRouteLoading(true);
    try {
      const newRoutes = approvedRoutes.filter(r => r !== route);
      await setApprovedRoutes(node.id, newRoutes);
      onRefresh();
    } finally {
      setRouteLoading(false);
    }
  }

  async function handleApproveAllSubnets() {
    setRouteLoading(true);
    try {
      const newRoutes = [...new Set([...approvedRoutes, ...advertisedSubnets])];
      await setApprovedRoutes(node.id, newRoutes);
      onRefresh();
    } finally {
      setRouteLoading(false);
    }
  }

  async function handleToggleExitNode() {
    setRouteLoading(true);
    try {
      let newRoutes: string[];
      if (exitNodeApproved) {
        // Remove exit routes
        newRoutes = approvedRoutes.filter(r => !isExitRoute(r));
      } else {
        // Add both exit routes
        newRoutes = [...new Set([...approvedRoutes, "0.0.0.0/0", "::/0"])];
      }
      await setApprovedRoutes(node.id, newRoutes);
      onRefresh();
    } finally {
      setRouteLoading(false);
    }
  }

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

  const tags = node.tags || [];

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
        <td className="text-sm">
          {tags.length > 0 && node.user?.name === "tagged-devices" ? (
            <div className="flex gap-1" style={{ flexWrap: "wrap" }}>
              {tags.map((tag) => (
                <span key={tag} className="badge tag">{tag}</span>
              ))}
            </div>
          ) : (
            node.user?.display_name || node.user?.name || "—"
          )}
        </td>
        <td className="text-sm text-secondary">
          {formatOS(node.os)}
        </td>
        <td className="text-sm text-secondary">
          {node.client_version || "—"}
        </td>
        <td>
          <div className="flex items-center gap-2" style={{ flexWrap: "wrap" }}>
            {expired ? (
              <span className="badge expired">Expired</span>
            ) : (
              <span className={`badge ${node.online ? "online" : "offline"}`}>
                {node.online ? "Connected" : "Disconnected"}
              </span>
            )}
            {pendingSubnets.length > 0 && (
              <span style={{
                fontSize: "0.6rem", padding: "0.1rem 0.4rem", borderRadius: 999,
                background: "color-mix(in srgb, var(--color-warning) 15%, transparent)",
                color: "var(--color-warning)", fontWeight: 600, whiteSpace: "nowrap",
              }}>
                {pendingSubnets.length} route{pendingSubnets.length > 1 ? "s" : ""} pending
              </span>
            )}
            {hasExitNode && !exitNodeApproved && (
              <span style={{
                fontSize: "0.6rem", padding: "0.1rem 0.4rem", borderRadius: 999,
                background: "color-mix(in srgb, var(--color-warning) 15%, transparent)",
                color: "var(--color-warning)", fontWeight: 600, whiteSpace: "nowrap",
              }}>Exit node pending</span>
            )}
          </div>
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

            {/* Managed by + Status + Owner */}
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
                {tags.length > 0 && node.user?.name === "tagged-devices" ? (
                  <div className="flex gap-1" style={{ flexWrap: "wrap", marginTop: 2 }}>
                    {tags.map((tag) => <span key={tag} className="badge tag">{tag}</span>)}
                  </div>
                ) : (
                  <span className="text-sm">{node.user?.display_name || node.user?.name || "—"}</span>
                )}
              </div>
            </div>

            {/* Subnet Routes & Exit Node */}
            {hasRoutes && (
              <div style={{ display: "grid", gridTemplateColumns: (advertisedSubnets.length > 0 && hasExitNode) ? "1fr 1fr" : "1fr", gap: "1.5rem", marginBottom: "1.25rem" }}>
                {/* Subnet Routes */}
                {advertisedSubnets.length > 0 && (
                  <div className="detail-section">
                    <div className="flex items-center justify-between" style={{ marginBottom: "0.5rem" }}>
                      <h4 className="detail-section-title" style={{ margin: 0 }}>Subnet Routes</h4>
                      {canWrite && pendingSubnets.length > 1 && (
                        <button
                          className="outline sm"
                          onClick={(e) => { e.stopPropagation(); handleApproveAllSubnets(); }}
                          disabled={routeLoading}
                          style={{ fontSize: "0.6875rem", padding: "0.2rem 0.5rem" }}
                        >
                          Approve all
                        </button>
                      )}
                    </div>
                    <p className="text-xs text-secondary" style={{ marginBottom: "0.5rem" }}>
                      Subnets this machine exposes to the network.
                    </p>
                    <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                      {advertisedSubnets.map((route) => {
                        const isApproved = approvedSubnets.includes(route);
                        const isPrimary = subnetRoutes.includes(route);
                        return (
                          <div key={route} style={{
                            display: "flex", alignItems: "center", justifyContent: "space-between",
                            padding: "0.375rem 0.625rem", borderRadius: "var(--radius)",
                            background: "var(--color-surface)", border: "1px solid var(--color-border)",
                          }}>
                            <div className="flex items-center gap-2">
                              <code style={{ fontSize: "0.8rem", color: isApproved ? "var(--color-text)" : "var(--color-text-secondary)" }}>{route}</code>
                              {isPrimary && (
                                <span style={{
                                  fontSize: "0.6rem", padding: "0.1rem 0.35rem", borderRadius: 999,
                                  background: "color-mix(in srgb, var(--color-primary) 15%, transparent)", color: "var(--color-primary)",
                                  fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.03em",
                                }}>Primary</span>
                              )}
                              {isApproved && !isPrimary && (
                                <span style={{
                                  fontSize: "0.6rem", padding: "0.1rem 0.35rem", borderRadius: 999,
                                  background: "color-mix(in srgb, var(--color-success) 15%, transparent)", color: "var(--color-success)",
                                  fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.03em",
                                }}>Approved</span>
                              )}
                              {!isApproved && (
                                <span style={{
                                  fontSize: "0.6rem", padding: "0.1rem 0.35rem", borderRadius: 999,
                                  background: "color-mix(in srgb, var(--color-warning) 15%, transparent)", color: "var(--color-warning)",
                                  fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.03em",
                                }}>Pending</span>
                              )}
                            </div>
                            {canWrite && (
                              <div className="flex gap-1">
                                {!isApproved ? (
                                  <button
                                    onClick={(e) => { e.stopPropagation(); handleApproveRoute(route); }}
                                    disabled={routeLoading}
                                    className="route-action-btn approve"
                                  >Approve</button>
                                ) : (
                                  <button
                                    onClick={(e) => { e.stopPropagation(); handleRejectRoute(route); }}
                                    disabled={routeLoading}
                                    className="route-action-btn revoke"
                                  >Revoke</button>
                                )}
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* Exit Node */}
                {hasExitNode && (
                  <div className="detail-section">
                    <h4 className="detail-section-title" style={{ marginBottom: "0.5rem" }}>Exit Node</h4>
                    <p className="text-xs text-secondary" style={{ marginBottom: "0.5rem" }}>
                      Allow this device to route all internet traffic for other nodes.
                    </p>
                    <div style={{
                      padding: "0.75rem", borderRadius: "var(--radius)",
                      background: "var(--color-surface)", border: "1px solid var(--color-border)",
                    }}>
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <div style={{
                            width: 32, height: 32, borderRadius: "var(--radius)", display: "flex", alignItems: "center", justifyContent: "center",
                            background: exitNodeApproved
                              ? "color-mix(in srgb, var(--color-success) 15%, transparent)"
                              : "color-mix(in srgb, var(--color-warning) 15%, transparent)",
                          }}>
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke={exitNodeApproved ? "var(--color-success)" : "var(--color-warning)"} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                              <circle cx="12" cy="12" r="10" /><line x1="2" y1="12" x2="22" y2="12" />
                              <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
                            </svg>
                          </div>
                          <div>
                            <div style={{ fontSize: "0.8125rem", fontWeight: 500, color: "var(--color-text)" }}>
                              {exitNodeApproved ? "Exit node enabled" : "Exit node requested"}
                            </div>
                            <div className="text-xs text-secondary">
                              Routes <code style={{ fontSize: "0.75rem" }}>0.0.0.0/0</code> + <code style={{ fontSize: "0.75rem" }}>::/0</code>
                            </div>
                          </div>
                        </div>
                        {canWrite && (
                          <button
                            onClick={(e) => { e.stopPropagation(); handleToggleExitNode(); }}
                            disabled={routeLoading}
                            className={`route-action-btn ${exitNodeApproved ? "revoke" : "approve"}`}
                            style={{ padding: "0.3rem 0.75rem" }}
                          >
                            {exitNodeApproved ? "Disable" : "Approve"}
                          </button>
                        )}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Machine Details + Addresses + Posture — three column layout */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "1.5rem" }}>
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
                </div>
              </div>

              {/* Middle: Addresses */}
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

              {/* Right: Device Posture */}
              <div className="detail-section">
                <h4 className="detail-section-title">Device Posture</h4>
                <div className="detail-grid">
                  <DetailRow label="OS" value={node.os ? `${formatOS(node.os)}${node.os_version ? " " + node.os_version : ""}` : "—"} />
                  {node.distro && <DetailRow label="Distribution" value={[node.distro, node.distro_version, node.distro_code_name ? `(${node.distro_code_name})` : ""].filter(Boolean).join(" ")} />}
                  {node.device_model && <DetailRow label="Device model" value={node.device_model} />}
                  {node.arch && <DetailRow label="Architecture" value={node.arch} />}
                  <DetailRow label="Tailscale version" value={node.client_version || "—"} />
                  {node.package && <DetailRow label="Package" value={node.package} />}
                  {node.go_version && <DetailRow label="Go version" value={node.go_version} />}
                  {node.cloud && <DetailRow label="Cloud" value={node.cloud} />}
                </div>
                <div style={{ display: "flex", gap: "0.375rem", flexWrap: "wrap", marginTop: "0.5rem" }}>
                  {node.state_encrypted !== undefined && (
                    <span style={{
                      padding: "0.125rem 0.5rem", borderRadius: "9999px", fontSize: "0.6875rem", fontWeight: 500,
                      background: node.state_encrypted ? "color-mix(in srgb, var(--color-success) 15%, transparent)" : "color-mix(in srgb, var(--color-text-tertiary) 15%, transparent)",
                      color: node.state_encrypted ? "var(--color-success)" : "var(--color-text-tertiary)",
                    }}>{node.state_encrypted ? "Encrypted" : "Unencrypted"}</span>
                  )}
                  {node.shields_up && (
                    <span style={{
                      padding: "0.125rem 0.5rem", borderRadius: "9999px", fontSize: "0.6875rem", fontWeight: 500,
                      background: "color-mix(in srgb, var(--color-warning) 15%, transparent)", color: "var(--color-warning)",
                    }}>Shields Up</span>
                  )}
                  {node.ssh_enabled && (
                    <span style={{
                      padding: "0.125rem 0.5rem", borderRadius: "9999px", fontSize: "0.6875rem", fontWeight: 500,
                      background: "color-mix(in srgb, var(--color-primary) 15%, transparent)", color: "var(--color-primary)",
                    }}>SSH</span>
                  )}
                  {node.container && (
                    <span style={{
                      padding: "0.125rem 0.5rem", borderRadius: "9999px", fontSize: "0.6875rem", fontWeight: 500,
                      background: "color-mix(in srgb, var(--color-primary) 15%, transparent)", color: "var(--color-primary)",
                    }}>Container</span>
                  )}
                  {node.tpm && (
                    <span style={{
                      padding: "0.125rem 0.5rem", borderRadius: "9999px", fontSize: "0.6875rem", fontWeight: 500,
                      background: "color-mix(in srgb, var(--color-success) 15%, transparent)", color: "var(--color-success)",
                    }} title={[node.tpm.vendor || node.tpm.manufacturer, node.tpm.family_indicator].filter(Boolean).join(" — ")}>TPM</span>
                  )}
                  {node.is_wireguard_only && (
                    <span style={{
                      padding: "0.125rem 0.5rem", borderRadius: "9999px", fontSize: "0.6875rem", fontWeight: 500,
                      background: "color-mix(in srgb, var(--color-text-tertiary) 15%, transparent)", color: "var(--color-text-tertiary)",
                    }}>WireGuard only</span>
                  )}
                </div>
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
  const [pendingRegs, setPendingRegs] = useState<PendingRegistration[]>([]);

  // Filters — restore persisted values from localStorage
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<"all" | "online" | "offline" | "expired">(() => {
    const v = localStorage.getItem("hs:nodes:statusFilter");
    return (v === "online" || v === "offline" || v === "expired") ? v : "all";
  });
  const [osFilter, setOsFilter] = useState<string>(() => localStorage.getItem("hs:nodes:osFilter") || "all");
  const [userFilters, setUserFilters] = useState<Set<string>>(() => {
    try { const v = localStorage.getItem("hs:nodes:userFilters"); return v ? new Set(JSON.parse(v)) : new Set(); } catch { return new Set(); }
  });
  const [groupByUser, setGroupByUser] = useState(() => localStorage.getItem("hs:nodes:groupByUser") === "true");
  const [showUserPicker, setShowUserPicker] = useState(false);

  // Persist filter values when they change
  useEffect(() => { localStorage.setItem("hs:nodes:statusFilter", statusFilter); }, [statusFilter]);
  useEffect(() => { localStorage.setItem("hs:nodes:osFilter", osFilter); }, [osFilter]);
  useEffect(() => { localStorage.setItem("hs:nodes:userFilters", JSON.stringify([...userFilters])); }, [userFilters]);
  useEffect(() => { localStorage.setItem("hs:nodes:groupByUser", String(groupByUser)); }, [groupByUser]);

  const fetchData = useCallback(async () => {
    try {
      const n = await listNodes();
      setNodes(n);
      setError("");
      if (user?.role === "admin") {
        try {
          const pending = await listPendingRegistrations();
          setPendingRegs(pending);
        } catch {
          // Ignore errors fetching pending registrations
        }
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, [user?.role]);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, [fetchData]);

  // Derive unique OS and user values for filter dropdowns
  const osOptions = useMemo(() => {
    const set = new Set<string>();
    nodes.forEach((n) => { if (n.os) set.add(n.os); });
    return Array.from(set).sort();
  }, [nodes]);

  const userOptions = useMemo(() => {
    const map = new Map<string, string>();
    nodes.forEach((n) => {
      if (n.user?.name && n.user.name !== "tagged-devices") {
        map.set(n.user.name, n.user.display_name || n.user.name);
      }
    });
    return Array.from(map.entries()).sort((a, b) => a[1].localeCompare(b[1]));
  }, [nodes]);

  const tagOptions = useMemo(() => {
    const set = new Set<string>();
    nodes.forEach((n) => {
      (n.forced_tags || []).forEach((t) => set.add(t));
      (n.tags || []).forEach((t) => set.add(t));
    });
    return Array.from(set).sort();
  }, [nodes]);

  // Apply filters
  const filtered = useMemo(() => {
    const q = search.toLowerCase().trim();
    return nodes.filter((n) => {
      // Search: match name, given_name, IPs, user, tags
      if (q) {
        const haystack = [
          n.name, n.given_name,
          ...(n.ip_addresses || []),
          n.user?.display_name, n.user?.name,
          ...(n.tags || []),
          n.os, n.client_version,
        ].filter(Boolean).join(" ").toLowerCase();
        if (!haystack.includes(q)) return false;
      }
      // Status
      if (statusFilter === "online" && !n.online) return false;
      if (statusFilter === "offline" && (n.online || isExpired(n))) return false;
      if (statusFilter === "expired" && !isExpired(n)) return false;
      // OS
      if (osFilter !== "all" && n.os !== osFilter) return false;
      // User / tag filter
      if (userFilters.size > 0) {
        const nodeTags = [...(n.forced_tags || []), ...(n.tags || [])];
        const matchesUser = n.user?.name && n.user.name !== "tagged-devices" && userFilters.has(n.user.name);
        const matchesTag = nodeTags.some((t) => userFilters.has(t));
        if (!matchesUser && !matchesTag) return false;
      }
      return true;
    });
  }, [nodes, search, statusFilter, osFilter, userFilters]);

  // Group by user
  const grouped = useMemo(() => {
    if (!groupByUser) return null;
    const map = new Map<string, { label: string; nodes: Node[] }>();
    filtered.forEach((n) => {
      const key = n.user?.name || "unknown";
      const label = (n.tags?.length && n.user?.name === "tagged-devices")
        ? "Tagged Devices"
        : (n.user?.display_name || n.user?.name || "Unknown");
      if (!map.has(key)) map.set(key, { label, nodes: [] });
      map.get(key)!.nodes.push(n);
    });
    return Array.from(map.entries()).sort((a, b) => {
      // Always push "Tagged Devices" to the bottom
      const aTagged = a[0] === "tagged-devices";
      const bTagged = b[0] === "tagged-devices";
      if (aTagged !== bTagged) return aTagged ? 1 : -1;
      return a[1].label.localeCompare(b[1].label);
    });
  }, [filtered, groupByUser]);

  const online = nodes.filter((n) => n.online).length;
  const hasActiveFilters = search || statusFilter !== "all" || osFilter !== "all" || userFilters.size > 0;

  if (loading) {
    return (
      <div className="flex items-center justify-between" style={{ padding: "3rem", justifyContent: "center" }}>
        <span className="spinner" />
      </div>
    );
  }

  const renderTable = (tableNodes: Node[]) => (
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
          {tableNodes.map((node) => (
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
  );

  return (
    <div>
      {/* Pending registrations banner (admin only) */}
      {pendingRegs.length > 0 && (
        <div
          style={{
            background: "var(--color-warning-subtle)",
            border: "1px solid color-mix(in srgb, var(--color-warning) 30%, transparent)",
            borderRadius: "var(--radius-lg)",
            padding: "0.75rem 1rem",
            marginBottom: "1rem",
          }}
        >
          <div className="flex items-center gap-2" style={{ marginBottom: "0.5rem" }}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--color-warning)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="10" />
              <polyline points="12 6 12 12 16 14" />
            </svg>
            <span style={{ fontWeight: 600, fontSize: "0.875rem", color: "var(--color-warning)" }}>
              {pendingRegs.length} pending registration{pendingRegs.length !== 1 ? "s" : ""}
            </span>
          </div>
          {pendingRegs.map((pr) => (
            <div
              key={pr.id}
              className="flex items-center justify-between"
              style={{
                background: "var(--color-surface)",
                border: "1px solid var(--color-border)",
                borderRadius: "var(--radius-md, 6px)",
                padding: "0.5rem 0.75rem",
                marginBottom: "0.375rem",
                fontSize: "0.8125rem",
              }}
            >
              <div>
                <span style={{ fontWeight: 500 }}>Device registration</span>
                <span className="text-secondary" style={{ marginLeft: "0.5rem" }}>
                  requested by <strong>{pr.requested_by}</strong>
                </span>
                <span className="text-tertiary" style={{ marginLeft: "0.5rem", fontSize: "0.75rem" }}>
                  {new Date(pr.requested_at).toLocaleString()}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <button
                  className="btn primary"
                  style={{ padding: "0.25rem 0.75rem", fontSize: "0.75rem" }}
                  onClick={async () => {
                    try {
                      await approvePendingRegistration(pr.id);
                      fetchData();
                    } catch (err: unknown) {
                      setError(err instanceof Error ? err.message : String(err));
                    }
                  }}
                >
                  Approve
                </button>
                <button
                  className="btn outline"
                  style={{ padding: "0.25rem 0.75rem", fontSize: "0.75rem" }}
                  onClick={async () => {
                    try {
                      await rejectPendingRegistration(pr.id);
                      fetchData();
                    } catch (err: unknown) {
                      setError(err instanceof Error ? err.message : String(err));
                    }
                  }}
                >
                  Reject
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Header row */}
      <div style={{ marginBottom: "1rem" }}>
        <div className="flex items-center justify-between" style={{ marginBottom: "0.5rem" }}>
          <div>
            <h2>Machines</h2>
            <p className="text-sm" style={{ marginTop: 2 }}>
              {nodes.length} machine{nodes.length !== 1 ? "s" : ""} &middot;{" "}
              {online} online
              {hasActiveFilters && ` · ${filtered.length} shown`}
            </p>
          </div>
        </div>

        {/* Unified toolbar — single row */}
        <div className="flex items-center gap-2" style={{ flexWrap: "nowrap" }}>
          {/* Search */}
          <div style={{ position: "relative", width: 200, flexShrink: 0 }}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--color-text-tertiary)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ position: "absolute", left: 10, top: "50%", transform: "translateY(-50%)", pointerEvents: "none" }}>
              <circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" />
            </svg>
            <input
              type="text"
              placeholder="Search..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              style={{ width: "100%", paddingLeft: 32, fontSize: "0.8125rem" }}
            />
          </div>

          {/* Status filter: colored dots */}
          <div className="flex items-center" style={{ border: "1px solid var(--color-border)", borderRadius: "var(--radius)", overflow: "hidden", flexShrink: 0 }}>
            {([
              { key: "all", color: "#a1a1aa", label: "All statuses" },
              { key: "online", color: "#34d399", label: "Online" },
              { key: "offline", color: "#71717a", label: "Offline" },
              { key: "expired", color: "#f87171", label: "Expired" },
            ] as const).map((s, i) => (
              <button
                key={s.key}
                onClick={() => setStatusFilter(statusFilter === s.key && s.key !== "all" ? "all" : s.key)}
                title={s.label}
                style={{
                  padding: "0.375rem 0.5rem",
                  border: "none",
                  borderRight: i < 3 ? "1px solid var(--color-border)" : "none",
                  background: statusFilter === s.key ? "rgba(255,255,255,0.08)" : "transparent",
                  cursor: "pointer",
                  display: "flex", alignItems: "center", justifyContent: "center",
                }}
              >
                <span style={{
                  width: 8, height: 8, borderRadius: "50%", display: "inline-block",
                  background: s.color,
                  opacity: statusFilter === s.key ? 1 : 0.45,
                }} />
              </button>
            ))}
          </div>

          {/* OS filter: platform icons */}
          {osOptions.length > 1 && (
            <div className="flex items-center" style={{ border: "1px solid var(--color-border)", borderRadius: "var(--radius)", overflow: "hidden", flexShrink: 0 }}>
              <button
                onClick={() => setOsFilter("all")}
                title="All platforms"
                style={{
                  padding: "0.375rem 0.5rem", border: "none",
                  borderRight: "1px solid var(--color-border)",
                  background: osFilter === "all" ? "rgba(255,255,255,0.08)" : "transparent",
                  color: osFilter === "all" ? "var(--color-text-primary)" : "var(--color-text-tertiary)",
                  cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center",
                }}
              >
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <rect x="2" y="3" width="20" height="14" rx="2" /><line x1="8" y1="21" x2="16" y2="21" /><line x1="12" y1="17" x2="12" y2="21" />
                </svg>
              </button>
              {osOptions.map((os, i) => {
                const active = osFilter === os;
                const iconColor = active ? "var(--color-text-primary)" : "var(--color-text-tertiary)";
                return (
                  <button
                    key={os}
                    onClick={() => setOsFilter(active ? "all" : os)}
                    title={formatOS(os)}
                    style={{
                      padding: "0.375rem 0.5rem", border: "none",
                      borderRight: i < osOptions.length - 1 ? "1px solid var(--color-border)" : "none",
                      background: active ? "rgba(255,255,255,0.08)" : "transparent",
                      cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center",
                    }}
                  >
                    {os === "linux" && (
                      <svg width="14" height="14" viewBox="0 0 24 24" fill={iconColor} stroke="none">
                        <path d="M12.5 2C10.4 2 8.7 3.8 8.3 6.2c-.3 1.7 0 3.5.7 5.1-1.2.8-2.4 1.8-3.2 3.1-.6 1-.5 2.3.3 3.2.5.6 1.3.9 2.1.9.4 0 .8-.1 1.2-.3.6-.4 1-.6 1.6-.6s1 .2 1.6.6c.7.4 1.5.4 2.2 0 .6-.4 1-.6 1.6-.6s1 .2 1.6.6c.4.2.8.3 1.2.3.8 0 1.6-.3 2.1-.9.8-.9.9-2.2.3-3.2-.8-1.3-2-2.3-3.2-3.1.7-1.6 1-3.4.7-5.1C15.3 3.8 13.6 2 12.5 2z"/>
                      </svg>
                    )}
                    {os === "windows" && (
                      <svg width="14" height="14" viewBox="0 0 24 24" fill={iconColor} stroke="none">
                        <path d="M3 12V6.5l8-1.1V12H3zm0 .5h8v6.6l-8-1.1V12.5zM11.5 5.3l9.5-1.3v8.5h-9.5V5.3zm0 7.2h9.5V21l-9.5-1.3V12.5z"/>
                      </svg>
                    )}
                    {(os === "macOS" || os === "iOS") && (
                      <svg width="14" height="14" viewBox="0 0 24 24" fill={iconColor} stroke="none">
                        <path d="M18.7 19.4c-.7 1-1.4 1.9-2.5 1.9s-1.4-.6-2.6-.6-1.6.6-2.6.6-1.7-.9-2.5-2C6.7 16.8 5.5 13.4 7.3 11.1c.9-1.2 2.3-1.9 3.6-1.9 1.1 0 2 .7 2.6.7.6 0 1.8-.9 3-.7.5 0 1.9.2 2.8 1.5-2.5 1.5-2.1 5.3.4 6.7zM14.7 3c.9 1.1.8 3-.1 4-.9 1-2.2 1.6-3.3 1.5-.2-1.2.3-2.4 1-3.3.8-1 2-1.6 2.4-2.2z"/>
                      </svg>
                    )}
                    {os === "android" && (
                      <svg width="14" height="14" viewBox="0 0 24 24" fill={iconColor} stroke="none">
                        <path d="M6 18c0 .55.45 1 1 1h1v3.5c0 .83.67 1.5 1.5 1.5s1.5-.67 1.5-1.5V19h2v3.5c0 .83.67 1.5 1.5 1.5s1.5-.67 1.5-1.5V19h1c.55 0 1-.45 1-1V8H6v10zM3.5 8C2.67 8 2 8.67 2 9.5v7c0 .83.67 1.5 1.5 1.5S5 17.33 5 16.5v-7C5 8.67 4.33 8 3.5 8zm17 0c-.83 0-1.5.67-1.5 1.5v7c0 .83.67 1.5 1.5 1.5s1.5-.67 1.5-1.5v-7c0-.83-.67-1.5-1.5-1.5zm-4.97-5.84l1.3-1.3c.2-.2.2-.51 0-.71-.2-.2-.51-.2-.71 0l-1.48 1.48C13.85 1.23 12.95 1 12 1c-.96 0-1.86.23-2.66.63L7.85.15c-.2-.2-.51-.2-.71 0-.2.2-.2.51 0 .71l1.31 1.31C6.97 3.26 6 5.01 6 7h12c0-1.99-.97-3.75-2.47-4.84zM10 5H9V4h1v1zm5 0h-1V4h1v1z"/>
                      </svg>
                    )}
                    {(os === "freebsd" || os === "openbsd") && (
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={iconColor} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <circle cx="12" cy="12" r="10" /><path d="M12 6v6l4 2" />
                      </svg>
                    )}
                    {!["linux","windows","macOS","iOS","android","freebsd","openbsd"].includes(os) && (
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={iconColor} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <rect x="2" y="3" width="20" height="14" rx="2" /><line x1="8" y1="21" x2="16" y2="21" /><line x1="12" y1="17" x2="12" y2="21" />
                      </svg>
                    )}
                  </button>
                );
              })}
            </div>
          )}

          {/* Spacer pushes actions right */}
          <div style={{ flex: 1 }} />

          {/* User/Tag multi-select picker */}
          {(userOptions.length > 0 || tagOptions.length > 0) && (
            <div style={{ position: "relative", flexShrink: 0 }}>
              <button
                onClick={() => setShowUserPicker(!showUserPicker)}
                title="Filter by user or tag"
                style={{
                  fontSize: "0.75rem", padding: "0.375rem 0.625rem",
                  borderRadius: "var(--radius)", border: "1px solid var(--color-border)",
                  background: userFilters.size > 0 ? "rgba(255,255,255,0.08)" : "transparent",
                  color: "var(--color-text-secondary)", cursor: "pointer",
                  width: 100, textAlign: "center",
                }}
              >
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ marginRight: 4, verticalAlign: "-2px" }}>
                  <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" /><circle cx="12" cy="7" r="4" />
                </svg>
                {userFilters.size > 0 ? `${userFilters.size} selected` : "Filter"}
                <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" style={{ marginLeft: 4, verticalAlign: "-1px" }}>
                  <polyline points="6 9 12 15 18 9" />
                </svg>
              </button>
              {showUserPicker && (
                <>
                  <div style={{ position: "fixed", inset: 0, zIndex: 99 }} onClick={() => setShowUserPicker(false)} />
                  <div style={{
                    position: "absolute", top: "calc(100% + 4px)", right: 0, zIndex: 100,
                    background: "var(--color-surface)", border: "1px solid var(--color-border)",
                    borderRadius: "var(--radius)", padding: "0.5rem 0", minWidth: 240, maxHeight: 360, overflowY: "auto",
                    boxShadow: "0 8px 24px rgba(0,0,0,0.5)",
                  }}>
                    {/* Users section */}
                    {userOptions.length > 0 && (
                      <>
                        <div style={{ padding: "0.375rem 0.75rem 0.25rem", fontSize: "0.6rem", fontWeight: 600, color: "var(--color-text-tertiary)", textTransform: "uppercase", letterSpacing: "0.06em" }}>Users</div>
                        {userOptions.map(([name, display]) => {
                          const checked = userFilters.has(name);
                          return (
                            <div key={name} onClick={() => {
                              setUserFilters((prev) => {
                                const next = new Set(prev);
                                if (next.has(name)) next.delete(name); else next.add(name);
                                return next;
                              });
                            }} style={{
                              display: "flex", alignItems: "center", gap: 10, padding: "0.35rem 0.75rem", fontSize: "0.8125rem",
                              cursor: "pointer", color: checked ? "var(--color-text)" : "var(--color-text-secondary)",
                              background: checked ? "var(--color-surface-2)" : "transparent",
                            }}
                              onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.background = "var(--color-surface-2)"; }}
                              onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.background = checked ? "var(--color-surface-2)" : "transparent"; }}
                            >
                              <span style={{
                                display: "inline-flex", alignItems: "center", justifyContent: "center",
                                width: 16, height: 16, borderRadius: 3, flexShrink: 0,
                                border: checked ? "1.5px solid var(--color-text-secondary)" : "1.5px solid var(--color-border-hover)",
                                background: checked ? "var(--color-surface-2)" : "transparent",
                              }}>
                                {checked && (
                                  <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="var(--color-text)" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12" /></svg>
                                )}
                              </span>
                              {display}
                            </div>
                          );
                        })}
                      </>
                    )}
                    {/* Divider */}
                    {userOptions.length > 0 && tagOptions.length > 0 && (
                      <div style={{ height: 1, background: "var(--color-border)", margin: "0.5rem 0" }} />
                    )}
                    {/* Tags section */}
                    {tagOptions.length > 0 && (
                      <>
                        <div style={{ padding: "0.375rem 0.75rem 0.375rem", fontSize: "0.6rem", fontWeight: 600, color: "var(--color-text-tertiary)", textTransform: "uppercase", letterSpacing: "0.06em" }}>Tags</div>
                        <div style={{ display: "flex", flexWrap: "wrap", gap: 6, padding: "0 0.625rem 0.25rem" }}>
                          {tagOptions.map((tag) => {
                            const checked = userFilters.has(tag);
                            return (
                              <button key={tag} onClick={() => {
                                setUserFilters((prev) => {
                                  const next = new Set(prev);
                                  if (next.has(tag)) next.delete(tag); else next.add(tag);
                                  return next;
                                });
                              }} style={{
                                fontSize: "0.6875rem", fontFamily: "monospace",
                                padding: "0.2rem 0.5rem", borderRadius: 999,
                                cursor: "pointer", whiteSpace: "nowrap",
                                border: checked ? "1px solid var(--color-text-secondary)" : "1px solid var(--color-border)",
                                background: checked ? "var(--color-surface-2)" : "transparent",
                                color: checked ? "var(--color-text)" : "var(--color-text-tertiary)",
                                transition: "all 0.15s ease",
                              }}
                                onMouseEnter={(e) => {
                                  if (!checked) {
                                    (e.currentTarget as HTMLElement).style.borderColor = "var(--color-border-hover)";
                                    (e.currentTarget as HTMLElement).style.color = "var(--color-text-secondary)";
                                  }
                                }}
                                onMouseLeave={(e) => {
                                  if (!checked) {
                                    (e.currentTarget as HTMLElement).style.borderColor = "var(--color-border)";
                                    (e.currentTarget as HTMLElement).style.color = "var(--color-text-tertiary)";
                                  }
                                }}
                              >
                                {tag}
                              </button>
                            );
                          })}
                        </div>
                      </>
                    )}
                    {/* Clear selection */}
                    {userFilters.size > 0 && (
                      <>
                        <div style={{ height: 1, background: "var(--color-border)", margin: "0.375rem 0" }} />
                        <button
                          onClick={() => setUserFilters(new Set())}
                          onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.background = "var(--color-surface-2)"; (e.currentTarget as HTMLElement).style.color = "var(--color-text-secondary)"; }}
                          onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.background = "transparent"; (e.currentTarget as HTMLElement).style.color = "var(--color-text-tertiary)"; }}
                          style={{
                            width: "100%", textAlign: "left", padding: "0.35rem 0.75rem", fontSize: "0.75rem",
                            border: "none", background: "transparent", color: "var(--color-text-tertiary)", cursor: "pointer",
                            transition: "all 0.15s ease",
                          }}
                        >
                          Clear selection
                        </button>
                      </>
                    )}
                  </div>
                </>
              )}
            </div>
          )}

          {/* Group by user */}
          <button
            onClick={() => setGroupByUser(!groupByUser)}
            title="Group by user"
            style={{
              fontSize: "0.75rem", padding: "0.375rem 0.625rem", flexShrink: 0,
              borderRadius: "var(--radius)", border: "1px solid var(--color-border)",
              background: groupByUser ? "rgba(255,255,255,0.08)" : "transparent",
              color: "var(--color-text-secondary)", cursor: "pointer",
            }}
          >
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ marginRight: 4, verticalAlign: "-2px" }}>
              <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" /><circle cx="9" cy="7" r="4" />
              <path d="M23 21v-2a4 4 0 0 0-3-3.87" /><path d="M16 3.13a4 4 0 0 1 0 7.75" />
            </svg>
            Group
          </button>

          {/* Clear filters */}
          <button
            onClick={hasActiveFilters ? () => { setSearch(""); setStatusFilter("all"); setOsFilter("all"); setUserFilters(new Set()); } : undefined}
            title="Clear all filters"
            style={{
              fontSize: "0.75rem", padding: "0.375rem 0.625rem", flexShrink: 0,
              borderRadius: "var(--radius)", border: "1px solid var(--color-border)",
              background: hasActiveFilters ? "var(--color-surface-2)" : "transparent",
              color: hasActiveFilters ? "var(--color-text)" : "var(--color-text-tertiary)",
              cursor: hasActiveFilters ? "pointer" : "default",
              opacity: hasActiveFilters ? 1 : 0.4,
            }}
          >
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" style={{ marginRight: 4, verticalAlign: "-1.5px" }}>
              <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
            </svg>
            Clear
          </button>
        </div>
      </div>

      {error && (
        <div className="alert error" style={{ marginBottom: "1rem" }}>
          {error}
        </div>
      )}

      {nodes.length === 0 ? (
        <div className="card" style={{ padding: 0 }}>
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
        </div>
      ) : filtered.length === 0 ? (
        <div className="card" style={{ padding: "2rem", textAlign: "center" }}>
          <p className="text-secondary">No machines match your filters.</p>
        </div>
      ) : groupByUser && grouped ? (
        // Grouped view
        <div style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
          {grouped.map(([key, group]) => (
            <div key={key}>
              <div className="flex items-center gap-2" style={{ marginBottom: "0.5rem" }}>
                <h3 style={{ fontSize: "0.9375rem", fontWeight: 600, margin: 0 }}>{group.label}</h3>
                <span className="text-xs text-tertiary">
                  {group.nodes.length} machine{group.nodes.length !== 1 ? "s" : ""}
                  {" · "}{group.nodes.filter(n => n.online).length} online
                </span>
              </div>
              <div className="card" style={{ padding: 0 }}>
                {renderTable(group.nodes)}
              </div>
            </div>
          ))}
        </div>
      ) : (
        // Flat view
        <div className="card" style={{ padding: 0 }}>
          {renderTable(filtered)}
        </div>
      )}
    </div>
  );
}
