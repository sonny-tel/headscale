import { useState, useEffect, useMemo, useCallback } from "react";
import {
  getDiscoveredServices,
  getAdvertisedServices,
  createAdvertisedService,
  updateAdvertisedService,
  deleteAdvertisedService,
  listNodes,
  type DiscoveredEndpoint,
  type DiscoveredServicesResponse,
  type AdvertisedService,
  type Node,
} from "../api";
import { useAuth } from "../auth";
import { getPermissions } from "../permissions";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function serviceIcon(type: string): string {
  switch (type) {
    case "SSH": return "⌨";
    case "HTTP": case "HTTPS": return "🌐";
    case "RDP": return "🖥";
    case "VNC": return "🖥";
    case "DNS": return "📡";
    case "MySQL": case "PostgreSQL": case "Redis": return "🗄";
    default: return "🔌";
  }
}

function actionForService(ep: DiscoveredEndpoint) {
  if (ep.type === "SSH") {
    return { label: "Copy ssh command", value: `ssh ${ep.ip}` };
  }
  if (ep.type === "HTTP" || ep.type === "HTTPS") {
    const proto = ep.type === "HTTPS" ? "https" : "http";
    const portSuffix = (ep.type === "HTTP" && ep.port === 80) || (ep.type === "HTTPS" && ep.port === 443) ? "" : `:${ep.port}`;
    return { label: "Open", value: `${proto}://${ep.ip}${portSuffix}` };
  }
  if (ep.type === "RDP") {
    return { label: "Copy address", value: `${ep.ip}:${ep.port}` };
  }
  return null;
}

// ─── Discovered Tab ───────────────────────────────────────────────────────────

function DiscoveredTab() {
  const [data, setData] = useState<DiscoveredServicesResponse | null>(null);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");
  const [userFilter, setUserFilter] = useState("all");
  const [copied, setCopied] = useState<string | null>(null);

  useEffect(() => {
    getDiscoveredServices()
      .then(setData)
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, []);

  const endpoints = data?.endpoints ?? [];

  // Unique types and users for filters
  const types = useMemo(() => [...new Set(endpoints.map((e) => e.type))].sort(), [endpoints]);
  const users = useMemo(() => [...new Set(endpoints.map((e) => e.user))].sort(), [endpoints]);

  // Filter
  const filtered = useMemo(() => {
    return endpoints.filter((ep) => {
      if (typeFilter !== "all" && ep.type !== typeFilter) return false;
      if (userFilter !== "all" && ep.user !== userFilter) return false;
      if (search) {
        const q = search.toLowerCase();
        return (
          ep.service_name.toLowerCase().includes(q) ||
          ep.machine.toLowerCase().includes(q) ||
          ep.ip.includes(q) ||
          ep.type.toLowerCase().includes(q) ||
          ep.user.toLowerCase().includes(q) ||
          String(ep.port).includes(q)
        );
      }
      return true;
    });
  }, [endpoints, typeFilter, userFilter, search]);

  if (error) {
    return <p style={{ color: "var(--color-danger)" }}>Failed to load services: {error}</p>;
  }
  if (!data) {
    return <div style={{ padding: "2rem", textAlign: "center" }}><span className="spinner" /></div>;
  }

  if (!data.collect_services) {
    return (
      <div style={{ padding: "3rem 2rem", textAlign: "center" }}>
        <p style={{ fontSize: "1rem", fontWeight: 500, marginBottom: "0.5rem" }}>Service collection is disabled</p>
        <p className="text-sm text-secondary" style={{ maxWidth: 480, margin: "0 auto", lineHeight: 1.6 }}>
          Enable <code style={{ fontSize: "0.8rem" }}>collect_services: true</code> in your headscale configuration to discover services running on your network nodes.
        </p>
      </div>
    );
  }

  if (endpoints.length === 0) {
    return (
      <div style={{ padding: "3rem 2rem", textAlign: "center" }}>
        <p style={{ fontSize: "1rem", fontWeight: 500, marginBottom: "0.5rem" }}>No services discovered</p>
        <p className="text-sm text-secondary" style={{ maxWidth: 480, margin: "0 auto", lineHeight: 1.6 }}>
          Service collection is enabled, but no online nodes are reporting open services yet. Services will appear here once nodes report their open ports.
        </p>
      </div>
    );
  }

  function handleAction(ep: DiscoveredEndpoint) {
    const action = actionForService(ep);
    if (!action) return;
    if (ep.type === "HTTP" || ep.type === "HTTPS") {
      window.open(action.value, "_blank", "noopener");
    } else {
      navigator.clipboard.writeText(action.value);
      setCopied(`${ep.ip}:${ep.port}`);
      setTimeout(() => setCopied(null), 1500);
    }
  }

  return (
    <div>
      {/* Toolbar */}
      <div className="flex items-center gap-3" style={{ marginBottom: "1rem", flexWrap: "wrap" }}>
        <input
          type="text"
          placeholder="Search services..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{
            padding: "0.5rem 0.75rem",
            fontSize: "0.8125rem",
            border: "1px solid var(--color-border)",
            borderRadius: "var(--radius)",
            background: "var(--color-surface)",
            color: "var(--color-text)",
            flex: "1 1 200px",
            minWidth: 180,
          }}
        />
        <select
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
          style={{
            padding: "0.5rem 0.75rem",
            fontSize: "0.8125rem",
            border: "1px solid var(--color-border)",
            borderRadius: "var(--radius)",
            background: "var(--color-surface)",
            color: "var(--color-text)",
          }}
        >
          <option value="all">All types</option>
          {types.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
        <select
          value={userFilter}
          onChange={(e) => setUserFilter(e.target.value)}
          style={{
            padding: "0.5rem 0.75rem",
            fontSize: "0.8125rem",
            border: "1px solid var(--color-border)",
            borderRadius: "var(--radius)",
            background: "var(--color-surface)",
            color: "var(--color-text)",
          }}
        >
          <option value="all">All users</option>
          {users.map((u) => <option key={u} value={u}>{u}</option>)}
        </select>
        <span className="text-sm text-secondary">
          {filtered.length} endpoint{filtered.length !== 1 ? "s" : ""}
        </span>
      </div>

      {/* Table */}
      <div className="card" style={{ overflow: "auto" }}>
        <table style={{ width: "100%" }}>
          <thead>
            <tr>
              <th>Service</th>
              <th>Type</th>
              <th>Machine</th>
              <th>User</th>
              <th style={{ width: 120 }}></th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((ep) => {
              const action = actionForService(ep);
              const isCopied = copied === `${ep.ip}:${ep.port}`;
              return (
                <tr key={`${ep.node_id}-${ep.ip}-${ep.port}-${ep.proto}`}>
                  <td>
                    <div className="flex items-center gap-2">
                      <span style={{ fontSize: "1rem" }}>{serviceIcon(ep.type)}</span>
                      <div>
                        <div style={{ fontWeight: 500, fontSize: "0.875rem" }}>{ep.service_name}</div>
                        <div className="flex gap-1" style={{ marginTop: 2 }}>
                          <span className="badge tag" style={{ fontSize: "0.6875rem" }}>{ep.ip}:{ep.port}</span>
                          <span className="badge" style={{ fontSize: "0.6875rem", background: "var(--color-surface)", color: "var(--color-text-tertiary)", border: "1px solid var(--color-border)" }}>{ep.proto.toUpperCase()}</span>
                        </div>
                      </div>
                    </div>
                  </td>
                  <td>
                    <span className="badge tag">{ep.type}</span>
                  </td>
                  <td className="text-sm">{ep.machine}</td>
                  <td className="text-sm text-secondary">{ep.user}</td>
                  <td style={{ textAlign: "right" }}>
                    {action && (
                      <button
                        onClick={() => handleAction(ep)}
                        style={{
                          padding: "0.25rem 0.5rem",
                          fontSize: "0.75rem",
                          color: "var(--color-primary)",
                          background: "transparent",
                          border: "1px solid var(--color-primary)",
                          borderRadius: "var(--radius)",
                          cursor: "pointer",
                          whiteSpace: "nowrap",
                        }}
                      >
                        {isCopied ? "Copied!" : action.label}
                      </button>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ─── Advertised Tab ───────────────────────────────────────────────────────────

function AdvertisedTab() {
  const { user } = useAuth();
  const perms = getPermissions(user?.role);
  const [services, setServices] = useState<AdvertisedService[]>([]);
  const [nodes, setNodes] = useState<Node[]>([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  // Form state
  const [showForm, setShowForm] = useState(false);
  const [editId, setEditId] = useState<number | null>(null);
  const [formNodeId, setFormNodeId] = useState<number>(0);
  const [formName, setFormName] = useState("");
  const [formProto, setFormProto] = useState("tcp");
  const [formPort, setFormPort] = useState("");
  const [saving, setSaving] = useState(false);

  const refresh = useCallback(() => {
    setLoading(true);
    Promise.all([getAdvertisedServices(), listNodes()])
      .then(([svcs, ns]) => {
        setServices(svcs);
        setNodes(ns);
        setError("");
      })
      .catch((e) => setError(e instanceof Error ? e.message : String(e)))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  function resetForm() {
    setShowForm(false);
    setEditId(null);
    setFormNodeId(0);
    setFormName("");
    setFormProto("tcp");
    setFormPort("");
  }

  function startEdit(svc: AdvertisedService) {
    setEditId(svc.id);
    setFormNodeId(svc.node_id);
    setFormName(svc.name);
    setFormProto(svc.proto);
    setFormPort(String(svc.port));
    setShowForm(true);
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const port = parseInt(formPort, 10);
    if (!formName || !port || port < 1 || port > 65535) return;
    setSaving(true);
    try {
      if (editId !== null) {
        await updateAdvertisedService(editId, { name: formName, proto: formProto, port });
      } else {
        if (!formNodeId) return;
        await createAdvertisedService({ node_id: formNodeId, name: formName, proto: formProto, port });
      }
      resetForm();
      refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete(id: number) {
    if (!confirm("Delete this advertised service?")) return;
    try {
      await deleteAdvertisedService(id);
      refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  if (loading && services.length === 0) {
    return <div style={{ padding: "2rem", textAlign: "center" }}><span className="spinner" /></div>;
  }

  if (error) {
    return <p style={{ color: "var(--color-danger)" }}>Failed to load advertised services: {error}</p>;
  }

  const inputStyle: React.CSSProperties = {
    padding: "0.5rem 0.75rem",
    fontSize: "0.8125rem",
    border: "1px solid var(--color-border)",
    borderRadius: "var(--radius)",
    background: "var(--color-surface)",
    color: "var(--color-text)",
  };

  return (
    <div>
      {/* Add button */}
      {perms.canWriteServices && !showForm && (
        <div style={{ marginBottom: "1rem" }}>
          <button
            onClick={() => { resetForm(); setShowForm(true); }}
            className="btn btn-primary"
            style={{ fontSize: "0.8125rem" }}
          >
            + Add Service
          </button>
        </div>
      )}

      {/* Inline form */}
      {showForm && (
        <form
          onSubmit={handleSubmit}
          className="card"
          style={{ padding: "1rem", marginBottom: "1rem" }}
        >
          <div className="flex items-center gap-3" style={{ flexWrap: "wrap" }}>
            {editId === null && (
              <select
                value={formNodeId}
                onChange={(e) => setFormNodeId(Number(e.target.value))}
                required
                style={{ ...inputStyle, minWidth: 160 }}
              >
                <option value={0} disabled>Select machine...</option>
                {nodes.map((n) => (
                  <option key={n.id} value={n.id}>{n.given_name || n.name}</option>
                ))}
              </select>
            )}
            <input
              placeholder="Service name"
              value={formName}
              onChange={(e) => setFormName(e.target.value)}
              required
              style={{ ...inputStyle, flex: "1 1 140px", minWidth: 120 }}
            />
            <select
              value={formProto}
              onChange={(e) => setFormProto(e.target.value)}
              style={{ ...inputStyle, width: 80 }}
            >
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
            </select>
            <div className="port-stepper" style={{
              display: "inline-flex",
              alignItems: "stretch",
              border: "1px solid var(--color-border)",
              borderRadius: "var(--radius)",
              background: "var(--color-surface)",
              overflow: "hidden",
              width: 110,
            }}>
              <input
                type="text"
                inputMode="numeric"
                pattern="[0-9]*"
                placeholder="Port"
                value={formPort}
                onChange={(e) => {
                  const v = e.target.value.replace(/\D/g, "");
                  if (v === "" || (Number(v) >= 0 && Number(v) <= 65535)) setFormPort(v);
                }}
                required
                style={{
                  flex: 1,
                  minWidth: 0,
                  padding: "0.5rem 0.5rem",
                  fontSize: "0.8125rem",
                  background: "transparent",
                  color: "var(--color-text)",
                  border: "none",
                  outline: "none",
                }}
              />
              <div style={{
                display: "flex",
                flexDirection: "column",
                borderLeft: "1px solid var(--color-border)",
              }}>
                <button type="button" tabIndex={-1} onClick={() => {
                  const n = Math.min(65535, (parseInt(formPort, 10) || 0) + 1);
                  setFormPort(String(n));
                }} style={{
                  flex: 1,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  width: 22,
                  padding: 0,
                  background: "transparent",
                  border: "none",
                  borderBottom: "1px solid var(--color-border)",
                  color: "var(--color-text-secondary)",
                  cursor: "pointer",
                  fontSize: "0.5rem",
                  lineHeight: 1,
                }}>▲</button>
                <button type="button" tabIndex={-1} onClick={() => {
                  const n = Math.max(1, (parseInt(formPort, 10) || 0) - 1);
                  setFormPort(String(n));
                }} style={{
                  flex: 1,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  width: 22,
                  padding: 0,
                  background: "transparent",
                  border: "none",
                  color: "var(--color-text-secondary)",
                  cursor: "pointer",
                  fontSize: "0.5rem",
                  lineHeight: 1,
                }}>▼</button>
              </div>
            </div>
            <button
              type="submit"
              className="btn btn-primary"
              disabled={saving}
              style={{ fontSize: "0.8125rem" }}
            >
              {saving ? "Saving..." : editId !== null ? "Update" : "Create"}
            </button>
            <button
              type="button"
              onClick={resetForm}
              style={{
                fontSize: "0.8125rem",
                padding: "0.5rem 0.75rem",
                background: "transparent",
                color: "var(--color-text-secondary)",
                border: "1px solid var(--color-border)",
                borderRadius: "var(--radius)",
                cursor: "pointer",
              }}
            >
              Cancel
            </button>
          </div>
        </form>
      )}

      {/* Table */}
      {services.length === 0 ? (
        <div style={{ padding: "3rem 2rem", textAlign: "center" }}>
          <p style={{ fontSize: "1rem", fontWeight: 500, marginBottom: "0.5rem" }}>No advertised services</p>
          <p className="text-sm text-secondary" style={{ maxWidth: 480, margin: "0 auto", lineHeight: 1.6 }}>
            Manually register services running on your nodes. Click "Add Service" above to get started.
          </p>
        </div>
      ) : (
        <div className="card" style={{ overflow: "auto" }}>
          <table style={{ width: "100%" }}>
            <thead>
              <tr>
                <th>Service</th>
                <th>Protocol</th>
                <th>Port</th>
                <th>Machine</th>
                {perms.canWriteServices && <th style={{ width: 120 }}></th>}
              </tr>
            </thead>
            <tbody>
              {services.map((svc) => (
                <tr key={svc.id}>
                  <td>
                    <span style={{ fontWeight: 500, fontSize: "0.875rem" }}>{svc.name}</span>
                  </td>
                  <td>
                    <span className="badge" style={{ fontSize: "0.6875rem", background: "var(--color-surface)", color: "var(--color-text-tertiary)", border: "1px solid var(--color-border)" }}>
                      {svc.proto.toUpperCase()}
                    </span>
                  </td>
                  <td className="text-sm">{svc.port}</td>
                  <td className="text-sm">{svc.machine_name || `Node ${svc.node_id}`}</td>
                  {perms.canWriteServices && (
                    <td style={{ textAlign: "right" }}>
                      <div className="flex items-center gap-1" style={{ justifyContent: "flex-end" }}>
                        <button
                          onClick={() => startEdit(svc)}
                          style={{
                            padding: "0.25rem 0.5rem",
                            fontSize: "0.75rem",
                            color: "var(--color-primary)",
                            background: "transparent",
                            border: "1px solid var(--color-primary)",
                            borderRadius: "var(--radius)",
                            cursor: "pointer",
                          }}
                        >
                          Edit
                        </button>
                        <button
                          onClick={() => handleDelete(svc.id)}
                          style={{
                            padding: "0.25rem 0.5rem",
                            fontSize: "0.75rem",
                            color: "var(--color-danger, #e53e3e)",
                            background: "transparent",
                            border: "1px solid var(--color-danger, #e53e3e)",
                            borderRadius: "var(--radius)",
                            cursor: "pointer",
                          }}
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ─── Services Page ────────────────────────────────────────────────────────────

const tabs = [
  { id: "discovered", label: "Discovered" },
  { id: "advertised", label: "Advertised" },
] as const;

type TabId = (typeof tabs)[number]["id"];

export function ServicesPage() {
  const { user } = useAuth();
  const perms = getPermissions(user?.role);
  const initial = (tabs.find(t => t.id === window.location.hash.replace(/^#/, ""))?.id ?? "discovered") as TabId;
  const [activeTab, setActiveTab] = useState<TabId>(initial);

  const switchTab = (id: TabId) => {
    setActiveTab(id);
    window.history.replaceState(null, "", `#${id}`);
  };

  if (!perms.canViewServices) {
    return (
      <div style={{ padding: "3rem 2rem", textAlign: "center" }}>
        <p className="text-secondary">You do not have permission to view services.</p>
      </div>
    );
  }

  return (
    <div>
      <div style={{ marginBottom: "1rem" }}>
        <h2 style={{ fontSize: "1.125rem", fontWeight: 600 }}>Services</h2>
      </div>

      {/* Tab bar */}
      <div
        className="flex items-center gap-1"
        style={{
          borderBottom: "1px solid var(--color-border)",
          marginBottom: "1.5rem",
        }}
      >
        {tabs.map((tab) => {
          const active = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => switchTab(tab.id)}
              style={{
                padding: "0.5rem 0.75rem",
                fontSize: "0.8125rem",
                fontWeight: active ? 500 : 400,
                color: active ? "var(--color-text)" : "var(--color-text-secondary)",
                background: "transparent",
                border: "none",
                borderBottom: active ? "2px solid var(--color-primary)" : "2px solid transparent",
                cursor: "pointer",
                marginBottom: -1,
                transition: "all var(--transition)",
              }}
            >
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* Tab content */}
      {activeTab === "discovered" && <DiscoveredTab />}
      {activeTab === "advertised" && <AdvertisedTab />}
    </div>
  );
}
