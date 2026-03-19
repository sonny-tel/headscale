import { useState, useEffect, useCallback, useMemo } from "react";
import Editor from "react-simple-code-editor";
import Prism from "prismjs";
import "prismjs/components/prism-json";
import { getPolicy, setPolicy, getServerInfo, listUsers, getPolicyPerspective, type User, type PerspectiveResult } from "../api";
import { useAuth } from "../auth";
import { getPermissions } from "../permissions";
import { UnsavedFooter } from "../UnsavedFooter";

export function ACLPage() {
  const { user } = useAuth();
  const perms = getPermissions(user?.role);
  const [policy, setLocalPolicy] = useState("");
  const [savedPolicy, setSavedPolicy] = useState("");
  const [updatedAt, setUpdatedAt] = useState("");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [policyMode, setPolicyMode] = useState<string>("");
  const [viewMode, setViewMode] = useState<"editor" | "diff" | "perspective">("editor");

  // Perspective state
  const [users, setUsersLocal] = useState<User[]>([]);
  const [selectedUserId, setSelectedUserId] = useState<string>("");
  const [perspectiveLoading, setPerspectiveLoading] = useState(false);
  const [perspectiveData, setPerspectiveData] = useState<PerspectiveResult | null>(null);

  const isFileMode = policyMode === "file";
  const canEdit = perms.canWriteACL && !isFileMode;
  const hasChanges = policy !== savedPolicy;

  const DEFAULT_POLICY = JSON.stringify({
    acls: [
      { action: "accept", src: ["*"], dst: ["*:*"] },
    ],
    ssh: [
      { action: "accept", src: ["autogroup:member"], dst: ["autogroup:self"], users: ["root", "autogroup:nonroot"] },
      { action: "accept", src: ["autogroup:member"], dst: ["autogroup:tagged"], users: ["root", "autogroup:nonroot"] },
    ],
    nodeAttrs: [
      {
        target: ["autogroup:member"],
        attr: ["drive:share", "drive:access"],
      },
    ],
    grants: [
      {
        src: ["autogroup:member"],
        dst: ["autogroup:self"],
        app: {
          "tailscale.com/cap/drive": [{ shares: ["*"], access: "rw" }],
        },
      },
    ],
  }, null, 2);

  const loadPolicy = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [data, info] = await Promise.all([getPolicy(), getServerInfo()]);
      setPolicyMode(info.policyMode);
      if (data.policy) {
        setLocalPolicy(data.policy);
        setSavedPolicy(data.policy);
        setUpdatedAt(data.updated_at);
      } else {
        setLocalPolicy(DEFAULT_POLICY);
        setSavedPolicy("");
      }
    } catch (err) {
      try {
        const info = await getServerInfo();
        setPolicyMode(info.policyMode);
      } catch { /* ignore */ }
      setLocalPolicy(DEFAULT_POLICY);
      setSavedPolicy("");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadPolicy();
  }, [loadPolicy]);

  // Load users when perspective tab is opened
  useEffect(() => {
    if (viewMode === "perspective" && users.length === 0) {
      listUsers().then(setUsersLocal).catch(() => {});
    }
  }, [viewMode, users.length]);

  // Load perspective when user is selected
  useEffect(() => {
    if (!selectedUserId) {
      setPerspectiveData(null);
      return;
    }
    setPerspectiveLoading(true);
    getPolicyPerspective(selectedUserId)
      .then((data) => setPerspectiveData(data))
      .catch(() => setPerspectiveData(null))
      .finally(() => setPerspectiveLoading(false));
  }, [selectedUserId]);

  async function handleSave() {
    setError("");
    setSuccess("");
    setSaving(true);
    try {
      const data = await setPolicy(policy);
      setSavedPolicy(data.policy);
      setLocalPolicy(data.policy);
      setUpdatedAt(data.updated_at);
      setSuccess("Policy saved successfully");
      setTimeout(() => setSuccess(""), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save policy");
    } finally {
      setSaving(false);
    }
  }

  function handleReset() {
    setLocalPolicy(savedPolicy);
    setError("");
    setSuccess("");
  }

  // Compute diff lines
  const diffLines = useMemo(() => {
    if (!hasChanges) return [];
    const oldLines = savedPolicy.split("\n");
    const newLines = policy.split("\n");
    return computeSimpleDiff(oldLines, newLines);
  }, [savedPolicy, policy, hasChanges]);

  if (loading) {
    return (
      <div className="flex items-center justify-center" style={{ padding: "3rem" }}>
        <span className="spinner" />
      </div>
    );
  }

  const tabStyle = (active: boolean) => ({
    padding: "0.375rem 0.75rem",
    fontSize: "0.75rem",
    fontWeight: 500 as const,
    borderRadius: "var(--radius)",
    border: "1px solid " + (active ? "var(--color-primary)" : "var(--color-border)"),
    background: active ? "color-mix(in srgb, var(--color-primary) 12%, transparent)" : "transparent",
    color: active ? "var(--color-primary)" : "var(--color-text-secondary)",
    cursor: "pointer" as const,
    transition: "all 0.15s",
  });

  return (
    <div>
      <div className="flex items-center justify-between" style={{ marginBottom: "1rem" }}>
        <div>
          <h2 style={{ fontSize: "1.125rem", fontWeight: 600 }}>Access Controls</h2>
          <p className="text-sm text-secondary" style={{ marginTop: "0.25rem" }}>
            Define ACL policies in HuJSON format to control access between nodes.
            {updatedAt && (
              <span className="text-tertiary">
                {" "}Last updated {new Date(updatedAt).toLocaleString()}
              </span>
            )}
          </p>
        </div>
        <div className="flex items-center gap-2">
          {!canEdit && (
            <span className="text-sm text-tertiary" style={{ marginRight: "0.5rem" }}>
              {isFileMode ? "File-based policy (read-only)" : "Read-only"}
            </span>
          )}
          <button style={tabStyle(viewMode === "editor")} onClick={() => setViewMode("editor")}>
            <span className="flex items-center gap-1">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
              Editor
            </span>
          </button>
          <button
            style={tabStyle(viewMode === "diff")}
            onClick={() => setViewMode("diff")}
            title={hasChanges ? "" : "No changes to diff"}
          >
            <span className="flex items-center gap-1">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 3v18"/><path d="M18 9l-6-6-6 6"/></svg>
              Diff {hasChanges && <span style={{ width: 6, height: 6, borderRadius: "50%", background: "var(--color-warning)" }} />}
            </span>
          </button>
          <button style={tabStyle(viewMode === "perspective")} onClick={() => setViewMode("perspective")}>
            <span className="flex items-center gap-1">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
              Perspective
            </span>
          </button>
        </div>
      </div>

      {error && (
        <div className="alert error" style={{ marginBottom: "0.75rem" }}>
          {error}
        </div>
      )}
      {success && (
        <div className="alert" style={{ marginBottom: "0.75rem", borderColor: "var(--color-success, #22c55e)" }}>
          {success}
        </div>
      )}

      {/* Editor View */}
      {viewMode === "editor" && (
        <div
          style={{
            border: "1px solid var(--color-border)",
            borderRadius: "var(--radius-lg)",
            overflow: "hidden",
          }}
        >
          <div
            className="flex items-center justify-between"
            style={{
              padding: "0.5rem 0.75rem",
              background: "var(--color-surface)",
              borderBottom: "1px solid var(--color-border)",
              fontSize: "0.75rem",
              color: "var(--color-text-secondary)",
            }}
          >
            <span>policy.json</span>
            {hasChanges && (
              <span style={{ color: "var(--color-warning, #f59e0b)" }}>● Unsaved changes</span>
            )}
          </div>

          <Editor
            value={policy}
            onValueChange={canEdit ? setLocalPolicy : () => {}}
            highlight={(code) => Prism.highlight(code, Prism.languages.json, "json")}
            padding={16}
            className="policy-editor"
            disabled={!canEdit}
            style={{
              fontFamily: "var(--font-mono)",
              fontSize: "0.8125rem",
              lineHeight: 1.6,
              minHeight: 500,
              background: "var(--color-bg)",
              color: "var(--color-text)",
            }}
            textareaClassName="policy-editor-textarea"
          />
        </div>
      )}

      {/* Diff View */}
      {viewMode === "diff" && (
        <div
          style={{
            border: "1px solid var(--color-border)",
            borderRadius: "var(--radius-lg)",
            overflow: "hidden",
          }}
        >
          <div
            className="flex items-center justify-between"
            style={{
              padding: "0.5rem 0.75rem",
              background: "var(--color-surface)",
              borderBottom: "1px solid var(--color-border)",
              fontSize: "0.75rem",
              color: "var(--color-text-secondary)",
            }}
          >
            <span>Diff: saved → current</span>
            {!hasChanges && <span className="text-tertiary">No changes</span>}
          </div>

          <div style={{ minHeight: 500, background: "var(--color-bg)", overflow: "auto" }}>
            {!hasChanges ? (
              <div className="flex items-center justify-center text-sm text-tertiary" style={{ padding: "3rem" }}>
                No unsaved changes to show
              </div>
            ) : (
              <DiffView lines={diffLines} />
            )}
          </div>
        </div>
      )}

      {/* Perspective View */}
      {viewMode === "perspective" && (
        <div
          style={{
            border: "1px solid var(--color-border)",
            borderRadius: "var(--radius-lg)",
            overflow: "hidden",
          }}
        >
          <div
            className="flex items-center gap-3"
            style={{
              padding: "0.5rem 0.75rem",
              background: "var(--color-surface)",
              borderBottom: "1px solid var(--color-border)",
              fontSize: "0.75rem",
              color: "var(--color-text-secondary)",
            }}
          >
            <span>View as user:</span>
            <select
              value={selectedUserId}
              onChange={(e) => setSelectedUserId(e.target.value)}
              style={{
                padding: "0.25rem 0.5rem",
                fontSize: "0.75rem",
                borderRadius: "var(--radius)",
                border: "1px solid var(--color-border)",
                background: "var(--color-bg)",
                color: "var(--color-text)",
                minWidth: 200,
              }}
            >
              <option value="">Select a user…</option>
              {users.map((u) => (
                <option key={u.id} value={u.id}>
                  {u.display_name || u.name}{u.email ? ` (${u.email})` : ""}
                </option>
              ))}
            </select>
            {perspectiveLoading && <span className="spinner" style={{ width: 14, height: 14 }} />}
          </div>

          <div style={{ minHeight: 500, background: "var(--color-bg)", padding: "1rem" }}>
            {!selectedUserId ? (
              <div className="flex items-center justify-center text-sm text-tertiary" style={{ padding: "3rem" }}>
                Select a user to preview their access, SSH targets, and features under the current policy
              </div>
            ) : perspectiveLoading ? (
              <div className="flex items-center justify-center" style={{ padding: "3rem" }}>
                <span className="spinner" />
              </div>
            ) : perspectiveData ? (
              <UserPerspectivePanel data={perspectiveData} />
            ) : (
              <div className="flex items-center justify-center text-sm text-tertiary" style={{ padding: "3rem" }}>
                Failed to load perspective data
              </div>
            )}
          </div>
        </div>
      )}

      <UnsavedFooter
        visible={canEdit && hasChanges}
        onDiscard={handleReset}
        onSave={handleSave}
        saving={saving}
        saveLabel="Save policy"
      />
    </div>
  );
}

/* ── Simple line diff ────────────────────────────────────────────── */

type DiffLine = { type: "same" | "add" | "del"; text: string; oldNum?: number; newNum?: number };

function computeSimpleDiff(oldLines: string[], newLines: string[]): DiffLine[] {
  // Myers-style LCS via DP for reasonable-sized policies
  const N = oldLines.length;
  const M = newLines.length;
  // Build DP table
  const dp: number[][] = Array.from({ length: N + 1 }, () => new Array(M + 1).fill(0));
  for (let i = N - 1; i >= 0; i--) {
    for (let j = M - 1; j >= 0; j--) {
      if (oldLines[i] === newLines[j]) {
        dp[i][j] = dp[i + 1][j + 1] + 1;
      } else {
        dp[i][j] = Math.max(dp[i + 1][j], dp[i][j + 1]);
      }
    }
  }
  const result: DiffLine[] = [];
  let i = 0, j = 0;
  while (i < N || j < M) {
    if (i < N && j < M && oldLines[i] === newLines[j]) {
      result.push({ type: "same", text: oldLines[i], oldNum: i + 1, newNum: j + 1 });
      i++; j++;
    } else if (j < M && (i >= N || dp[i][j + 1] >= dp[i + 1][j])) {
      result.push({ type: "add", text: newLines[j], newNum: j + 1 });
      j++;
    } else {
      result.push({ type: "del", text: oldLines[i], oldNum: i + 1 });
      i++;
    }
  }
  return result;
}

/* ── Diff view component ─────────────────────────────────────────── */

function DiffView({ lines }: { lines: DiffLine[] }) {
  return (
    <pre
      style={{
        margin: 0,
        padding: "0.75rem 0",
        fontFamily: "var(--font-mono)",
        fontSize: "0.8125rem",
        lineHeight: 1.6,
      }}
    >
      {lines.map((line, idx) => {
        const bg =
          line.type === "add"
            ? "color-mix(in srgb, #22c55e 10%, transparent)"
            : line.type === "del"
            ? "color-mix(in srgb, #ef4444 10%, transparent)"
            : "transparent";
        const col =
          line.type === "add"
            ? "#4ade80"
            : line.type === "del"
            ? "#f87171"
            : "var(--color-text-secondary)";
        const prefix = line.type === "add" ? "+" : line.type === "del" ? "-" : " ";
        return (
          <div
            key={idx}
            style={{
              display: "flex",
              background: bg,
              paddingLeft: "0.75rem",
              paddingRight: "0.75rem",
            }}
          >
            <span style={{ width: 35, textAlign: "right", color: "var(--color-text-tertiary)", userSelect: "none", flexShrink: 0, paddingRight: 8 }}>
              {line.oldNum ?? ""}
            </span>
            <span style={{ width: 35, textAlign: "right", color: "var(--color-text-tertiary)", userSelect: "none", flexShrink: 0, paddingRight: 8 }}>
              {line.newNum ?? ""}
            </span>
            <span style={{ color: col, userSelect: "none", width: 16, flexShrink: 0 }}>{prefix}</span>
            <span style={{ color: col, whiteSpace: "pre" }}>{line.text}</span>
          </div>
        );
      })}
    </pre>
  );
}

/* ── User perspective panel ───────────────────────────────────────── */

function UserPerspectivePanel({ data }: { data: PerspectiveResult }) {
  const [expandedNode, setExpandedNode] = useState<number | null>(
    data.nodes.length === 1 ? data.nodes[0].id : null,
  );
  const { user, nodes } = data;

  if (nodes.length === 0) {
    return (
      <div className="flex items-center justify-center text-sm text-tertiary" style={{ padding: "3rem" }}>
        This user has no registered nodes
      </div>
    );
  }

  // Aggregate stats across all user's nodes
  const totalPeers = new Set(nodes.flatMap((n) => n.peers.map((p) => p.id))).size;
  const totalSSH = new Set(nodes.flatMap((n) => n.ssh_targets.map((t) => t.node_id))).size;
  const allFeatures = [...new Set(nodes.flatMap((n) => n.features))];

  const featureLabels: Record<string, string> = {
    "drive:share": "Taildrive Share",
    "drive:access": "Taildrive Access",
    "funnel": "Funnel",
    "ssh": "SSH",
    "tailscale.com/cap/drive": "Taildrive",
    "tailscale.com/cap/funnel": "Funnel",
  };

  const sectionHeader: React.CSSProperties = {
    fontSize: "0.6875rem",
    fontWeight: 600,
    textTransform: "uppercase",
    letterSpacing: "0.05em",
    color: "var(--color-text-tertiary)",
    padding: "0.5rem 0.75rem 0.25rem",
  };

  const thStyle: React.CSSProperties = {
    padding: "0.375rem 0.75rem",
    textAlign: "left",
    fontWeight: 500,
    color: "var(--color-text-secondary)",
    fontSize: "0.75rem",
  };

  const tdStyle: React.CSSProperties = {
    padding: "0.375rem 0.75rem",
    fontSize: "0.8125rem",
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
      {/* User summary banner */}
      <div
        className="flex items-center gap-4"
        style={{
          padding: "0.75rem",
          background: "var(--color-surface)",
          borderRadius: "var(--radius)",
          border: "1px solid var(--color-border)",
        }}
      >
        <div style={{ flex: 1 }}>
          <div className="flex items-center gap-2">
            <span style={{ fontWeight: 600 }}>{user.display_name || user.name}</span>
            {user.email && <span className="text-sm text-tertiary">{user.email}</span>}
          </div>
          <div className="text-sm text-secondary" style={{ marginTop: "0.25rem" }}>
            {nodes.length} node{nodes.length !== 1 ? "s" : ""}
          </div>
        </div>
        <div className="flex items-center gap-4 text-sm">
          <div style={{ textAlign: "center" }}>
            <div style={{ fontWeight: 600, color: "var(--color-success)" }}>{totalPeers}</div>
            <div className="text-tertiary" style={{ fontSize: "0.6875rem" }}>peers</div>
          </div>
          <div style={{ textAlign: "center" }}>
            <div style={{ fontWeight: 600, color: "var(--color-primary)" }}>{totalSSH}</div>
            <div className="text-tertiary" style={{ fontSize: "0.6875rem" }}>SSH targets</div>
          </div>
          <div style={{ textAlign: "center" }}>
            <div style={{ fontWeight: 600, color: "var(--color-warning)" }}>{allFeatures.length}</div>
            <div className="text-tertiary" style={{ fontSize: "0.6875rem" }}>features</div>
          </div>
        </div>
      </div>

      {/* Features summary */}
      {allFeatures.length > 0 && (
        <div className="flex items-center gap-2" style={{ flexWrap: "wrap" }}>
          <span className="text-sm text-secondary" style={{ marginRight: "0.25rem" }}>Features:</span>
          {allFeatures.map((f) => (
            <span
              key={f}
              style={{
                padding: "0.125rem 0.5rem",
                fontSize: "0.6875rem",
                borderRadius: "9999px",
                background: "color-mix(in srgb, var(--color-primary) 12%, transparent)",
                color: "var(--color-primary)",
                border: "1px solid color-mix(in srgb, var(--color-primary) 25%, transparent)",
              }}
            >
              {featureLabels[f] || f}
            </span>
          ))}
        </div>
      )}

      {/* Per-node breakdown */}
      {nodes.map((node) => {
        const isExpanded = expandedNode === node.id;
        const accessCount = node.peers.filter((p) => p.can_access).length;
        const reachCount = node.peers.filter((p) => p.accepted_by).length;

        return (
          <div
            key={node.id}
            style={{
              border: "1px solid var(--color-border)",
              borderRadius: "var(--radius)",
              overflow: "hidden",
            }}
          >
            {/* Node row — clickable header */}
            <div
              onClick={() => setExpandedNode(isExpanded ? null : node.id)}
              className="flex items-center gap-3"
              style={{
                padding: "0.625rem 0.75rem",
                background: "var(--color-surface)",
                cursor: "pointer",
                userSelect: "none",
              }}
            >
              <svg
                width="12" height="12" viewBox="0 0 24 24" fill="none"
                stroke="currentColor" strokeWidth="2"
                style={{
                  transform: isExpanded ? "rotate(90deg)" : "rotate(0deg)",
                  transition: "transform 0.15s",
                  flexShrink: 0,
                  color: "var(--color-text-tertiary)",
                }}
              >
                <path d="M9 18l6-6-6-6" />
              </svg>
              <span
                style={{
                  width: 7,
                  height: 7,
                  borderRadius: "50%",
                  background: node.online ? "var(--color-success)" : "var(--color-text-tertiary)",
                  flexShrink: 0,
                }}
              />
              <span style={{ fontWeight: 500, fontSize: "0.8125rem" }}>{node.name}</span>
              <span className="text-sm text-secondary" style={{ fontFamily: "var(--font-mono)", fontSize: "0.75rem" }}>
                {node.ips?.[0]}
              </span>
              {node.tags && node.tags.length > 0 && (
                <span className="text-sm text-tertiary">{node.tags.join(", ")}</span>
              )}
              <div className="flex items-center gap-3 text-sm" style={{ marginLeft: "auto" }}>
                <span><span style={{ color: "var(--color-success)", fontWeight: 500 }}>{accessCount}</span> <span className="text-tertiary">out</span></span>
                <span><span style={{ color: "var(--color-primary)", fontWeight: 500 }}>{reachCount}</span> <span className="text-tertiary">in</span></span>
                {node.ssh_targets.length > 0 && (
                  <span><span style={{ color: "var(--color-warning)", fontWeight: 500 }}>{node.ssh_targets.length}</span> <span className="text-tertiary">SSH</span></span>
                )}
              </div>
            </div>

            {/* Expanded detail */}
            {isExpanded && (
              <div style={{ borderTop: "1px solid var(--color-border)" }}>
                {/* Network access */}
                <div style={sectionHeader}>Network Access</div>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr style={{ borderBottom: "1px solid var(--color-border)" }}>
                      <th style={thStyle}>Peer</th>
                      <th style={thStyle}>IP</th>
                      <th style={thStyle}>Owner</th>
                      <th style={{ ...thStyle, textAlign: "center" }}>Can Access →</th>
                      <th style={{ ...thStyle, textAlign: "center" }}>← Can Reach</th>
                    </tr>
                  </thead>
                  <tbody>
                    {node.peers.length === 0 ? (
                      <tr>
                        <td colSpan={5} className="text-sm text-tertiary" style={{ padding: "1.5rem", textAlign: "center" }}>
                          No peers visible under this policy
                        </td>
                      </tr>
                    ) : (
                      node.peers.map((p) => (
                        <tr key={p.id} style={{ borderBottom: "1px solid var(--color-border)" }}>
                          <td style={tdStyle}>
                            <div className="flex items-center gap-2">
                              <span style={{ width: 6, height: 6, borderRadius: "50%", background: p.online ? "var(--color-success)" : "var(--color-text-tertiary)", flexShrink: 0 }} />
                              {p.name}
                            </div>
                          </td>
                          <td style={{ ...tdStyle, fontFamily: "var(--font-mono)", fontSize: "0.75rem", color: "var(--color-text-secondary)" }}>
                            {p.ips?.[0] || "—"}
                          </td>
                          <td style={{ ...tdStyle, color: "var(--color-text-secondary)" }}>
                            {p.tags?.length ? p.tags.join(", ") : p.user || "—"}
                          </td>
                          <td style={{ ...tdStyle, textAlign: "center" }}>
                            {p.can_access
                              ? <span style={{ color: "var(--color-success)" }}>✓</span>
                              : <span style={{ color: "var(--color-text-tertiary)" }}>✗</span>}
                          </td>
                          <td style={{ ...tdStyle, textAlign: "center" }}>
                            {p.accepted_by
                              ? <span style={{ color: "var(--color-primary)" }}>✓</span>
                              : <span style={{ color: "var(--color-text-tertiary)" }}>✗</span>}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>

                {/* SSH targets */}
                {node.ssh_targets.length > 0 && (
                  <>
                    <div style={sectionHeader}>SSH Access</div>
                    <table style={{ width: "100%", borderCollapse: "collapse" }}>
                      <thead>
                        <tr style={{ borderBottom: "1px solid var(--color-border)" }}>
                          <th style={thStyle}>Target</th>
                          <th style={thStyle}>IP</th>
                          <th style={thStyle}>As Users</th>
                          <th style={thStyle}>Action</th>
                        </tr>
                      </thead>
                      <tbody>
                        {node.ssh_targets.map((t) => (
                          <tr key={t.node_id} style={{ borderBottom: "1px solid var(--color-border)" }}>
                            <td style={tdStyle}>{t.node_name}</td>
                            <td style={{ ...tdStyle, fontFamily: "var(--font-mono)", fontSize: "0.75rem", color: "var(--color-text-secondary)" }}>
                              {t.node_ips?.[0] || "—"}
                            </td>
                            <td style={{ ...tdStyle, fontFamily: "var(--font-mono)", fontSize: "0.75rem" }}>
                              {t.ssh_users.join(", ") || "*"}
                            </td>
                            <td style={tdStyle}>
                              <span
                                style={{
                                  padding: "0.125rem 0.375rem",
                                  fontSize: "0.6875rem",
                                  borderRadius: "var(--radius)",
                                  background: t.action === "accept"
                                    ? "color-mix(in srgb, var(--color-success) 12%, transparent)"
                                    : "color-mix(in srgb, var(--color-warning) 12%, transparent)",
                                  color: t.action === "accept" ? "var(--color-success)" : "var(--color-warning)",
                                }}
                              >
                                {t.action}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </>
                )}

                {/* Filter rules */}
                {node.filter_rules.length > 0 && (
                  <>
                    <div style={sectionHeader}>Filter Rules</div>
                    <div style={{ fontSize: "0.75rem", fontFamily: "var(--font-mono)" }}>
                      {node.filter_rules.map((rule, idx) => (
                        <div
                          key={idx}
                          className="flex items-start gap-3"
                          style={{
                            padding: "0.375rem 0.75rem",
                            borderBottom: idx < node.filter_rules.length - 1 ? "1px solid var(--color-border)" : "none",
                            background: idx % 2 === 0 ? "var(--color-surface)" : "transparent",
                          }}
                        >
                          <div>
                            <span className="text-tertiary">src: </span>
                            {rule.src_ips.join(", ")}
                          </div>
                          <span className="text-tertiary">→</span>
                          <div>
                            <span className="text-tertiary">dst: </span>
                            {rule.dst_ports.join(", ")}
                          </div>
                        </div>
                      ))}
                    </div>
                  </>
                )}

                {/* Features for this node */}
                {node.features.length > 0 && (
                  <>
                    <div style={sectionHeader}>Features & Capabilities</div>
                    <div className="flex items-center gap-2" style={{ padding: "0.375rem 0.75rem 0.75rem", flexWrap: "wrap" }}>
                      {node.features.map((f) => (
                        <span
                          key={f}
                          style={{
                            padding: "0.125rem 0.5rem",
                            fontSize: "0.6875rem",
                            borderRadius: "9999px",
                            background: "color-mix(in srgb, var(--color-primary) 12%, transparent)",
                            color: "var(--color-primary)",
                            border: "1px solid color-mix(in srgb, var(--color-primary) 25%, transparent)",
                          }}
                        >
                          {featureLabels[f] || f}
                        </span>
                      ))}
                    </div>
                  </>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
