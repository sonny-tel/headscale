import { useState, useEffect, useCallback } from "react";
import Editor from "react-simple-code-editor";
import Prism from "prismjs";
import "prismjs/components/prism-json";
import { getPolicy, setPolicy, getServerInfo } from "../api";
import { useAuth } from "../auth";
import { getPermissions } from "../permissions";

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
      // If fetching policy fails (e.g. no policy set yet in database mode),
      // pre-populate with the default so the user can save it.
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

  if (loading) {
    return (
      <div className="flex items-center justify-center" style={{ padding: "3rem" }}>
        <span className="spinner" />
      </div>
    );
  }

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
          {canEdit && hasChanges && (
            <button className="ghost sm" onClick={handleReset}>
              Discard
            </button>
          )}
          {canEdit && (
            <button
              onClick={handleSave}
              disabled={saving || !hasChanges}
              style={{
                padding: "0.375rem 1rem",
                background: hasChanges ? "var(--color-primary)" : "var(--color-surface-2)",
                color: hasChanges ? "#fff" : "var(--color-text-tertiary)",
                border: "none",
                borderRadius: "var(--radius)",
                fontSize: "0.8125rem",
                fontWeight: 500,
                cursor: hasChanges ? "pointer" : "default",
              }}
            >
              {saving ? "Saving…" : "Save"}
            </button>
          )}
          {!canEdit && (
            <span className="text-sm text-tertiary">
              {isFileMode ? "File-based policy (read-only)" : "Read-only"}
            </span>
          )}
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

      <div
        style={{
          border: "1px solid var(--color-border)",
          borderRadius: "var(--radius-lg)",
          overflow: "hidden",
        }}
      >
        {/* Editor header */}
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

        {/* Editor with syntax highlighting */}
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
    </div>
  );
}
