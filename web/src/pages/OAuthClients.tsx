import { useState, useEffect, useCallback, type FormEvent } from "react";
import {
  listOAuthClients,
  createOAuthClient,
  deleteOAuthClient,
  type OAuthClient,
} from "../api";
import ConfirmModal from "../ConfirmModal";

const ALL_SCOPES = ["auth_keys", "devices:core", "services"];

export function OAuthClientsPage() {
  const [clients, setClients] = useState<OAuthClient[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [showCreate, setShowCreate] = useState(false);
  const [selectedScopes, setSelectedScopes] = useState<string[]>([...ALL_SCOPES]);
  const [newCredentials, setNewCredentials] = useState<{
    client_id: string;
    client_secret: string;
  } | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<OAuthClient | null>(null);

  const fetchClients = useCallback(async () => {
    try {
      const data = await listOAuthClients();
      setClients(data);
      setError("");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchClients();
  }, [fetchClients]);

  async function handleCreate(e: FormEvent) {
    e.preventDefault();
    try {
      const resp = await createOAuthClient(selectedScopes);
      setNewCredentials({
        client_id: resp.client_id,
        client_secret: resp.client_secret,
      });
      setShowCreate(false);
      await fetchClients();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  async function confirmDelete() {
    if (!deleteTarget) return;
    try {
      await deleteOAuthClient(deleteTarget.id);
      await fetchClients();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setDeleteTarget(null);
    }
  }

  function toggleScope(scope: string) {
    setSelectedScopes((prev) =>
      prev.includes(scope) ? prev.filter((s) => s !== scope) : [...prev, scope],
    );
  }

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
      <div className="flex items-center justify-between" style={{ marginBottom: "1rem" }}>
        <div>
          <h2>OAuth Clients</h2>
          <p className="text-sm" style={{ marginTop: 2 }}>
            Manage OAuth2 clients for the Tailscale-compatible v2 API &middot;{" "}
            {clients.length} client{clients.length !== 1 ? "s" : ""}
          </p>
        </div>
        <div className="flex gap-2">
          <button className="outline" onClick={fetchClients}>
            Refresh
          </button>
          <button onClick={() => setShowCreate(!showCreate)}>
            {showCreate ? "Cancel" : "Create OAuth Client"}
          </button>
        </div>
      </div>

      {error && (
        <div className="alert error" style={{ marginBottom: "1rem" }}>
          {error}
        </div>
      )}

      {newCredentials && (
        <div className="alert success" style={{ marginBottom: "1rem" }}>
          <div className="text-xs" style={{ marginBottom: 8 }}>
            <strong>OAuth client created</strong> &mdash; save these credentials now, the
            secret won't be shown again:
          </div>
          <div style={{ marginBottom: 6 }}>
            <span className="text-xs text-secondary">Client ID:</span>
            <div className="copy-text">
              <code style={{ wordBreak: "break-all" }}>{newCredentials.client_id}</code>
              <button
                className="outline sm"
                onClick={() => navigator.clipboard.writeText(newCredentials.client_id)}
              >
                Copy
              </button>
            </div>
          </div>
          <div style={{ marginBottom: 6 }}>
            <span className="text-xs text-secondary">Client Secret:</span>
            <div className="copy-text">
              <code style={{ wordBreak: "break-all" }}>{newCredentials.client_secret}</code>
              <button
                className="outline sm"
                onClick={() => navigator.clipboard.writeText(newCredentials.client_secret)}
              >
                Copy
              </button>
            </div>
          </div>
          <div style={{ marginTop: 8 }}>
            <button className="outline sm" onClick={() => setNewCredentials(null)}>
              Dismiss
            </button>
          </div>
        </div>
      )}

      {showCreate && (
        <form onSubmit={handleCreate} className="card" style={{ marginBottom: "1rem" }}>
          <div className="card-body">
            <div style={{ marginBottom: 12 }}>
              <label
                className="text-xs text-secondary"
                style={{ display: "block", marginBottom: 6 }}
              >
                Scopes
              </label>
              <div className="flex gap-2" style={{ flexWrap: "wrap" }}>
                {ALL_SCOPES.map((scope) => (
                  <label
                    key={scope}
                    className="flex items-center gap-1"
                    style={{ cursor: "pointer" }}
                  >
                    <input
                      type="checkbox"
                      checked={selectedScopes.includes(scope)}
                      onChange={() => toggleScope(scope)}
                    />
                    <span className="text-sm">{scope}</span>
                  </label>
                ))}
              </div>
            </div>
            <button type="submit" disabled={selectedScopes.length === 0}>
              Create Client
            </button>
          </div>
        </form>
      )}

      <div className="card" style={{ padding: 0 }}>
        {clients.length === 0 ? (
          <div className="empty-state">
            <svg
              width="40"
              height="40"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
            >
              <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
              <path d="M7 11V7a5 5 0 0 1 10 0v4" />
            </svg>
            <h3>No OAuth clients</h3>
            <p>
              Create an OAuth client for the Tailscale K8s operator or other v2 API
              consumers.
            </p>
          </div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table>
              <thead>
                <tr>
                  <th>Client ID</th>
                  <th>Scopes</th>
                  <th>Created</th>
                  <th>Expires</th>
                  <th style={{ width: 80 }} />
                </tr>
              </thead>
              <tbody>
                {clients.map((c) => {
                  const expired =
                    c.expiration && new Date(c.expiration) < new Date();
                  return (
                    <tr
                      key={c.id}
                      style={expired ? { opacity: 0.5 } : undefined}
                    >
                      <td>
                        <code className="text-sm font-mono">{c.client_id}</code>
                      </td>
                      <td className="text-sm">
                        {(c.scopes || []).map((s) => (
                          <span
                            key={s}
                            className="badge"
                            style={{ marginRight: 4 }}
                          >
                            {s}
                          </span>
                        ))}
                      </td>
                      <td className="text-sm text-secondary">
                        {c.created_at
                          ? new Date(c.created_at).toLocaleDateString()
                          : "—"}
                      </td>
                      <td className="text-sm text-secondary">
                        {c.expiration
                          ? new Date(c.expiration).toLocaleDateString()
                          : "Never"}
                      </td>
                      <td>
                        <button
                          className="outline sm"
                          onClick={() => setDeleteTarget(c)}
                        >
                          Delete
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <ConfirmModal
        open={!!deleteTarget}
        title="Delete OAuth client"
        message={`Delete OAuth client "${deleteTarget?.client_id}"? All associated tokens will be revoked. This cannot be undone.`}
        confirmLabel="Delete"
        destructive
        onConfirm={confirmDelete}
        onCancel={() => setDeleteTarget(null)}
      />
    </div>
  );
}
