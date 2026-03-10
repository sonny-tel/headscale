import { useState, useEffect, useCallback, type FormEvent } from "react";
import {
  listAPIKeys,
  createAPIKey,
  expireAPIKey,
} from "../api";
import ConfirmModal from "../ConfirmModal";

interface APIKey {
  id: string;
  prefix: string;
  expiration: string;
  created_at: string;
}

export function APIKeysPage() {
  const [keys, setKeys] = useState<APIKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [showCreate, setShowCreate] = useState(false);
  const [expiration, setExpiration] = useState("720h");
  const [newKey, setNewKey] = useState("");
  const [expireTarget, setExpireTarget] = useState<string | null>(null);

  const fetchKeys = useCallback(async () => {
    try {
      const data = await listAPIKeys();
      setKeys(data);
      setError("");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchKeys();
  }, [fetchKeys]);

  async function handleCreate(e: FormEvent) {
    e.preventDefault();
    try {
      const durationMs = parseDuration(expiration);
      const expiresAt = new Date(Date.now() + durationMs).toISOString();

      const key = await createAPIKey(expiresAt);
      setNewKey(key);
      setShowCreate(false);
      await fetchKeys();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  async function handleExpire(prefix: string) {
    setExpireTarget(prefix);
  }

  async function confirmExpire() {
    if (!expireTarget) return;
    try {
      await expireAPIKey(expireTarget);
      await fetchKeys();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setExpireTarget(null);
    }
  }

  const activeKeys = keys.filter(
    (k) => !k.expiration || new Date(k.expiration) > new Date(),
  );
  const expiredKeys = keys.filter(
    (k) => k.expiration && new Date(k.expiration) <= new Date(),
  );

  if (loading) {
    return (
      <div className="flex items-center justify-between" style={{ padding: "3rem", justifyContent: "center" }}>
        <span className="spinner" />
      </div>
    );
  }

  return (
    <div>
      <div className="flex items-center justify-between" style={{ marginBottom: "1rem" }}>
        <div>
          <h2>Settings</h2>
          <p className="text-sm" style={{ marginTop: 2 }}>
            API keys &middot; {activeKeys.length} active, {expiredKeys.length} expired
          </p>
        </div>
        <div className="flex gap-2">
          <button className="outline" onClick={fetchKeys}>Refresh</button>
          <button onClick={() => setShowCreate(!showCreate)}>
            {showCreate ? "Cancel" : "Create API Key"}
          </button>
        </div>
      </div>

      {error && (
        <div className="alert error" style={{ marginBottom: "1rem" }}>
          {error}
        </div>
      )}

      {newKey && (
        <div className="alert success" style={{ marginBottom: "1rem" }}>
          <div className="text-xs" style={{ marginBottom: 4 }}>
            New API key created — copy it now, it won't be shown again:
          </div>
          <div className="copy-text">
            <code style={{ wordBreak: "break-all" }}>{newKey}</code>
            <button
              className="outline sm"
              onClick={() => {
                navigator.clipboard.writeText(newKey);
                setNewKey("");
              }}
            >
              Copy
            </button>
          </div>
        </div>
      )}

      {showCreate && (
        <form onSubmit={handleCreate} className="card" style={{ marginBottom: "1rem" }}>
          <div className="card-body">
            <div className="flex gap-3 items-end">
              <div>
                <label className="text-xs text-secondary" style={{ display: "block", marginBottom: 4 }}>
                  Expiration
                </label>
                <select value={expiration} onChange={(e) => setExpiration(e.target.value)}>
                  <option value="24h">24 hours</option>
                  <option value="168h">7 days</option>
                  <option value="720h">30 days</option>
                  <option value="2160h">90 days</option>
                  <option value="8760h">1 year</option>
                </select>
              </div>
              <button type="submit">Create</button>
            </div>
          </div>
        </form>
      )}

      <div className="card" style={{ padding: 0 }}>
        {keys.length === 0 ? (
          <div className="empty-state">
            <svg
              width="40"
              height="40"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
            >
              <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />
            </svg>
            <h3>No API keys</h3>
            <p>Create an API key for programmatic access.</p>
          </div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table>
              <thead>
                <tr>
                  <th>Prefix</th>
                  <th>Created</th>
                  <th>Expires</th>
                  <th>Status</th>
                  <th style={{ width: 80 }} />
                </tr>
              </thead>
              <tbody>
                {keys.map((k) => {
                  const expired = k.expiration && new Date(k.expiration) < new Date();
                  return (
                    <tr key={k.id} style={expired ? { opacity: 0.5 } : undefined}>
                      <td>
                        <code className="text-sm font-mono">{k.prefix}</code>
                      </td>
                      <td className="text-sm text-secondary">
                        {k.created_at ? new Date(k.created_at).toLocaleDateString() : "—"}
                      </td>
                      <td className="text-sm text-secondary">
                        {k.expiration ? new Date(k.expiration).toLocaleDateString() : "—"}
                      </td>
                      <td>
                        <span className={`badge ${expired ? "expired" : "online"}`}>
                          {expired ? "Expired" : "Active"}
                        </span>
                      </td>
                      <td>
                        {!expired && (
                          <button
                            className="outline sm"
                            onClick={() => handleExpire(k.prefix)}
                          >
                            Expire
                          </button>
                        )}
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
        open={!!expireTarget}
        title="Expire API key"
        message={`Expire API key with prefix "${expireTarget}"? This cannot be undone.`}
        confirmLabel="Expire"
        destructive
        onConfirm={confirmExpire}
        onCancel={() => setExpireTarget(null)}
      />
    </div>
  );
}

function parseDuration(s: string): number {
  const match = s.match(/^(\d+)(h|m|s)$/);
  if (!match) return 2592000000;
  const val = parseInt(match[1], 10);
  switch (match[2]) {
    case "h": return val * 3600000;
    case "m": return val * 60000;
    case "s": return val * 1000;
    default: return val * 3600000;
  }
}
