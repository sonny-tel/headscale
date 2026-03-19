import { useState, useEffect, useCallback, type FormEvent } from "react";
import {
  listPreAuthKeys,
  createPreAuthKey,
  expirePreAuthKey,
  listUsers,
  type PreAuthKey,
  type User,
} from "../api";
import ConfirmModal from "../ConfirmModal";

export function PreAuthKeysPage() {
  const [keys, setKeys] = useState<PreAuthKey[]>([]);
  const [users, setUsers] = useState<User[]>([]);
  const [selectedUser, setSelectedUser] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [showCreate, setShowCreate] = useState(false);
  const [reusable, setReusable] = useState(false);
  const [ephemeral, setEphemeral] = useState(false);
  const [expiration, setExpiration] = useState("24h");
  const [tags, setTags] = useState("");
  const [newKey, setNewKey] = useState("");
  const [expireTarget, setExpireTarget] = useState<string | null>(null);

  const fetchUsers = useCallback(async () => {
    try {
      const data = await listUsers();
      setUsers(data);
      if (data.length > 0 && !selectedUser) {
        setSelectedUser(data[0].id);
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }, [selectedUser]);

  const fetchKeys = useCallback(async () => {
    if (!selectedUser) return;
    try {
      setLoading(true);
      const data = await listPreAuthKeys();
      setKeys(data.filter((k) => k.user?.id === selectedUser));
      setError("");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, [selectedUser]);

  useEffect(() => {
    fetchUsers();
  }, [fetchUsers]);

  useEffect(() => {
    fetchKeys();
  }, [fetchKeys]);

  async function handleCreate(e: FormEvent) {
    e.preventDefault();
    try {
      const durationMs = parseDuration(expiration);
      const expiresAt = new Date(Date.now() + durationMs).toISOString();

      const aclTags = tags
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean);

      const key = await createPreAuthKey({
        user: selectedUser,
        reusable,
        ephemeral,
        expiration: expiresAt,
        acl_tags: aclTags.length > 0 ? aclTags : undefined,
      });

      setNewKey(key.key);
      setShowCreate(false);
      await fetchKeys();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  async function handleExpire(key: string) {
    setExpireTarget(key);
  }

  async function confirmExpire() {
    if (!expireTarget) return;
    try {
      // Find the key object to get its numeric ID
      const keyObj = keys.find((k) => k.key === expireTarget);
      if (keyObj) {
        await expirePreAuthKey(keyObj.id);
      }
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

  return (
    <div>
      <div className="flex items-center justify-between" style={{ marginBottom: "1rem" }}>
        <div>
          <h2>Auth Keys</h2>
          <p className="text-sm" style={{ marginTop: 2 }}>
            {activeKeys.length} active &middot; {expiredKeys.length} expired
          </p>
        </div>
        <div className="flex gap-2 items-center">
          <select
            value={selectedUser}
            onChange={(e) => setSelectedUser(e.target.value)}
            style={{ padding: "0.375rem 0.5rem", fontSize: "0.8125rem" }}
          >
            {users.map((u) => (
              <option key={u.id} value={u.id}>{u.name}</option>
            ))}
          </select>
          <button className="outline" onClick={fetchKeys}>Refresh</button>
          <button onClick={() => setShowCreate(!showCreate)}>
            {showCreate ? "Cancel" : "Create Key"}
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
            New key created — copy it now, it won't be shown again:
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
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.75rem", marginBottom: "0.75rem" }}>
              <div>
                <label className="text-xs text-secondary" style={{ display: "block", marginBottom: 4 }}>Expiration</label>
                <select value={expiration} onChange={(e) => setExpiration(e.target.value)} style={{ width: "100%" }}>
                  <option value="1h">1 hour</option>
                  <option value="24h">24 hours</option>
                  <option value="168h">7 days</option>
                  <option value="720h">30 days</option>
                  <option value="8760h">1 year</option>
                </select>
              </div>
              <div>
                <label className="text-xs text-secondary" style={{ display: "block", marginBottom: 4 }}>ACL Tags (comma-separated)</label>
                <input value={tags} onChange={(e) => setTags(e.target.value)} placeholder="tag:server, tag:web" style={{ width: "100%" }} />
              </div>
            </div>
            <div className="flex gap-4 items-center" style={{ marginBottom: "0.75rem" }}>
              <label className="text-sm flex items-center gap-2" style={{ cursor: "pointer" }}>
                <input type="checkbox" checked={reusable} onChange={(e) => setReusable(e.target.checked)} />
                Reusable
              </label>
              <label className="text-sm flex items-center gap-2" style={{ cursor: "pointer" }}>
                <input type="checkbox" checked={ephemeral} onChange={(e) => setEphemeral(e.target.checked)} />
                Ephemeral
              </label>
            </div>
            <button type="submit">Create Auth Key</button>
          </div>
        </form>
      )}

      {loading ? (
        <div className="flex items-center justify-between" style={{ padding: "3rem", justifyContent: "center" }}>
          <span className="spinner" />
        </div>
      ) : (
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
              <h3>No auth keys</h3>
              <p>Create an auth key to allow devices to register automatically.</p>
            </div>
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table>
                <thead>
                  <tr>
                    <th>Key</th>
                    <th>Properties</th>
                    <th>Tags</th>
                    <th>Status</th>
                    <th>Expires</th>
                    <th style={{ width: 80 }} />
                  </tr>
                </thead>
                <tbody>
                  {keys.map((k) => {
                    const expired = k.expiration && new Date(k.expiration) < new Date();
                    return (
                      <tr key={k.id} style={expired ? { opacity: 0.5 } : undefined}>
                        <td>
                          <code className="text-sm font-mono">{k.key?.substring(0, 12)}…</code>
                        </td>
                        <td>
                          <div className="flex gap-1">
                            {k.reusable && <span className="badge tag">reusable</span>}
                            {k.ephemeral && <span className="badge tag">ephemeral</span>}
                            {k.used && <span className="badge">used</span>}
                          </div>
                        </td>
                        <td className="text-xs text-secondary">
                          {k.acl_tags?.join(", ") || "—"}
                        </td>
                        <td>
                          <span className={`badge ${expired ? "expired" : "online"}`}>
                            {expired ? "Expired" : "Active"}
                          </span>
                        </td>
                        <td className="text-sm text-secondary">
                          {k.expiration ? new Date(k.expiration).toLocaleDateString() : "—"}
                        </td>
                        <td>
                          {!expired && (
                            <button
                              className="outline sm"
                              onClick={() => handleExpire(k.key)}
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
      )}
      <ConfirmModal
        open={!!expireTarget}
        title="Expire preauth key"
        message="Expire this preauth key? It will no longer be usable for new registrations."
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
  if (!match) return 86400000;
  const val = parseInt(match[1], 10);
  switch (match[2]) {
    case "h": return val * 3600000;
    case "m": return val * 60000;
    case "s": return val * 1000;
    default: return val * 3600000;
  }
}
