import { useState, useEffect, useCallback, type FormEvent } from "react";
import {
  listProviderAccounts,
  addProviderAccount,
  removeProviderAccount,
  syncProviderRelays,
  listProviderRelays,
  listProviderAllocations,
  listNodes,
  type ProviderAccount,
  type ProviderRelay,
  type KeyAllocation,
  type Node,
} from "../api";
import ConfirmModal from "../ConfirmModal";

export function VPNPage() {
  const [accounts, setAccounts] = useState<ProviderAccount[]>([]);
  const [relays, setRelays] = useState<ProviderRelay[]>([]);
  const [allocations, setAllocations] = useState<KeyAllocation[]>([]);
  const [nodes, setNodes] = useState<Node[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [syncing, setSyncing] = useState(false);
  const [showAddAccount, setShowAddAccount] = useState(false);
  const [removeTarget, setRemoveTarget] = useState<ProviderAccount | null>(null);
  const [showAccountIds, setShowAccountIds] = useState(false);

  function maskId(id: string) {
    if (showAccountIds) return id;
    if (id.length <= 4) return "••••";
    return "••••••" + id.slice(-4);
  }

  // Add account form state
  const [newProvider, setNewProvider] = useState("mullvad");
  const [newAccountId, setNewAccountId] = useState("");
  const [newMaxKeys, setNewMaxKeys] = useState(5);

  const fetchAll = useCallback(async () => {
    try {
      const [accts, allocs, nodeList] = await Promise.all([
        listProviderAccounts(),
        listProviderAllocations(),
        listNodes(),
      ]);
      setAccounts(accts);
      setAllocations(allocs);
      setNodes(nodeList);
      // Only fetch relays if there are accounts
      if (accts.length > 0) {
        const r = await listProviderRelays();
        setRelays(r);
      } else {
        setRelays([]);
      }
      setError("");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAll();
  }, [fetchAll]);

  async function handleAddAccount(e: FormEvent) {
    e.preventDefault();
    try {
      await addProviderAccount({
        provider_name: newProvider,
        account_id: newAccountId,
        max_keys: newMaxKeys,
      });
      setShowAddAccount(false);
      setNewAccountId("");
      setNewMaxKeys(5);
      await fetchAll();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  async function confirmRemoveAccount() {
    if (!removeTarget) return;
    try {
      await removeProviderAccount(removeTarget.id);
      await fetchAll();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setRemoveTarget(null);
    }
  }

  async function handleSync(providerName: string) {
    setSyncing(true);
    try {
      const count = await syncProviderRelays(providerName);
      setError("");
      // Refresh relays after sync
      const r = await listProviderRelays();
      setRelays(r);
      // Brief success feedback
      setError(`Synced ${count} relays`);
      setTimeout(() => setError(""), 3000);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSyncing(false);
    }
  }

  // Group relays by provider, then by country within each provider
  const relaysByProvider = relays.reduce<Record<string, ProviderRelay[]>>((acc, r) => {
    const key = r.provider_name || "unknown";
    if (!acc[key]) acc[key] = [];
    acc[key].push(r);
    return acc;
  }, {});

  const sortedProviders = Object.keys(relaysByProvider).sort();

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
          <h2>VPN Providers</h2>
          <p className="text-sm" style={{ marginTop: 2 }}>
            External WireGuard exit node providers &middot; {accounts.length} account{accounts.length !== 1 ? "s" : ""}, {relays.length} relay{relays.length !== 1 ? "s" : ""}, {allocations.length} allocation{allocations.length !== 1 ? "s" : ""}
          </p>
        </div>
        <div className="flex gap-2">
          <button className="btn outline" onClick={fetchAll}>Refresh</button>
          <button className="btn primary" onClick={() => setShowAddAccount(!showAddAccount)}>
            {showAddAccount ? "Cancel" : "Add Account"}
          </button>
        </div>
      </div>

      {error && (
        <div style={{
          padding: "0.5rem 0.75rem",
          marginBottom: "1rem",
          borderRadius: "var(--radius)",
          fontSize: "0.8125rem",
          background: error.startsWith("Synced") ? "var(--color-success-subtle)" : "var(--color-danger-subtle)",
          color: error.startsWith("Synced") ? "var(--color-success)" : "var(--color-danger)",
          border: `1px solid ${error.startsWith("Synced") ? "var(--color-success)" : "var(--color-danger)"}`,
        }}>
          {error}
        </div>
      )}

      {/* Add Account Form */}
      {showAddAccount && (
        <form onSubmit={handleAddAccount} className="card" style={{ marginBottom: "1.5rem" }}>
          <div className="card-header">
            <span style={{ fontWeight: 500 }}>Add Provider Account</span>
          </div>
          <div className="card-body" style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
            <div className="flex gap-2" style={{ alignItems: "end" }}>
              <label style={{ flex: 1 }}>
                <span className="text-sm" style={{ display: "block", marginBottom: 4 }}>Provider</span>
                <select
                  value={newProvider}
                  onChange={(e) => setNewProvider(e.target.value)}
                  style={{
                    width: "100%",
                    padding: "0.5rem 0.75rem",
                    background: "var(--color-surface-2)",
                    border: "1px solid var(--color-border)",
                    borderRadius: "var(--radius)",
                    color: "var(--color-text)",
                    fontSize: "0.8125rem",
                  }}
                >
                  <option value="mullvad">Mullvad</option>
                </select>
              </label>
              <label style={{ flex: 2 }}>
                <span className="text-sm" style={{ display: "block", marginBottom: 4 }}>Account ID</span>
                <input
                  type="text"
                  placeholder="e.g. 1234567890"
                  value={newAccountId}
                  onChange={(e) => setNewAccountId(e.target.value)}
                  required
                  style={{
                    width: "100%",
                    padding: "0.5rem 0.75rem",
                    background: "var(--color-surface-2)",
                    border: "1px solid var(--color-border)",
                    borderRadius: "var(--radius)",
                    color: "var(--color-text)",
                    fontSize: "0.8125rem",
                  }}
                />
              </label>
              <label style={{ flex: 0.5 }}>
                <span className="text-sm" style={{ display: "block", marginBottom: 4 }}>Max Keys</span>
                <div style={{
                  display: "flex",
                  alignItems: "stretch",
                  background: "var(--color-surface-2)",
                  border: "1px solid var(--color-border)",
                  borderRadius: "var(--radius)",
                  overflow: "hidden",
                }}>
                  <input
                    type="text"
                    inputMode="numeric"
                    pattern="[0-9]*"
                    value={newMaxKeys}
                    onChange={(e) => {
                      const v = parseInt(e.target.value);
                      if (!isNaN(v) && v >= 1) setNewMaxKeys(v);
                    }}
                    style={{
                      flex: 1,
                      minWidth: 0,
                      padding: "0.5rem 0.75rem",
                      background: "transparent",
                      border: "none",
                      color: "var(--color-text)",
                      fontSize: "0.8125rem",
                      outline: "none",
                    }}
                  />
                  <div style={{ display: "flex", flexDirection: "column", borderLeft: "1px solid var(--color-border)" }}>
                    <button
                      type="button"
                      onClick={() => setNewMaxKeys((k) => k + 1)}
                      style={{
                        flex: 1,
                        padding: "0 0.5rem",
                        background: "transparent",
                        border: "none",
                        borderBottom: "1px solid var(--color-border)",
                        color: "var(--color-text-secondary)",
                        cursor: "pointer",
                        fontSize: "0.625rem",
                        lineHeight: 1,
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                      }}
                      onMouseEnter={(e) => (e.currentTarget.style.background = "var(--color-surface-3)")}
                      onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                    >▲</button>
                    <button
                      type="button"
                      onClick={() => setNewMaxKeys((k) => Math.max(1, k - 1))}
                      style={{
                        flex: 1,
                        padding: "0 0.5rem",
                        background: "transparent",
                        border: "none",
                        color: "var(--color-text-secondary)",
                        cursor: "pointer",
                        fontSize: "0.625rem",
                        lineHeight: 1,
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                      }}
                      onMouseEnter={(e) => (e.currentTarget.style.background = "var(--color-surface-3)")}
                      onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                    >▼</button>
                  </div>
                </div>
              </label>
            </div>
            <div style={{ display: "flex", justifyContent: "flex-end" }}>
              <button type="submit" className="btn primary" disabled={!newAccountId.trim()}>
                Add Account
              </button>
            </div>
          </div>
        </form>
      )}

      {/* Accounts Section */}
      <section style={{ marginBottom: "2rem" }}>
        <h3 style={{ fontSize: "0.875rem", fontWeight: 600, marginBottom: "0.75rem" }}>Accounts</h3>
        {accounts.length === 0 ? (
          <div style={{
            padding: "2rem",
            textAlign: "center",
            color: "var(--color-text-tertiary)",
            fontSize: "0.8125rem",
            border: "1px solid var(--color-border)",
            borderRadius: "var(--radius-lg)",
          }}>
            No provider accounts configured. Add one to get started.
          </div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Provider</th>
                <th>
                  <span className="flex items-center gap-1">
                    Account ID
                    <button
                      onClick={() => setShowAccountIds(!showAccountIds)}
                      title={showAccountIds ? "Hide account IDs" : "Show account IDs"}
                      style={{
                        background: "none",
                        border: "none",
                        cursor: "pointer",
                        padding: 2,
                        color: "var(--color-text-secondary)",
                        display: "inline-flex",
                        alignItems: "center",
                      }}
                    >
                      {showAccountIds ? (
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                          <circle cx="12" cy="12" r="3" />
                        </svg>
                      ) : (
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94" />
                          <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19" />
                          <line x1="1" y1="1" x2="23" y2="23" />
                        </svg>
                      )}
                    </button>
                  </span>
                </th>
                <th>Keys</th>
                <th>Expires</th>
                <th>Status</th>
                <th style={{ width: 120 }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {accounts.map((acct) => {
                const expired = acct.expires_at && new Date(acct.expires_at) < new Date();
                return (
                  <tr key={acct.id}>
                    <td>
                      <span style={{ fontWeight: 500, textTransform: "capitalize" }}>{acct.provider_name}</span>
                    </td>
                    <td>
                      <code style={{ fontSize: "0.75rem", letterSpacing: showAccountIds ? undefined : "0.05em" }}>{maskId(acct.account_id)}</code>
                    </td>
                    <td>
                      <span style={{ fontVariantNumeric: "tabular-nums" }}>
                        {acct.active_keys} / {acct.max_keys}
                      </span>
                    </td>
                    <td>
                      {acct.expires_at
                        ? new Date(acct.expires_at).toLocaleDateString()
                        : "—"}
                    </td>
                    <td>
                      {expired ? (
                        <span className="badge expired">Expired</span>
                      ) : acct.enabled ? (
                        <span className="badge online">Active</span>
                      ) : (
                        <span className="badge offline">Disabled</span>
                      )}
                    </td>
                    <td>
                      <div className="flex gap-2">
                        <button
                          className="btn outline sm"
                          onClick={() => handleSync(acct.provider_name)}
                          disabled={syncing}
                        >
                          {syncing ? "…" : "Sync"}
                        </button>
                        <button
                          className="btn danger sm"
                          onClick={() => setRemoveTarget(acct)}
                        >
                          Remove
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </section>

      {/* Allocations Section */}
      {allocations.length > 0 && (
        <section style={{ marginBottom: "2rem" }}>
          <h3 style={{ fontSize: "0.875rem", fontWeight: 600, marginBottom: "0.75rem" }}>
            Key Allocations
            <span className="text-sm" style={{ fontWeight: 400, marginLeft: "0.5rem", color: "var(--color-text-secondary)" }}>
              {allocations.length} active
            </span>
          </h3>
          <table>
            <thead>
              <tr>
                <th>Node</th>
                <th>Account</th>
                <th>Key</th>
                <th>Allocated</th>
              </tr>
            </thead>
            <tbody>
              {allocations.map((alloc) => {
                const acct = accounts.find((a) => a.id === String(alloc.account_id));
                const node = nodes.find((n) => n.id === String(alloc.node_id));
                return (
                  <tr key={alloc.id}>
                    <td>{node ? node.given_name || node.name : `#${alloc.node_id}`}</td>
                    <td>
                      {acct ? (
                        <span>
                          <span style={{ textTransform: "capitalize" }}>{acct.provider_name}</span>
                          {" "}
                          <code style={{ fontSize: "0.75rem", letterSpacing: showAccountIds ? undefined : "0.05em" }}>{maskId(acct.account_id)}</code>
                        </span>
                      ) : (
                        <span style={{ color: "var(--color-text-tertiary)" }}>#{alloc.account_id}</span>
                      )}
                    </td>
                    <td>
                      <code style={{ fontSize: "0.75rem" }}>
                        {alloc.node_key.length > 20
                          ? alloc.node_key.slice(0, 20) + "…"
                          : alloc.node_key}
                      </code>
                    </td>
                    <td>
                      {alloc.allocated_at
                        ? new Date(alloc.allocated_at).toLocaleString()
                        : "—"}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </section>
      )}

      {/* Relays Section */}
      {relays.length > 0 && (
        <section>
          <h3 style={{ fontSize: "0.875rem", fontWeight: 600, marginBottom: "0.75rem" }}>Relays</h3>
          <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
            {sortedProviders.map((provider) => {
              const providerRelays = relaysByProvider[provider];
              const activeCount = providerRelays.filter((r) => r.active).length;
              const byCountry = providerRelays.reduce<Record<string, ProviderRelay[]>>((acc, r) => {
                const key = r.country || r.country_code || "Unknown";
                if (!acc[key]) acc[key] = [];
                acc[key].push(r);
                return acc;
              }, {});
              const countries = Object.keys(byCountry).sort();
              return (
                <div
                  key={provider}
                  style={{
                    padding: "1rem 1.25rem",
                    border: "1px solid var(--color-border)",
                    borderRadius: "var(--radius-lg)",
                    fontSize: "0.8125rem",
                  }}
                >
                  <div style={{ marginBottom: "0.5rem", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                    <span style={{ fontWeight: 600, textTransform: "capitalize" }}>{provider}</span>
                    <span style={{ color: "var(--color-text-secondary)" }}>
                      {providerRelays.length} relay{providerRelays.length !== 1 ? "s" : ""} across {countries.length} countr{countries.length !== 1 ? "ies" : "y"}
                      {" "}&middot; {activeCount} active
                    </span>
                  </div>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: "0.25rem 0.5rem", lineHeight: 1.7 }}>
                    {countries.map((country) => {
                      const countryRelays = byCountry[country];
                      const code = countryRelays[0]?.country_code?.toUpperCase() || "";
                      return (
                        <span
                          key={country}
                          style={{ whiteSpace: "nowrap", color: "var(--color-text-secondary)" }}
                          title={[...new Set(countryRelays.map((r) => r.city).filter(Boolean))].join(", ") || country}
                        >
                          <span style={{ fontWeight: 500, color: "var(--color-text)" }}>{code}</span>
                          {" "}
                          <span>{countryRelays.length}</span>
                        </span>
                      );
                    })}
                  </div>
                </div>
              );
            })}
          </div>
        </section>
      )}

      {/* Providers empty state with no relays */}
      {accounts.length > 0 && relays.length === 0 && (
        <section>
          <div style={{
            padding: "2rem",
            textAlign: "center",
            color: "var(--color-text-tertiary)",
            fontSize: "0.8125rem",
            border: "1px solid var(--color-border)",
            borderRadius: "var(--radius-lg)",
          }}>
            No relays cached. Click <strong>Sync</strong> on an account to fetch relays from the provider.
          </div>
        </section>
      )}

      <ConfirmModal
        open={!!removeTarget}
        title="Remove Provider Account"
        message={`Remove account "${removeTarget ? maskId(removeTarget.account_id) : ""}" (${removeTarget?.provider_name})? This will also remove all key allocations for this account.`}
        confirmLabel="Remove"
        destructive
        onConfirm={confirmRemoveAccount}
        onCancel={() => setRemoveTarget(null)}
      />
    </div>
  );
}
