import { useState, useEffect, useCallback, useRef, type FormEvent } from "react";
import {
  listUsers,
  createUser,
  deleteUser,
  setUserRole,
  type User,
} from "../api";
import { useAuth } from "../auth";
import { getPermissions } from "../permissions";
import ConfirmModal from "../ConfirmModal";
import { UnsavedFooter } from "../UnsavedFooter";

const ROLE_OPTIONS: { value: string; label: string; description: string }[] = [
  { value: "admin", label: "Admin", description: "Full access to all settings" },
  { value: "network_admin", label: "Network admin", description: "Manage network configuration" },
  { value: "it_admin", label: "IT admin", description: "Manage users and devices" },
  { value: "member", label: "Member", description: "Standard network access" },
  { value: "service_account", label: "Service account", description: "Automated integrations" },
];

function roleLabel(role: string): string {
  return ROLE_OPTIONS.find((r) => r.value === role)?.label || role;
}

function RoleDropdown({
  value,
  savedValue,
  onChange,
  disabled,
}: {
  value: string;
  savedValue: string;
  onChange: (role: string) => void;
  disabled?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const [pos, setPos] = useState({ top: 0, left: 0 });

  useEffect(() => {
    if (!open) return;
    function handleClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    function handleKey(e: KeyboardEvent) {
      if (e.key === "Escape") setOpen(false);
    }
    function handleScroll() {
      setOpen(false);
    }
    document.addEventListener("mousedown", handleClick);
    document.addEventListener("keydown", handleKey);
    window.addEventListener("scroll", handleScroll, true);
    return () => {
      document.removeEventListener("mousedown", handleClick);
      document.removeEventListener("keydown", handleKey);
      window.removeEventListener("scroll", handleScroll, true);
    };
  }, [open]);

  const hasChange = value !== savedValue;

  function toggle() {
    if (disabled) return;
    if (!open && triggerRef.current) {
      const rect = triggerRef.current.getBoundingClientRect();
      setPos({ top: rect.bottom + 4, left: rect.left });
    }
    setOpen(!open);
  }

  return (
    <div ref={ref} style={{ position: "relative", display: "inline-flex" }}>
      <button
        ref={triggerRef}
        type="button"
        onClick={toggle}
        disabled={disabled}
        className="role-dropdown-trigger"
        data-changed={hasChange || undefined}
      >
        <span
          className="text-sm"
          style={{ color: "var(--color-text-secondary)" }}
        >
          {roleLabel(value)}
        </span>
        <svg
          width="12"
          height="12"
          viewBox="0 0 12 12"
          fill="none"
          style={{
            transition: "transform 150ms",
            transform: open ? "rotate(180deg)" : undefined,
          }}
        >
          <path
            d="M3 4.5L6 7.5L9 4.5"
            stroke="currentColor"
            strokeWidth="1.5"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
      </button>
      {open && (
        <div
          className="role-dropdown-menu"
          style={{ position: "fixed", top: pos.top, left: pos.left }}
        >
          {ROLE_OPTIONS.map((r) => (
            <button
              key={r.value}
              type="button"
              className="role-dropdown-item"
              data-selected={r.value === value || undefined}
              onClick={() => {
                onChange(r.value);
                setOpen(false);
              }}
            >
              <span className="role-dropdown-check">
                {r.value === value && (
                  <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
                    <path
                      d="M3 7L6 10L11 4"
                      stroke="currentColor"
                      strokeWidth="2"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    />
                  </svg>
                )}
              </span>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div className="role-dropdown-label">{r.label}</div>
                <div className="role-dropdown-desc">{r.description}</div>
              </div>
              {r.value === savedValue && r.value !== value && (
                <span className="role-dropdown-current">current</span>
              )}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

export function UsersPage() {
  const { user: currentUser } = useAuth();
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [showCreate, setShowCreate] = useState(false);
  const [newName, setNewName] = useState("");
  const [newDisplayName, setNewDisplayName] = useState("");
  const [pendingRoles, setPendingRoles] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState<Record<string, boolean>>({});
  const [deleteTarget, setDeleteTarget] = useState<{ id: string; name: string } | null>(null);

  const fetchUsers = useCallback(async () => {
    try {
      const data = await listUsers();
      setUsers(data);
      setError("");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchUsers();
  }, [fetchUsers]);

  async function handleCreate(e: FormEvent) {
    e.preventDefault();
    try {
      await createUser(newName, newDisplayName || undefined);
      setNewName("");
      setNewDisplayName("");
      setShowCreate(false);
      await fetchUsers();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  async function handleDelete(id: string, name: string) {
    setDeleteTarget({ id, name });
  }

  async function confirmDelete() {
    if (!deleteTarget) return;
    try {
      await deleteUser(deleteTarget.id);
      await fetchUsers();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setDeleteTarget(null);
    }
  }

  async function handleRoleChange(id: string, newRole: string) {
    try {
      setSaving((s) => ({ ...s, [id]: true }));
      await setUserRole(id, newRole);
      setPendingRoles((p) => {
        const next = { ...p };
        delete next[id];
        return next;
      });
      await fetchUsers();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSaving((s) => {
        const next = { ...s };
        delete next[id];
        return next;
      });
    }
  }

  function stageRole(id: string, currentRole: string, newRole: string) {
    if (newRole === currentRole) {
      setPendingRoles((p) => {
        const next = { ...p };
        delete next[id];
        return next;
      });
    } else {
      setPendingRoles((p) => ({ ...p, [id]: newRole }));
    }
  }

  const pendingChanges = Object.keys(pendingRoles).length;

  const isAdmin = currentUser?.role === "admin";
  const perms = getPermissions(currentUser?.role);

  const pendingApprovalCount = users.filter((u) => u.role === "pending").length;

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
          <h2>Users</h2>
          <p className="text-sm" style={{ marginTop: 2 }}>
            {users.length} user{users.length !== 1 ? "s" : ""}
            {pendingApprovalCount > 0 && (
              <span style={{ color: "var(--color-warning, #f59e0b)", marginLeft: "0.5rem" }}>
                ({pendingApprovalCount} pending approval)
              </span>
            )}
          </p>
        </div>
        <div className="flex gap-2">
          <button className="outline" onClick={fetchUsers}>
            Refresh
          </button>
          {perms.canWriteUsers && (
            <button onClick={() => setShowCreate(!showCreate)}>
              {showCreate ? "Cancel" : "Create User"}
            </button>
          )}
        </div>
      </div>

      {error && (
        <div className="alert error" style={{ marginBottom: "1rem" }}>
          {error}
        </div>
      )}

      {showCreate && (
        <form onSubmit={handleCreate} className="card" style={{ marginBottom: "1rem" }}>
          <div className="card-body">
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr auto", gap: "0.75rem", alignItems: "end" }}>
              <div>
                <label className="text-xs text-secondary" style={{ display: "block", marginBottom: 4 }}>Username *</label>
                <input value={newName} onChange={(e) => setNewName(e.target.value)} required style={{ width: "100%" }} />
              </div>
              <div>
                <label className="text-xs text-secondary" style={{ display: "block", marginBottom: 4 }}>Display Name</label>
                <input value={newDisplayName} onChange={(e) => setNewDisplayName(e.target.value)} style={{ width: "100%" }} />
              </div>
              <button type="submit">Create</button>
            </div>
          </div>
        </form>
      )}

      <div className="card" style={{ padding: 0 }}>
        {users.length === 0 ? (
          <div className="empty-state">
            <h3>No users</h3>
            <p>Create a user to get started.</p>
          </div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table>
              <thead>
                <tr>
                  <th>User</th>
                  <th>Role</th>
                  <th>Provider</th>
                  <th>Created</th>
                  {perms.canWriteUsers && <th style={{ width: 80 }} />}
                </tr>
              </thead>
              <tbody>
                {users.map((user) => (
                  <tr key={user.id}>
                    <td>
                      <div className="flex items-center gap-3">
                        {user.profile_pic_url ? (
                          <img
                            src={user.profile_pic_url}
                            alt=""
                            style={{
                              width: 32,
                              height: 32,
                              borderRadius: "50%",
                              objectFit: "cover",
                              flexShrink: 0,
                            }}
                          />
                        ) : (
                        <div
                          style={{
                            width: 32,
                            height: 32,
                            borderRadius: "50%",
                            background: "var(--color-surface-2)",
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "center",
                            fontSize: "0.75rem",
                            fontWeight: 600,
                            color: "var(--color-text-secondary)",
                            flexShrink: 0,
                          }}
                        >
                          {(user.display_name || user.name || "?").charAt(0).toUpperCase()}
                        </div>
                        )}
                        <div>
                          <div style={{ fontWeight: 500 }}>{user.name}</div>
                          {user.display_name && (
                            <div className="text-xs text-tertiary">{user.display_name}</div>
                          )}
                        </div>
                      </div>
                    </td>
                    <td>
                      {(() => {
                        const staged = pendingRoles[user.id];
                        const canEdit = isAdmin && user.id !== currentUser?.id;
                        const isSaving = saving[user.id];

                        if (!canEdit) {
                          return (
                            <span style={{
                              fontSize: "0.6875rem",
                              fontWeight: 500,
                              color: "var(--color-text-secondary)",
                              marginLeft: "1rem",
                            }}>
                              {roleLabel(user.role)}
                            </span>
                          );
                        }

                        return (
                          <div className="flex items-center gap-2">
                            <RoleDropdown
                              value={staged ?? user.role}
                              savedValue={user.role}
                              onChange={(role) => stageRole(user.id, user.role, role)}
                              disabled={isSaving}
                            />
                          </div>
                        );
                      })()}
                    </td>
                    <td className="text-xs text-tertiary">{user.provider || "local"}</td>
                    <td className="text-sm text-secondary">
                      {user.created_at ? new Date(user.created_at).toLocaleDateString() : "—"}
                    </td>
                    {perms.canWriteUsers && (
                      <td>
                        <div className="flex gap-2">
                          {user.role === "pending" && !pendingRoles[user.id] && (
                            <button
                              className="sm"
                              onClick={() => stageRole(user.id, user.role, "member")}
                            >
                              Approve
                            </button>
                          )}
                          {user.id !== currentUser?.id && user.role !== "pending" && isAdmin && (
                            <button
                              className="outline sm"
                              onClick={() => stageRole(user.id, user.role, "pending")}
                            >
                              Suspend
                            </button>
                          )}
                          {user.id !== currentUser?.id && (
                            <button
                              className="danger sm"
                              onClick={() => handleDelete(user.id, user.name)}
                            >
                              Delete
                            </button>
                          )}
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
      <ConfirmModal
        open={!!deleteTarget}
        title="Delete user"
        message={`Delete user "${deleteTarget?.name}" and all associated data? This cannot be undone.`}
        confirmLabel="Delete"
        destructive
        onConfirm={confirmDelete}
        onCancel={() => setDeleteTarget(null)}
      />

      <UnsavedFooter
        visible={pendingChanges > 0}
        message={`${pendingChanges} unsaved role change${pendingChanges !== 1 ? "s" : ""}`}
        onDiscard={() => setPendingRoles({})}
        onSave={async () => {
          for (const [id, role] of Object.entries(pendingRoles)) {
            await handleRoleChange(id, role);
          }
        }}
        saveLabel="Apply all"
      />
    </div>
  );
}
