import { type ReactNode, useState, useRef, useEffect } from "react";
import { useAuth } from "./auth";
import { Link, useRouter } from "./router";
import { useTheme } from "./theme";
import { updateProfile, uploadAvatar } from "./api";
import { getPermissions, type Permissions } from "./permissions";

const navItems = [
  {
    path: "/admin/machines",
    label: "Machines",
    visible: (p: Permissions) => p.canViewMachines,
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <rect x="2" y="2" width="20" height="8" rx="2" ry="2" />
        <rect x="2" y="14" width="20" height="8" rx="2" ry="2" />
        <line x1="6" y1="6" x2="6.01" y2="6" />
        <line x1="6" y1="18" x2="6.01" y2="18" />
      </svg>
    ),
  },
  {
    path: "/admin/users",
    label: "Users",
    visible: (p: Permissions) => p.canViewUsers,
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
        <circle cx="9" cy="7" r="4" />
        <path d="M23 21v-2a4 4 0 0 0-3-3.87" />
        <path d="M16 3.13a4 4 0 0 1 0 7.75" />
      </svg>
    ),
  },
  {
    path: "/admin/acls",
    label: "Access Controls",
    visible: (p: Permissions) => p.canViewACL,
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
        <path d="M7 11V7a5 5 0 0 1 10 0v4" />
      </svg>
    ),
  },
  {
    path: "/admin/dns",
    label: "DNS",
    visible: (p: Permissions) => p.canViewDNS,
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="12" cy="12" r="10" />
        <line x1="2" y1="12" x2="22" y2="12" />
        <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
      </svg>
    ),
  },
  {
    path: "/admin/services",
    label: "Services",
    visible: (p: Permissions) => p.canViewServices,
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 2L2 7l10 5 10-5-10-5z" />
        <path d="M2 17l10 5 10-5" />
        <path d="M2 12l10 5 10-5" />
      </svg>
    ),
  },
  {
    path: "/admin/logs",
    label: "Logs",
    visible: (p: Permissions) => p.canViewLogs,
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
        <polyline points="14 2 14 8 20 8" />
      </svg>
    ),
  },
  {
    path: "/admin/settings",
    label: "Settings",
    visible: (p: Permissions) => p.canViewSettings,
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="12" cy="12" r="3" />
        <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
      </svg>
    ),
  },
];

function isActive(item: (typeof navItems)[number], currentPath: string): boolean {
  return currentPath === item.path || currentPath.startsWith(item.path + "/");
}

export function Layout({ children }: { children: ReactNode }) {
  const { user, logout, setUser } = useAuth();
  const { path } = useRouter();
  const { theme, toggle: toggleTheme } = useTheme();
  const perms = getPermissions(user?.role);

  const [profileOpen, setProfileOpen] = useState(false);
  const [editDisplayName, setEditDisplayName] = useState("");
  const [editPicUrl, setEditPicUrl] = useState("");
  const [saving, setSaving] = useState(false);
  const [uploading, setUploading] = useState(false);
  const popoverRef = useRef<HTMLDivElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Close popover on outside click
  useEffect(() => {
    if (!profileOpen) return;
    function onClickOutside(e: MouseEvent) {
      if (popoverRef.current && !popoverRef.current.contains(e.target as Node)) {
        setProfileOpen(false);
      }
    }
    document.addEventListener("mousedown", onClickOutside);
    return () => document.removeEventListener("mousedown", onClickOutside);
  }, [profileOpen]);

  function openProfile() {
    setEditDisplayName(user?.display_name || user?.name || "");
    setEditPicUrl(user?.profile_pic_url || "");
    setProfileOpen(true);
  }

  async function saveProfile() {
    if (!user) return;
    setSaving(true);
    try {
      const updated = await updateProfile(editDisplayName, editPicUrl);
      setUser(updated);
      setProfileOpen(false);
    } catch {
      // keep popover open on error
    } finally {
      setSaving(false);
    }
  }

  async function handleAvatarUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploading(true);
    try {
      const updated = await uploadAvatar(file);
      setUser(updated);
      setEditPicUrl(updated.profile_pic_url || "");
    } catch {
      // ignore
    } finally {
      setUploading(false);
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  }

  return (
    <div className="flex-col" style={{ minHeight: "100vh" }}>
      {/* Header */}
      <header
        style={{
          background: "var(--color-surface)",
          borderBottom: "1px solid var(--color-border)",
        }}
      >
        {/* Top row: logo + user */}
        <div
          className="flex items-center justify-between"
          style={{
            maxWidth: 1200,
            margin: "0 auto",
            padding: "0.75rem 1.5rem",
          }}
        >
          {/* Left: logo */}
          <Link
            to="/admin/machines"
            className="flex items-center gap-2"
            style={{ textDecoration: "none" }}
          >
            <svg
              width="28"
              height="14"
              viewBox="0 0 1280 640"
              xmlns="http://www.w3.org/2000/svg"
            >
              <circle cx="141.023" cy="338.36" r="117.472" style={{ fill: "#f8b5cb" }} transform="matrix(.997276 0 0 1.00556 10.0024 -14.823)" />
              <circle cx="352.014" cy="268.302" r="33.095" style={{ fill: "#a2a2a2" }} transform="matrix(1.01749 0 0 1 -3.15847 0)" />
              <circle cx="352.014" cy="268.302" r="33.095" style={{ fill: "#a2a2a2" }} transform="matrix(1.01749 0 0 1 -3.15847 115.914)" />
              <circle cx="352.014" cy="268.302" r="33.095" style={{ fill: "#a2a2a2" }} transform="matrix(1.01749 0 0 1 148.43 115.914)" />
              <circle cx="352.014" cy="268.302" r="33.095" style={{ fill: "#a2a2a2" }} transform="matrix(1.01749 0 0 1 148.851 0)" />
              <circle cx="805.557" cy="336.915" r="118.199" style={{ fill: "#8d8d8d" }} transform="matrix(.99196 0 0 1 3.36978 -10.2458)" />
              <circle cx="805.557" cy="336.915" r="118.199" style={{ fill: "#8d8d8d" }} transform="matrix(.99196 0 0 1 255.633 -10.2458)" />
              <path d="M680.282 124.808h-68.093v390.325h68.081v-28.23H640V153.228h40.282v-28.42Z" style={{ fill: "var(--color-text-tertiary)" }} />
              <path d="M680.282 124.808h-68.093v390.325h68.081v-28.23H640V153.228h40.282v-28.42Z" style={{ fill: "var(--color-text-tertiary)" }} transform="matrix(-1 0 0 1 1857.19 0)" />
            </svg>
            <span
              style={{
                fontWeight: 600,
                fontSize: "1.125rem",
                color: "var(--color-text)",
              }}
            >
              headscale
            </span>
          </Link>

          {/* Right: user menu */}
          {user && (
            <div className="flex items-center gap-3" style={{ position: "relative" }}>
              <button
                onClick={openProfile}
                className="flex items-center gap-2"
                style={{
                  background: "none",
                  border: "none",
                  cursor: "pointer",
                  padding: "0.25rem 0.5rem",
                  borderRadius: "var(--radius)",
                  color: "inherit",
                }}
              >
                {user.profile_pic_url ? (
                  <img
                    src={user.profile_pic_url}
                    alt=""
                    style={{
                      width: 28,
                      height: 28,
                      borderRadius: "50%",
                      objectFit: "cover",
                    }}
                  />
                ) : (
                  <div
                    style={{
                      width: 28,
                      height: 28,
                      borderRadius: "50%",
                      background: "var(--color-primary-subtle)",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      fontSize: "0.75rem",
                      fontWeight: 600,
                      color: "var(--color-primary)",
                    }}
                  >
                    {(user.display_name || user.name || "?")
                      .charAt(0)
                      .toUpperCase()}
                  </div>
                )}
                <span className="text-sm" style={{ color: "var(--color-text)" }}>
                  {user.display_name || user.name}
                </span>
                <span
                  className="text-xs"
                  style={{ color: "var(--color-text-tertiary)" }}
                >
                  {user.role === "network_admin" ? "Network admin" : user.role === "it_admin" ? "IT admin" : user.role === "service_account" ? "Service account" : user.role}
                </span>
              </button>
              <button className="ghost sm" onClick={logout}>
                Sign out
              </button>

              {/* Profile popover */}
              {profileOpen && (
                <div
                  ref={popoverRef}
                  style={{
                    position: "absolute",
                    top: "calc(100% + 8px)",
                    right: 0,
                    width: 320,
                    background: "var(--color-surface)",
                    border: "1px solid var(--color-border)",
                    borderRadius: "var(--radius-lg, 8px)",
                    boxShadow: "0 8px 24px rgba(0,0,0,0.15)",
                    padding: "1rem",
                    zIndex: 100,
                  }}
                >
                  <div style={{ marginBottom: "0.75rem", fontWeight: 600, fontSize: "0.875rem", color: "var(--color-text)" }}>
                    Edit Profile
                  </div>

                  {/* Current avatar preview */}
                  <div className="flex items-center gap-3" style={{ marginBottom: "1rem" }}>
                    <div style={{ position: "relative", cursor: "pointer" }} onClick={() => fileInputRef.current?.click()}>
                      {editPicUrl ? (
                        <img
                          src={editPicUrl}
                          alt=""
                          style={{
                            width: 48,
                            height: 48,
                            borderRadius: "50%",
                            objectFit: "cover",
                            border: "2px solid var(--color-border)",
                          }}
                        />
                      ) : (
                        <div
                          style={{
                            width: 48,
                            height: 48,
                            borderRadius: "50%",
                            background: "var(--color-primary-subtle)",
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "center",
                            fontSize: "1.125rem",
                            fontWeight: 600,
                            color: "var(--color-primary)",
                          }}
                        >
                          {(editDisplayName || user.name || "?").charAt(0).toUpperCase()}
                        </div>
                      )}
                      {/* Camera overlay */}
                      <div
                        style={{
                          position: "absolute",
                          bottom: -2,
                          right: -2,
                          width: 18,
                          height: 18,
                          borderRadius: "50%",
                          background: "var(--color-primary)",
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "center",
                        }}
                      >
                        <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                          <path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z" />
                          <circle cx="12" cy="13" r="4" />
                        </svg>
                      </div>
                      <input
                        ref={fileInputRef}
                        type="file"
                        accept="image/jpeg,image/png,image/gif,image/webp"
                        onChange={handleAvatarUpload}
                        style={{ display: "none" }}
                      />
                    </div>
                    <div>
                      <div style={{ fontWeight: 500, fontSize: "0.875rem", color: "var(--color-text)" }}>
                        {editDisplayName || user.name}
                      </div>
                      <div style={{ fontSize: "0.75rem", color: "var(--color-text-secondary)" }}>
                        {uploading ? "Uploading..." : user.name}
                      </div>
                    </div>
                  </div>

                  {/* Display Name */}
                  <label style={{ display: "block", marginBottom: "0.75rem" }}>
                    <span style={{ fontSize: "0.75rem", fontWeight: 500, color: "var(--color-text-secondary)", display: "block", marginBottom: "0.25rem" }}>
                      Display Name
                    </span>
                    <input
                      type="text"
                      value={editDisplayName}
                      onChange={(e) => setEditDisplayName(e.target.value)}
                      placeholder={user.name}
                      style={{ width: "100%" }}
                    />
                  </label>

                  {/* Profile Picture URL */}
                  <label style={{ display: "block", marginBottom: "1rem" }}>
                    <span style={{ fontSize: "0.75rem", fontWeight: 500, color: "var(--color-text-secondary)", display: "block", marginBottom: "0.25rem" }}>
                      Or enter image URL
                    </span>
                    <input
                      type="url"
                      value={editPicUrl}
                      onChange={(e) => setEditPicUrl(e.target.value)}
                      placeholder="https://example.com/avatar.jpg"
                      style={{ width: "100%" }}
                    />
                    <span style={{ fontSize: "0.6875rem", color: "var(--color-text-tertiary)", marginTop: "0.25rem", display: "block" }}>
                      Profile picture shows on Tailscale clients across your network
                    </span>
                  </label>

                  {/* Actions */}
                  <div className="flex items-center" style={{ gap: "0.5rem", justifyContent: "flex-end" }}>
                    <button className="ghost sm" onClick={() => setProfileOpen(false)}>
                      Cancel
                    </button>
                    <button className="primary sm" onClick={saveProfile} disabled={saving}>
                      {saving ? "Saving..." : "Save"}
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Nav tabs row */}
        <nav
          className="flex items-center"
          style={{
            maxWidth: 1200,
            margin: "0 auto",
            padding: "0 1.5rem",
            gap: "0.25rem",
          }}
        >
          {navItems
            .filter((item) => item.visible(perms))
            .map((item) => {
              const active = isActive(item, path);
              return (
                <Link
                  key={item.path}
                  to={item.path}
                  className="nav-tab"
                  data-active={active || undefined}
                >
                  {item.icon}
                  {item.label}
                </Link>
              );
            })}

          {/* Right-aligned */}
          <a
            href="#"
            className="icon-btn"
            title="GitHub"
            onClick={(e) => e.preventDefault()}
            style={{ marginLeft: "auto", padding: "0.375rem", borderRadius: "var(--radius)", background: "transparent", border: "none", color: "var(--color-text-tertiary)", cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", textDecoration: "none" }}
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z" />
            </svg>
          </a>
          <a
            href="#"
            className="icon-btn"
            title="Discord"
            onClick={(e) => e.preventDefault()}
            style={{ padding: "0.375rem", borderRadius: "var(--radius)", background: "transparent", border: "none", color: "var(--color-text-tertiary)", cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", textDecoration: "none" }}
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
              <path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028c.462-.63.874-1.295 1.226-1.994a.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.947 2.418-2.157 2.418z" />
            </svg>
          </a>
          <Link
            to="/admin/docs"
            className="icon-btn"
            title="Documentation"
            style={{ padding: "0.375rem", borderRadius: "var(--radius)", background: "transparent", border: "none", color: path === "/admin/docs" ? "var(--color-primary)" : "var(--color-text-tertiary)", cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", textDecoration: "none" }}
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z" />
              <path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z" />
            </svg>
          </Link>
          <button
            onClick={toggleTheme}
            className="icon-btn"
            title={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
            style={{ padding: "0.375rem", borderRadius: "var(--radius)", background: "transparent", border: "none", color: "var(--color-text-tertiary)", cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center" }}
          >
            {theme === "dark" ? (
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="12" cy="12" r="5" />
                <line x1="12" y1="1" x2="12" y2="3" />
                <line x1="12" y1="21" x2="12" y2="23" />
                <line x1="4.22" y1="4.22" x2="5.64" y2="5.64" />
                <line x1="18.36" y1="18.36" x2="19.78" y2="19.78" />
                <line x1="1" y1="12" x2="3" y2="12" />
                <line x1="21" y1="12" x2="23" y2="12" />
                <line x1="4.22" y1="19.78" x2="5.64" y2="18.36" />
                <line x1="18.36" y1="5.64" x2="19.78" y2="4.22" />
              </svg>
            ) : (
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
              </svg>
            )}
          </button>
        </nav>
      </header>

      {/* Main content */}
      <main
        style={{
          flex: 1,
          maxWidth: 1200,
          margin: "0 auto",
          padding: "1.5rem",
          width: "100%",
        }}
      >
        {perms.canAccessAdmin ? children : (
          <div style={{ textAlign: "center", padding: "4rem 1rem" }}>
            <h2>Access Restricted</h2>
            <p className="text-secondary" style={{ marginTop: "0.5rem" }}>
              Your account does not have permission to access the admin console.
              Contact an administrator if you need access.
            </p>
          </div>
        )}
      </main>
    </div>
  );
}
