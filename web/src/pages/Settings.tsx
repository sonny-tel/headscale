import { useState, useEffect } from "react";
import { PreAuthKeysPage } from "./PreAuthKeys";
import { APIKeysPage } from "./APIKeys";
import { VPNPage } from "./VPN";
import { getServerInfo, type ServerInfo } from "../api";

// ─── General Tab ──────────────────────────────────────────────────────────────

function Section({ title, description, children }: { title: string; description?: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: "2.5rem" }}>
      <h3 style={{ fontSize: "1.0625rem", fontWeight: 700, marginBottom: "0.25rem" }}>{title}</h3>
      {description && (
        <p className="text-sm text-secondary" style={{ marginBottom: "1rem", lineHeight: 1.6 }}>{description}</p>
      )}
      {children}
    </div>
  );
}

function ReadOnlyField({ value, mono }: { value: string; mono?: boolean }) {
  return (
    <div style={{
      display: "flex",
      alignItems: "center",
      padding: "0.625rem 0.875rem",
      background: "var(--color-surface)",
      border: "1px solid var(--color-border)",
      borderRadius: "var(--radius)",
      fontFamily: mono ? "'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace" : "inherit",
      fontSize: "0.8125rem",
      color: "var(--color-text-secondary)",
    }}>
      {value}
    </div>
  );
}

function FieldRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div style={{ marginBottom: "0.75rem" }}>
      <label style={{ display: "block", fontSize: "0.75rem", fontWeight: 500, color: "var(--color-text-secondary)", marginBottom: "0.375rem" }}>{label}</label>
      <ReadOnlyField value={value} mono={mono} />
    </div>
  );
}

function StatusPill({ enabled, labelOn, labelOff }: { enabled: boolean; labelOn?: string; labelOff?: string }) {
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", gap: "0.375rem",
      padding: "0.25rem 0.625rem", borderRadius: "9999px", fontSize: "0.75rem", fontWeight: 500,
      background: enabled ? "color-mix(in srgb, var(--color-success) 15%, transparent)" : "var(--color-surface)",
      color: enabled ? "var(--color-success)" : "var(--color-text-tertiary)",
      border: `1px solid ${enabled ? "color-mix(in srgb, var(--color-success) 30%, transparent)" : "var(--color-border)"}`,
    }}>
      <span style={{ width: 6, height: 6, borderRadius: "50%", background: enabled ? "var(--color-success)" : "var(--color-text-tertiary)" }} />
      {enabled ? (labelOn ?? "Enabled") : (labelOff ?? "Disabled")}
    </span>
  );
}

function GeneralTab() {
  const [info, setInfo] = useState<ServerInfo | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    getServerInfo()
      .then(setInfo)
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, []);

  if (error) {
    return <p style={{ color: "var(--color-danger)" }}>Failed to load server info: {error}</p>;
  }
  if (!info) {
    return <div style={{ padding: "2rem", textAlign: "center" }}><span className="spinner" /></div>;
  }

  const version = info.dirty ? `${info.version}-dirty` : info.version;
  const commitShort = info.commit?.length > 12 ? info.commit.slice(0, 12) : info.commit;

  return (
    <div>
      {/* ── Tailnet Identity ── */}
      <Section title="Tailnet identity" description="The display name and domain used to identify your tailnet.">
        <FieldRow label="Display name" value={info.tailnetDisplayName || "—"} />
        <FieldRow label="Server URL" value={info.serverUrl} mono />
        <FieldRow label="Base domain" value={info.baseDomain || "—"} mono />
      </Section>

      {/* ── Network Configuration ── */}
      <Section title="Network configuration" description="IP address allocation and relay settings for your tailnet.">
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.75rem" }}>
          {info.prefixV4 && <FieldRow label="IPv4 prefix" value={info.prefixV4} mono />}
          {info.prefixV6 && <FieldRow label="IPv6 prefix" value={info.prefixV6} mono />}
        </div>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "0.625rem 0.875rem", background: "var(--color-surface)", border: "1px solid var(--color-border)", borderRadius: "var(--radius)", marginTop: info.prefixV4 || info.prefixV6 ? 0 : undefined }}>
          <span style={{ fontSize: "0.8125rem" }}>Embedded DERP relay</span>
          <StatusPill enabled={info.derpEnabled} />
        </div>
      </Section>

      {/* ── Server Configuration ── */}
      <Section title="Server configuration" description="Database, policy, and logging settings.">
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.75rem" }}>
          <FieldRow label="Database" value={info.databaseType} />
          <FieldRow label="Policy mode" value={info.policyMode} />
          <FieldRow label="Log level" value={info.logLevel} />
        </div>
      </Section>

      {/* ── Build Information ── */}
      <Section title="Build information" description="Version and build details for this headscale instance.">
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.75rem" }}>
          <FieldRow label="Version" value={version} />
          <FieldRow label="Commit" value={commitShort} mono />
          <FieldRow label="Build time" value={info.buildTime || "—"} />
          <FieldRow label="Go" value={`${info.go.version} (${info.go.os}/${info.go.arch})`} mono />
        </div>
      </Section>
    </div>
  );
}

// ─── Settings Page ────────────────────────────────────────────────────────────

const tabs = [
  { id: "general", label: "General" },
  { id: "auth-keys", label: "Auth Keys" },
  { id: "api-keys", label: "API Keys" },
  { id: "vpn", label: "VPN" },
] as const;

type TabId = (typeof tabs)[number]["id"];

export function SettingsPage() {
  const initial = (tabs.find(t => t.id === window.location.hash.replace(/^#/, ""))?.id ?? "general") as TabId;
  const [activeTab, setActiveTab] = useState<TabId>(initial);

  const switchTab = (id: TabId) => {
    setActiveTab(id);
    window.history.replaceState(null, "", `#${id}`);
  };

  return (
    <div>
      <div style={{ marginBottom: "1rem" }}>
        <h2 style={{ fontSize: "1.125rem", fontWeight: 600 }}>Settings</h2>
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
      {activeTab === "general" && <GeneralTab />}
      {activeTab === "auth-keys" && <PreAuthKeysPage />}
      {activeTab === "api-keys" && <APIKeysPage />}
      {activeTab === "vpn" && <VPNPage />}
    </div>
  );
}
