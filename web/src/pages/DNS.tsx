import { useState, useEffect, useCallback, useMemo, useRef } from "react";
import {
  getDNSConfig,
  updateDNSConfig,
  restoreDNSDefaults,
  type DNSConfig,
} from "../api";
import { useAuth } from "../auth";
import { getPermissions } from "../permissions";

/* ------------------------------------------------------------------ */
/*  Icons                                                              */
/* ------------------------------------------------------------------ */

function LockIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="11" width="18" height="11" rx="2" ry="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" />
    </svg>
  );
}

function ChevronIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="9 18 15 12 9 6" />
    </svg>
  );
}

function ChevronDownIcon() {
  return (
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="6 9 12 15 18 9" />
    </svg>
  );
}

function CloseIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
    </svg>
  );
}

function CopyIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="9" y="9" width="13" height="13" rx="2" ry="2" /><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
    </svg>
  );
}

function CheckIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--color-success)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="20 6 9 17 4 12" />
    </svg>
  );
}

function DotsIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
      <circle cx="12" cy="5" r="1.5" /><circle cx="12" cy="12" r="1.5" /><circle cx="12" cy="19" r="1.5" />
    </svg>
  );
}

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

function Section({ title, description, children }: { title: string; description?: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: "2.5rem" }}>
      <h3 style={{ fontSize: "1.0625rem", fontWeight: 700, marginBottom: "0.25rem" }}>{title}</h3>
      {description && (
        <p className="text-sm text-secondary" style={{ marginBottom: "1rem", lineHeight: 1.6 }}>
          {description}{" "}
          <a href="https://headscale.net/ref/dns/" target="_blank" rel="noopener noreferrer">Learn more</a>
        </p>
      )}
      {children}
    </div>
  );
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      className="icon-btn"
      title="Copy"
      onClick={() => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1500); }}
    >
      {copied ? <CheckIcon /> : <CopyIcon />}
    </button>
  );
}

function Toggle({ checked, onChange }: { checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <button
      onClick={() => onChange(!checked)}
      style={{
        width: 40,
        height: 22,
        borderRadius: 11,
        background: checked ? "var(--color-primary)" : "var(--color-border)",
        border: "none",
        position: "relative",
        cursor: "pointer",
        transition: "background 150ms",
        flexShrink: 0,
        padding: 0,
      }}
    >
      <div style={{
        width: 18,
        height: 18,
        borderRadius: "50%",
        background: "#fff",
        position: "absolute",
        top: 2,
        left: checked ? 20 : 2,
        transition: "left 150ms",
      }} />
    </button>
  );
}

/** A field that looks "locked" / read-only with muted text and icon */
function LockedField({ value, icon }: { value: string; icon?: React.ReactNode }) {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "0.625rem 0.875rem",
        background: "var(--color-surface)",
        border: "1px solid var(--color-border)",
        borderRadius: "var(--radius)",
        fontFamily: "var(--font-mono)",
        fontSize: "0.8125rem",
        color: "var(--color-text-tertiary)",
      }}
    >
      <span>{value}</span>
      {icon ?? <LockIcon />}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Provider definitions                                               */
/* ------------------------------------------------------------------ */

interface ProviderDef {
  name: string;
  label: string;       // full display name
  ips: string[];
  doh?: boolean;       // display as "DoH" instead of IP
}

const DNS_PROVIDERS: ProviderDef[] = [
  { name: "cloudflare", label: "Cloudflare Public DNS", ips: ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"] },
  { name: "google", label: "Google Public DNS", ips: ["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"] },
  { name: "quad9", label: "Quad9 Public DNS", ips: ["9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"] },
  { name: "mullvad", label: "Mullvad DNS", ips: ["194.242.2.2", "194.242.2.3", "194.242.2.4", "194.242.2.5", "194.242.2.9"] },
  { name: "nextdns", label: "NextDNS", ips: [], doh: true },
  { name: "opendns", label: "OpenDNS", ips: ["208.67.222.222", "208.67.220.220", "2620:119:35::35", "2620:119:53::53"] },
  { name: "adguard", label: "AdGuard DNS", ips: ["94.140.14.14", "94.140.15.15", "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"] },
];

/** Group a list of IPs into provider groups */
function groupNameservers(servers: string[]): { provider: ProviderDef | null; ips: string[] }[] {
  const remaining = [...servers];
  const groups: { provider: ProviderDef | null; ips: string[] }[] = [];

  // NextDNS special
  const nextdns = remaining.filter(s => s.includes("dns.nextdns.io"));
  if (nextdns.length) {
    groups.push({ provider: DNS_PROVIDERS.find(p => p.name === "nextdns")!, ips: nextdns });
    nextdns.forEach(s => { const idx = remaining.indexOf(s); if (idx >= 0) remaining.splice(idx, 1); });
  }

  for (const provider of DNS_PROVIDERS) {
    if (!provider.ips.length) continue;
    const matched = remaining.filter(s => provider.ips.includes(s));
    if (matched.length) {
      groups.push({ provider, ips: matched });
      matched.forEach(s => { const idx = remaining.indexOf(s); if (idx >= 0) remaining.splice(idx, 1); });
    }
  }

  if (remaining.length) {
    groups.push({ provider: null, ips: remaining });
  }
  return groups;
}

/* ------------------------------------------------------------------ */
/*  Dropdown menu (used for "Add nameserver" and "..." menus)          */
/* ------------------------------------------------------------------ */

function Dropdown({ trigger, children, align = "left" }: {
  trigger: React.ReactNode;
  children: React.ReactNode;
  align?: "left" | "right";
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [open]);

  return (
    <div ref={ref} style={{ position: "relative", display: "inline-block" }}>
      <div onClick={() => setOpen(!open)}>{trigger}</div>
      {open && (
        <div
          style={{
            position: "absolute",
            top: "calc(100% + 4px)",
            [align === "right" ? "right" : "left"]: 0,
            minWidth: 240,
            background: "var(--color-surface-2)",
            border: "1px solid var(--color-border)",
            borderRadius: "var(--radius)",
            boxShadow: "var(--shadow-md)",
            zIndex: 50,
            padding: "0.25rem 0",
            overflow: "hidden",
          }}
          onClick={() => setOpen(false)}
        >
          {children}
        </div>
      )}
    </div>
  );
}

function DropdownItem({ children, onClick, destructive }: { children: React.ReactNode; onClick: () => void; destructive?: boolean }) {
  return (
    <button
      onClick={onClick}
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        width: "100%",
        padding: "0.5rem 0.75rem",
        background: "none",
        border: "none",
        color: destructive ? "var(--color-danger)" : "var(--color-text)",
        fontSize: "0.8125rem",
        cursor: "pointer",
        textAlign: "left",
        borderRadius: 0,
      }}
      onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface)")}
      onMouseLeave={e => (e.currentTarget.style.background = "none")}
    >
      {children}
    </button>
  );
}

/* ------------------------------------------------------------------ */
/*  Modal dialog                                                       */
/* ------------------------------------------------------------------ */

function Modal({ open, onClose, title, children }: {
  open: boolean;
  onClose: () => void;
  title: string;
  children: React.ReactNode;
}) {
  if (!open) return null;
  return (
    <div className="overlay" onClick={onClose}>
      <div className="dialog" onClick={e => e.stopPropagation()} style={{ minWidth: 440, maxWidth: 500 }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "1.25rem" }}>
          <h3 style={{ fontWeight: 600, fontSize: "0.9375rem" }}>{title}</h3>
          <button className="icon-btn" onClick={onClose}><CloseIcon /></button>
        </div>
        {children}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Nameserver group row (Tailscale card-style)                        */
/* ------------------------------------------------------------------ */

function NameserverGroupRow({ provider, ips, onRemove, onEdit, isLast }: {
  provider: ProviderDef | null;
  ips: string[];
  onRemove: () => void;
  onEdit: () => void;
  isLast: boolean;
}) {
  const [expanded, setExpanded] = useState(false);
  const label = provider?.label ?? "Custom";
  const summary = provider?.doh
    ? "DoH"
    : ips.length === 1
      ? ips[0]
      : `${ips[0]} and ${ips.length - 1} more`;

  return (
    <div style={{ borderBottom: isLast ? undefined : "1px solid var(--color-border)" }}>
      {/* Header row */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "0.625rem 1rem",
          cursor: ips.length > 1 ? "pointer" : undefined,
          gap: "0.75rem",
        }}
        onClick={() => { if (ips.length > 1) setExpanded(!expanded); }}
      >
        <span style={{ fontWeight: 500, fontSize: "0.8125rem", flexShrink: 0 }}>{label}</span>
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginLeft: "auto" }}>
          <span className="text-sm text-secondary" style={{ fontFamily: "var(--font-mono)" }}>{summary}</span>
          {ips.length > 1 && (
            <span className="text-tertiary" style={{
              display: "flex", alignItems: "center",
              transition: "transform 150ms",
              transform: expanded ? "rotate(90deg)" : undefined,
            }}><ChevronIcon /></span>
          )}
          <div onClick={e => e.stopPropagation()}>
            <Dropdown
              trigger={<button className="icon-btn" style={{ padding: "0.25rem" }}><DotsIcon /></button>}
              align="right"
            >
              <DropdownItem onClick={onEdit}>{"Edit\u2026"}</DropdownItem>
              <DropdownItem onClick={onRemove} destructive>Delete</DropdownItem>
            </Dropdown>
          </div>
        </div>
      </div>
      {/* Expanded IP list */}
      {expanded && (
        <div style={{ padding: "0 1rem 0.5rem 1.5rem" }}>
          {ips.map(ip => (
            <div key={ip} style={{
              padding: "0.25rem 0",
              fontFamily: "var(--font-mono)",
              fontSize: "0.8125rem",
              color: "var(--color-text-secondary)",
            }}>{ip}</div>
          ))}
        </div>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Dirty-state detection                                              */
/* ------------------------------------------------------------------ */

function configsEqual(a: DNSConfig, b: DNSConfig): boolean {
  const strip = (c: DNSConfig) => { const { isOverridden: _, ...rest } = c; return rest; };
  return JSON.stringify(strip(a)) === JSON.stringify(strip(b));
}

/* ------------------------------------------------------------------ */
/*  Main page component                                                */
/* ------------------------------------------------------------------ */

export function DNSPage() {
  const { user } = useAuth();
  const [config, setConfig] = useState<DNSConfig | null>(null);
  const [draft, setDraft] = useState<DNSConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  const [restoring, setRestoring] = useState(false);

  // Modals
  const [nsModalOpen, setNsModalOpen] = useState(false);
  const [sdModalOpen, setSdModalOpen] = useState(false);
  const [splitModalOpen, setSplitModalOpen] = useState(false);
  const [recordModalOpen, setRecordModalOpen] = useState(false);
  const [editGroupIdx, setEditGroupIdx] = useState<number | null>(null);

  const isAdmin = user?.role === "admin" || user?.role === "network_admin" || user?.role === "it_admin";
  const perms = getPermissions(user?.role);

  const fetchConfig = useCallback(async () => {
    try {
      const data = await getDNSConfig();
      setConfig(data);
      setDraft(JSON.parse(JSON.stringify(data)));
      setError("");
    } catch { setError("Failed to load DNS configuration."); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { if (isAdmin) fetchConfig(); else setLoading(false); }, [isAdmin, fetchConfig]);

  const isDirty = useMemo(() => !!(config && draft && !configsEqual(config, draft)), [config, draft]);

  if (!isAdmin) return <div><h2>DNS</h2><p className="text-sm text-secondary" style={{ marginTop: "0.25rem" }}>You don't have permission to view DNS settings.</p></div>;
  if (loading) return <div style={{ display: "flex", justifyContent: "center", padding: "3rem" }}><span className="spinner" /></div>;
  if (error || !config || !draft) return <div><h2>DNS</h2><div className="alert error" style={{ marginTop: "1rem" }}>{error}</div></div>;

  const update = (fn: (d: DNSConfig) => void) => {
    setDraft(prev => { if (!prev) return prev; const next = JSON.parse(JSON.stringify(prev)); fn(next); return next; });
  };

  const handleUndo = () => setDraft(JSON.parse(JSON.stringify(config)));

  const handleApply = async () => {
    setSaving(true);
    try {
      const { isOverridden: _, ...payload } = draft;
      const result = await updateDNSConfig(payload);
      setConfig(result);
      setDraft(JSON.parse(JSON.stringify(result)));
    } catch { setError("Failed to save DNS configuration."); }
    finally { setSaving(false); }
  };

  const handleRestore = async () => {
    setRestoring(true);
    try {
      const result = await restoreDNSDefaults();
      setConfig(result);
      setDraft(JSON.parse(JSON.stringify(result)));
    } catch { setError("Failed to restore defaults."); }
    finally { setRestoring(false); }
  };

  const nsGroups = groupNameservers(draft.nameservers.global);
  const splitDomains = Object.entries(draft.nameservers.split);

  // Which providers are already in use (for add dropdown)
  const usedProviders = new Set(nsGroups.map(g => g.provider?.name).filter(Boolean));

  return (
    <div style={{ paddingBottom: isDirty ? "4rem" : undefined }}>
      {/* Header */}
      <div style={{ marginBottom: "2rem" }}>
        <div className="flex items-center justify-between">
          <h2>DNS</h2>
          {perms.canWriteDNS ? (
            <button className="btn outline sm" onClick={handleRestore} disabled={restoring}>
              {restoring ? "Restoring\u2026" : "Reset to defaults"}
            </button>
          ) : (
            <span className="text-sm text-tertiary">Read-only</span>
          )}
        </div>
        <p className="text-sm text-secondary" style={{ marginTop: "0.25rem" }}>
          Manage DNS and nameservers of your network.{" "}
          <a href="https://headscale.net/ref/dns/" target="_blank" rel="noopener noreferrer">Learn more</a>
        </p>
      </div>

      {/* Override banner */}
      {config.isOverridden && !isDirty && (
        <div style={{
          padding: "0.5rem 0.75rem",
          marginBottom: "1.5rem",
          background: "var(--color-primary-subtle)",
          border: "1px solid rgba(59,130,246,0.25)",
          borderRadius: "var(--radius)",
          fontSize: "0.75rem",
          color: "var(--color-text-secondary)",
        }}>
          These settings have been customised and differ from the config file defaults.
        </div>
      )}

      {/* ── Tailnet DNS name ── */}
      <Section title="Tailnet DNS name" description="This unique name is used when registering DNS entries, sharing your device to other tailnets, and issuing TLS certificates.">
        <div style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "0.625rem 0.875rem",
          background: "var(--color-surface)",
          border: "1px solid var(--color-border)",
          borderRadius: "var(--radius)",
          fontFamily: "var(--font-mono)",
          fontSize: "0.8125rem",
          color: "var(--color-text-secondary)",
        }}>
          <span>{draft.baseDomain}</span>
          <CopyButton text={draft.baseDomain} />
        </div>
      </Section>

      {/* ── Nameservers ── */}
      <Section title="Nameservers" description="Set the nameservers used by devices on your network to resolve DNS queries.">
        {/* MagicDNS + base domain row */}
        {draft.baseDomain && (
          <div className="flex items-center gap-2" style={{ marginBottom: "0.75rem" }}>
            <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.8125rem", color: "var(--color-text-secondary)" }}>
              {draft.baseDomain}
            </span>
            {draft.magicDns && <span className="badge admin">MagicDNS</span>}
          </div>
        )}

        {/* Headscale resolver (locked) */}
        <LockedField value="100.100.100.100" />

        {/* Global nameservers label + override toggle */}
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", margin: "1rem 0 0.5rem" }}>
          <span style={{ fontWeight: 600, fontSize: "0.8125rem" }}>Global nameservers</span>
          <div className="flex items-center gap-2">
            <span className="text-sm text-secondary">Override DNS servers</span>
            <Toggle checked={draft.overrideLocalDns} onChange={v => update(x => { x.overrideLocalDns = v; })} />
          </div>
        </div>

        {/* Grouped nameserver card */}
        {nsGroups.length > 0 ? (
          <div className="card" style={{ padding: 0 }}>
            {nsGroups.map((g, i) => (
              <NameserverGroupRow
                key={g.provider?.name ?? `custom-${i}`}
                provider={g.provider}
                ips={g.ips}
                isLast={i === nsGroups.length - 1}
                onRemove={() => update(x => {
                  x.nameservers.global = x.nameservers.global.filter((ip: string) => !g.ips.includes(ip));
                })}
                onEdit={() => setEditGroupIdx(i)}
              />
            ))}
          </div>
        ) : (
          <p className="text-sm text-tertiary" style={{ fontStyle: "italic", marginBottom: "0.5rem" }}>No global nameservers configured</p>
        )}

        {/* Add nameserver dropdown */}
        <div style={{ marginTop: "0.75rem" }}>
          <Dropdown
            trigger={
              <button className="btn outline sm" style={{ gap: "0.375rem" }}>
                Add nameserver <ChevronDownIcon />
              </button>
            }
          >
            {DNS_PROVIDERS.filter(p => !usedProviders.has(p.name)).map(p => (
              <DropdownItem
                key={p.name}
                onClick={() => {
                  if (p.ips.length) {
                    update(x => { x.nameservers.global.push(...p.ips); });
                  }
                }}
              >
                <span>{p.label}</span>
                <span className="text-sm text-tertiary" style={{ fontFamily: "var(--font-mono)" }}>
                  {p.doh ? "DoH" : p.ips[0]}
                </span>
              </DropdownItem>
            ))}
            <div style={{ borderTop: "1px solid var(--color-border)", margin: "0.25rem 0" }} />
            <DropdownItem onClick={() => setNsModalOpen(true)}>{"Custom\u2026"}</DropdownItem>
          </Dropdown>
        </div>

        {/* Split DNS */}
        {splitDomains.length > 0 && (
          <div style={{ marginTop: "1.5rem" }}>
            <span style={{ fontWeight: 600, fontSize: "0.8125rem", display: "block", marginBottom: "0.5rem" }}>Split DNS</span>
            <div className="card" style={{ padding: 0 }}>
              {splitDomains.map(([domain, servers], i) => (
                <div
                  key={domain}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    padding: "0.625rem 1rem",
                    borderBottom: i < splitDomains.length - 1 ? "1px solid var(--color-border)" : undefined,
                  }}
                >
                  <div>
                    <div style={{ fontWeight: 500, fontSize: "0.8125rem" }}>{domain}</div>
                    <div className="text-xs text-tertiary" style={{ fontFamily: "var(--font-mono)", marginTop: "0.125rem" }}>
                      {servers.join(", ")}
                    </div>
                  </div>
                  <Dropdown trigger={<button className="icon-btn" style={{ padding: "0.25rem" }}><DotsIcon /></button>} align="right">
                    <DropdownItem onClick={() => update(x => { delete x.nameservers.split[domain]; })} destructive>Remove</DropdownItem>
                  </Dropdown>
                </div>
              ))}
            </div>
          </div>
        )}
        <div style={{ marginTop: splitDomains.length > 0 ? "0.75rem" : "1rem" }}>
          <button className="btn outline sm" onClick={() => setSplitModalOpen(true)}>{"Add split DNS rule\u2026"}</button>
        </div>
      </Section>

      {/* ── Search Domains ── */}
      <Section title="Search Domains" description="Set custom DNS search domains. With MagicDNS enabled, your tailnet domain is always the first search domain.">
        <div style={{ display: "flex", flexDirection: "column", gap: "0.375rem" }}>
          {draft.baseDomain && draft.magicDns && (
            <LockedField value={draft.baseDomain} />
          )}
          {draft.searchDomains.map((sd, i) => (
            <div
              key={`${sd}-${i}`}
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                padding: "0.625rem 0.875rem",
                background: "var(--color-surface)",
                border: "1px solid var(--color-border)",
                borderRadius: "var(--radius)",
                fontFamily: "var(--font-mono)",
                fontSize: "0.8125rem",
                color: "var(--color-text-secondary)",
              }}
            >
              <span>{sd}</span>
              <Dropdown trigger={<button className="icon-btn" style={{ padding: "0.25rem" }}><DotsIcon /></button>} align="right">
                <DropdownItem onClick={() => update(x => { x.searchDomains.splice(i, 1); })} destructive>Remove</DropdownItem>
              </Dropdown>
            </div>
          ))}
        </div>
        <div style={{ marginTop: "0.75rem" }}>
          <button className="btn outline sm" onClick={() => setSdModalOpen(true)}>{"Add search domain\u2026"}</button>
        </div>
      </Section>

      {/* ── MagicDNS ── */}
      <Section title="MagicDNS" description="Automatically register domain names for devices in your tailnet. This lets you use a machine's name instead of its IP address.">
        <div className="flex items-center justify-between" style={{
          padding: "0.75rem 1rem",
          background: "var(--color-surface)",
          border: "1px solid var(--color-border)",
          borderRadius: "var(--radius)",
        }}>
          <div>
            <div style={{ fontSize: "0.8125rem", fontWeight: 500 }}>{draft.magicDns ? "MagicDNS is enabled" : "MagicDNS is disabled"}</div>
          </div>
          <Toggle checked={draft.magicDns} onChange={v => update(x => { x.magicDns = v; })} />
        </div>
      </Section>

      {/* ── Extra Records ── */}
      <Section title="Extra Records" description="Additional DNS records served to devices in your tailnet.">
        {draft.extraRecords.length > 0 && (
          <div className="card" style={{ padding: 0 }}>
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Type</th>
                  <th>Value</th>
                  <th style={{ width: 40 }} />
                </tr>
              </thead>
              <tbody>
                {draft.extraRecords.map((rec, i) => (
                  <tr key={i}>
                    <td className="font-mono text-sm">{rec.name}</td>
                    <td><span className="badge">{rec.type}</span></td>
                    <td className="font-mono text-sm text-secondary">{rec.value}</td>
                    <td>
                      <Dropdown trigger={<button className="icon-btn" style={{ padding: "0.25rem" }}><DotsIcon /></button>} align="right">
                        <DropdownItem onClick={() => update(x => { x.extraRecords.splice(i, 1); })} destructive>Remove</DropdownItem>
                      </Dropdown>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div style={{ marginTop: "0.75rem" }}>
          <button className="btn outline sm" onClick={() => setRecordModalOpen(true)}>{"Add record\u2026"}</button>
        </div>
      </Section>

      {/* ── Footer ── */}
      <div className="text-xs text-tertiary" style={{
        padding: "0.75rem",
        border: "1px solid var(--color-border)",
        borderRadius: "var(--radius)",
        lineHeight: 1.5,
      }}>
        {config.isOverridden
          ? "These DNS settings are stored in the database and override the config file. Use \"Restore defaults\" to revert."
          : "DNS settings are loaded from the headscale config file. Changes made here will be saved to the database."
        }{" "}
        <a href="https://headscale.net/ref/dns/" target="_blank" rel="noopener noreferrer">Documentation</a>
      </div>

      {/* ── Sticky Undo / Apply bar ── */}
      {isDirty && perms.canWriteDNS && (
        <div style={{
          position: "fixed",
          bottom: 0,
          left: 0,
          right: 0,
          padding: "0.75rem 1.5rem",
          background: "var(--color-surface)",
          borderTop: "1px solid var(--color-border)",
          display: "flex",
          alignItems: "center",
          justifyContent: "flex-end",
          gap: "0.5rem",
          zIndex: 100,
          boxShadow: "0 -2px 12px rgba(0,0,0,0.3)",
        }}>
          <span className="text-sm text-secondary" style={{ marginRight: "auto" }}>You have unsaved changes</span>
          <button className="btn outline sm" onClick={handleUndo} disabled={saving}>Undo</button>
          <button className="btn primary sm" onClick={handleApply} disabled={saving}>{saving ? "Applying\u2026" : "Apply changes"}</button>
        </div>
      )}

      {/* ── Modals ── */}
      <AddNameserverModal open={nsModalOpen} onClose={() => setNsModalOpen(false)} onAdd={(ip, splitDomain) => {
        if (splitDomain) {
          update(x => {
            if (!x.nameservers.split) x.nameservers.split = {};
            if (!x.nameservers.split[splitDomain]) x.nameservers.split[splitDomain] = [];
            x.nameservers.split[splitDomain].push(ip);
          });
        } else {
          update(x => { x.nameservers.global.push(ip); });
        }
      }} />
      <AddSearchDomainModal open={sdModalOpen} onClose={() => setSdModalOpen(false)} onAdd={d => update(x => { x.searchDomains.push(d); })} />
      <AddSplitDnsModal open={splitModalOpen} onClose={() => setSplitModalOpen(false)} onAdd={(domain, server) => update(x => {
        if (!x.nameservers.split) x.nameservers.split = {};
        if (!x.nameservers.split[domain]) x.nameservers.split[domain] = [];
        x.nameservers.split[domain].push(server);
      })} />
      <AddRecordModal open={recordModalOpen} onClose={() => setRecordModalOpen(false)} onAdd={rec => update(x => { x.extraRecords.push(rec); })} />
      <EditNameserverGroupModal
        open={editGroupIdx !== null}
        group={editGroupIdx !== null ? nsGroups[editGroupIdx] : null}
        onClose={() => setEditGroupIdx(null)}
        onSave={(oldIps, newIps) => {
          update(x => {
            x.nameservers.global = x.nameservers.global.filter((ip: string) => !oldIps.includes(ip));
            x.nameservers.global.push(...newIps);
          });
          setEditGroupIdx(null);
        }}
      />
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Add Nameserver modal (matches Tailscale screenshot)                */
/* ------------------------------------------------------------------ */

function AddNameserverModal({ open, onClose, onAdd }: {
  open: boolean;
  onClose: () => void;
  onAdd: (ip: string, splitDomain?: string) => void;
}) {
  const [ip, setIp] = useState("");
  const [useSplit, setUseSplit] = useState(false);
  const [splitDomain, setSplitDomain] = useState("");

  const reset = () => { setIp(""); setUseSplit(false); setSplitDomain(""); };
  const handleClose = () => { reset(); onClose(); };
  const handleSave = () => {
    const v = ip.trim();
    if (!v) return;
    onAdd(v, useSplit && splitDomain.trim() ? splitDomain.trim() : undefined);
    handleClose();
  };

  return (
    <Modal open={open} onClose={handleClose} title="Add nameserver">
      <div style={{ marginBottom: "1rem" }}>
        <div style={{ fontWeight: 600, fontSize: "0.8125rem", marginBottom: "0.125rem" }}>Nameserver</div>
        <p className="text-xs text-tertiary" style={{ marginBottom: "0.5rem" }}>Use this IPv4 or IPv6 address to resolve names.</p>
        <input
          type="text"
          value={ip}
          onChange={e => setIp(e.target.value)}
          onKeyDown={e => e.key === "Enter" && handleSave()}
          placeholder="1.2.3.4"
          style={{ fontFamily: "var(--font-mono)" }}
          autoFocus
        />
      </div>

      <div style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "0.75rem 0",
        borderTop: "1px solid var(--color-border)",
      }}>
        <div>
          <div className="flex items-center gap-2">
            <span style={{ fontWeight: 600, fontSize: "0.8125rem" }}>Restrict to domain</span>
            <span className="badge admin">Split DNS</span>
          </div>
          <p className="text-xs text-tertiary" style={{ marginTop: "0.125rem" }}>This nameserver will only be used for some domains.</p>
        </div>
        <Toggle checked={useSplit} onChange={setUseSplit} />
      </div>

      {useSplit && (
        <div style={{ marginTop: "0.5rem" }}>
          <input
            type="text"
            value={splitDomain}
            onChange={e => setSplitDomain(e.target.value)}
            onKeyDown={e => e.key === "Enter" && handleSave()}
            placeholder="example.com"
            style={{ fontFamily: "var(--font-mono)" }}
          />
        </div>
      )}

      <div style={{ display: "flex", justifyContent: "flex-end", gap: "0.5rem", marginTop: "1.25rem" }}>
        <button className="btn outline" onClick={handleClose}>Cancel</button>
        <button className="btn primary" onClick={handleSave} disabled={!ip.trim()}>Save</button>
      </div>
    </Modal>
  );
}

/* ------------------------------------------------------------------ */
/*  Edit Nameserver Group modal                                        */
/* ------------------------------------------------------------------ */

function EditNameserverGroupModal({ open, group, onClose, onSave }: {
  open: boolean;
  group: { provider: ProviderDef | null; ips: string[] } | null;
  onClose: () => void;
  onSave: (oldIps: string[], newIps: string[]) => void;
}) {
  const [ips, setIps] = useState<string[]>([]);
  const [newIp, setNewIp] = useState("");

  useEffect(() => {
    if (group) setIps([...group.ips]);
  }, [group]);

  const handleClose = () => { setNewIp(""); onClose(); };
  const handleSave = () => {
    if (!group) return;
    onSave(group.ips, ips.filter(ip => ip.trim()));
    handleClose();
  };
  const addIp = () => {
    const v = newIp.trim();
    if (v && !ips.includes(v)) { setIps([...ips, v]); setNewIp(""); }
  };

  if (!group) return null;
  const label = group.provider?.label ?? "Custom nameservers";

  return (
    <Modal open={open} onClose={handleClose} title={`Edit ${label}`}>
      <div style={{ display: "flex", flexDirection: "column", gap: "0.375rem", marginBottom: "0.75rem" }}>
        {ips.map((ip, i) => (
          <div key={i} style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            padding: "0.5rem 0.75rem",
            background: "var(--color-surface)",
            border: "1px solid var(--color-border)",
            borderRadius: "var(--radius)",
            fontFamily: "var(--font-mono)",
            fontSize: "0.8125rem",
            color: "var(--color-text-secondary)",
          }}>
            <span>{ip}</span>
            <button
              className="icon-btn"
              onClick={() => setIps(ips.filter((_, j) => j !== i))}
              style={{ color: "var(--color-danger)" }}
            >
              <CloseIcon />
            </button>
          </div>
        ))}
      </div>
      <div style={{ display: "flex", gap: "0.5rem", marginBottom: "1.25rem" }}>
        <input
          type="text"
          value={newIp}
          onChange={e => setNewIp(e.target.value)}
          onKeyDown={e => { if (e.key === "Enter") addIp(); }}
          placeholder="Add IP address"
          style={{ flex: 1, fontFamily: "var(--font-mono)" }}
        />
        <button className="btn outline sm" onClick={addIp} disabled={!newIp.trim()}>Add</button>
      </div>
      <div style={{ display: "flex", justifyContent: "flex-end", gap: "0.5rem" }}>
        <button className="btn outline" onClick={handleClose}>Cancel</button>
        <button className="btn primary" onClick={handleSave}>Save</button>
      </div>
    </Modal>
  );
}

/* ------------------------------------------------------------------ */
/*  Add Search Domain modal                                            */
/* ------------------------------------------------------------------ */

function AddSearchDomainModal({ open, onClose, onAdd }: {
  open: boolean;
  onClose: () => void;
  onAdd: (domain: string) => void;
}) {
  const [domain, setDomain] = useState("");
  const handleClose = () => { setDomain(""); onClose(); };
  const handleAdd = () => { const v = domain.trim(); if (v) { onAdd(v); handleClose(); } };

  return (
    <Modal open={open} onClose={handleClose} title="Add search domain">
      <input
        type="text"
        value={domain}
        onChange={e => setDomain(e.target.value)}
        onKeyDown={e => e.key === "Enter" && handleAdd()}
        placeholder="foo.example.com"
        style={{ fontFamily: "var(--font-mono)", marginBottom: "0.375rem" }}
        autoFocus
      />
      <p className="text-xs text-tertiary" style={{ marginBottom: "1.25rem" }}>
        The search domain can only contain alphanumeric lowercase characters, hyphens, and periods.
      </p>
      <div style={{ display: "flex", justifyContent: "flex-end", gap: "0.5rem" }}>
        <button className="btn outline" onClick={handleClose}>Cancel</button>
        <button className="btn primary" onClick={handleAdd} disabled={!domain.trim()}>Add search domain</button>
      </div>
    </Modal>
  );
}

/* ------------------------------------------------------------------ */
/*  Add Split DNS modal                                                */
/* ------------------------------------------------------------------ */

function AddSplitDnsModal({ open, onClose, onAdd }: {
  open: boolean;
  onClose: () => void;
  onAdd: (domain: string, server: string) => void;
}) {
  const [domain, setDomain] = useState("");
  const [server, setServer] = useState("");
  const handleClose = () => { setDomain(""); setServer(""); onClose(); };
  const handleAdd = () => {
    const d = domain.trim(), s = server.trim();
    if (d && s) { onAdd(d, s); handleClose(); }
  };

  return (
    <Modal open={open} onClose={handleClose} title="Add split DNS rule">
      <div style={{ marginBottom: "1rem" }}>
        <label>Domain</label>
        <input type="text" value={domain} onChange={e => setDomain(e.target.value)} placeholder="corp.example.com" style={{ fontFamily: "var(--font-mono)" }} autoFocus />
      </div>
      <div style={{ marginBottom: "1.25rem" }}>
        <label>Nameserver</label>
        <input type="text" value={server} onChange={e => setServer(e.target.value)} onKeyDown={e => e.key === "Enter" && handleAdd()} placeholder="10.0.0.1" style={{ fontFamily: "var(--font-mono)" }} />
      </div>
      <div style={{ display: "flex", justifyContent: "flex-end", gap: "0.5rem" }}>
        <button className="btn outline" onClick={handleClose}>Cancel</button>
        <button className="btn primary" onClick={handleAdd} disabled={!domain.trim() || !server.trim()}>Add rule</button>
      </div>
    </Modal>
  );
}

/* ------------------------------------------------------------------ */
/*  Add Extra Record modal                                             */
/* ------------------------------------------------------------------ */

function AddRecordModal({ open, onClose, onAdd }: {
  open: boolean;
  onClose: () => void;
  onAdd: (rec: { name: string; type: string; value: string }) => void;
}) {
  const [name, setName] = useState("");
  const [type, setType] = useState("A");
  const [value, setValue] = useState("");
  const handleClose = () => { setName(""); setValue(""); setType("A"); onClose(); };
  const handleAdd = () => {
    const n = name.trim(), v = value.trim();
    if (n && v) { onAdd({ name: n, type, value: v }); handleClose(); }
  };

  return (
    <Modal open={open} onClose={handleClose} title="Add DNS record">
      <div style={{ marginBottom: "1rem" }}>
        <label>Name</label>
        <input type="text" value={name} onChange={e => setName(e.target.value)} placeholder="myservice.example.com" style={{ fontFamily: "var(--font-mono)" }} autoFocus />
      </div>
      <div style={{ marginBottom: "1rem" }}>
        <label>Type</label>
        <select value={type} onChange={e => setType(e.target.value)} style={{ width: "auto" }}>
          <option value="A">A</option>
          <option value="AAAA">AAAA</option>
          <option value="CNAME">CNAME</option>
        </select>
      </div>
      <div style={{ marginBottom: "1.25rem" }}>
        <label>Value</label>
        <input type="text" value={value} onChange={e => setValue(e.target.value)} onKeyDown={e => e.key === "Enter" && handleAdd()} placeholder="192.168.1.100" style={{ fontFamily: "var(--font-mono)" }} />
      </div>
      <div style={{ display: "flex", justifyContent: "flex-end", gap: "0.5rem" }}>
        <button className="btn outline" onClick={handleClose}>Cancel</button>
        <button className="btn primary" onClick={handleAdd} disabled={!name.trim() || !value.trim()}>Add record</button>
      </div>
    </Modal>
  );
}
