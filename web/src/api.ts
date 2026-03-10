const API_BASE = "/api/v1";

export interface User {
  id: string;
  name: string;
  created_at: string;
  display_name: string;
  email: string;
  provider_id: string;
  provider: string;
  profile_pic_url: string;
  role: string;
}

export interface Node {
  id: string;
  machine_key: string;
  node_key: string;
  disco_key: string;
  ip_addresses: string[];
  name: string;
  user: User;
  last_seen: string;
  expiry: string;
  pre_auth_key: PreAuthKey | null;
  created_at: string;
  register_method: string;
  given_name: string;
  online: boolean;
  approved_routes: string[];
  available_routes: string[];
  subnet_routes: string[];
  tags: string[];
  is_wireguard_only: boolean;
  is_jailed: boolean;
  endpoints: string[];
  valid_tags: string[];
  forced_tags: string[];
  location_country: string;
  location_country_code: string;
  location_city: string;
  location_city_code: string;
  // Enriched fields (from /v1/web/nodes)
  client_version?: string;
  os?: string;
  os_version?: string;
  fqdn?: string;
}

export interface PreAuthKey {
  id: string;
  user: string;
  key: string;
  reusable: boolean;
  ephemeral: boolean;
  used: boolean;
  expiration: string;
  created_at: string;
  acl_tags: string[];
}

export interface LoginResponse {
  session_token: string;
  expires_at: string;
  user: User;
  otp_required: boolean;
}

export interface AuthMethods {
  local_auth_enabled: boolean;
  github_auth_enabled: boolean;
}

class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

function getSessionToken(): string | null {
  const match = document.cookie
    .split("; ")
    .find((c) => c.startsWith("hs_session="));
  return match ? match.split("=")[1] : null;
}

function setSessionCookie(token: string, expiresAt: string) {
  const expires = new Date(expiresAt).toUTCString();
  const secure = window.location.protocol === "https:" ? "; Secure" : "";
  document.cookie = `hs_session=${token}; path=/; expires=${expires}; SameSite=Lax${secure}`;
}

function clearSessionCookie() {
  document.cookie = "hs_session=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT";
}

// Protobuf JSON uses camelCase, but our interfaces use snake_case.
// Convert all response keys from camelCase to snake_case.
function camelToSnake(str: string): string {
  return str.replace(/[A-Z]/g, (letter) => `_${letter.toLowerCase()}`);
}

function convertKeys(obj: unknown): unknown {
  if (Array.isArray(obj)) return obj.map(convertKeys);
  if (obj !== null && typeof obj === "object") {
    const converted: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
      converted[camelToSnake(key)] = convertKeys(value);
    }
    return converted;
  }
  return obj;
}

async function request<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string>),
  };

  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
    credentials: "same-origin",
  });

  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      if (body.message) msg = body.message;
    } catch {
      // ignore
    }
    throw new ApiError(res.status, msg);
  }

  const json = await res.json();
  return convertKeys(json) as T;
}

// --- Auth ---

export async function getAuthMethods(): Promise<AuthMethods> {
  const res = await fetch(`${API_BASE}/webauth/registration/discovery/methods`);
  if (!res.ok) {
    return { local_auth_enabled: true, github_auth_enabled: false };
  }
  const json = await res.json();
  return convertKeys(json) as AuthMethods;
}

export async function loginWithPassword(
  username: string,
  password: string,
): Promise<LoginResponse> {
  const resp = await request<LoginResponse>("/webauth/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });
  if (resp.session_token) {
    setSessionCookie(resp.session_token, resp.expires_at);
  }
  return resp;
}

export async function verifyOTP(code: string): Promise<LoginResponse> {
  const resp = await request<LoginResponse>("/webauth/otp/verify", {
    method: "POST",
    body: JSON.stringify({ code }),
  });
  if (resp.session_token) {
    setSessionCookie(resp.session_token, resp.expires_at);
  }
  return resp;
}

export async function getGitHubAuthURL(): Promise<string> {
  const resp = await request<{ auth_url: string }>("/webauth/github");
  return resp.auth_url;
}

export async function checkApprovalStatus(username: string): Promise<boolean> {
  const res = await fetch(
    `${API_BASE}/webauth/approval-status?username=${encodeURIComponent(username)}`,
  );
  if (!res.ok) return false;
  const json = await res.json();
  return json.approved === true;
}

export async function gitHubCallback(
  code: string,
  state: string,
): Promise<LoginResponse> {
  const resp = await request<LoginResponse>(
    `/webauth/github/callback?code=${encodeURIComponent(code)}&state=${encodeURIComponent(state)}`,
  );
  if (resp.session_token) {
    setSessionCookie(resp.session_token, resp.expires_at);
  }
  return resp;
}

export async function validateSession(): Promise<User> {
  const resp = await request<{ user: User }>("/webauth/session");
  return resp.user;
}

export async function logout(): Promise<void> {
  try {
    await request("/webauth/logout", { method: "POST" });
  } finally {
    clearSessionCookie();
  }
}

// --- Registration ---

export async function approveRegistration(authId: string, user?: string): Promise<void> {
  await request(`/webauth/registration/${encodeURIComponent(authId)}/approve`, {
    method: "POST",
    headers: user ? { "Grpc-Metadata-X-Assign-User": user } : undefined,
  });
}

// --- Users ---

export async function listUsers(): Promise<User[]> {
  const resp = await request<{ users: User[] }>("/user");
  return resp.users ?? [];
}

export async function createUser(
  name: string,
  displayName?: string,
): Promise<User> {
  const resp = await request<{ user: User }>("/user", {
    method: "POST",
    body: JSON.stringify({
      name,
      display_name: displayName,
    }),
  });
  return resp.user;
}

export async function deleteUser(id: string): Promise<void> {
  await request(`/user/${id}`, { method: "DELETE" });
}

export async function setUserRole(id: string, role: string): Promise<User> {
  const resp = await request<{ user: User }>(`/user/${id}/role`, {
    method: "POST",
    body: JSON.stringify({ role }),
  });
  return resp.user;
}

// --- Profile ---

export async function getProfile(): Promise<User> {
  const resp = await request<{ user: User }>("/profile/me");
  return resp.user;
}

export async function updateProfile(
  displayName: string,
  profilePicUrl: string
): Promise<User> {
  const resp = await request<{ user: User }>("/profile/me", {
    method: "PUT",
    body: JSON.stringify({
      display_name: displayName,
      profile_pic_url: profilePicUrl,
    }),
  });
  return resp.user;
}

export async function uploadAvatar(file: File): Promise<User> {
  const form = new FormData();
  form.append("avatar", file);

  const res = await fetch(`${API_BASE}/profile/me/avatar`, {
    method: "POST",
    body: form,
    credentials: "same-origin",
  });

  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try {
      const text = await res.text();
      if (text) msg = text;
    } catch {
      // ignore
    }
    throw new ApiError(res.status, msg);
  }

  const data = await res.json();
  const converted = convertKeys(data) as { user: User };
  return converted.user;
}

// --- Nodes ---

export async function listNodes(): Promise<Node[]> {
  const [nodeResp, extraResp] = await Promise.all([
    request<{ nodes: Node[] }>("/node"),
    request<{ nodes: { id: number; client_version?: string; os?: string; os_version?: string; fqdn?: string }[] }>("/web/nodes").catch(() => ({ nodes: [] })),
  ]);
  const nodes = nodeResp.nodes ?? [];
  const extraMap = new Map(extraResp.nodes.map((e) => [String(e.id), e]));
  for (const n of nodes) {
    const extra = extraMap.get(n.id);
    if (extra) {
      n.client_version = extra.client_version;
      n.os = extra.os;
      n.os_version = extra.os_version;
      n.fqdn = extra.fqdn;
    }
  }
  return nodes;
}

export async function deleteNode(id: string): Promise<void> {
  await request(`/node/${id}`, { method: "DELETE" });
}

export async function expireNode(id: string): Promise<Node> {
  const resp = await request<{ node: Node }>(`/node/${id}/expire`, {
    method: "POST",
  });
  return resp.node;
}

export async function renameNode(
  id: string,
  newName: string,
): Promise<Node> {
  const resp = await request<{ node: Node }>(`/node/${id}/rename/${newName}`, {
    method: "POST",
  });
  return resp.node;
}

export async function setNodeTags(
  id: string,
  tags: string[],
): Promise<Node> {
  const resp = await request<{ node: Node }>(`/node/${id}/tags`, {
    method: "POST",
    body: JSON.stringify({ tags }),
  });
  return resp.node;
}

// --- PreAuth Keys ---

export async function listPreAuthKeys(user: string): Promise<PreAuthKey[]> {
  const resp = await request<{ pre_auth_keys: PreAuthKey[] }>(
    `/preauthkey?user=${encodeURIComponent(user)}`,
  );
  return resp.pre_auth_keys ?? [];
}

export async function createPreAuthKey(params: {
  user: string;
  reusable: boolean;
  ephemeral: boolean;
  expiration: string;
  acl_tags?: string[];
}): Promise<PreAuthKey> {
  const resp = await request<{ pre_auth_key: PreAuthKey }>("/preauthkey", {
    method: "POST",
    body: JSON.stringify(params),
  });
  return resp.pre_auth_key;
}

export async function expirePreAuthKey(params: {
  user: string;
  key: string;
}): Promise<void> {
  await request("/preauthkey/expire", {
    method: "POST",
    body: JSON.stringify(params),
  });
}

// --- API Keys ---

export async function listAPIKeys(): Promise<
  { id: string; prefix: string; expiration: string; created_at: string }[]
> {
  const resp = await request<{
    api_keys: {
      id: string;
      prefix: string;
      expiration: string;
      created_at: string;
    }[];
  }>("/apikey");
  return resp.api_keys ?? [];
}

export async function createAPIKey(expiration: string): Promise<string> {
  const resp = await request<{ api_key: string }>("/apikey", {
    method: "POST",
    body: JSON.stringify({ expiration }),
  });
  return resp.api_key;
}

export async function expireAPIKey(prefix: string): Promise<void> {
  await request("/apikey/expire", {
    method: "POST",
    body: JSON.stringify({ prefix }),
  });
}

// --- Policy ---

export interface PolicyData {
  policy: string;
  updated_at: string;
}

export async function getPolicy(): Promise<PolicyData> {
  return request<PolicyData>("/policy");
}

export async function setPolicy(policy: string): Promise<PolicyData> {
  return request<PolicyData>("/policy", {
    method: "PUT",
    body: JSON.stringify({ policy }),
  });
}

// --- DNS Config ---

export interface DNSConfig {
  magicDns: boolean;
  baseDomain: string;
  overrideLocalDns: boolean;
  nameservers: {
    global: string[];
    split: Record<string, string[]>;
  };
  searchDomains: string[];
  extraRecords: { name: string; type: string; value: string }[];
  isOverridden?: boolean;
}

export async function getDNSConfig(): Promise<DNSConfig> {
  const res = await fetch(`${API_BASE}/dns/config`, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    throw new ApiError(res.status, `HTTP ${res.status}`);
  }
  return res.json();
}

export async function getDNSDefaults(): Promise<DNSConfig> {
  const res = await fetch(`${API_BASE}/dns/config/defaults`, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    throw new ApiError(res.status, `HTTP ${res.status}`);
  }
  return res.json();
}

export async function updateDNSConfig(config: Omit<DNSConfig, "isOverridden">): Promise<DNSConfig> {
  const res = await fetch(`${API_BASE}/dns/config`, {
    method: "PUT",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(config),
  });
  if (!res.ok) {
    throw new ApiError(res.status, `HTTP ${res.status}`);
  }
  return res.json();
}

export async function restoreDNSDefaults(): Promise<DNSConfig> {
  const res = await fetch(`${API_BASE}/dns/config/restore`, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    throw new ApiError(res.status, `HTTP ${res.status}`);
  }
  return res.json();
}

// --- VPN Provider ---

export interface ProviderAccount {
  id: string;
  provider_name: string;
  account_id: string;
  max_keys: number;
  active_keys: number;
  expires_at: string;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface KeyAllocation {
  id: string;
  account_id: string;
  node_id: string;
  node_key: string;
  allocated_at: string;
}

export interface ProviderRelay {
  hostname: string;
  provider_name: string;
  country_code: string;
  country: string;
  city_code: string;
  city: string;
  active: boolean;
}

export async function listProviderAccounts(providerName?: string): Promise<ProviderAccount[]> {
  const q = providerName ? `?provider_name=${encodeURIComponent(providerName)}` : "";
  const resp = await request<{ accounts: ProviderAccount[] }>(`/provider/account${q}`);
  return resp.accounts ?? [];
}

export async function addProviderAccount(params: {
  provider_name: string;
  account_id: string;
  max_keys: number;
}): Promise<ProviderAccount> {
  const resp = await request<{ account: ProviderAccount }>("/provider/account", {
    method: "POST",
    body: JSON.stringify(params),
  });
  return resp.account;
}

export async function removeProviderAccount(id: string): Promise<void> {
  await request(`/provider/account/${id}`, { method: "DELETE" });
}

export async function syncProviderRelays(providerName: string): Promise<number> {
  const resp = await request<{ relay_count: number }>("/provider/relay/sync", {
    method: "POST",
    body: JSON.stringify({ provider_name: providerName }),
  });
  return resp.relay_count;
}

export async function listProviderRelays(providerName?: string, countryCode?: string): Promise<ProviderRelay[]> {
  const params = new URLSearchParams();
  if (providerName) params.set("provider_name", providerName);
  if (countryCode) params.set("country_code", countryCode);
  const q = params.toString() ? `?${params}` : "";
  const resp = await request<{ relays: ProviderRelay[] }>(`/provider/relay${q}`);
  return resp.relays ?? [];
}

export async function listProviderAllocations(providerName?: string): Promise<KeyAllocation[]> {
  const q = providerName ? `?provider_name=${encodeURIComponent(providerName)}` : "";
  const resp = await request<{ allocations: KeyAllocation[] }>(`/provider/allocation${q}`);
  return resp.allocations ?? [];
}

// --- Audit Events ---

export interface AuditEvent {
  id: number;
  timestamp: string;
  event_type: string;
  actor: string;
  target_type: string;
  target_name: string;
  details: string;
}

export async function listAuditEvents(params?: {
  event_type?: string;
  limit?: number;
  offset?: number;
}): Promise<{ events: AuditEvent[]; total: number }> {
  const q = new URLSearchParams();
  if (params?.event_type) q.set("event_type", params.event_type);
  if (params?.limit) q.set("limit", String(params.limit));
  if (params?.offset) q.set("offset", String(params.offset));
  const qs = q.toString() ? `?${q}` : "";
  const res = await fetch(`${API_BASE}/audit/events${qs}`, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    throw new ApiError(res.status, `HTTP ${res.status}`);
  }
  return res.json();
}

// --- Console Logs ---

export interface ConsoleLogEntry {
  timestamp: string;
  message: string;
}

export async function listConsoleLogs(limit?: number): Promise<{ entries: ConsoleLogEntry[] }> {
  const q = limit ? `?limit=${limit}` : "";
  const res = await fetch(`${API_BASE}/console/logs${q}`, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    throw new ApiError(res.status, `HTTP ${res.status}`);
  }
  return res.json();
}

export { ApiError, clearSessionCookie, getSessionToken };

// --- Server Info ---

export interface ServerInfo {
  version: string;
  commit: string;
  buildTime: string;
  go: { version: string; os: string; arch: string };
  dirty: boolean;
  serverUrl: string;
  tailnetDisplayName: string;
  baseDomain: string;
  derpEnabled: boolean;
  databaseType: string;
  logLevel: string;
  policyMode: string;
  prefixV4?: string;
  prefixV6?: string;
  collectServices?: boolean;
}

export async function getServerInfo(): Promise<ServerInfo> {
  const res = await fetch(`${API_BASE}/server/info`, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) throw new ApiError(res.status, `HTTP ${res.status}`);
  return res.json();
}

// --- Discovered Services ---

export interface DiscoveredEndpoint {
  service_name: string;
  ip: string;
  port: number;
  proto: string;
  type: string;
  machine: string;
  user: string;
  node_id: number;
}

export interface DiscoveredServicesResponse {
  endpoints: DiscoveredEndpoint[] | null;
  collect_services: boolean;
}

export async function getDiscoveredServices(): Promise<DiscoveredServicesResponse> {
  const res = await fetch(`${API_BASE}/web/services/discovered`, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) throw new ApiError(res.status, `HTTP ${res.status}`);
  return res.json();
}

export interface DocEntry {
  path: string;
  title: string;
}

export async function getDocsTree(): Promise<DocEntry[]> {
  const res = await fetch(`${API_BASE}/web/docs/tree`, {
    credentials: "same-origin",
  });
  if (!res.ok) throw new ApiError(res.status, `HTTP ${res.status}`);
  const data = await res.json();
  return data.docs;
}

export async function getDocContent(path: string): Promise<string> {
  const res = await fetch(
    `${API_BASE}/web/docs/content?path=${encodeURIComponent(path)}`,
    { credentials: "same-origin" },
  );
  if (!res.ok) throw new ApiError(res.status, `HTTP ${res.status}`);
  return res.text();
}
