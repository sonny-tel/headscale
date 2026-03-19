-- This file is the representation of the SQLite schema of Headscale.
-- It is the "source of truth" and is used to validate any migrations
-- that are run against the database to ensure it ends in the expected state.

CREATE TABLE migrations(id text,PRIMARY KEY(id));

CREATE TABLE users(
  id integer PRIMARY KEY AUTOINCREMENT,
  name text,
  display_name text,
  email text,
  provider_identifier text,
  provider text,
  profile_pic_url text,
  role text NOT NULL DEFAULT 'member',

  created_at datetime,
  updated_at datetime,
  deleted_at datetime
);
CREATE INDEX idx_users_deleted_at ON users(deleted_at);


-- The following three UNIQUE indexes work together to enforce the user identity model:
--
-- 1. Users can be either local (provider_identifier is NULL) or from external providers (provider_identifier set)
-- 2. Each external provider identifier must be unique across the system
-- 3. Local usernames must be unique among local users
-- 4. The same username can exist across different providers with different identifiers
--
-- Examples:
-- - Can create local user "alice" (provider_identifier=NULL)
-- - Can create external user "alice" with GitHub (name="alice", provider_identifier="alice_github")
-- - Can create external user "alice" with Google (name="alice", provider_identifier="alice_google")
-- - Cannot create another local user "alice" (blocked by idx_name_no_provider_identifier)
-- - Cannot create another user with provider_identifier="alice_github" (blocked by idx_provider_identifier)
-- - Cannot create user "bob" with provider_identifier="alice_github" (blocked by idx_name_provider_identifier)
CREATE UNIQUE INDEX idx_provider_identifier ON users(provider_identifier) WHERE provider_identifier IS NOT NULL;
CREATE UNIQUE INDEX idx_name_provider_identifier ON users(name, provider_identifier);
CREATE UNIQUE INDEX idx_name_no_provider_identifier ON users(name) WHERE provider_identifier IS NULL;

CREATE TABLE pre_auth_keys(
  id integer PRIMARY KEY AUTOINCREMENT,
  key text,
  prefix text,
  hash blob,
  user_id integer,
  reusable numeric,
  ephemeral numeric DEFAULT false,
  used numeric DEFAULT false,
  tags text,
  expiration datetime,

  created_at datetime,

  CONSTRAINT fk_pre_auth_keys_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
);
CREATE UNIQUE INDEX idx_pre_auth_keys_prefix ON pre_auth_keys(prefix) WHERE prefix IS NOT NULL AND prefix != '';

CREATE TABLE api_keys(
  id integer PRIMARY KEY AUTOINCREMENT,
  prefix text,
  hash blob,
  expiration datetime,
  last_seen datetime,

  created_at datetime
);
CREATE UNIQUE INDEX idx_api_keys_prefix ON api_keys(prefix);

CREATE TABLE nodes(
  id integer PRIMARY KEY AUTOINCREMENT,
  machine_key text,
  node_key text,
  disco_key text,

  endpoints text,
  host_info text,
  ipv4 text,
  ipv6 text,
  hostname text,
  given_name varchar(63),
  -- user_id is NULL for tagged nodes (owned by tags, not a user).
  -- Only set for user-owned nodes (no tags).
  user_id integer,
  register_method text,
  tags text,
  auth_key_id integer,
  last_seen datetime,
  expiry datetime,
  approved_routes text,

  is_wireguard_only numeric NOT NULL DEFAULT false,
  is_jailed numeric NOT NULL DEFAULT false,
  exit_node_dns_resolvers text,

  location_country text,
  location_country_code text,
  location_city text,
  location_city_code text,
  location_latitude real,
  location_longitude real,
  location_priority integer DEFAULT 0,

  created_at datetime,
  updated_at datetime,
  deleted_at datetime,

  CONSTRAINT fk_nodes_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT fk_nodes_auth_key FOREIGN KEY(auth_key_id) REFERENCES pre_auth_keys(id)
);

CREATE TABLE policies(
  id integer PRIMARY KEY AUTOINCREMENT,
  data text,

  created_at datetime,
  updated_at datetime,
  deleted_at datetime
);
CREATE INDEX idx_policies_deleted_at ON policies(deleted_at);

CREATE TABLE runtime_dns_configs(
  id integer PRIMARY KEY AUTOINCREMENT,
  data text,

  created_at datetime,
  updated_at datetime,
  deleted_at datetime
);
CREATE INDEX idx_runtime_dns_configs_deleted_at ON runtime_dns_configs(deleted_at);

CREATE TABLE vpn_provider_accounts(
  id integer PRIMARY KEY AUTOINCREMENT,
  provider_name text NOT NULL,
  account_id text NOT NULL,
  max_keys integer NOT NULL DEFAULT 5,
  expires_at datetime,
  enabled numeric NOT NULL DEFAULT true,
  created_at datetime,
  updated_at datetime,
  UNIQUE(provider_name, account_id)
);

CREATE TABLE vpn_key_allocations(
  id integer PRIMARY KEY AUTOINCREMENT,
  account_id integer NOT NULL,
  node_id bigint NOT NULL,
  node_key text NOT NULL,
  assigned_ipv4 text DEFAULT '',
  assigned_ipv6 text DEFAULT '',
  allocated_at datetime,
  UNIQUE(account_id, node_key),
  CONSTRAINT fk_vpn_key_allocations_account FOREIGN KEY(account_id) REFERENCES vpn_provider_accounts(id) ON DELETE CASCADE,
  CONSTRAINT fk_vpn_key_allocations_node FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE
);

CREATE TABLE database_versions(
  id integer PRIMARY KEY,
  version text NOT NULL,
  updated_at datetime
);

CREATE TABLE user_credentials(
  user_id integer PRIMARY KEY,
  password_hash text,
  otp_secret text,
  otp_enabled numeric NOT NULL DEFAULT false,
  git_hub_id text,
  git_hub_login text,
  failed_login_attempts integer NOT NULL DEFAULT 0,
  locked_until datetime,
  password_changed_at datetime,
  must_change_password numeric NOT NULL DEFAULT false,
  created_at datetime,
  updated_at datetime,
  CONSTRAINT fk_user_credentials_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX idx_user_credentials_github_id ON user_credentials(git_hub_id) WHERE git_hub_id IS NOT NULL AND git_hub_id != '';

CREATE TABLE user_sessions(
  id text PRIMARY KEY,
  user_id integer NOT NULL,
  expires_at datetime NOT NULL,
  created_at datetime,
  ip_address text,
  user_agent text,
  CONSTRAINT fk_user_sessions_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE audit_events(
  id integer PRIMARY KEY AUTOINCREMENT,
  timestamp datetime NOT NULL,
  event_type text NOT NULL,
  actor text NOT NULL DEFAULT '',
  target_type text DEFAULT '',
  target_name text DEFAULT '',
  details text DEFAULT ''
);
CREATE INDEX idx_audit_events_timestamp ON audit_events(timestamp);
CREATE INDEX idx_audit_events_event_type ON audit_events(event_type);

CREATE TABLE advertised_services(
  id integer PRIMARY KEY AUTOINCREMENT,
  node_id bigint NOT NULL,
  name text NOT NULL,
  proto text NOT NULL DEFAULT 'tcp',
  port integer NOT NULL,
  created_at datetime,
  updated_at datetime,
  CONSTRAINT fk_advertised_services_node FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE
);

CREATE TABLE device_attributes(
  id integer PRIMARY KEY AUTOINCREMENT,
  node_id bigint NOT NULL,
  attr_key text NOT NULL,
  attr_value text NOT NULL,
  updated_at datetime,
  CONSTRAINT fk_device_attributes_node FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX idx_device_attr_node_key ON device_attributes(node_id, attr_key);

CREATE TABLE oauth_clients(
  id integer PRIMARY KEY AUTOINCREMENT,
  client_id text NOT NULL UNIQUE,
  hash blob NOT NULL,
  scopes text NOT NULL DEFAULT '[]',
  created_at datetime,
  expiration datetime
);

CREATE TABLE oauth_tokens(
  id integer PRIMARY KEY AUTOINCREMENT,
  o_auth_client_id integer NOT NULL,
  prefix text NOT NULL UNIQUE,
  hash blob NOT NULL,
  scopes text NOT NULL DEFAULT '[]',
  expires_at datetime NOT NULL,
  created_at datetime NOT NULL,
  CONSTRAINT fk_oauth_tokens_client FOREIGN KEY(o_auth_client_id) REFERENCES oauth_clients(id) ON DELETE CASCADE
);

CREATE TABLE vip_services(
  id integer PRIMARY KEY AUTOINCREMENT,
  name text NOT NULL UNIQUE,
  addrs text NOT NULL DEFAULT '[]',
  comment text NOT NULL DEFAULT '',
  annotations text NOT NULL DEFAULT '{}',
  ports text NOT NULL DEFAULT '[]',
  tags text NOT NULL DEFAULT '[]'
);

CREATE TABLE dns_records(
  id integer PRIMARY KEY AUTOINCREMENT,
  name text NOT NULL,
  type text NOT NULL DEFAULT '',
  value text NOT NULL,
  created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX idx_dns_records_name_type_value ON dns_records(name, type, value);
