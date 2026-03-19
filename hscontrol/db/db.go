package db

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/go-gormigrate/gormigrate/v2"
	"github.com/juanfont/headscale/hscontrol/db/sqliteconfig"
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"github.com/tailscale/squibble"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/schema"
	"zgo.at/zcache/v2"
)

//go:embed schema.sql
var dbSchema string

func init() {
	schema.RegisterSerializer("text", TextSerialiser{})
}

var errDatabaseNotSupported = errors.New("database type not supported")

var errForeignKeyConstraintsViolated = errors.New("foreign key constraints violated")

const (
	maxIdleConns       = 100
	maxOpenConns       = 100
	contextTimeoutSecs = 10
)

// Compiled regexps for SQLite-to-PostgreSQL DDL adaptation.
var (
	reAutoIncrement = regexp.MustCompile(`(?i)integer\s+PRIMARY\s+KEY\s+AUTOINCREMENT`)
	reBlob          = regexp.MustCompile(`(?i)\bblob\b`)
	reDatetime      = regexp.MustCompile(`(?i)\bdatetime\b`)
	reNumericType   = regexp.MustCompile(`(?i)\bnumeric\b`)
)

// adaptSQL converts SQLite DDL to PostgreSQL if needed.
// It rewrites: AUTOINCREMENT→SERIAL, blob→bytea, datetime→timestamptz, numeric→boolean.
func adaptSQL(dbType string, sql string) string {
	if dbType == types.DatabaseSqlite {
		return sql
	}
	sql = reAutoIncrement.ReplaceAllString(sql, "SERIAL PRIMARY KEY")
	sql = reBlob.ReplaceAllString(sql, "bytea")
	sql = reDatetime.ReplaceAllString(sql, "timestamptz")
	sql = reNumericType.ReplaceAllString(sql, "boolean")
	return sql
}

type HSDatabase struct {
	DB       *gorm.DB
	cfg      *types.Config
	regCache *zcache.Cache[types.AuthID, types.AuthRequest]
}

// NewHeadscaleDatabase creates a new database connection and runs migrations.
// It accepts the full configuration to allow migrations access to policy settings.
//
//nolint:gocyclo // complex database initialization with many migrations
func NewHeadscaleDatabase(
	cfg *types.Config,
	regCache *zcache.Cache[types.AuthID, types.AuthRequest],
) (*HSDatabase, error) {
	dbConn, err := openDB(cfg.Database)
	if err != nil {
		return nil, err
	}

	err = checkVersionUpgradePath(dbConn)
	if err != nil {
		return nil, fmt.Errorf("version check: %w", err)
	}

	migrations := gormigrate.New(
		dbConn,
		gormigrate.DefaultOptions,
		[]*gormigrate.Migration{
			// New migrations must be added as transactions at the end of this list.
			// Migrations start from v0.25.0. If upgrading from v0.24.x or earlier,
			// you must first upgrade to v0.25.1 before upgrading to this version.

			// v0.25.0
			{
				// Add a constraint to routes ensuring they cannot exist without a node.
				ID: "202501221827",
				Migrate: func(tx *gorm.DB) error {
					// Remove any invalid routes associated with a node that does not exist.
					if tx.Migrator().HasTable(&types.Route{}) && tx.Migrator().HasTable(&types.Node{}) { //nolint:staticcheck // SA1019: Route kept for migrations
						err := tx.Exec("delete from routes where node_id not in (select id from nodes)").Error
						if err != nil {
							return err
						}
					}

					// Remove any invalid routes without a node_id.
					if tx.Migrator().HasTable(&types.Route{}) { //nolint:staticcheck // SA1019: Route kept for migrations
						err := tx.Exec("delete from routes where node_id is null").Error
						if err != nil {
							return err
						}
					}

					err := tx.AutoMigrate(&types.Route{}) //nolint:staticcheck // SA1019: Route kept for migrations
					if err != nil {
						return fmt.Errorf("automigrating types.Route: %w", err)
					}

					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			// Add back constraint so you cannot delete preauth keys that
			// is still used by a node.
			{
				ID: "202501311657",
				Migrate: func(tx *gorm.DB) error {
					err := tx.AutoMigrate(&types.PreAuthKey{})
					if err != nil {
						return fmt.Errorf("automigrating types.PreAuthKey: %w", err)
					}

					err = tx.AutoMigrate(&types.Node{})
					if err != nil {
						return fmt.Errorf("automigrating types.Node: %w", err)
					}

					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			// Ensure there are no nodes referring to a deleted preauthkey.
			{
				ID: "202502070949",
				Migrate: func(tx *gorm.DB) error {
					if tx.Migrator().HasTable(&types.PreAuthKey{}) {
						err := tx.Exec(`
UPDATE nodes
SET auth_key_id = NULL
WHERE auth_key_id IS NOT NULL
AND auth_key_id NOT IN (
    SELECT id FROM pre_auth_keys
);
							`).Error
						if err != nil {
							return fmt.Errorf("setting auth_key to null on nodes with non-existing keys: %w", err)
						}
					}

					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			// v0.26.0
			// Migrate all routes from the Route table to the new field ApprovedRoutes
			// in the Node table. Then drop the Route table.
			{
				ID: "202502131714",
				Migrate: func(tx *gorm.DB) error {
					if !tx.Migrator().HasColumn(&types.Node{}, "approved_routes") {
						err := tx.Migrator().AddColumn(&types.Node{}, "approved_routes")
						if err != nil {
							return fmt.Errorf("adding column types.Node: %w", err)
						}
					}

					nodeRoutes := map[uint64][]netip.Prefix{}

					var routes []types.Route //nolint:staticcheck // SA1019: Route kept for migrations

					err = tx.Find(&routes).Error
					if err != nil {
						return fmt.Errorf("fetching routes: %w", err)
					}

					for _, route := range routes {
						if route.Enabled {
							nodeRoutes[route.NodeID] = append(nodeRoutes[route.NodeID], route.Prefix)
						}
					}

					for nodeID, routes := range nodeRoutes {
						slices.SortFunc(routes, netip.Prefix.Compare)
						routes = slices.Compact(routes)

						data, _ := json.Marshal(routes)

						err = tx.Model(&types.Node{}).Where("id = ?", nodeID).Update("approved_routes", data).Error
						if err != nil {
							return fmt.Errorf("saving approved routes to new column: %w", err)
						}
					}

					// Drop the old table.
					_ = tx.Migrator().DropTable(&types.Route{}) //nolint:staticcheck // SA1019: Route kept for migrations

					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			{
				ID: "202502171819",
				Migrate: func(tx *gorm.DB) error {
					// This migration originally removed the last_seen column
					// from the node table, but it was added back in
					// 202505091439.
					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			// Add back last_seen column to node table.
			{
				ID: "202505091439",
				Migrate: func(tx *gorm.DB) error {
					// Add back last_seen column to node table if it does not exist.
					// This is a workaround for the fact that the last_seen column
					// was removed in the 202502171819 migration, but only for some
					// beta testers.
					if !tx.Migrator().HasColumn(&types.Node{}, "last_seen") {
						_ = tx.Migrator().AddColumn(&types.Node{}, "last_seen")
					}

					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			// Fix the provider identifier for users that have a double slash in the
			// provider identifier.
			{
				ID: "202505141324",
				Migrate: func(tx *gorm.DB) error {
					users, err := ListUsers(tx)
					if err != nil {
						return fmt.Errorf("listing users: %w", err)
					}

					for _, user := range users {
						user.ProviderIdentifier.String = types.CleanIdentifier(user.ProviderIdentifier.String)

						err := tx.Save(user).Error
						if err != nil {
							return fmt.Errorf("saving user: %w", err)
						}
					}

					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			// v0.27.0
			// Schema migration to ensure all tables match the expected schema.
			// This migration recreates all tables to match the exact structure in schema.sql,
			// preserving all data during the process.
			// Only SQLite will be migrated for consistency.
			{
				ID: "202507021200",
				Migrate: func(tx *gorm.DB) error {
					// Only run on SQLite
					if cfg.Database.Type != types.DatabaseSqlite {
						log.Info().Msg("skipping schema migration on non-SQLite database")
						return nil
					}

					log.Info().Msg("starting schema recreation with table renaming")

					// Rename existing tables to _old versions
					tablesToRename := []string{"users", "pre_auth_keys", "api_keys", "nodes", "policies"}

					// Check if routes table exists and drop it (should have been migrated already)
					var routesExists bool

					err := tx.Raw("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='routes'").Row().Scan(&routesExists)
					if err == nil && routesExists {
						log.Info().Msg("dropping leftover routes table")

						err := tx.Exec("DROP TABLE routes").Error
						if err != nil {
							return fmt.Errorf("dropping routes table: %w", err)
						}
					}

					// Drop all indexes first to avoid conflicts
					indexesToDrop := []string{
						"idx_users_deleted_at",
						"idx_provider_identifier",
						"idx_name_provider_identifier",
						"idx_name_no_provider_identifier",
						"idx_api_keys_prefix",
						"idx_policies_deleted_at",
					}

					for _, index := range indexesToDrop {
						_ = tx.Exec("DROP INDEX IF EXISTS " + index).Error
					}

					for _, table := range tablesToRename {
						// Check if table exists before renaming
						var exists bool

						err := tx.Raw("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", table).Row().Scan(&exists)
						if err != nil {
							return fmt.Errorf("checking if table %s exists: %w", table, err)
						}

						if exists {
							// Drop old table if it exists from previous failed migration
							_ = tx.Exec("DROP TABLE IF EXISTS " + table + "_old").Error

							// Rename current table to _old
							err := tx.Exec("ALTER TABLE " + table + " RENAME TO " + table + "_old").Error
							if err != nil {
								return fmt.Errorf("renaming table %s to %s_old: %w", table, table, err)
							}
						}
					}

					// Create new tables with correct schema
					tableCreationSQL := []string{
						`CREATE TABLE users(
  id integer PRIMARY KEY AUTOINCREMENT,
  name text,
  display_name text,
  email text,
  provider_identifier text,
  provider text,
  profile_pic_url text,
  created_at datetime,
  updated_at datetime,
  deleted_at datetime
)`,
						`CREATE TABLE pre_auth_keys(
  id integer PRIMARY KEY AUTOINCREMENT,
  key text,
  user_id integer,
  reusable numeric,
  ephemeral numeric DEFAULT false,
  used numeric DEFAULT false,
  tags text,
  expiration datetime,
  created_at datetime,
  CONSTRAINT fk_pre_auth_keys_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
)`,
						`CREATE TABLE api_keys(
  id integer PRIMARY KEY AUTOINCREMENT,
  prefix text,
  hash blob,
  expiration datetime,
  last_seen datetime,
  created_at datetime
)`,
						`CREATE TABLE nodes(
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
  user_id integer,
  register_method text,
  forced_tags text,
  auth_key_id integer,
  last_seen datetime,
  expiry datetime,
  approved_routes text,
  created_at datetime,
  updated_at datetime,
  deleted_at datetime,
  CONSTRAINT fk_nodes_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT fk_nodes_auth_key FOREIGN KEY(auth_key_id) REFERENCES pre_auth_keys(id)
)`,
						`CREATE TABLE policies(
  id integer PRIMARY KEY AUTOINCREMENT,
  data text,
  created_at datetime,
  updated_at datetime,
  deleted_at datetime
)`,
					}

					for _, createSQL := range tableCreationSQL {
						err := tx.Exec(createSQL).Error
						if err != nil {
							return fmt.Errorf("creating new table: %w", err)
						}
					}

					// Copy data directly using SQL
					dataCopySQL := []string{
						`INSERT INTO users (id, name, display_name, email, provider_identifier, provider, profile_pic_url, created_at, updated_at, deleted_at)
             SELECT id, name, display_name, email, provider_identifier, provider, profile_pic_url, created_at, updated_at, deleted_at
             FROM users_old`,

						`INSERT INTO pre_auth_keys (id, key, user_id, reusable, ephemeral, used, tags, expiration, created_at)
             SELECT id, key, user_id, reusable, ephemeral, used, tags, expiration, created_at
             FROM pre_auth_keys_old`,

						`INSERT INTO api_keys (id, prefix, hash, expiration, last_seen, created_at)
             SELECT id, prefix, hash, expiration, last_seen, created_at
             FROM api_keys_old`,

						`INSERT INTO nodes (id, machine_key, node_key, disco_key, endpoints, host_info, ipv4, ipv6, hostname, given_name, user_id, register_method, forced_tags, auth_key_id, last_seen, expiry, approved_routes, created_at, updated_at, deleted_at)
             SELECT id, machine_key, node_key, disco_key, endpoints, host_info, ipv4, ipv6, hostname, given_name, user_id, register_method, forced_tags, auth_key_id, last_seen, expiry, approved_routes, created_at, updated_at, deleted_at
             FROM nodes_old`,

						`INSERT INTO policies (id, data, created_at, updated_at, deleted_at)
             SELECT id, data, created_at, updated_at, deleted_at
             FROM policies_old`,
					}

					for _, copySQL := range dataCopySQL {
						err := tx.Exec(copySQL).Error
						if err != nil {
							return fmt.Errorf("copying data: %w", err)
						}
					}

					// Create indexes
					indexes := []string{
						"CREATE INDEX idx_users_deleted_at ON users(deleted_at)",
						`CREATE UNIQUE INDEX idx_provider_identifier ON users(
  provider_identifier
) WHERE provider_identifier IS NOT NULL`,
						`CREATE UNIQUE INDEX idx_name_provider_identifier ON users(
  name,
  provider_identifier
)`,
						`CREATE UNIQUE INDEX idx_name_no_provider_identifier ON users(
  name
) WHERE provider_identifier IS NULL`,
						"CREATE UNIQUE INDEX idx_api_keys_prefix ON api_keys(prefix)",
						"CREATE INDEX idx_policies_deleted_at ON policies(deleted_at)",
					}

					for _, indexSQL := range indexes {
						err := tx.Exec(indexSQL).Error
						if err != nil {
							return fmt.Errorf("creating index: %w", err)
						}
					}

					// Drop old tables only after everything succeeds
					for _, table := range tablesToRename {
						err := tx.Exec("DROP TABLE IF EXISTS " + table + "_old").Error
						if err != nil {
							log.Warn().Str("table", table+"_old").Err(err).Msg("failed to drop old table, but migration succeeded")
						}
					}

					log.Info().Msg("schema recreation completed successfully")

					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			// v0.27.1
			{
				// Drop all tables that are no longer in use and has existed.
				// They potentially still present from broken migrations in the past.
				ID: "202510311551",
				Migrate: func(tx *gorm.DB) error {
					for _, oldTable := range []string{"namespaces", "machines", "shared_machines", "kvs", "pre_auth_key_acl_tags", "routes"} {
						err := tx.Migrator().DropTable(oldTable)
						if err != nil {
							log.Trace().Str("table", oldTable).
								Err(err).
								Msg("Error dropping old table, continuing...")
						}
					}

					return nil
				},
				Rollback: func(tx *gorm.DB) error {
					return nil
				},
			},
			{
				// Drop all indices that are no longer in use and has existed.
				// They potentially still present from broken migrations in the past.
				// They should all be cleaned up by the db engine, but we are a bit
				// conservative to ensure all our previous mess is cleaned up.
				ID: "202511101554-drop-old-idx",
				Migrate: func(tx *gorm.DB) error {
					for _, oldIdx := range []struct{ name, table string }{
						{"idx_namespaces_deleted_at", "namespaces"},
						{"idx_routes_deleted_at", "routes"},
						{"idx_shared_machines_deleted_at", "shared_machines"},
					} {
						err := tx.Migrator().DropIndex(oldIdx.table, oldIdx.name)
						if err != nil {
							log.Trace().
								Str("index", oldIdx.name).
								Str("table", oldIdx.table).
								Err(err).
								Msg("Error dropping old index, continuing...")
						}
					}

					return nil
				},
				Rollback: func(tx *gorm.DB) error {
					return nil
				},
			},

			// Migrations **above** this points will be REMOVED in version **0.29.0**
			// This is to clean up a lot of old migrations that is seldom used
			// and carries a lot of technical debt.
			// Any new migrations should be added after the comment below and follow
			// the rules it sets out.

			// From this point, the following rules must be followed:
			// - NEVER use gorm.AutoMigrate, write the exact migration steps needed
			// - AutoMigrate depends on the struct staying exactly the same, which it won't over time.
			// - Never write migrations that requires foreign keys to be disabled.
			// - ALL errors in migrations must be handled properly.

			{
				// Add columns for prefix and hash for pre auth keys, implementing
				// them with the same security model as api keys.
				ID: "202511011637-preauthkey-bcrypt",
				Migrate: func(tx *gorm.DB) error {
					// Check and add prefix column if it doesn't exist
					if !tx.Migrator().HasColumn(&types.PreAuthKey{}, "prefix") {
						err := tx.Migrator().AddColumn(&types.PreAuthKey{}, "prefix")
						if err != nil {
							return fmt.Errorf("adding prefix column: %w", err)
						}
					}

					// Check and add hash column if it doesn't exist
					if !tx.Migrator().HasColumn(&types.PreAuthKey{}, "hash") {
						err := tx.Migrator().AddColumn(&types.PreAuthKey{}, "hash")
						if err != nil {
							return fmt.Errorf("adding hash column: %w", err)
						}
					}

					// Create partial unique index to allow multiple legacy keys (NULL/empty prefix)
					// while enforcing uniqueness for new bcrypt-based keys
					err := tx.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_pre_auth_keys_prefix ON pre_auth_keys(prefix) WHERE prefix IS NOT NULL AND prefix != ''").Error
					if err != nil {
						return fmt.Errorf("creating prefix index: %w", err)
					}

					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			{
				ID: "202511122344-remove-newline-index",
				Migrate: func(tx *gorm.DB) error {
					// Reformat multi-line indexes to single-line for consistency
					// This migration drops and recreates the three user identity indexes
					// to match the single-line format expected by schema validation

					// Drop existing multi-line indexes
					dropIndexes := []string{
						`DROP INDEX IF EXISTS idx_provider_identifier`,
						`DROP INDEX IF EXISTS idx_name_provider_identifier`,
						`DROP INDEX IF EXISTS idx_name_no_provider_identifier`,
					}

					for _, dropSQL := range dropIndexes {
						err := tx.Exec(dropSQL).Error
						if err != nil {
							return fmt.Errorf("dropping index: %w", err)
						}
					}

					// Recreate indexes in single-line format
					createIndexes := []string{
						`CREATE UNIQUE INDEX idx_provider_identifier ON users(provider_identifier) WHERE provider_identifier IS NOT NULL`,
						`CREATE UNIQUE INDEX idx_name_provider_identifier ON users(name, provider_identifier)`,
						`CREATE UNIQUE INDEX idx_name_no_provider_identifier ON users(name) WHERE provider_identifier IS NULL`,
					}

					for _, createSQL := range createIndexes {
						err := tx.Exec(createSQL).Error
						if err != nil {
							return fmt.Errorf("creating index: %w", err)
						}
					}

					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			{
				// Rename forced_tags column to tags in nodes table.
				// This must run after migration 202505141324 which creates tables with forced_tags.
				ID: "202511131445-node-forced-tags-to-tags",
				Migrate: func(tx *gorm.DB) error {
					// Rename the column from forced_tags to tags
					err := tx.Migrator().RenameColumn(&types.Node{}, "forced_tags", "tags")
					if err != nil {
						return fmt.Errorf("renaming forced_tags to tags: %w", err)
					}

					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			{
				// Migrate RequestTags from host_info JSON to tags column.
				// In 0.27.x, tags from --advertise-tags (ValidTags) were stored only in
				// host_info.RequestTags, not in the tags column (formerly forced_tags).
				// This migration validates RequestTags against the policy's tagOwners
				// and merges validated tags into the tags column.
				// Fixes: https://github.com/juanfont/headscale/issues/3006
				ID: "202601121700-migrate-hostinfo-request-tags",
				Migrate: func(tx *gorm.DB) error {
					// 1. Load policy from file or database based on configuration
					policyData, err := PolicyBytes(tx, cfg)
					if err != nil {
						log.Warn().Err(err).Msg("failed to load policy, skipping RequestTags migration (tags will be validated on node reconnect)")
						return nil
					}

					if len(policyData) == 0 {
						log.Info().Msg("no policy found, skipping RequestTags migration (tags will be validated on node reconnect)")
						return nil
					}

					// 2. Load users and nodes to create PolicyManager
					users, err := ListUsers(tx)
					if err != nil {
						return fmt.Errorf("loading users for RequestTags migration: %w", err)
					}

					nodes, err := ListNodes(tx)
					if err != nil {
						return fmt.Errorf("loading nodes for RequestTags migration: %w", err)
					}

					// 3. Create PolicyManager (handles HuJSON parsing, groups, nested tags, etc.)
					polMan, err := policy.NewPolicyManager(policyData, users, nodes.ViewSlice())
					if err != nil {
						log.Warn().Err(err).Msg("failed to parse policy, skipping RequestTags migration (tags will be validated on node reconnect)")
						return nil
					}

					// 4. Process each node
					for _, node := range nodes {
						if node.Hostinfo == nil {
							continue
						}

						requestTags := node.Hostinfo.RequestTags
						if len(requestTags) == 0 {
							continue
						}

						existingTags := node.Tags

						var validatedTags, rejectedTags []string

						nodeView := node.View()

						for _, tag := range requestTags {
							if polMan.NodeCanHaveTag(nodeView, tag) {
								if !slices.Contains(existingTags, tag) {
									validatedTags = append(validatedTags, tag)
								}
							} else {
								rejectedTags = append(rejectedTags, tag)
							}
						}

						if len(validatedTags) == 0 {
							if len(rejectedTags) > 0 {
								log.Debug().
									EmbedObject(node).
									Strs("rejected_tags", rejectedTags).
									Msg("RequestTags rejected during migration (not authorized)")
							}

							continue
						}

						mergedTags := append(existingTags, validatedTags...)
						slices.Sort(mergedTags)
						mergedTags = slices.Compact(mergedTags)

						tagsJSON, err := json.Marshal(mergedTags)
						if err != nil {
							return fmt.Errorf("serializing merged tags for node %d: %w", node.ID, err)
						}

						err = tx.Exec("UPDATE nodes SET tags = ? WHERE id = ?", string(tagsJSON), node.ID).Error
						if err != nil {
							return fmt.Errorf("updating tags for node %d: %w", node.ID, err)
						}

						log.Info().
							EmbedObject(node).
							Strs("validated_tags", validatedTags).
							Strs("rejected_tags", rejectedTags).
							Strs("existing_tags", existingTags).
							Strs("merged_tags", mergedTags).
							Msg("Migrated validated RequestTags from host_info to tags column")
					}

					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			{
				// Clear user_id on tagged nodes.
				// Tagged nodes are owned by their tags, not a user.
				// Previously user_id was kept as "created by" tracking,
				// but this prevents deleting users whose nodes have been
				// tagged, and the ON DELETE CASCADE FK would destroy the
				// tagged nodes if the user were deleted.
				// Fixes: https://github.com/juanfont/headscale/issues/3077
				ID: "202602201200-clear-tagged-node-user-id",
				Migrate: func(tx *gorm.DB) error {
					err := tx.Exec(`
UPDATE nodes
SET user_id = NULL
WHERE tags IS NOT NULL AND tags != '[]' AND tags != '';
						`).Error
					if err != nil {
						return fmt.Errorf("clearing user_id on tagged nodes: %w", err)
					}

					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			{
				// Add support for external WireGuard-only peers and jailed nodes.
				// is_wireguard_only marks non-Tailscale WireGuard peers that don't speak Disco/DERP.
				// is_jailed marks nodes that cannot initiate connections into the tailnet.
				// exit_node_dns_resolvers stores DNS resolvers for WG-only exit nodes.
				ID: "202603051200-add-wireguard-only-jailed",
				Migrate: func(tx *gorm.DB) error {
					if !tx.Migrator().HasColumn(&types.Node{}, "is_wireguard_only") {
						err := tx.Exec(
							adaptSQL(cfg.Database.Type, "ALTER TABLE nodes ADD COLUMN is_wireguard_only numeric NOT NULL DEFAULT false"),
						).Error
						if err != nil {
							return fmt.Errorf("adding is_wireguard_only column: %w", err)
						}
					}

					if !tx.Migrator().HasColumn(&types.Node{}, "is_jailed") {
						err := tx.Exec(
							adaptSQL(cfg.Database.Type, "ALTER TABLE nodes ADD COLUMN is_jailed numeric NOT NULL DEFAULT false"),
						).Error
						if err != nil {
							return fmt.Errorf("adding is_jailed column: %w", err)
						}
					}

					if !tx.Migrator().HasColumn(&types.Node{}, "exit_node_dns_resolvers") {
						err := tx.Exec(
							"ALTER TABLE nodes ADD COLUMN exit_node_dns_resolvers text",
						).Error
						if err != nil {
							return fmt.Errorf("adding exit_node_dns_resolvers column: %w", err)
						}
					}

					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			{
				// Add location columns for external WireGuard peers.
				// Location columns populate tailcfg.Location for exit node picker UI.
				ID: "202603060100-add-external-peer-owner-location",
				Migrate: func(tx *gorm.DB) error {
					locationColumns := []struct {
						name string
						typ  string
					}{
						{"location_country", "text"},
						{"location_country_code", "text"},
						{"location_city", "text"},
						{"location_city_code", "text"},
						{"location_latitude", "real"},
						{"location_longitude", "real"},
						{"location_priority", "integer DEFAULT 0"},
					}
					for _, col := range locationColumns {
						if !tx.Migrator().HasColumn(&types.Node{}, col.name) {
							err := tx.Exec(
								fmt.Sprintf("ALTER TABLE nodes ADD COLUMN %s %s", col.name, col.typ),
							).Error
							if err != nil {
								return fmt.Errorf("adding %s column: %w", col.name, err)
							}
						}
					}

					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			{
				// Add tables for VPN provider account management and key allocations.
				// vpn_provider_accounts stores provider credentials (e.g. Mullvad account numbers).
				// vpn_key_allocations tracks which node has a WG key registered with which account.
				// Provider relay servers are NOT stored in the database — they are cached in memory.
				ID: "202603061500-add-vpn-provider-tables",
				Migrate: func(tx *gorm.DB) error {
					err := tx.Exec(adaptSQL(cfg.Database.Type, `CREATE TABLE IF NOT EXISTS vpn_provider_accounts (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					provider_name TEXT NOT NULL,
					account_id TEXT NOT NULL,
					max_keys INTEGER NOT NULL DEFAULT 5,
					expires_at DATETIME,
					enabled NUMERIC NOT NULL DEFAULT true,
					created_at DATETIME,
					updated_at DATETIME,
					UNIQUE(provider_name, account_id)
				)`)).Error
					if err != nil {
						return fmt.Errorf("creating vpn_provider_accounts table: %w", err)
					}

					err = tx.Exec(adaptSQL(cfg.Database.Type, `CREATE TABLE IF NOT EXISTS vpn_key_allocations (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					account_id INTEGER NOT NULL REFERENCES vpn_provider_accounts(id) ON DELETE CASCADE,
					node_id BIGINT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
					node_key TEXT NOT NULL,
					allocated_at DATETIME,
					UNIQUE(account_id, node_key)
				)`)).Error
					if err != nil {
						return fmt.Errorf("creating vpn_key_allocations table: %w", err)
					}

					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			{
				// Add assigned IP columns to vpn_key_allocations for masquerade support.
				// Mullvad assigns each registered WG key an internal IP (e.g. 10.139.55.16)
				// that must be used as the source address inside the WireGuard tunnel.
				ID: "202603071500-add-vpn-allocation-assigned-ips",
				Migrate: func(tx *gorm.DB) error {
					if err := tx.Exec(`ALTER TABLE vpn_key_allocations ADD COLUMN assigned_ipv4 TEXT DEFAULT ''`).Error; err != nil {
						return fmt.Errorf("adding assigned_ipv4 column: %w", err)
					}

					if err := tx.Exec(`ALTER TABLE vpn_key_allocations ADD COLUMN assigned_ipv6 TEXT DEFAULT ''`).Error; err != nil {
						return fmt.Errorf("adding assigned_ipv6 column: %w", err)
					}

					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			{
				// Remove the owner_node_id column from nodes table if it exists.
				// This column was added by a previous development build via AutoMigrate
				// but is no longer part of the Node struct.
				ID: "202603081200-drop-owner-node-id",
				Migrate: func(tx *gorm.DB) error {
					// Check if the column exists before attempting to drop it.
					// This migration is a no-op on fresh databases.
					if !tx.Migrator().HasColumn(&types.Node{}, "owner_node_id") {
						return nil
					}

					err := tx.Exec(`ALTER TABLE nodes DROP COLUMN owner_node_id`).Error
					if err != nil {
						return fmt.Errorf("dropping owner_node_id column: %w", err)
					}

					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			// As of 2025-07-02, no new IDs should be added here
			{
				// Add role column to users table (defaults to "member"),
				// create user_credentials table for optional local auth,
				// and user_sessions table for web UI sessions.
				ID: "202507021200-add-user-auth-tables",
				Migrate: func(tx *gorm.DB) error {
					// Add role to existing users table.
					if err := tx.Exec(
						`ALTER TABLE users ADD COLUMN role text NOT NULL DEFAULT 'member'`,
					).Error; err != nil {
						return fmt.Errorf("adding role to users: %w", err)
					}

					credSQL := adaptSQL(cfg.Database.Type, `CREATE TABLE IF NOT EXISTS user_credentials(
						user_id integer PRIMARY KEY,
						password_hash text,
						otp_secret text,
						otp_enabled numeric NOT NULL DEFAULT false,
						git_hub_id text,
						git_hub_login text,
						failed_login_attempts integer NOT NULL DEFAULT 0,
						locked_until datetime,
						created_at datetime,
						updated_at datetime,
						CONSTRAINT fk_user_credentials_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
					)`)
					if err := tx.Exec(credSQL).Error; err != nil {
						return fmt.Errorf("creating user_credentials table: %w", err)
					}

					if err := tx.Exec(
						`CREATE UNIQUE INDEX IF NOT EXISTS idx_user_credentials_github_id ON user_credentials(git_hub_id) WHERE git_hub_id IS NOT NULL AND git_hub_id != ''`,
					).Error; err != nil {
						return fmt.Errorf("creating git_hub_id index: %w", err)
					}

					sessSQL := adaptSQL(cfg.Database.Type, `CREATE TABLE IF NOT EXISTS user_sessions(
						id text PRIMARY KEY,
						user_id integer NOT NULL,
						expires_at datetime NOT NULL,
						created_at datetime,
						ip_address text,
						user_agent text,
						CONSTRAINT fk_user_sessions_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
					)`)
					if err := tx.Exec(sessSQL).Error; err != nil {
						return fmt.Errorf("creating user_sessions table: %w", err)
					}

					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			{
				// Remove owner role — admin is now the highest privilege.
				ID: "202507100100-remove-owner-role",
				Migrate: func(tx *gorm.DB) error {
					return tx.Exec(`UPDATE users SET role = 'admin' WHERE role = 'owner'`).Error
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			{
				// Add runtime_dns_configs table for DB-stored DNS overrides.
				ID: "202507140100-add-runtime-dns-configs",
				Migrate: func(tx *gorm.DB) error {
					err := tx.Exec(adaptSQL(cfg.Database.Type, `CREATE TABLE IF NOT EXISTS runtime_dns_configs(
						id integer PRIMARY KEY AUTOINCREMENT,
						data text,
						created_at datetime,
						updated_at datetime,
						deleted_at datetime
					)`)).Error
					if err != nil {
						return err
					}
					// Drop backtick-quoted index if it exists (from earlier AutoMigrate runs)
					tx.Exec(`DROP INDEX IF EXISTS "idx_runtime_dns_configs_deleted_at"`)
					return tx.Exec(`CREATE INDEX IF NOT EXISTS idx_runtime_dns_configs_deleted_at ON runtime_dns_configs(deleted_at)`).Error
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			{
				// Fix runtime_dns_configs index format (remove backtick-quoted version from AutoMigrate).
				ID: "202507140101-fix-runtime-dns-configs-index",
				Migrate: func(tx *gorm.DB) error {
					tx.Exec(`DROP INDEX IF EXISTS "idx_runtime_dns_configs_deleted_at"`)
					return tx.Exec(`CREATE INDEX IF NOT EXISTS idx_runtime_dns_configs_deleted_at ON runtime_dns_configs(deleted_at)`).Error
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			// As of 2025-07-02, no new IDs should be added here
			{
				ID: "202603100100-add-audit-events",
				Migrate: func(tx *gorm.DB) error {
					if err := tx.Exec(adaptSQL(cfg.Database.Type, `CREATE TABLE IF NOT EXISTS audit_events (
						id integer PRIMARY KEY AUTOINCREMENT,
						timestamp datetime NOT NULL,
						event_type text NOT NULL,
						actor text NOT NULL DEFAULT '',
						target_type text DEFAULT '',
						target_name text DEFAULT '',
						details text DEFAULT ''
					)`)).Error; err != nil {
						return err
					}
					if err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events(timestamp)`).Error; err != nil {
						return err
					}
					return tx.Exec(`CREATE INDEX IF NOT EXISTS idx_audit_events_event_type ON audit_events(event_type)`).Error
				},
				Rollback: func(db *gorm.DB) error {
					return db.Exec(`DROP TABLE IF EXISTS audit_events`).Error
				},
			},
			{
				ID: "202603100200-add-audit-events-indexes",
				Migrate: func(tx *gorm.DB) error {
					if err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events(timestamp)`).Error; err != nil {
						return err
					}
					return tx.Exec(`CREATE INDEX IF NOT EXISTS idx_audit_events_event_type ON audit_events(event_type)`).Error
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			{
				ID: "202603131100-add-advertised-services",
				Migrate: func(tx *gorm.DB) error {
					return tx.Exec(adaptSQL(cfg.Database.Type, `CREATE TABLE IF NOT EXISTS advertised_services (
						id integer PRIMARY KEY AUTOINCREMENT,
						node_id bigint NOT NULL,
						name text NOT NULL,
						proto text NOT NULL DEFAULT 'tcp',
						port integer NOT NULL,
						created_at datetime,
						updated_at datetime,
						CONSTRAINT fk_advertised_services_node FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE
					)`)).Error
				},
				Rollback: func(db *gorm.DB) error {
					return db.Exec(`DROP TABLE IF EXISTS advertised_services`).Error
				},
			},
			{
				ID: "202603141200-add-device-attributes",
				Migrate: func(tx *gorm.DB) error {
					if err := tx.Exec(adaptSQL(cfg.Database.Type, `CREATE TABLE IF NOT EXISTS device_attributes (
						id integer PRIMARY KEY AUTOINCREMENT,
						node_id bigint NOT NULL,
						attr_key text NOT NULL,
						attr_value text NOT NULL,
						updated_at datetime,
						CONSTRAINT fk_device_attributes_node FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE
					)`)).Error; err != nil {
						return err
					}
					return tx.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_device_attr_node_key ON device_attributes(node_id, attr_key)`).Error
				},
				Rollback: func(db *gorm.DB) error {
					return db.Exec(`DROP TABLE IF EXISTS device_attributes`).Error
				},
			},
			{
				ID: "202603141201-add-network-flow-logs",
				Migrate: func(tx *gorm.DB) error {
					if err := tx.Exec(adaptSQL(cfg.Database.Type, `CREATE TABLE IF NOT EXISTS network_flow_logs (
						id integer PRIMARY KEY AUTOINCREMENT,
						node_id bigint NOT NULL,
						action text NOT NULL,
						details text DEFAULT '',
						client_timestamp datetime NOT NULL,
						received_at datetime NOT NULL
					)`)).Error; err != nil {
						return err
					}
					if err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_flow_logs_node_id ON network_flow_logs(node_id)`).Error; err != nil {
						return err
					}
					if err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_flow_logs_action ON network_flow_logs(action)`).Error; err != nil {
						return err
					}
					return tx.Exec(`CREATE INDEX IF NOT EXISTS idx_flow_logs_received_at ON network_flow_logs(received_at)`).Error
				},
				Rollback: func(db *gorm.DB) error {
					return db.Exec(`DROP TABLE IF EXISTS network_flow_logs`).Error
				},
			},
			{
				ID: "202603141500-drop-network-flow-logs",
				Migrate: func(tx *gorm.DB) error {
					return tx.Exec(`DROP TABLE IF EXISTS network_flow_logs`).Error
				},
				Rollback: func(db *gorm.DB) error {
					return nil
				},
			},
			{
				ID: "202603161500-add-oauth-clients",
				Migrate: func(tx *gorm.DB) error {
					if err := tx.Exec(adaptSQL(cfg.Database.Type, `CREATE TABLE IF NOT EXISTS oauth_clients (
						id integer PRIMARY KEY AUTOINCREMENT,
						client_id text NOT NULL UNIQUE,
						hash blob NOT NULL,
						scopes text NOT NULL DEFAULT '[]',
						created_at datetime,
						expiration datetime
					)`)).Error; err != nil {
						return err
					}
					if err := tx.Exec(adaptSQL(cfg.Database.Type, `CREATE TABLE IF NOT EXISTS oauth_tokens (
						id integer PRIMARY KEY AUTOINCREMENT,
						o_auth_client_id integer NOT NULL,
						prefix text NOT NULL UNIQUE,
						hash blob NOT NULL,
						scopes text NOT NULL DEFAULT '[]',
						expires_at datetime NOT NULL,
						created_at datetime NOT NULL,
						CONSTRAINT fk_oauth_tokens_client FOREIGN KEY(o_auth_client_id) REFERENCES oauth_clients(id) ON DELETE CASCADE
					)`)).Error; err != nil {
						return err
					}
					return nil
				},
				Rollback: func(db *gorm.DB) error {
					if err := db.Exec(`DROP TABLE IF EXISTS oauth_tokens`).Error; err != nil {
						return err
					}
					return db.Exec(`DROP TABLE IF EXISTS oauth_clients`).Error
				},
			},
			{
				ID: "202603161501-add-vip-services",
				Migrate: func(tx *gorm.DB) error {
					return tx.Exec(adaptSQL(cfg.Database.Type, `CREATE TABLE IF NOT EXISTS vip_services (
						id integer PRIMARY KEY AUTOINCREMENT,
						name text NOT NULL UNIQUE,
						addrs text NOT NULL DEFAULT '[]',
						comment text NOT NULL DEFAULT '',
						annotations text NOT NULL DEFAULT '{}',
						ports text NOT NULL DEFAULT '[]',
						tags text NOT NULL DEFAULT '[]'
					)`)).Error
				},
				Rollback: func(db *gorm.DB) error {
					return db.Exec(`DROP TABLE IF EXISTS vip_services`).Error
				},
			},
			{
				ID: "202603181500-add-dns-records",
				Migrate: func(tx *gorm.DB) error {
					if err := tx.Exec(adaptSQL(cfg.Database.Type, `CREATE TABLE IF NOT EXISTS dns_records (
						id integer PRIMARY KEY AUTOINCREMENT,
						name text NOT NULL,
						type text NOT NULL DEFAULT '',
						value text NOT NULL,
						created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
						updated_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP
					)`)).Error; err != nil {
						return err
					}
					return tx.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_dns_records_name_type_value ON dns_records(name, type, value)`).Error
				},
				Rollback: func(db *gorm.DB) error {
					return db.Exec(`DROP TABLE IF EXISTS dns_records`).Error
				},
			},
			{
				ID: "202603191000-add-password-rotation-fields",
				Migrate: func(tx *gorm.DB) error {
					if err := tx.Exec(`ALTER TABLE user_credentials ADD COLUMN password_changed_at datetime`).Error; err != nil {
						return err
					}
					if err := tx.Exec(adaptSQL(cfg.Database.Type, `ALTER TABLE user_credentials ADD COLUMN must_change_password numeric NOT NULL DEFAULT false`)).Error; err != nil {
						return err
					}
					// Backfill: set password_changed_at to updated_at for existing credentials that have a password.
					return tx.Exec(`UPDATE user_credentials SET password_changed_at = updated_at WHERE password_hash IS NOT NULL AND password_hash != ''`).Error
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
		},
	)

	migrations.InitSchema(func(tx *gorm.DB) error {
		// Create all tables using AutoMigrate for core types.
		// This must produce a schema matching schema.sql for a fresh database.
		// When new tables are added via migrations, they must also be added here.
		err := tx.AutoMigrate(
			&types.User{},
			&types.PreAuthKey{},
			&types.APIKey{},
			&types.Node{},
			&types.Policy{},
			&types.RuntimeDNSConfig{},
		)
		if err != nil {
			return err
		}

		// Create VPN tables with raw SQL to exactly match schema.sql.
		// AutoMigrate cannot be used here because the GORM struct tags
		// don't fully express the composite UNIQUE constraints and FKs.
		vpnTables := []string{
			`CREATE TABLE IF NOT EXISTS vpn_provider_accounts(
				id integer PRIMARY KEY AUTOINCREMENT,
				provider_name text NOT NULL,
				account_id text NOT NULL,
				max_keys integer NOT NULL DEFAULT 5,
				expires_at datetime,
				enabled numeric NOT NULL DEFAULT true,
				created_at datetime,
				updated_at datetime,
				UNIQUE(provider_name, account_id)
			)`,
			`CREATE TABLE IF NOT EXISTS vpn_key_allocations(
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
			)`,
		}
		for _, sql := range vpnTables {
			if err := tx.Exec(adaptSQL(cfg.Database.Type, sql)).Error; err != nil {
				return err
			}
		}

		// Create web auth tables with raw SQL to exactly match schema.sql.
		authTables := []string{
			`CREATE TABLE IF NOT EXISTS user_credentials(
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
			)`,
			`CREATE TABLE IF NOT EXISTS user_sessions(
				id text PRIMARY KEY,
				user_id integer NOT NULL,
				expires_at datetime NOT NULL,
				created_at datetime,
				ip_address text,
				user_agent text,
				CONSTRAINT fk_user_sessions_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
			)`,
		}
		for _, sql := range authTables {
			if err := tx.Exec(adaptSQL(cfg.Database.Type, sql)).Error; err != nil {
				return err
			}
		}

		// Create audit_events table.
		if err := tx.Exec(adaptSQL(cfg.Database.Type, `CREATE TABLE IF NOT EXISTS audit_events (
			id integer PRIMARY KEY AUTOINCREMENT,
			timestamp datetime NOT NULL,
			event_type text NOT NULL,
			actor text NOT NULL DEFAULT '',
			target_type text DEFAULT '',
			target_name text DEFAULT '',
			details text DEFAULT ''
		)`)).Error; err != nil {
			return err
		}
		if err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events(timestamp)`).Error; err != nil {
			return err
		}
		if err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_audit_events_event_type ON audit_events(event_type)`).Error; err != nil {
			return err
		}

		// Create advertised_services table.
		if err := tx.Exec(adaptSQL(cfg.Database.Type, `CREATE TABLE IF NOT EXISTS advertised_services (
			id integer PRIMARY KEY AUTOINCREMENT,
			node_id bigint NOT NULL,
			name text NOT NULL,
			proto text NOT NULL DEFAULT 'tcp',
			port integer NOT NULL,
			created_at datetime,
			updated_at datetime,
			CONSTRAINT fk_advertised_services_node FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE
		)`)).Error; err != nil {
			return err
		}

		// Create device_attributes table.
		if err := tx.Exec(adaptSQL(cfg.Database.Type, `CREATE TABLE IF NOT EXISTS device_attributes (
			id integer PRIMARY KEY AUTOINCREMENT,
			node_id bigint NOT NULL,
			attr_key text NOT NULL,
			attr_value text NOT NULL,
			updated_at datetime,
			CONSTRAINT fk_device_attributes_node FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE
		)`)).Error; err != nil {
			return err
		}
		if err := tx.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_device_attr_node_key ON device_attributes(node_id, attr_key)`).Error; err != nil {
			return err
		}

		// Create OAuth client and token tables.
		if err := tx.Exec(adaptSQL(cfg.Database.Type, `CREATE TABLE IF NOT EXISTS oauth_clients (
			id integer PRIMARY KEY AUTOINCREMENT,
			client_id text NOT NULL UNIQUE,
			hash blob NOT NULL,
			scopes text NOT NULL DEFAULT '[]',
			created_at datetime,
			expiration datetime
		)`)).Error; err != nil {
			return err
		}
		if err := tx.Exec(adaptSQL(cfg.Database.Type, `CREATE TABLE IF NOT EXISTS oauth_tokens (
			id integer PRIMARY KEY AUTOINCREMENT,
			o_auth_client_id integer NOT NULL,
			prefix text NOT NULL UNIQUE,
			hash blob NOT NULL,
			scopes text NOT NULL DEFAULT '[]',
			expires_at datetime NOT NULL,
			created_at datetime NOT NULL,
			CONSTRAINT fk_oauth_tokens_client FOREIGN KEY(o_auth_client_id) REFERENCES oauth_clients(id) ON DELETE CASCADE
		)`)).Error; err != nil {
			return err
		}

		// Create VIP services table.
		if err := tx.Exec(adaptSQL(cfg.Database.Type, `CREATE TABLE IF NOT EXISTS vip_services (
			id integer PRIMARY KEY AUTOINCREMENT,
			name text NOT NULL UNIQUE,
			addrs text NOT NULL DEFAULT '[]',
			comment text NOT NULL DEFAULT '',
			annotations text NOT NULL DEFAULT '{}',
			ports text NOT NULL DEFAULT '[]',
			tags text NOT NULL DEFAULT '[]'
		)`)).Error; err != nil {
			return err
		}

		// Create DNS records table.
		if err := tx.Exec(adaptSQL(cfg.Database.Type, `CREATE TABLE IF NOT EXISTS dns_records (
			id integer PRIMARY KEY AUTOINCREMENT,
			name text NOT NULL,
			type text NOT NULL DEFAULT '',
			value text NOT NULL,
			created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`)).Error; err != nil {
			return err
		}
		if err := tx.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_dns_records_name_type_value ON dns_records(name, type, value)`).Error; err != nil {
			return err
		}

		// Drop all indexes (both GORM-created and potentially pre-existing ones)
		// to ensure we can recreate them in the correct format
		dropIndexes := []string{
			`DROP INDEX IF EXISTS "idx_users_deleted_at"`,
			`DROP INDEX IF EXISTS "idx_api_keys_prefix"`,
			`DROP INDEX IF EXISTS "idx_policies_deleted_at"`,
			`DROP INDEX IF EXISTS "idx_provider_identifier"`,
			`DROP INDEX IF EXISTS "idx_name_provider_identifier"`,
			`DROP INDEX IF EXISTS "idx_name_no_provider_identifier"`,
			`DROP INDEX IF EXISTS "idx_pre_auth_keys_prefix"`,
			`DROP INDEX IF EXISTS "idx_runtime_dns_configs_deleted_at"`,
		}

		for _, dropSQL := range dropIndexes {
			err := tx.Exec(dropSQL).Error
			if err != nil {
				return err
			}
		}

		// Recreate indexes without backticks to match schema.sql format
		indexes := []string{
			`CREATE INDEX idx_users_deleted_at ON users(deleted_at)`,
			`CREATE UNIQUE INDEX idx_api_keys_prefix ON api_keys(prefix)`,
			`CREATE INDEX idx_policies_deleted_at ON policies(deleted_at)`,
			`CREATE UNIQUE INDEX idx_provider_identifier ON users(provider_identifier) WHERE provider_identifier IS NOT NULL`,
			`CREATE UNIQUE INDEX idx_name_provider_identifier ON users(name, provider_identifier)`,
			`CREATE UNIQUE INDEX idx_name_no_provider_identifier ON users(name) WHERE provider_identifier IS NULL`,
			`CREATE UNIQUE INDEX idx_pre_auth_keys_prefix ON pre_auth_keys(prefix) WHERE prefix IS NOT NULL AND prefix != ''`,
			`CREATE UNIQUE INDEX idx_user_credentials_github_id ON user_credentials(git_hub_id) WHERE git_hub_id IS NOT NULL AND git_hub_id != ''`,
			`CREATE INDEX idx_runtime_dns_configs_deleted_at ON runtime_dns_configs(deleted_at)`,
		}

		for _, indexSQL := range indexes {
			err := tx.Exec(indexSQL).Error
			if err != nil {
				return err
			}
		}

		return nil
	})

	err = runMigrations(cfg.Database, dbConn, migrations)
	if err != nil {
		return nil, fmt.Errorf("migration failed: %w", err)
	}

	// Store the current version in the database after migrations succeed.
	// Dev builds skip this to preserve the stored version for the next
	// real versioned binary.
	currentVersion := types.GetVersionInfo().Version
	if !isDev(currentVersion) {
		err = setDatabaseVersion(dbConn, currentVersion)
		if err != nil {
			return nil, fmt.Errorf(
				"storing database version: %w",
				err,
			)
		}
	}

	// Validate that the schema ends up in the expected state.
	// This is currently only done on sqlite as squibble does not
	// support Postgres and we use our sqlite schema as our source of
	// truth.
	if cfg.Database.Type == types.DatabaseSqlite {
		sqlConn, err := dbConn.DB()
		if err != nil {
			return nil, fmt.Errorf("getting DB from gorm: %w", err)
		}

		// or else it blocks...
		sqlConn.SetMaxIdleConns(maxIdleConns)

		sqlConn.SetMaxOpenConns(maxOpenConns)
		defer sqlConn.SetMaxIdleConns(1)
		defer sqlConn.SetMaxOpenConns(1)

		ctx, cancel := context.WithTimeout(context.Background(), contextTimeoutSecs*time.Second)
		defer cancel()

		opts := squibble.DigestOptions{
			IgnoreTables: []string{
				// Litestream tables, these are inserted by
				// litestream and not part of our schema
				// https://litestream.io/how-it-works
				"_litestream_lock",
				"_litestream_seq",
			},
		}

		if err := squibble.Validate(ctx, sqlConn, dbSchema, &opts); err != nil { //nolint:noinlineerr
			return nil, fmt.Errorf("validating schema: %w", err)
		}
	}

	db := HSDatabase{
		DB:       dbConn,
		cfg:      cfg,
		regCache: regCache,
	}

	return &db, err
}

func openDB(cfg types.DatabaseConfig) (*gorm.DB, error) {
	// TODO(kradalby): Integrate this with zerolog
	var dbLogger logger.Interface
	if cfg.Debug {
		dbLogger = util.NewDBLogWrapper(&log.Logger, cfg.Gorm.SlowThreshold, cfg.Gorm.SkipErrRecordNotFound, cfg.Gorm.ParameterizedQueries)
	} else {
		dbLogger = logger.Default.LogMode(logger.Silent)
	}

	switch cfg.Type {
	case types.DatabaseSqlite:
		dir := filepath.Dir(cfg.Sqlite.Path)

		err := util.EnsureDir(dir)
		if err != nil {
			return nil, fmt.Errorf("creating directory for sqlite: %w", err)
		}

		log.Info().
			Str("database", types.DatabaseSqlite).
			Str("path", cfg.Sqlite.Path).
			Msg("Opening database")

		// Build SQLite configuration with pragmas set at connection time
		sqliteConfig := sqliteconfig.Default(cfg.Sqlite.Path)
		if cfg.Sqlite.WriteAheadLog {
			sqliteConfig.JournalMode = sqliteconfig.JournalModeWAL
			sqliteConfig.WALAutocheckpoint = cfg.Sqlite.WALAutoCheckPoint
		}

		connectionURL, err := sqliteConfig.ToURL()
		if err != nil {
			return nil, fmt.Errorf("building sqlite connection URL: %w", err)
		}

		db, err := gorm.Open(
			sqlite.Open(connectionURL),
			&gorm.Config{
				PrepareStmt: cfg.Gorm.PrepareStmt,
				Logger:      dbLogger,
			},
		)

		// The pure Go SQLite library does not handle locking in
		// the same way as the C based one and we can't use the gorm
		// connection pool as of 2022/02/23.
		sqlDB, _ := db.DB()
		sqlDB.SetMaxIdleConns(1)
		sqlDB.SetMaxOpenConns(1)
		sqlDB.SetConnMaxIdleTime(time.Hour)

		return db, err

	case types.DatabasePostgres:
		dbString := fmt.Sprintf(
			"host=%s dbname=%s user=%s",
			cfg.Postgres.Host,
			cfg.Postgres.Name,
			cfg.Postgres.User,
		)

		log.Info().
			Str("database", types.DatabasePostgres).
			Str("path", dbString).
			Msg("Opening database")

		if sslEnabled, err := strconv.ParseBool(cfg.Postgres.Ssl); err == nil { //nolint:noinlineerr
			if !sslEnabled {
				dbString += " sslmode=disable"
			}
		} else {
			dbString += " sslmode=" + cfg.Postgres.Ssl
		}

		if cfg.Postgres.Port != 0 {
			dbString += fmt.Sprintf(" port=%d", cfg.Postgres.Port)
		}

		if cfg.Postgres.Pass != "" {
			dbString += " password=" + cfg.Postgres.Pass
		}

		db, err := gorm.Open(postgres.Open(dbString), &gorm.Config{
			Logger: dbLogger,
		})
		if err != nil {
			return nil, err
		}

		sqlDB, _ := db.DB()
		sqlDB.SetMaxIdleConns(cfg.Postgres.MaxIdleConnections)
		sqlDB.SetMaxOpenConns(cfg.Postgres.MaxOpenConnections)
		sqlDB.SetConnMaxIdleTime(
			time.Duration(cfg.Postgres.ConnMaxIdleTimeSecs) * time.Second,
		)

		return db, nil
	}

	return nil, fmt.Errorf(
		"database of type %s is not supported: %w",
		cfg.Type,
		errDatabaseNotSupported,
	)
}

func runMigrations(cfg types.DatabaseConfig, dbConn *gorm.DB, migrations *gormigrate.Gormigrate) error {
	if cfg.Type == types.DatabaseSqlite {
		// SQLite: Run migrations step-by-step, only disabling foreign keys when necessary

		// List of migration IDs that require foreign keys to be disabled
		// These are migrations that perform complex schema changes that GORM cannot handle safely with FK enabled
		// NO NEW MIGRATIONS SHOULD BE ADDED HERE. ALL NEW MIGRATIONS MUST RUN WITH FOREIGN KEYS ENABLED.
		migrationsRequiringFKDisabled := map[string]bool{
			"202501221827": true, // Route table automigration with FK constraint issues
			"202501311657": true, // PreAuthKey table automigration with FK constraint issues
			// Add other migration IDs here as they are identified to need FK disabled
		}

		// Get the current foreign key status
		var fkOriginallyEnabled int
		if err := dbConn.Raw("PRAGMA foreign_keys").Scan(&fkOriginallyEnabled).Error; err != nil { //nolint:noinlineerr
			return fmt.Errorf("checking foreign key status: %w", err)
		}

		// Get all migration IDs in order from the actual migration definitions
		// Only IDs that are in the migrationsRequiringFKDisabled map will be processed with FK disabled
		// any other new migrations are ran after.
		migrationIDs := []string{
			// v0.25.0
			"202501221827",
			"202501311657",
			"202502070949",

			// v0.26.0
			"202502131714",
			"202502171819",
			"202505091439",
			"202505141324",

			// As of 2025-07-02, no new IDs should be added here.
			// They will be ran by the migrations.Migrate() call below.
		}

		for _, migrationID := range migrationIDs {
			log.Trace().Caller().Str("migration_id", migrationID).Msg("running migration")
			needsFKDisabled := migrationsRequiringFKDisabled[migrationID]

			if needsFKDisabled {
				// Disable foreign keys for this migration
				err := dbConn.Exec("PRAGMA foreign_keys = OFF").Error
				if err != nil {
					return fmt.Errorf("disabling foreign keys for migration %s: %w", migrationID, err)
				}
			} else {
				// Ensure foreign keys are enabled for this migration
				err := dbConn.Exec("PRAGMA foreign_keys = ON").Error
				if err != nil {
					return fmt.Errorf("enabling foreign keys for migration %s: %w", migrationID, err)
				}
			}

			// Run up to this specific migration (will only run the next pending migration)
			err := migrations.MigrateTo(migrationID)
			if err != nil {
				return fmt.Errorf("running migration %s: %w", migrationID, err)
			}
		}

		if err := dbConn.Exec("PRAGMA foreign_keys = ON").Error; err != nil { //nolint:noinlineerr
			return fmt.Errorf("restoring foreign keys: %w", err)
		}

		// Run the rest of the migrations
		if err := migrations.Migrate(); err != nil { //nolint:noinlineerr
			return err
		}

		// Check for constraint violations at the end
		type constraintViolation struct {
			Table           string
			RowID           int
			Parent          string
			ConstraintIndex int
		}

		var violatedConstraints []constraintViolation

		rows, err := dbConn.Raw("PRAGMA foreign_key_check").Rows()
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var violation constraintViolation

			err := rows.Scan(&violation.Table, &violation.RowID, &violation.Parent, &violation.ConstraintIndex)
			if err != nil {
				return err
			}

			violatedConstraints = append(violatedConstraints, violation)
		}

		if err := rows.Err(); err != nil { //nolint:noinlineerr
			return err
		}

		if len(violatedConstraints) > 0 {
			for _, violation := range violatedConstraints {
				log.Error().
					Str("table", violation.Table).
					Int("row_id", violation.RowID).
					Str("parent", violation.Parent).
					Msg("Foreign key constraint violated")
			}

			return errForeignKeyConstraintsViolated
		}
	} else {
		// PostgreSQL can run all migrations in one block - no foreign key issues
		err := migrations.Migrate()
		if err != nil {
			return err
		}
	}

	return nil
}

func (hsdb *HSDatabase) PingDB(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()

	sqlDB, err := hsdb.DB.DB()
	if err != nil {
		return err
	}

	return sqlDB.PingContext(ctx)
}

func (hsdb *HSDatabase) Close() error {
	db, err := hsdb.DB.DB()
	if err != nil {
		return err
	}

	if hsdb.cfg.Database.Type == types.DatabaseSqlite && hsdb.cfg.Database.Sqlite.WriteAheadLog {
		db.Exec("VACUUM") //nolint:errcheck,noctx
	}

	return db.Close()
}

func (hsdb *HSDatabase) Read(fn func(rx *gorm.DB) error) error {
	rx := hsdb.DB.Begin()
	defer rx.Rollback()

	return fn(rx)
}

func Read[T any](db *gorm.DB, fn func(rx *gorm.DB) (T, error)) (T, error) {
	rx := db.Begin()
	defer rx.Rollback()

	ret, err := fn(rx)
	if err != nil {
		var no T
		return no, err
	}

	return ret, nil
}

func (hsdb *HSDatabase) Write(fn func(tx *gorm.DB) error) error {
	tx := hsdb.DB.Begin()
	defer tx.Rollback()

	err := fn(tx)
	if err != nil {
		return err
	}

	return tx.Commit().Error
}

func Write[T any](db *gorm.DB, fn func(tx *gorm.DB) (T, error)) (T, error) {
	tx := db.Begin()
	defer tx.Rollback()

	ret, err := fn(tx)
	if err != nil {
		var no T
		return no, err
	}

	return ret, tx.Commit().Error
}
