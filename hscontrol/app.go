package hscontrol

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	_ "net/http/pprof" // nolint
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/davecgh/go-spew/spew"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/metrics"
	grpcRuntime "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/juanfont/headscale"
	"github.com/juanfont/headscale/docs"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/capver"
	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/derp"
	derpServer "github.com/juanfont/headscale/hscontrol/derp/server"
	"github.com/juanfont/headscale/hscontrol/dns"
	"github.com/juanfont/headscale/hscontrol/mapper"
	"github.com/juanfont/headscale/hscontrol/provider"
	_ "github.com/juanfont/headscale/hscontrol/provider/mullvad" // register Mullvad provider
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/juanfont/headscale/hscontrol/util"
	zerolog "github.com/philip-bui/grpc-zerolog"
	"github.com/pkg/profile"
	zl "github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/sasha-s/go-deadlock"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
	"tailscale.com/envknob"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/key"
	"tailscale.com/util/dnsname"
)

var (
	errSTUNAddressNotSet                   = errors.New("STUN address not set")
	errUnsupportedLetsEncryptChallengeType = errors.New(
		"unknown value for Lets Encrypt challenge type",
	)
	errEmptyInitialDERPMap = errors.New(
		"initial DERPMap is empty, Headscale requires at least one entry",
	)
)

type docEntry struct {
	Path  string `json:"path"`
	Title string `json:"title"`
}

var (
	debugDeadlock        = envknob.Bool("HEADSCALE_DEBUG_DEADLOCK")
	debugDeadlockTimeout = envknob.RegisterDuration("HEADSCALE_DEBUG_DEADLOCK_TIMEOUT")
)

func init() {
	deadlock.Opts.Disable = !debugDeadlock
	if debugDeadlock {
		deadlock.Opts.DeadlockTimeout = debugDeadlockTimeout()
		deadlock.Opts.PrintAllCurrentGoroutines = true
	}
}

const (
	AuthPrefix         = "Bearer "
	updateInterval     = 5 * time.Second
	privateKeyFileMode = 0o600
	headscaleDirPerm   = 0o700
)

// Headscale represents the base app of the service.
type Headscale struct {
	cfg             *types.Config
	state           *state.State
	noisePrivateKey *key.MachinePrivate
	sessionSecret   string
	ephemeralGC     *db.EphemeralGarbageCollector

	DERPServer *derpServer.DERPServer

	// Things that generate changes
	extraRecordMan *dns.ExtraRecordsMan
	authProvider   AuthProvider
	mapBatcher     mapper.Batcher

	clientStreamsOpen sync.WaitGroup
}

var (
	profilingEnabled = envknob.Bool("HEADSCALE_DEBUG_PROFILING_ENABLED")
	profilingPath    = envknob.String("HEADSCALE_DEBUG_PROFILING_PATH")
	tailsqlEnabled   = envknob.Bool("HEADSCALE_DEBUG_TAILSQL_ENABLED")
	tailsqlStateDir  = envknob.String("HEADSCALE_DEBUG_TAILSQL_STATE_DIR")
	tailsqlTSKey     = envknob.String("TS_AUTHKEY")
	dumpConfig       = envknob.Bool("HEADSCALE_DEBUG_DUMP_CONFIG")
)

func NewHeadscale(cfg *types.Config) (*Headscale, error) {
	var err error

	if profilingEnabled {
		runtime.SetBlockProfileRate(1)
	}

	noisePrivateKey, err := readOrCreatePrivateKey(cfg.NoisePrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("reading or creating Noise protocol private key: %w", err)
	}

	var sessionSecret string
	if cfg.WebUI.Enabled {
		sessionSecret, err = readOrCreateSessionSecret(cfg.WebUI.Session.SecretPath)
		if err != nil {
			return nil, fmt.Errorf("reading or creating session secret: %w", err)
		}
	}

	s, err := state.NewState(cfg)
	if err != nil {
		return nil, fmt.Errorf("init state: %w", err)
	}

	app := Headscale{
		cfg:               cfg,
		noisePrivateKey:   noisePrivateKey,
		sessionSecret:     sessionSecret,
		clientStreamsOpen: sync.WaitGroup{},
		state:             s,
	}

	// Initialize ephemeral garbage collector
	ephemeralGC := db.NewEphemeralGarbageCollector(func(ni types.NodeID) {
		node, ok := app.state.GetNodeByID(ni)
		if !ok {
			log.Error().Uint64("node.id", ni.Uint64()).Msg("ephemeral node deletion failed")
			log.Debug().Caller().Uint64("node.id", ni.Uint64()).Msg("ephemeral node deletion failed because node not found in NodeStore")

			return
		}

		policyChanged, err := app.state.DeleteNode(node)
		if err != nil {
			log.Error().Err(err).EmbedObject(node).Msg("ephemeral node deletion failed")
			return
		}

		app.Change(policyChanged)
		log.Debug().Caller().EmbedObject(node).Msg("ephemeral node deleted because garbage collection timeout reached")
	})
	app.ephemeralGC = ephemeralGC

	var authProvider AuthProvider

	webUIBasePath := ""
	if cfg.WebUI.Enabled {
		webUIBasePath = cfg.WebUI.BasePath
	}
	authProvider = NewAuthProviderWeb(cfg.ServerURL, webUIBasePath)
	if cfg.OIDC.Issuer != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		oidcProvider, err := NewAuthProviderOIDC(
			ctx,
			&app,
			cfg.ServerURL,
			&cfg.OIDC,
		)
		if err != nil {
			if cfg.OIDC.OnlyStartIfOIDCIsAvailable {
				return nil, err
			} else {
				log.Warn().Err(err).Msg("failed to set up OIDC provider, falling back to CLI based authentication")
			}
		} else {
			authProvider = oidcProvider
		}
	}

	app.authProvider = authProvider

	if app.cfg.TailcfgDNSConfig != nil && app.cfg.TailcfgDNSConfig.Proxied { // if MagicDNS
		// TODO(kradalby): revisit why this takes a list.
		var magicDNSDomains []dnsname.FQDN
		if cfg.PrefixV4 != nil {
			magicDNSDomains = append(
				magicDNSDomains,
				util.GenerateIPv4DNSRootDomain(*cfg.PrefixV4)...)
		}

		if cfg.PrefixV6 != nil {
			magicDNSDomains = append(
				magicDNSDomains,
				util.GenerateIPv6DNSRootDomain(*cfg.PrefixV6)...)
		}

		// we might have routes already from Split DNS
		if app.cfg.TailcfgDNSConfig.Routes == nil {
			app.cfg.TailcfgDNSConfig.Routes = make(map[string][]*dnstype.Resolver)
		}

		for _, d := range magicDNSDomains {
			app.cfg.TailcfgDNSConfig.Routes[d.WithoutTrailingDot()] = nil
		}
	}

	if cfg.DERP.ServerEnabled {
		derpServerKey, err := readOrCreatePrivateKey(cfg.DERP.ServerPrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("reading or creating DERP server private key: %w", err)
		}

		if derpServerKey.Equal(*noisePrivateKey) {
			return nil, fmt.Errorf(
				"DERP server private key and noise private key are the same: %w",
				err,
			)
		}

		if cfg.DERP.ServerVerifyClients {
			t := http.DefaultTransport.(*http.Transport) //nolint:forcetypeassert
			t.RegisterProtocol(
				derpServer.DerpVerifyScheme,
				derpServer.NewDERPVerifyTransport(app.handleVerifyRequest),
			)
		}

		embeddedDERPServer, err := derpServer.NewDERPServer(
			cfg.ServerURL,
			key.NodePrivate(*derpServerKey),
			&cfg.DERP,
		)
		if err != nil {
			return nil, err
		}

		app.DERPServer = embeddedDERPServer
	}

	// Initialize VPN provider manager if any provider accounts exist in the database.
	if err := app.initProviderManager(); err != nil {
		log.Warn().Err(err).Msg("failed to initialize VPN provider manager")
	}

	// Verify existing provider allocations are still valid on the provider API,
	// then reconcile to register any missing keys. This approach avoids the
	// destructive flush+re-register pattern which could create orphaned keys
	// through API timing races.
	if app.state.ProviderManager() != nil {
		app.state.VerifyProviderAllocations(context.Background())
		app.state.ReconcileProviderAllocations(context.Background())
	}

	// Load runtime DNS config override from database (if any).
	app.loadRuntimeDNSConfig()

	return &app, nil
}

// applyDNSConfig updates the running DNS configuration from a types.DNSConfig.
// It regenerates TailcfgDNSConfig and applies MagicDNS routes.
func (h *Headscale) applyDNSConfig(dns types.DNSConfig) {
	h.cfg.DNSConfig = dns
	h.cfg.TailcfgDNSConfig = types.DNSToTailcfgDNS(dns)

	if h.cfg.TailcfgDNSConfig != nil && h.cfg.TailcfgDNSConfig.Proxied {
		var magicDNSDomains []dnsname.FQDN
		if h.cfg.PrefixV4 != nil {
			magicDNSDomains = append(
				magicDNSDomains,
				util.GenerateIPv4DNSRootDomain(*h.cfg.PrefixV4)...)
		}
		if h.cfg.PrefixV6 != nil {
			magicDNSDomains = append(
				magicDNSDomains,
				util.GenerateIPv6DNSRootDomain(*h.cfg.PrefixV6)...)
		}
		if h.cfg.TailcfgDNSConfig.Routes == nil {
			h.cfg.TailcfgDNSConfig.Routes = make(map[string][]*dnstype.Resolver)
		}
		for _, d := range magicDNSDomains {
			h.cfg.TailcfgDNSConfig.Routes[d.WithoutTrailingDot()] = nil
		}
	}
}

// loadRuntimeDNSConfig checks DB for a runtime DNS config override and applies it.
func (h *Headscale) loadRuntimeDNSConfig() {
	rtCfg, err := h.state.DB().GetRuntimeDNSConfig()
	if err != nil {
		log.Warn().Err(err).Msg("failed to load runtime DNS config from database")
		return
	}
	if rtCfg == nil {
		return
	}

	var dns types.DNSConfig
	if err := json.Unmarshal([]byte(rtCfg.Data), &dns); err != nil {
		log.Warn().Err(err).Msg("failed to unmarshal runtime DNS config, using file defaults")
		return
	}

	h.applyDNSConfig(dns)
	log.Info().Msg("loaded runtime DNS config from database")
}

// fileDefaultsDNSConfig returns the DNS config from the original config file.
// This is used as the "defaults" for the restore operation.
func (h *Headscale) fileDefaultsDNSConfig() types.DNSConfig {
	return types.DNSConfigFromFile(h.cfg)
}

// dnsConfigToJSON builds the JSON response map for a DNS config.
func (h *Headscale) dnsConfigToJSON(dns types.DNSConfig) map[string]any {
	globalNS := make([]string, 0, len(dns.Nameservers.Global))
	globalNS = append(globalNS, dns.Nameservers.Global...)

	splitNS := make(map[string][]string)
	for domain, servers := range dns.Nameservers.Split {
		splitNS[domain] = servers
	}

	searchDomains := dns.SearchDomains
	if searchDomains == nil {
		searchDomains = []string{}
	}

	extraRecords := make([]map[string]string, 0, len(dns.ExtraRecords))
	for _, rec := range dns.ExtraRecords {
		extraRecords = append(extraRecords, map[string]string{
			"name":  rec.Name,
			"type":  rec.Type,
			"value": rec.Value,
		})
	}

	return map[string]any{
		"magicDns":         dns.MagicDNS,
		"baseDomain":       dns.BaseDomain,
		"overrideLocalDns": dns.OverrideLocalDNS,
		"nameservers": map[string]any{
			"global": globalNS,
			"split":  splitNS,
		},
		"searchDomains": searchDomains,
		"extraRecords":  extraRecords,
	}
}

// Redirect to our TLS url.
func (h *Headscale) redirect(w http.ResponseWriter, req *http.Request) {
	target := h.cfg.ServerURL + req.URL.RequestURI()
	http.Redirect(w, req, target, http.StatusFound)
}

const providerSyncInterval = 1 * time.Hour

// initProviderManager checks for VPN provider accounts in the database and,
// if any exist, creates a provider.Manager, registers all relevant providers,
// and performs an initial relay sync.
func (h *Headscale) initProviderManager() error {
	accounts, err := h.state.DB().ListProviderAccounts("")
	if err != nil {
		return fmt.Errorf("listing provider accounts: %w", err)
	}

	if len(accounts) == 0 {
		return nil
	}

	mgr := provider.NewManager(h.cfg.BaseDomain)

	// Determine unique provider names from accounts.
	seen := make(map[string]bool)
	for _, acct := range accounts {
		if acct.Enabled && !seen[acct.ProviderName] {
			seen[acct.ProviderName] = true

			if err := mgr.RegisterProvider(acct.ProviderName); err != nil {
				log.Warn().Err(err).Str("provider", acct.ProviderName).Msg("failed to register provider")
			}
		}
	}

	h.state.SetProviderManager(mgr)

	// Perform initial relay sync for each registered provider.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for name := range seen {
		if err := h.state.SyncProviderRelays(ctx, name); err != nil {
			log.Warn().Err(err).Str("provider", name).Msg("initial provider relay sync failed")
		}
	}

	return nil
}

func (h *Headscale) scheduledTasks(ctx context.Context) {
	expireTicker := time.NewTicker(updateInterval)
	defer expireTicker.Stop()

	lastExpiryCheck := time.Unix(0, 0)

	derpTickerChan := make(<-chan time.Time)

	if h.cfg.DERP.AutoUpdate && h.cfg.DERP.UpdateFrequency != 0 {
		derpTicker := time.NewTicker(h.cfg.DERP.UpdateFrequency)
		defer derpTicker.Stop()

		derpTickerChan = derpTicker.C
	}

	var extraRecordsUpdate <-chan []tailcfg.DNSRecord
	if h.extraRecordMan != nil {
		extraRecordsUpdate = h.extraRecordMan.UpdateCh()
	} else {
		extraRecordsUpdate = make(chan []tailcfg.DNSRecord)
	}

	providerTickerChan := make(<-chan time.Time)
	if h.state.ProviderManager() != nil {
		providerTicker := time.NewTicker(providerSyncInterval)
		defer providerTicker.Stop()

		providerTickerChan = providerTicker.C
	}

	for {
		select {
		case <-ctx.Done():
			log.Info().Caller().Msg("scheduled task worker is shutting down.")
			return

		case <-expireTicker.C:
			var (
				expiredNodeChanges []change.Change
				changed            bool
			)

			lastExpiryCheck, expiredNodeChanges, changed = h.state.ExpireExpiredNodes(lastExpiryCheck)

			if changed {
				log.Trace().Interface("changes", expiredNodeChanges).Msgf("expiring nodes")

				// Send the changes directly since they're already in the new format
				for _, nodeChange := range expiredNodeChanges {
					h.Change(nodeChange)
				}
			}

		case <-derpTickerChan:
			log.Info().Msg("fetching DERPMap updates")

			derpMap, err := backoff.Retry(ctx, func() (*tailcfg.DERPMap, error) { //nolint:contextcheck
				derpMap, err := derp.GetDERPMap(h.cfg.DERP)
				if err != nil {
					return nil, err
				}

				if h.cfg.DERP.ServerEnabled && h.cfg.DERP.AutomaticallyAddEmbeddedDerpRegion {
					region, _ := h.DERPServer.GenerateRegion()
					derpMap.Regions[region.RegionID] = &region
				}

				return derpMap, nil
			}, backoff.WithBackOff(backoff.NewExponentialBackOff()))
			if err != nil {
				log.Error().Err(err).Msg("failed to build new DERPMap, retrying later")
				continue
			}

			h.state.SetDERPMap(derpMap)

			h.Change(change.DERPMap())

		case records, ok := <-extraRecordsUpdate:
			if !ok {
				continue
			}

			h.cfg.TailcfgDNSConfig.ExtraRecords = records

			h.Change(change.ExtraRecords())

		case <-providerTickerChan:
			log.Info().Msg("syncing VPN provider relays")

			mgr := h.state.ProviderManager()
			if mgr == nil {
				continue
			}

			for _, name := range provider.Registered() {
				if _, ok := mgr.Provider(name); !ok {
					continue
				}

				if err := h.state.SyncProviderRelays(ctx, name); err != nil {
					log.Error().Err(err).Str("provider", name).Msg("failed to sync provider relays")

					continue
				}
			}

			// Reconcile key allocations after relay sync.
			h.state.ReconcileProviderAllocations(ctx)

			h.Change(change.Change{
				Reason:       "provider relay sync",
				SendAllPeers: true,
			})
		}
	}
}

func (h *Headscale) grpcAuthenticationInterceptor(ctx context.Context,
	req any,
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (any, error) {
	// Check if the request is coming from the on-server client.
	// This is not secure, but it is to maintain maintainability
	// with the "legacy" database-based client
	// It is also needed for grpc-gateway to be able to connect to
	// the server
	client, _ := peer.FromContext(ctx)

	log.Trace().
		Caller().
		Str("client_address", client.Addr.String()).
		Msg("Client is trying to authenticate")

	meta, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ctx, status.Errorf(
			codes.InvalidArgument,
			"retrieving metadata",
		)
	}

	authHeader, ok := meta["authorization"]
	if !ok {
		return ctx, status.Errorf(
			codes.Unauthenticated,
			"authorization token not supplied",
		)
	}

	token := authHeader[0]

	if !strings.HasPrefix(token, AuthPrefix) {
		return ctx, status.Error(
			codes.Unauthenticated,
			`missing "Bearer " prefix in "Authorization" header`,
		)
	}

	valid, err := h.state.ValidateAPIKey(strings.TrimPrefix(token, AuthPrefix))
	if err != nil {
		return ctx, status.Error(codes.Internal, "validating token")
	}

	if !valid {
		log.Info().
			Str("client_address", client.Addr.String()).
			Msg("invalid token")

		return ctx, status.Error(codes.Unauthenticated, "invalid token")
	}

	return handler(ctx, req)
}

func (h *Headscale) httpAuthenticationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(
		writer http.ResponseWriter,
		req *http.Request,
	) {
		log.Trace().
			Caller().
			Str("client_address", req.RemoteAddr).
			Msg("HTTP authentication invoked")

		// Public webauth endpoints that don't require pre-existing auth.
		if isPublicWebAuthPath(req.URL.Path) {
			next.ServeHTTP(writer, req)

			return
		}

		authHeader := req.Header.Get("Authorization")

		writeUnauthorized := func(statusCode int) {
			writer.WriteHeader(statusCode)

			if _, err := writer.Write([]byte("Unauthorized")); err != nil { //nolint:noinlineerr
				log.Error().Err(err).Msg("writing HTTP response failed")
			}
		}

		// Try Bearer API key authentication first.
		if strings.HasPrefix(authHeader, AuthPrefix) {
			valid, err := h.state.ValidateAPIKey(strings.TrimPrefix(authHeader, AuthPrefix))
			if err != nil {
				log.Info().
					Caller().
					Err(err).
					Str("client_address", req.RemoteAddr).
					Msg("failed to validate token")
				writeUnauthorized(http.StatusUnauthorized)

				return
			}

			if !valid {
				log.Info().
					Str("client_address", req.RemoteAddr).
					Msg("invalid token")
				writeUnauthorized(http.StatusUnauthorized)

				return
			}

			next.ServeHTTP(writer, req)

			return
		}

		// Try session cookie authentication (web UI sessions).
		if cookie, err := req.Cookie("hs_session"); err == nil && cookie.Value != "" {
			session, err := h.state.DB().ValidateUserSession(cookie.Value)
			if err == nil && session.User.CanWebAuth() {
				next.ServeHTTP(writer, req)

				return
			}
		}

		log.Error().
			Caller().
			Str("client_address", req.RemoteAddr).
			Msg("no valid authentication credentials provided")
		writeUnauthorized(http.StatusUnauthorized)
	})
}

// isPublicWebAuthPath returns true for webauth endpoints that must be
// accessible without pre-existing authentication (login, OAuth flows,
// auth methods discovery).
func isPublicWebAuthPath(urlPath string) bool {
	publicPrefixes := []string{
		"/api/v1/webauth/login",
		"/api/v1/webauth/github",
		"/api/v1/webauth/github/callback",
		"/api/v1/webauth/registration/",
		"/api/v1/webauth/otp/verify",
		"/api/v1/webauth/approval-status",
	}

	for _, p := range publicPrefixes {
		if urlPath == p || strings.HasPrefix(urlPath, p) {
			return true
		}
	}

	return false
}

// webRoleAuthorizationHandler wraps the gRPC-gateway handler with role-based
// authorization for web sessions. API key access is unrestricted (API keys are
// created by admins). Web session access is restricted per Tailscale's role model:
//
//	admin:         full access
//	network_admin: read all, write ACL/policy and DNS
//	it_admin:      read all, write users/machines/keys
//	member:        read-only (list operations only)
func (h *Headscale) webRoleAuthorizationHandler(
	grpcMux http.Handler,
) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		// API key auth — allow through (created by admins, trusted).
		authHeader := req.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, AuthPrefix) {
			grpcMux.ServeHTTP(w, req)
			return
		}

		// Public webauth paths — allow through.
		if isPublicWebAuthPath(req.URL.Path) {
			grpcMux.ServeHTTP(w, req)
			return
		}

		// Webauth session paths (login, session, logout, GitHub callback, OTP) — allow through.
		if strings.HasPrefix(req.URL.Path, "/api/v1/webauth/") {
			grpcMux.ServeHTTP(w, req)
			return
		}

		// Read-only endpoints — any authenticated user may access.
		if req.Method == http.MethodGet {
			grpcMux.ServeHTTP(w, req)
			return
		}

		// Everything else is a mutating operation. Extract user role from session.
		cookie, err := req.Cookie("hs_session")
		if err != nil || cookie.Value == "" {
			grpcMux.ServeHTTP(w, req)
			return
		}
		session, err := h.state.DB().ValidateUserSession(cookie.Value)
		if err != nil {
			grpcMux.ServeHTTP(w, req)
			return
		}

		role := string(session.User.Role)
		urlPath := req.URL.Path

		if !isRoleAllowed(role, req.Method, urlPath) {
			http.Error(w, "Forbidden: insufficient permissions for this action", http.StatusForbidden)
			return
		}

		grpcMux.ServeHTTP(w, req)
	}
}

// isRoleAllowed checks whether the given role can perform the HTTP method
// on the given endpoint path. Based on Tailscale's permission matrix.
func isRoleAllowed(role, method, urlPath string) bool {
	if role == types.UserRoleAdmin {
		return true
	}

	// Classify the operation by URL path prefix.
	switch {
	// User write operations: admin, it_admin
	case strings.HasPrefix(urlPath, "/api/v1/user"):
		return role == types.UserRoleITAdmin

	// Node write operations: admin, it_admin
	case strings.HasPrefix(urlPath, "/api/v1/node"):
		return role == types.UserRoleITAdmin

	// PreAuthKey write operations: admin, network_admin, it_admin
	case strings.HasPrefix(urlPath, "/api/v1/preauthkey"):
		return role == types.UserRoleNetworkAdmin || role == types.UserRoleITAdmin

	// API key write operations: admin, network_admin, it_admin
	case strings.HasPrefix(urlPath, "/api/v1/apikey"):
		return role == types.UserRoleNetworkAdmin || role == types.UserRoleITAdmin

	// Policy write operations: admin, network_admin
	case strings.HasPrefix(urlPath, "/api/v1/policy"):
		return role == types.UserRoleNetworkAdmin

	// Auth approve/reject operations: admin, it_admin
	case strings.HasPrefix(urlPath, "/api/v1/auth/"):
		return role == types.UserRoleITAdmin

	// Provider operations: admin only
	case strings.HasPrefix(urlPath, "/api/v1/provider"):
		return false

	default:
		// Unknown mutating endpoint. Admin only by default.
		return false
	}
}

// ensureUnixSocketIsAbsent will check if the given path for headscales unix socket is clear
// and will remove it if it is not.
func (h *Headscale) ensureUnixSocketIsAbsent() error {
	// File does not exist, all fine
	if _, err := os.Stat(h.cfg.UnixSocket); errors.Is(err, os.ErrNotExist) { //nolint:noinlineerr
		return nil
	}

	return os.Remove(h.cfg.UnixSocket)
}

func (h *Headscale) createRouter(grpcMux *grpcRuntime.ServeMux) *chi.Mux {
	r := chi.NewRouter()
	r.Use(metrics.Collector(metrics.CollectorOpts{
		Host:  false,
		Proto: true,
		Skip: func(r *http.Request) bool {
			return r.Method != http.MethodOptions
		},
	}))
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.RequestLogger(&zerologRequestLogger{}))
	r.Use(middleware.Recoverer)

	r.Post(ts2021UpgradePath, h.NoiseUpgradeHandler)

	r.Get("/robots.txt", h.RobotsHandler)
	r.Get("/health", h.HealthHandler)
	r.Get("/version", h.VersionHandler)
	r.Get("/key", h.KeyHandler)
	r.Get("/register/{auth_id}", h.authProvider.RegisterHandler)
	r.Get("/auth/{auth_id}", h.authProvider.AuthHandler)

	if provider, ok := h.authProvider.(*AuthProviderOIDC); ok {
		r.Get("/oidc/callback", provider.OIDCCallbackHandler)
	}

	r.Get("/apple", h.AppleConfigMessage)
	r.Get("/apple/{platform}", h.ApplePlatformConfig)
	r.Get("/windows", h.WindowsConfigMessage)

	// TODO(kristoffer): move swagger into a package
	r.Get("/swagger", headscale.SwaggerUI)
	r.Get("/swagger/v1/openapiv2.json", headscale.SwaggerAPIv1)

	r.Post("/verify", h.VerifyHandler)

	if h.cfg.DERP.ServerEnabled {
		r.HandleFunc("/derp", h.DERPServer.DERPHandler)
		r.HandleFunc("/derp/probe", derpServer.DERPProbeHandler)
		r.HandleFunc("/derp/latency-check", derpServer.DERPProbeHandler)
		r.HandleFunc("/bootstrap-dns", derpServer.DERPBootstrapDNSHandler(h.state.DERPMap()))
	}

	r.Route("/api", func(r chi.Router) {
		r.Use(h.httpAuthenticationMiddleware)

		// Lightweight approval-status check for pending users (no auth needed).
		r.Get("/v1/webauth/approval-status", func(w http.ResponseWriter, req *http.Request) {
			username := req.URL.Query().Get("username")
			approved := false
			if username != "" {
				if u, err := h.state.DB().GetUserByName(username); err == nil {
					approved = !u.IsPending()
				}
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"approved":%t}`, approved)
		})

		// GitHub OAuth callback: when GitHub redirects the browser here,
		// forward to the frontend SPA which handles the exchange via API.
		if h.cfg.WebUI.Enabled && h.cfg.WebUI.Auth.GitHub.Enabled {
			r.Get("/v1/webauth/github/callback", func(w http.ResponseWriter, req *http.Request) {
				// Browser navigations don't set Content-Type; the frontend fetch does.
				if !strings.Contains(req.Header.Get("Content-Type"), "application/json") {
					basePath := h.cfg.WebUI.BasePath
					if basePath == "" {
						basePath = "/admin"
					}
					target := fmt.Sprintf("%s/login?code=%s&state=%s",
						basePath,
						url.QueryEscape(req.URL.Query().Get("code")),
						url.QueryEscape(req.URL.Query().Get("state")))
					http.Redirect(w, req, target, http.StatusFound)
					return
				}
				grpcMux.ServeHTTP(w, req)
			})
		}

		// DNS config endpoints for the web UI (admin-only).
		r.Route("/v1/dns/config", func(r chi.Router) {
			// Admin check middleware for DNS endpoints.
			r.Use(func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					var isAdmin bool
					if cookie, err := req.Cookie("hs_session"); err == nil && cookie.Value != "" {
						if session, err := h.state.DB().ValidateUserSession(cookie.Value); err == nil {
							isAdmin = session.User.IsAdmin()
						}
					}
					authHeader := req.Header.Get("Authorization")
					if strings.HasPrefix(authHeader, AuthPrefix) {
						if valid, err := h.state.ValidateAPIKey(strings.TrimPrefix(authHeader, AuthPrefix)); err == nil && valid {
							isAdmin = true
						}
					}
					if !isAdmin {
						http.Error(w, "Forbidden", http.StatusForbidden)
						return
					}
					next.ServeHTTP(w, req)
				})
			})

			// GET — return the active DNS config.
			r.Get("/", func(w http.ResponseWriter, req *http.Request) {
				rtCfg, _ := h.state.DB().GetRuntimeDNSConfig()
				resp := h.dnsConfigToJSON(h.cfg.DNSConfig)
				resp["isOverridden"] = rtCfg != nil
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(resp) //nolint:errcheck
			})

			// GET — return file-based defaults.
			r.Get("/defaults", func(w http.ResponseWriter, req *http.Request) {
				fileDNS := h.fileDefaultsDNSConfig()
				resp := h.dnsConfigToJSON(fileDNS)
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(resp) //nolint:errcheck
			})

			// PUT — update runtime DNS config (stored in DB).
			r.Put("/", func(w http.ResponseWriter, req *http.Request) {
				var payload struct {
					MagicDns         bool                `json:"magicDns"`
					BaseDomain       string              `json:"baseDomain"`
					OverrideLocalDns bool                `json:"overrideLocalDns"`
					Nameservers      types.Nameservers   `json:"nameservers"`
					SearchDomains    []string            `json:"searchDomains"`
					ExtraRecords     []map[string]string `json:"extraRecords"`
				}
				if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
					http.Error(w, "Invalid JSON", http.StatusBadRequest)
					return
				}

				dnsCfg := types.DNSConfig{
					MagicDNS:         payload.MagicDns,
					BaseDomain:       payload.BaseDomain,
					OverrideLocalDNS: payload.OverrideLocalDns,
					Nameservers:      payload.Nameservers,
					SearchDomains:    payload.SearchDomains,
				}
				for _, rec := range payload.ExtraRecords {
					dnsCfg.ExtraRecords = append(dnsCfg.ExtraRecords, tailcfg.DNSRecord{
						Name:  rec["name"],
						Type:  rec["type"],
						Value: rec["value"],
					})
				}

				data, err := json.Marshal(dnsCfg)
				if err != nil {
					http.Error(w, "Failed to serialize config", http.StatusInternalServerError)
					return
				}
				if _, err := h.state.DB().SetRuntimeDNSConfig(string(data)); err != nil {
					http.Error(w, "Failed to save config", http.StatusInternalServerError)
					return
				}

				h.applyDNSConfig(dnsCfg)
				h.Change(change.DNSConfig())

				resp := h.dnsConfigToJSON(dnsCfg)
				resp["isOverridden"] = true
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(resp) //nolint:errcheck
			})

			// POST /restore — remove DB override, revert to file defaults.
			r.Post("/restore", func(w http.ResponseWriter, req *http.Request) {
				if err := h.state.DB().DeleteRuntimeDNSConfig(); err != nil {
					http.Error(w, "Failed to restore defaults", http.StatusInternalServerError)
					return
				}

				fileDNS := h.fileDefaultsDNSConfig()
				h.applyDNSConfig(fileDNS)
				h.Change(change.DNSConfig())

				resp := h.dnsConfigToJSON(fileDNS)
				resp["isOverridden"] = false
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(resp) //nolint:errcheck
			})
		})

		// Audit event log endpoint (admin-only).
		r.Route("/v1/audit/events", func(r chi.Router) {
			r.Use(func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					var isAdmin bool
					if cookie, err := req.Cookie("hs_session"); err == nil && cookie.Value != "" {
						if session, err := h.state.DB().ValidateUserSession(cookie.Value); err == nil {
							isAdmin = session.User.IsAdmin()
						}
					}
					authHeader := req.Header.Get("Authorization")
					if strings.HasPrefix(authHeader, AuthPrefix) {
						if valid, err := h.state.ValidateAPIKey(strings.TrimPrefix(authHeader, AuthPrefix)); err == nil && valid {
							isAdmin = true
						}
					}
					if !isAdmin {
						http.Error(w, "Forbidden", http.StatusForbidden)
						return
					}
					next.ServeHTTP(w, req)
				})
			})

			r.Get("/", func(w http.ResponseWriter, req *http.Request) {
				eventType := req.URL.Query().Get("event_type")
				limit := 100
				offset := 0
				if l := req.URL.Query().Get("limit"); l != "" {
					if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 500 {
						limit = n
					}
				}
				if o := req.URL.Query().Get("offset"); o != "" {
					if n, err := strconv.Atoi(o); err == nil && n >= 0 {
						offset = n
					}
				}

				events, total, err := h.state.DB().ListAuditEvents(eventType, limit, offset)
				if err != nil {
					http.Error(w, "Failed to list events", http.StatusInternalServerError)
					return
				}

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
					"events": events,
					"total":  total,
				})
			})
		})

		// Console log endpoint (admin-only) — returns recent headscale log output.
		r.Route("/v1/console/logs", func(r chi.Router) {
			r.Use(func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					var isAdmin bool
					if cookie, err := req.Cookie("hs_session"); err == nil && cookie.Value != "" {
						if session, err := h.state.DB().ValidateUserSession(cookie.Value); err == nil {
							isAdmin = session.User.IsAdmin()
						}
					}
					authHeader := req.Header.Get("Authorization")
					if strings.HasPrefix(authHeader, AuthPrefix) {
						if valid, err := h.state.ValidateAPIKey(strings.TrimPrefix(authHeader, AuthPrefix)); err == nil && valid {
							isAdmin = true
						}
					}
					if !isAdmin {
						http.Error(w, "Forbidden", http.StatusForbidden)
						return
					}
					next.ServeHTTP(w, req)
				})
			})

			r.Get("/", func(w http.ResponseWriter, req *http.Request) {
				limit := 500
				if l := req.URL.Query().Get("limit"); l != "" {
					if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 2000 {
						limit = n
					}
				}
				entries := ConsoleLogBuffer.Entries(limit)
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
					"entries": entries,
				})
			})
		})

		// Profile endpoint — lets the current user view/update their own profile.
		r.Route("/v1/profile/me", func(r chi.Router) {
			// GET — return the current user's profile.
			r.Get("/", func(w http.ResponseWriter, req *http.Request) {
				var user *types.User
				if cookie, err := req.Cookie("hs_session"); err == nil && cookie.Value != "" {
					if session, err := h.state.DB().ValidateUserSession(cookie.Value); err == nil {
						user = &session.User
					}
				}
				if user == nil {
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{"user": user.Proto()}) //nolint:errcheck
			})

			// PUT — update the current user's display name and profile picture.
			r.Put("/", func(w http.ResponseWriter, req *http.Request) {
				var user *types.User
				if cookie, err := req.Cookie("hs_session"); err == nil && cookie.Value != "" {
					if session, err := h.state.DB().ValidateUserSession(cookie.Value); err == nil {
						user = &session.User
					}
				}
				if user == nil {
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}

				var payload struct {
					DisplayName   string `json:"display_name"`
					ProfilePicURL string `json:"profile_pic_url"`
				}
				if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
					http.Error(w, "Invalid JSON", http.StatusBadRequest)
					return
				}

				// Validate profile pic URL if provided.
				if payload.ProfilePicURL != "" {
					if u, err := url.Parse(payload.ProfilePicURL); err != nil || (u.Scheme != "https" && u.Scheme != "http") {
						http.Error(w, "Invalid profile picture URL", http.StatusBadRequest)
						return
					}
				}

				updated, err := h.state.DB().UpdateUserProfile(
					types.UserID(user.ID),
					payload.DisplayName,
					payload.ProfilePicURL,
				)
				if err != nil {
					http.Error(w, "Failed to update profile", http.StatusInternalServerError)
					return
				}

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{"user": updated.Proto()}) //nolint:errcheck
			})
			// POST — upload an avatar image file.
			r.Post("/avatar", func(w http.ResponseWriter, req *http.Request) {
				var user *types.User
				if cookie, err := req.Cookie("hs_session"); err == nil && cookie.Value != "" {
					if session, err := h.state.DB().ValidateUserSession(cookie.Value); err == nil {
						user = &session.User
					}
				}
				if user == nil {
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}

				// 2 MB max
				req.Body = http.MaxBytesReader(w, req.Body, 2<<20)
				file, header, err := req.FormFile("avatar")
				if err != nil {
					http.Error(w, "Invalid file upload", http.StatusBadRequest)
					return
				}
				defer file.Close()

				// Read first 512 bytes to detect content type.
				buf := make([]byte, 512)
				n, err := file.Read(buf)
				if err != nil && err != io.EOF {
					http.Error(w, "Failed to read file", http.StatusBadRequest)
					return
				}
				contentType := http.DetectContentType(buf[:n])

				allowedTypes := map[string]string{
					"image/jpeg": ".jpg",
					"image/png":  ".png",
					"image/gif":  ".gif",
					"image/webp": ".webp",
				}
				ext, ok := allowedTypes[contentType]
				if !ok {
					http.Error(w, "File must be JPEG, PNG, GIF, or WebP", http.StatusBadRequest)
					return
				}

				// Ensure avatars directory exists next to the database.
				avatarDir := filepath.Join(filepath.Dir(h.cfg.Database.Sqlite.Path), "avatars")
				if err := os.MkdirAll(avatarDir, 0o750); err != nil {
					http.Error(w, "Failed to create avatar directory", http.StatusInternalServerError)
					return
				}

				// Save as {userID}{ext}
				filename := fmt.Sprintf("%d%s", user.ID, ext)
				destPath := filepath.Join(avatarDir, filename)

				// Remove old avatars for this user (different extension).
				for _, oldExt := range []string{".jpg", ".png", ".gif", ".webp"} {
					if oldExt != ext {
						os.Remove(filepath.Join(avatarDir, fmt.Sprintf("%d%s", user.ID, oldExt)))
					}
				}

				out, err := os.Create(destPath) //nolint:gosec
				if err != nil {
					http.Error(w, "Failed to save avatar", http.StatusInternalServerError)
					return
				}
				defer out.Close()

				// Write the already-read bytes, then copy the rest.
				if _, err := out.Write(buf[:n]); err != nil {
					http.Error(w, "Failed to save avatar", http.StatusInternalServerError)
					return
				}
				if _, err := io.Copy(out, file); err != nil {
					http.Error(w, "Failed to save avatar", http.StatusInternalServerError)
					return
				}

				_ = header // suppress unused warning

				// Build the avatar URL and update the user's profile.
				avatarURL := fmt.Sprintf("%s/api/v1/profile/avatar/%d%s", h.cfg.ServerURL, user.ID, ext)
				updated, err := h.state.DB().UpdateUserProfile(
					types.UserID(user.ID),
					user.DisplayName,
					avatarURL,
				)
				if err != nil {
					http.Error(w, "Failed to update profile", http.StatusInternalServerError)
					return
				}

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{"user": updated.Proto()}) //nolint:errcheck
			})
		})

		// Serve avatar images (public — Tailscale clients need to fetch these).
		r.Get("/v1/profile/avatar/{filename}", func(w http.ResponseWriter, req *http.Request) {
			filename := chi.URLParam(req, "filename")

			// Sanitize: only allow {digits}.{ext} patterns.
			if !isValidAvatarFilename(filename) {
				http.Error(w, "Not found", http.StatusNotFound)
				return
			}

			avatarDir := filepath.Join(filepath.Dir(h.cfg.Database.Sqlite.Path), "avatars")
			avatarPath := filepath.Join(avatarDir, filename)

			f, err := os.Open(avatarPath) //nolint:gosec
			if err != nil {
				http.Error(w, "Not found", http.StatusNotFound)
				return
			}
			defer f.Close()

			stat, err := f.Stat()
			if err != nil || stat.IsDir() {
				http.Error(w, "Not found", http.StatusNotFound)
				return
			}

			w.Header().Set("Cache-Control", "public, max-age=3600")
			http.ServeContent(w, req, stat.Name(), stat.ModTime(), f)
		})

		// Enriched nodes endpoint — returns the standard node list plus
		// client_version, os, and fqdn fields from Hostinfo.
		r.Get("/v1/web/nodes", func(w http.ResponseWriter, req *http.Request) {
			nodes := h.state.ListNodes()
			baseDomain := h.cfg.BaseDomain

			type enrichedNode struct {
				ID            uint64 `json:"id,omitempty"`
				ClientVersion string `json:"client_version,omitempty"`
				OS            string `json:"os,omitempty"`
				OSVersion     string `json:"os_version,omitempty"`
				FQDN          string `json:"fqdn,omitempty"`
			}

			result := make([]enrichedNode, 0, nodes.Len())
			for _, nv := range nodes.All() {
				en := enrichedNode{
					ID: uint64(nv.ID()),
				}
				if hi := nv.Hostinfo(); hi.Valid() {
					en.ClientVersion = hi.IPNVersion()
					en.OS = hi.OS()
					en.OSVersion = hi.OSVersion()
				}
				if fqdn, err := nv.GetFQDN(baseDomain); err == nil {
					en.FQDN = fqdn
				}
				result = append(result, en)
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"nodes": result}) //nolint:errcheck
		})

		// Discovered services endpoint — returns live endpoints from online nodes.
		// Each node reports its listening ports via Hostinfo.Services when
		// collect_services is enabled in the config.
		r.Get("/v1/web/services/discovered", func(w http.ResponseWriter, req *http.Request) {
			nodes := h.state.ListNodes()

			type discoveredEndpoint struct {
				ServiceName string `json:"service_name"`
				IP          string `json:"ip"`
				Port        uint16 `json:"port"`
				Proto       string `json:"proto"`
				Type        string `json:"type"`
				Machine     string `json:"machine"`
				User        string `json:"user"`
				NodeID      uint64 `json:"node_id"`
			}

			var endpoints []discoveredEndpoint

			for _, nv := range nodes.All() {
				// Only include online nodes — live monitoring.
				if !nv.IsOnline().Get() {
					continue
				}

				hi := nv.Hostinfo()
				if !hi.Valid() {
					continue
				}

				svcs := hi.Services()

				ips := nv.IPs()
				var ip string
				if len(ips) > 0 {
					ip = ips[0].String()
				}

				machine := nv.GivenName()
				user := nv.User().Name()

				for i := range svcs.Len() {
					svc := svcs.At(i)
					proto := string(svc.Proto)

					// Skip peerapi internal services.
					if svc.Proto == "peerapi4" || svc.Proto == "peerapi6" || svc.Proto == "peerapi-dns-proxy" {
						continue
					}

					svcType := classifyPort(svc.Port, proto)

					endpoints = append(endpoints, discoveredEndpoint{
						ServiceName: svc.Description,
						IP:          ip,
						Port:        svc.Port,
						Proto:       proto,
						Type:        svcType,
						Machine:     machine,
						User:        user,
						NodeID:      uint64(nv.ID()),
					})
				}
			}

			resp := map[string]any{
				"endpoints":        endpoints,
				"collect_services": h.cfg.CollectServices,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp) //nolint:errcheck
		})

		// Documentation tree endpoint — returns the list of markdown files.
		r.Get("/v1/web/docs/tree", func(w http.ResponseWriter, req *http.Request) {
			var entries []docEntry
			walkDir(docs.Content, ".", &entries)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"docs": entries}) //nolint:errcheck
		})

		// Documentation content endpoint — returns the raw markdown of one file.
		r.Get("/v1/web/docs/content", func(w http.ResponseWriter, req *http.Request) {
			docPath := req.URL.Query().Get("path")
			if docPath == "" {
				http.Error(w, "missing path parameter", http.StatusBadRequest)
				return
			}
			// Sanitise: prevent directory traversal.
			docPath = filepath.Clean(docPath)
			if strings.Contains(docPath, "..") {
				http.Error(w, "invalid path", http.StatusBadRequest)
				return
			}
			data, err := docs.Content.ReadFile(docPath)
			if err != nil {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Cache-Control", "public, max-age=3600")
			w.Write(data) //nolint:errcheck
		})

		// Server info endpoint — returns version, config basics for the admin UI.
		r.Get("/v1/server/info", func(w http.ResponseWriter, req *http.Request) {
			versionInfo := types.GetVersionInfo()
			info := map[string]any{
				"version":   versionInfo.Version,
				"commit":    versionInfo.Commit,
				"buildTime": versionInfo.BuildTime,
				"go": map[string]string{
					"version": versionInfo.Go.Version,
					"os":      versionInfo.Go.OS,
					"arch":    versionInfo.Go.Arch,
				},
				"dirty":              versionInfo.Dirty,
				"serverUrl":          h.cfg.ServerURL,
				"tailnetDisplayName": h.cfg.TailnetDisplayName,
				"baseDomain":         h.cfg.BaseDomain,
				"derpEnabled":        h.cfg.DERP.ServerEnabled,
				"databaseType":       h.cfg.Database.Type,
				"logLevel":           h.cfg.Log.Level.String(),
				"policyMode":         h.cfg.Policy.Mode,
				"collectServices":    h.cfg.CollectServices,
			}
			if h.cfg.PrefixV4 != nil {
				info["prefixV4"] = h.cfg.PrefixV4.String()
			}
			if h.cfg.PrefixV6 != nil {
				info["prefixV6"] = h.cfg.PrefixV6.String()
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(info) //nolint:errcheck
		})

		r.HandleFunc("/v1/*", h.webRoleAuthorizationHandler(grpcMux))
	})

	// Web UI SPA serving.
	if h.cfg.WebUI.Enabled {
		basePath := h.cfg.WebUI.BasePath
		if basePath == "" {
			basePath = "/admin"
		}

		r.Handle(basePath, h.webuiHandler())
		r.Handle(basePath+"/*", h.webuiHandler())
	}

	r.Get("/favicon.ico", FaviconHandler)

	if h.cfg.WebUI.Enabled {
		basePath := h.cfg.WebUI.BasePath
		if basePath == "" {
			basePath = "/admin"
		}

		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, basePath, http.StatusFound)
		})
	} else {
		r.Get("/", BlankHandler)
	}

	return r
}

// walkDir recursively walks an embed.FS and collects markdown file paths.
func walkDir(fsys embed.FS, dir string, out *[]docEntry) {
	entries, err := fsys.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		p := e.Name()
		if dir != "." {
			p = dir + "/" + e.Name()
		}
		if e.IsDir() {
			walkDir(fsys, p, out)
			continue
		}
		if !strings.HasSuffix(p, ".md") {
			continue
		}
		// Derive a title from the filename.
		name := strings.TrimSuffix(filepath.Base(p), ".md")
		title := strings.ReplaceAll(name, "-", " ")
		if len(title) > 0 {
			title = strings.ToUpper(title[:1]) + title[1:]
		}
		*out = append(*out, docEntry{Path: p, Title: title})
	}
}

// classifyPort maps well-known ports to human-readable service type names
// for the discovered services endpoint.
func classifyPort(port uint16, proto string) string {
	if proto == "udp" {
		switch port {
		case 53:
			return "DNS"
		case 443:
			return "QUIC"
		default:
			return "Other"
		}
	}
	switch port {
	case 22:
		return "SSH"
	case 80:
		return "HTTP"
	case 443:
		return "HTTPS"
	case 3389:
		return "RDP"
	case 5900:
		return "VNC"
	case 53:
		return "DNS"
	case 3306:
		return "MySQL"
	case 5432:
		return "PostgreSQL"
	case 6379:
		return "Redis"
	case 8080, 8443, 8888:
		return "HTTP"
	case 25, 587, 465:
		return "SMTP"
	case 143, 993:
		return "IMAP"
	case 110, 995:
		return "POP3"
	case 21:
		return "FTP"
	default:
		return "Other"
	}
}

// Serve launches the HTTP and gRPC server service Headscale and the API.
//
//nolint:gocyclo // complex server startup function
func (h *Headscale) Serve() error {
	var err error

	capver.CanOldCodeBeCleanedUp()

	if profilingEnabled {
		if profilingPath != "" {
			err = os.MkdirAll(profilingPath, os.ModePerm)
			if err != nil {
				log.Fatal().Err(err).Msg("failed to create profiling directory")
			}

			defer profile.Start(profile.ProfilePath(profilingPath)).Stop()
		} else {
			defer profile.Start().Stop()
		}
	}

	if dumpConfig {
		spew.Dump(h.cfg)
	}

	versionInfo := types.GetVersionInfo()
	log.Info().Str("version", versionInfo.Version).Str("commit", versionInfo.Commit).Msg("starting headscale")
	log.Info().
		Str("minimum_version", capver.TailscaleVersion(capver.MinSupportedCapabilityVersion)).
		Msg("Clients with a lower minimum version will be rejected")

	h.mapBatcher = mapper.NewBatcherAndMapper(h.cfg, h.state)

	h.mapBatcher.Start()
	defer h.mapBatcher.Close()

	if h.cfg.DERP.ServerEnabled {
		// When embedded DERP is enabled we always need a STUN server
		if h.cfg.DERP.STUNAddr == "" {
			return errSTUNAddressNotSet
		}

		go h.DERPServer.ServeSTUN()
	}

	derpMap, err := derp.GetDERPMap(h.cfg.DERP)
	if err != nil {
		return fmt.Errorf("getting DERPMap: %w", err)
	}

	if h.cfg.DERP.ServerEnabled && h.cfg.DERP.AutomaticallyAddEmbeddedDerpRegion {
		region, _ := h.DERPServer.GenerateRegion()
		derpMap.Regions[region.RegionID] = &region
	}

	if len(derpMap.Regions) == 0 {
		return errEmptyInitialDERPMap
	}

	h.state.SetDERPMap(derpMap)

	// Start ephemeral node garbage collector and schedule all nodes
	// that are already in the database and ephemeral. If they are still
	// around between restarts, they will reconnect and the GC will
	// be cancelled.
	go h.ephemeralGC.Start()

	ephmNodes := h.state.ListEphemeralNodes()
	for _, node := range ephmNodes.All() {
		h.ephemeralGC.Schedule(node.ID(), h.cfg.EphemeralNodeInactivityTimeout)
	}

	if h.cfg.DNSConfig.ExtraRecordsPath != "" {
		h.extraRecordMan, err = dns.NewExtraRecordsManager(h.cfg.DNSConfig.ExtraRecordsPath)
		if err != nil {
			return fmt.Errorf("setting up extrarecord manager: %w", err)
		}

		h.cfg.TailcfgDNSConfig.ExtraRecords = h.extraRecordMan.Records()

		go h.extraRecordMan.Run()
		defer h.extraRecordMan.Close()
	}

	// Start all scheduled tasks, e.g. expiring nodes, derp updates and
	// records updates
	scheduleCtx, scheduleCancel := context.WithCancel(context.Background())
	defer scheduleCancel()

	go h.scheduledTasks(scheduleCtx)

	if zl.GlobalLevel() == zl.TraceLevel {
		zerolog.RespLog = true
	} else {
		zerolog.RespLog = false
	}

	// Prepare group for running listeners
	errorGroup := new(errgroup.Group)

	ctx := context.Background()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	//
	//
	// Set up LOCAL listeners
	//

	err = h.ensureUnixSocketIsAbsent()
	if err != nil {
		return fmt.Errorf("removing old socket file: %w", err)
	}

	socketDir := filepath.Dir(h.cfg.UnixSocket)

	err = util.EnsureDir(socketDir)
	if err != nil {
		return fmt.Errorf("setting up unix socket: %w", err)
	}

	socketListener, err := new(net.ListenConfig).Listen(context.Background(), "unix", h.cfg.UnixSocket)
	if err != nil {
		return fmt.Errorf("setting up gRPC socket: %w", err)
	}

	// Change socket permissions
	if err := os.Chmod(h.cfg.UnixSocket, h.cfg.UnixSocketPermission); err != nil { //nolint:noinlineerr
		return fmt.Errorf("changing gRPC socket permission: %w", err)
	}

	grpcGatewayMux := grpcRuntime.NewServeMux()

	// Make the grpc-gateway connect to grpc over socket
	grpcGatewayConn, err := grpc.Dial( //nolint:staticcheck // SA1019: deprecated but supported in 1.x
		h.cfg.UnixSocket,
		[]grpc.DialOption{
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithContextDialer(util.GrpcSocketDialer),
		}...,
	)
	if err != nil {
		return fmt.Errorf("setting up gRPC gateway via socket: %w", err)
	}

	// Connect to the gRPC server over localhost to skip
	// the authentication.
	err = v1.RegisterHeadscaleServiceHandler(ctx, grpcGatewayMux, grpcGatewayConn)
	if err != nil {
		return fmt.Errorf("registering Headscale API service to gRPC: %w", err)
	}

	// Start the local gRPC server without TLS and without authentication
	grpcSocket := grpc.NewServer(
	// Uncomment to debug grpc communication.
	// zerolog.UnaryInterceptor(),
	)

	v1.RegisterHeadscaleServiceServer(grpcSocket, newHeadscaleV1APIServer(h))
	reflection.Register(grpcSocket)

	errorGroup.Go(func() error { return grpcSocket.Serve(socketListener) })

	//
	//
	// Set up REMOTE listeners
	//

	tlsConfig, err := h.getTLSSettings()
	if err != nil {
		return fmt.Errorf("configuring TLS settings: %w", err)
	}

	//
	//
	// gRPC setup
	//

	// We are sadly not able to run gRPC and HTTPS (2.0) on the same
	// port because the connection mux does not support matching them
	// since they are so similar. There is multiple issues open and we
	// can revisit this if changes:
	// https://github.com/soheilhy/cmux/issues/68
	// https://github.com/soheilhy/cmux/issues/91

	var (
		grpcServer   *grpc.Server
		grpcListener net.Listener
	)

	if tlsConfig != nil || h.cfg.GRPCAllowInsecure {
		log.Info().Msgf("enabling remote gRPC at %s", h.cfg.GRPCAddr)

		grpcOptions := []grpc.ServerOption{
			grpc.ChainUnaryInterceptor(
				h.grpcAuthenticationInterceptor,
				// Uncomment to debug grpc communication.
				// zerolog.NewUnaryServerInterceptor(),
			),
		}

		if tlsConfig != nil {
			grpcOptions = append(grpcOptions,
				grpc.Creds(credentials.NewTLS(tlsConfig)),
			)
		} else {
			log.Warn().Msg("gRPC is running without security")
		}

		grpcServer = grpc.NewServer(grpcOptions...)

		v1.RegisterHeadscaleServiceServer(grpcServer, newHeadscaleV1APIServer(h))
		reflection.Register(grpcServer)

		grpcListener, err = new(net.ListenConfig).Listen(context.Background(), "tcp", h.cfg.GRPCAddr)
		if err != nil {
			return fmt.Errorf("binding to TCP address: %w", err)
		}

		errorGroup.Go(func() error { return grpcServer.Serve(grpcListener) })

		log.Info().
			Msgf("listening and serving gRPC on: %s", h.cfg.GRPCAddr)
	}

	//
	//
	// HTTP setup
	//
	// This is the regular router that we expose
	// over our main Addr
	router := h.createRouter(grpcGatewayMux)

	httpServer := &http.Server{
		Addr:        h.cfg.Addr,
		Handler:     router,
		ReadTimeout: types.HTTPTimeout,

		// Long polling should not have any timeout, this is overridden
		// further down the chain
		WriteTimeout: types.HTTPTimeout,
	}

	var httpListener net.Listener

	if tlsConfig != nil {
		httpServer.TLSConfig = tlsConfig
		httpListener, err = tls.Listen("tcp", h.cfg.Addr, tlsConfig)
	} else {
		httpListener, err = new(net.ListenConfig).Listen(context.Background(), "tcp", h.cfg.Addr)
	}

	if err != nil {
		return fmt.Errorf("binding to TCP address: %w", err)
	}

	errorGroup.Go(func() error { return httpServer.Serve(httpListener) })

	log.Info().
		Msgf("listening and serving HTTP on: %s", h.cfg.Addr)

	// Only start debug/metrics server if address is configured
	var debugHTTPServer *http.Server

	var debugHTTPListener net.Listener

	if h.cfg.MetricsAddr != "" {
		debugHTTPListener, err = (&net.ListenConfig{}).Listen(ctx, "tcp", h.cfg.MetricsAddr)
		if err != nil {
			return fmt.Errorf("binding to TCP address: %w", err)
		}

		debugHTTPServer = h.debugHTTPServer()

		errorGroup.Go(func() error { return debugHTTPServer.Serve(debugHTTPListener) })

		log.Info().
			Msgf("listening and serving debug and metrics on: %s", h.cfg.MetricsAddr)
	} else {
		log.Info().Msg("metrics server disabled (metrics_listen_addr is empty)")
	}

	var tailsqlContext context.Context

	if tailsqlEnabled {
		if h.cfg.Database.Type != types.DatabaseSqlite {
			//nolint:gocritic // exitAfterDefer: Fatal exits during initialization before servers start
			log.Fatal().
				Str("type", h.cfg.Database.Type).
				Msgf("tailsql only support %q", types.DatabaseSqlite)
		}

		if tailsqlTSKey == "" {
			//nolint:gocritic // exitAfterDefer: Fatal exits during initialization before servers start
			log.Fatal().Msg("tailsql requires TS_AUTHKEY to be set")
		}

		tailsqlContext = context.Background()

		go runTailSQLService(ctx, util.TSLogfWrapper(), tailsqlStateDir, h.cfg.Database.Sqlite.Path) //nolint:errcheck
	}

	// Handle common process-killing signals so we can gracefully shut down:
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT,
		syscall.SIGHUP)

	sigFunc := func(c chan os.Signal) {
		// Wait for a SIGINT or SIGKILL:
		for {
			sig := <-c
			switch sig {
			case syscall.SIGHUP:
				log.Info().
					Str("signal", sig.String()).
					Msg("Received SIGHUP, reloading ACL policy")

				if h.cfg.Policy.IsEmpty() {
					continue
				}

				changes, err := h.state.ReloadPolicy()
				if err != nil {
					log.Error().Err(err).Msgf("reloading policy")
					continue
				}

				h.Change(changes...)

			default:
				info := func(msg string) { log.Info().Msg(msg) }

				log.Info().
					Str("signal", sig.String()).
					Msg("Received signal to stop, shutting down gracefully")

				scheduleCancel()
				h.ephemeralGC.Close()

				// Gracefully shut down servers
				shutdownCtx, cancel := context.WithTimeout(
					context.WithoutCancel(ctx),
					types.HTTPShutdownTimeout,
				)
				defer cancel()

				if debugHTTPServer != nil {
					info("shutting down debug http server")

					err := debugHTTPServer.Shutdown(shutdownCtx)
					if err != nil {
						log.Error().Err(err).Msg("failed to shutdown prometheus http")
					}
				}

				info("shutting down main http server")

				err := httpServer.Shutdown(shutdownCtx)
				if err != nil {
					log.Error().Err(err).Msg("failed to shutdown http")
				}

				info("closing batcher")
				h.mapBatcher.Close()

				info("waiting for netmap stream to close")
				h.clientStreamsOpen.Wait()

				info("shutting down grpc server (socket)")
				grpcSocket.GracefulStop()

				if grpcServer != nil {
					info("shutting down grpc server (external)")
					grpcServer.GracefulStop()
					grpcListener.Close()
				}

				if tailsqlContext != nil {
					info("shutting down tailsql")
					tailsqlContext.Done()
				}

				// Close network listeners
				info("closing network listeners")

				if debugHTTPListener != nil {
					debugHTTPListener.Close()
				}

				httpListener.Close()
				grpcGatewayConn.Close()

				// Stop listening (and unlink the socket if unix type):
				info("closing socket listener")
				socketListener.Close()

				// Close state connections
				info("closing state and database")

				err = h.state.Close()
				if err != nil {
					log.Error().Err(err).Msg("failed to close state")
				}

				log.Info().
					Msg("Headscale stopped")

				return
			}
		}
	}

	errorGroup.Go(func() error {
		sigFunc(sigc)

		return nil
	})

	return errorGroup.Wait()
}

func (h *Headscale) getTLSSettings() (*tls.Config, error) {
	var err error

	if h.cfg.TLS.LetsEncrypt.Hostname != "" {
		if !strings.HasPrefix(h.cfg.ServerURL, "https://") {
			log.Warn().
				Msg("Listening with TLS but ServerURL does not start with https://")
		}

		certManager := autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(h.cfg.TLS.LetsEncrypt.Hostname),
			Cache:      autocert.DirCache(h.cfg.TLS.LetsEncrypt.CacheDir),
			Client: &acme.Client{
				DirectoryURL: h.cfg.ACMEURL,
				HTTPClient: &http.Client{
					Transport: &acmeLogger{
						rt: http.DefaultTransport,
					},
				},
			},
			Email: h.cfg.ACMEEmail,
		}

		switch h.cfg.TLS.LetsEncrypt.ChallengeType {
		case types.TLSALPN01ChallengeType:
			// Configuration via autocert with TLS-ALPN-01 (https://tools.ietf.org/html/rfc8737)
			// The RFC requires that the validation is done on port 443; in other words, headscale
			// must be reachable on port 443.
			return certManager.TLSConfig(), nil

		case types.HTTP01ChallengeType:
			// Configuration via autocert with HTTP-01. This requires listening on
			// port 80 for the certificate validation in addition to the headscale
			// service, which can be configured to run on any other port.
			server := &http.Server{
				Addr:        h.cfg.TLS.LetsEncrypt.Listen,
				Handler:     certManager.HTTPHandler(http.HandlerFunc(h.redirect)),
				ReadTimeout: types.HTTPTimeout,
			}

			go func() {
				err := server.ListenAndServe()
				log.Fatal().
					Caller().
					Err(err).
					Msg("failed to set up a HTTP server")
			}()

			return certManager.TLSConfig(), nil

		default:
			return nil, errUnsupportedLetsEncryptChallengeType
		}
	} else if h.cfg.TLS.CertPath == "" {
		if !strings.HasPrefix(h.cfg.ServerURL, "http://") {
			log.Warn().Msg("listening without TLS but ServerURL does not start with http://")
		}

		return nil, err
	} else {
		if !strings.HasPrefix(h.cfg.ServerURL, "https://") {
			log.Warn().Msg("listening with TLS but ServerURL does not start with https://")
		}

		tlsConfig := &tls.Config{
			NextProtos:   []string{"http/1.1"},
			Certificates: make([]tls.Certificate, 1),
			MinVersion:   tls.VersionTLS12,
		}

		tlsConfig.Certificates[0], err = tls.LoadX509KeyPair(h.cfg.TLS.CertPath, h.cfg.TLS.KeyPath)

		return tlsConfig, err
	}
}

func readOrCreatePrivateKey(path string) (*key.MachinePrivate, error) {
	dir := filepath.Dir(path)

	err := util.EnsureDir(dir)
	if err != nil {
		return nil, fmt.Errorf("ensuring private key directory: %w", err)
	}

	privateKey, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		log.Info().Str("path", path).Msg("no private key file at path, creating...")

		machineKey := key.NewMachine()

		machineKeyStr, err := machineKey.MarshalText()
		if err != nil {
			return nil, fmt.Errorf(
				"converting private key to string for saving: %w",
				err,
			)
		}

		err = os.WriteFile(path, machineKeyStr, privateKeyFileMode)
		if err != nil {
			return nil, fmt.Errorf(
				"saving private key to disk at path %q: %w",
				path,
				err,
			)
		}

		return &machineKey, nil
	} else if err != nil {
		return nil, fmt.Errorf("reading private key file: %w", err)
	}

	trimmedPrivateKey := strings.TrimSpace(string(privateKey))

	var machineKey key.MachinePrivate
	if err = machineKey.UnmarshalText([]byte(trimmedPrivateKey)); err != nil { //nolint:noinlineerr
		return nil, fmt.Errorf("parsing private key: %w", err)
	}

	return &machineKey, nil
}

func readOrCreateSessionSecret(path string) (string, error) {
	dir := filepath.Dir(path)

	err := util.EnsureDir(dir)
	if err != nil {
		return "", fmt.Errorf("ensuring session secret directory: %w", err)
	}

	secretBytes, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		log.Info().Str("path", path).Msg("no session secret file at path, creating...")

		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return "", fmt.Errorf("generating random session secret: %w", err)
		}

		secret := hex.EncodeToString(raw)

		if err := os.WriteFile(path, []byte(secret), privateKeyFileMode); err != nil {
			return "", fmt.Errorf("saving session secret to disk at path %q: %w", path, err)
		}

		return secret, nil
	} else if err != nil {
		return "", fmt.Errorf("reading session secret file: %w", err)
	}

	return strings.TrimSpace(string(secretBytes)), nil
}

// Change is used to send changes to nodes.
// All change should be enqueued here and empty will be automatically
// ignored.
func (h *Headscale) Change(cs ...change.Change) {
	h.mapBatcher.AddWork(cs...)
}

// Provide some middleware that can inspect the ACME/autocert https calls
// and log when things are failing.
type acmeLogger struct {
	rt http.RoundTripper
}

// RoundTrip will log when ACME/autocert failures happen either when err != nil OR
// when http status codes indicate a failure has occurred.
func (l *acmeLogger) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := l.rt.RoundTrip(req)
	if err != nil {
		log.Error().Err(err).Str("url", req.URL.String()).Msg("acme request failed")
		return nil, err
	}

	if resp.StatusCode >= http.StatusBadRequest {
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		log.Error().Int("status_code", resp.StatusCode).Str("url", req.URL.String()).Bytes("body", body).Msg("acme request returned error")
	}

	return resp, nil
}

// zerologRequestLogger implements chi's middleware.LogFormatter
// to route HTTP request logs through zerolog.
type zerologRequestLogger struct{}

func (z *zerologRequestLogger) NewLogEntry(
	r *http.Request,
) middleware.LogEntry {
	return &zerologLogEntry{
		method: r.Method,
		path:   r.URL.Path,
		proto:  r.Proto,
		remote: r.RemoteAddr,
	}
}

type zerologLogEntry struct {
	method string
	path   string
	proto  string
	remote string
}

func (e *zerologLogEntry) Write(
	status, bytes int,
	header http.Header,
	elapsed time.Duration,
	extra any,
) {
	log.Debug().
		Str("method", e.method).
		Str("path", e.path).
		Str("proto", e.proto).
		Str("remote", e.remote).
		Int("status", status).
		Int("bytes", bytes).
		Dur("elapsed", elapsed).
		Msg("http request")
}

func (e *zerologLogEntry) Panic(
	v any,
	stack []byte,
) {
	log.Error().
		Interface("panic", v).
		Bytes("stack", stack).
		Msg("http handler panic")
}

// isValidAvatarFilename checks that the filename matches {digits}.{ext}.
func isValidAvatarFilename(name string) bool {
	dotIdx := strings.LastIndex(name, ".")
	if dotIdx <= 0 {
		return false
	}
	for _, c := range name[:dotIdx] {
		if c < '0' || c > '9' {
			return false
		}
	}
	ext := name[dotIdx:]
	return ext == ".jpg" || ext == ".png" || ext == ".gif" || ext == ".webp"
}
