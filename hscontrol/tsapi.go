package hscontrol

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
)

// Tailscale v2 API compatible handlers for the Kubernetes operator.
// These implement the subset of the Tailscale REST API that the official
// K8s operator (tsClient interface) requires:
//   - POST   /api/v2/oauth/token                          (token exchange)
//   - POST   /api/v2/tailnet/{tailnet}/keys               (create auth key)
//   - GET    /api/v2/tailnet/{tailnet}/keys/{keyID}        (get key)
//   - DELETE /api/v2/tailnet/{tailnet}/keys/{keyID}        (delete key)
//   - GET    /api/v2/device/{deviceID}                     (get device)
//   - DELETE /api/v2/device/{deviceID}                     (delete device)
//   - GET    /api/v2/tailnet/{tailnet}/devices             (list devices)
//   - GET    /api/v2/tailnet/{tailnet}/vip-services/{name} (get VIP service)
//   - GET    /api/v2/tailnet/{tailnet}/vip-services        (list VIP services)
//   - PUT    /api/v2/tailnet/{tailnet}/vip-services/{name} (create/update VIP service)
//   - DELETE /api/v2/tailnet/{tailnet}/vip-services/{name} (delete VIP service)

// tsAPIError writes a JSON error response matching Tailscale's format.
func tsAPIError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	//nolint:errcheck
	json.NewEncoder(w).Encode(map[string]string{"message": msg})
}

// tsAPIJSON writes a JSON response.
func tsAPIJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	//nolint:errcheck
	json.NewEncoder(w).Encode(v)
}

// oauthScopesFromContext retrieves OAuth scopes from request context.
// Returns nil if no OAuth scopes are present (e.g., API key auth).
func oauthScopesFromContext(r *http.Request) []string {
	scopes, _ := r.Context().Value(oauthScopesKey).([]string)
	return scopes
}

// hasScope checks if the request has a specific OAuth scope.
// Returns true if: (1) no scopes in context (API key auth, full access), or
// (2) the requested scope is present.
func hasScope(r *http.Request, scope string) bool {
	scopes := oauthScopesFromContext(r)
	if scopes == nil {
		return true // API key auth has full access
	}
	return slices.Contains(scopes, scope)
}

// --- OAuth Token Exchange ---

// tsOAuthTokenHandler handles POST /api/v2/oauth/token
// Implements the OAuth2 client_credentials grant type.
// This endpoint is UNAUTHENTICATED (uses Basic auth with client credentials).
func (h *Headscale) tsOAuthTokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		tsAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		// Also try form-encoded body (standard OAuth2).
		if err := r.ParseForm(); err != nil {
			tsAPIError(w, http.StatusBadRequest, "invalid request")
			return
		}
		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
	}

	grantType := r.FormValue("grant_type")
	if grantType == "" {
		// Try parsing form if not already parsed.
		if err := r.ParseForm(); err == nil {
			grantType = r.FormValue("grant_type")
		}
	}

	if grantType != "client_credentials" {
		tsAPIError(w, http.StatusBadRequest, "unsupported grant_type")
		return
	}

	if clientID == "" || clientSecret == "" {
		tsAPIError(w, http.StatusUnauthorized, "missing client credentials")
		return
	}

	client, err := h.state.ValidateOAuthClientCredentials(clientID, clientSecret)
	if err != nil {
		log.Info().Err(err).Str("client_id", clientID).Msg("OAuth token exchange failed")
		tsAPIError(w, http.StatusUnauthorized, "invalid client credentials")
		return
	}

	tokenStr, err := h.state.CreateOAuthToken(client)
	if err != nil {
		log.Error().Err(err).Msg("failed to create OAuth token")
		tsAPIError(w, http.StatusInternalServerError, "failed to create token")
		return
	}

	tsAPIJSON(w, http.StatusOK, map[string]any{
		"access_token": tokenStr,
		"token_type":   "Bearer",
		"expires_in":   3600,
	})
}

// --- Auth Keys (maps to PreAuthKeys) ---

// tsKeyCapabilities matches Tailscale's KeyCapabilities JSON format.
type tsKeyCapabilities struct {
	Devices tsKeyDeviceCapabilities `json:"devices,omitempty"`
}

type tsKeyDeviceCapabilities struct {
	Create tsKeyDeviceCreateCapabilities `json:"create"`
}

type tsKeyDeviceCreateCapabilities struct {
	Reusable      bool     `json:"reusable"`
	Ephemeral     bool     `json:"ephemeral"`
	Preauthorized bool     `json:"preauthorized"`
	Tags          []string `json:"tags,omitempty"`
}

// tsKeyResponse matches Tailscale's key creation response.
type tsKeyResponse struct {
	ID           string            `json:"id"`
	Key          string            `json:"key,omitempty"` // Only on creation
	Created      time.Time         `json:"created"`
	Expires      time.Time         `json:"expires"`
	Capabilities tsKeyCapabilities `json:"capabilities"`
}

// tsCreateKeyRequest matches Tailscale's key creation request body.
type tsCreateKeyRequest struct {
	Capabilities  tsKeyCapabilities `json:"capabilities"`
	ExpirySeconds int64             `json:"expirySeconds,omitempty"`
}

// tsCreateKeyHandler handles POST /api/v2/tailnet/{tailnet}/keys
func (h *Headscale) tsCreateKeyHandler(w http.ResponseWriter, r *http.Request) {
	if !hasScope(r, "auth_keys") {
		tsAPIError(w, http.StatusForbidden, "insufficient scope: auth_keys required")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		tsAPIError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	var req tsCreateKeyRequest
	if err := json.Unmarshal(body, &req); err != nil {
		tsAPIError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	caps := req.Capabilities.Devices.Create

	var expiration *time.Time
	if req.ExpirySeconds > 0 {
		exp := time.Now().Add(time.Duration(req.ExpirySeconds) * time.Second)
		expiration = &exp
	} else {
		// Default 90-day expiration matching Tailscale behavior.
		exp := time.Now().Add(90 * 24 * time.Hour)
		expiration = &exp
	}

	// The K8s operator always creates tagged keys with preauthorized=true.
	// Tags are required for tagged keys; no user parameter needed.
	pak, err := h.state.CreatePreAuthKey(
		nil, // No user — tagged keys use tags-as-identity
		caps.Reusable,
		caps.Ephemeral,
		expiration,
		caps.Tags,
	)
	if err != nil {
		log.Error().Err(err).Msg("failed to create pre-auth key via v2 API")
		tsAPIError(w, http.StatusInternalServerError, fmt.Sprintf("failed to create key: %s", err))
		return
	}

	resp := tsKeyResponse{
		ID:      strconv.FormatUint(pak.ID, 10),
		Key:     pak.Key,
		Created: *pak.CreatedAt,
		Expires: *pak.Expiration,
		Capabilities: tsKeyCapabilities{
			Devices: tsKeyDeviceCapabilities{
				Create: tsKeyDeviceCreateCapabilities{
					Reusable:      pak.Reusable,
					Ephemeral:     pak.Ephemeral,
					Preauthorized: true,
					Tags:          pak.Tags,
				},
			},
		},
	}

	tsAPIJSON(w, http.StatusOK, resp)
}

// tsGetKeyHandler handles GET /api/v2/tailnet/{tailnet}/keys/{keyID}
func (h *Headscale) tsGetKeyHandler(w http.ResponseWriter, r *http.Request) {
	if !hasScope(r, "auth_keys") {
		tsAPIError(w, http.StatusForbidden, "insufficient scope: auth_keys required")
		return
	}

	keyID := chi.URLParam(r, "keyID")

	id, err := strconv.ParseUint(keyID, 10, 64)
	if err != nil {
		tsAPIError(w, http.StatusBadRequest, "invalid key ID")
		return
	}

	keys, err := h.state.ListPreAuthKeys()
	if err != nil {
		tsAPIError(w, http.StatusInternalServerError, "failed to list keys")
		return
	}

	for _, k := range keys {
		if k.ID == id {
			resp := tsKeyResponse{
				ID: strconv.FormatUint(k.ID, 10),
				// Key secret is never returned after creation.
				Capabilities: tsKeyCapabilities{
					Devices: tsKeyDeviceCapabilities{
						Create: tsKeyDeviceCreateCapabilities{
							Reusable:      k.Reusable,
							Ephemeral:     k.Ephemeral,
							Preauthorized: true,
							Tags:          k.Tags,
						},
					},
				},
			}
			if k.CreatedAt != nil {
				resp.Created = *k.CreatedAt
			}
			if k.Expiration != nil {
				resp.Expires = *k.Expiration
			}

			tsAPIJSON(w, http.StatusOK, resp)
			return
		}
	}

	tsAPIError(w, http.StatusNotFound, "key not found")
}

// tsDeleteKeyHandler handles DELETE /api/v2/tailnet/{tailnet}/keys/{keyID}
func (h *Headscale) tsDeleteKeyHandler(w http.ResponseWriter, r *http.Request) {
	if !hasScope(r, "auth_keys") {
		tsAPIError(w, http.StatusForbidden, "insufficient scope: auth_keys required")
		return
	}

	keyID := chi.URLParam(r, "keyID")

	id, err := strconv.ParseUint(keyID, 10, 64)
	if err != nil {
		tsAPIError(w, http.StatusBadRequest, "invalid key ID")
		return
	}

	if err := h.state.DeletePreAuthKey(id); err != nil {
		tsAPIError(w, http.StatusInternalServerError, "failed to delete key")
		return
	}

	w.WriteHeader(http.StatusOK)
}

// --- Devices (maps to Nodes) ---

// tsDevice represents a Tailscale device in the v2 API format.
type tsDevice struct {
	Addresses                 []string `json:"addresses"`
	DeviceID                  string   `json:"id"`
	NodeID                    string   `json:"nodeId"`
	User                      string   `json:"user"`
	Name                      string   `json:"name"`
	Hostname                  string   `json:"hostname"`
	ClientVersion             string   `json:"clientVersion"`
	OS                        string   `json:"os"`
	Tags                      []string `json:"tags"`
	Created                   string   `json:"created"`
	LastSeen                  string   `json:"lastSeen"`
	KeyExpiryDisabled         bool     `json:"keyExpiryDisabled"`
	Expires                   string   `json:"expires"`
	Authorized                bool     `json:"authorized"`
	IsExternal                bool     `json:"isExternal"`
	MachineKey                string   `json:"machineKey"`
	NodeKey                   string   `json:"nodeKey"`
	BlocksIncomingConnections bool     `json:"blocksIncomingConnections"`
	EnabledRoutes             []string `json:"enabledRoutes"`
	AdvertisedRoutes          []string `json:"advertisedRoutes"`
}

// nodeToTSDevice converts a Headscale NodeView to a Tailscale v2 API Device.
func nodeToTSDevice(n types.NodeView) tsDevice {
	addrs := make([]string, 0, 2)
	for _, ip := range n.IPs() {
		addrs = append(addrs, ip.String())
	}

	var username string
	if n.User().Valid() {
		username = n.User().Name()
	}

	var tags []string
	if n.IsTagged() {
		tags = n.Tags().AsSlice()
	}
	if tags == nil {
		tags = []string{}
	}

	var clientVersion, osStr string
	hi := n.Hostinfo()
	if hi.Valid() {
		clientVersion = hi.IPNVersion()
		osStr = hi.OS()
	}

	var created, lastSeen, expires string
	if !n.CreatedAt().IsZero() {
		created = n.CreatedAt().UTC().Format(time.RFC3339)
	}
	if n.LastSeen().Valid() {
		lastSeen = n.LastSeen().Get().UTC().Format(time.RFC3339)
	}
	if n.Expiry().Valid() {
		expires = n.Expiry().Get().UTC().Format(time.RFC3339)
	}

	keyExpiryDisabled := !n.Expiry().Valid()

	enabledRoutes := make([]string, 0)
	for _, r := range n.AllApprovedRoutes() {
		enabledRoutes = append(enabledRoutes, r.String())
	}

	advertisedRoutes := make([]string, 0)
	for _, r := range n.AnnouncedRoutes() {
		advertisedRoutes = append(advertisedRoutes, r.String())
	}

	idStr := strconv.FormatUint(uint64(n.ID()), 10)

	return tsDevice{
		Addresses:         addrs,
		DeviceID:          idStr,
		NodeID:            idStr,
		User:              username,
		Name:              n.GivenName(),
		Hostname:          n.Hostname(),
		ClientVersion:     clientVersion,
		OS:                osStr,
		Tags:              tags,
		Created:           created,
		LastSeen:          lastSeen,
		KeyExpiryDisabled: keyExpiryDisabled,
		Expires:           expires,
		Authorized:        true,
		MachineKey:        n.MachineKey().String(),
		NodeKey:           n.NodeKey().String(),
		EnabledRoutes:     enabledRoutes,
		AdvertisedRoutes:  advertisedRoutes,
	}
}

// tsGetDeviceHandler handles GET /api/v2/device/{deviceID}
func (h *Headscale) tsGetDeviceHandler(w http.ResponseWriter, r *http.Request) {
	if !hasScope(r, "devices:core") {
		tsAPIError(w, http.StatusForbidden, "insufficient scope: devices:core required")
		return
	}

	deviceID := chi.URLParam(r, "deviceID")

	id, err := strconv.ParseUint(deviceID, 10, 64)
	if err != nil {
		tsAPIError(w, http.StatusNotFound, "device not found")
		return
	}

	node, ok := h.state.GetNodeByID(types.NodeID(id))
	if !ok {
		tsAPIError(w, http.StatusNotFound, "device not found")
		return
	}

	tsAPIJSON(w, http.StatusOK, nodeToTSDevice(node))
}

// tsDeleteDeviceHandler handles DELETE /api/v2/device/{deviceID}
func (h *Headscale) tsDeleteDeviceHandler(w http.ResponseWriter, r *http.Request) {
	if !hasScope(r, "devices:core") {
		tsAPIError(w, http.StatusForbidden, "insufficient scope: devices:core required")
		return
	}

	deviceID := chi.URLParam(r, "deviceID")

	id, err := strconv.ParseUint(deviceID, 10, 64)
	if err != nil {
		tsAPIError(w, http.StatusNotFound, "device not found")
		return
	}

	node, ok := h.state.GetNodeByID(types.NodeID(id))
	if !ok {
		tsAPIError(w, http.StatusNotFound, "device not found")
		return
	}

	if _, err := h.state.DeleteNode(node); err != nil {
		log.Error().Err(err).Uint64("node_id", id).Msg("failed to delete node via v2 API")
		tsAPIError(w, http.StatusInternalServerError, "failed to delete device")
		return
	}

	w.WriteHeader(http.StatusOK)
}

// tsListDevicesHandler handles GET /api/v2/tailnet/{tailnet}/devices
func (h *Headscale) tsListDevicesHandler(w http.ResponseWriter, r *http.Request) {
	if !hasScope(r, "devices:core") {
		tsAPIError(w, http.StatusForbidden, "insufficient scope: devices:core required")
		return
	}

	nodes := h.state.ListNodes()
	devices := make([]tsDevice, 0, nodes.Len())
	for i := range nodes.Len() {
		devices = append(devices, nodeToTSDevice(nodes.At(i)))
	}

	tsAPIJSON(w, http.StatusOK, map[string]any{"devices": devices})
}

// --- VIP Services ---

// tsGetVIPServiceHandler handles GET /api/v2/tailnet/{tailnet}/vip-services/{name}
func (h *Headscale) tsGetVIPServiceHandler(w http.ResponseWriter, r *http.Request) {
	if !hasScope(r, "services") {
		tsAPIError(w, http.StatusForbidden, "insufficient scope: services required")
		return
	}

	name := chi.URLParam(r, "name")

	svc, err := h.state.DB().GetVIPService(name)
	if err != nil {
		tsAPIError(w, http.StatusNotFound, "VIP service not found")
		return
	}

	tsAPIJSON(w, http.StatusOK, svc)
}

// tsListVIPServicesHandler handles GET /api/v2/tailnet/{tailnet}/vip-services
func (h *Headscale) tsListVIPServicesHandler(w http.ResponseWriter, r *http.Request) {
	if !hasScope(r, "services") {
		tsAPIError(w, http.StatusForbidden, "insufficient scope: services required")
		return
	}

	svcs, err := h.state.DB().ListVIPServices()
	if err != nil {
		log.Error().Err(err).Msg("failed to list VIP services")
		tsAPIError(w, http.StatusInternalServerError, "failed to list VIP services")
		return
	}

	tsAPIJSON(w, http.StatusOK, types.VIPServiceList{VIPServices: svcs})
}

// tsCreateOrUpdateVIPServiceHandler handles PUT /api/v2/tailnet/{tailnet}/vip-services/{name}
func (h *Headscale) tsCreateOrUpdateVIPServiceHandler(w http.ResponseWriter, r *http.Request) {
	if !hasScope(r, "services") {
		tsAPIError(w, http.StatusForbidden, "insufficient scope: services required")
		return
	}

	name := chi.URLParam(r, "name")

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		tsAPIError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	var svc types.VIPService
	if err := json.Unmarshal(body, &svc); err != nil {
		tsAPIError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	svc.Name = name

	// Ensure nil slices/maps are initialized to empty so GORM doesn't insert NULLs.
	if svc.Addrs == nil {
		svc.Addrs = []string{}
	}
	if svc.Annotations == nil {
		svc.Annotations = map[string]string{}
	}
	if svc.Ports == nil {
		svc.Ports = []string{}
	}
	if svc.Tags == nil {
		svc.Tags = []string{}
	}

	if err := h.state.DB().CreateOrUpdateVIPService(&svc); err != nil {
		log.Error().Err(err).Str("name", name).Msg("failed to create/update VIP service")
		tsAPIError(w, http.StatusInternalServerError, "failed to create/update VIP service")
		return
	}

	tsAPIJSON(w, http.StatusOK, svc)
}

// tsDeleteVIPServiceHandler handles DELETE /api/v2/tailnet/{tailnet}/vip-services/{name}
func (h *Headscale) tsDeleteVIPServiceHandler(w http.ResponseWriter, r *http.Request) {
	if !hasScope(r, "services") {
		tsAPIError(w, http.StatusForbidden, "insufficient scope: services required")
		return
	}

	name := chi.URLParam(r, "name")

	if err := h.state.DB().DeleteVIPService(name); err != nil {
		tsAPIError(w, http.StatusNotFound, "VIP service not found")
		return
	}

	w.WriteHeader(http.StatusOK)
}

// --- OAuth Client Management (admin endpoints) ---

type oauthClientResponse struct {
	ID         uint64   `json:"id"`
	ClientID   string   `json:"client_id"`
	Scopes     []string `json:"scopes"`
	CreatedAt  string   `json:"created_at,omitempty"`
	Expiration string   `json:"expiration,omitempty"`
}

type oauthCreateClientRequest struct {
	Scopes     []string `json:"scopes"`
	Expiration string   `json:"expiration,omitempty"` // RFC3339 or duration like "90d"
}

type oauthCreateClientResponse struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"` // Only shown once
	Scopes       []string `json:"scopes"`
	Expiration   string   `json:"expiration,omitempty"`
}

// oauthListClientsHandler handles GET /api/v1/oauth/clients
func (h *Headscale) oauthListClientsHandler(w http.ResponseWriter, r *http.Request) {
	clients, err := h.state.ListOAuthClients()
	if err != nil {
		tsAPIError(w, http.StatusInternalServerError, "failed to list OAuth clients")
		return
	}

	resp := make([]oauthClientResponse, 0, len(clients))
	for _, c := range clients {
		cr := oauthClientResponse{
			ID:       c.ID,
			ClientID: c.ClientID,
			Scopes:   c.Scopes,
		}
		if c.CreatedAt != nil {
			cr.CreatedAt = c.CreatedAt.UTC().Format(time.RFC3339)
		}
		if c.Expiration != nil {
			cr.Expiration = c.Expiration.UTC().Format(time.RFC3339)
		}
		resp = append(resp, cr)
	}

	tsAPIJSON(w, http.StatusOK, map[string]any{"clients": resp})
}

// oauthCreateClientHandler handles POST /api/v1/oauth/clients
func (h *Headscale) oauthCreateClientHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		tsAPIError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	var req oauthCreateClientRequest
	if err := json.Unmarshal(body, &req); err != nil {
		tsAPIError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if len(req.Scopes) == 0 {
		tsAPIError(w, http.StatusBadRequest, "scopes are required")
		return
	}

	var expiration *time.Time
	if req.Expiration != "" {
		t, err := time.Parse(time.RFC3339, req.Expiration)
		if err != nil {
			tsAPIError(w, http.StatusBadRequest, "invalid expiration format, use RFC3339")
			return
		}
		expiration = &t
	}

	clientID, clientSecret, _, err := h.state.CreateOAuthClient(req.Scopes, expiration)
	if err != nil {
		log.Error().Err(err).Msg("failed to create OAuth client")
		tsAPIError(w, http.StatusInternalServerError, fmt.Sprintf("failed to create OAuth client: %s", err))
		return
	}

	resp := oauthCreateClientResponse{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       req.Scopes,
	}
	if expiration != nil {
		resp.Expiration = expiration.UTC().Format(time.RFC3339)
	}

	tsAPIJSON(w, http.StatusCreated, resp)
}

// oauthDeleteClientHandler handles DELETE /api/v1/oauth/clients/{id}
func (h *Headscale) oauthDeleteClientHandler(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")

	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		tsAPIError(w, http.StatusBadRequest, "invalid client ID")
		return
	}

	if err := h.state.DeleteOAuthClient(id); err != nil {
		tsAPIError(w, http.StatusInternalServerError, "failed to delete OAuth client")
		return
	}

	w.WriteHeader(http.StatusOK)
}
