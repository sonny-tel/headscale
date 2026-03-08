package mullvad

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/juanfont/headscale/hscontrol/provider"
	"go4.org/mem"
	"tailscale.com/types/key"
)

const (
	// Official Mullvad App API (https://api.mullvad.net/app/documentation/).
	apiBase       = "https://api.mullvad.net/app"
	authBase      = "https://api.mullvad.net/auth"
	relayListURL  = apiBase + "/v1/relays"
	wgKeysURL     = apiBase + "/v1/wireguard-keys"
	replaceKeyURL = apiBase + "/v1/replace-wireguard-key"
	accountURL    = apiBase + "/v1/me"
	authTokenURL  = authBase + "/v1/token"

	httpTimeout = 30 * time.Second

	// Refresh the access token 5 minutes before expiry.
	tokenRefreshMargin = 5 * time.Minute
)

// Client wraps the Mullvad REST API.
type Client struct {
	http *http.Client

	// Access token cache, keyed by account number.
	mu     sync.Mutex
	tokens map[string]cachedToken
}

type cachedToken struct {
	accessToken string
	expiry      time.Time
}

// NewClient creates a Mullvad API client with sensible defaults.
func NewClient() *Client {
	return &Client{
		http:   &http.Client{Timeout: httpTimeout},
		tokens: make(map[string]cachedToken),
	}
}

// getAccessToken exchanges an account number for a Bearer access token,
// caching the result until near expiry.
func (c *Client) getAccessToken(ctx context.Context, accountNumber string) (string, error) {
	c.mu.Lock()
	if tok, ok := c.tokens[accountNumber]; ok && time.Now().Before(tok.expiry.Add(-tokenRefreshMargin)) {
		c.mu.Unlock()

		return tok.accessToken, nil
	}
	c.mu.Unlock()

	payload, err := json.Marshal(map[string]string{
		"account_number": accountNumber,
	})
	if err != nil {
		return "", fmt.Errorf("marshaling auth request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, authTokenURL, bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("creating auth token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("requesting auth token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))

		return "", fmt.Errorf("auth token API returned %d: %s", resp.StatusCode, string(body))
	}

	var authResp apiAuthTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return "", fmt.Errorf("decoding auth token response: %w", err)
	}

	c.mu.Lock()
	c.tokens[accountNumber] = cachedToken{
		accessToken: authResp.AccessToken,
		expiry:      authResp.Expiry,
	}
	c.mu.Unlock()

	return authResp.AccessToken, nil
}

// setBearerAuth sets the Authorization header using a Bearer access token
// obtained by exchanging the account number.
func (c *Client) setBearerAuth(ctx context.Context, req *http.Request, accountNumber string) error {
	token, err := c.getAccessToken(ctx, accountNumber)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+token)

	return nil
}

// resolvedRelay is a WireGuard relay with denormalized location data, ready
// for conversion to a provider.Relay.
type resolvedRelay struct {
	Hostname    string
	Active      bool
	CountryCode string
	Country     string
	CityCode    string
	City        string
	Latitude    float64
	Longitude   float64
	IPv4AddrIn  string
	IPv6AddrIn  string
	PublicKey   string
}

// FetchRelays returns the list of WireGuard relay servers from Mullvad.
// Uses the official App API GET /v1/relays endpoint.
func (c *Client) FetchRelays(ctx context.Context) ([]resolvedRelay, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, relayListURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating relay list request: %w", err)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching relay list: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))

		return nil, fmt.Errorf("relay list API returned %d: %s", resp.StatusCode, string(body))
	}

	var apiResp apiRelayResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("decoding relay list: %w", err)
	}

	relays := make([]resolvedRelay, 0, len(apiResp.WireGuard.Relays))

	for _, r := range apiResp.WireGuard.Relays {
		loc := apiResp.Locations[r.Location]

		// Parse country_code and city_code from the location key.
		// Format is typically "se-got" → country=se, city=got.
		countryCode, cityCode := parseLocationKey(r.Location)

		relays = append(relays, resolvedRelay{
			Hostname:    r.Hostname,
			Active:      r.Active,
			CountryCode: countryCode,
			Country:     loc.Country,
			CityCode:    cityCode,
			City:        loc.City,
			Latitude:    loc.Latitude,
			Longitude:   loc.Longitude,
			IPv4AddrIn:  r.IPv4AddrIn,
			IPv6AddrIn:  r.IPv6AddrIn,
			PublicKey:   r.PublicKey,
		})
	}

	return relays, nil
}

// parseLocationKey splits a Mullvad location key like "se-got" into
// country code ("se") and city code ("got").
func parseLocationKey(loc string) (countryCode, cityCode string) {
	if idx := strings.IndexByte(loc, '-'); idx >= 0 {
		return loc[:idx], loc[idx+1:]
	}

	return loc, ""
}

// RegisterKey registers a WireGuard public key with a Mullvad account.
// Uses POST /v1/wireguard-keys with JSON body and Bearer auth.
// Returns the assigned internal IPs from the API response.
func (c *Client) RegisterKey(ctx context.Context, accountID string, pubkey key.NodePublic) (*apiWGKeyResponse, error) {
	raw := pubkey.Raw32()
	payload := map[string]string{
		"pubkey": base64.StdEncoding.EncodeToString(raw[:]),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshaling register key request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, wgKeysURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating register key request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	if err := c.setBearerAuth(ctx, req, accountID); err != nil {
		return nil, fmt.Errorf("authenticating register key request: %w", err)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("registering key: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))

		return nil, fmt.Errorf("register key API returned %d: %s", resp.StatusCode, string(respBody))
	}

	var keyResp apiWGKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&keyResp); err != nil {
		return nil, fmt.Errorf("decoding register key response: %w", err)
	}

	return &keyResp, nil
}

// ReplaceKey atomically replaces an old WireGuard key with a new one on a Mullvad account.
// Uses POST /v1/replace-wireguard-key with JSON body and Bearer auth.
// Returns the assigned IPs for the new key.
func (c *Client) ReplaceKey(ctx context.Context, accountID string, oldKey, newKey key.NodePublic) (*apiWGKeyResponse, error) {
	oldRaw := oldKey.Raw32()
	newRaw := newKey.Raw32()
	payload := map[string]string{
		"old": base64.StdEncoding.EncodeToString(oldRaw[:]),
		"new": base64.StdEncoding.EncodeToString(newRaw[:]),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshaling replace key request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, replaceKeyURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating replace key request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	if err := c.setBearerAuth(ctx, req, accountID); err != nil {
		return nil, fmt.Errorf("authenticating replace key request: %w", err)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("replacing key: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))

		return nil, fmt.Errorf("replace key API returned %d: %s", resp.StatusCode, string(respBody))
	}

	var keyResp apiWGKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&keyResp); err != nil {
		return nil, fmt.Errorf("decoding replace key response: %w", err)
	}

	return &keyResp, nil
}

// GetKey retrieves information about a registered WireGuard key from a Mullvad account.
// Uses GET /v1/wireguard-keys/{pubkey} with Bearer auth.
// Returns ErrKeyNotFound if the key is not registered (404).
func (c *Client) GetKey(ctx context.Context, accountID string, pubkey key.NodePublic) (*apiWGKeyResponse, error) {
	raw := pubkey.Raw32()
	b64Key := base64.StdEncoding.EncodeToString(raw[:])
	keyURL := wgKeysURL + "/" + url.PathEscape(b64Key)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, keyURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating get key request: %w", err)
	}

	if err := c.setBearerAuth(ctx, req, accountID); err != nil {
		return nil, fmt.Errorf("authenticating get key request: %w", err)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("getting key: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, provider.ErrKeyNotFound
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))

		return nil, fmt.Errorf("get key API returned %d: %s", resp.StatusCode, string(body))
	}

	var keyResp apiWGKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&keyResp); err != nil {
		return nil, fmt.Errorf("decoding get key response: %w", err)
	}

	return &keyResp, nil
}

// DeregisterKey removes a WireGuard public key from a Mullvad account.
// Uses DELETE /v1/wireguard-keys/{pubkey} with Bearer auth.
func (c *Client) DeregisterKey(ctx context.Context, accountID string, pubkey key.NodePublic) error {
	raw := pubkey.Raw32()
	b64Key := base64.StdEncoding.EncodeToString(raw[:])
	keyURL := wgKeysURL + "/" + url.PathEscape(b64Key)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, keyURL, nil)
	if err != nil {
		return fmt.Errorf("creating deregister key request: %w", err)
	}

	if err := c.setBearerAuth(ctx, req, accountID); err != nil {
		return fmt.Errorf("authenticating deregister key request: %w", err)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("deregistering key: %w", err)
	}
	defer resp.Body.Close()

	// 204 = success, 404 = key already gone (treat as success for idempotent cleanup).
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))

		return fmt.Errorf("deregister key API returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// GetAccountInfo returns account information from Mullvad.
// Uses GET /v1/me with Bearer auth.
func (c *Client) GetAccountInfo(ctx context.Context, accountID string) (*apiAccountResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, accountURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating account info request: %w", err)
	}

	if err := c.setBearerAuth(ctx, req, accountID); err != nil {
		return nil, fmt.Errorf("authenticating account info request: %w", err)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching account info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))

		return nil, fmt.Errorf("account info API returned %d: %s", resp.StatusCode, string(body))
	}

	var account apiAccountResponse
	if err := json.NewDecoder(resp.Body).Decode(&account); err != nil {
		return nil, fmt.Errorf("decoding account info: %w", err)
	}

	return &account, nil
}

// parseWGPubKey decodes a base64 WireGuard public key into key.NodePublic.
func parseWGPubKey(b64 string) (key.NodePublic, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return key.NodePublic{}, fmt.Errorf("decoding base64 key: %w", err)
	}

	if len(raw) != 32 {
		return key.NodePublic{}, fmt.Errorf("invalid key length: %d", len(raw))
	}

	return key.NodePublicFromRaw32(mem.B(raw)), nil
}

// toRelay converts a resolvedRelay to parsed network addresses and a WG key.
// Returns false if the relay should be skipped.
func toRelay(r resolvedRelay) (netip.Addr, netip.Addr, key.NodePublic, bool) {
	ipv4, _ := netip.ParseAddr(r.IPv4AddrIn)
	ipv6, _ := netip.ParseAddr(r.IPv6AddrIn)

	wgKey, err := parseWGPubKey(r.PublicKey)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, key.NodePublic{}, false
	}

	return ipv4, ipv6, wgKey, true
}
