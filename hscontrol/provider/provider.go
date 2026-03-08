package provider

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"tailscale.com/types/key"
)

// ErrKeyNotFound is returned when a key is not registered with the provider.
var ErrKeyNotFound = errors.New("key not found on provider")

// RegistrationResult holds the addresses assigned by the provider when a key is registered.
type RegistrationResult struct {
	IPv4 netip.Addr // provider-assigned internal IPv4 (e.g. 10.139.55.16)
	IPv6 netip.Addr // provider-assigned internal IPv6
}

// Provider defines the interface that VPN provider implementations must satisfy.
type Provider interface {
	// Name returns the provider identifier (e.g., "mullvad").
	Name() string

	// FetchRelays returns the full list of relay servers from the provider API.
	FetchRelays(ctx context.Context) ([]Relay, error)

	// RegisterKey registers a WireGuard public key with the provider account.
	// Returns the provider-assigned internal IPs for the key.
	RegisterKey(ctx context.Context, accountID string, pubkey key.NodePublic) (*RegistrationResult, error)

	// DeregisterKey removes a WireGuard public key registration from the provider account.
	DeregisterKey(ctx context.Context, accountID string, pubkey key.NodePublic) error

	// GetKey retrieves information about a registered WireGuard key from the provider.
	// Returns ErrKeyNotFound if the key is not registered.
	GetKey(ctx context.Context, accountID string, pubkey key.NodePublic) (*RegistrationResult, error)

	// ReplaceKey atomically replaces an old key with a new key on the provider.
	// Returns the provider-assigned IPs for the new key.
	ReplaceKey(ctx context.Context, accountID string, oldKey, newKey key.NodePublic) (*RegistrationResult, error)

	// AccountInfo returns the current status of a provider account.
	AccountInfo(ctx context.Context, accountID string) (*AccountInfo, error)

	// MaxKeysPerAccount returns the maximum number of WireGuard keys allowed per account.
	MaxKeysPerAccount() int
}

// Relay represents a single VPN provider relay server.
type Relay struct {
	Hostname     string
	ProviderName string
	CountryCode  string
	Country      string
	CityCode     string
	City         string
	Latitude     float64
	Longitude    float64
	IPv4         netip.Addr
	IPv6         netip.Addr
	WGPubKey     key.NodePublic
	// Multihop port is used by some providers for chaining relays.
	MultihopPort uint16
	Active       bool
}

// AccountInfo holds the status of a provider account.
type AccountInfo struct {
	AccountID  string
	ExpiresAt  time.Time
	ActiveKeys int
	MaxKeys    int
	Valid      bool
}
