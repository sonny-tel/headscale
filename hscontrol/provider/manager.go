package provider

import (
	"context"
	"fmt"
	"sync"

	"github.com/rs/zerolog/log"
	"tailscale.com/types/key"
)

// Manager coordinates VPN providers, relay caching, and key allocation.
type Manager struct {
	mu        sync.Mutex
	providers map[string]Provider
	cache     *RelayCache
}

// NewManager creates a provider Manager with an empty relay cache.
func NewManager(baseDomain string) *Manager {
	return &Manager{
		providers: make(map[string]Provider),
		cache:     NewRelayCache(baseDomain),
	}
}

// RegisterProvider instantiates and registers a provider by name.
func (m *Manager) RegisterProvider(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.providers[name]; ok {
		return nil // already registered
	}

	p, err := Get(name)
	if err != nil {
		return fmt.Errorf("registering provider: %w", err)
	}

	m.providers[name] = p
	log.Info().Str("provider", name).Msg("registered VPN provider")

	return nil
}

// SyncRelays fetches the relay list from the named provider and updates the cache.
func (m *Manager) SyncRelays(ctx context.Context, providerName string) error {
	m.mu.Lock()
	p, ok := m.providers[providerName]
	m.mu.Unlock()

	if !ok {
		return fmt.Errorf("provider not registered: %q", providerName)
	}

	relays, err := p.FetchRelays(ctx)
	if err != nil {
		return fmt.Errorf("fetching relays from %s: %w", providerName, err)
	}

	m.cache.Refresh(providerName, relays)

	log.Info().
		Str("provider", providerName).
		Int("relays", len(relays)).
		Msg("synced provider relays")

	return nil
}

// Cache returns the relay cache.
func (m *Manager) Cache() *RelayCache {
	return m.cache
}

// Provider returns the named provider, if registered.
func (m *Manager) Provider(name string) (Provider, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	p, ok := m.providers[name]

	return p, ok
}

// RegisterKey registers a node's WireGuard key with the given provider account.
func (m *Manager) RegisterKey(ctx context.Context, providerName, accountID string, pubkey key.NodePublic) (*RegistrationResult, error) {
	m.mu.Lock()
	p, ok := m.providers[providerName]
	m.mu.Unlock()

	if !ok {
		return nil, fmt.Errorf("provider not registered: %q", providerName)
	}

	return p.RegisterKey(ctx, accountID, pubkey)
}

// DeregisterKey removes a node's WireGuard key from the given provider account.
func (m *Manager) DeregisterKey(ctx context.Context, providerName, accountID string, pubkey key.NodePublic) error {
	m.mu.Lock()
	p, ok := m.providers[providerName]
	m.mu.Unlock()

	if !ok {
		return fmt.Errorf("provider not registered: %q", providerName)
	}

	return p.DeregisterKey(ctx, accountID, pubkey)
}
