package mullvad

import (
	"context"
	"net/netip"

	"github.com/juanfont/headscale/hscontrol/provider"
	"tailscale.com/types/key"
)

const (
	providerName   = "mullvad"
	maxKeysPerAcct = 5
)

func init() {
	provider.Register(providerName, func() provider.Provider {
		return New()
	})
}

// Provider implements the provider.Provider interface for Mullvad VPN.
type Provider struct {
	client *Client
}

// New creates a Mullvad provider with a default API client.
func New() *Provider {
	return &Provider{client: NewClient()}
}

func (p *Provider) Name() string { return providerName }

func (p *Provider) MaxKeysPerAccount() int { return maxKeysPerAcct }

func (p *Provider) FetchRelays(ctx context.Context) ([]provider.Relay, error) {
	resolved, err := p.client.FetchRelays(ctx)
	if err != nil {
		return nil, err
	}

	relays := make([]provider.Relay, 0, len(resolved))

	for _, r := range resolved {
		ipv4, ipv6, wgKey, ok := toRelay(r)
		if !ok {
			continue
		}

		relays = append(relays, provider.Relay{
			Hostname:     r.Hostname,
			ProviderName: providerName,
			CountryCode:  r.CountryCode,
			Country:      r.Country,
			CityCode:     r.CityCode,
			City:         r.City,
			Latitude:     r.Latitude,
			Longitude:    r.Longitude,
			IPv4:         ipv4,
			IPv6:         ipv6,
			WGPubKey:     wgKey,
			Active:       r.Active,
		})
	}

	return relays, nil
}

func (p *Provider) RegisterKey(ctx context.Context, accountID string, pubkey key.NodePublic) (*provider.RegistrationResult, error) {
	keyResp, err := p.client.RegisterKey(ctx, accountID, pubkey)
	if err != nil {
		return nil, err
	}

	return parseKeyResponse(keyResp), nil
}

func (p *Provider) DeregisterKey(ctx context.Context, accountID string, pubkey key.NodePublic) error {
	return p.client.DeregisterKey(ctx, accountID, pubkey)
}

func (p *Provider) GetKey(ctx context.Context, accountID string, pubkey key.NodePublic) (*provider.RegistrationResult, error) {
	keyResp, err := p.client.GetKey(ctx, accountID, pubkey)
	if err != nil {
		return nil, err
	}

	return parseKeyResponse(keyResp), nil
}

func (p *Provider) ReplaceKey(ctx context.Context, accountID string, oldKey, newKey key.NodePublic) (*provider.RegistrationResult, error) {
	keyResp, err := p.client.ReplaceKey(ctx, accountID, oldKey, newKey)
	if err != nil {
		return nil, err
	}

	return parseKeyResponse(keyResp), nil
}

// parseKeyResponse converts a Mullvad API key response to a provider RegistrationResult.
func parseKeyResponse(keyResp *apiWGKeyResponse) *provider.RegistrationResult {
	var result provider.RegistrationResult

	if keyResp.IPv4Address != "" {
		if prefix, err := netip.ParsePrefix(keyResp.IPv4Address); err == nil {
			result.IPv4 = prefix.Addr()
		}
	}

	if keyResp.IPv6Address != "" {
		if prefix, err := netip.ParsePrefix(keyResp.IPv6Address); err == nil {
			result.IPv6 = prefix.Addr()
		}
	}

	return &result
}

func (p *Provider) AccountInfo(ctx context.Context, accountID string) (*provider.AccountInfo, error) {
	acct, err := p.client.GetAccountInfo(ctx, accountID)
	if err != nil {
		return nil, err
	}

	return &provider.AccountInfo{
		AccountID:  acct.Token,
		ExpiresAt:  acct.Expires,
		ActiveKeys: 0, // Mullvad API doesn't directly report this; tracked in our DB
		MaxKeys:    maxKeysPerAcct,
		Valid:      true,
	}, nil
}
