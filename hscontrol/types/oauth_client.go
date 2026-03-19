package types

import (
	"time"
)

// OAuthClient represents an OAuth2 client that can authenticate via
// client_credentials grant to obtain bearer tokens for the Tailscale-compatible
// v2 REST API. This enables the official Tailscale Kubernetes operator to
// use Headscale as its control server.
type OAuthClient struct {
	ID       uint64 `gorm:"primary_key"`
	ClientID string `gorm:"uniqueIndex"` // e.g. "hskey-oauth-{12chars}"
	Hash     []byte // bcrypt hash of client secret

	// Scopes controls which v2 API endpoints this client can access.
	// Valid scopes: "auth_keys", "devices:core", "services"
	Scopes []string `gorm:"serializer:json"`

	CreatedAt  *time.Time
	Expiration *time.Time
}

// TableName overrides GORM's default table name.
func (OAuthClient) TableName() string { return "oauth_clients" }

// IsExpired returns true if the client has an expiration date that has passed.
func (c *OAuthClient) IsExpired() bool {
	if c.Expiration == nil {
		return false
	}
	return c.Expiration.Before(time.Now())
}

// OAuthToken represents a bearer token issued via the OAuth2 token exchange.
// Tokens are short-lived (1 hour) and automatically refreshed by clients.
type OAuthToken struct {
	ID            uint64 `gorm:"primary_key"`
	OAuthClientID uint64
	OAuthClient   *OAuthClient `gorm:"constraint:OnDelete:CASCADE;"`
	Prefix        string       `gorm:"uniqueIndex"` // 12-char prefix for lookup
	Hash          []byte       // bcrypt hash of token secret

	Scopes    []string `gorm:"serializer:json"` // inherited from client
	ExpiresAt time.Time
	CreatedAt time.Time
}

// TableName overrides GORM's default table name.
func (OAuthToken) TableName() string { return "oauth_tokens" }

// IsExpired returns true if the token has expired.
func (t *OAuthToken) IsExpired() bool {
	return t.ExpiresAt.Before(time.Now())
}
