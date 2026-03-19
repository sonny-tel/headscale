package db

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"golang.org/x/crypto/bcrypt"
)

const (
	oauthClientPrefix = "hskey-oauth-"
	oauthTokenPrefix  = "hskey-oat-" //nolint:gosec // Prefix, not a credential
	oauthPrefixLength = 12
	oauthSecretLength = 64
	oauthTokenTTL     = 1 * time.Hour
)

var (
	ErrOAuthClientNotFound = errors.New("OAuth client not found")
	ErrOAuthTokenNotFound  = errors.New("OAuth token not found")
	ErrOAuthTokenExpired   = errors.New("OAuth token expired")
	ErrOAuthClientExpired  = errors.New("OAuth client expired")
	ErrOAuthInvalidGrant   = errors.New("invalid grant_type")
	ErrOAuthInvalidScope   = errors.New("invalid scope")
)

// ValidOAuthScopes are the scopes supported by the v2 API.
var ValidOAuthScopes = []string{"auth_keys", "devices:core", "services"}

// CreateOAuthClient creates a new OAuth client with the given scopes.
// Returns the full client_id, client_secret (shown once), and the stored client.
func (hsdb *HSDatabase) CreateOAuthClient(
	scopes []string,
	expiration *time.Time,
) (string, string, *types.OAuthClient, error) {
	// Validate scopes.
	for _, s := range scopes {
		valid := false
		for _, vs := range ValidOAuthScopes {
			if s == vs {
				valid = true
				break
			}
		}
		if !valid {
			return "", "", nil, fmt.Errorf("%w: %q", ErrOAuthInvalidScope, s)
		}
	}

	prefix, err := util.GenerateRandomStringURLSafe(oauthPrefixLength)
	if err != nil {
		return "", "", nil, fmt.Errorf("generating client ID prefix: %w", err)
	}

	secret, err := util.GenerateRandomStringURLSafe(oauthSecretLength)
	if err != nil {
		return "", "", nil, fmt.Errorf("generating client secret: %w", err)
	}

	clientID := oauthClientPrefix + prefix
	clientSecret := secret

	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return "", "", nil, fmt.Errorf("hashing client secret: %w", err)
	}

	client := types.OAuthClient{
		ClientID:   clientID,
		Hash:       hash,
		Scopes:     scopes,
		Expiration: expiration,
	}

	if err := hsdb.DB.Create(&client).Error; err != nil {
		return "", "", nil, fmt.Errorf("saving OAuth client: %w", err)
	}

	return clientID, clientSecret, &client, nil
}

// ValidateOAuthClientCredentials validates a client_id and client_secret pair.
// Returns the client if valid, or an error.
func (hsdb *HSDatabase) ValidateOAuthClientCredentials(clientID, clientSecret string) (*types.OAuthClient, error) {
	var client types.OAuthClient
	if err := hsdb.DB.First(&client, "client_id = ?", clientID).Error; err != nil {
		return nil, ErrOAuthClientNotFound
	}

	if client.IsExpired() {
		return nil, ErrOAuthClientExpired
	}

	if err := bcrypt.CompareHashAndPassword(client.Hash, []byte(clientSecret)); err != nil {
		return nil, ErrOAuthClientNotFound
	}

	return &client, nil
}

// ListOAuthClients returns all OAuth clients (without secrets).
func (hsdb *HSDatabase) ListOAuthClients() ([]types.OAuthClient, error) {
	var clients []types.OAuthClient
	if err := hsdb.DB.Find(&clients).Error; err != nil {
		return nil, err
	}
	return clients, nil
}

// DeleteOAuthClient removes an OAuth client and its associated tokens (via CASCADE).
func (hsdb *HSDatabase) DeleteOAuthClient(id uint64) error {
	// Delete associated tokens first for databases that don't support CASCADE.
	if err := hsdb.DB.Where("o_auth_client_id = ?", id).Delete(&types.OAuthToken{}).Error; err != nil {
		return fmt.Errorf("deleting OAuth tokens: %w", err)
	}
	if result := hsdb.DB.Unscoped().Delete(&types.OAuthClient{}, id); result.Error != nil {
		return result.Error
	}
	return nil
}

// CreateOAuthToken creates a new bearer token for the given OAuth client.
// Returns the full token string (shown once to the client).
func (hsdb *HSDatabase) CreateOAuthToken(client *types.OAuthClient) (string, error) {
	prefix, err := util.GenerateRandomStringDNSSafe(oauthPrefixLength)
	if err != nil {
		return "", fmt.Errorf("generating token prefix: %w", err)
	}

	secret, err := util.GenerateRandomStringURLSafe(oauthSecretLength)
	if err != nil {
		return "", fmt.Errorf("generating token secret: %w", err)
	}

	tokenStr := oauthTokenPrefix + prefix + "-" + secret

	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hashing token: %w", err)
	}

	now := time.Now()
	token := types.OAuthToken{
		OAuthClientID: client.ID,
		Prefix:        prefix,
		Hash:          hash,
		Scopes:        client.Scopes,
		ExpiresAt:     now.Add(oauthTokenTTL),
		CreatedAt:     now,
	}

	if err := hsdb.DB.Create(&token).Error; err != nil {
		return "", fmt.Errorf("saving OAuth token: %w", err)
	}

	return tokenStr, nil
}

// ValidateOAuthToken validates a bearer token string.
// Returns the token (with scopes) if valid.
func (hsdb *HSDatabase) ValidateOAuthToken(tokenStr string) (*types.OAuthToken, error) {
	// Parse token format: hskey-oat-{prefix}-{secret}
	// Prefix is always exactly oauthPrefixLength chars, followed by a dash, then the secret.
	// We use fixed-length slicing because the prefix/secret may contain dashes (base64url).
	remainder, found := strings.CutPrefix(tokenStr, oauthTokenPrefix)
	if !found {
		return nil, ErrOAuthTokenNotFound
	}

	// Minimum length: prefix + dash + secret
	expectedLen := oauthPrefixLength + 1 + oauthSecretLength
	if len(remainder) < expectedLen {
		return nil, ErrOAuthTokenNotFound
	}

	if remainder[oauthPrefixLength] != '-' {
		return nil, ErrOAuthTokenNotFound
	}

	prefix := remainder[:oauthPrefixLength]
	secret := remainder[oauthPrefixLength+1:]

	if len(secret) != oauthSecretLength {
		return nil, ErrOAuthTokenNotFound
	}

	var token types.OAuthToken
	if err := hsdb.DB.First(&token, "prefix = ?", prefix).Error; err != nil {
		return nil, ErrOAuthTokenNotFound
	}

	if err := bcrypt.CompareHashAndPassword(token.Hash, []byte(secret)); err != nil {
		return nil, ErrOAuthTokenNotFound
	}

	if token.IsExpired() {
		return nil, ErrOAuthTokenExpired
	}

	return &token, nil
}

// CleanupExpiredOAuthTokens removes all expired OAuth tokens.
func (hsdb *HSDatabase) CleanupExpiredOAuthTokens() error {
	return hsdb.DB.Where("expires_at < ?", time.Now()).Delete(&types.OAuthToken{}).Error
}
