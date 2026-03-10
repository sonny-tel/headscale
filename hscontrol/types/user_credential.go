package types

import "time"

// UserCredential stores local authentication data for a User.
// This is an optional 1:0..1 relationship — users who authenticate
// only via OIDC or who are service accounts will not have a credential
// record. Only users with a credential can perform password-based
// web authentication.
type UserCredential struct {
	UserID uint64 `gorm:"primaryKey"`
	User   User   `gorm:"constraint:OnDelete:CASCADE;"`

	PasswordHash string
	OTPSecret    string
	OTPEnabled   bool `gorm:"not null;default:false"`

	// GitHub OAuth linkage (optional).
	GitHubID    string `gorm:"uniqueIndex:idx_user_credentials_github_id,where:git_hub_id != ''"`
	GitHubLogin string

	// Account lockout fields.
	FailedLoginAttempts int `gorm:"not null;default:0"`
	LockedUntil         *time.Time

	CreatedAt time.Time
	UpdatedAt time.Time
}

// UserSession represents an authenticated web UI session.
// Only non-service-account users with valid credentials or OIDC
// provider linkage can hold sessions.
type UserSession struct {
	ID        string    `gorm:"primaryKey"` // crypto/rand token.
	UserID    uint64    `gorm:"not null"`
	User      User      `gorm:"constraint:OnDelete:CASCADE;"`
	ExpiresAt time.Time `gorm:"not null"`
	CreatedAt time.Time
	IPAddress string
	UserAgent string
}
