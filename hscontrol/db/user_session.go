package db

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"gorm.io/gorm"
)

var (
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionExpired  = errors.New("session expired")
)

const sessionTokenBytes = 32

// generateSessionToken creates a cryptographically random session token.
func generateSessionToken() (string, error) {
	b := make([]byte, sessionTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating session token: %w", err)
	}

	return hex.EncodeToString(b), nil
}

// CreateUserSession creates a new authenticated session for a user.
func (hsdb *HSDatabase) CreateUserSession(
	userID uint64,
	duration time.Duration,
	ipAddress string,
	userAgent string,
) (*types.UserSession, error) {
	return Write(hsdb.DB, func(tx *gorm.DB) (*types.UserSession, error) {
		return CreateUserSession(tx, userID, duration, ipAddress, userAgent)
	})
}

func CreateUserSession(
	tx *gorm.DB,
	userID uint64,
	duration time.Duration,
	ipAddress string,
	userAgent string,
) (*types.UserSession, error) {
	token, err := generateSessionToken()
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	session := types.UserSession{
		ID:        token,
		UserID:    userID,
		ExpiresAt: now.Add(duration),
		CreatedAt: now,
		IPAddress: ipAddress,
		UserAgent: userAgent,
	}

	if err := tx.Create(&session).Error; err != nil {
		return nil, fmt.Errorf("creating user session: %w", err)
	}

	return &session, nil
}

// ValidateUserSession looks up a session by token and verifies it has
// not expired. Returns the session with its User preloaded.
func (hsdb *HSDatabase) ValidateUserSession(token string) (*types.UserSession, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) (*types.UserSession, error) {
		return ValidateUserSession(rx, token)
	})
}

func ValidateUserSession(tx *gorm.DB, token string) (*types.UserSession, error) {
	var session types.UserSession
	if err := tx.Preload("User").First(&session, "id = ?", token).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrSessionNotFound
		}

		return nil, fmt.Errorf("validating user session: %w", err)
	}

	if time.Now().UTC().After(session.ExpiresAt) {
		return nil, ErrSessionExpired
	}

	return &session, nil
}

// DeleteUserSession removes a session (logout).
func (hsdb *HSDatabase) DeleteUserSession(token string) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return DeleteUserSession(tx, token)
	})
}

func DeleteUserSession(tx *gorm.DB, token string) error {
	result := tx.Delete(&types.UserSession{}, "id = ?", token)
	if result.Error != nil {
		return fmt.Errorf("deleting user session: %w", result.Error)
	}

	return nil
}

// DeleteExpiredUserSessions removes all expired sessions.
func (hsdb *HSDatabase) DeleteExpiredUserSessions() error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return tx.Delete(&types.UserSession{}, "expires_at < ?", time.Now().UTC()).Error
	})
}

// DeleteUserSessionsForUser removes all sessions for a given user (force logout).
func (hsdb *HSDatabase) DeleteUserSessionsForUser(userID uint64) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return tx.Delete(&types.UserSession{}, "user_id = ?", userID).Error
	})
}
