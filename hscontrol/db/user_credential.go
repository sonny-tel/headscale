package db

import (
	"errors"
	"fmt"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"gorm.io/gorm"
)

var (
	ErrCredentialNotFound = errors.New("user credential not found")
	ErrCredentialExists   = errors.New("user credential already exists")
)

// GetUserCredential returns the credential record for a user, if one exists.
func (hsdb *HSDatabase) GetUserCredential(userID uint64) (*types.UserCredential, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) (*types.UserCredential, error) {
		return GetUserCredential(rx, userID)
	})
}

func GetUserCredential(tx *gorm.DB, userID uint64) (*types.UserCredential, error) {
	var cred types.UserCredential
	if err := tx.Preload("User").First(&cred, "user_id = ?", userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrCredentialNotFound
		}

		return nil, fmt.Errorf("getting user credential: %w", err)
	}

	return &cred, nil
}

// GetUserCredentialByGitHubID returns the credential linked to a GitHub account.
func (hsdb *HSDatabase) GetUserCredentialByGitHubID(githubID string) (*types.UserCredential, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) (*types.UserCredential, error) {
		return GetUserCredentialByGitHubID(rx, githubID)
	})
}

func GetUserCredentialByGitHubID(tx *gorm.DB, githubID string) (*types.UserCredential, error) {
	var cred types.UserCredential
	if err := tx.Preload("User").First(&cred, "git_hub_id = ?", githubID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrCredentialNotFound
		}

		return nil, fmt.Errorf("getting credential by github id: %w", err)
	}

	return &cred, nil
}

// CreateUserCredential creates a credential record for a user.
func (hsdb *HSDatabase) CreateUserCredential(cred types.UserCredential) (*types.UserCredential, error) {
	return Write(hsdb.DB, func(tx *gorm.DB) (*types.UserCredential, error) {
		return CreateUserCredential(tx, cred)
	})
}

func CreateUserCredential(tx *gorm.DB, cred types.UserCredential) (*types.UserCredential, error) {
	now := time.Now().UTC()
	cred.CreatedAt = now
	cred.UpdatedAt = now

	if err := tx.Create(&cred).Error; err != nil {
		return nil, fmt.Errorf("creating user credential: %w", err)
	}

	return &cred, nil
}

// UpdateUserCredential saves changes to an existing credential.
func (hsdb *HSDatabase) UpdateUserCredential(cred *types.UserCredential) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return UpdateUserCredential(tx, cred)
	})
}

func UpdateUserCredential(tx *gorm.DB, cred *types.UserCredential) error {
	cred.UpdatedAt = time.Now().UTC()

	if err := tx.Save(cred).Error; err != nil {
		return fmt.Errorf("updating user credential: %w", err)
	}

	return nil
}

// DeleteUserCredential removes a user's credential record.
func (hsdb *HSDatabase) DeleteUserCredential(userID uint64) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return DeleteUserCredential(tx, userID)
	})
}

func DeleteUserCredential(tx *gorm.DB, userID uint64) error {
	result := tx.Delete(&types.UserCredential{}, "user_id = ?", userID)
	if result.Error != nil {
		return fmt.Errorf("deleting user credential: %w", result.Error)
	}

	return nil
}

// RecordFailedLogin increments the failed login counter and optionally
// locks the account until the given time.
func (hsdb *HSDatabase) RecordFailedLogin(
	userID uint64,
	lockUntil *time.Time,
) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return tx.Model(&types.UserCredential{}).
			Where("user_id = ?", userID).
			Updates(map[string]any{
				"failed_login_attempts": gorm.Expr("failed_login_attempts + 1"),
				"locked_until":          lockUntil,
				"updated_at":            time.Now().UTC(),
			}).Error
	})
}

// ResetFailedLogins clears the failed login counter and lockout.
func (hsdb *HSDatabase) ResetFailedLogins(userID uint64) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return tx.Model(&types.UserCredential{}).
			Where("user_id = ?", userID).
			Updates(map[string]any{
				"failed_login_attempts": 0,
				"locked_until":          nil,
				"updated_at":            time.Now().UTC(),
			}).Error
	})
}

// SetUserRole updates a user's role.
func (hsdb *HSDatabase) SetUserRole(userID uint64, role string) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return tx.Model(&types.User{}).
			Where("id = ?", userID).
			Update("role", role).Error
	})
}
