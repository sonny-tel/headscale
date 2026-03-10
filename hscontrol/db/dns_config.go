package db

import (
	"errors"

	"github.com/juanfont/headscale/hscontrol/types"
	"gorm.io/gorm"
)

// SetRuntimeDNSConfig stores a DNS config override in the database.
func (hsdb *HSDatabase) SetRuntimeDNSConfig(data string) (*types.RuntimeDNSConfig, error) {
	cfg := types.RuntimeDNSConfig{
		Data: data,
	}

	if err := hsdb.DB.Create(&cfg).Error; err != nil {
		return nil, err
	}

	return &cfg, nil
}

// GetRuntimeDNSConfig returns the latest runtime DNS config override, or nil if none exists.
func (hsdb *HSDatabase) GetRuntimeDNSConfig() (*types.RuntimeDNSConfig, error) {
	var cfg types.RuntimeDNSConfig

	err := hsdb.DB.Order("id DESC").Limit(1).First(&cfg).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}

		return nil, err
	}

	return &cfg, nil
}

// DeleteRuntimeDNSConfig removes all runtime DNS config overrides (restore to defaults).
func (hsdb *HSDatabase) DeleteRuntimeDNSConfig() error {
	return hsdb.DB.Where("1 = 1").Delete(&types.RuntimeDNSConfig{}).Error
}
