package db

import (
	"fmt"

	"github.com/juanfont/headscale/hscontrol/types"
)

// CreateOrUpdateVIPService creates or updates a VIP service by name.
func (hsdb *HSDatabase) CreateOrUpdateVIPService(svc *types.VIPService) error {
	var existing types.VIPService
	err := hsdb.DB.Where("name = ?", svc.Name).First(&existing).Error
	if err == nil {
		// Update existing.
		existing.Addrs = svc.Addrs
		existing.Comment = svc.Comment
		existing.Annotations = svc.Annotations
		existing.Ports = svc.Ports
		existing.Tags = svc.Tags
		return hsdb.DB.Save(&existing).Error
	}

	return hsdb.DB.Create(svc).Error
}

// GetVIPService returns a VIP service by name.
func (hsdb *HSDatabase) GetVIPService(name string) (*types.VIPService, error) {
	var svc types.VIPService
	if err := hsdb.DB.Where("name = ?", name).First(&svc).Error; err != nil {
		return nil, fmt.Errorf("VIP service not found: %w", err)
	}
	return &svc, nil
}

// ListVIPServices returns all VIP services.
func (hsdb *HSDatabase) ListVIPServices() ([]types.VIPService, error) {
	var services []types.VIPService
	if err := hsdb.DB.Find(&services).Error; err != nil {
		return nil, err
	}
	return services, nil
}

// DeleteVIPService removes a VIP service by name.
func (hsdb *HSDatabase) DeleteVIPService(name string) error {
	result := hsdb.DB.Where("name = ?", name).Delete(&types.VIPService{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("VIP service %q not found", name)
	}
	return nil
}
