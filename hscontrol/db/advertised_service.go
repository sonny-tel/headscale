package db

import (
	"fmt"

	"github.com/juanfont/headscale/hscontrol/types"
)

// ListAdvertisedServices returns all advertised services, optionally
// filtered by node ID when nodeID > 0.
func (hsdb *HSDatabase) ListAdvertisedServices(nodeID uint64) ([]types.AdvertisedService, error) {
	var services []types.AdvertisedService
	q := hsdb.DB.Model(&types.AdvertisedService{})
	if nodeID > 0 {
		q = q.Where("node_id = ?", nodeID)
	}
	if err := q.Order("id ASC").Find(&services).Error; err != nil {
		return nil, fmt.Errorf("listing advertised services: %w", err)
	}
	return services, nil
}

// CreateAdvertisedService inserts a new advertised service.
func (hsdb *HSDatabase) CreateAdvertisedService(svc *types.AdvertisedService) error {
	if err := hsdb.DB.Create(svc).Error; err != nil {
		return fmt.Errorf("creating advertised service: %w", err)
	}
	return nil
}

// UpdateAdvertisedService updates an existing advertised service by ID.
func (hsdb *HSDatabase) UpdateAdvertisedService(svc *types.AdvertisedService) error {
	result := hsdb.DB.Model(svc).Updates(map[string]any{
		"name":  svc.Name,
		"proto": svc.Proto,
		"port":  svc.Port,
	})
	if result.Error != nil {
		return fmt.Errorf("updating advertised service: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("advertised service %d not found", svc.ID)
	}
	return nil
}

// DeleteAdvertisedService removes an advertised service by ID.
func (hsdb *HSDatabase) DeleteAdvertisedService(id uint64) error {
	result := hsdb.DB.Delete(&types.AdvertisedService{}, id)
	if result.Error != nil {
		return fmt.Errorf("deleting advertised service: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("advertised service %d not found", id)
	}
	return nil
}
