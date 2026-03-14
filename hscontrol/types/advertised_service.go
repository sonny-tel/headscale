package types

import "time"

// AdvertisedService is a user-defined service endpoint advertised on
// a node. Unlike auto-discovered services (via CollectServices /
// HostInfo.Services), these are manually created through the web UI
// or API and persisted in the database.
type AdvertisedService struct {
	ID     uint64 `gorm:"primary_key" json:"id"`
	NodeID uint64 `gorm:"not null;index" json:"node_id"`
	Name   string `gorm:"not null" json:"name"`
	Proto  string `gorm:"not null;default:'tcp'" json:"proto"`
	Port   uint16 `gorm:"not null" json:"port"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (AdvertisedService) TableName() string {
	return "advertised_services"
}
