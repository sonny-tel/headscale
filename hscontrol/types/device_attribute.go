package types

import "time"

// DeviceAttribute stores a device posture attribute reported by a node
// via the Tailscale control protocol (PATCH /machine/set-device-attr).
// Attributes are key-value pairs where the value is stored as a JSON string.
type DeviceAttribute struct {
	ID        uint64    `gorm:"primaryKey" json:"id"`
	NodeID    uint64    `gorm:"not null;uniqueIndex:idx_device_attr_node_key" json:"node_id"`
	AttrKey   string    `gorm:"not null;uniqueIndex:idx_device_attr_node_key" json:"attr_key"`
	AttrValue string    `gorm:"not null" json:"attr_value"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (DeviceAttribute) TableName() string {
	return "device_attributes"
}
