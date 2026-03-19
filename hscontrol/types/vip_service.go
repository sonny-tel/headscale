package types

// VIPService represents a Tailscale VIP Service (virtual IP service).
// These are used by the Kubernetes operator for service mesh functionality.
type VIPService struct {
	ID          uint64            `gorm:"primary_key" json:"-"`
	Name        string            `gorm:"uniqueIndex" json:"name,omitempty"`
	Addrs       []string          `gorm:"serializer:json" json:"addrs,omitempty"`
	Comment     string            `json:"comment,omitempty"`
	Annotations map[string]string `gorm:"serializer:json" json:"annotations,omitempty"`
	Ports       []string          `gorm:"serializer:json" json:"ports,omitempty"`
	Tags        []string          `gorm:"serializer:json" json:"tags,omitempty"`
}

// TableName overrides GORM's default table name.
func (VIPService) TableName() string { return "vip_services" }

// VIPServiceList is the JSON response format for listing VIP services.
type VIPServiceList struct {
	VIPServices []VIPService `json:"vipServices"`
}
