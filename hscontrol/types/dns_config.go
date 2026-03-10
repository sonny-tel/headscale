package types

import (
	"gorm.io/gorm"
)

// RuntimeDNSConfig stores a DNS configuration override in the database.
// Only the latest row is used (same pattern as Policy).
type RuntimeDNSConfig struct {
	gorm.Model

	// Data contains the JSON-encoded DNSConfig override.
	Data string
}

// DNSConfigFromFile returns the original file-based DNS config stored at startup.
func DNSConfigFromFile(cfg *Config) DNSConfig {
	return cfg.FileDNSConfig
}
