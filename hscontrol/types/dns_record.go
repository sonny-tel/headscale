package types

import "time"

// DNSRecord represents a managed DNS record stored in the database.
// These records are merged into ExtraRecords in the DNS config sent to clients.
type DNSRecord struct {
	ID        uint64    `gorm:"primaryKey;autoIncrement" json:"id"`
	Name      string    `gorm:"not null" json:"name"`
	Type      string    `gorm:"not null;default:''" json:"type"`
	Value     string    `gorm:"not null" json:"value"`
	CreatedAt time.Time `gorm:"not null" json:"createdAt"`
	UpdatedAt time.Time `gorm:"not null" json:"updatedAt"`
}
