package db

import (
	"github.com/juanfont/headscale/hscontrol/types"
	"gorm.io/gorm"
)

// ListDNSRecords returns all managed DNS records.
func (hsdb *HSDatabase) ListDNSRecords() ([]types.DNSRecord, error) {
	var records []types.DNSRecord
	if err := hsdb.DB.Order("id ASC").Find(&records).Error; err != nil {
		return nil, err
	}
	return records, nil
}

// CreateDNSRecord inserts a new managed DNS record.
func (hsdb *HSDatabase) CreateDNSRecord(name, typ, value string) (*types.DNSRecord, error) {
	rec := types.DNSRecord{
		Name:  name,
		Type:  typ,
		Value: value,
	}
	if err := hsdb.DB.Create(&rec).Error; err != nil {
		return nil, err
	}
	return &rec, nil
}

// DeleteDNSRecord removes a DNS record by ID.
func (hsdb *HSDatabase) DeleteDNSRecord(id uint64) error {
	result := hsdb.DB.Delete(&types.DNSRecord{}, id)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}
