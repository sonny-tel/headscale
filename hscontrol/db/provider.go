package db

import (
	"fmt"
	"time"

	"gorm.io/gorm"
)

// VPNProviderAccount stores credentials for a VPN provider account.
type VPNProviderAccount struct {
	ID           uint   `gorm:"primaryKey"`
	ProviderName string `gorm:"not null"`
	AccountID    string `gorm:"not null"`
	MaxKeys      int    `gorm:"not null;default:5"`
	ExpiresAt    *time.Time
	Enabled      bool `gorm:"not null;default:true"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

func (VPNProviderAccount) TableName() string { return "vpn_provider_accounts" }

// VPNKeyAllocation tracks a WireGuard key registered with a provider account for a node.
type VPNKeyAllocation struct {
	ID           uint   `gorm:"primaryKey"`
	AccountID    uint   `gorm:"not null"`
	NodeID       uint64 `gorm:"not null"`
	NodeKey      string `gorm:"not null"`
	AssignedIPv4 string // provider-assigned internal IPv4 (e.g. "10.139.55.16")
	AssignedIPv6 string // provider-assigned internal IPv6
	AllocatedAt  *time.Time

	Account VPNProviderAccount `gorm:"foreignKey:AccountID;constraint:OnDelete:CASCADE"`
}

func (VPNKeyAllocation) TableName() string { return "vpn_key_allocations" }

// loadAllocAccounts explicitly loads the Account association for a slice of
// VPNKeyAllocation. This replaces GORM's Preload("Account") which breaks due
// to field name collision: both VPNKeyAllocation.AccountID (uint FK) and
// VPNProviderAccount.AccountID (string Mullvad number) map to column "account_id",
// causing GORM's Preload matching to silently return empty Account structs.
func (hsdb *HSDatabase) loadAllocAccounts(allocs []VPNKeyAllocation) error {
	if len(allocs) == 0 {
		return nil
	}

	// Collect unique account IDs.
	acctIDs := make(map[uint]struct{})
	for _, a := range allocs {
		acctIDs[a.AccountID] = struct{}{}
	}

	ids := make([]uint, 0, len(acctIDs))
	for id := range acctIDs {
		ids = append(ids, id)
	}

	// Load all accounts in one query.
	var accounts []VPNProviderAccount
	if err := hsdb.DB.Where("id IN ?", ids).Find(&accounts).Error; err != nil {
		return fmt.Errorf("loading accounts for allocations: %w", err)
	}

	acctMap := make(map[uint]VPNProviderAccount, len(accounts))
	for _, a := range accounts {
		acctMap[a.ID] = a
	}

	// Assign back to each allocation.
	for i := range allocs {
		allocs[i].Account = acctMap[allocs[i].AccountID]
	}

	return nil
}

// CreateProviderAccount inserts a new provider account.
func (hsdb *HSDatabase) CreateProviderAccount(tx *gorm.DB, providerName, accountID string, maxKeys int) (*VPNProviderAccount, error) {
	if tx == nil {
		tx = hsdb.DB
	}

	now := time.Now()
	acct := VPNProviderAccount{
		ProviderName: providerName,
		AccountID:    accountID,
		MaxKeys:      maxKeys,
		Enabled:      true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := tx.Create(&acct).Error; err != nil {
		return nil, fmt.Errorf("creating provider account: %w", err)
	}

	return &acct, nil
}

// ListProviderAccounts returns all accounts, optionally filtered by provider name.
func (hsdb *HSDatabase) ListProviderAccounts(providerName string) ([]VPNProviderAccount, error) {
	var accounts []VPNProviderAccount

	q := hsdb.DB
	if providerName != "" {
		q = q.Where("provider_name = ?", providerName)
	}

	if err := q.Find(&accounts).Error; err != nil {
		return nil, fmt.Errorf("listing provider accounts: %w", err)
	}

	return accounts, nil
}

// GetProviderAccount returns a single provider account by ID.
func (hsdb *HSDatabase) GetProviderAccount(id uint) (*VPNProviderAccount, error) {
	var acct VPNProviderAccount
	if err := hsdb.DB.First(&acct, id).Error; err != nil {
		return nil, fmt.Errorf("getting provider account: %w", err)
	}

	return &acct, nil
}

// DeleteProviderAccount removes an account and cascades to its key allocations.
func (hsdb *HSDatabase) DeleteProviderAccount(tx *gorm.DB, id uint) error {
	if tx == nil {
		tx = hsdb.DB
	}

	if err := tx.Delete(&VPNProviderAccount{}, id).Error; err != nil {
		return fmt.Errorf("deleting provider account: %w", err)
	}

	return nil
}

// CreateKeyAllocation records that a node's WG key has been registered with a provider account.
func (hsdb *HSDatabase) CreateKeyAllocation(tx *gorm.DB, accountID uint, nodeID uint64, nodeKey, assignedIPv4, assignedIPv6 string) (*VPNKeyAllocation, error) {
	if tx == nil {
		tx = hsdb.DB
	}

	now := time.Now()
	alloc := VPNKeyAllocation{
		AccountID:    accountID,
		NodeID:       nodeID,
		NodeKey:      nodeKey,
		AssignedIPv4: assignedIPv4,
		AssignedIPv6: assignedIPv6,
		AllocatedAt:  &now,
	}

	if err := tx.Create(&alloc).Error; err != nil {
		return nil, fmt.Errorf("creating key allocation: %w", err)
	}

	return &alloc, nil
}

// DeleteKeyAllocation removes a key allocation by ID.
func (hsdb *HSDatabase) DeleteKeyAllocation(tx *gorm.DB, id uint) error {
	if tx == nil {
		tx = hsdb.DB
	}

	if err := tx.Delete(&VPNKeyAllocation{}, id).Error; err != nil {
		return fmt.Errorf("deleting key allocation: %w", err)
	}

	return nil
}

// DeleteKeyAllocationByNodeAndProvider removes a key allocation for a specific node and provider.
func (hsdb *HSDatabase) DeleteKeyAllocationByNodeAndProvider(tx *gorm.DB, nodeID uint64, providerName string) error {
	if tx == nil {
		tx = hsdb.DB
	}

	err := tx.Exec(`
		DELETE FROM vpn_key_allocations
		WHERE node_id = ?
		  AND account_id IN (
		    SELECT id FROM vpn_provider_accounts WHERE provider_name = ?
		  )`, nodeID, providerName).Error
	if err != nil {
		return fmt.Errorf("deleting key allocation by node and provider: %w", err)
	}

	return nil
}

// ListKeyAllocations returns all allocations, optionally filtered by provider name.
func (hsdb *HSDatabase) ListKeyAllocations(providerName string) ([]VPNKeyAllocation, error) {
	var allocs []VPNKeyAllocation

	q := hsdb.DB
	if providerName != "" {
		q = q.Where("account_id IN (SELECT id FROM vpn_provider_accounts WHERE provider_name = ?)", providerName)
	}

	if err := q.Find(&allocs).Error; err != nil {
		return nil, fmt.Errorf("listing key allocations: %w", err)
	}

	if err := hsdb.loadAllocAccounts(allocs); err != nil {
		return nil, err
	}

	return allocs, nil
}

// CountAllocationsForAccount returns the number of active key allocations for an account.
func (hsdb *HSDatabase) CountAllocationsForAccount(accountID uint) (int64, error) {
	var count int64

	err := hsdb.DB.Model(&VPNKeyAllocation{}).Where("account_id = ?", accountID).Count(&count).Error
	if err != nil {
		return 0, fmt.Errorf("counting allocations: %w", err)
	}

	return count, nil
}

// FindAccountWithFreeSlot returns an enabled account for the given provider that has
// at least one free key slot. Returns nil if no capacity is available.
func (hsdb *HSDatabase) FindAccountWithFreeSlot(providerName string) (*VPNProviderAccount, error) {
	var accounts []VPNProviderAccount
	if err := hsdb.DB.Where("provider_name = ? AND enabled = true", providerName).Find(&accounts).Error; err != nil {
		return nil, fmt.Errorf("finding accounts: %w", err)
	}

	for i := range accounts {
		count, err := hsdb.CountAllocationsForAccount(accounts[i].ID)
		if err != nil {
			return nil, err
		}

		if count < int64(accounts[i].MaxKeys) {
			return &accounts[i], nil
		}
	}

	return nil, nil //nolint:nilnil // intentional: no account with free slots
}

// FlushAllKeyAllocations deletes ALL key allocations across all providers
// and returns the deleted records so callers can deregister from provider APIs.
func (hsdb *HSDatabase) FlushAllKeyAllocations() ([]VPNKeyAllocation, error) {
	allocs, err := hsdb.ListKeyAllocations("")
	if err != nil {
		return nil, fmt.Errorf("listing all allocations for flush: %w", err)
	}

	if len(allocs) == 0 {
		return nil, nil
	}

	if err := hsdb.DB.Exec(`DELETE FROM vpn_key_allocations`).Error; err != nil {
		return nil, fmt.Errorf("flushing all key allocations: %w", err)
	}

	return allocs, nil
}

// FlushKeyAllocationsForProvider deletes all key allocations for the given provider
// and returns the records that were deleted (so callers can attempt API-side deregistration).
func (hsdb *HSDatabase) FlushKeyAllocationsForProvider(providerName string) ([]VPNKeyAllocation, error) {
	// First, fetch all allocations for this provider so we can return them.
	allocs, err := hsdb.ListKeyAllocations(providerName)
	if err != nil {
		return nil, fmt.Errorf("listing allocations for flush: %w", err)
	}

	if len(allocs) == 0 {
		return nil, nil
	}

	err = hsdb.DB.Exec(`
		DELETE FROM vpn_key_allocations
		WHERE account_id IN (
		  SELECT id FROM vpn_provider_accounts WHERE provider_name = ?
		)`, providerName).Error
	if err != nil {
		return nil, fmt.Errorf("flushing key allocations: %w", err)
	}

	return allocs, nil
}

// ListKeyAllocationsForNode returns all allocations for a given node across all providers.
func (hsdb *HSDatabase) ListKeyAllocationsForNode(nodeID uint64) ([]VPNKeyAllocation, error) {
	var allocs []VPNKeyAllocation

	err := hsdb.DB.Where("node_id = ?", nodeID).Find(&allocs).Error
	if err != nil {
		return nil, fmt.Errorf("listing allocations for node: %w", err)
	}

	if err := hsdb.loadAllocAccounts(allocs); err != nil {
		return nil, err
	}

	return allocs, nil
}

// GetKeyAllocationForNode returns the allocation for a node with the given provider, if any.
func (hsdb *HSDatabase) GetKeyAllocationForNode(nodeID uint64, providerName string) (*VPNKeyAllocation, error) {
	var alloc VPNKeyAllocation

	err := hsdb.DB.
		Where("node_id = ? AND account_id IN (SELECT id FROM vpn_provider_accounts WHERE provider_name = ?)", nodeID, providerName).
		First(&alloc).Error
	if err != nil {
		return nil, err
	}

	// Explicitly load the account to avoid GORM Preload issues caused by
	// field name collision: VPNKeyAllocation.AccountID (uint FK) vs
	// VPNProviderAccount.AccountID (string Mullvad account number).
	var account VPNProviderAccount
	if err := hsdb.DB.First(&account, alloc.AccountID).Error; err != nil {
		return nil, fmt.Errorf("loading account for allocation: %w", err)
	}

	alloc.Account = account

	return &alloc, nil
}
