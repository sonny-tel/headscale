package db

import (
	"fmt"
	"time"

	"gorm.io/gorm"
)

// AuditEvent represents a logged action in the system.
type AuditEvent struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	Timestamp  time.Time `gorm:"not null;index" json:"timestamp"`
	EventType  string    `gorm:"not null;index" json:"event_type"`
	Actor      string    `gorm:"not null" json:"actor"`
	TargetType string    `json:"target_type"`
	TargetName string    `json:"target_name"`
	Details    string    `json:"details"`
}

func (AuditEvent) TableName() string {
	return "audit_events"
}

// LogAuditEvent inserts an audit event into the database.
func (hsdb *HSDatabase) LogAuditEvent(eventType, actor, targetType, targetName, details string) {
	event := AuditEvent{
		Timestamp:  time.Now().UTC(),
		EventType:  eventType,
		Actor:      actor,
		TargetType: targetType,
		TargetName: targetName,
		Details:    details,
	}
	// Best-effort: don't let audit logging break the operation.
	hsdb.DB.Create(&event) //nolint:errcheck
}

// ListAuditEvents returns audit events, newest first. Supports optional
// filtering by event type and pagination via limit/offset.
func (hsdb *HSDatabase) ListAuditEvents(eventType string, limit, offset int) ([]AuditEvent, int64, error) {
	var events []AuditEvent
	var total int64

	q := hsdb.DB.Model(&AuditEvent{})
	if eventType != "" {
		q = q.Where("event_type = ?", eventType)
	}

	if err := q.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("counting audit events: %w", err)
	}

	if limit <= 0 {
		limit = 100
	}

	if err := q.Order("timestamp DESC").Limit(limit).Offset(offset).Find(&events).Error; err != nil {
		return nil, 0, fmt.Errorf("listing audit events: %w", err)
	}

	return events, total, nil
}

// PruneAuditEvents deletes audit events older than the given duration.
func (hsdb *HSDatabase) PruneAuditEvents(tx *gorm.DB, olderThan time.Duration) (int64, error) {
	if tx == nil {
		tx = hsdb.DB
	}
	cutoff := time.Now().UTC().Add(-olderThan)
	result := tx.Where("timestamp < ?", cutoff).Delete(&AuditEvent{})
	return result.RowsAffected, result.Error
}
