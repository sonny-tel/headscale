package db

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"gorm.io/gorm/clause"
)

// SetDeviceAttributes upserts device posture attributes for a node.
// Attributes not in the update map are left unchanged.
// A nil value deletes the attribute.
func (hsdb *HSDatabase) SetDeviceAttributes(nodeID uint64, attrs map[string]any) error {
	now := time.Now().UTC()
	for key, val := range attrs {
		if val == nil {
			// Delete the attribute.
			if err := hsdb.DB.
				Where("node_id = ? AND attr_key = ?", nodeID, key).
				Delete(&types.DeviceAttribute{}).Error; err != nil {
				return fmt.Errorf("deleting device attribute %q: %w", key, err)
			}
			continue
		}

		valJSON, err := json.Marshal(val)
		if err != nil {
			return fmt.Errorf("marshalling device attribute value for %q: %w", key, err)
		}

		attr := types.DeviceAttribute{
			NodeID:    nodeID,
			AttrKey:   key,
			AttrValue: string(valJSON),
			UpdatedAt: now,
		}
		if err := hsdb.DB.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "node_id"}, {Name: "attr_key"}},
			DoUpdates: clause.AssignmentColumns([]string{"attr_value", "updated_at"}),
		}).Create(&attr).Error; err != nil {
			return fmt.Errorf("upserting device attribute %q: %w", key, err)
		}
	}
	return nil
}

// ListDeviceAttributes returns all device posture attributes for a node,
// or for all nodes if nodeID is 0.
func (hsdb *HSDatabase) ListDeviceAttributes(nodeID uint64) ([]types.DeviceAttribute, error) {
	var attrs []types.DeviceAttribute
	q := hsdb.DB.Model(&types.DeviceAttribute{})
	if nodeID > 0 {
		q = q.Where("node_id = ?", nodeID)
	}
	if err := q.Order("node_id ASC, attr_key ASC").Find(&attrs).Error; err != nil {
		return nil, fmt.Errorf("listing device attributes: %w", err)
	}
	return attrs, nil
}
