package policy

import (
	"fmt"
	"net/netip"
	"slices"
	"testing"

	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
)

func TestApproveRoutesWithPolicy_NeverRemovesApprovedRoutes(t *testing.T) {
	user1 := types.User{
		Model: gorm.Model{ID: 1},
		Name:  "testuser@",
	}
	user2 := types.User{
		Model: gorm.Model{ID: 2},
		Name:  "otheruser@",
	}
	users := []types.User{user1, user2}

	node1 := &types.Node{
		ID:             1,
		MachineKey:     key.NewMachine().Public(),
		NodeKey:        key.NewNode().Public(),
		Hostname:       "test-node",
		UserID:         new(user1.ID),
		User:           new(user1),
		RegisterMethod: util.RegisterMethodAuthKey,
		IPv4:           new(netip.MustParseAddr("100.64.0.1")),
		Tags:           []string{"tag:test"},
	}

	node2 := &types.Node{
		ID:             2,
		MachineKey:     key.NewMachine().Public(),
		NodeKey:        key.NewNode().Public(),
		Hostname:       "other-node",
		UserID:         new(user2.ID),
		User:           new(user2),
		RegisterMethod: util.RegisterMethodAuthKey,
		IPv4:           new(netip.MustParseAddr("100.64.0.2")),
	}

	// Create a policy that auto-approves specific routes
	policyJSON := `{
		"groups": {
			"group:test": ["testuser@"]
		},
		"tagOwners": {
			"tag:test": ["testuser@"]
		},
		"acls": [
			{
				"action": "accept",
				"src": ["*"],
				"dst": ["*:*"]
			}
		],
		"autoApprovers": {
			"routes": {
				"10.0.0.0/8": ["testuser@", "tag:test"],
				"10.1.0.0/24": ["testuser@"],
				"10.2.0.0/24": ["testuser@"],
				"192.168.0.0/24": ["tag:test"]
			}
		}
	}`

	pm, err := policyv2.NewPolicyManager([]byte(policyJSON), users, views.SliceOf([]types.NodeView{node1.View(), node2.View()}))
	require.NoError(t, err)

	tests := []struct {
		name            string
		node            *types.Node
		currentApproved []netip.Prefix
		announcedRoutes []netip.Prefix
		wantApproved    []netip.Prefix
		wantChanged     bool
		description     string
	}{
		{
			name: "previously_approved_route_no_longer_advertised_should_remain",
			node: node1,
			currentApproved: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
				netip.MustParsePrefix("192.168.0.0/24"),
			},
			announcedRoutes: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"), // Only this one is still advertised
			},
			wantApproved: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
				netip.MustParsePrefix("192.168.0.0/24"), // Should still be here!
			},
			wantChanged: false,
			description: "Previously approved routes should never be removed even when no longer advertised",
		},
		{
			name: "add_new_auto_approved_route_keeps_old_approved",
			node: node1,
			currentApproved: []netip.Prefix{
				netip.MustParsePrefix("10.5.0.0/24"), // This was manually approved
			},
			announcedRoutes: []netip.Prefix{
				netip.MustParsePrefix("10.1.0.0/24"), // New route that should be auto-approved
			},
			wantApproved: []netip.Prefix{
				netip.MustParsePrefix("10.1.0.0/24"), // New auto-approved route (subset of 10.0.0.0/8)
				netip.MustParsePrefix("10.5.0.0/24"), // Old approved route kept
			},
			wantChanged: true,
			description: "New auto-approved routes should be added while keeping old approved routes",
		},
		{
			name: "no_announced_routes_keeps_all_approved",
			node: node1,
			currentApproved: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
				netip.MustParsePrefix("192.168.0.0/24"),
				netip.MustParsePrefix("172.16.0.0/16"),
			},
			announcedRoutes: []netip.Prefix{}, // No routes announced
			wantApproved: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
				netip.MustParsePrefix("172.16.0.0/16"),
				netip.MustParsePrefix("192.168.0.0/24"),
			},
			wantChanged: false,
			description: "All approved routes should remain when no routes are announced",
		},
		{
			name: "no_changes_when_announced_equals_approved",
			node: node1,
			currentApproved: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
			},
			announcedRoutes: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
			},
			wantApproved: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
			},
			wantChanged: false,
			description: "No changes should occur when announced routes match approved routes",
		},
		{
			name: "auto_approve_multiple_new_routes",
			node: node1,
			currentApproved: []netip.Prefix{
				netip.MustParsePrefix("172.16.0.0/24"), // This was manually approved
			},
			announcedRoutes: []netip.Prefix{
				netip.MustParsePrefix("10.2.0.0/24"),    // Should be auto-approved (subset of 10.0.0.0/8)
				netip.MustParsePrefix("192.168.0.0/24"), // Should be auto-approved for tag:test
			},
			wantApproved: []netip.Prefix{
				netip.MustParsePrefix("10.2.0.0/24"),    // New auto-approved
				netip.MustParsePrefix("172.16.0.0/24"),  // Original kept
				netip.MustParsePrefix("192.168.0.0/24"), // New auto-approved
			},
			wantChanged: true,
			description: "Multiple new routes should be auto-approved while keeping existing approved routes",
		},
		{
			name: "node_without_permission_no_auto_approval",
			node: node2, // Different node without the tag
			currentApproved: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
			},
			announcedRoutes: []netip.Prefix{
				netip.MustParsePrefix("192.168.0.0/24"), // This requires tag:test
			},
			wantApproved: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"), // Only the original approved route
			},
			wantChanged: false,
			description: "Routes should not be auto-approved for nodes without proper permissions",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotApproved, gotChanged := ApproveRoutesWithPolicy(pm, tt.node.View(), tt.currentApproved, tt.announcedRoutes)

			assert.Equal(t, tt.wantChanged, gotChanged, "changed flag mismatch: %s", tt.description)

			// Sort for comparison since ApproveRoutesWithPolicy sorts the results
			slices.SortFunc(tt.wantApproved, netip.Prefix.Compare)
			assert.Equal(t, tt.wantApproved, gotApproved, "approved routes mismatch: %s", tt.description)

			// Verify that all previously approved routes are still present
			for _, prevRoute := range tt.currentApproved {
				assert.Contains(t, gotApproved, prevRoute,
					"previously approved route %s was removed - this should never happen", prevRoute)
			}
		})
	}
}

func TestApproveRoutesWithPolicy_NilAndEmptyCases(t *testing.T) {
	// Create a basic policy for edge case testing
	aclPolicy := `
{
	"acls": [
		{"action": "accept", "src": ["*"], "dst": ["*:*"]},
	],
	"autoApprovers": {
		"routes": {
			"10.1.0.0/24": ["test@"],
		},
	},
}`

	pmfs := PolicyManagerFuncsForTest([]byte(aclPolicy))

	tests := []struct {
		name            string
		currentApproved []netip.Prefix
		announcedRoutes []netip.Prefix
		wantApproved    []netip.Prefix
		wantChanged     bool
	}{
		{
			name: "nil_policy_manager",
			currentApproved: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
			},
			announcedRoutes: []netip.Prefix{
				netip.MustParsePrefix("192.168.0.0/24"),
			},
			wantApproved: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
			},
			wantChanged: false,
		},
		{
			name:            "nil_current_approved",
			currentApproved: nil,
			announcedRoutes: []netip.Prefix{
				netip.MustParsePrefix("10.1.0.0/24"),
			},
			wantApproved: []netip.Prefix{
				netip.MustParsePrefix("10.1.0.0/24"),
			},
			wantChanged: true,
		},
		{
			name: "nil_announced_routes",
			currentApproved: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
			},
			announcedRoutes: nil,
			wantApproved: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
			},
			wantChanged: false,
		},
		{
			name: "duplicate_approved_routes",
			currentApproved: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
				netip.MustParsePrefix("10.0.0.0/24"), // Duplicate
			},
			announcedRoutes: []netip.Prefix{
				netip.MustParsePrefix("10.1.0.0/24"),
			},
			wantApproved: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
				netip.MustParsePrefix("10.1.0.0/24"),
			},
			wantChanged: true,
		},
		{
			name:            "empty_slices",
			currentApproved: []netip.Prefix{},
			announcedRoutes: []netip.Prefix{},
			wantApproved:    []netip.Prefix{},
			wantChanged:     false,
		},
	}

	for _, tt := range tests {
		for i, pmf := range pmfs {
			t.Run(fmt.Sprintf("%s-policy-index%d", tt.name, i), func(t *testing.T) {
				// Create test user
				user := types.User{
					Model: gorm.Model{ID: 1},
					Name:  "test",
				}
				users := []types.User{user}

				// Create test node
				node := types.Node{
					ID:             1,
					MachineKey:     key.NewMachine().Public(),
					NodeKey:        key.NewNode().Public(),
					Hostname:       "testnode",
					UserID:         new(user.ID),
					User:           new(user),
					RegisterMethod: util.RegisterMethodAuthKey,
					IPv4:           new(netip.MustParseAddr("100.64.0.1")),
					ApprovedRoutes: tt.currentApproved,
				}
				nodes := types.Nodes{&node}

				// Create policy manager or use nil if specified
				var (
					pm  PolicyManager
					err error
				)

				if tt.name != "nil_policy_manager" {
					pm, err = pmf(users, nodes.ViewSlice())
					require.NoError(t, err)
				} else {
					pm = nil
				}

				gotApproved, gotChanged := ApproveRoutesWithPolicy(pm, node.View(), tt.currentApproved, tt.announcedRoutes)

				assert.Equal(t, tt.wantChanged, gotChanged, "changed flag mismatch")

				// Handle nil vs empty slice comparison
				if tt.wantApproved == nil {
					assert.Nil(t, gotApproved, "expected nil approved routes")
				} else {
					slices.SortFunc(tt.wantApproved, netip.Prefix.Compare)
					assert.Equal(t, tt.wantApproved, gotApproved, "approved routes mismatch")
				}
			})
		}
	}
}

func TestApproveRoutesWithPolicy_AppConnectorAutoApproval(t *testing.T) {
	user1 := types.User{
		Model: gorm.Model{ID: 1},
		Name:  "testuser@",
	}
	user2 := types.User{
		Model: gorm.Model{ID: 2},
		Name:  "otheruser@",
	}
	users := []types.User{user1, user2}

	// App connector node — targeted by nodeAttrs rule
	appConnNode := &types.Node{
		ID:             1,
		MachineKey:     key.NewMachine().Public(),
		NodeKey:        key.NewNode().Public(),
		Hostname:       "app-connector",
		UserID:         new(user1.ID),
		User:           new(user1),
		RegisterMethod: util.RegisterMethodAuthKey,
		IPv4:           new(netip.MustParseAddr("100.64.0.1")),
		Tags:           []string{"tag:connector"},
	}

	// Regular node — NOT an app connector
	regularNode := &types.Node{
		ID:             2,
		MachineKey:     key.NewMachine().Public(),
		NodeKey:        key.NewNode().Public(),
		Hostname:       "regular-node",
		UserID:         new(user2.ID),
		User:           new(user2),
		RegisterMethod: util.RegisterMethodAuthKey,
		IPv4:           new(netip.MustParseAddr("100.64.0.2")),
	}

	// Policy with nodeAttrs granting app-connectors capability to tag:connector nodes
	policyJSON := `{
		"tagOwners": {
			"tag:connector": ["testuser@"]
		},
		"acls": [
			{"action": "accept", "src": ["*"], "dst": ["*:*"]}
		],
		"nodeAttrs": [
			{
				"target": ["tag:connector"],
				"app": {
					"tailscale.com/app-connectors": [{"domains": ["example.com", "*.example.com"]}]
				}
			}
		]
	}`

	pm, err := policyv2.NewPolicyManager(
		[]byte(policyJSON),
		users,
		views.SliceOf([]types.NodeView{appConnNode.View(), regularNode.View()}),
	)
	require.NoError(t, err)

	tests := []struct {
		name            string
		node            *types.Node
		currentApproved []netip.Prefix
		announcedRoutes []netip.Prefix
		wantApproved    []netip.Prefix
		wantChanged     bool
		description     string
	}{
		{
			name:            "app_connector_auto_approves_all_routes",
			node:            appConnNode,
			currentApproved: []netip.Prefix{},
			announcedRoutes: []netip.Prefix{
				netip.MustParsePrefix("93.184.216.34/32"), // resolved IP for example.com
				netip.MustParsePrefix("93.184.216.35/32"), // another resolved IP
			},
			wantApproved: []netip.Prefix{
				netip.MustParsePrefix("93.184.216.34/32"),
				netip.MustParsePrefix("93.184.216.35/32"),
			},
			wantChanged: true,
			description: "App connector nodes should have all announced routes auto-approved",
		},
		{
			name:            "regular_node_not_auto_approved_without_autoApprovers",
			node:            regularNode,
			currentApproved: []netip.Prefix{},
			announcedRoutes: []netip.Prefix{
				netip.MustParsePrefix("93.184.216.34/32"),
			},
			wantApproved: []netip.Prefix{},
			wantChanged:  false,
			description:  "Regular nodes without autoApprovers should NOT get routes auto-approved",
		},
		{
			name: "app_connector_keeps_existing_approved",
			node: appConnNode,
			currentApproved: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"), // previously approved
			},
			announcedRoutes: []netip.Prefix{
				netip.MustParsePrefix("93.184.216.34/32"), // new dynamic route
			},
			wantApproved: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
				netip.MustParsePrefix("93.184.216.34/32"),
			},
			wantChanged: true,
			description: "App connector should keep previously approved routes and add new ones",
		},
		{
			name: "app_connector_no_new_routes",
			node: appConnNode,
			currentApproved: []netip.Prefix{
				netip.MustParsePrefix("93.184.216.34/32"),
			},
			announcedRoutes: []netip.Prefix{
				netip.MustParsePrefix("93.184.216.34/32"), // same route
			},
			wantApproved: []netip.Prefix{
				netip.MustParsePrefix("93.184.216.34/32"),
			},
			wantChanged: false,
			description: "No change when app connector re-announces already approved routes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotApproved, gotChanged := ApproveRoutesWithPolicy(pm, tt.node.View(), tt.currentApproved, tt.announcedRoutes)

			assert.Equal(t, tt.wantChanged, gotChanged, "changed flag mismatch: %s", tt.description)

			slices.SortFunc(tt.wantApproved, netip.Prefix.Compare)
			assert.Equal(t, tt.wantApproved, gotApproved, "approved routes mismatch: %s", tt.description)
		})
	}
}
