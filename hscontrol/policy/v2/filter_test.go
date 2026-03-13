package v2

import (
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go4.org/netipx"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/wgengine/filter"
)

// aliasWithPorts creates an AliasWithPorts structure from an alias and ports.
func aliasWithPorts(alias Alias, ports ...tailcfg.PortRange) AliasWithPorts {
	return AliasWithPorts{
		Alias: alias,
		Ports: ports,
	}
}

func TestParsing(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "testuser"},
	}
	tests := []struct {
		name    string
		format  string
		acl     string
		want    []tailcfg.FilterRule
		wantErr bool
	}{
		{
			name:   "invalid-hujson",
			format: "hujson",
			acl: `
{
		`,
			want:    []tailcfg.FilterRule{},
			wantErr: true,
		},
		// The new parser will ignore all that is irrelevant
		// 		{
		// 			name:   "valid-hujson-invalid-content",
		// 			format: "hujson",
		// 			acl: `
		// {
		//   "valid_json": true,
		//   "but_a_policy_though": false
		// }
		// 				`,
		// 			want:    []tailcfg.FilterRule{},
		// 			wantErr: true,
		// 		},
		// 		{
		// 			name:   "invalid-cidr",
		// 			format: "hujson",
		// 			acl: `
		// {"example-host-1": "100.100.100.100/42"}
		// 				`,
		// 			want:    []tailcfg.FilterRule{},
		// 			wantErr: true,
		// 		},
		{
			name:   "basic-rule",
			format: "hujson",
			acl: `
{
	"hosts": {
		"host-1": "100.100.100.100",
		"subnet-1": "100.100.101.100/24",
	},

	"acls": [
		{
			"action": "accept",
			"src": [
				"subnet-1",
				"192.168.1.0/24"
			],
			"dst": [
				"*:22,3389",
				"host-1:*",
			],
		},
	],
}
		`,
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.100.101.0/24", "192.168.1.0/24"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "*", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						{IP: "*", Ports: tailcfg.PortRange{First: 3389, Last: 3389}},
						{IP: "100.100.100.100/32", Ports: tailcfg.PortRangeAny},
					},
					IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
				},
			},
			wantErr: false,
		},
		{
			name:   "parse-protocol",
			format: "hujson",
			acl: `
{
	"hosts": {
		"host-1": "100.100.100.100",
		"subnet-1": "100.100.101.100/24",
	},

	"acls": [
		{
			"Action": "accept",
			"src": [
				"*",
			],
			"proto": "tcp",
			"dst": [
				"host-1:*",
			],
		},
		{
			"Action": "accept",
			"src": [
				"*",
			],
			"proto": "udp",
			"dst": [
				"host-1:53",
			],
		},
		{
			"Action": "accept",
			"src": [
				"*",
			],
			"proto": "icmp",
			"dst": [
				"host-1:*",
			],
		},
	],
}`,
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.0/10", "fd7a:115c:a1e0::/48"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.100.100.100/32", Ports: tailcfg.PortRangeAny},
					},
					IPProto: []int{ProtocolTCP},
				},
				{
					SrcIPs: []string{"100.64.0.0/10", "fd7a:115c:a1e0::/48"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.100.100.100/32", Ports: tailcfg.PortRange{First: 53, Last: 53}},
					},
					IPProto: []int{ProtocolUDP},
				},
				{
					SrcIPs: []string{"100.64.0.0/10", "fd7a:115c:a1e0::/48"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.100.100.100/32", Ports: tailcfg.PortRangeAny},
					},
					// proto:icmp only includes ICMP (1), not ICMPv6 (58)
					IPProto: []int{ProtocolICMP},
				},
			},
			wantErr: false,
		},
		{
			name:   "port-wildcard",
			format: "hujson",
			acl: `
{
	"hosts": {
		"host-1": "100.100.100.100",
		"subnet-1": "100.100.101.100/24",
	},

	"acls": [
		{
			"Action": "accept",
			"src": [
				"*",
			],
			"dst": [
				"host-1:*",
			],
		},
	],
}
`,
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.0/10", "fd7a:115c:a1e0::/48"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.100.100.100/32", Ports: tailcfg.PortRangeAny},
					},
					IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
				},
			},
			wantErr: false,
		},
		{
			name:   "port-range",
			format: "hujson",
			acl: `
{
	"hosts": {
		"host-1": "100.100.100.100",
		"subnet-1": "100.100.101.100/24",
	},

	"acls": [
		{
			"action": "accept",
			"src": [
				"subnet-1",
			],
			"dst": [
				"host-1:5400-5500",
			],
		},
	],
}
`,
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.100.101.0/24"},
					DstPorts: []tailcfg.NetPortRange{
						{
							IP:    "100.100.100.100/32",
							Ports: tailcfg.PortRange{First: 5400, Last: 5500},
						},
					},
					IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
				},
			},
			wantErr: false,
		},
		{
			name:   "port-group",
			format: "hujson",
			acl: `
{
	"groups": {
		"group:example": [
			"testuser@",
		],
	},

	"hosts": {
		"host-1": "100.100.100.100",
		"subnet-1": "100.100.101.100/24",
	},

	"acls": [
		{
			"action": "accept",
			"src": [
				"group:example",
			],
			"dst": [
				"host-1:*",
			],
		},
	],
}
`,
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"200.200.200.200/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.100.100.100/32", Ports: tailcfg.PortRangeAny},
					},
					IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
				},
			},
			wantErr: false,
		},
		{
			name:   "port-user",
			format: "hujson",
			acl: `
{
	"hosts": {
		"host-1": "100.100.100.100",
		"subnet-1": "100.100.101.100/24",
	},

	"acls": [
		{
			"action": "accept",
			"src": [
				"testuser@",
			],
			"dst": [
				"host-1:*",
			],
		},
	],
}
`,
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"200.200.200.200/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.100.100.100/32", Ports: tailcfg.PortRangeAny},
					},
					IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
				},
			},
			wantErr: false,
		},
		{
			name:   "ipv6",
			format: "hujson",
			acl: `
{
	"hosts": {
		"host-1": "100.100.100.100/32",
		"subnet-1": "100.100.101.100/24",
	},

	"acls": [
		{
			"action": "accept",
			"src": [
				"*",
			],
			"dst": [
				"host-1:*",
			],
		},
	],
}
`,
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.0/10", "fd7a:115c:a1e0::/48"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.100.100.100/32", Ports: tailcfg.PortRangeAny},
					},
					IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pol, err := unmarshalPolicy([]byte(tt.acl))
			if tt.wantErr && err == nil {
				t.Errorf("parsing() error = %v, wantErr %v", err, tt.wantErr)

				return
			} else if !tt.wantErr && err != nil {
				t.Errorf("parsing() error = %v, wantErr %v", err, tt.wantErr)

				return
			}

			if err != nil {
				return
			}

			rules, err := pol.compileFilterRules(
				users,
				types.Nodes{
					&types.Node{
						IPv4: ap("100.100.100.100"),
					},
					&types.Node{
						IPv4:     ap("200.200.200.200"),
						User:     &users[0],
						Hostinfo: &tailcfg.Hostinfo{},
					},
				}.ViewSlice())

			if (err != nil) != tt.wantErr {
				t.Errorf("parsing() error = %v, wantErr %v", err, tt.wantErr)

				return
			}

			if diff := cmp.Diff(tt.want, rules); diff != "" {
				t.Errorf("parsing() unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}

func TestCompileSSHPolicy_UserMapping(t *testing.T) {
	users := types.Users{
		{Name: "user1", Model: gorm.Model{ID: 1}},
		{Name: "user2", Model: gorm.Model{ID: 2}},
	}

	// Create test nodes - use tagged nodes as SSH destinations
	// and untagged nodes as SSH sources (since group->username destinations
	// are not allowed per Tailscale security model, but groups can SSH to tags)
	nodeTaggedServer := types.Node{
		Hostname: "tagged-server",
		IPv4:     createAddr("100.64.0.1"),
		UserID:   new(users[0].ID),
		User:     new(users[0]),
		Tags:     []string{"tag:server"},
	}
	nodeTaggedDB := types.Node{
		Hostname: "tagged-db",
		IPv4:     createAddr("100.64.0.2"),
		UserID:   new(users[1].ID),
		User:     new(users[1]),
		Tags:     []string{"tag:database"},
	}
	// Add untagged node for user2 - this will be the SSH source
	// (group:admins contains user2, so user2's untagged node provides the source IPs)
	nodeUser2Untagged := types.Node{
		Hostname: "user2-device",
		IPv4:     createAddr("100.64.0.3"),
		UserID:   new(users[1].ID),
		User:     new(users[1]),
	}

	nodes := types.Nodes{&nodeTaggedServer, &nodeTaggedDB, &nodeUser2Untagged}

	acceptAction := &tailcfg.SSHAction{
		Accept:                    true,
		AllowAgentForwarding:      true,
		AllowLocalPortForwarding:  true,
		AllowRemotePortForwarding: true,
	}
	user2Principal := []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.3"}}

	tests := []struct {
		name       string
		targetNode types.Node
		policy     *Policy
		want       *tailcfg.SSHPolicy
	}{
		{
			name:       "specific user mapping",
			targetNode: nodeTaggedServer,
			policy: &Policy{
				TagOwners: TagOwners{
					Tag("tag:server"): Owners{up("user1@")},
				},
				Groups: Groups{
					Group("group:admins"): []Username{Username("user2@")},
				},
				SSHs: []SSH{
					{
						Action:       "accept",
						Sources:      SSHSrcAliases{gp("group:admins")},
						Destinations: SSHDstAliases{tp("tag:server")},
						Users:        []SSHUser{"ssh-it-user"},
					},
				},
			},
			want: &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{
				{
					Principals: user2Principal,
					SSHUsers:   map[string]string{"root": "", "ssh-it-user": "ssh-it-user"},
					Action:     acceptAction,
				},
			}},
		},
		{
			name:       "multiple specific users",
			targetNode: nodeTaggedServer,
			policy: &Policy{
				TagOwners: TagOwners{
					Tag("tag:server"): Owners{up("user1@")},
				},
				Groups: Groups{
					Group("group:admins"): []Username{Username("user2@")},
				},
				SSHs: []SSH{
					{
						Action:       "accept",
						Sources:      SSHSrcAliases{gp("group:admins")},
						Destinations: SSHDstAliases{tp("tag:server")},
						Users:        []SSHUser{"ubuntu", "admin", "deploy"},
					},
				},
			},
			want: &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{
				{
					Principals: user2Principal,
					SSHUsers:   map[string]string{"root": "", "ubuntu": "ubuntu", "admin": "admin", "deploy": "deploy"},
					Action:     acceptAction,
				},
			}},
		},
		{
			name:       "autogroup:nonroot only",
			targetNode: nodeTaggedServer,
			policy: &Policy{
				TagOwners: TagOwners{
					Tag("tag:server"): Owners{up("user1@")},
				},
				Groups: Groups{
					Group("group:admins"): []Username{Username("user2@")},
				},
				SSHs: []SSH{
					{
						Action:       "accept",
						Sources:      SSHSrcAliases{gp("group:admins")},
						Destinations: SSHDstAliases{tp("tag:server")},
						Users:        []SSHUser{SSHUser(AutoGroupNonRoot)},
					},
				},
			},
			want: &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{
				{
					Principals: user2Principal,
					SSHUsers:   map[string]string{"*": "=", "root": ""},
					Action:     acceptAction,
				},
			}},
		},
		{
			name:       "root only",
			targetNode: nodeTaggedServer,
			policy: &Policy{
				TagOwners: TagOwners{
					Tag("tag:server"): Owners{up("user1@")},
				},
				Groups: Groups{
					Group("group:admins"): []Username{Username("user2@")},
				},
				SSHs: []SSH{
					{
						Action:       "accept",
						Sources:      SSHSrcAliases{gp("group:admins")},
						Destinations: SSHDstAliases{tp("tag:server")},
						Users:        []SSHUser{"root"},
					},
				},
			},
			want: &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{
				{
					Principals: user2Principal,
					SSHUsers:   map[string]string{"root": "root"},
					Action:     acceptAction,
				},
			}},
		},
		{
			name:       "autogroup:nonroot plus root",
			targetNode: nodeTaggedServer,
			policy: &Policy{
				TagOwners: TagOwners{
					Tag("tag:server"): Owners{up("user1@")},
				},
				Groups: Groups{
					Group("group:admins"): []Username{Username("user2@")},
				},
				SSHs: []SSH{
					{
						Action:       "accept",
						Sources:      SSHSrcAliases{gp("group:admins")},
						Destinations: SSHDstAliases{tp("tag:server")},
						Users:        []SSHUser{SSHUser(AutoGroupNonRoot), "root"},
					},
				},
			},
			want: &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{
				{
					Principals: user2Principal,
					SSHUsers:   map[string]string{"*": "=", "root": "root"},
					Action:     acceptAction,
				},
			}},
		},
		{
			name:       "mixed specific users and autogroups",
			targetNode: nodeTaggedServer,
			policy: &Policy{
				TagOwners: TagOwners{
					Tag("tag:server"): Owners{up("user1@")},
				},
				Groups: Groups{
					Group("group:admins"): []Username{Username("user2@")},
				},
				SSHs: []SSH{
					{
						Action:       "accept",
						Sources:      SSHSrcAliases{gp("group:admins")},
						Destinations: SSHDstAliases{tp("tag:server")},
						Users:        []SSHUser{SSHUser(AutoGroupNonRoot), "root", "ubuntu", "admin"},
					},
				},
			},
			want: &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{
				{
					Principals: user2Principal,
					SSHUsers:   map[string]string{"*": "=", "root": "root", "ubuntu": "ubuntu", "admin": "admin"},
					Action:     acceptAction,
				},
			}},
		},
		{
			name:       "no matching destination",
			targetNode: nodeTaggedDB, // Target tag:database, but policy only allows tag:server
			policy: &Policy{
				TagOwners: TagOwners{
					Tag("tag:server"):   Owners{up("user1@")},
					Tag("tag:database"): Owners{up("user1@")},
				},
				Groups: Groups{
					Group("group:admins"): []Username{Username("user2@")},
				},
				SSHs: []SSH{
					{
						Action:       "accept",
						Sources:      SSHSrcAliases{gp("group:admins")},
						Destinations: SSHDstAliases{tp("tag:server")}, // Only tag:server, not tag:database
						Users:        []SSHUser{"ssh-it-user"},
					},
				},
			},
			want: &tailcfg.SSHPolicy{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.NoError(t, tt.policy.validate())

			got, err := tt.policy.compileSSHPolicy("unused-server-url", users, tt.targetNode.View(), nodes.ViewSlice())
			require.NoError(t, err)

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("compileSSHPolicy() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestCompileSSHPolicy_LocalpartMapping(t *testing.T) {
	users := types.Users{
		{Name: "alice", Email: "alice@example.com", Model: gorm.Model{ID: 1}},
		{Name: "bob", Email: "bob@example.com", Model: gorm.Model{ID: 2}},
		{Name: "charlie", Email: "charlie@other.com", Model: gorm.Model{ID: 3}},
		{Name: "dave", Model: gorm.Model{ID: 4}}, // CLI user, no email
	}

	nodeTaggedServer := types.Node{
		Hostname: "tagged-server",
		IPv4:     createAddr("100.64.0.1"),
		UserID:   new(users[0].ID),
		User:     new(users[0]),
		Tags:     []string{"tag:server"},
	}
	nodeAlice := types.Node{
		Hostname: "alice-device",
		IPv4:     createAddr("100.64.0.2"),
		UserID:   new(users[0].ID),
		User:     new(users[0]),
	}
	nodeBob := types.Node{
		Hostname: "bob-device",
		IPv4:     createAddr("100.64.0.3"),
		UserID:   new(users[1].ID),
		User:     new(users[1]),
	}
	nodeCharlie := types.Node{
		Hostname: "charlie-device",
		IPv4:     createAddr("100.64.0.4"),
		UserID:   new(users[2].ID),
		User:     new(users[2]),
	}
	nodeDave := types.Node{
		Hostname: "dave-device",
		IPv4:     createAddr("100.64.0.5"),
		UserID:   new(users[3].ID),
		User:     new(users[3]),
	}

	nodes := types.Nodes{&nodeTaggedServer, &nodeAlice, &nodeBob, &nodeCharlie, &nodeDave}

	acceptAction := &tailcfg.SSHAction{
		Accept:                    true,
		AllowAgentForwarding:      true,
		AllowLocalPortForwarding:  true,
		AllowRemotePortForwarding: true,
	}

	tests := []struct {
		name       string
		users      types.Users // nil → use default users
		nodes      types.Nodes // nil → use default nodes
		targetNode types.Node
		policy     *Policy
		want       *tailcfg.SSHPolicy
	}{
		{
			name:       "localpart only",
			targetNode: nodeTaggedServer,
			policy: &Policy{
				TagOwners: TagOwners{
					Tag("tag:server"): Owners{up("alice@example.com")},
				},
				SSHs: []SSH{
					{
						Action:       "accept",
						Sources:      SSHSrcAliases{agp("autogroup:member")},
						Destinations: SSHDstAliases{tp("tag:server")},
						Users:        []SSHUser{SSHUser("localpart:*@example.com")},
					},
				},
			},
			// Per-user common+localpart rules interleaved, then non-matching users.
			want: &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.2"}},
					SSHUsers:   map[string]string{"root": ""},
					Action:     acceptAction,
				},
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.2"}},
					SSHUsers:   map[string]string{"alice": "alice"},
					Action:     acceptAction,
				},
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.3"}},
					SSHUsers:   map[string]string{"root": ""},
					Action:     acceptAction,
				},
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.3"}},
					SSHUsers:   map[string]string{"bob": "bob"},
					Action:     acceptAction,
				},
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.4"}},
					SSHUsers:   map[string]string{"root": ""},
					Action:     acceptAction,
				},
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.5"}},
					SSHUsers:   map[string]string{"root": ""},
					Action:     acceptAction,
				},
			}},
		},
		{
			name:       "localpart with root",
			targetNode: nodeTaggedServer,
			policy: &Policy{
				TagOwners: TagOwners{
					Tag("tag:server"): Owners{up("alice@example.com")},
				},
				SSHs: []SSH{
					{
						Action:       "accept",
						Sources:      SSHSrcAliases{agp("autogroup:member")},
						Destinations: SSHDstAliases{tp("tag:server")},
						Users:        []SSHUser{SSHUser("localpart:*@example.com"), "root"},
					},
				},
			},
			// Per-user common+localpart rules interleaved, then non-matching users.
			want: &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.2"}},
					SSHUsers:   map[string]string{"root": "root"},
					Action:     acceptAction,
				},
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.2"}},
					SSHUsers:   map[string]string{"alice": "alice"},
					Action:     acceptAction,
				},
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.3"}},
					SSHUsers:   map[string]string{"root": "root"},
					Action:     acceptAction,
				},
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.3"}},
					SSHUsers:   map[string]string{"bob": "bob"},
					Action:     acceptAction,
				},
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.4"}},
					SSHUsers:   map[string]string{"root": "root"},
					Action:     acceptAction,
				},
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.5"}},
					SSHUsers:   map[string]string{"root": "root"},
					Action:     acceptAction,
				},
			}},
		},
		{
			name:       "localpart no matching users in domain",
			targetNode: nodeTaggedServer,
			policy: &Policy{
				TagOwners: TagOwners{
					Tag("tag:server"): Owners{up("alice@example.com")},
				},
				SSHs: []SSH{
					{
						Action:       "accept",
						Sources:      SSHSrcAliases{agp("autogroup:member")},
						Destinations: SSHDstAliases{tp("tag:server")},
						Users:        []SSHUser{SSHUser("localpart:*@nonexistent.com")},
					},
				},
			},
			// No localpart matches, but per-user common rules still emitted (root deny)
			want: &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.2"}},
					SSHUsers:   map[string]string{"root": ""},
					Action:     acceptAction,
				},
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.3"}},
					SSHUsers:   map[string]string{"root": ""},
					Action:     acceptAction,
				},
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.4"}},
					SSHUsers:   map[string]string{"root": ""},
					Action:     acceptAction,
				},
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.5"}},
					SSHUsers:   map[string]string{"root": ""},
					Action:     acceptAction,
				},
			}},
		},
		{
			name: "localpart with special chars in email",
			users: types.Users{
				{Name: "dave+sshuser", Email: "dave+sshuser@example.com", Model: gorm.Model{ID: 10}},
			},
			nodes: func() types.Nodes {
				specialUser := types.User{Name: "dave+sshuser", Email: "dave+sshuser@example.com", Model: gorm.Model{ID: 10}}
				n := types.Node{
					Hostname: "special-device",
					IPv4:     createAddr("100.64.0.10"),
					UserID:   new(specialUser.ID),
					User:     &specialUser,
				}

				return types.Nodes{&nodeTaggedServer, &n}
			}(),
			targetNode: nodeTaggedServer,
			policy: &Policy{
				TagOwners: TagOwners{
					Tag("tag:server"): Owners{up("dave+sshuser@example.com")},
				},
				SSHs: []SSH{
					{
						Action:       "accept",
						Sources:      SSHSrcAliases{agp("autogroup:member")},
						Destinations: SSHDstAliases{tp("tag:server")},
						Users:        []SSHUser{SSHUser("localpart:*@example.com")},
					},
				},
			},
			// Per-user common rule (root deny), then separate localpart rule.
			want: &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.10"}},
					SSHUsers:   map[string]string{"root": ""},
					Action:     acceptAction,
				},
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.10"}},
					SSHUsers:   map[string]string{"dave+sshuser": "dave+sshuser"},
					Action:     acceptAction,
				},
			}},
		},
		{
			name: "localpart excludes CLI users without email",
			users: types.Users{
				{Name: "dave", Model: gorm.Model{ID: 4}},
			},
			nodes: func() types.Nodes {
				cliUser := types.User{Name: "dave", Model: gorm.Model{ID: 4}}
				n := types.Node{
					Hostname: "dave-cli-device",
					IPv4:     createAddr("100.64.0.5"),
					UserID:   new(cliUser.ID),
					User:     &cliUser,
				}

				return types.Nodes{&nodeTaggedServer, &n}
			}(),
			targetNode: nodeTaggedServer,
			policy: &Policy{
				TagOwners: TagOwners{
					Tag("tag:server"): Owners{up("dave@")},
				},
				SSHs: []SSH{
					{
						Action:       "accept",
						Sources:      SSHSrcAliases{agp("autogroup:member")},
						Destinations: SSHDstAliases{tp("tag:server")},
						Users:        []SSHUser{SSHUser("localpart:*@example.com")},
					},
				},
			},
			// No localpart matches (CLI user, no email), but implicit root deny emits common rule
			want: &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.5"}},
					SSHUsers:   map[string]string{"root": ""},
					Action:     acceptAction,
				},
			}},
		},
		{
			name:       "localpart with multiple domains",
			targetNode: nodeTaggedServer,
			policy: &Policy{
				TagOwners: TagOwners{
					Tag("tag:server"): Owners{up("alice@example.com")},
				},
				SSHs: []SSH{
					{
						Action:       "accept",
						Sources:      SSHSrcAliases{agp("autogroup:member")},
						Destinations: SSHDstAliases{tp("tag:server")},
						Users: []SSHUser{
							SSHUser("localpart:*@example.com"),
							SSHUser("localpart:*@other.com"),
						},
					},
				},
			},
			// Per-user common+localpart rules interleaved:
			// alice/bob match *@example.com, charlie matches *@other.com.
			want: &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.2"}},
					SSHUsers:   map[string]string{"root": ""},
					Action:     acceptAction,
				},
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.2"}},
					SSHUsers:   map[string]string{"alice": "alice"},
					Action:     acceptAction,
				},
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.3"}},
					SSHUsers:   map[string]string{"root": ""},
					Action:     acceptAction,
				},
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.3"}},
					SSHUsers:   map[string]string{"bob": "bob"},
					Action:     acceptAction,
				},
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.4"}},
					SSHUsers:   map[string]string{"root": ""},
					Action:     acceptAction,
				},
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.4"}},
					SSHUsers:   map[string]string{"charlie": "charlie"},
					Action:     acceptAction,
				},
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.5"}},
					SSHUsers:   map[string]string{"root": ""},
					Action:     acceptAction,
				},
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testUsers := users
			if tt.users != nil {
				testUsers = tt.users
			}

			testNodes := nodes
			if tt.nodes != nil {
				testNodes = tt.nodes
			}

			require.NoError(t, tt.policy.validate())

			got, err := tt.policy.compileSSHPolicy(
				"unused-server-url", testUsers, tt.targetNode.View(), testNodes.ViewSlice(),
			)
			require.NoError(t, err)

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("compileSSHPolicy() unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}

func TestCompileSSHPolicy_CheckAction(t *testing.T) {
	users := types.Users{
		{Name: "user1", Model: gorm.Model{ID: 1}},
		{Name: "user2", Model: gorm.Model{ID: 2}},
	}

	// Use tagged nodes for SSH user mapping tests
	nodeTaggedServer := types.Node{
		Hostname: "tagged-server",
		IPv4:     createAddr("100.64.0.1"),
		UserID:   new(users[0].ID),
		User:     new(users[0]),
		Tags:     []string{"tag:server"},
	}
	nodeUser2 := types.Node{
		Hostname: "user2-device",
		IPv4:     createAddr("100.64.0.2"),
		UserID:   new(users[1].ID),
		User:     new(users[1]),
	}

	nodes := types.Nodes{&nodeTaggedServer, &nodeUser2}

	policy := &Policy{
		TagOwners: TagOwners{
			Tag("tag:server"): Owners{up("user1@")},
		},
		Groups: Groups{
			Group("group:admins"): []Username{Username("user2@")},
		},
		SSHs: []SSH{
			{
				Action:       "check",
				CheckPeriod:  &SSHCheckPeriod{Duration: 24 * time.Hour},
				Sources:      SSHSrcAliases{gp("group:admins")},
				Destinations: SSHDstAliases{tp("tag:server")},
				Users:        []SSHUser{"ssh-it-user"},
			},
		},
	}

	require.NoError(t, policy.validate())

	sshPolicy, err := policy.compileSSHPolicy("unused-server-url", users, nodeTaggedServer.View(), nodes.ViewSlice())
	require.NoError(t, err)
	require.NotNil(t, sshPolicy)
	require.Len(t, sshPolicy.Rules, 1)

	rule := sshPolicy.Rules[0]

	// Verify SSH users are correctly mapped
	expectedUsers := map[string]string{
		"ssh-it-user": "ssh-it-user",
		"root":        "",
	}
	assert.Equal(t, expectedUsers, rule.SSHUsers)

	// Verify check action: Accept is false, HoldAndDelegate is set
	assert.False(t, rule.Action.Accept)
	assert.False(t, rule.Action.Reject)
	assert.NotEmpty(t, rule.Action.HoldAndDelegate)
	assert.Contains(t, rule.Action.HoldAndDelegate, "/machine/ssh/action/")
	assert.Equal(t, 24*time.Hour, rule.Action.SessionDuration)

	// Verify check params are NOT encoded in the URL (looked up server-side).
	assert.NotContains(t, rule.Action.HoldAndDelegate, "check_explicit")
	assert.NotContains(t, rule.Action.HoldAndDelegate, "check_period")
}

// TestCompileSSHPolicy_CheckBeforeAcceptOrdering verifies that check
// (HoldAndDelegate) rules are sorted before accept rules, even when
// the accept rule appears first in the policy definition.
func TestCompileSSHPolicy_CheckBeforeAcceptOrdering(t *testing.T) {
	users := types.Users{
		{Name: "user1", Model: gorm.Model{ID: 1}},
		{Name: "user2", Model: gorm.Model{ID: 2}},
	}

	nodeTaggedServer := types.Node{
		Hostname: "tagged-server",
		IPv4:     createAddr("100.64.0.1"),
		UserID:   new(users[0].ID),
		User:     new(users[0]),
		Tags:     []string{"tag:server"},
	}
	nodeUser2 := types.Node{
		Hostname: "user2-device",
		IPv4:     createAddr("100.64.0.2"),
		UserID:   new(users[1].ID),
		User:     new(users[1]),
	}

	nodes := types.Nodes{&nodeTaggedServer, &nodeUser2}

	// Accept rule appears BEFORE check rule in policy definition.
	policy := &Policy{
		TagOwners: TagOwners{
			Tag("tag:server"): Owners{up("user1@")},
		},
		Groups: Groups{
			Group("group:admins"): []Username{Username("user2@")},
		},
		SSHs: []SSH{
			{
				Action:       "accept",
				Sources:      SSHSrcAliases{gp("group:admins")},
				Destinations: SSHDstAliases{tp("tag:server")},
				Users:        []SSHUser{"root"},
			},
			{
				Action:       "check",
				CheckPeriod:  &SSHCheckPeriod{Duration: 24 * time.Hour},
				Sources:      SSHSrcAliases{gp("group:admins")},
				Destinations: SSHDstAliases{tp("tag:server")},
				Users:        []SSHUser{"ssh-it-user"},
			},
		},
	}

	err := policy.validate()
	require.NoError(t, err)

	sshPolicy, err := policy.compileSSHPolicy(
		"unused-server-url",
		users,
		nodeTaggedServer.View(),
		nodes.ViewSlice(),
	)
	require.NoError(t, err)
	require.NotNil(t, sshPolicy)
	require.Len(t, sshPolicy.Rules, 2)

	// First rule must be the check rule (HoldAndDelegate set).
	assert.NotEmpty(t, sshPolicy.Rules[0].Action.HoldAndDelegate,
		"first rule should be check (HoldAndDelegate)")
	assert.False(t, sshPolicy.Rules[0].Action.Accept,
		"first rule should not be accept")

	// Second rule must be the accept rule.
	assert.True(t, sshPolicy.Rules[1].Action.Accept,
		"second rule should be accept")
	assert.Empty(t, sshPolicy.Rules[1].Action.HoldAndDelegate,
		"second rule should not have HoldAndDelegate")
}

// TestSSHIntegrationReproduction reproduces the exact scenario from the integration test
// TestSSHOneUserToAll that was failing with empty sshUsers.
func TestSSHIntegrationReproduction(t *testing.T) {
	// Create users matching the integration test
	users := types.Users{
		{Name: "user1", Model: gorm.Model{ID: 1}},
		{Name: "user2", Model: gorm.Model{ID: 2}},
	}

	// Create simple nodes for testing
	node1 := &types.Node{
		Hostname: "user1-node",
		IPv4:     createAddr("100.64.0.1"),
		UserID:   new(users[0].ID),
		User:     new(users[0]),
	}

	node2 := &types.Node{
		Hostname: "user2-node",
		IPv4:     createAddr("100.64.0.2"),
		UserID:   new(users[1].ID),
		User:     new(users[1]),
	}

	nodes := types.Nodes{node1, node2}

	// Create a simple policy that reproduces the issue
	// Updated to use autogroup:self instead of username destination (per Tailscale security model)
	policy := &Policy{
		Groups: Groups{
			Group("group:integration-test"): []Username{Username("user1@"), Username("user2@")},
		},
		SSHs: []SSH{
			{
				Action:       "accept",
				Sources:      SSHSrcAliases{gp("group:integration-test")},
				Destinations: SSHDstAliases{agp("autogroup:self")}, // Users can SSH to their own devices
				Users:        []SSHUser{SSHUser("ssh-it-user")},    // This is the key - specific user
			},
		},
	}

	require.NoError(t, policy.validate())

	// Test SSH policy compilation for node2 (owned by user2, who is in the group)
	got, err := policy.compileSSHPolicy("unused-server-url", users, node2.View(), nodes.ViewSlice())
	require.NoError(t, err)

	want := &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{
		{
			Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.2"}},
			SSHUsers:   map[string]string{"root": "", "ssh-it-user": "ssh-it-user"},
			Action: &tailcfg.SSHAction{
				Accept:                    true,
				AllowAgentForwarding:      true,
				AllowLocalPortForwarding:  true,
				AllowRemotePortForwarding: true,
			},
		},
	}}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("compileSSHPolicy() mismatch (-want +got):\n%s", diff)
	}
}

// TestSSHJSONSerialization verifies that the SSH policy can be properly serialized
// to JSON and that the sshUsers field is not empty.
func TestSSHJSONSerialization(t *testing.T) {
	users := types.Users{
		{Name: "user1", Model: gorm.Model{ID: 1}},
	}

	uid := uint(1)
	node := &types.Node{
		Hostname: "test-node",
		IPv4:     createAddr("100.64.0.1"),
		UserID:   &uid,
		User:     &users[0],
	}

	nodes := types.Nodes{node}

	policy := &Policy{
		SSHs: []SSH{
			{
				Action:       "accept",
				Sources:      SSHSrcAliases{up("user1@")},
				Destinations: SSHDstAliases{up("user1@")},
				Users:        []SSHUser{"ssh-it-user", "ubuntu", "admin"},
			},
		},
	}

	require.NoError(t, policy.validate())

	got, err := policy.compileSSHPolicy("unused-server-url", users, node.View(), nodes.ViewSlice())
	require.NoError(t, err)

	want := &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{
		{
			Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.1"}},
			SSHUsers:   map[string]string{"root": "", "ssh-it-user": "ssh-it-user", "ubuntu": "ubuntu", "admin": "admin"},
			Action: &tailcfg.SSHAction{
				Accept:                    true,
				AllowAgentForwarding:      true,
				AllowLocalPortForwarding:  true,
				AllowRemotePortForwarding: true,
			},
		},
	}}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("compileSSHPolicy() mismatch (-want +got):\n%s", diff)
	}

	// Verify JSON round-trip preserves the full structure
	jsonData, err := json.MarshalIndent(got, "", "  ")
	require.NoError(t, err)

	var parsed tailcfg.SSHPolicy
	require.NoError(t, json.Unmarshal(jsonData, &parsed))

	if diff := cmp.Diff(want, &parsed); diff != "" {
		t.Errorf("JSON round-trip mismatch (-want +got):\n%s", diff)
	}
}

func TestCompileFilterRulesForNodeWithAutogroupSelf(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "user1"},
		{Model: gorm.Model{ID: 2}, Name: "user2"},
	}

	nodes := types.Nodes{
		{
			User: new(users[0]),
			IPv4: ap("100.64.0.1"),
		},
		{
			User: new(users[0]),
			IPv4: ap("100.64.0.2"),
		},
		{
			User: new(users[1]),
			IPv4: ap("100.64.0.3"),
		},
		{
			User: new(users[1]),
			IPv4: ap("100.64.0.4"),
		},
		// Tagged device for user1
		{
			User: &users[0],
			IPv4: ap("100.64.0.5"),
			Tags: []string{"tag:test"},
		},
		// Tagged device for user2
		{
			User: &users[1],
			IPv4: ap("100.64.0.6"),
			Tags: []string{"tag:test"},
		},
	}

	// Test: Tailscale intended usage pattern (autogroup:member + autogroup:self)
	policy2 := &Policy{
		ACLs: []ACL{
			{
				Action:  "accept",
				Sources: []Alias{agp("autogroup:member")},
				Destinations: []AliasWithPorts{
					aliasWithPorts(agp("autogroup:self"), tailcfg.PortRangeAny),
				},
			},
		},
	}

	err := policy2.validate()
	if err != nil {
		t.Fatalf("policy validation failed: %v", err)
	}

	// Test compilation for user1's first node
	node1 := nodes[0].View()

	rules, err := policy2.compileFilterRulesForNode(users, node1, nodes.ViewSlice())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}

	// Check that the rule includes:
	// - Sources: only user1's untagged devices (filtered by autogroup:self semantics)
	// - Destinations: only user1's untagged devices (autogroup:self)
	rule := rules[0]

	// Sources should ONLY include user1's untagged devices (100.64.0.1, 100.64.0.2)
	expectedSourceIPs := []string{"100.64.0.1", "100.64.0.2"}

	for _, expectedIP := range expectedSourceIPs {
		found := false

		addr := netip.MustParseAddr(expectedIP)

		for _, prefix := range rule.SrcIPs {
			pref := netip.MustParsePrefix(prefix)
			if pref.Contains(addr) {
				found = true
				break
			}
		}

		if !found {
			t.Errorf("expected source IP %s to be covered by generated prefixes %v", expectedIP, rule.SrcIPs)
		}
	}

	// Verify that other users' devices and tagged devices are not included in sources
	excludedSourceIPs := []string{"100.64.0.3", "100.64.0.4", "100.64.0.5", "100.64.0.6"}
	for _, excludedIP := range excludedSourceIPs {
		addr := netip.MustParseAddr(excludedIP)

		for _, prefix := range rule.SrcIPs {
			pref := netip.MustParsePrefix(prefix)
			if pref.Contains(addr) {
				t.Errorf("SECURITY VIOLATION: source IP %s should not be included but found in prefix %s", excludedIP, prefix)
			}
		}
	}

	expectedDestIPs := []string{"100.64.0.1/32", "100.64.0.2/32"}

	actualDestIPs := make([]string, 0, len(rule.DstPorts))
	for _, dst := range rule.DstPorts {
		actualDestIPs = append(actualDestIPs, dst.IP)
	}

	for _, expectedIP := range expectedDestIPs {
		found := slices.Contains(actualDestIPs, expectedIP)

		if !found {
			t.Errorf("expected destination IP %s to be included, got: %v", expectedIP, actualDestIPs)
		}
	}

	// Verify that other users' devices and tagged devices are not in destinations
	excludedDestIPs := []string{"100.64.0.3/32", "100.64.0.4/32", "100.64.0.5/32", "100.64.0.6/32"}
	for _, excludedIP := range excludedDestIPs {
		for _, actualIP := range actualDestIPs {
			if actualIP == excludedIP {
				t.Errorf("SECURITY: destination IP %s should not be included but found in destinations", excludedIP)
			}
		}
	}
}

// TestTagUserMutualExclusivity tests that user-owned nodes and tagged nodes
// are treated as separate identity classes and cannot inadvertently access each other.
func TestTagUserMutualExclusivity(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "user1"},
		{Model: gorm.Model{ID: 2}, Name: "user2"},
	}

	nodes := types.Nodes{
		// User-owned nodes
		{
			User: new(users[0]),
			IPv4: ap("100.64.0.1"),
		},
		{
			User: new(users[1]),
			IPv4: ap("100.64.0.2"),
		},
		// Tagged nodes
		{
			User: &users[0], // "created by" tracking
			IPv4: ap("100.64.0.10"),
			Tags: []string{"tag:server"},
		},
		{
			User: &users[1], // "created by" tracking
			IPv4: ap("100.64.0.11"),
			Tags: []string{"tag:database"},
		},
	}

	policy := &Policy{
		TagOwners: TagOwners{
			Tag("tag:server"):   Owners{new(Username("user1@"))},
			Tag("tag:database"): Owners{new(Username("user2@"))},
		},
		ACLs: []ACL{
			// Rule 1: user1 (user-owned) should NOT be able to reach tagged nodes
			{
				Action:  "accept",
				Sources: []Alias{up("user1@")},
				Destinations: []AliasWithPorts{
					aliasWithPorts(tp("tag:server"), tailcfg.PortRangeAny),
				},
			},
			// Rule 2: tag:server should be able to reach tag:database
			{
				Action:  "accept",
				Sources: []Alias{tp("tag:server")},
				Destinations: []AliasWithPorts{
					aliasWithPorts(tp("tag:database"), tailcfg.PortRangeAny),
				},
			},
		},
	}

	err := policy.validate()
	if err != nil {
		t.Fatalf("policy validation failed: %v", err)
	}

	// Test user1's user-owned node (100.64.0.1)
	userNode := nodes[0].View()

	userRules, err := policy.compileFilterRulesForNode(users, userNode, nodes.ViewSlice())
	if err != nil {
		t.Fatalf("unexpected error for user node: %v", err)
	}

	// User1's user-owned node should NOT reach tag:server (100.64.0.10)
	// because user1@ as a source only matches user1's user-owned devices, NOT tagged devices
	for _, rule := range userRules {
		for _, dst := range rule.DstPorts {
			if dst.IP == "100.64.0.10" {
				t.Errorf("SECURITY: user-owned node should NOT reach tagged node (got dest %s in rule)", dst.IP)
			}
		}
	}

	// Test tag:server node (100.64.0.10)
	// compileFilterRulesForNode returns rules for what the node can ACCESS (as source)
	taggedNode := nodes[2].View()

	taggedRules, err := policy.compileFilterRulesForNode(users, taggedNode, nodes.ViewSlice())
	if err != nil {
		t.Fatalf("unexpected error for tagged node: %v", err)
	}

	// Tag:server (as source) should be able to reach tag:database (100.64.0.11)
	// Check destinations in the rules for this node
	foundDatabaseDest := false

	for _, rule := range taggedRules {
		// Check if this rule applies to tag:server as source
		if !slices.Contains(rule.SrcIPs, "100.64.0.10/32") {
			continue
		}

		// Check if tag:database is in destinations
		for _, dst := range rule.DstPorts {
			if dst.IP == "100.64.0.11/32" {
				foundDatabaseDest = true
				break
			}
		}

		if foundDatabaseDest {
			break
		}
	}

	if !foundDatabaseDest {
		t.Errorf("tag:server should reach tag:database but didn't find 100.64.0.11 in destinations")
	}
}

// TestAutogroupTagged tests that autogroup:tagged correctly selects all devices
// with tag-based identity (IsTagged() == true or has requested tags in tagOwners).
func TestAutogroupTagged(t *testing.T) {
	t.Parallel()

	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "user1"},
		{Model: gorm.Model{ID: 2}, Name: "user2"},
	}

	nodes := types.Nodes{
		// User-owned nodes (not tagged)
		{
			User: new(users[0]),
			IPv4: ap("100.64.0.1"),
		},
		{
			User: new(users[1]),
			IPv4: ap("100.64.0.2"),
		},
		// Tagged nodes
		{
			User: &users[0], // "created by" tracking
			IPv4: ap("100.64.0.10"),
			Tags: []string{"tag:server"},
		},
		{
			User: &users[1], // "created by" tracking
			IPv4: ap("100.64.0.11"),
			Tags: []string{"tag:database"},
		},
		{
			User: &users[0],
			IPv4: ap("100.64.0.12"),
			Tags: []string{"tag:web", "tag:prod"},
		},
	}

	policy := &Policy{
		TagOwners: TagOwners{
			Tag("tag:server"):   Owners{new(Username("user1@"))},
			Tag("tag:database"): Owners{new(Username("user2@"))},
			Tag("tag:web"):      Owners{new(Username("user1@"))},
			Tag("tag:prod"):     Owners{new(Username("user1@"))},
		},
		ACLs: []ACL{
			// Rule: autogroup:tagged can reach user-owned nodes
			{
				Action:  "accept",
				Sources: []Alias{agp("autogroup:tagged")},
				Destinations: []AliasWithPorts{
					aliasWithPorts(up("user1@"), tailcfg.PortRangeAny),
					aliasWithPorts(up("user2@"), tailcfg.PortRangeAny),
				},
			},
		},
	}

	err := policy.validate()
	require.NoError(t, err)

	// Verify autogroup:tagged includes all tagged nodes
	ag := AutoGroupTagged
	taggedIPs, err := ag.Resolve(policy, users, nodes.ViewSlice())
	require.NoError(t, err)
	require.NotNil(t, taggedIPs)

	// Should contain all tagged nodes
	assert.True(t, taggedIPs.Contains(*ap("100.64.0.10")), "should include tag:server")
	assert.True(t, taggedIPs.Contains(*ap("100.64.0.11")), "should include tag:database")
	assert.True(t, taggedIPs.Contains(*ap("100.64.0.12")), "should include tag:web,tag:prod")

	// Should NOT contain user-owned nodes
	assert.False(t, taggedIPs.Contains(*ap("100.64.0.1")), "should not include user1 node")
	assert.False(t, taggedIPs.Contains(*ap("100.64.0.2")), "should not include user2 node")

	// Test ACL filtering: all tagged nodes should be able to reach user nodes
	tests := []struct {
		name        string
		sourceNode  types.NodeView
		shouldReach []string // IP strings for comparison
	}{
		{
			name:        "tag:server can reach user-owned nodes",
			sourceNode:  nodes[2].View(),
			shouldReach: []string{"100.64.0.1", "100.64.0.2"},
		},
		{
			name:        "tag:database can reach user-owned nodes",
			sourceNode:  nodes[3].View(),
			shouldReach: []string{"100.64.0.1", "100.64.0.2"},
		},
		{
			name:        "tag:web,tag:prod can reach user-owned nodes",
			sourceNode:  nodes[4].View(),
			shouldReach: []string{"100.64.0.1", "100.64.0.2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rules, err := policy.compileFilterRulesForNode(users, tt.sourceNode, nodes.ViewSlice())
			require.NoError(t, err)

			// Verify all expected destinations are reachable
			for _, expectedDest := range tt.shouldReach {
				found := false

				for _, rule := range rules {
					for _, dstPort := range rule.DstPorts {
						// DstPort.IP is CIDR notation like "100.64.0.1/32"
						if strings.HasPrefix(dstPort.IP, expectedDest+"/") || dstPort.IP == expectedDest {
							found = true
							break
						}
					}

					if found {
						break
					}
				}

				assert.True(t, found, "Expected to find destination %s in rules", expectedDest)
			}
		})
	}
}

func TestAutogroupSelfInSourceIsRejected(t *testing.T) {
	// Test that autogroup:self cannot be used in sources (per Tailscale spec)
	policy := &Policy{
		ACLs: []ACL{
			{
				Action:  "accept",
				Sources: []Alias{agp("autogroup:self")},
				Destinations: []AliasWithPorts{
					aliasWithPorts(agp("autogroup:member"), tailcfg.PortRangeAny),
				},
			},
		},
	}

	err := policy.validate()
	if err == nil {
		t.Error("expected validation error when using autogroup:self in sources")
	}

	if !strings.Contains(err.Error(), "autogroup:self") {
		t.Errorf("expected error message to mention autogroup:self, got: %v", err)
	}
}

// TestAutogroupSelfWithSpecificUserSource verifies that when autogroup:self is in
// the destination and a specific user is in the source, only that user's devices
// are allowed (and only if they match the target user).
func TestAutogroupSelfWithSpecificUserSource(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "user1"},
		{Model: gorm.Model{ID: 2}, Name: "user2"},
	}

	nodes := types.Nodes{
		{User: new(users[0]), IPv4: ap("100.64.0.1")},
		{User: new(users[0]), IPv4: ap("100.64.0.2")},
		{User: new(users[1]), IPv4: ap("100.64.0.3")},
		{User: new(users[1]), IPv4: ap("100.64.0.4")},
	}

	policy := &Policy{
		ACLs: []ACL{
			{
				Action:  "accept",
				Sources: []Alias{up("user1@")},
				Destinations: []AliasWithPorts{
					aliasWithPorts(agp("autogroup:self"), tailcfg.PortRangeAny),
				},
			},
		},
	}

	err := policy.validate()
	require.NoError(t, err)

	// For user1's node: sources should be user1's devices
	node1 := nodes[0].View()
	rules, err := policy.compileFilterRulesForNode(users, node1, nodes.ViewSlice())
	require.NoError(t, err)
	require.Len(t, rules, 1)

	expectedSourceIPs := []string{"100.64.0.1", "100.64.0.2"}
	for _, expectedIP := range expectedSourceIPs {
		found := false
		addr := netip.MustParseAddr(expectedIP)

		for _, prefix := range rules[0].SrcIPs {
			pref := netip.MustParsePrefix(prefix)
			if pref.Contains(addr) {
				found = true
				break
			}
		}

		assert.True(t, found, "expected source IP %s to be present", expectedIP)
	}

	actualDestIPs := make([]string, 0, len(rules[0].DstPorts))
	for _, dst := range rules[0].DstPorts {
		actualDestIPs = append(actualDestIPs, dst.IP)
	}

	expectedDestIPs := []string{"100.64.0.1/32", "100.64.0.2/32"}
	assert.ElementsMatch(t, expectedDestIPs, actualDestIPs)

	node2 := nodes[2].View()
	rules2, err := policy.compileFilterRulesForNode(users, node2, nodes.ViewSlice())
	require.NoError(t, err)
	assert.Empty(t, rules2, "user2's node should have no rules (user1@ devices can't match user2's self)")
}

// TestAutogroupSelfWithGroupSource verifies that when a group is used as source
// and autogroup:self as destination, only group members who are the same user
// as the target are allowed.
func TestAutogroupSelfWithGroupSource(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "user1"},
		{Model: gorm.Model{ID: 2}, Name: "user2"},
		{Model: gorm.Model{ID: 3}, Name: "user3"},
	}

	nodes := types.Nodes{
		{User: new(users[0]), IPv4: ap("100.64.0.1")},
		{User: new(users[0]), IPv4: ap("100.64.0.2")},
		{User: new(users[1]), IPv4: ap("100.64.0.3")},
		{User: new(users[1]), IPv4: ap("100.64.0.4")},
		{User: new(users[2]), IPv4: ap("100.64.0.5")},
	}

	policy := &Policy{
		Groups: Groups{
			Group("group:admins"): []Username{Username("user1@"), Username("user2@")},
		},
		ACLs: []ACL{
			{
				Action:  "accept",
				Sources: []Alias{gp("group:admins")},
				Destinations: []AliasWithPorts{
					aliasWithPorts(agp("autogroup:self"), tailcfg.PortRangeAny),
				},
			},
		},
	}

	err := policy.validate()
	require.NoError(t, err)

	// (group:admins has user1+user2, but autogroup:self filters to same user)
	node1 := nodes[0].View()
	rules, err := policy.compileFilterRulesForNode(users, node1, nodes.ViewSlice())
	require.NoError(t, err)
	require.Len(t, rules, 1)

	expectedSrcIPs := []string{"100.64.0.1", "100.64.0.2"}
	for _, expectedIP := range expectedSrcIPs {
		found := false
		addr := netip.MustParseAddr(expectedIP)

		for _, prefix := range rules[0].SrcIPs {
			pref := netip.MustParsePrefix(prefix)
			if pref.Contains(addr) {
				found = true
				break
			}
		}

		assert.True(t, found, "expected source IP %s for user1", expectedIP)
	}

	node3 := nodes[4].View()
	rules3, err := policy.compileFilterRulesForNode(users, node3, nodes.ViewSlice())
	require.NoError(t, err)
	assert.Empty(t, rules3, "user3 should have no rules")
}

// Helper function to create IP addresses for testing.
func createAddr(ip string) *netip.Addr {
	addr, _ := netip.ParseAddr(ip)
	return &addr
}

// TestSSHWithAutogroupSelfInDestination verifies that SSH policies work correctly
// with autogroup:self in destinations.
func TestSSHWithAutogroupSelfInDestination(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "user1"},
		{Model: gorm.Model{ID: 2}, Name: "user2"},
	}

	nodes := types.Nodes{
		// User1's nodes
		{User: new(users[0]), IPv4: ap("100.64.0.1"), Hostname: "user1-node1"},
		{User: new(users[0]), IPv4: ap("100.64.0.2"), Hostname: "user1-node2"},
		// User2's nodes
		{User: new(users[1]), IPv4: ap("100.64.0.3"), Hostname: "user2-node1"},
		{User: new(users[1]), IPv4: ap("100.64.0.4"), Hostname: "user2-node2"},
		// Tagged node for user1 (should be excluded)
		{User: new(users[0]), IPv4: ap("100.64.0.5"), Hostname: "user1-tagged", Tags: []string{"tag:server"}},
	}

	policy := &Policy{
		SSHs: []SSH{
			{
				Action:       "accept",
				Sources:      SSHSrcAliases{agp("autogroup:member")},
				Destinations: SSHDstAliases{agp("autogroup:self")},
				Users:        []SSHUser{"autogroup:nonroot"},
			},
		},
	}

	err := policy.validate()
	require.NoError(t, err)

	// Test for user1's first node
	node1 := nodes[0].View()
	sshPolicy, err := policy.compileSSHPolicy("unused-server-url", users, node1, nodes.ViewSlice())
	require.NoError(t, err)
	require.NotNil(t, sshPolicy)
	require.Len(t, sshPolicy.Rules, 1)

	rule := sshPolicy.Rules[0]

	// Principals should only include user1's untagged devices
	require.Len(t, rule.Principals, 2, "should have 2 principals (user1's 2 untagged nodes)")

	principalIPs := make([]string, len(rule.Principals))
	for i, p := range rule.Principals {
		principalIPs[i] = p.NodeIP
	}

	assert.ElementsMatch(t, []string{"100.64.0.1", "100.64.0.2"}, principalIPs)

	// Test for user2's first node
	node3 := nodes[2].View()
	sshPolicy2, err := policy.compileSSHPolicy("unused-server-url", users, node3, nodes.ViewSlice())
	require.NoError(t, err)
	require.NotNil(t, sshPolicy2)
	require.Len(t, sshPolicy2.Rules, 1)

	rule2 := sshPolicy2.Rules[0]

	// Principals should only include user2's untagged devices
	require.Len(t, rule2.Principals, 2, "should have 2 principals (user2's 2 untagged nodes)")

	principalIPs2 := make([]string, len(rule2.Principals))
	for i, p := range rule2.Principals {
		principalIPs2[i] = p.NodeIP
	}

	assert.ElementsMatch(t, []string{"100.64.0.3", "100.64.0.4"}, principalIPs2)

	// Test for tagged node (should have no SSH rules)
	node5 := nodes[4].View()
	sshPolicy3, err := policy.compileSSHPolicy("unused-server-url", users, node5, nodes.ViewSlice())
	require.NoError(t, err)

	if sshPolicy3 != nil {
		assert.Empty(t, sshPolicy3.Rules, "tagged nodes should not get SSH rules with autogroup:self")
	}
}

// TestSSHWithAutogroupSelfAndSpecificUser verifies that when a specific user
// is in the source and autogroup:self in destination, only that user's devices
// can SSH (and only if they match the target user).
func TestSSHWithAutogroupSelfAndSpecificUser(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "user1"},
		{Model: gorm.Model{ID: 2}, Name: "user2"},
	}

	nodes := types.Nodes{
		{User: new(users[0]), IPv4: ap("100.64.0.1")},
		{User: new(users[0]), IPv4: ap("100.64.0.2")},
		{User: new(users[1]), IPv4: ap("100.64.0.3")},
		{User: new(users[1]), IPv4: ap("100.64.0.4")},
	}

	policy := &Policy{
		SSHs: []SSH{
			{
				Action:       "accept",
				Sources:      SSHSrcAliases{up("user1@")},
				Destinations: SSHDstAliases{agp("autogroup:self")},
				Users:        []SSHUser{"ubuntu"},
			},
		},
	}

	err := policy.validate()
	require.NoError(t, err)

	// For user1's node: should allow SSH from user1's devices
	node1 := nodes[0].View()
	sshPolicy, err := policy.compileSSHPolicy("unused-server-url", users, node1, nodes.ViewSlice())
	require.NoError(t, err)
	require.NotNil(t, sshPolicy)
	require.Len(t, sshPolicy.Rules, 1)

	rule := sshPolicy.Rules[0]
	require.Len(t, rule.Principals, 2, "user1 should have 2 principals")

	principalIPs := make([]string, len(rule.Principals))
	for i, p := range rule.Principals {
		principalIPs[i] = p.NodeIP
	}

	assert.ElementsMatch(t, []string{"100.64.0.1", "100.64.0.2"}, principalIPs)

	// For user2's node: should have no rules (user1's devices can't match user2's self)
	node3 := nodes[2].View()
	sshPolicy2, err := policy.compileSSHPolicy("unused-server-url", users, node3, nodes.ViewSlice())
	require.NoError(t, err)

	if sshPolicy2 != nil {
		assert.Empty(t, sshPolicy2.Rules, "user2 should have no SSH rules since source is user1")
	}
}

// TestSSHWithAutogroupSelfAndGroup verifies SSH with group sources and autogroup:self destinations.
func TestSSHWithAutogroupSelfAndGroup(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "user1"},
		{Model: gorm.Model{ID: 2}, Name: "user2"},
		{Model: gorm.Model{ID: 3}, Name: "user3"},
	}

	nodes := types.Nodes{
		{User: new(users[0]), IPv4: ap("100.64.0.1")},
		{User: new(users[0]), IPv4: ap("100.64.0.2")},
		{User: new(users[1]), IPv4: ap("100.64.0.3")},
		{User: new(users[1]), IPv4: ap("100.64.0.4")},
		{User: new(users[2]), IPv4: ap("100.64.0.5")},
	}

	policy := &Policy{
		Groups: Groups{
			Group("group:admins"): []Username{Username("user1@"), Username("user2@")},
		},
		SSHs: []SSH{
			{
				Action:       "accept",
				Sources:      SSHSrcAliases{gp("group:admins")},
				Destinations: SSHDstAliases{agp("autogroup:self")},
				Users:        []SSHUser{"root"},
			},
		},
	}

	err := policy.validate()
	require.NoError(t, err)

	// For user1's node: should allow SSH from user1's devices only (not user2's)
	node1 := nodes[0].View()
	sshPolicy, err := policy.compileSSHPolicy("unused-server-url", users, node1, nodes.ViewSlice())
	require.NoError(t, err)
	require.NotNil(t, sshPolicy)
	require.Len(t, sshPolicy.Rules, 1)

	rule := sshPolicy.Rules[0]
	require.Len(t, rule.Principals, 2, "user1 should have 2 principals (only user1's nodes)")

	principalIPs := make([]string, len(rule.Principals))
	for i, p := range rule.Principals {
		principalIPs[i] = p.NodeIP
	}

	assert.ElementsMatch(t, []string{"100.64.0.1", "100.64.0.2"}, principalIPs)

	// For user3's node: should have no rules (not in group:admins)
	node5 := nodes[4].View()
	sshPolicy2, err := policy.compileSSHPolicy("unused-server-url", users, node5, nodes.ViewSlice())
	require.NoError(t, err)

	if sshPolicy2 != nil {
		assert.Empty(t, sshPolicy2.Rules, "user3 should have no SSH rules (not in group)")
	}
}

// TestSSHWithAutogroupSelfExcludesTaggedDevices verifies that tagged devices
// are excluded from both sources and destinations when autogroup:self is used.
func TestSSHWithAutogroupSelfExcludesTaggedDevices(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "user1"},
	}

	nodes := types.Nodes{
		{User: new(users[0]), IPv4: ap("100.64.0.1"), Hostname: "untagged1"},
		{User: new(users[0]), IPv4: ap("100.64.0.2"), Hostname: "untagged2"},
		{User: new(users[0]), IPv4: ap("100.64.0.3"), Hostname: "tagged1", Tags: []string{"tag:server"}},
		{User: new(users[0]), IPv4: ap("100.64.0.4"), Hostname: "tagged2", Tags: []string{"tag:web"}},
	}

	policy := &Policy{
		TagOwners: TagOwners{
			Tag("tag:server"): Owners{up("user1@")},
			Tag("tag:web"):    Owners{up("user1@")},
		},
		SSHs: []SSH{
			{
				Action:       "accept",
				Sources:      SSHSrcAliases{agp("autogroup:member")},
				Destinations: SSHDstAliases{agp("autogroup:self")},
				Users:        []SSHUser{"admin"},
			},
		},
	}

	err := policy.validate()
	require.NoError(t, err)

	// For untagged node: should only get principals from other untagged nodes
	node1 := nodes[0].View()
	sshPolicy, err := policy.compileSSHPolicy("unused-server-url", users, node1, nodes.ViewSlice())
	require.NoError(t, err)
	require.NotNil(t, sshPolicy)
	require.Len(t, sshPolicy.Rules, 1)

	rule := sshPolicy.Rules[0]
	require.Len(t, rule.Principals, 2, "should only have 2 principals (untagged nodes)")

	principalIPs := make([]string, len(rule.Principals))
	for i, p := range rule.Principals {
		principalIPs[i] = p.NodeIP
	}

	assert.ElementsMatch(t, []string{"100.64.0.1", "100.64.0.2"}, principalIPs,
		"should only include untagged devices")

	// For tagged node: should get no SSH rules
	node3 := nodes[2].View()
	sshPolicy2, err := policy.compileSSHPolicy("unused-server-url", users, node3, nodes.ViewSlice())
	require.NoError(t, err)

	if sshPolicy2 != nil {
		assert.Empty(t, sshPolicy2.Rules, "tagged node should get no SSH rules with autogroup:self")
	}
}

// TestSSHWithAutogroupSelfAndMixedDestinations tests that SSH rules can have both
// autogroup:self and other destinations (like tag:router) in the same rule, and that
// autogroup:self filtering only applies to autogroup:self destinations, not others.
func TestSSHWithAutogroupSelfAndMixedDestinations(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "user1"},
		{Model: gorm.Model{ID: 2}, Name: "user2"},
	}

	nodes := types.Nodes{
		{User: new(users[0]), IPv4: ap("100.64.0.1"), Hostname: "user1-device"},
		{User: new(users[0]), IPv4: ap("100.64.0.2"), Hostname: "user1-device2"},
		{User: new(users[1]), IPv4: ap("100.64.0.3"), Hostname: "user2-device"},
		{User: new(users[1]), IPv4: ap("100.64.0.4"), Hostname: "user2-router", Tags: []string{"tag:router"}},
	}

	policy := &Policy{
		TagOwners: TagOwners{
			Tag("tag:router"): Owners{up("user2@")},
		},
		SSHs: []SSH{
			{
				Action:       "accept",
				Sources:      SSHSrcAliases{agp("autogroup:member")},
				Destinations: SSHDstAliases{agp("autogroup:self"), tp("tag:router")},
				Users:        []SSHUser{"admin"},
			},
		},
	}

	err := policy.validate()
	require.NoError(t, err)

	// Test 1: Compile for user1's device (should only match autogroup:self destination)
	node1 := nodes[0].View()
	sshPolicy1, err := policy.compileSSHPolicy("unused-server-url", users, node1, nodes.ViewSlice())
	require.NoError(t, err)
	require.NotNil(t, sshPolicy1)
	require.Len(t, sshPolicy1.Rules, 1, "user1's device should have 1 SSH rule (autogroup:self)")

	// Verify autogroup:self rule has filtered sources (only same-user devices)
	selfRule := sshPolicy1.Rules[0]
	require.Len(t, selfRule.Principals, 2, "autogroup:self rule should only have user1's devices")

	selfPrincipals := make([]string, len(selfRule.Principals))
	for i, p := range selfRule.Principals {
		selfPrincipals[i] = p.NodeIP
	}

	require.ElementsMatch(t, []string{"100.64.0.1", "100.64.0.2"}, selfPrincipals,
		"autogroup:self rule should only include same-user untagged devices")

	// Test 2: Compile for router (should only match tag:router destination)
	routerNode := nodes[3].View() // user2-router
	sshPolicyRouter, err := policy.compileSSHPolicy("unused-server-url", users, routerNode, nodes.ViewSlice())
	require.NoError(t, err)
	require.NotNil(t, sshPolicyRouter)
	require.Len(t, sshPolicyRouter.Rules, 1, "router should have 1 SSH rule (tag:router)")

	routerRule := sshPolicyRouter.Rules[0]

	routerPrincipals := make([]string, len(routerRule.Principals))
	for i, p := range routerRule.Principals {
		routerPrincipals[i] = p.NodeIP
	}

	require.Contains(t, routerPrincipals, "100.64.0.1", "router rule should include user1's device (unfiltered sources)")
	require.Contains(t, routerPrincipals, "100.64.0.2", "router rule should include user1's other device (unfiltered sources)")
	require.Contains(t, routerPrincipals, "100.64.0.3", "router rule should include user2's device (unfiltered sources)")
}

// TestAutogroupSelfWithNonExistentUserInGroup verifies that when a group
// contains a non-existent user, partial resolution still works correctly.
// This reproduces the issue from https://github.com/juanfont/headscale/issues/2990
// where autogroup:self breaks when groups contain users that don't have
// registered nodes.
func TestAutogroupSelfWithNonExistentUserInGroup(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "superadmin"},
		{Model: gorm.Model{ID: 2}, Name: "admin"},
		{Model: gorm.Model{ID: 3}, Name: "direction"},
	}

	nodes := types.Nodes{
		// superadmin's device
		{ID: 1, User: new(users[0]), IPv4: ap("100.64.0.1"), Hostname: "superadmin-device"},
		// admin's device
		{ID: 2, User: new(users[1]), IPv4: ap("100.64.0.2"), Hostname: "admin-device"},
		// direction's device
		{ID: 3, User: new(users[2]), IPv4: ap("100.64.0.3"), Hostname: "direction-device"},
		// tagged servers
		{ID: 4, IPv4: ap("100.64.0.10"), Hostname: "common-server", Tags: []string{"tag:common"}},
		{ID: 5, IPv4: ap("100.64.0.11"), Hostname: "tech-server", Tags: []string{"tag:tech"}},
		{ID: 6, IPv4: ap("100.64.0.12"), Hostname: "privileged-server", Tags: []string{"tag:privileged"}},
	}

	policy := &Policy{
		Groups: Groups{
			// group:superadmin contains "phantom_user" who doesn't exist
			Group("group:superadmin"): []Username{Username("superadmin@"), Username("phantom_user@")},
			Group("group:admin"):      []Username{Username("admin@")},
			Group("group:direction"):  []Username{Username("direction@")},
		},
		TagOwners: TagOwners{
			Tag("tag:common"):     Owners{gp("group:superadmin")},
			Tag("tag:tech"):       Owners{gp("group:superadmin")},
			Tag("tag:privileged"): Owners{gp("group:superadmin")},
		},
		ACLs: []ACL{
			{
				// Rule 1: all groups -> tag:common
				Action:  "accept",
				Sources: []Alias{gp("group:superadmin"), gp("group:admin"), gp("group:direction")},
				Destinations: []AliasWithPorts{
					aliasWithPorts(tp("tag:common"), tailcfg.PortRangeAny),
				},
			},
			{
				// Rule 2: superadmin + admin -> tag:tech
				Action:  "accept",
				Sources: []Alias{gp("group:superadmin"), gp("group:admin")},
				Destinations: []AliasWithPorts{
					aliasWithPorts(tp("tag:tech"), tailcfg.PortRangeAny),
				},
			},
			{
				// Rule 3: superadmin -> tag:privileged + autogroup:self
				Action:  "accept",
				Sources: []Alias{gp("group:superadmin")},
				Destinations: []AliasWithPorts{
					aliasWithPorts(tp("tag:privileged"), tailcfg.PortRangeAny),
					aliasWithPorts(agp("autogroup:self"), tailcfg.PortRangeAny),
				},
			},
		},
	}

	err := policy.validate()
	require.NoError(t, err)

	containsIP := func(rules []tailcfg.FilterRule, ip string) bool {
		addr := netip.MustParseAddr(ip)

		for _, rule := range rules {
			for _, dp := range rule.DstPorts {
				// DstPort IPs may be bare addresses or CIDR prefixes
				pref, err := netip.ParsePrefix(dp.IP)
				if err != nil {
					// Try as bare address
					a, err2 := netip.ParseAddr(dp.IP)
					if err2 != nil {
						continue
					}

					if a == addr {
						return true
					}

					continue
				}

				if pref.Contains(addr) {
					return true
				}
			}
		}

		return false
	}

	containsSrcIP := func(rules []tailcfg.FilterRule, ip string) bool {
		addr := netip.MustParseAddr(ip)

		for _, rule := range rules {
			for _, srcIP := range rule.SrcIPs {
				pref, err := netip.ParsePrefix(srcIP)
				if err != nil {
					a, err2 := netip.ParseAddr(srcIP)
					if err2 != nil {
						continue
					}

					if a == addr {
						return true
					}

					continue
				}

				if pref.Contains(addr) {
					return true
				}
			}
		}

		return false
	}

	// Test superadmin's device: should have rules with tag:common, tag:tech, tag:privileged destinations
	// and superadmin's IP should appear in sources (partial resolution of group:superadmin works)
	superadminNode := nodes[0].View()
	superadminRules, err := policy.compileFilterRulesForNode(users, superadminNode, nodes.ViewSlice())
	require.NoError(t, err)
	assert.True(t, containsIP(superadminRules, "100.64.0.10"), "rules should include tag:common server")
	assert.True(t, containsIP(superadminRules, "100.64.0.11"), "rules should include tag:tech server")
	assert.True(t, containsIP(superadminRules, "100.64.0.12"), "rules should include tag:privileged server")

	// Key assertion: superadmin's IP should appear as a source in rules
	// despite phantom_user in group:superadmin causing a partial resolution error
	assert.True(t, containsSrcIP(superadminRules, "100.64.0.1"),
		"superadmin's IP should appear in sources despite phantom_user in group:superadmin")

	// Test admin's device: admin is in group:admin which has NO phantom users.
	// The key bug was: when group:superadmin (with phantom_user) appeared as a source
	// alongside group:admin, the error from resolving group:superadmin caused its
	// partial result to be discarded via `continue`. With the fix, superadmin's IPs
	// from group:superadmin are retained alongside admin's IPs from group:admin.
	adminNode := nodes[1].View()
	adminRules, err := policy.compileFilterRulesForNode(users, adminNode, nodes.ViewSlice())
	require.NoError(t, err)

	// Rule 1 sources: [group:superadmin, group:admin, group:direction]
	// Without fix: group:superadmin discarded -> only admin + direction IPs in sources
	// With fix: superadmin IP preserved -> superadmin + admin + direction IPs in sources
	assert.True(t, containsIP(adminRules, "100.64.0.10"),
		"admin rules should include tag:common server (group:admin resolves correctly)")
	assert.True(t, containsSrcIP(adminRules, "100.64.0.1"),
		"superadmin's IP should be in sources for rules seen by admin (partial resolution preserved)")
	assert.True(t, containsSrcIP(adminRules, "100.64.0.2"),
		"admin's own IP should be in sources")

	// Test direction's device: similar to admin, verifies group:direction sources work
	directionNode := nodes[2].View()
	directionRules, err := policy.compileFilterRulesForNode(users, directionNode, nodes.ViewSlice())
	require.NoError(t, err)
	assert.True(t, containsIP(directionRules, "100.64.0.10"),
		"direction rules should include tag:common server")
	assert.True(t, containsSrcIP(directionRules, "100.64.0.3"),
		"direction's own IP should be in sources")
	// With fix: superadmin's IP preserved in rules that include group:superadmin
	assert.True(t, containsSrcIP(directionRules, "100.64.0.1"),
		"superadmin's IP should be in sources for rule 1 (partial resolution preserved)")
}

func TestMergeFilterRules(t *testing.T) {
	tests := []struct {
		name  string
		input []tailcfg.FilterRule
		want  []tailcfg.FilterRule
	}{
		{
			name:  "empty input",
			input: []tailcfg.FilterRule{},
			want:  []tailcfg.FilterRule{},
		},
		{
			name: "single rule unchanged",
			input: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.1/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.2/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
					},
					IPProto: []int{ProtocolTCP},
				},
			},
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.1/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.2/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
					},
					IPProto: []int{ProtocolTCP},
				},
			},
		},
		{
			name: "merge two rules with same key",
			input: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.1/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.2/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
					},
					IPProto: []int{ProtocolTCP, ProtocolUDP},
				},
				{
					SrcIPs: []string{"100.64.0.1/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.2/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
					},
					IPProto: []int{ProtocolTCP, ProtocolUDP},
				},
			},
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.1/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.2/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						{IP: "100.64.0.2/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
					},
					IPProto: []int{ProtocolTCP, ProtocolUDP},
				},
			},
		},
		{
			name: "different SrcIPs not merged",
			input: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.1/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.3/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
					},
					IPProto: []int{ProtocolTCP},
				},
				{
					SrcIPs: []string{"100.64.0.2/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.3/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
					},
					IPProto: []int{ProtocolTCP},
				},
			},
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.1/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.3/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
					},
					IPProto: []int{ProtocolTCP},
				},
				{
					SrcIPs: []string{"100.64.0.2/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.3/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
					},
					IPProto: []int{ProtocolTCP},
				},
			},
		},
		{
			name: "different IPProto not merged",
			input: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.1/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.2/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
					},
					IPProto: []int{ProtocolTCP},
				},
				{
					SrcIPs: []string{"100.64.0.1/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.2/32", Ports: tailcfg.PortRange{First: 53, Last: 53}},
					},
					IPProto: []int{ProtocolUDP},
				},
			},
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.1/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.2/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
					},
					IPProto: []int{ProtocolTCP},
				},
				{
					SrcIPs: []string{"100.64.0.1/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.2/32", Ports: tailcfg.PortRange{First: 53, Last: 53}},
					},
					IPProto: []int{ProtocolUDP},
				},
			},
		},
		{
			name: "DstPorts combined without deduplication",
			input: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.1/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.2/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
					},
					IPProto: []int{ProtocolTCP},
				},
				{
					SrcIPs: []string{"100.64.0.1/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.2/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
					},
					IPProto: []int{ProtocolTCP},
				},
			},
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.1/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.2/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						{IP: "100.64.0.2/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
					},
					IPProto: []int{ProtocolTCP},
				},
			},
		},
		{
			name: "merge three rules with same key",
			input: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.1/32", "100.64.0.2/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.3/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
					},
					IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
				},
				{
					SrcIPs: []string{"100.64.0.1/32", "100.64.0.2/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.3/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
					},
					IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
				},
				{
					SrcIPs: []string{"100.64.0.1/32", "100.64.0.2/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.4/32", Ports: tailcfg.PortRange{First: 443, Last: 443}},
					},
					IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
				},
			},
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.1/32", "100.64.0.2/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.3/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						{IP: "100.64.0.3/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						{IP: "100.64.0.4/32", Ports: tailcfg.PortRange{First: 443, Last: 443}},
					},
					IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergeFilterRules(tt.input)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("mergeFilterRules() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestCompileSSHPolicy_CheckPeriodVariants(t *testing.T) {
	users := types.Users{
		{Name: "user1", Model: gorm.Model{ID: 1}},
	}

	node := types.Node{
		Hostname: "device",
		IPv4:     createAddr("100.64.0.1"),
		UserID:   new(users[0].ID),
		User:     new(users[0]),
	}

	nodes := types.Nodes{&node}

	tests := []struct {
		name         string
		checkPeriod  *SSHCheckPeriod
		wantDuration time.Duration
	}{
		{
			name:         "nil period defaults to 12h",
			checkPeriod:  nil,
			wantDuration: SSHCheckPeriodDefault,
		},
		{
			name:         "always period uses 0",
			checkPeriod:  &SSHCheckPeriod{Always: true},
			wantDuration: 0,
		},
		{
			name:         "explicit 2h",
			checkPeriod:  &SSHCheckPeriod{Duration: 2 * time.Hour},
			wantDuration: 2 * time.Hour,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &Policy{
				SSHs: []SSH{
					{
						Action:       SSHActionCheck,
						Sources:      SSHSrcAliases{up("user1@")},
						Destinations: SSHDstAliases{agp("autogroup:member")},
						Users:        SSHUsers{"root"},
						CheckPeriod:  tt.checkPeriod,
					},
				},
			}

			err := policy.validate()
			require.NoError(t, err)

			sshPolicy, err := policy.compileSSHPolicy(
				"http://test",
				users,
				node.View(),
				nodes.ViewSlice(),
			)
			require.NoError(t, err)
			require.NotNil(t, sshPolicy)
			require.Len(t, sshPolicy.Rules, 1)

			rule := sshPolicy.Rules[0]
			assert.Equal(t, tt.wantDuration, rule.Action.SessionDuration)
			// Check params must NOT be in the URL; they are
			// resolved server-side via SSHCheckParams.
			assert.NotContains(t, rule.Action.HoldAndDelegate, "check_explicit")
			assert.NotContains(t, rule.Action.HoldAndDelegate, "check_period")
		})
	}
}

func TestIPSetToPrincipals(t *testing.T) {
	tests := []struct {
		name string
		ips  []string // IPs to add to the set
		want []*tailcfg.SSHPrincipal
	}{
		{
			name: "nil input",
			ips:  nil,
			want: nil,
		},
		{
			name: "single IPv4",
			ips:  []string{"100.64.0.1"},
			want: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.1"}},
		},
		{
			name: "multiple IPs",
			ips:  []string{"100.64.0.1", "100.64.0.2"},
			want: []*tailcfg.SSHPrincipal{
				{NodeIP: "100.64.0.1"},
				{NodeIP: "100.64.0.2"},
			},
		},
		{
			name: "IPv6",
			ips:  []string{"fd7a:115c:a1e0::1"},
			want: []*tailcfg.SSHPrincipal{{NodeIP: "fd7a:115c:a1e0::1"}},
		},
		{
			name: "mixed IPv4 and IPv6",
			ips:  []string{"100.64.0.1", "fd7a:115c:a1e0::1"},
			want: []*tailcfg.SSHPrincipal{
				{NodeIP: "100.64.0.1"},
				{NodeIP: "fd7a:115c:a1e0::1"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ipSet *netipx.IPSet

			if tt.ips != nil {
				var builder netipx.IPSetBuilder

				for _, ip := range tt.ips {
					addr := netip.MustParseAddr(ip)
					builder.Add(addr)
				}

				var err error

				ipSet, err = builder.IPSet()
				require.NoError(t, err)
			}

			got := ipSetToPrincipals(ipSet)

			// Sort for deterministic comparison
			sortPrincipals := func(p []*tailcfg.SSHPrincipal) {
				slices.SortFunc(p, func(a, b *tailcfg.SSHPrincipal) int {
					if a.NodeIP < b.NodeIP {
						return -1
					}

					if a.NodeIP > b.NodeIP {
						return 1
					}

					return 0
				})
			}
			sortPrincipals(got)
			sortPrincipals(tt.want)

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("ipSetToPrincipals() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestSSHCheckParams(t *testing.T) {
	users := types.Users{
		{Name: "user1", Model: gorm.Model{ID: 1}},
		{Name: "user2", Model: gorm.Model{ID: 2}},
	}

	nodeUser1 := types.Node{
		ID:       1,
		Hostname: "user1-device",
		IPv4:     createAddr("100.64.0.1"),
		UserID:   new(users[0].ID),
		User:     new(users[0]),
	}
	nodeUser2 := types.Node{
		ID:       2,
		Hostname: "user2-device",
		IPv4:     createAddr("100.64.0.2"),
		UserID:   new(users[1].ID),
		User:     new(users[1]),
	}
	nodeTaggedServer := types.Node{
		ID:       3,
		Hostname: "tagged-server",
		IPv4:     createAddr("100.64.0.3"),
		UserID:   new(users[0].ID),
		User:     new(users[0]),
		Tags:     []string{"tag:server"},
	}

	nodes := types.Nodes{&nodeUser1, &nodeUser2, &nodeTaggedServer}

	tests := []struct {
		name       string
		policy     []byte
		srcID      types.NodeID
		dstID      types.NodeID
		wantPeriod time.Duration
		wantOK     bool
	}{
		{
			name: "explicit check period for tagged destination",
			policy: []byte(`{
				"tagOwners": {"tag:server": ["user1@"]},
				"ssh": [{
					"action": "check",
					"checkPeriod": "2h",
					"src": ["user2@"],
					"dst": ["tag:server"],
					"users": ["autogroup:nonroot"]
				}]
			}`),
			srcID:      types.NodeID(2),
			dstID:      types.NodeID(3),
			wantPeriod: 2 * time.Hour,
			wantOK:     true,
		},
		{
			name: "default period when checkPeriod omitted",
			policy: []byte(`{
				"tagOwners": {"tag:server": ["user1@"]},
				"ssh": [{
					"action": "check",
					"src": ["user2@"],
					"dst": ["tag:server"],
					"users": ["autogroup:nonroot"]
				}]
			}`),
			srcID:      types.NodeID(2),
			dstID:      types.NodeID(3),
			wantPeriod: SSHCheckPeriodDefault,
			wantOK:     true,
		},
		{
			name: "always check (checkPeriod always)",
			policy: []byte(`{
				"tagOwners": {"tag:server": ["user1@"]},
				"ssh": [{
					"action": "check",
					"checkPeriod": "always",
					"src": ["user2@"],
					"dst": ["tag:server"],
					"users": ["autogroup:nonroot"]
				}]
			}`),
			srcID:      types.NodeID(2),
			dstID:      types.NodeID(3),
			wantPeriod: 0,
			wantOK:     true,
		},
		{
			name: "no match when src not in rule",
			policy: []byte(`{
				"tagOwners": {"tag:server": ["user1@"]},
				"ssh": [{
					"action": "check",
					"src": ["user1@"],
					"dst": ["tag:server"],
					"users": ["autogroup:nonroot"]
				}]
			}`),
			srcID:  types.NodeID(2),
			dstID:  types.NodeID(3),
			wantOK: false,
		},
		{
			name: "no match when dst not in rule",
			policy: []byte(`{
				"tagOwners": {"tag:server": ["user1@"]},
				"ssh": [{
					"action": "check",
					"src": ["user2@"],
					"dst": ["tag:server"],
					"users": ["autogroup:nonroot"]
				}]
			}`),
			srcID:  types.NodeID(2),
			dstID:  types.NodeID(1),
			wantOK: false,
		},
		{
			name: "accept rule is not returned",
			policy: []byte(`{
				"tagOwners": {"tag:server": ["user1@"]},
				"ssh": [{
					"action": "accept",
					"src": ["user2@"],
					"dst": ["tag:server"],
					"users": ["autogroup:nonroot"]
				}]
			}`),
			srcID:  types.NodeID(2),
			dstID:  types.NodeID(3),
			wantOK: false,
		},
		{
			name: "autogroup:self matches same-user pair",
			policy: []byte(`{
				"ssh": [{
					"action": "check",
					"checkPeriod": "6h",
					"src": ["user1@"],
					"dst": ["autogroup:self"],
					"users": ["autogroup:nonroot"]
				}]
			}`),
			srcID:      types.NodeID(1),
			dstID:      types.NodeID(1),
			wantPeriod: 6 * time.Hour,
			wantOK:     true,
		},
		{
			name: "autogroup:self rejects cross-user pair",
			policy: []byte(`{
				"ssh": [{
					"action": "check",
					"src": ["user1@"],
					"dst": ["autogroup:self"],
					"users": ["autogroup:nonroot"]
				}]
			}`),
			srcID:  types.NodeID(1),
			dstID:  types.NodeID(2),
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm, err := NewPolicyManager(tt.policy, users, nodes.ViewSlice())
			require.NoError(t, err)

			period, ok := pm.SSHCheckParams(tt.srcID, tt.dstID)
			assert.Equal(t, tt.wantOK, ok, "ok mismatch")

			if tt.wantOK {
				assert.Equal(t, tt.wantPeriod, period, "period mismatch")
			}
		})
	}
}

func TestResolveLocalparts(t *testing.T) {
	tests := []struct {
		name    string
		entries []SSHUser
		users   types.Users
		want    map[uint]string
	}{
		{
			name:    "no entries",
			entries: nil,
			users:   types.Users{{Name: "alice", Email: "alice@example.com", Model: gorm.Model{ID: 1}}},
			want:    nil,
		},
		{
			name:    "single match",
			entries: []SSHUser{"localpart:*@example.com"},
			users: types.Users{
				{Name: "alice", Email: "alice@example.com", Model: gorm.Model{ID: 1}},
			},
			want: map[uint]string{1: "alice"},
		},
		{
			name:    "domain mismatch",
			entries: []SSHUser{"localpart:*@other.com"},
			users: types.Users{
				{Name: "alice", Email: "alice@example.com", Model: gorm.Model{ID: 1}},
			},
			want: map[uint]string{},
		},
		{
			name:    "case insensitive domain",
			entries: []SSHUser{"localpart:*@EXAMPLE.COM"},
			users: types.Users{
				{Name: "alice", Email: "alice@example.com", Model: gorm.Model{ID: 1}},
			},
			want: map[uint]string{1: "alice"},
		},
		{
			name:    "user without email skipped",
			entries: []SSHUser{"localpart:*@example.com"},
			users: types.Users{
				{Name: "cli-user", Model: gorm.Model{ID: 1}},
			},
			want: map[uint]string{},
		},
		{
			name: "multiple domains multiple users",
			entries: []SSHUser{
				"localpart:*@example.com",
				"localpart:*@other.com",
			},
			users: types.Users{
				{Name: "alice", Email: "alice@example.com", Model: gorm.Model{ID: 1}},
				{Name: "bob", Email: "bob@other.com", Model: gorm.Model{ID: 2}},
				{Name: "charlie", Email: "charlie@nope.com", Model: gorm.Model{ID: 3}},
			},
			want: map[uint]string{1: "alice", 2: "bob"},
		},
		{
			name:    "special chars in local part",
			entries: []SSHUser{"localpart:*@example.com"},
			users: types.Users{
				{Name: "d", Email: "dave+ssh@example.com", Model: gorm.Model{ID: 1}},
			},
			want: map[uint]string{1: "dave+ssh"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveLocalparts(tt.entries, tt.users)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("resolveLocalparts() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestGroupSourcesByUser(t *testing.T) {
	alice := types.User{
		Name: "alice", Email: "alice@example.com",
		Model: gorm.Model{ID: 1},
	}
	bob := types.User{
		Name: "bob", Email: "bob@example.com",
		Model: gorm.Model{ID: 2},
	}

	nodeAlice := types.Node{
		Hostname: "alice-dev",
		IPv4:     createAddr("100.64.0.1"),
		UserID:   &alice.ID,
		User:     &alice,
	}
	nodeBob := types.Node{
		Hostname: "bob-dev",
		IPv4:     createAddr("100.64.0.2"),
		UserID:   &bob.ID,
		User:     &bob,
	}
	nodeTagged := types.Node{
		Hostname: "tagged",
		IPv4:     createAddr("100.64.0.3"),
		UserID:   &alice.ID,
		User:     &alice,
		Tags:     []string{"tag:server"},
	}

	// Build an IPSet that includes all node IPs
	allIPs := func() *netipx.IPSet {
		var b netipx.IPSetBuilder
		b.AddPrefix(netip.MustParsePrefix("100.64.0.0/24"))

		s, _ := b.IPSet()

		return s
	}()

	tests := []struct {
		name          string
		nodes         types.Nodes
		srcIPs        *netipx.IPSet
		wantUIDs      []uint
		wantUserCount int
		wantHasTagged bool
		wantTaggedLen int
		wantAliceIP   string
		wantBobIP     string
		wantTaggedIP  string
	}{
		{
			name:          "user-owned only",
			nodes:         types.Nodes{&nodeAlice, &nodeBob},
			srcIPs:        allIPs,
			wantUIDs:      []uint{1, 2},
			wantUserCount: 2,
			wantAliceIP:   "100.64.0.1",
			wantBobIP:     "100.64.0.2",
		},
		{
			name:          "mixed user and tagged",
			nodes:         types.Nodes{&nodeAlice, &nodeTagged},
			srcIPs:        allIPs,
			wantUIDs:      []uint{1},
			wantUserCount: 1,
			wantHasTagged: true,
			wantTaggedLen: 1,
			wantAliceIP:   "100.64.0.1",
			wantTaggedIP:  "100.64.0.3",
		},
		{
			name:          "tagged only",
			nodes:         types.Nodes{&nodeTagged},
			srcIPs:        allIPs,
			wantUIDs:      nil,
			wantUserCount: 0,
			wantHasTagged: true,
			wantTaggedLen: 1,
		},
		{
			name:  "node not in srcIPs excluded",
			nodes: types.Nodes{&nodeAlice, &nodeBob},
			srcIPs: func() *netipx.IPSet {
				var b netipx.IPSetBuilder
				b.Add(netip.MustParseAddr("100.64.0.1")) // only alice

				s, _ := b.IPSet()

				return s
			}(),
			wantUIDs:      []uint{1},
			wantUserCount: 1,
			wantAliceIP:   "100.64.0.1",
		},
		{
			name:          "sorted by user ID",
			nodes:         types.Nodes{&nodeBob, &nodeAlice}, // reverse order
			srcIPs:        allIPs,
			wantUIDs:      []uint{1, 2}, // still sorted
			wantUserCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sortedUIDs, byUser, tagged := groupSourcesByUser(
				tt.nodes.ViewSlice(), tt.srcIPs,
			)

			assert.Equal(t, tt.wantUIDs, sortedUIDs, "sortedUIDs")
			assert.Len(t, byUser, tt.wantUserCount, "byUser count")

			if tt.wantHasTagged {
				assert.Len(t, tagged, tt.wantTaggedLen, "tagged count")
			} else {
				assert.Empty(t, tagged, "tagged should be empty")
			}

			if tt.wantAliceIP != "" {
				require.Contains(t, byUser, uint(1))
				assert.Equal(t, tt.wantAliceIP, byUser[1][0].NodeIP)
			}

			if tt.wantBobIP != "" {
				require.Contains(t, byUser, uint(2))
				assert.Equal(t, tt.wantBobIP, byUser[2][0].NodeIP)
			}

			if tt.wantTaggedIP != "" {
				require.NotEmpty(t, tagged)
				assert.Equal(t, tt.wantTaggedIP, tagged[0].NodeIP)
			}
		})
	}
}

func TestBuildCapMapDriveSharer(t *testing.T) {
	t.Run("drive-grant-adds-drive-sharer", func(t *testing.T) {
		app := map[string][]json.RawMessage{
			"tailscale.com/cap/drive": {
				json.RawMessage(`{"shares":["*"]}`),
			},
		}
		capMap := buildCapMap(app)

		require.Contains(t, capMap, tailcfg.PeerCapabilityTaildrive,
			"should contain the original drive capability")
		require.Contains(t, capMap, tailcfg.PeerCapabilityTaildriveSharer,
			"should also contain drive-sharer for peer discovery")

		// Values should match
		assert.Equal(t, capMap[tailcfg.PeerCapabilityTaildrive], capMap[tailcfg.PeerCapabilityTaildriveSharer])
	})

	t.Run("explicit-drive-sharer-not-overwritten", func(t *testing.T) {
		app := map[string][]json.RawMessage{
			"tailscale.com/cap/drive": {
				json.RawMessage(`{"shares":["*"]}`),
			},
			"tailscale.com/cap/drive-sharer": {
				json.RawMessage(`{"custom":"value"}`),
			},
		}
		capMap := buildCapMap(app)

		// Explicit drive-sharer should NOT be overwritten
		require.Len(t, capMap[tailcfg.PeerCapabilityTaildriveSharer], 1)
		assert.Equal(t, tailcfg.RawMessage(`{"custom":"value"}`), capMap[tailcfg.PeerCapabilityTaildriveSharer][0])
	})

	t.Run("non-drive-app-unchanged", func(t *testing.T) {
		app := map[string][]json.RawMessage{
			"tailscale.com/cap/webui": {
				json.RawMessage(`{}`),
			},
		}
		capMap := buildCapMap(app)

		require.Contains(t, capMap, tailcfg.PeerCapability("tailscale.com/cap/webui"))
		assert.NotContains(t, capMap, tailcfg.PeerCapabilityTaildriveSharer,
			"non-drive apps should not add drive-sharer")
	})
}

func TestCompileGrantRules(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "user1"},
		{Model: gorm.Model{ID: 2}, Name: "user2"},
	}

	nodes := types.Nodes{
		{
			User: new(users[0]),
			IPv4: ap("100.64.0.1"),
		},
		{
			User: new(users[0]),
			IPv4: ap("100.64.0.2"),
		},
		{
			User: new(users[1]),
			IPv4: ap("100.64.0.3"),
		},
	}

	t.Run("app-only-grant-wildcard-dst", func(t *testing.T) {
		pol := &Policy{
			Grants: []Grant{
				{
					Sources:      Aliases{agp("autogroup:member")},
					Destinations: Aliases{Asterix(0)},
					App: map[string][]json.RawMessage{
						"tailscale.com/cap/drive": {
							json.RawMessage(`{"shares":["*"],"access":"rw"}`),
						},
					},
				},
			},
		}

		require.NoError(t, pol.validate())

		rules, err := pol.compileGrantRules(users, nodes.ViewSlice())
		require.NoError(t, err)
		require.Len(t, rules, 1)

		rule := rules[0]
		// Should have no DstPorts (app grants use CapGrant, not DstPorts)
		assert.Empty(t, rule.DstPorts)
		// Should have CapGrant
		require.Len(t, rule.CapGrant, 1)
		// CapGrant should have wildcard destinations (AllIPv4 + AllIPv6)
		assert.Len(t, rule.CapGrant[0].Dsts, 2)
		// CapMap should contain the drive capability
		require.Contains(t, rule.CapGrant[0].CapMap, tailcfg.PeerCapability("tailscale.com/cap/drive"))
		capMsgs := rule.CapGrant[0].CapMap[tailcfg.PeerCapability("tailscale.com/cap/drive")]
		require.Len(t, capMsgs, 1)
		assert.JSONEq(t, `{"shares":["*"],"access":"rw"}`, string(capMsgs[0]))
		// Sources should include all member nodes
		assert.NotEmpty(t, rule.SrcIPs)
	})

	t.Run("app-only-grant-specific-user-dst", func(t *testing.T) {
		pol := &Policy{
			Grants: []Grant{
				{
					Sources:      Aliases{up("user1@")},
					Destinations: Aliases{up("user2@")},
					App: map[string][]json.RawMessage{
						"tailscale.com/cap/drive": {
							json.RawMessage(`{"shares":["docs"],"access":"ro"}`),
						},
					},
				},
			},
		}

		require.NoError(t, pol.validate())

		rules, err := pol.compileGrantRules(users, nodes.ViewSlice())
		require.NoError(t, err)
		require.Len(t, rules, 1)

		rule := rules[0]
		require.Len(t, rule.CapGrant, 1)
		// Destinations should only contain user2's IPs
		for _, prefix := range rule.CapGrant[0].Dsts {
			assert.True(t, prefix.Contains(netip.MustParseAddr("100.64.0.3")),
				"destination should contain user2's IP 100.64.0.3, got %s", prefix)
		}
		// Sources should only contain user1's IPs
		for _, srcIP := range rule.SrcIPs {
			prefix := netip.MustParsePrefix(srcIP)
			assert.False(t, prefix.Contains(netip.MustParseAddr("100.64.0.3")),
				"source should NOT contain user2's IP")
		}
	})

	t.Run("ip-only-grant-wildcard", func(t *testing.T) {
		pol := &Policy{
			Grants: []Grant{
				{
					Sources:      Aliases{up("user1@")},
					Destinations: Aliases{up("user2@")},
					IP: GrantIPSpecs{
						{Ports: []tailcfg.PortRange{tailcfg.PortRangeAny}},
					},
				},
			},
		}

		require.NoError(t, pol.validate())

		rules, err := pol.compileGrantRules(users, nodes.ViewSlice())
		require.NoError(t, err)
		require.Len(t, rules, 1)

		rule := rules[0]
		// ip-only grants should have DstPorts, not CapGrant
		assert.NotEmpty(t, rule.DstPorts)
		assert.Empty(t, rule.CapGrant)
		// Should have default protocols (TCP+UDP+ICMP+ICMPv6)
		assert.Equal(t, []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP}, rule.IPProto)
	})

	t.Run("ip-only-grant-specific-port", func(t *testing.T) {
		pol := &Policy{
			Grants: []Grant{
				{
					Sources:      Aliases{up("user1@")},
					Destinations: Aliases{up("user2@")},
					IP: GrantIPSpecs{
						{
							Protocol: ProtocolNameTCP,
							Ports:    []tailcfg.PortRange{{First: 443, Last: 443}},
						},
					},
				},
			},
		}

		require.NoError(t, pol.validate())

		rules, err := pol.compileGrantRules(users, nodes.ViewSlice())
		require.NoError(t, err)
		require.Len(t, rules, 1)

		rule := rules[0]
		assert.NotEmpty(t, rule.DstPorts)
		assert.Empty(t, rule.CapGrant)
		assert.Equal(t, []int{ProtocolTCP}, rule.IPProto)
		// Check DstPorts contain the correct port
		found := false
		for _, dp := range rule.DstPorts {
			if dp.Ports.First == 443 && dp.Ports.Last == 443 {
				found = true
				break
			}
		}
		assert.True(t, found, "DstPorts should contain port 443")
	})

	t.Run("ip-and-app-grant-produces-separate-rules", func(t *testing.T) {
		pol := &Policy{
			Grants: []Grant{
				{
					Sources:      Aliases{agp("autogroup:member")},
					Destinations: Aliases{Asterix(0)},
					IP: GrantIPSpecs{
						{
							Protocol: ProtocolNameTCP,
							Ports:    []tailcfg.PortRange{{First: 80, Last: 80}},
						},
					},
					App: map[string][]json.RawMessage{
						"tailscale.com/cap/drive": {
							json.RawMessage(`{"shares":["*"]}`),
						},
					},
				},
			},
		}

		require.NoError(t, pol.validate())

		rules, err := pol.compileGrantRules(users, nodes.ViewSlice())
		require.NoError(t, err)
		// Should produce 2 rules: one for ip (DstPorts), one for app (CapGrant)
		require.Len(t, rules, 2)

		var ipRule, appRule *tailcfg.FilterRule
		for i := range rules {
			if len(rules[i].DstPorts) > 0 {
				ipRule = &rules[i]
			}
			if len(rules[i].CapGrant) > 0 {
				appRule = &rules[i]
			}
		}

		require.NotNil(t, ipRule, "should have an ip rule with DstPorts")
		require.NotNil(t, appRule, "should have an app rule with CapGrant")

		// ip rule should not have CapGrant
		assert.Empty(t, ipRule.CapGrant)
		// app rule should not have DstPorts
		assert.Empty(t, appRule.DstPorts)
	})

	t.Run("ip-different-protocols-produce-separate-rules", func(t *testing.T) {
		pol := &Policy{
			Grants: []Grant{
				{
					Sources:      Aliases{up("user1@")},
					Destinations: Aliases{up("user2@")},
					IP: GrantIPSpecs{
						{Protocol: ProtocolNameTCP, Ports: []tailcfg.PortRange{{First: 443, Last: 443}}},
						{Protocol: ProtocolNameUDP, Ports: []tailcfg.PortRange{{First: 53, Last: 53}}},
					},
				},
			},
		}

		require.NoError(t, pol.validate())

		rules, err := pol.compileGrantRules(users, nodes.ViewSlice())
		require.NoError(t, err)
		// TCP and UDP have different protocol numbers, so should produce 2 FilterRules
		require.Len(t, rules, 2)

		var tcpRule, udpRule *tailcfg.FilterRule
		for i := range rules {
			if slices.Contains(rules[i].IPProto, ProtocolTCP) {
				tcpRule = &rules[i]
			}
			if slices.Contains(rules[i].IPProto, ProtocolUDP) {
				udpRule = &rules[i]
			}
		}

		require.NotNil(t, tcpRule, "should have a TCP rule")
		require.NotNil(t, udpRule, "should have a UDP rule")

		// TCP rule should have port 443
		foundTCP := false
		for _, dp := range tcpRule.DstPorts {
			if dp.Ports.First == 443 && dp.Ports.Last == 443 {
				foundTCP = true
				break
			}
		}
		assert.True(t, foundTCP, "TCP rule should have port 443")

		// UDP rule should have port 53
		foundUDP := false
		for _, dp := range udpRule.DstPorts {
			if dp.Ports.First == 53 && dp.Ports.Last == 53 {
				foundUDP = true
				break
			}
		}
		assert.True(t, foundUDP, "UDP rule should have port 53")
	})

	t.Run("ip-same-protocol-accumulates-ports", func(t *testing.T) {
		pol := &Policy{
			Grants: []Grant{
				{
					Sources:      Aliases{up("user1@")},
					Destinations: Aliases{up("user2@")},
					IP: GrantIPSpecs{
						{Protocol: ProtocolNameTCP, Ports: []tailcfg.PortRange{{First: 443, Last: 443}}},
						{Protocol: ProtocolNameTCP, Ports: []tailcfg.PortRange{{First: 80, Last: 80}}},
					},
				},
			},
		}

		require.NoError(t, pol.validate())

		rules, err := pol.compileGrantRules(users, nodes.ViewSlice())
		require.NoError(t, err)
		// Same protocol, so ports should be accumulated into a single FilterRule
		require.Len(t, rules, 1)

		rule := rules[0]
		assert.Equal(t, []int{ProtocolTCP}, rule.IPProto)

		// Should contain both ports 443 and 80
		ports := make(map[uint16]bool)
		for _, dp := range rule.DstPorts {
			ports[dp.Ports.First] = true
		}
		assert.True(t, ports[443], "should contain port 443")
		assert.True(t, ports[80], "should contain port 80")
	})

	t.Run("grant-no-ip-no-app-skipped", func(t *testing.T) {
		pol := &Policy{
			Grants: []Grant{
				{
					Sources:      Aliases{agp("autogroup:member")},
					Destinations: Aliases{Asterix(0)},
				},
			},
		}

		rules, err := pol.compileGrantRules(users, nodes.ViewSlice())
		require.NoError(t, err)
		assert.Empty(t, rules, "grants with no ip and no app should be skipped")
	})

	t.Run("nil-policy-returns-nil", func(t *testing.T) {
		var pol *Policy
		rules, err := pol.compileGrantRules(users, nodes.ViewSlice())
		require.NoError(t, err)
		assert.Nil(t, rules)
	})
}

func TestCompileGrantRulesForNodeWithAutogroupSelf(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "user1"},
		{Model: gorm.Model{ID: 2}, Name: "user2"},
	}

	nodes := types.Nodes{
		{
			User: new(users[0]),
			IPv4: ap("100.64.0.1"),
		},
		{
			User: new(users[0]),
			IPv4: ap("100.64.0.2"),
		},
		{
			User: new(users[1]),
			IPv4: ap("100.64.0.3"),
		},
		// Tagged node for user1 - should be excluded from autogroup:self
		{
			User: &users[0],
			IPv4: ap("100.64.0.4"),
			Tags: []string{"tag:server"},
		},
	}

	t.Run("app-only-user1-sees-only-user1-peers", func(t *testing.T) {
		pol := &Policy{
			Grants: []Grant{
				{
					Sources:      Aliases{agp("autogroup:member")},
					Destinations: Aliases{agp("autogroup:self")},
					App: map[string][]json.RawMessage{
						"tailscale.com/cap/drive": {
							json.RawMessage(`{"shares":["*"],"access":"rw"}`),
						},
					},
				},
			},
		}

		require.NoError(t, pol.validate())

		node1 := nodes[0].View()
		rules, err := pol.compileGrantRulesForNode(users, node1, nodes.ViewSlice())
		require.NoError(t, err)
		require.Len(t, rules, 1)

		rule := rules[0]
		require.Len(t, rule.CapGrant, 1)

		// Destinations should only include user1's untagged nodes
		for _, prefix := range rule.CapGrant[0].Dsts {
			assert.False(t, prefix.Contains(netip.MustParseAddr("100.64.0.3")),
				"user1's grant destinations should NOT include user2's IP")
			assert.False(t, prefix.Contains(netip.MustParseAddr("100.64.0.4")),
				"user1's grant destinations should NOT include tagged node's IP")
		}

		// Sources should only include user1's untagged nodes
		for _, srcIP := range rule.SrcIPs {
			prefix := netip.MustParsePrefix(srcIP)
			assert.False(t, prefix.Contains(netip.MustParseAddr("100.64.0.3")),
				"user1's grant sources should NOT include user2's IP")
			assert.False(t, prefix.Contains(netip.MustParseAddr("100.64.0.4")),
				"user1's grant sources should NOT include tagged node's IP")
		}

		// Check drive capability is present
		require.Contains(t, rule.CapGrant[0].CapMap, tailcfg.PeerCapability("tailscale.com/cap/drive"))
	})

	t.Run("app-only-user2-sees-only-user2-peers", func(t *testing.T) {
		pol := &Policy{
			Grants: []Grant{
				{
					Sources:      Aliases{agp("autogroup:member")},
					Destinations: Aliases{agp("autogroup:self")},
					App: map[string][]json.RawMessage{
						"tailscale.com/cap/drive": {
							json.RawMessage(`{"shares":["*"],"access":"rw"}`),
						},
					},
				},
			},
		}

		require.NoError(t, pol.validate())

		node3 := nodes[2].View()
		rules, err := pol.compileGrantRulesForNode(users, node3, nodes.ViewSlice())
		require.NoError(t, err)
		require.Len(t, rules, 1)

		rule := rules[0]
		require.Len(t, rule.CapGrant, 1)

		// Destinations should only include user2's IP
		for _, prefix := range rule.CapGrant[0].Dsts {
			assert.True(t, prefix.Contains(netip.MustParseAddr("100.64.0.3")),
				"user2's grant destinations should include 100.64.0.3")
			assert.False(t, prefix.Contains(netip.MustParseAddr("100.64.0.1")),
				"user2's grant destinations should NOT include user1's IP")
		}
	})

	t.Run("tagged-node-gets-no-self-grants", func(t *testing.T) {
		pol := &Policy{
			Grants: []Grant{
				{
					Sources:      Aliases{agp("autogroup:member")},
					Destinations: Aliases{agp("autogroup:self")},
					App: map[string][]json.RawMessage{
						"tailscale.com/cap/drive": {
							json.RawMessage(`{"shares":["*"],"access":"rw"}`),
						},
					},
				},
			},
		}

		require.NoError(t, pol.validate())

		taggedNode := nodes[3].View()
		rules, err := pol.compileGrantRulesForNode(users, taggedNode, nodes.ViewSlice())
		require.NoError(t, err)
		assert.Empty(t, rules, "tagged nodes should not receive autogroup:self grant rules")
	})

	t.Run("ip-with-autogroup-self", func(t *testing.T) {
		pol := &Policy{
			Grants: []Grant{
				{
					Sources:      Aliases{agp("autogroup:member")},
					Destinations: Aliases{agp("autogroup:self")},
					IP: GrantIPSpecs{
						{
							Protocol: ProtocolNameTCP,
							Ports:    []tailcfg.PortRange{{First: 22, Last: 22}},
						},
					},
				},
			},
		}

		require.NoError(t, pol.validate())

		node1 := nodes[0].View()
		rules, err := pol.compileGrantRulesForNode(users, node1, nodes.ViewSlice())
		require.NoError(t, err)
		require.Len(t, rules, 1)

		rule := rules[0]
		// ip grants produce DstPorts, not CapGrant
		assert.NotEmpty(t, rule.DstPorts)
		assert.Empty(t, rule.CapGrant)
		assert.Equal(t, []int{ProtocolTCP}, rule.IPProto)

		// DstPorts should only include user1's untagged nodes
		for _, dp := range rule.DstPorts {
			prefix := netip.MustParsePrefix(dp.IP)
			assert.False(t, prefix.Contains(netip.MustParseAddr("100.64.0.3")),
				"user1's grant DstPorts should NOT include user2's IP, got %s", dp.IP)
			assert.False(t, prefix.Contains(netip.MustParseAddr("100.64.0.4")),
				"user1's grant DstPorts should NOT include tagged node's IP, got %s", dp.IP)
		}
	})

	t.Run("ip-and-app-with-autogroup-self", func(t *testing.T) {
		pol := &Policy{
			Grants: []Grant{
				{
					Sources:      Aliases{agp("autogroup:member")},
					Destinations: Aliases{agp("autogroup:self")},
					IP: GrantIPSpecs{
						{Ports: []tailcfg.PortRange{tailcfg.PortRangeAny}},
					},
					App: map[string][]json.RawMessage{
						"tailscale.com/cap/drive": {
							json.RawMessage(`{"shares":["*"]}`),
						},
					},
				},
			},
		}

		require.NoError(t, pol.validate())

		node1 := nodes[0].View()
		rules, err := pol.compileGrantRulesForNode(users, node1, nodes.ViewSlice())
		require.NoError(t, err)
		// Should have 2 rules: one for ip, one for app
		require.Len(t, rules, 2)

		var hasIP, hasApp bool
		for _, r := range rules {
			if len(r.DstPorts) > 0 {
				hasIP = true
			}
			if len(r.CapGrant) > 0 {
				hasApp = true
			}
		}
		assert.True(t, hasIP, "should have ip rule")
		assert.True(t, hasApp, "should have app rule")
	})
}

// TestTaildriveEndToEnd verifies the entire Taildrive capability flow from
// policy parsing through to client-side filter compilation. This tests that:
// 1. NodeAttrs with drive:share/drive:access reach the self node's CapMap
// 2. Grants with tailscale.com/cap/drive produce CapGrant rules with drive-sharer
// 3. The client-side filter.MatchesFromFilterRules preserves CapGrant data
// 4. CapsWithValues returns drive-sharer for same-user peers
func TestTaildriveEndToEnd(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "sonny-tel"},
		{Model: gorm.Model{ID: 2}, Name: "allusivewheat"},
	}

	nodes := types.Nodes{
		// sonny-tel nodes
		{
			ID:       1,
			User:     new(users[0]),
			IPv4:     ap("100.64.0.1"),
			Hostname: "pixel",
		},
		{
			ID:       2,
			User:     new(users[0]),
			IPv4:     ap("100.64.0.8"),
			Hostname: "euclid",
		},
		// allusivewheat nodes
		{
			ID:       3,
			User:     new(users[1]),
			IPv4:     ap("100.64.0.2"),
			Hostname: "desktop",
		},
		{
			ID:       4,
			User:     new(users[1]),
			IPv4:     ap("100.64.0.3"),
			Hostname: "fish",
		},
	}

	// This is the exact policy a user would configure for Taildrive
	policyJSON := []byte(`{
		"acls": [
			{
				"action": "accept",
				"src": ["autogroup:member"],
				"dst": ["autogroup:member:*"]
			}
		],
		"nodeAttrs": [
			{
				"target": ["autogroup:member"],
				"attr": ["drive:share", "drive:access"]
			}
		],
		"grants": [
			{
				"src": ["autogroup:member"],
				"dst": ["autogroup:self"],
				"app": {
					"tailscale.com/cap/drive": [{"shares": ["*"]}]
				}
			}
		]
	}`)

	pm, err := NewPolicyManager(policyJSON, users, nodes.ViewSlice())
	require.NoError(t, err, "PolicyManager creation should succeed")

	t.Run("self-node-has-drive-nodeAttrs", func(t *testing.T) {
		// Every non-tagged node should get drive:share and drive:access
		for i, node := range nodes {
			nv := node.View()
			attrs := pm.NodeAttrsForNode(nv)

			assert.Contains(t, attrs, "drive:share",
				"node %d (%s) should have drive:share in nodeAttrs", i, node.Hostname)
			assert.Contains(t, attrs, "drive:access",
				"node %d (%s) should have drive:access in nodeAttrs", i, node.Hostname)
		}
	})

	t.Run("filter-has-capgrant-with-drive-sharer", func(t *testing.T) {
		// Test for each node
		for i, node := range nodes {
			nv := node.View()
			rules, err := pm.FilterForNode(nv)
			require.NoError(t, err,
				"FilterForNode should succeed for node %d (%s)", i, node.Hostname)

			// Find CapGrant rules
			var capGrantRules []tailcfg.FilterRule
			for _, rule := range rules {
				if len(rule.CapGrant) > 0 {
					capGrantRules = append(capGrantRules, rule)
				}
			}

			require.NotEmpty(t, capGrantRules,
				"node %d (%s) should have CapGrant rules from drive grants", i, node.Hostname)

			// Check that drive and drive-sharer capabilities are present
			var hasDrive, hasDriveSharer bool
			for _, rule := range capGrantRules {
				for _, cg := range rule.CapGrant {
					for c := range cg.CapMap {
						if c == tailcfg.PeerCapability("tailscale.com/cap/drive") {
							hasDrive = true
						}
						if c == tailcfg.PeerCapability("tailscale.com/cap/drive-sharer") {
							hasDriveSharer = true
						}
					}
				}
			}

			assert.True(t, hasDrive,
				"node %d (%s) should have tailscale.com/cap/drive in CapGrant", i, node.Hostname)
			assert.True(t, hasDriveSharer,
				"node %d (%s) should have tailscale.com/cap/drive-sharer in CapGrant", i, node.Hostname)
		}
	})

	t.Run("capgrant-dsts-contain-self-node-ip", func(t *testing.T) {
		// For euclid (sonny-tel), CapGrant Dsts should contain euclid's own IP
		// (after ReduceFilterRules), and SrcIPs should only include same-user nodes
		euclid := nodes[1].View()
		rules, err := pm.FilterForNode(euclid)
		require.NoError(t, err)

		for _, rule := range rules {
			for _, cg := range rule.CapGrant {
				// Check that user2's IPs are not in SrcIPs
				for _, srcIP := range rule.SrcIPs {
					prefix := netip.MustParsePrefix(srcIP)
					assert.False(t, prefix.Contains(netip.MustParseAddr("100.64.0.2")),
						"euclid's CapGrant SrcIPs should NOT include allusivewheat's desktop IP")
					assert.False(t, prefix.Contains(netip.MustParseAddr("100.64.0.3")),
						"euclid's CapGrant SrcIPs should NOT include allusivewheat's fish IP")
				}
				// SrcIPs should include same-user nodes
				var hasSrcPixel, hasSrcEuclid bool
				for _, srcIP := range rule.SrcIPs {
					prefix := netip.MustParsePrefix(srcIP)
					if prefix.Contains(netip.MustParseAddr("100.64.0.1")) {
						hasSrcPixel = true
					}
					if prefix.Contains(netip.MustParseAddr("100.64.0.8")) {
						hasSrcEuclid = true
					}
				}
				assert.True(t, hasSrcPixel, "SrcIPs should include pixel (same user)")
				assert.True(t, hasSrcEuclid, "SrcIPs should include euclid (same user)")

				// After ReduceFilterRules, Dsts should contain euclid's own IP
				var hasDstEuclid bool
				for _, dst := range cg.Dsts {
					if dst.Contains(netip.MustParseAddr("100.64.0.8")) {
						hasDstEuclid = true
					}
				}
				assert.True(t, hasDstEuclid, "euclid's CapGrant Dsts should include euclid's IP")
			}
		}
	})

	t.Run("client-filter-compilation-preserves-capgrant", func(t *testing.T) {
		// Simulate what the Tailscale client does: compile FilterRules into filter.Match
		euclid := nodes[1].View()
		rules, err := pm.FilterForNode(euclid)
		require.NoError(t, err)

		// Compile using the Tailscale client's filter compilation
		matches, err := filter.MatchesFromFilterRules(rules)
		require.NoError(t, err, "filter.MatchesFromFilterRules should succeed")

		// Verify that CapMatch entries exist in the compiled matches
		var hasCapMatch bool
		for _, m := range matches {
			if len(m.Caps) > 0 {
				hasCapMatch = true
				break
			}
		}
		assert.True(t, hasCapMatch,
			"compiled filter should have CapMatch entries from CapGrant rules")
	})

	t.Run("CapsWithValues-returns-drive-sharer-for-same-user-peer", func(t *testing.T) {
		// This is the critical test: simulates what the Tailscale client does
		// when checking PeerHasCap(peer, "tailscale.com/cap/drive-sharer")

		euclid := nodes[1].View()
		rules, err := pm.FilterForNode(euclid)
		require.NoError(t, err)

		matches, err := filter.MatchesFromFilterRules(rules)
		require.NoError(t, err)

		// Build a filter (matching what the Tailscale client does)
		var localBuilder netipx.IPSetBuilder
		localBuilder.AddPrefix(netip.MustParsePrefix("100.64.0.8/32"))
		localSet, err := localBuilder.IPSet()
		require.NoError(t, err)

		filt := filter.New(matches, nil, localSet, localSet, nil, t.Logf)

		// Check: pixel (same user as euclid) should have drive-sharer capability
		pixelIP := netip.MustParseAddr("100.64.0.1")
		euclidIP := netip.MustParseAddr("100.64.0.8")

		caps := filt.CapsWithValues(pixelIP, euclidIP)
		assert.Contains(t, caps, tailcfg.PeerCapability("tailscale.com/cap/drive-sharer"),
			"pixel (same user) should have drive-sharer capability when checked from euclid")
		assert.Contains(t, caps, tailcfg.PeerCapability("tailscale.com/cap/drive"),
			"pixel (same user) should have drive capability when checked from euclid")

		// Check: desktop (different user) should NOT have drive-sharer capability
		desktopIP := netip.MustParseAddr("100.64.0.2")
		caps = filt.CapsWithValues(desktopIP, euclidIP)
		assert.NotContains(t, caps, tailcfg.PeerCapability("tailscale.com/cap/drive-sharer"),
			"desktop (different user) should NOT have drive-sharer when checked from euclid")
	})
}
