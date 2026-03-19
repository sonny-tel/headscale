package mullvad

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/types/key"
)

func TestParseAssignedAddr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "plain ipv4",
			raw:  "10.64.1.12",
			want: "10.64.1.12",
		},
		{
			name: "cidr ipv4",
			raw:  "10.64.1.12/32",
			want: "10.64.1.12",
		},
		{
			name: "plain ipv6",
			raw:  "fc00::1234",
			want: "fc00::1234",
		},
		{
			name: "cidr ipv6",
			raw:  "fc00::1234/128",
			want: "fc00::1234",
		},
		{
			name: "invalid",
			raw:  "not-an-ip",
			want: "invalid IP",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := parseAssignedAddr(tt.raw)
			if diff := cmp.Diff(tt.want, got.String()); diff != "" {
				t.Fatalf("parseAssignedAddr() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestParseKeyResponse(t *testing.T) {
	t.Parallel()

	resp := &apiWGKeyResponse{
		ID:          "test-id",
		PubKey:      key.NewNode().Public().String(),
		IPv4Address: "10.77.0.4",
		IPv6Address: "fc00::77/128",
	}

	result := parseKeyResponse(resp)
	if diff := cmp.Diff("10.77.0.4", result.IPv4.String()); diff != "" {
		t.Fatalf("parseKeyResponse() IPv4 mismatch (-want +got):\n%s", diff)
	}

	if diff := cmp.Diff("fc00::77", result.IPv6.String()); diff != "" {
		t.Fatalf("parseKeyResponse() IPv6 mismatch (-want +got):\n%s", diff)
	}
}
