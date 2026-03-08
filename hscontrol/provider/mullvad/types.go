package mullvad

import "time"

// apiRelayResponse is the top-level response from GET /v1/relays
// (https://api.mullvad.net/app/v1/relays).
type apiRelayResponse struct {
	Locations map[string]apiLocation `json:"locations"`
	WireGuard apiWireGuard           `json:"wireguard"`
}

// apiLocation describes a relay location.
type apiLocation struct {
	City      string  `json:"city"`
	Country   string  `json:"country"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
}

// apiWireGuard is the WireGuard section of the relay list response.
type apiWireGuard struct {
	PortRanges  [][]int      `json:"port_ranges"`
	IPv4Gateway string       `json:"ipv4_gateway"`
	IPv6Gateway string       `json:"ipv6_gateway"`
	Relays      []apiWGRelay `json:"relays"`
}

// apiWGRelay is a single WireGuard relay from the App API.
type apiWGRelay struct {
	Hostname         string `json:"hostname"`
	Active           bool   `json:"active"`
	Owned            bool   `json:"owned"`
	Location         string `json:"location"` // key into the locations map, e.g. "se-got"
	Provider         string `json:"provider"`
	IPv4AddrIn       string `json:"ipv4_addr_in"`
	IPv6AddrIn       string `json:"ipv6_addr_in"`
	Weight           int    `json:"weight"`
	IncludeInCountry bool   `json:"include_in_country"`
	PublicKey        string `json:"public_key"`
}

// apiWGKeyResponse is the response from POST /v1/wireguard-keys.
type apiWGKeyResponse struct {
	ID          string `json:"id"`
	PubKey      string `json:"pubkey"`
	IPv4Address string `json:"ipv4_address"`
	IPv6Address string `json:"ipv6_address"`
}

// apiAccountResponse is the response from GET /v1/me.
type apiAccountResponse struct {
	Token   string    `json:"token"`
	Expires time.Time `json:"expires"`
}

// apiAuthTokenResponse is the response from POST /auth/v1/token.
type apiAuthTokenResponse struct {
	AccessToken string    `json:"access_token"`
	Expiry      time.Time `json:"expiry"`
}
