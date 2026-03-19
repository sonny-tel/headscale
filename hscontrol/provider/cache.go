package provider

import (
	"fmt"
	"hash/fnv"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
)

// RelayCache holds relay servers in memory, synthesized from provider APIs.
// Relays are never persisted to disk — the cache is rebuilt on startup.
type RelayCache struct {
	mu                   sync.RWMutex
	baseDomain           string                     // headscale base domain for node names
	spoofProviderDomains bool                       // use <provider>.ts.net instead of <provider>.<baseDomain>
	relays               map[string][]Relay         // provider name → relay list
	lastSync             map[string]time.Time       // provider name → last sync time
	tailNodeCache        map[string][]*tailcfg.Node // provider name → synthetic nodes (memoized)
}

// NewRelayCache creates an empty relay cache.
func NewRelayCache(baseDomain string, spoofProviderDomains bool) *RelayCache {
	return &RelayCache{
		baseDomain:           baseDomain,
		spoofProviderDomains: spoofProviderDomains,
		relays:               make(map[string][]Relay),
		lastSync:             make(map[string]time.Time),
		tailNodeCache:        make(map[string][]*tailcfg.Node),
	}
}

// Refresh replaces the cached relays for a provider and invalidates the
// memoized tailcfg.Node slice so the next AllTailNodes call rebuilds it.
func (rc *RelayCache) Refresh(providerName string, relays []Relay) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	rc.relays[providerName] = relays
	rc.lastSync[providerName] = time.Now()

	// Invalidate memoized nodes.
	delete(rc.tailNodeCache, providerName)
}

// ListRelays returns a snapshot of relays for the given provider.
// If providerName is empty, relays for all providers are returned.
func (rc *RelayCache) ListRelays(providerName string) []Relay {
	rc.mu.RLock()
	defer rc.mu.RUnlock()

	if providerName != "" {
		return rc.relays[providerName]
	}

	var all []Relay
	for _, relays := range rc.relays {
		all = append(all, relays...)
	}
	return all
}

// LastSync returns when relays were last synced for the provider.
func (rc *RelayCache) LastSync(providerName string) time.Time {
	rc.mu.RLock()
	defer rc.mu.RUnlock()

	return rc.lastSync[providerName]
}

// AllTailNodes returns all synthetic tailcfg.Node entries across all providers.
// Results are memoized per provider and rebuilt only when Refresh is called.
func (rc *RelayCache) AllTailNodes() []*tailcfg.Node {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	var all []*tailcfg.Node

	for providerName, relays := range rc.relays {
		nodes, ok := rc.tailNodeCache[providerName]
		if !ok {
			nodes = buildSyntheticNodes(providerName, relays, rc.baseDomain, rc.spoofProviderDomains)
			rc.tailNodeCache[providerName] = nodes
		}

		all = append(all, nodes...)
	}

	return all
}

// syntheticNodeID produces a deterministic NodeID from the provider name and
// relay hostname using FNV-64a. The high bit is set to avoid collisions with
// real headscale node IDs (which are sequential small integers).
func syntheticNodeID(providerName, hostname string) tailcfg.NodeID {
	h := fnv.New64a()
	fmt.Fprintf(h, "%s:%s", providerName, hostname)

	// Set the high bit so synthetic IDs never collide with real DB IDs.
	return tailcfg.NodeID(h.Sum64() | (1 << 63)) //nolint:gosec // intentional uint64→int64; high-bit tag
}

// syntheticCGNATAddr produces a deterministic IPv4 address in the upper half
// of the 100.64.0.0/10 CGNAT range (100.96.0.0/11) from the relay's synthetic
// node ID. Real headscale IPs are allocated sequentially from 100.64.0.1, so
// the upper half avoids collisions.
func syntheticCGNATAddr(nodeID tailcfg.NodeID) netip.Addr {
	offset := uint32(nodeID) & 0x1FFFFF // 21 bits → 2M addresses
	// 100.96.0.0 = 0x64600000
	ip := uint32(0x64600000) + offset
	return netip.AddrFrom4([4]byte{
		byte(ip >> 24),
		byte(ip >> 16),
		byte(ip >> 8),
		byte(ip),
	})
}

// syntheticTailscaleIPv6 produces a deterministic IPv6 address in the Tailscale
// ULA range (fd7a:115c:a1e0::/48) from the relay's synthetic node ID.
// The subnet byte is set to 0x80+ to separate from real allocations.
func syntheticTailscaleIPv6(nodeID tailcfg.NodeID) netip.Addr {
	h := uint64(nodeID) //nolint:gosec // intentional int64→uint64 for bit extraction
	var addr [16]byte
	// fd7a:115c:a1e0:: prefix (48 bits)
	addr[0] = 0xfd
	addr[1] = 0x7a
	addr[2] = 0x11
	addr[3] = 0x5c
	addr[4] = 0xa1
	addr[5] = 0xe0
	// Use hash bits for host portion, set high bit in first subnet byte
	// to separate from real allocations
	addr[6] = byte(h>>40) | 0x80
	addr[7] = byte(h >> 32)
	addr[8] = byte(h >> 24)
	addr[9] = byte(h >> 16)
	addr[10] = byte(h >> 8)
	addr[11] = byte(h)
	addr[12] = byte(h >> 48)
	addr[13] = byte(h >> 56)
	addr[14] = 0
	addr[15] = 1 // avoid zero-host
	return netip.AddrFrom16(addr)
}

func buildSyntheticNodes(providerName string, relays []Relay, baseDomain string, spoofDomain bool) []*tailcfg.Node {
	nodes := make([]*tailcfg.Node, 0, len(relays))

	for _, r := range relays {
		if !r.Active {
			continue
		}

		nodeID := syntheticNodeID(providerName, r.Hostname)
		stableID := tailcfg.StableNodeID(strconv.FormatUint(uint64(nodeID), 10))

		// Addresses are synthesized CGNAT/ULA IPs that identify this node
		// within the tailnet. Using the relay's real public IP here would
		// create a routing loop (the client would try to reach the relay's
		// endpoint IP through the tunnel to that same relay).
		addrs := []netip.Prefix{
			netip.PrefixFrom(syntheticCGNATAddr(nodeID), 32),
			netip.PrefixFrom(syntheticTailscaleIPv6(nodeID), 128),
		}

		// Endpoints are the real public IP:port for WireGuard handshake.
		var endpoints []netip.AddrPort
		if r.IPv4.IsValid() {
			endpoints = append(endpoints, netip.AddrPortFrom(r.IPv4, 51820))
		}

		loc := &tailcfg.Location{
			Country:     r.Country,
			CountryCode: r.CountryCode,
			City:        r.City,
			CityCode:    r.CityCode,
			Latitude:    r.Latitude,
			Longitude:   r.Longitude,
		}

		hi := (&tailcfg.Hostinfo{
			OS:       providerName,
			Hostname: r.Hostname,
			Location: loc,
		}).View()

		online := true

		tNode := &tailcfg.Node{
			ID:       nodeID,
			StableID: stableID,
			Name:     providerNodeName(r.Hostname, providerName, baseDomain, spoofDomain),
			User:     tailcfg.UserID(2147455555), // TaggedDevices

			Key:       r.WGPubKey,
			Addresses: addrs,
			AllowedIPs: []netip.Prefix{
				netip.MustParsePrefix("0.0.0.0/0"),
				netip.MustParsePrefix("::/0"),
			},
			Endpoints: endpoints,
			Hostinfo:  hi,

			Online:            &online,
			MachineAuthorized: true,
			IsWireGuardOnly:   true,
			IsJailed:          true,

			Tags: []string{"tag:vpn-provider", "tag:" + providerName},

			ExitNodeDNSResolvers: defaultDNSResolvers(providerName),

			CapMap: tailcfg.NodeCapMap{
				tailcfg.NodeAttrSuggestExitNode: nil,
			},
		}

		nodes = append(nodes, tNode)
	}

	return nodes
}

// providerNodeName returns the FQDN for a provider relay node.
// When spoofDomain is enabled, it always uses "<hostname>.mullvad.ts.net."
// regardless of the actual provider, because Tailscale clients only
// recognise "mullvad.ts.net" for the native VPN picker UI.
// Otherwise it uses "<hostname>.<provider>.<baseDomain>.".
func providerNodeName(hostname, providerName, baseDomain string, spoofDomain bool) string {
	if spoofDomain {
		return hostname + ".mullvad.ts.net."
	}
	return hostname + "." + providerName + "." + baseDomain + "."
}

// defaultDNSResolvers returns the default exit-node DNS resolvers for a provider.
func defaultDNSResolvers(providerName string) []*dnstype.Resolver {
	switch providerName {
	case "mullvad":
		return []*dnstype.Resolver{
			{Addr: "194.242.2.2"},
		}
	default:
		return nil
	}
}
