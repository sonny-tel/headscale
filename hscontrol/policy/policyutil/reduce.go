package policyutil

import (
	"net/netip"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"tailscale.com/tailcfg"
)

// ReduceFilterRules takes a node and a set of global filter rules and removes all rules
// and destinations that are not relevant to that particular node.
//
// IMPORTANT: This function is designed for global filters only. Per-node filters
// (from autogroup:self policies) are already node-specific and should not be passed
// to this function. Use PolicyManager.FilterForNode() instead, which handles both cases.
func ReduceFilterRules(node types.NodeView, rules []tailcfg.FilterRule) []tailcfg.FilterRule {
	ret := []tailcfg.FilterRule{}

	for _, rule := range rules {
		// Handle rules with DstPorts (network-layer rules from ACLs and grant "ip" specs).
		if len(rule.DstPorts) > 0 {
			if reduced, ok := reduceDstPortsRule(node, rule); ok {
				ret = append(ret, reduced)
			}
			continue
		}

		// Handle rules with CapGrant (application-layer rules from grant "app" specs).
		if len(rule.CapGrant) > 0 {
			if reduced, ok := reduceCapGrantRule(node, rule); ok {
				ret = append(ret, reduced)
			}
			continue
		}
	}

	return ret
}

// reduceDstPortsRule reduces a network-layer FilterRule (with DstPorts) to only
// include destinations relevant to the given node.
func reduceDstPortsRule(node types.NodeView, rule tailcfg.FilterRule) (tailcfg.FilterRule, bool) {
	var dests []tailcfg.NetPortRange

DEST_LOOP:
	for _, dest := range rule.DstPorts {
		expanded, err := util.ParseIPSet(dest.IP, nil)
		// Fail closed, if we can't parse it, then we should not allow
		// access.
		if err != nil {
			continue DEST_LOOP
		}

		if node.InIPSet(expanded) {
			dests = append(dests, dest)
			continue DEST_LOOP
		}

		// If the node exposes routes, ensure they are note removed
		// when the filters are reduced.
		if node.Hostinfo().Valid() {
			routableIPs := node.Hostinfo().RoutableIPs()
			if routableIPs.Len() > 0 {
				for _, routableIP := range routableIPs.All() {
					if expanded.OverlapsPrefix(routableIP) {
						dests = append(dests, dest)
						continue DEST_LOOP
					}
				}
			}
		}

		// Also check approved subnet routes - nodes should have access
		// to subnets they're approved to route traffic for.
		subnetRoutes := node.SubnetRoutes()

		for _, subnetRoute := range subnetRoutes {
			if expanded.OverlapsPrefix(subnetRoute) {
				dests = append(dests, dest)
				continue DEST_LOOP
			}
		}
	}

	if len(dests) == 0 {
		return tailcfg.FilterRule{}, false
	}

	return tailcfg.FilterRule{
		SrcIPs:   rule.SrcIPs,
		DstPorts: dests,
		IPProto:  rule.IPProto,
	}, true
}

// reduceCapGrantRule reduces an application-layer FilterRule (with CapGrant) to only
// include CapGrant entries whose destinations are relevant to the given node.
func reduceCapGrantRule(node types.NodeView, rule tailcfg.FilterRule) (tailcfg.FilterRule, bool) {
	var grants []tailcfg.CapGrant

	for _, cg := range rule.CapGrant {
		var matchingDsts []netip.Prefix

		for _, dst := range cg.Dsts {
			if nodeMatchesPrefix(node, dst) {
				matchingDsts = append(matchingDsts, dst)
			}
		}

		if len(matchingDsts) > 0 {
			grants = append(grants, tailcfg.CapGrant{
				Dsts:   matchingDsts,
				Caps:   cg.Caps,
				CapMap: cg.CapMap,
			})
		}
	}

	if len(grants) == 0 {
		return tailcfg.FilterRule{}, false
	}

	return tailcfg.FilterRule{
		SrcIPs:   rule.SrcIPs,
		CapGrant: grants,
	}, true
}

// nodeMatchesPrefix checks if a node's IPs or routes overlap with the given prefix.
func nodeMatchesPrefix(node types.NodeView, prefix netip.Prefix) bool {
	expanded, err := util.ParseIPSet(prefix.String(), nil)
	if err != nil {
		return false
	}

	if node.InIPSet(expanded) {
		return true
	}

	if node.Hostinfo().Valid() {
		routableIPs := node.Hostinfo().RoutableIPs()
		for _, routableIP := range routableIPs.All() {
			if expanded.OverlapsPrefix(routableIP) {
				return true
			}
		}
	}

	for _, subnetRoute := range node.SubnetRoutes() {
		if expanded.OverlapsPrefix(subnetRoute) {
			return true
		}
	}

	return false
}
