package provider

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"
	"tailscale.com/types/key"
)

// NodeAttrPrefix is the legacy nodeAttr prefix for VPN provider key allocation.
// Both "mullvad" (direct provider name) and "use-exit-node-mullvad" (prefixed)
// are supported in nodeAttrs policy.
const NodeAttrPrefix = "use-exit-node-"

// NodeInfo is the minimal node information needed for allocation reconciliation.
type NodeInfo struct {
	ID     uint64
	PubKey key.NodePublic
	Attrs  []string // from policy NodeAttrsForNode
}

// providerFromAttr resolves a nodeAttr to a registered provider name.
// Matches the attr directly as a provider name first, then falls back to
// stripping the "use-exit-node-" prefix. Returns empty string if no match.
func providerFromAttr(attr string, mgr *Manager) string {
	// Direct provider name match (e.g. "mullvad").
	if _, ok := mgr.Provider(attr); ok {
		return attr
	}

	// Legacy prefixed match (e.g. "use-exit-node-mullvad").
	if len(attr) > len(NodeAttrPrefix) && attr[:len(NodeAttrPrefix)] == NodeAttrPrefix {
		return attr[len(NodeAttrPrefix):]
	}

	return ""
}

// ReconcileAllocations ensures that key allocations match the desired state
// expressed by nodeAttrs policy. For each node:
//   - If it has a use-exit-node-<provider> attr and no allocation: register a key
//   - If it has an allocation but no corresponding attr: deregister the key
func ReconcileAllocations(
	ctx context.Context,
	mgr *Manager,
	nodes []NodeInfo,
	findAccount func(providerName string) (accountID uint, accountStr string, err error),
	getAlloc func(nodeID uint64, providerName string) (exists bool, acctID uint, nodeKey string, accountStr string, err error),
	createAlloc func(accountID uint, nodeID uint64, nodeKey, assignedIPv4, assignedIPv6 string) error,
	deleteAlloc func(nodeID uint64, providerName string) error,
) error {
	for _, node := range nodes {
		// Determine which providers this node should be allocated to.
		wantProviders := make(map[string]bool)
		for _, attr := range node.Attrs {
			if prov := providerFromAttr(attr, mgr); prov != "" {
				wantProviders[prov] = true
			}
		}

		log.Debug().
			Uint64("node", node.ID).
			Str("node_key", node.PubKey.ShortString()).
			Strs("attrs", node.Attrs).
			Int("want_providers", len(wantProviders)).
			Msg("reconcile: processing node")

		// Allocate keys for newly wanted providers.
		for provName := range wantProviders {
			p, ok := mgr.Provider(provName)
			if !ok {
				log.Warn().
					Str("provider", provName).
					Uint64("node", node.ID).
					Msg("provider not registered, skipping allocation")

				continue
			}

			exists, allocAcctID, allocKeyStr, allocAcctStr, err := getAlloc(node.ID, provName)
			if err != nil {
				log.Warn().Err(err).
					Str("provider", provName).
					Uint64("node", node.ID).
					Msg("failed to check existing allocation")

				continue
			}

			if exists && allocKeyStr == node.PubKey.String() {
				continue // already allocated with correct key
			}

			// If allocation exists but key has changed (rotation), use atomic replace.
			if exists && allocKeyStr != node.PubKey.String() {
				var oldKey key.NodePublic
				if err := oldKey.UnmarshalText([]byte(allocKeyStr)); err != nil {
					log.Error().Err(err).
						Str("provider", provName).
						Uint64("node", node.ID).
						Msg("failed to parse old node key for rotation")

					continue
				}

				// Use the atomic replace-key API to swap old→new without orphaning keys.
				replaceResult, replaceErr := p.ReplaceKey(ctx, allocAcctStr, oldKey, node.PubKey)
				if replaceErr != nil {
					log.Warn().Err(replaceErr).
						Str("provider", provName).
						Uint64("node", node.ID).
						Msg("atomic key replace failed, trying deregister + fresh register")

					// Fallback: deregister old, then register new.
					if deregErr := p.DeregisterKey(ctx, allocAcctStr, oldKey); deregErr != nil {
						log.Warn().Err(deregErr).
							Str("provider", provName).
							Uint64("node", node.ID).
							Msg("failed to deregister old key during rotation fallback")
						// Don't delete DB record or continue — old key may still be on provider.
						// Leave allocation as-is so we can retry next reconciliation cycle.
						continue
					}

					// Old key successfully deregistered — delete DB record and let the
					// fresh registration path below handle the new key.
					if err := deleteAlloc(node.ID, provName); err != nil {
						log.Error().Err(err).
							Str("provider", provName).
							Uint64("node", node.ID).
							Msg("failed to delete stale allocation during key rotation")

						continue
					}

					// Fall through to the fresh registration path below.
					log.Info().
						Str("provider", provName).
						Uint64("node", node.ID).
						Msg("deregistered old key during rotation, will re-register")
				} else {
					// Atomic replace succeeded — update the DB allocation in place.
					if err := deleteAlloc(node.ID, provName); err != nil {
						log.Error().Err(err).
							Str("provider", provName).
							Uint64("node", node.ID).
							Msg("failed to delete old allocation after key replace")

						continue
					}

					var rv4, rv6 string
					if replaceResult != nil {
						if replaceResult.IPv4.IsValid() {
							rv4 = replaceResult.IPv4.String()
						}

						if replaceResult.IPv6.IsValid() {
							rv6 = replaceResult.IPv6.String()
						}
					}

					if err := createAlloc(allocAcctID, node.ID, node.PubKey.String(), rv4, rv6); err != nil {
						log.Error().Err(err).
							Str("provider", provName).
							Uint64("node", node.ID).
							Msg("failed to create allocation after key replace")
					} else {
						log.Info().
							Str("provider", provName).
							Uint64("node", node.ID).
							Msg("rotated VPN provider key for node via atomic replace")
					}

					continue
				}
			}

			acctID, acctStr, err := findAccount(provName)
			if err != nil {
				log.Warn().Err(err).
					Str("provider", provName).
					Uint64("node", node.ID).
					Str("node_key", node.PubKey.ShortString()).
					Msg("no account with free slots")

				continue
			}

			log.Debug().
				Str("provider", provName).
				Uint64("node", node.ID).
				Str("node_key", node.PubKey.ShortString()).
				Uint("account_id", acctID).
				Msg("reconcile: registering key with provider")

			regResult, err := p.RegisterKey(ctx, acctStr, node.PubKey)
			if err != nil {
				// Registration failed — the key may already exist on the provider
				// from a previous run. Re-check the DB first: if another goroutine
				// already created the allocation, we can skip this node.
				recheckExists, _, _, _, recheckErr := getAlloc(node.ID, provName)
				if recheckErr == nil && recheckExists {
					log.Info().
						Str("provider", provName).
						Uint64("node", node.ID).
						Msg("allocation appeared after initial register failed, skipping (handled by another call)")

					continue
				}

				// Not in DB — check if the key already exists on the provider via GET.
				// This handles orphaned keys (registered on provider but not tracked in DB).
				getResult, getErr := p.GetKey(ctx, acctStr, node.PubKey)
				if getErr == nil && getResult != nil {
					// Key exists on provider! Create a DB allocation using the returned IPs.
					var gv4, gv6 string
					if getResult.IPv4.IsValid() {
						gv4 = getResult.IPv4.String()
					}

					if getResult.IPv6.IsValid() {
						gv6 = getResult.IPv6.String()
					}

					if createErr := createAlloc(acctID, node.ID, node.PubKey.String(), gv4, gv6); createErr != nil {
						log.Error().Err(createErr).
							Str("provider", provName).
							Uint64("node", node.ID).
							Msg("failed to create DB allocation for existing provider key")
					} else {
						log.Info().
							Str("provider", provName).
							Uint64("node", node.ID).
							Msg("recovered existing provider key into DB allocation")
					}

					continue
				}

				// Key doesn't exist on provider either — transient API error.
				// Retry once after a short delay.
				log.Warn().Err(err).
					Str("provider", provName).
					Uint64("node", node.ID).
					Str("node_key", node.PubKey.ShortString()).
					Msg("registration failed, retrying after delay")

				time.Sleep(2 * time.Second)

				regResult, err = p.RegisterKey(ctx, acctStr, node.PubKey)
				if err != nil {
					log.Error().Err(err).
						Str("provider", provName).
						Uint64("node", node.ID).
						Str("node_key", node.PubKey.ShortString()).
						Msg("failed to register key with provider after retry")

					continue
				}
			}

			var assignedV4, assignedV6 string
			if regResult != nil {
				if regResult.IPv4.IsValid() {
					assignedV4 = regResult.IPv4.String()
				}

				if regResult.IPv6.IsValid() {
					assignedV6 = regResult.IPv6.String()
				}
			}

			if err := createAlloc(acctID, node.ID, node.PubKey.String(), assignedV4, assignedV6); err != nil {
				log.Error().Err(err).
					Str("provider", provName).
					Uint64("node", node.ID).
					Msg("failed to create key allocation record")

				// Attempt to deregister the key we just registered since we can't track it.
				_ = p.DeregisterKey(ctx, acctStr, node.PubKey)

				continue
			}

			log.Info().
				Str("provider", provName).
				Uint64("node", node.ID).
				Msg("allocated VPN provider key for node")
		}

		// Deallocate keys for providers that are no longer wanted.
		// Check all registered providers.
		for _, provName := range Registered() {
			if wantProviders[provName] {
				continue
			}

			p, ok := mgr.Provider(provName)
			if !ok {
				continue
			}

			exists, _, nodeKeyStr, acctStr, err := getAlloc(node.ID, provName)
			if err != nil || !exists {
				continue
			}

			// Parse the stored key.
			var nodeKey key.NodePublic
			if err := nodeKey.UnmarshalText([]byte(nodeKeyStr)); err != nil {
				log.Error().Err(err).
					Str("provider", provName).
					Uint64("node", node.ID).
					Msg("failed to parse stored node key for deregistration")

				continue
			}

			if err := p.DeregisterKey(ctx, acctStr, nodeKey); err != nil {
				log.Error().Err(err).
					Str("provider", provName).
					Uint64("node", node.ID).
					Msg("failed to deregister key with provider")
				// Continue to remove DB record anyway — the key may already be gone.
			}

			if err := deleteAlloc(node.ID, provName); err != nil {
				log.Error().Err(err).
					Str("provider", provName).
					Uint64("node", node.ID).
					Msg("failed to delete key allocation record")

				continue
			}

			log.Info().
				Str("provider", provName).
				Uint64("node", node.ID).
				Msg("deallocated VPN provider key for node")
		}
	}

	return nil
}

// ReconcileForNodes is a convenience method on Manager.
func (m *Manager) ReconcileForNodes(
	ctx context.Context,
	nodes []NodeInfo,
	findAccount func(providerName string) (accountID uint, accountStr string, err error),
	getAlloc func(nodeID uint64, providerName string) (exists bool, acctID uint, nodeKey string, accountStr string, err error),
	createAlloc func(accountID uint, nodeID uint64, nodeKey, assignedIPv4, assignedIPv6 string) error,
	deleteAlloc func(nodeID uint64, providerName string) error,
) error {
	return ReconcileAllocations(ctx, m, nodes, findAccount, getAlloc, createAlloc, deleteAlloc)
}
