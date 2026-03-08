package hscontrol

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

type AuthProvider interface {
	RegisterHandler(w http.ResponseWriter, r *http.Request)
	AuthHandler(w http.ResponseWriter, r *http.Request)
	RegisterURL(authID types.AuthID) string
	AuthURL(authID types.AuthID) string
}

func (h *Headscale) handleRegister(
	ctx context.Context,
	req tailcfg.RegisterRequest,
	machineKey key.MachinePublic,
) (*tailcfg.RegisterResponse, error) {
	// Check for logout/expiry FIRST, before checking auth key.
	// Tailscale clients may send logout requests with BOTH a past expiry AND an auth key.
	// A past expiry takes precedence - it's a logout regardless of other fields.
	if !req.Expiry.IsZero() && req.Expiry.Before(time.Now()) {
		log.Debug().
			Str("node.key", req.NodeKey.ShortString()).
			Time("expiry", req.Expiry).
			Bool("has_auth", req.Auth != nil).
			Msg("Detected register request with past expiry")

		if node, ok := h.state.GetNodeByNodeKey(req.NodeKey); ok {
			if node.MachineKey() != machineKey {
				return nil, NewHTTPError(http.StatusUnauthorized, "machine key mismatch", nil)
			}

			// If the node is already expired, the client is echoing stale logout
			// state (e.g. the time.Unix(123,0) logout marker from a previous
			// session). Clear the stale expiry and allow reconnection rather than
			// perpetuating a re-auth loop.
			if node.IsExpired() {
				log.Info().
					EmbedObject(node).
					Time("stale_expiry", node.Expiry().Get()).
					Time("req_expiry", req.Expiry).
					Msg("Clearing stale expiry on node with past expiry in register request")

				updatedNode, c, err := h.state.SetNodeExpiry(node.ID(), nil)
				if err != nil {
					return nil, fmt.Errorf("clearing stale node expiry: %w", err)
				}

				h.Change(c)

				return nodeToRegisterResponse(updatedNode), nil
			}

			// Node is NOT expired — this is a fresh logout request.
			log.Debug().
				EmbedObject(node).
				Bool("is_ephemeral", node.IsEphemeral()).
				Bool("has_authkey", node.AuthKey().Valid()).
				Msg("Found non-expired node for logout, calling handleLogout")

			resp, err := h.handleLogout(node, req, machineKey)
			if err != nil {
				return nil, fmt.Errorf("handling logout: %w", err)
			}

			if resp != nil {
				return resp, nil
			}
		} else {
			log.Debug().
				Str("node.key", req.NodeKey.ShortString()).
				Msg("Past expiry request but node not found by NodeKey, falling through")
		}
	}

	// If the register request does not contain a Auth struct, it means we are logging
	// out an existing node (legacy logout path for clients that send Auth=nil).
	if req.Auth == nil {
		// If the register request present a NodeKey that is currently in use, we will
		// check if the node needs to be sent to re-auth, or if the node is logging out.
		// We do not look up nodes by [key.MachinePublic] as it might belong to multiple
		// nodes, separated by users and this path is handling expiring/logout paths.
		if node, ok := h.state.GetNodeByNodeKey(req.NodeKey); ok {
			// When tailscaled restarts, it sends RegisterRequest with Auth=nil and Expiry=zero.
			// Return the current node state without modification.
			// See: https://github.com/juanfont/headscale/issues/2862
			//
			// We check !node.IsExpired() which covers all non-expired states:
			// - nil Expiry (never set, e.g. web auth) → not expired
			// - zero time Expiry (IsZero=true) → not expired
			// - future Expiry → not expired
			// Previously this used node.Expiry().Valid() which returns false for nil
			// Expiry pointers, causing web-auth nodes to incorrectly fall through
			// to handleLogout on every reconnection.
			if req.Expiry.IsZero() && !node.IsExpired() {
				return nodeToRegisterResponse(node), nil
			}

			// If the client sends Expiry=zero but the node has a stale past expiry
			// (e.g. epoch time from a previous logout), the client is reconnecting
			// after having already re-authenticated. Clear the stale expiry and
			// allow the reconnection instead of forcing another re-auth loop.
			if req.Expiry.IsZero() && node.IsExpired() {
				log.Info().
					EmbedObject(node).
					Time("stale_expiry", node.Expiry().Get()).
					Msg("Clearing stale expiry on reconnecting node")

				updatedNode, c, err := h.state.SetNodeExpiry(node.ID(), nil)
				if err != nil {
					return nil, fmt.Errorf("clearing stale node expiry: %w", err)
				}

				h.Change(c)

				return nodeToRegisterResponse(updatedNode), nil
			}

			resp, err := h.handleLogout(node, req, machineKey)
			if err != nil {
				return nil, fmt.Errorf("handling existing node: %w", err)
			}

			// If resp is not nil, we have a response to return to the node.
			// If resp is nil, we should proceed and see if the node is trying to re-auth.
			if resp != nil {
				return resp, nil
			}
		} else if !req.OldNodeKey.IsZero() {
			// The client rotated its NodeKey (e.g. because it thought the key was expired).
			// The new NodeKey isn't in the store, but the old one might be.
			// Look up the node by OldNodeKey, update the key, and allow reconnection.
			if node, ok := h.state.GetNodeByNodeKey(req.OldNodeKey); ok {
				if node.MachineKey() != machineKey {
					return nil, NewHTTPError(http.StatusUnauthorized, "machine key mismatch on node key rotation", nil)
				}

				log.Info().
					EmbedObject(node).
					Str("old_node_key", req.OldNodeKey.ShortString()).
					Str("new_node_key", req.NodeKey.ShortString()).
					Msg("Node key rotation on reconnect, updating key and clearing expiry")

				updatedNode, ok := h.state.NodeStoreUpdateNode(node.ID(), func(n *types.Node) {
					n.NodeKey = req.NodeKey
					n.Expiry = nil
				})
				if !ok {
					return nil, fmt.Errorf("failed to update node key in store")
				}

				if err := h.state.PersistNodeKeyAndExpiry(node.ID(), req.NodeKey, nil); err != nil {
					return nil, fmt.Errorf("persisting node key rotation: %w", err)
				}

				c := change.NodeAdded(node.ID())
				h.Change(c)

				return nodeToRegisterResponse(updatedNode), nil
			}

			log.Debug().
				Str("node.key", req.NodeKey.ShortString()).
				Str("old_node.key", req.OldNodeKey.ShortString()).
				Str("machine.key", machineKey.ShortString()).
				Msg("Node key rotation but old key not found either")
		} else {
			// If the register request is not attempting to register a node, and
			// we cannot match it with an existing node, we consider that unexpected
			// as only register nodes should attempt to log out.
			log.Debug().
				Str("node.key", req.NodeKey.ShortString()).
				Str("machine.key", machineKey.ShortString()).
				Bool("unexpected", true).
				Msg("received register request with no auth, and no existing node")
		}
	}

	// If the [tailcfg.RegisterRequest] has a Followup URL, it means that the
	// node has already started the registration process and we should wait for
	// it to finish the original registration.
	if req.Followup != "" {
		return h.waitForFollowup(ctx, req, machineKey)
	}

	// Pre authenticated keys are handled slightly different than interactive
	// logins as they can be done fully sync and we can respond to the node with
	// the result as it is waiting.
	if isAuthKey(req) {
		resp, err := h.handleRegisterWithAuthKey(req, machineKey)
		if err != nil {
			// Preserve HTTPError types so they can be handled properly by the HTTP layer
			if httpErr, ok := errors.AsType[HTTPError](err); ok {
				return nil, httpErr
			}

			return nil, fmt.Errorf("handling register with auth key: %w", err)
		}

		return resp, nil
	}

	resp, err := h.handleRegisterInteractive(req, machineKey)
	if err != nil {
		return nil, fmt.Errorf("handling register interactive: %w", err)
	}

	return resp, nil
}

// handleLogout checks if the [tailcfg.RegisterRequest] is a
// logout attempt from a node. If the node is not attempting to.
func (h *Headscale) handleLogout(
	node types.NodeView,
	req tailcfg.RegisterRequest,
	machineKey key.MachinePublic,
) (*tailcfg.RegisterResponse, error) {
	// Fail closed if it looks like this is an attempt to modify a node where
	// the node key and the machine key the noise session was started with does
	// not align.
	if node.MachineKey() != machineKey {
		return nil, NewHTTPError(http.StatusUnauthorized, "node exist with different machine key", nil)
	}

	// Note: We do NOT return early if req.Auth is set, because Tailscale clients
	// may send logout requests with BOTH a past expiry AND an auth key.
	// A past expiry indicates logout, regardless of whether Auth is present.
	// The expiry check below will handle the logout logic.

	// If the node is already expired, clear the stale expiry and allow
	// reconnection rather than forcing re-authentication. handleRegister
	// handles most stale-expiry cases before calling us, but this covers
	// edge cases (e.g. legacy paths).
	if node.IsExpired() {
		log.Info().
			EmbedObject(node).
			Time("stale_expiry", node.Expiry().Get()).
			Msg("Clearing stale expiry in handleLogout for already-expired node")

		updatedNode, c, err := h.state.SetNodeExpiry(node.ID(), nil)
		if err != nil {
			return nil, fmt.Errorf("clearing stale node expiry in handleLogout: %w", err)
		}

		h.Change(c)

		return nodeToRegisterResponse(updatedNode), nil
	}

	// If we get here, the node is not currently expired, and not trying to
	// do an auth.
	// The node is likely logging out, but before we run that logic, we will validate
	// that the node is not attempting to tamper/extend their expiry.
	// If it is not, we will expire the node or in the case of an ephemeral node, delete it.

	// The client is trying to extend their key, this is not allowed.
	if req.Expiry.After(time.Now()) {
		return nil, NewHTTPError(http.StatusBadRequest, "extending key is not allowed", nil)
	}

	// If the request expiry is in the past, we consider it a logout.
	// Zero expiry is handled in handleRegister() before calling this function.
	if req.Expiry.Before(time.Now()) {
		log.Debug().
			EmbedObject(node).
			Bool("is_ephemeral", node.IsEphemeral()).
			Bool("has_authkey", node.AuthKey().Valid()).
			Time("req.expiry", req.Expiry).
			Msg("Processing logout request with past expiry")

		if node.IsEphemeral() {
			log.Info().
				EmbedObject(node).
				Msg("Deleting ephemeral node during logout")

			c, err := h.state.DeleteNode(node)
			if err != nil {
				return nil, fmt.Errorf("deleting ephemeral node: %w", err)
			}

			h.Change(c)

			return &tailcfg.RegisterResponse{
				NodeKeyExpired:    true,
				MachineAuthorized: false,
			}, nil
		}

		log.Debug().
			EmbedObject(node).
			Msg("Node is not ephemeral, setting expiry instead of deleting")
	}

	// Update the internal state with the nodes new expiry, meaning it is
	// logged out.
	expiry := req.Expiry

	updatedNode, c, err := h.state.SetNodeExpiry(node.ID(), &expiry)
	if err != nil {
		return nil, fmt.Errorf("setting node expiry: %w", err)
	}

	h.Change(c)

	return nodeToRegisterResponse(updatedNode), nil
}

// isAuthKey reports if the register request is a registration request
// using an pre auth key.
func isAuthKey(req tailcfg.RegisterRequest) bool {
	return req.Auth != nil && req.Auth.AuthKey != ""
}

func nodeToRegisterResponse(node types.NodeView) *tailcfg.RegisterResponse {
	resp := &tailcfg.RegisterResponse{
		NodeKeyExpired: node.IsExpired(),

		// Headscale does not implement the concept of machine authorization
		// so we always return true here.
		// Revisit this if #2176 gets implemented.
		MachineAuthorized: true,
	}

	// For tagged nodes, use the TaggedDevices special user
	// For user-owned nodes, include User and Login information from the actual user
	if node.IsTagged() {
		resp.User = types.TaggedDevices.View().TailscaleUser()
		resp.Login = types.TaggedDevices.View().TailscaleLogin()
	} else if node.Owner().Valid() {
		resp.User = node.Owner().TailscaleUser()
		resp.Login = node.Owner().TailscaleLogin()
	}

	return resp
}

func (h *Headscale) waitForFollowup(
	ctx context.Context,
	req tailcfg.RegisterRequest,
	machineKey key.MachinePublic,
) (*tailcfg.RegisterResponse, error) {
	fu, err := url.Parse(req.Followup)
	if err != nil {
		return nil, NewHTTPError(http.StatusUnauthorized, "invalid followup URL", err)
	}

	followupReg, err := types.AuthIDFromString(strings.ReplaceAll(fu.Path, "/register/", ""))
	if err != nil {
		return nil, NewHTTPError(http.StatusUnauthorized, "invalid registration ID", err)
	}

	if reg, ok := h.state.GetAuthCacheEntry(followupReg); ok {
		select {
		case <-ctx.Done():
			return nil, NewHTTPError(http.StatusUnauthorized, "registration timed out", err)
		case verdict := <-reg.WaitForAuth():
			if verdict.Accept() {
				if !verdict.Node.Valid() {
					// registration is expired in the cache, instruct the client to try a new registration
					return h.reqToNewRegisterResponse(req, machineKey)
				}

				return nodeToRegisterResponse(verdict.Node), nil
			}
		}
	}

	// if the follow-up registration isn't found anymore, instruct the client to try a new registration
	return h.reqToNewRegisterResponse(req, machineKey)
}

// reqToNewRegisterResponse refreshes the registration flow by creating a new
// registration ID and returning the corresponding AuthURL so the client can
// restart the authentication process.
func (h *Headscale) reqToNewRegisterResponse(
	req tailcfg.RegisterRequest,
	machineKey key.MachinePublic,
) (*tailcfg.RegisterResponse, error) {
	newAuthID, err := types.NewAuthID()
	if err != nil {
		return nil, NewHTTPError(http.StatusInternalServerError, "failed to generate registration ID", err)
	}

	// Ensure we have a valid hostname
	hostname := util.EnsureHostname(
		req.Hostinfo.View(),
		machineKey.String(),
		req.NodeKey.String(),
	)

	// Ensure we have valid hostinfo
	hostinfo := cmp.Or(req.Hostinfo, &tailcfg.Hostinfo{})
	hostinfo.Hostname = hostname

	nodeToRegister := types.Node{
		Hostname:   hostname,
		MachineKey: machineKey,
		NodeKey:    req.NodeKey,
		Hostinfo:   hostinfo,
		LastSeen:   new(time.Now()),
	}

	if !req.Expiry.IsZero() {
		nodeToRegister.Expiry = &req.Expiry
	}

	authRegReq := types.NewRegisterAuthRequest(nodeToRegister)

	log.Info().Msgf("new followup node registration using auth id: %s", newAuthID)
	h.state.SetAuthCacheEntry(newAuthID, authRegReq)

	return &tailcfg.RegisterResponse{
		AuthURL: h.authProvider.RegisterURL(newAuthID),
	}, nil
}

func (h *Headscale) handleRegisterWithAuthKey(
	req tailcfg.RegisterRequest,
	machineKey key.MachinePublic,
) (*tailcfg.RegisterResponse, error) {
	node, changed, err := h.state.HandleNodeFromPreAuthKey(
		req,
		machineKey,
	)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, NewHTTPError(http.StatusUnauthorized, "invalid pre auth key", nil)
		}

		if perr, ok := errors.AsType[types.PAKError](err); ok {
			return nil, NewHTTPError(http.StatusUnauthorized, perr.Error(), nil)
		}

		return nil, err
	}

	// If node is not valid, it means an ephemeral node was deleted during logout
	if !node.Valid() {
		h.Change(changed)
		return nil, nil //nolint:nilnil // intentional: no node to return when ephemeral deleted
	}

	// This is a bit of a back and forth, but we have a bit of a chicken and egg
	// dependency here.
	// Because the way the policy manager works, we need to have the node
	// in the database, then add it to the policy manager and then we can
	// approve the route. This means we get this dance where the node is
	// first added to the database, then we add it to the policy manager via
	// nodesChangedHook and then we can auto approve the routes.
	// As that only approves the struct object, we need to save it again and
	// ensure we send an update.
	// This works, but might be another good candidate for doing some sort of
	// eventbus.
	// TODO(kradalby): This needs to be ran as part of the batcher maybe?
	// now since we dont update the node/pol here anymore
	routesChange, err := h.state.AutoApproveRoutes(node)
	if err != nil {
		return nil, fmt.Errorf("auto approving routes: %w", err)
	}

	// Send both changes. Empty changes are ignored by Change().
	h.Change(changed, routesChange)

	resp := &tailcfg.RegisterResponse{
		MachineAuthorized: true,
		NodeKeyExpired:    node.IsExpired(),
		User:              node.Owner().TailscaleUser(),
		Login:             node.Owner().TailscaleLogin(),
	}

	log.Trace().
		Caller().
		Interface("reg.resp", resp).
		Interface("reg.req", req).
		EmbedObject(node).
		Msg("RegisterResponse")

	return resp, nil
}

func (h *Headscale) handleRegisterInteractive(
	req tailcfg.RegisterRequest,
	machineKey key.MachinePublic,
) (*tailcfg.RegisterResponse, error) {
	authID, err := types.NewAuthID()
	if err != nil {
		return nil, fmt.Errorf("generating registration ID: %w", err)
	}

	// Ensure we have a valid hostname
	hostname := util.EnsureHostname(
		req.Hostinfo.View(),
		machineKey.String(),
		req.NodeKey.String(),
	)

	// Ensure we have valid hostinfo
	hostinfo := cmp.Or(req.Hostinfo, &tailcfg.Hostinfo{})
	if req.Hostinfo == nil {
		log.Warn().
			Str("machine.key", machineKey.ShortString()).
			Str("node.key", req.NodeKey.ShortString()).
			Str("generated.hostname", hostname).
			Msg("Received registration request with nil hostinfo, generated default hostname")
	} else if req.Hostinfo.Hostname == "" {
		log.Warn().
			Str("machine.key", machineKey.ShortString()).
			Str("node.key", req.NodeKey.ShortString()).
			Str("generated.hostname", hostname).
			Msg("Received registration request with empty hostname, generated default")
	}

	hostinfo.Hostname = hostname

	nodeToRegister := types.Node{
		Hostname:   hostname,
		MachineKey: machineKey,
		NodeKey:    req.NodeKey,
		Hostinfo:   hostinfo,
		LastSeen:   new(time.Now()),
	}

	if !req.Expiry.IsZero() {
		nodeToRegister.Expiry = &req.Expiry
	}

	authRegReq := types.NewRegisterAuthRequest(nodeToRegister)

	h.state.SetAuthCacheEntry(
		authID,
		authRegReq,
	)

	log.Info().Msgf("starting node registration using auth id: %s", authID)

	return &tailcfg.RegisterResponse{
		AuthURL: h.authProvider.RegisterURL(authID),
	}, nil
}
