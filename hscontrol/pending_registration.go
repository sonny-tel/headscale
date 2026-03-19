package hscontrol

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
)

// authenticateWebSession extracts and validates the session cookie from
// an HTTP request. Returns the authenticated user or writes an error response.
func (h *Headscale) authenticateWebSession(w http.ResponseWriter, req *http.Request) (*types.User, bool) {
	cookie, err := req.Cookie("hs_session")
	if err != nil || cookie.Value == "" {
		http.Error(w, `{"error":"session required"}`, http.StatusUnauthorized)
		return nil, false
	}

	session, err := h.state.DB().ValidateUserSession(cookie.Value)
	if err != nil {
		http.Error(w, `{"error":"invalid or expired session"}`, http.StatusUnauthorized)
		return nil, false
	}

	if !session.User.CanWebAuth() {
		http.Error(w, `{"error":"account cannot use web UI"}`, http.StatusForbidden)
		return nil, false
	}

	return &session.User, true
}

// handleRequestRegistration allows any authenticated user to submit a
// device registration request. Admins approve immediately; non-admins
// create a pending registration that requires admin approval.
func (h *Headscale) handleRequestRegistration(w http.ResponseWriter, req *http.Request) {
	caller, ok := h.authenticateWebSession(w, req)
	if !ok {
		return
	}

	var payload struct {
		AuthID string `json:"auth_id"`
	}
	if err := json.NewDecoder(req.Body).Decode(&payload); err != nil || payload.AuthID == "" {
		http.Error(w, `{"error":"auth_id is required"}`, http.StatusBadRequest)
		return
	}

	// Validate auth_id format
	if _, err := types.AuthIDFromString(payload.AuthID); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"invalid auth_id: %s"}`, err.Error()), http.StatusBadRequest)
		return
	}

	// Verify the auth request exists in cache
	if _, ok := h.state.GetAuthCacheEntry(types.AuthID(payload.AuthID)); !ok {
		http.Error(w, `{"error":"registration request not found or expired"}`, http.StatusNotFound)
		return
	}

	// If admin, approve directly using the existing flow
	if caller.IsAdmin() {
		registrationId, _ := types.AuthIDFromString(payload.AuthID)
		node, nodeChange, err := h.state.HandleNodeFromAuthPath(
			registrationId,
			types.UserID(caller.ID),
			nil,
			util.RegisterMethodCLI,
		)
		if err != nil {
			log.Error().Err(err).Str("auth_id", payload.AuthID).Msg("failed to approve registration")
			http.Error(w, fmt.Sprintf(`{"error":"failed to approve: %s"}`, err.Error()), http.StatusInternalServerError)
			return
		}

		routeChange, err := h.state.AutoApproveRoutes(node)
		if err != nil {
			log.Error().Err(err).Msg("auto approving routes")
		}

		h.Change(nodeChange, routeChange)
		h.state.DB().LogAuditEvent("node.approved", caller.Name, "node", payload.AuthID,
			fmt.Sprintf("approved by %s", caller.Name))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "approved"}) //nolint:errcheck
		return
	}

	// Non-admin: create a pending registration request
	pendingID := fmt.Sprintf("pr-%d", time.Now().UnixNano())

	pending := &PendingRegistration{
		ID:            pendingID,
		AuthID:        payload.AuthID,
		RequestedBy:   caller.Name,
		RequestedByID: fmt.Sprintf("%d", caller.ID),
		RequestedAt:   time.Now().UTC().Format(time.RFC3339),
	}

	h.pendingRegistrationsMu.Lock()
	h.pendingRegistrations[pendingID] = pending
	h.pendingRegistrationsMu.Unlock()

	log.Info().
		Str("pending_id", pendingID).
		Str("auth_id", payload.AuthID).
		Str("requested_by", caller.Name).
		Msg("device registration requested, awaiting admin approval")

	h.state.DB().LogAuditEvent("node.registration_requested", caller.Name, "node", payload.AuthID,
		fmt.Sprintf("registration requested by %s", caller.Name))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "pending", "id": pendingID}) //nolint:errcheck
}

// handleListPendingRegistrations returns all pending device registration
// requests. Admin only.
func (h *Headscale) handleListPendingRegistrations(w http.ResponseWriter, req *http.Request) {
	caller, ok := h.authenticateWebSession(w, req)
	if !ok {
		return
	}

	if !caller.IsAdmin() {
		http.Error(w, `{"error":"admin role required"}`, http.StatusForbidden)
		return
	}

	h.pendingRegistrationsMu.RLock()
	pending := make([]*PendingRegistration, 0, len(h.pendingRegistrations))
	for _, p := range h.pendingRegistrations {
		// Only include requests whose auth cache entry is still valid
		if _, ok := h.state.GetAuthCacheEntry(types.AuthID(p.AuthID)); ok {
			pending = append(pending, p)
		}
	}
	h.pendingRegistrationsMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"pending_registrations": pending}) //nolint:errcheck
}

// handleApprovePendingRegistration allows an admin to approve a pending
// device registration request.
func (h *Headscale) handleApprovePendingRegistration(w http.ResponseWriter, req *http.Request) {
	caller, ok := h.authenticateWebSession(w, req)
	if !ok {
		return
	}

	if !caller.IsAdmin() {
		http.Error(w, `{"error":"admin role required"}`, http.StatusForbidden)
		return
	}

	pendingID := chi.URLParam(req, "id")
	if pendingID == "" {
		http.Error(w, `{"error":"pending registration id required"}`, http.StatusBadRequest)
		return
	}

	h.pendingRegistrationsMu.Lock()
	pending, exists := h.pendingRegistrations[pendingID]
	if !exists {
		h.pendingRegistrationsMu.Unlock()
		http.Error(w, `{"error":"pending registration not found"}`, http.StatusNotFound)
		return
	}
	delete(h.pendingRegistrations, pendingID)
	h.pendingRegistrationsMu.Unlock()

	registrationId, err := types.AuthIDFromString(pending.AuthID)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"invalid auth_id: %s"}`, err.Error()), http.StatusBadRequest)
		return
	}

	// Determine owner: use the requesting user as the owner
	ownerUserID := types.UserID(caller.ID)
	if pending.RequestedByID != "" {
		var uid uint
		if _, err := fmt.Sscanf(pending.RequestedByID, "%d", &uid); err == nil {
			ownerUserID = types.UserID(uid)
		}
	}

	node, nodeChange, err := h.state.HandleNodeFromAuthPath(
		registrationId,
		ownerUserID,
		nil,
		util.RegisterMethodCLI,
	)
	if err != nil {
		log.Error().Err(err).Str("auth_id", pending.AuthID).Msg("failed to approve pending registration")
		http.Error(w, fmt.Sprintf(`{"error":"failed to approve: %s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	routeChange, err := h.state.AutoApproveRoutes(node)
	if err != nil {
		log.Error().Err(err).Msg("auto approving routes")
	}

	h.Change(nodeChange, routeChange)

	h.state.DB().LogAuditEvent("node.approved", caller.Name, "node", pending.AuthID,
		fmt.Sprintf("approved by %s (requested by %s)", caller.Name, pending.RequestedBy))

	log.Info().
		Str("pending_id", pendingID).
		Str("auth_id", pending.AuthID).
		Str("approved_by", caller.Name).
		Str("requested_by", pending.RequestedBy).
		Msg("pending device registration approved")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "approved"}) //nolint:errcheck
}

// handleDeletePendingRegistration allows an admin to reject/delete a
// pending device registration request.
func (h *Headscale) handleDeletePendingRegistration(w http.ResponseWriter, req *http.Request) {
	caller, ok := h.authenticateWebSession(w, req)
	if !ok {
		return
	}

	if !caller.IsAdmin() {
		http.Error(w, `{"error":"admin role required"}`, http.StatusForbidden)
		return
	}

	pendingID := chi.URLParam(req, "id")
	if pendingID == "" {
		http.Error(w, `{"error":"pending registration id required"}`, http.StatusBadRequest)
		return
	}

	h.pendingRegistrationsMu.Lock()
	pending, exists := h.pendingRegistrations[pendingID]
	if !exists {
		h.pendingRegistrationsMu.Unlock()
		http.Error(w, `{"error":"pending registration not found"}`, http.StatusNotFound)
		return
	}
	delete(h.pendingRegistrations, pendingID)
	h.pendingRegistrationsMu.Unlock()

	h.state.DB().LogAuditEvent("node.registration_rejected", caller.Name, "node", pending.AuthID,
		fmt.Sprintf("rejected by %s (requested by %s)", caller.Name, pending.RequestedBy))

	log.Info().
		Str("pending_id", pendingID).
		Str("auth_id", pending.AuthID).
		Str("rejected_by", caller.Name).
		Msg("pending device registration rejected")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "rejected"}) //nolint:errcheck
}
