package httpapi

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/1day0fmylife/Guardian/internal/domain"
	"github.com/1day0fmylife/Guardian/internal/security"
	"github.com/1day0fmylife/Guardian/internal/store"
)

// vpnProfileUpdateRequest is a partial update: omitted fields keep their value.
type vpnProfileUpdateRequest struct {
	ExpectedRevision    int64     `json:"expected_revision"`
	Name                *string   `json:"name"`
	ServerPublicKey     *string   `json:"server_public_key"`
	Endpoint            *string   `json:"endpoint"`
	AllowedIPs          *[]string `json:"allowed_ips"`
	DNSServers          *[]string `json:"dns_servers"`
	PersistentKeepalive *int      `json:"persistent_keepalive"`
	AddressPoolID       *string   `json:"address_pool_id"`
	// RotationGraceSeconds keeps the replaced key/endpoint listed as
	// previous_* this long (default 7 days, at most 90 days).
	RotationGraceSeconds *int64 `json:"rotation_grace_seconds"`
}

func (s *Server) getVPNProfile(w http.ResponseWriter, r *http.Request, _ domain.Principal) {
	profile, err := s.store.GetVPNProfile(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, profile)
}

// updateVPNProfile changes the server key, endpoint or tunnel parameters of a
// profile in place. Every enrolled device of the profile gets a new config
// revision and an apply-config command; nobody has to enroll again.
func (s *Server) updateVPNProfile(w http.ResponseWriter, r *http.Request, principal domain.Principal) {
	var input vpnProfileUpdateRequest
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if input.ExpectedRevision <= 0 {
		writeError(w, http.StatusBadRequest, "expected_revision_required", "expected_revision is required")
		return
	}
	update := store.VPNProfileUpdate{
		ExpectedRevision: input.ExpectedRevision, Name: input.Name, ServerPublicKey: input.ServerPublicKey,
		Endpoint: input.Endpoint, AllowedIPs: input.AllowedIPs, DNSServers: input.DNSServers,
		PersistentKeepalive: input.PersistentKeepalive, AddressPoolID: input.AddressPoolID,
	}
	if input.RotationGraceSeconds != nil {
		if *input.RotationGraceSeconds <= 0 || *input.RotationGraceSeconds > int64(store.MaxProfileRotationGrace/time.Second) {
			writeError(w, http.StatusBadRequest, "invalid_rotation_grace", "rotation_grace_seconds must be between 1 and 7776000")
			return
		}
		update.RotationGrace = time.Duration(*input.RotationGraceSeconds) * time.Second
	}
	result, err := s.store.UpdateVPNProfile(r.Context(), auditMeta(r, principal), r.PathValue("id"), update)
	if err != nil {
		if errors.Is(err, security.ErrInvalidWireGuardPublicKey) {
			writeStoreError(w, err)
			return
		}
		writeCatalogError(w, err)
		return
	}
	hub := signalHubFor(s)
	for _, deviceID := range result.NotifiedDeviceIDs {
		hub.publish(deviceID, deviceSignal{Type: "commands_available"})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"profile":               result.Profile,
		"changed":               result.Changed,
		"device_config_changed": result.DeviceConfigChanged,
		"server_key_rotated":    result.ServerKeyRotated,
		"affected_peers":        result.AffectedPeers,
		"notified_devices":      len(result.NotifiedDeviceIDs),
	})
}

func (s *Server) vpnProfileRollout(w http.ResponseWriter, r *http.Request, _ domain.Principal) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	rollout, err := s.store.VPNProfileRollout(r.Context(), r.PathValue("id"), limit)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rollout)
}
