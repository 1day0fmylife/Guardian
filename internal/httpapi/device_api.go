package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/1day0fmylife/Guardian/internal/domain"
	"github.com/1day0fmylife/Guardian/internal/rbac"
	"github.com/1day0fmylife/Guardian/internal/security"
	"github.com/1day0fmylife/Guardian/internal/store"
)

type deviceHandler func(http.ResponseWriter, *http.Request, domain.DevicePrincipal)

// ManagementHandler extends the original administrative API with the managed
// device channel. Existing routes continue to be served by Handler().
func (s *Server) ManagementHandler() http.Handler {
	mux := http.NewServeMux()
	wrap := func(handler http.Handler) http.Handler {
		return s.requestIDMiddleware(s.securityHeaders(handler))
	}

	// Enrollment is shadowed here so credential issuance is part of the same
	// database transaction as peer creation and enrollment consumption.
	mux.Handle("POST /api/v1/device/enroll", wrap(http.HandlerFunc(s.claimManagedEnrollment)))

	mux.Handle("GET /api/v1/device/me", wrap(s.requireDevice(false, s.deviceMe)))
	mux.Handle("GET /api/v1/device/config", wrap(s.requireDevice(true, s.deviceConfig)))
	mux.Handle("GET /api/v1/device/commands", wrap(s.requireDevice(false, s.devicePollCommands)))
	mux.Handle("POST /api/v1/device/commands/{id}/result", wrap(s.requireDevice(false, s.deviceCommandResult)))
	mux.Handle("POST /api/v1/device/telemetry", wrap(s.requireDevice(false, s.deviceTelemetry)))
	mux.Handle("POST /api/v1/device/credential/rotate", wrap(s.requireDevice(true, s.deviceRotateCredential)))
	mux.Handle("POST /api/v1/device/wireguard/rotate-key", wrap(s.requireDevice(true, s.deviceRotateWireGuardKey)))

	mux.Handle("GET /api/v1/devices/{id}/commands", wrap(s.require(rbac.CommandsRead, s.adminListDeviceCommands)))
	mux.Handle("POST /api/v1/devices/{id}/commands", wrap(s.require(rbac.CommandsCreate, s.adminCreateDeviceCommand)))
	mux.Handle("GET /api/v1/devices/{id}/telemetry/latest", wrap(s.require(rbac.DevicesRead, s.adminLatestTelemetry)))
	mux.Handle("POST /api/v1/devices/{id}/credentials/revoke", wrap(s.require(rbac.DevicesUpdate, s.adminRevokeDeviceCredentials)))
	mux.Handle("POST /api/v1/devices/{id}/suspend", wrap(s.require(rbac.DevicesUpdate, s.adminSuspendDevice)))

	mux.Handle("/", s.Handler())
	return mux
}

func (s *Server) requireDevice(activeRequired bool, next deviceHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := deviceToken(r.Header.Get("Authorization"))
		if token == "" {
			w.Header().Set("WWW-Authenticate", `Guardian-Device realm="Guardian"`)
			writeError(w, http.StatusUnauthorized, "device_authentication_required", "device credential is required")
			return
		}
		principal, err := s.store.DevicePrincipalByCredential(r.Context(), security.HashToken(token))
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Guardian-Device realm="Guardian"`)
			writeError(w, http.StatusUnauthorized, "invalid_device_credential", "device credential is invalid or revoked")
			return
		}
		if activeRequired && (principal.Suspended || principal.Status != "active") {
			writeError(w, http.StatusForbidden, "device_not_active", "device is not allowed to perform this operation")
			return
		}
		next(w, r, principal)
	}
}

func deviceToken(header string) string {
	scheme, token, ok := strings.Cut(strings.TrimSpace(header), " ")
	if !ok || !strings.EqualFold(scheme, "Guardian-Device") {
		return ""
	}
	return strings.TrimSpace(token)
}

func (s *Server) claimManagedEnrollment(w http.ResponseWriter, r *http.Request) {
	token := enrollmentToken(r.Header.Get("Authorization"))
	if token == "" {
		writeError(w, http.StatusUnauthorized, "enrollment_token_required", "valid enrollment authorization is required")
		return
	}
	var input domain.EnrollmentClaim
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	result, err := s.store.ClaimManagedEnrollment(r.Context(), token, input)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrInvalid), errors.Is(err, security.ErrInvalidWireGuardPublicKey):
			writeError(w, http.StatusBadRequest, "invalid_enrollment_request", "enrollment request is invalid")
		case errors.Is(err, store.ErrNotFound):
			writeError(w, http.StatusUnauthorized, "invalid_enrollment", "enrollment token is invalid")
		case errors.Is(err, store.ErrConflict):
			writeError(w, http.StatusConflict, "enrollment_rejected", "enrollment is expired, consumed, revoked, or does not match the device")
		default:
			writeStoreError(w, err)
		}
		return
	}
	_ = s.audit(r, "", "enrollment.claim", "device", result.Device.ID, map[string]any{
		"device_uuid": result.Device.DeviceUUID,
		"profile_id":  result.Config.ProfileID,
	})
	writeJSON(w, http.StatusCreated, result)
}

func (s *Server) deviceMe(w http.ResponseWriter, _ *http.Request, principal domain.DevicePrincipal) {
	writeJSON(w, http.StatusOK, principal)
}

func (s *Server) deviceConfig(w http.ResponseWriter, r *http.Request, principal domain.DevicePrincipal) {
	cfg, err := s.store.ManagedConfigForDevice(r.Context(), principal.DeviceID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) devicePollCommands(w http.ResponseWriter, r *http.Request, principal domain.DevicePrincipal) {
	limit, _ := pagination(r)
	if limit > 50 {
		limit = 50
	}
	items, err := s.store.PollDeviceCommands(r.Context(), principal.DeviceID, limit, principal.Suspended)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

type deviceCommandResultRequest struct {
	Status       string          `json:"status"`
	Result       json.RawMessage `json:"result"`
	ErrorMessage string          `json:"error_message"`
}

func (s *Server) deviceCommandResult(w http.ResponseWriter, r *http.Request, principal domain.DevicePrincipal) {
	var input deviceCommandResultRequest
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := s.store.UpdateDeviceCommandResult(r.Context(), principal.DeviceID, r.PathValue("id"), input.Status, input.Result, input.ErrorMessage); err != nil {
		writeManagementStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) deviceTelemetry(w http.ResponseWriter, r *http.Request, principal domain.DevicePrincipal) {
	var input domain.DeviceTelemetryInput
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	telemetry, err := s.store.RecordDeviceTelemetry(r.Context(), principal.DeviceID, input)
	if err != nil {
		writeManagementStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, telemetry)
}

func (s *Server) deviceRotateCredential(w http.ResponseWriter, r *http.Request, principal domain.DevicePrincipal) {
	issued, err := s.store.RotateDeviceCredential(r.Context(), principal)
	if err != nil {
		writeManagementStoreError(w, err)
		return
	}
	_ = s.audit(r, "", "device.credential.rotate", "device", principal.DeviceID, nil)
	writeJSON(w, http.StatusCreated, issued)
}

type deviceWireGuardKeyRotationRequest struct {
	PublicKey        string `json:"public_key"`
	ExpectedRevision int64  `json:"expected_revision"`
}

func (s *Server) deviceRotateWireGuardKey(w http.ResponseWriter, r *http.Request, principal domain.DevicePrincipal) {
	var input deviceWireGuardKeyRotationRequest
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	cfg, err := s.store.RotateDeviceWireGuardPublicKey(r.Context(), principal.DeviceID, input.PublicKey, input.ExpectedRevision)
	if err != nil {
		if errors.Is(err, security.ErrInvalidWireGuardPublicKey) {
			writeError(w, http.StatusBadRequest, "invalid_wireguard_public_key", "WireGuard public key is invalid")
			return
		}
		writeManagementStoreError(w, err)
		return
	}
	_ = s.audit(r, "", "wireguard.key.rotate", "device", principal.DeviceID, map[string]any{"config_revision": cfg.ConfigRevision})
	writeJSON(w, http.StatusAccepted, map[string]any{"wireguard": cfg, "reconcile_pending": true})
}

type adminCommandCreateRequest struct {
	Type           string          `json:"type"`
	IdempotencyKey string          `json:"idempotency_key"`
	Payload        json.RawMessage `json:"payload"`
	TTLSeconds     int             `json:"ttl_seconds"`
}

func (s *Server) adminCreateDeviceCommand(w http.ResponseWriter, r *http.Request, principal domain.Principal) {
	var input adminCommandCreateRequest
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	required := commandPermission(input.Type)
	if required == "" {
		writeError(w, http.StatusBadRequest, "invalid_command_type", "unsupported device command type")
		return
	}
	if !rbac.HasPermission(principal.Permissions, required) {
		writeError(w, http.StatusForbidden, "permission_denied", "required device-action permission is not granted")
		return
	}
	cmd, err := s.store.CreateDeviceCommand(r.Context(), store.DeviceCommandCreate{
		DeviceID: r.PathValue("id"), Type: input.Type, IdempotencyKey: input.IdempotencyKey,
		Payload: input.Payload, TTL: time.Duration(input.TTLSeconds) * time.Second,
	})
	if err != nil {
		writeManagementStoreError(w, err)
		return
	}
	_ = s.audit(r, principal.UserID, "device.command.create", "device_command", cmd.ID, map[string]any{
		"device_id": cmd.DeviceID,
		"type":      cmd.Type,
	})
	writeJSON(w, http.StatusCreated, cmd)
}

func (s *Server) adminListDeviceCommands(w http.ResponseWriter, r *http.Request, _ domain.Principal) {
	limit, offset := pagination(r)
	items, total, err := s.store.ListDeviceCommands(r.Context(), r.PathValue("id"), limit, offset)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total, "limit": limit, "offset": offset})
}

func (s *Server) adminLatestTelemetry(w http.ResponseWriter, r *http.Request, _ domain.Principal) {
	telemetry, err := s.store.LatestDeviceTelemetry(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, telemetry)
}

func (s *Server) adminRevokeDeviceCredentials(w http.ResponseWriter, r *http.Request, principal domain.Principal) {
	deviceID := r.PathValue("id")
	if err := s.store.RevokeDeviceCredentials(r.Context(), deviceID); err != nil {
		writeStoreError(w, err)
		return
	}
	_ = s.audit(r, principal.UserID, "device.credential.revoke", "device", deviceID, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) adminSuspendDevice(w http.ResponseWriter, r *http.Request, principal domain.Principal) {
	deviceID := r.PathValue("id")
	cmd, err := s.store.SuspendDeviceAndQueueDisconnect(r.Context(), deviceID)
	if err != nil {
		writeManagementStoreError(w, err)
		return
	}
	_ = s.audit(r, principal.UserID, "device.suspend", "device", deviceID, map[string]any{"disconnect_command_id": cmd.ID})
	writeJSON(w, http.StatusAccepted, map[string]any{"device_id": deviceID, "disconnect_command": cmd})
}

func commandPermission(commandType string) string {
	switch strings.TrimSpace(commandType) {
	case "connect":
		return rbac.DevicesConnect
	case "disconnect":
		return rbac.DevicesDisconnect
	case "rotate-key":
		return rbac.DevicesRotateKey
	case "apply-config":
		return rbac.DevicesReconfigure
	default:
		return ""
	}
}

func writeManagementStoreError(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrInvalid) {
		writeError(w, http.StatusBadRequest, "invalid_request", "request is invalid")
		return
	}
	writeStoreError(w, err)
}
