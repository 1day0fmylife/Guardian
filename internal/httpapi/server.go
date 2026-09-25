package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/1day0fmylife/Guardian/internal/domain"
	"github.com/1day0fmylife/Guardian/internal/rbac"
	"github.com/1day0fmylife/Guardian/internal/security"
	"github.com/1day0fmylife/Guardian/internal/store"
)

type contextKey string

const (
	requestIDKey contextKey = "request_id"
	maxBodyBytes            = 1 << 20
)

type Server struct {
	store             *store.Store
	startedAt         time.Time
	publicURL         string
	sessionTTL        time.Duration
	dummyPasswordHash string
}

func New(st *store.Store, publicURL string, sessionTTL time.Duration) *Server {
	dummyHash, _ := security.HashPassword("guardian-invalid-password")
	return &Server{
		store:             st,
		startedAt:         time.Now().UTC(),
		publicURL:         strings.TrimRight(publicURL, "/"),
		sessionTTL:        sessionTTL,
		dummyPasswordHash: dummyHash,
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /readyz", s.ready)
	mux.HandleFunc("GET /api/v1", s.apiRoot)

	mux.HandleFunc("GET /api/v1/setup/status", s.setupStatus)
	mux.HandleFunc("POST /api/v1/auth/bootstrap", s.bootstrap)
	mux.HandleFunc("POST /api/v1/auth/login", s.login)
	mux.HandleFunc("POST /api/v1/device/enroll", s.claimEnrollment)

	mux.HandleFunc("GET /api/v1/me", s.require("", s.me))
	mux.HandleFunc("POST /api/v1/auth/logout", s.require("", s.logout))

	mux.HandleFunc("GET /api/v1/devices", s.require(rbac.DevicesRead, s.listDevices))
	mux.HandleFunc("POST /api/v1/devices", s.require(rbac.DevicesCreate, s.createDevice))
	mux.HandleFunc("GET /api/v1/devices/{id}", s.require(rbac.DevicesRead, s.getDevice))
	mux.HandleFunc("POST /api/v1/devices/{id}/suspend", s.require(rbac.DevicesUpdate, s.suspendDevice))
	mux.HandleFunc("POST /api/v1/devices/{id}/resume", s.require(rbac.DevicesUpdate, s.resumeDevice))

	mux.HandleFunc("GET /api/v1/address-pools", s.require(rbac.PoolsRead, s.listAddressPools))
	mux.HandleFunc("POST /api/v1/address-pools", s.require(rbac.PoolsCreate, s.createAddressPool))

	mux.HandleFunc("GET /api/v1/vpn-profiles", s.require(rbac.ProfilesRead, s.listVPNProfiles))
	mux.HandleFunc("POST /api/v1/vpn-profiles", s.require(rbac.ProfilesCreate, s.createVPNProfile))

	mux.HandleFunc("GET /api/v1/enrollments", s.require(rbac.EnrollmentRead, s.listEnrollments))
	mux.HandleFunc("POST /api/v1/enrollments", s.require(rbac.EnrollmentCreate, s.createEnrollment))
	mux.HandleFunc("POST /api/v1/enrollments/{id}/revoke", s.require(rbac.EnrollmentRevoke, s.revokeEnrollment))

	return s.requestIDMiddleware(s.securityHeaders(mux))
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":         "ok",
		"service":        "guardian-server",
		"uptime_seconds": int64(time.Since(s.startedAt).Seconds()),
	})
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.store.Ping(ctx); err != nil {
		writeError(w, http.StatusServiceUnavailable, "database_unavailable", "database is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ready"})
}

func (s *Server) apiRoot(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"name":    "Guardian API",
		"version": "v1",
	})
}

func (s *Server) setupStatus(w http.ResponseWriter, r *http.Request) {
	count, err := s.store.UserCount(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"bootstrap_required": count == 0})
}

type bootstrapRequest struct {
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Password    string `json:"password"`
}

func (s *Server) bootstrap(w http.ResponseWriter, r *http.Request) {
	var input bootstrapRequest
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	passwordHash, err := security.HashPassword(input.Password)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_password", err.Error())
		return
	}

	user, err := s.store.CreateBootstrapUser(r.Context(), input.Username, input.DisplayName, passwordHash)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "already_bootstrapped", "Guardian has already been bootstrapped")
			return
		}
		writeStoreError(w, err)
		return
	}

	token, expiresAt, err := s.issueSession(r.Context(), user.ID)
	if err != nil {
		writeStoreError(w, err)
		return
	}

	_ = s.audit(r, user.ID, "auth.bootstrap", "user", user.ID, map[string]any{"username": user.Username})
	writeJSON(w, http.StatusCreated, map[string]any{
		"user":       user,
		"token":      token,
		"expires_at": expiresAt.Format(time.RFC3339Nano),
	})
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var input loginRequest
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	user, err := s.store.FindUserForLogin(r.Context(), input.Username)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			_, _ = security.VerifyPassword(input.Password, s.dummyPasswordHash)
			writeError(w, http.StatusUnauthorized, "invalid_credentials", "invalid username or password")
			return
		}
		writeStoreError(w, err)
		return
	}
	if user.Disabled {
		_, _ = security.VerifyPassword(input.Password, user.PasswordHash)
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "invalid username or password")
		return
	}
	ok, err := security.VerifyPassword(input.Password, user.PasswordHash)
	if err != nil || !ok {
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "invalid username or password")
		return
	}

	token, expiresAt, err := s.issueSession(r.Context(), user.ID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	_ = s.audit(r, user.ID, "auth.login", "user", user.ID, nil)
	writeJSON(w, http.StatusOK, map[string]any{
		"token":      token,
		"expires_at": expiresAt.Format(time.RFC3339Nano),
	})
}

func (s *Server) issueSession(ctx context.Context, userID string) (string, time.Time, error) {
	token, err := security.NewOpaqueToken("gdn_s_")
	if err != nil {
		return "", time.Time{}, err
	}
	expiresAt := time.Now().UTC().Add(s.sessionTTL)
	if _, err := s.store.CreateSession(ctx, userID, security.HashToken(token), expiresAt); err != nil {
		return "", time.Time{}, err
	}
	return token, expiresAt, nil
}

func (s *Server) me(w http.ResponseWriter, _ *http.Request, principal domain.Principal) {
	writeJSON(w, http.StatusOK, principal)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, principal domain.Principal) {
	if err := s.store.DeleteSession(r.Context(), principal.TokenHash); err != nil {
		writeStoreError(w, err)
		return
	}
	_ = s.audit(r, principal.UserID, "auth.logout", "user", principal.UserID, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listDevices(w http.ResponseWriter, r *http.Request, _ domain.Principal) {
	limit, offset := pagination(r)
	devices, total, err := s.store.ListDevices(r.Context(), limit, offset)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":  devices,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

func (s *Server) createDevice(w http.ResponseWriter, r *http.Request, principal domain.Principal) {
	var input domain.DeviceCreate
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	device, err := s.store.CreateDevice(r.Context(), input)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "device_exists", "device identity already exists")
			return
		}
		writeStoreError(w, err)
		return
	}
	_ = s.audit(r, principal.UserID, "device.create", "device", device.ID, map[string]any{"device_uuid": device.DeviceUUID})
	writeJSON(w, http.StatusCreated, device)
}

func (s *Server) getDevice(w http.ResponseWriter, r *http.Request, _ domain.Principal) {
	device, err := s.store.GetDevice(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, device)
}

func (s *Server) suspendDevice(w http.ResponseWriter, r *http.Request, principal domain.Principal) {
	s.setDeviceSuspension(w, r, principal, true)
}

func (s *Server) resumeDevice(w http.ResponseWriter, r *http.Request, principal domain.Principal) {
	s.setDeviceSuspension(w, r, principal, false)
}

func (s *Server) setDeviceSuspension(w http.ResponseWriter, r *http.Request, principal domain.Principal, suspended bool) {
	id := r.PathValue("id")
	if err := s.store.SetDeviceSuspended(r.Context(), id, suspended); err != nil {
		writeStoreError(w, err)
		return
	}
	action := "device.resume"
	if suspended {
		action = "device.suspend"
	}
	_ = s.audit(r, principal.UserID, action, "device", id, nil)
	w.WriteHeader(http.StatusNoContent)
}

type addressPoolRequest struct {
	Name       string   `json:"name"`
	CIDR       string   `json:"cidr"`
	Gateway    string   `json:"gateway"`
	DNSServers []string `json:"dns_servers"`
}

func (s *Server) listAddressPools(w http.ResponseWriter, r *http.Request, _ domain.Principal) {
	items, err := s.store.ListAddressPools(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) createAddressPool(w http.ResponseWriter, r *http.Request, principal domain.Principal) {
	var input addressPoolRequest
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	pool, err := s.store.CreateAddressPool(r.Context(), store.AddressPoolCreate{
		Name: input.Name, CIDR: input.CIDR, Gateway: input.Gateway, DNSServers: input.DNSServers,
	})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	_ = s.audit(r, principal.UserID, "address_pool.create", "address_pool", pool.ID, map[string]any{"cidr": pool.CIDR})
	writeJSON(w, http.StatusCreated, pool)
}

type vpnProfileRequest struct {
	Name                string   `json:"name"`
	ServerPublicKey     string   `json:"server_public_key"`
	Endpoint            string   `json:"endpoint"`
	AllowedIPs          []string `json:"allowed_ips"`
	DNSServers          []string `json:"dns_servers"`
	PersistentKeepalive int      `json:"persistent_keepalive"`
	AddressPoolID       string   `json:"address_pool_id"`
}

func (s *Server) listVPNProfiles(w http.ResponseWriter, r *http.Request, _ domain.Principal) {
	items, err := s.store.ListVPNProfiles(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) createVPNProfile(w http.ResponseWriter, r *http.Request, principal domain.Principal) {
	var input vpnProfileRequest
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	profile, err := s.store.CreateVPNProfile(r.Context(), store.VPNProfileCreate{
		Name: input.Name, ServerPublicKey: input.ServerPublicKey, Endpoint: input.Endpoint,
		AllowedIPs: input.AllowedIPs, DNSServers: input.DNSServers,
		PersistentKeepalive: input.PersistentKeepalive, AddressPoolID: input.AddressPoolID,
	})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	_ = s.audit(r, principal.UserID, "vpn_profile.create", "vpn_profile", profile.ID, nil)
	writeJSON(w, http.StatusCreated, profile)
}

type enrollmentCreateRequest struct {
	Name              string `json:"name"`
	ProfileID         string `json:"profile_id"`
	BoundDeviceUUID   string `json:"bound_device_uuid"`
	BoundSerialNumber string `json:"bound_serial_number"`
	BoundMAC          string `json:"bound_mac"`
	TTLSeconds        int    `json:"ttl_seconds"`
}

func (s *Server) listEnrollments(w http.ResponseWriter, r *http.Request, _ domain.Principal) {
	limit, offset := pagination(r)
	items, total, err := s.store.ListEnrollments(r.Context(), limit, offset)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": items, "total": total, "limit": limit, "offset": offset,
	})
}

func (s *Server) createEnrollment(w http.ResponseWriter, r *http.Request, principal domain.Principal) {
	var input enrollmentCreateRequest
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	ttl := time.Duration(input.TTLSeconds) * time.Second
	issued, err := s.store.CreateEnrollment(r.Context(), store.EnrollmentCreate{
		Name: input.Name, ProfileID: input.ProfileID,
		BoundDeviceUUID: input.BoundDeviceUUID, BoundSerialNumber: input.BoundSerialNumber,
		BoundMAC: input.BoundMAC, TTL: ttl, CreatedByUserID: principal.UserID,
	})
	if err != nil {
		writeStoreError(w, err)
		return
	}

	provisioningURI := "guardian://enroll?server=" + url.QueryEscape(s.publicURL) + "&token=" + url.QueryEscape(issued.Token)
	_ = s.audit(r, principal.UserID, "enrollment.create", "enrollment", issued.Enrollment.ID,
		map[string]any{"profile_id": issued.Enrollment.ProfileID, "expires_at": issued.Enrollment.ExpiresAt})

	writeJSON(w, http.StatusCreated, map[string]any{
		"enrollment":       issued.Enrollment,
		"token":            issued.Token,
		"provisioning_uri": provisioningURI,
		"claim_url":        s.publicURL + "/api/v1/device/enroll",
	})
}

func (s *Server) revokeEnrollment(w http.ResponseWriter, r *http.Request, principal domain.Principal) {
	id := r.PathValue("id")
	if err := s.store.RevokeEnrollment(r.Context(), id); err != nil {
		writeStoreError(w, err)
		return
	}
	_ = s.audit(r, principal.UserID, "enrollment.revoke", "enrollment", id, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) claimEnrollment(w http.ResponseWriter, r *http.Request) {
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
	result, err := s.store.ClaimEnrollment(r.Context(), token, input)
	if err != nil {
		switch {
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

type authedHandler func(http.ResponseWriter, *http.Request, domain.Principal)

func (s *Server) require(permission string, next authedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r.Header.Get("Authorization"))
		if token == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="Guardian"`)
			writeError(w, http.StatusUnauthorized, "authentication_required", "bearer authentication is required")
			return
		}
		principal, err := s.store.PrincipalBySession(r.Context(), security.HashToken(token), time.Now().UTC())
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="Guardian"`)
			writeError(w, http.StatusUnauthorized, "invalid_session", "session is invalid or expired")
			return
		}
		if permission != "" && !rbac.HasPermission(principal.Permissions, permission) {
			writeError(w, http.StatusForbidden, "permission_denied", "required permission is not granted")
			return
		}
		next(w, r, principal)
	}
}

func bearerToken(header string) string {
	scheme, token, ok := strings.Cut(strings.TrimSpace(header), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(token)
}

func enrollmentToken(header string) string {
	scheme, token, ok := strings.Cut(strings.TrimSpace(header), " ")
	if !ok || !strings.EqualFold(scheme, "Guardian-Enrollment") {
		return ""
	}
	return strings.TrimSpace(token)
}

func (s *Server) audit(r *http.Request, actor, action, resourceType, resourceID string, details any) error {
	detailsJSON := "{}"
	if details != nil {
		if raw, err := json.Marshal(details); err == nil {
			detailsJSON = string(raw)
		}
	}
	return s.store.AppendAudit(r.Context(), domain.AuditEvent{
		ActorUserID:  actor,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		SourceIP:     remoteIP(r),
		RequestID:    requestID(r),
		Details:      detailsJSON,
	})
}

func (s *Server) requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := security.NewID()
		if err != nil {
			id = strconv.FormatInt(time.Now().UTC().UnixNano(), 36)
		}
		w.Header().Set("X-Request-ID", id)
		ctx := context.WithValue(r.Context(), requestIDKey, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func requestID(r *http.Request) string {
	if value, ok := r.Context().Value(requestIDKey).(string); ok {
		return value
	}
	return ""
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func pagination(r *http.Request) (int, int) {
	limit := 50
	offset := 0
	if value, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && value > 0 {
		limit = value
	}
	if limit > 100 {
		limit = 100
	}
	if value, err := strconv.Atoi(r.URL.Query().Get("offset")); err == nil && value >= 0 {
		offset = value
	}
	return limit, offset
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("invalid JSON body")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("multiple JSON values are not allowed")
	}
	return nil
}

func writeStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "resource was not found")
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, "conflict", "request conflicts with current state")
	case errors.Is(err, security.ErrInvalidWireGuardPublicKey):
		writeError(w, http.StatusBadRequest, "invalid_wireguard_public_key", "WireGuard public key is invalid")
	default:
		// Do not expose driver errors or secrets to API callers.
		writeError(w, http.StatusInternalServerError, "internal_error", "internal server error")
	}
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
