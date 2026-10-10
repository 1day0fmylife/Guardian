package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/1day0fmylife/Guardian/internal/domain"
	"github.com/1day0fmylife/Guardian/internal/rbac"
	"github.com/1day0fmylife/Guardian/internal/store"
)

// registerServiceCatalogRoutes mounts the administrative service catalog,
// grant and device-scope endpoints. Reads need services.read; every mutation
// needs services.manage and is audited in the same transaction.
func (s *Server) registerServiceCatalogRoutes(mux *http.ServeMux) {
	wrap := func(h http.HandlerFunc) http.Handler {
		return s.requestIDMiddleware(s.securityHeaders(h))
	}
	mux.Handle("GET /api/v1/services", wrap(s.require(rbac.ServicesRead, s.adminListServices)))
	mux.Handle("GET /api/v1/services/{id}", wrap(s.require(rbac.ServicesRead, s.adminGetService)))
	mux.Handle("PUT /api/v1/services/{id}", wrap(s.require(rbac.ServicesManage, s.adminUpdateService)))
	mux.Handle("GET /api/v1/services/{id}/revisions", wrap(s.require(rbac.ServicesRead, s.adminListServiceRevisions)))
	mux.Handle("GET /api/v1/services/{id}/grants", wrap(s.require(rbac.ServicesRead, s.adminListServiceGrants)))
	mux.Handle("POST /api/v1/services/{id}/grants", wrap(s.require(rbac.ServicesManage, s.adminSetServiceGrant)))
	mux.Handle("DELETE /api/v1/services/{id}/grants/{grant_id}", wrap(s.require(rbac.ServicesManage, s.adminRevokeServiceGrant)))
	mux.Handle("GET /api/v1/devices/{id}/services", wrap(s.require(rbac.ServicesRead, s.adminDeviceServicePolicy)))
	mux.Handle("GET /api/v1/devices/{id}/scopes", wrap(s.require(rbac.ServicesRead, s.adminGetDeviceScopes)))
	mux.Handle("PUT /api/v1/devices/{id}/scopes", wrap(s.require(rbac.ServicesManage, s.adminSetDeviceScopes)))
}

func auditMeta(r *http.Request, principal domain.Principal) store.AuditMeta {
	return store.AuditMeta{ActorUserID: principal.UserID, SourceIP: remoteIP(r), RequestID: requestID(r)}
}

func writeCatalogError(w http.ResponseWriter, err error) {
	var catalogErr *store.ServiceCatalogError
	if errors.As(err, &catalogErr) {
		status := http.StatusInternalServerError
		switch {
		case errors.Is(catalogErr, store.ErrInvalid):
			status = http.StatusBadRequest
		case errors.Is(catalogErr, store.ErrNotFound):
			status = http.StatusNotFound
		case errors.Is(catalogErr, store.ErrConflict):
			status = http.StatusConflict
		}
		writeError(w, status, catalogErr.Code, catalogErr.Message)
		return
	}
	writeManagementStoreError(w, err)
}

func (s *Server) adminListServices(w http.ResponseWriter, r *http.Request, _ domain.Principal) {
	limit, offset := pagination(r)
	var filter store.ServiceDefinitionFilter
	if raw := r.URL.Query().Get("enabled"); raw != "" {
		switch raw {
		case "true":
			v := true
			filter.Enabled = &v
		case "false":
			v := false
			filter.Enabled = &v
		default:
			writeError(w, http.StatusBadRequest, "invalid_filter", "enabled must be true or false")
			return
		}
	}
	items, total, err := s.store.ListServiceDefinitions(r.Context(), filter, limit, offset)
	if err != nil {
		writeCatalogError(w, err)
		return
	}
	revision, err := s.store.ServicePolicyRevision(r.Context())
	if err != nil {
		writeCatalogError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": items, "total": total, "limit": limit, "offset": offset, "policy_revision": revision,
	})
}

func (s *Server) adminGetService(w http.ResponseWriter, r *http.Request, _ domain.Principal) {
	def, err := s.store.GetServiceDefinition(r.Context(), r.PathValue("id"))
	if err != nil {
		writeCatalogError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, def)
}

type serviceUpdateRequest struct {
	ExpectedRevision int64 `json:"expected_revision"`
	domain.ServiceDefinitionInput
}

func (s *Server) adminUpdateService(w http.ResponseWriter, r *http.Request, principal domain.Principal) {
	var input serviceUpdateRequest
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	result, err := s.store.UpdateServiceDefinition(r.Context(), auditMeta(r, principal), r.PathValue("id"),
		input.ExpectedRevision, input.ServiceDefinitionInput)
	if err != nil {
		writeCatalogError(w, err)
		return
	}
	if result.Changed {
		signalHubFor(s).publishPolicy("", result.PolicyRevision)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"service": result.Definition, "policy_revision": result.PolicyRevision, "changed": result.Changed,
	})
}

func (s *Server) adminListServiceRevisions(w http.ResponseWriter, r *http.Request, _ domain.Principal) {
	limit, offset := pagination(r)
	items, total, err := s.store.ListServiceDefinitionRevisions(r.Context(), r.PathValue("id"), limit, offset)
	if err != nil {
		writeCatalogError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total, "limit": limit, "offset": offset})
}

func (s *Server) adminListServiceGrants(w http.ResponseWriter, r *http.Request, _ domain.Principal) {
	limit, offset := pagination(r)
	query := r.URL.Query()
	filter := store.ServiceGrantFilter{
		ServiceID:      r.PathValue("id"),
		ScopeType:      strings.ToLower(query.Get("scope_type")),
		ScopeID:        query.Get("scope_id"),
		Effect:         strings.ToLower(query.Get("effect")),
		IncludeRevoked: query.Get("include_revoked") == "true",
		Sort:           query.Get("sort"),
	}
	if filter.ScopeType != "" && !domain.ValidScopeType(filter.ScopeType) {
		writeError(w, http.StatusBadRequest, "invalid_scope_type", "scope_type must be one of tenant, site, group, device")
		return
	}
	if filter.Effect != "" && !domain.ValidGrantEffect(filter.Effect) {
		writeError(w, http.StatusBadRequest, "invalid_effect", "effect must be allow or deny")
		return
	}
	items, total, err := s.store.ListServiceGrants(r.Context(), filter, limit, offset)
	if err != nil {
		writeCatalogError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total, "limit": limit, "offset": offset})
}

type serviceGrantRequest struct {
	ScopeType string `json:"scope_type"`
	ScopeID   string `json:"scope_id"`
	Effect    string `json:"effect"`
}

func (s *Server) adminSetServiceGrant(w http.ResponseWriter, r *http.Request, principal domain.Principal) {
	var input serviceGrantRequest
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	result, err := s.store.SetServiceGrant(r.Context(), auditMeta(r, principal), r.PathValue("id"),
		input.ScopeType, input.ScopeID, input.Effect)
	if err != nil {
		writeCatalogError(w, err)
		return
	}
	status := http.StatusOK
	if result.Changed {
		status = http.StatusCreated
	}
	if result.Changed {
		signalHubFor(s).publishPolicy("", result.PolicyRevision)
	}
	writeJSON(w, status, map[string]any{"grant": result.Grant, "policy_revision": result.PolicyRevision, "changed": result.Changed})
}

func (s *Server) adminRevokeServiceGrant(w http.ResponseWriter, r *http.Request, principal domain.Principal) {
	result, err := s.store.RevokeServiceGrant(r.Context(), auditMeta(r, principal), r.PathValue("id"), r.PathValue("grant_id"))
	if err != nil {
		writeCatalogError(w, err)
		return
	}
	if result.Changed {
		signalHubFor(s).publishPolicy("", result.PolicyRevision)
	}
	writeJSON(w, http.StatusOK, map[string]any{"grant": result.Grant, "policy_revision": result.PolicyRevision, "changed": result.Changed})
}

func (s *Server) adminDeviceServicePolicy(w http.ResponseWriter, r *http.Request, _ domain.Principal) {
	policy, err := s.store.AdminDevicePolicy(r.Context(), r.PathValue("id"))
	if err != nil {
		writeCatalogError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, policy)
}

func (s *Server) adminGetDeviceScopes(w http.ResponseWriter, r *http.Request, _ domain.Principal) {
	scopes, err := s.store.GetDeviceScopes(r.Context(), r.PathValue("id"))
	if err != nil {
		writeCatalogError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, scopes)
}

func (s *Server) adminSetDeviceScopes(w http.ResponseWriter, r *http.Request, principal domain.Principal) {
	var input domain.DeviceScopes
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	result, err := s.store.SetDeviceScopes(r.Context(), auditMeta(r, principal), r.PathValue("id"), input)
	if err != nil {
		writeCatalogError(w, err)
		return
	}
	if result.Changed {
		signalHubFor(s).publishPolicy("", result.PolicyRevision)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"scopes": result.Scopes, "policy_revision": result.PolicyRevision, "changed": result.Changed,
	})
}

// deviceServices returns the effective service policy of the authenticated
// device. It is read-only, keyed only by the device credential, and contains
// no credentials, upstream URLs with paths, or administrative endpoints.
func (s *Server) deviceServices(w http.ResponseWriter, r *http.Request, principal domain.DevicePrincipal) {
	w.Header().Set("Cache-Control", "no-store")
	policy, err := s.store.DeviceServicePolicy(r.Context(), principal.DeviceID)
	if err != nil {
		writeCatalogError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, policy)
}
