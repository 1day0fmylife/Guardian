package httpapi

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/1day0fmylife/Guardian/internal/domain"
	"github.com/1day0fmylife/Guardian/internal/rbac"
	"github.com/1day0fmylife/Guardian/internal/security"
	"github.com/1day0fmylife/Guardian/internal/store"
)

// AdminHandler extends the management API with human-administration routes.
// It intentionally wraps ManagementHandler so device protocol semantics stay
// separate from administrator CRUD and audit surfaces.
func (s *Server) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /api/v1/users", s.require(rbac.UsersRead, s.adminListUsers))
	mux.Handle("POST /api/v1/users", s.require(rbac.UsersCreate, s.adminCreateUser))
	mux.Handle("PATCH /api/v1/users/{id}", s.require(rbac.UsersUpdate, s.adminUpdateUser))
	mux.Handle("POST /api/v1/users/{id}/password", s.require(rbac.UsersUpdate, s.adminSetUserPassword))
	mux.Handle("GET /api/v1/roles", s.require(rbac.RolesRead, s.adminListRoles))
	mux.Handle("POST /api/v1/roles", s.require(rbac.RolesCreate, s.adminCreateRole))
	mux.Handle("PATCH /api/v1/roles/{id}", s.require(rbac.RolesUpdate, s.adminUpdateRole))
	mux.Handle("GET /api/v1/permissions", s.require(rbac.RolesRead, s.adminListPermissions))
	mux.Handle("GET /api/v1/audit", s.require(rbac.AuditRead, s.adminListAudit))
	mux.Handle("GET /api/v1/commands", s.require(rbac.CommandsRead, s.adminListCommands))
	mux.Handle("GET /api/v1/settings", s.require(rbac.SettingsRead, s.adminGetSettings))
	mux.Handle("PATCH /api/v1/settings", s.require(rbac.SettingsUpdate, s.adminUpdateSettings))
	mux.Handle("/", s.ManagementHandler())
	return mux
}

type adminUserCreateRequest struct {
	Username    string   `json:"username"`
	DisplayName string   `json:"display_name"`
	Password    string   `json:"password"`
	Roles       []string `json:"roles"`
}

type adminUserUpdateRequest struct {
	DisplayName string   `json:"display_name"`
	Disabled    bool     `json:"disabled"`
	Roles       []string `json:"roles"`
}

type adminPasswordRequest struct { Password string `json:"password"` }

type adminRoleRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
}

func (s *Server) adminListUsers(w http.ResponseWriter, r *http.Request, _ domain.Principal) {
	items, err := s.store.ListUsers(r.Context())
	if err != nil { writeStoreError(w, err); return }
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) adminCreateUser(w http.ResponseWriter, r *http.Request, principal domain.Principal) {
	var input adminUserCreateRequest
	if err := decodeJSON(w, r, &input); err != nil { writeError(w, http.StatusBadRequest, "invalid_request", err.Error()); return }
	passwordHash, err := security.HashPassword(input.Password)
	if err != nil { writeError(w, http.StatusBadRequest, "invalid_password", err.Error()); return }
	user, err := s.store.CreateAdminUser(r.Context(), store.AdminUserCreate{Username: input.Username, DisplayName: input.DisplayName, PasswordHash: passwordHash, Roles: input.Roles})
	if err != nil { writeManagementStoreError(w, err); return }
	_ = s.audit(r, principal.UserID, "user.create", "user", user.ID, map[string]any{"username": user.Username, "roles": user.Roles})
	writeJSON(w, http.StatusCreated, user)
}

func (s *Server) adminUpdateUser(w http.ResponseWriter, r *http.Request, principal domain.Principal) {
	var input adminUserUpdateRequest
	if err := decodeJSON(w, r, &input); err != nil { writeError(w, http.StatusBadRequest, "invalid_request", err.Error()); return }
	id := r.PathValue("id")
	if id == principal.UserID && input.Disabled { writeError(w, http.StatusConflict, "cannot_disable_self", "the current administrator cannot disable its own account"); return }
	user, err := s.store.UpdateAdminUser(r.Context(), id, store.AdminUserUpdate{DisplayName: input.DisplayName, Disabled: input.Disabled, Roles: input.Roles})
	if err != nil { writeManagementStoreError(w, err); return }
	_ = s.audit(r, principal.UserID, "user.update", "user", user.ID, map[string]any{"disabled": user.Disabled, "roles": user.Roles})
	writeJSON(w, http.StatusOK, user)
}

func (s *Server) adminSetUserPassword(w http.ResponseWriter, r *http.Request, principal domain.Principal) {
	var input adminPasswordRequest
	if err := decodeJSON(w, r, &input); err != nil { writeError(w, http.StatusBadRequest, "invalid_request", err.Error()); return }
	hash, err := security.HashPassword(input.Password)
	if err != nil { writeError(w, http.StatusBadRequest, "invalid_password", err.Error()); return }
	id := r.PathValue("id")
	if err := s.store.SetAdminUserPassword(r.Context(), id, hash); err != nil { writeManagementStoreError(w, err); return }
	_ = s.audit(r, principal.UserID, "user.password.reset", "user", id, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) adminListRoles(w http.ResponseWriter, r *http.Request, _ domain.Principal) {
	items, err := s.store.ListRoles(r.Context()); if err != nil { writeStoreError(w, err); return }
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) adminCreateRole(w http.ResponseWriter, r *http.Request, principal domain.Principal) {
	var input adminRoleRequest
	if err := decodeJSON(w, r, &input); err != nil { writeError(w, http.StatusBadRequest, "invalid_request", err.Error()); return }
	role, err := s.store.CreateRole(r.Context(), input.Name, input.Description, input.Permissions)
	if err != nil { writeManagementStoreError(w, err); return }
	_ = s.audit(r, principal.UserID, "role.create", "role", role.ID, map[string]any{"permissions": role.Permissions})
	writeJSON(w, http.StatusCreated, role)
}

func (s *Server) adminUpdateRole(w http.ResponseWriter, r *http.Request, principal domain.Principal) {
	var input adminRoleRequest
	if err := decodeJSON(w, r, &input); err != nil { writeError(w, http.StatusBadRequest, "invalid_request", err.Error()); return }
	role, err := s.store.UpdateRole(r.Context(), r.PathValue("id"), input.Description, input.Permissions)
	if err != nil { writeManagementStoreError(w, err); return }
	_ = s.audit(r, principal.UserID, "role.update", "role", role.ID, map[string]any{"permissions": role.Permissions})
	writeJSON(w, http.StatusOK, role)
}

func (s *Server) adminListPermissions(w http.ResponseWriter, r *http.Request, _ domain.Principal) {
	items, err := s.store.ListPermissions(r.Context()); if err != nil { writeStoreError(w, err); return }
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) adminListAudit(w http.ResponseWriter, r *http.Request, _ domain.Principal) {
	limit, offset := pagination(r)
	items, total, err := s.store.ListAuditEvents(r.Context(), limit, offset)
	if err != nil { writeStoreError(w, err); return }
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total, "limit": limit, "offset": offset})
}

func (s *Server) adminListCommands(w http.ResponseWriter, r *http.Request, _ domain.Principal) {
	limit, offset := pagination(r)
	items, total, err := s.store.ListAllDeviceCommands(r.Context(), limit, offset)
	if err != nil { writeStoreError(w, err); return }
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total, "limit": limit, "offset": offset})
}

var editableSettings = map[string]struct{}{
	"site_name": {},
	"command_default_ttl_seconds": {},
	"telemetry_stale_seconds": {},
}

func (s *Server) adminGetSettings(w http.ResponseWriter, r *http.Request, _ domain.Principal) {
	values, err := s.store.GetSystemSettings(r.Context()); if err != nil { writeStoreError(w, err); return }
	if values["site_name"] == "" { values["site_name"] = "Guardian" }
	if values["command_default_ttl_seconds"] == "" { values["command_default_ttl_seconds"] = "300" }
	if values["telemetry_stale_seconds"] == "" { values["telemetry_stale_seconds"] = "120" }
	writeJSON(w, http.StatusOK, map[string]any{"values": values, "public_url": s.publicURL, "editable": []string{"site_name", "command_default_ttl_seconds", "telemetry_stale_seconds"}})
}

func (s *Server) adminUpdateSettings(w http.ResponseWriter, r *http.Request, principal domain.Principal) {
	var input struct { Values map[string]string `json:"values"` }
	if err := decodeJSON(w, r, &input); err != nil { writeError(w, http.StatusBadRequest, "invalid_request", err.Error()); return }
	if len(input.Values) == 0 { writeError(w, http.StatusBadRequest, "invalid_request", "at least one setting is required"); return }
	for key, value := range input.Values {
		if _, ok := editableSettings[key]; !ok { writeError(w, http.StatusBadRequest, "setting_not_editable", "setting is not editable"); return }
		value = strings.TrimSpace(value)
		if key == "site_name" && (value == "" || len(value) > 80) { writeError(w, http.StatusBadRequest, "invalid_setting", "site_name must contain 1-80 characters"); return }
		if key != "site_name" {
			n, err := strconv.Atoi(value); if err != nil || n < 5 || n > 86400 { writeError(w, http.StatusBadRequest, "invalid_setting", key+" must be an integer between 5 and 86400"); return }
		}
		if err := s.store.SetSystemSetting(r.Context(), key, value); err != nil { writeManagementStoreError(w, err); return }
	}
	_ = s.audit(r, principal.UserID, "settings.update", "settings", "system", map[string]any{"keys": mapKeys(input.Values)})
	s.adminGetSettings(w, r, principal)
}

func mapKeys(values map[string]string) []string { keys := make([]string, 0, len(values)); for key := range values { keys = append(keys, key) }; return keys }
