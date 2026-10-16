package httpapi

import (
	"context"
	"errors"
	"net/http"
	"sort"
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
	mux.Handle("GET /api/v1/users/{id}", s.require(rbac.UsersRead, s.adminGetUser))
	mux.Handle("PATCH /api/v1/users/{id}", s.require(rbac.UsersUpdate, s.adminUpdateUser))
	mux.Handle("POST /api/v1/users/{id}/password", s.require(rbac.UsersUpdate, s.adminSetUserPassword))
	mux.Handle("POST /api/v1/users/{id}/lock", s.require(rbac.UsersUpdate, s.adminLockUser))
	mux.Handle("POST /api/v1/users/{id}/unlock", s.require(rbac.UsersUpdate, s.adminUnlockUser))
	mux.Handle("GET /api/v1/roles", s.require(rbac.RolesRead, s.adminListRoles))
	mux.Handle("POST /api/v1/roles", s.require(rbac.RolesCreate, s.adminCreateRole))
	mux.Handle("PATCH /api/v1/roles/{id}", s.require(rbac.RolesUpdate, s.adminUpdateRole))
	mux.Handle("GET /api/v1/permissions", s.require(rbac.RolesRead, s.adminListPermissions))
	mux.Handle("GET /api/v1/audit", s.require(rbac.AuditRead, s.adminListAudit))
	mux.Handle("GET /api/v1/commands", s.require(rbac.CommandsRead, s.adminListCommands))
	mux.Handle("GET /api/v1/settings", s.require(rbac.SettingsRead, s.adminGetSettings))
	mux.Handle("PATCH /api/v1/settings", s.require(rbac.SettingsUpdate, s.adminUpdateSettings))
	s.registerServiceCatalogRoutes(mux)
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

type adminPasswordRequest struct {
	Password string `json:"password"`
}

type adminRoleRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
}

func (s *Server) adminListUsers(w http.ResponseWriter, r *http.Request, _ domain.Principal) {
	limit, offset := pagination(r)
	values := r.URL.Query()
	sortKey, desc := strings.TrimPrefix(values.Get("sort"), "-"), strings.HasPrefix(values.Get("sort"), "-")
	if order := values.Get("order"); order != "" {
		desc = strings.EqualFold(order, "desc")
	}
	items, total, err := s.store.ListUsersPage(r.Context(), store.UserListQuery{
		Search: values.Get("q"), Status: values.Get("status"), Role: values.Get("role"),
		Sort: sortKey, Desc: desc, Limit: limit, Offset: offset,
	})
	if err != nil {
		if errors.Is(err, store.ErrInvalid) {
			writeError(w, http.StatusBadRequest, "invalid_query", "unsupported user filter or sort")
			return
		}
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total, "limit": limit, "offset": offset})
}

func (s *Server) adminGetUser(w http.ResponseWriter, r *http.Request, _ domain.Principal) {
	user, err := s.store.GetUser(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, user)
}

// errPrivilegeEscalation is returned when an administrator would grant, or
// act on an account holding, permissions the administrator does not hold.
var errPrivilegeEscalation = errors.New("privilege escalation")

// authorizeUserManagement enforces permission containment: the actor may only
// manage accounts whose effective permissions are a subset of its own and may
// only assign roles whose permissions it holds. This keeps "admin" from
// resetting a superadmin password or granting itself superadmin, without any
// role-name checks.
func (s *Server) authorizeUserManagement(ctx context.Context, actor domain.Principal, targetUserID string, assignRoles []string) error {
	if targetUserID != "" {
		current, err := s.store.UserPermissions(ctx, targetUserID)
		if err != nil {
			return err
		}
		if !rbac.Covers(actor.Permissions, current) {
			return errPrivilegeEscalation
		}
	}
	if assignRoles != nil {
		requested, err := s.store.RolesPermissions(ctx, assignRoles)
		if err != nil {
			return err
		}
		if !rbac.Covers(actor.Permissions, requested) {
			return errPrivilegeEscalation
		}
	}
	return nil
}

func writeUserManagementError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errPrivilegeEscalation):
		writeError(w, http.StatusForbidden, "privilege_escalation", "the target account or requested roles exceed your permissions")
	case errors.Is(err, store.ErrLastSuperadmin):
		writeError(w, http.StatusConflict, "last_superadmin", "at least one active superadmin must remain")
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, "user_conflict", "username already exists or the request conflicts with current state")
	default:
		writeManagementStoreError(w, err)
	}
}

func (s *Server) adminCreateUser(w http.ResponseWriter, r *http.Request, principal domain.Principal) {
	var input adminUserCreateRequest
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if len(input.Roles) == 0 {
		writeError(w, http.StatusBadRequest, "roles_required", "at least one role is required")
		return
	}
	if err := s.authorizeUserManagement(r.Context(), principal, "", input.Roles); err != nil {
		writeUserManagementError(w, err)
		return
	}
	if err := security.ValidateNewPassword(input.Password, "", input.Username); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_password", err.Error())
		return
	}
	passwordHash, err := security.HashPassword(input.Password)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_password", err.Error())
		return
	}
	user, err := s.store.CreateAdminUser(r.Context(), store.AdminUserCreate{
		Username: input.Username, DisplayName: input.DisplayName, PasswordHash: passwordHash, Roles: input.Roles,
		MustChangePassword: true,
	})
	if err != nil {
		writeUserManagementError(w, err)
		return
	}
	_ = s.audit(r, principal.UserID, "user.create", "user", user.ID, map[string]any{"username": user.Username, "roles": user.Roles, "must_change_password": true})
	writeJSON(w, http.StatusCreated, user)
}

func (s *Server) adminUpdateUser(w http.ResponseWriter, r *http.Request, principal domain.Principal) {
	var input adminUserUpdateRequest
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	id := r.PathValue("id")
	if id == principal.UserID && input.Disabled {
		writeError(w, http.StatusConflict, "cannot_disable_self", "the current administrator cannot disable its own account")
		return
	}
	before, err := s.store.GetUser(r.Context(), id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if err := s.authorizeUserManagement(r.Context(), principal, id, input.Roles); err != nil {
		writeUserManagementError(w, err)
		return
	}
	user, err := s.store.UpdateAdminUser(r.Context(), id, store.AdminUserUpdate{DisplayName: input.DisplayName, Disabled: input.Disabled, Roles: input.Roles})
	if err != nil {
		writeUserManagementError(w, err)
		return
	}
	_ = s.audit(r, principal.UserID, "user.update", "user", user.ID, map[string]any{
		"disabled": user.Disabled, "roles": user.Roles, "previous_roles": before.Roles, "previous_disabled": before.Disabled,
	})
	writeJSON(w, http.StatusOK, user)
}

func (s *Server) adminLockUser(w http.ResponseWriter, r *http.Request, principal domain.Principal) {
	s.setUserLocked(w, r, principal, true)
}

func (s *Server) adminUnlockUser(w http.ResponseWriter, r *http.Request, principal domain.Principal) {
	s.setUserLocked(w, r, principal, false)
}

func (s *Server) setUserLocked(w http.ResponseWriter, r *http.Request, principal domain.Principal, locked bool) {
	id := r.PathValue("id")
	if id == principal.UserID && locked {
		writeError(w, http.StatusConflict, "cannot_disable_self", "the current administrator cannot disable its own account")
		return
	}
	if err := s.authorizeUserManagement(r.Context(), principal, id, nil); err != nil {
		writeUserManagementError(w, err)
		return
	}
	user, err := s.store.SetUserDisabled(r.Context(), id, locked)
	if err != nil {
		writeUserManagementError(w, err)
		return
	}
	action := "user.unlock"
	if locked {
		action = "user.lock"
	}
	_ = s.audit(r, principal.UserID, action, "user", id, map[string]any{"username": user.Username})
	writeJSON(w, http.StatusOK, user)
}

func (s *Server) adminSetUserPassword(w http.ResponseWriter, r *http.Request, principal domain.Principal) {
	var input adminPasswordRequest
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	id := r.PathValue("id")
	if id == principal.UserID {
		writeError(w, http.StatusConflict, "use_password_change", "use POST /api/v1/auth/password to change your own password")
		return
	}
	target, err := s.store.GetUser(r.Context(), id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if err := s.authorizeUserManagement(r.Context(), principal, id, nil); err != nil {
		writeUserManagementError(w, err)
		return
	}
	if err := security.ValidateNewPassword(input.Password, "", target.Username); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_password", err.Error())
		return
	}
	hash, err := security.HashPassword(input.Password)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_password", err.Error())
		return
	}
	if err := s.store.SetAdminUserPassword(r.Context(), id, hash); err != nil {
		writeUserManagementError(w, err)
		return
	}
	_ = s.audit(r, principal.UserID, "user.password.reset", "user", id, map[string]any{"must_change_password": true})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) adminListRoles(w http.ResponseWriter, r *http.Request, _ domain.Principal) {
	items, err := s.store.ListRoles(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) adminCreateRole(w http.ResponseWriter, r *http.Request, principal domain.Principal) {
	var input adminRoleRequest
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	role, err := s.store.CreateRole(r.Context(), input.Name, input.Description, input.Permissions)
	if err != nil {
		writeManagementStoreError(w, err)
		return
	}
	_ = s.audit(r, principal.UserID, "role.create", "role", role.ID, map[string]any{"permissions": role.Permissions})
	writeJSON(w, http.StatusCreated, role)
}

func (s *Server) adminUpdateRole(w http.ResponseWriter, r *http.Request, principal domain.Principal) {
	var input adminRoleRequest
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	role, err := s.store.UpdateRole(r.Context(), r.PathValue("id"), input.Description, input.Permissions)
	if err != nil {
		writeManagementStoreError(w, err)
		return
	}
	_ = s.audit(r, principal.UserID, "role.update", "role", role.ID, map[string]any{"permissions": role.Permissions})
	writeJSON(w, http.StatusOK, role)
}

func (s *Server) adminListPermissions(w http.ResponseWriter, r *http.Request, _ domain.Principal) {
	items, err := s.store.ListPermissions(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) adminListAudit(w http.ResponseWriter, r *http.Request, _ domain.Principal) {
	limit, offset := pagination(r)
	items, total, err := s.store.ListAuditEvents(r.Context(), limit, offset)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total, "limit": limit, "offset": offset})
}

func (s *Server) adminListCommands(w http.ResponseWriter, r *http.Request, _ domain.Principal) {
	limit, offset := pagination(r)
	items, total, err := s.store.ListAllDeviceCommands(r.Context(), limit, offset)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total, "limit": limit, "offset": offset})
}

var editableSettings = map[string]struct{}{
	"site_name":                   {},
	"command_default_ttl_seconds": {},
	"telemetry_stale_seconds":     {},
}

func (s *Server) adminGetSettings(w http.ResponseWriter, r *http.Request, _ domain.Principal) {
	values, err := s.store.GetSystemSettings(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if values["site_name"] == "" {
		values["site_name"] = "Guardian"
	}
	if values["command_default_ttl_seconds"] == "" {
		values["command_default_ttl_seconds"] = "300"
	}
	if values["telemetry_stale_seconds"] == "" {
		values["telemetry_stale_seconds"] = "120"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"values":     values,
		"public_url": s.publicURL,
		"editable":   []string{"site_name", "command_default_ttl_seconds", "telemetry_stale_seconds"},
	})
}

func (s *Server) adminUpdateSettings(w http.ResponseWriter, r *http.Request, principal domain.Principal) {
	var input struct {
		Values map[string]string `json:"values"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if len(input.Values) == 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", "at least one setting is required")
		return
	}
	for key, value := range input.Values {
		if _, ok := editableSettings[key]; !ok {
			writeError(w, http.StatusBadRequest, "setting_not_editable", "setting is not editable")
			return
		}
		value = strings.TrimSpace(value)
		if key == "site_name" && (value == "" || len(value) > 80) {
			writeError(w, http.StatusBadRequest, "invalid_setting", "site_name must contain 1-80 characters")
			return
		}
		if key != "site_name" {
			n, err := strconv.Atoi(value)
			if err != nil || n < 5 || n > 86400 {
				writeError(w, http.StatusBadRequest, "invalid_setting", key+" must be an integer between 5 and 86400")
				return
			}
		}
		if err := s.store.SetSystemSetting(r.Context(), key, value); err != nil {
			writeManagementStoreError(w, err)
			return
		}
	}
	keys := mapKeys(input.Values)
	_ = s.audit(r, principal.UserID, "settings.update", "settings", "system", map[string]any{"keys": keys})
	s.adminGetSettings(w, r, principal)
}

func mapKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
