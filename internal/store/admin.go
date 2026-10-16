package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/1day0fmylife/Guardian/internal/domain"
	"github.com/1day0fmylife/Guardian/internal/security"
)

type AdminRole struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	System      bool     `json:"system"`
	Permissions []string `json:"permissions"`
}

type AdminUserCreate struct {
	Username     string
	DisplayName  string
	PasswordHash string
	Roles        []string
	// MustChangePassword forces the user to replace the temporary password.
	MustChangePassword bool
}

type AdminUserUpdate struct {
	DisplayName string
	Disabled    bool
	Roles       []string
}

type GlobalDeviceCommand struct {
	domain.DeviceCommand
	DeviceName string `json:"device_name"`
	DeviceUUID string `json:"device_uuid"`
}

// UserListQuery is the server-side pagination/filter/sort contract for the
// user collection.
type UserListQuery struct {
	Search string // case-insensitive match on username or display name
	Status string // "", "active", "disabled" or "password_change"
	Role   string // role id the user must hold
	Sort   string // "username", "display_name", "created_at" or "updated_at"
	Desc   bool
	Limit  int
	Offset int
}

var userSortColumns = map[string]string{
	"username":     "u.username",
	"display_name": "u.display_name",
	"created_at":   "u.created_at",
	"updated_at":   "u.updated_at",
}

// ListUsers returns every user ordered by username.
func (s *Store) ListUsers(ctx context.Context) ([]domain.User, error) {
	users, _, err := s.ListUsersPage(ctx, UserListQuery{Limit: 1 << 30})
	return users, err
}

func (s *Store) ListUsersPage(ctx context.Context, query UserListQuery) ([]domain.User, int, error) {
	var where []string
	var args []any
	if search := strings.ToLower(strings.TrimSpace(query.Search)); search != "" {
		pattern := "%" + escapeLike(search) + "%"
		where = append(where, `(LOWER(u.username) LIKE ? ESCAPE '\' OR LOWER(u.display_name) LIKE ? ESCAPE '\')`)
		args = append(args, pattern, pattern)
	}
	switch query.Status {
	case "":
	case "active":
		where = append(where, "u.disabled = 0")
	case "disabled":
		where = append(where, "u.disabled = 1")
	case "password_change":
		where = append(where, "u.must_change_password = 1")
	default:
		return nil, 0, ErrInvalid
	}
	if role := strings.TrimSpace(query.Role); role != "" {
		where = append(where, "EXISTS (SELECT 1 FROM user_roles fr WHERE fr.user_id = u.id AND fr.role_id = ?)")
		args = append(args, role)
	}
	sortColumn := "u.username"
	if query.Sort != "" {
		column, ok := userSortColumns[query.Sort]
		if !ok {
			return nil, 0, ErrInvalid
		}
		sortColumn = column
	}
	direction := "ASC"
	if query.Desc {
		direction = "DESC"
	}
	clause := ""
	if len(where) > 0 {
		clause = " WHERE " + strings.Join(where, " AND ")
	}
	var total int
	if err := s.db.QueryRowContext(ctx, s.q(`SELECT COUNT(*) FROM users u`+clause), args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count users: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT u.id, u.username, u.display_name, u.disabled, u.must_change_password, COALESCE(u.password_changed_at, ''), u.created_at, u.updated_at FROM users u`+clause+
		` ORDER BY `+sortColumn+` `+direction+`, u.id `+direction+` LIMIT ? OFFSET ?`), append(args, query.Limit, query.Offset)...)
	if err != nil {
		return nil, 0, fmt.Errorf("list users: %w", err)
	}
	users := []domain.User{}
	for rows.Next() {
		user, err := scanUser(rows)
		if err != nil {
			rows.Close()
			return nil, 0, err
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, 0, err
	}
	if err := rows.Close(); err != nil {
		return nil, 0, fmt.Errorf("close users: %w", err)
	}
	for index := range users {
		roles, err := s.userRoles(ctx, users[index].ID)
		if err != nil {
			return nil, 0, err
		}
		users[index].Roles = roles
	}
	return users, total, nil
}

type rowScanner interface{ Scan(dest ...any) error }

func scanUser(row rowScanner) (domain.User, error) {
	var user domain.User
	var disabled, mustChange int
	if err := row.Scan(&user.ID, &user.Username, &user.DisplayName, &disabled, &mustChange, &user.PasswordChangedAt, &user.CreatedAt, &user.UpdatedAt); err != nil {
		if err == sql.ErrNoRows {
			return domain.User{}, ErrNotFound
		}
		return domain.User{}, fmt.Errorf("scan user: %w", err)
	}
	user.Disabled = disabled != 0
	user.MustChangePassword = mustChange != 0
	return user, nil
}

func (s *Store) GetUser(ctx context.Context, id string) (domain.User, error) {
	user, err := scanUser(s.db.QueryRowContext(ctx, s.q(`SELECT id, username, display_name, disabled, must_change_password, COALESCE(password_changed_at, ''), created_at, updated_at FROM users WHERE id = ?`), id))
	if err != nil {
		return domain.User{}, err
	}
	if user.Roles, err = s.userRoles(ctx, id); err != nil {
		return domain.User{}, err
	}
	return user, nil
}

// UserPermissions returns the effective permission set of a user.
func (s *Store) UserPermissions(ctx context.Context, userID string) ([]string, error) {
	return s.distinctPermissions(ctx, `SELECT DISTINCT rp.permission_id FROM role_permissions rp JOIN user_roles ur ON ur.role_id = rp.role_id WHERE ur.user_id = ? ORDER BY rp.permission_id`, userID)
}

// RolesPermissions returns the union of permissions granted by the roles.
// Unknown roles return ErrInvalid.
func (s *Store) RolesPermissions(ctx context.Context, roles []string) ([]string, error) {
	roles = uniqueStrings(roles)
	if len(roles) == 0 {
		return nil, nil
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(roles)), ",")
	args := make([]any, len(roles))
	for i, role := range roles {
		args[i] = role
	}
	var known int
	if err := s.db.QueryRowContext(ctx, s.q(`SELECT COUNT(*) FROM roles WHERE id IN (`+placeholders+`)`), args...).Scan(&known); err != nil {
		return nil, fmt.Errorf("check roles: %w", err)
	}
	if known != len(roles) {
		return nil, ErrInvalid
	}
	return s.distinctPermissions(ctx, `SELECT DISTINCT permission_id FROM role_permissions WHERE role_id IN (`+placeholders+`) ORDER BY permission_id`, args...)
}

func (s *Store) distinctPermissions(ctx context.Context, query string, args ...any) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, s.q(query), args...)
	if err != nil {
		return nil, fmt.Errorf("list permissions: %w", err)
	}
	defer rows.Close()
	var result []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	return result, rows.Err()
}

// SetUserDisabled locks or unlocks an account. Locking revokes its sessions and
// is refused for the last active superadmin.
func (s *Store) SetUserDisabled(ctx context.Context, id string, disabled bool) (domain.User, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.User{}, fmt.Errorf("begin lock user: %w", err)
	}
	defer tx.Rollback()
	var exists int
	if err := tx.QueryRowContext(ctx, s.q(`SELECT COUNT(*) FROM users WHERE id = ?`), id).Scan(&exists); err != nil {
		return domain.User{}, fmt.Errorf("load user: %w", err)
	}
	if exists == 0 {
		return domain.User{}, ErrNotFound
	}
	if disabled {
		if err := s.guardLastSuperadmin(ctx, tx, id); err != nil {
			return domain.User{}, err
		}
		if _, err := tx.ExecContext(ctx, s.q(`DELETE FROM auth_sessions WHERE user_id = ?`), id); err != nil {
			return domain.User{}, fmt.Errorf("revoke sessions: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, s.q(`UPDATE users SET disabled = ?, updated_at = ? WHERE id = ?`), boolInt(disabled), nowText(), id); err != nil {
		return domain.User{}, fmt.Errorf("update user: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return domain.User{}, fmt.Errorf("commit lock user: %w", err)
	}
	return s.GetUser(ctx, id)
}

// guardLastSuperadmin returns ErrLastSuperadmin when removing the user from the
// active superadmin set would leave none.
func (s *Store) guardLastSuperadmin(ctx context.Context, tx *sql.Tx, userID string) error {
	has, err := txUserHasRole(ctx, tx, s, userID, "superadmin")
	if err != nil || !has {
		return err
	}
	count, err := txActiveRoleCount(ctx, tx, s, "superadmin", userID)
	if err != nil {
		return err
	}
	if count == 0 {
		return ErrLastSuperadmin
	}
	return nil
}

func escapeLike(value string) string {
	return strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(value)
}

func (s *Store) userRoles(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT r.name FROM roles r JOIN user_roles ur ON ur.role_id = r.id WHERE ur.user_id = ? ORDER BY r.name`), userID)
	if err != nil {
		return nil, fmt.Errorf("list user roles: %w", err)
	}
	defer rows.Close()
	var roles []string
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return nil, fmt.Errorf("scan user role: %w", err)
		}
		roles = append(roles, role)
	}
	return roles, rows.Err()
}

func (s *Store) CreateAdminUser(ctx context.Context, input AdminUserCreate) (domain.User, error) {
	input.Username = strings.ToLower(strings.TrimSpace(input.Username))
	input.DisplayName = strings.TrimSpace(input.DisplayName)
	if input.Username == "" || input.PasswordHash == "" || len(input.Roles) == 0 {
		return domain.User{}, ErrInvalid
	}
	id, err := security.NewID()
	if err != nil {
		return domain.User{}, err
	}
	now := nowText()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.User{}, fmt.Errorf("begin create user: %w", err)
	}
	defer tx.Rollback()
	if err := ensureRolesExist(ctx, tx, s, input.Roles); err != nil {
		return domain.User{}, err
	}
	if _, err := tx.ExecContext(ctx, s.q(`INSERT INTO users(id, username, display_name, password_hash, disabled, must_change_password, created_at, updated_at) VALUES(?, ?, ?, ?, 0, ?, ?, ?)`), id, input.Username, input.DisplayName, input.PasswordHash, boolInt(input.MustChangePassword), now, now); err != nil {
		return domain.User{}, mapConflict(err, "create user")
	}
	for _, role := range uniqueStrings(input.Roles) {
		if _, err := tx.ExecContext(ctx, s.q(`INSERT INTO user_roles(user_id, role_id) VALUES(?, ?)`), id, role); err != nil {
			return domain.User{}, fmt.Errorf("grant role: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return domain.User{}, fmt.Errorf("commit create user: %w", err)
	}
	return domain.User{ID: id, Username: input.Username, DisplayName: input.DisplayName, Roles: uniqueStrings(input.Roles), MustChangePassword: input.MustChangePassword, CreatedAt: now, UpdatedAt: now}, nil
}

func (s *Store) UpdateAdminUser(ctx context.Context, id string, input AdminUserUpdate) (domain.User, error) {
	input.DisplayName = strings.TrimSpace(input.DisplayName)
	if strings.TrimSpace(id) == "" || len(input.Roles) == 0 {
		return domain.User{}, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.User{}, fmt.Errorf("begin update user: %w", err)
	}
	defer tx.Rollback()
	if err := ensureRolesExist(ctx, tx, s, input.Roles); err != nil {
		return domain.User{}, err
	}
	var oldDisabled int
	if err := tx.QueryRowContext(ctx, s.q(`SELECT disabled FROM users WHERE id = ?`), id).Scan(&oldDisabled); err != nil {
		if err == sql.ErrNoRows {
			return domain.User{}, ErrNotFound
		}
		return domain.User{}, fmt.Errorf("load user: %w", err)
	}
	hadSuperadmin, err := txUserHasRole(ctx, tx, s, id, "superadmin")
	if err != nil {
		return domain.User{}, err
	}
	willSuperadmin := containsString(input.Roles, "superadmin")
	if hadSuperadmin && (!willSuperadmin || input.Disabled) {
		count, err := txActiveRoleCount(ctx, tx, s, "superadmin", id)
		if err != nil {
			return domain.User{}, err
		}
		if count == 0 {
			return domain.User{}, ErrLastSuperadmin
		}
	}
	now := nowText()
	disabled := 0
	if input.Disabled {
		disabled = 1
	}
	if _, err := tx.ExecContext(ctx, s.q(`UPDATE users SET display_name = ?, disabled = ?, updated_at = ? WHERE id = ?`), input.DisplayName, disabled, now, id); err != nil {
		return domain.User{}, fmt.Errorf("update user: %w", err)
	}
	if _, err := tx.ExecContext(ctx, s.q(`DELETE FROM user_roles WHERE user_id = ?`), id); err != nil {
		return domain.User{}, fmt.Errorf("clear roles: %w", err)
	}
	for _, role := range uniqueStrings(input.Roles) {
		if _, err := tx.ExecContext(ctx, s.q(`INSERT INTO user_roles(user_id, role_id) VALUES(?, ?)`), id, role); err != nil {
			return domain.User{}, fmt.Errorf("grant role: %w", err)
		}
	}
	if input.Disabled && oldDisabled == 0 {
		if _, err := tx.ExecContext(ctx, s.q(`DELETE FROM auth_sessions WHERE user_id = ?`), id); err != nil {
			return domain.User{}, fmt.Errorf("revoke sessions: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return domain.User{}, fmt.Errorf("commit update user: %w", err)
	}
	return s.GetUser(ctx, id)
}

// SetAdminUserPassword sets an administrator-issued temporary password. The
// user must replace it at next sign-in and all existing sessions are revoked.
func (s *Store) SetAdminUserPassword(ctx context.Context, id, passwordHash string) error {
	if id == "" || passwordHash == "" {
		return ErrInvalid
	}
	result, err := s.db.ExecContext(ctx, s.q(`UPDATE users SET password_hash = ?, must_change_password = 1, updated_at = ? WHERE id = ?`), passwordHash, nowText(), id)
	if err != nil {
		return fmt.Errorf("update password: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	_, err = s.db.ExecContext(ctx, s.q(`DELETE FROM auth_sessions WHERE user_id = ?`), id)
	return err
}

func (s *Store) ListRoles(ctx context.Context) ([]AdminRole, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, description, system FROM roles ORDER BY system DESC, name`)
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	var roles []AdminRole
	for rows.Next() {
		var role AdminRole
		var system int
		if err := rows.Scan(&role.ID, &role.Name, &role.Description, &system); err != nil {
			rows.Close()
			return nil, err
		}
		role.System = system != 0
		roles = append(roles, role)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close roles: %w", err)
	}
	for index := range roles {
		permissions, err := s.rolePermissions(ctx, roles[index].ID)
		if err != nil {
			return nil, err
		}
		roles[index].Permissions = permissions
	}
	return roles, nil
}

func (s *Store) rolePermissions(ctx context.Context, roleID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT p.name FROM permissions p JOIN role_permissions rp ON rp.permission_id = p.id WHERE rp.role_id = ? ORDER BY p.name`), roleID)
	if err != nil {
		return nil, fmt.Errorf("list role permissions: %w", err)
	}
	defer rows.Close()
	var result []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	return result, rows.Err()
}

func (s *Store) CreateRole(ctx context.Context, name, description string, permissions []string) (AdminRole, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	description = strings.TrimSpace(description)
	if name == "" || len(permissions) == 0 {
		return AdminRole{}, ErrInvalid
	}
	if err := s.replaceRole(ctx, name, name, description, permissions, true); err != nil {
		return AdminRole{}, err
	}
	return AdminRole{ID: name, Name: name, Description: description, Permissions: uniqueStrings(permissions)}, nil
}

func (s *Store) UpdateRole(ctx context.Context, id, description string, permissions []string) (AdminRole, error) {
	id = strings.TrimSpace(id)
	description = strings.TrimSpace(description)
	if id == "" || len(permissions) == 0 {
		return AdminRole{}, ErrInvalid
	}
	var name string
	var system int
	if err := s.db.QueryRowContext(ctx, s.q(`SELECT name, system FROM roles WHERE id = ?`), id).Scan(&name, &system); err != nil {
		if err == sql.ErrNoRows {
			return AdminRole{}, ErrNotFound
		}
		return AdminRole{}, err
	}
	if system != 0 {
		return AdminRole{}, ErrConflict
	}
	if err := s.replaceRole(ctx, id, name, description, permissions, false); err != nil {
		return AdminRole{}, err
	}
	return AdminRole{ID: id, Name: name, Description: description, Permissions: uniqueStrings(permissions)}, nil
}

func (s *Store) replaceRole(ctx context.Context, id, name, description string, permissions []string, create bool) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, permission := range uniqueStrings(permissions) {
		var count int
		if err := tx.QueryRowContext(ctx, s.q(`SELECT COUNT(*) FROM permissions WHERE id = ?`), permission).Scan(&count); err != nil {
			return err
		}
		if count == 0 {
			return ErrInvalid
		}
	}
	if create {
		if _, err := tx.ExecContext(ctx, s.q(`INSERT INTO roles(id, name, description, system) VALUES(?, ?, ?, 0)`), id, name, description); err != nil {
			return mapConflict(err, "create role")
		}
	} else {
		if _, err := tx.ExecContext(ctx, s.q(`UPDATE roles SET description = ? WHERE id = ?`), description, id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, s.q(`DELETE FROM role_permissions WHERE role_id = ?`), id); err != nil {
			return err
		}
	}
	for _, permission := range uniqueStrings(permissions) {
		if _, err := tx.ExecContext(ctx, s.q(`INSERT INTO role_permissions(role_id, permission_id) VALUES(?, ?)`), id, permission); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) ListPermissions(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name FROM permissions ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (s *Store) ListAuditEvents(ctx context.Context, limit, offset int) ([]domain.AuditEvent, int, error) {
	return s.listAuditEvents(ctx, "", nil, limit, offset)
}

// ListDeviceAuditEvents includes device events and explicit device grant history.
// Scoped grants and global catalog changes remain in the global audit view.
func (s *Store) ListDeviceAuditEvents(ctx context.Context, deviceID string, limit, offset int) ([]domain.AuditEvent, int, error) {
	if _, err := s.GetDevice(ctx, deviceID); err != nil {
		return nil, 0, err
	}
	return s.listAuditEvents(ctx, ` WHERE (resource_type = 'device' AND resource_id = ?) OR
		(resource_type = 'service_grant' AND resource_id IN
		(SELECT id FROM service_grants WHERE scope_type = 'device' AND scope_id = ?))`, []any{deviceID, deviceID}, limit, offset)
}

func (s *Store) listAuditEvents(ctx context.Context, where string, args []any, limit, offset int) ([]domain.AuditEvent, int, error) {
	var total int
	if err := s.db.QueryRowContext(ctx, s.q(`SELECT COUNT(*) FROM audit_events`+where), args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT id, COALESCE(actor_user_id, ''), action, resource_type, resource_id, source_ip, request_id, details, created_at FROM audit_events`+where+` ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?`), append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var events []domain.AuditEvent
	for rows.Next() {
		var event domain.AuditEvent
		if err := rows.Scan(&event.ID, &event.ActorUserID, &event.Action, &event.ResourceType, &event.ResourceID, &event.SourceIP, &event.RequestID, &event.Details, &event.CreatedAt); err != nil {
			return nil, 0, err
		}
		events = append(events, event)
	}
	return events, total, rows.Err()
}

func (s *Store) ListAllDeviceCommands(ctx context.Context, limit, offset int) ([]GlobalDeviceCommand, int, error) {
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM device_commands`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT c.id, c.device_id, d.name, d.device_uuid, c.type, c.status, c.idempotency_key, c.payload, COALESCE(c.result, '{}'), c.error_message, c.created_at, COALESCE(c.delivered_at, ''), COALESCE(c.acknowledged_at, ''), COALESCE(c.finished_at, ''), c.expires_at FROM device_commands c JOIN devices d ON d.id = c.device_id ORDER BY c.created_at DESC LIMIT ? OFFSET ?`), limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var result []GlobalDeviceCommand
	for rows.Next() {
		var item GlobalDeviceCommand
		var payload, commandResult string
		if err := rows.Scan(&item.ID, &item.DeviceID, &item.DeviceName, &item.DeviceUUID, &item.Type, &item.Status, &item.IdempotencyKey, &payload, &commandResult, &item.ErrorMessage, &item.CreatedAt, &item.DeliveredAt, &item.AcknowledgedAt, &item.FinishedAt, &item.ExpiresAt); err != nil {
			return nil, 0, err
		}
		item.Payload = json.RawMessage(payload)
		item.Result = json.RawMessage(commandResult)
		result = append(result, item)
	}
	return result, total, rows.Err()
}

func (s *Store) GetSystemSettings(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key, value FROM system_state ORDER BY key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := map[string]string{}
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, err
		}
		result[key] = value
	}
	return result, rows.Err()
}

func (s *Store) SetSystemSetting(ctx context.Context, key, value string) error {
	key = strings.TrimSpace(key)
	value = strings.TrimSpace(value)
	if key == "" {
		return ErrInvalid
	}
	_, err := s.db.ExecContext(ctx, s.q(`INSERT INTO system_state(key, value, updated_at) VALUES(?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`), key, value, nowText())
	return err
}

func ensureRolesExist(ctx context.Context, tx *sql.Tx, s *Store, roles []string) error {
	for _, role := range uniqueStrings(roles) {
		var count int
		if err := tx.QueryRowContext(ctx, s.q(`SELECT COUNT(*) FROM roles WHERE id = ?`), role).Scan(&count); err != nil {
			return err
		}
		if count == 0 {
			return ErrInvalid
		}
	}
	return nil
}

func txUserHasRole(ctx context.Context, tx *sql.Tx, s *Store, userID, role string) (bool, error) {
	var count int
	err := tx.QueryRowContext(ctx, s.q(`SELECT COUNT(*) FROM user_roles WHERE user_id = ? AND role_id = ?`), userID, role).Scan(&count)
	return count > 0, err
}

func txActiveRoleCount(ctx context.Context, tx *sql.Tx, s *Store, role, excludingUserID string) (int, error) {
	var count int
	err := tx.QueryRowContext(ctx, s.q(`SELECT COUNT(*) FROM users u JOIN user_roles ur ON ur.user_id = u.id WHERE ur.role_id = ? AND u.disabled = 0 AND u.id <> ?`), role, excludingUserID).Scan(&count)
	return count, err
}

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == target {
			return true
		}
	}
	return false
}

func mapConflict(err error, prefix string) error {
	if err == nil {
		return nil
	}
	text := strings.ToLower(err.Error())
	if strings.Contains(text, "unique") || strings.Contains(text, "duplicate") {
		return ErrConflict
	}
	return fmt.Errorf("%s: %w", prefix, err)
}
