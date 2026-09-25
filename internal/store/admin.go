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

func (s *Store) ListUsers(ctx context.Context) ([]domain.User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, username, display_name, disabled, created_at, updated_at FROM users ORDER BY username`)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()
	var users []domain.User
	for rows.Next() {
		var user domain.User
		var disabled int
		if err := rows.Scan(&user.ID, &user.Username, &user.DisplayName, &disabled, &user.CreatedAt, &user.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		user.Disabled = disabled != 0
		roles, err := s.userRoles(ctx, user.ID)
		if err != nil {
			return nil, err
		}
		user.Roles = roles
		users = append(users, user)
	}
	return users, rows.Err()
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
	if _, err := tx.ExecContext(ctx, s.q(`INSERT INTO users(id, username, display_name, password_hash, disabled, created_at, updated_at) VALUES(?, ?, ?, ?, 0, ?, ?)`), id, input.Username, input.DisplayName, input.PasswordHash, now, now); err != nil {
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
	return domain.User{ID: id, Username: input.Username, DisplayName: input.DisplayName, Roles: uniqueStrings(input.Roles), CreatedAt: now, UpdatedAt: now}, nil
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
	var username, createdAt string
	var oldDisabled int
	if err := tx.QueryRowContext(ctx, s.q(`SELECT username, disabled, created_at FROM users WHERE id = ?`), id).Scan(&username, &oldDisabled, &createdAt); err != nil {
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
			return domain.User{}, ErrConflict
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
	return domain.User{ID: id, Username: username, DisplayName: input.DisplayName, Disabled: input.Disabled, Roles: uniqueStrings(input.Roles), CreatedAt: createdAt, UpdatedAt: now}, nil
}

func (s *Store) SetAdminUserPassword(ctx context.Context, id, passwordHash string) error {
	if id == "" || passwordHash == "" {
		return ErrInvalid
	}
	result, err := s.db.ExecContext(ctx, s.q(`UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?`), passwordHash, nowText(), id)
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
	defer rows.Close()
	var roles []AdminRole
	for rows.Next() {
		var role AdminRole
		var system int
		if err := rows.Scan(&role.ID, &role.Name, &role.Description, &system); err != nil {
			return nil, err
		}
		role.System = system != 0
		permissions, err := s.rolePermissions(ctx, role.ID)
		if err != nil {
			return nil, err
		}
		role.Permissions = permissions
		roles = append(roles, role)
	}
	return roles, rows.Err()
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
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_events`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT id, COALESCE(actor_user_id, ''), action, resource_type, resource_id, source_ip, request_id, details, created_at FROM audit_events ORDER BY created_at DESC LIMIT ? OFFSET ?`), limit, offset)
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
