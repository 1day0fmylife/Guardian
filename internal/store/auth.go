package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/1day0fmylife/Guardian/internal/domain"
	"github.com/1day0fmylife/Guardian/internal/rbac"
	"github.com/1day0fmylife/Guardian/internal/security"
)

func (s *Store) SeedRBAC(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin rbac seed: %w", err)
	}
	defer tx.Rollback()

	for _, permission := range rbac.AllPermissions {
		if _, err := tx.ExecContext(ctx, s.q(`
			INSERT INTO permissions(id, name, description)
			VALUES(?, ?, ?)
			ON CONFLICT(id) DO UPDATE SET name = excluded.name
		`), permission, permission, permission); err != nil {
			return fmt.Errorf("seed permission %s: %w", permission, err)
		}
	}

	for _, role := range rbac.DefaultRoles {
		if _, err := tx.ExecContext(ctx, s.q(`
			INSERT INTO roles(id, name, description, system)
			VALUES(?, ?, ?, 1)
			ON CONFLICT(id) DO UPDATE SET name = excluded.name, description = excluded.description, system = 1
		`), role.Name, role.Name, role.Description); err != nil {
			return fmt.Errorf("seed role %s: %w", role.Name, err)
		}
		for _, permission := range role.Permissions {
			if _, err := tx.ExecContext(ctx, s.q(`
				INSERT INTO role_permissions(role_id, permission_id)
				VALUES(?, ?)
				ON CONFLICT(role_id, permission_id) DO NOTHING
			`), role.Name, permission); err != nil {
				return fmt.Errorf("seed role permission %s/%s: %w", role.Name, permission, err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit rbac seed: %w", err)
	}
	return nil
}

func (s *Store) UserCount(ctx context.Context) (int, error) {
	var count int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&count); err != nil {
		return 0, fmt.Errorf("count users: %w", err)
	}
	return count, nil
}

func (s *Store) CreateBootstrapUser(ctx context.Context, username, displayName, passwordHash string) (domain.User, error) {
	username = strings.TrimSpace(strings.ToLower(username))
	displayName = strings.TrimSpace(displayName)
	if username == "" {
		return domain.User{}, fmt.Errorf("username is required")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.User{}, fmt.Errorf("begin bootstrap: %w", err)
	}
	defer tx.Rollback()

	var count int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&count); err != nil {
		return domain.User{}, fmt.Errorf("count bootstrap users: %w", err)
	}
	if count != 0 {
		return domain.User{}, ErrConflict
	}

	id, err := security.NewID()
	if err != nil {
		return domain.User{}, err
	}
	now := nowText()

	if _, err := tx.ExecContext(ctx, s.q(`
		INSERT INTO users(id, username, display_name, password_hash, disabled, created_at, updated_at)
		VALUES(?, ?, ?, ?, 0, ?, ?)
	`), id, username, displayName, passwordHash, now, now); err != nil {
		return domain.User{}, fmt.Errorf("create bootstrap user: %w", err)
	}
	if _, err := tx.ExecContext(ctx, s.q(`
		INSERT INTO user_roles(user_id, role_id) VALUES(?, ?)
	`), id, "superadmin"); err != nil {
		return domain.User{}, fmt.Errorf("grant superadmin: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return domain.User{}, fmt.Errorf("commit bootstrap: %w", err)
	}

	return domain.User{
		ID:          id,
		Username:    username,
		DisplayName: displayName,
		Roles:       []string{"superadmin"},
		CreatedAt:   now,
		UpdatedAt:   now,
	}, nil
}

type loginUser struct {
	domain.User
	PasswordHash string
}

func (s *Store) FindUserForLogin(ctx context.Context, username string) (loginUser, error) {
	username = strings.TrimSpace(strings.ToLower(username))
	var u loginUser
	var disabled int
	err := s.db.QueryRowContext(ctx, s.q(`
		SELECT id, username, display_name, password_hash, disabled, created_at, updated_at
		FROM users
		WHERE username = ?
	`), username).Scan(
		&u.ID, &u.Username, &u.DisplayName, &u.PasswordHash,
		&disabled, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return loginUser{}, ErrNotFound
		}
		return loginUser{}, fmt.Errorf("find user: %w", err)
	}
	u.Disabled = disabled != 0
	return u, nil
}

func (s *Store) CreateSession(ctx context.Context, userID, tokenHash string, expiresAt time.Time) (string, error) {
	id, err := security.NewID()
	if err != nil {
		return "", err
	}
	now := nowText()
	_, err = s.db.ExecContext(ctx, s.q(`
		INSERT INTO auth_sessions(id, user_id, token_hash, expires_at, created_at, last_seen_at)
		VALUES(?, ?, ?, ?, ?, ?)
	`), id, userID, tokenHash, expiresAt.UTC().Format(time.RFC3339Nano), now, now)
	if err != nil {
		return "", fmt.Errorf("create session: %w", err)
	}
	return id, nil
}

func (s *Store) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, s.q("DELETE FROM auth_sessions WHERE token_hash = ?"), tokenHash)
	if err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

func (s *Store) PrincipalBySession(ctx context.Context, tokenHash string, now time.Time) (domain.Principal, error) {
	var p domain.Principal
	var expiresAt string
	var disabled int
	err := s.db.QueryRowContext(ctx, s.q(`
		SELECT s.id, s.user_id, u.username, u.display_name, u.disabled, s.expires_at
		FROM auth_sessions s
		JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = ?
	`), tokenHash).Scan(&p.SessionID, &p.UserID, &p.Username, &p.DisplayName, &disabled, &expiresAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return domain.Principal{}, ErrNotFound
		}
		return domain.Principal{}, fmt.Errorf("load session: %w", err)
	}
	if disabled != 0 {
		return domain.Principal{}, ErrNotFound
	}
	expiry, err := time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil || !expiry.After(now.UTC()) {
		_ = s.DeleteSession(ctx, tokenHash)
		return domain.Principal{}, ErrNotFound
	}

	roleRows, err := s.db.QueryContext(ctx, s.q(`
		SELECT r.name
		FROM roles r
		JOIN user_roles ur ON ur.role_id = r.id
		WHERE ur.user_id = ?
		ORDER BY r.name
	`), p.UserID)
	if err != nil {
		return domain.Principal{}, fmt.Errorf("load principal roles: %w", err)
	}
	for roleRows.Next() {
		var role string
		if err := roleRows.Scan(&role); err != nil {
			roleRows.Close()
			return domain.Principal{}, fmt.Errorf("scan principal role: %w", err)
		}
		p.Roles = append(p.Roles, role)
	}
	if err := roleRows.Close(); err != nil {
		return domain.Principal{}, fmt.Errorf("close principal roles: %w", err)
	}

	permissionRows, err := s.db.QueryContext(ctx, s.q(`
		SELECT DISTINCT p.name
		FROM permissions p
		JOIN role_permissions rp ON rp.permission_id = p.id
		JOIN user_roles ur ON ur.role_id = rp.role_id
		WHERE ur.user_id = ?
		ORDER BY p.name
	`), p.UserID)
	if err != nil {
		return domain.Principal{}, fmt.Errorf("load principal permissions: %w", err)
	}
	defer permissionRows.Close()
	for permissionRows.Next() {
		var permission string
		if err := permissionRows.Scan(&permission); err != nil {
			return domain.Principal{}, fmt.Errorf("scan principal permission: %w", err)
		}
		p.Permissions = append(p.Permissions, permission)
	}
	if err := permissionRows.Err(); err != nil {
		return domain.Principal{}, fmt.Errorf("iterate principal permissions: %w", err)
	}

	p.TokenHash = tokenHash
	return p, nil
}

func (s *Store) AppendAudit(ctx context.Context, event domain.AuditEvent) error {
	if event.ID == "" {
		id, err := security.NewID()
		if err != nil {
			return err
		}
		event.ID = id
	}
	if event.CreatedAt == "" {
		event.CreatedAt = nowText()
	}
	if event.Details == "" {
		event.Details = "{}"
	} else if !json.Valid([]byte(event.Details)) {
		event.Details = "{}"
	}

	_, err := s.db.ExecContext(ctx, s.q(`
		INSERT INTO audit_events(
			id, actor_user_id, action, resource_type, resource_id,
			source_ip, request_id, details, created_at
		) VALUES(?, NULLIF(?, ''), ?, ?, ?, ?, ?, ?, ?)
	`), event.ID, event.ActorUserID, event.Action, event.ResourceType, event.ResourceID,
		event.SourceIP, event.RequestID, event.Details, event.CreatedAt)
	if err != nil {
		return fmt.Errorf("append audit: %w", err)
	}
	return nil
}
