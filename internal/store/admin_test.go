package store

import (
	"context"
	"errors"
	"testing"

	"github.com/1day0fmylife/Guardian/internal/rbac"
	"github.com/1day0fmylife/Guardian/internal/security"
)

func TestAdminUserProtectsLastActiveSuperadmin(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	hash, err := security.HashPassword("a sufficiently long admin password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	first, err := st.CreateBootstrapUser(ctx, "admin", "Administrator", hash)
	if err != nil {
		t.Fatalf("CreateBootstrapUser: %v", err)
	}

	if _, err := st.UpdateAdminUser(ctx, first.ID, AdminUserUpdate{
		DisplayName: first.DisplayName,
		Disabled:    true,
		Roles:       []string{"superadmin"},
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("disable last superadmin error = %v, want ErrConflict", err)
	}
	if _, err := st.UpdateAdminUser(ctx, first.ID, AdminUserUpdate{
		DisplayName: first.DisplayName,
		Roles:       []string{"admin"},
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("demote last superadmin error = %v, want ErrConflict", err)
	}

	second, err := st.CreateAdminUser(ctx, AdminUserCreate{
		Username:     "backup-admin",
		DisplayName:  "Backup Administrator",
		PasswordHash: hash,
		Roles:        []string{"superadmin"},
	})
	if err != nil {
		t.Fatalf("CreateAdminUser: %v", err)
	}
	if _, err := st.UpdateAdminUser(ctx, first.ID, AdminUserUpdate{
		DisplayName: first.DisplayName,
		Roles:       []string{"admin"},
	}); err != nil {
		t.Fatalf("demote first superadmin after backup exists: %v", err)
	}

	users, err := st.ListUsers(ctx)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("user count = %d, want 2", len(users))
	}
	foundBackup := false
	for _, user := range users {
		if user.ID == second.ID {
			foundBackup = containsString(user.Roles, "superadmin")
		}
	}
	if !foundBackup {
		t.Fatal("backup superadmin role was not persisted")
	}
}

func TestAdminRolesKeepSystemRolesImmutable(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	if _, err := st.UpdateRole(ctx, "operator", "modified", []string{rbac.DevicesRead}); !errors.Is(err, ErrConflict) {
		t.Fatalf("UpdateRole(system) error = %v, want ErrConflict", err)
	}

	role, err := st.CreateRole(ctx, "helpdesk", "Help desk operators", []string{rbac.DevicesRead, rbac.CommandsRead})
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if role.System {
		t.Fatal("custom role unexpectedly marked system")
	}
	updated, err := st.UpdateRole(ctx, role.ID, "Help desk with enrollment visibility", []string{rbac.DevicesRead, rbac.CommandsRead, rbac.EnrollmentRead})
	if err != nil {
		t.Fatalf("UpdateRole(custom): %v", err)
	}
	if !containsString(updated.Permissions, rbac.EnrollmentRead) {
		t.Fatalf("updated permissions = %#v", updated.Permissions)
	}

	roles, err := st.ListRoles(ctx)
	if err != nil {
		t.Fatalf("ListRoles: %v", err)
	}
	found := false
	for _, candidate := range roles {
		if candidate.ID == role.ID {
			found = containsString(candidate.Permissions, rbac.EnrollmentRead)
		}
	}
	if !found {
		t.Fatal("updated custom role not returned by ListRoles")
	}
}

func TestSystemSettingsRoundTrip(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	if err := st.SetSystemSetting(ctx, "site_name", "Guardian Lab"); err != nil {
		t.Fatalf("SetSystemSetting: %v", err)
	}
	if err := st.SetSystemSetting(ctx, "telemetry_stale_seconds", "180"); err != nil {
		t.Fatalf("SetSystemSetting second: %v", err)
	}
	values, err := st.GetSystemSettings(ctx)
	if err != nil {
		t.Fatalf("GetSystemSettings: %v", err)
	}
	if values["site_name"] != "Guardian Lab" || values["telemetry_stale_seconds"] != "180" {
		t.Fatalf("settings = %#v", values)
	}
}
