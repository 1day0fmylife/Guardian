package rbac

import "testing"

func TestDefaultRolesDoNotGrantViewerMutation(t *testing.T) {
	var viewer RoleDefinition
	for _, role := range DefaultRoles {
		if role.Name == "viewer" {
			viewer = role
			break
		}
	}
	if viewer.Name == "" {
		t.Fatal("viewer role missing")
	}
	if HasPermission(viewer.Permissions, DevicesUpdate) {
		t.Fatal("viewer must not have devices.update")
	}
	if !HasPermission(viewer.Permissions, DevicesRead) {
		t.Fatal("viewer must have devices.read")
	}
}

func TestServicePermissionsAreDistinctAndRoleScoped(t *testing.T) {
	if ServicesRead == ServicesManage {
		t.Fatal("services.read and services.manage must be distinct")
	}
	if !HasPermission(AllPermissions, ServicesRead) || !HasPermission(AllPermissions, ServicesManage) {
		t.Fatal("services permissions must be part of the permission namespace")
	}

	want := map[string]struct{ read, manage bool }{
		"superadmin": {true, true},
		"admin":      {true, true},
		"operator":   {true, false},
		"auditor":    {true, false},
		"viewer":     {false, false},
	}
	for _, role := range DefaultRoles {
		expected, ok := want[role.Name]
		if !ok {
			t.Fatalf("unexpected default role %q", role.Name)
		}
		if got := HasPermission(role.Permissions, ServicesRead); got != expected.read {
			t.Errorf("role %s services.read = %v, want %v", role.Name, got, expected.read)
		}
		if got := HasPermission(role.Permissions, ServicesManage); got != expected.manage {
			t.Errorf("role %s services.manage = %v, want %v", role.Name, got, expected.manage)
		}
	}
}
