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
