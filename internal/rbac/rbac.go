package rbac

type RoleDefinition struct {
	Name        string
	Description string
	Permissions []string
}

const (
	DevicesRead        = "devices.read"
	DevicesCreate      = "devices.create"
	DevicesUpdate      = "devices.update"
	DevicesDelete      = "devices.delete"
	DevicesConnect     = "devices.connect"
	DevicesDisconnect  = "devices.disconnect"
	DevicesRotateKey   = "devices.rotate_key"
	DevicesReconfigure = "devices.reconfigure"

	EnrollmentRead   = "enrollment.read"
	EnrollmentCreate = "enrollment.create"
	EnrollmentRevoke = "enrollment.revoke"

	ProfilesRead   = "profiles.read"
	ProfilesCreate = "profiles.create"
	ProfilesUpdate = "profiles.update"
	ProfilesDelete = "profiles.delete"

	PoolsRead   = "pools.read"
	PoolsCreate = "pools.create"
	PoolsUpdate = "pools.update"
	PoolsDelete = "pools.delete"

	CommandsRead   = "commands.read"
	CommandsCreate = "commands.create"

	UsersRead   = "users.read"
	UsersCreate = "users.create"
	UsersUpdate = "users.update"
	UsersDelete = "users.delete"

	RolesRead   = "roles.read"
	RolesCreate = "roles.create"
	RolesUpdate = "roles.update"
	RolesDelete = "roles.delete"

	ServicesRead   = "services.read"
	ServicesManage = "services.manage"

	AuditRead = "audit.read"

	SettingsRead   = "settings.read"
	SettingsUpdate = "settings.update"
)

var AllPermissions = []string{
	DevicesRead, DevicesCreate, DevicesUpdate, DevicesDelete,
	DevicesConnect, DevicesDisconnect, DevicesRotateKey, DevicesReconfigure,
	EnrollmentRead, EnrollmentCreate, EnrollmentRevoke,
	ProfilesRead, ProfilesCreate, ProfilesUpdate, ProfilesDelete,
	PoolsRead, PoolsCreate, PoolsUpdate, PoolsDelete,
	CommandsRead, CommandsCreate,
	ServicesRead, ServicesManage,
	UsersRead, UsersCreate, UsersUpdate, UsersDelete,
	RolesRead, RolesCreate, RolesUpdate, RolesDelete,
	AuditRead,
	SettingsRead, SettingsUpdate,
}

var DefaultRoles = []RoleDefinition{
	{
		Name:        "superadmin",
		Description: "Unrestricted platform administration",
		Permissions: AllPermissions,
	},
	{
		Name:        "admin",
		Description: "Administrative management of devices, enrollment, VPN profiles and users",
		Permissions: []string{
			DevicesRead, DevicesCreate, DevicesUpdate, DevicesDelete,
			DevicesConnect, DevicesDisconnect, DevicesRotateKey, DevicesReconfigure,
			EnrollmentRead, EnrollmentCreate, EnrollmentRevoke,
			ProfilesRead, ProfilesCreate, ProfilesUpdate, ProfilesDelete,
			PoolsRead, PoolsCreate, PoolsUpdate, PoolsDelete,
			CommandsRead, CommandsCreate,
			ServicesRead, ServicesManage,
			UsersRead, UsersCreate, UsersUpdate,
			RolesRead,
			AuditRead,
			SettingsRead,
		},
	},
	{
		Name:        "operator",
		Description: "Operational device actions and configuration deployment",
		Permissions: []string{
			DevicesRead, DevicesUpdate,
			DevicesConnect, DevicesDisconnect, DevicesRotateKey, DevicesReconfigure,
			EnrollmentRead,
			ProfilesRead, PoolsRead,
			CommandsRead, CommandsCreate,
			ServicesRead,
		},
	},
	{
		Name:        "auditor",
		Description: "Read-only administrative and audit access",
		Permissions: []string{
			DevicesRead, EnrollmentRead, ProfilesRead, PoolsRead,
			CommandsRead, ServicesRead, UsersRead, RolesRead, AuditRead, SettingsRead,
		},
	},
	{
		Name:        "viewer",
		Description: "Read-only operational access",
		Permissions: []string{
			DevicesRead, ProfilesRead, PoolsRead, CommandsRead,
		},
	},
}

func HasPermission(granted []string, required string) bool {
	for _, permission := range granted {
		if permission == required {
			return true
		}
	}
	return false
}

// Covers reports whether granted includes every permission in required.
func Covers(granted, required []string) bool {
	set := make(map[string]struct{}, len(granted))
	for _, permission := range granted {
		set[permission] = struct{}{}
	}
	for _, permission := range required {
		if _, ok := set[permission]; !ok {
			return false
		}
	}
	return true
}
