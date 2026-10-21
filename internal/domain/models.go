package domain

type User struct {
	ID          string   `json:"id"`
	Username    string   `json:"username"`
	DisplayName string   `json:"display_name"`
	Disabled    bool     `json:"disabled"`
	Roles       []string `json:"roles,omitempty"`
	// MustChangePassword is set for bootstrap and administrator-issued
	// passwords; the API refuses everything except password change until cleared.
	MustChangePassword bool   `json:"must_change_password"`
	PasswordChangedAt  string `json:"password_changed_at,omitempty"`
	CreatedAt          string `json:"created_at"`
	UpdatedAt          string `json:"updated_at"`
}

type Principal struct {
	UserID      string   `json:"user_id"`
	Username    string   `json:"username"`
	DisplayName string   `json:"display_name"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
	// MustChangePassword mirrors the user flag at session load time.
	MustChangePassword bool   `json:"must_change_password"`
	SessionID          string `json:"-"`
	TokenHash          string `json:"-"`
}

type Device struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	DeviceUUID   string `json:"device_uuid"`
	SerialNumber string `json:"serial_number,omitempty"`
	PrimaryMAC   string `json:"primary_mac,omitempty"`
	Status       string `json:"status"`
	Suspended    bool   `json:"suspended"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
	LastSeenAt   string `json:"last_seen_at,omitempty"`
}

type DeviceCreate struct {
	Name         string `json:"name"`
	DeviceUUID   string `json:"device_uuid"`
	SerialNumber string `json:"serial_number,omitempty"`
	PrimaryMAC   string `json:"primary_mac,omitempty"`
}

type AddressPool struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	CIDR       string   `json:"cidr"`
	Gateway    string   `json:"gateway,omitempty"`
	DNSServers []string `json:"dns_servers,omitempty"`
	CreatedAt  string   `json:"created_at"`
	UpdatedAt  string   `json:"updated_at"`
}

type VPNProfile struct {
	ID                  string   `json:"id"`
	Name                string   `json:"name"`
	ServerPublicKey     string   `json:"server_public_key"`
	Endpoint            string   `json:"endpoint"`
	AllowedIPs          []string `json:"allowed_ips"`
	DNSServers          []string `json:"dns_servers,omitempty"`
	PersistentKeepalive int      `json:"persistent_keepalive"`
	AddressPoolID       string   `json:"address_pool_id"`
	// Revision increases with every change that devices must apply.
	Revision int64 `json:"revision"`
	// Previous* keep the server key/endpoint replaced by the last rotation
	// until PreviousValidUntil, so an operator can retire the old gateway key
	// only after the devices have applied the new configuration.
	PreviousServerPublicKey string `json:"previous_server_public_key,omitempty"`
	PreviousEndpoint        string `json:"previous_endpoint,omitempty"`
	PreviousValidUntil      string `json:"previous_valid_until,omitempty"`
	CreatedAt               string `json:"created_at"`
	UpdatedAt               string `json:"updated_at"`
}

type Enrollment struct {
	ID                string `json:"id"`
	Name              string `json:"name,omitempty"`
	ProfileID         string `json:"profile_id"`
	BoundDeviceUUID   string `json:"bound_device_uuid,omitempty"`
	BoundSerialNumber string `json:"bound_serial_number,omitempty"`
	BoundMAC          string `json:"bound_mac,omitempty"`
	ExpiresAt         string `json:"expires_at"`
	ConsumedAt        string `json:"consumed_at,omitempty"`
	RevokedAt         string `json:"revoked_at,omitempty"`
	CreatedAt         string `json:"created_at"`
}

type WireGuardPeer struct {
	ID              string `json:"id"`
	DeviceID        string `json:"device_id"`
	ProfileID       string `json:"profile_id"`
	PublicKey       string `json:"public_key"`
	AssignedAddress string `json:"assigned_address"`
	DesiredState    string `json:"desired_state"`
	ObservedState   string `json:"observed_state"`
	ConfigRevision  int64  `json:"config_revision"`
	RevokedAt       string `json:"revoked_at,omitempty"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
}

type AuditEvent struct {
	ID           string `json:"id"`
	ActorUserID  string `json:"actor_user_id,omitempty"`
	Action       string `json:"action"`
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id,omitempty"`
	SourceIP     string `json:"source_ip,omitempty"`
	RequestID    string `json:"request_id,omitempty"`
	Details      string `json:"details,omitempty"`
	CreatedAt    string `json:"created_at"`
}
