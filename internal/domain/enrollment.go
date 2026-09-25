package domain

type EnrollmentClaim struct {
	DeviceUUID           string `json:"device_uuid"`
	SerialNumber         string `json:"serial_number,omitempty"`
	PrimaryMAC           string `json:"primary_mac,omitempty"`
	DeviceName           string `json:"device_name"`
	PublicKey            string `json:"public_key"`
	DeviceCredentialHash string `json:"device_credential_hash,omitempty"`
}

type ManagedWireGuardConfig struct {
	DeviceID            string   `json:"device_id"`
	PeerID              string   `json:"peer_id"`
	ProfileID           string   `json:"profile_id"`
	AssignedAddress     string   `json:"assigned_address"`
	ServerPublicKey     string   `json:"server_public_key"`
	Endpoint            string   `json:"endpoint"`
	AllowedIPs          []string `json:"allowed_ips"`
	DNSServers          []string `json:"dns_servers,omitempty"`
	PersistentKeepalive int      `json:"persistent_keepalive"`
	ConfigRevision      int64    `json:"config_revision"`
}

type EnrollmentClaimResult struct {
	Device Device                 `json:"device"`
	Config ManagedWireGuardConfig `json:"wireguard"`
}
