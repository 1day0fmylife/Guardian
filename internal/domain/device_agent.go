package domain

import "encoding/json"

type DevicePrincipal struct {
	DeviceID     string `json:"device_id"`
	DeviceUUID   string `json:"device_uuid"`
	CredentialID string `json:"-"`
	Status       string `json:"status"`
	Suspended    bool   `json:"suspended"`
}

type DeviceCredential struct {
	ID         string `json:"id"`
	DeviceID   string `json:"device_id"`
	CreatedAt  string `json:"created_at"`
	LastUsedAt string `json:"last_used_at,omitempty"`
	RevokedAt  string `json:"revoked_at,omitempty"`
	ExpiresAt  string `json:"expires_at,omitempty"`
}

type DeviceCredentialIssued struct {
	Credential DeviceCredential `json:"credential"`
	Token      string           `json:"token"`
}

type ManagedEnrollmentClaimResult struct {
	Device     Device                 `json:"device"`
	Config     ManagedWireGuardConfig `json:"wireguard"`
	Credential DeviceCredentialIssued `json:"device_credential"`
}

type DeviceCommand struct {
	ID             string          `json:"id"`
	DeviceID       string          `json:"device_id"`
	Type           string          `json:"type"`
	Status         string          `json:"status"`
	IdempotencyKey string          `json:"idempotency_key"`
	Payload        json.RawMessage `json:"payload"`
	Result         json.RawMessage `json:"result,omitempty"`
	ErrorMessage   string          `json:"error_message,omitempty"`
	CreatedAt      string          `json:"created_at"`
	DeliveredAt    string          `json:"delivered_at,omitempty"`
	AcknowledgedAt string          `json:"acknowledged_at,omitempty"`
	FinishedAt     string          `json:"finished_at,omitempty"`
	ExpiresAt      string          `json:"expires_at"`
}

type DeviceTelemetryInput struct {
	TunnelState         string `json:"tunnel_state"`
	LatestHandshakeAt   string `json:"latest_handshake_at,omitempty"`
	Endpoint            string `json:"endpoint,omitempty"`
	AssignedAddress     string `json:"assigned_address,omitempty"`
	RXBytes             int64  `json:"rx_bytes"`
	TXBytes             int64  `json:"tx_bytes"`
	TunnelUptimeSeconds int64  `json:"tunnel_uptime_seconds"`
	LatencyMS           *int64 `json:"latency_ms,omitempty"`
	ConfigRevision      int64  `json:"config_revision"`
	ArlanPhoneVersion   string `json:"arlanphone_version,omitempty"`
	AgentVersion        string `json:"agent_version,omitempty"`
	WireGuardVersion    string `json:"wireguard_version,omitempty"`
	ErrorCode           string `json:"error_code,omitempty"`
	ErrorMessage        string `json:"error_message,omitempty"`
}

type DeviceTelemetry struct {
	ID                  string `json:"id"`
	DeviceID            string `json:"device_id"`
	ObservedAt          string `json:"observed_at"`
	TunnelState         string `json:"tunnel_state"`
	LatestHandshakeAt   string `json:"latest_handshake_at,omitempty"`
	Endpoint            string `json:"endpoint,omitempty"`
	AssignedAddress     string `json:"assigned_address,omitempty"`
	RXBytes             int64  `json:"rx_bytes"`
	TXBytes             int64  `json:"tx_bytes"`
	TunnelUptimeSeconds int64  `json:"tunnel_uptime_seconds"`
	LatencyMS           *int64 `json:"latency_ms,omitempty"`
	ConfigRevision      int64  `json:"config_revision"`
	ArlanPhoneVersion   string `json:"arlanphone_version,omitempty"`
	AgentVersion        string `json:"agent_version,omitempty"`
	WireGuardVersion    string `json:"wireguard_version,omitempty"`
	ErrorCode           string `json:"error_code,omitempty"`
	ErrorMessage        string `json:"error_message,omitempty"`
}
