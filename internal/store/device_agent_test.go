package store

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/1day0fmylife/Guardian/internal/domain"
	"github.com/1day0fmylife/Guardian/internal/security"
)

func TestManagedEnrollmentDeviceChannel(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	pool, err := st.CreateAddressPool(ctx, AddressPoolCreate{
		Name: "managed-phones", CIDR: "10.88.0.0/29", Gateway: "10.88.0.1",
	})
	if err != nil {
		t.Fatalf("CreateAddressPool: %v", err)
	}
	profile, err := st.CreateVPNProfile(ctx, VPNProfileCreate{
		Name: "managed-hq", ServerPublicKey: testWGKey(11), Endpoint: "vpn.example.test:51820",
		AllowedIPs: []string{"10.0.0.0/8"}, PersistentKeepalive: 25, AddressPoolID: pool.ID,
	})
	if err != nil {
		t.Fatalf("CreateVPNProfile: %v", err)
	}
	issued, err := st.CreateEnrollment(ctx, EnrollmentCreate{
		Name: "managed-phone", ProfileID: profile.ID, BoundDeviceUUID: "managed-device-1", TTL: 15 * time.Minute,
	})
	if err != nil {
		t.Fatalf("CreateEnrollment: %v", err)
	}
	claim, err := st.ClaimManagedEnrollment(ctx, issued.Token, domain.EnrollmentClaim{
		DeviceUUID: "managed-device-1", DeviceName: "ArlanPhone Managed", PublicKey: testWGKey(12),
	})
	if err != nil {
		t.Fatalf("ClaimManagedEnrollment: %v", err)
	}
	if claim.Credential.Token == "" {
		t.Fatal("device credential token is empty")
	}
	if claim.Config.AssignedAddress != "10.88.0.2/32" {
		t.Fatalf("assigned address = %q", claim.Config.AssignedAddress)
	}

	var storedHash string
	if err := st.DB().QueryRowContext(ctx, sQuery(st, "SELECT token_hash FROM device_credentials WHERE id = ?"), claim.Credential.Credential.ID).Scan(&storedHash); err != nil {
		t.Fatalf("read device credential: %v", err)
	}
	if storedHash == claim.Credential.Token {
		t.Fatal("device credential stored in plaintext")
	}
	if storedHash != security.HashToken(claim.Credential.Token) {
		t.Fatal("device credential hash mismatch")
	}

	principal, err := st.DevicePrincipalByCredential(ctx, security.HashToken(claim.Credential.Token))
	if err != nil {
		t.Fatalf("DevicePrincipalByCredential: %v", err)
	}
	if principal.DeviceID != claim.Device.ID || principal.Suspended {
		t.Fatalf("unexpected device principal: %+v", principal)
	}

	rotatedConfig, err := st.RotateDeviceWireGuardPublicKey(ctx, claim.Device.ID, testWGKey(13), 1)
	if err != nil {
		t.Fatalf("RotateDeviceWireGuardPublicKey: %v", err)
	}
	if rotatedConfig.ConfigRevision != 2 {
		t.Fatalf("rotated config revision = %d, want 2", rotatedConfig.ConfigRevision)
	}
	if _, err := st.RotateDeviceWireGuardPublicKey(ctx, claim.Device.ID, testWGKey(14), 1); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale key rotation error = %v, want ErrConflict", err)
	}

	command, err := st.CreateDeviceCommand(ctx, DeviceCommandCreate{
		DeviceID: claim.Device.ID, Type: "apply-config", Payload: json.RawMessage(`{"revision":1}`), TTL: time.Minute,
	})
	if err != nil {
		t.Fatalf("CreateDeviceCommand: %v", err)
	}
	polled, err := st.PollDeviceCommands(ctx, claim.Device.ID, 20, false)
	if err != nil {
		t.Fatalf("PollDeviceCommands: %v", err)
	}
	if len(polled) != 1 || polled[0].ID != command.ID || polled[0].Status != "delivered" {
		t.Fatalf("unexpected polled commands: %+v", polled)
	}
	if err := st.UpdateDeviceCommandResult(ctx, claim.Device.ID, command.ID, "running", nil, ""); err != nil {
		t.Fatalf("command running: %v", err)
	}
	if err := st.UpdateDeviceCommandResult(ctx, claim.Device.ID, command.ID, "succeeded", json.RawMessage(`{"applied_revision":1}`), ""); err != nil {
		t.Fatalf("command succeeded: %v", err)
	}

	latency := int64(8)
	telemetry, err := st.RecordDeviceTelemetry(ctx, claim.Device.ID, domain.DeviceTelemetryInput{
		TunnelState: "connected", AssignedAddress: "10.88.0.2", RXBytes: 100, TXBytes: 200,
		TunnelUptimeSeconds: 30, LatencyMS: &latency, ConfigRevision: 1, AgentVersion: "test",
	})
	if err != nil {
		t.Fatalf("RecordDeviceTelemetry: %v", err)
	}
	latest, err := st.LatestDeviceTelemetry(ctx, claim.Device.ID)
	if err != nil {
		t.Fatalf("LatestDeviceTelemetry: %v", err)
	}
	if latest.ID != telemetry.ID || latest.ConfigRevision != 1 || latest.LatencyMS == nil || *latest.LatencyMS != latency {
		t.Fatalf("unexpected latest telemetry: %+v", latest)
	}

	disconnect, err := st.SuspendDeviceVPNAndQueueDisconnect(ctx, claim.Device.ID)
	if err != nil {
		t.Fatalf("SuspendDeviceVPNAndQueueDisconnect: %v", err)
	}
	if disconnect.Type != "disconnect" {
		t.Fatalf("suspend command type = %q", disconnect.Type)
	}
	principal, err = st.DevicePrincipalByCredential(ctx, security.HashToken(claim.Credential.Token))
	if err != nil {
		t.Fatalf("suspended device management auth: %v", err)
	}
	if !principal.Suspended {
		t.Fatal("suspended device lost suspension state in principal")
	}
	if _, err := st.RotateDeviceCredential(ctx, principal); !errors.Is(err, ErrConflict) {
		t.Fatalf("rotate while suspended error = %v, want ErrConflict", err)
	}

	resumeCommand, err := st.ResumeDeviceVPNAndQueueConnect(ctx, claim.Device.ID)
	if err != nil {
		t.Fatalf("ResumeDeviceVPNAndQueueConnect: %v", err)
	}
	if resumeCommand.Type != "connect" {
		t.Fatalf("resume command type = %q", resumeCommand.Type)
	}
	principal, err = st.DevicePrincipalByCredential(ctx, security.HashToken(claim.Credential.Token))
	if err != nil {
		t.Fatalf("principal after resume: %v", err)
	}
	rotated, err := st.RotateDeviceCredential(ctx, principal)
	if err != nil {
		t.Fatalf("RotateDeviceCredential: %v", err)
	}
	if _, err := st.DevicePrincipalByCredential(ctx, security.HashToken(claim.Credential.Token)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old credential error = %v, want ErrNotFound", err)
	}
	if _, err := st.DevicePrincipalByCredential(ctx, security.HashToken(rotated.Token)); err != nil {
		t.Fatalf("new credential auth: %v", err)
	}

	revokeCommand, err := st.BeginDeviceVPNRevocation(ctx, claim.Device.ID)
	if err != nil {
		t.Fatalf("BeginDeviceVPNRevocation: %v", err)
	}
	if revokeCommand.Type != "disconnect" {
		t.Fatalf("revoke command type = %q", revokeCommand.Type)
	}
	revokingPrincipal, err := st.DevicePrincipalByCredential(ctx, security.HashToken(rotated.Token))
	if err != nil {
		t.Fatalf("revoking device management auth: %v", err)
	}
	if !revokingPrincipal.Suspended || revokingPrincipal.Status != "revoking" {
		t.Fatalf("unexpected revoking principal: %+v", revokingPrincipal)
	}
	if _, err := st.ManagedConfigForDevice(ctx, claim.Device.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("config after revoke error = %v, want ErrNotFound", err)
	}
	if err := st.CompleteDeviceVPNRevocation(ctx, claim.Device.ID, 4); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale revocation completion error = %v, want ErrConflict", err)
	}
	if err := st.CompleteDeviceVPNRevocation(ctx, claim.Device.ID, 5); err != nil {
		t.Fatalf("CompleteDeviceVPNRevocation: %v", err)
	}
	if _, err := st.DevicePrincipalByCredential(ctx, security.HashToken(rotated.Token)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("credential after finalized revoke error = %v, want ErrNotFound", err)
	}
	var currentLeaseCount int
	if err := st.DB().QueryRowContext(ctx, sQuery(st, "SELECT COUNT(*) FROM address_leases WHERE device_id = ?"), claim.Device.ID).Scan(&currentLeaseCount); err != nil {
		t.Fatalf("count finalized current leases: %v", err)
	}
	if currentLeaseCount != 0 {
		t.Fatalf("finalized current lease count = %d, want 0", currentLeaseCount)
	}
	var archivedLeaseCount int
	if err := st.DB().QueryRowContext(ctx, sQuery(st, "SELECT COUNT(*) FROM address_lease_history WHERE device_id = ?"), claim.Device.ID).Scan(&archivedLeaseCount); err != nil {
		t.Fatalf("count archived leases: %v", err)
	}
	if archivedLeaseCount != 1 {
		t.Fatalf("archived lease count = %d, want 1", archivedLeaseCount)
	}
}
