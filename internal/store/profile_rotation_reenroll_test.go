package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/1day0fmylife/Guardian/internal/domain"
	"github.com/1day0fmylife/Guardian/internal/security"
)

type rotationFixture struct {
	profile domain.VPNProfile
	pool    domain.AddressPool
}

func newRotationFixture(t *testing.T, st *Store, label, cidr string, keyFill byte) rotationFixture {
	t.Helper()
	ctx := context.Background()
	pool, err := st.CreateAddressPool(ctx, AddressPoolCreate{Name: label, CIDR: cidr})
	if err != nil {
		t.Fatalf("CreateAddressPool: %v", err)
	}
	profile, err := st.CreateVPNProfile(ctx, VPNProfileCreate{
		Name: label, ServerPublicKey: testWGKey(keyFill), Endpoint: "192.0.2.1:51820",
		AllowedIPs: []string{"10.78.0.0/28"}, DNSServers: []string{"10.78.0.2"}, AddressPoolID: pool.ID,
	})
	if err != nil {
		t.Fatalf("CreateVPNProfile: %v", err)
	}
	return rotationFixture{profile: profile, pool: pool}
}

func (f rotationFixture) enroll(t *testing.T, st *Store, uuid, serial string, boundUUID string, key byte) (domain.ManagedEnrollmentClaimResult, error) {
	t.Helper()
	issued, err := st.CreateEnrollment(context.Background(), EnrollmentCreate{
		Name: uuid, ProfileID: f.profile.ID, BoundDeviceUUID: boundUUID, TTL: time.Minute,
	})
	if err != nil {
		t.Fatalf("CreateEnrollment: %v", err)
	}
	return st.ClaimManagedEnrollment(context.Background(), issued.Token, domain.EnrollmentClaim{
		DeviceUUID: uuid, SerialNumber: serial, DeviceName: uuid, PublicKey: testWGKey(key),
	})
}

func strPtr(v string) *string { return &v }

func TestVPNProfileRotationReachesEnrolledDevices(t *testing.T) {
	forEachDialect(t, func(t *testing.T, st *Store) {
		ctx := context.Background()
		meta := testActor(t, st)
		f := newRotationFixture(t, st, "rotate", "10.140.0.0/29", 51)
		active, err := f.enroll(t, st, "rotate-active", "", "", 52)
		if err != nil {
			t.Fatalf("enroll active: %v", err)
		}
		suspended, err := f.enroll(t, st, "rotate-suspended", "", "", 53)
		if err != nil {
			t.Fatalf("enroll suspended: %v", err)
		}
		if _, err := st.SuspendDeviceVPNAndQueueDisconnect(ctx, suspended.Device.ID); err != nil {
			t.Fatalf("suspend: %v", err)
		}

		newKey := testWGKey(54)
		result, err := st.UpdateVPNProfile(ctx, meta, f.profile.ID, VPNProfileUpdate{
			ExpectedRevision: 1, ServerPublicKey: &newKey, Endpoint: strPtr("192.0.2.2:51821"),
			RotationGrace: time.Hour,
		})
		if err != nil {
			t.Fatalf("UpdateVPNProfile: %v", err)
		}
		if !result.Changed || !result.ServerKeyRotated || !result.DeviceConfigChanged || result.AffectedPeers != 2 {
			t.Fatalf("result = %+v", result)
		}
		if len(result.NotifiedDeviceIDs) != 1 || result.NotifiedDeviceIDs[0] != active.Device.ID {
			t.Fatalf("notified = %v, want only the active device", result.NotifiedDeviceIDs)
		}
		p := result.Profile
		if p.Revision != 2 || p.ServerPublicKey != newKey || p.PreviousServerPublicKey != f.profile.ServerPublicKey ||
			p.PreviousEndpoint != "192.0.2.1:51820" || p.PreviousValidUntil == "" {
			t.Fatalf("profile = %+v", p)
		}
		stored, err := st.GetVPNProfile(ctx, f.profile.ID)
		if err != nil || stored.Revision != 2 || stored.PreviousServerPublicKey != f.profile.ServerPublicKey {
			t.Fatalf("stored profile = %+v, %v", stored, err)
		}

		// The device fetches the new configuration with a higher revision.
		cfg, err := st.ManagedConfigForDevice(ctx, active.Device.ID)
		if err != nil {
			t.Fatalf("ManagedConfigForDevice: %v", err)
		}
		if cfg.ServerPublicKey != newKey || cfg.Endpoint != "192.0.2.2:51821" || cfg.ConfigRevision != 2 {
			t.Fatalf("device config = %+v", cfg)
		}
		if rev, err := st.DeviceConfigRevision(ctx, active.Device.ID); err != nil || rev != 2 {
			t.Fatalf("DeviceConfigRevision = %d, %v", rev, err)
		}
		commands, err := st.PollDeviceCommands(ctx, active.Device.ID, 10, false)
		if err != nil {
			t.Fatalf("PollDeviceCommands: %v", err)
		}
		var apply int
		for _, c := range commands {
			if c.Type == "apply-config" {
				apply++
				var payload map[string]any
				_ = json.Unmarshal(c.Payload, &payload)
				if payload["reason"] != "profile_updated" {
					t.Fatalf("payload = %s", c.Payload)
				}
			}
		}
		if apply != 1 {
			t.Fatalf("apply-config commands = %d, want 1 (%+v)", apply, commands)
		}
		// The gateway re-applies the peers for the new revision.
		pending, err := st.ListPendingWireGuardReconciliations(ctx, 100)
		if err != nil {
			t.Fatalf("ListPendingWireGuardReconciliations: %v", err)
		}
		seen := map[string]bool{}
		for _, item := range pending {
			seen[item.DeviceID] = true
		}
		if !seen[active.Device.ID] || !seen[suspended.Device.ID] {
			t.Fatalf("pending reconciliations = %+v", pending)
		}

		// Replay of the same request is a no-op, even with the stale revision.
		replay, err := st.UpdateVPNProfile(ctx, meta, f.profile.ID, VPNProfileUpdate{
			ExpectedRevision: 1, ServerPublicKey: &newKey, Endpoint: strPtr("192.0.2.2:51821"),
		})
		if err != nil || replay.Changed || replay.Profile.Revision != 2 {
			t.Fatalf("replay = %+v, %v", replay, err)
		}
		// A different change against a stale revision is refused.
		var coded *ServiceCatalogError
		_, err = st.UpdateVPNProfile(ctx, meta, f.profile.ID, VPNProfileUpdate{ExpectedRevision: 1, PersistentKeepalive: ptrInt(15)})
		if !errors.As(err, &coded) || coded.Code != "revision_conflict" {
			t.Fatalf("stale update err = %v", err)
		}
		_, err = st.UpdateVPNProfile(ctx, meta, f.profile.ID, VPNProfileUpdate{ExpectedRevision: 2, AddressPoolID: strPtr("other")})
		if !errors.As(err, &coded) || coded.Code != "profile_address_pool_immutable" {
			t.Fatalf("pool change err = %v", err)
		}
		bad := "not-a-key"
		if _, err := st.UpdateVPNProfile(ctx, meta, f.profile.ID, VPNProfileUpdate{ExpectedRevision: 2, ServerPublicKey: &bad}); !errors.Is(err, security.ErrInvalidWireGuardPublicKey) {
			t.Fatalf("bad key err = %v", err)
		}
		// A name-only change bumps the profile but not the devices.
		renamed, err := st.UpdateVPNProfile(ctx, meta, f.profile.ID, VPNProfileUpdate{ExpectedRevision: 2, Name: strPtr("rotate-renamed")})
		if err != nil || !renamed.Changed || renamed.DeviceConfigChanged || renamed.AffectedPeers != 0 {
			t.Fatalf("rename = %+v, %v", renamed, err)
		}
		if rev, _ := st.DeviceConfigRevision(ctx, active.Device.ID); rev != 2 {
			t.Fatalf("rename changed device revision to %d", rev)
		}

		// Rollout: pending until the device reports the new revision.
		rollout, err := st.VPNProfileRollout(ctx, f.profile.ID, 10)
		if err != nil || rollout.Peers != 1 || rollout.Pending != 1 || rollout.PreviousKeyRetirable {
			t.Fatalf("rollout before telemetry = %+v, %v", rollout, err)
		}
		if _, err := st.RecordDeviceTelemetry(ctx, active.Device.ID, domain.DeviceTelemetryInput{TunnelState: "connected", ConfigRevision: 2}); err != nil {
			t.Fatalf("RecordDeviceTelemetry: %v", err)
		}
		rollout, err = st.VPNProfileRollout(ctx, f.profile.ID, 10)
		if err != nil || rollout.Applied != 1 || rollout.Pending != 0 || !rollout.PreviousKeyRetirable {
			t.Fatalf("rollout after telemetry = %+v, %v", rollout, err)
		}

		// Every change is audited in the same transaction.
		var audits int
		if err := st.DB().QueryRowContext(ctx, sQuery(st, "SELECT COUNT(*) FROM audit_events WHERE action = 'vpn_profile.update' AND resource_id = ?"), f.profile.ID).Scan(&audits); err != nil {
			t.Fatalf("count audit: %v", err)
		}
		if audits != 2 {
			t.Fatalf("vpn_profile.update audit events = %d, want 2", audits)
		}
	})
}

func ptrInt(v int) *int { return &v }

func TestRevokedDeviceReenrollsWithBoundEnrollment(t *testing.T) {
	forEachDialect(t, func(t *testing.T, st *Store) {
		ctx := context.Background()
		f := newRotationFixture(t, st, "reenroll", "10.141.0.0/29", 61)
		uuid := fmt.Sprintf("reenroll-%d", time.Now().UnixNano())
		first, err := f.enroll(t, st, uuid, "SN-1", "", 62)
		if err != nil {
			t.Fatalf("first enroll: %v", err)
		}

		var coded *ServiceCatalogError
		// Suspended: resume, not enroll.
		if _, err := st.SuspendDeviceVPNAndQueueDisconnect(ctx, first.Device.ID); err != nil {
			t.Fatalf("suspend: %v", err)
		}
		if _, err := f.enroll(t, st, uuid, "SN-1", uuid, 63); !errors.As(err, &coded) || coded.Code != "device_suspended" {
			t.Fatalf("enroll suspended err = %v", err)
		}
		if _, err := st.ResumeDeviceVPNAndQueueConnect(ctx, first.Device.ID); err != nil {
			t.Fatalf("resume: %v", err)
		}

		cmd, err := st.BeginDeviceVPNRevocation(ctx, first.Device.ID)
		if err != nil {
			t.Fatalf("BeginDeviceVPNRevocation: %v", err)
		}
		_ = cmd
		if _, err := f.enroll(t, st, uuid, "SN-1", uuid, 63); !errors.As(err, &coded) || coded.Code != "device_revocation_pending" {
			t.Fatalf("enroll while revoking err = %v", err)
		}
		var revision int64
		if err := st.DB().QueryRowContext(ctx, sQuery(st, "SELECT config_revision FROM wireguard_peers WHERE device_id = ?"), first.Device.ID).Scan(&revision); err != nil {
			t.Fatalf("load revision: %v", err)
		}
		if err := st.CompleteDeviceVPNRevocation(ctx, first.Device.ID, revision); err != nil {
			t.Fatalf("CompleteDeviceVPNRevocation: %v", err)
		}

		// Unbound token: a known UUID cannot be taken over.
		if _, err := f.enroll(t, st, uuid, "SN-1", "", 63); !errors.As(err, &coded) || coded.Code != "reenrollment_requires_bound_enrollment" {
			t.Fatalf("unbound re-enroll err = %v", err)
		}
		// Bound token, but another serial number.
		if _, err := f.enroll(t, st, uuid, "SN-2", uuid, 63); !errors.As(err, &coded) || coded.Code != "device_identity_mismatch" {
			t.Fatalf("wrong serial err = %v", err)
		}
		// The revoked key can never come back.
		if _, err := f.enroll(t, st, uuid, "SN-1", uuid, 62); !errors.Is(err, ErrConflict) {
			t.Fatalf("revoked key reuse err = %v", err)
		}

		again, err := f.enroll(t, st, uuid, "SN-1", uuid, 64)
		if err != nil {
			t.Fatalf("re-enroll: %v", err)
		}
		if !again.Reactivated || again.PreviousStatus != "revoked" {
			t.Fatalf("reactivation flags = %v/%q", again.Reactivated, again.PreviousStatus)
		}
		if again.Device.ID != first.Device.ID || again.Device.Status != "active" || again.Device.Suspended {
			t.Fatalf("device = %+v, want the same active record", again.Device)
		}
		if again.Config.ConfigRevision <= revision || again.Config.PeerID != first.Config.PeerID {
			t.Fatalf("config = %+v, want the reused peer with a newer revision than %d", again.Config, revision)
		}
		principal, err := st.DevicePrincipalByCredential(ctx, security.HashToken(again.Credential.Token))
		if err != nil || principal.DeviceID != first.Device.ID || principal.Status != "active" || principal.Suspended {
			t.Fatalf("new credential principal = %+v, %v", principal, err)
		}
		if _, err := st.DevicePrincipalByCredential(ctx, security.HashToken(first.Credential.Token)); !errors.Is(err, ErrNotFound) {
			t.Fatalf("old credential still valid: %v", err)
		}
		cfg, err := st.ManagedConfigForDevice(ctx, first.Device.ID)
		if err != nil || cfg.ConfigRevision != again.Config.ConfigRevision {
			t.Fatalf("managed config = %+v, %v", cfg, err)
		}
		pending, err := st.ListPendingWireGuardReconciliations(ctx, 100)
		if err != nil {
			t.Fatalf("ListPendingWireGuardReconciliations: %v", err)
		}
		found := false
		for _, item := range pending {
			if item.DeviceID == first.Device.ID && item.DesiredState == "connected" && item.PublicKey == testWGKey(64) {
				found = true
			}
		}
		if !found {
			t.Fatalf("reactivated peer is not pending on the gateway: %+v", pending)
		}
		// device_identities stays consistent with devices: one row per kind, all
		// owned by the reactivated record.
		rows, err := st.DB().QueryContext(ctx, sQuery(st, "SELECT kind, value, device_id FROM device_identities WHERE value IN (?, ?) ORDER BY kind"), uuid, "SN-1")
		if err != nil {
			t.Fatalf("load identities: %v", err)
		}
		var kinds []string
		for rows.Next() {
			var kind, value, owner string
			if err := rows.Scan(&kind, &value, &owner); err != nil {
				t.Fatal(err)
			}
			if owner != first.Device.ID {
				t.Fatalf("identity %s=%s owned by %s, want %s", kind, value, owner, first.Device.ID)
			}
			kinds = append(kinds, kind)
		}
		rows.Close()
		if fmt.Sprint(kinds) != "[device_uuid serial_number]" {
			t.Fatalf("identity rows = %v", kinds)
		}
		var deviceRows int
		if err := st.DB().QueryRowContext(ctx, sQuery(st, "SELECT COUNT(*) FROM devices WHERE device_uuid = ?"), uuid).Scan(&deviceRows); err != nil || deviceRows != 1 {
			t.Fatalf("device rows for uuid = %d, %v", deviceRows, err)
		}
		// Re-using the consumed token is still refused.
		if _, err := f.enroll(t, st, uuid, "SN-1", uuid, 65); !errors.Is(err, ErrConflict) {
			t.Fatalf("enroll an active device err = %v", err)
		}
	})
}

// A device key rotation whose response was lost must still be recoverable
// after a profile change raised the revision again.
func TestDeviceKeyRotationRetrySurvivesProfileChange(t *testing.T) {
	forEachDialect(t, func(t *testing.T, st *Store) {
		ctx := context.Background()
		f := newRotationFixture(t, st, "rotate-retry", "10.142.0.0/29", 71)
		claim, err := f.enroll(t, st, fmt.Sprintf("rotate-retry-%d", time.Now().UnixNano()), "", "", 72)
		if err != nil {
			t.Fatalf("enroll: %v", err)
		}
		if _, err := st.RotateDeviceWireGuardPublicKey(ctx, claim.Device.ID, testWGKey(73), 1); err != nil {
			t.Fatalf("rotate: %v", err)
		}
		newKey := testWGKey(74)
		if _, err := st.UpdateVPNProfile(ctx, testActor(t, st), f.profile.ID, VPNProfileUpdate{ExpectedRevision: 1, ServerPublicKey: &newKey}); err != nil {
			t.Fatalf("UpdateVPNProfile: %v", err)
		}
		cfg, err := st.RotateDeviceWireGuardPublicKey(ctx, claim.Device.ID, testWGKey(73), 1)
		if err != nil {
			t.Fatalf("retried rotation after profile change: %v", err)
		}
		if cfg.ServerPublicKey != newKey || cfg.ConfigRevision != 3 {
			t.Fatalf("config = %+v", cfg)
		}
		if _, err := st.RotateDeviceWireGuardPublicKey(ctx, claim.Device.ID, testWGKey(73), 9); !errors.Is(err, ErrConflict) {
			t.Fatalf("future revision err = %v", err)
		}
	})
}

// Identities owned by another record (serial reused under a new UUID, or a
// device row edited by hand as on the lab stand) give a stable 409 code, not
// a unique-constraint driver error.
func TestEnrollmentIdentityConflictsAreStable(t *testing.T) {
	forEachDialect(t, func(t *testing.T, st *Store) {
		ctx := context.Background()
		f := newRotationFixture(t, st, "identity-conflict", "10.143.0.0/29", 81)
		uuid := fmt.Sprintf("identity-%d", time.Now().UnixNano())
		first, err := f.enroll(t, st, uuid, "SN-X", "", 82)
		if err != nil {
			t.Fatalf("enroll: %v", err)
		}
		var coded *ServiceCatalogError
		if _, err := f.enroll(t, st, uuid+"-other", "SN-X", "", 83); !errors.As(err, &coded) || coded.Code != "device_identity_conflict" {
			t.Fatalf("serial reused under a new UUID: %v", err)
		}
		// Hand edit: the device row gets another UUID, device_identities keeps the old one.
		if _, err := st.DB().ExecContext(ctx, sQuery(st, "UPDATE devices SET device_uuid = ? WHERE id = ?"), uuid+"-renamed", first.Device.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.enroll(t, st, uuid, "", "", 84); !errors.As(err, &coded) || coded.Code != "device_identity_conflict" {
			t.Fatalf("enroll after hand-edited UUID: %v", err)
		}
	})
}
