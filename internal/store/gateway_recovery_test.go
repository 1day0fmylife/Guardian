package store

import (
	"context"
	"errors"
	"github.com/1day0fmylife/Guardian/internal/domain"
	"testing"
	"time"

	"github.com/1day0fmylife/Guardian/internal/security"
)

func TestRestartRequeuesDesiredPeersWithoutRestoringRevocation(t *testing.T) {
	forEachDialect(t, func(t *testing.T, st *Store) {
		ctx := context.Background()
		active, _ := enrollActiveDevice(t, st)
		revoked, _ := enrollActiveDevice(t, st)
		meta := testActor(t, st)
		if _, err := st.UpdateServiceDefinition(ctx, meta, "sunkardav", 1, davInput(true)); err != nil {
			t.Fatal(err)
		}
		for _, id := range []string{active.ID, revoked.ID} {
			if _, err := st.SetServiceGrant(ctx, meta, "sunkardav", "device", id, "allow"); err != nil {
				t.Fatal(err)
			}
		}
		pending, err := st.ListPendingWireGuardReconciliations(ctx, 10)
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range pending {
			if err := st.MarkWireGuardPeerApplied(ctx, item.PeerID, item.ConfigRevision); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := st.BeginDeviceVPNRevocation(ctx, revoked.ID); err != nil {
			t.Fatal(err)
		}
		// API/reconciler restart while peer removal is pending.
		if err := st.RequeueWireGuardReconciliation(ctx); err != nil {
			t.Fatal(err)
		}
		snap, err := st.ServiceAccessSnapshot(ctx)
		if err != nil || len(snap.Targets) != 1 || snap.Targets[0].DeviceID != active.ID {
			t.Fatalf("snapshot=%+v err=%v", snap, err)
		}
		pending, err = st.ListPendingWireGuardReconciliations(ctx, 10)
		if err != nil || len(pending) != 2 {
			t.Fatalf("recovery=%+v err=%v", pending, err)
		}
		for _, item := range pending {
			if item.DeviceID == revoked.ID && item.DesiredState != "revoked" {
				t.Fatal("revoking peer restored")
			}
			if err := st.MarkWireGuardPeerApplied(ctx, item.PeerID, item.ConfigRevision); err != nil {
				t.Fatal(err)
			}
		}
		if err := st.RequeueWireGuardReconciliation(ctx); err != nil {
			t.Fatal(err)
		}
		pending, err = st.ListPendingWireGuardReconciliations(ctx, 10)
		if err != nil || len(pending) != 1 || pending[0].DeviceID != active.ID {
			t.Fatalf("final recovery=%+v err=%v", pending, err)
		}
	})
}

func TestRotationIsStagedAndRejectsStaleLifecycle(t *testing.T) {
	forEachDialect(t, func(t *testing.T, st *Store) {
		ctx := context.Background()
		device, _ := enrollActiveDevice(t, st)
		cfg, err := st.ManagedConfigForDevice(ctx, device.ID)
		if err != nil {
			t.Fatal(err)
		}
		before, err := st.ServicePolicyRevision(ctx)
		if err != nil {
			t.Fatal(err)
		}
		rotated, err := st.RotateDeviceWireGuardPublicKey(ctx, device.ID, testWGKey(211), cfg.ConfigRevision)
		if err != nil {
			t.Fatal(err)
		}
		after, err := st.ServicePolicyRevision(ctx)
		if err != nil || after <= before {
			t.Fatalf("rotation policy revision=%d <= %d, err=%v", after, before, err)
		}
		if _, err := st.RotateDeviceWireGuardPublicKey(ctx, device.ID, testWGKey(212), rotated.ConfigRevision); !errors.Is(err, ErrConflict) {
			t.Fatalf("overlapping rotation: %v", err)
		}
		if _, err := st.RotateDeviceWireGuardPublicKey(ctx, device.ID, testWGKey(211), cfg.ConfigRevision); err != nil {
			t.Fatalf("exact retry: %v", err)
		}
		if err := st.RequeueWireGuardReconciliation(ctx); err != nil {
			t.Fatal(err)
		}
		pending, err := st.ListPendingWireGuardReconciliations(ctx, 10)
		if err != nil || len(pending) != 1 || pending[0].PreviousPublicKey == "" {
			t.Fatalf("restart lost previous key: %+v %v", pending, err)
		}
		if err := st.MarkWireGuardPeerApplied(ctx, cfg.PeerID, rotated.ConfigRevision); err != nil {
			t.Fatal(err)
		}
		if _, err := st.RotateDeviceWireGuardPublicKey(ctx, device.ID, testWGKey(212), cfg.ConfigRevision); !errors.Is(err, ErrConflict) {
			t.Fatalf("stale revision: %v", err)
		}
		if _, err := st.BeginDeviceVPNRevocation(ctx, device.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := st.RotateDeviceWireGuardPublicKey(ctx, device.ID, testWGKey(212), rotated.ConfigRevision); !errors.Is(err, ErrConflict) {
			t.Fatalf("revoking rotation: %v", err)
		}
	})
}

func TestCredentialRenewalCannotRacePastSuspensionOrRevocation(t *testing.T) {
	forEachDialect(t, func(t *testing.T, st *Store) {
		for _, action := range []string{"suspend", "revoke"} {
			ctx := context.Background()
			device, token := enrollActiveDevice(t, st)
			principal, err := st.DevicePrincipalByCredential(ctx, security.HashToken(token))
			if err != nil {
				t.Fatal(err)
			}
			if action == "suspend" {
				_, err = st.SuspendDeviceVPNAndQueueDisconnect(ctx, device.ID)
			} else {
				_, err = st.BeginDeviceVPNRevocation(ctx, device.ID)
			}
			if err != nil {
				t.Fatal(err)
			}
			replacement := "replacement-" + device.ID
			if _, err := st.RotateDeviceCredentialHash(ctx, principal, security.HashToken(replacement)); !errors.Is(err, ErrConflict) {
				t.Fatalf("%s stale principal renewal=%v", action, err)
			}
			if _, err := st.DevicePrincipalByCredential(ctx, security.HashToken(replacement)); !errors.Is(err, ErrNotFound) {
				t.Fatalf("replacement issued after %s: %v", action, err)
			}
		}
	})
}

func TestCredentialRenewalPreservesGrantsAndPolicyRevision(t *testing.T) {
	forEachDialect(t, func(t *testing.T, st *Store) {
		ctx := context.Background()
		device, token := enrollActiveDevice(t, st)
		meta := testActor(t, st)
		if _, err := st.UpdateServiceDefinition(ctx, meta, "sunkardav", 1, davInput(true)); err != nil {
			t.Fatal(err)
		}
		if _, err := st.SetServiceGrant(ctx, meta, "sunkardav", "device", device.ID, "allow"); err != nil {
			t.Fatal(err)
		}
		before, err := st.DeviceServicePolicy(ctx, device.ID)
		if err != nil {
			t.Fatal(err)
		}
		principal, err := st.DevicePrincipalByCredential(ctx, security.HashToken(token))
		if err != nil {
			t.Fatal(err)
		}
		replacement := "renewed-" + device.ID
		if _, err := st.RotateDeviceCredentialHash(ctx, principal, security.HashToken(replacement)); err != nil {
			t.Fatal(err)
		}
		renewed, err := st.DevicePrincipalByCredential(ctx, security.HashToken(replacement))
		if err != nil || renewed.DeviceID != device.ID {
			t.Fatalf("renewed principal=%+v err=%v", renewed, err)
		}
		after, err := st.DeviceServicePolicy(ctx, renewed.DeviceID)
		if err != nil {
			t.Fatal(err)
		}
		if before.Revision != after.Revision || len(after.Services) != 1 || after.Services[0].ID != "sunkardav" {
			t.Fatalf("renewal changed policy: %+v -> %+v", before, after)
		}
		if _, err := st.DevicePrincipalByCredential(ctx, security.HashToken(token)); !errors.Is(err, ErrNotFound) {
			t.Fatalf("old credential retained: %v", err)
		}
	})
}

func TestPreviousKeyCannotBeReassignedBeforeRemovalCompletes(t *testing.T) {
	forEachDialect(t, func(t *testing.T, st *Store) {
		ctx := context.Background()
		a, _ := enrollActiveDevice(t, st)
		b, _ := enrollActiveDevice(t, st)
		acfg, err := st.ManagedConfigForDevice(ctx, a.ID)
		if err != nil {
			t.Fatal(err)
		}
		bcfg, err := st.ManagedConfigForDevice(ctx, b.ID)
		if err != nil {
			t.Fatal(err)
		}
		var oldKey string
		if err := st.db.QueryRowContext(ctx, st.q("SELECT public_key FROM wireguard_peers WHERE id = ?"), acfg.PeerID).Scan(&oldKey); err != nil {
			t.Fatal(err)
		}
		rotated, err := st.RotateDeviceWireGuardPublicKey(ctx, a.ID, testWGKey(213), acfg.ConfigRevision)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.RotateDeviceWireGuardPublicKey(ctx, b.ID, oldKey, bcfg.ConfigRevision); !errors.Is(err, ErrConflict) {
			t.Fatalf("pending old key reassigned by rotation: %v", err)
		}
		issued, err := st.CreateEnrollment(ctx, EnrollmentCreate{Name: "pending-key-reservation", ProfileID: bcfg.ProfileID, TTL: time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		input := domain.EnrollmentClaim{DeviceUUID: "pending-key-reservation", DeviceName: "Key reservation", PublicKey: oldKey}
		if _, err := st.ClaimManagedEnrollment(ctx, issued.Token, input); !errors.Is(err, ErrConflict) {
			t.Fatalf("pending old key reassigned by managed enrollment: %v", err)
		}
		if _, err := st.ClaimEnrollment(ctx, issued.Token, input); !errors.Is(err, ErrConflict) {
			t.Fatalf("pending old key reassigned by legacy enrollment: %v", err)
		}
		if err := st.MarkWireGuardPeerApplied(ctx, acfg.PeerID, rotated.ConfigRevision); err != nil {
			t.Fatal(err)
		}
		if _, err := st.ClaimManagedEnrollment(ctx, issued.Token, input); err != nil {
			t.Fatalf("removed old key could not be enrolled: %v", err)
		}
	})
}

func TestAddressReleaseWaitsForDurableACLRemoval(t *testing.T) {
	forEachDialect(t, func(t *testing.T, st *Store) {
		ctx := context.Background()
		device, token := enrollActiveDevice(t, st)
		cfg, err := st.ManagedConfigForDevice(ctx, device.ID)
		if err != nil {
			t.Fatal(err)
		}
		if err := st.RequireServiceACLAcknowledgement(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := st.BeginDeviceVPNRevocation(ctx, device.ID); err != nil {
			t.Fatal(err)
		}
		pending, err := st.ListPendingWireGuardReconciliations(ctx, 10)
		if err != nil || len(pending) != 1 {
			t.Fatalf("pending=%+v %v", pending, err)
		}
		revision, err := st.ServicePolicyRevision(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := st.RecordServiceACLApplied(ctx, revision-1); err != nil {
			t.Fatal(err)
		}
		if err := st.MarkWireGuardPeerApplied(ctx, cfg.PeerID, pending[0].ConfigRevision); !errors.Is(err, ErrConflict) {
			t.Fatalf("early lease release=%v", err)
		}
		var leases int
		if err := st.db.QueryRowContext(ctx, st.q("SELECT COUNT(*) FROM address_leases WHERE device_id = ? AND status = 'revoking'"), device.ID).Scan(&leases); err != nil || leases != 1 {
			t.Fatalf("lease released before ACL removal: %d %v", leases, err)
		}
		if _, err := st.DevicePrincipalByCredential(ctx, security.HashToken(token)); err != nil {
			t.Fatalf("draining credential invalidated early: %v", err)
		}
		issued, err := st.CreateEnrollment(ctx, EnrollmentCreate{Name: "during-revocation", ProfileID: cfg.ProfileID, TTL: time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		newcomer, err := st.ClaimManagedEnrollment(ctx, issued.Token, domain.EnrollmentClaim{DeviceUUID: "during-revocation", DeviceName: "New device", PublicKey: testWGKey(214)})
		if err != nil {
			t.Fatalf("unrelated enrollment blocked by held lease: %v", err)
		}
		if newcomer.Config.AssignedAddress == cfg.AssignedAddress {
			t.Fatal("revoking address reused before ACL acknowledgement")
		}

		if err := st.RequeueWireGuardReconciliation(ctx); err != nil {
			t.Fatal(err)
		}
		if err := st.CompleteDeviceVPNRevocation(ctx, device.ID, pending[0].ConfigRevision); !errors.Is(err, ErrConflict) {
			t.Fatalf("restart bypassed gate: %v", err)
		}
		revision, err = st.ServicePolicyRevision(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := st.RecordServiceACLApplied(ctx, revision); err != nil {
			t.Fatal(err)
		}
		if err := st.RecordServiceACLApplied(ctx, revision-1); !errors.Is(err, ErrConflict) {
			t.Fatalf("stale ACL ack accepted: %v", err)
		}
		if err := st.RecordServiceACLApplied(ctx, revision+1); !errors.Is(err, ErrConflict) {
			t.Fatalf("future ACL ack accepted: %v", err)
		}
		if err := st.MarkWireGuardPeerApplied(ctx, cfg.PeerID, pending[0].ConfigRevision); err != nil {
			t.Fatal(err)
		}
		if _, err := st.DevicePrincipalByCredential(ctx, security.HashToken(token)); !errors.Is(err, ErrNotFound) {
			t.Fatalf("credential retained after release: %v", err)
		}
	})
}

func TestACLAcknowledgementMigrationPreservesPendingRevocation(t *testing.T) {
	forEachDialect(t, func(t *testing.T, st *Store) {
		ctx := context.Background()
		device, _ := enrollActiveDevice(t, st)
		if _, err := st.BeginDeviceVPNRevocation(ctx, device.ID); err != nil {
			t.Fatal(err)
		}
		for _, statement := range []string{"DROP TABLE service_acl_state", "ALTER TABLE wireguard_peers DROP COLUMN service_revocation_revision", "DELETE FROM schema_migrations WHERE version = 7"} {
			if _, err := st.db.ExecContext(ctx, statement); err != nil {
				t.Fatal(err)
			}
		}
		if err := st.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		if err := st.RequireServiceACLAcknowledgement(ctx); err != nil {
			t.Fatal(err)
		}
		pending, err := st.ListPendingWireGuardReconciliations(ctx, 10)
		if err != nil || len(pending) != 1 {
			t.Fatalf("pending=%+v err=%v", pending, err)
		}
		if err := st.MarkWireGuardPeerApplied(ctx, pending[0].PeerID, pending[0].ConfigRevision); !errors.Is(err, ErrConflict) {
			t.Fatalf("upgraded pending revocation bypassed ACK: %v", err)
		}
		revision, err := st.ServicePolicyRevision(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := st.RecordServiceACLApplied(ctx, revision); err != nil {
			t.Fatal(err)
		}
		if err := st.MarkWireGuardPeerApplied(ctx, pending[0].PeerID, pending[0].ConfigRevision); err != nil {
			t.Fatalf("upgraded revocation stranded: %v", err)
		}
	})
}
