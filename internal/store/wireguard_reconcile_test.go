package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/1day0fmylife/Guardian/internal/domain"
	"github.com/1day0fmylife/Guardian/internal/security"
)

func TestWireGuardReconcileStoreLifecycle(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	pool, err := st.CreateAddressPool(ctx, AddressPoolCreate{Name: "reconcile", CIDR: "10.99.0.0/29", Gateway: "10.99.0.1"})
	if err != nil {
		t.Fatalf("CreateAddressPool: %v", err)
	}
	profile, err := st.CreateVPNProfile(ctx, VPNProfileCreate{
		Name: "reconcile", ServerPublicKey: testWGKey(21), Endpoint: "vpn.example.test:51820",
		AllowedIPs: []string{"10.0.0.0/8"}, AddressPoolID: pool.ID,
	})
	if err != nil {
		t.Fatalf("CreateVPNProfile: %v", err)
	}
	issued, err := st.CreateEnrollment(ctx, EnrollmentCreate{Name: "reconcile", ProfileID: profile.ID, TTL: time.Minute})
	if err != nil {
		t.Fatalf("CreateEnrollment: %v", err)
	}
	claim, err := st.ClaimManagedEnrollment(ctx, issued.Token, domain.EnrollmentClaim{
		DeviceUUID: "reconcile-device", DeviceName: "Reconcile Phone", PublicKey: testWGKey(22),
	})
	if err != nil {
		t.Fatalf("ClaimManagedEnrollment: %v", err)
	}

	pending, err := st.ListPendingWireGuardReconciliations(ctx, 10)
	if err != nil {
		t.Fatalf("ListPendingWireGuardReconciliations: %v", err)
	}
	if len(pending) != 1 || pending[0].ConfigRevision != 1 || pending[0].DesiredState != "connected" {
		t.Fatalf("initial pending = %+v", pending)
	}
	peerID := pending[0].PeerID
	if err := st.MarkWireGuardPeerApplied(ctx, peerID, 2); !errors.Is(err, ErrConflict) {
		t.Fatalf("future revision apply error = %v, want ErrConflict", err)
	}
	if err := st.MarkWireGuardPeerApplied(ctx, peerID, 1); err != nil {
		t.Fatalf("MarkWireGuardPeerApplied initial: %v", err)
	}

	rotated, err := st.RotateDeviceWireGuardPublicKey(ctx, claim.Device.ID, testWGKey(23), 1)
	if err != nil {
		t.Fatalf("RotateDeviceWireGuardPublicKey: %v", err)
	}
	if rotated.ConfigRevision != 2 {
		t.Fatalf("rotation revision = %d", rotated.ConfigRevision)
	}
	if err := st.MarkWireGuardPeerReconcileError(ctx, peerID, 2, "temporary provider failure"); err != nil {
		t.Fatalf("MarkWireGuardPeerReconcileError: %v", err)
	}
	pending, err = st.ListPendingWireGuardReconciliations(ctx, 10)
	if err != nil || len(pending) != 1 || pending[0].ReconcileState != "error" {
		t.Fatalf("error retry pending=%+v err=%v", pending, err)
	}
	if err := st.MarkWireGuardPeerApplied(ctx, peerID, 2); err != nil {
		t.Fatalf("MarkWireGuardPeerApplied rotation: %v", err)
	}

	if _, err := st.SuspendDeviceVPNAndQueueDisconnect(ctx, claim.Device.ID); err != nil {
		t.Fatalf("SuspendDeviceVPNAndQueueDisconnect: %v", err)
	}
	pending, _ = st.ListPendingWireGuardReconciliations(ctx, 10)
	if len(pending) != 1 || pending[0].ConfigRevision != 3 || pending[0].DesiredState != "disconnected" {
		t.Fatalf("suspend pending = %+v", pending)
	}
	if err := st.MarkWireGuardPeerApplied(ctx, peerID, 3); err != nil {
		t.Fatalf("apply suspension: %v", err)
	}

	if _, err := st.ResumeDeviceVPNAndQueueConnect(ctx, claim.Device.ID); err != nil {
		t.Fatalf("ResumeDeviceVPNAndQueueConnect: %v", err)
	}
	pending, _ = st.ListPendingWireGuardReconciliations(ctx, 10)
	if len(pending) != 1 || pending[0].ConfigRevision != 4 || pending[0].DesiredState != "connected" {
		t.Fatalf("resume pending = %+v", pending)
	}
	if err := st.MarkWireGuardPeerApplied(ctx, peerID, 4); err != nil {
		t.Fatalf("apply resume: %v", err)
	}

	if _, err := st.BeginDeviceVPNRevocation(ctx, claim.Device.ID); err != nil {
		t.Fatalf("BeginDeviceVPNRevocation: %v", err)
	}
	pending, _ = st.ListPendingWireGuardReconciliations(ctx, 10)
	if len(pending) != 1 || pending[0].ConfigRevision != 5 || pending[0].DesiredState != "revoked" {
		t.Fatalf("revoke pending = %+v", pending)
	}
	if err := st.MarkWireGuardPeerApplied(ctx, peerID, 5); err != nil {
		t.Fatalf("apply revoke: %v", err)
	}
	if _, err := st.DevicePrincipalByCredential(ctx, security.HashToken(claim.Credential.Token)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("credential after reconcile revoke error = %v", err)
	}
	pending, err = st.ListPendingWireGuardReconciliations(ctx, 10)
	if err != nil || len(pending) != 0 {
		t.Fatalf("pending after finalized revoke = %+v err=%v", pending, err)
	}
}
