package store

import (
	"context"
	"testing"
	"time"

	"github.com/1day0fmylife/Guardian/internal/domain"
)

func TestWireGuardRotationRetainsPreviousKeyUntilReconciled(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	pool, err := st.CreateAddressPool(ctx, AddressPoolCreate{Name: "rotation-state", CIDR: "10.121.0.0/29", Gateway: "10.121.0.1"})
	if err != nil {
		t.Fatalf("CreateAddressPool: %v", err)
	}
	profile, err := st.CreateVPNProfile(ctx, VPNProfileCreate{
		Name: "rotation-state", ServerPublicKey: testWGKey(41), Endpoint: "vpn.example.test:51820", AddressPoolID: pool.ID,
	})
	if err != nil {
		t.Fatalf("CreateVPNProfile: %v", err)
	}
	issued, err := st.CreateEnrollment(ctx, EnrollmentCreate{Name: "rotation-state", ProfileID: profile.ID, TTL: time.Minute})
	if err != nil {
		t.Fatalf("CreateEnrollment: %v", err)
	}
	oldKey := testWGKey(42)
	claim, err := st.ClaimManagedEnrollment(ctx, issued.Token, domain.EnrollmentClaim{
		DeviceUUID: "rotation-state-device", DeviceName: "Rotation State", PublicKey: oldKey,
	})
	if err != nil {
		t.Fatalf("ClaimManagedEnrollment: %v", err)
	}
	pending, err := st.ListPendingWireGuardReconciliations(ctx, 10)
	if err != nil || len(pending) != 1 {
		t.Fatalf("initial pending=%+v err=%v", pending, err)
	}
	if err := st.MarkWireGuardPeerApplied(ctx, pending[0].PeerID, 1); err != nil {
		t.Fatalf("apply initial peer: %v", err)
	}

	newKey := testWGKey(43)
	if _, err := st.RotateDeviceWireGuardPublicKey(ctx, claim.Device.ID, newKey, 1); err != nil {
		t.Fatalf("RotateDeviceWireGuardPublicKey: %v", err)
	}
	pending, err = st.ListPendingWireGuardReconciliations(ctx, 10)
	if err != nil || len(pending) != 1 {
		t.Fatalf("rotation pending=%+v err=%v", pending, err)
	}
	item := pending[0]
	if item.PublicKey != newKey || item.PreviousPublicKey != oldKey || item.ConfigRevision != 2 {
		t.Fatalf("rotation item = %+v", item)
	}
	if err := st.MarkWireGuardPeerReconcileError(ctx, item.PeerID, 2, "retry"); err != nil {
		t.Fatalf("mark rotation error: %v", err)
	}
	pending, err = st.ListPendingWireGuardReconciliations(ctx, 10)
	if err != nil || len(pending) != 1 || pending[0].PreviousPublicKey != oldKey {
		t.Fatalf("retry lost previous key: pending=%+v err=%v", pending, err)
	}
	if err := st.MarkWireGuardPeerApplied(ctx, item.PeerID, 2); err != nil {
		t.Fatalf("apply rotation: %v", err)
	}
	var previous string
	if err := st.DB().QueryRowContext(ctx, sQuery(st, "SELECT previous_public_key FROM wireguard_peers WHERE id = ?"), item.PeerID).Scan(&previous); err != nil {
		t.Fatalf("read previous key: %v", err)
	}
	if previous != "" {
		t.Fatalf("previous public key after reconcile = %q, want empty", previous)
	}
}
