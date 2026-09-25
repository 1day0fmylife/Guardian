package store

import (
	"context"
	"testing"
	"time"

	"github.com/1day0fmylife/Guardian/internal/domain"
)

func TestReleasedAddressIsArchivedAndReusable(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	pool, err := st.CreateAddressPool(ctx, AddressPoolCreate{
		Name: "reuse", CIDR: "10.120.0.0/29", Gateway: "10.120.0.1",
	})
	if err != nil {
		t.Fatalf("CreateAddressPool: %v", err)
	}
	profile, err := st.CreateVPNProfile(ctx, VPNProfileCreate{
		Name: "reuse", ServerPublicKey: testWGKey(31), Endpoint: "vpn.example.test:51820",
		AddressPoolID: pool.ID,
	})
	if err != nil {
		t.Fatalf("CreateVPNProfile: %v", err)
	}

	enroll := func(name, uuid string, key byte) domain.ManagedEnrollmentClaimResult {
		t.Helper()
		issued, err := st.CreateEnrollment(ctx, EnrollmentCreate{Name: name, ProfileID: profile.ID, TTL: time.Minute})
		if err != nil {
			t.Fatalf("CreateEnrollment(%s): %v", name, err)
		}
		claim, err := st.ClaimManagedEnrollment(ctx, issued.Token, domain.EnrollmentClaim{
			DeviceUUID: uuid, DeviceName: name, PublicKey: testWGKey(key),
		})
		if err != nil {
			t.Fatalf("ClaimManagedEnrollment(%s): %v", name, err)
		}
		return claim
	}

	first := enroll("phone-a", "reuse-device-a", 32)
	if first.Config.AssignedAddress != "10.120.0.2/32" {
		t.Fatalf("first address = %q", first.Config.AssignedAddress)
	}
	if _, err := st.BeginDeviceVPNRevocation(ctx, first.Device.ID); err != nil {
		t.Fatalf("BeginDeviceVPNRevocation: %v", err)
	}
	if err := st.CompleteDeviceVPNRevocation(ctx, first.Device.ID, 2); err != nil {
		t.Fatalf("CompleteDeviceVPNRevocation: %v", err)
	}

	var activeCount int
	if err := st.DB().QueryRowContext(ctx, sQuery(st, "SELECT COUNT(*) FROM address_leases WHERE device_id = ?"), first.Device.ID).Scan(&activeCount); err != nil {
		t.Fatalf("count active leases: %v", err)
	}
	if activeCount != 0 {
		t.Fatalf("current lease rows = %d, want 0", activeCount)
	}
	var archivedAddress, reason string
	if err := st.DB().QueryRowContext(ctx, sQuery(st, `
		SELECT address, release_reason FROM address_lease_history WHERE device_id = ?
	`), first.Device.ID).Scan(&archivedAddress, &reason); err != nil {
		t.Fatalf("load lease history: %v", err)
	}
	if archivedAddress != "10.120.0.2" || reason != "vpn_revoked" {
		t.Fatalf("archived lease = %q/%q", archivedAddress, reason)
	}

	second := enroll("phone-b", "reuse-device-b", 33)
	if second.Config.AssignedAddress != "10.120.0.2/32" {
		t.Fatalf("reused address = %q, want 10.120.0.2/32", second.Config.AssignedAddress)
	}
}
