package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/1day0fmylife/Guardian/internal/domain"
	"github.com/1day0fmylife/Guardian/internal/security"
)

func enrollCredentialRotationDevice(t *testing.T, st *Store, suffix string) (domain.ManagedEnrollmentClaimResult, string, domain.DevicePrincipal) {
	t.Helper()
	ctx := context.Background()

	pool, err := st.CreateAddressPool(ctx, AddressPoolCreate{
		Name: "credential-rotation-pool-" + suffix,
		CIDR: "10.92.0.0/29",
		Gateway: "10.92.0.1",
	})
	if err != nil {
		t.Fatalf("CreateAddressPool: %v", err)
	}
	profile, err := st.CreateVPNProfile(ctx, VPNProfileCreate{
		Name: "credential-rotation-profile-" + suffix,
		ServerPublicKey: testWGKey(41),
		Endpoint: "vpn.example.test:51820",
		AllowedIPs: []string{"10.0.0.0/8"},
		PersistentKeepalive: 25,
		AddressPoolID: pool.ID,
	})
	if err != nil {
		t.Fatalf("CreateVPNProfile: %v", err)
	}
	enrollment, err := st.CreateEnrollment(ctx, EnrollmentCreate{
		Name: "credential-rotation-enrollment-" + suffix,
		ProfileID: profile.ID,
		BoundDeviceUUID: "credential-rotation-device-" + suffix,
		TTL: 15 * time.Minute,
	})
	if err != nil {
		t.Fatalf("CreateEnrollment: %v", err)
	}

	oldSecret := "gdn_d_old-device-owned-secret-" + suffix
	claim, err := st.ClaimManagedEnrollment(ctx, enrollment.Token, domain.EnrollmentClaim{
		DeviceUUID: "credential-rotation-device-" + suffix,
		DeviceName: "ArlanPhone Credential Rotation",
		PublicKey: testWGKey(42),
		DeviceCredentialHash: security.HashToken(oldSecret),
	})
	if err != nil {
		t.Fatalf("ClaimManagedEnrollment: %v", err)
	}
	principal, err := st.DevicePrincipalByCredential(ctx, security.HashToken(oldSecret))
	if err != nil {
		t.Fatalf("DevicePrincipalByCredential(old): %v", err)
	}
	return claim, oldSecret, principal
}

func TestRotateDeviceCredentialHashAtomicallyCutsOver(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	claim, oldSecret, oldPrincipal := enrollCredentialRotationDevice(t, st, "success")

	newSecret := "gdn_d_new-device-owned-secret-success"
	credential, err := st.RotateDeviceCredentialHash(ctx, oldPrincipal, security.HashToken(newSecret))
	if err != nil {
		t.Fatalf("RotateDeviceCredentialHash: %v", err)
	}
	if credential.ID == "" || credential.DeviceID != claim.Device.ID {
		t.Fatalf("rotated credential = %+v", credential)
	}

	if _, err := st.DevicePrincipalByCredential(ctx, security.HashToken(oldSecret)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old credential auth error = %v, want ErrNotFound", err)
	}
	newPrincipal, err := st.DevicePrincipalByCredential(ctx, security.HashToken(newSecret))
	if err != nil {
		t.Fatalf("new credential authentication: %v", err)
	}
	if newPrincipal.CredentialID != credential.ID || newPrincipal.DeviceID != claim.Device.ID {
		t.Fatalf("new principal = %+v, credential = %+v", newPrincipal, credential)
	}

	// A stale concurrent request authenticated with the old credential cannot
	// revoke or replace the credential that already won the cutover.
	if _, err := st.RotateDeviceCredentialHash(ctx, oldPrincipal, security.HashToken("gdn_d_stale-replacement")); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale rotation error = %v, want ErrConflict", err)
	}
	if _, err := st.DevicePrincipalByCredential(ctx, security.HashToken(newSecret)); err != nil {
		t.Fatalf("winning credential stopped working after stale rotation: %v", err)
	}
}

func TestRotateDeviceCredentialHashInvalidInputRollsBack(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	_, oldSecret, principal := enrollCredentialRotationDevice(t, st, "invalid")

	if _, err := st.RotateDeviceCredentialHash(ctx, principal, "not-a-sha256-digest"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid rotation error = %v, want ErrInvalid", err)
	}
	if _, err := st.DevicePrincipalByCredential(ctx, security.HashToken(oldSecret)); err != nil {
		t.Fatalf("old credential was lost after rejected rotation: %v", err)
	}
}
