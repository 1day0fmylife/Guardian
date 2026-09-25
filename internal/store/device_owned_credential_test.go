package store

import (
	"context"
	"testing"
	"time"

	"github.com/1day0fmylife/Guardian/internal/domain"
	"github.com/1day0fmylife/Guardian/internal/security"
)

func TestManagedEnrollmentAcceptsDeviceCredentialHashAndRotationRetry(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	pool, err := st.CreateAddressPool(ctx, AddressPoolCreate{
		Name: "device-owned-credential", CIDR: "10.91.0.0/29", Gateway: "10.91.0.1",
	})
	if err != nil {
		t.Fatalf("CreateAddressPool: %v", err)
	}
	profile, err := st.CreateVPNProfile(ctx, VPNProfileCreate{
		Name: "device-owned-profile", ServerPublicKey: testWGKey(31), Endpoint: "vpn.example.test:51820",
		AllowedIPs: []string{"10.0.0.0/8"}, PersistentKeepalive: 25, AddressPoolID: pool.ID,
	})
	if err != nil {
		t.Fatalf("CreateVPNProfile: %v", err)
	}
	issued, err := st.CreateEnrollment(ctx, EnrollmentCreate{
		Name: "device-owned-enrollment", ProfileID: profile.ID,
		BoundDeviceUUID: "managed-device-hash-1", TTL: 15 * time.Minute,
	})
	if err != nil {
		t.Fatalf("CreateEnrollment: %v", err)
	}

	deviceCredential := "gdn_d_device-generated-secret-that-is-persisted-before-enrollment"
	credentialHash := security.HashToken(deviceCredential)
	claim, err := st.ClaimManagedEnrollment(ctx, issued.Token, domain.EnrollmentClaim{
		DeviceUUID: "managed-device-hash-1", DeviceName: "ArlanPhone Hash Credential",
		PublicKey: testWGKey(32), DeviceCredentialHash: credentialHash,
	})
	if err != nil {
		t.Fatalf("ClaimManagedEnrollment: %v", err)
	}
	if claim.Credential.Token != "" {
		t.Fatal("Guardian must not echo a device-generated plaintext credential")
	}
	if claim.Credential.Credential.ID == "" {
		t.Fatal("credential metadata is missing")
	}

	principal, err := st.DevicePrincipalByCredential(ctx, security.HashToken(deviceCredential))
	if err != nil {
		t.Fatalf("DevicePrincipalByCredential: %v", err)
	}
	if principal.DeviceID != claim.Device.ID {
		t.Fatalf("principal device = %q, want %q", principal.DeviceID, claim.Device.ID)
	}

	rotatedKey := testWGKey(33)
	rotated, err := st.RotateDeviceWireGuardPublicKey(ctx, claim.Device.ID, rotatedKey, 1)
	if err != nil {
		t.Fatalf("RotateDeviceWireGuardPublicKey: %v", err)
	}
	if rotated.ConfigRevision != 2 {
		t.Fatalf("rotated revision = %d, want 2", rotated.ConfigRevision)
	}

	// Simulate a lost HTTP response: the device retries the exact same public
	// key with the revision it originally used. Guardian returns the committed
	// configuration instead of creating another revision or rejecting recovery.
	retried, err := st.RotateDeviceWireGuardPublicKey(ctx, claim.Device.ID, rotatedKey, 1)
	if err != nil {
		t.Fatalf("idempotent rotation retry: %v", err)
	}
	if retried.ConfigRevision != 2 {
		t.Fatalf("retried revision = %d, want 2", retried.ConfigRevision)
	}
}
