package store

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/1day0fmylife/Guardian/internal/domain"
	"github.com/1day0fmylife/Guardian/internal/rbac"
	"github.com/1day0fmylife/Guardian/internal/security"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	ctx := context.Background()
	st, err := Open(ctx, "sqlite://:memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if err := st.SeedRBAC(ctx); err != nil {
		t.Fatalf("SeedRBAC: %v", err)
	}
	return st
}

func testWGKey(fill byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{fill}, 32))
}

func TestBootstrapCreatesSuperadminPrincipal(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	passwordHash, err := security.HashPassword("a sufficiently long admin password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	user, err := st.CreateBootstrapUser(ctx, "Admin", "Administrator", passwordHash)
	if err != nil {
		t.Fatalf("CreateBootstrapUser: %v", err)
	}
	if user.Username != "admin" {
		t.Fatalf("username normalization = %q", user.Username)
	}

	token := "session-test-token"
	if _, err := st.CreateSession(ctx, user.ID, security.HashToken(token), time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	principal, err := st.PrincipalBySession(ctx, security.HashToken(token), time.Now())
	if err != nil {
		t.Fatalf("PrincipalBySession: %v", err)
	}
	if !rbac.HasPermission(principal.Permissions, rbac.DevicesCreate) {
		t.Fatal("bootstrap superadmin missing devices.create")
	}

	if _, err := st.CreateBootstrapUser(ctx, "second", "Second", passwordHash); !errors.Is(err, ErrConflict) {
		t.Fatalf("second bootstrap error = %v, want ErrConflict", err)
	}
}

func TestEnrollmentIsSingleUseAndAllocatesUniqueAddresses(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	pool, err := st.CreateAddressPool(ctx, AddressPoolCreate{
		Name:       "phones",
		CIDR:       "10.77.0.0/29",
		Gateway:    "10.77.0.1",
		DNSServers: []string{"10.77.0.1"},
	})
	if err != nil {
		t.Fatalf("CreateAddressPool: %v", err)
	}
	profile, err := st.CreateVPNProfile(ctx, VPNProfileCreate{
		Name:                "hq",
		ServerPublicKey:     testWGKey(1),
		Endpoint:            "vpn.example.test:51820",
		AllowedIPs:          []string{"10.0.0.0/8"},
		DNSServers:          []string{"10.77.0.1"},
		PersistentKeepalive: 25,
		AddressPoolID:       pool.ID,
	})
	if err != nil {
		t.Fatalf("CreateVPNProfile: %v", err)
	}

	first, err := st.CreateEnrollment(ctx, EnrollmentCreate{
		Name:            "phone-1",
		ProfileID:       profile.ID,
		BoundDeviceUUID: "device-1",
		TTL:             15 * time.Minute,
	})
	if err != nil {
		t.Fatalf("CreateEnrollment: %v", err)
	}

	var storedHash string
	if err := st.DB().QueryRowContext(ctx, sQuery(st, "SELECT token_hash FROM enrollment_tokens WHERE id = ?"), first.Enrollment.ID).Scan(&storedHash); err != nil {
		t.Fatalf("read token hash: %v", err)
	}
	if storedHash == first.Token {
		t.Fatal("enrollment token was stored in plaintext")
	}
	if storedHash != security.HashToken(first.Token) {
		t.Fatal("stored enrollment hash does not match token hash")
	}

	result1, err := st.ClaimEnrollment(ctx, first.Token, domain.EnrollmentClaim{
		DeviceUUID: "device-1",
		DeviceName: "ArlanPhone 1",
		PublicKey:  testWGKey(2),
	})
	if err != nil {
		t.Fatalf("ClaimEnrollment first: %v", err)
	}
	if got, want := result1.Config.AssignedAddress, "10.77.0.2/32"; got != want {
		t.Fatalf("first address = %q, want %q", got, want)
	}

	if _, err := st.ClaimEnrollment(ctx, first.Token, domain.EnrollmentClaim{
		DeviceUUID: "device-1",
		DeviceName: "ArlanPhone 1",
		PublicKey:  testWGKey(2),
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("reused enrollment error = %v, want ErrConflict", err)
	}

	second, err := st.CreateEnrollment(ctx, EnrollmentCreate{
		Name:            "phone-2",
		ProfileID:       profile.ID,
		BoundDeviceUUID: "device-2",
		TTL:             15 * time.Minute,
	})
	if err != nil {
		t.Fatalf("CreateEnrollment second: %v", err)
	}
	result2, err := st.ClaimEnrollment(ctx, second.Token, domain.EnrollmentClaim{
		DeviceUUID: "device-2",
		DeviceName: "ArlanPhone 2",
		PublicKey:  testWGKey(3),
	})
	if err != nil {
		t.Fatalf("ClaimEnrollment second: %v", err)
	}
	if got, want := result2.Config.AssignedAddress, "10.77.0.3/32"; got != want {
		t.Fatalf("second address = %q, want %q", got, want)
	}
}

func sQuery(st *Store, query string) string {
	return st.q(query)
}
