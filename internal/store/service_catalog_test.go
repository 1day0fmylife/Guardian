package store

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/1day0fmylife/Guardian/internal/domain"
)

// postgresTestURLEnv enables the PostgreSQL leg of the dialect matrix. When it
// is unset the PostgreSQL subtests are skipped and only SQLite runs.
const postgresTestURLEnv = "GUARDIAN_TEST_POSTGRES_URL"

var schemaCounter atomic.Int64

func newPostgresTestStore(t *testing.T) *Store {
	t.Helper()
	base := os.Getenv(postgresTestURLEnv)
	if base == "" {
		t.Skipf("%s is not set", postgresTestURLEnv)
	}
	ctx := context.Background()
	admin, err := Open(ctx, base)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	schema := fmt.Sprintf("g01_%d_%d", time.Now().UnixNano(), schemaCounter.Add(1))
	if _, err := admin.db.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.db.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		_ = admin.Close()
	})

	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parse postgres url: %v", err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	st, err := Open(ctx, u.String())
	if err != nil {
		t.Fatalf("open postgres schema: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate postgres: %v", err)
	}
	if err := st.SeedRBAC(ctx); err != nil {
		t.Fatalf("seed postgres rbac: %v", err)
	}
	return st
}

// forEachDialect runs fn against SQLite and, when configured, PostgreSQL.
func forEachDialect(t *testing.T, fn func(t *testing.T, st *Store)) {
	t.Helper()
	t.Run("sqlite", func(t *testing.T) { fn(t, newTestStore(t)) })
	t.Run("postgres", func(t *testing.T) { fn(t, newPostgresTestStore(t)) })
}

var deviceCounter atomic.Int64

// enrollActiveDevice creates an active managed device through the real
// enrollment flow and returns it with its plaintext credential.
func enrollActiveDevice(t *testing.T, st *Store) (domain.Device, string) {
	t.Helper()
	ctx := context.Background()
	n := int(deviceCounter.Add(1))
	pool, err := st.CreateAddressPool(ctx, AddressPoolCreate{
		Name: fmt.Sprintf("g01-pool-%d", n), CIDR: fmt.Sprintf("10.%d.0.0/29", 100+n%100), Gateway: fmt.Sprintf("10.%d.0.1", 100+n%100),
	})
	if err != nil {
		t.Fatalf("CreateAddressPool: %v", err)
	}
	profile, err := st.CreateVPNProfile(ctx, VPNProfileCreate{
		Name: fmt.Sprintf("g01-profile-%d", n), ServerPublicKey: testWGKey(byte(n)), Endpoint: "vpn.example.test:51820",
		AllowedIPs: []string{"10.0.0.0/8"}, PersistentKeepalive: 25, AddressPoolID: pool.ID,
	})
	if err != nil {
		t.Fatalf("CreateVPNProfile: %v", err)
	}
	uuid := fmt.Sprintf("g01-device-%d-%d", time.Now().UnixNano(), n)
	issued, err := st.CreateEnrollment(ctx, EnrollmentCreate{
		Name: "g01", ProfileID: profile.ID, BoundDeviceUUID: uuid, TTL: 15 * time.Minute,
	})
	if err != nil {
		t.Fatalf("CreateEnrollment: %v", err)
	}
	claim, err := st.ClaimManagedEnrollment(ctx, issued.Token, domain.EnrollmentClaim{
		DeviceUUID: uuid, DeviceName: "G01 device", PublicKey: testWGKey(byte(100 + n%100)),
	})
	if err != nil {
		t.Fatalf("ClaimManagedEnrollment: %v", err)
	}
	return claim.Device, claim.Credential.Token
}

func testActor(t *testing.T, st *Store) AuditMeta {
	t.Helper()
	user, err := st.CreateBootstrapUser(context.Background(), "g01-admin", "G01 Admin", "hash")
	if err != nil {
		t.Fatalf("CreateBootstrapUser: %v", err)
	}
	return AuditMeta{ActorUserID: user.ID, SourceIP: "192.0.2.10", RequestID: "req-g01"}
}

func davInput(enabled bool) domain.ServiceDefinitionInput {
	return domain.ServiceDefinitionInput{
		DisplayName: "SunkarDAV", InternalDNSName: "dav.internal", Protocol: "https", Port: 443,
		TLSPolicy: "required", AllowedScopes: []string{"tenant", "site", "group", "device"}, Enabled: enabled,
	}
}

func serviceIDs(policy domain.DeviceServicePolicy) []string {
	ids := []string{}
	for _, svc := range policy.Services {
		ids = append(ids, svc.ID)
	}
	return ids
}

func countAudit(t *testing.T, st *Store, action, resourceID string) (count int, actor string) {
	t.Helper()
	rows, err := st.db.Query(st.q("SELECT COALESCE(actor_user_id, '') FROM audit_events WHERE action = ? AND resource_id = ?"), action, resourceID)
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		if err := rows.Scan(&actor); err != nil {
			t.Fatalf("scan audit: %v", err)
		}
		count++
	}
	return count, actor
}

func TestServiceCatalogSeededDisabledAndDenyByDefault(t *testing.T) {
	forEachDialect(t, func(t *testing.T, st *Store) {
		ctx := context.Background()
		items, total, err := st.ListServiceDefinitions(ctx, ServiceDefinitionFilter{}, 50, 0)
		if err != nil {
			t.Fatalf("ListServiceDefinitions: %v", err)
		}
		if total != 3 || len(items) != 3 {
			t.Fatalf("catalog size = %d/%d, want 3", len(items), total)
		}
		got := []string{}
		for _, item := range items {
			got = append(got, item.ID)
			if item.Enabled {
				t.Errorf("service %s is enabled by default", item.ID)
			}
			if item.Revision != 1 || item.TLSPolicy != "required" || item.Port != 443 {
				t.Errorf("unexpected seed for %s: %+v", item.ID, item)
			}
		}
		if strings.Join(got, ",") != "admiral-device,sunkarcwmp-acs,sunkardav" {
			t.Fatalf("catalog ids = %v", got)
		}

		device, _ := enrollActiveDevice(t, st)
		policy, err := st.DeviceServicePolicy(ctx, device.ID)
		if err != nil {
			t.Fatalf("DeviceServicePolicy: %v", err)
		}
		if policy.AccessState != domain.AccessStateActive || len(policy.Services) != 0 {
			t.Fatalf("fresh device policy = %+v, want active with no services", policy)
		}
	})
}

func TestServiceDefinitionVersioningAndIdempotency(t *testing.T) {
	forEachDialect(t, func(t *testing.T, st *Store) {
		ctx := context.Background()
		meta := testActor(t, st)

		if _, err := st.UpdateServiceDefinition(ctx, meta, "sunkardav", 0, davInput(true)); !errors.Is(err, ErrInvalid) {
			t.Fatalf("missing expected_revision error = %v, want ErrInvalid", err)
		}
		bad := davInput(true)
		bad.InternalDNSName = "https://evil.example/path"
		if _, err := st.UpdateServiceDefinition(ctx, meta, "sunkardav", 1, bad); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid definition error = %v, want ErrInvalid", err)
		}
		if _, err := st.UpdateServiceDefinition(ctx, meta, "unknown-service", 1, davInput(true)); !errors.Is(err, ErrNotFound) {
			t.Fatalf("unknown service error = %v, want ErrNotFound", err)
		}

		first, err := st.UpdateServiceDefinition(ctx, meta, "sunkardav", 1, davInput(true))
		if err != nil {
			t.Fatalf("UpdateServiceDefinition: %v", err)
		}
		if !first.Changed || first.Definition.Revision != 2 || !first.Definition.Enabled {
			t.Fatalf("first update = %+v", first)
		}
		if first.Definition.UpdatedByUserID != meta.ActorUserID {
			t.Fatalf("updated_by = %q, want actor %q", first.Definition.UpdatedByUserID, meta.ActorUserID)
		}

		// A retry of the same request after a lost response is a no-op.
		retry, err := st.UpdateServiceDefinition(ctx, meta, "sunkardav", 1, davInput(true))
		if err != nil {
			t.Fatalf("retry: %v", err)
		}
		if retry.Changed || retry.Definition.Revision != 2 || retry.PolicyRevision != first.PolicyRevision {
			t.Fatalf("retry = %+v, want unchanged revision 2", retry)
		}

		// A stale writer with different content is rejected.
		stale := davInput(true)
		stale.Port = 8443
		if _, err := st.UpdateServiceDefinition(ctx, meta, "sunkardav", 1, stale); !errors.Is(err, ErrConflict) {
			t.Fatalf("stale update error = %v, want ErrConflict", err)
		}
		var catalogErr *ServiceCatalogError
		if _, err := st.UpdateServiceDefinition(ctx, meta, "sunkardav", 1, stale); !errors.As(err, &catalogErr) || catalogErr.Code != "service_revision_conflict" {
			t.Fatalf("conflict code = %v", err)
		}

		second, err := st.UpdateServiceDefinition(ctx, meta, "sunkardav", 2, stale)
		if err != nil {
			t.Fatalf("second update: %v", err)
		}
		if second.Definition.Revision != 3 || second.Definition.Port != 8443 || second.PolicyRevision <= first.PolicyRevision {
			t.Fatalf("second update = %+v", second)
		}

		revisions, total, err := st.ListServiceDefinitionRevisions(ctx, "sunkardav", 10, 0)
		if err != nil {
			t.Fatalf("ListServiceDefinitionRevisions: %v", err)
		}
		if total != 3 || revisions[0].Revision != 3 || revisions[2].Revision != 1 || revisions[2].Enabled {
			t.Fatalf("revision history = %+v", revisions)
		}

		if n, actor := countAudit(t, st, "service.update", "sunkardav"); n != 2 || actor != meta.ActorUserID {
			t.Fatalf("service.update audit rows = %d actor=%q, want 2 by actor", n, actor)
		}
	})
}

func TestDevicesWithDifferentGrantsReceiveDistinctPolicy(t *testing.T) {
	forEachDialect(t, func(t *testing.T, st *Store) {
		ctx := context.Background()
		meta := testActor(t, st)
		deviceA, _ := enrollActiveDevice(t, st)
		deviceB, _ := enrollActiveDevice(t, st)

		for _, id := range []string{"sunkardav", "sunkarcwmp-acs"} {
			def, _ := st.GetServiceDefinition(ctx, id)
			in := davInput(true)
			in.DisplayName, in.InternalDNSName = def.DisplayName, def.InternalDNSName
			if _, err := st.UpdateServiceDefinition(ctx, meta, id, def.Revision, in); err != nil {
				t.Fatalf("enable %s: %v", id, err)
			}
		}

		// Device A: DAV by device grant. Device B: ACS by group membership.
		if _, err := st.SetServiceGrant(ctx, meta, "sunkardav", "device", deviceA.ID, "allow"); err != nil {
			t.Fatalf("grant A: %v", err)
		}
		if _, err := st.SetDeviceScopes(ctx, meta, deviceB.ID, domain.DeviceScopes{GroupIDs: []string{"field-phones"}}); err != nil {
			t.Fatalf("scopes B: %v", err)
		}
		if _, err := st.SetServiceGrant(ctx, meta, "sunkarcwmp-acs", "group", "field-phones", "allow"); err != nil {
			t.Fatalf("grant group: %v", err)
		}

		policyA, err := st.DeviceServicePolicy(ctx, deviceA.ID)
		if err != nil {
			t.Fatalf("policy A: %v", err)
		}
		policyB, err := st.DeviceServicePolicy(ctx, deviceB.ID)
		if err != nil {
			t.Fatalf("policy B: %v", err)
		}
		if got := strings.Join(serviceIDs(policyA), ","); got != "sunkardav" {
			t.Fatalf("device A services = %q, want sunkardav", got)
		}
		if got := strings.Join(serviceIDs(policyB), ","); got != "sunkarcwmp-acs" {
			t.Fatalf("device B services = %q, want sunkarcwmp-acs", got)
		}
		if policyA.Services[0].Host != "dav.internal" || policyA.Services[0].Port != 443 {
			t.Fatalf("endpoint = %+v", policyA.Services[0])
		}
		// admiral-device was never granted to anyone.
		for _, p := range []domain.DeviceServicePolicy{policyA, policyB} {
			for _, svc := range p.Services {
				if svc.ID == "admiral-device" {
					t.Fatalf("ungranted service leaked into policy: %+v", p)
				}
			}
		}
	})
}

func TestDeviceOverrideAndGrantRevocation(t *testing.T) {
	forEachDialect(t, func(t *testing.T, st *Store) {
		ctx := context.Background()
		meta := testActor(t, st)
		device, _ := enrollActiveDevice(t, st)
		def, _ := st.GetServiceDefinition(ctx, "sunkardav")
		if _, err := st.UpdateServiceDefinition(ctx, meta, "sunkardav", def.Revision, davInput(true)); err != nil {
			t.Fatalf("enable: %v", err)
		}
		if _, err := st.SetDeviceScopes(ctx, meta, device.ID, domain.DeviceScopes{TenantID: "acme", SiteID: "almaty"}); err != nil {
			t.Fatalf("scopes: %v", err)
		}
		tenantGrant, err := st.SetServiceGrant(ctx, meta, "sunkardav", "tenant", "acme", "allow")
		if err != nil {
			t.Fatalf("tenant grant: %v", err)
		}
		allowed := func() bool {
			p, err := st.DeviceServicePolicy(ctx, device.ID)
			if err != nil {
				t.Fatalf("policy: %v", err)
			}
			return len(p.Services) == 1
		}
		if !allowed() {
			t.Fatal("tenant allow did not reach the device")
		}

		// Explicit device-level deny overrides the tenant allow.
		denyGrant, err := st.SetServiceGrant(ctx, meta, "sunkardav", "device", device.ID, "deny")
		if err != nil {
			t.Fatalf("device deny: %v", err)
		}
		if allowed() {
			t.Fatal("device deny did not override tenant allow")
		}
		admin, err := st.AdminDevicePolicy(ctx, device.ID)
		if err != nil {
			t.Fatalf("AdminDevicePolicy: %v", err)
		}
		var dav domain.AdminServiceDecision
		for _, svc := range admin.Services {
			if svc.ServiceID == "sunkardav" {
				dav = svc
			}
		}
		if dav.Allowed || dav.Reason != "device_deny" || dav.SourceGrantID != denyGrant.Grant.ID {
			t.Fatalf("admin decision = %+v", dav)
		}

		// Revoking the override restores the tenant-level allow; revoking
		// the tenant grant then removes access entirely.
		if _, err := st.RevokeServiceGrant(ctx, meta, "sunkardav", denyGrant.Grant.ID); err != nil {
			t.Fatalf("revoke deny: %v", err)
		}
		if !allowed() {
			t.Fatal("tenant allow not restored after override revoked")
		}
		revoked, err := st.RevokeServiceGrant(ctx, meta, "sunkardav", tenantGrant.Grant.ID)
		if err != nil {
			t.Fatalf("revoke tenant: %v", err)
		}
		if !revoked.Changed || revoked.Grant.RevokedAt == "" || revoked.Grant.RevokedByUserID != meta.ActorUserID {
			t.Fatalf("revoked grant = %+v", revoked)
		}
		if allowed() {
			t.Fatal("access survived grant revocation")
		}

		// Revoking twice is idempotent and does not move the revision.
		again, err := st.RevokeServiceGrant(ctx, meta, "sunkardav", tenantGrant.Grant.ID)
		if err != nil || again.Changed || again.PolicyRevision != revoked.PolicyRevision {
			t.Fatalf("second revoke = %+v err=%v", again, err)
		}
		if _, err := st.RevokeServiceGrant(ctx, meta, "sunkardav", "no-such-grant"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("unknown grant error = %v", err)
		}
		if _, err := st.RevokeServiceGrant(ctx, meta, "admiral-device", tenantGrant.Grant.ID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("grant of another service error = %v, want ErrNotFound", err)
		}

		if n, actor := countAudit(t, st, "service_grant.revoke", tenantGrant.Grant.ID); n != 1 || actor != meta.ActorUserID {
			t.Fatalf("revoke audit rows = %d actor=%q", n, actor)
		}
	})
}

func TestSuspendedAndRevokedDevicesLoseServiceAccess(t *testing.T) {
	forEachDialect(t, func(t *testing.T, st *Store) {
		ctx := context.Background()
		meta := testActor(t, st)
		device, _ := enrollActiveDevice(t, st)
		def, _ := st.GetServiceDefinition(ctx, "sunkardav")
		if _, err := st.UpdateServiceDefinition(ctx, meta, "sunkardav", def.Revision, davInput(true)); err != nil {
			t.Fatalf("enable: %v", err)
		}
		if _, err := st.SetServiceGrant(ctx, meta, "sunkardav", "device", device.ID, "allow"); err != nil {
			t.Fatalf("grant: %v", err)
		}

		active, err := st.DeviceServicePolicy(ctx, device.ID)
		if err != nil || len(active.Services) != 1 {
			t.Fatalf("active policy = %+v err=%v", active, err)
		}

		if _, err := st.SuspendDeviceVPNAndQueueDisconnect(ctx, device.ID); err != nil {
			t.Fatalf("suspend: %v", err)
		}
		suspended, err := st.DeviceServicePolicy(ctx, device.ID)
		if err != nil {
			t.Fatalf("suspended policy: %v", err)
		}
		if suspended.AccessState != domain.AccessStateSuspended || len(suspended.Services) != 0 {
			t.Fatalf("suspended policy = %+v", suspended)
		}
		if suspended.Revision <= active.Revision {
			t.Fatalf("suspension did not advance policy revision: %d -> %d", active.Revision, suspended.Revision)
		}

		if _, err := st.ResumeDeviceVPNAndQueueConnect(ctx, device.ID); err != nil {
			t.Fatalf("resume: %v", err)
		}
		resumed, err := st.DeviceServicePolicy(ctx, device.ID)
		if err != nil || len(resumed.Services) != 1 || resumed.Revision <= suspended.Revision {
			t.Fatalf("resumed policy = %+v err=%v", resumed, err)
		}

		if _, err := st.BeginDeviceVPNRevocation(ctx, device.ID); err != nil {
			t.Fatalf("begin revocation: %v", err)
		}
		revoking, err := st.DeviceServicePolicy(ctx, device.ID)
		if err != nil {
			t.Fatalf("revoking policy: %v", err)
		}
		if revoking.AccessState != domain.AccessStateRevoking || len(revoking.Services) != 0 {
			t.Fatalf("revoking policy = %+v", revoking)
		}
		// A resumed device must not regain access while revocation is pending.
		if _, err := st.ResumeDeviceVPNAndQueueConnect(ctx, device.ID); err == nil {
			t.Fatal("device in revoking state could be resumed")
		}
	})
}

func TestSetServiceGrantValidationAndIdempotency(t *testing.T) {
	forEachDialect(t, func(t *testing.T, st *Store) {
		ctx := context.Background()
		meta := testActor(t, st)
		device, _ := enrollActiveDevice(t, st)

		cases := []struct {
			name                                string
			service, scopeType, scopeID, effect string
			want                                error
			code                                string
		}{
			{"unknown service", "nope", "device", device.ID, "allow", ErrNotFound, "service_not_found"},
			{"unknown scope type", "sunkardav", "planet", "x", "allow", ErrInvalid, "invalid_scope_type"},
			{"unknown effect", "sunkardav", "tenant", "acme", "permit", ErrInvalid, "invalid_effect"},
			{"empty scope id", "sunkardav", "tenant", "", "allow", ErrInvalid, "invalid_scope_id"},
			{"wildcard scope id", "sunkardav", "tenant", "*", "allow", ErrInvalid, "invalid_scope_id"},
			{"unknown device", "sunkardav", "device", "no-such-device", "allow", ErrNotFound, "device_not_found"},
		}
		for _, tc := range cases {
			_, err := st.SetServiceGrant(ctx, meta, tc.service, tc.scopeType, tc.scopeID, tc.effect)
			var ce *ServiceCatalogError
			if !errors.Is(err, tc.want) || !errors.As(err, &ce) || ce.Code != tc.code {
				t.Errorf("%s: error = %v, want kind %v code %s", tc.name, err, tc.want, tc.code)
			}
		}

		first, err := st.SetServiceGrant(ctx, meta, "sunkardav", "tenant", "acme", "allow")
		if err != nil || !first.Changed {
			t.Fatalf("first grant = %+v err=%v", first, err)
		}
		repeat, err := st.SetServiceGrant(ctx, meta, "sunkardav", "tenant", "acme", "allow")
		if err != nil || repeat.Changed || repeat.Grant.ID != first.Grant.ID || repeat.PolicyRevision != first.PolicyRevision {
			t.Fatalf("repeat grant = %+v err=%v", repeat, err)
		}
		flipped, err := st.SetServiceGrant(ctx, meta, "sunkardav", "tenant", "acme", "deny")
		if err != nil || !flipped.Changed || flipped.Grant.ID == first.Grant.ID || flipped.PolicyRevision <= first.PolicyRevision {
			t.Fatalf("flipped grant = %+v err=%v", flipped, err)
		}

		active, total, err := st.ListServiceGrants(ctx, ServiceGrantFilter{ServiceID: "sunkardav"}, 50, 0)
		if err != nil || total != 1 || active[0].Effect != "deny" {
			t.Fatalf("active grants = %+v total=%d err=%v", active, total, err)
		}
		history, total, err := st.ListServiceGrants(ctx, ServiceGrantFilter{ServiceID: "sunkardav", IncludeRevoked: true, Sort: "created_at"}, 50, 0)
		if err != nil || total != 2 || history[0].RevokedAt == "" {
			t.Fatalf("grant history = %+v total=%d err=%v", history, total, err)
		}
		if _, _, err := st.ListServiceGrants(ctx, ServiceGrantFilter{ServiceID: "sunkardav", Sort: "password"}, 50, 0); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid sort error = %v", err)
		}
		page, total, err := st.ListServiceGrants(ctx, ServiceGrantFilter{ServiceID: "sunkardav", IncludeRevoked: true}, 1, 1)
		if err != nil || total != 2 || len(page) != 1 {
			t.Fatalf("paged grants = %+v total=%d err=%v", page, total, err)
		}

		// Narrowing allowed_scopes makes existing device grants inert and
		// prevents creating new ones.
		def, _ := st.GetServiceDefinition(ctx, "sunkardav")
		if _, err := st.SetServiceGrant(ctx, meta, "sunkardav", "device", device.ID, "allow"); err != nil {
			t.Fatalf("device grant: %v", err)
		}
		in := davInput(true)
		in.AllowedScopes = []string{"tenant"}
		if _, err := st.UpdateServiceDefinition(ctx, meta, "sunkardav", def.Revision, in); err != nil {
			t.Fatalf("narrow scopes: %v", err)
		}
		if _, err := st.SetServiceGrant(ctx, meta, "sunkardav", "device", device.ID, "deny"); !errors.Is(err, ErrInvalid) {
			t.Fatalf("grant outside allowed_scopes error = %v", err)
		}
		policy, err := st.DeviceServicePolicy(ctx, device.ID)
		if err != nil || len(policy.Services) != 0 {
			t.Fatalf("policy after narrowing = %+v err=%v", policy, err)
		}
	})
}

func TestDeviceScopesUpdateIsAuditedAndIdempotent(t *testing.T) {
	forEachDialect(t, func(t *testing.T, st *Store) {
		ctx := context.Background()
		meta := testActor(t, st)
		device, _ := enrollActiveDevice(t, st)

		initial, err := st.GetDeviceScopes(ctx, device.ID)
		if err != nil || initial.TenantID != "" || len(initial.GroupIDs) != 0 {
			t.Fatalf("initial scopes = %+v err=%v", initial, err)
		}
		if _, err := st.GetDeviceScopes(ctx, "missing"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("missing device error = %v", err)
		}
		if _, err := st.SetDeviceScopes(ctx, meta, device.ID, domain.DeviceScopes{TenantID: "bad tenant"}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid scope error = %v", err)
		}

		want := domain.DeviceScopes{TenantID: "acme", SiteID: "almaty", GroupIDs: []string{"b", "a", "b"}}
		res, err := st.SetDeviceScopes(ctx, meta, device.ID, want)
		if err != nil || !res.Changed {
			t.Fatalf("SetDeviceScopes = %+v err=%v", res, err)
		}
		if strings.Join(res.Scopes.GroupIDs, ",") != "a,b" {
			t.Fatalf("groups = %v", res.Scopes.GroupIDs)
		}
		again, err := st.SetDeviceScopes(ctx, meta, device.ID, want)
		if err != nil || again.Changed || again.PolicyRevision != res.PolicyRevision {
			t.Fatalf("repeat = %+v err=%v", again, err)
		}
		loaded, _ := st.GetDeviceScopes(ctx, device.ID)
		if loaded.TenantID != "acme" || loaded.SiteID != "almaty" || strings.Join(loaded.GroupIDs, ",") != "a,b" {
			t.Fatalf("loaded scopes = %+v", loaded)
		}
		if n, actor := countAudit(t, st, "device.scopes.update", device.ID); n != 1 || actor != meta.ActorUserID {
			t.Fatalf("scope audit rows = %d actor=%q", n, actor)
		}
	})
}

func TestServicePolicyMigrationUpgradesExistingDatabase(t *testing.T) {
	forEachDialect(t, testServicePolicyMigrationUpgrade)
}

func testServicePolicyMigrationUpgrade(t *testing.T, st *Store) {
	// Backward compatibility: a database that already holds enrolled devices
	// and was migrated only up to 005 must upgrade to 006 without touching
	// them and without granting any service access.
	ctx := context.Background()
	device, _ := enrollActiveDevice(t, st)

	for _, stmt := range []string{
		"DROP TABLE device_scope_memberships",
		"DROP TABLE service_grants",
		"DROP TABLE service_definition_revisions",
		"DROP TABLE service_definitions",
		"DROP TABLE service_policy_state",
		"DELETE FROM schema_migrations WHERE version = 6",
	} {
		if _, err := st.db.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("upgrade Migrate: %v", err)
	}
	// Re-running the migration set is a no-op.
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}

	loaded, err := st.GetDevice(ctx, device.ID)
	if err != nil || loaded.Status != "active" {
		t.Fatalf("device after upgrade = %+v err=%v", loaded, err)
	}
	var grants, enabled int
	_ = st.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM service_grants").Scan(&grants)
	_ = st.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM service_definition_revisions WHERE enabled <> 0").Scan(&enabled)
	if grants != 0 || enabled != 0 {
		t.Fatalf("upgrade grants=%d enabled=%d, want 0/0", grants, enabled)
	}
	policy, err := st.DeviceServicePolicy(ctx, device.ID)
	if err != nil || len(policy.Services) != 0 || policy.AccessState != domain.AccessStateActive {
		t.Fatalf("policy after upgrade = %+v err=%v", policy, err)
	}
}

func TestServiceAccessSnapshotMatchesDevicePolicy(t *testing.T) {
	forEachDialect(t, func(t *testing.T, st *Store) {
		ctx := context.Background()
		meta := testActor(t, st)
		allowedDev, _ := enrollActiveDevice(t, st)
		ungranted, _ := enrollActiveDevice(t, st)
		suspended, _ := enrollActiveDevice(t, st)
		revoked, _ := enrollActiveDevice(t, st)

		for _, id := range []string{"sunkardav", "sunkarcwmp-acs", "admiral-device"} {
			def, _ := st.GetServiceDefinition(ctx, id)
			in := davInput(true)
			in.DisplayName, in.InternalDNSName = def.DisplayName, def.InternalDNSName
			if _, err := st.UpdateServiceDefinition(ctx, meta, id, def.Revision, in); err != nil {
				t.Fatalf("enable %s: %v", id, err)
			}
		}
		if _, err := st.SetDeviceScopes(ctx, meta, allowedDev.ID, domain.DeviceScopes{GroupIDs: []string{"field"}}); err != nil {
			t.Fatalf("scopes: %v", err)
		}
		grants := []struct{ svc, scope, id string }{
			{"sunkardav", "device", allowedDev.ID},
			{"sunkarcwmp-acs", "group", "field"},
			{"sunkardav", "device", suspended.ID},
			{"sunkardav", "device", revoked.ID},
		}
		for _, g := range grants {
			if _, err := st.SetServiceGrant(ctx, meta, g.svc, g.scope, g.id, "allow"); err != nil {
				t.Fatalf("grant %+v: %v", g, err)
			}
		}
		if _, err := st.SuspendDeviceVPNAndQueueDisconnect(ctx, suspended.ID); err != nil {
			t.Fatalf("suspend: %v", err)
		}
		if _, err := st.BeginDeviceVPNRevocation(ctx, revoked.ID); err != nil {
			t.Fatalf("revoke: %v", err)
		}

		snap, err := st.ServiceAccessSnapshot(ctx)
		if err != nil {
			t.Fatalf("ServiceAccessSnapshot: %v", err)
		}
		if len(snap.Targets) != 1 {
			t.Fatalf("targets = %+v, want only the active granted device", snap.Targets)
		}
		got := snap.Targets[0]
		if got.DeviceID != allowedDev.ID || strings.Join(got.ServiceIDs, ",") != "sunkarcwmp-acs,sunkardav" {
			t.Fatalf("target = %+v", got)
		}
		if !got.Address.Is4() {
			t.Fatalf("address = %v", got.Address)
		}
		policy, err := st.DeviceServicePolicy(ctx, allowedDev.ID)
		if err != nil || strings.Join(serviceIDs(policy), ",") != "sunkarcwmp-acs,sunkardav" {
			t.Fatalf("device policy disagrees with snapshot: %+v err=%v", policy, err)
		}
		if snap.PolicyRevision > policy.Revision {
			t.Fatalf("snapshot revision %d is newer than device policy %d", snap.PolicyRevision, policy.Revision)
		}
		_ = ungranted
	})
}

func TestParsePeerAddress(t *testing.T) {
	cases := map[string]bool{
		"10.77.0.2": true, "10.77.0.2/32": true, "::ffff:10.77.0.2": true,
		"": false, "10.77.0.0/24": false, "garbage": false, "10.77.0.2/33": false,
	}
	for raw, ok := range cases {
		if _, got := parsePeerAddress(raw); got != ok {
			t.Errorf("parsePeerAddress(%q) ok=%v, want %v", raw, got, ok)
		}
	}
}
