package store

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/1day0fmylife/Guardian/internal/domain"
)

func TestTenantOwnershipAndGrantIsolation(t *testing.T) {
	forEachDialect(t, func(t *testing.T, st *Store) {
		ctx := context.Background()
		meta := testActor(t, st)
		a, _ := enrollActiveDevice(t, st)
		b, _ := enrollActiveDevice(t, st)
		enableDAVForTest(t, st, meta)
		assign := func(id, tenant, site, group string) error {
			groups := []string{}
			if group != "" {
				groups = append(groups, group)
			}
			_, err := st.SetDeviceScopes(ctx, meta, id, domain.DeviceScopes{TenantID: tenant, SiteID: site, GroupIDs: groups})
			return err
		}
		if err := assign(a.ID, "tenant-a", "site-a", "group-a"); err != nil {
			t.Fatal(err)
		}
		if err := assign(b.ID, "tenant-b", "site-b", "group-b"); err != nil {
			t.Fatal(err)
		}
		for _, scope := range []struct{ kind, id string }{{"tenant", "tenant-a"}, {"site", "site-a"}, {"group", "group-a"}} {
			grant, err := st.SetServiceGrant(ctx, meta, "sunkardav", scope.kind, scope.id, "allow")
			if err != nil {
				t.Fatal(err)
			}
			pa, err := st.DeviceServicePolicy(ctx, a.ID)
			if err != nil || len(pa.Services) != 1 {
				t.Fatalf("owner policy = %+v, %v", pa, err)
			}
			pb, err := st.DeviceServicePolicy(ctx, b.ID)
			if err != nil || len(pb.Services) != 0 {
				t.Fatalf("cross-tenant policy = %+v, %v", pb, err)
			}
			if _, err := st.RevokeServiceGrant(ctx, meta, "sunkardav", grant.Grant.ID); err != nil {
				t.Fatal(err)
			}
		}
		// Invalid replacements must not change membership, revision, audit, or owner.
		before, _ := st.readServicePolicyRevision(ctx, st.db)
		_, auditBefore, _ := st.ListAuditEvents(ctx, 100, 0)
		for _, scopes := range []domain.DeviceScopes{
			{TenantID: "tenant-b", SiteID: "site-a"},
			{TenantID: "tenant-b", GroupIDs: []string{"new-b-group", "group-a"}},
			{SiteID: "site-a"},
		} {
			if _, err := st.SetDeviceScopes(ctx, meta, b.ID, scopes); !errors.Is(err, ErrConflict) {
				t.Fatalf("cross-owner replacement = %v, want conflict", err)
			}
		}
		after, _ := st.readServicePolicyRevision(ctx, st.db)
		_, auditAfter, _ := st.ListAuditEvents(ctx, 100, 0)
		if before != after || auditBefore != auditAfter {
			t.Fatal("rejected membership changed revision/audit")
		}
		actual, err := st.GetDeviceScopes(ctx, b.ID)
		if err != nil || actual.TenantID != "tenant-b" || actual.SiteID != "site-b" {
			t.Fatalf("replacement was not atomic: %+v, %v", actual, err)
		}
		// Failed insertion of new-b-group rolled back; another tenant may claim it.
		if err := assign(a.ID, "tenant-a", "site-a", "new-b-group"); err != nil {
			t.Fatal(err)
		}
		if err := assign(a.ID, "", "", ""); err != nil {
			t.Fatal(err)
		}
		if err := assign(b.ID, "tenant-b", "site-a", ""); !errors.Is(err, ErrConflict) {
			t.Fatalf("abandoned owner reused: %v", err)
		}
		// Legacy unscoped devices remain supported in their own namespace.
		if err := assign(a.ID, "", "legacy-site", "legacy-group"); err != nil {
			t.Fatal(err)
		}
		if err := assign(b.ID, "tenant-b", "legacy-site", ""); !errors.Is(err, ErrConflict) {
			t.Fatalf("legacy namespace reused: %v", err)
		}
	})
}

func TestPoolOverlapAndConcurrentCreation(t *testing.T) {
	forEachDialect(t, func(t *testing.T, st *Store) {
		ctx := context.Background()
		meta := testActor(t, st)
		if _, err := st.CreateAddressPoolAudited(ctx, meta, AddressPoolCreate{Name: "first", CIDR: "10.230.0.7/24"}); err != nil {
			t.Fatal(err)
		}
		for _, cidr := range []string{"10.230.0.0/24", "10.230.0.8/29", "10.230.0.0/16"} {
			if _, err := st.CreateAddressPoolAudited(ctx, meta, AddressPoolCreate{Name: cidr, CIDR: cidr}); !errors.Is(err, ErrConflict) {
				t.Fatalf("overlap %s = %v, want conflict", cidr, err)
			}
		}
		// Both writers start together. Only one may commit intersecting ranges.
		start := make(chan struct{})
		results := make(chan error, 2)
		var wg sync.WaitGroup
		for _, cidr := range []string{"10.231.0.0/24", "10.231.0.0/29"} {
			wg.Add(1)
			go func(cidr string) {
				defer wg.Done()
				<-start
				_, err := st.CreateAddressPool(ctx, AddressPoolCreate{Name: cidr, CIDR: cidr})
				results <- err
			}(cidr)
		}
		close(start)
		wg.Wait()
		close(results)
		successes, conflicts := 0, 0
		for err := range results {
			if err == nil {
				successes++
			} else if errors.Is(err, ErrConflict) {
				conflicts++
			} else {
				t.Fatal(err)
			}
		}
		if successes != 1 || conflicts != 1 {
			t.Fatalf("concurrent overlap successes=%d conflicts=%d", successes, conflicts)
		}
		events, total, err := st.ListAuditEvents(ctx, 100, 0)
		if err != nil || total != 1 || events[0].ActorUserID != meta.ActorUserID {
			t.Fatalf("pool audit = %+v, %d, %v", events, total, err)
		}
	})
}

func TestScopeCorruptionFailsClosed(t *testing.T) {
	forEachDialect(t, func(t *testing.T, st *Store) {
		ctx := context.Background()
		meta := testActor(t, st)
		a, _ := enrollActiveDevice(t, st)
		if _, err := st.SetDeviceScopes(ctx, meta, a.ID, domain.DeviceScopes{TenantID: "a", GroupIDs: []string{"group"}}); err != nil {
			t.Fatal(err)
		}
		enableDAVForTest(t, st, meta)
		if _, err := st.SetServiceGrant(ctx, meta, "sunkardav", "group", "group", "allow"); err != nil {
			t.Fatal(err)
		}
		if _, err := st.db.ExecContext(ctx, st.q("UPDATE device_scope_memberships SET scope_id = ? WHERE device_id = ? AND scope_type = 'tenant'"), "b", a.ID); err != nil {
			t.Fatal(err)
		}
		policy, err := st.DeviceServicePolicy(ctx, a.ID)
		if err == nil || len(policy.Services) != 0 {
			t.Fatalf("corrupted policy = %+v,%v; want fail closed", policy, err)
		}
		snapshot, err := st.ServiceAccessSnapshot(ctx)
		if err == nil || len(snapshot.Targets) != 0 {
			t.Fatalf("corrupted ACL = %+v,%v; want fail closed", snapshot, err)
		}
	})
}

func TestSuspensionReinstateAndTerminalRevocation(t *testing.T) {
	forEachDialect(t, func(t *testing.T, st *Store) {
		ctx := context.Background()
		meta := testActor(t, st)
		a, _ := enrollActiveDevice(t, st)
		enableDAVForTest(t, st, meta)
		if _, err := st.SetServiceGrant(ctx, meta, "sunkardav", "device", a.ID, "allow"); err != nil {
			t.Fatal(err)
		}
		if _, err := st.SuspendDeviceVPNAndQueueDisconnect(ctx, a.ID); err != nil {
			t.Fatal(err)
		}
		p, err := st.DeviceServicePolicy(ctx, a.ID)
		if err != nil || len(p.Services) != 0 {
			t.Fatalf("suspended policy = %+v,%v", p, err)
		}
		if _, err := st.ResumeDeviceVPNAndQueueConnect(ctx, a.ID); err != nil {
			t.Fatal(err)
		}
		p, err = st.DeviceServicePolicy(ctx, a.ID)
		if err != nil || len(p.Services) != 1 {
			t.Fatalf("resumed policy = %+v,%v", p, err)
		}
		if _, err := st.BeginDeviceVPNRevocation(ctx, a.ID); err != nil {
			t.Fatal(err)
		}
		for _, suspended := range []bool{true, false} {
			if err := st.SetDeviceSuspended(ctx, a.ID, suspended); !errors.Is(err, ErrConflict) {
				t.Fatalf("terminal lifecycle changed = %v", err)
			}
		}
		if _, err := st.ResumeDeviceVPNAndQueueConnect(ctx, a.ID); !errors.Is(err, ErrConflict) {
			t.Fatalf("revoking peer reinstated = %v", err)
		}
	})
}

func removeIsolationMigration(t *testing.T, st *Store) {
	t.Helper()
	for _, sql := range []string{"DROP INDEX idx_device_single_tenant", "DROP INDEX idx_device_single_site", "DROP INDEX idx_address_leases_global_active", "DROP TABLE scope_owners", "DROP TABLE network_allocation_state", "DELETE FROM schema_migrations WHERE version = 9"} {
		if _, err := st.db.ExecContext(context.Background(), sql); err != nil {
			t.Fatal(err)
		}
	}
}

func TestIsolationMigrationBackfillAndRefusal(t *testing.T) {
	for _, scenario := range []string{"valid", "ambiguous-owner", "overlap", "duplicate-ip"} {
		t.Run(scenario, func(t *testing.T) {
			forEachDialect(t, func(t *testing.T, st *Store) {
				ctx := context.Background()
				a, _ := enrollActiveDevice(t, st)
				b, _ := enrollActiveDevice(t, st)
				removeIsolationMigration(t, st)
				for _, member := range []struct{ device, kind, id string }{{a.ID, "tenant", "tenant-a"}, {a.ID, "site", "site-a"}, {a.ID, "group", "group-a"}} {
					if _, err := st.db.ExecContext(ctx, st.q("INSERT INTO device_scope_memberships(device_id,scope_type,scope_id,created_at) VALUES(?,?,?,?)"), member.device, member.kind, member.id, nowText()); err != nil {
						t.Fatal(err)
					}
				}
				switch scenario {
				case "ambiguous-owner":
					for _, member := range []struct{ kind, id string }{{"tenant", "tenant-b"}, {"group", "group-a"}} {
						if _, err := st.db.ExecContext(ctx, st.q("INSERT INTO device_scope_memberships(device_id,scope_type,scope_id,created_at) VALUES(?,?,?,?)"), b.ID, member.kind, member.id, nowText()); err != nil {
							t.Fatal(err)
						}
					}
				case "duplicate-ip":
					var address string
					if err := st.db.QueryRowContext(ctx, st.q("SELECT address FROM address_leases WHERE device_id = ?"), a.ID).Scan(&address); err != nil {
						t.Fatal(err)
					}
					if _, err := st.db.ExecContext(ctx, st.q("UPDATE address_leases SET address = ? WHERE device_id = ?"), address, b.ID); err != nil {
						t.Fatal(err)
					}
				case "overlap":
					if _, err := st.db.ExecContext(ctx, "UPDATE address_pools SET cidr = '10.240.0.0/24'"); err != nil {
						t.Fatal(err)
					}
				}
				err := st.Migrate(ctx)
				if scenario == "valid" {
					if err != nil {
						t.Fatal(err)
					}
					if err := st.Migrate(ctx); err != nil {
						t.Fatal(err)
					}
					actual, err := st.GetDeviceScopes(ctx, a.ID)
					if err != nil || actual.TenantID != "tenant-a" || actual.SiteID != "site-a" {
						t.Fatalf("backfill = %+v,%v", actual, err)
					}
				} else {
					if err == nil {
						t.Fatalf("migration accepted %s", scenario)
					}
					var count int
					if err := st.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations WHERE version = 9").Scan(&count); err != nil || count != 0 {
						t.Fatalf("failed migration recorded = %d,%v", count, err)
					}
				}
			})
		})
	}
}

func TestConcurrentScopeOwnersAndGlobalLeaseConstraint(t *testing.T) {
	forEachDialect(t, func(t *testing.T, st *Store) {
		ctx := context.Background()
		meta := testActor(t, st)
		a, _ := enrollActiveDevice(t, st)
		b, _ := enrollActiveDevice(t, st)
		start := make(chan struct{})
		results := make(chan error, 2)
		for _, pair := range []struct{ device, tenant string }{{a.ID, "a"}, {b.ID, "b"}} {
			go func(id, tenant string) {
				<-start
				_, err := st.SetDeviceScopes(ctx, meta, id, domain.DeviceScopes{TenantID: tenant, GroupIDs: []string{"contended-group"}})
				results <- err
			}(pair.device, pair.tenant)
		}
		close(start)
		successes, conflicts := 0, 0
		for i := 0; i < 2; i++ {
			err := <-results
			if err == nil {
				successes++
			} else if errors.Is(err, ErrConflict) {
				conflicts++
			} else {
				t.Fatal(err)
			}
		}
		if successes != 1 || conflicts != 1 {
			t.Fatalf("owner race successes=%d conflicts=%d", successes, conflicts)
		}
		var address string
		if err := st.db.QueryRowContext(ctx, st.q("SELECT address FROM address_leases WHERE device_id = ? AND status = 'active'"), a.ID).Scan(&address); err != nil {
			t.Fatal(err)
		}
		if _, err := st.db.ExecContext(ctx, st.q("UPDATE address_leases SET address = ? WHERE device_id = ?"), address, b.ID); err == nil {
			t.Fatal("global occupied-IP constraint allowed duplicate across pools")
		}
		if _, err := st.CreateAddressPoolAudited(ctx, AuditMeta{ActorUserID: "missing-actor"}, AddressPoolCreate{Name: "must-rollback", CIDR: "10.245.0.0/24"}); err == nil {
			t.Fatal("pool committed without audit actor")
		}
		if _, err := st.CreateAddressPoolAudited(ctx, meta, AddressPoolCreate{Name: "retry-after-audit-failure", CIDR: "10.245.0.0/24"}); err != nil {
			t.Fatalf("audit rollback retained pool: %v", err)
		}
	})
}
