package store

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// BenchmarkServiceAccessSnapshot measures the complete database snapshot with
// three explicit individual grants per device. Fixture creation is not timed.
// PostgreSQL uses a disposable schema; never point the test URL at production.
func BenchmarkServiceAccessSnapshot(b *testing.B) {
	for _, dialect := range []string{"sqlite", "postgres"} {
		b.Run(dialect, func(b *testing.B) {
			for _, n := range []int{100, 1000, 10000} {
				b.Run(fmt.Sprintf("devices_%d", n), func(b *testing.B) {
					ctx := context.Background()
					dsn := "sqlite://" + filepath.Join(b.TempDir(), "scale.db")
					if dialect == "postgres" {
						base := os.Getenv(postgresTestURLEnv)
						if base == "" {
							b.Skip("GUARDIAN_TEST_POSTGRES_URL unset")
						}
						admin, err := Open(ctx, base)
						if err != nil {
							b.Fatal(err)
						}
						schema := fmt.Sprintf("g09_%d", time.Now().UnixNano())
						if _, err := admin.db.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
							b.Fatal(err)
						}
						b.Cleanup(func() { _, _ = admin.db.ExecContext(ctx, "DROP SCHEMA "+schema+" CASCADE"); _ = admin.Close() })
						u, err := url.Parse(base)
						if err != nil {
							b.Fatal(err)
						}
						q := u.Query()
						q.Set("search_path", schema)
						u.RawQuery = q.Encode()
						dsn = u.String()
					}
					st, err := Open(ctx, dsn)
					if err != nil {
						b.Fatal(err)
					}
					b.Cleanup(func() { _ = st.Close() })
					if err := st.Migrate(ctx); err != nil {
						b.Fatal(err)
					}
					seedScaleBenchmark(b, st, n)
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						snap, err := st.ServiceAccessSnapshot(ctx)
						if err != nil {
							b.Fatal(err)
						}
						if len(snap.Targets) != n {
							b.Fatalf("targets: got %d want %d", len(snap.Targets), n)
						}
						for _, target := range snap.Targets {
							if len(target.ServiceIDs) != 3 {
								b.Fatal("fixture grant missing")
							}
						}
					}
					b.StopTimer()
					b.ReportMetric(float64(n), "devices")
				})
			}
		})
	}
}

func seedScaleBenchmark(b *testing.B, st *Store, n int) {
	b.Helper()
	ctx := context.Background()
	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		b.Fatal(err)
	}
	defer tx.Rollback()
	now := nowText()
	exec := func(query string, args ...any) {
		b.Helper()
		if _, err := tx.ExecContext(ctx, st.q(query), args...); err != nil {
			b.Fatal(err)
		}
	}
	exec(`INSERT INTO address_pools(id,name,cidr,gateway,created_at,updated_at) VALUES('scale','scale','10.246.0.0/16','10.246.0.1',?,?)`, now, now)
	key := sha256.Sum256([]byte("synthetic-server"))
	exec(`INSERT INTO vpn_profiles(id,name,server_public_key,endpoint,allowed_ips,address_pool_id,created_at,updated_at) VALUES('scale','scale',?,'benchmark.invalid:51820','10.246.0.0/16','scale',?,?)`, base64.StdEncoding.EncodeToString(key[:]), now, now)
	exec(`UPDATE service_definition_revisions SET enabled=1`)
	queries := []string{
		`INSERT INTO devices(id,name,device_uuid,status,created_at,updated_at) VALUES(?,?,?,'active',?,?)`,
		`INSERT INTO wireguard_peers(id,device_id,profile_id,public_key,assigned_address,config_revision,applied_revision,reconcile_state,created_at,updated_at) VALUES(?,?,'scale',?,?,1,1,'applied',?,?)`,
		`INSERT INTO service_grants(id,service_id,scope_type,scope_id,effect,policy_revision,created_at) VALUES(?,?,'device',?,'allow',1,?)`,
	}
	device, err := tx.PrepareContext(ctx, st.q(queries[0]))
	if err != nil {
		b.Fatal(err)
	}
	defer device.Close()
	peer, err := tx.PrepareContext(ctx, st.q(queries[1]))
	if err != nil {
		b.Fatal(err)
	}
	defer peer.Close()
	grant, err := tx.PrepareContext(ctx, st.q(queries[2]))
	if err != nil {
		b.Fatal(err)
	}
	defer grant.Close()
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("scale-%d", i)
		key := sha256.Sum256([]byte(id))
		address := fmt.Sprintf("10.246.%d.%d/32", (i+2)/256, (i+2)%256)
		if _, err := device.ExecContext(ctx, id, id, id, now, now); err != nil {
			b.Fatal(err)
		}
		if _, err := peer.ExecContext(ctx, id, id, base64.StdEncoding.EncodeToString(key[:]), address, now, now); err != nil {
			b.Fatal(err)
		}
		for _, svc := range []string{"sunkardav", "admiral-device", "sunkarcwmp-acs"} {
			if _, err := grant.ExecContext(ctx, id+svc, svc, id, now); err != nil {
				b.Fatal(err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}
}
