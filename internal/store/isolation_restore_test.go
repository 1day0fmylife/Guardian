package store

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/1day0fmylife/Guardian/internal/domain"
	"github.com/1day0fmylife/Guardian/internal/security"
)

// The PostgreSQL leg uses pg_dump/psql if installed, or a deliberately selected
// disposable test container. No production database is ever inferred.
func TestIsolationBackupRestoreIntoNewEnvironment(t *testing.T) {
	forEachDialect(t, func(t *testing.T, source *Store) {
		ctx := context.Background()
		meta := testActor(t, source)
		a, tokenA := enrollActiveDevice(t, source)
		b, tokenB := enrollActiveDevice(t, source)
		enableDAVForTest(t, source, meta)
		for _, pair := range []struct{ device, tenant, group string }{{a.ID, "a", "a-group"}, {b.ID, "b", "b-group"}} {
			if _, err := source.SetDeviceScopes(ctx, meta, pair.device, domain.DeviceScopes{TenantID: pair.tenant, GroupIDs: []string{pair.group}}); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := source.SetServiceGrant(ctx, meta, "sunkardav", "group", "a-group", "allow"); err != nil {
			t.Fatal(err)
		}
		var restored *Store
		var dump []byte
		if source.dialect == "sqlite" {
			path := filepath.Join(t.TempDir(), "restored.db")
			if _, err := source.db.ExecContext(ctx, "VACUUM INTO ?", path); err != nil {
				t.Fatal(err)
			}
			var err error
			dump, err = os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			restored, err = Open(ctx, "sqlite://"+path)
			if err != nil {
				t.Fatal(err)
			}
		} else {
			restored, dump = restorePostgresFixture(t, source)
		}
		defer restored.Close()
		for _, token := range []string{tokenA, tokenB} {
			if bytes.Contains(dump, []byte(token)) {
				t.Fatal("backup contains plaintext device credential")
			}
		}
		if err := restored.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		if err := restored.SeedRBAC(ctx); err != nil {
			t.Fatal(err)
		}
		p, err := restored.DeviceServicePolicy(ctx, a.ID)
		if err != nil || len(p.Services) != 1 {
			t.Fatalf("restored owner policy=%+v,%v", p, err)
		}
		p, err = restored.DeviceServicePolicy(ctx, b.ID)
		if err != nil || len(p.Services) != 0 {
			t.Fatalf("restored foreign policy=%+v,%v", p, err)
		}
		if _, err := restored.SetDeviceScopes(ctx, meta, b.ID, domain.DeviceScopes{TenantID: "b", GroupIDs: []string{"a-group"}}); err == nil {
			t.Fatal("restore lost immutable ownership")
		}
		principal, err := restored.DevicePrincipalByCredential(ctx, security.HashToken(tokenA))
		if err != nil || principal.DeviceID != a.ID {
			t.Fatal("restore lost hashed authentication")
		}
		raw, _ := source.DeviceServicePolicy(ctx, a.ID)
		if raw.Revision != p.Revision {
			t.Fatal("restore changed policy revision")
		}
		// Exercise the documented suspend/reinstate then terminal revoke sequence.
		if _, err := restored.SuspendDeviceVPNAndQueueDisconnect(ctx, a.ID); err != nil {
			t.Fatal(err)
		}
		p, err = restored.DeviceServicePolicy(ctx, a.ID)
		if err != nil || len(p.Services) != 0 {
			t.Fatal("suspension retained access")
		}
		if _, err := restored.ResumeDeviceVPNAndQueueConnect(ctx, a.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := restored.BeginDeviceVPNRevocation(ctx, a.ID); err != nil {
			t.Fatal(err)
		}
		pending, err := restored.ListPendingWireGuardReconciliations(ctx, 100)
		if err != nil {
			t.Fatal(err)
		}
		for _, peer := range pending {
			if peer.DeviceID == a.ID {
				if err := restored.MarkWireGuardPeerApplied(ctx, peer.PeerID, peer.ConfigRevision); err != nil {
					t.Fatal(err)
				}
			}
		}
		if _, err := restored.DevicePrincipalByCredential(ctx, security.HashToken(tokenA)); err == nil {
			t.Fatal("revoked credential survived completion")
		}
		if _, err := restored.ResumeDeviceVPNAndQueueConnect(ctx, a.ID); err == nil {
			t.Fatal("revoked device reinstated without enrollment")
		}
	})
}

func restorePostgresFixture(t *testing.T, source *Store) (*Store, []byte) {
	t.Helper()
	base, err := url.Parse(os.Getenv(postgresTestURLEnv))
	if err != nil {
		t.Fatal(err)
	}
	container := os.Getenv("GUARDIAN_TEST_POSTGRES_CONTAINER")
	if container == "" {
		for _, tool := range []string{"pg_dump", "psql"} {
			if _, err := exec.LookPath(tool); err != nil {
				t.Skip("PostgreSQL restore requires pg_dump/psql or GUARDIAN_TEST_POSTGRES_CONTAINER")
			}
		}
	}
	var schema string
	if err := source.db.QueryRowContext(context.Background(), "SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	database := fmt.Sprintf("g08_restore_%d", time.Now().UnixNano())
	if _, err := source.db.ExecContext(context.Background(), "CREATE DATABASE "+database); err != nil {
		t.Fatal("test role needs CREATEDB for restore fixture")
	}
	t.Cleanup(func() { _, _ = source.db.ExecContext(context.Background(), "DROP DATABASE "+database+" WITH (FORCE)") })
	run := func(tool, db string, input []byte, args ...string) []byte {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		var cmd *exec.Cmd
		if container != "" {
			all := []string{"exec", "-i", container, tool, "-U", base.User.Username(), "-d", db}
			cmd = exec.CommandContext(ctx, "docker", append(all, args...)...)
		} else {
			cmd = exec.CommandContext(ctx, tool, args...)
			password, _ := base.User.Password()
			cmd.Env = append(os.Environ(), "PGHOST="+base.Hostname(), "PGPORT="+base.Port(), "PGUSER="+base.User.Username(), "PGPASSWORD="+password, "PGDATABASE="+db, "PGSSLMODE="+base.Query().Get("sslmode"))
		}
		cmd.Stdin = bytes.NewReader(input)
		output, err := cmd.Output()
		if err != nil {
			t.Fatalf("%s restore fixture command failed (diagnostic omitted)", tool)
		}
		return output
	}
	dump := run("pg_dump", strings.TrimPrefix(base.Path, "/"), nil, "--schema="+schema, "--no-owner", "--no-privileges", "--format=plain")
	run("psql", database, dump, "-X", "-v", "ON_ERROR_STOP=1")
	base.Path = "/" + database
	q := base.Query()
	q.Set("search_path", schema)
	base.RawQuery = q.Encode()
	restored, err := Open(context.Background(), base.String())
	if err != nil {
		t.Fatal("open restored test database failed")
	}
	return restored, dump
}
