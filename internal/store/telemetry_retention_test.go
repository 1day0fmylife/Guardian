package store

import (
	"context"
	"testing"
	"time"

	"github.com/1day0fmylife/Guardian/internal/domain"
)

func TestTelemetryRetentionPreviewApplyAndLatestProtection(t *testing.T) {
	forEachDialect(t, func(t *testing.T, st *Store) {
		ctx := context.Background()
		a, _ := enrollActiveDevice(t, st)
		b, _ := enrollActiveDevice(t, st)
		insert := func(device, stamp string) string {
			t.Helper()
			row, err := st.RecordDeviceTelemetry(ctx, device, domain.DeviceTelemetryInput{TunnelState: "connected"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := st.db.ExecContext(ctx, st.q("UPDATE device_telemetry SET observed_at = ? WHERE id = ?"), stamp, row.ID); err != nil {
				t.Fatal(err)
			}
			return row.ID
		}
		insert(a.ID, "2020-01-01T00:00:00.1Z")
		insert(a.ID, "2020-01-01T00:00:00.11Z")
		insert(a.ID, "2020-01-02T00:00:00Z") // Exact cutoff must remain.
		latest := insert(a.ID, "2020-01-03T00:00:00.1Z")
		// Offline device: all ties in its latest second are retained, even if old.
		insert(b.ID, "2019-01-01T00:00:00.1Z")
		insert(b.ID, "2019-01-01T00:00:00.11Z")
		cutoff, _ := time.Parse(time.RFC3339, "2020-01-02T00:00:00Z")
		preview, err := st.PruneDeviceTelemetry(ctx, cutoff, 1, true)
		if err != nil || preview.Candidates != 1 || preview.Deleted != 0 {
			t.Fatalf("Prune dry-run = %+v, %v; want one candidate, zero deleted", preview, err)
		}
		var count int
		if err := st.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM device_telemetry").Scan(&count); err != nil || count != 6 {
			t.Fatalf("dry-run count = %d, %v; want 6", count, err)
		}
		applied, err := st.PruneDeviceTelemetry(ctx, cutoff, 1, false)
		if err != nil || applied.Deleted != 1 {
			t.Fatalf("Prune apply = %+v, %v; want one deleted", applied, err)
		}
		applied, err = st.PruneDeviceTelemetry(ctx, cutoff, 100, false)
		if err != nil || applied.Deleted != 1 {
			t.Fatalf("Prune second batch = %+v, %v; want one deleted", applied, err)
		}
		applied, err = st.PruneDeviceTelemetry(ctx, cutoff, 100, false)
		if err != nil || applied.Deleted != 0 {
			t.Fatalf("Prune repeat = %+v, %v; want zero deleted", applied, err)
		}
		row, err := st.LatestDeviceTelemetry(ctx, a.ID)
		if err != nil || row.ID != latest {
			t.Fatalf("LatestDeviceTelemetry after prune = %s, %v; want %s", row.ID, err, latest)
		}
		if _, err := st.LatestDeviceTelemetry(ctx, b.ID); err != nil {
			t.Fatalf("offline telemetry lost: %v", err)
		}
		events, total, err := st.ListAuditEvents(ctx, 100, 0)
		if err != nil || total != 2 || events[0].Action != "telemetry.retention" {
			t.Fatalf("retention audit = %d, %v; want 2 events", total, err)
		}
		for _, bad := range []struct {
			before time.Time
			limit  int
		}{{time.Time{}, 1}, {time.Now().Add(time.Hour), 1}, {cutoff, 0}, {cutoff, 10001}} {
			if _, err := st.PruneDeviceTelemetry(ctx, bad.before, bad.limit, false); err == nil {
				t.Fatalf("Prune(%v,%d) accepted invalid input", bad.before, bad.limit)
			}
		}
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := st.PruneDeviceTelemetry(cancelled, cutoff, 100, false); err == nil {
			t.Fatal("cancelled prune succeeded")
		}
	})
}

func TestTelemetryRetentionMigrationUpgradeIsIdempotent(t *testing.T) {
	forEachDialect(t, func(t *testing.T, st *Store) {
		ctx := context.Background()
		device, _ := enrollActiveDevice(t, st)
		latest, err := st.RecordDeviceTelemetry(ctx, device.ID, domain.DeviceTelemetryInput{TunnelState: "connected"})
		if err != nil {
			t.Fatal(err)
		}
		for _, statement := range []string{"DROP INDEX idx_device_telemetry_retention", "DELETE FROM schema_migrations WHERE version = 8"} {
			if _, err := st.db.ExecContext(ctx, statement); err != nil {
				t.Fatal(err)
			}
		}
		for i := 0; i < 2; i++ {
			if err := st.Migrate(ctx); err != nil {
				t.Fatal(err)
			}
		}
		var count int
		if err := st.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations WHERE version = 8").Scan(&count); err != nil || count != 1 {
			t.Fatalf("migration count = %d, %v", count, err)
		}
		row, err := st.LatestDeviceTelemetry(ctx, device.ID)
		if err != nil || row.ID != latest.ID {
			t.Fatalf("upgrade changed telemetry: %+v, %v", row, err)
		}
		// Dropping the index also proves the upgrade recreated it on both dialects.
		if _, err := st.db.ExecContext(ctx, "DROP INDEX idx_device_telemetry_retention"); err != nil {
			t.Fatal(err)
		}
	})
}
