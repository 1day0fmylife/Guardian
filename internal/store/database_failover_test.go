package store

import (
	"context"
	"testing"
)

func TestPostgresConnectionFailoverPreservesDeniedPolicy(t *testing.T) {
	st := newPostgresTestStore(t)
	ctx := context.Background()
	device, _ := enrollActiveDevice(t, st)
	// Force the application's only connection to disappear, as happens when a
	// PostgreSQL backend/primary is replaced. database/sql must reconnect.
	st.db.SetMaxOpenConns(1)
	st.db.SetMaxIdleConns(1)
	var pid int
	if err := st.db.QueryRowContext(ctx, "SELECT pg_backend_pid()").Scan(&pid); err != nil {
		t.Fatal(err)
	}
	admin := newPostgresTestStore(t)
	var terminated bool
	if err := admin.db.QueryRowContext(ctx, "SELECT pg_terminate_backend($1)", pid).Scan(&terminated); err != nil || !terminated {
		t.Fatalf("terminate application backend = %v, %v", terminated, err)
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		policy, err := st.DeviceServicePolicy(ctx, device.ID)
		lastErr = err
		if err == nil {
			if len(policy.Services) != 0 {
				t.Fatal("connection recovery granted default service access")
			}
			return
		}
		if len(policy.Services) != 0 {
			t.Fatal("failed read returned partial service grants")
		}
	}
	t.Fatalf("DeviceServicePolicy after connection loss did not recover: %v", lastErr)
}
