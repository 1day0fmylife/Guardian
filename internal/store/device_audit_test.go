package store

import (
	"context"
	"testing"
)

func TestDeviceAuditDialectMatrix(t *testing.T) {
	forEachDialect(t, func(t *testing.T, st *Store) {
		ctx := context.Background()
		actor := testActor(t, st)
		a, _ := enrollActiveDevice(t, st)
		b, _ := enrollActiveDevice(t, st)
		grant, err := st.SetServiceGrant(ctx, actor, "sunkardav", "device", a.ID, "allow")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.RevokeServiceGrant(ctx, actor, "sunkardav", grant.Grant.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := st.SetServiceGrant(ctx, actor, "sunkardav", "device", b.ID, "allow"); err != nil {
			t.Fatal(err)
		}
		items, total, err := st.ListDeviceAuditEvents(ctx, a.ID, 100, 0)
		if err != nil {
			t.Fatal(err)
		}
		if total != 2 || len(items) != 2 {
			t.Fatalf("expected set+revoke, got %d/%d", total, len(items))
		}
		for _, event := range items {
			if event.ResourceID != grant.Grant.ID || event.ActorUserID != actor.ActorUserID {
				t.Fatal("audit isolation/actor mismatch")
			}
		}
		page, count, err := st.ListDeviceAuditEvents(ctx, a.ID, 1, 1)
		if err != nil || count != total || len(page) != 1 || page[0].ID != items[1].ID {
			t.Fatalf("paging: %v", err)
		}
	})
}
