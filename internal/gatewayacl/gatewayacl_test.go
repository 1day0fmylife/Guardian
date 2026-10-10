package gatewayacl

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/1day0fmylife/Guardian/internal/store"
)

var allServices = []string{"sunkardav", "admiral-device", "sunkarcwmp-acs"}

func target(addr string, services ...string) store.ServiceAccessTarget {
	return store.ServiceAccessTarget{DeviceID: addr, Address: netip.MustParseAddr(addr), ServiceIDs: services}
}

func TestRenderIsDeterministicAndFlushesEmptySets(t *testing.T) {
	targets := []store.ServiceAccessTarget{
		target("10.77.0.9", "sunkardav"),
		target("10.77.0.2", "sunkardav", "sunkarcwmp-acs"),
	}
	got, err := Render("guardian_gw", allServices, targets)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	want := strings.Join([]string{
		"flush set inet guardian_gw svc_admiral_device_v4",
		"flush set inet guardian_gw svc_sunkarcwmp_acs_v4",
		"add element inet guardian_gw svc_sunkarcwmp_acs_v4 { 10.77.0.2 }",
		"flush set inet guardian_gw svc_sunkardav_v4",
		"add element inet guardian_gw svc_sunkardav_v4 { 10.77.0.2, 10.77.0.9 }",
		"",
	}, "\n")
	if got != want {
		t.Fatalf("script mismatch\n got:\n%s\nwant:\n%s", got, want)
	}
	reversed, _ := Render("guardian_gw", allServices, []store.ServiceAccessTarget{targets[1], targets[0]})
	if reversed != got {
		t.Fatal("render depends on target order")
	}
}

func TestRenderRejectsInjectionAndIgnoresUnsafeInput(t *testing.T) {
	if _, err := Render("guardian_gw; flush ruleset", allServices, nil); err == nil {
		t.Fatal("table name with nft syntax accepted")
	}
	if _, err := Render("guardian_gw", []string{"dav }\nflush ruleset"}, nil); err == nil {
		t.Fatal("service id with nft syntax accepted")
	}
	got, err := Render("guardian_gw", allServices, []store.ServiceAccessTarget{
		target("fd00::2", "sunkardav"),                // IPv6 is never projected
		target("10.77.0.3", "unknown-service"),        // not a gateway service
		target("10.77.0.4", "sunkardav", "sunkardav"), // duplicates collapse
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if strings.Contains(got, "fd00") || strings.Contains(got, "10.77.0.3") {
		t.Fatalf("unexpected element in script:\n%s", got)
	}
	if strings.Count(got, "10.77.0.4") != 1 {
		t.Fatalf("duplicate not collapsed:\n%s", got)
	}
}

type fakeSource struct {
	snap store.ServiceAccessSnapshot
	err  error
}

func (f *fakeSource) ServiceAccessSnapshot(context.Context) (store.ServiceAccessSnapshot, error) {
	return f.snap, f.err
}

type fakeApplier struct {
	scripts []string
	err     error
}

func (f *fakeApplier) Apply(_ context.Context, script string) error {
	if f.err != nil {
		return f.err
	}
	f.scripts = append(f.scripts, script)
	return nil
}

func TestSyncerAppliesOnlyChangesAndFailsClosedAfterStaleTTL(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	src := &fakeSource{snap: store.ServiceAccessSnapshot{
		PolicyRevision: 5, Targets: []store.ServiceAccessTarget{target("10.77.0.2", "sunkardav")},
	}}
	app := &fakeApplier{}
	syncer := &Syncer{
		Source: src, Applier: app, Table: "guardian_gw", ServiceIDs: allServices,
		StaleTTL: 30 * time.Second, Now: func() time.Time { return now },
	}
	ctx := context.Background()

	res, err := syncer.SyncOnce(ctx)
	if err != nil || !res.Changed || res.PolicyRevision != 5 || len(app.scripts) != 1 {
		t.Fatalf("first sync = %+v err=%v scripts=%d", res, err, len(app.scripts))
	}
	res, err = syncer.SyncOnce(ctx)
	if err != nil || res.Changed || len(app.scripts) != 1 {
		t.Fatalf("unchanged sync = %+v err=%v scripts=%d", res, err, len(app.scripts))
	}

	// Revocation: the device disappears from the snapshot and is removed.
	src.snap = store.ServiceAccessSnapshot{PolicyRevision: 6}
	res, err = syncer.SyncOnce(ctx)
	if err != nil || !res.Changed || strings.Contains(app.scripts[len(app.scripts)-1], "add element") {
		t.Fatalf("revocation sync = %+v err=%v script=%q", res, err, app.scripts[len(app.scripts)-1])
	}

	// Outage within the TTL keeps the last good state...
	src.snap = store.ServiceAccessSnapshot{PolicyRevision: 7, Targets: []store.ServiceAccessTarget{target("10.77.0.2", "sunkardav")}}
	if _, err := syncer.SyncOnce(ctx); err != nil {
		t.Fatalf("restore sync: %v", err)
	}
	applied := len(app.scripts)
	src.err = errors.New("database down")
	now = now.Add(10 * time.Second)
	res, err = syncer.SyncOnce(ctx)
	if err == nil || res.FailedClosed || len(app.scripts) != applied {
		t.Fatalf("short outage = %+v err=%v scripts=%d", res, err, len(app.scripts))
	}
	// ...but a longer outage flushes every set.
	now = now.Add(time.Minute)
	res, err = syncer.SyncOnce(ctx)
	if err == nil || !res.FailedClosed || len(app.scripts) != applied+1 {
		t.Fatalf("long outage = %+v err=%v scripts=%d", res, err, len(app.scripts))
	}
	if strings.Contains(app.scripts[len(app.scripts)-1], "add element") {
		t.Fatal("fail-closed script still contains elements")
	}
}

func TestSyncerFailsClosedWhenNeverSynced(t *testing.T) {
	src := &fakeSource{err: errors.New("database down")}
	app := &fakeApplier{}
	syncer := &Syncer{Source: src, Applier: app, Table: "guardian_gw", ServiceIDs: allServices, StaleTTL: time.Minute}
	res, err := syncer.SyncOnce(context.Background())
	if err == nil || !res.FailedClosed || len(app.scripts) != 1 {
		t.Fatalf("cold failure = %+v err=%v scripts=%d", res, err, len(app.scripts))
	}
}

func TestSyncerKeepsRetryingWhenApplyFails(t *testing.T) {
	src := &fakeSource{snap: store.ServiceAccessSnapshot{
		PolicyRevision: 1, Targets: []store.ServiceAccessTarget{target("10.77.0.2", "sunkardav")},
	}}
	app := &fakeApplier{err: errors.New("nft unavailable")}
	syncer := &Syncer{Source: src, Applier: app, Table: "guardian_gw", ServiceIDs: allServices, StaleTTL: time.Minute}
	if _, err := syncer.SyncOnce(context.Background()); err == nil {
		t.Fatal("apply failure not reported")
	}
	// A failed apply must not be remembered as applied.
	app.err = nil
	res, err := syncer.SyncOnce(context.Background())
	if err != nil || !res.Changed || len(app.scripts) != 1 {
		t.Fatalf("retry = %+v err=%v scripts=%d", res, err, len(app.scripts))
	}
}

func TestSyncerResyncsUnchangedPolicyAfterInterval(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	src := &fakeSource{snap: store.ServiceAccessSnapshot{
		PolicyRevision: 1, Targets: []store.ServiceAccessTarget{target("10.77.0.2", "sunkardav")},
	}}
	app := &fakeApplier{}
	syncer := &Syncer{
		Source: src, Applier: app, Table: "guardian_gw", ServiceIDs: allServices,
		StaleTTL: time.Minute, ResyncInterval: 30 * time.Second, Now: func() time.Time { return now },
	}
	ctx := context.Background()
	if _, err := syncer.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}
	now = now.Add(5 * time.Second)
	res, _ := syncer.SyncOnce(ctx)
	if res.Changed || len(app.scripts) != 1 {
		t.Fatalf("applied again before resync interval: scripts=%d", len(app.scripts))
	}
	// The gateway ruleset may have been reloaded, which empties the sets.
	now = now.Add(31 * time.Second)
	res, err := syncer.SyncOnce(ctx)
	if err != nil || res.Changed || len(app.scripts) != 2 {
		t.Fatalf("resync = %+v err=%v scripts=%d", res, err, len(app.scripts))
	}
}
