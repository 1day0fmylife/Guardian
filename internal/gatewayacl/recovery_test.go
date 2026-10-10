package gatewayacl

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/1day0fmylife/Guardian/internal/store"
)

func TestStaleRevisionCannotRestoreRevokedAccess(t *testing.T) {
	source := &fakeSource{snap: store.ServiceAccessSnapshot{PolicyRevision: 10}}
	applier := &fakeApplier{}
	syncer := &Syncer{Source: source, Applier: applier, Table: "guardian_gw", ServiceIDs: allServices, StaleTTL: time.Minute}
	if _, err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	source.snap = store.ServiceAccessSnapshot{PolicyRevision: 9, Targets: []store.ServiceAccessTarget{target("10.77.0.2", "sunkardav")}}
	result, err := syncer.SyncOnce(context.Background())
	if err == nil || !result.FailedClosed {
		t.Fatalf("stale result=%+v err=%v", result, err)
	}
	if strings.Contains(applier.scripts[len(applier.scripts)-1], "add element") {
		t.Fatal("stale revision reopened service")
	}
	source.snap.PolicyRevision = 11
	if _, err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestLeaseRenewalAndRestartRecovery(t *testing.T) {
	now := time.Now()
	source := &fakeSource{snap: store.ServiceAccessSnapshot{PolicyRevision: 2, Targets: []store.ServiceAccessTarget{target("10.77.0.2", "sunkardav")}}}
	applier := &fakeApplier{}
	syncer := &Syncer{Source: source, Applier: applier, Table: "guardian_gw", ServiceIDs: allServices, ResyncInterval: time.Hour, Now: func() time.Time { return now }}
	if _, err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(applier.scripts[0], "timeout 30s") {
		t.Fatal("membership is not leased")
	}
	now = now.Add(10 * time.Second)
	if _, err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(applier.scripts) != 2 {
		t.Fatal("large resync interval disabled lease renewal")
	}
	// Controller memory is lost; durable revoked state must replace kernel ACL.
	source.snap = store.ServiceAccessSnapshot{PolicyRevision: 3}
	restarted := &Syncer{Source: source, Applier: applier, Table: "guardian_gw", ServiceIDs: allServices}
	if _, err := restarted.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(applier.scripts[2], "add element") {
		t.Fatal("restart restored revoked access")
	}
}

func TestFailedFlushDoesNotClaimFailClosedAndRetries(t *testing.T) {
	source := &fakeSource{err: errors.New("database unavailable")}
	applier := &fakeApplier{err: errors.New("nft unavailable")}
	syncer := &Syncer{Source: source, Applier: applier, Table: "guardian_gw", ServiceIDs: allServices}
	result, err := syncer.SyncOnce(context.Background())
	if err == nil || result.FailedClosed {
		t.Fatalf("false fail-closed success: %+v %v", result, err)
	}
	applier.err = nil
	result, err = syncer.SyncOnce(context.Background())
	if err == nil || !result.FailedClosed || len(applier.scripts) != 1 {
		t.Fatalf("retry=%+v err=%v", result, err)
	}
}

func TestFailedNewRevisionStillPreventsOlderSnapshotReplay(t *testing.T) {
	source := &fakeSource{snap: store.ServiceAccessSnapshot{PolicyRevision: 20}}
	applier := &fakeApplier{}
	syncer := &Syncer{Source: source, Applier: applier, Table: "guardian_gw", ServiceIDs: allServices, StaleTTL: time.Minute}
	if _, err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	source.snap.PolicyRevision = 22
	applier.err = errors.New("apply failed")
	source.snap.Targets = []store.ServiceAccessTarget{target("10.77.0.2", "sunkardav")}
	if _, err := syncer.SyncOnce(context.Background()); err == nil {
		t.Fatal("failed apply accepted")
	}
	applier.err = nil
	source.snap.PolicyRevision = 21
	result, err := syncer.SyncOnce(context.Background())
	if err == nil || !result.FailedClosed {
		t.Fatalf("rollback after apply failure=%+v err=%v", result, err)
	}
	if strings.Contains(applier.scripts[len(applier.scripts)-1], "add element") {
		t.Fatal("older policy replayed")
	}
}

type acknowledgedSource struct {
	fakeSource
	acknowledgements []int64
}

func (s *acknowledgedSource) RecordServiceACLApplied(_ context.Context, revision int64) error {
	s.acknowledgements = append(s.acknowledgements, revision)
	return nil
}
func TestOnlySuccessfulApplyAcknowledgesPolicy(t *testing.T) {
	source := &acknowledgedSource{fakeSource: fakeSource{snap: store.ServiceAccessSnapshot{PolicyRevision: 3}}}
	applier := &fakeApplier{err: errors.New("nft down")}
	syncer := &Syncer{Source: source, Applier: applier, Table: "guardian_gw", ServiceIDs: allServices}
	if _, err := syncer.SyncOnce(context.Background()); err == nil {
		t.Fatal("failed apply accepted")
	}
	if len(source.acknowledgements) != 0 {
		t.Fatal("failed apply acknowledged")
	}
	applier.err = nil
	if _, err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(source.acknowledgements) != 1 || source.acknowledgements[0] != 3 {
		t.Fatalf("acknowledgements=%v", source.acknowledgements)
	}
}
