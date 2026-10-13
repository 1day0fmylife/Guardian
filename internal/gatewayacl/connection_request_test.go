package gatewayacl

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/1day0fmylife/Guardian/internal/store"
)

func TestConnectionRequestProjectionRequiresMatchingACSGrant(t *testing.T) {
	good := target("10.77.0.2", "sunkarcwmp-acs")
	good.CWMPConnectionRequestSource = "10.78.0.12"
	other := target("10.77.0.3", "sunkardav")
	other.CWMPConnectionRequestSource = "10.78.0.12"
	mismatch := target("10.77.0.4", "sunkarcwmp-acs")
	mismatch.CWMPConnectionRequestSource = "10.78.0.11"
	script, err := RenderConnectionRequests("guardian_gw", "10.78.0.12", []store.ServiceAccessTarget{other, good, mismatch, good})
	if err != nil || strings.Count(script, "10.77.0.2") != 1 || strings.Contains(script, "10.77.0.3") || strings.Contains(script, "10.77.0.4") {
		t.Fatalf("CR projection = %q, %v", script, err)
	}
	empty, err := RenderConnectionRequests("guardian_gw", "10.78.0.12", nil)
	if err != nil || strings.Contains(empty, "add element") {
		t.Fatalf("revoked projection = %q, %v", empty, err)
	}
	for _, source := range []string{"8.8.8.8", "10.78.0.0/24", "::ffff:10.78.0.12"} {
		if _, err := RenderConnectionRequests("guardian_gw", source, nil); err == nil {
			t.Errorf("accepted source %s", source)
		}
	}
}

func TestConnectionRequestSourceOutageFlushesBothCapabilities(t *testing.T) {
	now := time.Now()
	peer := target("10.77.0.2", "sunkarcwmp-acs")
	peer.CWMPConnectionRequestSource = "10.78.0.12"
	src := &fakeSource{snap: store.ServiceAccessSnapshot{PolicyRevision: 1, Targets: []store.ServiceAccessTarget{peer}}}
	app := &fakeApplier{}
	syncer := &Syncer{Source: src, Applier: app, Table: "guardian_gw", ServiceIDs: allServices, ConnectionRequestSource: "10.78.0.12", StaleTTL: time.Second, Now: func() time.Time { return now }}
	if _, err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	src.err = errors.New("database unavailable")
	now = now.Add(2 * time.Second)
	result, err := syncer.SyncOnce(context.Background())
	if err == nil || !result.FailedClosed {
		t.Fatalf("outage result = %+v, %v", result, err)
	}
	last := app.scripts[len(app.scripts)-1]
	if !strings.Contains(last, "flush set inet guardian_gw cwmp_cr_v4") || strings.Contains(last, "add element") {
		t.Fatalf("stale reverse capability retained: %s", last)
	}
}
