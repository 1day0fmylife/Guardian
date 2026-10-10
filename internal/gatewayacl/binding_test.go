package gatewayacl

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/1day0fmylife/Guardian/internal/store"
	"github.com/1day0fmylife/Guardian/internal/wireguard"
)

func bound(device, key, addr string, services ...string) store.ServiceAccessTarget {
	return store.ServiceAccessTarget{
		DeviceID: device, PeerID: "peer-" + device, PublicKey: key, Address: netip.MustParseAddr(addr),
		ConfigRevision: 3, AppliedRevision: 3, ServiceIDs: services,
	}
}

func peer(key string, allowed ...string) wireguard.ObservedPeer {
	p := wireguard.ObservedPeer{PublicKey: key}
	for _, a := range allowed {
		p.AllowedIPs = append(p.AllowedIPs, netip.MustParsePrefix(a))
	}
	return p
}

func reasons(rejected []Rejection) map[string]string {
	out := map[string]string{}
	for _, r := range rejected {
		out[r.DeviceID] = r.Reason
	}
	return out
}

func TestVerifyBindingsAcceptsOnlyMatchingKernelState(t *testing.T) {
	targets := []store.ServiceAccessTarget{
		bound("ok", "KEY-OK", "10.77.0.2", "sunkardav"),
		bound("removed", "KEY-REMOVED", "10.77.0.3", "sunkardav"),
		bound("rotated", "KEY-NEW", "10.77.0.4", "sunkardav"),
		bound("moved", "KEY-MOVED", "10.77.0.5", "sunkardav"),
		bound("wide", "KEY-WIDE", "10.77.0.6", "sunkardav"),
		bound("extra", "KEY-EXTRA", "10.77.0.7", "sunkardav"),
		bound("noroute", "KEY-NOROUTE", "10.77.0.8", "sunkardav"),
	}
	observed := []wireguard.ObservedPeer{
		peer("KEY-OK", "10.77.0.2/32"),
		// removed: not present
		peer("KEY-OLD", "10.77.0.4/32"),    // rotated: kernel still has the previous key
		peer("KEY-MOVED", "10.77.0.99/32"), // address differs from Guardian's record
		peer("KEY-WIDE", "10.77.0.0/24"),   // whole subnet: lateral movement
		peer("KEY-EXTRA", "10.77.0.7/32", "10.77.0.50/32"),
		peer("KEY-NOROUTE"),                  // no allowed-ips at all
		peer("KEY-UNKNOWN", "10.77.0.77/32"), // not a Guardian device
	}

	verified, rejected, unexpected := VerifyBindings(targets, observed)
	if len(verified) != 1 || verified[0].DeviceID != "ok" {
		t.Fatalf("verified = %+v", verified)
	}
	want := map[string]string{
		"removed": RejectPeerNotInterface, "rotated": RejectPeerNotInterface,
		"moved": RejectAllowedIPsMismatch, "wide": RejectAllowedIPsMismatch,
		"extra": RejectAllowedIPsMismatch, "noroute": RejectAllowedIPsMismatch,
	}
	got := reasons(rejected)
	for device, reason := range want {
		if got[device] != reason {
			t.Errorf("rejection[%s] = %q, want %q", device, got[device], reason)
		}
	}
	if len(got) != len(want) {
		t.Errorf("rejections = %v", got)
	}
	// KEY-OLD is unknown to Guardian too; neither unknown key gets a grant.
	if strings.Join(unexpected, ",") != "KEY-OLD,KEY-UNKNOWN" {
		t.Errorf("unexpected = %v", unexpected)
	}
}

func TestVerifyBindingsDeniesReassignedAddressUntilKernelCatchesUp(t *testing.T) {
	// Guardian reassigned 10.77.0.9 to the new device, but the kernel still
	// routes it to the previous owner's key. The old key holder must not
	// inherit the new device's grants, and the new device is not honored
	// until its own peer owns the address.
	targets := []store.ServiceAccessTarget{bound("new-device", "KEY-NEW", "10.77.0.9", "sunkardav")}
	staleKernel := []wireguard.ObservedPeer{peer("KEY-PREVIOUS-OWNER", "10.77.0.9/32")}
	verified, rejected, _ := VerifyBindings(targets, staleKernel)
	if len(verified) != 0 || reasons(rejected)["new-device"] != RejectPeerNotInterface {
		t.Fatalf("stale kernel: verified=%+v rejected=%+v", verified, rejected)
	}
	// Both keys present and both claim the address.
	overlap := []wireguard.ObservedPeer{peer("KEY-PREVIOUS-OWNER", "10.77.0.9/32"), peer("KEY-NEW", "10.77.0.9/32")}
	verified, rejected, _ = VerifyBindings(targets, overlap)
	if len(verified) != 0 || reasons(rejected)["new-device"] != RejectAddressClaimedByOther {
		t.Fatalf("overlap: verified=%+v rejected=%+v", verified, rejected)
	}
	// Once the kernel matches the record the grant applies.
	synced := []wireguard.ObservedPeer{peer("KEY-NEW", "10.77.0.9/32")}
	verified, _, _ = VerifyBindings(targets, synced)
	if len(verified) != 1 {
		t.Fatalf("synced: verified=%+v", verified)
	}
}

type fakeObserver struct {
	peers []wireguard.ObservedPeer
	err   error
}

func (f *fakeObserver) ObservePeers(context.Context) ([]wireguard.ObservedPeer, error) {
	return f.peers, f.err
}

func TestSyncerOnlyProjectsVerifiedBindings(t *testing.T) {
	src := &fakeSource{snap: store.ServiceAccessSnapshot{
		PolicyRevision: 4, AddressConflicts: 1,
		Targets: []store.ServiceAccessTarget{
			bound("a", "KEY-A", "10.77.0.2", "sunkardav"),
			bound("b", "KEY-B", "10.77.0.3", "sunkardav"),
		},
	}}
	app := &fakeApplier{}
	obs := &fakeObserver{peers: []wireguard.ObservedPeer{peer("KEY-A", "10.77.0.2/32")}}
	syncer := &Syncer{
		Source: src, Applier: app, Observer: obs, Table: "guardian_gw", ServiceIDs: allServices, StaleTTL: time.Minute,
	}

	res, err := syncer.SyncOnce(context.Background())
	if err != nil {
		t.Fatalf("SyncOnce: %v", err)
	}
	script := app.scripts[len(app.scripts)-1]
	if !strings.Contains(script, "10.77.0.2") || strings.Contains(script, "10.77.0.3") {
		t.Fatalf("script projects unverified peer:\n%s", script)
	}
	if res.Targets != 1 || len(res.Rejected) != 1 || res.Rejected[0].DeviceID != "b" || res.AddressConflicts != 1 {
		t.Fatalf("result = %+v", res)
	}

	// The kernel peer for b appears: the grant is applied on the next pass.
	obs.peers = append(obs.peers, peer("KEY-B", "10.77.0.3/32"))
	if _, err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatalf("second sync: %v", err)
	}
	if !strings.Contains(app.scripts[len(app.scripts)-1], "10.77.0.3") {
		t.Fatal("verified peer was not projected")
	}

	// Peer removed from the kernel (revocation/disconnect): access is
	// withdrawn even though the database still lists the device as active.
	obs.peers = obs.peers[:1]
	if _, err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatalf("third sync: %v", err)
	}
	if strings.Contains(app.scripts[len(app.scripts)-1], "10.77.0.3") {
		t.Fatal("removed peer kept its grant")
	}
}

func TestSyncerFailsClosedWhenKernelStateUnreadable(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	src := &fakeSource{snap: store.ServiceAccessSnapshot{
		Targets: []store.ServiceAccessTarget{bound("a", "KEY-A", "10.77.0.2", "sunkardav")},
	}}
	app := &fakeApplier{}
	obs := &fakeObserver{err: errors.New("netlink unavailable")}
	syncer := &Syncer{
		Source: src, Applier: app, Observer: obs, Table: "guardian_gw", ServiceIDs: allServices,
		StaleTTL: 30 * time.Second, Now: func() time.Time { return now },
	}
	res, err := syncer.SyncOnce(context.Background())
	if err == nil || !res.FailedClosed {
		t.Fatalf("cold observer failure = %+v err=%v", res, err)
	}
	if strings.Contains(app.scripts[len(app.scripts)-1], "add element") {
		t.Fatal("unverifiable state produced grants")
	}
}

func TestRenderIsOneTransactionForScopeChange(t *testing.T) {
	// A device moving from SunkarDAV to ACS must be expressed as a single
	// script (applied with one `nft -f -`), never as separate flush and add
	// steps, so the unchanged services of other devices never blink.
	before, _ := Render("guardian_gw", allServices, []store.ServiceAccessTarget{target("10.77.0.2", "sunkardav"), target("10.77.0.3", "admiral-device")})
	after, _ := Render("guardian_gw", allServices, []store.ServiceAccessTarget{target("10.77.0.2", "sunkarcwmp-acs"), target("10.77.0.3", "admiral-device")})
	if before == after {
		t.Fatal("scope change not reflected")
	}
	for _, id := range allServices {
		if !strings.Contains(after, "flush set inet guardian_gw "+SetName(id)) {
			t.Fatalf("script does not cover %s in the same transaction:\n%s", id, after)
		}
	}
	if strings.Contains(after, "delete") || strings.Contains(after, "table inet guardian_gw {") {
		t.Fatalf("script must only replace set contents:\n%s", after)
	}
}
