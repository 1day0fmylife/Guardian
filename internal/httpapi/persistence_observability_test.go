package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/1day0fmylife/Guardian/internal/domain"
	"github.com/1day0fmylife/Guardian/internal/gatewayacl"
	"github.com/1day0fmylife/Guardian/internal/security"
	"github.com/1day0fmylife/Guardian/internal/store"
	"github.com/1day0fmylife/Guardian/internal/wireguard"
)

func TestDatabaseOutageRecoveryDoesNotRestoreRevokedAccess(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := context.Background()
			dsn := "sqlite://" + filepath.Join(t.TempDir(), "failover.db")
			if dialect == "postgres" {
				base := os.Getenv("GUARDIAN_TEST_POSTGRES_URL")
				if base == "" {
					t.Skip("GUARDIAN_TEST_POSTGRES_URL is not set")
				}
				admin, err := store.Open(ctx, base)
				if err != nil {
					t.Fatal(err)
				}
				id, err := security.NewID()
				if err != nil {
					t.Fatal(err)
				}
				schema := "g07_" + strings.ReplaceAll(id, "-", "")
				if _, err := admin.DB().ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _, _ = admin.DB().ExecContext(ctx, "DROP SCHEMA "+schema+" CASCADE"); _ = admin.Close() })
				u, err := url.Parse(base)
				if err != nil {
					t.Fatal(err)
				}
				q := u.Query()
				q.Set("search_path", schema)
				u.RawQuery = q.Encode()
				dsn = u.String()
			}
			open := func() *store.Store {
				t.Helper()
				st, err := store.Open(ctx, dsn)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = st.Close() })
				if err := st.Migrate(ctx); err != nil {
					t.Fatal(err)
				}
				if err := st.SeedRBAC(ctx); err != nil {
					t.Fatal(err)
				}
				return st
			}
			st := open()
			api := New(st, "https://guardian.test", time.Hour)
			h := &apiHarness{t: t, st: st, handler: api.AdminHandler()}
			var boot struct {
				Token string `json:"token"`
			}
			h.mustDo(http.MethodPost, "/api/v1/auth/bootstrap", "", "", map[string]any{"username": "outage-admin", "display_name": "Outage admin", "password": "long outage test password"}, http.StatusCreated, &boot)
			h.admin = boot.Token
			a, token := h.enrollDevice()
			b, _ := h.enrollDevice()
			h.enableService("sunkardav")
			h.mustDo(http.MethodPost, "/api/v1/services/sunkardav/grants", "", h.admin, map[string]any{"scope_type": "device", "scope_id": a.ID, "effect": "allow"}, http.StatusCreated, nil)
			if p := h.devicePolicy(token); p.ids() != "sunkardav" {
				t.Fatalf("pre-outage grants = %s, want sunkardav", p.ids())
			}
			pending, err := st.ListPendingWireGuardReconciliations(ctx, 10)
			if err != nil {
				t.Fatal(err)
			}
			for _, peer := range pending {
				if err := st.MarkWireGuardPeerApplied(ctx, peer.PeerID, peer.ConfigRevision); err != nil {
					t.Fatal(err)
				}
			}
			allowed, err := st.ServiceAccessSnapshot(ctx)
			if err != nil || len(allowed.Targets) != 1 {
				t.Fatalf("initial ACL targets = %d, %v; want 1", len(allowed.Targets), err)
			}
			target := allowed.Targets[0]
			applier := &outageApplier{}
			now := time.Now()
			syncer := &gatewayacl.Syncer{Source: st, Applier: applier, Table: "guardian_gw", ServiceIDs: domain.KnownServiceIDs(), StaleTTL: time.Second, Now: func() time.Time { return now }, Observer: outageObserver{peer: wireguard.ObservedPeer{PublicKey: target.PublicKey, AllowedIPs: []netip.Prefix{netip.PrefixFrom(target.Address, 32)}}}}
			if _, err := syncer.SyncOnce(ctx); err != nil || !strings.Contains(applier.script, "add element") {
				t.Fatalf("initial ACL projection failed: %v", err)
			}
			h.mustDo(http.MethodPost, "/api/v1/devices/"+a.ID+"/revoke", "", h.admin, nil, http.StatusAccepted, nil)
			_ = st.Close()
			now = now.Add(2 * time.Second)
			result, err := syncer.SyncOnce(ctx)
			if err == nil || !result.FailedClosed || strings.Contains(applier.script, "add element") {
				t.Fatalf("database outage ACL = %+v, %v; want fail-closed flush", result, err)
			}
			h.mustDo(http.MethodGet, "/readyz", "", "", nil, http.StatusServiceUnavailable, nil)
			code, body := h.do(http.MethodGet, "/api/v1/device/services", "Guardian-Device", token, nil)
			if code < 400 || strings.Contains(string(body), `"services"`) {
				t.Fatalf("outage policy = %d, want denial without service endpoints", code)
			}
			scrape := httptest.NewRecorder()
			api.Metrics().Handler(st).ServeHTTP(scrape, httptest.NewRequest("GET", "/metrics", nil))
			if !strings.Contains(scrape.Body.String(), "guardian_database_up 0") || strings.Contains(scrape.Body.String(), token) {
				t.Fatal("DB outage scrape not safe")
			}
			st = open()
			api = New(st, "https://guardian.test", time.Hour)
			h.st = st
			h.handler = api.AdminHandler()
			syncer.Source = st
			if _, err := syncer.SyncOnce(ctx); err != nil || strings.Contains(applier.script, "add element") {
				t.Fatalf("recovery restored revoked ACL: %v", err)
			}
			h.mustDo(http.MethodGet, "/readyz", "", "", nil, http.StatusOK, nil)
			recoveredPolicy := h.devicePolicy(token)
			if recoveredPolicy.AccessState != "revoking" || len(recoveredPolicy.Services) != 0 {
				t.Fatalf("restart policy = %+v, want revoking without endpoints", recoveredPolicy)
			}
			policy, err := st.AdminDevicePolicy(ctx, a.ID)
			if err != nil || policy.AccessState != "revoking" {
				t.Fatalf("revoked state after restart = %s, %v", policy.AccessState, err)
			}
			snapshot, err := st.ServiceAccessSnapshot(ctx)
			if err != nil || len(snapshot.Targets) != 0 {
				t.Fatalf("recovery snapshot targets = %d, %v; want none", len(snapshot.Targets), err)
			}
			other, err := st.DeviceServicePolicy(ctx, b.ID)
			if err != nil || len(other.Services) != 0 {
				t.Fatalf("ungranted device policy = %d, %v; want none", len(other.Services), err)
			}
		})
	}
}

func TestPolicyMetricsNeverExposeCredentialsOrIdentifiers(t *testing.T) {
	h := newAPIHarness(t)
	// Use a single Server for both the device policy and metrics recorder.
	api := New(h.st, "https://guardian.test", time.Hour)
	h.handler = api.AdminHandler()
	device, token := h.enrollDevice()
	h.mustDo(http.MethodGet, "/api/v1/device/services", "Guardian-Device", token, nil, http.StatusOK, nil)
	h.mustDo(http.MethodGet, "/api/v1/device/services", "", "", nil, http.StatusUnauthorized, nil)
	rec := httptest.NewRecorder()
	api.Metrics().Handler(h.st).ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	for _, secret := range []string{token, h.admin, device.ID, device.DeviceUUID, "dav.internal"} {
		if strings.Contains(rec.Body.String(), secret) {
			t.Fatalf("metrics expose sensitive fixture data")
		}
	}
	if !strings.Contains(rec.Body.String(), `guardian_service_access_denials_total{service="sunkardav",reason="service_disabled"} 1`) || !strings.Contains(rec.Body.String(), "guardian_policy_auth_denials_total 1") {
		t.Fatal("denied policy/auth requests not measured")
	}
	h.mustDo(http.MethodGet, "/metrics", "", "", nil, http.StatusNotFound, nil)
}

type outageApplier struct{ script string }

func (a *outageApplier) Apply(_ context.Context, script string) error { a.script = script; return nil }

type outageObserver struct{ peer wireguard.ObservedPeer }

func (o outageObserver) ObservePeers(context.Context) ([]wireguard.ObservedPeer, error) {
	return []wireguard.ObservedPeer{o.peer}, nil
}
