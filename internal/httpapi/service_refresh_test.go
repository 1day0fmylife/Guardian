package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/1day0fmylife/Guardian/internal/security"
	"github.com/1day0fmylife/Guardian/internal/store"
	"golang.org/x/net/websocket"
)

func TestPolicyHintsKeepNewestRevisionAndDoNotHideCommands(t *testing.T) {
	hub := newDeviceSignalHub()
	sub, cancel := hub.subscribe("a")
	defer cancel()
	other, cancelOther := hub.subscribe("b")
	defer cancelOther()
	hub.publish("a", deviceSignal{Type: "commands_available"})
	for _, revision := range []int64{4, 9, 5, 9} {
		hub.publishPolicy("a", revision)
	}
	if got := hub.policyRevision(sub); got != 9 {
		t.Fatalf("revision = %d", got)
	}
	select {
	case <-sub.policy:
	default:
		t.Fatal("missing policy hint")
	}
	select {
	case <-sub.policy:
		t.Fatal("hints not coalesced")
	default:
	}
	select {
	case <-sub.wake:
	default:
		t.Fatal("command wake lost")
	}
	select {
	case <-other.policy:
		t.Fatal("targeted policy hint leaked")
	default:
	}
	hub.publishPolicy("", 10)
	if hub.policyRevision(sub) != 10 || hub.policyRevision(other) != 10 {
		t.Fatal("catalog broadcast missing")
	}
}

func TestPolicyExpiryAndWebSocketGrantRefresh(t *testing.T) {
	h := newAPIHarness(t)
	device, token := h.enrollDevice()
	server := New(h.st, "https://guardian.test", time.Hour)
	h.handler = server.WebSocketHandler(server.AdminHandler())
	ts := httptest.NewServer(h.handler)
	defer ts.Close()
	config, err := websocket.NewConfig("ws"+strings.TrimPrefix(ts.URL, "http")+"/api/v1/device/ws", ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	config.Header.Set("Authorization", "Guardian-Device "+token)
	conn, err := websocket.DialConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	receive := func(want string) deviceSignal {
		t.Helper()
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		var signal deviceSignal
		if err := websocket.JSON.Receive(conn, &signal); err != nil {
			t.Fatal(err)
		}
		if signal.Type != want {
			t.Fatalf("signal = %+v, want %s", signal, want)
		}
		return signal
	}
	receive("ready")
	receive("commands_available")
	initial := receive("policy_changed")
	h.enableService("sunkardav")
	enabled := receive("policy_changed")
	if enabled.Revision <= initial.Revision {
		t.Fatal("catalog revision did not advance")
	}
	h.grant("sunkardav", "device", device.ID, "allow", http.StatusCreated)
	granted := receive("policy_changed")
	if granted.Revision <= enabled.Revision {
		t.Fatal("grant revision did not advance")
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/device/services", nil)
	req.Header.Set("Authorization", "Guardian-Device "+token)
	response := httptest.NewRecorder()
	h.handler.ServeHTTP(response, req)
	if response.Code != 200 || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("policy response = %d %v", response.Code, response.Header())
	}
	var policy struct {
		Revision     int64             `json:"revision"`
		GeneratedAt  time.Time         `json:"generated_at"`
		ExpiresAt    time.Time         `json:"expires_at"`
		MandatoryVPN bool              `json:"mandatory_vpn"`
		Services     []json.RawMessage `json:"services"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &policy); err != nil {
		t.Fatal(err)
	}
	if !policy.MandatoryVPN || policy.ExpiresAt.Sub(policy.GeneratedAt) != 5*time.Minute || len(policy.Services) != 1 || policy.Revision != granted.Revision {
		t.Fatalf("policy = %+v", policy)
	}
	h.grant("sunkardav", "device", device.ID, "deny", http.StatusCreated)
	denied := receive("policy_changed")
	if denied.Revision <= granted.Revision || len(h.devicePolicy(token).Services) != 0 {
		t.Fatal("deny did not remove service")
	}
	sub, cancel := signalHubFor(server).subscribe(device.ID)
	defer cancel()
	// Idempotent retries and rejected mutations do not generate policy hints.
	h.grant("sunkardav", "device", device.ID, "deny", http.StatusOK)
	h.mustDo(http.MethodPost, "/api/v1/services/sunkardav/grants", "", "", map[string]any{"scope_type": "device", "scope_id": device.ID, "effect": "allow"}, http.StatusUnauthorized, nil)
	select {
	case <-sub.policy:
		t.Fatal("unchanged or rejected mutation sent a hint")
	default:
	}
	// Changes written outside this HTTP server remain visible through durable polling.
	before, _ := h.st.ServicePolicyRevision(context.Background())
	_, err = h.st.SetServiceGrant(context.Background(), store.AuditMeta{}, "sunkardav", "device", device.ID, "allow")
	if err != nil {
		t.Fatal(err)
	}
	after, _ := h.st.ServicePolicyRevision(context.Background())
	if after <= before {
		t.Fatal("durable revision did not advance")
	}
	if err := server.refreshDeviceSignalState(context.Background(), device.ID, security.HashToken(token)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-sub.policy:
	default:
		t.Fatal("durable revision hint missing")
	}
	if err := h.st.RevokeDeviceCredentials(context.Background(), device.ID); err != nil {
		t.Fatal(err)
	}
	if err := server.refreshDeviceSignalState(context.Background(), device.ID, security.HashToken(token)); err == nil {
		t.Fatal("revoked credential accepted by keepalive refresh")
	}
}

func TestLifecycleChangesWakePolicyRefresh(t *testing.T) {
	h := newAPIHarness(t)
	device, token := h.enrollDevice()
	server := New(h.st, "https://guardian.test", time.Hour)
	h.handler = server.WebSocketHandler(server.AdminHandler())
	h.enableService("sunkardav")
	h.grant("sunkardav", "device", device.ID, "allow", http.StatusCreated)
	sub, cancel := signalHubFor(server).subscribe(device.ID)
	defer cancel()
	var revision int64
	for _, action := range []string{"suspend", "resume", "revoke"} {
		h.mustDo(http.MethodPost, "/api/v1/devices/"+device.ID+"/"+action, "", h.admin, nil, http.StatusAccepted, nil)
		select {
		case <-sub.policy:
		default:
			t.Fatalf("%s missing policy hint", action)
		}
		next := signalHubFor(server).policyRevision(sub)
		if next <= revision {
			t.Fatalf("%s revision %d <= %d", action, next, revision)
		}
		revision = next
		p := h.devicePolicy(token)
		if action != "resume" && len(p.Services) != 0 {
			t.Fatalf("%s retained services", action)
		}
	}
}
