package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/1day0fmylife/Guardian/internal/domain"
	"github.com/1day0fmylife/Guardian/internal/store"
)

type apiHarness struct {
	t       *testing.T
	st      *store.Store
	handler http.Handler
	admin   string // superadmin session token
}

func newAPIHarness(t *testing.T) *apiHarness {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, "sqlite://:memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if err := st.SeedRBAC(ctx); err != nil {
		t.Fatalf("SeedRBAC: %v", err)
	}
	h := &apiHarness{t: t, st: st, handler: New(st, "https://guardian.test", time.Hour).AdminHandler()}

	var boot struct {
		Token string `json:"token"`
	}
	h.mustDo(http.MethodPost, "/api/v1/auth/bootstrap", "", "", map[string]any{
		"username": "root", "display_name": "Root", "password": "a sufficiently long root password",
	}, http.StatusCreated, &boot)
	h.admin = boot.Token
	return h
}

func (h *apiHarness) do(method, path, scheme, token string, body any) (int, []byte) {
	h.t.Helper()
	var reader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			h.t.Fatalf("marshal: %v", err)
		}
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	req.RemoteAddr = "192.0.2.50:4000"
	if token != "" {
		if scheme == "" {
			scheme = "Bearer"
		}
		req.Header.Set("Authorization", scheme+" "+token)
	}
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes()
}

func (h *apiHarness) mustDo(method, path, scheme, token string, body any, want int, out any) {
	h.t.Helper()
	status, raw := h.do(method, path, scheme, token, body)
	if status != want {
		h.t.Fatalf("%s %s = %d, want %d: %s", method, path, status, want, raw)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			h.t.Fatalf("decode %s %s: %v: %s", method, path, err, raw)
		}
	}
}

func (h *apiHarness) errorCode(method, path, token string, body any, wantStatus int) string {
	h.t.Helper()
	status, raw := h.do(method, path, "Bearer", token, body)
	if status != wantStatus {
		h.t.Fatalf("%s %s = %d, want %d: %s", method, path, status, wantStatus, raw)
	}
	var env struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(raw, &env)
	return env.Error.Code
}

// userToken creates a user with one role and returns its session token.
func (h *apiHarness) userToken(username, role string) string {
	h.t.Helper()
	h.mustDo(http.MethodPost, "/api/v1/users", "", h.admin, map[string]any{
		"username": username, "display_name": username,
		"password": "a sufficiently long password for " + username, "roles": []string{role},
	}, http.StatusCreated, nil)
	var login struct {
		Token string `json:"token"`
	}
	h.mustDo(http.MethodPost, "/api/v1/auth/login", "", "", map[string]any{
		"username": username, "password": "a sufficiently long password for " + username,
	}, http.StatusOK, &login)
	return login.Token
}

var deviceSeq int

// enrollDevice runs the managed enrollment flow and returns the device and
// its plaintext device credential.
func (h *apiHarness) enrollDevice() (domain.Device, string) {
	h.t.Helper()
	ctx := context.Background()
	deviceSeq++
	n := deviceSeq
	pool, err := h.st.CreateAddressPool(ctx, store.AddressPoolCreate{
		Name: fmt.Sprintf("pool-%d", n), CIDR: fmt.Sprintf("10.%d.0.0/29", 150+n), Gateway: fmt.Sprintf("10.%d.0.1", 150+n),
	})
	if err != nil {
		h.t.Fatalf("CreateAddressPool: %v", err)
	}
	key := func(fill byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{fill}, 32)) }
	profile, err := h.st.CreateVPNProfile(ctx, store.VPNProfileCreate{
		Name: fmt.Sprintf("profile-%d", n), ServerPublicKey: key(byte(n)), Endpoint: "vpn.example.test:51820",
		AllowedIPs: []string{"10.0.0.0/8"}, PersistentKeepalive: 25, AddressPoolID: pool.ID,
	})
	if err != nil {
		h.t.Fatalf("CreateVPNProfile: %v", err)
	}
	uuid := fmt.Sprintf("api-device-%d", n)
	issued, err := h.st.CreateEnrollment(ctx, store.EnrollmentCreate{
		ProfileID: profile.ID, BoundDeviceUUID: uuid, TTL: 10 * time.Minute,
	})
	if err != nil {
		h.t.Fatalf("CreateEnrollment: %v", err)
	}
	claim, err := h.st.ClaimManagedEnrollment(ctx, issued.Token, domain.EnrollmentClaim{
		DeviceUUID: uuid, DeviceName: "API device", PublicKey: key(byte(90 + n)),
	})
	if err != nil {
		h.t.Fatalf("ClaimManagedEnrollment: %v", err)
	}
	return claim.Device, claim.Credential.Token
}

type policyResponse struct {
	DeviceID    string `json:"device_id"`
	AccessState string `json:"access_state"`
	Revision    int64  `json:"revision"`
	Services    []struct {
		ID   string `json:"id"`
		Host string `json:"host"`
		Port int    `json:"port"`
	} `json:"services"`
}

func (p policyResponse) ids() string {
	ids := []string{}
	for _, svc := range p.Services {
		ids = append(ids, svc.ID)
	}
	return strings.Join(ids, ",")
}

func (h *apiHarness) devicePolicy(token string) policyResponse {
	h.t.Helper()
	var p policyResponse
	h.mustDo(http.MethodGet, "/api/v1/device/services", "Guardian-Device", token, nil, http.StatusOK, &p)
	return p
}

func (h *apiHarness) enableService(id string) {
	h.t.Helper()
	var svc domain.ServiceDefinition
	h.mustDo(http.MethodGet, "/api/v1/services/"+id, "", h.admin, nil, http.StatusOK, &svc)
	h.mustDo(http.MethodPut, "/api/v1/services/"+id, "", h.admin, map[string]any{
		"expected_revision": svc.Revision, "display_name": svc.DisplayName, "internal_dns_name": svc.InternalDNSName,
		"protocol": svc.Protocol, "port": svc.Port, "tls_policy": svc.TLSPolicy,
		"allowed_scopes": svc.AllowedScopes, "enabled": true,
	}, http.StatusOK, nil)
}

func (h *apiHarness) grant(service, scopeType, scopeID, effect string, want int) {
	h.t.Helper()
	h.mustDo(http.MethodPost, "/api/v1/services/"+service+"/grants", "", h.admin, map[string]any{
		"scope_type": scopeType, "scope_id": scopeID, "effect": effect,
	}, want, nil)
}

func TestServiceCatalogAuthorizationBoundaries(t *testing.T) {
	h := newAPIHarness(t)
	device, _ := h.enrollDevice()
	viewer := h.userToken("viewer1", "viewer")
	operator := h.userToken("operator1", "operator")
	auditor := h.userToken("auditor1", "auditor")
	admin := h.userToken("admin1", "admin")

	read := []string{
		"/api/v1/services",
		"/api/v1/services/sunkardav",
		"/api/v1/services/sunkardav/revisions",
		"/api/v1/services/sunkardav/grants",
		"/api/v1/devices/" + device.ID + "/services",
		"/api/v1/devices/" + device.ID + "/scopes",
	}
	updateBody := map[string]any{
		"expected_revision": 1, "display_name": "SunkarDAV", "internal_dns_name": "dav.internal",
		"protocol": "https", "port": 443, "allowed_scopes": []string{"device"}, "enabled": true,
	}
	grantBody := map[string]any{"scope_type": "device", "scope_id": device.ID, "effect": "allow"}

	t.Run("anonymous is rejected", func(t *testing.T) {
		for _, path := range read {
			if code := h.errorCode(http.MethodGet, path, "", nil, http.StatusUnauthorized); code != "authentication_required" {
				t.Errorf("GET %s code = %s", path, code)
			}
		}
		h.errorCode(http.MethodPut, "/api/v1/services/sunkardav", "", updateBody, http.StatusUnauthorized)
		h.errorCode(http.MethodPost, "/api/v1/services/sunkardav/grants", "", grantBody, http.StatusUnauthorized)
	})

	t.Run("viewer has no access to the catalog", func(t *testing.T) {
		for _, path := range read {
			if code := h.errorCode(http.MethodGet, path, viewer, nil, http.StatusForbidden); code != "permission_denied" {
				t.Errorf("GET %s code = %s", path, code)
			}
		}
	})

	t.Run("read-only roles cannot mutate", func(t *testing.T) {
		for name, token := range map[string]string{"operator": operator, "auditor": auditor} {
			for _, path := range read {
				h.mustDo(http.MethodGet, path, "", token, nil, http.StatusOK, nil)
			}
			if code := h.errorCode(http.MethodPut, "/api/v1/services/sunkardav", token, updateBody, http.StatusForbidden); code != "permission_denied" {
				t.Errorf("%s PUT service code = %s", name, code)
			}
			h.errorCode(http.MethodPost, "/api/v1/services/sunkardav/grants", token, grantBody, http.StatusForbidden)
			h.errorCode(http.MethodDelete, "/api/v1/services/sunkardav/grants/anything", token, nil, http.StatusForbidden)
			h.errorCode(http.MethodPut, "/api/v1/devices/"+device.ID+"/scopes", token,
				map[string]any{"tenant_id": "acme"}, http.StatusForbidden)
		}
		// Nothing changed behind the rejected requests.
		var svc domain.ServiceDefinition
		h.mustDo(http.MethodGet, "/api/v1/services/sunkardav", "", h.admin, nil, http.StatusOK, &svc)
		if svc.Revision != 1 || svc.Enabled {
			t.Fatalf("service modified by unauthorized caller: %+v", svc)
		}
		var grants struct{ Total int }
		h.mustDo(http.MethodGet, "/api/v1/services/sunkardav/grants?include_revoked=true", "", h.admin, nil, http.StatusOK, &grants)
		if grants.Total != 0 {
			t.Fatalf("grants created by unauthorized caller: %d", grants.Total)
		}
	})

	t.Run("admin role may manage", func(t *testing.T) {
		h.mustDo(http.MethodPut, "/api/v1/services/sunkardav", "", admin, updateBody, http.StatusOK, nil)
	})

	t.Run("custom role without services permissions has no access", func(t *testing.T) {
		h.mustDo(http.MethodPost, "/api/v1/roles", "", h.admin, map[string]any{
			"name": "devices-only", "description": "no services", "permissions": []string{"devices.read", "devices.update"},
		}, http.StatusCreated, nil)
		token := h.userToken("custom1", "devices-only")
		h.errorCode(http.MethodGet, "/api/v1/services", token, nil, http.StatusForbidden)
		h.errorCode(http.MethodPost, "/api/v1/services/sunkardav/grants", token, grantBody, http.StatusForbidden)
	})
}

func TestDeviceEffectivePolicyIsPerDeviceAndSecretFree(t *testing.T) {
	h := newAPIHarness(t)
	deviceA, tokenA := h.enrollDevice()
	deviceB, tokenB := h.enrollDevice()
	h.enableService("sunkardav")
	h.enableService("sunkarcwmp-acs")

	// Deny-by-default: enabled services but no grants.
	if p := h.devicePolicy(tokenA); p.AccessState != "active" || len(p.Services) != 0 {
		t.Fatalf("policy without grants = %+v", p)
	}

	h.grant("sunkardav", "device", deviceA.ID, "allow", http.StatusCreated)
	h.mustDo(http.MethodPut, "/api/v1/devices/"+deviceB.ID+"/scopes", "", h.admin,
		map[string]any{"tenant_id": "acme", "group_ids": []string{"acs-fleet"}}, http.StatusOK, nil)
	h.grant("sunkarcwmp-acs", "group", "acs-fleet", "allow", http.StatusCreated)

	a, b := h.devicePolicy(tokenA), h.devicePolicy(tokenB)
	if a.DeviceID != deviceA.ID || a.ids() != "sunkardav" {
		t.Fatalf("device A policy = %+v", a)
	}
	if b.DeviceID != deviceB.ID || b.ids() != "sunkarcwmp-acs" {
		t.Fatalf("device B policy = %+v", b)
	}
	if a.Revision != b.Revision || a.Revision < 2 {
		t.Fatalf("revisions = %d/%d", a.Revision, b.Revision)
	}

	t.Run("response is non-secret", func(t *testing.T) {
		status, raw := h.do(http.MethodGet, "/api/v1/device/services", "Guardian-Device", tokenA, nil)
		if status != http.StatusOK {
			t.Fatalf("status = %d", status)
		}
		body := string(raw)
		for _, secret := range []string{tokenA, tokenB, "gdn_", "password", "secret", "credential", "token", "private", "created_by", "actor"} {
			if strings.Contains(strings.ToLower(body), strings.ToLower(secret)) {
				t.Fatalf("device policy leaks %q: %s", secret, body)
			}
		}
		var decoded map[string]any
		_ = json.Unmarshal(raw, &decoded)
		allowedTop := map[string]bool{"device_id": true, "access_state": true, "revision": true, "generated_at": true, "services": true}
		for key := range decoded {
			if !allowedTop[key] {
				t.Errorf("unexpected top-level field %q", key)
			}
		}
		allowedSvc := map[string]bool{"id": true, "display_name": true, "host": true, "port": true, "protocol": true, "tls_policy": true, "revision": true}
		for _, svc := range decoded["services"].([]any) {
			for key := range svc.(map[string]any) {
				if !allowedSvc[key] {
					t.Errorf("unexpected service field %q", key)
				}
			}
		}
	})

	t.Run("credential scheme and principal separation", func(t *testing.T) {
		h.errorCode(http.MethodGet, "/api/v1/device/services", "", nil, http.StatusUnauthorized)
		// An administrator session is not a device credential.
		status, _ := h.do(http.MethodGet, "/api/v1/device/services", "Guardian-Device", h.admin, nil)
		if status != http.StatusUnauthorized {
			t.Fatalf("admin token on device endpoint = %d, want 401", status)
		}
		// A device credential is not an administrator session.
		status, _ = h.do(http.MethodGet, "/api/v1/services", "Bearer", tokenA, nil)
		if status != http.StatusUnauthorized {
			t.Fatalf("device token on admin endpoint = %d, want 401", status)
		}
		status, _ = h.do(http.MethodGet, "/api/v1/services", "Guardian-Device", tokenA, nil)
		if status != http.StatusUnauthorized {
			t.Fatalf("device scheme on admin endpoint = %d, want 401", status)
		}
		// The endpoint is read-only.
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
			status, _ := h.do(method, "/api/v1/device/services", "Guardian-Device", tokenA, map[string]any{})
			if status == http.StatusOK || status == http.StatusCreated {
				t.Errorf("%s on device endpoint = %d", method, status)
			}
		}
	})

	t.Run("admin effective view explains the decision", func(t *testing.T) {
		var view domain.AdminDevicePolicy
		h.mustDo(http.MethodGet, "/api/v1/devices/"+deviceB.ID+"/services", "", h.admin, nil, http.StatusOK, &view)
		reasons := map[string]string{}
		for _, svc := range view.Services {
			reasons[svc.ServiceID] = svc.Reason
		}
		want := map[string]string{"sunkarcwmp-acs": "group_grant", "sunkardav": "no_grant", "admiral-device": "service_disabled"}
		for id, reason := range want {
			if reasons[id] != reason {
				t.Errorf("reason[%s] = %q, want %q", id, reasons[id], reason)
			}
		}
		if view.Scopes.TenantID != "acme" || len(view.Scopes.GroupIDs) != 1 {
			t.Errorf("scopes = %+v", view.Scopes)
		}
	})
}

func TestSuspendedRevokedDeviceAndRevokedGrantLoseAccess(t *testing.T) {
	h := newAPIHarness(t)
	device, token := h.enrollDevice()
	h.enableService("sunkardav")
	h.grant("sunkardav", "device", device.ID, "allow", http.StatusCreated)

	active := h.devicePolicy(token)
	if active.ids() != "sunkardav" {
		t.Fatalf("active policy = %+v", active)
	}

	h.mustDo(http.MethodPost, "/api/v1/devices/"+device.ID+"/suspend", "", h.admin, nil, http.StatusAccepted, nil)
	suspended := h.devicePolicy(token)
	if suspended.AccessState != "suspended" || len(suspended.Services) != 0 || suspended.Revision <= active.Revision {
		t.Fatalf("suspended policy = %+v (active revision %d)", suspended, active.Revision)
	}
	h.mustDo(http.MethodPost, "/api/v1/devices/"+device.ID+"/resume", "", h.admin, nil, http.StatusAccepted, nil)
	if p := h.devicePolicy(token); p.ids() != "sunkardav" {
		t.Fatalf("resumed policy = %+v", p)
	}

	// Revoking the grant takes the service away without touching the device.
	var grants struct {
		Items []domain.ServiceGrant `json:"items"`
	}
	h.mustDo(http.MethodGet, "/api/v1/services/sunkardav/grants", "", h.admin, nil, http.StatusOK, &grants)
	if len(grants.Items) != 1 {
		t.Fatalf("grants = %+v", grants)
	}
	h.mustDo(http.MethodDelete, "/api/v1/services/sunkardav/grants/"+grants.Items[0].ID, "", h.admin, nil, http.StatusOK, nil)
	if p := h.devicePolicy(token); len(p.Services) != 0 || p.AccessState != "active" {
		t.Fatalf("policy after grant revocation = %+v", p)
	}

	// Credential revocation ends the device's ability to read policy at all.
	h.grant("sunkardav", "device", device.ID, "allow", http.StatusCreated)
	h.mustDo(http.MethodPost, "/api/v1/devices/"+device.ID+"/credentials/revoke", "", h.admin, nil, http.StatusNoContent, nil)
	status, _ := h.do(http.MethodGet, "/api/v1/device/services", "Guardian-Device", token, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("revoked credential status = %d, want 401", status)
	}
}

func TestServiceMutationsAreAuditedWithActorAndRevision(t *testing.T) {
	h := newAPIHarness(t)
	device, _ := h.enrollDevice()
	operator := h.userToken("operator2", "operator")
	var me struct {
		UserID string `json:"user_id"`
	}
	h.mustDo(http.MethodGet, "/api/v1/me", "", h.admin, nil, http.StatusOK, &me)

	h.enableService("sunkardav")
	h.grant("sunkardav", "device", device.ID, "allow", http.StatusCreated)
	h.mustDo(http.MethodPut, "/api/v1/devices/"+device.ID+"/scopes", "", h.admin,
		map[string]any{"site_id": "almaty"}, http.StatusOK, nil)
	// Rejected mutation by a read-only role must not leave an audit trail of success.
	h.errorCode(http.MethodPost, "/api/v1/services/sunkardav/grants", operator,
		map[string]any{"scope_type": "tenant", "scope_id": "acme", "effect": "allow"}, http.StatusForbidden)

	var audit struct {
		Items []domain.AuditEvent `json:"items"`
	}
	h.mustDo(http.MethodGet, "/api/v1/audit?limit=100", "", h.admin, nil, http.StatusOK, &audit)
	seen := map[string]int{}
	for _, event := range audit.Items {
		switch event.Action {
		case "service.update", "service_grant.set", "device.scopes.update":
			seen[event.Action]++
			if event.ActorUserID != me.UserID {
				t.Errorf("%s actor = %q, want %q", event.Action, event.ActorUserID, me.UserID)
			}
			if event.RequestID == "" || event.SourceIP != "192.0.2.50" {
				t.Errorf("%s request_id=%q source_ip=%q", event.Action, event.RequestID, event.SourceIP)
			}
			var details map[string]any
			if err := json.Unmarshal([]byte(event.Details), &details); err != nil {
				t.Fatalf("details: %v", err)
			}
			if rev, _ := details["policy_revision"].(float64); rev < 2 {
				t.Errorf("%s details lack policy_revision: %s", event.Action, event.Details)
			}
		}
	}
	for _, action := range []string{"service.update", "service_grant.set", "device.scopes.update"} {
		if seen[action] != 1 {
			t.Errorf("audit events for %s = %d, want 1", action, seen[action])
		}
	}
}

func TestServiceCatalogErrorCodesAndIdempotency(t *testing.T) {
	h := newAPIHarness(t)
	device, _ := h.enrollDevice()
	valid := map[string]any{
		"expected_revision": 1, "display_name": "SunkarDAV", "internal_dns_name": "dav.internal",
		"protocol": "https", "port": 443, "tls_policy": "required",
		"allowed_scopes": []string{"tenant", "device"}, "enabled": true,
	}

	with := func(key string, value any) map[string]any {
		out := map[string]any{}
		for k, v := range valid {
			out[k] = v
		}
		out[key] = value
		return out
	}

	checks := []struct {
		name, method, path string
		body               any
		status             int
		code               string
	}{
		{"unknown service", http.MethodGet, "/api/v1/services/not-a-service", nil, 404, "service_not_found"},
		{"unknown field", http.MethodPut, "/api/v1/services/sunkardav", with("upstream_password", "x"), 400, "invalid_request"},
		{"missing revision", http.MethodPut, "/api/v1/services/sunkardav", with("expected_revision", 0), 400, "expected_revision_required"},
		{"url as host", http.MethodPut, "/api/v1/services/sunkardav", with("internal_dns_name", "https://dav.internal/x"), 400, "invalid_service_definition"},
		{"bad port", http.MethodPut, "/api/v1/services/sunkardav", with("port", 70000), 400, "invalid_service_definition"},
		{"bad filter", http.MethodGet, "/api/v1/services?enabled=maybe", nil, 400, "invalid_filter"},
		{"bad sort", http.MethodGet, "/api/v1/services/sunkardav/grants?sort=password", nil, 400, "invalid_sort"},
		{"bad scope filter", http.MethodGet, "/api/v1/services/sunkardav/grants?scope_type=planet", nil, 400, "invalid_scope_type"},
		{"grant bad effect", http.MethodPost, "/api/v1/services/sunkardav/grants", map[string]any{"scope_type": "tenant", "scope_id": "acme", "effect": "maybe"}, 400, "invalid_effect"},
		{"grant unknown device", http.MethodPost, "/api/v1/services/sunkardav/grants", map[string]any{"scope_type": "device", "scope_id": "ghost", "effect": "allow"}, 404, "device_not_found"},
		{"grant unknown service", http.MethodPost, "/api/v1/services/ghost/grants", map[string]any{"scope_type": "tenant", "scope_id": "acme", "effect": "allow"}, 404, "service_not_found"},
		{"revoke unknown grant", http.MethodDelete, "/api/v1/services/sunkardav/grants/ghost", nil, 404, "grant_not_found"},
		{"scopes unknown device", http.MethodPut, "/api/v1/devices/ghost/scopes", map[string]any{"tenant_id": "acme"}, 404, "device_not_found"},
		{"scopes invalid id", http.MethodPut, "/api/v1/devices/" + device.ID + "/scopes", map[string]any{"tenant_id": "a b"}, 400, "invalid_scope_id"},
		{"effective view unknown device", http.MethodGet, "/api/v1/devices/ghost/services", nil, 404, "device_not_found"},
	}
	for _, tc := range checks {
		t.Run(tc.name, func(t *testing.T) {
			if code := h.errorCode(tc.method, tc.path, h.admin, tc.body, tc.status); code != tc.code {
				t.Fatalf("code = %q, want %q", code, tc.code)
			}
		})
	}

	// Optimistic concurrency: the same update twice is idempotent, a stale
	// writer with different content gets a stable conflict code.
	var first, retry struct {
		Service       domain.ServiceDefinition `json:"service"`
		Changed       bool                     `json:"changed"`
		PolicyVersion int64                    `json:"policy_revision"`
	}
	h.mustDo(http.MethodPut, "/api/v1/services/sunkardav", "", h.admin, valid, http.StatusOK, &first)
	h.mustDo(http.MethodPut, "/api/v1/services/sunkardav", "", h.admin, valid, http.StatusOK, &retry)
	if !first.Changed || first.Service.Revision != 2 || retry.Changed || retry.Service.Revision != 2 || retry.PolicyVersion != first.PolicyVersion {
		t.Fatalf("first=%+v retry=%+v", first, retry)
	}
	if code := h.errorCode(http.MethodPut, "/api/v1/services/sunkardav", h.admin, with("port", 8443), http.StatusConflict); code != "service_revision_conflict" {
		t.Fatalf("stale update code = %q", code)
	}

	// Grant POST is idempotent: 201 on creation, 200 on repeat.
	h.grant("sunkardav", "tenant", "acme", "allow", http.StatusCreated)
	h.grant("sunkardav", "tenant", "acme", "allow", http.StatusOK)
	// A device grant is rejected because the service now only accepts tenant and device... device is allowed:
	h.grant("sunkardav", "device", device.ID, "deny", http.StatusCreated)
	h.grant("sunkardav", "group", "ops", "allow", http.StatusBadRequest)

	// Pagination metadata and filtering on the collection endpoints.
	var list struct {
		Items []domain.ServiceDefinition `json:"items"`
		Total int                        `json:"total"`
		Limit int                        `json:"limit"`
	}
	h.mustDo(http.MethodGet, "/api/v1/services?enabled=true&limit=1", "", h.admin, nil, http.StatusOK, &list)
	if list.Total != 1 || len(list.Items) != 1 || list.Limit != 1 || list.Items[0].ID != "sunkardav" {
		t.Fatalf("enabled list = %+v", list)
	}
	var grants struct {
		Items []domain.ServiceGrant `json:"items"`
		Total int                   `json:"total"`
	}
	h.mustDo(http.MethodGet, "/api/v1/services/sunkardav/grants?scope_type=device&effect=deny", "", h.admin, nil, http.StatusOK, &grants)
	if grants.Total != 1 || grants.Items[0].ScopeID != device.ID {
		t.Fatalf("filtered grants = %+v", grants)
	}
}

func TestExistingEndpointsRemainCompatible(t *testing.T) {
	h := newAPIHarness(t)
	device, token := h.enrollDevice()

	var devices struct{ Total int }
	h.mustDo(http.MethodGet, "/api/v1/devices", "", h.admin, nil, http.StatusOK, &devices)
	if devices.Total != 1 {
		t.Fatalf("devices total = %d", devices.Total)
	}
	var me domain.DevicePrincipal
	h.mustDo(http.MethodGet, "/api/v1/device/me", "Guardian-Device", token, nil, http.StatusOK, &me)
	if me.DeviceID != device.ID {
		t.Fatalf("device me = %+v", me)
	}
	h.mustDo(http.MethodGet, "/api/v1/device/config", "Guardian-Device", token, nil, http.StatusOK, nil)
	h.mustDo(http.MethodGet, "/api/v1/device/commands", "Guardian-Device", token, nil, http.StatusOK, nil)

	// The new permissions show up in the permission catalog and in the
	// system roles after the idempotent RBAC seed.
	var perms struct {
		Items []string `json:"items"`
	}
	h.mustDo(http.MethodGet, "/api/v1/permissions", "", h.admin, nil, http.StatusOK, &perms)
	joined := strings.Join(perms.Items, ",")
	if !strings.Contains(joined, "services.read") || !strings.Contains(joined, "services.manage") {
		t.Fatalf("permissions = %v", perms.Items)
	}
}
