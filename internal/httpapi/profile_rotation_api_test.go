package httpapi

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/1day0fmylife/Guardian/internal/domain"
	"github.com/1day0fmylife/Guardian/internal/store"
)

func wgKey(fill byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{fill}, 32))
}

func TestVPNProfileUpdateAPI(t *testing.T) {
	h := newAPIHarness(t)
	device, credential := h.enrollDevice()
	cfg, err := h.st.ManagedConfigForDevice(context.Background(), device.ID)
	if err != nil {
		t.Fatalf("ManagedConfigForDevice: %v", err)
	}
	path := "/api/v1/vpn-profiles/" + cfg.ProfileID

	var me struct {
		DeviceID       string `json:"device_id"`
		ConfigRevision int64  `json:"config_revision"`
	}
	h.mustDo(http.MethodGet, "/api/v1/device/me", "Guardian-Device", credential, nil, http.StatusOK, &me)
	if me.DeviceID != device.ID || me.ConfigRevision != 1 {
		t.Fatalf("/device/me = %+v", me)
	}

	// Read-only operators cannot rotate.
	operator := h.userToken("profile-operator", "operator")
	if code := h.errorCode(http.MethodPut, path, operator, map[string]any{"expected_revision": 1, "server_public_key": wgKey(200)}, http.StatusForbidden); code == "" {
		t.Fatalf("operator PUT has no error code")
	}
	if code := h.errorCode(http.MethodPut, path, h.admin, map[string]any{"server_public_key": wgKey(200)}, http.StatusBadRequest); code != "expected_revision_required" {
		t.Fatalf("missing revision code = %q", code)
	}
	if code := h.errorCode(http.MethodPut, path, h.admin, map[string]any{"expected_revision": 1, "server_public_key": "bad"}, http.StatusBadRequest); code != "invalid_wireguard_public_key" {
		t.Fatalf("bad key code = %q", code)
	}
	if code := h.errorCode(http.MethodPut, path, h.admin, map[string]any{"expected_revision": 1, "endpoint": "no-port"}, http.StatusBadRequest); code != "invalid_profile" {
		t.Fatalf("bad endpoint code = %q", code)
	}
	if code := h.errorCode(http.MethodPut, "/api/v1/vpn-profiles/missing", h.admin, map[string]any{"expected_revision": 1, "persistent_keepalive": 10}, http.StatusNotFound); code != "not_found" {
		t.Fatalf("missing profile code = %q", code)
	}

	body := map[string]any{"expected_revision": 1, "server_public_key": wgKey(201), "rotation_grace_seconds": 3600}
	var updated struct {
		Profile          domain.VPNProfile `json:"profile"`
		Changed          bool              `json:"changed"`
		ServerKeyRotated bool              `json:"server_key_rotated"`
		NotifiedDevices  int               `json:"notified_devices"`
	}
	h.mustDo(http.MethodPut, path, "", h.admin, body, http.StatusOK, &updated)
	if !updated.Changed || !updated.ServerKeyRotated || updated.NotifiedDevices != 1 || updated.Profile.Revision != 2 ||
		updated.Profile.PreviousServerPublicKey != cfg.ServerPublicKey {
		t.Fatalf("update = %+v", updated)
	}
	// Retried PUT after a lost response: same answer, no new revision.
	h.mustDo(http.MethodPut, path, "", h.admin, body, http.StatusOK, &updated)
	if updated.Changed || updated.Profile.Revision != 2 {
		t.Fatalf("replay = %+v", updated)
	}
	if code := h.errorCode(http.MethodPut, path, h.admin, map[string]any{"expected_revision": 1, "persistent_keepalive": 10}, http.StatusConflict); code != "revision_conflict" {
		t.Fatalf("stale revision code = %q", code)
	}

	// The device notices the new revision and fetches the rotated key.
	h.mustDo(http.MethodGet, "/api/v1/device/me", "Guardian-Device", credential, nil, http.StatusOK, &me)
	if me.ConfigRevision != 2 {
		t.Fatalf("/device/me revision = %d, want 2", me.ConfigRevision)
	}
	var deviceCfg domain.ManagedWireGuardConfig
	h.mustDo(http.MethodGet, "/api/v1/device/config", "Guardian-Device", credential, nil, http.StatusOK, &deviceCfg)
	if deviceCfg.ServerPublicKey != wgKey(201) || deviceCfg.ConfigRevision != 2 {
		t.Fatalf("device config = %+v", deviceCfg)
	}
	var commands struct {
		Items []domain.DeviceCommand `json:"items"`
	}
	h.mustDo(http.MethodGet, "/api/v1/device/commands", "Guardian-Device", credential, nil, http.StatusOK, &commands)
	if len(commands.Items) != 1 || commands.Items[0].Type != "apply-config" {
		t.Fatalf("device commands = %+v", commands.Items)
	}

	var rollout store.VPNProfileRollout
	h.mustDo(http.MethodGet, path+"/rollout", "", operator, nil, http.StatusOK, &rollout)
	if rollout.Peers != 1 || rollout.Pending != 1 || rollout.PreviousKeyRetirable {
		t.Fatalf("rollout = %+v", rollout)
	}
	var got domain.VPNProfile
	h.mustDo(http.MethodGet, path, "", operator, nil, http.StatusOK, &got)
	if got.Revision != 2 || got.ServerPublicKey != wgKey(201) {
		t.Fatalf("GET profile = %+v", got)
	}
}

func TestReenrollmentErrorCodesOverHTTP(t *testing.T) {
	h := newAPIHarness(t)
	device, credential := h.enrollDevice()
	ctx := context.Background()
	cfg, _ := h.st.ManagedConfigForDevice(ctx, device.ID)

	claim := func(token string, key byte) (int, string) {
		t.Helper()
		status, raw := h.do(http.MethodPost, "/api/v1/device/enroll", "Guardian-Enrollment", token, map[string]any{
			"device_uuid": device.DeviceUUID, "device_name": "API device", "public_key": wgKey(key),
		})
		var env struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
			Reactivated bool `json:"reactivated"`
		}
		_ = json.Unmarshal(raw, &env)
		if env.Reactivated {
			return status, "reactivated"
		}
		return status, env.Error.Code
	}
	issue := func(bound string) string {
		t.Helper()
		issued, err := h.st.CreateEnrollment(ctx, store.EnrollmentCreate{ProfileID: cfg.ProfileID, BoundDeviceUUID: bound, TTL: time.Minute})
		if err != nil {
			t.Fatalf("CreateEnrollment: %v", err)
		}
		return issued.Token
	}

	h.mustDo(http.MethodPost, "/api/v1/devices/"+device.ID+"/revoke", "", h.admin, nil, http.StatusAccepted, nil)
	if status, code := claim(issue(device.DeviceUUID), 230); status != http.StatusConflict || code != "device_revocation_pending" {
		t.Fatalf("revoking claim = %d %q", status, code)
	}
	if err := h.st.CompleteDeviceVPNRevocation(ctx, device.ID, cfg.ConfigRevision+1); err != nil {
		t.Fatalf("CompleteDeviceVPNRevocation: %v", err)
	}
	if status, _ := h.do(http.MethodGet, "/api/v1/device/me", "Guardian-Device", credential, nil); status != http.StatusUnauthorized {
		t.Fatalf("revoked credential /me = %d", status)
	}
	if status, code := claim(issue(""), 231); status != http.StatusConflict || code != "reenrollment_requires_bound_enrollment" {
		t.Fatalf("unbound claim = %d %q", status, code)
	}
	if status, code := claim(issue(device.DeviceUUID), 232); status != http.StatusCreated || code != "reactivated" {
		t.Fatalf("bound claim = %d %q", status, code)
	}
	var events struct {
		Items []domain.AuditEvent `json:"items"`
	}
	h.mustDo(http.MethodGet, "/api/v1/audit?limit=100", "", h.admin, nil, http.StatusOK, &events)
	found := false
	for _, e := range events.Items {
		if e.Action == "enrollment.claim" && e.ResourceID == device.ID && strings.Contains(string(e.Details), `"reactivated":true`) {
			found = true
		}
	}
	if !found {
		t.Fatalf("no reactivation audit event in %+v", events.Items)
	}
}

func TestDeviceTrustBundle(t *testing.T) {
	h := newAPIHarness(t)
	_, credential := h.enrollDevice()

	// Not configured: an empty bundle, not an error.
	var empty trustBundleResponse
	h.mustDo(http.MethodGet, "/api/v1/device/trust-bundle", "Guardian-Device", credential, nil, http.StatusOK, &empty)
	if empty.BundlePEM != "" || len(empty.Certificates) != 0 {
		t.Fatalf("unconfigured bundle = %+v", empty)
	}
	if status, _ := h.do(http.MethodGet, "/api/v1/device/trust-bundle", "", "", nil); status != http.StatusUnauthorized {
		t.Fatalf("anonymous trust bundle = %d", status)
	}

	dir := t.TempDir()
	oldCA, oldKey := testCA(t, "old CA", nil, nil)
	newCA, newKey := testCA(t, "new CA", nil, nil)
	cross, _ := testCA(t, "new CA", oldCA, oldKey, newKey)
	bundle := append(append(pemCert(oldCA), pemCert(newCA)...), pemCert(cross)...)
	file := filepath.Join(dir, "bundle.pem")
	if err := os.WriteFile(file, bundle, 0o644); err != nil {
		t.Fatal(err)
	}
	server := New(h.st, "https://guardian.test", time.Hour)
	server.SetDeviceTrustBundleFile(file)
	handler := server.AdminHandler()
	get := func() (int, trustBundleResponse) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/device/trust-bundle", nil)
		req.Header.Set("Authorization", "Guardian-Device "+credential)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		var out trustBundleResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	status, got := get()
	if status != http.StatusOK || got.BundlePEM != string(bundle) || len(got.Certificates) != 3 || got.SHA256 == "" {
		t.Fatalf("bundle = %d %+v", status, got)
	}
	if !got.Certificates[0].SelfSigned || got.Certificates[2].SelfSigned {
		t.Fatalf("self-signed flags = %+v", got.Certificates)
	}

	// A leaf in the bundle is refused as a whole.
	leaf := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, oldCA, &oldKey.PublicKey, oldKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, append(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})...), 0o644); err != nil {
		t.Fatal(err)
	}
	if status, _ := get(); status != http.StatusServiceUnavailable {
		t.Fatalf("bundle with leaf = %d", status)
	}
}

// testCA creates a CA certificate. With a parent it is a cross-certificate:
// subjectKey (or a fresh key) certified by the parent.
func testCA(t *testing.T, cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, subjectKey ...*ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if len(subjectKey) > 0 {
		key = subjectKey[0]
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func pemCert(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}
