package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDeviceAuthenticationStoreOutageIsRetryable(t *testing.T) {
	h := newAPIHarness(t)
	_, credential := h.enrollDevice()
	h.mustDo(http.MethodGet, "/api/v1/device/me", "Guardian-Device", credential, nil, http.StatusOK, nil)
	h.mustDo(http.MethodGet, "/api/v1/device/me", "Guardian-Device", "invalid-token", nil, http.StatusUnauthorized, nil)
	if err := h.st.Close(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/v1/device/me", "/api/v1/device/services", "/api/v1/device/commands"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.Header.Set("Authorization", "Guardian-Device "+credential)
			rec := httptest.NewRecorder()
			h.handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("GET %s with unavailable store = %d, want 503", path, rec.Code)
			}
			if rec.Header().Get("Retry-After") == "" || rec.Header().Get("WWW-Authenticate") != "" {
				t.Errorf("outage must be retryable without authentication challenge: %v", rec.Header())
			}
			var body struct {
				Error struct {
					Code string `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body.Error.Code != "device_authentication_unavailable" {
				t.Errorf("outage error code = %q, want device_authentication_unavailable", body.Error.Code)
			}
		})
	}
}
