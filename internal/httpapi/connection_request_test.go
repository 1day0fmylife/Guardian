package httpapi

import (
	"github.com/1day0fmylife/Guardian/internal/domain"
	"net/http"
	"testing"
)

func TestConnectionRequestAdminOptInPreserveAndRevoke(t *testing.T) {
	h := newAPIHarness(t)
	path := "/api/v1/services/sunkarcwmp-acs"
	var def domain.ServiceDefinition
	h.mustDo(http.MethodGet, path, "", h.admin, nil, 200, &def)
	body := map[string]any{"expected_revision": def.Revision, "display_name": def.DisplayName, "internal_dns_name": def.InternalDNSName, "protocol": def.Protocol, "port": def.Port, "tls_policy": def.TLSPolicy, "allowed_scopes": def.AllowedScopes, "enabled": true, "connection_request": map[string]any{"source_address": "10.78.0.12", "port": 7547}}
	h.mustDo(http.MethodPut, path, "", "", body, http.StatusUnauthorized, nil)
	h.mustDo(http.MethodPut, path, "", h.admin, body, 200, nil)
	h.mustDo(http.MethodGet, path, "", h.admin, nil, 200, &def)
	if def.ConnectionRequest == nil {
		t.Fatal("explicit callback capability missing")
	}
	body["expected_revision"] = def.Revision
	delete(body, "connection_request")
	body["display_name"] = "ACS renamed"
	h.mustDo(http.MethodPut, path, "", h.admin, body, 200, nil)
	h.mustDo(http.MethodGet, path, "", h.admin, nil, 200, &def)
	if def.ConnectionRequest == nil {
		t.Fatal("legacy admin update dropped callback capability")
	}
	body["expected_revision"] = def.Revision
	body["connection_request"] = nil
	h.mustDo(http.MethodPut, path, "", h.admin, body, 200, nil)
	def = domain.ServiceDefinition{}
	h.mustDo(http.MethodGet, path, "", h.admin, nil, 200, &def)
	if def.ConnectionRequest != nil {
		t.Fatal("explicit null did not revoke callback")
	}
}
