package httpapi

import (
	"net/http"
	"strings"
	"testing"

	"github.com/1day0fmylife/Guardian/internal/domain"
)

func TestTenantScopeAPIRejectsForeignMembershipAndKeepsPolicyPrivate(t *testing.T) {
	h := newAPIHarness(t)
	a, tokenA := h.enrollDevice()
	b, tokenB := h.enrollDevice()
	h.enableService(domain.ServiceSunkarDAV)
	pathA := "/api/v1/devices/" + a.ID + "/scopes"
	pathB := "/api/v1/devices/" + b.ID + "/scopes"
	h.mustDo(http.MethodPut, pathA, "", h.admin, map[string]any{"tenant_id": "tenant-a", "site_id": "site-a", "group_ids": []string{"group-a"}}, http.StatusOK, nil)
	h.mustDo(http.MethodPut, pathB, "", h.admin, map[string]any{"tenant_id": "tenant-b", "site_id": "site-b"}, http.StatusOK, nil)
	h.mustDo(http.MethodPost, "/api/v1/services/sunkardav/grants", "", h.admin, map[string]any{"scope_type": "group", "scope_id": "group-a", "effect": "allow"}, http.StatusCreated, nil)
	if code := h.errorCode(http.MethodPut, pathB, h.admin, map[string]any{"tenant_id": "tenant-b", "group_ids": []string{"group-a"}}, http.StatusConflict); code != "scope_tenant_conflict" {
		t.Fatalf("code=%s", code)
	}
	if p := h.devicePolicy(tokenA); p.ids() != "sunkardav" {
		t.Fatalf("owner policy=%s", p.ids())
	}
	if p := h.devicePolicy(tokenB); p.ids() != "" {
		t.Fatalf("foreign policy=%s", p.ids())
	}
	code, raw := h.do(http.MethodGet, "/api/v1/device/services", "Guardian-Device", tokenB, nil)
	if code != http.StatusOK {
		t.Fatalf("policy code=%d", code)
	}
	for _, value := range []string{tokenA, tokenB, h.admin, "tenant-a", "site-a", "group-a", a.ID} {
		if strings.Contains(string(raw), value) {
			t.Fatal("policy leaked another tenant or credential")
		}
	}
	h.mustDo(http.MethodPut, pathA, "Guardian-Device", tokenB, map[string]any{"tenant_id": "tenant-b"}, http.StatusUnauthorized, nil)
}

func TestPoolOverlapAPIAndRolePermissions(t *testing.T) {
	h := newAPIHarness(t)
	h.mustDo(http.MethodPost, "/api/v1/address-pools", "", h.admin, map[string]any{"name": "first", "cidr": "10.249.0.0/24"}, http.StatusCreated, nil)
	overlap := map[string]any{"name": "overlap", "cidr": "10.249.0.8/29"}
	if code := h.errorCode(http.MethodPost, "/api/v1/address-pools", h.admin, overlap, http.StatusConflict); code != "address_pool_overlap" {
		t.Fatalf("overlap code = %s", code)
	}
	for _, role := range []string{"viewer", "auditor", "operator"} {
		token := h.userToken("pool-"+role, role)
		h.mustDo(http.MethodPost, "/api/v1/address-pools", "", token, overlap, http.StatusForbidden, nil)
	}
}
