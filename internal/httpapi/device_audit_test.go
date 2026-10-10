package httpapi

import (
	"github.com/1day0fmylife/Guardian/internal/domain"
	"net/http"
	"testing"
)

func TestDeviceAuditAuthorizationIsolationAndPagination(t *testing.T) {
	h := newAPIHarness(t)
	a, credential := h.enrollDevice()
	b, _ := h.enrollDevice()
	h.enableService("sunkardav")
	var grant struct {
		Grant domain.ServiceGrant `json:"grant"`
	}
	h.mustDo(http.MethodPost, "/api/v1/services/sunkardav/grants", "", h.admin, map[string]any{"scope_type": "device", "scope_id": a.ID, "effect": "allow"}, http.StatusCreated, &grant)
	h.mustDo(http.MethodDelete, "/api/v1/services/sunkardav/grants/"+grant.Grant.ID, "", h.admin, nil, http.StatusOK, nil)
	path := "/api/v1/devices/" + a.ID + "/audit"
	h.mustDo(http.MethodGet, path, "", "", nil, http.StatusUnauthorized, nil)
	h.mustDo(http.MethodGet, path, "Device", credential, nil, http.StatusUnauthorized, nil)
	for _, role := range []string{"viewer", "operator"} {
		token := h.userToken("audit-"+role, role)
		h.mustDo(http.MethodGet, path, "", token, nil, http.StatusForbidden, nil)
	}
	auditor := h.userToken("audit-reader", "auditor")
	var all struct {
		Items []domain.AuditEvent `json:"items"`
		Total int                 `json:"total"`
	}
	h.mustDo(http.MethodGet, path, "", auditor, nil, http.StatusOK, &all)
	seenSet, seenRevoke := false, false
	for _, event := range all.Items {
		if event.ResourceID == b.ID {
			t.Fatal("other device leaked")
		}
		if event.Action == "service_grant.set" {
			seenSet = true
		}
		if event.Action == "service_grant.revoke" {
			seenRevoke = true
		}
		if event.Action == "service.update" {
			t.Fatal("global catalog event in device audit")
		}
	}
	if !seenSet || !seenRevoke {
		t.Fatal("grant history missing")
	}
	var page struct {
		Items []domain.AuditEvent `json:"items"`
		Total int                 `json:"total"`
	}
	h.mustDo(http.MethodGet, path+"?limit=1&offset=1", "", auditor, nil, http.StatusOK, &page)
	if len(page.Items) != 1 || page.Total != all.Total || page.Items[0].ID != all.Items[1].ID {
		t.Fatal("invalid pagination")
	}
	h.mustDo(http.MethodGet, "/api/v1/devices/missing/audit", "", auditor, nil, http.StatusNotFound, nil)
	var global struct {
		Total int `json:"total"`
	}
	h.mustDo(http.MethodGet, "/api/v1/audit", "", auditor, nil, http.StatusOK, &global)
	if global.Total <= all.Total {
		t.Fatal("global audit compatibility lost")
	}
}
