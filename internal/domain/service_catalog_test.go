package domain

import (
	"strings"
	"testing"
)

func testDef(enabled bool, scopes ...string) ServiceDefinition {
	if len(scopes) == 0 {
		scopes = []string{ScopeTenant, ScopeSite, ScopeGroup, ScopeDevice}
	}
	return ServiceDefinition{ID: ServiceSunkarDAV, Revision: 1, Enabled: enabled, AllowedScopes: scopes}
}

func grant(id, scopeType, scopeID, effect string) ServiceGrant {
	return ServiceGrant{ID: id, ServiceID: ServiceSunkarDAV, ScopeType: scopeType, ScopeID: scopeID, Effect: effect}
}

func TestEvaluateServiceAccessDenyByDefault(t *testing.T) {
	scopes := DeviceScopes{TenantID: "t1", SiteID: "s1", GroupIDs: []string{"g1"}}
	got := EvaluateServiceAccess(testDef(true), "dev-1", true, scopes, nil)
	if got.Allowed || got.Reason != ReasonNoGrant {
		t.Fatalf("decision without grants = %+v, want deny/no_grant", got)
	}
}

func TestEvaluateServiceAccessPrecedence(t *testing.T) {
	scopes := DeviceScopes{TenantID: "t1", SiteID: "s1", GroupIDs: []string{"g1", "g2"}}
	tests := []struct {
		name    string
		grants  []ServiceGrant
		allowed bool
		reason  string
	}{
		{"tenant allow", []ServiceGrant{grant("a", ScopeTenant, "t1", GrantEffectAllow)}, true, "tenant_grant"},
		{"site deny overrides tenant allow", []ServiceGrant{
			grant("a", ScopeTenant, "t1", GrantEffectAllow), grant("b", ScopeSite, "s1", GrantEffectDeny)}, false, "site_deny"},
		{"group allow overrides site deny", []ServiceGrant{
			grant("a", ScopeSite, "s1", GrantEffectDeny), grant("b", ScopeGroup, "g1", GrantEffectAllow)}, true, "group_grant"},
		{"device deny overrides group allow", []ServiceGrant{
			grant("a", ScopeGroup, "g1", GrantEffectAllow), grant("b", ScopeDevice, "dev-1", GrantEffectDeny)}, false, "device_deny"},
		{"device allow overrides tenant deny", []ServiceGrant{
			grant("a", ScopeTenant, "t1", GrantEffectDeny), grant("b", ScopeDevice, "dev-1", GrantEffectAllow)}, true, "device_grant"},
		{"deny wins inside one scope level", []ServiceGrant{
			grant("a", ScopeGroup, "g1", GrantEffectAllow), grant("b", ScopeGroup, "g2", GrantEffectDeny)}, false, "group_deny"},
		{"grant of another tenant does not apply", []ServiceGrant{grant("a", ScopeTenant, "t2", GrantEffectAllow)}, false, ReasonNoGrant},
		{"grant of another device does not apply", []ServiceGrant{grant("a", ScopeDevice, "dev-2", GrantEffectAllow)}, false, ReasonNoGrant},
		{"revoked grant is ignored", []ServiceGrant{{
			ID: "a", ServiceID: ServiceSunkarDAV, ScopeType: ScopeDevice, ScopeID: "dev-1",
			Effect: GrantEffectAllow, RevokedAt: "2026-10-10T00:00:00Z"}}, false, ReasonNoGrant},
		{"grant of another service is ignored", []ServiceGrant{{
			ID: "a", ServiceID: ServiceAdmiralDevice, ScopeType: ScopeDevice, ScopeID: "dev-1", Effect: GrantEffectAllow}}, false, ReasonNoGrant},
		{"unknown effect is ignored", []ServiceGrant{grant("a", ScopeDevice, "dev-1", "permit")}, false, ReasonNoGrant},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := EvaluateServiceAccess(testDef(true), "dev-1", true, scopes, tc.grants)
			if got.Allowed != tc.allowed || got.Reason != tc.reason {
				t.Fatalf("decision = %+v, want allowed=%v reason=%s", got, tc.allowed, tc.reason)
			}
		})
	}
}

func TestEvaluateServiceAccessIsOrderIndependent(t *testing.T) {
	scopes := DeviceScopes{GroupIDs: []string{"g1", "g2"}}
	a := grant("a", ScopeGroup, "g1", GrantEffectAllow)
	b := grant("b", ScopeGroup, "g2", GrantEffectAllow)
	first := EvaluateServiceAccess(testDef(true), "dev-1", true, scopes, []ServiceGrant{a, b})
	second := EvaluateServiceAccess(testDef(true), "dev-1", true, scopes, []ServiceGrant{b, a})
	if first != second {
		t.Fatalf("decision depends on grant order: %+v vs %+v", first, second)
	}
	if first.SourceGrantID != "a" {
		t.Fatalf("source grant = %q, want deterministic smallest id", first.SourceGrantID)
	}
}

func TestEvaluateServiceAccessGateConditions(t *testing.T) {
	scopes := DeviceScopes{}
	allow := []ServiceGrant{grant("a", ScopeDevice, "dev-1", GrantEffectAllow)}

	if got := EvaluateServiceAccess(testDef(false), "dev-1", true, scopes, allow); got.Allowed || got.Reason != ReasonServiceDisabled {
		t.Fatalf("disabled service = %+v", got)
	}
	if got := EvaluateServiceAccess(testDef(true), "dev-1", false, scopes, allow); got.Allowed || got.Reason != ReasonDeviceNotActive {
		t.Fatalf("inactive device = %+v", got)
	}
	// A service that no longer accepts device-scoped grants must fail closed.
	narrow := testDef(true, ScopeTenant)
	if got := EvaluateServiceAccess(narrow, "dev-1", true, scopes, allow); got.Allowed {
		t.Fatalf("grant outside allowed_scopes was honored: %+v", got)
	}
	// Empty membership must never match grants with an empty scope id.
	empty := []ServiceGrant{grant("a", ScopeTenant, "", GrantEffectAllow)}
	if got := EvaluateServiceAccess(testDef(true), "dev-1", true, scopes, empty); got.Allowed {
		t.Fatalf("empty scope matched: %+v", got)
	}
}

func TestServiceDefinitionInputNormalize(t *testing.T) {
	valid := ServiceDefinitionInput{
		DisplayName: " SunkarDAV ", InternalDNSName: " DAV.Internal ", Protocol: "HTTPS", Port: 443,
		AllowedScopes: []string{"device", "tenant", "device"},
	}
	if err := valid.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if valid.InternalDNSName != "dav.internal" || valid.Protocol != "https" || valid.TLSPolicy != TLSPolicyRequired {
		t.Fatalf("normalized = %+v", valid)
	}
	if strings.Join(valid.AllowedScopes, ",") != "tenant,device" {
		t.Fatalf("scopes = %v", valid.AllowedScopes)
	}

	invalid := map[string]ServiceDefinitionInput{
		"scheme in host":    {DisplayName: "x", InternalDNSName: "https://dav.internal", Protocol: "https", Port: 443, AllowedScopes: []string{"device"}},
		"port in host":      {DisplayName: "x", InternalDNSName: "dav.internal:443", Protocol: "https", Port: 443, AllowedScopes: []string{"device"}},
		"userinfo in host":  {DisplayName: "x", InternalDNSName: "user@dav.internal", Protocol: "https", Port: 443, AllowedScopes: []string{"device"}},
		"path in host":      {DisplayName: "x", InternalDNSName: "dav.internal/admin", Protocol: "https", Port: 443, AllowedScopes: []string{"device"}},
		"empty label":       {DisplayName: "x", InternalDNSName: "dav..internal", Protocol: "https", Port: 443, AllowedScopes: []string{"device"}},
		"port zero":         {DisplayName: "x", InternalDNSName: "dav.internal", Protocol: "https", Port: 0, AllowedScopes: []string{"device"}},
		"port too large":    {DisplayName: "x", InternalDNSName: "dav.internal", Protocol: "https", Port: 65536, AllowedScopes: []string{"device"}},
		"unknown protocol":  {DisplayName: "x", InternalDNSName: "dav.internal", Protocol: "ftp", Port: 21, AllowedScopes: []string{"device"}},
		"https without tls": {DisplayName: "x", InternalDNSName: "dav.internal", Protocol: "https", Port: 443, TLSPolicy: "disabled", AllowedScopes: []string{"device"}},
		"no scopes":         {DisplayName: "x", InternalDNSName: "dav.internal", Protocol: "https", Port: 443},
		"unknown scope":     {DisplayName: "x", InternalDNSName: "dav.internal", Protocol: "https", Port: 443, AllowedScopes: []string{"planet"}},
		"empty name":        {DisplayName: " ", InternalDNSName: "dav.internal", Protocol: "https", Port: 443, AllowedScopes: []string{"device"}},
	}
	for name, input := range invalid {
		t.Run(name, func(t *testing.T) {
			if err := input.Normalize(); err == nil {
				t.Fatalf("Normalize accepted %+v", input)
			}
		})
	}
}

func TestDeviceAccessState(t *testing.T) {
	cases := []struct {
		status    string
		suspended bool
		want      string
	}{
		{"active", false, AccessStateActive},
		{"active", true, AccessStateSuspended},
		{"suspended", true, AccessStateSuspended},
		{"pending", false, AccessStatePending},
		{"revoking", true, AccessStateRevoking},
		{"revoked", true, AccessStateRevoked},
		{"something-new", false, AccessStateRevoked},
	}
	for _, tc := range cases {
		if got := DeviceAccessState(tc.status, tc.suspended); got != tc.want {
			t.Errorf("DeviceAccessState(%q,%v) = %q, want %q", tc.status, tc.suspended, got, tc.want)
		}
	}
}
