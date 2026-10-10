package domain

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Logical identifiers of the services Guardian can broker access to.
const (
	ServiceSunkarDAV     = "sunkardav"
	ServiceAdmiralDevice = "admiral-device"
	ServiceSunkarCWMPACS = "sunkarcwmp-acs"
)

// Grant scope types, ordered from the broadest to the most specific.
const (
	ScopeTenant = "tenant"
	ScopeSite   = "site"
	ScopeGroup  = "group"
	ScopeDevice = "device"
)

const (
	GrantEffectAllow = "allow"
	GrantEffectDeny  = "deny"
)

const (
	ServiceProtocolHTTPS = "https"
	ServiceProtocolHTTP  = "http"
	ServiceProtocolTCP   = "tcp"

	TLSPolicyRequired = "required"
	TLSPolicyDisabled = "disabled"
)

// Device access states reported by the effective-policy views.
const (
	AccessStateActive    = "active"
	AccessStatePending   = "pending"
	AccessStateSuspended = "suspended"
	AccessStateRevoking  = "revoking"
	AccessStateRevoked   = "revoked"
)

// Reasons attached to an access decision. They are stable machine-readable
// values for the administrative view only; devices never receive them.
const (
	ReasonDeviceNotActive  = "device_not_active"
	ReasonServiceDisabled  = "service_disabled"
	ReasonNoGrant          = "no_grant"
	ReasonGrantSuffix      = "_grant"
	ReasonDenySuffix       = "_deny"
	maxScopeIDLength       = 128
	maxDisplayNameLength   = 80
	maxInternalDNSLength   = 253
	maxDNSLabelLength      = 63
	maxAllowedScopesLength = 4
)

var scopePrecedence = map[string]int{
	ScopeTenant: 1,
	ScopeSite:   2,
	ScopeGroup:  3,
	ScopeDevice: 4,
}

var (
	scopeIDPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)
	dnsLabelPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)
)

// KnownServiceIDs returns the catalog identifiers shipped with Guardian.
func KnownServiceIDs() []string {
	return []string{ServiceSunkarDAV, ServiceAdmiralDevice, ServiceSunkarCWMPACS}
}

// ServiceDefinition is one immutable revision of a catalog entry. The current
// revision of each service is the one used for policy evaluation.
type ServiceDefinition struct {
	ID              string   `json:"id"`
	Revision        int64    `json:"revision"`
	DisplayName     string   `json:"display_name"`
	InternalDNSName string   `json:"internal_dns_name"`
	Protocol        string   `json:"protocol"`
	Port            int      `json:"port"`
	TLSPolicy       string   `json:"tls_policy"`
	AllowedScopes   []string `json:"allowed_scopes"`
	Enabled         bool     `json:"enabled"`
	UpdatedByUserID string   `json:"updated_by_user_id,omitempty"`
	CreatedAt       string   `json:"created_at"`
	UpdatedAt       string   `json:"updated_at"`
}

// ServiceDefinitionInput is the mutable part of a service definition.
type ServiceDefinitionInput struct {
	DisplayName     string   `json:"display_name"`
	InternalDNSName string   `json:"internal_dns_name"`
	Protocol        string   `json:"protocol"`
	Port            int      `json:"port"`
	TLSPolicy       string   `json:"tls_policy"`
	AllowedScopes   []string `json:"allowed_scopes"`
	Enabled         bool     `json:"enabled"`
}

// Normalize trims and canonicalizes the input in place and validates it.
func (in *ServiceDefinitionInput) Normalize() error {
	in.DisplayName = strings.TrimSpace(in.DisplayName)
	in.InternalDNSName = strings.ToLower(strings.TrimSpace(in.InternalDNSName))
	in.Protocol = strings.ToLower(strings.TrimSpace(in.Protocol))
	in.TLSPolicy = strings.ToLower(strings.TrimSpace(in.TLSPolicy))
	if in.TLSPolicy == "" {
		in.TLSPolicy = TLSPolicyRequired
	}

	if in.DisplayName == "" || len(in.DisplayName) > maxDisplayNameLength {
		return fmt.Errorf("display_name must contain 1-%d characters", maxDisplayNameLength)
	}
	if err := validateInternalDNSName(in.InternalDNSName); err != nil {
		return err
	}
	switch in.Protocol {
	case ServiceProtocolHTTPS, ServiceProtocolHTTP, ServiceProtocolTCP:
	default:
		return fmt.Errorf("protocol must be one of https, http, tcp")
	}
	if in.Port < 1 || in.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	switch in.TLSPolicy {
	case TLSPolicyRequired, TLSPolicyDisabled:
	default:
		return fmt.Errorf("tls_policy must be one of required, disabled")
	}
	if in.Protocol == ServiceProtocolHTTPS && in.TLSPolicy != TLSPolicyRequired {
		return fmt.Errorf("protocol https requires tls_policy required")
	}
	if in.Protocol == ServiceProtocolHTTP && in.TLSPolicy != TLSPolicyDisabled {
		return fmt.Errorf("protocol http requires tls_policy disabled")
	}

	scopes := make([]string, 0, len(in.AllowedScopes))
	seen := map[string]struct{}{}
	for _, scope := range in.AllowedScopes {
		scope = strings.ToLower(strings.TrimSpace(scope))
		if _, ok := scopePrecedence[scope]; !ok {
			return fmt.Errorf("allowed_scopes contains unsupported scope")
		}
		if _, dup := seen[scope]; dup {
			continue
		}
		seen[scope] = struct{}{}
		scopes = append(scopes, scope)
	}
	if len(scopes) == 0 || len(scopes) > maxAllowedScopesLength {
		return fmt.Errorf("allowed_scopes must contain at least one scope")
	}
	sort.Slice(scopes, func(i, j int) bool { return scopePrecedence[scopes[i]] < scopePrecedence[scopes[j]] })
	in.AllowedScopes = scopes
	return nil
}

func validateInternalDNSName(name string) error {
	if name == "" || len(name) > maxInternalDNSLength {
		return fmt.Errorf("internal_dns_name must be a DNS host name")
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > maxDNSLabelLength || !dnsLabelPattern.MatchString(label) {
			return fmt.Errorf("internal_dns_name must be a DNS host name without scheme, port or path")
		}
	}
	return nil
}

// ValidateScopeID checks the opaque identifier of a tenant, site or group.
func ValidateScopeID(scopeID string) error {
	if scopeID == "" || len(scopeID) > maxScopeIDLength || !scopeIDPattern.MatchString(scopeID) {
		return fmt.Errorf("scope_id must be 1-%d characters of letters, digits, '.', '_', ':' or '-'", maxScopeIDLength)
	}
	return nil
}

// ValidScopeType reports whether the value is a supported grant scope.
func ValidScopeType(scopeType string) bool {
	_, ok := scopePrecedence[scopeType]
	return ok
}

// ValidGrantEffect reports whether the value is a supported grant effect.
func ValidGrantEffect(effect string) bool {
	return effect == GrantEffectAllow || effect == GrantEffectDeny
}

// ServiceGrant binds an allow or deny decision for one service to a scope.
type ServiceGrant struct {
	ID                    string `json:"id"`
	ServiceID             string `json:"service_id"`
	ScopeType             string `json:"scope_type"`
	ScopeID               string `json:"scope_id"`
	Effect                string `json:"effect"`
	PolicyRevision        int64  `json:"policy_revision"`
	CreatedByUserID       string `json:"created_by_user_id,omitempty"`
	CreatedAt             string `json:"created_at"`
	RevokedAt             string `json:"revoked_at,omitempty"`
	RevokedByUserID       string `json:"revoked_by_user_id,omitempty"`
	RevokedPolicyRevision int64  `json:"revoked_policy_revision,omitempty"`
}

// DeviceScopes lists the tenant, site and groups a device belongs to.
type DeviceScopes struct {
	TenantID string   `json:"tenant_id"`
	SiteID   string   `json:"site_id"`
	GroupIDs []string `json:"group_ids"`
}

// Normalize validates the membership and sorts group identifiers.
func (s *DeviceScopes) Normalize() error {
	s.TenantID = strings.TrimSpace(s.TenantID)
	s.SiteID = strings.TrimSpace(s.SiteID)
	if s.TenantID != "" {
		if err := ValidateScopeID(s.TenantID); err != nil {
			return fmt.Errorf("tenant_id: %w", err)
		}
	}
	if s.SiteID != "" {
		if err := ValidateScopeID(s.SiteID); err != nil {
			return fmt.Errorf("site_id: %w", err)
		}
	}
	groups := make([]string, 0, len(s.GroupIDs))
	seen := map[string]struct{}{}
	for _, group := range s.GroupIDs {
		group = strings.TrimSpace(group)
		if err := ValidateScopeID(group); err != nil {
			return fmt.Errorf("group_ids: %w", err)
		}
		if _, dup := seen[group]; dup {
			continue
		}
		seen[group] = struct{}{}
		groups = append(groups, group)
	}
	if len(groups) > 64 {
		return fmt.Errorf("group_ids must contain at most 64 entries")
	}
	sort.Strings(groups)
	s.GroupIDs = groups
	return nil
}

// ServiceAccessDecision is the outcome of evaluating one service for a device.
type ServiceAccessDecision struct {
	Allowed         bool   `json:"allowed"`
	Reason          string `json:"reason"`
	SourceScopeType string `json:"source_scope_type,omitempty"`
	SourceGrantID   string `json:"source_grant_id,omitempty"`
}

// EvaluateServiceAccess resolves access of one device to one service.
//
// The decision is deny-by-default. Only active grants of scope types that the
// service definition allows are considered. The most specific matching scope
// wins (device > group > site > tenant); within that scope a deny always beats
// an allow, which makes the result independent of grant ordering.
func EvaluateServiceAccess(def ServiceDefinition, deviceID string, deviceActive bool, scopes DeviceScopes, grants []ServiceGrant) ServiceAccessDecision {
	if !deviceActive {
		return ServiceAccessDecision{Reason: ReasonDeviceNotActive}
	}
	if !def.Enabled {
		return ServiceAccessDecision{Reason: ReasonServiceDisabled}
	}

	allowedScope := map[string]struct{}{}
	for _, scope := range def.AllowedScopes {
		allowedScope[scope] = struct{}{}
	}

	var best *ServiceGrant
	bestRank := 0
	for i := range grants {
		g := &grants[i]
		if g.ServiceID != def.ID || g.RevokedAt != "" || !ValidGrantEffect(g.Effect) {
			continue
		}
		if _, ok := allowedScope[g.ScopeType]; !ok {
			continue
		}
		if !scopeMatches(*g, deviceID, scopes) {
			continue
		}
		rank := scopePrecedence[g.ScopeType]
		switch {
		case best == nil || rank > bestRank:
			best, bestRank = g, rank
		case rank == bestRank && betterGrant(*g, *best):
			best = g
		}
	}
	if best == nil {
		return ServiceAccessDecision{Reason: ReasonNoGrant}
	}
	decision := ServiceAccessDecision{
		Allowed:         best.Effect == GrantEffectAllow,
		SourceScopeType: best.ScopeType,
		SourceGrantID:   best.ID,
	}
	if decision.Allowed {
		decision.Reason = best.ScopeType + ReasonGrantSuffix
	} else {
		decision.Reason = best.ScopeType + ReasonDenySuffix
	}
	return decision
}

func scopeMatches(g ServiceGrant, deviceID string, scopes DeviceScopes) bool {
	switch g.ScopeType {
	case ScopeDevice:
		return g.ScopeID == deviceID
	case ScopeTenant:
		return scopes.TenantID != "" && g.ScopeID == scopes.TenantID
	case ScopeSite:
		return scopes.SiteID != "" && g.ScopeID == scopes.SiteID
	case ScopeGroup:
		for _, group := range scopes.GroupIDs {
			if group == g.ScopeID {
				return true
			}
		}
	}
	return false
}

// betterGrant orders grants of the same scope level: deny first, then by ID.
func betterGrant(candidate, current ServiceGrant) bool {
	if candidate.Effect != current.Effect {
		return candidate.Effect == GrantEffectDeny
	}
	return candidate.ID < current.ID
}

// DeviceServiceEndpoint is the non-secret description of one permitted
// service as seen by a device. It never carries credentials or admin URLs.
type DeviceServiceEndpoint struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Protocol    string `json:"protocol"`
	TLSPolicy   string `json:"tls_policy"`
	Revision    int64  `json:"revision"`
}

// DeviceServicePolicy is the effective policy returned to a device.
type DeviceServicePolicy struct {
	DeviceID    string                  `json:"device_id"`
	AccessState string                  `json:"access_state"`
	Revision    int64                   `json:"revision"`
	GeneratedAt string                  `json:"generated_at"`
	Services    []DeviceServiceEndpoint `json:"services"`
}

// AdminServiceDecision is one row of the administrative effective-policy view.
type AdminServiceDecision struct {
	ServiceID       string `json:"service_id"`
	ServiceRevision int64  `json:"service_revision"`
	DisplayName     string `json:"display_name"`
	Enabled         bool   `json:"enabled"`
	ServiceAccessDecision
}

// AdminDevicePolicy is the administrative effective-policy view of a device.
type AdminDevicePolicy struct {
	DeviceID    string                 `json:"device_id"`
	AccessState string                 `json:"access_state"`
	Revision    int64                  `json:"revision"`
	Scopes      DeviceScopes           `json:"scopes"`
	Services    []AdminServiceDecision `json:"services"`
}

// DeviceAccessState maps persisted device fields to a policy access state.
// Anything other than a fully active, non-suspended device has no access.
func DeviceAccessState(status string, suspended bool) string {
	switch status {
	case "active":
		if suspended {
			return AccessStateSuspended
		}
		return AccessStateActive
	case "pending":
		return AccessStatePending
	case "suspended":
		return AccessStateSuspended
	case "revoking":
		return AccessStateRevoking
	case "revoked":
		return AccessStateRevoked
	default:
		return AccessStateRevoked
	}
}
