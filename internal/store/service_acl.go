package store

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/1day0fmylife/Guardian/internal/domain"
)

// ServiceAccessTarget is one provisioned WireGuard peer address together with
// the services its device is currently allowed to reach.
//
// DeviceID, PeerID, PublicKey, Address and ConfigRevision together are the
// binding Guardian attests for the peer: the immutable device id owns exactly
// this WireGuard key and tunnel address at this configuration revision. The
// gateway must only honor the grant for traffic that the kernel can attribute
// to that same key and address (see gatewayacl.VerifyBindings).
type ServiceAccessTarget struct {
	DeviceID        string
	PeerID          string
	PublicKey       string
	Address         netip.Addr
	ConfigRevision  int64
	AppliedRevision int64
	ServiceIDs      []string
}

// ServiceAccessSnapshot is a consistent-enough view of the service ACL: the
// revision is read before the content, so the targets are never older than
// the revision they are labelled with.
type ServiceAccessSnapshot struct {
	PolicyRevision int64
	Targets        []ServiceAccessTarget
	// AddressConflicts counts active peers excluded because another active
	// peer claims the same tunnel address. Both are denied (fail closed).
	AddressConflicts int
}

// ServiceAccessSnapshot resolves the service policy of every active,
// non-suspended device that owns an unrevoked WireGuard peer. It evaluates
// all devices with a fixed number of queries and the same
// domain.EvaluateServiceAccess used for the device-facing policy, so the
// network ACL and the policy API cannot disagree.
//
// Devices that are not active, are suspended or revoking, or whose peer is
// revoked never appear: they have no service access. Peers with an address
// that cannot be parsed are skipped (fail closed).
func (s *Store) ServiceAccessSnapshot(ctx context.Context) (ServiceAccessSnapshot, error) {
	var snap ServiceAccessSnapshot
	revision, err := s.readServicePolicyRevision(ctx, s.db)
	if err != nil {
		return snap, err
	}
	snap.PolicyRevision = revision

	definitions, _, err := s.ListServiceDefinitions(ctx, ServiceDefinitionFilter{}, 1000, 0)
	if err != nil {
		return snap, err
	}

	type peer struct {
		deviceID, peerID, publicKey string
		address                     netip.Addr
		configRevision, applied     int64
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT d.id, p.id, p.public_key, p.assigned_address, p.config_revision, p.applied_revision
		FROM devices d
		JOIN wireguard_peers p ON p.device_id = d.id
		WHERE d.status = 'active' AND d.suspended = 0
		  AND p.revoked_at IS NULL AND p.desired_state <> 'revoked'
		ORDER BY d.id`)
	if err != nil {
		return snap, fmt.Errorf("list provisioned peers: %w", err)
	}
	var peers []peer
	for rows.Next() {
		var p peer
		var raw string
		if err := rows.Scan(&p.deviceID, &p.peerID, &p.publicKey, &raw, &p.configRevision, &p.applied); err != nil {
			rows.Close()
			return snap, fmt.Errorf("scan provisioned peer: %w", err)
		}
		if addr, ok := parsePeerAddress(raw); ok {
			p.address = addr
			peers = append(peers, p)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return snap, err
	}
	rows.Close()

	// Two active peers must never share a tunnel address. If they do (for
	// example overlapping pools), neither is attributed: ambiguity is denial.
	owners := map[netip.Addr]int{}
	for _, p := range peers {
		owners[p.address]++
	}
	unique := peers[:0]
	for _, p := range peers {
		if owners[p.address] > 1 {
			snap.AddressConflicts++
			continue
		}
		unique = append(unique, p)
	}
	peers = unique
	if len(peers) == 0 {
		return snap, nil
	}

	scopes := map[string]*domain.DeviceScopes{}
	mrows, err := s.db.QueryContext(ctx, `SELECT device_id, scope_type, scope_id FROM device_scope_memberships ORDER BY device_id`)
	if err != nil {
		return snap, fmt.Errorf("list device scopes: %w", err)
	}
	for mrows.Next() {
		var deviceID, scopeType, scopeID string
		if err := mrows.Scan(&deviceID, &scopeType, &scopeID); err != nil {
			mrows.Close()
			return snap, fmt.Errorf("scan device scope: %w", err)
		}
		sc := scopes[deviceID]
		if sc == nil {
			sc = &domain.DeviceScopes{GroupIDs: []string{}}
			scopes[deviceID] = sc
		}
		switch scopeType {
		case domain.ScopeTenant:
			sc.TenantID = scopeID
		case domain.ScopeSite:
			sc.SiteID = scopeID
		case domain.ScopeGroup:
			sc.GroupIDs = append(sc.GroupIDs, scopeID)
		}
	}
	if err := mrows.Err(); err != nil {
		mrows.Close()
		return snap, err
	}
	mrows.Close()

	var grants []domain.ServiceGrant
	grows, err := s.db.QueryContext(ctx, "SELECT "+serviceGrantColumns+" FROM service_grants WHERE revoked_at IS NULL")
	if err != nil {
		return snap, fmt.Errorf("list active grants: %w", err)
	}
	for grows.Next() {
		grant, err := scanServiceGrant(grows.Scan)
		if err != nil {
			grows.Close()
			return snap, fmt.Errorf("scan grant: %w", err)
		}
		grants = append(grants, grant)
	}
	if err := grows.Err(); err != nil {
		grows.Close()
		return snap, err
	}
	grows.Close()

	for _, p := range peers {
		deviceScopes := domain.DeviceScopes{GroupIDs: []string{}}
		if sc := scopes[p.deviceID]; sc != nil {
			deviceScopes = *sc
		}
		allowed := []string{}
		for _, def := range definitions {
			if domain.EvaluateServiceAccess(def, p.deviceID, true, deviceScopes, grants).Allowed {
				allowed = append(allowed, def.ID)
			}
		}
		if len(allowed) == 0 {
			continue
		}
		sort.Strings(allowed)
		snap.Targets = append(snap.Targets, ServiceAccessTarget{
			DeviceID: p.deviceID, PeerID: p.peerID, PublicKey: p.publicKey, Address: p.address,
			ConfigRevision: p.configRevision, AppliedRevision: p.applied, ServiceIDs: allowed,
		})
	}
	return snap, nil
}

// parsePeerAddress accepts "10.0.0.2" and "10.0.0.2/32" and returns the host
// address. Anything else, including a non-host prefix, is rejected.
func parsePeerAddress(raw string) (netip.Addr, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return netip.Addr{}, false
	}
	if strings.Contains(raw, "/") {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || prefix.Bits() != prefix.Addr().BitLen() {
			return netip.Addr{}, false
		}
		return prefix.Addr().Unmap(), true
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}
