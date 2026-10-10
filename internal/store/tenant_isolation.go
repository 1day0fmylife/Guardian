package store

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"

	"github.com/1day0fmylife/Guardian/internal/domain"
)

// validateIsolationUpgrade refuses ambiguous legacy ownership or overlapping
// pools. Operators must resolve these offline, never silently remap live peers.
func (s *Store) validateIsolationUpgrade(ctx context.Context, tx *sql.Tx) error {
	var ambiguous int
	err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM (
 SELECT m.scope_type, m.scope_id FROM device_scope_memberships m
 LEFT JOIN device_scope_memberships t ON t.device_id = m.device_id AND t.scope_type = 'tenant'
 WHERE m.scope_type IN ('site', 'group')
 GROUP BY m.scope_type, m.scope_id HAVING COUNT(DISTINCT COALESCE(t.scope_id, '')) > 1
 ) conflicts`).Scan(&ambiguous)
	if err != nil {
		return fmt.Errorf("validate scope ownership: %w", err)
	}
	if ambiguous != 0 {
		return fmt.Errorf("migration 009 requires resolving ambiguous site/group tenant ownership offline")
	}
	prefixes, err := loadPoolPrefixes(ctx, tx)
	if err != nil {
		return err
	}
	for i, a := range prefixes {
		for _, b := range prefixes[i+1:] {
			if a.Overlaps(b) {
				return fmt.Errorf("migration 009 requires resolving overlapping tunnel pools offline")
			}
		}
	}
	return nil
}

func loadPoolPrefixes(ctx context.Context, q sqlQueryer) ([]netip.Prefix, error) {
	rows, err := q.QueryContext(ctx, "SELECT cidr FROM address_pools")
	if err != nil {
		return nil, fmt.Errorf("load pool prefixes: %w", err)
	}
	defer rows.Close()
	prefixes := []netip.Prefix{}
	for rows.Next() {
		var cidr string
		if err := rows.Scan(&cidr); err != nil {
			return nil, err
		}
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil || !prefix.Addr().Is4() || prefix.Bits() < 16 || prefix.Bits() > 30 {
			return nil, fmt.Errorf("invalid stored tunnel pool")
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes, rows.Err()
}

func scopeOwnerConflict() error {
	return catalogErr(ErrConflict, "scope_tenant_conflict", "site or group belongs to a different tenant namespace; use a distinct identifier")
}

// bindScopeOwnersTx keeps owners after memberships disappear, so an old grant
// cannot be inherited by a different tenant reusing the identifier.
func (s *Store) bindScopeOwnersTx(ctx context.Context, tx *sql.Tx, scopes domain.DeviceScopes) error {
	bind := func(kind, id string) error {
		if id == "" {
			return nil
		}
		if _, err := tx.ExecContext(ctx, s.q(`INSERT INTO scope_owners(scope_type, scope_id, tenant_id) VALUES(?, ?, ?) ON CONFLICT(scope_type, scope_id) DO NOTHING`), kind, id, scopes.TenantID); err != nil {
			return fmt.Errorf("register scope owner: %w", err)
		}
		var owner string
		if err := tx.QueryRowContext(ctx, s.q("SELECT tenant_id FROM scope_owners WHERE scope_type = ? AND scope_id = ?"), kind, id).Scan(&owner); err != nil {
			return fmt.Errorf("read scope owner: %w", err)
		}
		if owner != scopes.TenantID {
			return scopeOwnerConflict()
		}
		return nil
	}
	if err := bind(domain.ScopeSite, scopes.SiteID); err != nil {
		return err
	}
	for _, group := range scopes.GroupIDs {
		if err := bind(domain.ScopeGroup, group); err != nil {
			return err
		}
	}
	return nil
}

// validateScopeOwners fails closed if offline edits introduce invalid ownership.
func (s *Store) validateScopeOwners(ctx context.Context, q sqlQueryer, scopes domain.DeviceScopes) error {
	check := func(kind, id string) error {
		if id == "" {
			return nil
		}
		var owner string
		if err := q.QueryRowContext(ctx, s.q("SELECT tenant_id FROM scope_owners WHERE scope_type = ? AND scope_id = ?"), kind, id).Scan(&owner); err != nil {
			return scopeOwnerConflict()
		}
		if owner != scopes.TenantID {
			return scopeOwnerConflict()
		}
		return nil
	}
	if err := check(domain.ScopeSite, scopes.SiteID); err != nil {
		return err
	}
	for _, group := range scopes.GroupIDs {
		if err := check(domain.ScopeGroup, group); err != nil {
			return err
		}
	}
	return nil
}
