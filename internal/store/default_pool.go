package store

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
)

// DefaultAddressPoolName names the pool seeded on an empty database.
const DefaultAddressPoolName = "Default"

// EnsureDefaultAddressPool creates a pool for cidr when no address pools exist,
// reserving the first host as the gateway. Once any pool exists it is a no-op,
// so operators keep full control after first start.
func (s *Store) EnsureDefaultAddressPool(ctx context.Context, cidr string) (bool, error) {
	var count int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM address_pools").Scan(&count); err != nil {
		return false, fmt.Errorf("count address pools: %w", err)
	}
	if count > 0 {
		return false, nil
	}
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return false, fmt.Errorf("default address pool: %w", err)
	}
	gateway := prefix.Masked().Addr().Next()
	_, err = s.createAddressPool(ctx, &AuditMeta{}, AddressPoolCreate{
		Name: DefaultAddressPoolName, CIDR: cidr, Gateway: gateway.String(),
	})
	if errors.Is(err, ErrConflict) {
		// Another instance seeded concurrently.
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}
