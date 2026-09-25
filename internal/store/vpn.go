package store

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"strings"

	"github.com/1day0fmylife/Guardian/internal/domain"
	"github.com/1day0fmylife/Guardian/internal/security"
)

type AddressPoolCreate struct {
	Name       string
	CIDR       string
	Gateway    string
	DNSServers []string
}

func (s *Store) CreateAddressPool(ctx context.Context, input AddressPoolCreate) (domain.AddressPool, error) {
	input.Name = strings.TrimSpace(input.Name)
	input.CIDR = strings.TrimSpace(input.CIDR)
	input.Gateway = strings.TrimSpace(input.Gateway)
	if input.Name == "" || len(input.Name) > 200 {
		return domain.AddressPool{}, fmt.Errorf("invalid pool name")
	}
	prefix, err := netip.ParsePrefix(input.CIDR)
	if err != nil || !prefix.Addr().Is4() {
		return domain.AddressPool{}, fmt.Errorf("phase 1 address pools must use a valid IPv4 CIDR")
	}
	prefix = prefix.Masked()
	input.CIDR = prefix.String()
	if prefix.Bits() < 16 || prefix.Bits() > 30 {
		return domain.AddressPool{}, fmt.Errorf("address pool prefix must be between /16 and /30")
	}
	if input.Gateway != "" {
		gateway, err := netip.ParseAddr(input.Gateway)
		if err != nil || !gateway.Is4() || !prefix.Contains(gateway) {
			return domain.AddressPool{}, fmt.Errorf("gateway must be an IPv4 address within the pool")
		}
		input.Gateway = gateway.String()
	}
	dns := normalizeStringList(input.DNSServers)
	for _, value := range dns {
		if _, err := netip.ParseAddr(value); err != nil {
			return domain.AddressPool{}, fmt.Errorf("invalid DNS server %q", value)
		}
	}

	id, err := security.NewID()
	if err != nil {
		return domain.AddressPool{}, err
	}
	now := nowText()
	_, err = s.db.ExecContext(ctx, s.q(`
		INSERT INTO address_pools(id, name, cidr, gateway, dns_servers, created_at, updated_at)
		VALUES(?, ?, ?, ?, ?, ?, ?)
	`), id, input.Name, input.CIDR, input.Gateway, strings.Join(dns, ","), now, now)
	if err != nil {
		return domain.AddressPool{}, fmt.Errorf("create address pool: %w", err)
	}
	return domain.AddressPool{
		ID: id, Name: input.Name, CIDR: input.CIDR, Gateway: input.Gateway,
		DNSServers: dns, CreatedAt: now, UpdatedAt: now,
	}, nil
}

func (s *Store) ListAddressPools(ctx context.Context) ([]domain.AddressPool, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, cidr, gateway, dns_servers, created_at, updated_at
		FROM address_pools ORDER BY name
	`)
	if err != nil {
		return nil, fmt.Errorf("list address pools: %w", err)
	}
	defer rows.Close()

	var pools []domain.AddressPool
	for rows.Next() {
		var p domain.AddressPool
		var dns string
		if err := rows.Scan(&p.ID, &p.Name, &p.CIDR, &p.Gateway, &dns, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan address pool: %w", err)
		}
		p.DNSServers = splitList(dns)
		pools = append(pools, p)
	}
	return pools, rows.Err()
}

type VPNProfileCreate struct {
	Name                string
	ServerPublicKey     string
	Endpoint            string
	AllowedIPs          []string
	DNSServers          []string
	PersistentKeepalive int
	AddressPoolID       string
}

func (s *Store) CreateVPNProfile(ctx context.Context, input VPNProfileCreate) (domain.VPNProfile, error) {
	input.Name = strings.TrimSpace(input.Name)
	input.Endpoint = strings.TrimSpace(input.Endpoint)
	input.AddressPoolID = strings.TrimSpace(input.AddressPoolID)
	if input.Name == "" || input.Endpoint == "" || input.AddressPoolID == "" {
		return domain.VPNProfile{}, fmt.Errorf("name, endpoint and address_pool_id are required")
	}
	if err := security.ValidateWireGuardPublicKey(strings.TrimSpace(input.ServerPublicKey)); err != nil {
		return domain.VPNProfile{}, err
	}
	input.ServerPublicKey = strings.TrimSpace(input.ServerPublicKey)
	if input.PersistentKeepalive == 0 {
		input.PersistentKeepalive = 25
	}
	if input.PersistentKeepalive < 0 || input.PersistentKeepalive > 65535 {
		return domain.VPNProfile{}, fmt.Errorf("invalid persistent keepalive")
	}
	allowed := normalizeStringList(input.AllowedIPs)
	if len(allowed) == 0 {
		allowed = []string{"0.0.0.0/0"}
	}
	for _, value := range allowed {
		if _, err := netip.ParsePrefix(value); err != nil {
			return domain.VPNProfile{}, fmt.Errorf("invalid allowed IP %q", value)
		}
	}
	dns := normalizeStringList(input.DNSServers)
	for _, value := range dns {
		if _, err := netip.ParseAddr(value); err != nil {
			return domain.VPNProfile{}, fmt.Errorf("invalid DNS server %q", value)
		}
	}

	var poolExists int
	if err := s.db.QueryRowContext(ctx, s.q("SELECT COUNT(*) FROM address_pools WHERE id = ?"), input.AddressPoolID).Scan(&poolExists); err != nil {
		return domain.VPNProfile{}, fmt.Errorf("check address pool: %w", err)
	}
	if poolExists == 0 {
		return domain.VPNProfile{}, ErrNotFound
	}

	id, err := security.NewID()
	if err != nil {
		return domain.VPNProfile{}, err
	}
	now := nowText()
	_, err = s.db.ExecContext(ctx, s.q(`
		INSERT INTO vpn_profiles(
			id, name, server_public_key, endpoint, allowed_ips,
			dns_servers, persistent_keepalive, address_pool_id, created_at, updated_at
		) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`), id, input.Name, input.ServerPublicKey, input.Endpoint, strings.Join(allowed, ","),
		strings.Join(dns, ","), input.PersistentKeepalive, input.AddressPoolID, now, now)
	if err != nil {
		return domain.VPNProfile{}, fmt.Errorf("create VPN profile: %w", err)
	}
	return domain.VPNProfile{
		ID: id, Name: input.Name, ServerPublicKey: input.ServerPublicKey, Endpoint: input.Endpoint,
		AllowedIPs: allowed, DNSServers: dns, PersistentKeepalive: input.PersistentKeepalive,
		AddressPoolID: input.AddressPoolID, CreatedAt: now, UpdatedAt: now,
	}, nil
}

func (s *Store) GetVPNProfile(ctx context.Context, id string) (domain.VPNProfile, error) {
	var p domain.VPNProfile
	var allowed, dns string
	err := s.db.QueryRowContext(ctx, s.q(`
		SELECT id, name, server_public_key, endpoint, allowed_ips, dns_servers,
		       persistent_keepalive, address_pool_id, created_at, updated_at
		FROM vpn_profiles WHERE id = ?
	`), id).Scan(&p.ID, &p.Name, &p.ServerPublicKey, &p.Endpoint, &allowed, &dns,
		&p.PersistentKeepalive, &p.AddressPoolID, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return domain.VPNProfile{}, ErrNotFound
		}
		return domain.VPNProfile{}, fmt.Errorf("get VPN profile: %w", err)
	}
	p.AllowedIPs = splitList(allowed)
	p.DNSServers = splitList(dns)
	return p, nil
}

func (s *Store) ListVPNProfiles(ctx context.Context) ([]domain.VPNProfile, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, server_public_key, endpoint, allowed_ips, dns_servers,
		       persistent_keepalive, address_pool_id, created_at, updated_at
		FROM vpn_profiles ORDER BY name
	`)
	if err != nil {
		return nil, fmt.Errorf("list VPN profiles: %w", err)
	}
	defer rows.Close()

	var profiles []domain.VPNProfile
	for rows.Next() {
		var p domain.VPNProfile
		var allowed, dns string
		if err := rows.Scan(&p.ID, &p.Name, &p.ServerPublicKey, &p.Endpoint, &allowed, &dns,
			&p.PersistentKeepalive, &p.AddressPoolID, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan VPN profile: %w", err)
		}
		p.AllowedIPs = splitList(allowed)
		p.DNSServers = splitList(dns)
		profiles = append(profiles, p)
	}
	return profiles, rows.Err()
}

func normalizeStringList(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func splitList(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return normalizeStringList(strings.Split(value, ","))
}

func nextIPv4(addr netip.Addr) (netip.Addr, bool) {
	if !addr.Is4() {
		return netip.Addr{}, false
	}
	b := addr.As4()
	n := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	if n == ^uint32(0) {
		return netip.Addr{}, false
	}
	n++
	return netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}), true
}

func (s *Store) allocateAddressTx(ctx context.Context, tx *sql.Tx, poolID, deviceID string) (string, error) {
	var cidr, gateway string
	poolQuery := "SELECT cidr, gateway FROM address_pools WHERE id = ?"
	if s.dialect == "postgres" {
		poolQuery += " FOR UPDATE"
	}
	err := tx.QueryRowContext(ctx, s.q(poolQuery), poolID).Scan(&cidr, &gateway)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("load address pool: %w", err)
	}
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil || !prefix.Addr().Is4() {
		return "", fmt.Errorf("invalid stored address pool")
	}
	prefix = prefix.Masked()
	network := prefix.Addr()

	// Never allocate the network address. The final address in the prefix is
	// reserved as the IPv4 broadcast address. Gateway, when configured, is
	// also excluded.
	candidate, ok := nextIPv4(network)
	if !ok {
		return "", fmt.Errorf("address pool exhausted")
	}
	maxCandidates := 1 << (32 - prefix.Bits())
	for i := 1; i < maxCandidates-1 && prefix.Contains(candidate); i++ {
		if candidate.String() == gateway {
			candidate, ok = nextIPv4(candidate)
			if !ok {
				break
			}
			continue
		}

		var used int
		err := tx.QueryRowContext(ctx, s.q(`
			SELECT COUNT(*) FROM address_leases
			WHERE pool_id = ? AND address = ? AND status = 'active'
		`), poolID, candidate.String()).Scan(&used)
		if err != nil {
			return "", fmt.Errorf("check address lease: %w", err)
		}
		if used == 0 {
			leaseID, err := security.NewID()
			if err != nil {
				return "", err
			}
			_, err = tx.ExecContext(ctx, s.q(`
				INSERT INTO address_leases(id, pool_id, device_id, address, status, allocated_at)
				VALUES(?, ?, ?, ?, 'active', ?)
			`), leaseID, poolID, deviceID, candidate.String(), nowText())
			if err != nil {
				return "", fmt.Errorf("allocate address: %w", err)
			}
			return candidate.String(), nil
		}

		candidate, ok = nextIPv4(candidate)
		if !ok {
			break
		}
	}
	return "", fmt.Errorf("address pool exhausted")
}
