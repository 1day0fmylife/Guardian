package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
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
	return s.createAddressPool(ctx, nil, input)
}

// CreateAddressPoolAudited validates global pool uniqueness and audits atomically.
func (s *Store) CreateAddressPoolAudited(ctx context.Context, meta AuditMeta, input AddressPoolCreate) (domain.AddressPool, error) {
	return s.createAddressPool(ctx, &meta, input)
}

func (s *Store) createAddressPool(ctx context.Context, meta *AuditMeta, input AddressPoolCreate) (domain.AddressPool, error) {
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
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.AddressPool{}, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "UPDATE network_allocation_state SET revision = revision + 1 WHERE id = 1"); err != nil {
		return domain.AddressPool{}, fmt.Errorf("lock pool allocation: %w", err)
	}
	prefixes, err := loadPoolPrefixes(ctx, tx)
	if err != nil {
		return domain.AddressPool{}, err
	}
	for _, existing := range prefixes {
		if prefix.Overlaps(existing) {
			return domain.AddressPool{}, catalogErr(ErrConflict, "address_pool_overlap", "tunnel address pools must not overlap")
		}
	}
	now := nowText()
	_, err = tx.ExecContext(ctx, s.q(`
		INSERT INTO address_pools(id, name, cidr, gateway, dns_servers, created_at, updated_at)
		VALUES(?, ?, ?, ?, ?, ?, ?)
	`), id, input.Name, input.CIDR, input.Gateway, strings.Join(dns, ","), now, now)
	if err != nil {
		return domain.AddressPool{}, fmt.Errorf("create address pool: %w", err)
	}
	if meta != nil {
		if err := s.appendAuditTx(ctx, tx, *meta, "address_pool.create", "address_pool", id, map[string]any{"cidr": input.CIDR}); err != nil {
			return domain.AddressPool{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return domain.AddressPool{}, err
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

	pools := []domain.AddressPool{}
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
	input.AddressPoolID = strings.TrimSpace(input.AddressPoolID)
	if input.Name == "" || strings.TrimSpace(input.Endpoint) == "" || input.AddressPoolID == "" {
		return domain.VPNProfile{}, fmt.Errorf("name, endpoint and address_pool_id are required")
	}
	if input.PersistentKeepalive == 0 {
		input.PersistentKeepalive = 25
	}
	if len(normalizeStringList(input.AllowedIPs)) == 0 {
		input.AllowedIPs = []string{"0.0.0.0/0"}
	}
	fields := vpnProfileFields{
		ServerPublicKey: input.ServerPublicKey, Endpoint: input.Endpoint, AllowedIPs: input.AllowedIPs,
		DNSServers: input.DNSServers, PersistentKeepalive: input.PersistentKeepalive,
	}
	if err := fields.normalize(); err != nil {
		return domain.VPNProfile{}, err
	}
	input.ServerPublicKey, input.Endpoint = fields.ServerPublicKey, fields.Endpoint
	allowed, dns := fields.AllowedIPs, fields.DNSServers

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
		AddressPoolID: input.AddressPoolID, Revision: 1, CreatedAt: now, UpdatedAt: now,
	}, nil
}

const vpnProfileColumns = `id, name, server_public_key, endpoint, allowed_ips, dns_servers,
		       persistent_keepalive, address_pool_id, revision, previous_server_public_key,
		       previous_endpoint, previous_valid_until, created_at, updated_at`

func scanVPNProfile(scan scanFunc) (domain.VPNProfile, error) {
	var p domain.VPNProfile
	var allowed, dns string
	var validUntil sql.NullString
	if err := scan(&p.ID, &p.Name, &p.ServerPublicKey, &p.Endpoint, &allowed, &dns,
		&p.PersistentKeepalive, &p.AddressPoolID, &p.Revision, &p.PreviousServerPublicKey,
		&p.PreviousEndpoint, &validUntil, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return domain.VPNProfile{}, err
	}
	p.AllowedIPs = splitList(allowed)
	p.DNSServers = splitList(dns)
	if validUntil.Valid {
		p.PreviousValidUntil = validUntil.String
	}
	return p, nil
}

// vpnProfileFields are the profile values every device applies.
type vpnProfileFields struct {
	ServerPublicKey     string
	Endpoint            string
	AllowedIPs          []string
	DNSServers          []string
	PersistentKeepalive int
}

func (f *vpnProfileFields) normalize() error {
	f.ServerPublicKey = strings.TrimSpace(f.ServerPublicKey)
	f.Endpoint = strings.TrimSpace(f.Endpoint)
	if err := security.ValidateWireGuardPublicKey(f.ServerPublicKey); err != nil {
		return err
	}
	if host, port, err := net.SplitHostPort(f.Endpoint); err != nil || host == "" || port == "" {
		return invalidf("endpoint must be host:port")
	} else if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return invalidf("endpoint port is invalid")
	}
	if f.PersistentKeepalive < 0 || f.PersistentKeepalive > 65535 {
		return invalidf("invalid persistent keepalive")
	}
	f.AllowedIPs = normalizeStringList(f.AllowedIPs)
	if len(f.AllowedIPs) == 0 {
		return invalidf("allowed_ips must not be empty")
	}
	for _, value := range f.AllowedIPs {
		if _, err := netip.ParsePrefix(value); err != nil {
			return invalidf("invalid allowed IP %q", value)
		}
	}
	f.DNSServers = normalizeStringList(f.DNSServers)
	for _, value := range f.DNSServers {
		if _, err := netip.ParseAddr(value); err != nil {
			return invalidf("invalid DNS server %q", value)
		}
	}
	return nil
}

func (s *Store) GetVPNProfile(ctx context.Context, id string) (domain.VPNProfile, error) {
	row := s.db.QueryRowContext(ctx, s.q("SELECT "+vpnProfileColumns+" FROM vpn_profiles WHERE id = ?"), id)
	p, err := scanVPNProfile(row.Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.VPNProfile{}, ErrNotFound
		}
		return domain.VPNProfile{}, fmt.Errorf("get VPN profile: %w", err)
	}
	return p, nil
}

func (s *Store) ListVPNProfiles(ctx context.Context) ([]domain.VPNProfile, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+vpnProfileColumns+" FROM vpn_profiles ORDER BY name")
	if err != nil {
		return nil, fmt.Errorf("list VPN profiles: %w", err)
	}
	defer rows.Close()

	profiles := []domain.VPNProfile{}
	for rows.Next() {
		p, err := scanVPNProfile(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("scan VPN profile: %w", err)
		}
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
			WHERE address = ? AND status IN ('active', 'revoking')
		`), candidate.String()).Scan(&used)
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
