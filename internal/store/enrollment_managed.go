package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/1day0fmylife/Guardian/internal/domain"
	"github.com/1day0fmylife/Guardian/internal/security"
)

// ClaimManagedEnrollment performs enrollment and permanent device-credential
// issuance in one transaction. The plaintext credential is returned exactly
// once and Guardian stores only its hash.
func (s *Store) ClaimManagedEnrollment(ctx context.Context, token string, input domain.EnrollmentClaim) (domain.ManagedEnrollmentClaimResult, error) {
	token = strings.TrimSpace(token)
	input.DeviceUUID = strings.TrimSpace(input.DeviceUUID)
	input.SerialNumber = strings.TrimSpace(input.SerialNumber)
	input.DeviceName = strings.TrimSpace(input.DeviceName)
	input.PublicKey = strings.TrimSpace(input.PublicKey)
	if token == "" || input.DeviceUUID == "" || input.DeviceName == "" {
		return domain.ManagedEnrollmentClaimResult{}, invalidf("token, device_uuid and device_name are required")
	}
	if len(input.DeviceName) > 200 || len(input.DeviceUUID) > 200 {
		return domain.ManagedEnrollmentClaimResult{}, invalidf("invalid device identity")
	}
	if err := security.ValidateWireGuardPublicKey(input.PublicKey); err != nil {
		return domain.ManagedEnrollmentClaimResult{}, err
	}
	mac, err := normalizeMAC(input.PrimaryMAC)
	if err != nil {
		return domain.ManagedEnrollmentClaimResult{}, invalidf("invalid MAC address")
	}
	input.PrimaryMAC = mac

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.ManagedEnrollmentClaimResult{}, fmt.Errorf("begin managed enrollment: %w", err)
	}
	defer tx.Rollback()

	var (
		enrollmentID string
		profileID    string
		boundUUID    string
		boundSerial  string
		boundMAC     string
		expiresAt    string
		consumedAt   sql.NullString
		revokedAt    sql.NullString
	)
	query := `
		SELECT id, profile_id, bound_device_uuid, bound_serial_number, bound_mac,
		       expires_at, consumed_at, revoked_at
		FROM enrollment_tokens WHERE token_hash = ?
	`
	if s.dialect == "postgres" {
		query += " FOR UPDATE"
	}
	if err := tx.QueryRowContext(ctx, s.q(query), security.HashToken(token)).Scan(
		&enrollmentID, &profileID, &boundUUID, &boundSerial, &boundMAC,
		&expiresAt, &consumedAt, &revokedAt,
	); err != nil {
		if err == sql.ErrNoRows {
			return domain.ManagedEnrollmentClaimResult{}, ErrNotFound
		}
		return domain.ManagedEnrollmentClaimResult{}, fmt.Errorf("load enrollment: %w", err)
	}

	expiry, err := time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil {
		return domain.ManagedEnrollmentClaimResult{}, fmt.Errorf("invalid stored enrollment expiry")
	}
	if consumedAt.Valid || revokedAt.Valid || !expiry.After(time.Now().UTC()) {
		return domain.ManagedEnrollmentClaimResult{}, ErrConflict
	}
	if boundUUID != "" && boundUUID != input.DeviceUUID {
		return domain.ManagedEnrollmentClaimResult{}, ErrConflict
	}
	if boundSerial != "" && boundSerial != input.SerialNumber {
		return domain.ManagedEnrollmentClaimResult{}, ErrConflict
	}
	if boundMAC != "" && boundMAC != input.PrimaryMAC {
		return domain.ManagedEnrollmentClaimResult{}, ErrConflict
	}

	device, err := s.getOrCreateEnrollmentDeviceTx(ctx, tx, input)
	if err != nil {
		return domain.ManagedEnrollmentClaimResult{}, err
	}

	var (
		serverPublicKey string
		endpoint        string
		allowedRaw      string
		dnsRaw          string
		keepalive       int
		poolID          string
	)
	if err := tx.QueryRowContext(ctx, s.q(`
		SELECT server_public_key, endpoint, allowed_ips, dns_servers,
		       persistent_keepalive, address_pool_id
		FROM vpn_profiles WHERE id = ?
	`), profileID).Scan(&serverPublicKey, &endpoint, &allowedRaw, &dnsRaw, &keepalive, &poolID); err != nil {
		if err == sql.ErrNoRows {
			return domain.ManagedEnrollmentClaimResult{}, ErrNotFound
		}
		return domain.ManagedEnrollmentClaimResult{}, fmt.Errorf("load enrollment VPN profile: %w", err)
	}

	var existingPeer int
	if err := tx.QueryRowContext(ctx, s.q("SELECT COUNT(*) FROM wireguard_peers WHERE device_id = ? AND revoked_at IS NULL"), device.ID).Scan(&existingPeer); err != nil {
		return domain.ManagedEnrollmentClaimResult{}, fmt.Errorf("check existing peer: %w", err)
	}
	if existingPeer != 0 {
		return domain.ManagedEnrollmentClaimResult{}, ErrConflict
	}
	var publicKeyExists int
	if err := tx.QueryRowContext(ctx, s.q("SELECT COUNT(*) FROM wireguard_peers WHERE public_key = ?"), input.PublicKey).Scan(&publicKeyExists); err != nil {
		return domain.ManagedEnrollmentClaimResult{}, fmt.Errorf("check WireGuard public key: %w", err)
	}
	if publicKeyExists != 0 {
		return domain.ManagedEnrollmentClaimResult{}, ErrConflict
	}

	address, err := s.allocateAddressTx(ctx, tx, poolID, device.ID)
	if err != nil {
		return domain.ManagedEnrollmentClaimResult{}, err
	}
	peerID, err := security.NewID()
	if err != nil {
		return domain.ManagedEnrollmentClaimResult{}, err
	}
	now := nowText()
	if _, err := tx.ExecContext(ctx, s.q(`
		INSERT INTO wireguard_peers(
			id, device_id, profile_id, public_key, assigned_address,
			desired_state, observed_state, config_revision, created_at, updated_at
		) VALUES(?, ?, ?, ?, ?, 'connected', 'unknown', 1, ?, ?)
	`), peerID, device.ID, profileID, input.PublicKey, address, now, now); err != nil {
		return domain.ManagedEnrollmentClaimResult{}, fmt.Errorf("create WireGuard peer: %w", err)
	}

	credential, err := s.issueDeviceCredentialTx(ctx, tx, device.ID)
	if err != nil {
		return domain.ManagedEnrollmentClaimResult{}, err
	}
	if _, err := tx.ExecContext(ctx, s.q(`
		UPDATE enrollment_tokens SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL
	`), now, enrollmentID); err != nil {
		return domain.ManagedEnrollmentClaimResult{}, fmt.Errorf("consume enrollment: %w", err)
	}
	if _, err := tx.ExecContext(ctx, s.q(`
		UPDATE devices SET status = 'active', updated_at = ? WHERE id = ?
	`), now, device.ID); err != nil {
		return domain.ManagedEnrollmentClaimResult{}, fmt.Errorf("activate enrolled device: %w", err)
	}
	device.Status = "active"
	device.UpdatedAt = now

	if err := tx.Commit(); err != nil {
		return domain.ManagedEnrollmentClaimResult{}, fmt.Errorf("commit managed enrollment: %w", err)
	}

	return domain.ManagedEnrollmentClaimResult{
		Device: device,
		Config: domain.ManagedWireGuardConfig{
			DeviceID:            device.ID,
			PeerID:              peerID,
			ProfileID:           profileID,
			AssignedAddress:     address + "/32",
			ServerPublicKey:     serverPublicKey,
			Endpoint:            endpoint,
			AllowedIPs:          splitList(allowedRaw),
			DNSServers:          splitList(dnsRaw),
			PersistentKeepalive: keepalive,
			ConfigRevision:      1,
		},
		Credential: credential,
	}, nil
}
