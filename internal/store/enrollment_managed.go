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
// issuance in one transaction. New managed devices may pre-generate their
// credential and submit only its SHA-256 hash, eliminating the crash window
// between consuming the enrollment token and persisting a server-generated
// plaintext credential. Legacy clients may omit the hash and receive a
// server-generated credential exactly once.
func (s *Store) ClaimManagedEnrollment(ctx context.Context, token string, input domain.EnrollmentClaim) (domain.ManagedEnrollmentClaimResult, error) {
	token = strings.TrimSpace(token)
	input.DeviceUUID = strings.TrimSpace(input.DeviceUUID)
	input.SerialNumber = strings.TrimSpace(input.SerialNumber)
	input.DeviceName = strings.TrimSpace(input.DeviceName)
	input.PublicKey = strings.TrimSpace(input.PublicKey)
	input.DeviceCredentialHash = strings.TrimSpace(input.DeviceCredentialHash)
	if token == "" || input.DeviceUUID == "" || input.DeviceName == "" {
		return domain.ManagedEnrollmentClaimResult{}, invalidf("token, device_uuid and device_name are required")
	}
	if len(input.DeviceName) > 200 || len(input.DeviceUUID) > 200 {
		return domain.ManagedEnrollmentClaimResult{}, invalidf("invalid device identity")
	}
	if err := security.ValidateWireGuardPublicKey(input.PublicKey); err != nil {
		return domain.ManagedEnrollmentClaimResult{}, err
	}
	if input.DeviceCredentialHash != "" {
		if err := validateDeviceCredentialHash(input.DeviceCredentialHash); err != nil {
			return domain.ManagedEnrollmentClaimResult{}, err
		}
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

	device, previousStatus, err := s.getOrCreateEnrollmentDeviceTx(ctx, tx, input, boundUUID)
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

	peerID, address, configRevision, err := s.enrollPeerTx(ctx, tx, device.ID, profileID, poolID, input.PublicKey, previousStatus == "revoked")
	if err != nil {
		return domain.ManagedEnrollmentClaimResult{}, err
	}
	now := nowText()

	var credential domain.DeviceCredentialIssued
	if input.DeviceCredentialHash != "" {
		credential, err = s.issueDeviceCredentialHashTx(ctx, tx, device.ID, input.DeviceCredentialHash)
	} else {
		credential, err = s.issueDeviceCredentialTx(ctx, tx, device.ID)
	}
	if err != nil {
		return domain.ManagedEnrollmentClaimResult{}, err
	}
	if _, err := tx.ExecContext(ctx, s.q(`
		UPDATE enrollment_tokens SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL
	`), now, enrollmentID); err != nil {
		return domain.ManagedEnrollmentClaimResult{}, fmt.Errorf("consume enrollment: %w", err)
	}
	if _, err := tx.ExecContext(ctx, s.q(`
		UPDATE devices SET status = 'active', suspended = 0, updated_at = ? WHERE id = ?
	`), now, device.ID); err != nil {
		return domain.ManagedEnrollmentClaimResult{}, fmt.Errorf("activate enrolled device: %w", err)
	}
	device.Status = "active"
	device.Suspended = false
	device.UpdatedAt = now

	if _, err := s.bumpServicePolicyRevision(ctx, tx); err != nil {
		return domain.ManagedEnrollmentClaimResult{}, err
	}
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
			ConfigRevision:      configRevision,
		},
		Credential:     credential,
		Reactivated:    previousStatus == "revoked",
		PreviousStatus: previousStatus,
	}, nil
}
