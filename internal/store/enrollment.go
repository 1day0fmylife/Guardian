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

type EnrollmentCreate struct {
	Name              string
	ProfileID         string
	BoundDeviceUUID   string
	BoundSerialNumber string
	BoundMAC          string
	TTL               time.Duration
	CreatedByUserID   string
}

type EnrollmentIssued struct {
	Enrollment domain.Enrollment
	Token      string
}

func (s *Store) CreateEnrollment(ctx context.Context, input EnrollmentCreate) (EnrollmentIssued, error) {
	input.Name = strings.TrimSpace(input.Name)
	input.ProfileID = strings.TrimSpace(input.ProfileID)
	input.BoundDeviceUUID = strings.TrimSpace(input.BoundDeviceUUID)
	input.BoundSerialNumber = strings.TrimSpace(input.BoundSerialNumber)

	mac, err := normalizeMAC(input.BoundMAC)
	if err != nil {
		return EnrollmentIssued{}, err
	}
	input.BoundMAC = mac

	if input.ProfileID == "" {
		return EnrollmentIssued{}, fmt.Errorf("profile_id is required")
	}
	if input.TTL <= 0 {
		input.TTL = 15 * time.Minute
	}
	if input.TTL > 24*time.Hour {
		return EnrollmentIssued{}, fmt.Errorf("enrollment TTL cannot exceed 24 hours")
	}

	var profileExists int
	if err := s.db.QueryRowContext(ctx, s.q("SELECT COUNT(*) FROM vpn_profiles WHERE id = ?"), input.ProfileID).Scan(&profileExists); err != nil {
		return EnrollmentIssued{}, fmt.Errorf("check VPN profile: %w", err)
	}
	if profileExists == 0 {
		return EnrollmentIssued{}, ErrNotFound
	}

	token, err := security.NewOpaqueToken("gdn_e_")
	if err != nil {
		return EnrollmentIssued{}, err
	}
	id, err := security.NewID()
	if err != nil {
		return EnrollmentIssued{}, err
	}
	now := time.Now().UTC()
	expires := now.Add(input.TTL)
	enrollment := domain.Enrollment{
		ID:                id,
		Name:              input.Name,
		ProfileID:         input.ProfileID,
		BoundDeviceUUID:   input.BoundDeviceUUID,
		BoundSerialNumber: input.BoundSerialNumber,
		BoundMAC:          input.BoundMAC,
		ExpiresAt:         expires.Format(time.RFC3339Nano),
		CreatedAt:         now.Format(time.RFC3339Nano),
	}

	_, err = s.db.ExecContext(ctx, s.q(`
		INSERT INTO enrollment_tokens(
			id, token_hash, name, profile_id, bound_device_uuid,
			bound_serial_number, bound_mac, expires_at, created_by_user_id, created_at
		) VALUES(?, ?, ?, ?, ?, ?, ?, ?, NULLIF(?, ''), ?)
	`), enrollment.ID, security.HashToken(token), enrollment.Name, enrollment.ProfileID,
		enrollment.BoundDeviceUUID, enrollment.BoundSerialNumber, enrollment.BoundMAC,
		enrollment.ExpiresAt, input.CreatedByUserID, enrollment.CreatedAt)
	if err != nil {
		return EnrollmentIssued{}, fmt.Errorf("create enrollment: %w", err)
	}

	return EnrollmentIssued{Enrollment: enrollment, Token: token}, nil
}

func (s *Store) ListEnrollments(ctx context.Context, limit, offset int) ([]domain.Enrollment, int, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM enrollment_tokens").Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count enrollments: %w", err)
	}

	rows, err := s.db.QueryContext(ctx, s.q(`
		SELECT id, name, profile_id, bound_device_uuid, bound_serial_number, bound_mac,
		       expires_at, consumed_at, revoked_at, created_at
		FROM enrollment_tokens
		ORDER BY created_at DESC
		LIMIT ? OFFSET ?
	`), limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list enrollments: %w", err)
	}
	defer rows.Close()

	var result []domain.Enrollment
	for rows.Next() {
		var item domain.Enrollment
		var consumed, revoked sql.NullString
		if err := rows.Scan(&item.ID, &item.Name, &item.ProfileID, &item.BoundDeviceUUID,
			&item.BoundSerialNumber, &item.BoundMAC, &item.ExpiresAt, &consumed, &revoked, &item.CreatedAt); err != nil {
			return nil, 0, fmt.Errorf("scan enrollment: %w", err)
		}
		if consumed.Valid {
			item.ConsumedAt = consumed.String
		}
		if revoked.Valid {
			item.RevokedAt = revoked.String
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate enrollments: %w", err)
	}
	return result, total, nil
}

func (s *Store) RevokeEnrollment(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, s.q(`
		UPDATE enrollment_tokens
		SET revoked_at = ?
		WHERE id = ? AND consumed_at IS NULL AND revoked_at IS NULL
	`), nowText(), id)
	if err != nil {
		return fmt.Errorf("revoke enrollment: %w", err)
	}
	n, err := result.RowsAffected()
	if err == nil && n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) ClaimEnrollment(ctx context.Context, token string, input domain.EnrollmentClaim) (domain.EnrollmentClaimResult, error) {
	token = strings.TrimSpace(token)
	input.DeviceUUID = strings.TrimSpace(input.DeviceUUID)
	input.SerialNumber = strings.TrimSpace(input.SerialNumber)
	input.DeviceName = strings.TrimSpace(input.DeviceName)
	input.PublicKey = strings.TrimSpace(input.PublicKey)

	if token == "" || input.DeviceUUID == "" || input.DeviceName == "" {
		return domain.EnrollmentClaimResult{}, fmt.Errorf("token, device_uuid and device_name are required")
	}
	if len(input.DeviceName) > 200 || len(input.DeviceUUID) > 200 {
		return domain.EnrollmentClaimResult{}, fmt.Errorf("invalid device identity")
	}
	if err := security.ValidateWireGuardPublicKey(input.PublicKey); err != nil {
		return domain.EnrollmentClaimResult{}, err
	}
	mac, err := normalizeMAC(input.PrimaryMAC)
	if err != nil {
		return domain.EnrollmentClaimResult{}, err
	}
	input.PrimaryMAC = mac

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.EnrollmentClaimResult{}, fmt.Errorf("begin enrollment claim: %w", err)
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
	enrollmentQuery := `
		SELECT id, profile_id, bound_device_uuid, bound_serial_number, bound_mac,
		       expires_at, consumed_at, revoked_at
		FROM enrollment_tokens
		WHERE token_hash = ?
	`
	if s.dialect == "postgres" {
		enrollmentQuery += " FOR UPDATE"
	}
	err = tx.QueryRowContext(ctx, s.q(enrollmentQuery), security.HashToken(token)).Scan(
		&enrollmentID, &profileID, &boundUUID, &boundSerial, &boundMAC,
		&expiresAt, &consumedAt, &revokedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return domain.EnrollmentClaimResult{}, ErrNotFound
		}
		return domain.EnrollmentClaimResult{}, fmt.Errorf("load enrollment: %w", err)
	}

	expiry, err := time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil {
		return domain.EnrollmentClaimResult{}, fmt.Errorf("invalid stored enrollment expiry")
	}
	if consumedAt.Valid || revokedAt.Valid || !expiry.After(time.Now().UTC()) {
		return domain.EnrollmentClaimResult{}, ErrConflict
	}
	if boundUUID != "" && boundUUID != input.DeviceUUID {
		return domain.EnrollmentClaimResult{}, ErrConflict
	}
	if boundSerial != "" && boundSerial != input.SerialNumber {
		return domain.EnrollmentClaimResult{}, ErrConflict
	}
	if boundMAC != "" && boundMAC != input.PrimaryMAC {
		return domain.EnrollmentClaimResult{}, ErrConflict
	}

	device, err := s.getOrCreateEnrollmentDeviceTx(ctx, tx, input)
	if err != nil {
		return domain.EnrollmentClaimResult{}, err
	}

	var (
		serverPublicKey string
		endpoint        string
		allowedRaw      string
		dnsRaw          string
		keepalive       int
		poolID          string
	)
	err = tx.QueryRowContext(ctx, s.q(`
		SELECT server_public_key, endpoint, allowed_ips, dns_servers,
		       persistent_keepalive, address_pool_id
		FROM vpn_profiles
		WHERE id = ?
	`), profileID).Scan(&serverPublicKey, &endpoint, &allowedRaw, &dnsRaw, &keepalive, &poolID)
	if err != nil {
		if err == sql.ErrNoRows {
			return domain.EnrollmentClaimResult{}, ErrNotFound
		}
		return domain.EnrollmentClaimResult{}, fmt.Errorf("load enrollment VPN profile: %w", err)
	}

	var existingPeer int
	if err := tx.QueryRowContext(ctx, s.q("SELECT COUNT(*) FROM wireguard_peers WHERE device_id = ? AND revoked_at IS NULL"), device.ID).Scan(&existingPeer); err != nil {
		return domain.EnrollmentClaimResult{}, fmt.Errorf("check existing peer: %w", err)
	}
	if existingPeer != 0 {
		return domain.EnrollmentClaimResult{}, ErrConflict
	}
	var publicKeyExists int
	if err := tx.QueryRowContext(ctx, s.q("SELECT COUNT(*) FROM wireguard_peers WHERE public_key = ?"), input.PublicKey).Scan(&publicKeyExists); err != nil {
		return domain.EnrollmentClaimResult{}, fmt.Errorf("check WireGuard public key: %w", err)
	}
	if publicKeyExists != 0 {
		return domain.EnrollmentClaimResult{}, ErrConflict
	}

	address, err := s.allocateAddressTx(ctx, tx, poolID, device.ID)
	if err != nil {
		return domain.EnrollmentClaimResult{}, err
	}
	peerID, err := security.NewID()
	if err != nil {
		return domain.EnrollmentClaimResult{}, err
	}
	now := nowText()
	_, err = tx.ExecContext(ctx, s.q(`
		INSERT INTO wireguard_peers(
			id, device_id, profile_id, public_key, assigned_address,
			desired_state, observed_state, config_revision, created_at, updated_at
		) VALUES(?, ?, ?, ?, ?, 'connected', 'unknown', 1, ?, ?)
	`), peerID, device.ID, profileID, input.PublicKey, address, now, now)
	if err != nil {
		return domain.EnrollmentClaimResult{}, fmt.Errorf("create WireGuard peer: %w", err)
	}

	_, err = tx.ExecContext(ctx, s.q(`
		UPDATE enrollment_tokens SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL
	`), now, enrollmentID)
	if err != nil {
		return domain.EnrollmentClaimResult{}, fmt.Errorf("consume enrollment: %w", err)
	}
	_, err = tx.ExecContext(ctx, s.q(`
		UPDATE devices SET status = 'active', updated_at = ? WHERE id = ?
	`), now, device.ID)
	if err != nil {
		return domain.EnrollmentClaimResult{}, fmt.Errorf("activate enrolled device: %w", err)
	}
	device.Status = "active"
	device.UpdatedAt = now

	if err := tx.Commit(); err != nil {
		return domain.EnrollmentClaimResult{}, fmt.Errorf("commit enrollment claim: %w", err)
	}

	return domain.EnrollmentClaimResult{
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
	}, nil
}

func (s *Store) getOrCreateEnrollmentDeviceTx(ctx context.Context, tx *sql.Tx, input domain.EnrollmentClaim) (domain.Device, error) {
	var d domain.Device
	var suspended int
	var lastSeen sql.NullString
	err := tx.QueryRowContext(ctx, s.q(`
		SELECT id, name, device_uuid, serial_number, primary_mac, status,
		       suspended, created_at, updated_at, last_seen_at
		FROM devices WHERE device_uuid = ?
	`), input.DeviceUUID).Scan(
		&d.ID, &d.Name, &d.DeviceUUID, &d.SerialNumber, &d.PrimaryMAC, &d.Status,
		&suspended, &d.CreatedAt, &d.UpdatedAt, &lastSeen,
	)
	if err == nil {
		d.Suspended = suspended != 0
		if d.Suspended {
			return domain.Device{}, ErrConflict
		}
		if d.SerialNumber != "" && input.SerialNumber != "" && d.SerialNumber != input.SerialNumber {
			return domain.Device{}, ErrConflict
		}
		if d.PrimaryMAC != "" && input.PrimaryMAC != "" && d.PrimaryMAC != input.PrimaryMAC {
			return domain.Device{}, ErrConflict
		}
		return d, nil
	}
	if err != sql.ErrNoRows {
		return domain.Device{}, fmt.Errorf("lookup enrollment device: %w", err)
	}

	id, err := security.NewID()
	if err != nil {
		return domain.Device{}, err
	}
	now := nowText()
	d = domain.Device{
		ID:           id,
		Name:         input.DeviceName,
		DeviceUUID:   input.DeviceUUID,
		SerialNumber: input.SerialNumber,
		PrimaryMAC:   input.PrimaryMAC,
		Status:       "pending",
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	_, err = tx.ExecContext(ctx, s.q(`
		INSERT INTO devices(
			id, name, device_uuid, serial_number, primary_mac,
			status, suspended, created_at, updated_at
		) VALUES(?, ?, ?, ?, ?, 'pending', 0, ?, ?)
	`), d.ID, d.Name, d.DeviceUUID, d.SerialNumber, d.PrimaryMAC, now, now)
	if err != nil {
		return domain.Device{}, fmt.Errorf("create enrollment device: %w", err)
	}

	identities := [][2]string{{"device_uuid", d.DeviceUUID}}
	if d.SerialNumber != "" {
		identities = append(identities, [2]string{"serial_number", d.SerialNumber})
	}
	if d.PrimaryMAC != "" {
		identities = append(identities, [2]string{"mac", d.PrimaryMAC})
	}
	for _, identity := range identities {
		identityID, err := security.NewID()
		if err != nil {
			return domain.Device{}, err
		}
		if _, err := tx.ExecContext(ctx, s.q(`
			INSERT INTO device_identities(id, device_id, kind, value, verified, created_at)
			VALUES(?, ?, ?, ?, 1, ?)
		`), identityID, d.ID, identity[0], identity[1], now); err != nil {
			return domain.Device{}, fmt.Errorf("create enrollment identity: %w", err)
		}
	}
	return d, nil
}
