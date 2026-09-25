package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/1day0fmylife/Guardian/internal/domain"
	"github.com/1day0fmylife/Guardian/internal/security"
)

const defaultCommandTTL = 5 * time.Minute

var allowedDeviceCommandTypes = map[string]struct{}{
	"connect":      {},
	"disconnect":   {},
	"apply-config": {},
	"rotate-key":   {},
}

type DeviceCommandCreate struct {
	DeviceID       string
	Type           string
	IdempotencyKey string
	Payload        json.RawMessage
	TTL            time.Duration
}

func (s *Store) issueDeviceCredentialTx(ctx context.Context, tx *sql.Tx, deviceID string) (domain.DeviceCredentialIssued, error) {
	token, err := security.NewOpaqueToken("gdn_d_")
	if err != nil {
		return domain.DeviceCredentialIssued{}, err
	}
	id, err := security.NewID()
	if err != nil {
		return domain.DeviceCredentialIssued{}, err
	}
	now := nowText()
	credential := domain.DeviceCredential{ID: id, DeviceID: deviceID, CreatedAt: now}
	if _, err := tx.ExecContext(ctx, s.q(`
		INSERT INTO device_credentials(id, device_id, token_hash, created_at)
		VALUES(?, ?, ?, ?)
	`), id, deviceID, security.HashToken(token), now); err != nil {
		return domain.DeviceCredentialIssued{}, fmt.Errorf("issue device credential: %w", err)
	}
	return domain.DeviceCredentialIssued{Credential: credential, Token: token}, nil
}

func (s *Store) DevicePrincipalByCredential(ctx context.Context, tokenHash string) (domain.DevicePrincipal, error) {
	tokenHash = strings.TrimSpace(tokenHash)
	if tokenHash == "" {
		return domain.DevicePrincipal{}, ErrNotFound
	}
	var p domain.DevicePrincipal
	var suspended int
	err := s.db.QueryRowContext(ctx, s.q(`
		SELECT d.id, d.device_uuid, d.status, d.suspended, c.id
		FROM device_credentials c
		JOIN devices d ON d.id = c.device_id
		WHERE c.token_hash = ?
		  AND c.revoked_at IS NULL
		  AND (c.expires_at IS NULL OR c.expires_at > ?)
	`), tokenHash, nowText()).Scan(&p.DeviceID, &p.DeviceUUID, &p.Status, &suspended, &p.CredentialID)
	if err != nil {
		if err == sql.ErrNoRows {
			return domain.DevicePrincipal{}, ErrNotFound
		}
		return domain.DevicePrincipal{}, fmt.Errorf("authenticate device credential: %w", err)
	}
	p.Suspended = suspended != 0
	_, _ = s.db.ExecContext(ctx, s.q("UPDATE device_credentials SET last_used_at = ? WHERE id = ?"), nowText(), p.CredentialID)
	return p, nil
}

func (s *Store) RotateDeviceCredential(ctx context.Context, principal domain.DevicePrincipal) (domain.DeviceCredentialIssued, error) {
	if principal.Suspended || principal.Status != "active" {
		return domain.DeviceCredentialIssued{}, ErrConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.DeviceCredentialIssued{}, fmt.Errorf("begin credential rotation: %w", err)
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx, s.q(`
		UPDATE device_credentials SET revoked_at = ?
		WHERE id = ? AND device_id = ? AND revoked_at IS NULL
	`), nowText(), principal.CredentialID, principal.DeviceID)
	if err != nil {
		return domain.DeviceCredentialIssued{}, fmt.Errorf("revoke old device credential: %w", err)
	}
	if n, err := result.RowsAffected(); err == nil && n == 0 {
		return domain.DeviceCredentialIssued{}, ErrConflict
	}
	issued, err := s.issueDeviceCredentialTx(ctx, tx, principal.DeviceID)
	if err != nil {
		return domain.DeviceCredentialIssued{}, err
	}
	if err := tx.Commit(); err != nil {
		return domain.DeviceCredentialIssued{}, fmt.Errorf("commit credential rotation: %w", err)
	}
	return issued, nil
}

func (s *Store) RevokeDeviceCredentials(ctx context.Context, deviceID string) error {
	result, err := s.db.ExecContext(ctx, s.q(`
		UPDATE device_credentials SET revoked_at = ?
		WHERE device_id = ? AND revoked_at IS NULL
	`), nowText(), deviceID)
	if err != nil {
		return fmt.Errorf("revoke device credentials: %w", err)
	}
	if n, err := result.RowsAffected(); err == nil && n == 0 {
		var exists int
		if err := s.db.QueryRowContext(ctx, s.q("SELECT COUNT(*) FROM devices WHERE id = ?"), deviceID).Scan(&exists); err != nil {
			return fmt.Errorf("check device: %w", err)
		}
		if exists == 0 {
			return ErrNotFound
		}
	}
	return nil
}

func (s *Store) ManagedConfigForDevice(ctx context.Context, deviceID string) (domain.ManagedWireGuardConfig, error) {
	var cfg domain.ManagedWireGuardConfig
	var allowed, dns string
	err := s.db.QueryRowContext(ctx, s.q(`
		SELECT p.device_id, p.id, p.profile_id, p.assigned_address,
		       v.server_public_key, v.endpoint, v.allowed_ips, v.dns_servers,
		       v.persistent_keepalive, p.config_revision
		FROM wireguard_peers p
		JOIN vpn_profiles v ON v.id = p.profile_id
		WHERE p.device_id = ? AND p.revoked_at IS NULL
	`), deviceID).Scan(&cfg.DeviceID, &cfg.PeerID, &cfg.ProfileID, &cfg.AssignedAddress,
		&cfg.ServerPublicKey, &cfg.Endpoint, &allowed, &dns, &cfg.PersistentKeepalive, &cfg.ConfigRevision)
	if err != nil {
		if err == sql.ErrNoRows {
			return domain.ManagedWireGuardConfig{}, ErrNotFound
		}
		return domain.ManagedWireGuardConfig{}, fmt.Errorf("load managed config: %w", err)
	}
	cfg.AssignedAddress += "/32"
	cfg.AllowedIPs = splitList(allowed)
	cfg.DNSServers = splitList(dns)
	return cfg, nil
}

func (s *Store) CreateDeviceCommand(ctx context.Context, input DeviceCommandCreate) (domain.DeviceCommand, error) {
	input.DeviceID = strings.TrimSpace(input.DeviceID)
	input.Type = strings.TrimSpace(input.Type)
	input.IdempotencyKey = strings.TrimSpace(input.IdempotencyKey)
	if input.DeviceID == "" {
		return domain.DeviceCommand{}, invalidf("device_id is required")
	}
	if _, ok := allowedDeviceCommandTypes[input.Type]; !ok {
		return domain.DeviceCommand{}, invalidf("unsupported command type %q", input.Type)
	}
	if len(input.Payload) == 0 {
		input.Payload = json.RawMessage(`{}`)
	}
	if !json.Valid(input.Payload) {
		return domain.DeviceCommand{}, invalidf("command payload must be valid JSON")
	}
	if input.TTL <= 0 {
		input.TTL = defaultCommandTTL
	}
	if input.TTL > 24*time.Hour {
		return domain.DeviceCommand{}, invalidf("command TTL cannot exceed 24 hours")
	}
	if input.IdempotencyKey != "" {
		existing, err := s.deviceCommandByIdempotencyKey(ctx, input.IdempotencyKey)
		if err == nil {
			if existing.DeviceID == input.DeviceID && existing.Type == input.Type {
				return existing, nil
			}
			return domain.DeviceCommand{}, ErrConflict
		}
		if err != ErrNotFound {
			return domain.DeviceCommand{}, err
		}
	}

	var exists int
	if err := s.db.QueryRowContext(ctx, s.q("SELECT COUNT(*) FROM devices WHERE id = ?"), input.DeviceID).Scan(&exists); err != nil {
		return domain.DeviceCommand{}, fmt.Errorf("check command device: %w", err)
	}
	if exists == 0 {
		return domain.DeviceCommand{}, ErrNotFound
	}

	id, err := security.NewID()
	if err != nil {
		return domain.DeviceCommand{}, err
	}
	if input.IdempotencyKey == "" {
		input.IdempotencyKey = id
	}
	now := time.Now().UTC()
	cmd := domain.DeviceCommand{
		ID: id, DeviceID: input.DeviceID, Type: input.Type, Status: "pending",
		IdempotencyKey: input.IdempotencyKey, Payload: append(json.RawMessage(nil), input.Payload...),
		Result: json.RawMessage(`{}`), CreatedAt: now.Format(time.RFC3339Nano),
		ExpiresAt: now.Add(input.TTL).Format(time.RFC3339Nano),
	}
	_, err = s.db.ExecContext(ctx, s.q(`
		INSERT INTO device_commands(
			id, device_id, type, status, idempotency_key, payload, result, created_at, expires_at
		) VALUES(?, ?, ?, 'pending', ?, ?, '{}', ?, ?)
	`), cmd.ID, cmd.DeviceID, cmd.Type, cmd.IdempotencyKey, string(cmd.Payload), cmd.CreatedAt, cmd.ExpiresAt)
	if err != nil {
		if input.IdempotencyKey != "" {
			existing, lookupErr := s.deviceCommandByIdempotencyKey(ctx, input.IdempotencyKey)
			if lookupErr == nil && existing.DeviceID == input.DeviceID && existing.Type == input.Type {
				return existing, nil
			}
		}
		return domain.DeviceCommand{}, fmt.Errorf("create device command: %w", err)
	}
	return cmd, nil
}

func (s *Store) deviceCommandByIdempotencyKey(ctx context.Context, key string) (domain.DeviceCommand, error) {
	row := s.db.QueryRowContext(ctx, s.q(`
		SELECT id, device_id, type, status, idempotency_key, payload, result,
		       error_message, created_at, delivered_at, acknowledged_at, finished_at, expires_at
		FROM device_commands WHERE idempotency_key = ?
	`), key)
	cmd, err := scanDeviceCommand(row.Scan)
	if err != nil {
		if err == sql.ErrNoRows || strings.Contains(err.Error(), "no rows") {
			return domain.DeviceCommand{}, ErrNotFound
		}
		return domain.DeviceCommand{}, err
	}
	return cmd, nil
}

func (s *Store) ListDeviceCommands(ctx context.Context, deviceID string, limit, offset int) ([]domain.DeviceCommand, int, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	var total int
	if err := s.db.QueryRowContext(ctx, s.q("SELECT COUNT(*) FROM device_commands WHERE device_id = ?"), deviceID).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count device commands: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, s.q(`
		SELECT id, device_id, type, status, idempotency_key, payload, result,
		       error_message, created_at, delivered_at, acknowledged_at, finished_at, expires_at
		FROM device_commands WHERE device_id = ?
		ORDER BY created_at DESC LIMIT ? OFFSET ?
	`), deviceID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list device commands: %w", err)
	}
	defer rows.Close()
	items := make([]domain.DeviceCommand, 0)
	for rows.Next() {
		cmd, err := scanDeviceCommand(rows.Scan)
		if err != nil {
			return nil, 0, err
		}
		items = append(items, cmd)
	}
	return items, total, rows.Err()
}

func (s *Store) PollDeviceCommands(ctx context.Context, deviceID string, limit int, disconnectOnly bool) ([]domain.DeviceCommand, error) {
	if limit <= 0 || limit > 50 {
		limit = 20
	}
	now := nowText()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin command poll: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, s.q(`
		UPDATE device_commands SET status = 'expired', finished_at = ?
		WHERE device_id = ? AND status IN ('pending', 'delivered', 'running') AND expires_at <= ?
	`), now, deviceID, now); err != nil {
		return nil, fmt.Errorf("expire device commands: %w", err)
	}
	query := `
		SELECT id, device_id, type, status, idempotency_key, payload, result,
		       error_message, created_at, delivered_at, acknowledged_at, finished_at, expires_at
		FROM device_commands
		WHERE device_id = ? AND status IN ('pending', 'delivered') AND expires_at > ?
	`
	if disconnectOnly {
		query += " AND type = 'disconnect'"
	}
	query += " ORDER BY created_at ASC LIMIT ?"
	if s.dialect == "postgres" {
		query += " FOR UPDATE"
	}
	rows, err := tx.QueryContext(ctx, s.q(query), deviceID, now, limit)
	if err != nil {
		return nil, fmt.Errorf("poll device commands: %w", err)
	}
	items := make([]domain.DeviceCommand, 0)
	for rows.Next() {
		cmd, err := scanDeviceCommand(rows.Scan)
		if err != nil {
			rows.Close()
			return nil, err
		}
		items = append(items, cmd)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("iterate polled commands: %w", err)
	}
	rows.Close()
	for i := range items {
		if items[i].Status != "pending" {
			continue
		}
		if _, err := tx.ExecContext(ctx, s.q(`
			UPDATE device_commands SET status = 'delivered', delivered_at = ?
			WHERE id = ? AND device_id = ? AND status = 'pending'
		`), now, items[i].ID, deviceID); err != nil {
			return nil, fmt.Errorf("mark command delivered: %w", err)
		}
		items[i].Status = "delivered"
		items[i].DeliveredAt = now
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit command poll: %w", err)
	}
	return items, nil
}

func (s *Store) UpdateDeviceCommandResult(ctx context.Context, deviceID, commandID, status string, result json.RawMessage, errorMessage string) error {
	status = strings.TrimSpace(status)
	if len(result) == 0 {
		result = json.RawMessage(`{}`)
	}
	if !json.Valid(result) {
		return invalidf("command result must be valid JSON")
	}
	now := nowText()
	var res sql.Result
	var err error
	switch status {
	case "running":
		res, err = s.db.ExecContext(ctx, s.q(`
			UPDATE device_commands
			SET status = 'running', acknowledged_at = COALESCE(acknowledged_at, ?)
			WHERE id = ? AND device_id = ? AND status IN ('pending', 'delivered') AND expires_at > ?
		`), now, commandID, deviceID, now)
	case "succeeded", "failed":
		res, err = s.db.ExecContext(ctx, s.q(`
			UPDATE device_commands
			SET status = ?, acknowledged_at = COALESCE(acknowledged_at, ?), finished_at = ?,
			    result = ?, error_message = ?
			WHERE id = ? AND device_id = ? AND status IN ('pending', 'delivered', 'running') AND expires_at > ?
		`), status, now, now, string(result), strings.TrimSpace(errorMessage), commandID, deviceID, now)
	default:
		return invalidf("unsupported command status %q", status)
	}
	if err != nil {
		return fmt.Errorf("update command result: %w", err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return ErrConflict
	}
	return nil
}

func (s *Store) RecordDeviceTelemetry(ctx context.Context, deviceID string, input domain.DeviceTelemetryInput) (domain.DeviceTelemetry, error) {
	input.TunnelState = strings.TrimSpace(input.TunnelState)
	if input.TunnelState == "" {
		input.TunnelState = "unknown"
	}
	if input.RXBytes < 0 || input.TXBytes < 0 || input.TunnelUptimeSeconds < 0 || input.ConfigRevision < 0 {
		return domain.DeviceTelemetry{}, invalidf("telemetry counters cannot be negative")
	}
	if input.LatencyMS != nil && *input.LatencyMS < 0 {
		return domain.DeviceTelemetry{}, invalidf("latency cannot be negative")
	}
	id, err := security.NewID()
	if err != nil {
		return domain.DeviceTelemetry{}, err
	}
	now := nowText()
	t := domain.DeviceTelemetry{
		ID: id, DeviceID: deviceID, ObservedAt: now, TunnelState: input.TunnelState,
		LatestHandshakeAt: input.LatestHandshakeAt, Endpoint: strings.TrimSpace(input.Endpoint),
		AssignedAddress: strings.TrimSpace(input.AssignedAddress), RXBytes: input.RXBytes, TXBytes: input.TXBytes,
		TunnelUptimeSeconds: input.TunnelUptimeSeconds, LatencyMS: input.LatencyMS, ConfigRevision: input.ConfigRevision,
		ArlanPhoneVersion: strings.TrimSpace(input.ArlanPhoneVersion), AgentVersion: strings.TrimSpace(input.AgentVersion),
		WireGuardVersion: strings.TrimSpace(input.WireGuardVersion), ErrorCode: strings.TrimSpace(input.ErrorCode),
		ErrorMessage: strings.TrimSpace(input.ErrorMessage),
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.DeviceTelemetry{}, fmt.Errorf("begin telemetry write: %w", err)
	}
	defer tx.Rollback()
	var latency any
	if t.LatencyMS != nil {
		latency = *t.LatencyMS
	}
	_, err = tx.ExecContext(ctx, s.q(`
		INSERT INTO device_telemetry(
			id, device_id, observed_at, tunnel_state, latest_handshake_at, endpoint,
			rx_bytes, tx_bytes, tunnel_uptime_seconds, latency_ms, arlanphone_version,
			agent_version, wireguard_version, error_code, error_message, assigned_address, config_revision
		) VALUES(?, ?, ?, ?, NULLIF(?, ''), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`), t.ID, t.DeviceID, t.ObservedAt, t.TunnelState, t.LatestHandshakeAt, t.Endpoint,
		t.RXBytes, t.TXBytes, t.TunnelUptimeSeconds, latency, t.ArlanPhoneVersion,
		t.AgentVersion, t.WireGuardVersion, t.ErrorCode, t.ErrorMessage, t.AssignedAddress, t.ConfigRevision)
	if err != nil {
		return domain.DeviceTelemetry{}, fmt.Errorf("insert device telemetry: %w", err)
	}
	result, err := tx.ExecContext(ctx, s.q(`
		UPDATE devices SET last_seen_at = ?, updated_at = ? WHERE id = ?
	`), now, now, deviceID)
	if err != nil {
		return domain.DeviceTelemetry{}, fmt.Errorf("update device last seen: %w", err)
	}
	if n, err := result.RowsAffected(); err == nil && n == 0 {
		return domain.DeviceTelemetry{}, ErrNotFound
	}
	_, _ = tx.ExecContext(ctx, s.q(`
		UPDATE wireguard_peers SET observed_state = ?, updated_at = ?
		WHERE device_id = ? AND revoked_at IS NULL
	`), t.TunnelState, now, deviceID)
	if err := tx.Commit(); err != nil {
		return domain.DeviceTelemetry{}, fmt.Errorf("commit telemetry write: %w", err)
	}
	return t, nil
}

func (s *Store) LatestDeviceTelemetry(ctx context.Context, deviceID string) (domain.DeviceTelemetry, error) {
	var t domain.DeviceTelemetry
	var handshake sql.NullString
	var latency sql.NullInt64
	err := s.db.QueryRowContext(ctx, s.q(`
		SELECT id, device_id, observed_at, tunnel_state, latest_handshake_at, endpoint,
		       rx_bytes, tx_bytes, tunnel_uptime_seconds, latency_ms, arlanphone_version,
		       agent_version, wireguard_version, error_code, error_message, assigned_address, config_revision
		FROM device_telemetry WHERE device_id = ? ORDER BY observed_at DESC LIMIT 1
	`), deviceID).Scan(&t.ID, &t.DeviceID, &t.ObservedAt, &t.TunnelState, &handshake, &t.Endpoint,
		&t.RXBytes, &t.TXBytes, &t.TunnelUptimeSeconds, &latency, &t.ArlanPhoneVersion,
		&t.AgentVersion, &t.WireGuardVersion, &t.ErrorCode, &t.ErrorMessage, &t.AssignedAddress, &t.ConfigRevision)
	if err != nil {
		if err == sql.ErrNoRows {
			return domain.DeviceTelemetry{}, ErrNotFound
		}
		return domain.DeviceTelemetry{}, fmt.Errorf("load latest telemetry: %w", err)
	}
	if handshake.Valid {
		t.LatestHandshakeAt = handshake.String
	}
	if latency.Valid {
		value := latency.Int64
		t.LatencyMS = &value
	}
	return t, nil
}

func (s *Store) SuspendDeviceAndQueueDisconnect(ctx context.Context, deviceID string) (domain.DeviceCommand, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.DeviceCommand{}, fmt.Errorf("begin device suspension: %w", err)
	}
	defer tx.Rollback()
	now := nowText()
	result, err := tx.ExecContext(ctx, s.q(`
		UPDATE devices SET suspended = 1, status = 'suspended', updated_at = ? WHERE id = ?
	`), now, deviceID)
	if err != nil {
		return domain.DeviceCommand{}, fmt.Errorf("suspend device: %w", err)
	}
	if n, err := result.RowsAffected(); err == nil && n == 0 {
		return domain.DeviceCommand{}, ErrNotFound
	}
	_, _ = tx.ExecContext(ctx, s.q(`
		UPDATE wireguard_peers SET desired_state = 'disconnected', updated_at = ?
		WHERE device_id = ? AND revoked_at IS NULL
	`), now, deviceID)

	id, err := security.NewID()
	if err != nil {
		return domain.DeviceCommand{}, err
	}
	cmd := domain.DeviceCommand{
		ID: id, DeviceID: deviceID, Type: "disconnect", Status: "pending", IdempotencyKey: "suspend:" + id,
		Payload: json.RawMessage(`{"reason":"device_suspended"}`), Result: json.RawMessage(`{}`),
		CreatedAt: now, ExpiresAt: time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339Nano),
	}
	_, err = tx.ExecContext(ctx, s.q(`
		INSERT INTO device_commands(id, device_id, type, status, idempotency_key, payload, result, created_at, expires_at)
		VALUES(?, ?, 'disconnect', 'pending', ?, ?, '{}', ?, ?)
	`), cmd.ID, deviceID, cmd.IdempotencyKey, string(cmd.Payload), cmd.CreatedAt, cmd.ExpiresAt)
	if err != nil {
		return domain.DeviceCommand{}, fmt.Errorf("queue suspend disconnect: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return domain.DeviceCommand{}, fmt.Errorf("commit device suspension: %w", err)
	}
	return cmd, nil
}

type scanFunc func(dest ...any) error

func scanDeviceCommand(scan scanFunc) (domain.DeviceCommand, error) {
	var cmd domain.DeviceCommand
	var payload, result string
	var delivered, acknowledged, finished sql.NullString
	if err := scan(&cmd.ID, &cmd.DeviceID, &cmd.Type, &cmd.Status, &cmd.IdempotencyKey,
		&payload, &result, &cmd.ErrorMessage, &cmd.CreatedAt, &delivered, &acknowledged, &finished, &cmd.ExpiresAt); err != nil {
		return domain.DeviceCommand{}, fmt.Errorf("scan device command: %w", err)
	}
	cmd.Payload = json.RawMessage(payload)
	cmd.Result = json.RawMessage(result)
	if delivered.Valid {
		cmd.DeliveredAt = delivered.String
	}
	if acknowledged.Valid {
		cmd.AcknowledgedAt = acknowledged.String
	}
	if finished.Valid {
		cmd.FinishedAt = finished.String
	}
	return cmd, nil
}
