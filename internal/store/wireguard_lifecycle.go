package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/1day0fmylife/Guardian/internal/domain"
	"github.com/1day0fmylife/Guardian/internal/security"
)

// BeginDeviceVPNRevocation starts a two-phase revocation. The management
// credential intentionally stays usable so the device can receive disconnect
// and submit its final telemetry while the server-side peer removal is pending.
func (s *Store) BeginDeviceVPNRevocation(ctx context.Context, deviceID string) (domain.DeviceCommand, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.DeviceCommand{}, fmt.Errorf("begin VPN revocation: %w", err)
	}
	defer tx.Rollback()

	now := nowText()
	result, err := tx.ExecContext(ctx, s.q(`
		UPDATE devices
		SET suspended = 1, status = 'revoking', updated_at = ?
		WHERE id = ? AND status <> 'revoked'
	`), now, deviceID)
	if err != nil {
		return domain.DeviceCommand{}, fmt.Errorf("mark device revoking: %w", err)
	}
	if n, err := result.RowsAffected(); err == nil && n == 0 {
		var exists int
		if err := tx.QueryRowContext(ctx, s.q("SELECT COUNT(*) FROM devices WHERE id = ?"), deviceID).Scan(&exists); err != nil {
			return domain.DeviceCommand{}, fmt.Errorf("check revocation device: %w", err)
		}
		if exists == 0 {
			return domain.DeviceCommand{}, ErrNotFound
		}
		return domain.DeviceCommand{}, ErrConflict
	}

	var peerID string
	var currentRevision int64
	query := `
		SELECT id, config_revision FROM wireguard_peers
		WHERE device_id = ? AND revoked_at IS NULL
	`
	if s.dialect == "postgres" {
		query += " FOR UPDATE"
	}
	if err := tx.QueryRowContext(ctx, s.q(query), deviceID).Scan(&peerID, &currentRevision); err != nil {
		if err == sql.ErrNoRows {
			return domain.DeviceCommand{}, ErrNotFound
		}
		return domain.DeviceCommand{}, fmt.Errorf("load peer for revocation: %w", err)
	}
	nextRevision := currentRevision + 1
	if _, err := tx.ExecContext(ctx, s.q(`
		UPDATE wireguard_peers
		SET desired_state = 'revoked', revoked_at = ?, config_revision = ?,
		    reconcile_state = 'pending', reconcile_error = '', updated_at = ?
		WHERE id = ? AND config_revision = ?
	`), now, nextRevision, now, peerID, currentRevision); err != nil {
		return domain.DeviceCommand{}, fmt.Errorf("mark peer revoked: %w", err)
	}
	if _, err := tx.ExecContext(ctx, s.q(`
		UPDATE address_leases SET status = 'revoking'
		WHERE device_id = ? AND status = 'active'
	`), deviceID); err != nil {
		return domain.DeviceCommand{}, fmt.Errorf("mark lease revoking: %w", err)
	}

	commandID, err := security.NewID()
	if err != nil {
		return domain.DeviceCommand{}, err
	}
	cmd := domain.DeviceCommand{
		ID: commandID, DeviceID: deviceID, Type: "disconnect", Status: "pending",
		IdempotencyKey: "revoke:" + peerID + ":" + fmt.Sprint(nextRevision),
		Payload:        json.RawMessage(`{"reason":"vpn_revoked"}`), Result: json.RawMessage(`{}`),
		CreatedAt: now, ExpiresAt: time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339Nano),
	}
	if _, err := tx.ExecContext(ctx, s.q(`
		INSERT INTO device_commands(id, device_id, type, status, idempotency_key, payload, result, created_at, expires_at)
		VALUES(?, ?, 'disconnect', 'pending', ?, ?, '{}', ?, ?)
	`), cmd.ID, cmd.DeviceID, cmd.IdempotencyKey, string(cmd.Payload), cmd.CreatedAt, cmd.ExpiresAt); err != nil {
		return domain.DeviceCommand{}, fmt.Errorf("queue revocation disconnect: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return domain.DeviceCommand{}, fmt.Errorf("commit VPN revocation: %w", err)
	}
	return cmd, nil
}

// CompleteDeviceVPNRevocation is called only after the WireGuard provider has
// removed the peer for the exact desired revision. Only then may the address be
// released and permanent management credentials be revoked.
func (s *Store) CompleteDeviceVPNRevocation(ctx context.Context, deviceID string, expectedRevision int64) error {
	if expectedRevision <= 0 {
		return invalidf("positive expected_revision is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin revocation completion: %w", err)
	}
	defer tx.Rollback()

	var peerID, desiredState string
	var revision int64
	query := `
		SELECT id, desired_state, config_revision FROM wireguard_peers
		WHERE device_id = ?
		ORDER BY updated_at DESC LIMIT 1
	`
	if s.dialect == "postgres" {
		query += " FOR UPDATE"
	}
	if err := tx.QueryRowContext(ctx, s.q(query), deviceID).Scan(&peerID, &desiredState, &revision); err != nil {
		if err == sql.ErrNoRows {
			return ErrNotFound
		}
		return fmt.Errorf("load revoked peer: %w", err)
	}
	if desiredState != "revoked" || revision != expectedRevision {
		return ErrConflict
	}
	now := nowText()
	if _, err := tx.ExecContext(ctx, s.q(`
		UPDATE wireguard_peers
		SET reconcile_state = 'applied', applied_revision = ?, reconcile_error = '', reconciled_at = ?, updated_at = ?
		WHERE id = ? AND config_revision = ?
	`), revision, now, now, peerID, revision); err != nil {
		return fmt.Errorf("mark revoked peer reconciled: %w", err)
	}
	if err := s.archiveAddressLeaseTx(ctx, tx, deviceID, now, "vpn_revoked"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, s.q(`
		UPDATE device_credentials SET revoked_at = ?
		WHERE device_id = ? AND revoked_at IS NULL
	`), now, deviceID); err != nil {
		return fmt.Errorf("revoke finalized device credentials: %w", err)
	}
	if _, err := tx.ExecContext(ctx, s.q(`
		UPDATE devices SET status = 'revoked', suspended = 1, updated_at = ? WHERE id = ?
	`), now, deviceID); err != nil {
		return fmt.Errorf("finalize revoked device: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit revocation completion: %w", err)
	}
	return nil
}

func (s *Store) SuspendDeviceVPNAndQueueDisconnect(ctx context.Context, deviceID string) (domain.DeviceCommand, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.DeviceCommand{}, fmt.Errorf("begin device suspension: %w", err)
	}
	defer tx.Rollback()
	now := nowText()
	result, err := tx.ExecContext(ctx, s.q(`
		UPDATE devices SET suspended = 1, status = 'suspended', updated_at = ?
		WHERE id = ? AND status = 'active'
	`), now, deviceID)
	if err != nil {
		return domain.DeviceCommand{}, fmt.Errorf("suspend device: %w", err)
	}
	if n, err := result.RowsAffected(); err == nil && n == 0 {
		var exists int
		if err := tx.QueryRowContext(ctx, s.q("SELECT COUNT(*) FROM devices WHERE id = ?"), deviceID).Scan(&exists); err != nil {
			return domain.DeviceCommand{}, fmt.Errorf("check suspension device: %w", err)
		}
		if exists == 0 {
			return domain.DeviceCommand{}, ErrNotFound
		}
		return domain.DeviceCommand{}, ErrConflict
	}

	var peerID string
	var revision int64
	query := `SELECT id, config_revision FROM wireguard_peers WHERE device_id = ? AND revoked_at IS NULL`
	if s.dialect == "postgres" {
		query += " FOR UPDATE"
	}
	if err := tx.QueryRowContext(ctx, s.q(query), deviceID).Scan(&peerID, &revision); err != nil {
		if err == sql.ErrNoRows {
			return domain.DeviceCommand{}, ErrNotFound
		}
		return domain.DeviceCommand{}, fmt.Errorf("load peer for suspension: %w", err)
	}
	nextRevision := revision + 1
	if _, err := tx.ExecContext(ctx, s.q(`
		UPDATE wireguard_peers
		SET desired_state = 'disconnected', config_revision = ?, reconcile_state = 'pending',
		    reconcile_error = '', updated_at = ?
		WHERE id = ? AND config_revision = ?
	`), nextRevision, now, peerID, revision); err != nil {
		return domain.DeviceCommand{}, fmt.Errorf("set suspended peer desired state: %w", err)
	}

	id, err := security.NewID()
	if err != nil {
		return domain.DeviceCommand{}, err
	}
	cmd := domain.DeviceCommand{
		ID: id, DeviceID: deviceID, Type: "disconnect", Status: "pending",
		IdempotencyKey: "suspend:" + peerID + ":" + fmt.Sprint(nextRevision),
		Payload:        json.RawMessage(`{"reason":"device_suspended"}`), Result: json.RawMessage(`{}`),
		CreatedAt: now, ExpiresAt: time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339Nano),
	}
	if _, err := tx.ExecContext(ctx, s.q(`
		INSERT INTO device_commands(id, device_id, type, status, idempotency_key, payload, result, created_at, expires_at)
		VALUES(?, ?, 'disconnect', 'pending', ?, ?, '{}', ?, ?)
	`), cmd.ID, deviceID, cmd.IdempotencyKey, string(cmd.Payload), cmd.CreatedAt, cmd.ExpiresAt); err != nil {
		return domain.DeviceCommand{}, fmt.Errorf("queue suspend disconnect: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return domain.DeviceCommand{}, fmt.Errorf("commit device suspension: %w", err)
	}
	return cmd, nil
}

func (s *Store) ResumeDeviceVPNAndQueueConnect(ctx context.Context, deviceID string) (domain.DeviceCommand, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.DeviceCommand{}, fmt.Errorf("begin device resume: %w", err)
	}
	defer tx.Rollback()
	now := nowText()
	result, err := tx.ExecContext(ctx, s.q(`
		UPDATE devices SET suspended = 0, status = 'active', updated_at = ?
		WHERE id = ? AND status = 'suspended'
	`), now, deviceID)
	if err != nil {
		return domain.DeviceCommand{}, fmt.Errorf("resume device: %w", err)
	}
	if n, err := result.RowsAffected(); err == nil && n == 0 {
		var exists int
		if err := tx.QueryRowContext(ctx, s.q("SELECT COUNT(*) FROM devices WHERE id = ?"), deviceID).Scan(&exists); err != nil {
			return domain.DeviceCommand{}, fmt.Errorf("check resume device: %w", err)
		}
		if exists == 0 {
			return domain.DeviceCommand{}, ErrNotFound
		}
		return domain.DeviceCommand{}, ErrConflict
	}

	var peerID string
	var revision int64
	query := `SELECT id, config_revision FROM wireguard_peers WHERE device_id = ? AND revoked_at IS NULL`
	if s.dialect == "postgres" {
		query += " FOR UPDATE"
	}
	if err := tx.QueryRowContext(ctx, s.q(query), deviceID).Scan(&peerID, &revision); err != nil {
		if err == sql.ErrNoRows {
			return domain.DeviceCommand{}, ErrNotFound
		}
		return domain.DeviceCommand{}, fmt.Errorf("load peer for resume: %w", err)
	}
	nextRevision := revision + 1
	if _, err := tx.ExecContext(ctx, s.q(`
		UPDATE wireguard_peers
		SET desired_state = 'connected', config_revision = ?, reconcile_state = 'pending',
		    reconcile_error = '', updated_at = ?
		WHERE id = ? AND config_revision = ?
	`), nextRevision, now, peerID, revision); err != nil {
		return domain.DeviceCommand{}, fmt.Errorf("set resumed peer desired state: %w", err)
	}

	id, err := security.NewID()
	if err != nil {
		return domain.DeviceCommand{}, err
	}
	cmd := domain.DeviceCommand{
		ID: id, DeviceID: deviceID, Type: "connect", Status: "pending",
		IdempotencyKey: "resume:" + peerID + ":" + fmt.Sprint(nextRevision),
		Payload:        json.RawMessage(`{"reason":"device_resumed"}`), Result: json.RawMessage(`{}`),
		CreatedAt: now, ExpiresAt: time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339Nano),
	}
	if _, err := tx.ExecContext(ctx, s.q(`
		INSERT INTO device_commands(id, device_id, type, status, idempotency_key, payload, result, created_at, expires_at)
		VALUES(?, ?, 'connect', 'pending', ?, ?, '{}', ?, ?)
	`), cmd.ID, deviceID, cmd.IdempotencyKey, string(cmd.Payload), cmd.CreatedAt, cmd.ExpiresAt); err != nil {
		return domain.DeviceCommand{}, fmt.Errorf("queue resume connect: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return domain.DeviceCommand{}, fmt.Errorf("commit device resume: %w", err)
	}
	return cmd, nil
}
