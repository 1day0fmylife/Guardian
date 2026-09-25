package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/1day0fmylife/Guardian/internal/domain"
	"github.com/1day0fmylife/Guardian/internal/security"
)

func (s *Store) RotateDeviceWireGuardPublicKey(ctx context.Context, deviceID, publicKey string, expectedRevision int64) (domain.ManagedWireGuardConfig, error) {
	deviceID = strings.TrimSpace(deviceID)
	publicKey = strings.TrimSpace(publicKey)
	if deviceID == "" || expectedRevision <= 0 {
		return domain.ManagedWireGuardConfig{}, invalidf("device_id and positive expected_revision are required")
	}
	if err := security.ValidateWireGuardPublicKey(publicKey); err != nil {
		return domain.ManagedWireGuardConfig{}, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.ManagedWireGuardConfig{}, fmt.Errorf("begin WireGuard key rotation: %w", err)
	}
	defer tx.Rollback()

	var peerID, currentKey string
	var currentRevision int64
	query := `
		SELECT id, public_key, config_revision
		FROM wireguard_peers
		WHERE device_id = ? AND revoked_at IS NULL
	`
	if s.dialect == "postgres" {
		query += " FOR UPDATE"
	}
	if err := tx.QueryRowContext(ctx, s.q(query), deviceID).Scan(&peerID, &currentKey, &currentRevision); err != nil {
		if err == sql.ErrNoRows {
			return domain.ManagedWireGuardConfig{}, ErrNotFound
		}
		return domain.ManagedWireGuardConfig{}, fmt.Errorf("load WireGuard peer for rotation: %w", err)
	}
	if currentRevision != expectedRevision {
		return domain.ManagedWireGuardConfig{}, ErrConflict
	}
	if currentKey == publicKey {
		if err := tx.Commit(); err != nil {
			return domain.ManagedWireGuardConfig{}, fmt.Errorf("commit idempotent key rotation: %w", err)
		}
		return s.ManagedConfigForDevice(ctx, deviceID)
	}

	var keyInUse int
	if err := tx.QueryRowContext(ctx, s.q(`
		SELECT COUNT(*) FROM wireguard_peers
		WHERE public_key = ? AND id <> ?
	`), publicKey, peerID).Scan(&keyInUse); err != nil {
		return domain.ManagedWireGuardConfig{}, fmt.Errorf("check WireGuard public key uniqueness: %w", err)
	}
	if keyInUse != 0 {
		return domain.ManagedWireGuardConfig{}, ErrConflict
	}

	nextRevision := currentRevision + 1
	result, err := tx.ExecContext(ctx, s.q(`
		UPDATE wireguard_peers
		SET public_key = ?, config_revision = ?, observed_state = 'unknown',
		    reconcile_state = 'pending', reconcile_error = '', updated_at = ?
		WHERE id = ? AND config_revision = ? AND revoked_at IS NULL
	`), publicKey, nextRevision, nowText(), peerID, currentRevision)
	if err != nil {
		return domain.ManagedWireGuardConfig{}, fmt.Errorf("rotate WireGuard public key: %w", err)
	}
	if n, err := result.RowsAffected(); err == nil && n == 0 {
		return domain.ManagedWireGuardConfig{}, ErrConflict
	}
	if err := tx.Commit(); err != nil {
		return domain.ManagedWireGuardConfig{}, fmt.Errorf("commit WireGuard key rotation: %w", err)
	}
	return s.ManagedConfigForDevice(ctx, deviceID)
}
