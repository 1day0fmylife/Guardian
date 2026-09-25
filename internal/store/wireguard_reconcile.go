package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/1day0fmylife/Guardian/internal/domain"
)

func (s *Store) ListPendingWireGuardReconciliations(ctx context.Context, limit int) ([]domain.WireGuardReconcileItem, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, s.q(`
		SELECT id, device_id, profile_id, public_key, assigned_address,
		       desired_state, config_revision, applied_revision, reconcile_state
		FROM wireguard_peers
		WHERE reconcile_state IN ('pending', 'error')
		  AND applied_revision < config_revision
		ORDER BY updated_at ASC
		LIMIT ?
	`), limit)
	if err != nil {
		return nil, fmt.Errorf("list pending WireGuard reconciliations: %w", err)
	}
	defer rows.Close()
	items := make([]domain.WireGuardReconcileItem, 0)
	for rows.Next() {
		var item domain.WireGuardReconcileItem
		if err := rows.Scan(&item.PeerID, &item.DeviceID, &item.ProfileID, &item.PublicKey,
			&item.AssignedAddress, &item.DesiredState, &item.ConfigRevision,
			&item.AppliedRevision, &item.ReconcileState); err != nil {
			return nil, fmt.Errorf("scan pending WireGuard reconciliation: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate pending WireGuard reconciliations: %w", err)
	}
	return items, nil
}

func (s *Store) MarkWireGuardPeerApplied(ctx context.Context, peerID string, expectedRevision int64) error {
	if strings.TrimSpace(peerID) == "" || expectedRevision <= 0 {
		return invalidf("peer_id and positive expected_revision are required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin peer reconcile completion: %w", err)
	}
	defer tx.Rollback()

	var deviceID, desiredState string
	var revision int64
	query := `SELECT device_id, desired_state, config_revision FROM wireguard_peers WHERE id = ?`
	if s.dialect == "postgres" {
		query += " FOR UPDATE"
	}
	if err := tx.QueryRowContext(ctx, s.q(query), peerID).Scan(&deviceID, &desiredState, &revision); err != nil {
		if err == sql.ErrNoRows {
			return ErrNotFound
		}
		return fmt.Errorf("load reconciled peer: %w", err)
	}
	if revision != expectedRevision {
		return ErrConflict
	}
	if desiredState == "revoked" {
		// Completion owns all revocation side effects (lease release and
		// credential invalidation) in one transaction.
		if err := tx.Rollback(); err != nil && err != sql.ErrTxDone {
			return fmt.Errorf("rollback before revocation completion: %w", err)
		}
		return s.CompleteDeviceVPNRevocation(ctx, deviceID, expectedRevision)
	}

	now := nowText()
	result, err := tx.ExecContext(ctx, s.q(`
		UPDATE wireguard_peers
		SET reconcile_state = 'applied', applied_revision = ?, reconcile_error = '',
		    reconciled_at = ?, updated_at = ?
		WHERE id = ? AND config_revision = ?
	`), expectedRevision, now, now, peerID, expectedRevision)
	if err != nil {
		return fmt.Errorf("mark WireGuard peer applied: %w", err)
	}
	if n, err := result.RowsAffected(); err == nil && n == 0 {
		return ErrConflict
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit peer reconcile completion: %w", err)
	}
	return nil
}

func (s *Store) MarkWireGuardPeerReconcileError(ctx context.Context, peerID string, expectedRevision int64, message string) error {
	if strings.TrimSpace(peerID) == "" || expectedRevision <= 0 {
		return invalidf("peer_id and positive expected_revision are required")
	}
	message = strings.TrimSpace(message)
	if len(message) > 1000 {
		message = message[:1000]
	}
	result, err := s.db.ExecContext(ctx, s.q(`
		UPDATE wireguard_peers
		SET reconcile_state = 'error', reconcile_error = ?, updated_at = ?
		WHERE id = ? AND config_revision = ?
	`), message, nowText(), peerID, expectedRevision)
	if err != nil {
		return fmt.Errorf("mark WireGuard reconcile error: %w", err)
	}
	if n, err := result.RowsAffected(); err == nil && n == 0 {
		return ErrConflict
	}
	return nil
}
