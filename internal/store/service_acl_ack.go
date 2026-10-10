package store

import (
	"context"
	"fmt"
)

// RequireServiceACLAcknowledgement enables the durable gateway safety gate.
// It is deliberately sticky: a later process missing the flag cannot bypass it.
func (s *Store) RequireServiceACLAcknowledgement(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "UPDATE service_acl_state SET required = 1 WHERE id = 1"); err != nil {
		return fmt.Errorf("enable service ACL revocation gate: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE wireguard_peers
 SET service_revocation_revision = (SELECT revision FROM service_policy_state WHERE id = 1)
 WHERE service_revocation_revision = 0 AND desired_state = 'revoked'
 AND device_id IN (SELECT id FROM devices WHERE status = 'revoking')`); err != nil {
		return err
	}
	return tx.Commit()
}

// RecordServiceACLApplied is called by the single ACL writer for this gateway
// after applying the whole verified snapshot. It does not acknowledge errors.
func (s *Store) RecordServiceACLApplied(ctx context.Context, revision int64) error {
	if revision <= 0 {
		return ErrInvalid
	}
	result, err := s.db.ExecContext(ctx, s.q(`UPDATE service_acl_state SET applied_revision = ?
 WHERE id = 1 AND applied_revision <= ?
 AND ? <= (SELECT revision FROM service_policy_state WHERE id = 1)`), revision, revision, revision)
	if err != nil {
		return fmt.Errorf("acknowledge service ACL: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return ErrConflict
	}
	return nil
}
