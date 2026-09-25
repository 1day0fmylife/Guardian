package store

import (
	"context"
	"database/sql"
	"fmt"
)

func (s *Store) archiveAddressLeaseTx(ctx context.Context, tx *sql.Tx, deviceID, releasedAt, reason string) error {
	if _, err := tx.ExecContext(ctx, s.q(`
		INSERT INTO address_lease_history(
			id, pool_id, device_id, address, allocated_at, released_at, release_reason
		)
		SELECT id, pool_id, device_id, address, allocated_at, ?, ?
		FROM address_leases
		WHERE device_id = ? AND status = 'revoking'
		ON CONFLICT(id) DO NOTHING
	`), releasedAt, reason, deviceID); err != nil {
		return fmt.Errorf("archive address lease: %w", err)
	}
	if _, err := tx.ExecContext(ctx, s.q(`
		DELETE FROM address_leases
		WHERE device_id = ? AND status = 'revoking'
	`), deviceID); err != nil {
		return fmt.Errorf("release address lease: %w", err)
	}
	return nil
}
