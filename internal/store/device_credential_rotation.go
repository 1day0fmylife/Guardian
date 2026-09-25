package store

import (
	"context"
	"fmt"

	"github.com/1day0fmylife/Guardian/internal/domain"
)

// RotateDeviceCredentialHash atomically replaces the credential used to
// authenticate the current device. The plaintext replacement credential is
// generated and persisted by the device before this call; Guardian receives
// only its SHA-256 hash.
//
// The authenticated current credential acts as the compare-and-swap guard. A
// concurrent or repeated request using an already-revoked credential cannot
// revoke the newly installed credential.
func (s *Store) RotateDeviceCredentialHash(ctx context.Context, principal domain.DevicePrincipal, tokenHash string) (domain.DeviceCredential, error) {
	if principal.Suspended || principal.Status != "active" {
		return domain.DeviceCredential{}, ErrConflict
	}
	normalizedHash, err := normalizeDeviceCredentialHash(tokenHash)
	if err != nil {
		return domain.DeviceCredential{}, err
	}
	tokenHash = normalizedHash

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.DeviceCredential{}, fmt.Errorf("begin credential hash rotation: %w", err)
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx, s.q(`
		UPDATE device_credentials SET revoked_at = ?
		WHERE id = ? AND device_id = ? AND revoked_at IS NULL
	`), nowText(), principal.CredentialID, principal.DeviceID)
	if err != nil {
		return domain.DeviceCredential{}, fmt.Errorf("revoke current device credential: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return domain.DeviceCredential{}, fmt.Errorf("inspect revoked device credential rows: %w", err)
	}
	if affected != 1 {
		return domain.DeviceCredential{}, ErrConflict
	}

	issued, err := s.issueDeviceCredentialHashTx(ctx, tx, principal.DeviceID, tokenHash)
	if err != nil {
		return domain.DeviceCredential{}, err
	}
	if err := tx.Commit(); err != nil {
		return domain.DeviceCredential{}, fmt.Errorf("commit credential hash rotation: %w", err)
	}
	return issued.Credential, nil
}
