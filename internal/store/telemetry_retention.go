package store

import (
	"context"
	"fmt"
	"time"
)

type TelemetryRetentionResult struct {
	Candidates int64  `json:"candidates"`
	Deleted    int64  `json:"deleted"`
	DryRun     bool   `json:"dry_run"`
	Before     string `json:"before"`
}

// PruneDeviceTelemetry deletes at most limit historical rows. The latest second
// of telemetry for each device is preserved, including all same-second ties.
// Server timestamps are UTC RFC3339; a whole-second prefix avoids fractional
// RFC3339 text ordering ambiguity without dialect-specific date functions.
func (s *Store) PruneDeviceTelemetry(ctx context.Context, before time.Time, limit int, dryRun bool) (TelemetryRetentionResult, error) {
	result := TelemetryRetentionResult{DryRun: dryRun, Before: before.UTC().Truncate(time.Second).Format(time.RFC3339)}
	if before.IsZero() || before.After(time.Now()) || limit < 1 || limit > 10000 {
		return result, invalidf("retention requires a past cutoff and limit between 1 and 10000")
	}
	cutoff := before.UTC().Truncate(time.Second).Format("2006-01-02T15:04:05")
	candidates := `SELECT t.id FROM device_telemetry t WHERE t.observed_at < ?
 AND t.observed_at < (SELECT substr(MAX(n.observed_at), 1, 19) FROM device_telemetry n WHERE n.device_id = t.device_id)
 ORDER BY t.observed_at, t.id LIMIT ?`
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, fmt.Errorf("begin retention: %w", err)
	}
	defer tx.Rollback()
	if dryRun {
		err := tx.QueryRowContext(ctx, s.q("SELECT COUNT(*) FROM ("+candidates+") candidates"), cutoff, limit).Scan(&result.Candidates)
		if err != nil {
			return result, fmt.Errorf("preview retention: %w", err)
		}
		return result, nil
	}
	rows, err := tx.ExecContext(ctx, s.q("DELETE FROM device_telemetry WHERE id IN ("+candidates+")"), cutoff, limit)
	if err != nil {
		return result, fmt.Errorf("prune telemetry: %w", err)
	}
	result.Deleted, err = rows.RowsAffected()
	result.Candidates = result.Deleted
	if err != nil {
		return result, fmt.Errorf("count pruned telemetry: %w", err)
	}
	if result.Deleted > 0 {
		if err := s.appendAuditTx(ctx, tx, AuditMeta{}, "telemetry.retention", "telemetry", "history", map[string]any{"before": result.Before, "deleted": result.Deleted, "limit": limit}); err != nil {
			return result, err
		}
	}
	if err := tx.Commit(); err != nil {
		return result, fmt.Errorf("commit retention: %w", err)
	}
	return result, nil
}
