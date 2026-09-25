package store

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

func (s *Store) Migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY,
		applied_at TEXT NOT NULL
	)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	entries, err := fs.Glob(migrationFS, "migrations/*.sql")
	if err != nil {
		return fmt.Errorf("list migrations: %w", err)
	}
	sort.Strings(entries)

	for _, name := range entries {
		version, err := migrationVersion(name)
		if err != nil {
			return err
		}

		var exists int
		err = s.db.QueryRowContext(ctx, s.q("SELECT COUNT(*) FROM schema_migrations WHERE version = ?"), version).Scan(&exists)
		if err != nil {
			return fmt.Errorf("check migration %d: %w", version, err)
		}
		if exists != 0 {
			continue
		}

		body, err := migrationFS.ReadFile(name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}

		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin migration %d: %w", version, err)
		}
		ok := false
		defer func() {
			if !ok {
				_ = tx.Rollback()
			}
		}()

		for _, statement := range splitStatements(string(body)) {
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("migration %d: %w", version, err)
			}
		}
		if _, err := tx.ExecContext(ctx, s.q("INSERT INTO schema_migrations(version, applied_at) VALUES(?, ?)"), version, nowText()); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record migration %d: %w", version, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %d: %w", version, err)
		}
		ok = true
	}

	return nil
}

func migrationVersion(name string) (int, error) {
	base := name[strings.LastIndex(name, "/")+1:]
	prefix, _, ok := strings.Cut(base, "_")
	if !ok {
		return 0, fmt.Errorf("invalid migration filename %q", name)
	}
	version, err := strconv.Atoi(prefix)
	if err != nil {
		return 0, fmt.Errorf("invalid migration version %q: %w", prefix, err)
	}
	return version, nil
}

func splitStatements(sqlText string) []string {
	parts := strings.Split(sqlText, ";")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
