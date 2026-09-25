package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflict")
)

type Store struct {
	db      *sql.DB
	dialect string
}

func Open(ctx context.Context, databaseURL string) (*Store, error) {
	var (
		driver  string
		dsn     string
		dialect string
	)

	switch {
	case strings.HasPrefix(databaseURL, "sqlite://"):
		driver = "sqlite"
		dialect = "sqlite"
		path := strings.TrimPrefix(databaseURL, "sqlite://")
		if path == "" {
			return nil, fmt.Errorf("sqlite database path is empty")
		}
		if path == ":memory:" {
			dsn = "file:guardian?mode=memory&cache=shared"
		} else if strings.HasPrefix(path, "file:") {
			dsn = path
		} else {
			if dir := filepath.Dir(path); dir != "." {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					return nil, fmt.Errorf("create sqlite directory: %w", err)
				}
			}
			dsn = "file:" + path
		}
	case strings.HasPrefix(databaseURL, "postgres://"), strings.HasPrefix(databaseURL, "postgresql://"):
		driver = "pgx"
		dialect = "postgres"
		dsn = databaseURL
	default:
		return nil, fmt.Errorf("unsupported database URL")
	}

	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	if dialect == "sqlite" {
		// Standalone mode favors deterministic locking over write concurrency.
		db.SetMaxOpenConns(1)
		db.SetMaxIdleConns(1)
		if _, err := db.ExecContext(ctx, "PRAGMA foreign_keys = ON"); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("enable sqlite foreign keys: %w", err)
		}
		if _, err := db.ExecContext(ctx, "PRAGMA busy_timeout = 5000"); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("set sqlite busy timeout: %w", err)
		}
	} else {
		db.SetMaxOpenConns(20)
		db.SetMaxIdleConns(5)
		db.SetConnMaxLifetime(30 * time.Minute)
	}

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}

	return &Store{db: db, dialect: dialect}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

func (s *Store) DB() *sql.DB {
	return s.db
}

func (s *Store) Dialect() string {
	return s.dialect
}

func (s *Store) q(query string) string {
	if s.dialect != "postgres" {
		return query
	}

	var b strings.Builder
	arg := 1
	for _, r := range query {
		if r == '?' {
			fmt.Fprintf(&b, "$%d", arg)
			arg++
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func nowText() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}
