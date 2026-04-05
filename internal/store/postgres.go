// Package store provides PostgreSQL and Redis persistence adapters for silkie.
package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const migrationLockID int64 = 8246351001

// DB wraps a pgxpool.Pool for database access.
type DB struct {
	Pool *pgxpool.Pool
}

// OpenDB creates a new connection pool and verifies connectivity.
func OpenDB(ctx context.Context, databaseURL string) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database config: %w", err)
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("open database pool: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}

	return &DB{Pool: pool}, nil
}

// Close shuts down the underlying connection pool.
func (db *DB) Close() {
	if db == nil || db.Pool == nil {
		return
	}

	db.Pool.Close()
}

// Ping checks database connectivity.
func (db *DB) Ping(ctx context.Context) error {
	return db.Pool.Ping(ctx)
}

// RunMigrations applies all pending SQL migrations from the given directory.
//
//nolint:gocognit,gocyclo // sequential migration steps are clearer as one function
func (db *DB) RunMigrations(ctx context.Context, dir string) error {
	migrationDir, err := resolveMigrationDir(dir)
	if err != nil {
		return err
	}

	conn, err := db.Pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire migration connection: %w", err)
	}
	defer conn.Release()

	if _, execErr := conn.Exec(ctx, "CREATE TABLE IF NOT EXISTS schema_migrations (filename text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())"); execErr != nil {
		return fmt.Errorf("ensure schema_migrations: %w", execErr)
	}

	if _, lockErr := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", migrationLockID); lockErr != nil {
		return fmt.Errorf("acquire migration lock: %w", lockErr)
	}
	defer conn.Exec(ctx, "SELECT pg_advisory_unlock($1)", migrationLockID) //nolint:errcheck // best-effort advisory unlock

	entries, err := os.ReadDir(migrationDir)
	if err != nil {
		return fmt.Errorf("read migrations directory: %w", err)
	}

	filenames := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		filenames = append(filenames, entry.Name())
	}
	sort.Strings(filenames)

	for _, filename := range filenames {
		var applied bool
		if scanErr := conn.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE filename = $1)", filename).Scan(&applied); scanErr != nil {
			return fmt.Errorf("check migration %s: %w", filename, scanErr)
		}
		if applied {
			continue
		}

		contents, readErr := os.ReadFile(filepath.Join(migrationDir, filename)) //nolint:gosec // G304: paths are controlled server-side, not user input
		if readErr != nil {
			return fmt.Errorf("read migration %s: %w", filename, readErr)
		}

		tx, beginErr := conn.Begin(ctx)
		if beginErr != nil {
			return fmt.Errorf("begin migration %s: %w", filename, beginErr)
		}

		if _, execErr := tx.Exec(ctx, string(contents)); execErr != nil {
			tx.Rollback(ctx) //nolint:errcheck // rollback is best-effort after exec failure
			return fmt.Errorf("apply migration %s: %w", filename, execErr)
		}

		if _, execErr := tx.Exec(ctx, "INSERT INTO schema_migrations (filename) VALUES ($1)", filename); execErr != nil {
			tx.Rollback(ctx) //nolint:errcheck // rollback is best-effort after exec failure
			return fmt.Errorf("record migration %s: %w", filename, execErr)
		}

		if commitErr := tx.Commit(ctx); commitErr != nil {
			return fmt.Errorf("commit migration %s: %w", filename, commitErr)
		}
	}

	return nil
}

func resolveMigrationDir(dir string) (string, error) {
	candidates := []string{}
	if dir != "" {
		candidates = append(candidates, filepath.Clean(dir))
	}
	if dir != "/migrations" {
		candidates = append(candidates, "/migrations")
	}

	for _, candidate := range candidates {
		info, err := os.Stat(candidate)
		if err == nil && info.IsDir() {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("migrations directory not found: %v", candidates)
}
