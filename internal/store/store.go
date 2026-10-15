// Package store is tagcess's SQLite state: connection setup, the embedded migrator and the
// sqlc-generated queries (ADR 0006). Writes go through a single process; resilience comes from
// WAL, a busy timeout and the pre-migration backup.
package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"strconv"

	_ "modernc.org/sqlite" // registers the "sqlite" driver

	"github.com/nesiler/tagcess/internal/store/db"
)

const (
	busyTimeoutMS = 5000 // milliseconds; ADR 0006 requires a busy timeout but fixes no value
	dryRunKey     = "dry_run"
)

// embeddedMigrations holds the numbered SQL migrations shipped in the binary.
//
//go:embed migrations/*.sql
var embeddedMigrations embed.FS

// Store is an open database with migrations applied.
type Store struct {
	db   *sql.DB
	q    *db.Queries
	path string
}

// Open opens (creating it if needed) the SQLite database at path, applies pending migrations and
// returns the ready store. The parent directory must already exist.
func Open(ctx context.Context, path string) (*Store, error) {
	sqldb, err := OpenDB(ctx, path)
	if err != nil {
		return nil, err
	}
	migrations, err := fs.Sub(embeddedMigrations, "migrations")
	if err != nil {
		_ = sqldb.Close()
		return nil, fmt.Errorf("store: %w", err)
	}
	if _, err := Migrate(ctx, sqldb, path, migrations); err != nil {
		_ = sqldb.Close()
		return nil, err
	}
	return &Store{db: sqldb, q: db.New(sqldb), path: path}, nil
}

// OpenDB opens the SQLite database at path with the pragmas ADR 0006 requires on every pooled
// connection: WAL journaling, a busy timeout, foreign key enforcement and immediate transactions.
// It does not migrate.
func OpenDB(ctx context.Context, path string) (*sql.DB, error) {
	query := url.Values{
		"_journal_mode": {"WAL"},
		"_busy_timeout": {strconv.Itoa(busyTimeoutMS)},
		"_foreign_keys": {"1"},
		// Read-write transactions take the write lock when they begin. A deferred transaction that
		// read before another connection committed fails its first write with SQLITE_BUSY
		// (snapshot) at once in WAL mode, without waiting for the busy timeout; the alert loop's
		// read-then-write transactions then lost a whole round next to the health runner's writes
		// (U-15). Read-only transactions must not inherit this mode: they pass
		// sql.TxOptions{ReadOnly: true} so the driver begins them deferred, taking a read snapshot
		// instead of the single write lock a concurrent writer needs.
		"_txlock": {"immediate"},
	}
	// OmitHost keeps a relative path relative ("file:rel.db"): without it URL.String builds
	// "file://rel.db", whose host is the path and which SQLite rejects as an invalid URI authority.
	dsn := url.URL{Scheme: "file", OmitHost: true, Path: path, RawQuery: query.Encode()}
	sqldb, err := sql.Open("sqlite", dsn.String())
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	if err := sqldb.PingContext(ctx); err != nil {
		_ = sqldb.Close()
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	return sqldb, nil
}

// CheckReadable is the liveness read: the database file must still exist at its path (an unlinked
// file stays readable through the open handle) and PRAGMA quick_check on a fresh connection must
// report "ok". The caller bounds it with ctx.
func (s *Store) CheckReadable(ctx context.Context) error {
	if _, err := os.Stat(s.path); err != nil {
		return fmt.Errorf("store: database file: %w", err)
	}
	// A fresh handle: the pooled connections keep cached pages and never notice a rewritten file.
	probe, err := OpenDB(ctx, s.path)
	if err != nil {
		return err
	}
	defer func() { _ = probe.Close() }()
	var res string
	if err := probe.QueryRowContext(ctx, "PRAGMA quick_check(1)").Scan(&res); err != nil {
		return fmt.Errorf("store: quick_check: %w", err)
	}
	if res != "ok" {
		return fmt.Errorf("store: quick_check: %s", res)
	}
	return nil
}

// Close closes the underlying database.
func (s *Store) Close() error { return s.db.Close() }

// DB returns the underlying *sql.DB.
func (s *Store) DB() *sql.DB { return s.db }

// Queries returns the sqlc-generated query interface.
func (s *Store) Queries() *db.Queries { return s.q }

// DryRun reports whether dry-run mode is on (Y-06). New databases start with it on (Y-06.2).
func (s *Store) DryRun(ctx context.Context) (bool, error) {
	value, err := s.q.GetSetting(ctx, dryRunKey)
	if err != nil {
		return false, fmt.Errorf("store: read %s: %w", dryRunKey, err)
	}
	on, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("store: setting %s = %q: %w", dryRunKey, value, err)
	}
	return on, nil
}
