package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
)

// backupSuffix is appended to the database path for the pre-migration backup file.
const backupSuffix = ".backup"

var migrationFile = regexp.MustCompile(`^(\d+)_[^/]+\.sql$`)

type migration struct {
	version int
	name    string
	sql     string
}

// Migrate applies the migrations in fsys (a flat directory of NNNN_name.sql files) that are newer
// than the database's PRAGMA user_version, in version order. Before the first one it backs up the
// database file, and each migration runs in its own transaction (ADR 0006). It returns the number
// of migrations applied.
func Migrate(ctx context.Context, sqldb *sql.DB, dbPath string, fsys fs.FS) (int, error) {
	migrations, err := loadMigrations(fsys)
	if err != nil {
		return 0, err
	}
	current, err := userVersion(ctx, sqldb)
	if err != nil {
		return 0, err
	}
	// Fail safe (AGENTS.md 7): a database written by a newer tagcess must not be opened with an
	// older, unaware binary, which could silently ignore or corrupt the unknown schema.
	if newest := migrations[len(migrations)-1].version; current > newest {
		return 0, fmt.Errorf(
			"store: database schema version %d is newer than this binary supports (%d)", current, newest)
	}
	var pending []migration
	for _, m := range migrations {
		if m.version > current {
			pending = append(pending, m)
		}
	}
	if len(pending) == 0 {
		return 0, nil
	}
	if _, err := backup(ctx, sqldb, dbPath); err != nil {
		return 0, err
	}
	for i, m := range pending {
		if err := applyMigration(ctx, sqldb, m); err != nil {
			return i, err
		}
	}
	return len(pending), nil
}

func loadMigrations(fsys fs.FS) ([]migration, error) {
	names, err := fs.Glob(fsys, "*.sql")
	if err != nil {
		return nil, fmt.Errorf("store: read migrations: %w", err)
	}
	if len(names) == 0 {
		return nil, errors.New("store: no migrations found")
	}
	seen := make(map[int]string, len(names))
	migrations := make([]migration, 0, len(names))
	for _, name := range names {
		match := migrationFile.FindStringSubmatch(name)
		if match == nil {
			return nil, fmt.Errorf("store: migration %q must be named NNNN_name.sql", name)
		}
		version, err := strconv.Atoi(match[1])
		if err != nil || version < 1 {
			return nil, fmt.Errorf("store: migration %q has an invalid version", name)
		}
		if prev, ok := seen[version]; ok {
			return nil, fmt.Errorf("store: duplicate migration version %d (%s and %s)", version, prev, name)
		}
		seen[version] = name
		body, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, fmt.Errorf("store: read migration %s: %w", name, err)
		}
		migrations = append(migrations, migration{version: version, name: name, sql: string(body)})
	}
	sort.Slice(migrations, func(i, j int) bool { return migrations[i].version < migrations[j].version })
	// Versions must be 1..N with no gap: a missing file would otherwise silently skip a migration.
	for i, m := range migrations {
		if m.version != i+1 {
			return nil, fmt.Errorf("store: migration versions must be contiguous from 1: expected %d, got %d", i+1, m.version)
		}
	}
	return migrations, nil
}

func applyMigration(ctx context.Context, sqldb *sql.DB, m migration) error {
	tx, err := sqldb.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: migration %s: begin: %w", m.name, err)
	}
	if _, err := tx.ExecContext(ctx, m.sql); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("store: migration %s: %w", m.name, err)
	}
	// PRAGMA takes no bound parameters; version is a validated int.
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", m.version)); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("store: migration %s: set user_version: %w", m.name, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: migration %s: commit: %w", m.name, err)
	}
	return nil
}

func userVersion(ctx context.Context, sqldb *sql.DB) (int, error) {
	var version int
	if err := sqldb.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return 0, fmt.Errorf("store: read user_version: %w", err)
	}
	return version, nil
}

// backup writes a consistent copy of the database to dbPath+backupSuffix using VACUUM INTO, which
// snapshots the database (WAL included) without copying sidecar files. It writes to a temporary name
// and renames it into place, so a failure never destroys the previous backup.
func backup(ctx context.Context, sqldb *sql.DB, dbPath string) (string, error) {
	path := dbPath + backupSuffix
	tmp, err := os.CreateTemp(filepath.Dir(dbPath), filepath.Base(dbPath)+backupSuffix+".tmp-*")
	if err != nil {
		return "", fmt.Errorf("store: backup: %w", err)
	}
	tmpPath := tmp.Name()
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("store: backup: %w", err)
	}
	// VACUUM INTO refuses to write to an existing file, and the rename below removes it on success.
	if err := os.Remove(tmpPath); err != nil {
		return "", fmt.Errorf("store: backup: %w", err)
	}
	if _, err := sqldb.ExecContext(ctx, "VACUUM INTO ?", tmpPath); err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("store: backup %s: %w", path, err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("store: backup %s: %w", path, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("store: backup %s: %w", path, err)
	}
	return path, nil
}
