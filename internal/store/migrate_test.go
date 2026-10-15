package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
)

func testDBPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "tagcess.db")
}

func openTestDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	d, err := OpenDB(context.Background(), path)
	if err != nil {
		t.Fatalf("OpenDB(%s): %v", path, err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func sqlFS(files map[string]string) fs.FS {
	m := fstest.MapFS{}
	for name, body := range files {
		m[name] = &fstest.MapFile{Data: []byte(body)}
	}
	return m
}

func realMigrations(t *testing.T) fs.FS {
	t.Helper()
	sub, err := fs.Sub(embeddedMigrations, "migrations")
	if err != nil {
		t.Fatalf("fs.Sub: %v", err)
	}
	return sub
}

func tableExists(t *testing.T, d *sql.DB, name string) bool {
	t.Helper()
	var got string
	err := d.QueryRowContext(context.Background(),
		`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`, name).Scan(&got)
	if errors.Is(err, sql.ErrNoRows) {
		return false
	}
	if err != nil {
		t.Fatalf("sqlite_master %s: %v", name, err)
	}
	return true
}

// AC1: a fresh database gets every migration, applied in version order, and user_version is the last.
func TestMigrate_FreshDB(t *testing.T) {
	ctx := context.Background()

	t.Run("applies every migration in version order", func(t *testing.T) {
		path := testDBPath(t)
		d := openTestDB(t, path)
		// Unpadded names: lexicographic order would run 10 before 2 and fail, so 10 depending on 2
		// proves the order is numeric. Versions must also be a contiguous 1..N sequence.
		f := map[string]string{"1_init.sql": "CREATE TABLE t1 (id INTEGER PRIMARY KEY);"}
		f["2_add_b.sql"] = "ALTER TABLE t1 ADD COLUMN b TEXT;"
		for v := 3; v <= 9; v++ {
			f[fmt.Sprintf("%d_noop.sql", v)] = fmt.Sprintf("ALTER TABLE t1 ADD COLUMN c%d TEXT;", v)
		}
		f["10_seed.sql"] = "INSERT INTO t1 (id, b) VALUES (1, 'x');"

		n, err := Migrate(ctx, d, path, sqlFS(f))
		if err != nil {
			t.Fatalf("Migrate: %v", err)
		}
		if n != 10 {
			t.Fatalf("applied = %d, want 10", n)
		}
		if v, err := userVersion(ctx, d); err != nil || v != 10 {
			t.Fatalf("user_version = %d (err %v), want 10", v, err)
		}
		var b string
		if err := d.QueryRowContext(ctx, "SELECT b FROM t1 WHERE id = 1").Scan(&b); err != nil {
			t.Fatalf("2/10 did not apply in order: %v", err)
		}
	})

	t.Run("embedded schema", func(t *testing.T) {
		path := testDBPath(t)
		d := openTestDB(t, path)
		n, err := Migrate(ctx, d, path, realMigrations(t))
		if err != nil {
			t.Fatalf("Migrate: %v", err)
		}
		if n != 8 {
			t.Fatalf("applied = %d, want 8", n)
		}
		if v, err := userVersion(ctx, d); err != nil || v != 8 {
			t.Fatalf("user_version = %d (err %v), want 8", v, err)
		}
		for _, tbl := range []string{
			"settings", "changes", "audit_events", "applied_artifacts", "sync_runs", "webhook_events", "alerts",
			"sites", "site_hosts", "site_api_rules", "site_redirects", "site_headers",
			"zitadel_owned_uris", "site_versions", "policy_revisions", "headscale_maintenance", "k8s_snapshots", "k8s_snapshot_attempts", "k8s_drafts", "k8s_draft_routes", "observations",
		} {
			if !tableExists(t, d, tbl) {
				t.Errorf("table %s missing after migration", tbl)
			}
		}
	})
}

// AC2: a second run must change nothing.
func TestMigrate_Idempotent(t *testing.T) {
	ctx := context.Background()
	path := testDBPath(t)
	d := openTestDB(t, path)
	f := realMigrations(t)

	if n, err := Migrate(ctx, d, path, f); err != nil || n != 8 {
		t.Fatalf("first Migrate: n=%d err=%v", n, err)
	}
	// A no-op run must not touch the existing backup (no new migrations means no new backup).
	backup := path + backupSuffix
	before, err := os.Stat(backup)
	if err != nil {
		t.Fatalf("stat backup after first Migrate: %v", err)
	}
	beforeContent, err := os.ReadFile(backup)
	if err != nil {
		t.Fatalf("read backup after first Migrate: %v", err)
	}

	if n, err := Migrate(ctx, d, path, f); err != nil || n != 0 {
		t.Fatalf("second Migrate: n=%d err=%v, want 0", n, err)
	}

	after, err := os.Stat(backup)
	if err != nil {
		t.Fatalf("stat backup after second Migrate: %v", err)
	}
	if !after.ModTime().Equal(before.ModTime()) {
		t.Errorf("second Migrate rewrote the backup: mtime %v -> %v", before.ModTime(), after.ModTime())
	}
	afterContent, err := os.ReadFile(backup)
	if err != nil {
		t.Fatalf("read backup after second Migrate: %v", err)
	}
	if !bytes.Equal(beforeContent, afterContent) {
		t.Error("second Migrate changed the backup content")
	}
	if v, err := userVersion(ctx, d); err != nil || v != 8 {
		t.Fatalf("user_version = %d (err %v), want 8", v, err)
	}
	// The seeded row must not be inserted twice.
	var count int
	if err := d.QueryRowContext(ctx, `SELECT count(*) FROM settings WHERE key = 'dry_run'`).Scan(&count); err != nil {
		t.Fatalf("count settings: %v", err)
	}
	if count != 1 {
		t.Fatalf("dry_run rows = %d, want 1", count)
	}
}

// AC3: a failing migration rolls back and leaves user_version untouched.
func TestMigrate_FailureRollsBack(t *testing.T) {
	ctx := context.Background()
	path := testDBPath(t)
	d := openTestDB(t, path)
	base := sqlFS(map[string]string{"0001_init.sql": "CREATE TABLE t1 (id INTEGER PRIMARY KEY);"})
	if _, err := Migrate(ctx, d, path, base); err != nil {
		t.Fatalf("setup Migrate: %v", err)
	}

	// 0002 writes a row and bumps user_version before failing on the unique constraint: a real
	// partial write, so only a rollback can leave neither the table nor the version change behind.
	f := sqlFS(map[string]string{
		"0001_init.sql": "CREATE TABLE t1 (id INTEGER PRIMARY KEY);",
		"0002_bad.sql": "CREATE TABLE t2 (id INTEGER PRIMARY KEY);" +
			"PRAGMA user_version = 2;" +
			"INSERT INTO t2 (id) VALUES (1);" +
			"INSERT INTO t2 (id) VALUES (1);",
	})
	if _, err := Migrate(ctx, d, path, f); err == nil {
		t.Fatal("Migrate with a failing migration: want error, got nil")
	}
	if v, err := userVersion(ctx, d); err != nil || v != 1 {
		t.Fatalf("user_version = %d (err %v), want 1 after rollback", v, err)
	}
	if tableExists(t, d, "t2") {
		t.Fatal("t2 exists after rollback; migration 0002 was not rolled back")
	}
}

// A database written by a newer binary must not be opened (AGENTS.md 7, fail safe).
func TestMigrate_NewerSchemaFails(t *testing.T) {
	ctx := context.Background()
	path := testDBPath(t)
	d := openTestDB(t, path)
	f := sqlFS(map[string]string{"0001_init.sql": "CREATE TABLE t1 (id INTEGER PRIMARY KEY);"})
	if _, err := Migrate(ctx, d, path, f); err != nil {
		t.Fatalf("setup Migrate: %v", err)
	}
	if _, err := d.ExecContext(ctx, "PRAGMA user_version = 99"); err != nil {
		t.Fatalf("bump user_version: %v", err)
	}
	if _, err := Migrate(ctx, d, path, f); err == nil {
		t.Fatal("Migrate on a newer schema: want error, got nil")
	}
}

// Migration files must be a contiguous 1..N sequence; a gap would silently skip one.
func TestMigrate_RejectsGap(t *testing.T) {
	ctx := context.Background()
	path := testDBPath(t)
	d := openTestDB(t, path)
	f := sqlFS(map[string]string{
		"0001_init.sql": "CREATE TABLE t1 (id INTEGER PRIMARY KEY);",
		"0003_gap.sql":  "CREATE TABLE t3 (id INTEGER PRIMARY KEY);",
	})
	if _, err := Migrate(ctx, d, path, f); err == nil {
		t.Fatal("Migrate with a version gap: want error, got nil")
	}
}

// AC4: the database file is backed up before a migration is applied.
func TestMigrate_BackupBeforeApply(t *testing.T) {
	ctx := context.Background()
	path := testDBPath(t)
	d := openTestDB(t, path)
	first := sqlFS(map[string]string{"0001_init.sql": "CREATE TABLE t1 (id INTEGER PRIMARY KEY);"})
	if _, err := Migrate(ctx, d, path, first); err != nil {
		t.Fatalf("first Migrate: %v", err)
	}
	if _, err := d.ExecContext(ctx, "INSERT INTO t1 (id) VALUES (7)"); err != nil {
		t.Fatalf("seed t1: %v", err)
	}

	second := sqlFS(map[string]string{
		"0001_init.sql": "CREATE TABLE t1 (id INTEGER PRIMARY KEY);",
		"0002_add.sql":  "CREATE TABLE t2 (id INTEGER PRIMARY KEY);",
	})
	if _, err := Migrate(ctx, d, path, second); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}

	backup := path + backupSuffix
	if _, err := os.Stat(backup); err != nil {
		t.Fatalf("backup %s missing: %v", backup, err)
	}
	// The backup must be the pre-migration state: version 1, no t2, row 7 present.
	b := openTestDB(t, backup)
	if v, err := userVersion(ctx, b); err != nil || v != 1 {
		t.Fatalf("backup user_version = %d (err %v), want 1", v, err)
	}
	if tableExists(t, b, "t2") {
		t.Fatal("backup contains t2; it was taken after the migration, not before")
	}
	var id int
	if err := b.QueryRowContext(ctx, "SELECT id FROM t1").Scan(&id); err != nil || id != 7 {
		t.Fatalf("backup t1 row = %d (err %v), want 7", id, err)
	}
}

// A failed new backup must leave the previous backup intact (the old one is not deleted first).
func TestBackup_FailureKeepsPrevious(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "tagcess.db")
	backupPath := dbPath + backupSuffix
	const previous = "previous backup contents"
	if err := os.WriteFile(backupPath, []byte(previous), 0o600); err != nil {
		t.Fatalf("seed previous backup: %v", err)
	}

	d := openTestDB(t, dbPath)
	if err := d.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}
	// VACUUM INTO on a closed database fails; the previous backup must survive the attempt.
	if _, err := backup(ctx, d, dbPath); err == nil {
		t.Fatal("backup with a closed database: want error, got nil")
	}
	got, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("previous backup was removed by a failed backup: %v", err)
	}
	if string(got) != previous {
		t.Fatalf("previous backup = %q, want %q", got, previous)
	}
}

// Config does not force data_dir to be absolute, so OpenDB must accept a relative path.
func TestOpenDB_RelativePath(t *testing.T) {
	ctx := context.Background()
	t.Chdir(t.TempDir())

	d, err := OpenDB(ctx, "tagcess.db")
	if err != nil {
		t.Fatalf("OpenDB(relative path): %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	if _, err := d.ExecContext(ctx, "CREATE TABLE t (id INTEGER PRIMARY KEY)"); err != nil {
		t.Fatalf("use relative database: %v", err)
	}
	if _, err := os.Stat("tagcess.db"); err != nil {
		t.Fatalf("relative database file not created: %v", err)
	}
}

// AC5: opening a connection applies WAL, busy_timeout and foreign_keys.
func TestOpen_Pragmas(t *testing.T) {
	ctx := context.Background()
	path := testDBPath(t)
	d := openTestDB(t, path)

	var mode string
	if err := d.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatalf("journal_mode: %v", err)
	}
	if mode != "wal" {
		t.Errorf("journal_mode = %q, want wal", mode)
	}
	for _, tc := range []struct {
		pragma string
		want   int
	}{{"foreign_keys", 1}, {"busy_timeout", busyTimeoutMS}} {
		var got int
		if err := d.QueryRowContext(ctx, "PRAGMA "+tc.pragma).Scan(&got); err != nil {
			t.Fatalf("PRAGMA %s: %v", tc.pragma, err)
		}
		if got != tc.want {
			t.Errorf("PRAGMA %s = %d, want %d", tc.pragma, got, tc.want)
		}
	}

	if _, err := d.ExecContext(ctx,
		"CREATE TABLE parent (id INTEGER PRIMARY KEY);"+
			"CREATE TABLE child (pid INTEGER REFERENCES parent(id));"); err != nil {
		t.Fatalf("create fk tables: %v", err)
	}
	if _, err := d.ExecContext(ctx, "INSERT INTO child (pid) VALUES (99)"); err == nil {
		t.Error("foreign_keys=ON not enforced: orphan insert succeeded")
	}
}

// AC6: a freshly created database starts with dry-run mode on (Y-06.2).
func TestSettings_DryRunDefaultOn(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, testDBPath(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	on, err := s.DryRun(ctx)
	if err != nil {
		t.Fatalf("DryRun: %v", err)
	}
	if !on {
		t.Fatal("dry-run mode should default to on for a new database")
	}
}

// F3-005 AC1: the policy_revisions migration creates the table with its CHECK and NOT NULL
// constraints and leaves tables and rows from the earlier migrations untouched.
func TestMigrate_PolicyRevisions(t *testing.T) {
	ctx := context.Background()
	path := testDBPath(t)
	d := openTestDB(t, path)
	all := realMigrations(t)

	// Apply everything before 0005 and put a row in an existing table.
	before := fstest.MapFS{}
	for _, name := range []string{"0001_init.sql", "0002_sites.sql", "0003_zitadel_owned_uris.sql", "0004_site_versions.sql"} {
		body, err := fs.ReadFile(all, name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		before[name] = &fstest.MapFile{Data: body}
	}
	if n, err := Migrate(ctx, d, path, before); err != nil || n != 4 {
		t.Fatalf("Migrate(before): n=%d err=%v", n, err)
	}
	if _, err := d.ExecContext(ctx,
		`INSERT INTO site_versions (site_id, change_id, op, hosts, snapshot, actor, created_at) VALUES (1, 2, 'add', 'h', 's', 'a', 't')`); err != nil {
		t.Fatalf("seed site_versions: %v", err)
	}
	if tableExists(t, d, "policy_revisions") {
		t.Fatal("policy_revisions exists before its migration")
	}

	through5 := fstest.MapFS{}
	for _, name := range []string{"0001_init.sql", "0002_sites.sql", "0003_zitadel_owned_uris.sql", "0004_site_versions.sql", "0005_policy_revisions.sql"} {
		body, err := fs.ReadFile(all, name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		through5[name] = &fstest.MapFile{Data: body}
	}
	if n, err := Migrate(ctx, d, path, through5); err != nil || n != 1 {
		t.Fatalf("Migrate(through 0005): n=%d err=%v, want 1", n, err)
	}
	if !tableExists(t, d, "policy_revisions") {
		t.Fatal("policy_revisions missing after migration")
	}
	var rows int
	if err := d.QueryRowContext(ctx, `SELECT count(*) FROM site_versions`).Scan(&rows); err != nil || rows != 1 {
		t.Errorf("site_versions rows = %d (err %v), want 1 kept", rows, err)
	}

	insert := func(status, source string, rawHash any) error {
		_, err := d.ExecContext(ctx,
			`INSERT INTO policy_revisions (raw, raw_hash, canonical_hash, source, actor, created_at, apply_status)
			 VALUES ('{}', ?, 'c', ?, 'a', 't', ?)`, rawHash, source, status)
		return err
	}
	if err := insert("pending", "ui", "h"); err != nil {
		t.Fatalf("valid insert: %v", err)
	}
	for _, status := range []string{"applied", "failed", "unknown", "dry_run"} {
		if err := insert(status, "sync", "h"); err != nil {
			t.Errorf("status %s rejected: %v", status, err)
		}
	}
	for _, source := range []string{"rollback", "recovery", "external"} {
		if err := insert("pending", source, "h"); err != nil {
			t.Errorf("source %s rejected: %v", source, err)
		}
	}
	if err := insert("rolled_back", "ui", "h"); err == nil {
		t.Error("apply_status CHECK accepted an unknown status")
	}
	if err := insert("pending", "cli", "h"); err == nil {
		t.Error("source CHECK accepted an unknown source")
	}
	if err := insert("pending", "ui", nil); err == nil {
		t.Error("raw_hash NOT NULL accepted NULL")
	}
}

// F3b-013 AC1: the maintenance migration seeds exactly one row, in state off, and its constraints
// keep it a single row with a known state.
func TestMigrate_HeadscaleMaintenance(t *testing.T) {
	ctx := context.Background()
	path := testDBPath(t)
	d := openTestDB(t, path)
	if _, err := Migrate(ctx, d, path, realMigrations(t)); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	var n int
	var state string
	if err := d.QueryRowContext(ctx, `SELECT count(*), min(state) FROM headscale_maintenance`).Scan(&n, &state); err != nil {
		t.Fatalf("read row: %v", err)
	}
	if n != 1 || state != "off" {
		t.Errorf("rows = %d state = %q, want one row in state off", n, state)
	}
	if _, err := d.ExecContext(ctx, `INSERT INTO headscale_maintenance (id) VALUES (2)`); err == nil {
		t.Error("a second maintenance row was accepted")
	}
	if _, err := d.ExecContext(ctx, `UPDATE headscale_maintenance SET state = 'maybe'`); err == nil {
		t.Error("an unknown state was accepted")
	}
}
