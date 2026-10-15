package store

import (
	"context"
	"database/sql"
	"errors"
	"io/fs"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/nesiler/tagcess/internal/store/db"
)

// f4Tables are the tables the single F4 migration creates.
var f4Tables = []string{"k8s_snapshots", "k8s_snapshot_attempts", "k8s_drafts", "k8s_draft_routes", "observations"}

func containsFold(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}

// migrationsThrough returns the real embedded migrations up to and including version max.
func migrationsThrough(t *testing.T, max int) fs.FS {
	t.Helper()
	all := realMigrations(t)
	names, err := fs.Glob(all, "*.sql")
	if err != nil {
		t.Fatalf("glob migrations: %v", err)
	}
	m := fstest.MapFS{}
	for _, name := range names {
		version := 0
		for _, r := range name[:4] {
			version = version*10 + int(r-'0')
		}
		if version > max {
			continue
		}
		body, err := fs.ReadFile(all, name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		m[name] = &fstest.MapFile{Data: body}
	}
	return m
}

func tableColumns(t *testing.T, d *sql.DB, table string) map[string]bool {
	t.Helper()
	rows, err := d.QueryContext(context.Background(), `PRAGMA table_info(`+table+`)`)
	if err != nil {
		t.Fatalf("table_info %s: %v", table, err)
	}
	defer func() { _ = rows.Close() }()
	cols := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			t.Fatalf("scan %s table_info: %v", table, err)
		}
		cols[name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate %s table_info: %v", table, err)
	}
	return cols
}

// indexInfo returns the indexed column names of an index in key order.
func indexInfo(t *testing.T, d *sql.DB, index string) []string {
	t.Helper()
	rows, err := d.QueryContext(context.Background(), `PRAGMA index_info(`+index+`)`)
	if err != nil {
		t.Fatalf("index_info %s: %v", index, err)
	}
	defer func() { _ = rows.Close() }()
	var cols []string
	for rows.Next() {
		var seqno, cid int
		var name string
		if err := rows.Scan(&seqno, &cid, &name); err != nil {
			t.Fatalf("scan index_info %s: %v", index, err)
		}
		cols = append(cols, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate index_info %s: %v", index, err)
	}
	return cols
}

// findForbiddenColumn reports the first column that matches a forbidden fragment, or "" if the set
// is clean. It is the single scan used both for the real F4 tables and for the positive control.
func findForbiddenColumn(cols map[string]bool, forbidden []string) string {
	for c := range cols {
		for _, f := range forbidden {
			if containsFold(c, f) {
				return c + " (matches " + f + ")"
			}
		}
	}
	return ""
}

// AC1: a fresh database and a 0006-era database both reach the single F4 schema version: snapshot,
// draft and observation tables plus the extended alerts columns; reopening keeps the same version.
func TestF4Schema_FreshAndExistingDatabaseUpgrade(t *testing.T) {
	ctx := context.Background()

	t.Run("fresh database", func(t *testing.T) {
		path := testDBPath(t)
		d := openTestDB(t, path)
		if n, err := Migrate(ctx, d, path, realMigrations(t)); err != nil || n != 8 {
			t.Fatalf("Migrate: n=%d err=%v, want 8", n, err)
		}
		if v, err := userVersion(ctx, d); err != nil || v != 8 {
			t.Fatalf("user_version = %d (err %v), want 8", v, err)
		}
		for _, tbl := range f4Tables {
			if !tableExists(t, d, tbl) {
				t.Errorf("table %s missing after F4 migration", tbl)
			}
		}
		for _, col := range []string{"subject", "severity", "acknowledged_at", "last_success",
			"last_consumed_sample", "freshness", "muted", "consecutive_failures", "consecutive_successes", "evidence_summary"} {
			if !tableColumns(t, d, "alerts")[col] {
				t.Errorf("alerts column %s missing", col)
			}
		}
		if err := d.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
		// Reopening the same path keeps the same schema version and the tables.
		d2 := openTestDB(t, path)
		if v, err := userVersion(ctx, d2); err != nil || v != 8 {
			t.Fatalf("reopen user_version = %d (err %v), want 8", v, err)
		}
		if !tableExists(t, d2, "observations") {
			t.Error("observations missing after reopen")
		}
	})

	t.Run("database upgraded from 0006", func(t *testing.T) {
		path := testDBPath(t)
		d := openTestDB(t, path)
		if n, err := Migrate(ctx, d, path, migrationsThrough(t, 6)); err != nil || n != 6 {
			t.Fatalf("Migrate(0006): n=%d err=%v, want 6", n, err)
		}
		if tableExists(t, d, "observations") || tableExists(t, d, "k8s_snapshots") || tableExists(t, d, "k8s_drafts") ||
			tableExists(t, d, "k8s_snapshot_attempts") || tableExists(t, d, "k8s_draft_routes") {
			t.Fatal("F4 tables exist before the F4 migration")
		}
		if tableColumns(t, d, "alerts")["subject"] {
			t.Fatal("alerts already extended before the F4 migration")
		}
		if _, err := Migrate(ctx, d, path, realMigrations(t)); err != nil {
			t.Fatalf("Migrate(all): %v", err)
		}
		if v, err := userVersion(ctx, d); err != nil || v != 8 {
			t.Fatalf("user_version = %d (err %v), want 8", v, err)
		}
		for _, tbl := range f4Tables {
			if !tableExists(t, d, tbl) {
				t.Errorf("table %s missing after F4 migration", tbl)
			}
		}
		// The same upgrade must extend alerts, not only a fresh install.
		for _, col := range []string{"subject", "severity", "acknowledged_at", "last_success",
			"last_consumed_sample", "freshness", "muted", "consecutive_failures", "consecutive_successes", "evidence_summary"} {
			if !tableColumns(t, d, "alerts")[col] {
				t.Errorf("alerts column %s missing after the 0006->0007 upgrade", col)
			}
		}
	})
}

// AC2: legacy sites, settings and open/resolved F1/F3 alerts survive the upgrade untouched; the new
// alert columns get safe defaults and the all-column legacy projections still yield db.Alert types.
func TestF4Schema_UpgradePreservesLegacyState(t *testing.T) {
	ctx := context.Background()
	path := testDBPath(t)
	d := openTestDB(t, path)
	if _, err := Migrate(ctx, d, path, migrationsThrough(t, 6)); err != nil {
		t.Fatalf("Migrate(0006): %v", err)
	}

	if _, err := d.ExecContext(ctx,
		`INSERT INTO sites (kind, open_reason, cert, target_kind, target_url, created_at, updated_at)
		 VALUES ('open', 'intentional', 'auto', 'k8s', 'https://internal.example', '2026-10-01T00:00:00Z', '2026-10-01T00:00:00Z')`); err != nil {
		t.Fatalf("seed site: %v", err)
	}
	if _, err := d.ExecContext(ctx,
		`UPDATE settings SET value = 'true', updated_at = '2026-10-01T00:00:00Z' WHERE key = 'dry_run'`); err != nil {
		t.Fatalf("seed setting: %v", err)
	}
	if _, err := d.ExecContext(ctx,
		`INSERT INTO alerts (kind, source, first_seen_at, last_seen_at) VALUES ('reconcile_read_failed', 'zitadel', '2026-10-01T00:00:00Z', '2026-10-01T01:00:00Z')`); err != nil {
		t.Fatalf("seed open alert: %v", err)
	}
	if _, err := d.ExecContext(ctx,
		`INSERT INTO alerts (kind, source, first_seen_at, last_seen_at, resolved_at) VALUES ('policy_drift', 'site-1', '2026-10-01T00:00:00Z', '2026-10-01T01:00:00Z', '2026-10-01T02:00:00Z')`); err != nil {
		t.Fatalf("seed resolved alert: %v", err)
	}

	if _, err := Migrate(ctx, d, path, realMigrations(t)); err != nil {
		t.Fatalf("Migrate(all): %v", err)
	}

	var siteCount int
	if err := d.QueryRowContext(ctx, `SELECT count(*) FROM sites`).Scan(&siteCount); err != nil || siteCount != 1 {
		t.Errorf("sites rows = %d (err %v), want 1 kept", siteCount, err)
	}
	var dryRun string
	if err := d.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = 'dry_run'`).Scan(&dryRun); err != nil || dryRun != "true" {
		t.Errorf("dry_run = %q (err %v), want true kept", dryRun, err)
	}
	var alerts int
	if err := d.QueryRowContext(ctx, `SELECT count(*) FROM alerts`).Scan(&alerts); err != nil || alerts != 2 {
		t.Fatalf("alerts rows = %d (err %v), want 2 kept", alerts, err)
	}
	var resolved sql.NullString
	if err := d.QueryRowContext(ctx,
		`SELECT resolved_at FROM alerts WHERE kind = 'policy_drift'`).Scan(&resolved); err != nil || !resolved.Valid || resolved.String != "2026-10-01T02:00:00Z" {
		t.Errorf("resolved_at = %v (err %v), want 2026-10-01T02:00:00Z kept", resolved, err)
	}

	// New columns default safely on legacy rows: empty subject/severity/freshness, NULL timestamps,
	// zero counters, unmuted.
	var subject, severity, freshness string
	var ack, lastSuccess, lastConsumed sql.NullString
	var muted, failures, successes int64
	err := d.QueryRowContext(ctx,
		`SELECT subject, severity, acknowledged_at, last_success, last_consumed_sample, freshness, muted, consecutive_failures, consecutive_successes
		 FROM alerts WHERE kind = 'reconcile_read_failed'`).
		Scan(&subject, &severity, &ack, &lastSuccess, &lastConsumed, &freshness, &muted, &failures, &successes)
	if err != nil {
		t.Fatalf("read new columns: %v", err)
	}
	if subject != "" || severity != "" || ack.Valid || lastSuccess.Valid ||
		(lastConsumed.Valid && lastConsumed.String != "") ||
		freshness != "" || muted != 0 || failures != 0 || successes != 0 {
		t.Errorf("legacy row got unsafe defaults: subject=%q severity=%q ack=%v lastSuccess=%v consumed=%v freshness=%q muted=%d failures=%d successes=%d",
			subject, severity, ack, lastSuccess, lastConsumed, freshness, muted, failures, successes)
	}

	// The legacy query contract holds: InsertAlert yields db.Alert and ListOpenAlerts []db.Alert.
	q := db.New(d)
	var inserted db.Alert
	inserted, err = q.InsertAlert(ctx, db.InsertAlertParams{
		Kind: "reconcile_read_failed", Source: "headscale",
		FirstSeenAt: "2026-10-02T00:00:00Z", LastSeenAt: "2026-10-02T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("InsertAlert: %v", err)
	}
	var open []db.Alert
	open, err = q.ListOpenAlerts(ctx)
	if err != nil {
		t.Fatalf("ListOpenAlerts: %v", err)
	}
	if len(open) != 2 {
		t.Fatalf("open alerts = %d, want 2", len(open))
	}
	// The legacy open alert must appear with its legacy fields and empty new lifecycle state.
	found := false
	for _, a := range open {
		if a.Kind == "reconcile_read_failed" && a.Source == "zitadel" {
			found = true
			if a.ResolvedAt.Valid || a.Subject != "" || a.Severity != "" || a.Muted != 0 {
				t.Errorf("legacy open alert read back with new state: %+v", a)
			}
		}
	}
	if !found {
		t.Error("legacy open alert missing from ListOpenAlerts")
	}
	// The inserted alert itself must round-trip through the widened projection with safe lifecycle
	// defaults, not just appear in the list.
	if inserted.ID == 0 || inserted.Kind != "reconcile_read_failed" || inserted.Source != "headscale" {
		t.Errorf("InsertAlert returned unexpected identity: %+v", inserted)
	}
	if inserted.ResolvedAt.Valid || inserted.Subject != "" || inserted.Severity != "" ||
		inserted.AcknowledgedAt.Valid || inserted.LastSuccess.Valid ||
		inserted.LastConsumedSample != "" || inserted.Freshness != "" ||
		inserted.Muted != 0 || inserted.ConsecutiveFailures != 0 || inserted.ConsecutiveSuccesses != 0 {
		t.Errorf("InsertAlert returned unsafe lifecycle defaults: %+v", inserted)
	}
}

// AC3: the snapshot/draft/observation records stay separate tables with category/source/time fields,
// and no credential or raw-response column exists anywhere in the F4 schema.
func TestF4Schema_SeparatedRecordsHaveNoSecretFields(t *testing.T) {
	ctx := context.Background()
	path := testDBPath(t)
	d := openTestDB(t, path)
	if _, err := Migrate(ctx, d, path, realMigrations(t)); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	tableSQL := func(name string) string {
		t.Helper()
		var sqlText string
		if err := d.QueryRowContext(ctx,
			`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?`, name).Scan(&sqlText); err != nil {
			t.Fatalf("sqlite_master %s: %v", name, err)
		}
		return sqlText
	}

	// Separation: distinct tables, each carrying its own time/source dimension.
	snapshotSQL := tableSQL("k8s_snapshots")
	attemptSQL := tableSQL("k8s_snapshot_attempts")
	draftSQL := tableSQL("k8s_drafts")
	routeSQL := tableSQL("k8s_draft_routes")
	obsSQL := tableSQL("observations")
	for _, want := range []string{"scope", "profile_version", "observed_at", "payload"} {
		if !containsFold(snapshotSQL, want) {
			t.Errorf("k8s_snapshots lacks %q", want)
		}
	}
	for _, want := range []string{"scope", "profile_version", "attempted_at", "outcome", "error_class"} {
		if !containsFold(attemptSQL, want) {
			t.Errorf("k8s_snapshot_attempts lacks %q", want)
		}
	}
	for _, want := range []string{"host", "access_choice", "review_state", "created_at"} {
		if !containsFold(draftSQL, want) {
			t.Errorf("k8s_drafts lacks %q", want)
		}
	}
	for _, want := range []string{"namespace", "ingress_uid", "path", "backend", "resource_version"} {
		if !containsFold(routeSQL, want) {
			t.Errorf("k8s_draft_routes lacks %q", want)
		}
	}
	for _, want := range []string{"category", "source", "vantage", "endpoint", "sni", "observed_at", "last_attempt_at"} {
		if !containsFold(obsSQL, want) {
			t.Errorf("observations lacks %q", want)
		}
	}

	// Separation is more than names: the distinguishing dimension of each record kind must be owned
	// by exactly one table, so a snapshot cannot absorb draft, attempt or observation fields.
	cols := map[string]map[string]bool{}
	for _, tbl := range f4Tables {
		cols[tbl] = tableColumns(t, d, tbl)
	}
	own := []struct{ table, col string }{
		{"k8s_snapshots", "payload"},
		{"k8s_snapshot_attempts", "outcome"},
		{"k8s_drafts", "access_choice"},
		{"k8s_draft_routes", "ingress_uid"},
		{"observations", "vantage"},
		{"observations", "tls_fingerprint"},
	}
	for _, o := range own {
		for _, tbl := range f4Tables {
			if has := cols[tbl][o.col]; has != (tbl == o.table) {
				t.Errorf("column %q in %s = %v, want only in %s", o.col, tbl, has, o.table)
			}
		}
	}

	// The record kinds must remain distinct physical tables.
	var n int
	if err := d.QueryRowContext(ctx,
		`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name IN
		 ('k8s_snapshots', 'k8s_snapshot_attempts', 'k8s_drafts', 'k8s_draft_routes', 'observations')`).Scan(&n); err != nil {
		t.Fatalf("count F4 tables: %v", err)
	}
	if n != len(f4Tables) {
		t.Fatalf("F4 record tables = %d, want %d separated tables", n, len(f4Tables))
	}

	// No credential or raw-response field anywhere in the new tables or the extended alerts. The
	// list matches the AC3 claim: token, credential, password, secret, private, kubeconfig, cookie,
	// authorization, body, header.
	forbidden := []string{"token", "credential", "password", "secret", "private", "kubeconfig",
		"cookie", "authorization", "body", "header"}
	for _, tbl := range append(append([]string{}, f4Tables...), "alerts") {
		if f := findForbiddenColumn(tableColumns(t, d, tbl), forbidden); f != "" {
			t.Errorf("%s has forbidden field %s", tbl, f)
		}
	}

	// Positive control: the scan above must be able to fail. Plant a forbidden column in a throwaway
	// database and prove it is detected; a clean control table must stay clean.
	pd := openTestDB(t, testDBPath(t))
	if _, err := pd.ExecContext(ctx,
		`CREATE TABLE planted_secret (id INTEGER PRIMARY KEY, session_token TEXT);`+
			`CREATE TABLE planted_clean (id INTEGER PRIMARY KEY, sni TEXT, observed_at TEXT);`); err != nil {
		t.Fatalf("create control tables: %v", err)
	}
	if findForbiddenColumn(tableColumns(t, pd, "planted_secret"), forbidden) == "" {
		t.Error("forbidden-column scan did not detect a planted session_token column")
	}
	if f := findForbiddenColumn(tableColumns(t, pd, "planted_clean"), forbidden); f != "" {
		t.Errorf("forbidden-column scan flagged a clean column: %s", f)
	}

	// TLS observation evidence is kept as leaf metadata only (no raw handshake material).
	if !containsFold(obsSQL, "tls_not_after") || !containsFold(obsSQL, "tls_fingerprint") {
		t.Error("observations must keep leaf TLS evidence (not_after, fingerprint)")
	}
}

// Review fix (F4-006): the observation key must carry every measurement dimension, so a second
// vantage, endpoint, SNI or path is stored separately instead of overwriting the first (R3 B-05/B-06).
func TestF4Schema_ObservationKeySeparatesMeasurementDimensions(t *testing.T) {
	ctx := context.Background()
	path := testDBPath(t)
	d := openTestDB(t, path)
	if _, err := Migrate(ctx, d, path, realMigrations(t)); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	// The unique key itself must name all dimensions, not only category/site/host/route/source.
	key := map[string]bool{}
	for _, c := range indexInfo(t, d, "idx_observations_key") {
		key[c] = true
	}
	for _, c := range []string{"category", "site", "host", "route", "source", "vantage", "endpoint", "sni", "path"} {
		if !key[c] {
			t.Errorf("idx_observations_key lacks %q", c)
		}
	}

	insert := func(vantage, endpoint, sni, p string) error {
		_, err := d.ExecContext(ctx,
			`INSERT INTO observations (category, site, host, route, source, vantage, endpoint, sni, path, observed_at)
			 VALUES ('caddy_gate', 'site-1', 'app.example', '/', 'internal', ?, ?, ?, ?, '2026-10-04T00:00:00Z')`,
			vantage, endpoint, sni, p)
		return err
	}
	variants := []struct{ vantage, endpoint, sni, path string }{
		{"internal", "10.0.0.1:443", "app.example", "/"},
		{"external", "10.0.0.1:443", "app.example", "/"},
		{"internal", "[2001:db8::1]:443", "app.example", "/"},
		{"internal", "10.0.0.1:443", "other.example", "/"},
		{"internal", "10.0.0.1:443", "app.example", "/health"},
	}
	for _, v := range variants {
		if err := insert(v.vantage, v.endpoint, v.sni, v.path); err != nil {
			t.Fatalf("insert %+v: %v", v, err)
		}
	}
	var rows int
	if err := d.QueryRowContext(ctx, `SELECT count(*) FROM observations`).Scan(&rows); err != nil {
		t.Fatalf("count observations: %v", err)
	}
	if rows != len(variants) {
		t.Fatalf("observations rows = %d, want %d distinct measurement dimensions", rows, len(variants))
	}
	// The exact same measurement key is the same observation: a duplicate must be rejected.
	if err := insert(variants[0].vantage, variants[0].endpoint, variants[0].sni, variants[0].path); err == nil {
		t.Error("exact duplicate observation key was accepted")
	}
	// success is a real boolean, not an arbitrary integer.
	if _, err := d.ExecContext(ctx,
		`INSERT INTO observations (category, success) VALUES ('tls', 2)`); err == nil {
		t.Error("success CHECK accepted 2")
	}
}

// Review fix (F4-006): every read attempt is recorded in k8s_snapshot_attempts, so the first failed
// read and the first read of a new profile version are representable, while k8s_snapshots keeps only
// successful snapshots and a failure can never read back as an empty current snapshot.
func TestF4Schema_SnapshotAttemptsAndProfileVersion(t *testing.T) {
	ctx := context.Background()
	path := testDBPath(t)
	d := openTestDB(t, path)
	if _, err := Migrate(ctx, d, path, realMigrations(t)); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	mustExec := func(q string, args ...any) {
		t.Helper()
		if _, err := d.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("exec %q: %v", q, err)
		}
	}
	// current is the documented reader rule: the latest snapshot of the exact (scope, profile_version).
	current := func(scope, version string) (payload string, err error) {
		err = d.QueryRowContext(ctx,
			`SELECT payload FROM k8s_snapshots WHERE scope = ? AND profile_version = ?
			 ORDER BY observed_at DESC, id DESC LIMIT 1`, scope, version).Scan(&payload)
		return payload, err
	}
	lastAttempt := func(scope, version string) (outcome, class string, snapshotID sql.NullInt64) {
		t.Helper()
		if err := d.QueryRowContext(ctx,
			`SELECT outcome, error_class, snapshot_id FROM k8s_snapshot_attempts
			 WHERE scope = ? AND profile_version = ? ORDER BY attempted_at DESC, id DESC LIMIT 1`,
			scope, version).Scan(&outcome, &class, &snapshotID); err != nil {
			t.Fatalf("last attempt %s/%s: %v", scope, version, err)
		}
		return outcome, class, snapshotID
	}

	// The very first read fails: recordable, and there is no (empty) current snapshot.
	mustExec(`INSERT INTO k8s_snapshot_attempts (scope, profile_version, attempted_at, outcome, error_class, error)
	          VALUES ('ns-a', 'traefik-v1', '2026-10-04T00:00:00Z', 'failed', 'credential_expired', 'HTTP 401')`)
	if _, err := current("ns-a", "traefik-v1"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("failed first read produced a current snapshot (err %v), want none", err)
	}
	if o, c, _ := lastAttempt("ns-a", "traefik-v1"); o != "failed" || c != "credential_expired" {
		t.Errorf("last attempt = %s/%s, want failed/credential_expired", o, c)
	}

	// A successful read: snapshot and ok attempt in one transaction.
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	res, err := tx.ExecContext(ctx,
		`INSERT INTO k8s_snapshots (scope, profile_version, observed_at, payload)
		 VALUES ('ns-a', 'traefik-v1', '2026-10-04T01:00:00Z', '{"p":"v1"}')`)
	if err != nil {
		t.Fatalf("insert snapshot: %v", err)
	}
	snapID, _ := res.LastInsertId()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO k8s_snapshot_attempts (scope, profile_version, attempted_at, outcome, snapshot_id)
		 VALUES ('ns-a', 'traefik-v1', '2026-10-04T01:00:00Z', 'ok', ?)`, snapID); err != nil {
		t.Fatalf("insert ok attempt: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if p, err := current("ns-a", "traefik-v1"); err != nil || p != `{"p":"v1"}` {
		t.Fatalf("current v1 = %q (err %v), want the v1 payload", p, err)
	}

	// A later failure: the good snapshot is untouched and the failure is the last attempt.
	mustExec(`INSERT INTO k8s_snapshot_attempts (scope, profile_version, attempted_at, outcome, error_class, error)
	          VALUES ('ns-a', 'traefik-v1', '2026-10-04T02:00:00Z', 'failed', 'timeout', 'page 2 timed out')`)
	if p, err := current("ns-a", "traefik-v1"); err != nil || p != `{"p":"v1"}` {
		t.Fatalf("current v1 after failure = %q (err %v), want the unchanged v1 payload", p, err)
	}
	if o, c, linked := lastAttempt("ns-a", "traefik-v1"); o != "failed" || c != "timeout" || linked.Valid {
		t.Errorf("last attempt = %s/%s linked=%v, want failed/timeout unlinked", o, c, linked)
	}

	// Old profile version: its snapshot is never served as the new version's snapshot. The v1 query
	// above is the positive control (it does return data); the v2 query must return nothing even
	// though a v1 snapshot of the same scope exists and a failed v2 attempt is recorded.
	mustExec(`INSERT INTO k8s_snapshot_attempts (scope, profile_version, attempted_at, outcome, error_class, error)
	          VALUES ('ns-a', 'traefik-v2', '2026-10-04T03:00:00Z', 'failed', 'forbidden', 'HTTP 403')`)
	if p, err := current("ns-a", "traefik-v2"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("old v1 snapshot served as current v2 snapshot: %q (err %v)", p, err)
	}
	if p, err := current("ns-a", "traefik-v1"); err != nil || p != `{"p":"v1"}` {
		t.Fatalf("positive control: current v1 = %q (err %v), want the v1 payload", p, err)
	}
	mustExec(`INSERT INTO k8s_snapshots (scope, profile_version, observed_at, payload)
	          VALUES ('ns-a', 'traefik-v2', '2026-10-04T04:00:00Z', '{"p":"v2"}')`)
	if p, err := current("ns-a", "traefik-v2"); err != nil || p != `{"p":"v2"}` {
		t.Fatalf("current v2 = %q (err %v), want the v2 payload", p, err)
	}
	if p, err := current("ns-a", "traefik-v1"); err != nil || p != `{"p":"v1"}` {
		t.Fatalf("old version info lost after the new version appeared: %q (err %v)", p, err)
	}

	// Invariants enforced by the schema: a failed attempt links no snapshot, a snapshot has a payload,
	// and the outcome is one of ok/failed.
	for name, q := range map[string]string{
		"failed attempt linking a snapshot": `INSERT INTO k8s_snapshot_attempts (scope, attempted_at, outcome, snapshot_id)
			VALUES ('ns-a', 't', 'failed', ` + strconv.FormatInt(snapID, 10) + `)`,
		"empty payload":   `INSERT INTO k8s_snapshots (scope, observed_at, payload) VALUES ('ns-a', 't', '')`,
		"unknown outcome": `INSERT INTO k8s_snapshot_attempts (scope, attempted_at, outcome) VALUES ('ns-a', 't', 'weird')`,
	} {
		if _, err := d.ExecContext(ctx, q); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}

	// Pruning an old snapshot (F4-042 retention) must not need a migration or break references.
	mustExec(`INSERT INTO k8s_drafts (cluster, host, snapshot_id, created_at, updated_at)
	          VALUES ('lab', 'app.example', ?, 't', 't')`, snapID)
	mustExec(`DELETE FROM k8s_snapshots WHERE id = ?`, snapID)
	var draftSnap sql.NullInt64
	if err := d.QueryRowContext(ctx, `SELECT snapshot_id FROM k8s_drafts WHERE host = 'app.example'`).Scan(&draftSnap); err != nil || draftSnap.Valid {
		t.Errorf("draft snapshot_id after prune = %v (err %v), want NULL", draftSnap, err)
	}
	if _, _, linked := lastAttempt("ns-a", "traefik-v1"); linked.Valid {
		t.Error("attempt still links a pruned snapshot")
	}
}

// Review fix (F4-006): an observation row carries outcome fields for every category plus separate
// last-good and last-attempt column groups. The documented UPSERT rule is exercised here so the
// F4-017 queries need no schema change: a failed attempt never overwrites the good group.
func TestF4Schema_ObservationOutcomeAndLastGoodRule(t *testing.T) {
	ctx := context.Background()
	path := testDBPath(t)
	d := openTestDB(t, path)
	if _, err := Migrate(ctx, d, path, realMigrations(t)); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	cols := tableColumns(t, d, "observations")
	for _, c := range []string{
		// route/backend binding and outcome of every category
		"backend", "http_status", "gate_class", "risk_finding", "risk_context", "unscanned_scope",
		// last good TLS leaf
		"tls_not_after", "tls_fingerprint",
		// last attempt
		"last_attempt_at", "success", "last_result", "last_http_status", "last_error",
		"last_tls_not_after", "last_tls_fingerprint", "last_tls_verify_error",
	} {
		if !cols[c] {
			t.Errorf("observations lacks %q", c)
		}
	}

	const key = `'tls', 'site-1', 'app.example', '', 'caddy', 'tagcess-host', '10.0.0.1:443', 'app.example', ''`
	// good: attempt that met the expectation writes both groups.
	good := func(at, notAfter, fp string) {
		t.Helper()
		if _, err := d.ExecContext(ctx,
			`INSERT INTO observations (category, site, host, route, source, vantage, endpoint, sni, path,
			    observed_at, tls_not_after, tls_fingerprint,
			    last_attempt_at, success, last_result, last_tls_not_after, last_tls_fingerprint, last_tls_verify_error)
			 VALUES (`+key+`, ?, ?, ?, ?, 1, 'ok', ?, ?, '')
			 ON CONFLICT (category, site, host, route, source, vantage, endpoint, sni, path) DO UPDATE SET
			    observed_at = excluded.observed_at, tls_not_after = excluded.tls_not_after,
			    tls_fingerprint = excluded.tls_fingerprint, last_attempt_at = excluded.last_attempt_at,
			    success = 1, last_result = 'ok', last_error = '', last_tls_not_after = excluded.last_tls_not_after,
			    last_tls_fingerprint = excluded.last_tls_fingerprint, last_tls_verify_error = ''`,
			at, notAfter, fp, at, notAfter, fp); err != nil {
			t.Fatalf("good upsert: %v", err)
		}
	}
	// failed: only the attempt group changes; diagnostic leaf data lands in last_tls_*.
	failed := func(at, result, errText, diagNotAfter, diagFP, verifyErr string) {
		t.Helper()
		if _, err := d.ExecContext(ctx,
			`INSERT INTO observations (category, site, host, route, source, vantage, endpoint, sni, path,
			    last_attempt_at, success, last_result, last_error, last_tls_not_after, last_tls_fingerprint, last_tls_verify_error)
			 VALUES (`+key+`, ?, 0, ?, ?, ?, ?, ?)
			 ON CONFLICT (category, site, host, route, source, vantage, endpoint, sni, path) DO UPDATE SET
			    last_attempt_at = excluded.last_attempt_at, success = 0, last_result = excluded.last_result,
			    last_error = excluded.last_error, last_tls_not_after = excluded.last_tls_not_after,
			    last_tls_fingerprint = excluded.last_tls_fingerprint, last_tls_verify_error = excluded.last_tls_verify_error`,
			at, result, errText, diagNotAfter, diagFP, verifyErr); err != nil {
			t.Fatalf("failed upsert: %v", err)
		}
	}
	type row struct {
		observedAt, notAfter, fp, attemptAt, result, lastNotAfter, verifyErr string
		success, count                                                       int
	}
	read := func() row {
		t.Helper()
		var r row
		if err := d.QueryRowContext(ctx,
			`SELECT observed_at, tls_not_after, tls_fingerprint, last_attempt_at, last_result, last_tls_not_after,
			        last_tls_verify_error, success, (SELECT count(*) FROM observations)
			 FROM observations`).Scan(&r.observedAt, &r.notAfter, &r.fp, &r.attemptAt, &r.result,
			&r.lastNotAfter, &r.verifyErr, &r.success, &r.count); err != nil {
			t.Fatalf("read observation: %v", err)
		}
		return r
	}

	// The first-ever attempt fails: representable, with no good observation yet.
	failed("2026-10-04T00:00:00Z", "timeout", "dial timeout", "", "", "")
	if r := read(); r.count != 1 || r.observedAt != "" || r.notAfter != "" || r.success != 0 || r.result != "timeout" {
		t.Fatalf("first failed attempt = %+v, want one row without good evidence", r)
	}

	good("2026-10-04T01:00:00Z", "2027-01-01T00:00:00Z", "fp-1")
	if r := read(); r.count != 1 || r.observedAt != "2026-10-04T01:00:00Z" || r.notAfter != "2027-01-01T00:00:00Z" || r.success != 1 {
		t.Fatalf("after good = %+v", r)
	}

	// Later failure keeps the good group; the attempt group shows the failure.
	failed("2026-10-04T02:00:00Z", "timeout", "dial timeout", "", "", "")
	r := read()
	if r.observedAt != "2026-10-04T01:00:00Z" || r.notAfter != "2027-01-01T00:00:00Z" || r.fp != "fp-1" {
		t.Errorf("failed attempt changed the last good group: %+v", r)
	}
	if r.attemptAt != "2026-10-04T02:00:00Z" || r.success != 0 || r.result != "timeout" {
		t.Errorf("failed attempt not recorded in the attempt group: %+v", r)
	}

	// An expired/unverifiable diagnostic leaf is an attempt fact: it never refreshes the verified
	// tls_not_after, but is readable for the immediate-critical alert.
	failed("2026-10-04T03:00:00Z", "tls_unverified", "", "2026-09-01T00:00:00Z", "fp-expired", "expired")
	r = read()
	if r.notAfter != "2027-01-01T00:00:00Z" || r.observedAt != "2026-10-04T01:00:00Z" {
		t.Errorf("diagnostic leaf refreshed the good group: %+v", r)
	}
	if r.lastNotAfter != "2026-09-01T00:00:00Z" || r.verifyErr != "expired" || r.result != "tls_unverified" {
		t.Errorf("diagnostic leaf not readable from the attempt group: %+v", r)
	}

	// A later good attempt clears the attempt-side diagnostics and refreshes both groups.
	good("2026-10-04T04:00:00Z", "2027-02-01T00:00:00Z", "fp-2")
	r = read()
	if r.observedAt != "2026-10-04T04:00:00Z" || r.notAfter != "2027-02-01T00:00:00Z" || r.verifyErr != "" || r.success != 1 {
		t.Errorf("good attempt after failures = %+v", r)
	}
}

// Review fix (F4-006): a draft is one row per (cluster, host) with its route provenance in a child
// table, so several Ingress routes of one host share one set of user choices (F4-009/F4-010 AC7), and
// the route-conflict review request is persisted on the draft.
func TestF4Schema_DraftHostKeyRouteProvenanceAndReview(t *testing.T) {
	ctx := context.Background()
	path := testDBPath(t)
	d := openTestDB(t, path)
	if _, err := Migrate(ctx, d, path, realMigrations(t)); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	mustExec := func(q string, args ...any) {
		t.Helper()
		if _, err := d.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("exec %q: %v", q, err)
		}
	}
	insertDraft := func(cluster, host string) error {
		_, err := d.ExecContext(ctx,
			`INSERT INTO k8s_drafts (cluster, host, created_at, updated_at) VALUES (?, ?, 't', 't')`, cluster, host)
		return err
	}
	if err := insertDraft("lab", "app.example"); err != nil {
		t.Fatalf("insert first draft: %v", err)
	}
	if err := insertDraft("lab", "app.example"); err == nil {
		t.Error("duplicate (cluster, host) draft was accepted")
	}
	if err := insertDraft("other", "app.example"); err != nil {
		t.Errorf("same host in another cluster rejected: %v", err)
	}
	if err := insertDraft("lab", ""); err == nil {
		t.Error("draft with an empty host was accepted")
	}

	var draftID int64
	if err := d.QueryRowContext(ctx, `SELECT id FROM k8s_drafts WHERE cluster = 'lab' AND host = 'app.example'`).Scan(&draftID); err != nil {
		t.Fatalf("read draft id: %v", err)
	}
	insertRoute := func(uid, p string) error {
		_, err := d.ExecContext(ctx,
			`INSERT INTO k8s_draft_routes (draft_id, namespace, ingress_name, ingress_uid, resource_version, path, path_type, backend_service, backend_port, class, observed_at)
			 VALUES (?, 'ns-a', 'ing', ?, '7', ?, 'Prefix', 'svc', '80', 'traefik', 't')`, draftID, uid, p)
		return err
	}
	for _, r := range []struct{ uid, path string }{{"uid-1", "/"}, {"uid-1", "/api"}, {"uid-2", "/"}} {
		if err := insertRoute(r.uid, r.path); err != nil {
			t.Fatalf("insert route %+v: %v", r, err)
		}
	}
	if err := insertRoute("uid-1", "/"); err == nil {
		t.Error("duplicate route provenance was accepted")
	}

	// The review request lives on the draft and carries reason, candidates and the default assessment.
	mustExec(`UPDATE k8s_drafts SET review_state = 'needed', review_reason = 'route_conflict',
	          review_candidates = '["svc-a:80","svc-b:80"]', review_default = 'unknown' WHERE id = ?`, draftID)
	var state, reason, cands, def string
	if err := d.QueryRowContext(ctx,
		`SELECT review_state, review_reason, review_candidates, review_default FROM k8s_drafts WHERE id = ?`, draftID).
		Scan(&state, &reason, &cands, &def); err != nil || state != "needed" || reason != "route_conflict" || def != "unknown" || cands == "[]" {
		t.Errorf("review = %q/%q/%q/%q (err %v)", state, reason, cands, def, err)
	}
	if _, err := d.ExecContext(ctx, `UPDATE k8s_drafts SET review_state = 'bogus' WHERE id = ?`, draftID); err == nil {
		t.Error("review_state CHECK accepted bogus")
	}

	// Deleting a draft removes its provenance and nothing else.
	mustExec(`DELETE FROM k8s_drafts WHERE id = ?`, draftID)
	var routes int
	if err := d.QueryRowContext(ctx, `SELECT count(*) FROM k8s_draft_routes`).Scan(&routes); err != nil || routes != 0 {
		t.Errorf("routes after draft delete = %d (err %v), want 0", routes, err)
	}
}

// Review fix (F4-006): F4-022's (kind, subject, source) lookup has a supporting index.
func TestF4Schema_AlertsSubjectSourceIndex(t *testing.T) {
	ctx := context.Background()
	path := testDBPath(t)
	d := openTestDB(t, path)
	if _, err := Migrate(ctx, d, path, realMigrations(t)); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	var n int
	if err := d.QueryRowContext(ctx,
		`SELECT count(*) FROM sqlite_master WHERE type = 'index' AND name = 'idx_alerts_kind_subject_source'`).Scan(&n); err != nil {
		t.Fatalf("sqlite_master index: %v", err)
	}
	if n != 1 {
		t.Fatal("idx_alerts_kind_subject_source missing")
	}
	key := map[string]bool{}
	for _, c := range indexInfo(t, d, "idx_alerts_kind_subject_source") {
		key[c] = true
	}
	for _, c := range []string{"kind", "subject", "source"} {
		if !key[c] {
			t.Errorf("idx_alerts_kind_subject_source lacks %q", c)
		}
	}
}
