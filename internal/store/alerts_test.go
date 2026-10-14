package store

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/internal/store/db"
)

// alertTestDB migrates a fresh real SQLite database to the current schema and returns it with the
// generated query interface. These tests exercise the sqlc query contract directly; the F4 schema
// itself is proven by f4_schema_test.go (F4-006).
func alertTestDB(t *testing.T) (*sql.DB, *db.Queries) {
	t.Helper()
	path := testDBPath(t)
	d := openTestDB(t, path)
	if _, err := Migrate(context.Background(), d, path, realMigrations(t)); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return d, db.New(d)
}

// AC1: the existing F1/F3 alert queries keep their signatures and dedupe/resolve semantics. New
// monitor queries must not change them.
func TestAlertsLifecycleLegacyQueriesRemainCompatible(t *testing.T) {
	ctx := context.Background()
	d, q := alertTestDB(t)

	const kind, source = "reconcile_read_failed", "zitadel"

	// InsertAlert keeps its RETURNING db.Alert contract (the compiler is the signature check).
	var inserted db.Alert
	inserted, err := q.InsertAlert(ctx, db.InsertAlertParams{
		Kind: kind, Source: source, FirstSeenAt: "2026-10-04T00:00:00Z", LastSeenAt: "2026-10-04T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("InsertAlert: %v", err)
	}
	if inserted.ID == 0 || inserted.Kind != kind || inserted.Source != source || inserted.Subject != "" {
		t.Fatalf("InsertAlert returned %+v", inserted)
	}

	// A repeated failure touches the open (kind, source) row instead of piling up duplicates.
	for i := 0; i < 2; i++ {
		touched, err := q.TouchAlert(ctx, db.TouchAlertParams{
			LastSeenAt: "2026-10-04T00:00:01Z", Kind: kind, Source: source,
		})
		if err != nil {
			t.Fatalf("TouchAlert #%d: %v", i, err)
		}
		if touched != 1 {
			t.Fatalf("TouchAlert #%d touched %d rows, want 1", i, touched)
		}
	}
	if n := countAlerts(t, d, `kind = ? AND source = ?`, kind, source); n != 1 {
		t.Fatalf("%s/%s rows = %d, want 1 deduped", kind, source, n)
	}

	var open []db.Alert
	open, err = q.ListOpenAlerts(ctx)
	if err != nil {
		t.Fatalf("ListOpenAlerts: %v", err)
	}
	if len(open) != 1 || open[0].Kind != kind || open[0].Source != source {
		t.Fatalf("ListOpenAlerts = %+v, want the open %s/%s row", open, kind, source)
	}

	// ResolveAlerts resolves the open (kind, source) once; the row disappears from the open list.
	rows, err := q.ResolveAlerts(ctx, db.ResolveAlertsParams{
		ResolvedAt: sql.NullString{String: "2026-10-04T00:00:02Z", Valid: true}, Kind: kind, Source: source,
	})
	if err != nil || rows != 1 {
		t.Fatalf("ResolveAlerts rows = %d err = %v, want 1", rows, err)
	}
	if open, err = q.ListOpenAlerts(ctx); err != nil || len(open) != 0 {
		t.Fatalf("ListOpenAlerts after resolve = %+v err = %v, want empty", open, err)
	}

	// A later failure raises a fresh row: dedupe only folds repeats into the still-open one.
	if _, err := q.InsertAlert(ctx, db.InsertAlertParams{
		Kind: kind, Source: source, FirstSeenAt: "2026-10-04T00:00:03Z", LastSeenAt: "2026-10-04T00:00:03Z",
	}); err != nil {
		t.Fatalf("re-raise InsertAlert: %v", err)
	}
	// ResolveAlertKind is the pipeline's broad kind resolve (F1-011); it stays available and resolves
	// every open alert of the kind.
	rows, err = q.ResolveAlertKind(ctx, db.ResolveAlertKindParams{
		ResolvedAt: sql.NullString{String: "2026-10-04T00:00:04Z", Valid: true}, Kind: kind,
	})
	if err != nil || rows != 1 {
		t.Fatalf("ResolveAlertKind rows = %d err = %v, want 1", rows, err)
	}
	if open, err = q.ListOpenAlerts(ctx); err != nil || len(open) != 0 {
		t.Fatalf("ListOpenAlerts after kind resolve = %+v err = %v, want empty", open, err)
	}
}

// AC2: the monitor key is (kind, subject, source). Different subjects, sources and kinds stay
// independent and a repeated open key folds into one row instead of duplicating it. Legacy rows
// (subject ”) keep their own (kind, source) key and are neither touched nor shadowed by a monitor key.
func TestAlertsLifecycleSubjectSourceDedup(t *testing.T) {
	ctx := context.Background()
	d, q := alertTestDB(t)

	const kind = "target_down"
	raise := func(kind, subject, source, severity string) db.Alert {
		t.Helper()
		a, err := q.InsertMonitorAlert(ctx, db.InsertMonitorAlertParams{
			Kind: kind, Subject: subject, Source: source, Severity: severity,
			Freshness: "fresh", EvidenceSummary: "HTTP 503",
			FirstSeenAt: "2026-10-04T00:00:00Z", LastSeenAt: "2026-10-04T00:00:00Z",
		})
		if err != nil {
			t.Fatalf("InsertMonitorAlert(%s/%s/%s): %v", kind, subject, source, err)
		}
		return a
	}
	app := raise(kind, "app.example", "target", "critical")
	// Different subject, same source: independent alert.
	raise(kind, "api.example", "target", "critical")
	// Same subject, different source: independent alert.
	raise(kind, "app.example", "tls", "warning")
	// Same subject and source, different kind: a distinct key the touch below must not fold in.
	other := raise("tls_expiry", "app.example", "target", "warning")
	// A legacy pipeline alert of the same kind and source (subject '') is independent too.
	legacy, err := q.InsertAlert(ctx, db.InsertAlertParams{
		Kind: kind, Source: "target", FirstSeenAt: "2026-10-04T00:00:00Z", LastSeenAt: "2026-10-04T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("legacy InsertAlert: %v", err)
	}
	if legacy.Subject != "" {
		t.Fatalf("legacy insert got subject %q, want empty", legacy.Subject)
	}

	// The same open monitor key is touched, not duplicated; the legacy row and the other kind keep
	// their own stamps.
	touched, err := q.TouchMonitorAlert(ctx, db.TouchMonitorAlertParams{
		LastSeenAt: "2026-10-04T00:05:00Z", Kind: kind, Subject: "app.example", Source: "target",
	})
	if err != nil || touched != 1 {
		t.Fatalf("TouchMonitorAlert rows = %d err = %v, want 1", touched, err)
	}
	if n := countAlerts(t, d, `kind = ?`, kind); n != 4 {
		t.Fatalf("%s rows = %d, want 4 independent alerts", kind, n)
	}
	if n := countAlerts(t, d, `id = ? AND last_seen_at = ?`, other.ID, "2026-10-04T00:00:00Z"); n != 1 {
		t.Fatalf("touch crossed kinds: tls_expiry row changed (rows=%d, want 1 unchanged)", n)
	}

	var legacySeen string
	if err := d.QueryRowContext(ctx,
		`SELECT last_seen_at FROM alerts WHERE id = ?`, legacy.ID).Scan(&legacySeen); err != nil {
		t.Fatalf("read legacy: %v", err)
	}
	if legacySeen != "2026-10-04T00:00:00Z" {
		t.Fatalf("monitor touch changed the legacy row: last_seen_at = %q", legacySeen)
	}

	open, err := q.ListOpenAlerts(ctx)
	if err != nil {
		t.Fatalf("ListOpenAlerts: %v", err)
	}
	if len(open) != 5 {
		t.Fatalf("open alerts = %d, want 5 independent rows", len(open))
	}
	// The touched monitor row is found by its exact open key, and its identity is intact.
	got, err := q.GetOpenMonitorAlert(ctx, db.GetOpenMonitorAlertParams{
		Kind: kind, Subject: "app.example", Source: "target",
	})
	if err != nil {
		t.Fatalf("GetOpenMonitorAlert: %v", err)
	}
	if got.ID != app.ID || got.LastSeenAt != "2026-10-04T00:05:00Z" || got.Severity != "critical" || got.Freshness != "fresh" {
		t.Fatalf("GetOpenMonitorAlert = %+v, want the touched %+v", got, app)
	}
}

// AC3: ack, mute, counters, last consumed sample and freshness are independent monitor state: they
// change without resolving the alert, never bleed into another open alert, refuse to touch a resolved
// alert, and every value survives closing and reopening the database.
func TestAlertsLifecyclePersistsIndependentStates(t *testing.T) {
	ctx := context.Background()
	path := testDBPath(t)
	d := openTestDB(t, path)
	if _, err := Migrate(ctx, d, path, realMigrations(t)); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	q := db.New(d)

	raised, err := q.InsertMonitorAlert(ctx, db.InsertMonitorAlertParams{
		Kind: "target_down", Subject: "app.example", Source: "target", Severity: "critical",
		Freshness: "fresh", EvidenceSummary: "HTTP 503",
		FirstSeenAt: "2026-10-04T00:00:00Z", LastSeenAt: "2026-10-04T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("InsertMonitorAlert: %v", err)
	}
	// A second open alert proves the id-scoped mutations touch only their own row.
	secondKey := db.GetOpenMonitorAlertParams{Kind: "target_down", Subject: "api.example", Source: "target"}
	if _, err := q.InsertMonitorAlert(ctx, db.InsertMonitorAlertParams{
		Kind: secondKey.Kind, Subject: secondKey.Subject, Source: secondKey.Source, Severity: "critical",
		Freshness: "fresh", EvidenceSummary: "HTTP 503",
		FirstSeenAt: "2026-10-04T00:00:00Z", LastSeenAt: "2026-10-04T00:00:00Z",
	}); err != nil {
		t.Fatalf("InsertMonitorAlert(second): %v", err)
	}
	secondBefore, err := q.GetOpenMonitorAlert(ctx, secondKey)
	if err != nil {
		t.Fatalf("GetOpenMonitorAlert(second): %v", err)
	}

	// Monitor state update: severity/freshness/evidence, last success, consumed sample and counters.
	rows, err := q.UpdateMonitorAlert(ctx, db.UpdateMonitorAlertParams{
		Severity: "warning", Freshness: "stale", EvidenceSummary: "3 consecutive failures",
		LastSuccess:         sql.NullString{String: "2026-10-03T23:00:00Z", Valid: true},
		LastConsumedSample:  "42@2026-10-04T01:00:00Z",
		ConsecutiveFailures: 3, ConsecutiveSuccesses: 0,
		LastSeenAt: "2026-10-04T01:00:00Z", ID: raised.ID,
	})
	if err != nil || rows != 1 {
		t.Fatalf("UpdateMonitorAlert rows = %d err = %v, want 1", rows, err)
	}
	// Acknowledge and mute are separate states and never resolve.
	if rows, err = q.SetAlertAcknowledged(ctx, db.SetAlertAcknowledgedParams{
		AcknowledgedAt: sql.NullString{String: "2026-10-04T02:00:00Z", Valid: true}, ID: raised.ID,
	}); err != nil || rows != 1 {
		t.Fatalf("SetAlertAcknowledged rows = %d err = %v, want 1", rows, err)
	}
	if rows, err = q.SetAlertMuted(ctx, db.SetAlertMutedParams{Muted: 1, ID: raised.ID}); err != nil || rows != 1 {
		t.Fatalf("SetAlertMuted rows = %d err = %v, want 1", rows, err)
	}

	// None of the three id-scoped mutations leaked into the other open alert.
	secondAfter, err := q.GetOpenMonitorAlert(ctx, secondKey)
	if err != nil {
		t.Fatalf("GetOpenMonitorAlert(second) after mutations: %v", err)
	}
	if secondAfter.Severity != secondBefore.Severity || secondAfter.Freshness != secondBefore.Freshness ||
		secondAfter.EvidenceSummary != secondBefore.EvidenceSummary || secondAfter.AcknowledgedAt.Valid ||
		secondAfter.Muted != secondBefore.Muted || secondAfter.LastSeenAt != secondBefore.LastSeenAt ||
		secondAfter.ConsecutiveFailures != secondBefore.ConsecutiveFailures {
		t.Errorf("another open alert changed: %+v -> %+v", secondBefore, secondAfter)
	}

	check := func(t *testing.T, got db.Alert) {
		t.Helper()
		if got.ResolvedAt.Valid {
			t.Errorf("resolved_at = %v, want NULL (ack/mute/update must not resolve)", got.ResolvedAt)
		}
		if got.Severity != "warning" || got.Freshness != "stale" || got.EvidenceSummary != "3 consecutive failures" {
			t.Errorf("state = %q/%q/%q", got.Severity, got.Freshness, got.EvidenceSummary)
		}
		if !got.AcknowledgedAt.Valid || got.AcknowledgedAt.String != "2026-10-04T02:00:00Z" {
			t.Errorf("acknowledged_at = %v", got.AcknowledgedAt)
		}
		if !got.LastSuccess.Valid || got.LastSuccess.String != "2026-10-03T23:00:00Z" {
			t.Errorf("last_success = %v", got.LastSuccess)
		}
		if got.LastConsumedSample != "42@2026-10-04T01:00:00Z" {
			t.Errorf("last_consumed_sample = %q", got.LastConsumedSample)
		}
		if got.Muted != 1 || got.ConsecutiveFailures != 3 || got.ConsecutiveSuccesses != 0 {
			t.Errorf("muted/failures/successes = %d/%d/%d", got.Muted, got.ConsecutiveFailures, got.ConsecutiveSuccesses)
		}
		if got.LastSeenAt != "2026-10-04T01:00:00Z" {
			t.Errorf("last_seen_at = %q", got.LastSeenAt)
		}
	}
	key := db.GetOpenMonitorAlertParams{Kind: "target_down", Subject: "app.example", Source: "target"}
	inMemory, err := q.GetOpenMonitorAlert(ctx, key)
	if err != nil {
		t.Fatalf("GetOpenMonitorAlert: %v", err)
	}
	check(t, inMemory)

	// Reopen the same database: the lifecycle state is durable and the alert is still open.
	if err := d.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	d2 := openTestDB(t, path)
	q2 := db.New(d2)
	reopened, err := q2.GetOpenMonitorAlert(ctx, key)
	if err != nil {
		t.Fatalf("GetOpenMonitorAlert after reopen: %v", err)
	}
	if reopened.ID != raised.ID {
		t.Fatalf("reopened alert id = %d, want %d", reopened.ID, raised.ID)
	}
	check(t, reopened)

	// Resolved rows are terminal for the lifecycle mutations: once the first alert is resolved,
	// update/ack/mute must refuse it (0 rows) and leave its stored state alone.
	if rows, err := q2.ResolveMonitorAlert(ctx, db.ResolveMonitorAlertParams{
		ResolvedAt: sql.NullString{String: "2026-10-04T04:00:00Z", Valid: true},
		Kind:       key.Kind, Subject: key.Subject, Source: key.Source,
	}); err != nil || rows != 1 {
		t.Fatalf("ResolveMonitorAlert rows = %d err = %v, want 1", rows, err)
	}
	if _, err := q2.GetOpenMonitorAlert(ctx, key); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("resolved alert still open: err = %v, want sql.ErrNoRows", err)
	}
	if rows, err := q2.UpdateMonitorAlert(ctx, db.UpdateMonitorAlertParams{
		Severity: "critical", Freshness: "fresh", EvidenceSummary: "should not apply",
		LastConsumedSample: "99", ConsecutiveFailures: 9, ConsecutiveSuccesses: 9,
		LastSeenAt: "2026-10-04T05:00:00Z", ID: raised.ID,
	}); err != nil || rows != 0 {
		t.Fatalf("UpdateMonitorAlert on resolved rows = %d err = %v, want 0", rows, err)
	}
	if rows, err := q2.SetAlertAcknowledged(ctx, db.SetAlertAcknowledgedParams{
		AcknowledgedAt: sql.NullString{String: "2026-10-04T05:00:00Z", Valid: true}, ID: raised.ID,
	}); err != nil || rows != 0 {
		t.Fatalf("SetAlertAcknowledged on resolved rows = %d err = %v, want 0", rows, err)
	}
	if rows, err := q2.SetAlertMuted(ctx, db.SetAlertMutedParams{Muted: 0, ID: raised.ID}); err != nil || rows != 0 {
		t.Fatalf("SetAlertMuted on resolved rows = %d err = %v, want 0", rows, err)
	}
	var severity, freshness, sample, seen string
	var ack, resolved sql.NullString
	var muted, failures, successes int64
	if err := d2.QueryRowContext(ctx,
		`SELECT severity, freshness, last_consumed_sample, last_seen_at, acknowledged_at, muted,
		        consecutive_failures, consecutive_successes, resolved_at
		 FROM alerts WHERE id = ?`, raised.ID).Scan(
		&severity, &freshness, &sample, &seen, &ack, &muted, &failures, &successes, &resolved); err != nil {
		t.Fatalf("read resolved row: %v", err)
	}
	if severity != "warning" || freshness != "stale" || sample != "42@2026-10-04T01:00:00Z" ||
		seen != "2026-10-04T01:00:00Z" || !ack.Valid || ack.String != "2026-10-04T02:00:00Z" ||
		muted != 1 || failures != 3 || !resolved.Valid || resolved.String != "2026-10-04T04:00:00Z" {
		t.Errorf("refused mutations changed the resolved row: %q/%q/%q/%q ack=%v muted=%d failures=%d resolved=%v",
			severity, freshness, sample, seen, ack, muted, failures, resolved)
	}
}

// AC4: a subject-specific recovery resolves only its own (kind, subject, source) alert. Unrelated
// monitor keys and the legacy F1/F3 pipeline critical stay open, and no query exposes a
// token/header/body or raw-response storage API.
func TestAlertsLifecycleScopedUpdatesKeepLegacyCriticals(t *testing.T) {
	ctx := context.Background()
	d, q := alertTestDB(t)

	// The F1 pipeline critical owns broad resolve semantics; the monitor lifecycle must not touch it.
	legacy, err := q.InsertAlert(ctx, db.InsertAlertParams{
		Kind: "policy_mismatch", Source: "site-1", FirstSeenAt: "2026-10-04T00:00:00Z", LastSeenAt: "2026-10-04T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("InsertAlert: %v", err)
	}
	raise := func(kind, subject, source string) db.Alert {
		t.Helper()
		a, err := q.InsertMonitorAlert(ctx, db.InsertMonitorAlertParams{
			Kind: kind, Subject: subject, Source: source, Severity: "critical",
			Freshness: "fresh", EvidenceSummary: "HTTP 503",
			FirstSeenAt: "2026-10-04T00:00:00Z", LastSeenAt: "2026-10-04T00:00:00Z",
		})
		if err != nil {
			t.Fatalf("InsertMonitorAlert(%s/%s/%s): %v", kind, subject, source, err)
		}
		return a
	}
	app := raise("target_down", "app.example", "target")
	// Same kind and subject, different source; and same subject and source, different kind. Both are
	// unrelated keys that the exact resolve below must leave open.
	sameKindOtherSource := raise("target_down", "app.example", "tls")
	otherKind := raise("tls_expiry", "app.example", "target")

	// app.example recovers: only its exact open key is resolved.
	rows, err := q.ResolveMonitorAlert(ctx, db.ResolveMonitorAlertParams{
		ResolvedAt: sql.NullString{String: "2026-10-04T03:00:00Z", Valid: true},
		Kind:       "target_down", Subject: "app.example", Source: "target",
	})
	if err != nil || rows != 1 {
		t.Fatalf("ResolveMonitorAlert rows = %d err = %v, want 1", rows, err)
	}
	if _, err := q.GetOpenMonitorAlert(ctx, db.GetOpenMonitorAlertParams{
		Kind: "target_down", Subject: "app.example", Source: "target",
	}); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("recovered subject still open: err = %v, want sql.ErrNoRows", err)
	}
	// The two unrelated keys are addressed directly and must still return the untouched rows.
	for _, tc := range []struct {
		key db.GetOpenMonitorAlertParams
		id  int64
	}{
		{db.GetOpenMonitorAlertParams{Kind: "target_down", Subject: "app.example", Source: "tls"}, sameKindOtherSource.ID},
		{db.GetOpenMonitorAlertParams{Kind: "tls_expiry", Subject: "app.example", Source: "target"}, otherKind.ID},
	} {
		got, err := q.GetOpenMonitorAlert(ctx, tc.key)
		if err != nil {
			t.Fatalf("unrelated key %+v was resolved: %v", tc.key, err)
		}
		if got.ID != tc.id || got.ID == app.ID {
			t.Fatalf("unrelated key %+v = %+v, want the untouched row %d", tc.key, got, tc.id)
		}
	}

	// The legacy pipeline critical and both unrelated monitor keys remain open.
	var openLegacy, openSameKind, openOtherKind bool
	open, err := q.ListOpenAlerts(ctx)
	if err != nil {
		t.Fatalf("ListOpenAlerts: %v", err)
	}
	for _, a := range open {
		switch {
		case a.ID == legacy.ID && a.Kind == "policy_mismatch" && !a.ResolvedAt.Valid:
			openLegacy = true
		case a.ID == sameKindOtherSource.ID && !a.ResolvedAt.Valid:
			openSameKind = true
		case a.ID == otherKind.ID && !a.ResolvedAt.Valid:
			openOtherKind = true
		}
	}
	if !openLegacy || !openSameKind || !openOtherKind {
		t.Fatalf("open legacy=%v same-kind=%v other-kind=%v, want all open after scoped resolve",
			openLegacy, openSameKind, openOtherKind)
	}

	// No lifecycle query exposes a secret/raw-response field: params, results and the table columns
	// are all free of forbidden fragments (mirrors the F4-006 AC3 scan at the query API layer).
	forbidden := []string{"token", "credential", "password", "secret", "private", "kubeconfig",
		"cookie", "authorization", "body", "header"}
	structs := []any{
		db.Alert{},
		db.GetOpenMonitorAlertParams{}, db.InsertMonitorAlertParams{}, db.TouchMonitorAlertParams{},
		db.UpdateMonitorAlertParams{}, db.SetAlertAcknowledgedParams{}, db.SetAlertMutedParams{},
		db.ResolveMonitorAlertParams{},
	}
	for _, s := range structs {
		typ := reflect.TypeOf(s)
		if f := findForbiddenField(typ, forbidden); f != "" {
			t.Errorf("%s exposes forbidden field %s", typ.Name(), f)
		}
	}
	// Positive control: the scan must be able to fail. A planted forbidden field is detected and a
	// clean one passes, so the loop above cannot pass vacuously.
	if f := findForbiddenField(reflect.TypeOf(struct{ SessionToken string }{}), forbidden); f == "" {
		t.Error("forbidden-field scan did not detect a planted SessionToken field")
	}
	if f := findForbiddenField(reflect.TypeOf(struct {
		Kind    string
		Subject string
	}{}), forbidden); f != "" {
		t.Errorf("forbidden-field scan flagged a clean field: %s", f)
	}
	if f := findForbiddenColumn(tableColumns(t, d, "alerts"), forbidden); f != "" {
		t.Errorf("alerts table has forbidden column %s", f)
	}
}

// countAlerts returns the number of alert rows matching a WHERE clause and args.
func countAlerts(t *testing.T, d *sql.DB, where string, args ...any) int {
	t.Helper()
	var n int
	q := `SELECT count(*) FROM alerts WHERE ` + where
	if err := d.QueryRowContext(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatalf("count alerts (%s): %v", where, err)
	}
	return n
}

// findForbiddenField reports the first struct field name matching a forbidden fragment, or "" if the
// struct is clean. It is the single scan used both for the query structs and the positive control.
func findForbiddenField(t reflect.Type, forbidden []string) string {
	for i := 0; i < t.NumField(); i++ {
		name := t.Field(i).Name
		for _, f := range forbidden {
			if strings.Contains(strings.ToLower(name), f) {
				return name + " (matches " + f + ")"
			}
		}
	}
	return ""
}
