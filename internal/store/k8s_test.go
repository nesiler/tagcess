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

// openK8sSnapshotStore opens a migrated store at path. The caller closes it; reopening the same
// path is how the tests model a process restart (AC1).
func openK8sSnapshotStore(t *testing.T, path string) *Store {
	t.Helper()
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open(%s): %v", path, err)
	}
	return s
}

// forbiddenSnapshotField returns "<field> (matches <fragment>)" for the first struct field whose name
// contains a forbidden fragment, or "" when every field is clean. It is the single scan used both for
// the real db types and for the positive control.
func forbiddenSnapshotField(typ reflect.Type, forbidden []string) string {
	for i := 0; i < typ.NumField(); i++ {
		name := strings.ToLower(typ.Field(i).Name)
		for _, f := range forbidden {
			if strings.Contains(name, f) {
				return typ.Field(i).Name + " (matches " + f + ")"
			}
		}
	}
	return ""
}

// AC1: a complete snapshot and its successful read attempt are written in one transaction and the
// same snapshot ID, scope and observed time come back after the database is reopened.
func TestK8sSnapshotStore_CompleteSnapshotRoundTrip(t *testing.T) {
	ctx := context.Background()
	path := testDBPath(t)

	const (
		scope    = "ns-a"
		version  = "traefik-v1"
		observed = "2026-10-04T01:00:00Z"
		payload  = `{"ingresses":[{"name":"app"}],"services":[]}`
	)

	s := openK8sSnapshotStore(t, path)
	tx, err := s.DB().BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	tq := s.Queries().WithTx(tx)
	snap, err := tq.InsertK8sSnapshot(ctx, db.InsertK8sSnapshotParams{
		Scope:          scope,
		ProfileVersion: version,
		ObservedAt:     observed,
		Payload:        payload,
	})
	if err != nil {
		t.Fatalf("InsertK8sSnapshot: %v", err)
	}
	if snap.ID == 0 || snap.Scope != scope || snap.ProfileVersion != version || snap.ObservedAt != observed || snap.Payload != payload {
		t.Fatalf("InsertK8sSnapshot returned %+v, want the stored read", snap)
	}
	attempt, err := tq.InsertK8sSnapshotAttempt(ctx, db.InsertK8sSnapshotAttemptParams{
		Scope:          scope,
		ProfileVersion: version,
		AttemptedAt:    observed,
		Outcome:        "ok",
		SnapshotID:     sql.NullInt64{Int64: snap.ID, Valid: true},
	})
	if err != nil {
		t.Fatalf("InsertK8sSnapshotAttempt(ok): %v", err)
	}
	if attempt.Outcome != "ok" || !attempt.SnapshotID.Valid || attempt.SnapshotID.Int64 != snap.ID {
		t.Fatalf("ok attempt = %+v, want outcome ok linked to snapshot %d", attempt, snap.ID)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Reopen the same database file: the transaction result must survive the restart.
	s2 := openK8sSnapshotStore(t, path)
	t.Cleanup(func() { _ = s2.Close() })

	got, err := s2.Queries().GetK8sSnapshot(ctx, snap.ID)
	if err != nil {
		t.Fatalf("GetK8sSnapshot(%d): %v", snap.ID, err)
	}
	if got.Scope != scope || got.ProfileVersion != version || got.ObservedAt != observed || got.Payload != payload {
		t.Errorf("reopened snapshot by id = %+v, want the complete read back", got)
	}
	current, err := s2.Queries().LatestK8sSnapshot(ctx, db.LatestK8sSnapshotParams{Scope: scope, ProfileVersion: version})
	if err != nil {
		t.Fatalf("LatestK8sSnapshot: %v", err)
	}
	if current.ID != snap.ID || current.ObservedAt != observed || current.Payload != payload {
		t.Errorf("reopened current snapshot = %+v, want snapshot %d", current, snap.ID)
	}
	last, err := s2.Queries().LatestK8sSnapshotAttempt(ctx, db.LatestK8sSnapshotAttemptParams{Scope: scope, ProfileVersion: version})
	if err != nil {
		t.Fatalf("LatestK8sSnapshotAttempt: %v", err)
	}
	if last.Outcome != "ok" || !last.SnapshotID.Valid || last.SnapshotID.Int64 != snap.ID {
		t.Errorf("reopened last attempt = %+v, want the successful linked attempt", last)
	}
}

// AC2: a failed read records only the attempt; the previous complete snapshot ID, payload and
// observed time stay untouched, and a rolled-back snapshot transaction leaves no new snapshot.
func TestK8sSnapshotStore_FailureKeepsLastGood(t *testing.T) {
	ctx := context.Background()
	path := testDBPath(t)
	s := openK8sSnapshotStore(t, path)
	t.Cleanup(func() { _ = s.Close() })
	q := s.Queries()

	const (
		scope    = "ns-a"
		version  = "traefik-v1"
		goodAt   = "2026-10-04T01:00:00Z"
		goodBody = `{"ingresses":[{"name":"app","rev":"7"}]}`
	)

	// Cold start (review fix): the very first read fails with NO prior snapshot. The failure is
	// recorded as an attempt, but the headline claim must still hold: it never reads back as an
	// empty/current snapshot (LatestK8sSnapshot stays sql.ErrNoRows) while the attempt reports failed.
	t.Run("cold_start_failure_leaves_no_snapshot", func(t *testing.T) {
		cs := openK8sSnapshotStore(t, testDBPath(t))
		t.Cleanup(func() { _ = cs.Close() })
		cq := cs.Queries()

		coldFailed, err := cq.InsertK8sSnapshotAttempt(ctx, db.InsertK8sSnapshotAttemptParams{
			Scope: scope, ProfileVersion: version, AttemptedAt: goodAt,
			Outcome: "failed", ErrorClass: "timeout", Error: "page 1 timed out",
		})
		if err != nil {
			t.Fatalf("InsertK8sSnapshotAttempt(cold failed): %v", err)
		}
		if coldFailed.Outcome != "failed" || coldFailed.SnapshotID.Valid {
			t.Fatalf("cold failed attempt = %+v, want unlinked failure", coldFailed)
		}
		if got, err := cq.LatestK8sSnapshot(ctx, db.LatestK8sSnapshotParams{Scope: scope, ProfileVersion: version}); !errors.Is(err, sql.ErrNoRows) {
			t.Errorf("cold-start failure read back as a current snapshot: %+v (err %v), want sql.ErrNoRows", got, err)
		}
		coldLast, err := cq.LatestK8sSnapshotAttempt(ctx, db.LatestK8sSnapshotAttemptParams{Scope: scope, ProfileVersion: version})
		if err != nil {
			t.Fatalf("cold LatestK8sSnapshotAttempt: %v", err)
		}
		if coldLast.Outcome != "failed" || coldLast.ErrorClass != "timeout" || coldLast.SnapshotID.Valid {
			t.Errorf("cold last attempt = %+v, want the recorded failure", coldLast)
		}
		// Positive control: once a complete snapshot + ok attempt exist, the same query returns the
		// row, so the ErrNoRows above is the missing snapshot, not a broken query.
		okSnap, err := cq.InsertK8sSnapshot(ctx, db.InsertK8sSnapshotParams{
			Scope: scope, ProfileVersion: version, ObservedAt: "2026-10-04T01:30:00Z", Payload: `{"ingresses":[]}`,
		})
		if err != nil {
			t.Fatalf("InsertK8sSnapshot(cold positive): %v", err)
		}
		if _, err := cq.InsertK8sSnapshotAttempt(ctx, db.InsertK8sSnapshotAttemptParams{
			Scope: scope, ProfileVersion: version, AttemptedAt: "2026-10-04T01:30:00Z", Outcome: "ok",
			SnapshotID: sql.NullInt64{Int64: okSnap.ID, Valid: true},
		}); err != nil {
			t.Fatalf("InsertK8sSnapshotAttempt(cold positive): %v", err)
		}
		if got, err := cq.LatestK8sSnapshot(ctx, db.LatestK8sSnapshotParams{Scope: scope, ProfileVersion: version}); err != nil || got.ID != okSnap.ID {
			t.Fatalf("positive control: current after ok snapshot = %+v (err %v), want snapshot %d", got, err, okSnap.ID)
		}
	})

	good, err := q.InsertK8sSnapshot(ctx, db.InsertK8sSnapshotParams{
		Scope: scope, ProfileVersion: version, ObservedAt: goodAt, Payload: goodBody,
	})
	if err != nil {
		t.Fatalf("InsertK8sSnapshot(good): %v", err)
	}
	if _, err := q.InsertK8sSnapshotAttempt(ctx, db.InsertK8sSnapshotAttemptParams{
		Scope: scope, ProfileVersion: version, AttemptedAt: goodAt, Outcome: "ok",
		SnapshotID: sql.NullInt64{Int64: good.ID, Valid: true},
	}); err != nil {
		t.Fatalf("InsertK8sSnapshotAttempt(ok): %v", err)
	}

	// The next read fails: only an attempt row is written and it links no snapshot.
	failed, err := q.InsertK8sSnapshotAttempt(ctx, db.InsertK8sSnapshotAttemptParams{
		Scope: scope, ProfileVersion: version, AttemptedAt: "2026-10-04T02:00:00Z",
		Outcome: "failed", ErrorClass: "timeout", Error: "page 2 timed out",
	})
	if err != nil {
		t.Fatalf("InsertK8sSnapshotAttempt(failed): %v", err)
	}
	if failed.Outcome != "failed" || failed.ErrorClass != "timeout" || failed.SnapshotID.Valid {
		t.Fatalf("failed attempt = %+v, want unlinked failure", failed)
	}

	current, err := q.LatestK8sSnapshot(ctx, db.LatestK8sSnapshotParams{Scope: scope, ProfileVersion: version})
	if err != nil {
		t.Fatalf("LatestK8sSnapshot after failure: %v", err)
	}
	if current.ID != good.ID || current.Payload != goodBody || current.ObservedAt != goodAt {
		t.Errorf("failure changed the last good snapshot: %+v, want snapshot %d", current, good.ID)
	}
	last, err := q.LatestK8sSnapshotAttempt(ctx, db.LatestK8sSnapshotAttemptParams{Scope: scope, ProfileVersion: version})
	if err != nil {
		t.Fatalf("LatestK8sSnapshotAttempt after failure: %v", err)
	}
	if last.Outcome != "failed" || last.ErrorClass != "timeout" || last.Error != "page 2 timed out" {
		t.Errorf("last attempt = %+v, want the recorded failure", last)
	}

	// Positive control (review fix): a COMMITTED newer snapshot of the same pair must become the
	// current one, proving the ORDER BY observed_at DESC, id DESC contract is actually applied.
	newer, err := q.InsertK8sSnapshot(ctx, db.InsertK8sSnapshotParams{
		Scope: scope, ProfileVersion: version, ObservedAt: "2026-10-04T02:30:00Z",
		Payload: `{"ingresses":[{"name":"app","rev":"8"}]}`,
	})
	if err != nil {
		t.Fatalf("InsertK8sSnapshot(newer): %v", err)
	}
	if _, err := q.InsertK8sSnapshotAttempt(ctx, db.InsertK8sSnapshotAttemptParams{
		Scope: scope, ProfileVersion: version, AttemptedAt: "2026-10-04T02:30:00Z", Outcome: "ok",
		SnapshotID: sql.NullInt64{Int64: newer.ID, Valid: true},
	}); err != nil {
		t.Fatalf("InsertK8sSnapshotAttempt(newer ok): %v", err)
	}
	current, err = q.LatestK8sSnapshot(ctx, db.LatestK8sSnapshotParams{Scope: scope, ProfileVersion: version})
	if err != nil {
		t.Fatalf("LatestK8sSnapshot after committed newer: %v", err)
	}
	if current.ID != newer.ID || current.Payload != newer.Payload {
		t.Fatalf("committed newer snapshot is not current: %+v, want snapshot %d", current, newer.ID)
	}

	// A new snapshot whose transaction rolls back must leave no partial snapshot behind: the
	// committed newer snapshot stays current.
	tx, err := s.DB().BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := s.Queries().WithTx(tx).InsertK8sSnapshot(ctx, db.InsertK8sSnapshotParams{
		Scope: scope, ProfileVersion: version, ObservedAt: "2026-10-04T03:00:00Z", Payload: `{"partial":true}`,
	}); err != nil {
		t.Fatalf("InsertK8sSnapshot(rolled back): %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	after, err := q.LatestK8sSnapshot(ctx, db.LatestK8sSnapshotParams{Scope: scope, ProfileVersion: version})
	if err != nil {
		t.Fatalf("LatestK8sSnapshot after rollback: %v", err)
	}
	if after.ID != newer.ID || after.Payload != newer.Payload {
		t.Errorf("rolled-back transaction changed the current snapshot: %+v, want snapshot %d", after, newer.ID)
	}
	var n int
	if err := s.DB().QueryRowContext(ctx, `SELECT count(*) FROM k8s_snapshots`).Scan(&n); err != nil {
		t.Fatalf("count snapshots: %v", err)
	}
	if n != 2 {
		t.Errorf("k8s_snapshots rows = %d, want the two committed snapshots", n)
	}
}

// AC3: an old profile/scope version is never served as the current snapshot of another version, and
// the snapshot/attempt read contract carries no credential field.
func TestK8sSnapshotStore_ScopeAndSecretSeparation(t *testing.T) {
	ctx := context.Background()
	path := testDBPath(t)
	s := openK8sSnapshotStore(t, path)
	t.Cleanup(func() { _ = s.Close() })
	q := s.Queries()

	current := func(scope, version string) (db.K8sSnapshot, error) {
		return q.LatestK8sSnapshot(ctx, db.LatestK8sSnapshotParams{Scope: scope, ProfileVersion: version})
	}
	insert := func(scope, version, at, payload string) {
		t.Helper()
		if _, err := q.InsertK8sSnapshot(ctx, db.InsertK8sSnapshotParams{
			Scope: scope, ProfileVersion: version, ObservedAt: at, Payload: payload,
		}); err != nil {
			t.Fatalf("InsertK8sSnapshot(%s/%s): %v", scope, version, err)
		}
	}

	insert("ns-a", "traefik-v1", "2026-10-04T01:00:00Z", `{"p":"a-v1"}`)

	// A newer profile version has no snapshot yet: the v1 data must not answer for it.
	if got, err := current("ns-a", "traefik-v2"); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("v1 snapshot served as current v2: %+v (err %v)", got, err)
	}
	// Another scope must not reuse this scope's snapshot either.
	if got, err := current("ns-b", "traefik-v1"); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("ns-a snapshot served as current ns-b: %+v (err %v)", got, err)
	}
	// Positive control: the exact pair still returns its own data.
	if got, err := current("ns-a", "traefik-v1"); err != nil || got.Payload != `{"p":"a-v1"}` {
		t.Fatalf("positive control: current ns-a/v1 = %+v (err %v)", got, err)
	}

	// Once the new version has its own read, it is current for itself while v1 stays old-scope data.
	insert("ns-a", "traefik-v2", "2026-10-04T04:00:00Z", `{"p":"a-v2"}`)
	if got, err := current("ns-a", "traefik-v2"); err != nil || got.Payload != `{"p":"a-v2"}` {
		t.Errorf("current v2 = %+v (err %v), want the v2 payload", got, err)
	}
	if got, err := current("ns-a", "traefik-v1"); err != nil || got.Payload != `{"p":"a-v1"}` {
		t.Errorf("old v1 data lost after v2 arrived: %+v (err %v)", got, err)
	}

	// The query contract exposes no credential/secret/raw-request field; only sanitized metadata.
	forbidden := []string{"token", "credential", "password", "secret", "private", "kubeconfig",
		"cookie", "authorization", "body", "header"}
	for _, typ := range []reflect.Type{reflect.TypeOf(db.K8sSnapshot{}), reflect.TypeOf(db.K8sSnapshotAttempt{})} {
		if f := forbiddenSnapshotField(typ, forbidden); f != "" {
			t.Errorf("%s carries a forbidden field %s", typ.Name(), f)
		}
	}
	// Positive control (review fix): the scan must be able to fail. A planted struct with a Token
	// field must be flagged, so the clean result above cannot come from scanning nothing.
	type plantedSnapshot struct {
		ID    int64
		Token string
	}
	if f := forbiddenSnapshotField(reflect.TypeOf(plantedSnapshot{}), forbidden); f == "" {
		t.Error("forbidden-field scan did not detect a planted Token field")
	}
}

// Review fix (MEDIUM): same-pair ordering is part of the contract. The latest row of the exact
// (scope, profile_version) is chosen by observed_at DESC then id DESC, so dropping the ORDER BY is
// caught. Timestamps use the repo's canonical fixed-format UTC ("2006-01-02T15:04:05.000Z").
func TestK8sSnapshotStore_SamePairOrdering(t *testing.T) {
	ctx := context.Background()
	s := openK8sSnapshotStore(t, testDBPath(t))
	t.Cleanup(func() { _ = s.Close() })
	q := s.Queries()

	const scope, version = "ns-a", "traefik-v1"
	insert := func(at, payload string) db.K8sSnapshot {
		t.Helper()
		snap, err := q.InsertK8sSnapshot(ctx, db.InsertK8sSnapshotParams{
			Scope: scope, ProfileVersion: version, ObservedAt: at, Payload: payload,
		})
		if err != nil {
			t.Fatalf("InsertK8sSnapshot(%s): %v", at, err)
		}
		return snap
	}
	current := func() db.K8sSnapshot {
		t.Helper()
		got, err := q.LatestK8sSnapshot(ctx, db.LatestK8sSnapshotParams{Scope: scope, ProfileVersion: version})
		if err != nil {
			t.Fatalf("LatestK8sSnapshot: %v", err)
		}
		return got
	}

	first := insert("2026-10-04T01:00:00.000Z", `{"p":"1"}`)
	if got := current(); got.ID != first.ID {
		t.Fatalf("current = %d, want the first snapshot %d", got.ID, first.ID)
	}
	// A later observed_at wins; the canonical fixed-width format keeps text order chronological.
	second := insert("2026-10-04T01:00:00.500Z", `{"p":"2"}`)
	if got := current(); got.ID != second.ID || got.Payload != `{"p":"2"}` {
		t.Fatalf("current = %+v, want the later observed_at snapshot %d", got, second.ID)
	}
	// Equal observed_at: the higher id wins (id DESC tie-break).
	tie := insert("2026-10-04T01:00:00.500Z", `{"p":"tie"}`)
	if got := current(); got.ID != tie.ID || got.Payload != `{"p":"tie"}` {
		t.Fatalf("current = %+v, want the highest-id snapshot at the same observed_at %d", got, tie.ID)
	}
	// An older observed_at must never win even though its id is higher.
	older := insert("2026-10-04T00:59:59.000Z", `{"p":"old"}`)
	if older.ID <= tie.ID {
		t.Fatalf("test setup: older snapshot id %d should be higher than %d", older.ID, tie.ID)
	}
	if got := current(); got.ID != tie.ID {
		t.Fatalf("current = %+v, want observed_at to outrank the higher id %d", got, tie.ID)
	}
}

// Review fix (MEDIUM, F4-007 AC4): when a scope/profile change leaves the new pair without any
// snapshot, the reader can still surface the previous scope's data as explicit OLD data via
// LatestK8sSnapshotOtherPair, without it ever answering the current-pair query.
func TestK8sSnapshotStore_OtherPairShowsOldScope(t *testing.T) {
	ctx := context.Background()
	s := openK8sSnapshotStore(t, testDBPath(t))
	t.Cleanup(func() { _ = s.Close() })
	q := s.Queries()

	insert := func(scope, version, at, payload string) {
		t.Helper()
		if _, err := q.InsertK8sSnapshot(ctx, db.InsertK8sSnapshotParams{
			Scope: scope, ProfileVersion: version, ObservedAt: at, Payload: payload,
		}); err != nil {
			t.Fatalf("InsertK8sSnapshot(%s/%s): %v", scope, version, err)
		}
	}
	other := func(scope, version string) (db.K8sSnapshot, error) {
		return q.LatestK8sSnapshotOtherPair(ctx, db.LatestK8sSnapshotOtherPairParams{Scope: scope, ProfileVersion: version})
	}

	insert("ns-a", "traefik-v1", "2026-10-04T01:00:00Z", `{"p":"a-v1"}`)
	// The new pair has no current snapshot ...
	if got, err := q.LatestK8sSnapshot(ctx, db.LatestK8sSnapshotParams{Scope: "ns-a", ProfileVersion: "traefik-v2"}); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("new pair unexpectedly has a snapshot: %+v (err %v)", got, err)
	}
	// ... but the previous scope is readable as OLD data, not as the new pair's current snapshot.
	old, err := other("ns-a", "traefik-v2")
	if err != nil {
		t.Fatalf("LatestK8sSnapshotOtherPair(ns-a/v2): %v", err)
	}
	if old.Scope != "ns-a" || old.ProfileVersion != "traefik-v1" || old.Payload != `{"p":"a-v1"}` {
		t.Errorf("old-scope snapshot = %+v, want ns-a/traefik-v1", old)
	}
	// Negative control: when the queried pair is the only pair there is no other data.
	if got, err := other("ns-a", "traefik-v1"); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("other-pair query for the only pair = %+v (err %v), want sql.ErrNoRows", got, err)
	}
	// Across several pairs the latest observed_at/id wins.
	insert("ns-a", "traefik-v2", "2026-10-04T04:00:00.000Z", `{"p":"a-v2"}`)
	insert("ns-b", "traefik-v1", "2026-10-04T05:00:00.000Z", `{"p":"b-v1"}`)
	old, err = other("ns-a", "traefik-v2")
	if err != nil {
		t.Fatalf("LatestK8sSnapshotOtherPair(ns-a/v2) after ns-b: %v", err)
	}
	if old.Scope != "ns-b" || old.ProfileVersion != "traefik-v1" || old.Payload != `{"p":"b-v1"}` {
		t.Errorf("latest other pair = %+v, want ns-b/traefik-v1", old)
	}
}
