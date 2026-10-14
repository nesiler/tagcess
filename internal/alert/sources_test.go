package alert

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/store/db"
)

// F4-025 tests: the stored observation/sync/pending-change results are bridged to the monitor
// alerts. The observation/sync/pending readers are fakes (store-only by construction), so the
// tests prove the bridge never needs a network client. The alert service runs on a real SQLite
// database, so dedup, persistence and scoping are the real contracts.

// The real generated query surface satisfies every read surface, so the bridge can only read the
// local stores (F4-031 wires these; there is no external client to inject).
var (
	_ ObservationSource   = (*db.Queries)(nil)
	_ LegacyAlertSource   = (*db.Queries)(nil)
	_ SyncRunSource       = (*db.Queries)(nil)
	_ PendingChangeSource = (*db.Queries)(nil)
)

// obsFake is a store-only observation reader. err models an unreadable store source.
type obsFake struct {
	rows  map[string][]db.Observation
	err   error
	calls int
}

func (f *obsFake) ListObservationsBySite(_ context.Context, site string) ([]db.Observation, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.rows[site], nil
}

// legacyFake feeds the open legacy pipeline alerts (F1/F3).
type legacyFake struct {
	alerts []db.Alert
	err    error
	calls  int
}

func (f *legacyFake) ListOpenAlerts(context.Context) ([]db.Alert, error) {
	f.calls++
	return f.alerts, f.err
}

// runFake feeds the newest sync run.
type runFake struct {
	run   db.SyncRun
	err   error
	calls int
}

func (f *runFake) GetLatestSyncRun(context.Context) (db.SyncRun, error) {
	f.calls++
	return f.run, f.err
}

// pendingFake feeds the changes waiting for approval.
type pendingFake struct {
	changes []db.Change
	err     error
	calls   int
}

func (f *pendingFake) ListPendingChanges(context.Context) ([]db.Change, error) {
	f.calls++
	return f.changes, f.err
}

func newTestSources(t *testing.T, svc *Service, sites []string, obs ObservationSource, legacy LegacyAlertSource, runs SyncRunSource, pending PendingChangeSource) *Sources {
	t.Helper()
	s, err := NewSources(svc, SourcesConfig{
		Sites:        func(context.Context) ([]string, error) { return sites, nil },
		Observations: obs,
		LegacyAlerts: legacy,
		SyncRuns:     runs,
		Pending:      pending,
	})
	if err != nil {
		t.Fatalf("NewSources: %v", err)
	}
	return s
}

// failedTargetRow is one stored target attempt that did not meet its expectation: a failure class
// label plus the fixed, sanitized text the F4-017 store keeps.
func failedTargetRow(host, at string) db.Observation {
	return db.Observation{
		Category: "target", Site: "site-1", Host: host, Source: "net_probe",
		Vantage: "tagcess-net", Endpoint: "10.0.0.1:443", Sni: host, Path: "/",
		LastAttemptAt: at, Success: 0, LastResult: "unexpected_status", LastHttpStatus: 503,
		LastError: "unexpected HTTP status",
	}
}

// failedGateRow is one stored Caddy gate attempt that did not answer as expected.
func failedGateRow(at string) db.Observation {
	return db.Observation{
		Category: "caddy_gate", Site: "site-1", Host: "app.example", Source: "net_probe",
		Vantage: "tagcess-net", Endpoint: "10.0.0.1:8443", Sni: "app.example", Path: "/",
		LastAttemptAt: at, Success: 0, LastResult: "unreachable", LastError: "connection or TLS handshake failed",
	}
}

// invalidTLSRow is one stored presented-leaf evaluation whose leaf could not be verified.
func invalidTLSRow(at string) db.Observation {
	return db.Observation{
		Category: "tls", Site: "site-1", Host: "app.example", Source: "net_probe",
		Vantage: "tagcess-net", Endpoint: "10.0.0.1:443", Sni: "app.example", Path: "/",
		LastAttemptAt: at, Success: 0, LastResult: "tls_unverified",
		LastTlsVerifyError: "x509: certificate has expired", LastTlsNotAfter: at,
	}
}

// successfulTargetRow is a target attempt that met its expectation: both the attempt group and a
// last-good time are present.
func successfulTargetRow(host, at string) db.Observation {
	row := failedTargetRow(host, at)
	row.Success = 1
	row.LastResult = "ok"
	row.LastError = ""
	row.ObservedAt = at
	row.LastHttpStatus = 200
	return row
}

// findView returns the first view of one (source, origin) key and how many matched.
func findView(views []SourceView, source SourceKind, origin string) (SourceView, int) {
	var first SourceView
	n := 0
	for _, v := range views {
		if v.Source == source && v.Origin == origin {
			if n == 0 {
				first = v
			}
			n++
		}
	}
	return first, n
}

func countViews(views []SourceView, source SourceKind) int {
	n := 0
	for _, v := range views {
		if v.Source == source {
			n++
		}
	}
	return n
}

// AC1 / R3-AC-10: target/TLS/gate observations, an existing sync error and the pending changes all
// surface with the correct source/subject; re-reading the same observation sample, including after
// a restart, does not re-count, and the legacy sync alert is surfaced, not copied or duplicated.
func TestAlertSourcesUseExistingObservationsSyncAndPendingChanges(t *testing.T) {
	ctx := context.Background()
	svc, st, _, path := openService(t)
	clock := newFakeClock(testBaseTime)
	svc.clock = clock.now

	obs := &obsFake{rows: map[string][]db.Observation{}}
	legacyRow, err := st.Queries().InsertAlert(ctx, db.InsertAlertParams{
		Kind: "reconcile_read_failed", Source: "zitadel",
		FirstSeenAt: stamp(testBaseTime), LastSeenAt: stamp(testBaseTime),
	})
	if err != nil {
		t.Fatalf("insert legacy alert: %v", err)
	}
	legacy := &legacyFake{alerts: []db.Alert{legacyRow}}
	runs := &runFake{run: db.SyncRun{ID: 1, StartedAt: stamp(testBaseTime), Trigger: "webhook", Result: "failed"}}
	pending := &pendingFake{changes: []db.Change{
		{ID: 1, Kind: "policy", Status: "pending_approval", CreatedAt: stamp(testBaseTime), UpdatedAt: stamp(testBaseTime)},
		{ID: 2, Kind: "site", Status: "pending_approval", CreatedAt: stamp(testBaseTime), UpdatedAt: stamp(testBaseTime)},
	}}
	sources := newTestSources(t, svc, []string{"site-1"}, obs, legacy, runs, pending)

	// Three cycles raise the three-failure health alerts; the invalid leaf is critical at once.
	var views []SourceView
	for i := 0; i < 3; i++ {
		at := stamp(testBaseTime.Add(time.Duration(i) * time.Minute))
		obs.rows["site-1"] = []db.Observation{failedTargetRow("app.example", at), invalidTLSRow(at), failedGateRow(at)}
		got, err := sources.Evaluate(ctx)
		if err != nil {
			t.Fatalf("Evaluate #%d: %v", i+1, err)
		}
		views = got
	}

	target, n := findView(views, SourceObservations, "target")
	if n != 1 || target.Subject != "app.example" || target.AlertKind != KindTargetHealth ||
		target.Severity != SeverityCritical || target.State != StateActive || target.Status != SourceFresh {
		t.Fatalf("target view = %+v (n=%d), want one active critical target health view", target, n)
	}
	gate, n := findView(views, SourceObservations, "caddy_gate")
	if n != 1 || gate.Subject != "app.example" || gate.AlertKind != KindTargetHealth || gate.Severity != SeverityCritical {
		t.Fatalf("gate view = %+v (n=%d), want one active critical gate health view", gate, n)
	}
	tls, n := findView(views, SourceObservations, "tls")
	if n != 1 || tls.Subject != "app.example" || tls.AlertKind != KindTLSExpiry || tls.Severity != SeverityCritical {
		t.Fatalf("tls view = %+v (n=%d), want one critical TLS expiry view", tls, n)
	}
	syncAlert, n := findView(views, SourceSyncRuns, "zitadel")
	if n != 1 || syncAlert.AlertKind != "reconcile_read_failed" || syncAlert.Severity != SeverityCritical {
		t.Fatalf("sync alert view = %+v (n=%d), want the legacy read-failure alert", syncAlert, n)
	}
	runView, n := findView(views, SourceSyncRuns, "webhook")
	if n != 1 || runView.Evidence != "failed" {
		t.Fatalf("sync run view = %+v (n=%d), want the failed run result", runView, n)
	}
	if got := countViews(views, SourcePendingChanges); got != 2 {
		t.Fatalf("pending change views = %d, want 2", got)
	}

	// The dashboard shows exactly one alert per monitor key and the counters are the real ones.
	open, err := svc.ListOpen(ctx)
	if err != nil {
		t.Fatalf("ListOpen: %v", err)
	}
	counts := map[string]int{}
	for _, a := range open {
		counts[a.Kind+"/"+a.Source]++
	}
	if counts[KindTargetHealth+"/"+AlertSourceTarget] != 1 ||
		counts[KindTargetHealth+"/"+AlertSourceGate] != 1 ||
		counts[KindTLSExpiry+"/"+AlertSourceTLS] != 1 || len(open) != 3 {
		t.Fatalf("open alerts = %+v (%v), want one per monitor key", open, counts)
	}
	if got := mustGet(t, svc, KindTargetHealth, "app.example", "target"); got.ConsecutiveFailures != 3 {
		t.Fatalf("target failures = %d, want 3", got.ConsecutiveFailures)
	}

	// The legacy alert is surfaced once and never copied into a monitor row.
	var legacyRows int
	if err := st.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM alerts WHERE kind = 'reconcile_read_failed' AND source = 'zitadel'`).Scan(&legacyRows); err != nil {
		t.Fatalf("count legacy: %v", err)
	}
	if legacyRows != 1 {
		t.Fatalf("legacy reconcile_read_failed rows = %d, want exactly the original", legacyRows)
	}

	// Restart: re-reading the same stored sample must not re-count (stable sample identity).
	svc2, st2 := reopenService(t, st, path)
	svc2.clock = clock.now // the rows are dated by the fake clock; a real clock would make them over-age
	sources2 := newTestSources(t, svc2, []string{"site-1"}, obs, legacy, runs, pending)
	if _, err := sources2.Evaluate(ctx); err != nil {
		t.Fatalf("Evaluate after restart: %v", err)
	}
	if got := mustGet(t, svc2, KindTargetHealth, "app.example", "target"); got.ConsecutiveFailures != 3 {
		t.Fatalf("target failures after restart = %d, want still 3", got.ConsecutiveFailures)
	}
	var total int
	if err := st2.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM alerts WHERE kind LIKE 'monitor_%'`).Scan(&total); err != nil {
		t.Fatalf("count monitor alerts: %v", err)
	}
	if total != 3 {
		t.Fatalf("monitor alerts after restart = %d, want the three monitor rows", total)
	}
}

// AC2 / R3-AC-10: an unreadable observation source or an incomplete stored result is shown as
// stale/unknown and does not count as a recovery of the existing health alert.
func TestAlertSourcesIncompleteReadDoesNotRecover(t *testing.T) {
	ctx := context.Background()
	svc, _, _, _ := openService(t)
	clock := newFakeClock(testBaseTime)
	svc.clock = clock.now

	obs := &obsFake{rows: map[string][]db.Observation{}}
	sources := newTestSources(t, svc, []string{"site-1"}, obs,
		&legacyFake{}, &runFake{err: sql.ErrNoRows}, &pendingFake{})

	for i := 0; i < 3; i++ {
		at := stamp(testBaseTime.Add(time.Duration(i) * time.Minute))
		obs.rows["site-1"] = []db.Observation{failedTargetRow("app.example", at)}
		if _, err := sources.Evaluate(ctx); err != nil {
			t.Fatalf("Evaluate #%d: %v", i+1, err)
		}
	}
	if got := mustGet(t, svc, KindTargetHealth, "app.example", "target"); got.ConsecutiveFailures != 3 {
		t.Fatalf("target failures = %d, want 3", got.ConsecutiveFailures)
	}

	// The store source cannot be read: the existing alert stays, and a freshness alert opens.
	obs.err = errors.New("store unavailable")
	views, err := sources.Evaluate(ctx)
	if err == nil {
		t.Fatalf("an unreadable observation source must surface an error")
	}
	if got := mustGet(t, svc, KindTargetHealth, "app.example", "target"); got.Resolved || got.ConsecutiveFailures != 3 {
		t.Fatalf("after a failed read = %+v, want the alert kept with 3 failures", got)
	}
	if got := mustGet(t, svc, KindSourceStale, "site-1", AlertSourceStore); got.Severity != SeverityWarning || got.Freshness != FreshnessStale {
		t.Fatalf("freshness alert = %+v, want a stale warning", got)
	}
	if v, n := findView(views, SourceObservations, AlertSourceStore); n != 1 || v.Subject != "site-1" || v.Status != SourceStale {
		t.Fatalf("failed-read view = %+v (n=%d), want a stale observation source view", v, n)
	}

	// A stored attempt that claims success without a last-good observation is incomplete: it must
	// not be treated as a recovery.
	obs.err = nil
	obs.rows["site-1"] = []db.Observation{successfulTargetRow("app.example", stamp(testBaseTime.Add(10*time.Minute)))}
	obs.rows["site-1"][0].ObservedAt = "" // incomplete: success claimed, no good evidence
	views, err = sources.Evaluate(ctx)
	if err != nil {
		t.Fatalf("Evaluate with an incomplete row: %v", err)
	}
	if got := mustGet(t, svc, KindTargetHealth, "app.example", "target"); got.Resolved || got.ConsecutiveFailures != 3 {
		t.Fatalf("after an incomplete success = %+v, want the alert kept unchanged", got)
	}
	if v, n := findView(views, SourceObservations, "target"); n != 1 || v.Status != SourceUnknown {
		t.Fatalf("incomplete view = %+v (n=%d), want an unknown status", v, n)
	}
}

// AC3 / P-02.5: one source/subject succeeding resolves only its own alert; the other subject and an
// unrelated legacy policy critical stay open.
func TestAlertSourcesDoNotResolveOtherSubjectsOrLegacyCriticals(t *testing.T) {
	ctx := context.Background()
	svc, st, _, _ := openService(t)
	clock := newFakeClock(testBaseTime)
	svc.clock = clock.now

	legacy := &legacyFake{}
	obs := &obsFake{rows: map[string][]db.Observation{}}
	sources := newTestSources(t, svc, []string{"site-1"}, obs, legacy,
		&runFake{err: sql.ErrNoRows}, &pendingFake{})

	for i := 0; i < 3; i++ {
		at := stamp(testBaseTime.Add(time.Duration(i) * time.Minute))
		obs.rows["site-1"] = []db.Observation{
			failedTargetRow("app.example", at),
			failedTargetRow("api.example", at),
		}
		if _, err := sources.Evaluate(ctx); err != nil {
			t.Fatalf("Evaluate #%d: %v", i+1, err)
		}
	}
	if _, err := st.Queries().InsertAlert(ctx, db.InsertAlertParams{
		Kind: "policy_mismatch", Source: "policy",
		FirstSeenAt: stamp(testBaseTime), LastSeenAt: stamp(testBaseTime),
	}); err != nil {
		t.Fatalf("insert legacy critical: %v", err)
	}

	// app.example recovers (two successes); api.example keeps failing.
	lastFail := stamp(testBaseTime.Add(2 * time.Minute))
	obs.rows["site-1"][0] = successfulTargetRow("app.example", stamp(testBaseTime.Add(10*time.Minute)))
	if _, err := sources.Evaluate(ctx); err != nil {
		t.Fatalf("first success: %v", err)
	}
	obs.rows["site-1"][0] = successfulTargetRow("app.example", stamp(testBaseTime.Add(11*time.Minute)))
	obs.rows["site-1"][1] = failedTargetRow("api.example", lastFail) // unchanged sample: no re-count
	if _, err := sources.Evaluate(ctx); err != nil {
		t.Fatalf("second success: %v", err)
	}

	if _, err := svc.Get(ctx, KindTargetHealth, "app.example", "target"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("app.example err = %v, want resolved", err)
	}
	if got := mustGet(t, svc, KindTargetHealth, "api.example", "target"); got.Resolved {
		t.Fatalf("api.example = %+v, want it still open", got)
	}
	// The unrelated legacy critical is untouched: same row, still open.
	rows, err := st.Queries().ListOpenAlerts(ctx)
	if err != nil {
		t.Fatalf("ListOpenAlerts: %v", err)
	}
	legacyOpen := false
	for _, r := range rows {
		if r.Kind == "policy_mismatch" {
			legacyOpen = true
			if r.ResolvedAt.Valid {
				t.Fatalf("legacy policy_mismatch was resolved: %+v", r)
			}
		}
	}
	if !legacyOpen {
		t.Fatalf("legacy policy_mismatch is gone, want it untouched")
	}
}

// AC4 / R3 B-07: the read results produce fixed, sanitized evidence — never the stored error text,
// body or header — and the bridge writes nowhere but the alerts table (no external client call).
func TestAlertSourcesUseStoredResultsAndSanitizeEvidence(t *testing.T) {
	ctx := context.Background()
	svc, st, _, _ := openService(t)
	clock := newFakeClock(testBaseTime)
	svc.clock = clock.now

	secret := "Authorization: Bearer SUPERSECRETTOKEN"
	obs := &obsFake{rows: map[string][]db.Observation{}}
	legacy := &legacyFake{}
	runs := &runFake{err: sql.ErrNoRows}
	pending := &pendingFake{}
	sources := newTestSources(t, svc, []string{"site-1"}, obs, legacy, runs, pending)

	before := tableCounts(t, st)
	var views []SourceView
	for i := 0; i < 3; i++ {
		at := stamp(testBaseTime.Add(time.Duration(i) * time.Minute))
		row := failedTargetRow("app.example", at)
		row.LastError = secret // a stored field the evidence must never echo
		obs.rows["site-1"] = []db.Observation{row}
		got, err := sources.Evaluate(ctx)
		if err != nil {
			t.Fatalf("Evaluate #%d: %v", i+1, err)
		}
		views = got
	}

	v, n := findView(views, SourceObservations, "target")
	if n != 1 || v.Evidence != "unexpected HTTP status" {
		t.Fatalf("target view = %+v (n=%d), want the fixed failure label", v, n)
	}
	for _, view := range views {
		if strings.Contains(view.Evidence, "SUPERSECRETTOKEN") {
			t.Fatalf("evidence leaked a stored secret: %+v", view)
		}
	}
	if got := mustGet(t, svc, KindTargetHealth, "app.example", "target"); strings.Contains(got.Evidence, "SUPERSECRETTOKEN") {
		t.Fatalf("alert evidence leaked a stored secret: %+v", got)
	}

	// Only alerts changed: no audit, notification or other external record.
	after := tableCounts(t, st)
	for name, count := range after {
		if name == "alerts" {
			continue
		}
		if count != before[name] {
			t.Fatalf("table %s changed from %d to %d; the bridge must only write alerts", name, before[name], count)
		}
	}

	// The bridge read only the injected store readers; no external client surface exists.
	if obs.calls == 0 || legacy.calls == 0 || runs.calls == 0 || pending.calls == 0 {
		t.Fatalf("store readers calls obs=%d legacy=%d runs=%d pending=%d, want all used",
			obs.calls, legacy.calls, runs.calls, pending.calls)
	}
}
