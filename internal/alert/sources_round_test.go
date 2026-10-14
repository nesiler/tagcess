package alert

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/monitor"
	"github.com/nesiler/tagcess/internal/store/db"
)

// Round-review fixes (C-H1, B-H-3, C-M1, B-M-7, C-M2): which stored rows count, how old a success may
// be, and what happens to the alerts of a site that is gone.

// listedAlert finds one alert in the lifecycle listing, resolved or not.
func listedAlert(t *testing.T, svc *Service, kind, subject, source string) Alert {
	t.Helper()
	list, err := svc.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, a := range list {
		if a.Kind == kind && a.Subject == subject && a.Source == source {
			return a
		}
	}
	t.Fatalf("no %s alert for %s/%s in %+v", kind, subject, source, list)
	return Alert{}
}

func pathRow(base db.Observation, path string, id int64) db.Observation {
	base.Path, base.ID = path, id
	return base
}

// C-H1/B-H-3: an old success row left by a changed path must not keep resetting the failure counter
// of the current failing row; three current failures raise the critical alert.
func TestAlertSourcesStaleSuccessRowDoesNotMaskFailingTarget(t *testing.T) {
	ctx := context.Background()
	svc, _, _, _ := openService(t)
	clock := newFakeClock(testBaseTime)
	svc.clock = clock.now
	obs := &obsFake{rows: map[string][]db.Observation{}}
	sources := newTestSources(t, svc, []string{"site-1"}, obs, &legacyFake{}, &runFake{err: sql.ErrNoRows}, &pendingFake{})

	frozen := pathRow(successfulTargetRow("app.example", stamp(testBaseTime.Add(-time.Hour))), "/", 1)
	for i := 0; i < 6; i++ {
		at := stamp(testBaseTime.Add(time.Duration(i) * time.Minute))
		obs.rows["site-1"] = []db.Observation{frozen, pathRow(failedTargetRow("app.example", at), "/healthz", 2)}
		_, _ = sources.Evaluate(ctx)
	}
	got := mustGet(t, svc, KindTargetHealth, "app.example", "target")
	if got.Severity != SeverityCritical || got.ConsecutiveFailures < 3 {
		t.Fatalf("alert = severity %q failures %d, want critical after the current row failed 6 times", got.Severity, got.ConsecutiveFailures)
	}
}

// The reverse: an old failing row must not keep resetting the success counter, so a recovered
// target resolves.
func TestAlertSourcesStaleFailingRowDoesNotBlockRecovery(t *testing.T) {
	ctx := context.Background()
	svc, _, _, _ := openService(t)
	clock := newFakeClock(testBaseTime)
	svc.clock = clock.now
	obs := &obsFake{rows: map[string][]db.Observation{}}
	sources := newTestSources(t, svc, []string{"site-1"}, obs, &legacyFake{}, &runFake{err: sql.ErrNoRows}, &pendingFake{})

	for i := 0; i < 3; i++ {
		at := stamp(testBaseTime.Add(time.Duration(i) * time.Minute))
		obs.rows["site-1"] = []db.Observation{pathRow(failedTargetRow("app.example", at), "/", 1)}
		_, _ = sources.Evaluate(ctx)
	}
	oldFailing := pathRow(failedTargetRow("app.example", stamp(testBaseTime.Add(2*time.Minute))), "/", 1)
	for i := 3; i < 9; i++ {
		at := stamp(testBaseTime.Add(time.Duration(i) * time.Minute))
		obs.rows["site-1"] = []db.Observation{oldFailing, pathRow(successfulTargetRow("app.example", at), "/healthz", 2)}
		_, _ = sources.Evaluate(ctx)
	}
	got := listedAlert(t, svc, KindTargetHealth, "app.example", "target")
	if !got.Resolved {
		t.Fatalf("alert = %+v, want resolved once the current row succeeded", got)
	}
}

func sourcesWithSettings(t *testing.T, svc *Service, sites []string, obs ObservationSource, st func(context.Context) (monitor.Settings, error)) *Sources {
	t.Helper()
	s, err := NewSources(svc, SourcesConfig{
		Sites: func(context.Context) ([]string, error) { return sites, nil }, Observations: obs,
		LegacyAlerts: &legacyFake{}, SyncRuns: &runFake{err: sql.ErrNoRows}, Pending: &pendingFake{},
		Settings: st,
	})
	if err != nil {
		t.Fatalf("NewSources: %v", err)
	}
	return s
}

// C-M1/B-M-7: a success older than twice the measurement interval is stale, raises the freshness
// alert and is no recovery; a new attempt clears the freshness alert.
func TestAlertSourcesOverAgeSuccessRaisesFreshnessAlert(t *testing.T) {
	ctx := context.Background()
	svc, _, _, _ := openService(t)
	clock := newFakeClock(testBaseTime)
	svc.clock = clock.now
	obs := &obsFake{rows: map[string][]db.Observation{}}
	sources := sourcesWithSettings(t, svc, []string{"site-1"}, obs, nil)

	row := successfulTargetRow("app.example", stamp(testBaseTime.Add(-10*time.Minute))) // 60 s interval: far over 2x
	obs.rows["site-1"] = []db.Observation{row}
	views, err := sources.Evaluate(ctx)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if v, n := findView(views, SourceObservations, "target"); n != 1 || v.Freshness != FreshnessStale {
		t.Fatalf("target view = %+v (n=%d), want a stale view", v, n)
	}
	if got := mustGet(t, svc, KindSourceStale, "app.example", AlertSourceTarget); got.Freshness != FreshnessStale {
		t.Fatalf("freshness alert = %+v, want a stale warning", got)
	}

	// A fresh attempt clears it.
	obs.rows["site-1"] = []db.Observation{successfulTargetRow("app.example", stamp(testBaseTime.Add(-10*time.Second)))}
	views, err = sources.Evaluate(ctx)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if v, _ := findView(views, SourceObservations, "target"); v.Freshness != FreshnessFresh {
		t.Fatalf("target view = %+v, want fresh", v)
	}
	mustNotFound(t, svc, KindSourceStale, "app.example", AlertSourceTarget)
}

// C-L6: a failed attempt's evidence is stale, never fresh.
func TestAlertSourcesFailedAttemptIsStale(t *testing.T) {
	ctx := context.Background()
	svc, _, _, _ := openService(t)
	clock := newFakeClock(testBaseTime)
	svc.clock = clock.now
	obs := &obsFake{rows: map[string][]db.Observation{"site-1": {failedTargetRow("app.example", stamp(testBaseTime))}}}
	sources := sourcesWithSettings(t, svc, []string{"site-1"}, obs, nil)
	views, err := sources.Evaluate(ctx)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if v, n := findView(views, SourceObservations, "target"); n != 1 || v.Freshness != FreshnessStale {
		t.Fatalf("failed target view = %+v (n=%d), want stale", v, n)
	}
}

// C-M2: after a complete read, the monitor alerts of a host that no site lists any more are resolved
// with the "site removed" evidence; a failed site-list read resolves nothing.
func TestAlertSourcesResolveAlertsOfRemovedSites(t *testing.T) {
	ctx := context.Background()
	svc, _, _, _ := openService(t)
	clock := newFakeClock(testBaseTime)
	svc.clock = clock.now
	obs := &obsFake{rows: map[string][]db.Observation{}}
	sites := []string{"site-1", "site-2"}
	listErr := error(nil)
	sources, err := NewSources(svc, SourcesConfig{
		Sites: func(context.Context) ([]string, error) {
			if listErr != nil {
				return nil, listErr
			}
			return sites, nil
		},
		Observations: obs, LegacyAlerts: &legacyFake{}, SyncRuns: &runFake{err: sql.ErrNoRows}, Pending: &pendingFake{},
	})
	if err != nil {
		t.Fatalf("NewSources: %v", err)
	}
	failing := func(site, host string, i int) db.Observation {
		r := failedTargetRow(host, stamp(testBaseTime.Add(time.Duration(i)*time.Minute)))
		r.Site = site
		return r
	}
	for i := 0; i < 3; i++ {
		obs.rows["site-1"] = []db.Observation{failing("site-1", "one.example", i)}
		obs.rows["site-2"] = []db.Observation{failing("site-2", "two.example", i)}
		if _, err := sources.Evaluate(ctx); err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
	}
	// A legacy/drift alert of another subject must stay untouched.
	if _, err := svc.RecordSource(ctx, SourceSample{Subject: "policy", Source: SourceDrift, Failed: true, Error: "x"}); err != nil {
		t.Fatalf("RecordSource: %v", err)
	}

	listErr = errors.New("sites unreadable")
	_, _ = sources.Evaluate(ctx)
	if got := listedAlert(t, svc, KindTargetHealth, "two.example", "target"); got.Resolved {
		t.Fatal("an unreadable site list resolved an alert")
	}

	listErr = nil
	sites = []string{"site-1"}
	if _, err := sources.Evaluate(ctx); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	gone := listedAlert(t, svc, KindTargetHealth, "two.example", "target")
	if !gone.Resolved || gone.Evidence != "site removed" {
		t.Fatalf("removed site alert = resolved %v evidence %q, want resolved with 'site removed'", gone.Resolved, gone.Evidence)
	}
	if got := listedAlert(t, svc, KindTargetHealth, "one.example", "target"); got.Resolved {
		t.Fatal("the listed site's alert was resolved")
	}
	if got := listedAlert(t, svc, KindSourceStale, "policy", SourceDrift); got.Resolved {
		t.Fatal("a drift freshness alert was resolved as a removed site")
	}
}

// B-L-11: a failed network-measurement row of the two-gate category is not "recorded/fresh".
func TestAlertSourcesConfigRiskViewBranchesOnSource(t *testing.T) {
	ctx := context.Background()
	svc, _, _, _ := openService(t)
	clock := newFakeClock(testBaseTime)
	svc.clock = clock.now
	risk := db.Observation{ID: 1, Category: "config_risk", Site: "site-1", Host: "app.example", Source: "k8s_config",
		Route: "app.example/", RiskFinding: "alternate_path_candidate", LastAttemptAt: stamp(testBaseTime)}
	probe := db.Observation{ID: 2, Category: "config_risk", Site: "site-1", Host: "app.example", Source: "net_probe",
		Route: "app.example/", LastAttemptAt: stamp(testBaseTime), Success: 0, LastResult: "timeout"}
	obs := &obsFake{rows: map[string][]db.Observation{"site-1": {risk, probe}}}
	sources := sourcesWithSettings(t, svc, []string{"site-1"}, obs, nil)
	views, err := sources.Evaluate(ctx)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	var riskView, probeView SourceView
	for _, v := range views {
		if v.Origin != "config_risk" {
			continue
		}
		if v.Evidence == "alternate path candidate" {
			riskView = v
		} else {
			probeView = v
		}
	}
	if riskView.Freshness != FreshnessFresh {
		t.Fatalf("risk view = %+v, want the declared risk row unchanged", riskView)
	}
	if probeView.Freshness != FreshnessStale || probeView.Evidence == "network measurement recorded" || probeView.Evidence == "" {
		t.Fatalf("failed probe view = %+v, want stale with the failure text", probeView)
	}
}

// A-M4: an old open alert is still listed when more than listLimit newer resolved rows exist.
func TestAlertListKeepsOldOpenAlertBehindManyResolvedRows(t *testing.T) {
	ctx := context.Background()
	svc, st, _, _ := openService(t)
	insert := func(subject, severity, seen string, resolved any) {
		t.Helper()
		if _, err := st.DB().ExecContext(ctx,
			`INSERT INTO alerts (kind, source, subject, severity, first_seen_at, last_seen_at, resolved_at, freshness)
			 VALUES ('monitor_target_health', 'target', ?, ?, ?, ?, ?, 'fresh')`,
			subject, severity, seen, seen, resolved); err != nil {
			t.Fatalf("insert %s: %v", subject, err)
		}
	}
	insert("old-open.example", "critical", stamp(testBaseTime.Add(-24*time.Hour)), nil)
	for i := 0; i < listLimit+5; i++ {
		at := stamp(testBaseTime.Add(time.Duration(i) * time.Second))
		insert("resolved-"+at, "critical", at, at)
	}
	list, err := svc.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var found bool
	resolved := 0
	for _, a := range list {
		if a.Subject == "old-open.example" && !a.Resolved {
			found = true
		}
		if a.Resolved {
			resolved++
		}
	}
	if !found {
		t.Fatalf("the old open alert is missing from %d listed rows", len(list))
	}
	if resolved != listLimit {
		t.Fatalf("resolved rows = %d, want the limit %d", resolved, listLimit)
	}
}
