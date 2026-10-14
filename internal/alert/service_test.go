package alert

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/gitlog"
	"github.com/nesiler/tagcess/internal/monitor"
	"github.com/nesiler/tagcess/internal/store/db"
	pipesync "github.com/nesiler/tagcess/internal/sync"
)

// raiseTarget drives three consecutive failed health samples for a key, the default hysteresis
// opening point, and returns the open alert.
func raiseTarget(t *testing.T, svc *Service, clock *fakeClock, subject, source string) Alert {
	t.Helper()
	ctx := context.Background()
	var got Alert
	for i := 1; i <= 3; i++ {
		sample := HealthSample{
			Subject: subject, Source: source, At: clock.now(),
			SampleID: fmt.Sprintf("%s/%s/h%d", subject, source, i), Success: false, Evidence: "HTTP 503",
		}
		a, err := svc.RecordHealth(ctx, sample)
		if err != nil {
			t.Fatalf("RecordHealth fail #%d: %v", i, err)
		}
		got = a
	}
	if got.State != StateActive || got.Severity != SeverityCritical || got.ConsecutiveFailures != 3 {
		t.Fatalf("after 3 failures = %+v, want active critical with 3 failures", got)
	}
	return got
}

// AC1 / R3-AC-10: with the default thresholds three consecutive target failures open the alert and
// two consecutive successes resolve it; the counters and lifecycle are observable through the
// service, a repeated sample does not re-count, and acknowledgement is not a recovery.
func TestAlertHysteresisAcknowledgementAndFreshness(t *testing.T) {
	ctx := context.Background()
	svc, _, _, _ := openService(t)
	clock := newFakeClock(testBaseTime)
	svc.clock = clock.now

	// Two failures are below the opening threshold and stay pending, but the counter is persisted
	// and observable.
	for i := 1; i <= 2; i++ {
		got, err := svc.RecordHealth(ctx, HealthSample{
			Subject: "app.example", Source: "target", At: clock.now(),
			SampleID: fmt.Sprintf("s%d", i), Success: false, Evidence: "HTTP 503",
		})
		if err != nil {
			t.Fatalf("RecordHealth #%d: %v", i, err)
		}
		if got.State != StatePending || got.ConsecutiveFailures != i || got.Severity != "" {
			t.Fatalf("after %d failures = %+v, want pending with %d failures and no severity", i, got, i)
		}
	}

	// The third failure opens the alert.
	raised, err := svc.RecordHealth(ctx, HealthSample{
		Subject: "app.example", Source: "target", At: clock.now(),
		SampleID: "s3", Success: false, Evidence: "HTTP 503",
	})
	if err != nil {
		t.Fatalf("RecordHealth #3: %v", err)
	}
	if raised.State != StateActive || raised.Severity != SeverityCritical || raised.ConsecutiveFailures != 3 {
		t.Fatalf("after 3 failures = %+v, want active critical with 3 failures", raised)
	}
	if raised.ID == 0 || raised.Freshness != FreshnessFresh {
		t.Fatalf("raised = %+v, want an id and fresh freshness", raised)
	}

	// Re-feeding the same sample identity never re-counts.
	again, err := svc.RecordHealth(ctx, HealthSample{
		Subject: "app.example", Source: "target", At: clock.now(),
		SampleID: "s3", Success: false, Evidence: "HTTP 503",
	})
	if err != nil {
		t.Fatalf("dedup sample: %v", err)
	}
	if again.ID != raised.ID || again.ConsecutiveFailures != 3 {
		t.Fatalf("dedup sample = %+v, want the unchanged alert with 3 failures", again)
	}

	// Acknowledgement records the read but is not a recovery.
	acked, err := svc.Acknowledge(ctx, KindTargetHealth, "app.example", "target")
	if err != nil {
		t.Fatalf("Acknowledge: %v", err)
	}
	if !acked.Acknowledged || acked.Resolved || acked.State != StateAcknowledged {
		t.Fatalf("acknowledged = %+v, want acknowledged and still open", acked)
	}
	if open, _ := svc.Get(ctx, KindTargetHealth, "app.example", "target"); open.Resolved {
		t.Fatalf("Get after ack resolved the alert: %+v", open)
	}

	// One success is not enough...
	one, err := svc.RecordHealth(ctx, HealthSample{
		Subject: "app.example", Source: "target", At: clock.now(),
		SampleID: "app.example/target/h4", Success: true,
	})
	if err != nil {
		t.Fatalf("RecordHealth success #1: %v", err)
	}
	if one.Resolved || one.ConsecutiveSuccesses != 1 || one.ConsecutiveFailures != 0 {
		t.Fatalf("after 1 success = %+v, want still open with one success", one)
	}
	// ...two successes resolve it.
	two, err := svc.RecordHealth(ctx, HealthSample{
		Subject: "app.example", Source: "target", At: clock.now(),
		SampleID: "app.example/target/h5", Success: true,
	})
	if err != nil {
		t.Fatalf("RecordHealth success #2: %v", err)
	}
	if !two.Resolved || two.ConsecutiveSuccesses != 2 {
		t.Fatalf("after 2 successes = %+v, want resolved with two successes", two)
	}
	if _, err := svc.Get(ctx, KindTargetHealth, "app.example", "target"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after resolve err = %v, want ErrNotFound", err)
	}
}

// AC2 / R3-AC-10: acknowledging or losing the source is not a recovery. A source read failure
// keeps the existing health alert open, marks it stale and raises a separate freshness alert; the
// source recovering resolves only the freshness alert.
func TestAlertAcknowledgementAndSourceLossDoNotRecover(t *testing.T) {
	ctx := context.Background()
	svc, _, _, _ := openService(t)
	clock := newFakeClock(testBaseTime)
	svc.clock = clock.now

	raiseTarget(t, svc, clock, "app.example", "target")
	if _, err := svc.Acknowledge(ctx, KindTargetHealth, "app.example", "target"); err != nil {
		t.Fatalf("Acknowledge: %v", err)
	}

	stale, err := svc.RecordSource(ctx, SourceSample{
		Subject: "app.example", Source: "target", At: clock.now(),
		SampleID: "src1", Failed: true, Error: "read timeout",
	})
	if err != nil {
		t.Fatalf("RecordSource failed: %v", err)
	}
	if stale.Kind != KindSourceStale || stale.Resolved || stale.Severity != SeverityWarning || stale.Freshness != FreshnessStale {
		t.Fatalf("freshness alert = %+v, want an open warning stale freshness alert", stale)
	}

	// The existing health alert is not resolved; only its freshness is updated and the ack kept.
	kept, err := svc.Get(ctx, KindTargetHealth, "app.example", "target")
	if err != nil {
		t.Fatalf("Get health after source loss: %v", err)
	}
	if kept.Resolved {
		t.Fatalf("source loss resolved the health alert: %+v", kept)
	}
	if kept.Freshness != FreshnessStale || !kept.Acknowledged {
		t.Fatalf("health after source loss = %+v, want stale and still acknowledged", kept)
	}

	// A complete recovery resolves the freshness alert but never the health alert by itself.
	if _, err := svc.RecordSource(ctx, SourceSample{
		Subject: "app.example", Source: "target", At: clock.now(), SampleID: "src2", Failed: false,
	}); err != nil {
		t.Fatalf("RecordSource recovered: %v", err)
	}
	if _, err := svc.Get(ctx, KindSourceStale, "app.example", "target"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("freshness alert after recovery err = %v, want ErrNotFound", err)
	}
	if still, err := svc.Get(ctx, KindTargetHealth, "app.example", "target"); err != nil || still.Resolved {
		t.Fatalf("health after source recovery = %+v err = %v, want still open", still, err)
	}
}

// AC3 / R3-AC-10: counters and the same open alert survive closing and reopening the database; the
// same observation sample is not counted twice after the restart, and the lifecycle only produces
// alert rows (dashboard-only, no external notification record).
func TestAlertRestartDedupAndDashboardOnly(t *testing.T) {
	ctx := context.Background()
	svc, st, _, path := openService(t)
	clock := newFakeClock(testBaseTime)
	svc.clock = clock.now

	// Snapshot before the first sample so an open-time notification row would be seen too.
	before := tableCounts(t, st)
	raised := raiseTarget(t, svc, clock, "app.example", "target")

	// Restart: same path, fresh process state.
	svc2, reopened := reopenService(t, st, path)

	// The same sample identity read again after the restart must not re-count.
	dedup, err := svc2.RecordHealth(ctx, HealthSample{
		Subject: "app.example", Source: "target", At: clock.now(),
		SampleID: "app.example/target/h3", Success: false, Evidence: "HTTP 503",
	})
	if err != nil {
		t.Fatalf("restart dedup: %v", err)
	}
	if dedup.ID != raised.ID || dedup.ConsecutiveFailures != 3 {
		t.Fatalf("restart dedup = %+v, want the same alert with 3 failures", dedup)
	}

	// A genuinely new failure after the restart continues the same alert and increments the counter.
	next, err := svc2.RecordHealth(ctx, HealthSample{
		Subject: "app.example", Source: "target", At: clock.now(),
		SampleID: "app.example/target/h4", Success: false, Evidence: "HTTP 503",
	})
	if err != nil {
		t.Fatalf("restart next failure: %v", err)
	}
	if next.ID != raised.ID || next.ConsecutiveFailures != 4 {
		t.Fatalf("after restart = %+v, want the same alert id %d with 4 failures", next, raised.ID)
	}

	// The dashboard lists it once.
	open, err := svc2.ListOpen(ctx)
	if err != nil {
		t.Fatalf("ListOpen: %v", err)
	}
	if len(open) != 1 || open[0].ID != raised.ID || open[0].ConsecutiveFailures != 4 {
		t.Fatalf("ListOpen = %+v, want exactly the persisted alert", open)
	}

	// Only the alerts table changed across the restart/dedup: no audit/webhook/other notification row.
	after := tableCounts(t, reopened)
	for name, n := range after {
		if name == "alerts" {
			continue
		}
		if n != before[name] {
			t.Fatalf("table %s changed from %d to %d; the service must only write alerts (dashboard-only)", name, before[name], n)
		}
	}
}

// AC4 / R3-AC-17: the presented-leaf remaining lifetime produces info/warning/critical exactly at
// the typed 30/14/7-day boundaries, and an expired or unverifiable leaf is critical immediately,
// without waiting for the health failure counter.
func TestCertificateExpiryThresholds(t *testing.T) {
	ctx := context.Background()
	svc, _, _, _ := openService(t)
	clock := newFakeClock(testBaseTime)
	svc.clock = clock.now

	cfg := monitor.DefaultSettings()
	if cfg.TLSInfoDays != 30 || cfg.TLSWarnDays != 14 || cfg.TLSCriticalDays != 7 {
		t.Fatalf("defaults = %d/%d/%d, want 30/14/7", cfg.TLSInfoDays, cfg.TLSWarnDays, cfg.TLSCriticalDays)
	}

	// Each boundary is evaluated on the exact threshold instant.
	cases := []struct {
		name     string
		notAfter time.Time
		invalid  bool
		want     Severity
	}{
		{"info boundary 30d", clock.now().Add(30 * 24 * time.Hour), false, SeverityInfo},
		{"warn boundary 14d", clock.now().Add(14 * 24 * time.Hour), false, SeverityWarning},
		{"critical boundary 7d", clock.now().Add(7 * 24 * time.Hour), false, SeverityCritical},
	}
	for _, tc := range cases {
		got, err := svc.RecordTLS(ctx, TLSSample{
			Subject: "tls-" + tc.name, Source: "tls", At: clock.now(),
			SampleID: "tls-" + tc.name, NotAfter: tc.notAfter, Invalid: tc.invalid,
		})
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got.Severity != tc.want || got.Resolved {
			t.Fatalf("%s = %+v, want %s", tc.name, got, tc.want)
		}
	}

	// Above the info threshold there is no alert; an open alert resolves.
	healthy, err := svc.RecordTLS(ctx, TLSSample{
		Subject: "tls-healthy", Source: "tls", At: clock.now(),
		SampleID: "healthy", NotAfter: clock.now().Add(31 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("healthy: %v", err)
	}
	if healthy.ID != 0 || healthy.Severity != "" {
		t.Fatalf("healthy = %+v, want no alert", healthy)
	}

	// Let the same host's certificate cross into the warning and then critical band.
	host := "tls-shrink"
	if got, err := svc.RecordTLS(ctx, TLSSample{
		Subject: host, Source: "tls", At: clock.now(), SampleID: "a",
		NotAfter: clock.now().Add(20 * 24 * time.Hour),
	}); err != nil || got.Severity != SeverityInfo {
		t.Fatalf("tls-shrink info = %+v err = %v", got, err)
	}
	if got, err := svc.RecordTLS(ctx, TLSSample{
		Subject: host, Source: "tls", At: clock.now(), SampleID: "b",
		NotAfter: clock.now().Add(10 * 24 * time.Hour),
	}); err != nil || got.Severity != SeverityWarning {
		t.Fatalf("tls-shrink warn = %+v err = %v", got, err)
	}
	if got, err := svc.RecordTLS(ctx, TLSSample{
		Subject: host, Source: "tls", At: clock.now(), SampleID: "c",
		NotAfter: clock.now().Add(3 * 24 * time.Hour),
	}); err != nil || got.Severity != SeverityCritical {
		t.Fatalf("tls-shrink critical = %+v err = %v", got, err)
	}
	// Recovered certificate resolves the same TLS alert.
	if got, err := svc.RecordTLS(ctx, TLSSample{
		Subject: host, Source: "tls", At: clock.now(), SampleID: "d",
		NotAfter: clock.now().Add(60 * 24 * time.Hour),
	}); err != nil || !got.Resolved {
		t.Fatalf("tls-shrink recovered = %+v err = %v, want resolved", got, err)
	}

	// Expired and unverifiable leaves are critical on the very first evaluation, and produce no
	// health-counted alert.
	for _, tc := range []struct {
		name   string
		sample TLSSample
	}{
		{"expired", TLSSample{Subject: "tls-expired", Source: "tls", At: clock.now(), SampleID: "e", NotAfter: clock.now().Add(-time.Hour)}},
		{"invalid", TLSSample{Subject: "tls-invalid", Source: "tls", At: clock.now(), SampleID: "f", Invalid: true}},
	} {
		got, err := svc.RecordTLS(ctx, tc.sample)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got.Severity != SeverityCritical || got.ConsecutiveFailures != 0 || got.Resolved {
			t.Fatalf("%s = %+v, want an immediate critical TLS alert with no health counter", tc.name, got)
		}
	}

	// The same subject/source has no health alert: TLS never used the 3-failure counter.
	if _, err := svc.Get(ctx, KindTargetHealth, host, "tls"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("TLS created a health alert: err = %v, want ErrNotFound", err)
	}
}

// AC5 / R3-AC-17: maintenance mutes the alert label without stopping measurement, the next real
// sample after maintenance presents unmuted, and changing the thresholds in the settings store
// applies to the following evaluation without a restart.
func TestAlertMaintenanceAndSettingsUpdates(t *testing.T) {
	ctx := context.Background()
	svc, _, settings, _ := openService(t)
	clock := newFakeClock(testBaseTime)
	svc.clock = clock.now

	if err := svc.SetMaintenance(ctx, "app.example", true); err != nil {
		t.Fatalf("SetMaintenance on: %v", err)
	}
	raised := raiseTarget(t, svc, clock, "app.example", "target")
	if !raised.Muted {
		t.Fatalf("alert during maintenance = %+v, want muted", raised)
	}

	if err := svc.SetMaintenance(ctx, "app.example", false); err != nil {
		t.Fatalf("SetMaintenance off: %v", err)
	}
	unmuted, err := svc.Get(ctx, KindTargetHealth, "app.example", "target")
	if err != nil {
		t.Fatalf("Get after maintenance: %v", err)
	}
	if unmuted.Muted {
		t.Fatalf("alert after maintenance = %+v, want unmuted", unmuted)
	}

	// The next real measurement is accepted and presented unmuted (one success keeps it open).
	after, err := svc.RecordHealth(ctx, HealthSample{
		Subject: "app.example", Source: "target", At: clock.now(),
		SampleID: "app.example/target/h4", Success: true,
	})
	if err != nil {
		t.Fatalf("RecordHealth after maintenance: %v", err)
	}
	if after.Muted || after.Resolved || after.ConsecutiveSuccesses != 1 {
		t.Fatalf("measurement after maintenance = %+v, want unmuted and still open", after)
	}

	// A UI-style settings change applies to the next evaluation: 1 failure opens, 1 success resolves.
	cfg := monitor.DefaultSettings()
	cfg.HealthFailThreshold = 1
	cfg.HealthOKThreshold = 1
	if err := settings.Set(ctx, cfg); err != nil {
		t.Fatalf("settings.Set: %v", err)
	}
	quick, err := svc.RecordHealth(ctx, HealthSample{
		Subject: "api.example", Source: "target", At: clock.now(), SampleID: "api1", Success: false,
	})
	if err != nil {
		t.Fatalf("RecordHealth with new threshold: %v", err)
	}
	if quick.State != StateActive || quick.ConsecutiveFailures != 1 {
		t.Fatalf("new threshold = %+v, want active after a single failure", quick)
	}
	done, err := svc.RecordHealth(ctx, HealthSample{
		Subject: "api.example", Source: "target", At: clock.now(), SampleID: "api2", Success: true,
	})
	if err != nil {
		t.Fatalf("RecordHealth resolve with new threshold: %v", err)
	}
	if !done.Resolved {
		t.Fatalf("new resolve threshold = %+v, want resolved after a single success", done)
	}
}

// AC6 / R3-AC-10: a success on another subject never resolves an unrelated alert, and a failed
// persistence never reports the transition as successful or leaves a partial write behind.
func TestAlertTransitionsAreScopedAndDurable(t *testing.T) {
	ctx := context.Background()
	svc, st, _, _ := openService(t)
	clock := newFakeClock(testBaseTime)
	svc.clock = clock.now

	raiseTarget(t, svc, clock, "app.example", "target")
	other := raiseTarget(t, svc, clock, "api.example", "target")

	// Resolving app.example leaves api.example open.
	for i, id := range []string{"ok1", "ok2"} {
		if _, err := svc.RecordHealth(ctx, HealthSample{
			Subject: "app.example", Source: "target", At: clock.now(), SampleID: id, Success: true,
		}); err != nil {
			t.Fatalf("resolve app success #%d: %v", i+1, err)
		}
	}
	if _, err := svc.Get(ctx, KindTargetHealth, "app.example", "target"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("app.example err = %v, want resolved", err)
	}
	still, err := svc.Get(ctx, KindTargetHealth, "api.example", "target")
	if err != nil || still.Resolved || still.ID != other.ID {
		t.Fatalf("api.example = %+v err = %v, want the same open alert", still, err)
	}

	// Force every alert UPDATE to fail: the transition must surface the error and change nothing.
	if _, err := st.DB().ExecContext(ctx,
		`CREATE TRIGGER fail_alert_update BEFORE UPDATE ON alerts BEGIN SELECT RAISE(ABORT, 'boom'); END;`); err != nil {
		t.Fatalf("create trigger: %v", err)
	}
	failed, err := svc.RecordHealth(ctx, HealthSample{
		Subject: "api.example", Source: "target", At: clock.now(), SampleID: "api-fail", Success: false,
	})
	if err == nil {
		t.Fatalf("RecordHealth with broken persistence = %+v, want an error", failed)
	}
	afterFail, err := svc.Get(ctx, KindTargetHealth, "api.example", "target")
	if err != nil {
		t.Fatalf("Get after failed write: %v", err)
	}
	if afterFail.ConsecutiveFailures != 3 || afterFail.LastConsumedSample == "api-fail" || afterFail.Resolved {
		t.Fatalf("failed persistence left a partial transition: %+v", afterFail)
	}

	// Once persistence works again the same transition applies (nothing was swallowed).
	if _, err := st.DB().ExecContext(ctx, `DROP TRIGGER fail_alert_update`); err != nil {
		t.Fatalf("drop trigger: %v", err)
	}
	recovered, err := svc.RecordHealth(ctx, HealthSample{
		Subject: "api.example", Source: "target", At: clock.now(), SampleID: "api-fail", Success: false,
	})
	if err != nil {
		t.Fatalf("RecordHealth after fixing persistence: %v", err)
	}
	if recovered.ConsecutiveFailures != 4 || recovered.ID != other.ID {
		t.Fatalf("recovered = %+v, want the same alert with 4 failures", recovered)
	}
}

// --- F4-023 review fixes ---------------------------------------------------------------------

// health feeds one health sample; at stays zero so the service clock is used.
func health(subject, source, id string, success bool) HealthSample {
	return HealthSample{Subject: subject, Source: source, SampleID: id, Success: success}
}

// mustHealth records a health sample and fails the test on error.
func mustHealth(t *testing.T, svc *Service, in HealthSample) Alert {
	t.Helper()
	got, err := svc.RecordHealth(context.Background(), in)
	if err != nil {
		t.Fatalf("RecordHealth %s/%s %s: %v", in.Subject, in.Source, in.SampleID, err)
	}
	return got
}

func mustTLS(t *testing.T, svc *Service, in TLSSample) Alert {
	t.Helper()
	got, err := svc.RecordTLS(context.Background(), in)
	if err != nil {
		t.Fatalf("RecordTLS %s/%s %s: %v", in.Subject, in.Source, in.SampleID, err)
	}
	return got
}

func mustSource(t *testing.T, svc *Service, in SourceSample) Alert {
	t.Helper()
	got, err := svc.RecordSource(context.Background(), in)
	if err != nil {
		t.Fatalf("RecordSource %s/%s %s: %v", in.Subject, in.Source, in.SampleID, err)
	}
	return got
}

func mustGet(t *testing.T, svc *Service, kind, subject, source string) Alert {
	t.Helper()
	got, err := svc.Get(context.Background(), kind, subject, source)
	if err != nil {
		t.Fatalf("Get %s %s/%s: %v", kind, subject, source, err)
	}
	return got
}

func mustNotFound(t *testing.T, svc *Service, kind, subject, source string) {
	t.Helper()
	if got, err := svc.Get(context.Background(), kind, subject, source); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get %s %s/%s = %+v err = %v, want ErrNotFound", kind, subject, source, got, err)
	}
}

// Review (1): a pending (sub-threshold) row is bookkeeping and cannot be acknowledged; otherwise the
// alert would be born already acknowledged without anyone having read it.
func TestAlertAcknowledgeRejectsPendingRow(t *testing.T) {
	ctx := context.Background()
	svc, _, _, _ := openService(t)
	clock := newFakeClock(testBaseTime)
	svc.clock = clock.now

	if got := mustHealth(t, svc, health("app.example", "target", "p1", false)); got.State != StatePending {
		t.Fatalf("1 failure = %+v, want pending", got)
	}
	if got, err := svc.Acknowledge(ctx, KindTargetHealth, "app.example", "target"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Acknowledge pending = %+v err = %v, want ErrNotFound", got, err)
	}
	if pending := mustGet(t, svc, KindTargetHealth, "app.example", "target"); pending.Acknowledged {
		t.Fatalf("pending row was acknowledged: %+v", pending)
	}

	mustHealth(t, svc, health("app.example", "target", "p2", false))
	raised := mustHealth(t, svc, health("app.example", "target", "p3", false))
	if raised.State != StateActive || raised.Acknowledged {
		t.Fatalf("raised after a rejected ack = %+v, want active and unacknowledged", raised)
	}

	// Nothing to acknowledge for an unknown key or another kind.
	if _, err := svc.Acknowledge(ctx, KindTargetHealth, "none.example", "target"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Acknowledge unknown key err = %v, want ErrNotFound", err)
	}
	if _, err := svc.Acknowledge(ctx, KindTLSExpiry, "app.example", "target"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Acknowledge other kind err = %v, want ErrNotFound", err)
	}
	if _, err := svc.Acknowledge(ctx, KindTargetHealth, " ", "target"); err == nil {
		t.Fatalf("Acknowledge with a blank subject must fail")
	}
}

// Review (2): stale evidence is not a recovery. Successes that carry stale freshness only touch the
// freshness/evidence and never count toward resolving (AC2 intent).
func TestAlertStaleSuccessDoesNotResolve(t *testing.T) {
	ctx := context.Background()
	svc, _, _, _ := openService(t)
	clock := newFakeClock(testBaseTime)
	svc.clock = clock.now

	// Nothing tracked: a stale success creates nothing.
	if got := mustHealth(t, svc, HealthSample{Subject: "none.example", Source: "target", SampleID: "z", Success: true, Freshness: FreshnessStale}); got.ID != 0 {
		t.Fatalf("stale success without a row created %+v", got)
	}
	mustNotFound(t, svc, KindTargetHealth, "none.example", "target")

	raiseTarget(t, svc, clock, "app.example", "target")
	for i := 1; i <= 2; i++ {
		got := mustHealth(t, svc, HealthSample{
			Subject: "app.example", Source: "target", SampleID: fmt.Sprintf("stale%d", i),
			Success: true, Freshness: FreshnessStale, Evidence: "cached",
		})
		if got.Resolved || got.ConsecutiveSuccesses != 0 || got.ConsecutiveFailures != 3 {
			t.Fatalf("stale success #%d = %+v, want open with counters unchanged", i, got)
		}
		if got.Freshness != FreshnessStale || got.Evidence != "cached" {
			t.Fatalf("stale success #%d = %+v, want stale freshness and the new evidence", i, got)
		}
	}
	kept := mustGet(t, svc, KindTargetHealth, "app.example", "target")
	if kept.LastConsumedSample != "app.example/target/h3" || !kept.LastSuccess.IsZero() {
		t.Fatalf("stale successes were recorded as real measurements: %+v", kept)
	}

	// Real successes still resolve it.
	mustHealth(t, svc, health("app.example", "target", "ok1", true))
	if done := mustHealth(t, svc, health("app.example", "target", "ok2", true)); !done.Resolved {
		t.Fatalf("two fresh successes = %+v, want resolved", done)
	}

	// A pending row is left alone as well.
	mustHealth(t, svc, health("api.example", "target", "f1", false))
	mustHealth(t, svc, health("api.example", "target", "f2", false))
	got := mustHealth(t, svc, HealthSample{Subject: "api.example", Source: "target", SampleID: "s1", Success: true, Freshness: FreshnessStale})
	if got.ConsecutiveFailures != 2 || got.ConsecutiveSuccesses != 0 || got.State != StatePending {
		t.Fatalf("stale success on a pending row = %+v, want counters unchanged", got)
	}
	_ = ctx
}

// Review (4): success/failure interleaving. A failure resets the success run and a success resets
// the failure run, so an open alert needs two *consecutive* successes and a pending counter needs
// three *consecutive* failures.
func TestAlertConsecutiveCountersResetOnTheOtherOutcome(t *testing.T) {
	svc, _, _, _ := openService(t)
	clock := newFakeClock(testBaseTime)
	svc.clock = clock.now

	raiseTarget(t, svc, clock, "app.example", "target")
	if got := mustHealth(t, svc, health("app.example", "target", "a1", true)); got.ConsecutiveSuccesses != 1 || got.ConsecutiveFailures != 0 {
		t.Fatalf("success = %+v, want 1 success", got)
	}
	if got := mustHealth(t, svc, health("app.example", "target", "a2", false)); got.ConsecutiveSuccesses != 0 || got.ConsecutiveFailures != 1 || got.Resolved {
		t.Fatalf("failure after a success = %+v, want the success run reset", got)
	}
	got := mustHealth(t, svc, health("app.example", "target", "a3", true))
	if got.Resolved || got.ConsecutiveSuccesses != 1 {
		t.Fatalf("success after a failure = %+v, want still open with one success", got)
	}
	if got := mustHealth(t, svc, health("app.example", "target", "a4", true)); !got.Resolved {
		t.Fatalf("two consecutive successes = %+v, want resolved", got)
	}

	// Pending: failure, failure, success, failure, failure must not open (failure run was reset).
	for i, ok := range []bool{false, false, true, false, false} {
		got := mustHealth(t, svc, health("api.example", "target", fmt.Sprintf("b%d", i), ok))
		if got.State == StateActive {
			t.Fatalf("step %d opened the alert although failures were not consecutive: %+v", i, got)
		}
	}
	if got := mustHealth(t, svc, health("api.example", "target", "b5", false)); got.State != StateActive || got.ConsecutiveFailures != 3 {
		t.Fatalf("third consecutive failure = %+v, want active with 3 failures", got)
	}
}

// Review (4): TLS boundaries with positive controls on either side of every threshold.
func TestCertificateExpiryBoundariesBothSides(t *testing.T) {
	svc, _, _, _ := openService(t)
	clock := newFakeClock(testBaseTime)
	svc.clock = clock.now
	d := 24 * time.Hour

	cases := []struct {
		name  string
		left  time.Duration
		want  Severity
		valid bool // false means: expect no alert
	}{
		{"30d+1s healthy", 30*d + time.Second, "", false},
		{"30d info", 30 * d, SeverityInfo, true},
		{"14d+1s info", 14*d + time.Second, SeverityInfo, true},
		{"14d warning", 14 * d, SeverityWarning, true},
		{"7d+1s warning", 7*d + time.Second, SeverityWarning, true},
		{"7d critical", 7 * d, SeverityCritical, true},
		{"7d-1s critical", 7*d - time.Second, SeverityCritical, true},
		{"1s critical", time.Second, SeverityCritical, true},
		{"now expired", 0, SeverityCritical, true},
		{"1s ago expired", -time.Second, SeverityCritical, true},
	}
	for _, tc := range cases {
		got := mustTLS(t, svc, TLSSample{
			Subject: tc.name, Source: "tls", SampleID: tc.name, At: clock.now(), NotAfter: clock.now().Add(tc.left),
		})
		if tc.valid && got.Severity != tc.want {
			t.Fatalf("%s = %+v, want %s", tc.name, got, tc.want)
		}
		if !tc.valid && (got.ID != 0 || got.Severity != "") {
			t.Fatalf("%s = %+v, want no alert", tc.name, got)
		}
	}

	// Invalid wins over a perfectly valid far-future expiry; a zero NotAfter is unverifiable.
	for _, tc := range []struct {
		name   string
		sample TLSSample
	}{
		{"invalid far future", TLSSample{Subject: "inv", Source: "tls", SampleID: "i", NotAfter: clock.now().Add(365 * d), Invalid: true}},
		{"zero not-after", TLSSample{Subject: "zero", Source: "tls", SampleID: "z"}},
	} {
		if got := mustTLS(t, svc, tc.sample); got.Severity != SeverityCritical {
			t.Fatalf("%s = %+v, want critical", tc.name, got)
		}
	}
}

// Review (4): the TLS day thresholds come from the typed settings on every evaluation, not from
// constants (AC5 for the certificate side).
func TestCertificateThresholdsFollowSettings(t *testing.T) {
	ctx := context.Background()
	svc, _, settings, _ := openService(t)
	clock := newFakeClock(testBaseTime)
	svc.clock = clock.now
	d := 24 * time.Hour

	cfg := monitor.DefaultSettings()
	cfg.TLSInfoDays, cfg.TLSWarnDays, cfg.TLSCriticalDays = 60, 20, 5
	if err := settings.Set(ctx, cfg); err != nil {
		t.Fatalf("settings.Set: %v", err)
	}
	for _, tc := range []struct {
		name string
		left time.Duration
		want Severity
	}{
		{"61d healthy", 61 * d, ""},
		{"60d info", 60 * d, SeverityInfo},
		{"40d info (healthy under defaults)", 40 * d, SeverityInfo},
		{"20d warning", 20 * d, SeverityWarning},
		{"18d warning (info under defaults)", 18 * d, SeverityWarning},
		{"5d critical", 5 * d, SeverityCritical},
		{"6d warning (critical under defaults)", 6 * d, SeverityWarning},
	} {
		got := mustTLS(t, svc, TLSSample{
			Subject: tc.name, Source: "tls", SampleID: tc.name, NotAfter: clock.now().Add(tc.left),
		})
		if got.Severity != tc.want {
			t.Fatalf("%s = %+v, want %q", tc.name, got, tc.want)
		}
	}
}

// Review (4): the same sample identity is never applied twice by TLS and source evaluations either.
func TestAlertTLSAndSourceDedupSampleIDs(t *testing.T) {
	svc, _, _, _ := openService(t)
	clock := newFakeClock(testBaseTime)
	svc.clock = clock.now

	// TLS: a replayed sample neither resolves nor rewrites the alert.
	crit := mustTLS(t, svc, TLSSample{Subject: "tls.example", Source: "tls", SampleID: "t1", NotAfter: clock.now().Add(3 * 24 * time.Hour), Evidence: "first"})
	clock.advance(time.Minute)
	replay := mustTLS(t, svc, TLSSample{Subject: "tls.example", Source: "tls", SampleID: "t1", NotAfter: clock.now().Add(90 * 24 * time.Hour), Evidence: "second"})
	if replay.Resolved || replay.Severity != SeverityCritical || replay.Evidence != "first" || !replay.LastSeen.Equal(crit.LastSeen) {
		t.Fatalf("replayed TLS sample = %+v, want the unchanged alert %+v", replay, crit)
	}
	stored := mustGet(t, svc, KindTLSExpiry, "tls.example", "tls")
	if stored.Evidence != "first" || !stored.LastSeen.Equal(crit.LastSeen) {
		t.Fatalf("stored TLS alert changed by the replay: %+v", stored)
	}
	if fresh := mustTLS(t, svc, TLSSample{Subject: "tls.example", Source: "tls", SampleID: "t2", NotAfter: clock.now().Add(90 * 24 * time.Hour)}); !fresh.Resolved {
		t.Fatalf("a new healthy sample = %+v, want resolved", fresh)
	}

	// Source: a replayed failed read does not rewrite the freshness alert.
	first := mustSource(t, svc, SourceSample{Subject: "app.example", Source: "target", SampleID: "s1", Failed: true, Error: "first error"})
	clock.advance(time.Minute)
	replaySrc := mustSource(t, svc, SourceSample{Subject: "app.example", Source: "target", SampleID: "s1", Failed: true, Error: "second error"})
	if replaySrc.Evidence != "first error" || !replaySrc.LastSeen.Equal(first.LastSeen) {
		t.Fatalf("replayed source sample = %+v, want the unchanged alert %+v", replaySrc, first)
	}
	clock.advance(time.Minute)
	next := mustSource(t, svc, SourceSample{Subject: "app.example", Source: "target", SampleID: "s2", Failed: true, Error: "third error"})
	if next.ID != first.ID || next.Evidence != "third error" || !next.LastSeen.Equal(clock.now()) {
		t.Fatalf("a new source sample = %+v, want the same alert updated at %s", next, clock.now())
	}
}

// Review (4): alerts are keyed by (kind, subject, source); a sample of one key never lands on
// another, even when the sample identities collide.
func TestAlertKeysAreIndependentPerKindSubjectAndSource(t *testing.T) {
	ctx := context.Background()
	svc, _, _, _ := openService(t)
	clock := newFakeClock(testBaseTime)
	svc.clock = clock.now
	soon := clock.now().Add(3 * 24 * time.Hour)
	far := clock.now().Add(90 * 24 * time.Hour)

	// Health: same subject, two sources, identical sample ids.
	for _, src := range []string{"target-a", "target-b"} {
		for i := 1; i <= 3; i++ {
			mustHealth(t, svc, health("app.example", src, fmt.Sprintf("h%d", i), false))
		}
	}
	// Health: same source, two subjects, identical sample ids.
	for i := 1; i <= 3; i++ {
		mustHealth(t, svc, health("api.example", "target-a", fmt.Sprintf("h%d", i), false))
	}
	for _, key := range [][2]string{{"app.example", "target-a"}, {"app.example", "target-b"}, {"api.example", "target-a"}} {
		if got := mustGet(t, svc, KindTargetHealth, key[0], key[1]); got.ConsecutiveFailures != 3 || got.State != StateActive {
			t.Fatalf("health %v = %+v, want its own 3 failures", key, got)
		}
	}
	mustHealth(t, svc, health("app.example", "target-a", "ok1", true))
	mustHealth(t, svc, health("app.example", "target-a", "ok2", true))
	mustNotFound(t, svc, KindTargetHealth, "app.example", "target-a")
	for _, key := range [][2]string{{"app.example", "target-b"}, {"api.example", "target-a"}} {
		if got := mustGet(t, svc, KindTargetHealth, key[0], key[1]); got.ConsecutiveFailures != 3 {
			t.Fatalf("health %v = %+v, want it untouched by the other key's recovery", key, got)
		}
	}

	// TLS: same subject/two sources and same source/two subjects with identical sample ids.
	for _, key := range [][2]string{{"tls.example", "tls-a"}, {"tls.example", "tls-b"}, {"other.example", "tls-a"}} {
		if got := mustTLS(t, svc, TLSSample{Subject: key[0], Source: key[1], SampleID: "same", NotAfter: soon}); got.Severity != SeverityCritical || got.ID == 0 {
			t.Fatalf("TLS %v = %+v, want its own critical alert", key, got)
		}
	}
	mustTLS(t, svc, TLSSample{Subject: "tls.example", Source: "tls-a", SampleID: "fixed", NotAfter: far})
	mustNotFound(t, svc, KindTLSExpiry, "tls.example", "tls-a")
	mustGet(t, svc, KindTLSExpiry, "tls.example", "tls-b")
	mustGet(t, svc, KindTLSExpiry, "other.example", "tls-a")

	// Source: three keys with the same sample identity each get their own freshness alert.
	ids := map[int64]bool{}
	for _, key := range [][2]string{{"src.example", "reader-a"}, {"other-src.example", "reader-a"}, {"src.example", "reader-b"}} {
		got := mustSource(t, svc, SourceSample{Subject: key[0], Source: key[1], SampleID: "same", Failed: true, Error: "boom"})
		if got.ID == 0 || ids[got.ID] {
			t.Fatalf("source %v = %+v, want a distinct freshness alert", key, got)
		}
		ids[got.ID] = true
	}

	// Kinds: health, TLS and source alerts of one subject/source are three alerts that never resolve,
	// acknowledge or dedup each other.
	subj, src := "kinds.example", "shared"
	for i := 1; i <= 3; i++ {
		mustHealth(t, svc, health(subj, src, fmt.Sprintf("p%d", i), false))
	}
	mustTLS(t, svc, TLSSample{Subject: subj, Source: src, SampleID: "p3", NotAfter: soon})
	mustSource(t, svc, SourceSample{Subject: subj, Source: src, SampleID: "p3", Failed: true, Error: "boom"})
	h, tl, st := mustGet(t, svc, KindTargetHealth, subj, src), mustGet(t, svc, KindTLSExpiry, subj, src), mustGet(t, svc, KindSourceStale, subj, src)
	if h.ID == tl.ID || tl.ID == st.ID || h.ID == st.ID {
		t.Fatalf("kinds collapsed into one row: %d %d %d", h.ID, tl.ID, st.ID)
	}
	if _, err := svc.Acknowledge(ctx, KindTLSExpiry, subj, src); err != nil {
		t.Fatalf("Acknowledge TLS: %v", err)
	}
	if mustGet(t, svc, KindTargetHealth, subj, src).Acknowledged || mustGet(t, svc, KindSourceStale, subj, src).Acknowledged {
		t.Fatalf("acknowledging the TLS alert acknowledged another kind")
	}
	mustTLS(t, svc, TLSSample{Subject: subj, Source: src, SampleID: "p4", NotAfter: far})
	mustNotFound(t, svc, KindTLSExpiry, subj, src)
	if mustGet(t, svc, KindTargetHealth, subj, src).Resolved {
		t.Fatalf("a healthy certificate resolved the health alert")
	}
	mustHealth(t, svc, health(subj, src, "ok1", true))
	mustHealth(t, svc, health(subj, src, "ok2", true))
	mustNotFound(t, svc, KindTargetHealth, subj, src)
	mustGet(t, svc, KindSourceStale, subj, src)
}

// Review (4): maintenance is per subject; toggling one site never mutes or unmutes another.
func TestAlertMaintenanceIsPerSubject(t *testing.T) {
	ctx := context.Background()
	svc, _, _, _ := openService(t)
	clock := newFakeClock(testBaseTime)
	svc.clock = clock.now

	raiseTarget(t, svc, clock, "app.example", "target")
	raiseTarget(t, svc, clock, "api.example", "target")
	if err := svc.SetMaintenance(ctx, "app.example", true); err != nil {
		t.Fatalf("SetMaintenance: %v", err)
	}
	if !mustGet(t, svc, KindTargetHealth, "app.example", "target").Muted {
		t.Fatalf("app.example was not muted")
	}
	if mustGet(t, svc, KindTargetHealth, "api.example", "target").Muted {
		t.Fatalf("maintenance of app.example muted api.example")
	}

	// Mute api.example too, then unmute only app.example.
	if err := svc.SetMaintenance(ctx, "api.example", true); err != nil {
		t.Fatalf("SetMaintenance api: %v", err)
	}
	if err := svc.SetMaintenance(ctx, "app.example", false); err != nil {
		t.Fatalf("SetMaintenance off: %v", err)
	}
	if mustGet(t, svc, KindTargetHealth, "app.example", "target").Muted {
		t.Fatalf("app.example is still muted")
	}
	if !mustGet(t, svc, KindTargetHealth, "api.example", "target").Muted {
		t.Fatalf("unmuting app.example unmuted api.example")
	}
	if err := svc.SetMaintenance(ctx, " ", true); err == nil {
		t.Fatalf("SetMaintenance with a blank subject must fail")
	}
}

// Review (4): maintenance mutes new TLS and freshness alerts too, and clears when it ends.
func TestAlertMaintenanceMutesTLSAndSourceAlerts(t *testing.T) {
	ctx := context.Background()
	svc, _, _, _ := openService(t)
	clock := newFakeClock(testBaseTime)
	svc.clock = clock.now
	soon := clock.now().Add(3 * 24 * time.Hour)

	if err := svc.SetMaintenance(ctx, "app.example", true); err != nil {
		t.Fatalf("SetMaintenance: %v", err)
	}
	if got := mustTLS(t, svc, TLSSample{Subject: "app.example", Source: "tls", SampleID: "t1", NotAfter: soon}); !got.Muted {
		t.Fatalf("TLS alert during maintenance = %+v, want muted", got)
	}
	if got := mustSource(t, svc, SourceSample{Subject: "app.example", Source: "target", SampleID: "s1", Failed: true, Error: "boom"}); !got.Muted {
		t.Fatalf("freshness alert during maintenance = %+v, want muted", got)
	}
	if got := mustTLS(t, svc, TLSSample{Subject: "other.example", Source: "tls", SampleID: "t2", NotAfter: soon}); got.Muted {
		t.Fatalf("TLS alert of another site = %+v, want not muted", got)
	}

	if err := svc.SetMaintenance(ctx, "app.example", false); err != nil {
		t.Fatalf("SetMaintenance off: %v", err)
	}
	// Next real measurements present unmuted.
	if got := mustTLS(t, svc, TLSSample{Subject: "app.example", Source: "tls", SampleID: "t3", NotAfter: soon}); got.Muted {
		t.Fatalf("TLS alert after maintenance = %+v, want unmuted", got)
	}
	if got := mustSource(t, svc, SourceSample{Subject: "app.example", Source: "target", SampleID: "s2", Failed: true, Error: "boom"}); got.Muted {
		t.Fatalf("freshness alert after maintenance = %+v, want unmuted", got)
	}
}

// Review (4) and LOW (e): ListOpen shows only raised monitor alerts, newest first; pending counters
// and legacy pipeline alerts are not listed.
func TestAlertListOpenFiltersPendingAndLegacyRows(t *testing.T) {
	ctx := context.Background()
	svc, st, _, _ := openService(t)
	clock := newFakeClock(testBaseTime)
	svc.clock = clock.now

	if _, err := st.Queries().InsertAlert(ctx, db.InsertAlertParams{
		Kind: change.AlertPolicyMismatch, Source: "headscale", FirstSeenAt: stamp(clock.now()), LastSeenAt: stamp(clock.now()),
	}); err != nil {
		t.Fatalf("InsertAlert legacy: %v", err)
	}
	// Even a non-monitor row that carries a severity is not a monitor alert.
	if _, err := st.DB().ExecContext(ctx, `UPDATE alerts SET severity = 'critical' WHERE kind = ?`, change.AlertPolicyMismatch); err != nil {
		t.Fatalf("set legacy severity: %v", err)
	}
	older := raiseTarget(t, svc, clock, "older.example", "target")
	clock.advance(time.Minute)
	mustHealth(t, svc, health("pending.example", "target", "p1", false))
	clock.advance(time.Minute)
	newer := raiseTarget(t, svc, clock, "newer.example", "target")

	open, err := svc.ListOpen(ctx)
	if err != nil {
		t.Fatalf("ListOpen: %v", err)
	}
	if len(open) != 2 || open[0].ID != newer.ID || open[1].ID != older.ID {
		t.Fatalf("ListOpen = %+v, want [newer, older] only", open)
	}
}

// failingSettings is a SettingsReader that always fails.
type failingSettings struct{ err error }

func (f failingSettings) Get(context.Context) (monitor.Settings, error) {
	return monitor.Settings{}, f.err
}

// Review (4): an unreadable settings store never falls back silently to defaults and writes
// nothing (fail safe); a nil reader uses the documented defaults.
func TestAlertSettingsReadErrorIsSurfaced(t *testing.T) {
	ctx := context.Background()
	_, st, _, _ := openService(t)
	boom := errors.New("settings unreadable")
	svc := New(NewStore(st.DB(), st.Queries()), failingSettings{err: boom})

	if got, err := svc.RecordHealth(ctx, health("app.example", "target", "h1", false)); !errors.Is(err, boom) {
		t.Fatalf("RecordHealth = %+v err = %v, want the settings error", got, err)
	}
	if got, err := svc.RecordTLS(ctx, TLSSample{Subject: "app.example", Source: "tls", SampleID: "t1", Invalid: true}); !errors.Is(err, boom) {
		t.Fatalf("RecordTLS = %+v err = %v, want the settings error", got, err)
	}
	if n := tableCounts(t, st)["alerts"]; n != 0 {
		t.Fatalf("alerts rows = %d after unreadable settings, want 0", n)
	}

	// Without a reader the documented defaults apply.
	plain := New(NewStore(st.DB(), st.Queries()), nil)
	for i := 1; i <= 3; i++ {
		got, err := plain.RecordHealth(ctx, health("app.example", "target", fmt.Sprintf("h%d", i), false))
		if err != nil {
			t.Fatalf("RecordHealth with default settings: %v", err)
		}
		if (i < 3) != (got.State == StatePending) {
			t.Fatalf("failure #%d = %+v, want the default 3-failure hysteresis", i, got)
		}
	}
}

// Review (4): every timestamp follows the advancing fake clock; acknowledgement keeps its first time.
func TestAlertTimestampsFollowTheClock(t *testing.T) {
	ctx := context.Background()
	svc, st, _, _ := openService(t)
	clock := newFakeClock(testBaseTime)
	svc.clock = clock.now
	t0 := clock.now()
	step := func() time.Time { clock.advance(time.Minute); return clock.now() }

	first := mustHealth(t, svc, health("app.example", "target", "f1", false))
	if !first.FirstSeen.Equal(t0) || !first.LastSeen.Equal(t0) {
		t.Fatalf("first failure = %+v, want first/last seen %s", first, t0)
	}
	t1 := step()
	if second := mustHealth(t, svc, health("app.example", "target", "f2", false)); !second.FirstSeen.Equal(t0) || !second.LastSeen.Equal(t1) {
		t.Fatalf("second failure = %+v, want first %s last %s", second, t0, t1)
	}
	t2 := step()
	raised := mustHealth(t, svc, health("app.example", "target", "f3", false))
	if !raised.FirstSeen.Equal(t0) || !raised.LastSeen.Equal(t2) || !raised.LastSuccess.IsZero() {
		t.Fatalf("raised = %+v, want first %s last %s and no success yet", raised, t0, t2)
	}

	t3 := step()
	acked, err := svc.Acknowledge(ctx, KindTargetHealth, "app.example", "target")
	if err != nil || !acked.AcknowledgedAt.Equal(t3) {
		t.Fatalf("Acknowledge = %+v err = %v, want acknowledged at %s", acked, err, t3)
	}
	t4 := step()
	one := mustHealth(t, svc, health("app.example", "target", "s1", true))
	if !one.LastSeen.Equal(t4) || !one.LastSuccess.Equal(t4) || !one.AcknowledgedAt.Equal(t3) {
		t.Fatalf("first success = %+v, want last seen/success %s and the ack kept at %s", one, t4, t3)
	}
	step()
	again, err := svc.Acknowledge(ctx, KindTargetHealth, "app.example", "target")
	if err != nil || !again.AcknowledgedAt.Equal(t3) {
		t.Fatalf("second Acknowledge = %+v err = %v, want the first time %s kept", again, err, t3)
	}
	if stored := mustGet(t, svc, KindTargetHealth, "app.example", "target"); !stored.AcknowledgedAt.Equal(t3) {
		t.Fatalf("stored ack time = %s, want %s", stored.AcknowledgedAt, t3)
	}

	t6 := step()
	done := mustHealth(t, svc, health("app.example", "target", "s2", true))
	if !done.Resolved || !done.ResolvedAt.Equal(t6) {
		t.Fatalf("resolved = %+v, want resolved at %s", done, t6)
	}
	var resolvedAt string
	if err := st.DB().QueryRowContext(ctx, `SELECT resolved_at FROM alerts WHERE id = ?`, raised.ID).Scan(&resolvedAt); err != nil {
		t.Fatalf("read resolved_at: %v", err)
	}
	if resolvedAt != stamp(t6) {
		t.Fatalf("stored resolved_at = %s, want %s", resolvedAt, stamp(t6))
	}

	// An explicit sample time wins over the service clock.
	explicit := t6.Add(-time.Hour)
	if got := mustHealth(t, svc, HealthSample{Subject: "api.example", Source: "target", SampleID: "e1", At: explicit}); !got.LastSeen.Equal(explicit) {
		t.Fatalf("explicit sample time = %+v, want last seen %s", got, explicit)
	}
}

// Review (4): the counters of a pending alert survive a restart, so the third failure after the
// restart still opens the same row; the maintenance preference survives as well.
func TestAlertPendingCountersAndMaintenanceSurviveRestart(t *testing.T) {
	ctx := context.Background()
	svc, st, _, path := openService(t)
	clock := newFakeClock(testBaseTime)
	svc.clock = clock.now

	if err := svc.SetMaintenance(ctx, "quiet.example", true); err != nil {
		t.Fatalf("SetMaintenance: %v", err)
	}
	mustHealth(t, svc, health("app.example", "target", "p1", false))
	second := mustHealth(t, svc, health("app.example", "target", "p2", false))
	if second.State != StatePending || second.ConsecutiveFailures != 2 {
		t.Fatalf("second failure = %+v, want pending with 2", second)
	}

	svc2, _ := reopenService(t, st, path)
	svc2.clock = clock.now
	replay := mustHealth(t, svc2, health("app.example", "target", "p2", false))
	if replay.ID != second.ID || replay.ConsecutiveFailures != 2 {
		t.Fatalf("replay after restart = %+v, want the pending row with 2 failures", replay)
	}
	opened := mustHealth(t, svc2, health("app.example", "target", "p3", false))
	if opened.ID != second.ID || opened.State != StateActive || opened.ConsecutiveFailures != 3 {
		t.Fatalf("third failure after restart = %+v, want the same row active with 3 failures", opened)
	}

	// Maintenance is still on for the quiet site after the restart.
	for i := 1; i <= 3; i++ {
		mustHealth(t, svc2, health("quiet.example", "target", fmt.Sprintf("q%d", i), false))
	}
	if !mustGet(t, svc2, KindTargetHealth, "quiet.example", "target").Muted {
		t.Fatalf("maintenance did not survive the restart")
	}
	if mustGet(t, svc2, KindTargetHealth, "app.example", "target").Muted {
		t.Fatalf("maintenance leaked to another site after the restart")
	}
}

// LOW (c): an acknowledged TLS alert that gets worse is shown to devops again; a lower or equal
// severity keeps the acknowledgement.
func TestAlertAcknowledgementResetsWhenSeverityIncreases(t *testing.T) {
	ctx := context.Background()
	svc, _, _, _ := openService(t)
	clock := newFakeClock(testBaseTime)
	svc.clock = clock.now
	d := 24 * time.Hour
	sample := func(id string, left time.Duration) Alert {
		return mustTLS(t, svc, TLSSample{Subject: "tls.example", Source: "tls", SampleID: id, NotAfter: clock.now().Add(left)})
	}

	if got := sample("a", 20*d); got.Severity != SeverityInfo {
		t.Fatalf("info = %+v", got)
	}
	if _, err := svc.Acknowledge(ctx, KindTLSExpiry, "tls.example", "tls"); err != nil {
		t.Fatalf("Acknowledge: %v", err)
	}
	if got := sample("b", 19*d); got.Severity != SeverityInfo || !got.Acknowledged {
		t.Fatalf("same severity = %+v, want the acknowledgement kept", got)
	}
	warn := sample("c", 10*d)
	if warn.Severity != SeverityWarning || warn.Acknowledged || warn.State != StateActive {
		t.Fatalf("escalated to warning = %+v, want active and unacknowledged", warn)
	}
	if _, err := svc.Acknowledge(ctx, KindTLSExpiry, "tls.example", "tls"); err != nil {
		t.Fatalf("Acknowledge warning: %v", err)
	}
	if got := sample("d", 20*d); got.Severity != SeverityInfo || !got.Acknowledged {
		t.Fatalf("de-escalated = %+v, want the acknowledgement kept", got)
	}
	crit := sample("e", 3*d)
	if crit.Severity != SeverityCritical || crit.Acknowledged {
		t.Fatalf("escalated to critical = %+v, want unacknowledged", crit)
	}
	if stored := mustGet(t, svc, KindTLSExpiry, "tls.example", "tls"); stored.Acknowledged {
		t.Fatalf("stored alert = %+v, want the acknowledgement cleared", stored)
	}

	// warning -> critical resets as well.
	if got := sample("f", 10*d); got.Severity != SeverityWarning {
		t.Fatalf("de-escalated to warning = %+v", got)
	}
	if _, err := svc.Acknowledge(ctx, KindTLSExpiry, "tls.example", "tls"); err != nil {
		t.Fatalf("Acknowledge warning again: %v", err)
	}
	if got := sample("g", 3*d); got.Severity != SeverityCritical || got.Acknowledged {
		t.Fatalf("warning -> critical = %+v, want unacknowledged", got)
	}
}

// LOW (d): a recovered source read is not a fresh measurement. The health alert stays stale until
// its next real sample, which presents fresh again.
func TestAlertFreshnessReturnsWithTheNextSample(t *testing.T) {
	svc, _, _, _ := openService(t)
	clock := newFakeClock(testBaseTime)
	svc.clock = clock.now

	raiseTarget(t, svc, clock, "app.example", "target")
	mustSource(t, svc, SourceSample{Subject: "app.example", Source: "target", SampleID: "s1", Failed: true, Error: "boom"})
	mustSource(t, svc, SourceSample{Subject: "app.example", Source: "target", SampleID: "s2"})
	if got := mustGet(t, svc, KindTargetHealth, "app.example", "target"); got.Freshness != FreshnessStale {
		t.Fatalf("health after source recovery = %+v, want stale until the next sample", got)
	}
	got := mustHealth(t, svc, health("app.example", "target", "h4", false))
	if got.Freshness != FreshnessFresh {
		t.Fatalf("health after the next sample = %+v, want fresh", got)
	}
}

// LOW (e): the monitor kinds stay disjoint from every F1/F3 pipeline kind, because the legacy
// TouchAlert/ResolveAlerts/ResolveAlertKind queries match on kind only.
func TestAlertMonitorKindsAreDisjointFromPipelineKinds(t *testing.T) {
	pipeline := []string{
		change.AlertPolicyMismatch, change.AlertPolicyExpireFailed, change.AlertPolicyUnverified,
		change.AlertPolicyStale, change.AlertPolicyBookkeepingFailed,
		change.AlertSiteDrift, change.AlertSiteUnverified, change.AlertSitePartial,
		change.AlertSiteRollbackFailed, change.AlertSiteCaddyFile, change.AlertSiteDNSUnverified,
		change.AlertSiteBookkeepingFailed,
		pipesync.AlertReadFailed, pipesync.AlertKeyRevokeFailed,
		gitlog.AlertGitSecret, gitlog.AlertGitFailed,
	}
	monitorKinds := []string{KindTargetHealth, KindTLSExpiry, KindSourceStale}
	for _, kind := range monitorKinds {
		if !isMonitorKind(kind) {
			t.Fatalf("%s is not recognised as a monitor kind", kind)
		}
	}
	for _, kind := range pipeline {
		if isMonitorKind(kind) || strings.HasPrefix(kind, "monitor_") {
			t.Fatalf("pipeline kind %q collides with the monitor kind namespace", kind)
		}
		for _, m := range monitorKinds {
			if kind == m {
				t.Fatalf("pipeline kind %q equals a monitor kind", kind)
			}
		}
	}
}

// LOW (e): a monitor evaluation that shares a source name with an open F1/F3 alert never resolves,
// touches or counts that alert.
func TestAlertMonitorOutcomesLeavePipelineAlertsOpen(t *testing.T) {
	ctx := context.Background()
	svc, st, _, _ := openService(t)
	clock := newFakeClock(testBaseTime)
	svc.clock = clock.now
	legacy := map[string]string{
		change.AlertPolicyMismatch: "headscale",
		pipesync.AlertReadFailed:   "headscale",
	}
	for kind, source := range legacy {
		if _, err := st.Queries().InsertAlert(ctx, db.InsertAlertParams{
			Kind: kind, Source: source, FirstSeenAt: stamp(clock.now()), LastSeenAt: stamp(clock.now()),
		}); err != nil {
			t.Fatalf("InsertAlert %s: %v", kind, err)
		}
	}

	raiseTarget(t, svc, clock, "app.example", "headscale")
	mustHealth(t, svc, health("app.example", "headscale", "ok1", true))
	mustHealth(t, svc, health("app.example", "headscale", "ok2", true))
	mustNotFound(t, svc, KindTargetHealth, "app.example", "headscale")
	mustTLS(t, svc, TLSSample{Subject: "app.example", Source: "headscale", SampleID: "t1", NotAfter: clock.now().Add(3 * 24 * time.Hour)})
	mustTLS(t, svc, TLSSample{Subject: "app.example", Source: "headscale", SampleID: "t2", NotAfter: clock.now().Add(90 * 24 * time.Hour)})
	mustSource(t, svc, SourceSample{Subject: "app.example", Source: "headscale", SampleID: "s1", Failed: true, Error: "boom"})
	mustSource(t, svc, SourceSample{Subject: "app.example", Source: "headscale", SampleID: "s2"})

	rows, err := st.Queries().ListOpenAlerts(ctx)
	if err != nil {
		t.Fatalf("ListOpenAlerts: %v", err)
	}
	open := map[string]bool{}
	for _, r := range rows {
		if r.Subject == "" {
			open[r.Kind] = true
		}
	}
	for kind := range legacy {
		if !open[kind] {
			t.Fatalf("pipeline alert %q was resolved by a monitor outcome; open = %v", kind, open)
		}
	}
}

// Review (4): samples without an identity are always counted (the dedup guard needs an id).
func TestAlertSamplesWithoutIDAreAlwaysCounted(t *testing.T) {
	svc, _, _, _ := openService(t)
	clock := newFakeClock(testBaseTime)
	svc.clock = clock.now

	var got Alert
	for i := 1; i <= 3; i++ {
		got = mustHealth(t, svc, health("app.example", "target", "", false))
		if got.ConsecutiveFailures != i {
			t.Fatalf("failure #%d without id = %+v, want %d failures", i, got, i)
		}
	}
	if got.State != StateActive {
		t.Fatalf("3 failures without ids = %+v, want active", got)
	}
	soon := clock.now().Add(3 * 24 * time.Hour)
	first := mustTLS(t, svc, TLSSample{Subject: "tls.example", Source: "tls", NotAfter: soon, Evidence: "one"})
	clock.advance(time.Minute)
	if again := mustTLS(t, svc, TLSSample{Subject: "tls.example", Source: "tls", NotAfter: soon, Evidence: "two"}); again.Evidence != "two" || !again.LastSeen.After(first.LastSeen) {
		t.Fatalf("TLS sample without id = %+v, want it applied", again)
	}
	mustSource(t, svc, SourceSample{Subject: "app.example", Source: "target", Failed: true, Error: "one"})
	clock.advance(time.Minute)
	if again := mustSource(t, svc, SourceSample{Subject: "app.example", Source: "target", Failed: true, Error: "two"}); again.Evidence != "two" {
		t.Fatalf("source sample without id = %+v, want it applied", again)
	}
}

// Review (4): source loss marks both the health and the TLS alert of the key stale, resolving
// neither.
func TestAlertSourceLossMarksTLSAlertStale(t *testing.T) {
	svc, _, _, _ := openService(t)
	clock := newFakeClock(testBaseTime)
	svc.clock = clock.now

	mustTLS(t, svc, TLSSample{Subject: "app.example", Source: "target", SampleID: "t1", NotAfter: clock.now().Add(3 * 24 * time.Hour)})
	raiseTarget(t, svc, clock, "app.example", "target")
	mustSource(t, svc, SourceSample{Subject: "app.example", Source: "target", SampleID: "s1", Failed: true, Error: "boom"})
	for _, kind := range []string{KindTLSExpiry, KindTargetHealth} {
		if got := mustGet(t, svc, kind, "app.example", "target"); got.Freshness != FreshnessStale || got.Resolved {
			t.Fatalf("%s after source loss = %+v, want open and stale", kind, got)
		}
	}
}

// Review (4): evidence is stored as a trimmed, one-line, bounded, valid-UTF-8 summary.
func TestAlertEvidenceIsSanitized(t *testing.T) {
	long := strings.Repeat("a", 300)
	for _, tc := range []struct{ name, in, want string }{
		{"trim", "  x  ", "x"},
		{"trim before newline replace", "  x\n", "x"},
		{"newlines", "a\nb\r\nc", "a b  c"},
		{"bounded", long, long[:maxEvidence]},
		{"invalid utf8", "ab\xffcd", "abcd"},
		{"cut rune dropped", strings.Repeat("a", maxEvidence-1) + "é", strings.Repeat("a", maxEvidence-1)},
	} {
		if got := sanitizeEvidence(tc.in); got != tc.want {
			t.Fatalf("%s: sanitizeEvidence(%q) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}

	svc, _, _, _ := openService(t)
	h := mustHealth(t, svc, HealthSample{Subject: "app.example", Source: "target", SampleID: "e", Evidence: "line1\nline2"})
	if h.Evidence != "line1 line2" {
		t.Fatalf("health evidence = %q, want a single line", h.Evidence)
	}
	tl := mustTLS(t, svc, TLSSample{Subject: "app.example", Source: "tls", SampleID: "e", Invalid: true, Evidence: "a\nb"})
	if tl.Evidence != "a b" {
		t.Fatalf("TLS evidence = %q, want a single line", tl.Evidence)
	}
	src := mustSource(t, svc, SourceSample{Subject: "app.example", Source: "target", SampleID: "e", Failed: true, Error: "x\ny"})
	if src.Evidence != "x y" {
		t.Fatalf("source evidence = %q, want a single line", src.Evidence)
	}
}

// Review (4): subject and source are required by every entry point and nothing is written without.
func TestAlertRequiresSubjectAndSource(t *testing.T) {
	ctx := context.Background()
	svc, st, _, _ := openService(t)
	for _, key := range [][2]string{{"", "target"}, {"  ", "target"}, {"app.example", ""}, {"app.example", " "}} {
		if _, err := svc.RecordHealth(ctx, health(key[0], key[1], "x", false)); err == nil {
			t.Fatalf("RecordHealth %q/%q: want an error", key[0], key[1])
		}
		if _, err := svc.RecordTLS(ctx, TLSSample{Subject: key[0], Source: key[1], SampleID: "x", Invalid: true}); err == nil {
			t.Fatalf("RecordTLS %q/%q: want an error", key[0], key[1])
		}
		if _, err := svc.RecordSource(ctx, SourceSample{Subject: key[0], Source: key[1], SampleID: "x", Failed: true}); err == nil {
			t.Fatalf("RecordSource %q/%q: want an error", key[0], key[1])
		}
		if _, err := svc.Acknowledge(ctx, KindTargetHealth, key[0], key[1]); err == nil {
			t.Fatalf("Acknowledge %q/%q: want an error", key[0], key[1])
		}
	}
	if n := tableCounts(t, st)["alerts"]; n != 0 {
		t.Fatalf("alerts rows = %d, want 0", n)
	}
}

// Review (4): a corrupt or unreadable maintenance preference fails the evaluation instead of
// silently muting or unmuting (fail safe), and writes nothing.
func TestAlertMaintenanceReadFailuresAreSurfaced(t *testing.T) {
	ctx := context.Background()
	svc, st, _, _ := openService(t)
	if _, err := st.DB().ExecContext(ctx,
		`INSERT INTO settings (key, value, updated_at) VALUES (?, 'maybe', '2026-10-04T12:00:00.000Z')`,
		maintenanceKey("app.example")); err != nil {
		t.Fatalf("seed corrupt maintenance: %v", err)
	}
	if got, err := svc.RecordHealth(ctx, health("app.example", "target", "h1", false)); err == nil {
		t.Fatalf("RecordHealth with a corrupt maintenance setting = %+v, want an error", got)
	}
	if n := tableCounts(t, st)["alerts"]; n != 0 {
		t.Fatalf("alerts rows = %d after a corrupt maintenance setting, want 0", n)
	}

	// Unreadable settings table (no typed reader, so only the maintenance read touches it).
	plain := New(NewStore(st.DB(), st.Queries()), nil)
	if _, err := st.DB().ExecContext(ctx, `ALTER TABLE settings RENAME TO settings_gone`); err != nil {
		t.Fatalf("rename settings: %v", err)
	}
	if got, err := plain.RecordHealth(ctx, health("api.example", "target", "h1", false)); err == nil {
		t.Fatalf("RecordHealth with an unreadable settings table = %+v, want an error", got)
	}
}
