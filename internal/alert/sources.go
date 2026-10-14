// sources.go is the F4-025 bridge from the ready F4 store results to the monitor alerts
// (P-02.1/P-02.4/P-02.6, R3 B-06/B-07, ADR 0032 proposed).
//
// It reads only local stores: the measurement observations F4-018 wrote (F4-017), the open legacy
// F1/F3 pipeline alerts, the newest sync run and the changes waiting for approval (Y-03.4). It
// hands the stored observations to the alert service with a stable (kind, subject, source) key and
// surfaces the sync/pending results as read-only views. It never calls Headscale, Zitadel, Caddy or
// a probe, never writes outside the alerts table, and never copies a legacy alarm into a monitor
// one: an existing reconcile_read_failed or a policy/site critical is shown as it is and is never
// resolved in bulk. The periodic call and the source-loss tracking belong to F4-038; the binary
// composition to F4-031.
//
// Cleaning removed sites (round review C-M2, [Ö]): the health runner deletes the observation rows it
// no longer measures (internal/health); this reader deletes nothing. It counts only the newest row
// per (category, subject), so a row left by a changed path or endpoint never masks the current one,
// and after a COMPLETE site-list read it resolves the monitor alerts of a host no current site lists
// any more ("site removed", never "recovered").
package alert

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	probe "github.com/nesiler/tagcess/internal/health"
	"github.com/nesiler/tagcess/internal/monitor"
	"github.com/nesiler/tagcess/internal/store/db"
)

// SourceKind names which stored result surface a view line comes from.
type SourceKind string

const (
	// SourceObservations is a measurement row of the F4-017 observation store.
	SourceObservations SourceKind = "observations"
	// SourceSyncRuns is a sync result: an open legacy sync alert or the newest sync run.
	SourceSyncRuns SourceKind = "sync_runs"
	// SourcePendingChanges is a change waiting for approval.
	SourcePendingChanges SourceKind = "pending_changes"
)

// SourceStatus is the completeness/freshness of one source read, not an alarm severity. A failed or
// incomplete read is stale/unknown and never counts as a recovery of an existing alert.
type SourceStatus string

const (
	// SourceFresh: the source was read completely.
	SourceFresh SourceStatus = "fresh"
	// SourceStale: the source could not be read but its stale state is shown.
	SourceStale SourceStatus = "stale"
	// SourceUnknown: the source could not be read or the stored result is incomplete.
	SourceUnknown SourceStatus = "unknown"
)

// Alert source keys of the monitor rows the bridge raises. They extend the (kind, subject, source)
// key of the F4-023 service; the health kind is shared by target and Caddy gate and told apart by
// the source.
const (
	// AlertSourceTarget is the target-health alert source.
	AlertSourceTarget = "target"
	// AlertSourceGate is the Caddy access-gate health alert source.
	AlertSourceGate = "caddy_gate"
	// AlertSourceTLS is the presented-leaf expiry alert source.
	AlertSourceTLS = "tls"
	// AlertSourceStore is the observation-store freshness alert source.
	AlertSourceStore = "observation_store"
)

// Fixed subjects of the read-only sync/pending views.
const (
	// SubjectSync names the sync source in the unified view.
	SubjectSync = "sync"
	// SubjectPendingChange names a pending change before its id is appended.
	SubjectPendingChange = "pending_changes"
)

// SourceView is one line of the unified dashboard alert view: where it came from, the alert key it
// describes, its lifecycle/evidence and how complete the read was. It carries no secret, body or
// header content.
type SourceView struct {
	Source    SourceKind
	Subject   string
	Origin    string // the alert's source key (or the run trigger / change kind)
	AlertKind string
	Severity  Severity
	State     State
	// Freshness is the alert's evidence freshness; Status is the read completeness.
	Freshness  string
	Status     SourceStatus
	Evidence   string
	ObservedAt time.Time
	LastSeen   time.Time
}

// ObservationSource reads the stored measurement rows of one site (F4-017). It is read-only; the
// generated *db.Queries satisfies it.
type ObservationSource interface {
	ListObservationsBySite(ctx context.Context, site string) ([]db.Observation, error)
}

// LegacyAlertSource reads the open legacy F1/F3 pipeline alerts. It is read-only; *db.Queries
// satisfies it.
type LegacyAlertSource interface {
	ListOpenAlerts(ctx context.Context) ([]db.Alert, error)
}

// SyncRunSource reads the newest reconcile run (Y-05.2). It is read-only; *db.Queries satisfies
// it.
type SyncRunSource interface {
	GetLatestSyncRun(ctx context.Context) (db.SyncRun, error)
}

// PendingChangeSource reads the changes waiting for approval (Y-03.4). It is read-only; *db.Queries
// satisfies it.
type PendingChangeSource interface {
	ListPendingChanges(ctx context.Context) ([]db.Change, error)
}

// SourcesConfig wires the read-only store surfaces. Sites is the current site list; the periodic
// caller (F4-038) or the binary (F4-031) supplies it.
type SourcesConfig struct {
	Sites        func(ctx context.Context) ([]string, error)
	Observations ObservationSource
	LegacyAlerts LegacyAlertSource
	SyncRuns     SyncRunSource
	Pending      PendingChangeSource
	// Settings supplies the measurement intervals that bound how old an attempt may be before it is
	// stale. Optional: nil (or a read error) uses the documented defaults.
	Settings func(ctx context.Context) (monitor.Settings, error)
}

// Sources evaluates the ready store results and applies/raises the monitor alerts. It holds only the
// alert service and read-only store surfaces; there is no external client to call.
type Sources struct {
	svc *Service
	cfg SourcesConfig
}

// NewSources validates the wiring. A missing surface is a wiring error rather than a silently
// healthy source.
func NewSources(svc *Service, cfg SourcesConfig) (*Sources, error) {
	switch {
	case svc == nil:
		return nil, errors.New("alert: sources need the alert service")
	case cfg.Sites == nil:
		return nil, errors.New("alert: sources need the site list")
	case cfg.Observations == nil:
		return nil, errors.New("alert: sources need the observation reader")
	case cfg.LegacyAlerts == nil:
		return nil, errors.New("alert: sources need the legacy alert reader")
	case cfg.SyncRuns == nil:
		return nil, errors.New("alert: sources need the sync run reader")
	case cfg.Pending == nil:
		return nil, errors.New("alert: sources need the pending change reader")
	}
	return &Sources{svc: svc, cfg: cfg}, nil
}

// Evaluate reads every source once and returns the unified view. A source that cannot be read is
// shown stale/unknown and does not recover its alerts; its error is joined into the returned error
// while the other sources still run (fail safe: never widen access, never lose the last state).
func (s *Sources) Evaluate(ctx context.Context) ([]SourceView, error) {
	views, errs := s.evaluateObservations(ctx)
	if err := s.evaluateSync(ctx, &views); err != nil {
		errs = append(errs, err)
	}
	if err := s.evaluatePending(ctx, &views); err != nil {
		errs = append(errs, err)
	}
	return views, errors.Join(errs...)
}

// evaluateObservations reads every current site's observations and applies the health/TLS lifecycle.
// A site read failure raises the store freshness alert and keeps the health/TLS alerts untouched; a
// complete read clears only the freshness alert, never a health/TLS alert.
func (s *Sources) evaluateObservations(ctx context.Context) ([]SourceView, []error) {
	sites, err := s.cfg.Sites(ctx)
	if err != nil {
		view := SourceView{
			Source: SourceObservations, Origin: AlertSourceStore, AlertKind: KindSourceStale,
			Severity: SeverityWarning, State: StateActive, Freshness: FreshnessStale,
			Status: SourceStale, Evidence: "site list could not be read",
		}
		return []SourceView{view}, []error{fmt.Errorf("alert: sources: site list: %w", err)}
	}

	now := s.svc.at(time.Time{})
	cfg := monitor.DefaultSettings()
	if s.cfg.Settings != nil {
		if got, serr := s.cfg.Settings(ctx); serr == nil {
			cfg = got
		}
	}

	var views []SourceView
	var errs []error
	complete := true
	current := map[string]bool{} // alert subjects of the current sites' observations
	for _, site := range sites {
		rows, rerr := s.cfg.Observations.ListObservationsBySite(ctx, site)
		if rerr != nil {
			if _, e := s.svc.RecordSource(ctx, SourceSample{
				Subject: site, Source: AlertSourceStore, Failed: true,
				Error: "observation store could not be read",
			}); e != nil {
				errs = append(errs, e)
			}
			views = append(views, SourceView{
				Source: SourceObservations, Subject: site, Origin: AlertSourceStore,
				AlertKind: KindSourceStale, Severity: SeverityWarning, State: StateActive,
				Freshness: FreshnessStale, Status: SourceStale,
				Evidence: "observation store could not be read",
			})
			errs = append(errs, fmt.Errorf("alert: sources: observations %q: %w", site, rerr))
			complete = false
			continue
		}
		// A complete read clears the store freshness alert; it never resolves a health/TLS alert.
		if _, e := s.svc.RecordSource(ctx, SourceSample{
			Subject: site, Source: AlertSourceStore, Failed: false,
		}); e != nil {
			errs = append(errs, e)
		}
		for _, row := range rows {
			current[probe.ObservationSubject(row)] = true
		}
		// Only the newest attempt per (category, subject) counts: an older row of a changed key is
		// frozen and would otherwise be replayed against the current one every round.
		for _, row := range probe.NewestPerSubject(rows) {
			v, e := s.applyObservation(ctx, row, now, cfg)
			if e != nil {
				errs = append(errs, e)
			}
			views = append(views, v...)
		}
	}
	if complete {
		if e := s.svc.resolveRemoved(ctx, current); e != nil {
			errs = append(errs, e)
		}
	}
	return views, errs
}

// applyObservation maps one stored row to its alarm surface. Target and Caddy gate rows are health
// checks, a TLS row is the presented-leaf expiry, a config_risk row is a read-only risk view.
func (s *Sources) applyObservation(ctx context.Context, row db.Observation, now time.Time, cfg monitor.Settings) ([]SourceView, error) {
	switch row.Category {
	case AlertSourceTarget, AlertSourceGate:
		return s.applyHealth(ctx, row, now, cfg)
	case AlertSourceTLS:
		return s.applyTLS(ctx, row, now, cfg)
	case "config_risk":
		return []SourceView{configRiskView(row)}, nil
	default:
		return []SourceView{observationView(row, SourceUnknown, "unknown observation category")}, nil
	}
}

// applyHealth applies the hysteresis lifecycle of one target/gate attempt. An incomplete stored
// result (no attempt, or a success without a last-good observation) is never handed to the service.
func (s *Sources) applyHealth(ctx context.Context, row db.Observation, now time.Time, cfg monitor.Settings) ([]SourceView, error) {
	if row.LastAttemptAt == "" {
		return []SourceView{observationView(row, SourceUnknown, "no attempt recorded")}, nil
	}
	if row.Success == 1 && row.ObservedAt == "" {
		return []SourceView{observationView(row, SourceUnknown, "incomplete observation")}, nil
	}
	freshness := s.freshness(ctx, row, now, cfg)
	a, err := s.svc.RecordHealth(ctx, HealthSample{
		Subject:   observationSubject(row),
		Source:    row.Category,
		SampleID:  observationSampleID(row),
		Success:   row.Success == 1,
		Freshness: freshness,
		Evidence:  healthEvidence(row),
	})
	if err != nil {
		return nil, err
	}
	v := alertView(SourceObservations, observationSubject(row), row.Category, a)
	if freshness == FreshnessStale || v.Freshness == "" { // an over-age or failed attempt is never shown fresh
		v.Freshness = freshness
	}
	return []SourceView{v}, nil
}

// applyTLS applies the presented-leaf expiry lifecycle of one TLS row. A row with no verified leaf
// and no verification error is not a certificate result: it is shown unknown and resolves nothing.
func (s *Sources) applyTLS(ctx context.Context, row db.Observation, now time.Time, cfg monitor.Settings) ([]SourceView, error) {
	if row.LastAttemptAt == "" {
		return []SourceView{observationView(row, SourceUnknown, "no attempt recorded")}, nil
	}
	in := TLSSample{
		Subject:  observationSubject(row),
		Source:   AlertSourceTLS,
		SampleID: observationSampleID(row),
	}
	switch {
	case row.LastTlsVerifyError != "":
		in.Invalid, in.Evidence = true, "certificate did not verify"
	case row.LastTlsNotAfter != "":
		notAfter, perr := time.Parse(probe.TimeFormat, row.LastTlsNotAfter)
		if perr != nil {
			return []SourceView{observationView(row, SourceUnknown, "unreadable leaf expiry")}, nil
		}
		in.NotAfter = notAfter
	case row.Success == 1 && row.TlsNotAfter != "":
		notAfter, perr := time.Parse(probe.TimeFormat, row.TlsNotAfter)
		if perr != nil {
			return []SourceView{observationView(row, SourceUnknown, "unreadable leaf expiry")}, nil
		}
		in.NotAfter = notAfter
	default:
		return []SourceView{observationView(row, SourceUnknown, "no verified leaf recorded")}, nil
	}
	s.freshness(ctx, row, now, cfg)
	a, err := s.svc.RecordTLS(ctx, in)
	if err != nil {
		return nil, err
	}
	return []SourceView{alertView(SourceObservations, observationSubject(row), AlertSourceTLS, a)}, nil
}

// evaluateSync surfaces the sync state read-only: the open legacy sync alerts (which already
// describe a sync problem and are NOT copied) and the newest run result. It raises no monitor alert
// and resolves no legacy alert.
func (s *Sources) evaluateSync(ctx context.Context, views *[]SourceView) error {
	var errs []error

	alerts, err := s.cfg.LegacyAlerts.ListOpenAlerts(ctx)
	if err != nil {
		*views = append(*views, SourceView{
			Source: SourceSyncRuns, Subject: SubjectSync, Origin: "legacy_alerts",
			Status: SourceUnknown, Evidence: "legacy alerts could not be read",
		})
		errs = append(errs, fmt.Errorf("alert: sources: legacy alerts: %w", err))
	} else {
		for _, a := range alerts {
			if !legacySyncAlertKinds[a.Kind] {
				continue
			}
			*views = append(*views, SourceView{
				Source: SourceSyncRuns, Subject: SubjectSync, Origin: a.Source, AlertKind: a.Kind,
				Severity: SeverityCritical, State: StateActive, Freshness: FreshnessFresh,
				Status: SourceFresh, ObservedAt: parseTime(a.FirstSeenAt), LastSeen: parseTime(a.LastSeenAt),
			})
		}
	}

	run, err := s.cfg.SyncRuns.GetLatestSyncRun(ctx)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		*views = append(*views, SourceView{
			Source: SourceSyncRuns, Subject: SubjectSync, Origin: "sync_run",
			Status: SourceUnknown, Evidence: "no sync run recorded",
		})
	case err != nil:
		*views = append(*views, SourceView{
			Source: SourceSyncRuns, Subject: SubjectSync, Origin: "sync_run",
			Status: SourceUnknown, Evidence: "sync run could not be read",
		})
		errs = append(errs, fmt.Errorf("alert: sources: sync run: %w", err))
	default:
		severity := Severity("")
		if run.Result != "" && !syncRunSuccess[run.Result] {
			severity = SeverityWarning
		}
		*views = append(*views, SourceView{
			Source: SourceSyncRuns, Subject: SubjectSync, Origin: run.Trigger,
			Severity: severity, Freshness: FreshnessFresh, Status: SourceFresh,
			Evidence: run.Result, ObservedAt: parseTime(run.StartedAt), LastSeen: parseTime(run.StartedAt),
		})
	}
	return errors.Join(errs...)
}

// evaluatePending surfaces the changes waiting for approval as read-only views. It raises no monitor
// alert, so approving one is never inferred from a missing monitor row.
func (s *Sources) evaluatePending(ctx context.Context, views *[]SourceView) error {
	changes, err := s.cfg.Pending.ListPendingChanges(ctx)
	if err != nil {
		*views = append(*views, SourceView{
			Source: SourcePendingChanges, Subject: SubjectPendingChange, Origin: "changes",
			Status: SourceUnknown, Evidence: "pending changes could not be read",
		})
		return fmt.Errorf("alert: sources: pending changes: %w", err)
	}
	for _, c := range changes {
		*views = append(*views, SourceView{
			Source: SourcePendingChanges, Subject: fmt.Sprintf("change-%d", c.ID), Origin: c.Kind,
			Severity: SeverityWarning, State: StateActive, Freshness: FreshnessFresh, Status: SourceFresh,
			Evidence: c.Status, ObservedAt: parseTime(c.CreatedAt), LastSeen: parseTime(c.UpdatedAt),
		})
	}
	return nil
}

// observationSubject is the alert subject of one observation: the host, or the site when no host is
// recorded. The R3 alarm key is subject_id/host.
func observationSubject(row db.Observation) string { return probe.ObservationSubject(row) }

// freshness is the evidence freshness of one stored attempt (probe.ObservationFreshness): fresh only
// for a success that is not older than twice the measurement interval. A row whose last attempt is
// that old means the measurement loop went silent, so the source freshness alert is raised
// (R3 B-07); a recent attempt clears it. A failed freshness write is not fatal: the label is still
// returned and the next round retries.
func (s *Sources) freshness(ctx context.Context, row db.Observation, now time.Time, cfg monitor.Settings) string {
	interval := probe.ObservationInterval(row.Category, cfg)
	overdue := probe.ObservationOverdue(row, now, interval)
	_, _ = s.svc.RecordSource(ctx, SourceSample{
		Subject: observationSubject(row), Source: row.Category, Failed: overdue,
		Error: "no recent measurement",
	})
	if probe.ObservationFreshness(row, now, interval) == probe.RowFresh {
		return FreshnessFresh
	}
	return FreshnessStale
}

// observationSampleID is the stable identity of one stored attempt: the full measurement key plus
// the attempt time. It is the same before and after a restart, so the service's last-consumed-sample
// dedup cannot be reset by re-reading the same row.
func observationSampleID(row db.Observation) string {
	return strings.Join([]string{
		row.Category, row.Site, row.Host, row.Route, row.Source, row.Vantage,
		row.Endpoint, row.Sni, row.Path, row.LastAttemptAt,
	}, "\x1f")
}

// healthEvidence is the evidence of one health attempt: empty on success, else the fixed label of
// its failure class (never the raw stored error text).
func healthEvidence(row db.Observation) string {
	if row.Success == 1 {
		return ""
	}
	if text, ok := probe.FailureText(row.LastResult); ok {
		return text
	}
	return "check failed"
}

// riskEvidence is the fixed evidence of a stored configuration-risk row; unknown findings and raw
// contexts are not echoed.
func riskEvidence(finding string) string {
	switch finding {
	case "alternate_path_candidate":
		return "alternate path candidate"
	case "unknown":
		return "unknown configuration risk"
	default:
		return "configuration risk recorded"
	}
}

// alertView builds a view from one applied monitor alert.
func alertView(source SourceKind, subject, origin string, a Alert) SourceView {
	return SourceView{
		Source: source, Subject: subject, Origin: origin, AlertKind: a.Kind,
		Severity: a.Severity, State: a.State, Freshness: a.Freshness, Status: SourceFresh,
		Evidence: a.Evidence, ObservedAt: a.LastSuccess, LastSeen: a.LastSeen,
	}
}

// observationView is the read-only view of a row that is not a clean, complete result.
func observationView(row db.Observation, status SourceStatus, evidence string) SourceView {
	return SourceView{
		Source: SourceObservations, Subject: observationSubject(row), Origin: row.Category,
		Status: status, Freshness: FreshnessStale, Evidence: evidence,
		ObservedAt: parseTime(row.ObservedAt), LastSeen: parseTime(row.LastAttemptAt),
	}
}

// configRiskView is the read-only view of a stored configuration-risk row.
func configRiskView(row db.Observation) SourceView {
	status, freshness := SourceFresh, FreshnessFresh
	evidence := riskEvidence(row.RiskFinding)
	if row.Source == "net_probe" { // a network measurement of the route, not the declared risk
		evidence = "network measurement recorded"
		if row.Success != 1 {
			freshness, evidence = FreshnessStale, "network measurement failed: "+healthEvidence(row)
		}
	}
	if row.LastAttemptAt == "" {
		status, evidence = SourceUnknown, "no attempt recorded"
	}
	return SourceView{
		Source: SourceObservations, Subject: observationSubject(row), Origin: "config_risk",
		Status: status, Freshness: freshness, Evidence: evidence,
		ObservedAt: parseTime(row.ObservedAt), LastSeen: parseTime(row.LastAttemptAt),
	}
}

// legacySyncAlertKinds are the F1/F3 pipeline alarms that already describe a sync problem
// (sync.AlertReadFailed). They are surfaced read-only and never copied into a monitor alert.
var legacySyncAlertKinds = map[string]bool{"reconcile_read_failed": true}

// syncRunSuccess is the set of sync results that are not a problem. Anything else (failed,
// read_failed, blocked, held, needs_reapproval, pending_approval) is shown with a warning severity.
var syncRunSuccess = map[string]bool{"applied": true, "no_change": true, "dry_run": true}

// siteRemovedEvidence is the evidence of an alert closed because its host left the site list.
const siteRemovedEvidence = "site removed"

// resolveRemoved resolves, in one transaction, the open health/TLS/freshness monitor alerts of the
// observation sources whose subject is not in current. It is called only after a complete read of the
// site list and of every site's observations. It never touches drift, k8s or legacy alerts, and the
// evidence says "site removed", not a recovery.
func (s *Service) resolveRemoved(ctx context.Context, current map[string]bool) error {
	at := s.at(time.Time{})
	return s.store.withTx(ctx, func(t *tx) error {
		open, err := t.listOpenMonitor(ctx)
		if err != nil {
			return err
		}
		for _, a := range open {
			if !observationAlertKinds[a.Kind] || !observationAlertSources[a.Source] || current[a.Subject] {
				continue
			}
			if _, err := t.update(ctx, db.UpdateMonitorAlertParams{
				Severity: a.Severity, Freshness: a.Freshness, EvidenceSummary: siteRemovedEvidence,
				LastSuccess: a.LastSuccess, LastConsumedSample: a.LastConsumedSample,
				ConsecutiveFailures: a.ConsecutiveFailures, ConsecutiveSuccesses: a.ConsecutiveSuccesses,
				LastSeenAt: a.LastSeenAt, ID: a.ID,
			}); err != nil {
				return err
			}
			if _, err := t.resolve(ctx, a.Kind, a.Subject, a.Source, at); err != nil {
				return err
			}
		}
		return nil
	})
}

// The alert kinds and sources the observation bridge owns; resolveRemoved touches nothing else.
var (
	observationAlertKinds   = map[string]bool{KindTargetHealth: true, KindTLSExpiry: true, KindSourceStale: true}
	observationAlertSources = map[string]bool{AlertSourceTarget: true, AlertSourceGate: true, AlertSourceTLS: true, AlertSourceStore: true}
)
