package alert

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/nesiler/tagcess/internal/monitor"
	"github.com/nesiler/tagcess/internal/store/db"
)

// Monitor alert kinds. They are prefixed so they stay disjoint from the F1/F3 pipeline kinds
// (policy_mismatch, reconcile_read_failed, ...): the legacy TouchAlert/ResolveAlerts/ResolveAlertKind
// queries match on kind only and would otherwise touch or resolve monitor rows (F4-022 note).
const (
	// KindTargetHealth is the hysteresis alert of one target/route health check.
	KindTargetHealth = "monitor_target_health"
	// KindTLSExpiry is the presented-leaf expiry alert of one host/SNI.
	KindTLSExpiry = "monitor_tls_expiry"
	// KindSourceStale is the freshness alert raised when a measurement source cannot be read.
	KindSourceStale = "monitor_source_stale"
)

// Severity of an alert. The empty severity marks a pending row that only carries the counters below
// the opening threshold; it is bookkeeping, not a dashboard alert.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

// Freshness labels a stored alert's evidence: fresh after a current measurement, stale once its
// source could not be read. It is not a recovery.
const (
	FreshnessFresh = "fresh"
	FreshnessStale = "stale"
)

// State is the derived lifecycle state shown on the dashboard.
type State string

const (
	// StatePending is an open row below the opening threshold (no severity yet).
	StatePending State = "pending"
	// StateActive is an open, unacknowledged, raised alert.
	StateActive State = "active"
	// StateAcknowledged is an open alert a devops read (not a recovery).
	StateAcknowledged State = "acknowledged"
	// StateResolved is a closed alert.
	StateResolved State = "resolved"
)

// maxEvidence bounds the sanitized summary stored with an alert.
const maxEvidence = 256

// maintenanceKeyPrefix names the per-site maintenance preference in the shared settings table.
const maintenanceKeyPrefix = "monitor.maintenance."

// Alert is one monitor alert as the service and the dashboard see it.
type Alert struct {
	ID       int64
	Kind     string
	Subject  string
	Source   string
	Severity Severity
	State    State
	Muted    bool

	Freshness string
	Evidence  string

	ConsecutiveFailures  int
	ConsecutiveSuccesses int

	Acknowledged bool
	Resolved     bool

	LastConsumedSample string

	FirstSeen      time.Time
	LastSeen       time.Time
	LastSuccess    time.Time
	AcknowledgedAt time.Time
	ResolvedAt     time.Time
}

// HealthSample is one target/Caddy health observation.
type HealthSample struct {
	Subject  string
	Source   string
	SampleID string
	At       time.Time
	Success  bool
	// Freshness defaults to fresh; callers pass stale only for already-stale evidence.
	Freshness string
	Evidence  string
}

// TLSSample is one evaluation of the presented leaf of a host/SNI.
type TLSSample struct {
	Subject  string
	Source   string
	SampleID string
	At       time.Time
	// NotAfter is the presented leaf's expiry. Zero with Invalid unset is treated as unverifiable.
	NotAfter time.Time
	// Invalid marks a leaf that could not be verified (wrong chain/hostname) or is expired.
	Invalid  bool
	Evidence string
}

// SourceSample reports the outcome of reading one observation source. A failed read keeps the
// existing alerts and raises a separate freshness alert; a complete read resolves only the
// freshness alert.
type SourceSample struct {
	Subject  string
	Source   string
	SampleID string
	At       time.Time
	Failed   bool
	Error    string
}

// SettingsReader supplies the typed monitoring settings; *monitor.SettingsStore satisfies it.
type SettingsReader interface {
	Get(ctx context.Context) (monitor.Settings, error)
}

// Service applies the monitor-alert lifecycle over the durable store.
type Service struct {
	store    *Store
	settings SettingsReader
	clock    func() time.Time
}

// New returns a service over the durable store and the monitoring settings. A nil settings reader
// falls back to the documented defaults (useful for callers that only track a subset).
func New(store *Store, settings SettingsReader) *Service {
	return &Service{store: store, settings: settings, clock: time.Now}
}

// RecordHealth applies one health observation with the configured hysteresis: the alert opens after
// health_fail_threshold consecutive failures and resolves after health_ok_threshold consecutive
// successes. The same sample identity is never counted twice, so a restarted reader cannot
// double-count. Health failures are the only thing that open or resolve this alert.
func (s *Service) RecordHealth(ctx context.Context, in HealthSample) (Alert, error) {
	if err := checkKey(in.Subject, in.Source); err != nil {
		return Alert{}, err
	}
	cfg, err := s.readSettings(ctx)
	if err != nil {
		return Alert{}, err
	}
	at := s.at(in.At)
	lastSeen := stamp(at)
	evidence := sanitizeEvidence(in.Evidence)
	freshness := in.Freshness
	if freshness == "" {
		freshness = FreshnessFresh
	}

	var out Alert
	err = s.store.withTx(ctx, func(t *tx) error {
		muted, err := t.maintenance(ctx, in.Subject)
		if err != nil {
			return err
		}
		cur, found, err := t.getOpen(ctx, KindTargetHealth, in.Subject, in.Source)
		if err != nil {
			return err
		}
		if found && in.SampleID != "" && cur.LastConsumedSample == in.SampleID {
			out = toAlert(cur) // repeated sample: no counter change
			return nil
		}
		if !found && in.Success {
			out = Alert{} // healthy with nothing to track
			return nil
		}
		if found && in.Success && freshness == FreshnessStale {
			// Stale evidence is not a recovery: only the freshness/evidence move, the counters, the
			// consumed sample and last_seen stay as the last real measurement left them.
			if _, err := t.update(ctx, db.UpdateMonitorAlertParams{
				Severity: cur.Severity, Freshness: FreshnessStale, EvidenceSummary: evidence,
				LastSuccess: cur.LastSuccess, LastConsumedSample: cur.LastConsumedSample,
				ConsecutiveFailures: cur.ConsecutiveFailures, ConsecutiveSuccesses: cur.ConsecutiveSuccesses,
				LastSeenAt: cur.LastSeenAt, ID: cur.ID,
			}); err != nil {
				return err
			}
			row, found, err := t.getOpen(ctx, KindTargetHealth, in.Subject, in.Source)
			if err != nil {
				return err
			}
			if !found {
				return ErrNotFound
			}
			out = toAlert(row)
			return nil
		}

		failures, successes := int64(0), int64(0)
		lastSuccess := sql.NullString{}
		if found {
			failures, successes = cur.ConsecutiveFailures, cur.ConsecutiveSuccesses
			lastSuccess = cur.LastSuccess
		}
		if in.Success {
			successes++
			failures = 0
			lastSuccess = sql.NullString{String: lastSeen, Valid: true}
		} else {
			failures++
			successes = 0
		}

		if found && successes >= int64(cfg.HealthOKThreshold) {
			if _, err := t.resolve(ctx, KindTargetHealth, in.Subject, in.Source, at); err != nil {
				return err
			}
			cur.ResolvedAt = sql.NullString{String: lastSeen, Valid: true}
			cur.ConsecutiveFailures, cur.ConsecutiveSuccesses = failures, successes
			out = toAlert(cur)
			return nil
		}

		id := cur.ID
		if !found {
			// The row is born pending; the update below applies the severity in the same transaction.
			row, err := t.insert(ctx, db.InsertMonitorAlertParams{
				Kind: KindTargetHealth, Subject: in.Subject, Source: in.Source,
				Severity: "", Freshness: freshness, EvidenceSummary: evidence,
				FirstSeenAt: lastSeen, LastSeenAt: lastSeen,
			})
			if err != nil {
				return err
			}
			id = row.ID
		}
		severity := cur.Severity
		if failures >= int64(cfg.HealthFailThreshold) {
			severity = string(SeverityCritical)
		}
		if _, err := t.update(ctx, db.UpdateMonitorAlertParams{
			Severity: severity, Freshness: freshness, EvidenceSummary: evidence,
			LastSuccess: lastSuccess, LastConsumedSample: in.SampleID,
			ConsecutiveFailures: failures, ConsecutiveSuccesses: successes,
			LastSeenAt: lastSeen, ID: id,
		}); err != nil {
			return err
		}
		if _, err := t.setMuted(ctx, id, muted); err != nil {
			return err
		}
		row, found, err := t.getOpen(ctx, KindTargetHealth, in.Subject, in.Source)
		if err != nil {
			return err
		}
		if !found {
			return ErrNotFound
		}
		out = toAlert(row)
		return nil
	})
	return out, err
}

// RecordTLS applies one presented-leaf evaluation: remaining lifetime at or below the typed
// critical/warn/info thresholds raises critical/warning/info immediately, and an expired or
// unverifiable leaf is critical at once, without using the health failure counter. A healthy leaf
// resolves the alert. An acknowledgement is dropped when the severity increases.
func (s *Service) RecordTLS(ctx context.Context, in TLSSample) (Alert, error) {
	if err := checkKey(in.Subject, in.Source); err != nil {
		return Alert{}, err
	}
	cfg, err := s.readSettings(ctx)
	if err != nil {
		return Alert{}, err
	}
	at := s.at(in.At)
	lastSeen := stamp(at)
	severity := tlsSeverity(at, in, cfg)
	evidence := sanitizeEvidence(in.Evidence)

	var out Alert
	err = s.store.withTx(ctx, func(t *tx) error {
		muted, err := t.maintenance(ctx, in.Subject)
		if err != nil {
			return err
		}
		cur, found, err := t.getOpen(ctx, KindTLSExpiry, in.Subject, in.Source)
		if err != nil {
			return err
		}
		if found && in.SampleID != "" && cur.LastConsumedSample == in.SampleID {
			out = toAlert(cur)
			return nil
		}

		if severity == "" {
			if found {
				if _, err := t.resolve(ctx, KindTLSExpiry, in.Subject, in.Source, at); err != nil {
					return err
				}
				cur.ResolvedAt = sql.NullString{String: lastSeen, Valid: true}
				out = toAlert(cur)
				return nil
			}
			out = Alert{}
			return nil
		}

		id := cur.ID
		if !found {
			row, err := t.insert(ctx, db.InsertMonitorAlertParams{
				Kind: KindTLSExpiry, Subject: in.Subject, Source: in.Source,
				Severity: string(severity), Freshness: FreshnessFresh, EvidenceSummary: evidence,
				FirstSeenAt: lastSeen, LastSeenAt: lastSeen,
			})
			if err != nil {
				return err
			}
			id = row.ID
		}
		if _, err := t.update(ctx, db.UpdateMonitorAlertParams{
			Severity: string(severity), Freshness: FreshnessFresh, EvidenceSummary: evidence,
			LastSuccess: cur.LastSuccess, LastConsumedSample: in.SampleID,
			ConsecutiveFailures: 0, ConsecutiveSuccesses: 0,
			LastSeenAt: lastSeen, ID: id,
		}); err != nil {
			return err
		}
		if _, err := t.setMuted(ctx, id, muted); err != nil {
			return err
		}
		// A certificate that got worse is shown to devops again: the old read no longer covers it.
		if found && severityRank(string(severity)) > severityRank(cur.Severity) {
			if _, err := t.clearAcknowledged(ctx, id); err != nil {
				return err
			}
		}
		row, found, err := t.getOpen(ctx, KindTLSExpiry, in.Subject, in.Source)
		if err != nil {
			return err
		}
		if !found {
			return ErrNotFound
		}
		out = toAlert(row)
		return nil
	})
	return out, err
}

// RecordSource applies the outcome of reading one observation source. A failed read marks the
// existing health/TLS alerts of the key stale and raises the separate freshness alert without
// resolving anything; a complete read resolves only the freshness alert.
func (s *Service) RecordSource(ctx context.Context, in SourceSample) (Alert, error) {
	if err := checkKey(in.Subject, in.Source); err != nil {
		return Alert{}, err
	}
	at := s.at(in.At)
	lastSeen := stamp(at)

	var out Alert
	err := s.store.withTx(ctx, func(t *tx) error {
		muted, err := t.maintenance(ctx, in.Subject)
		if err != nil {
			return err
		}
		if !in.Failed {
			if _, err := t.resolve(ctx, KindSourceStale, in.Subject, in.Source, at); err != nil {
				return err
			}
			out = Alert{}
			return nil
		}

		// A failed read never resolves a health/TLS alert; it only marks the evidence stale.
		for _, kind := range []string{KindTargetHealth, KindTLSExpiry, KindDrift} {
			cur, found, err := t.getOpen(ctx, kind, in.Subject, in.Source)
			if err != nil {
				return err
			}
			if !found {
				continue
			}
			if _, err := t.update(ctx, db.UpdateMonitorAlertParams{
				Severity: cur.Severity, Freshness: FreshnessStale, EvidenceSummary: cur.EvidenceSummary,
				LastSuccess: cur.LastSuccess, LastConsumedSample: cur.LastConsumedSample,
				ConsecutiveFailures: cur.ConsecutiveFailures, ConsecutiveSuccesses: cur.ConsecutiveSuccesses,
				LastSeenAt: cur.LastSeenAt, ID: cur.ID,
			}); err != nil {
				return err
			}
		}

		cur, found, err := t.getOpen(ctx, KindSourceStale, in.Subject, in.Source)
		if err != nil {
			return err
		}
		if found && in.SampleID != "" && cur.LastConsumedSample == in.SampleID {
			out = toAlert(cur)
			return nil
		}
		id := cur.ID
		if !found {
			row, err := t.insert(ctx, db.InsertMonitorAlertParams{
				Kind: KindSourceStale, Subject: in.Subject, Source: in.Source,
				Severity: string(SeverityWarning), Freshness: FreshnessStale,
				EvidenceSummary: sanitizeEvidence(in.Error),
				FirstSeenAt:     lastSeen, LastSeenAt: lastSeen,
			})
			if err != nil {
				return err
			}
			id = row.ID
		}
		if _, err := t.update(ctx, db.UpdateMonitorAlertParams{
			Severity: string(SeverityWarning), Freshness: FreshnessStale,
			EvidenceSummary: sanitizeEvidence(in.Error),
			LastSuccess:     cur.LastSuccess, LastConsumedSample: in.SampleID,
			ConsecutiveFailures: cur.ConsecutiveFailures, ConsecutiveSuccesses: cur.ConsecutiveSuccesses,
			LastSeenAt: lastSeen, ID: id,
		}); err != nil {
			return err
		}
		if _, err := t.setMuted(ctx, id, muted); err != nil {
			return err
		}
		row, found, err := t.getOpen(ctx, KindSourceStale, in.Subject, in.Source)
		if err != nil {
			return err
		}
		if !found {
			return ErrNotFound
		}
		out = toAlert(row)
		return nil
	})
	return out, err
}

// Acknowledge marks a raised alert read. It never resolves the alert and keeps the first
// acknowledgement time. A pending row (below the opening threshold) is not an alert yet and is
// reported as ErrNotFound.
func (s *Service) Acknowledge(ctx context.Context, kind, subject, source string) (Alert, error) {
	if err := checkKey(subject, source); err != nil {
		return Alert{}, err
	}
	at := s.at(time.Time{})
	var out Alert
	err := s.store.withTx(ctx, func(t *tx) error {
		cur, found, err := t.getOpen(ctx, kind, subject, source)
		if err != nil {
			return err
		}
		if !found || cur.Severity == "" {
			// A pending row below the opening threshold is bookkeeping, not an alert anyone can read.
			return ErrNotFound
		}
		ackAt := at
		if cur.AcknowledgedAt.Valid {
			if parsed, perr := time.Parse(timeFormat, cur.AcknowledgedAt.String); perr == nil {
				ackAt = parsed
			}
		}
		if _, err := t.setAcknowledged(ctx, cur.ID, ackAt); err != nil {
			return err
		}
		cur.AcknowledgedAt = sql.NullString{String: stamp(ackAt), Valid: true}
		out = toAlert(cur)
		return nil
	})
	return out, err
}

// SetMaintenance stores the persistent per-site monitoring maintenance preference and applies the
// muted label to every currently open monitor alert of that site. Maintenance never stops
// measurement, resolves an alert or touches the H-07 config maintenance.
func (s *Service) SetMaintenance(ctx context.Context, subject string, muted bool) error {
	if strings.TrimSpace(subject) == "" {
		return errors.New("alert: subject is required")
	}
	at := s.at(time.Time{})
	return s.store.withTx(ctx, func(t *tx) error {
		if err := t.setMaintenance(ctx, subject, muted, at); err != nil {
			return err
		}
		rows, err := t.listOpenMonitor(ctx)
		if err != nil {
			return err
		}
		for _, r := range rows {
			if r.Subject != subject {
				continue
			}
			if _, err := t.setMuted(ctx, r.ID, muted); err != nil {
				return err
			}
		}
		return nil
	})
}

// Get returns the open alert of one key, or ErrNotFound.
func (s *Service) Get(ctx context.Context, kind, subject, source string) (Alert, error) {
	row, err := s.store.q.GetOpenMonitorAlert(ctx, db.GetOpenMonitorAlertParams{
		Kind: kind, Subject: subject, Source: source,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return Alert{}, ErrNotFound
	}
	if err != nil {
		return Alert{}, fmt.Errorf("alert: get: %w", err)
	}
	return toAlert(row), nil
}

// ListOpen returns the raised monitor alerts for the dashboard, newest first. Pending rows below
// the opening threshold are bookkeeping and are not listed.
func (s *Service) ListOpen(ctx context.Context) ([]Alert, error) {
	rows, err := s.store.q.ListOpenAlerts(ctx)
	if err != nil {
		return nil, fmt.Errorf("alert: list: %w", err)
	}
	var out []Alert
	for _, r := range rows {
		if !isMonitorKind(r.Kind) || r.Severity == "" {
			continue
		}
		out = append(out, toAlert(r))
	}
	return out, nil
}

// listLimit bounds the resolved history of the lifecycle listing so a long history cannot load
// without end. Open rows are never limited.
const listLimit = 200

// List returns the monitor-alert lifecycle for the alerts screen, newest first: every raised
// (active/acknowledged) row, and the newest resolved rows up to listLimit, so the resolution state
// stays visible after recovery and an old open alert is never pushed out by newer rows. Pending
// counters below the opening threshold and the legacy F1/F3 pipeline alerts are bookkeeping and are
// not listed.
func (s *Service) List(ctx context.Context) ([]Alert, error) {
	open, err := s.store.q.ListOpenMonitorAlertRows(ctx)
	if err != nil {
		return nil, fmt.Errorf("alert: list lifecycle: %w", err)
	}
	resolved, err := s.store.q.ListResolvedMonitorAlertRows(ctx, listLimit)
	if err != nil {
		return nil, fmt.Errorf("alert: list lifecycle: %w", err)
	}
	out := make([]Alert, 0, len(open)+len(resolved))
	for _, r := range open {
		out = append(out, toAlert(r))
	}
	for _, r := range resolved {
		out = append(out, toAlert(r))
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].LastSeen.Equal(out[j].LastSeen) {
			return out[i].LastSeen.After(out[j].LastSeen)
		}
		return out[i].ID > out[j].ID
	})
	return out, nil
}

// readSettings returns the typed monitoring settings, or the documented defaults when no reader
// was supplied. A read error is surfaced (fail safe: never silently reset the thresholds).
func (s *Service) readSettings(ctx context.Context) (monitor.Settings, error) {
	if s.settings == nil {
		return monitor.DefaultSettings(), nil
	}
	cfg, err := s.settings.Get(ctx)
	if err != nil {
		return monitor.Settings{}, fmt.Errorf("alert: settings: %w", err)
	}
	return cfg, nil
}

// at resolves the sample time, falling back to the service clock.
func (s *Service) at(t time.Time) time.Time {
	if t.IsZero() {
		return s.clock()
	}
	return t
}

// tlsSeverity classifies the presented leaf: an expired or unverifiable leaf is critical; otherwise
// the remaining lifetime at or below the typed critical/warn/info day thresholds picks the
// severity, and a lifetime above the info threshold is healthy (empty).
func tlsSeverity(now time.Time, in TLSSample, cfg monitor.Settings) Severity {
	if in.Invalid || in.NotAfter.IsZero() || !in.NotAfter.After(now) {
		return SeverityCritical
	}
	remaining := in.NotAfter.Sub(now)
	switch {
	case remaining <= days(cfg.TLSCriticalDays):
		return SeverityCritical
	case remaining <= days(cfg.TLSWarnDays):
		return SeverityWarning
	case remaining <= days(cfg.TLSInfoDays):
		return SeverityInfo
	}
	return ""
}

// severityRank orders severities so an escalation can be told from a de-escalation.
func severityRank(severity string) int {
	switch Severity(severity) {
	case SeverityInfo:
		return 1
	case SeverityWarning:
		return 2
	case SeverityCritical:
		return 3
	}
	return 0
}

func days(n int) time.Duration { return time.Duration(n) * 24 * time.Hour }

func toAlert(row db.Alert) Alert {
	a := Alert{
		ID:                   row.ID,
		Kind:                 row.Kind,
		Subject:              row.Subject,
		Source:               row.Source,
		Severity:             Severity(row.Severity),
		Freshness:            row.Freshness,
		Evidence:             row.EvidenceSummary,
		Muted:                row.Muted != 0,
		ConsecutiveFailures:  int(row.ConsecutiveFailures),
		ConsecutiveSuccesses: int(row.ConsecutiveSuccesses),
		LastConsumedSample:   row.LastConsumedSample,
		FirstSeen:            parseTime(row.FirstSeenAt),
		LastSeen:             parseTime(row.LastSeenAt),
	}
	if row.LastSuccess.Valid {
		a.LastSuccess = parseTime(row.LastSuccess.String)
	}
	if row.AcknowledgedAt.Valid {
		a.AcknowledgedAt = parseTime(row.AcknowledgedAt.String)
		a.Acknowledged = true
	}
	if row.ResolvedAt.Valid {
		a.ResolvedAt = parseTime(row.ResolvedAt.String)
		a.Resolved = true
	}
	switch {
	case a.Resolved:
		a.State = StateResolved
	case a.Severity == "":
		a.State = StatePending
	case a.Acknowledged:
		a.State = StateAcknowledged
	default:
		a.State = StateActive
	}
	return a
}

func parseTime(value string) time.Time {
	if value == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(timeFormat, value)
	if err != nil {
		return time.Time{}
	}
	return parsed
}

func checkKey(subject, source string) error {
	if strings.TrimSpace(subject) == "" {
		return errors.New("alert: subject is required")
	}
	if strings.TrimSpace(source) == "" {
		return errors.New("alert: source is required")
	}
	return nil
}

// sanitizeEvidence trims a one-line, length-bounded metadata summary. Callers never pass raw
// response bodies, headers or tokens.
func sanitizeEvidence(s string) string {
	s = strings.TrimSpace(s)
	s = strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
	if len(s) > maxEvidence {
		s = s[:maxEvidence]
	}
	return strings.ToValidUTF8(s, "")
}

func maintenanceKey(subject string) string { return maintenanceKeyPrefix + subject }

func isMonitorKind(kind string) bool { return strings.HasPrefix(kind, "monitor_") }
