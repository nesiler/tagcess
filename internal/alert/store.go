// Package alert owns the durable monitor-alert lifecycle for the F4 dashboard (P-02, ADR 0032
// proposal): the hysteresis thresholds, acknowledgement, maintenance muting, certificate expiry
// severities and freshness alerts. It reuses the existing alerts table and the typed monitoring
// settings; it sends nothing outside the dashboard.
//
// store.go is the persistence half: every state transition of one alert runs inside a single
// transaction, so a failure never leaves a half-written transition (rule 7, fail safe).
package alert

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	probe "github.com/nesiler/tagcess/internal/health"
	"github.com/nesiler/tagcess/internal/store/db"
)

// timeFormat matches the audit log, the change pipeline and the migration seeds: fixed-width
// milliseconds so the stored text sorts chronologically in SQLite.
const timeFormat = probe.TimeFormat

// ErrNotFound is returned by Get when no open alert exists for the key.
var ErrNotFound = errors.New("alert: not found")

// Store is the durable alert state over the shared SQLite database. A transition is applied by
// withTx, which hands the callback the query surface bound to one transaction.
type Store struct {
	db *sql.DB
	q  *db.Queries
}

// NewStore returns the store over an open database and its generated queries.
func NewStore(sqldb *sql.DB, q *db.Queries) *Store {
	return &Store{db: sqldb, q: q}
}

// tx is the persistence surface inside one transaction.
type tx struct {
	q *db.Queries
}

// withTx runs fn inside a transaction: the callback's writes commit together or not at all.
func (s *Store) withTx(ctx context.Context, fn func(*tx) error) error {
	sqltx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("alert: begin: %w", err)
	}
	defer func() { _ = sqltx.Rollback() }() // a no-op once Commit has succeeded
	if err := fn(&tx{q: s.q.WithTx(sqltx)}); err != nil {
		return err
	}
	if err := sqltx.Commit(); err != nil {
		return fmt.Errorf("alert: commit: %w", err)
	}
	return nil
}

// getOpen finds the open alert of one (kind, subject, source) key. Not finding it is not an error.
func (t *tx) getOpen(ctx context.Context, kind, subject, source string) (db.Alert, bool, error) {
	row, err := t.q.GetOpenMonitorAlert(ctx, db.GetOpenMonitorAlertParams{
		Kind: kind, Subject: subject, Source: source,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return db.Alert{}, false, nil
	}
	if err != nil {
		return db.Alert{}, false, fmt.Errorf("alert: open lookup: %w", err)
	}
	return row, true, nil
}

// insert creates a new open monitor alert. InsertMonitorAlert cannot set counters or the consumed
// sample, so callers follow it with an update in the same transaction.
func (t *tx) insert(ctx context.Context, p db.InsertMonitorAlertParams) (db.Alert, error) {
	row, err := t.q.InsertMonitorAlert(ctx, p)
	if err != nil {
		return db.Alert{}, fmt.Errorf("alert: insert: %w", err)
	}
	return row, nil
}

// update writes the monitor state (severity/freshness/evidence/counters/consumed sample) of one
// open alert and never touches its identity or resolved_at.
func (t *tx) update(ctx context.Context, p db.UpdateMonitorAlertParams) (int64, error) {
	rows, err := t.q.UpdateMonitorAlert(ctx, p)
	if err != nil {
		return 0, fmt.Errorf("alert: update: %w", err)
	}
	return rows, nil
}

// resolve closes one exact (kind, subject, source) alert.
func (t *tx) resolve(ctx context.Context, kind, subject, source string, at time.Time) (int64, error) {
	rows, err := t.q.ResolveMonitorAlert(ctx, db.ResolveMonitorAlertParams{
		ResolvedAt: sql.NullString{String: stamp(at), Valid: true},
		Kind:       kind, Subject: subject, Source: source,
	})
	if err != nil {
		return 0, fmt.Errorf("alert: resolve: %w", err)
	}
	return rows, nil
}

// setAcknowledged records who/when read the alert without resolving it.
func (t *tx) setAcknowledged(ctx context.Context, id int64, at time.Time) (int64, error) {
	rows, err := t.q.SetAlertAcknowledged(ctx, db.SetAlertAcknowledgedParams{
		AcknowledgedAt: sql.NullString{String: stamp(at), Valid: true}, ID: id,
	})
	if err != nil {
		return 0, fmt.Errorf("alert: acknowledge: %w", err)
	}
	return rows, nil
}

// clearAcknowledged drops the acknowledgement of one open alert (it got worse after being read).
func (t *tx) clearAcknowledged(ctx context.Context, id int64) (int64, error) {
	rows, err := t.q.SetAlertAcknowledged(ctx, db.SetAlertAcknowledgedParams{AcknowledgedAt: sql.NullString{}, ID: id})
	if err != nil {
		return 0, fmt.Errorf("alert: clear acknowledgement: %w", err)
	}
	return rows, nil
}

// setMuted sets the maintenance label of one open alert.
func (t *tx) setMuted(ctx context.Context, id int64, muted bool) (int64, error) {
	flag := int64(0)
	if muted {
		flag = 1
	}
	rows, err := t.q.SetAlertMuted(ctx, db.SetAlertMutedParams{Muted: flag, ID: id})
	if err != nil {
		return 0, fmt.Errorf("alert: set muted: %w", err)
	}
	return rows, nil
}

// maintenance reads the persistent per-site maintenance preference from the settings table. An
// unset key means off; a value that is not a boolean is a corrupt setting and returns an error
// (fail safe: never silently mute or unmute).
func (t *tx) maintenance(ctx context.Context, subject string) (bool, error) {
	value, err := t.q.GetSetting(ctx, maintenanceKey(subject))
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("alert: read maintenance: %w", err)
	}
	switch value {
	case "1", "true":
		return true, nil
	case "0", "false":
		return false, nil
	default:
		return false, fmt.Errorf("alert: maintenance setting %q = %q: want 0 or 1", maintenanceKey(subject), value)
	}
}

// setMaintenance stores the persistent maintenance preference for one site.
func (t *tx) setMaintenance(ctx context.Context, subject string, muted bool, at time.Time) error {
	value := "0"
	if muted {
		value = "1"
	}
	if err := t.q.UpsertSetting(ctx, db.UpsertSettingParams{
		Key: maintenanceKey(subject), Value: value, UpdatedAt: stamp(at),
	}); err != nil {
		return fmt.Errorf("alert: write maintenance: %w", err)
	}
	return nil
}

// listOpenMonitor returns the open monitor alerts (legacy pipeline kinds excluded) including the
// pending rows that only carry the sub-threshold counters.
func (t *tx) listOpenMonitor(ctx context.Context) ([]db.Alert, error) {
	rows, err := t.q.ListOpenAlerts(ctx)
	if err != nil {
		return nil, fmt.Errorf("alert: list open: %w", err)
	}
	out := rows[:0]
	for _, r := range rows {
		if isMonitorKind(r.Kind) {
			out = append(out, r)
		}
	}
	return out, nil
}

// stamp formats a time the way every stored timestamp in the project is formatted.
func stamp(t time.Time) string { return t.UTC().Format(timeFormat) }
