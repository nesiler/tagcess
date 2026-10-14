package web

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/store/db"
	"github.com/nesiler/tagcess/internal/sync"
)

// dryRunSettingKey is the settings key holding dry-run mode, seeded true on first start (Y-06.2).
// It matches store.dryRunKey; the database is the shared source of truth.
const dryRunSettingKey = "dry_run"

// storedTimeFormat matches the audit log, the change pipeline and the migration seeds: fixed-width
// milliseconds so the text sorts chronologically in SQLite.
const storedTimeFormat = "2006-01-02T15:04:05.000Z"

// OverviewConfig wires the production sync overview reader.
type OverviewConfig struct {
	// Queries reads the run, alert, change and setting rows. Required.
	Queries *db.Queries
	// Preview computes the current diff without applying (sync.Reconciler.Preview). Required.
	Preview func(ctx context.Context) (sync.Plan, error)
	// DefaultInterval is shown when the stored interval is unset or invalid.
	DefaultInterval time.Duration
	// Clock is the time source for parsing; empty means time.Now (only used for defaults).
	Clock func() time.Time
}

// overviewReader assembles the sync page snapshot from the store and a read-only plan preview.
type overviewReader struct {
	q               *db.Queries
	preview         func(ctx context.Context) (sync.Plan, error)
	defaultInterval time.Duration
	clock           func() time.Time
}

// NewOverviewReader validates the wiring and returns the production SyncOverviewReader.
func NewOverviewReader(cfg OverviewConfig) (SyncOverviewReader, error) {
	switch {
	case cfg.Queries == nil:
		return nil, errors.New("web: sync overview needs a query set")
	case cfg.Preview == nil:
		return nil, errors.New("web: sync overview needs a preview function")
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	return &overviewReader{q: cfg.Queries, preview: cfg.Preview, defaultInterval: cfg.DefaultInterval, clock: cfg.Clock}, nil
}

// Overview reads the status, alerts, pending change, settings and the current diff. A missing
// setting falls back to its default; only a real database error fails the page.
func (o *overviewReader) Overview(ctx context.Context) (SyncOverview, error) {
	var out SyncOverview

	run, err := o.q.GetLatestSyncRun(ctx)
	switch {
	case err == nil:
		at, perr := time.Parse(storedTimeFormat, run.StartedAt)
		if perr != nil {
			return SyncOverview{}, fmt.Errorf("web: parse sync run time %q: %w", run.StartedAt, perr)
		}
		out.LastRun = &SyncRunView{At: at, Trigger: run.Trigger, Result: run.Result, Summary: run.DiffSummary}
	case errors.Is(err, sql.ErrNoRows):
		// No run yet: the page shows "Kayıt yok".
	default:
		return SyncOverview{}, fmt.Errorf("web: read latest sync run: %w", err)
	}

	alerts, err := o.q.ListOpenAlerts(ctx)
	if err != nil {
		return SyncOverview{}, fmt.Errorf("web: list open alerts: %w", err)
	}
	for _, a := range alerts {
		// A monitor row (non-empty subject) without a severity is a sub-threshold hysteresis counter
		// (F4-023), not a raised alert. Legacy pipeline alerts have an empty subject and stay listed.
		if a.Subject != "" && a.Severity == "" {
			continue
		}
		last, perr := time.Parse(storedTimeFormat, a.LastSeenAt)
		if perr != nil {
			return SyncOverview{}, fmt.Errorf("web: parse alert time %q: %w", a.LastSeenAt, perr)
		}
		out.Alerts = append(out.Alerts, SyncAlertView{Kind: a.Kind, Source: a.Source, LastSeen: last})
	}

	pending, err := o.q.ListPendingChanges(ctx)
	if err != nil {
		return SyncOverview{}, fmt.Errorf("web: list pending changes: %w", err)
	}
	for _, p := range pending {
		out.Pending = append(out.Pending, SyncPendingView{
			ID:      p.ID,
			Actor:   p.Actor,
			Summary: proposalSummary(p.AfterSummary),
			Version: change.ProposalVersion(p.AfterSummary),
		})
	}

	out.DryRun, err = o.boolSetting(ctx, dryRunSettingKey)
	if err != nil {
		return SyncOverview{}, err
	}
	interval, err := o.q.GetSetting(ctx, sync.SyncIntervalSetting)
	switch {
	case err == nil:
		out.IntervalMin = int(sync.IntervalFromSetting(interval, o.defaultInterval) / time.Minute)
	case errors.Is(err, sql.ErrNoRows):
		out.IntervalMin = int(o.defaultInterval / time.Minute)
	default:
		return SyncOverview{}, fmt.Errorf("web: read sync interval: %w", err)
	}

	plan, err := o.preview(ctx)
	if err != nil {
		return SyncOverview{}, fmt.Errorf("web: preview sync plan: %w", err)
	}
	out.Plan = plan
	return out, nil
}

// boolSetting reads a boolean setting, defaulting to false when unset.
func (o *overviewReader) boolSetting(ctx context.Context, key string) (bool, error) {
	value, err := o.q.GetSetting(ctx, key)
	switch {
	case err == nil:
		on, perr := strconv.ParseBool(value)
		if perr != nil {
			return false, fmt.Errorf("web: setting %s = %q: %w", key, value, perr)
		}
		return on, nil
	case errors.Is(err, sql.ErrNoRows):
		return false, nil
	default:
		return false, fmt.Errorf("web: read setting %s: %w", key, err)
	}
}

// proposal is the stored shape of changes.after_summary (change.proposalJSON). Only the fields the
// page shows are decoded; the full proposal is never trusted for display.
type proposal struct {
	Expire []uint64 `json:"expire,omitempty"`
	Reason string   `json:"reason,omitempty"`
}

// proposalSummary turns the stored proposal JSON into a short human-readable line. Malformed JSON
// yields an empty summary rather than failing the page: the pending change is still actionable.
func proposalSummary(stored string) string {
	var p proposal
	if err := json.Unmarshal([]byte(stored), &p); err != nil {
		return ""
	}
	summary := p.Reason
	if len(p.Expire) > 0 {
		if summary != "" {
			summary += "; "
		}
		summary += fmt.Sprintf("%d node expire edilecek", len(p.Expire))
	}
	return summary
}

// PipelineApprover approves through the change pipeline, re-running the plan from the current state
// (F1-010) so a plan that changed is not applied under the old approval.
type PipelineApprover struct {
	Pipeline *change.Pipeline
	Replan   func(ctx context.Context) (change.Request, error)
}

// NewPipelineApprover wires the approval flow.
func NewPipelineApprover(pipeline *change.Pipeline, replan func(ctx context.Context) (change.Request, error)) SyncApprover {
	return PipelineApprover{Pipeline: pipeline, Replan: replan}
}

// Approve applies a pending change; it is *change.Pipeline.Approve. A proposal that changed since the
// form was rendered surfaces as ErrApprovalStale so the handler can tell the operator to reload.
func (a PipelineApprover) Approve(ctx context.Context, actor string, changeID int64, proposalVersion string) (SyncApproval, error) {
	res, err := a.Pipeline.Approve(ctx, actor, changeID, proposalVersion, a.Replan)
	if err != nil {
		if errors.Is(err, change.ErrProposalStale) {
			return SyncApproval{}, ErrApprovalStale
		}
		return SyncApproval{}, err
	}
	return SyncApproval{ChangeID: res.ChangeID, Status: res.Status, Applied: res.Applied}, nil
}

// ChangeRejecter closes a pending change without applying it. The status CHECK allows no "rejected"
// value, so a rejection is stored as failed carrying its reason; the WHERE guard makes it a no-op if
// the change is no longer pending.
type ChangeRejecter struct {
	Queries *db.Queries
	Clock   func() time.Time
}

// NewChangeRejecter wires the rejection path.
func NewChangeRejecter(q *db.Queries) SyncRejecter {
	return ChangeRejecter{Queries: q, Clock: time.Now}
}

// Reject marks the pending change failed with the rejection reason. A change that is not pending is
// refused, so a stale page cannot close a change that already moved on.
func (r ChangeRejecter) Reject(ctx context.Context, changeID int64) error {
	stamp := r.Clock().UTC().Format(storedTimeFormat)
	n, err := r.Queries.RejectChange(ctx, db.RejectChangeParams{
		Error:     "reddedildi",
		UpdatedAt: stamp,
		ID:        changeID,
	})
	if err != nil {
		return fmt.Errorf("web: reject change %d: %w", changeID, err)
	}
	if n == 0 {
		return fmt.Errorf("web: change %d is not pending approval", changeID)
	}
	return nil
}

// SettingDryRun stores dry-run mode in the settings table.
type SettingDryRun struct {
	Queries *db.Queries
	Clock   func() time.Time
}

// NewSettingDryRun wires the dry-run toggle.
func NewSettingDryRun(q *db.Queries) SyncDryRunSetter {
	return SettingDryRun{Queries: q, Clock: time.Now}
}

// SetDryRun writes the dry_run setting under the pipeline's writer lock, so the toggle is serialized
// with an apply: an in-flight apply either observes the new value before it writes or completes first
// (Y-06).
func (s SettingDryRun) SetDryRun(ctx context.Context, on bool) error {
	err := change.WithWriterLock(func() error {
		return s.Queries.UpsertSetting(ctx, db.UpsertSettingParams{
			Key:       dryRunSettingKey,
			Value:     strconv.FormatBool(on),
			UpdatedAt: s.Clock().UTC().Format(storedTimeFormat),
		})
	})
	if err != nil {
		return fmt.Errorf("web: set dry-run: %w", err)
	}
	return nil
}

// SettingInterval stores the periodic reconcile interval in whole minutes.
type SettingInterval struct {
	Queries *db.Queries
	Clock   func() time.Time
}

// NewSettingInterval wires the interval setting.
func NewSettingInterval(q *db.Queries) SyncIntervalSetter {
	return SettingInterval{Queries: q, Clock: time.Now}
}

// SetInterval validates the 1-60 minute bound again (the handler validates too) and writes the
// setting as a whole-minute string, the canonical form sync.IntervalFromSetting reads (F1-013).
func (s SettingInterval) SetInterval(ctx context.Context, minutes int) error {
	if minutes < sync.MinSyncIntervalMinutes || minutes > sync.MaxSyncIntervalMinutes {
		return fmt.Errorf("web: sync interval %d out of range [%d,%d]", minutes, sync.MinSyncIntervalMinutes, sync.MaxSyncIntervalMinutes)
	}
	err := s.Queries.UpsertSetting(ctx, db.UpsertSettingParams{
		Key:       sync.SyncIntervalSetting,
		Value:     strconv.Itoa(minutes),
		UpdatedAt: s.Clock().UTC().Format(storedTimeFormat),
	})
	if err != nil {
		return fmt.Errorf("web: set sync interval: %w", err)
	}
	return nil
}
