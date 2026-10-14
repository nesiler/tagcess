// Reconciler is the reconcile orchestrator (architecture.md §5): one run reads Zitadel and
// Headscale, lets the pure decision engine (plan.go) build a plan, hands the plan to the change
// pipeline and records the outcome. It owns the read-failure alerts: a system that cannot be read
// completely raises an alert and nothing is applied (Y-03.3, Y-04.5); once the read is healthy
// again the alert is resolved (P-02.1).
//
// The orchestrator adds no policy logic of its own: gates, the protection threshold and node
// expiries all come from Compute and Request. Its job is I/O order, the alert lifecycle and
// turning the plan into a change.
package sync

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/headscale"
	"github.com/nesiler/tagcess/internal/maintenance"
	"github.com/nesiler/tagcess/internal/render"
	"github.com/nesiler/tagcess/internal/store/db"
	"github.com/nesiler/tagcess/internal/zitadel"
)

const (
	// SystemActor is the actor recorded for a reconcile nobody triggered by hand (architecture §4).
	SystemActor = "system:sync"

	// AlertReadFailed is raised when Zitadel or Headscale cannot be read completely; the run then
	// applies nothing and keeps the last known-good policy (Y-03.3, Y-04.5).
	AlertReadFailed = "reconcile_read_failed"
	// SourceZitadel and SourceHeadscale make the (kind, source) alert key; they also name the
	// failing system in the dashboard.
	SourceZitadel   = "zitadel"
	SourceHeadscale = "headscale"
)

// Results the orchestrator writes to sync_runs itself. A run that reaches the change pipeline has
// its row written by the pipeline instead.
const (
	// ResultNoChange: the plan had nothing to apply (architecture §4 step 3).
	ResultNoChange = "no_change"
	// ResultReadFailed: a read was incomplete or failed, so nothing was applied.
	ResultReadFailed = "read_failed"
)

const (
	// EventMaintenanceClosed is the audit event of a maintenance that ended after a complete reconcile
	// (H-07, F3b-019).
	EventMaintenanceClosed = "headscale.maintenance.closed"
	// DryRunSkippedNote is the close note when dry run was on: the reconcile counted as complete but
	// applied no diff (R2:29 f). The UI (F3b-020) words it.
	DryRunSkippedNote = "dry_run_skipped"
)

// timeFormat matches the audit log, the change pipeline and the migration seeds: fixed-width
// milliseconds so the text sorts chronologically in SQLite.
const timeFormat = "2006-01-02T15:04:05.000Z"

var validTriggers = map[string]bool{"webhook": true, "periodic": true, "manual": true}

// ZitadelReader is the read-only Zitadel surface the orchestrator uses (satisfied by *zitadel.Client).
type ZitadelReader interface {
	ListGrants(ctx context.Context) ([]zitadel.Grant, error)
	UserStates(ctx context.Context, ids []string) (map[string]zitadel.UserState, error)
}

// HeadscaleReader is the Headscale read surface (satisfied by *headscale.Client).
type HeadscaleReader interface {
	GetPolicy(ctx context.Context) (headscale.Policy, error)
	ListUsers(ctx context.Context) ([]headscale.User, error)
	ListNodes(ctx context.Context) ([]headscale.Node, error)
}

// Pipeline applies a change. It is satisfied by *change.Pipeline.
type Pipeline interface {
	Submit(ctx context.Context, req change.Request) (change.Result, error)
}

// DryRun reports whether tagcess is in dry-run mode (Y-06). Satisfied by *store.Store.
type DryRun interface {
	DryRun(ctx context.Context) (bool, error)
}

// MaintenanceFlag is the maintenance row as the reconcile uses it (H-07, ADR 0021 c/d): it records a
// reconcile the gate held back, and a complete reconcile ends a maintenance that is waiting for one.
// Satisfied by *maintenance.Service.
type MaintenanceFlag interface {
	MarkPendingReconcile(ctx context.Context) error
	Get(ctx context.Context) (maintenance.Status, error)
	Off(ctx context.Context, note string) error
}

// ReconcilerConfig wires the orchestrator. Only Zitadel, Headscale, Pipeline, Queries, DryRun and
// Issuer are required.
type ReconcilerConfig struct {
	Zitadel   ZitadelReader
	Headscale HeadscaleReader
	Pipeline  Pipeline
	Queries   *db.Queries
	DryRun    DryRun
	// Issuer is the OIDC issuer of the Zitadel instance; Headscale users whose provider ID is not
	// "<Issuer>/<id>" are left alone.
	Issuer string
	// Actor is recorded on the change and its audit events. Empty means SystemActor.
	Actor string
	// Format writes a user into the policy. Empty means render.ProviderIDFormat(Issuer).
	Format render.MemberFormat
	// Settings carries the protection thresholds; the dry-run flag is read through DryRun each run.
	Settings Settings
	// Clock is the time source; empty means time.Now.
	Clock func() time.Time
	// Maintenance, when set, is told about a run whose policy step the maintenance gate held, which
	// becomes the durable pending reconcile intent (F3b-016). A run that starts while the maintenance
	// is reconcile_pending and finishes complete and clean also ends it (F3b-019).
	Maintenance MaintenanceFlag
	// Keys, when set, enables the personal pre-auth key revocation step (F3-013): usable personal
	// keys of users without a role or with a closed account are expired after the group and node
	// steps. Use NewKeyRevoker for the executor-backed implementation.
	Keys KeyRevoker
	// PeriodicCheck, when set, runs after every periodic run (Y-02): the F2-010 redirect URI drift
	// check (change.SitePipeline.CheckURIDrift). Its error is returned next to the run's own, so
	// the scheduler logs it; it never stops or changes the reconcile.
	PeriodicCheck func(ctx context.Context) error
}

// Reconciler performs a reconcile run. It does not serialize runs itself; the debounced scheduler
// (F1-013) is the single caller, and the change pipeline holds the process-wide writer lock for
// applies.
type Reconciler struct {
	z        ZitadelReader
	hs       HeadscaleReader
	pipe     Pipeline
	q        *db.Queries
	dryRun   DryRun
	issuer   string
	actor    string
	format   render.MemberFormat
	settings Settings
	clock    func() time.Time
	periodic func(ctx context.Context) error
	keys     KeyRevoker
	maint    MaintenanceFlag
}

// NewReconciler validates the wiring and returns the orchestrator.
func NewReconciler(cfg ReconcilerConfig) (*Reconciler, error) {
	switch {
	case cfg.Zitadel == nil:
		return nil, errors.New("sync: a Zitadel reader is required")
	case cfg.Headscale == nil:
		return nil, errors.New("sync: a Headscale reader is required")
	case cfg.Pipeline == nil:
		return nil, errors.New("sync: a change pipeline is required")
	case cfg.Queries == nil:
		return nil, errors.New("sync: a query set is required")
	case cfg.DryRun == nil:
		return nil, errors.New("sync: a dry-run source is required")
	case strings.TrimSpace(cfg.Issuer) == "":
		return nil, errors.New("sync: an issuer is required")
	}
	r := &Reconciler{
		z:        cfg.Zitadel,
		hs:       cfg.Headscale,
		pipe:     cfg.Pipeline,
		q:        cfg.Queries,
		dryRun:   cfg.DryRun,
		issuer:   cfg.Issuer,
		actor:    cfg.Actor,
		format:   cfg.Format,
		settings: cfg.Settings,
		clock:    cfg.Clock,
		periodic: cfg.PeriodicCheck,
		keys:     cfg.Keys,
		maint:    cfg.Maintenance,
	}
	if strings.TrimSpace(r.actor) == "" {
		r.actor = SystemActor
	}
	if r.format == nil {
		r.format = render.ProviderIDFormat(r.issuer)
	}
	if r.clock == nil {
		r.clock = time.Now
	}
	return r, nil
}

// Result is what one reconcile run did.
type Result struct {
	// Status is the change status when the pipeline ran, else ResultNoChange or ResultReadFailed.
	Status string
	Plan   Plan
	Change change.Result
	// RevokedKeys are the personal pre-auth keys the key step expired; in dry run, the ones it
	// would have expired. KeyErr is the key step's failure, also raised as an alert; it never
	// affects Status or the group and node steps.
	RevokedKeys []KeyRevocation
	KeyErr      error
}

// Run performs one reconcile: read, plan, apply, record. It returns an error only when the run
// could not be carried out (a broken database or wiring), never for a read failure of the managed
// systems: those are recorded and alerted, and the run is a normal ResultReadFailed. A periodic
// run then also runs the PeriodicCheck (F2-011 AC6).
func (r *Reconciler) Run(ctx context.Context, trigger string) (Result, error) {
	// A reconcile_pending maintenance is read before the run: only a run that began after the success
	// (or the explicit close) counts as the reconcile that ends it. The run itself does not depend on
	// the pending mark; it always runs (F3b-016 review).
	waiting, werr := r.waitingMaintenance(ctx)
	res, err := r.reconcile(ctx, trigger)
	err = errors.Join(werr, err)
	if waiting != "" && err == nil {
		err = r.endMaintenance(ctx, waiting, res)
	}
	if trigger == TriggerPeriodic && r.periodic != nil {
		err = errors.Join(err, r.periodic(ctx))
	}
	return res, err
}

// waitingMaintenance returns the request ID of a maintenance that is waiting for this reconcile, or
// "" when there is none or the state cannot be read (then nothing is closed; fail safe).
func (r *Reconciler) waitingMaintenance(ctx context.Context) (string, error) {
	if r.maint == nil {
		return "", nil
	}
	st, err := r.maint.Get(ctx)
	if err != nil {
		return "", fmt.Errorf("sync: read maintenance: %w", err)
	}
	if st.State != maintenance.ReconcilePending {
		return "", nil
	}
	return st.RequestID, nil
}

// endMaintenance ends the maintenance after a run that read both systems and applied or found
// nothing to apply (or only reported, in dry run). Anything else keeps reconcile_pending: a failed
// or held change, a blocked or approval-pending plan, a failed read. The audit comes first, so a
// crash in between repeats it instead of losing it.
func (r *Reconciler) endMaintenance(ctx context.Context, requestID string, res Result) error {
	switch res.Status {
	case ResultNoChange, change.StatusApplied, change.StatusDryRun:
	default:
		return nil
	}
	note := ""
	if res.Plan.DryRun {
		note = DryRunSkippedNote
	}
	entry := audit.Entry{
		Actor: r.actor, Event: EventMaintenanceClosed, Target: "request:" + requestID, Result: string(maintenance.Off),
		Diff: audit.Diff{{Field: "reconcile", After: res.Status}, {Field: "close_note", After: note}},
	}
	if _, err := audit.New(r.q).Write(ctx, entry); err != nil {
		return fmt.Errorf("sync: audit maintenance close: %w", err)
	}
	if err := r.maint.Off(ctx, note); err != nil && !errors.Is(err, maintenance.ErrInvalidTransition) {
		return fmt.Errorf("sync: end maintenance: %w", err)
	}
	return nil
}

func (r *Reconciler) reconcile(ctx context.Context, trigger string) (Result, error) {
	if !validTriggers[trigger] {
		return Result{}, fmt.Errorf("sync: unknown trigger %q", trigger)
	}
	ev, err := r.evaluate(ctx)
	// Resolve the read alerts before acting on an evaluation error: a failed dry-run read must not
	// skip the alert lifecycle (the reads themselves were healthy in that path).
	if uerr := r.updateReadAlert(ctx, SourceHeadscale, ev.hsErr, ev.now); uerr != nil {
		return Result{}, uerr
	}
	if uerr := r.updateReadAlert(ctx, SourceZitadel, ev.zErr, ev.now); uerr != nil {
		return Result{}, uerr
	}
	if err != nil {
		return Result{}, err
	}

	if ev.hsErr != nil || ev.zErr != nil {
		var res Result
		res.Status = ResultReadFailed
		reason := readFailureReason(ev.zErr, ev.hsErr)
		if err := r.recordRun(ctx, trigger, ResultReadFailed, reason, ev.now); err != nil {
			return res, err
		}
		return res, nil
	}

	res, err := r.applyPlan(ctx, trigger, ev)
	// The read was healthy, so the key step runs whatever the group and node steps did.
	return res, errors.Join(err, r.revokeKeys(ctx, ev, &res))
}

// applyPlan hands the plan of a healthy read to the change pipeline and records the run.
func (r *Reconciler) applyPlan(ctx context.Context, trigger string, ev evaluation) (Result, error) {
	var res Result
	in, plan := ev.in, ev.plan
	res.Plan = plan

	req, err := Request(in, plan, r.actor, trigger, planSummary(plan))
	if err != nil {
		// The plan could not be turned into a change; nothing was applied. Record it so a
		// persistent problem is visible on the dashboard instead of only in the caller's log.
		reason := "plan apply edilemedi: " + err.Error()
		if rerr := r.recordRun(ctx, trigger, ResultReadFailed, reason, ev.now); rerr != nil {
			return res, errors.Join(err, rerr)
		}
		return res, fmt.Errorf("sync: build change request: %w", err)
	}
	// Nothing to apply: no diff and no gate. Blocked/NeedsApproval plans still go to the pipeline
	// so the operator sees them.
	if !req.Blocked && !req.NeedsApproval && !planHasChanges(plan) {
		res.Status = ResultNoChange
		if err := r.recordRun(ctx, trigger, ResultNoChange, planSummary(plan), ev.now); err != nil {
			return res, err
		}
		// The read was complete and the live state already matches the wanted one, so a critical
		// alert an earlier change raised no longer describes reality: clear it like a clean apply,
		// otherwise a problem fixed out of band would stay on the dashboard forever.
		if err := r.resolveApplyAlerts(ctx, ev.now); err != nil {
			return res, err
		}
		return res, nil
	}

	cres, err := r.pipe.Submit(ctx, req)
	// The gate held the policy step: node expiries ran (or failed and are retried), and the held
	// reconcile becomes a durable pending intent that survives a restart (F3b-016, ADR 0021 d).
	if cres.PolicyHeld && r.maint != nil {
		if merr := r.maint.MarkPendingReconcile(ctx); merr != nil {
			err = errors.Join(err, fmt.Errorf("sync: mark pending reconcile: %w", merr))
		}
	}
	if err != nil {
		return res, err
	}
	res.Change = cres
	res.Status = cres.Status
	// A clean apply verifies the whole rendered policy and writes its records, so it is the proof
	// that a critical alert from an earlier change no longer describes reality (F1-011 AC3). A
	// failed apply must not clear its own alert, so this runs only on success.
	if cres.Applied {
		if err := r.resolveApplyAlerts(ctx, ev.now); err != nil {
			return res, err
		}
	}
	return res, nil
}

// evaluation is one read-and-decide pass over the managed systems: the Compute input, the plan and
// the per-system read errors. The caller decides what to do with it (Run records and applies,
// Preview shows, Replan rebuilds a request). A read error is carried, not returned as an error.
type evaluation struct {
	in    Input
	plan  Plan
	hsErr error
	zErr  error
	now   time.Time
}

// evaluate reads Zitadel and Headscale and computes the plan without applying or recording anything.
// It never touches the alert lifecycle (Run owns that). A read failure becomes part of the input, so
// Compute explains it in the plan reason instead of yielding an error (fail safe).
func (r *Reconciler) evaluate(ctx context.Context) (evaluation, error) {
	now := r.clock().UTC()

	// Read every system independently so a failure in one still lets the other's alert resolve.
	policy, pErr := r.hs.GetPolicy(ctx)
	users, uErr := r.hs.ListUsers(ctx)
	nodes, nErr := r.hs.ListNodes(ctx)
	grants, gErr := r.z.ListGrants(ctx)

	var (
		states map[string]zitadel.UserState
		sErr   error
	)
	if gErr == nil {
		var ids []string
		if pErr == nil && uErr == nil && nErr == nil {
			ids = r.stateIDs(grants, users, nodes)
		} else {
			ids = grantUserIDs(grants)
		}
		states, sErr = r.z.UserStates(ctx, ids)
		if sErr != nil {
			sErr = fmt.Errorf("kullanıcı durumları: %w", sErr)
		}
	}
	hsErr := errors.Join(pErr, uErr, nErr)
	zErr := errors.Join(gErr, sErr)
	readErr := errors.Join(zErr, hsErr)

	in := Input{
		Read:   Read{Complete: readErr == nil, Err: readErr, Grants: grants, States: states},
		Policy: []byte(policy.Text),
		// The decision engine expects every role of the vpn project. Zitadel's role-listing APIs
		// are unusable in F1 (R1 B-04), so the roles are derived from the grants: a role the
		// project no longer hands out counts as removed, which holds the plan for approval rather
		// than applying it silently.
		Roles:  rolesFromGrants(grants),
		Users:  users,
		Nodes:  nodes,
		Format: r.format,
		Issuer: r.issuer,
		Now:    now,
	}
	// Dry run is only read from a trusted state; a failed read already gates the plan, and touching
	// the settings on a read failure would only add another failure path. When the dry-run read
	// itself fails, the partial evaluation is returned alongside the error so Run can still resolve
	// the read alerts for the healthy systems before it aborts.
	if readErr == nil {
		dryRun, err := r.dryRun.DryRun(ctx)
		if err != nil {
			return evaluation{in: in, plan: Compute(in), hsErr: hsErr, zErr: zErr, now: now},
				fmt.Errorf("sync: read dry-run setting: %w", err)
		}
		in.Settings = Settings{DryRun: dryRun, MaxRemovedPercent: r.settings.MaxRemovedPercent, MaxRemovedUsers: r.settings.MaxRemovedUsers}
	}
	return evaluation{in: in, plan: Compute(in), hsErr: hsErr, zErr: zErr, now: now}, nil
}

// Evaluation is one read-and-decide pass for callers outside the package: the policy writer (F3-010)
// runs it under the writer lock to get the Compute input and plan, and tells a Headscale read failure
// from a Zitadel one.
type Evaluation struct {
	Input        Input
	Plan         Plan
	HeadscaleErr error
	ZitadelErr   error
}

// Evaluate reads Zitadel and Headscale and computes the plan without applying or recording anything. A
// failed read is carried in the Evaluation, not returned; the error is only a failed dry-run read.
func (r *Reconciler) Evaluate(ctx context.Context) (Evaluation, error) {
	ev, err := r.evaluate(ctx)
	return Evaluation{Input: ev.in, Plan: ev.plan, HeadscaleErr: ev.hsErr, ZitadelErr: ev.zErr}, err
}

// Preview computes the current diff without applying or recording anything. It is the read-only view
// behind the sync screen (Y-05.1): a failed read yields a plan whose Reason names the failure rather
// than an error, so the page shows why it cannot show a diff.
func (r *Reconciler) Preview(ctx context.Context) (Plan, error) {
	ev, err := r.evaluate(ctx)
	if err != nil {
		return Plan{}, err
	}
	return ev.plan, nil
}

// Replan rebuilds the change request from the current state for the approval flow (F1-010): the
// change pipeline re-runs it before applying so a plan that changed since it was proposed is not
// applied. On a failed read, Request marks the request blocked, so an untrusted read never becomes a
// change. The pipeline overwrites the actor and trigger on approval.
func (r *Reconciler) Replan(ctx context.Context) (change.Request, error) {
	ev, err := r.evaluate(ctx)
	if err != nil {
		return change.Request{}, err
	}
	return Request(ev.in, ev.plan, r.actor, TriggerManual, planSummary(ev.plan))
}

// resolveApplyAlerts clears the pipeline's critical alerts whose cause a clean apply or a no-change
// run proves gone: the write was verified (mismatch/unverified/stale) and a pending node expiry was
// retried or is no longer needed. A bookkeeping alert is deliberately not cleared: the record it
// reports as lost stays lost, so the operator must still see it.
func (r *Reconciler) resolveApplyAlerts(ctx context.Context, now time.Time) error {
	for _, kind := range []string{
		change.AlertPolicyMismatch,
		change.AlertPolicyUnverified,
		change.AlertPolicyExpireFailed,
		change.AlertPolicyStale,
	} {
		if _, err := r.q.ResolveAlertKind(ctx, db.ResolveAlertKindParams{
			ResolvedAt: sql.NullString{String: now.Format(timeFormat), Valid: true}, Kind: kind,
		}); err != nil {
			return fmt.Errorf("sync: resolve %s alert: %w", kind, err)
		}
	}
	return nil
}

// stateIDs is the set of Zitadel users whose state matters: everyone with a grant, plus the owner
// of every untagged Headscale node (a tagged node is owned by its tag and never expired, so its
// creator's state is irrelevant). Sorted for determinism.
func (r *Reconciler) stateIDs(grants []zitadel.Grant, users []headscale.User, nodes []headscale.Node) []string {
	set := map[string]bool{}
	for _, g := range grants {
		set[g.UserID] = true
	}
	owner := map[uint64]string{}
	for _, u := range users {
		if id, ok := render.MatchUserID(u.ProviderID, r.issuer); ok {
			owner[u.ID] = id
		}
	}
	for _, n := range nodes {
		if len(n.Tags) > 0 {
			continue
		}
		if id, ok := owner[n.UserID]; ok {
			set[id] = true
		}
	}
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func grantUserIDs(grants []zitadel.Grant) []string {
	set := map[string]bool{}
	for _, g := range grants {
		set[g.UserID] = true
	}
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func rolesFromGrants(grants []zitadel.Grant) []string {
	set := map[string]bool{}
	for _, g := range grants {
		set[g.Role] = true
	}
	out := make([]string, 0, len(set))
	for role := range set {
		out = append(out, role)
	}
	sort.Strings(out)
	return out
}

// updateReadAlert raises (readErr != nil) or resolves (readErr == nil) the read alert of one
// system. A repeated failure bumps the open row's last_seen_at instead of inserting a duplicate.
func (r *Reconciler) updateReadAlert(ctx context.Context, source string, readErr error, now time.Time) error {
	return r.updateAlert(ctx, AlertReadFailed, source, readErr, now)
}

// updateAlert is updateReadAlert for any alert kind: raised (or touched) while cause is non-nil,
// resolved when it is nil.
func (r *Reconciler) updateAlert(ctx context.Context, kind, source string, cause error, now time.Time) error {
	stamp := now.Format(timeFormat)
	if cause == nil {
		if _, err := r.q.ResolveAlerts(ctx, db.ResolveAlertsParams{
			ResolvedAt: sql.NullString{String: stamp, Valid: true}, Kind: kind, Source: source,
		}); err != nil {
			return fmt.Errorf("sync: resolve %s alert: %w", source, err)
		}
		return nil
	}
	touched, err := r.q.TouchAlert(ctx, db.TouchAlertParams{
		LastSeenAt: stamp, Kind: kind, Source: source,
	})
	if err != nil {
		return fmt.Errorf("sync: touch %s alert: %w", source, err)
	}
	if touched > 0 {
		return nil
	}
	if _, err := r.q.InsertAlert(ctx, db.InsertAlertParams{
		Kind: kind, Source: source, FirstSeenAt: stamp, LastSeenAt: stamp,
	}); err != nil {
		return fmt.Errorf("sync: raise %s alert: %w", source, err)
	}
	return nil
}

func (r *Reconciler) recordRun(ctx context.Context, trigger, result, summary string, now time.Time) error {
	if _, err := r.q.InsertSyncRun(ctx, db.InsertSyncRunParams{
		StartedAt: now.Format(timeFormat), Trigger: trigger, Result: result, DiffSummary: summary,
	}); err != nil {
		return fmt.Errorf("sync: record run: %w", err)
	}
	return nil
}

// planHasChanges reports whether the plan would touch Headscale at all.
func planHasChanges(p Plan) bool {
	return len(p.GroupDiff.Groups) > 0 || len(p.GroupDiff.RemovedGroups) > 0 || len(p.ExpireNodes) > 0
}

// planSummary is the human-readable diff written to sync_runs.
func planSummary(p Plan) string {
	var added, removed int
	for _, g := range p.GroupDiff.Groups {
		added += len(g.Added)
		removed += len(g.Removed)
	}
	var parts []string
	if added > 0 || removed > 0 {
		parts = append(parts, fmt.Sprintf("%d üye eklendi, %d çıkarıldı", added, removed))
	}
	if len(p.GroupDiff.RemovedGroups) > 0 {
		parts = append(parts, fmt.Sprintf("%d grup silinecek", len(p.GroupDiff.RemovedGroups)))
	}
	if len(p.ExpireNodes) > 0 {
		parts = append(parts, fmt.Sprintf("%d node expire edilecek", len(p.ExpireNodes)))
	}
	if p.Identity != nil {
		parts = append(parts, fmt.Sprintf("Kimlik dönüşümü: %d kimlik, %d eşleşmeyen, %d düşürülecek",
			len(p.Identity.Mappings), len(p.Identity.Unmatched), len(p.Identity.Dropped)))
	}
	if len(parts) == 0 {
		return "fark yok"
	}
	if p.Reason != "" {
		parts = append(parts, p.Reason)
	}
	return strings.Join(parts, "; ")
}

func readFailureReason(errs ...error) string {
	parts := []string{"okuma hatası"}
	for _, e := range errs {
		if e != nil {
			parts = append(parts, e.Error())
		}
	}
	return strings.Join(parts, "; ")
}
