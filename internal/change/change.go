// Package change is tagcess's change pipeline (architecture.md §4). Every write to a managed system
// goes through it: the request is validated, gated (approval, dry run), applied under a single
// writer lock, read back, and recorded in changes, sync_runs and the audit log. A failure after a
// write never restores a previous artifact unless it is proven not to widen access: on a
// verification mismatch the live state is kept (restoring the previous policy cannot be shown safe),
// when the outcome is unknown the last known-good state is kept, and only a follow-up step (node
// expire) failing after the policy was verified keeps the verified policy; every one of these raises
// a critical alert (rule 7). Terminal records are retried and then backed by an independent alert so
// an applied write is never silently lost.
//
// F1 only applies the Headscale policy and node expiries; F2 adds the Caddy, DNS and Zitadel
// artifacts. The package is deliberately independent of internal/sync so the reconcile
// orchestrator can depend on it.
package change

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tailscale/hujson"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/gitlog"
	"github.com/nesiler/tagcess/internal/headscale"
	"github.com/nesiler/tagcess/internal/maintenance"
	"github.com/nesiler/tagcess/internal/store/db"
)

// Change statuses and results. The first four fit the changes.status CHECK constraint; the last
// three are results the pipeline reports without storing a change row.
const (
	StatusPendingApproval = "pending_approval"
	StatusApplied         = "applied"
	StatusFailed          = "failed"
	StatusRolledBack      = "rolled_back"

	StatusBlocked         = "blocked"
	StatusDryRun          = "dry_run"
	StatusNeedsReapproval = "needs_reapproval"
	// StatusHeld is the result of a sync request whose policy step the maintenance gate skipped
	// (F3b-015); Result.PolicyHeld says the same.
	StatusHeld = "held"
)

// KindPolicy is the change kind for the Headscale ACL policy and node expiries.
const KindPolicy = "policy"

// Alert kinds raised when a policy change could not be completed safely. They are distinct so the
// dashboard tells a verification mismatch apart from an expiry failure, an unverifiable write, a
// stale plan and a failed record.
const (
	// AlertPolicyMismatch is raised when an applied policy read back different from the target. The
	// pipeline does not restore the previous policy: it cannot prove the restore would not widen
	// access, so it keeps the live state and asks an operator to reconcile (rule 7).
	AlertPolicyMismatch = "policy_mismatch"
	// AlertPolicyExpireFailed is raised when the verified policy was kept but a node expiry failed;
	// the next reconcile retries the expiry (rule 7: never widen access).
	AlertPolicyExpireFailed = "policy_expire_failed"
	// AlertPolicyUnverified is raised when a policy write's outcome could not be read back; the last
	// verified/known-good state is kept rather than guessed at.
	AlertPolicyUnverified = "policy_unverified"
	// AlertPolicyStale is raised when the plan was computed from a policy that has since changed.
	AlertPolicyStale = "policy_stale"
	// AlertPolicyBookkeepingFailed is raised when the external write succeeded but its change,
	// sync_run or audit record could not be written.
	AlertPolicyBookkeepingFailed = "policy_bookkeeping_failed"
)

// timeFormat matches the audit log and the migration seeds: fixed-width milliseconds, so the text
// sorts chronologically in SQLite.
const timeFormat = "2006-01-02T15:04:05.000Z"

// recoveryTimeout bounds the bookkeeping that must still happen after an external write was
// attempted, even when the caller's context was canceled (shutdown).
const recoveryTimeout = 10 * time.Second

// ErrNotPending means the change is not waiting for approval.
var ErrNotPending = errors.New("change: not pending approval")

// ErrProposalStale means the proposal an approval form was rendered from is no longer the stored one
// (a reapproval replaced it). The approval is refused so a stale form cannot apply a plan the
// operator never saw (Y-03.4).
var ErrProposalStale = errors.New("change: proposal changed; reload and approve again")

// Headscale is the narrow write surface the pipeline needs: read the policy, validate and set it,
// and expire a node. It is satisfied by *headscale.Client.
type Headscale interface {
	GetPolicy(ctx context.Context) (headscale.Policy, error)
	CheckPolicy(ctx context.Context, policy string) error
	SetPolicy(ctx context.Context, policy string) (headscale.Policy, error)
	ExpireNode(ctx context.Context, id uint64) (headscale.Node, error)
}

// Request is one change to apply: the rendered artifact plus the node expiries that follow it.
type Request struct {
	Kind    string
	Actor   string
	Trigger string
	Summary string
	// Target is the artifact to write (for KindPolicy: the rendered policy text).
	Target []byte
	// Expire lists Headscale node ids to expire after the target is verified.
	Expire []uint64
	// SourcePolicy is the policy snapshot the target was computed from. When set, the pipeline
	// refuses to overwrite a policy that changed since, so a stale plan cannot silently drop a
	// concurrent change (lost update). Empty skips the check.
	SourcePolicy []byte
	// Gates: at most one applies. Blocked never reaches Headscale, NeedsApproval waits for an
	// approver, DryRun only records the run.
	Blocked       bool
	NeedsApproval bool
	DryRun        bool
	Reason        string
	// Revision describes the policy revision recorded for this request when the pipeline has a
	// PolicyRevisions recorder (H-04, F3-010). Callers set Source explicitly; the sync flow sets
	// "sync" (sync.Request).
	Revision RevisionMeta
}

// RevisionMeta is what a policy revision records beyond the target text. Source is explicit; an
// empty Source is not the sync flow, the maintenance gate treats it as an admin write (F3b-027 AC2).
type RevisionMeta struct {
	Source     string // ui, sync, rollback or recovery
	Reason     string
	Validation string // JSON stage results; empty means "{}"
	RollbackOf int64
}

// Revision outcomes, matching the policy revision statuses the recorder finishes with.
const (
	RevisionApplied = "applied"
	RevisionFailed  = "failed"
	RevisionUnknown = "unknown"
	RevisionDryRun  = "dry_run"
)

// PolicyRevisions records the durable revision of a policy write (H-04, A-03). It is optional: without
// it nothing is recorded. Begin stores the pending revision before the write and returns its id; if
// it fails the write is not attempted. Finish moves it once to its final outcome.
type PolicyRevisions interface {
	Begin(ctx context.Context, req Request, changeID int64) (int64, error)
	Finish(ctx context.Context, id int64, outcome, detail string) error
}

// Result is what the pipeline did with a request.
type Result struct {
	ChangeID int64
	Status   string
	Applied  bool
	// Revision is the Git revision of the verified artifacts (A-02). It is empty when no history is
	// configured or the commit failed; GitFailed tells the two apart, so a missing revision is never
	// shown as a success.
	Revision  string
	GitFailed bool
	// RevisionID is the policy revision recorded for this apply; 0 when no recorder is configured.
	RevisionID int64
	// PolicyHeld says the maintenance gate skipped the policy step of a sync request: nothing was
	// written to the policy (the Expire list still ran). The sync turns it into a pending reconcile.
	PolicyHeld bool

	// outcome and detail say how the revision ends when the apply did not complete cleanly.
	outcome string
	detail  string
}

// writerLock serializes every apply in the process. It is package-level, not per Pipeline: the
// architecture wants one writer (architecture §4), so a caller that builds several Pipeline values
// still cannot run two applies at once.
var writerLock sync.Mutex

// WithWriterLock runs fn while holding the process-wide writer lock. The settings layer uses it to
// make a dry-run toggle atomic with an apply (Y-06): either the apply reads the new value before it
// writes, or the toggle takes effect after the apply finished. fn must not call Submit or Approve
// (the lock is not reentrant).
func WithWriterLock(fn func() error) error {
	writerLock.Lock()
	defer writerLock.Unlock()
	return fn()
}

// WriterLockBusy reports whether an apply holds the writer lock right now. It never waits and never
// keeps the lock, so a read-only checker (the drift check) can skip while artifacts are in flux.
func WriterLockBusy() bool {
	if !writerLock.TryLock() {
		return true
	}
	writerLock.Unlock()
	return false
}

// DryRun reports whether dry-run mode is on (Y-06). It is read inside the writer lock immediately
// before an external write, so a toggle that landed after a plan was computed still stops the write.
// Satisfied by *store.Store.
type DryRun interface {
	DryRun(ctx context.Context) (bool, error)
}

// MaintenanceGate is the Headscale maintenance gate (H-07, ADR 0021): CheckWidening refuses while a
// host change is running and, after it, until the reconcile finished. *maintenance.Service satisfies
// it.
type MaintenanceGate interface {
	CheckWidening(ctx context.Context, source string) error
}

// Pipeline applies changes. Use New.
type Pipeline struct {
	hs     Headscale
	q      *db.Queries
	log    *audit.Logger
	dryRun DryRun
	clock  func() time.Time
	git    ArtifactGit
	revs   PolicyRevisions
	maint  MaintenanceGate
}

// WithMaintenance sets the maintenance gate checked under the writer lock before every policy write
// (F3b-015) and returns the pipeline. Without it the policy is never held.
func (p *Pipeline) WithMaintenance(g MaintenanceGate) *Pipeline {
	p.maint = g
	return p
}

// WithRevisions sets the recorder that stores a revision for every policy apply (H-04) and returns the
// pipeline. Without it no revision is recorded.
func (p *Pipeline) WithRevisions(r PolicyRevisions) *Pipeline {
	p.revs = r
	return p
}

// WithGit sets the local history the verified policy is committed to (A-02, ADR 0016) and returns
// the pipeline. Without it nothing is committed.
func (p *Pipeline) WithGit(g ArtifactGit) *Pipeline {
	p.git = g
	return p
}

// New returns a pipeline writing to the given Headscale client, query set and audit log. dryRun is
// required: it is read under the writer lock right before every write so a dry-run toggle is honored.
func New(hs Headscale, q *db.Queries, log *audit.Logger, dryRun DryRun) *Pipeline {
	return &Pipeline{hs: hs, q: q, log: log, dryRun: dryRun, clock: time.Now}
}

// ProposalVersion is the stable version/hash of a stored proposal (changes.after_summary). The sync
// page renders it into the approval form and Approve checks it under the writer lock, so a stale form
// can never apply a proposal that was replaced in the meantime (Y-03.4).
func ProposalVersion(afterSummary string) string {
	sum := sha256.Sum256([]byte(afterSummary))
	return hex.EncodeToString(sum[:])
}

// Submit handles a freshly computed plan. A blocked plan is recorded and never applied, a dry run
// only records the run, and a plan that needs approval is stored until Approve is called.
func (p *Pipeline) Submit(ctx context.Context, req Request) (Result, error) {
	if err := validateActor(req.Actor); err != nil {
		return Result{}, err
	}
	writerLock.Lock()
	defer writerLock.Unlock()
	return p.submitLocked(ctx, req)
}

// SubmitBuilt takes the writer lock first and then asks build for the request, so every read build
// makes (live policy, users, nodes, Zitadel roles) is covered by the same lock as the apply
// (ADR 0020). A build error is returned as is and nothing is written. The actor is stamped on the
// request. build must not call Submit, SubmitBuilt or Approve (the lock is not reentrant).
func (p *Pipeline) SubmitBuilt(ctx context.Context, actor string, build func(context.Context) (Request, error)) (Result, error) {
	if err := validateActor(actor); err != nil {
		return Result{}, err
	}
	writerLock.Lock()
	defer writerLock.Unlock()
	req, err := build(ctx)
	if err != nil {
		return Result{}, err
	}
	req.Actor = actor
	return p.submitLocked(ctx, req)
}

// submitLocked is Submit's body; the caller holds the writer lock and has validated the actor.
func (p *Pipeline) submitLocked(ctx context.Context, req Request) (Result, error) {
	if req.Kind == "" {
		req.Kind = KindPolicy
	}
	// Dry run wins over every other gate: it never writes to a managed system, so it must never
	// create a change row or an approval either (Y-06).
	switch {
	case req.DryRun:
		if err := p.syncRun(ctx, req, StatusDryRun, req.Summary); err != nil {
			return Result{}, err
		}
		return Result{Status: StatusDryRun}, nil
	case req.Blocked:
		id, err := p.finish(ctx, 0, req, StatusFailed, "", "plan bloklu: "+req.Reason)
		if err != nil {
			return Result{}, err
		}
		if err := p.syncRun(ctx, req, StatusBlocked, req.Reason); err != nil {
			return Result{}, err
		}
		if err := p.audit(ctx, req, "policy.blocked", StatusBlocked, req.Reason); err != nil {
			return Result{}, err
		}
		return Result{ChangeID: id, Status: StatusBlocked}, nil
	case req.NeedsApproval:
		id, err := p.finish(ctx, 0, req, StatusPendingApproval, "", "")
		if err != nil {
			return Result{}, err
		}
		if err := p.syncRun(ctx, req, StatusPendingApproval, req.Summary); err != nil {
			return Result{}, err
		}
		if err := p.audit(ctx, req, "policy.pending_approval", StatusPendingApproval, req.Reason); err != nil {
			return Result{}, err
		}
		return Result{ChangeID: id, Status: StatusPendingApproval}, nil
	default:
		return p.applyLocked(ctx, 0, req)
	}
}

// Approve applies a pending change. proposalVersion must be the version of the proposal the operator
// saw (ProposalVersion of the stored after_summary); it is checked under the writer lock first, so a
// stale form whose proposal was replaced in the meantime is refused with ErrProposalStale and nothing
// is applied. It then asks replan for the plan from the current state: if the plan changed it
// replaces the stored proposal and waits for approval again; only an unchanged plan is applied
// (Y-03.4). replan runs under the writer lock and must not call back into Submit/Approve (the lock is
// not reentrant), and it should build its request with sync.Request so an unapplicable read never
// becomes a change.
func (p *Pipeline) Approve(ctx context.Context, actor string, changeID int64, proposalVersion string, replan func(context.Context) (Request, error)) (Result, error) {
	if err := validateActor(actor); err != nil {
		return Result{}, err
	}
	writerLock.Lock()
	defer writerLock.Unlock()

	row, err := p.q.GetChange(ctx, changeID)
	if err != nil {
		return Result{}, fmt.Errorf("change: read %d: %w", changeID, err)
	}
	if row.Status != StatusPendingApproval {
		return Result{}, fmt.Errorf("%w: change %d is %s", ErrNotPending, changeID, row.Status)
	}
	// Bind the approval to the version the operator saw: if a reapproval replaced the stored proposal
	// after the page was rendered, this form must not apply the unseen plan (Y-03.4).
	if ProposalVersion(row.AfterSummary) != proposalVersion {
		return Result{}, ErrProposalStale
	}

	fresh, err := replan(ctx)
	fresh.Actor = actor
	// An approval is a manual action; this also keeps sync_runs.trigger valid when replan failed and
	// returned a zero request (the trigger column has a CHECK constraint).
	fresh.Trigger = "manual"
	if fresh.Kind == "" {
		fresh.Kind = row.Kind
	}
	if err != nil {
		id, ferr := p.finish(ctx, changeID, fresh, StatusFailed, row.BeforeSummary, "yeniden hesaplama başarısız: "+err.Error())
		if ferr != nil {
			return Result{}, ferr
		}
		if serr := p.syncRun(ctx, fresh, StatusFailed, err.Error()); serr != nil {
			return Result{}, serr
		}
		if aerr := p.audit(ctx, fresh, "policy.approve_failed", StatusFailed, err.Error()); aerr != nil {
			return Result{}, aerr
		}
		return Result{ChangeID: id, Status: StatusFailed}, nil
	}
	// Dry run switched on after the change was queued: approving must only record the run, never
	// write (Y-06.1). The change stays pending.
	if fresh.DryRun {
		if serr := p.syncRun(ctx, fresh, StatusDryRun, fresh.Summary); serr != nil {
			return Result{}, serr
		}
		if aerr := p.audit(ctx, fresh, "policy.approve_dry_run", StatusDryRun, fresh.Summary); aerr != nil {
			return Result{}, aerr
		}
		return Result{ChangeID: changeID, Status: StatusDryRun}, nil
	}
	if fresh.Blocked {
		id, ferr := p.finish(ctx, changeID, fresh, StatusFailed, row.BeforeSummary, "plan bloklu: "+fresh.Reason)
		if ferr != nil {
			return Result{}, ferr
		}
		if serr := p.syncRun(ctx, fresh, StatusBlocked, fresh.Reason); serr != nil {
			return Result{}, serr
		}
		if aerr := p.audit(ctx, fresh, "policy.blocked", StatusBlocked, fresh.Reason); aerr != nil {
			return Result{}, aerr
		}
		return Result{ChangeID: id, Status: StatusBlocked}, nil
	}
	// A non-gated request with no target cannot be applied (it is not a rendered policy).
	if len(fresh.Target) == 0 {
		id, ferr := p.finish(ctx, changeID, fresh, StatusFailed, row.BeforeSummary, "onaylanacak hedef yok")
		if ferr != nil {
			return Result{}, ferr
		}
		if serr := p.syncRun(ctx, fresh, StatusFailed, "onaylanacak hedef yok"); serr != nil {
			return Result{}, serr
		}
		if aerr := p.audit(ctx, fresh, "policy.approve_failed", StatusFailed, "onaylanacak hedef yok"); aerr != nil {
			return Result{}, aerr
		}
		return Result{ChangeID: id, Status: StatusFailed}, nil
	}

	if got := proposalJSON(fresh); got != row.AfterSummary {
		err := p.q.UpdateChange(ctx, db.UpdateChangeParams{
			Status:        StatusPendingApproval,
			BeforeSummary: row.BeforeSummary,
			AfterSummary:  got,
			Error:         "plan değişti, yeniden onay gerekli",
			UpdatedAt:     p.stamp(),
			ID:            changeID,
		})
		if err != nil {
			return Result{}, fmt.Errorf("change: update %d: %w", changeID, err)
		}
		if serr := p.syncRun(ctx, fresh, StatusNeedsReapproval, fresh.Summary); serr != nil {
			return Result{}, serr
		}
		if aerr := p.audit(ctx, fresh, "policy.reapproval_required", StatusNeedsReapproval, "plan değişti"); aerr != nil {
			return Result{}, aerr
		}
		return Result{ChangeID: changeID, Status: StatusNeedsReapproval}, nil
	}

	return p.applyLocked(ctx, changeID, fresh)
}

// applyLocked is the apply → verify → (keep/alert) → audit path. The caller holds the lock.
func (p *Pipeline) applyLocked(ctx context.Context, changeID int64, req Request) (Result, error) {
	// Dry-run is re-read under the writer lock, immediately before any external call: a toggle that
	// landed after the plan was computed must still stop the write (Y-06). The lock serializes this
	// read with the toggle itself (web's SettingDryRun takes the same lock via WithWriterLock), so the
	// value cannot change between here and SetPolicy. A read failure aborts without writing.
	if p.dryRun == nil {
		return Result{}, errors.New("change: no dry-run source configured")
	}
	on, derr := p.dryRun.DryRun(ctx)
	if derr != nil {
		return Result{}, fmt.Errorf("change: read dry-run: %w", derr)
	}
	recording := p.revs != nil && req.Kind == KindPolicy
	if on {
		res := Result{ChangeID: changeID, Status: StatusDryRun}
		if recording {
			// A dry run still leaves a revision, finished at once so it is never pending (F3-010 AC11).
			id, err := p.revs.Begin(ctx, req, changeID)
			if err != nil {
				return Result{}, fmt.Errorf("change: record revision: %w", err)
			}
			res.RevisionID = id
		}
		serr := p.syncRun(ctx, req, StatusDryRun, req.Summary)
		var rerr error
		if recording {
			rerr = p.finishRevision(ctx, res.RevisionID, RevisionDryRun, req.Summary)
		}
		if err := errors.Join(serr, rerr); err != nil {
			return Result{}, err
		}
		return res, nil
	}
	// The maintenance gate runs here: under the writer lock, after the caller's fresh reads (SubmitBuilt's
	// build, Approve's replan) and before the first external call and the apply_start audit.
	if p.maint != nil {
		if gerr := p.maint.CheckWidening(ctx, gateSource(req)); gerr != nil {
			return p.heldOrRefused(ctx, req, gerr)
		}
	}
	if !recording {
		return p.applyWrite(ctx, changeID, req)
	}

	// The change row is reserved before the write so the revision can name it; the terminal records
	// below update this same row. A crash after this point leaves a failed row and a pending revision,
	// which the policy writer treats as an uncertain state.
	if changeID == 0 {
		id, err := p.finish(ctx, 0, req, StatusFailed, "", "apply sürüyor")
		if err != nil {
			return Result{}, err
		}
		changeID = id
	}
	revID, berr := p.revs.Begin(ctx, req, changeID)
	if berr != nil {
		res, ferr := p.failed(ctx, changeID, req, "", "revision kaydedilemedi: "+berr.Error(), "")
		return res, errors.Join(fmt.Errorf("change: record revision: %w", berr), ferr)
	}
	res, err := p.applyWrite(ctx, changeID, req)
	if res.ChangeID == 0 {
		res.ChangeID = changeID
	}
	res.RevisionID = revID
	outcome := res.outcome
	switch {
	case res.Applied:
		outcome = RevisionApplied
	case outcome == "":
		outcome = RevisionFailed
	}
	if err != nil && res.Status == "" {
		// Nothing was written and the pipeline stopped before recording an outcome: say so on the
		// reserved row instead of leaving "in progress".
		res, _ = p.failed(ctx, changeID, req, "", err.Error(), "")
		res.RevisionID = revID
		outcome = RevisionFailed
	}
	if ferr := p.finishRevision(ctx, revID, outcome, res.detail); ferr != nil {
		if aerr := p.raiseAlert(ctx, res.ChangeID, AlertPolicyBookkeepingFailed); aerr != nil {
			ferr = errors.Join(ferr, aerr)
		}
		err = errors.Join(err, ferr)
	}
	return res, err
}

// gateSource maps the request's revision source to the maintenance gate's: only an explicit sync
// source may write while the reconcile is pending. An empty source is not the sync flow and is
// treated as an admin write, so a caller that forgets to set it cannot write through the gate
// (F3b-027 AC2). Every production caller sets Source explicitly (sync, ui, rollback, recovery).
func gateSource(req Request) string {
	if req.Revision.Source == maintenance.SourceSync {
		return maintenance.SourceSync
	}
	return maintenance.SourceAdmin
}

// heldOrRefused handles a policy write the maintenance gate stopped; nothing was written yet. An
// admin write (UI save, rollback, recovery) is refused with the gate's error. The sync's policy step
// is skipped and reported as PolicyHeld, while its Expire list still runs: expiring a node only
// narrows access (ADR 0021 d).
func (p *Pipeline) heldOrRefused(ctx context.Context, req Request, gateErr error) (Result, error) {
	rctx, cancel := recovery(ctx)
	defer cancel()
	if gateSource(req) != maintenance.SourceSync {
		if err := p.audit(rctx, req, "policy.apply_refused", "refused", gateErr.Error()); err != nil {
			return Result{}, errors.Join(gateErr, err)
		}
		return Result{}, gateErr
	}
	for _, nodeID := range req.Expire {
		if _, err := p.hs.ExpireNode(ctx, nodeID); err != nil {
			// Nodes already expired stay expired; the next reconcile retries the rest.
			res, ferr := p.failed(ctx, 0, req, "", fmt.Sprintf("bakım sürerken policy tutuldu; node %d expire edilemedi: %v", nodeID, err), AlertPolicyExpireFailed)
			res.PolicyHeld = true
			return res, ferr
		}
	}
	summary := fmt.Sprintf("policy tutuldu (%s); %d node expire edildi", gateErr.Error(), len(req.Expire))
	var errs []error
	errs = append(errs, p.syncRun(rctx, req, StatusHeld, summary))
	errs = append(errs, p.audit(rctx, req, "policy.held", StatusHeld, summary))
	return Result{Status: StatusHeld, PolicyHeld: true}, errors.Join(errs...)
}

// finishRevision moves the revision to its final outcome on a context detached from the caller: the
// write may already have happened, so a canceled request must not leave the revision pending.
func (p *Pipeline) finishRevision(ctx context.Context, id int64, outcome, detail string) error {
	rctx, cancel := recovery(ctx)
	defer cancel()
	err := retryRecord(rctx, func() error { return p.revs.Finish(rctx, id, outcome, detail) })
	if err != nil {
		return fmt.Errorf("change: finish revision %d: %w", id, err)
	}
	return nil
}

// applyWrite is the check → write → verify part of the apply. The caller holds the lock and has
// already passed the dry-run gate.
func (p *Pipeline) applyWrite(ctx context.Context, changeID int64, req Request) (Result, error) {
	target := string(req.Target)

	before, err := p.hs.GetPolicy(ctx)
	if err != nil {
		return p.failed(ctx, changeID, req, "", "önceki policy okunamadı: "+err.Error(), "")
	}
	// Lost-update guard: never overwrite a policy that changed since the plan was computed; the
	// rendered target no longer describes the live state (rule 7).
	if len(req.SourcePolicy) > 0 && !samePolicy(before.Text, string(req.SourcePolicy)) {
		return p.failed(ctx, changeID, req, before.Text, "policy plandan sonra değişti; yeniden planlanmalı", AlertPolicyStale)
	}
	if err := p.hs.CheckPolicy(ctx, target); err != nil {
		return p.failed(ctx, changeID, req, before.Text, "Headscale doğrulaması reddetti: "+err.Error(), "")
	}
	// Record the intent before the external write: if this cannot be stored, nothing is written, and
	// a crash mid-write still leaves a trace (A-01.1).
	if err := p.audit(ctx, req, "policy.apply_start", "started", req.Summary); err != nil {
		return Result{}, err
	}

	// SetPolicy may fail after the server committed the policy, so a SetPolicy error is not proof
	// that nothing was written; read back to find out. The readback runs on a context detached from
	// the caller: a canceled request must not hide a write that already happened (rule 7).
	if _, setErr := p.hs.SetPolicy(ctx, target); setErr != nil {
		cur, gerr := p.readPolicy(ctx)
		switch {
		case gerr != nil:
			// The write's result is unknown. Never guess by restoring the previous policy: it may be
			// wider, and rule 7 forbids widening access. Keep the last known-good state and alert.
			return p.failed(ctx, changeID, req, before.Text,
				"policy yazılamadı ve durum doğrulanamadı: "+setErr.Error()+"; "+gerr.Error(), AlertPolicyUnverified)
		case samePolicy(cur.Text, target):
			// committed despite the error; the written state is what we wanted
		case samePolicy(cur.Text, before.Text):
			return p.failed(ctx, changeID, req, before.Text, "policy yazılamadı: "+setErr.Error(), "")
		default:
			// SetPolicy errored, so the write's fate is ambiguous and the live policy is neither what
			// we wanted nor the previous state (a concurrent change, or a write we cannot attribute).
			// Never restore on a guess: the previous policy could be wider (rule 7). Keep the live
			// state and alert.
			return p.failed(ctx, changeID, req, before.Text,
				"policy yazılamadı ve mevcut policy beklenmedik: "+setErr.Error(), AlertPolicyUnverified)
		}
	} else {
		got, gerr := p.readPolicy(ctx)
		switch {
		case gerr != nil:
			// SetPolicy reported success, so the target is (presumably) applied. Do not restore the
			// possibly wider previous policy on an unverifiable readback (rule 7); keep it and alert.
			return p.failed(ctx, changeID, req, before.Text, "yazılan policy doğrulanamadı: "+gerr.Error(), AlertPolicyUnverified)
		case !samePolicy(got.Text, target):
			// The live policy is neither what we wanted nor, necessarily, what was there before. The
			// previous policy may be wider than the current one (a removed group, for example), so
			// restoring it could widen access; we cannot prove it is safe. Keep the live state and
			// let an operator reconcile (rule 7).
			return p.failed(ctx, changeID, req, before.Text, "yazılan policy geri okunduğunda beklenenden farklı; erişimi genişletmemek için önceki policy geri yüklenmedi", AlertPolicyMismatch)
		}
	}

	// The policy is verified here: it is the final artifact whatever the node expiry below does, so it
	// is committed now. An uncertain write never gets here (every such branch returned above).
	revision, gitFailed := p.commitPolicy(ctx, req)

	for _, nodeID := range req.Expire {
		if _, err := p.hs.ExpireNode(ctx, nodeID); err != nil {
			// The policy was written and verified, so it is the intended state; restoring the
			// previous one could widen access, which rule 7 forbids. Keep it, alert, and let the
			// next reconcile retry the expiry. Nodes already expired stay expired. before_summary
			// still records the real previous policy.
			res, ferr := p.failed(ctx, changeID, req, before.Text, fmt.Sprintf("node %d expire edilemedi: %v", nodeID, err), AlertPolicyExpireFailed)
			res.Revision, res.GitFailed = revision, gitFailed
			// The verified policy is live, so the revision is applied even though the change failed.
			res.outcome = RevisionApplied
			return res, ferr
		}
	}

	// The external write is done; recording it must not be lost to a canceled caller context. Attempt
	// every terminal record even if an earlier one fails, and raise the alert through an independent
	// path so a bookkeeping error never hides the applied write from the operator.
	rctx, cancel := recovery(ctx)
	defer cancel()
	var recErrs []error
	id, err := p.finish(rctx, changeID, req, StatusApplied, before.Text, "")
	if err != nil {
		recErrs = append(recErrs, err)
		id = changeID
	}
	if err := p.syncRun(rctx, req, StatusApplied, req.Summary); err != nil {
		recErrs = append(recErrs, err)
	}
	if err := p.audit(rctx, req, "policy.apply", StatusApplied, req.Summary); err != nil {
		recErrs = append(recErrs, err)
	}
	if len(recErrs) > 0 {
		if aerr := p.raiseAlert(rctx, id, AlertPolicyBookkeepingFailed); aerr != nil {
			recErrs = append(recErrs, aerr)
		}
		return Result{ChangeID: id, Status: StatusApplied, Applied: true, Revision: revision, GitFailed: gitFailed}, errors.Join(recErrs...)
	}
	return Result{ChangeID: id, Status: StatusApplied, Applied: true, Revision: revision, GitFailed: gitFailed}, nil
}

// commitPolicy commits the verified policy text under the acting user. A history error is not the
// change's error: gitlog audits, alerts and queues the intent itself.
func (p *Pipeline) commitPolicy(ctx context.Context, req Request) (revision string, failed bool) {
	if p.git == nil || req.Kind != KindPolicy {
		return "", false
	}
	rctx, cancel := recovery(ctx)
	defer cancel()
	return commitVerified(rctx, p.git, p.q, gitlog.CommitRequest{
		Actor: req.Actor, AppliedAt: p.clock(),
		Files: []gitlog.File{{Name: GitFilePolicy, Content: req.Target}},
	})
}

// readPolicy reads the live policy on a fresh, bounded context detached from parent. Once a write
// may have been attempted, a canceled caller context must not blind the readback: a committed write
// mistaken for a failure would be reported against the live, unverified state (rule 7).
func (p *Pipeline) readPolicy(parent context.Context) (headscale.Policy, error) {
	ctx, cancel := recovery(parent)
	defer cancel()
	return p.hs.GetPolicy(ctx)
}

// failed records a failed change. It never touches the managed system: the previous policy is not
// restored because restoring it cannot be proven not to widen access (rule 7). When alertKind is
// non-empty a critical alert of that kind is raised. The status is always failed, matching
// architecture §4. Every terminal record is attempted even if an earlier one fails, and the alerts
// are raised through an independent path so a bookkeeping error cannot hide the failure. The recovery
// work runs on a context detached from the caller so a cancellation after the write cannot lose the
// record.
func (p *Pipeline) failed(ctx context.Context, changeID int64, req Request, before, reason string, alertKind string) (Result, error) {
	rctx, cancel := recovery(ctx)
	defer cancel()
	// An unverifiable or mismatching write may have changed the live policy: its revision is unknown,
	// not failed. Everything else was refused before, or did not change, the live policy.
	outcome := RevisionFailed
	if alertKind == AlertPolicyUnverified || alertKind == AlertPolicyMismatch {
		outcome = RevisionUnknown
	}
	var errs []error
	id, err := p.finish(rctx, changeID, req, StatusFailed, before, reason)
	if err != nil {
		errs = append(errs, err)
		id = changeID
	}
	if err := p.syncRun(rctx, req, StatusFailed, reason); err != nil {
		errs = append(errs, err)
	}
	if err := p.audit(rctx, req, "policy.apply_failed", StatusFailed, reason); err != nil {
		errs = append(errs, err)
	}
	if alertKind != "" {
		if err := p.raiseAlert(rctx, id, alertKind); err != nil {
			errs = append(errs, err)
		}
	}
	// After the branch alert: if any terminal record (change, sync_run, audit or the branch alert)
	// could not be written, raise a distinct alert so the operator can tell a missing record apart
	// from the change's own failure.
	if len(errs) > 0 {
		if err := p.raiseAlert(rctx, id, AlertPolicyBookkeepingFailed); err != nil {
			errs = append(errs, err)
		}
	}
	res := Result{ChangeID: id, Status: StatusFailed, outcome: outcome, detail: reason}
	if len(errs) > 0 {
		return res, errors.Join(errs...)
	}
	return res, nil
}

// finish inserts a new change row (changeID 0) or updates the pending one, with the proposal stored
// as after_summary.
func (p *Pipeline) finish(ctx context.Context, changeID int64, req Request, status, before, errText string) (int64, error) {
	now := p.stamp()
	after := proposalJSON(req)
	if changeID == 0 {
		var id int64
		err := retryRecord(ctx, func() error {
			row, err := p.q.InsertChange(ctx, db.InsertChangeParams{
				Kind:          req.Kind,
				Actor:         strings.TrimSpace(req.Actor),
				Status:        status,
				BeforeSummary: before,
				AfterSummary:  after,
				Error:         errText,
				CreatedAt:     now,
				UpdatedAt:     now,
			})
			if err != nil {
				return err
			}
			id = row.ID
			return nil
		})
		if err != nil {
			return 0, fmt.Errorf("change: insert %s: %w", status, err)
		}
		return id, nil
	}
	err := retryRecord(ctx, func() error {
		return p.q.UpdateChange(ctx, db.UpdateChangeParams{
			Status:        status,
			BeforeSummary: before,
			AfterSummary:  after,
			Error:         errText,
			UpdatedAt:     now,
			ID:            changeID,
		})
	})
	if err != nil {
		return 0, fmt.Errorf("change: update %d: %w", changeID, err)
	}
	return changeID, nil
}

func (p *Pipeline) syncRun(ctx context.Context, req Request, result, summary string) error {
	err := retryRecord(ctx, func() error {
		_, err := p.q.InsertSyncRun(ctx, db.InsertSyncRunParams{
			StartedAt:   p.stamp(),
			Trigger:     req.Trigger,
			Result:      result,
			DiffSummary: summary,
		})
		return err
	})
	if err != nil {
		return fmt.Errorf("change: sync_run %s: %w", result, err)
	}
	return nil
}

func (p *Pipeline) audit(ctx context.Context, req Request, event, result, summary string) error {
	err := retryRecord(ctx, func() error {
		_, err := p.log.Write(ctx, audit.Entry{
			Actor:  req.Actor,
			Event:  event,
			Target: "headscale:policy",
			Diff:   audit.Diff{{Field: "policy", After: summary}},
			Result: result,
		})
		return err
	})
	if err != nil {
		return fmt.Errorf("change: audit %s: %w", event, err)
	}
	return nil
}

func (p *Pipeline) raiseAlert(parent context.Context, changeID int64, kind string) error {
	// A fresh bounded context: a slow change/sync_run/audit write must not starve the critical alert
	// by consuming the shared recovery budget.
	ctx, cancel := recovery(parent)
	defer cancel()
	now := p.stamp()
	err := retryRecord(ctx, func() error {
		_, err := p.q.InsertAlert(ctx, db.InsertAlertParams{
			Kind:        kind,
			Source:      fmt.Sprintf("change:%d", changeID),
			FirstSeenAt: now,
			LastSeenAt:  now,
		})
		return err
	})
	if err != nil {
		return fmt.Errorf("change: raise alert %s: %w", kind, err)
	}
	return nil
}

func (p *Pipeline) stamp() string { return p.clock().UTC().Format(timeFormat) }

// recovery returns a bounded context detached from parent: bookkeeping after an external write must
// still run when the caller's context is canceled (shutdown), but must not hang forever.
func recovery(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), recoveryTimeout)
}

// recordAttempts is how many times a terminal bookkeeping write is attempted before it is given up
// to the critical alert. A transient failure (a busy SQLite writer, a blip) must not silently drop
// the record of an external write (AC9).
const recordAttempts = 3

// recordBackoff is the pause between attempts. It is short: a permanent failure must still return
// quickly, and the independent critical alert is the durable fallback.
const recordBackoff = 10 * time.Millisecond

// retryRecord runs fn until it succeeds, the context ends, or the attempts are exhausted, returning
// the last error. It backs every terminal record (change, sync_run, audit, alert): an external write
// that succeeded must leave a durable trace even if the first record write fails.
func retryRecord(ctx context.Context, fn func() error) error {
	var err error
	for attempt := 0; attempt < recordAttempts; attempt++ {
		if err = fn(); err == nil {
			return nil
		}
		if attempt == recordAttempts-1 {
			break
		}
		select {
		case <-time.After(recordBackoff):
		case <-ctx.Done():
			return err
		}
	}
	return err
}

func validateActor(actor string) error {
	if strings.TrimSpace(actor) == "" {
		return errors.New("change: actor is required")
	}
	return nil
}

// proposal is the comparable form of a request: the artifact and expiries it would apply. It is
// stored as after_summary and compared on approval.
type proposal struct {
	Target string   `json:"target"`
	Expire []uint64 `json:"expire,omitempty"`
	Reason string   `json:"reason,omitempty"`
}

func proposalJSON(req Request) string {
	expire := append([]uint64(nil), req.Expire...)
	slices.Sort(expire)
	b, err := json.Marshal(proposal{Target: string(req.Target), Expire: expire, Reason: req.Reason})
	if err != nil {
		return fmt.Sprintf(`{"error":%q}`, err.Error())
	}
	return string(b)
}

// samePolicy reports whether Headscale holds the policy we wrote, comparing JSON semantics so
// insignificant formatting differences do not trigger a rollback.
func samePolicy(got, want string) bool {
	vg, err := canonicalJSON(got)
	if err != nil {
		return false
	}
	vw, err := canonicalJSON(want)
	if err != nil {
		return false
	}
	return reflect.DeepEqual(vg, vw)
}

func canonicalJSON(s string) (any, error) {
	root, err := hujson.Parse([]byte(s))
	if err != nil {
		return nil, err
	}
	root.Standardize()
	var v any
	if err := json.Unmarshal(root.Pack(), &v); err != nil {
		return nil, err
	}
	return v, nil
}
