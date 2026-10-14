package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/sync"
)

// SyncRunView is the most recent reconcile run shown on the sync page (Y-05.2).
type SyncRunView struct {
	At      time.Time
	Trigger string
	Result  string
	Summary string
}

// SyncAlertView is one open alert shown at the top of the sync page (P-02.1).
type SyncAlertView struct {
	Kind     string
	Source   string
	LastSeen time.Time
}

// SyncPendingView is the change waiting for an operator decision (Y-03.4, G-03). Version is the
// proposal's version/hash (change.ProposalVersion); the approval form carries it back so a stale
// form whose proposal was replaced cannot apply an unseen plan.
type SyncPendingView struct {
	ID      int64
	Actor   string
	Summary string
	Version string
}

// SyncOverview is the read-only snapshot the sync page renders: status, the current Zitadel-Headscale
// diff and the open alerts (Y-05, Y-06, G-03). Plan carries the diff; when a read failed its Reason
// explains why rather than the page failing. Pending holds every change waiting for an operator, so a
// proposal superseded by a newer run is still reachable.
type SyncOverview struct {
	LastRun     *SyncRunView
	Alerts      []SyncAlertView
	Pending     []SyncPendingView
	DryRun      bool
	IntervalMin int
	Plan        sync.Plan
}

// SyncOverviewReader assembles the sync page snapshot. The production reader is NewOverviewReader;
// it is an interface so handler tests can supply a fixed snapshot.
type SyncOverviewReader interface {
	Overview(ctx context.Context) (SyncOverview, error)
}

// SyncApproval is the outcome of approving a pending change.
type SyncApproval struct {
	ChangeID int64
	Status   string
	Applied  bool
}

// ErrApprovalStale means the operator approved a proposal that is no longer the stored one; the form
// was stale, so nothing was applied and the operator must reload and decide again (Y-03.4).
var ErrApprovalStale = errors.New("web: approval proposal changed")

// SyncApprover approves a pending change. proposalVersion is the version the form was rendered from;
// the production implementation re-runs the plan through the change pipeline (F1-010) before
// applying, so a plan that changed is not applied (Y-03.4).
type SyncApprover interface {
	Approve(ctx context.Context, actor string, changeID int64, proposalVersion string) (SyncApproval, error)
}

// SyncRejecter closes a pending change without applying anything.
type SyncRejecter interface {
	Reject(ctx context.Context, changeID int64) error
}

// SyncDryRunSetter switches dry-run mode (Y-06). Turning it off is a state-changing action.
type SyncDryRunSetter interface {
	SetDryRun(ctx context.Context, on bool) error
}

// SyncIntervalSetter stores the periodic reconcile interval in whole minutes (Y-02.1).
type SyncIntervalSetter interface {
	SetInterval(ctx context.Context, minutes int) error
}

// SyncTriggerer queues a manual reconcile. It is satisfied by *sync.Trigger.
type SyncTriggerer interface {
	RequestManual()
}

// SyncAuditor writes the operator actions (approve, reject, dry-run, interval) to the append-only
// log (security.md §4, §9). It is satisfied by *audit.Logger.
type SyncAuditor interface {
	Write(ctx context.Context, e audit.Entry) (audit.Event, error)
}

// SyncHandlerConfig wires the sync page and its actions.
type SyncHandlerConfig struct {
	Overview SyncOverviewReader
	Approver SyncApprover
	Rejecter SyncRejecter
	DryRun   SyncDryRunSetter
	Interval SyncIntervalSetter
	Trigger  SyncTriggerer
	Auditor  SyncAuditor
	CSRF     *CSRF
}

// SyncHandler serves the sync page and its state-changing forms. The page is a pure read (GET); every
// action is a POST and is audited. It is mounted behind RequireDevops and CSRF.Protect, so the actor
// and the CSRF token are already enforced by the time a handler runs.
type SyncHandler struct {
	cfg SyncHandlerConfig
}

// NewSyncHandler validates the wiring.
func NewSyncHandler(cfg SyncHandlerConfig) (*SyncHandler, error) {
	switch {
	case cfg.Overview == nil:
		return nil, errors.New("web: sync page needs an overview reader")
	case cfg.Approver == nil:
		return nil, errors.New("web: sync page needs an approver")
	case cfg.Rejecter == nil:
		return nil, errors.New("web: sync page needs a rejecter")
	case cfg.DryRun == nil:
		return nil, errors.New("web: sync page needs a dry-run setter")
	case cfg.Interval == nil:
		return nil, errors.New("web: sync page needs an interval setter")
	case cfg.Trigger == nil:
		return nil, errors.New("web: sync page needs a trigger")
	case cfg.Auditor == nil:
		return nil, errors.New("web: sync page needs an auditor")
	case cfg.CSRF == nil:
		return nil, errors.New("web: sync page needs a CSRF signer")
	}
	return &SyncHandler{cfg: cfg}, nil
}

// Register adds the sync page and its action routes to mux.
func (h *SyncHandler) Register(mux *http.ServeMux) {
	mux.Handle("/sync", http.HandlerFunc(h.page))
	mux.Handle("/sync/approve", http.HandlerFunc(h.approve))
	mux.Handle("/sync/reject", http.HandlerFunc(h.reject))
	mux.Handle("/sync/dry-run", http.HandlerFunc(h.dryRun))
	mux.Handle("/sync/interval", http.HandlerFunc(h.interval))
	mux.Handle("/sync/trigger", http.HandlerFunc(h.trigger))
}

// page renders the snapshot (Y-05). It is read-only: only GET is answered.
func (h *SyncHandler) page(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	actor, _ := ActorFrom(r.Context())
	ov, err := h.cfg.Overview.Overview(r.Context())
	if err != nil {
		http.Error(w, "sync durumu okunamadı", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = Layout(actor, h.cfg.CSRF.Token(), "sync", "Sync",
		SyncPage(ov, h.cfg.CSRF.Token())).Render(r.Context(), w)
}

// approve applies a pending change through the recalculation flow (Y-03.4, G-03). The operator
// decision is audited before the pipeline runs, so an approval that cannot be recorded is never
// applied; the pipeline records the apply itself.
func (h *SyncHandler) approve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	actor, ok := operatorActor(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id, err := formChangeID(r)
	if err != nil {
		http.Error(w, "geçersiz değişiklik", http.StatusBadRequest)
		return
	}
	version := strings.TrimSpace(r.PostFormValue("proposal_version"))
	if version == "" {
		http.Error(w, "teklif sürümü yok; sayfayı yenileyin", http.StatusBadRequest)
		return
	}
	target := fmt.Sprintf("change:%d", id)
	if err := h.auditAction(r.Context(), actor, "sync.approve", target, audit.Diff{{Field: "decision", After: "approve"}}, "requested"); err != nil {
		http.Error(w, "onay kaydedilemedi", http.StatusInternalServerError)
		return
	}
	if _, err := h.cfg.Approver.Approve(r.Context(), actor, id, version); err != nil {
		if errors.Is(err, ErrApprovalStale) {
			http.Error(w, "teklif değişti; sayfayı yenileyip yeniden onaylayın", http.StatusConflict)
			return
		}
		http.Error(w, "onay başarısız", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/sync", http.StatusSeeOther)
}

// reject closes a pending change without applying anything (Y-03.4). The rejection is audited before
// it is stored, so it is never unaudited.
func (h *SyncHandler) reject(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	actor, ok := operatorActor(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id, err := formChangeID(r)
	if err != nil {
		http.Error(w, "geçersiz değişiklik", http.StatusBadRequest)
		return
	}
	target := fmt.Sprintf("change:%d", id)
	if err := h.auditAction(r.Context(), actor, "sync.reject", target, audit.Diff{{Field: "decision", After: "reject"}}, "requested"); err != nil {
		http.Error(w, "reddetme kaydedilemedi", http.StatusInternalServerError)
		return
	}
	if err := h.cfg.Rejecter.Reject(r.Context(), id); err != nil {
		http.Error(w, "reddetme başarısız", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/sync", http.StatusSeeOther)
}

// dryRun switches dry-run mode. The form must carry an explicit confirmation, so a stray or scripted
// POST that does not confirm is refused before anything changes (Y-06, AC4). The change is audited
// before it is stored, so turning dry-run off (which enables live writes) is never unaudited.
func (h *SyncHandler) dryRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	if r.PostFormValue("confirm") != "1" {
		http.Error(w, "onay gerekli", http.StatusBadRequest)
		return
	}
	actor, ok := operatorActor(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	on, err := strconv.ParseBool(strings.TrimSpace(r.PostFormValue("dry_run")))
	if err != nil {
		http.Error(w, "geçersiz değer", http.StatusBadRequest)
		return
	}
	diff := audit.Diff{{Field: "dry_run", After: strconv.FormatBool(on)}}
	if err := h.auditAction(r.Context(), actor, "sync.dry_run", "sync", diff, "requested"); err != nil {
		http.Error(w, "dry-run kaydedilemedi", http.StatusInternalServerError)
		return
	}
	if err := h.cfg.DryRun.SetDryRun(r.Context(), on); err != nil {
		http.Error(w, "dry-run değiştirilemedi", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/sync", http.StatusSeeOther)
}

// interval stores the periodic reconcile interval. The value must be a whole number of minutes in
// [MinSyncIntervalMinutes, MaxSyncIntervalMinutes] (Y-02.1, AC7); anything else is refused before it
// reaches the settings store. The change is audited before it is stored.
func (h *SyncHandler) interval(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	actor, ok := operatorActor(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	minutes, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue("minutes")))
	if err != nil || minutes < sync.MinSyncIntervalMinutes || minutes > sync.MaxSyncIntervalMinutes {
		http.Error(w, "aralık 1 ile 60 dakika arasında olmalı", http.StatusBadRequest)
		return
	}
	diff := audit.Diff{{Field: "interval_minutes", After: strconv.Itoa(minutes)}}
	if err := h.auditAction(r.Context(), actor, "sync.interval", "sync", diff, "requested"); err != nil {
		http.Error(w, "aralık kaydedilemedi", http.StatusInternalServerError)
		return
	}
	if err := h.cfg.Interval.SetInterval(r.Context(), minutes); err != nil {
		http.Error(w, "aralık kaydedilemedi", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/sync", http.StatusSeeOther)
}

// trigger queues a manual reconcile (Y-05). The operator is audited before the signal is queued, so
// "who triggered this" is always recorded; the run itself records its trigger in sync_runs.
func (h *SyncHandler) trigger(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	actor, ok := operatorActor(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	diff := audit.Diff{{Field: "trigger", After: sync.TriggerManual}}
	if err := h.auditAction(r.Context(), actor, "sync.trigger", "sync", diff, "requested"); err != nil {
		http.Error(w, "tetik kaydedilemedi", http.StatusInternalServerError)
		return
	}
	h.cfg.Trigger.RequestManual()
	http.Redirect(w, r, "/sync", http.StatusSeeOther)
}

// auditAction writes one operator action to the append-only log.
func (h *SyncHandler) auditAction(ctx context.Context, actor, event, target string, diff audit.Diff, result string) error {
	_, err := h.cfg.Auditor.Write(ctx, audit.Entry{
		Actor:  actor,
		Event:  event,
		Target: target,
		Diff:   diff,
		Result: result,
	})
	return err
}

// operatorActor returns the signed-in actor for the audit log and whether one is present. Without a
// non-empty actor an action cannot be audited, so it is refused rather than applied unnamed: every
// audit entry must say who (A-01.1, security.md §9).
func operatorActor(r *http.Request) (string, bool) {
	actor, _ := ActorFrom(r.Context())
	label := actorLabel(actor)
	return label, label != ""
}

// actorLabel identifies the operator for the audit log. The e-mail is preferred; a proxy that only
// sets the user header still yields a non-empty actor.
func actorLabel(a Actor) string {
	if email := strings.TrimSpace(a.Email); email != "" {
		return email
	}
	return strings.TrimSpace(a.User)
}

// formChangeID parses the change_id form field; a missing or non-positive id is refused.
func formChangeID(r *http.Request) (int64, error) {
	id, err := strconv.ParseInt(strings.TrimSpace(r.PostFormValue("change_id")), 10, 64)
	if err != nil || id <= 0 {
		return 0, errors.New("web: invalid change id")
	}
	return id, nil
}

// methodNotAllowed answers with 405 and the allowed method, matching the audit page.
func methodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

// syncPlanEmpty reports a plan that was computed and changes nothing: no group or node change, no
// hold, no note. A plan whose read failed carries a Reason, so it never counts as empty (fail safe).
func syncPlanEmpty(p sync.Plan) bool {
	return !p.Blocked && !p.NeedsApproval && p.Reason == "" && len(p.Warnings) == 0 &&
		len(p.GroupDiff.Groups) == 0 && len(p.GroupDiff.RemovedGroups) == 0 && len(p.ExpireNodes) == 0
}
