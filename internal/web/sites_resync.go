package web

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/change"
)

// The resync action (F2-021, S-04.3): the sites screen's "kayıtlardan yeniden uygula" button
// re-applies the stored records over the live Caddy/DNS/Zitadel artifacts after a partial
// failure. It is the F2-011 pipeline's own resync path behind the F2-015 review pattern: the
// preview plans read-only, the approval re-plans and refuses a plan that moved, and every action
// is audited before the pipeline runs. Like the resync itself, the approval overwrites a drifted
// artifact on purpose — that is the operator's explicit decision.

// SiteResyncConfig wires the resync action.
type SiteResyncConfig struct {
	Reviewer SiteReviewer
	Changes  SiteChangeReader
	Lister   SiteLister
	Auditor  SiteAuditor
	CSRF     *CSRF
}

// SiteResyncHandler serves the resync preview and approval.
type SiteResyncHandler struct {
	cfg SiteResyncConfig
}

// NewSiteResyncHandler validates the wiring.
func NewSiteResyncHandler(cfg SiteResyncConfig) (*SiteResyncHandler, error) {
	switch {
	case cfg.Reviewer == nil:
		return nil, errors.New("web: site resync needs a reviewer")
	case cfg.Changes == nil:
		return nil, errors.New("web: site resync needs a change reader")
	case cfg.Lister == nil:
		return nil, errors.New("web: site resync needs a lister")
	case cfg.Auditor == nil:
		return nil, errors.New("web: site resync needs an auditor")
	case cfg.CSRF == nil:
		return nil, errors.New("web: site resync needs a CSRF signer")
	}
	return &SiteResyncHandler{cfg: cfg}, nil
}

// Register adds the resync routes to mux.
func (h *SiteResyncHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /sites/resync/preview", h.preview)
	mux.HandleFunc("POST /sites/resync/approve", h.approve)
}

// resyncTarget is the audit target of the whole-set operation.
const resyncTarget = "site:*"

// preview plans the resync read-only and shows the diff with the version-bound approval (AC1).
func (h *SiteResyncHandler) preview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	actor, ok := operatorActor(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := h.audit(r, actor, "site.resync_preview", "requested", ""); err != nil {
		http.Error(w, "işlem kaydedilemedi", http.StatusInternalServerError)
		return
	}
	pl, err := h.cfg.Reviewer.Preview(r.Context(), change.SiteRequest{Actor: actor, Op: change.SiteResync})
	if err != nil {
		if errors.Is(err, change.ErrBlocked) {
			h.auditOutcome(r, actor, "site.resync_preview", "blocked", err.Error())
			h.renderReview(w, r, SiteResyncReviewView{Blocked: err.Error()})
			return
		}
		h.auditOutcome(r, actor, "site.resync_preview", "failed", err.Error())
		http.Error(w, "plan hesaplanamadı: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// A resync re-applies the whole set in the pipeline's order; steps whose artifact already
	// matches are rewritten too.
	h.renderReview(w, r, SiteResyncReviewView{
		Order:   "DNS → Caddy → Zitadel",
		Diff:    pl.Diff,
		Version: SitePlanVersion(pl),
	})
}

// approve re-plans the resync and applies it only when the plan still matches the one the
// operator saw (AC2). The decision is audited before the pipeline runs.
func (h *SiteResyncHandler) approve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	actor, ok := operatorActor(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	version := strings.TrimSpace(r.PostFormValue("plan_version"))
	if version == "" {
		http.Error(w, "plan sürümü yok; preview'u yenileyin", http.StatusBadRequest)
		return
	}
	if err := h.audit(r, actor, "site.resync", "requested", ""); err != nil {
		http.Error(w, "onay kaydedilemedi", http.StatusInternalServerError)
		return
	}
	// Replan: a plan that moved since the preview no longer matches the displayed version and is
	// refused (Y-03.4).
	pl, err := h.cfg.Reviewer.Preview(r.Context(), change.SiteRequest{Actor: actor, Op: change.SiteResync})
	switch {
	case err != nil:
		h.auditOutcome(r, actor, "site.resync", "failed", err.Error())
		http.Error(w, "plan yeniden hesaplanamadı: "+err.Error(), http.StatusConflict)
		return
	case SitePlanVersion(pl) != version:
		h.auditOutcome(r, actor, "site.resync", "failed", "plan değişti")
		http.Error(w, "plan değişti; preview'u yenileyip yeniden onaylayın", http.StatusConflict)
		return
	}
	res, err := h.cfg.Reviewer.Submit(r.Context(), change.SiteRequest{Actor: actor, Op: change.SiteResync})
	h.auditOutcome(r, actor, "site.resync", auditResult(res, err), reasonOr(res, err))
	h.renderResult(w, r, res, err)
}

// renderReview writes the review page.
func (h *SiteResyncHandler) renderReview(w http.ResponseWriter, r *http.Request, view SiteResyncReviewView) {
	actor, _ := ActorFrom(r.Context())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = Layout(actor, h.cfg.CSRF.Token(), "siteler", "Kayıtlardan yeniden apply",
		SiteResyncReviewPage(view, h.cfg.CSRF.Token())).Render(r.Context(), w)
}

// renderResult writes the shared result screen (AC2/AC3).
func (h *SiteResyncHandler) renderResult(w http.ResponseWriter, r *http.Request, res change.SiteResult, applyErr error) {
	actor, _ := ActorFrom(r.Context())
	view := buildSiteResultView(r.Context(), h.cfg.Changes, h.cfg.Lister, res, applyErr)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = Layout(actor, h.cfg.CSRF.Token(), "siteler", "Değişiklik sonucu",
		SiteResultPage(view)).Render(r.Context(), w)
}

// audit writes one operator action before the pipeline runs.
func (h *SiteResyncHandler) audit(r *http.Request, actor, event, result, reason string) error {
	var diff audit.Diff
	if reason != "" {
		diff = audit.Diff{{Field: "error", After: reason}}
	}
	_, err := h.cfg.Auditor.Write(r.Context(), audit.Entry{
		Actor: actor, Event: event, Target: resyncTarget, Diff: diff, Result: result,
	})
	return err
}

// auditOutcome writes the post-action result; the requested entry already records the action.
func (h *SiteResyncHandler) auditOutcome(r *http.Request, actor, event, result, reason string) {
	if err := h.audit(r, actor, event, result, reason); err != nil {
		slog.Default().Warn("site resync: audit outcome write failed", "event", event, "target", resyncTarget, "err", err)
	}
}
