package web

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/site"
)

// The site review handlers (F2-014, S-02/S-03/S-04): the review screen of a form-submitted site
// change, the version-bound approval and the result screen, plus the first-import action
// (G-01: seed load, parity difference, approval). Like the sync page, every action is a POST
// behind RequireDevops and CSRF, audited before the pipeline runs; the pipeline records the apply
// itself.

// SiteReviewHandler serves the review, approval and first-import screens.
type SiteReviewHandler struct {
	cfg SiteReviewConfig
}

// NewSiteReviewHandler validates the wiring. Gate and Seed are optional but only appear together.
func NewSiteReviewHandler(cfg SiteReviewConfig) (*SiteReviewHandler, error) {
	switch {
	case cfg.Reviewer == nil:
		return nil, errors.New("web: site review needs a reviewer")
	case cfg.Lister == nil:
		return nil, errors.New("web: site review needs a lister")
	case cfg.URIs == nil:
		return nil, errors.New("web: site review needs a redirect URI reader")
	case cfg.Settings == nil:
		return nil, errors.New("web: site review needs a settings source")
	case cfg.Changes == nil:
		return nil, errors.New("web: site review needs a change reader")
	case cfg.Auditor == nil:
		return nil, errors.New("web: site review needs an auditor")
	case cfg.CSRF == nil:
		return nil, errors.New("web: site review needs a CSRF signer")
	case (cfg.Gate == nil) != (cfg.Seed == nil):
		return nil, errors.New("web: site review needs the first-import gate and seed together")
	}
	return &SiteReviewHandler{cfg: cfg}, nil
}

// Register adds the review routes to mux.
func (h *SiteReviewHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /sites/review", h.review)
	mux.HandleFunc("POST /sites/review/approve", h.approve)
	mux.HandleFunc("GET /sites/first-import", h.firstImportPage)
	mux.HandleFunc("POST /sites/first-import/preview", h.firstImportPreview)
	mux.HandleFunc("POST /sites/first-import", h.firstImportApply)
}

// review is the shared preview entry: it re-shows the review of a carried request.
func (h *SiteReviewHandler) review(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	req, err := decodeSiteRequest(r.PostFormValue("request"))
	if err != nil {
		http.Error(w, "geçersiz değişiklik isteği", http.StatusBadRequest)
		return
	}
	h.preview(w, r, req, func(w http.ResponseWriter, r *http.Request, perr error) {
		http.Error(w, perr.Error(), statusFor(perr))
	})
}

// previewForm is the hand-off for the site form: it audits, plans and renders the review screen.
// A request error (an invalid record) calls onFormError so the form handler shows the form again;
// a state block renders the review page with the reason and no approval.
func (h *SiteReviewHandler) previewForm(w http.ResponseWriter, r *http.Request, req change.SiteRequest, onFormError func(http.ResponseWriter, *http.Request, error)) {
	h.preview(w, r, req, onFormError)
}

func (h *SiteReviewHandler) preview(w http.ResponseWriter, r *http.Request, req change.SiteRequest, onFormError func(http.ResponseWriter, *http.Request, error)) {
	actor, ok := operatorActor(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	// The actor never travels with the form: the plan is made as the signed-in operator, the same
	// identity the approval applies it as.
	req.Actor = actor
	if err := h.audit(r, actor, "site.preview", reviewTarget(req), "requested", ""); err != nil {
		http.Error(w, "işlem kaydedilemedi", http.StatusInternalServerError)
		return
	}
	view, err := h.buildSiteReviewView(r.Context(), req)
	if err != nil {
		if herr := h.audit(r, actor, "site.preview", reviewTarget(req), "failed", err.Error()); herr != nil {
			slog.Default().Warn("site review: audit outcome write failed", "err", herr)
		}
		onFormError(w, r, err)
		return
	}
	if view.Blocked != "" {
		if herr := h.audit(r, actor, "site.preview", reviewTarget(req), "blocked", view.Blocked); herr != nil {
			slog.Default().Warn("site review: audit outcome write failed", "err", herr)
		}
	}
	h.renderReview(w, r, view)
}

// approve re-plans the carried request and applies it only when the plan still matches the one
// the operator saw (Y-03.4). The decision is audited before the pipeline runs.
func (h *SiteReviewHandler) approve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	actor, ok := operatorActor(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	req, err := decodeSiteRequest(r.PostFormValue("request"))
	if err != nil {
		http.Error(w, "geçersiz değişiklik isteği", http.StatusBadRequest)
		return
	}
	// The actor never travels with the form: the signed-in operator owns the decision.
	req.Actor = actor
	version := strings.TrimSpace(r.PostFormValue("plan_version"))
	if version == "" {
		http.Error(w, "plan sürümü yok; preview'u yenileyin", http.StatusBadRequest)
		return
	}
	target := reviewTarget(req)
	if err := h.audit(r, actor, "site.approve", target, "requested", ""); err != nil {
		http.Error(w, "onay kaydedilemedi", http.StatusInternalServerError)
		return
	}
	// Replan: the plan is computed again from the current state; a plan that moved (a drift, a
	// concurrent change, a widened diff) no longer matches the displayed version and is refused.
	pl, err := h.cfg.Reviewer.Preview(r.Context(), req)
	switch {
	case err != nil:
		h.auditOutcome(r, actor, "site.approve", target, "failed", err.Error())
		http.Error(w, "plan yeniden hesaplanamadı: "+err.Error(), http.StatusConflict)
		return
	case SitePlanVersion(pl) != version:
		h.auditOutcome(r, actor, "site.approve", target, "failed", "plan değişti")
		http.Error(w, "plan değişti; preview'u yenileyip yeniden onaylayın", http.StatusConflict)
		return
	}
	res, err := h.cfg.Reviewer.Submit(r.Context(), req)
	h.auditOutcome(r, actor, "site.approve", target, auditResult(res, err), reasonOr(res, err))
	h.renderResult(w, r, res, err)
}

// firstImportPage shows the first-import action while it is available.
func (h *SiteReviewHandler) firstImportPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	actor, _ := ActorFrom(r.Context())
	var v SiteFirstImportView
	v.DryRun = h.dryRunOn(r.Context())
	if h.cfg.Seed == nil {
		v.SeedErr = "ilk import yapılandırılmadı"
	} else {
		pending, err := h.cfg.Gate.FirstImportPending(r.Context())
		if err != nil {
			v.GateErr = err.Error()
		}
		done, err := h.cfg.Gate.FirstImportDone(r.Context())
		if err != nil {
			v.GateErr = err.Error()
		}
		v.Pending, v.Done = pending, done
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = Layout(actor, h.cfg.CSRF.Token(), "siteler", "İlk import",
		SiteFirstImportPage(v, h.cfg.CSRF.Token(), false)).Render(r.Context(), w)
}

// firstImportPreview runs the parity comparison read-only and shows the review.
func (h *SiteReviewHandler) firstImportPreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	actor, ok := operatorActor(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := h.audit(r, actor, "site.first_import_preview", "site:*", "requested", ""); err != nil {
		http.Error(w, "işlem kaydedilemedi", http.StatusInternalServerError)
		return
	}
	v := h.buildFirstImportView(r.Context())
	pageActor, _ := ActorFrom(r.Context())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = Layout(pageActor, h.cfg.CSRF.Token(), "siteler", "İlk import",
		SiteFirstImportPage(v, h.cfg.CSRF.Token(), true)).Render(r.Context(), w)
}

// firstImportApply loads the seed and applies the first import through the pipeline, only when
// the parity the operator approved is still the current one.
func (h *SiteReviewHandler) firstImportApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	actor, ok := operatorActor(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	version := strings.TrimSpace(r.PostFormValue("parity_version"))
	if version == "" {
		http.Error(w, "karşılaştırma sürümü yok; preview'u yenileyin", http.StatusBadRequest)
		return
	}
	if err := h.audit(r, actor, "site.first_import", "site:*", "requested", ""); err != nil {
		http.Error(w, "onay kaydedilemedi", http.StatusInternalServerError)
		return
	}
	v := h.buildFirstImportView(r.Context())
	switch {
	case !firstImportApprovable(v):
		h.auditOutcome(r, actor, "site.first_import", "site:*", "failed", "ilk import apply edilemez")
		http.Error(w, "ilk import apply edilemez; preview'u yenileyin", http.StatusConflict)
		return
	case v.Version != version:
		h.auditOutcome(r, actor, "site.first_import", "site:*", "failed", "karşılaştırma sürümü değişti")
		http.Error(w, "karşılaştırma değişti; preview'u yenileyip yeniden onaylayın", http.StatusConflict)
		return
	}
	seed, err := h.cfg.Seed.Read(r.Context())
	if err != nil {
		h.auditOutcome(r, actor, "site.first_import", "site:*", "failed", err.Error())
		http.Error(w, "aktarılacak kayıtlar okunamadı", http.StatusInternalServerError)
		return
	}
	res, err := h.cfg.Reviewer.FirstImport(r.Context(), actor, seed, site.SeedOptions{
		TagcessHost:            h.cfg.Seed.TagcessHost,
		ZitadelInternalSources: h.cfg.Seed.ZitadelInternalSources,
	})
	h.auditOutcome(r, actor, "site.first_import", "site:*", auditResult(res, err), reasonOr(res, err))
	h.renderResult(w, r, res, err)
}

// renderReview writes the review page.
func (h *SiteReviewHandler) renderReview(w http.ResponseWriter, r *http.Request, view SiteReviewView) {
	actor, _ := ActorFrom(r.Context())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = Layout(actor, h.cfg.CSRF.Token(), "siteler", "Değişiklik preview'u",
		SiteReviewPage(view, h.cfg.CSRF.Token())).Render(r.Context(), w)
}

// renderResult writes the result screen (AC3).
func (h *SiteReviewHandler) renderResult(w http.ResponseWriter, r *http.Request, res change.SiteResult, applyErr error) {
	actor, _ := ActorFrom(r.Context())
	view := h.buildSiteResultView(r.Context(), res, applyErr)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = Layout(actor, h.cfg.CSRF.Token(), "siteler", "Değişiklik sonucu",
		SiteResultPage(view)).Render(r.Context(), w)
}

// audit writes one operator action before the pipeline runs.
func (h *SiteReviewHandler) audit(r *http.Request, actor, event, target, result, reason string) error {
	var diff audit.Diff
	if reason != "" {
		diff = audit.Diff{{Field: "error", After: reason}}
	}
	_, err := h.cfg.Auditor.Write(r.Context(), audit.Entry{
		Actor: actor, Event: event, Target: target, Diff: diff, Result: result,
	})
	return err
}

// auditOutcome writes the post-action result; the requested entry already records the action, so
// a failed outcome write only reaches the server log (F2-013 pattern).
func (h *SiteReviewHandler) auditOutcome(r *http.Request, actor, event, target, result, reason string) {
	if err := h.audit(r, actor, event, target, result, reason); err != nil {
		slog.Default().Warn("site review: audit outcome write failed", "event", event, "target", target, "err", err)
	}
}

// reviewTarget names the audit target of a request.
func reviewTarget(req change.SiteRequest) string {
	if len(req.Site.Hosts) > 0 {
		return "site:" + req.Site.Hosts[0]
	}
	if req.ID > 0 {
		return fmt.Sprintf("site:%d", req.ID)
	}
	return "site:*"
}

// auditResult maps a pipeline outcome to the audit result.
func auditResult(res change.SiteResult, err error) string {
	switch {
	case err != nil && res.Status == "":
		return "failed"
	case res.Status == "":
		return "failed"
	default:
		return res.Status
	}
}

// reasonOr prefers the recorded reason (the result screen reads the change row); the returned
// error is the fallback for outcomes that never reached a change row.
func reasonOr(res change.SiteResult, err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}
