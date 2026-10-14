package web

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/change"
)

// The site settings handlers (F2-015, S-06): the S-06 key screen and its preview → approval →
// apply flow. The toggle never writes directly: the approval re-plans the resync against the
// target key state, stores the value under the writer lock and applies through the site change
// pipeline, which renders and loads the new access matrix.

// SiteSettingsPreviewer plans a resync against an explicit settings snapshot and applies
// requests. It is satisfied by *change.SitePipeline.
type SiteSettingsPreviewer interface {
	PreviewSettings(ctx context.Context, settings change.SiteSettings) (change.SitePlan, error)
	Submit(ctx context.Context, req change.SiteRequest) (change.SiteResult, error)
}

// SiteSettingsHandlerConfig wires the settings screen.
type SiteSettingsHandlerConfig struct {
	Previewer SiteSettingsPreviewer
	Settings  SiteSettingsSource
	// DryRun is re-read under the writer lock right before the value is stored (Y-06).
	DryRun  change.DryRun
	Setter  SiteS06Setter
	Changes SiteChangeReader
	Lister  SiteLister
	Auditor SiteAuditor
	CSRF    *CSRF
}

// SiteSettingsHandler serves the site settings screen and the S-06 actions.
type SiteSettingsHandler struct {
	cfg SiteSettingsHandlerConfig
}

// NewSiteSettingsHandler validates the wiring.
func NewSiteSettingsHandler(cfg SiteSettingsHandlerConfig) (*SiteSettingsHandler, error) {
	switch {
	case cfg.Previewer == nil:
		return nil, errors.New("web: site settings needs a previewer")
	case cfg.Settings == nil:
		return nil, errors.New("web: site settings needs a settings source")
	case cfg.DryRun == nil:
		return nil, errors.New("web: site settings needs a dry-run source")
	case cfg.Setter == nil:
		return nil, errors.New("web: site settings needs a setter")
	case cfg.Changes == nil:
		return nil, errors.New("web: site settings needs a change reader")
	case cfg.Lister == nil:
		return nil, errors.New("web: site settings needs a lister")
	case cfg.Auditor == nil:
		return nil, errors.New("web: site settings needs an auditor")
	case cfg.CSRF == nil:
		return nil, errors.New("web: site settings needs a CSRF signer")
	}
	return &SiteSettingsHandler{cfg: cfg}, nil
}

// Register adds the settings routes to mux.
func (h *SiteSettingsHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /sites/settings", h.page)
	mux.HandleFunc("POST /sites/s06/preview", h.preview)
	mux.HandleFunc("POST /sites/s06/approve", h.approve)
}

// s06TargetView is the settings page data: the current key state.
type SiteSettingsView struct {
	S06Open  bool
	GateErr  string
	S06State string
}

// page shows the current S-06 state and the toggle.
func (h *SiteSettingsHandler) page(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	actor, _ := ActorFrom(r.Context())
	var v SiteSettingsView
	settings, err := h.cfg.Settings.Settings(r.Context())
	switch {
	case err != nil:
		v.GateErr = err.Error()
	default:
		v.S06Open = settings.Caddy.S06Open
		if v.S06Open {
			v.S06State = "açık"
		} else {
			v.S06State = "kapalı"
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = Layout(actor, h.cfg.CSRF.Token(), "siteler", "Site ayarları",
		SiteSettingsPage(v, h.cfg.CSRF.Token())).Render(r.Context(), w)
}

// parseS06Form reads the target key state; anything but the two values is a tampered form.
func parseS06Form(r *http.Request) (open bool, ok bool) {
	switch r.PostFormValue("s06") {
	case "open":
		return true, true
	case "closed":
		return false, true
	default:
		return false, false
	}
}

// targetSettings reads the current settings and applies the target key state: the plan shows the
// diff the flip would produce, before anything is stored. The previous value travels with the
// target: a submit that does not reach the target state must leave the stored key at it, never
// one step ahead of the live matrix.
func (h *SiteSettingsHandler) targetSettings(ctx context.Context, open bool) (prev bool, settings change.SiteSettings, err error) {
	settings, err = h.cfg.Settings.Settings(ctx)
	if err != nil {
		return false, change.SiteSettings{}, err
	}
	prev = settings.Caddy.S06Open
	settings.Caddy.S06Open = open
	return prev, settings, nil
}

// preview plans the key flip read-only and shows the review.
func (h *SiteSettingsHandler) preview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	actor, ok := operatorActor(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	open, ok := parseS06Form(r)
	if !ok {
		http.Error(w, "geçersiz switch durumu", http.StatusBadRequest)
		return
	}
	if err := h.audit(r, actor, "site.s06_preview", "sites:s06", "requested", ""); err != nil {
		http.Error(w, "işlem kaydedilemedi", http.StatusInternalServerError)
		return
	}
	_, settings, err := h.targetSettings(r.Context(), open)
	if err != nil {
		h.auditOutcome(r, actor, "site.s06_preview", "sites:s06", "failed", err.Error())
		http.Error(w, "ayarlar okunamadı", http.StatusInternalServerError)
		return
	}
	pl, err := h.cfg.Previewer.PreviewSettings(r.Context(), settings)
	if err != nil {
		h.auditOutcome(r, actor, "site.s06_preview", "sites:s06", "failed", err.Error())
		h.renderS06Blocked(w, r, open, err.Error())
		return
	}
	view := SiteS06ReviewView{
		Open:    open,
		Order:   applyOrder(pl),
		Diff:    pl.Diff,
		Version: SitePlanVersion(pl),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	pageActor, _ := ActorFrom(r.Context())
	_ = Layout(pageActor, h.cfg.CSRF.Token(), "siteler", "Switch değişikliği",
		SiteS06ReviewPage(view, h.cfg.CSRF.Token())).Render(r.Context(), w)
}

// approve re-plans the flip, stores the value under the writer lock (with a fresh dry-run check)
// and applies the resync (AC2). The decision is audited before anything runs.
func (h *SiteSettingsHandler) approve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	actor, ok := operatorActor(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	open, ok := parseS06Form(r)
	if !ok {
		http.Error(w, "geçersiz switch durumu", http.StatusBadRequest)
		return
	}
	version := strings.TrimSpace(r.PostFormValue("plan_version"))
	if version == "" {
		http.Error(w, "plan sürümü yok; preview'u yenileyin", http.StatusBadRequest)
		return
	}
	const target = "sites:s06"
	if err := h.audit(r, actor, "site.s06", target, "requested", ""); err != nil {
		http.Error(w, "onay kaydedilemedi", http.StatusInternalServerError)
		return
	}
	// Replan against the target key state: a plan that moved since the preview is refused
	// (Y-03.4 pattern). The previous key value travels along for the restore.
	prev, settings, err := h.targetSettings(r.Context(), open)
	if err != nil {
		h.auditOutcome(r, actor, "site.s06", target, "failed", err.Error())
		http.Error(w, "ayarlar okunamadı", http.StatusConflict)
		return
	}
	pl, err := h.cfg.Previewer.PreviewSettings(r.Context(), settings)
	switch {
	case err != nil:
		h.auditOutcome(r, actor, "site.s06", target, "failed", err.Error())
		http.Error(w, "plan yeniden hesaplanamadı: "+err.Error(), http.StatusConflict)
		return
	case SitePlanVersion(pl) != version:
		h.auditOutcome(r, actor, "site.s06", target, "failed", "plan değişti")
		http.Error(w, "plan değişti; preview'u yenileyip yeniden onaylayın", http.StatusConflict)
		return
	}
	// Store the value under the writer lock with a fresh dry-run check, so the toggle cannot
	// interleave with an apply and dry-run never stores the key (Y-06).
	storeErr := change.WithWriterLock(func() error {
		on, err := h.cfg.DryRun.DryRun(r.Context())
		if err != nil {
			return err
		}
		if on {
			return errSettingsDryRun
		}
		return h.cfg.Setter.SetS06Open(r.Context(), open)
	})
	switch {
	case errors.Is(storeErr, errSettingsDryRun):
		h.auditOutcome(r, actor, "site.s06", target, string(change.StatusDryRun), "")
		h.renderResult(w, r, change.SiteResult{Result: change.Result{Status: change.StatusDryRun}}, nil, "")
		return
	case storeErr != nil:
		h.auditOutcome(r, actor, "site.s06", target, "failed", storeErr.Error())
		http.Error(w, "switch kaydedilemedi", http.StatusInternalServerError)
		return
	}
	res, err := h.cfg.Previewer.Submit(r.Context(), change.SiteRequest{Actor: actor, Op: change.SiteResync})
	h.auditOutcome(r, actor, "site.s06", target, auditResult(res, err), reasonOr(res, err))
	note := ""
	if !s06KeyAtTarget(res, err) {
		note = h.restoreS06(r, actor, target, prev)
	}
	h.renderResult(w, r, res, err, note)
}

// s06KeyAtTarget reports whether the submit outcome leaves the stored key correct: applied and
// no_change mean the live matrix moved to (or already matched) the stored target state. Every
// other outcome — failed, blocked, rolled back, or an error before a change row — leaves the
// live matrix at the old state, so the stored key must go back to it.
func s06KeyAtTarget(res change.SiteResult, err error) bool {
	if err != nil {
		return false
	}
	return res.Status == change.StatusApplied || res.Status == change.StatusNoChange
}

// restoreS06 puts the key back to its previous value when the apply did not reach the target
// state: the stored key may never claim a state the live matrix does not have (a closed key
// while the tail is still open reads as "access is closed"; an open key widens the next
// unrelated resync). It runs under the writer lock with the same dry-run guard as the store,
// audits its own outcome and returns the note the result screen shows.
func (h *SiteSettingsHandler) restoreS06(r *http.Request, actor, target string, prev bool) string {
	storeErr := change.WithWriterLock(func() error {
		on, err := h.cfg.DryRun.DryRun(r.Context())
		if err != nil {
			return err
		}
		if on {
			return errSettingsDryRun
		}
		return h.cfg.Setter.SetS06Open(r.Context(), prev)
	})
	if storeErr == nil {
		h.auditOutcome(r, actor, "site.s06", target, "restored", "switch önceki değerine döndürüldü (apply hedef duruma ulaşamadı)")
		return "Apply hedef duruma ulaşamadı; switch eski değerine (" + s06Label(prev) + ") geri alındı. Canlı yapı değişmedi."
	}
	h.auditOutcome(r, actor, "site.s06", target, "restore_failed", storeErr.Error())
	return "Apply hedef duruma ulaşamadı ve switch eski değerine geri alınamadı (" + storeErr.Error() +
		"); depolanan switch canlı yapıdan farklı olabilir, kontrol edin."
}

// s06Label is the Turkish label of the key state for the result note.
func s06Label(open bool) string {
	if open {
		return "açık"
	}
	return "kapalı"
}

// renderS06Blocked shows a state problem without the approval.
func (h *SiteSettingsHandler) renderS06Blocked(w http.ResponseWriter, r *http.Request, open bool, reason string) {
	view := SiteS06ReviewView{Open: open, Blocked: reason}
	pageActor, _ := ActorFrom(r.Context())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = Layout(pageActor, h.cfg.CSRF.Token(), "siteler", "Switch değişikliği",
		SiteS06ReviewPage(view, h.cfg.CSRF.Token())).Render(r.Context(), w)
}

// renderResult writes the shared result screen; note explains a key restore next to the outcome.
func (h *SiteSettingsHandler) renderResult(w http.ResponseWriter, r *http.Request, res change.SiteResult, applyErr error, note string) {
	actor, _ := ActorFrom(r.Context())
	view := buildSiteResultView(r.Context(), h.cfg.Changes, h.cfg.Lister, res, applyErr)
	view.Note = note
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = Layout(actor, h.cfg.CSRF.Token(), "siteler", "Değişiklik sonucu",
		SiteResultPage(view)).Render(r.Context(), w)
}

// audit writes one operator action before anything runs.
func (h *SiteSettingsHandler) audit(r *http.Request, actor, event, target, result, reason string) error {
	var diff audit.Diff
	if reason != "" {
		diff = audit.Diff{{Field: "error", After: reason}}
	}
	_, err := h.cfg.Auditor.Write(r.Context(), audit.Entry{
		Actor: actor, Event: event, Target: target, Diff: diff, Result: result,
	})
	return err
}

// auditOutcome writes the post-action result; the requested entry already records the action.
func (h *SiteSettingsHandler) auditOutcome(r *http.Request, actor, event, target, result, reason string) {
	if err := h.audit(r, actor, event, target, result, reason); err != nil {
		slog.Default().Warn("site settings: audit outcome write failed", "event", event, "target", target, "err", err)
	}
}
