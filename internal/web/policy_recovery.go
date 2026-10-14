package web

import (
	"errors"
	"net/http"

	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/policyrev"
	"github.com/nesiler/tagcess/internal/policywriter"
)

// The recovery page (F3-029, H-04, R2 karar 20/163): while an earlier policy write is unresolved, the
// devops sees the candidate — the last applied revision's text rebuilt with today's Zitadel groups and
// the locked tests, validated — and its fresh difference from the live policy, and applies it with an
// explicit approval. Everything is the policy writer's (source=recovery): the page only shows it. It
// is never called by anything but this page's own requests, and the approval does not skip a check.

const (
	// recoveryInactive is shown while no earlier write is unresolved.
	recoveryInactive = "Şu an belirsiz durum yok: recovery yalnız önceki bir apply'ın sonucu belirsizken açılır."
	// recoveryStale is the refusal of an approval whose base is no longer the live policy.
	recoveryStale = "canlı policy değişti; sayfayı yenileyip adayı ve farkı yeniden inceleyin."
)

// PolicyRecoveryConfig wires the recovery page. Every field is required; Editor is the policy
// writer's surface (the same one the editor page uses).
type PolicyRecoveryConfig struct {
	Editor PolicyEditor
	DryRun change.DryRun
	CSRF   *CSRF
}

// PolicyRecoveryHandler serves /headscale/policy/recovery.
type PolicyRecoveryHandler struct {
	cfg    PolicyRecoveryConfig
	policy *PolicyHandler // its result page and dry-run handling are reused
}

// NewPolicyRecoveryHandler validates the wiring.
func NewPolicyRecoveryHandler(cfg PolicyRecoveryConfig) (*PolicyRecoveryHandler, error) {
	policy, err := NewPolicyHandler(PolicyHandlerConfig{Editor: cfg.Editor, DryRun: cfg.DryRun, CSRF: cfg.CSRF})
	if err != nil {
		return nil, err
	}
	return &PolicyRecoveryHandler{cfg: cfg, policy: policy}, nil
}

// Register adds the recovery routes: the read-only page and the approval.
func (h *PolicyRecoveryHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /headscale/policy/recovery", h.page)
	mux.HandleFunc("POST /headscale/policy/recovery", h.apply)
}

type policyRecoveryView struct {
	DryRun      bool
	Inactive    bool
	Uncertain   string
	Blocked     string // why the recovery is blocked; nothing can be approved
	SyncPending bool
	Target      *policyRevRow
	Candidate   string
	Preview     *policyPreviewView
	BaseHash    string
}

// page shows the candidate and the fresh diff. It writes nothing.
func (h *PolicyRecoveryHandler) page(w http.ResponseWriter, r *http.Request) {
	actor, ok := operatorActor(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	v := policyRecoveryView{}
	live, err := h.cfg.Editor.Live(r.Context())
	switch {
	case err != nil:
		v.Blocked = "Policy okunamadı: " + err.Error()
		h.render(w, r, http.StatusBadGateway, v)
		return
	case live.HeadscaleErr != nil:
		v.Blocked = live.HeadscaleErr.Error()
		h.render(w, r, http.StatusBadGateway, v)
		return
	case live.Uncertain == "":
		v.Inactive = true
		h.render(w, r, http.StatusOK, v)
		return
	}
	v.Uncertain, v.BaseHash = live.Uncertain, live.BaseHash
	res, err := h.cfg.Editor.Preview(r.Context(), policywriter.SaveRequest{
		Actor: actor, BaseHash: live.BaseHash, Source: policyrev.SourceRecovery,
	})
	if err != nil {
		h.refuse(w, r, v, err)
		return
	}
	target := revRow(res.Target)
	v.Target, v.Candidate = &target, res.Text
	pv := policyPreviewView{
		Report:        res.Report,
		Raw:           rawDiffRows(res.RawDiff),
		Semantic:      semanticRows(res.Semantic),
		GroupsRebuilt: res.GroupsRebuilt,
		Confirm:       res.Report.Valid(),
		SaveAction:    "/headscale/policy/recovery",
	}
	for _, c := range res.Locked {
		pv.Locked = append(pv.Locked, string(c.Kind)+" "+c.Rule)
	}
	pv.AutoApprovers = hasSection(pv.Semantic, "autoApprovers")
	v.Preview = &pv
	h.render(w, r, http.StatusOK, v)
}

// apply is the explicit approval: the writer rebuilds, re-validates and applies under its lock and
// reads the result back. The text is never taken from the form.
func (h *PolicyRecoveryHandler) apply(w http.ResponseWriter, r *http.Request) {
	actor, ok := operatorActor(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "geçersiz form", http.StatusBadRequest)
		return
	}
	res, err := h.cfg.Editor.Save(r.Context(), policywriter.SaveRequest{
		Actor: actor, BaseHash: r.PostFormValue("base_hash"), Source: policyrev.SourceRecovery,
	})
	switch {
	case err == nil:
		h.policy.renderResult(w, r, http.StatusOK, res)
	case res.Change.Applied:
		// The policy is live; the error is bookkeeping after the apply (see PolicyHandler.save).
		h.policy.renderResult(w, r, http.StatusOK, withBookkeepingError(res, err))
	case errors.Is(err, policywriter.ErrNotApplied):
		// Failed or unknown: never success, and the state stays uncertain (the writer's revision says which).
		h.policy.renderResult(w, r, http.StatusBadGateway, res)
	default:
		h.refuse(w, r, policyRecoveryView{}, err)
	}
}

// refuse shows why the recovery is blocked; nothing was written.
func (h *PolicyRecoveryHandler) refuse(w http.ResponseWriter, r *http.Request, v policyRecoveryView, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, policywriter.ErrNotUncertain):
		v.Inactive, status = true, http.StatusConflict
	case errors.Is(err, policywriter.ErrZitadelUnavailable):
		v.Blocked, status = err.Error(), http.StatusServiceUnavailable
	case errors.Is(err, policywriter.ErrHeadscaleUnavailable):
		v.Blocked, status = err.Error(), http.StatusBadGateway
	case errors.Is(err, policywriter.ErrStale):
		v.Blocked, status = recoveryStale, http.StatusConflict
	case errors.Is(err, policywriter.ErrSyncPending):
		v.Blocked, v.SyncPending, status = err.Error(), true, http.StatusConflict
	case errors.Is(err, policywriter.ErrNoRecoveryTarget), errors.Is(err, policywriter.ErrInvalid):
		v.Blocked, status = err.Error(), http.StatusConflict
	default:
		v.Blocked = "Recovery işlenemedi; hiçbir şey yazılmadı: " + err.Error()
	}
	h.render(w, r, status, v)
}

func (h *PolicyRecoveryHandler) render(w http.ResponseWriter, r *http.Request, status int, v policyRecoveryView) {
	dryRun, err := h.cfg.DryRun.DryRun(r.Context())
	if err != nil {
		http.Error(w, "dry-run durumu okunamadı", http.StatusInternalServerError)
		return
	}
	v.DryRun = dryRun
	token := h.cfg.CSRF.Token()
	actor, _ := ActorFrom(r.Context())
	noStore(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = Layout(actor, token, "headscale", "ACL / policy", PolicyRecoveryPage(v, token)).Render(r.Context(), w)
}
