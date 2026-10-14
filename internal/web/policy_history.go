package web

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/a-h/templ"

	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/policydoc"
	"github.com/nesiler/tagcess/internal/policyrev"
	"github.com/nesiler/tagcess/internal/policywriter"
)

// The policy history and rollback pages (F3-025, A-03, ADR 0020). The list and the detail read the
// revision store. "Bu sürüme dön" loads the stored raw text as a candidate and runs the editor's
// normal preview and approval through the policy writer with source=rollback: the writer rebuilds
// today's groups and the locked tests, validates, and applies it as a new revision. Nothing here
// writes a revision or the live policy itself, and the text is taken from the store, never from the
// form.

const (
	// historyLimit is how many revisions the list reads.
	historyLimit = 200
	// rollbackScopeNote is shown on every rollback page: what a policy rollback does not cover.
	rollbackScopeNote = "Geri alma yalnız policy metnini kapsar: cihaz/key/expiry/ownership dönüşümünü kapsamaz; autoApprovers farkı varsa route onayları yeniden değerlendirilebilir."
	// rollbackOnlyApplied is the reason a revision is not a rollback target.
	rollbackOnlyApplied = "Geri alma hedefi yalnız apply edilmiş (applied) revision'lar olabilir; failed, unknown, pending ve dry_run revision'lara dönülemez."
)

// PolicyRevisions is the revision store's read side; *policyrev.Repo satisfies it.
type PolicyRevisions interface {
	List(ctx context.Context, limit int) ([]policyrev.Revision, error)
	Get(ctx context.Context, id int64) (policyrev.Revision, error)
}

// PolicyHistoryConfig wires the history pages. Every field is required.
type PolicyHistoryConfig struct {
	Editor    PolicyEditor
	Revisions PolicyRevisions
	DryRun    change.DryRun
	CSRF      *CSRF
}

// PolicyHistoryHandler serves /headscale/policy/history. It reuses the editor page's refusal and
// result rendering, so a rollback is stopped and reported exactly like an editor save.
type PolicyHistoryHandler struct {
	cfg    PolicyHistoryConfig
	policy *PolicyHandler
}

// NewPolicyHistoryHandler validates the wiring.
func NewPolicyHistoryHandler(cfg PolicyHistoryConfig) (*PolicyHistoryHandler, error) {
	if cfg.Revisions == nil {
		return nil, errors.New("web: policy history needs a revision store")
	}
	policy, err := NewPolicyHandler(PolicyHandlerConfig{Editor: cfg.Editor, DryRun: cfg.DryRun, CSRF: cfg.CSRF})
	if err != nil {
		return nil, err
	}
	return &PolicyHistoryHandler{cfg: cfg, policy: policy}, nil
}

// Register adds the history routes.
func (h *PolicyHistoryHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /headscale/policy/history", h.list)
	mux.HandleFunc("GET /headscale/policy/history/{id}", h.detail)
	mux.HandleFunc("GET /headscale/policy/history/{id}/rollback", h.rollbackPage)
	mux.HandleFunc("POST /headscale/policy/history/{id}/rollback", h.rollbackSave)
}

// policyRevRow is one revision as the pages show it.
type policyRevRow struct {
	ID          int64
	At          time.Time
	Actor       string
	Source      string
	Status      string
	Reason      string
	Detail      string
	RollbackOf  int64
	CanRollback bool
}

func revRow(r policyrev.Revision) policyRevRow {
	return policyRevRow{
		ID: r.ID, At: r.CreatedAt, Actor: r.Actor, Source: string(r.Source), Status: string(r.ApplyStatus),
		Reason: r.Reason, Detail: r.ApplyDetail, RollbackOf: r.RollbackOf,
		CanRollback: r.ApplyStatus == policyrev.StatusApplied,
	}
}

type policyHistoryView struct {
	DryRun bool
	Rows   []policyRevRow
}

type policyRevisionView struct {
	DryRun       bool
	Row          policyRevRow
	Raw          string
	HeadscaleErr string // the live policy could not be read; no difference is shown
	Raw2Live     []diffRow
	Semantic     []semanticRow
}

type policyRollbackView struct {
	DryRun  bool
	Row     policyRevRow
	Raw     string
	Blocked string            // the revision is not a target
	Page    policyPageView    // the banners of a refusal
	Report  *policydoc.Report // a failed validation shown without a preview
	Preview *policyPreviewView
}

func (h *PolicyHistoryHandler) list(w http.ResponseWriter, r *http.Request) {
	revs, err := h.cfg.Revisions.List(r.Context(), historyLimit)
	if err != nil {
		http.Error(w, "revision'lar okunamadı", http.StatusInternalServerError)
		return
	}
	v := policyHistoryView{}
	for _, rev := range revs {
		v.Rows = append(v.Rows, revRow(rev))
	}
	h.page(w, r, http.StatusOK, func(dry bool) templ.Component {
		v.DryRun = dry
		return PolicyHistoryPage(v)
	})
}

// revision loads the revision of the path; it answers 404 itself for an unknown or malformed id.
func (h *PolicyHistoryHandler) revision(w http.ResponseWriter, r *http.Request) (policyrev.Revision, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		http.NotFound(w, r)
		return policyrev.Revision{}, false
	}
	rev, err := h.cfg.Revisions.Get(r.Context(), id)
	switch {
	case errors.Is(err, policyrev.ErrNotFound):
		http.NotFound(w, r)
		return rev, false
	case err != nil:
		http.Error(w, "revision okunamadı", http.StatusInternalServerError)
		return rev, false
	}
	return rev, true
}

func (h *PolicyHistoryHandler) detail(w http.ResponseWriter, r *http.Request) {
	rev, ok := h.revision(w, r)
	if !ok {
		return
	}
	v := policyRevisionView{Row: revRow(rev), Raw: rev.Raw}
	status := http.StatusOK
	live, err := h.cfg.Editor.Live(r.Context())
	switch {
	case err != nil:
		v.HeadscaleErr = "Policy okunamadı: " + err.Error()
		status = http.StatusBadGateway
	case live.HeadscaleErr != nil:
		v.HeadscaleErr = live.HeadscaleErr.Error()
		status = http.StatusBadGateway
	default:
		v.Raw2Live = rawDiffRows(change.LineDiff(live.Text, rev.Raw))
		v.Semantic = semanticRows(policywriter.SemanticDiff(live.Text, rev.Raw))
	}
	h.page(w, r, status, func(dry bool) templ.Component {
		v.DryRun = dry
		return PolicyRevisionPage(v)
	})
}

// rollbackPage is the candidate: the stored raw text, previewed by the writer (today's groups, the
// locked tests rebuilt, validated). It writes nothing.
func (h *PolicyHistoryHandler) rollbackPage(w http.ResponseWriter, r *http.Request) {
	actor, ok := operatorActor(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	rev, ok := h.revision(w, r)
	if !ok {
		return
	}
	v := policyRollbackView{Row: revRow(rev), Raw: rev.Raw}
	if !v.Row.CanRollback {
		v.Blocked = rollbackOnlyApplied
		h.renderRollback(w, r, http.StatusConflict, v)
		return
	}
	live, err := h.cfg.Editor.Live(r.Context())
	switch {
	case err != nil:
		v.Page.Notice = "Policy okunamadı: " + err.Error()
		h.renderRollback(w, r, http.StatusBadGateway, v)
		return
	case live.HeadscaleErr != nil:
		v.Page.HeadscaleErr = live.HeadscaleErr.Error()
		h.renderRollback(w, r, http.StatusBadGateway, v)
		return
	}
	res, err := h.cfg.Editor.Preview(r.Context(), rollbackRequest(actor, rev, live.BaseHash))
	if err != nil {
		h.refuse(w, r, v, res, err)
		return
	}
	pv := policyPreviewView{
		Report:        res.Report,
		Raw:           rawDiffRows(res.RawDiff),
		Semantic:      semanticRows(res.Semantic),
		GroupsRebuilt: res.GroupsRebuilt,
		Confirm:       res.Report.Valid(),
		SaveAction:    rollbackAction(rev.ID),
	}
	for _, c := range res.Locked {
		pv.Locked = append(pv.Locked, string(c.Kind)+" "+c.Rule)
	}
	pv.AutoApprovers = hasSection(pv.Semantic, "autoApprovers")
	v.Preview = &pv
	v.Page.BaseHash = live.BaseHash
	h.renderRollback(w, r, http.StatusOK, v)
}

// rollbackSave applies the rollback through the writer. The text is the stored revision's, never the
// form's; the writer re-validates and rebuilds everything, and the base hash is the preview's.
func (h *PolicyHistoryHandler) rollbackSave(w http.ResponseWriter, r *http.Request) {
	actor, ok := operatorActor(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	rev, ok := h.revision(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "geçersiz form", http.StatusBadRequest)
		return
	}
	v := policyRollbackView{Row: revRow(rev), Raw: rev.Raw}
	if !v.Row.CanRollback {
		v.Blocked = rollbackOnlyApplied
		h.renderRollback(w, r, http.StatusConflict, v)
		return
	}
	res, err := h.cfg.Editor.Save(r.Context(), rollbackRequest(actor, rev, r.PostFormValue("base_hash")))
	switch {
	case err == nil:
		h.policy.renderResult(w, r, http.StatusOK, res)
	case res.Change.Applied:
		// The policy is live; the error is bookkeeping after the apply (see PolicyHandler.save).
		h.policy.renderResult(w, r, http.StatusOK, withBookkeepingError(res, err))
	case errors.Is(err, policywriter.ErrNotApplied):
		h.policy.renderResult(w, r, http.StatusBadGateway, res)
	default:
		h.refuse(w, r, v, res, err)
	}
}

// refuse shows a refusal the writer returned before writing anything.
func (h *PolicyHistoryHandler) refuse(w http.ResponseWriter, r *http.Request, v policyRollbackView, res policywriter.SaveResult, err error) {
	v.Page.ReloadHref = "/headscale/policy/history/" + strconv.FormatInt(v.Row.ID, 10) + "/rollback"
	status := h.policy.refusal(&v.Page, res, err)
	v.Report, v.Page.Report = v.Page.Report, nil
	h.renderRollback(w, r, status, v)
}

func rollbackRequest(actor string, rev policyrev.Revision, baseHash string) policywriter.SaveRequest {
	return policywriter.SaveRequest{
		Actor: actor, Text: rev.Raw, BaseHash: baseHash,
		Source: policyrev.SourceRollback, RollbackOf: rev.ID,
		Reason: "revision #" + strconv.FormatInt(rev.ID, 10) + "'e geri alma",
	}
}

func rollbackAction(id int64) string {
	return "/headscale/policy/history/" + strconv.FormatInt(id, 10) + "/rollback"
}

func (h *PolicyHistoryHandler) renderRollback(w http.ResponseWriter, r *http.Request, status int, v policyRollbackView) {
	token := h.cfg.CSRF.Token()
	h.page(w, r, status, func(dry bool) templ.Component {
		v.DryRun = dry
		return PolicyRollbackPage(v, token)
	})
}

// page renders a component inside the layout with the dry-run flag of the section's tab bar.
func (h *PolicyHistoryHandler) page(w http.ResponseWriter, r *http.Request, status int, build func(dryRun bool) templ.Component) {
	dryRun, err := h.cfg.DryRun.DryRun(r.Context())
	if err != nil {
		http.Error(w, "dry-run durumu okunamadı", http.StatusInternalServerError)
		return
	}
	actor, _ := ActorFrom(r.Context())
	noStore(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = Layout(actor, h.cfg.CSRF.Token(), "headscale", "ACL / policy", build(dryRun)).Render(r.Context(), w)
}
