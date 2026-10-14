package web

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/tailscale/hujson"

	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/policydoc"
	"github.com/nesiler/tagcess/internal/policyrev"
	"github.com/nesiler/tagcess/internal/policywriter"
)

// The policy editor page (F3-019, H-04): a plain textarea with the live policy, a server-side
// validation panel, the raw and semantic diff, and a confirm step. The draft is stateless: the page
// carries the text, the base hash and the previewed text's hash as form fields, and a save
// re-validates everything in the writer (the preview is never the authority to apply). Every refusal
// comes from the policy writer (F3-010); the page only shows it.

// PolicyEditor is the policy writer's surface; *policywriter.Writer satisfies it.
type PolicyEditor interface {
	Live(ctx context.Context) (policywriter.Live, error)
	Preview(ctx context.Context, req policywriter.SaveRequest) (policywriter.SaveResult, error)
	Save(ctx context.Context, req policywriter.SaveRequest) (policywriter.SaveResult, error)
}

// PolicyHandlerConfig wires the editor page. Editor, DryRun and CSRF are required; the tag-form
// collaborators (F3-024) are optional — without them the tagOwners/autoApprovers card stays hidden.
type PolicyHandlerConfig struct {
	Editor PolicyEditor
	// DryRun carries the dry-run note of the section tab bar (R2 karar 22).
	DryRun change.DryRun
	CSRF   *CSRF
	// Nodes counts the nodes per tag for the tag forms. *admin.AdminClient satisfies it.
	Nodes hsAdminLister
	// Protected reads the protected server tags (F3-009). *hsadmin.Executor satisfies it.
	Protected protectedLister
}

// PolicyHandler serves /headscale/policy.
type PolicyHandler struct {
	cfg PolicyHandlerConfig
}

// NewPolicyHandler validates the wiring.
func NewPolicyHandler(cfg PolicyHandlerConfig) (*PolicyHandler, error) {
	switch {
	case cfg.Editor == nil:
		return nil, errors.New("web: policy page needs a policy editor")
	case cfg.DryRun == nil:
		return nil, errors.New("web: policy page needs a dry-run source")
	case cfg.CSRF == nil:
		return nil, errors.New("web: policy page needs a CSRF signer")
	}
	return &PolicyHandler{cfg: cfg}, nil
}

// Register adds the policy routes. /headscale/policy/recovery belongs to F3-029; the banner links
// to it. The rules and tag form routes (F3-023/024) edit the draft text only; saving stays the
// preview/save flow below.
func (h *PolicyHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /headscale/policy", h.page)
	mux.HandleFunc("GET /headscale/policy/revalidate", h.revalidate)
	mux.HandleFunc("POST /headscale/policy/preview", h.preview)
	mux.HandleFunc("POST /headscale/policy/save", h.save)
	mux.HandleFunc("POST /headscale/policy/rules/add", h.ruleAdd)
	mux.HandleFunc("POST /headscale/policy/rules/update", h.ruleUpdate)
	mux.HandleFunc("POST /headscale/policy/rules/delete", h.ruleDelete)
	if h.cfg.Nodes != nil && h.cfg.Protected != nil {
		mux.HandleFunc("POST /headscale/policy/tags/set", h.tagSet)
		mux.HandleFunc("POST /headscale/policy/tags/delete", h.tagDelete)
		mux.HandleFunc("POST /headscale/policy/routes/set", h.routeSet)
		mux.HandleFunc("POST /headscale/policy/routes/delete", h.routeDelete)
		mux.HandleFunc("POST /headscale/policy/routes/exitnode", h.exitNodeSet)
	}
}

const (
	// revalidateStill and revalidateCleared are the two answers of a fresh read of the unresolved state.
	revalidateStill   = "still"
	revalidateCleared = "cleared"
)

// policyPageView is everything the editor page shows.
type policyPageView struct {
	DryRun   bool
	Text     string
	BaseHash string
	Groups   string // the live groups section, read-only (H-04.3)

	HeadscaleErr string // the live policy could not be read
	ZitadelErr   string // editing is closed
	Uncertain    string // an earlier write is unresolved: the detail
	Stale        bool   // the base hash is no longer the live policy's
	SyncPending  string // the sync holds a group change; /sync is the place
	Notice       string // any other refusal, shown as an alert
	Revalidated  string // "", revalidateStill or revalidateCleared
	ReloadHref   string // where the stale banner links; the editor when empty

	Preview *policyPreviewView
	Report  *policydoc.Report // a validation report shown without a preview (a refused save)
	// Editable is false whenever a banner closes editing; the text is still shown.
	Editable bool

	// Rules is the form view of the acls section (F3-023); Tags is the one of tagOwners and
	// autoApprovers (F3-024). render fills them from the text when a handler leaves them out.
	Rules *policyRulesView
	Tags  *policyTagsView
}

// policyPreviewView is a successful preview: the report, the diffs and the notices.
type policyPreviewView struct {
	Report        policydoc.Report
	Raw           []diffRow
	Semantic      []semanticRow
	GroupsRebuilt bool
	Locked        []string
	AutoApprovers bool
	// Confirm is true when the text may be saved: every stage passed.
	Confirm bool
	// Text and ReportHash bind the editor's confirm form to the previewed text; the rollback page
	// leaves them empty (its text comes from the stored revision). SaveAction defaults to the
	// editor's.
	Text       string
	ReportHash string
	SaveAction string
}

// policyResultView is the result page of a save.
type policyResultView struct {
	DryRun      bool
	Outcome     string // "applied", "failed", "unknown" or "dry_run"
	RevisionID  int64
	Status      string
	Detail      string
	GitRevision string
	GitFailed   bool
	Dry         bool
}

func (h *PolicyHandler) page(w http.ResponseWriter, r *http.Request) {
	h.renderLive(w, r, "")
}

// revalidate is the "yeniden doğrula" link: a fresh read of the unresolved state, reported on the page.
func (h *PolicyHandler) revalidate(w http.ResponseWriter, r *http.Request) {
	h.renderLive(w, r, "fresh")
}

// renderLive builds the page from a fresh read of the live policy.
func (h *PolicyHandler) renderLive(w http.ResponseWriter, r *http.Request, mode string) {
	live, err := h.cfg.Editor.Live(r.Context())
	view := policyPageView{}
	status := http.StatusOK
	switch {
	case err != nil:
		view.Notice = "Policy okunamadı: " + err.Error()
		status = http.StatusBadGateway
	default:
		view.Text, view.BaseHash = live.Text, live.BaseHash
		if live.HeadscaleErr != nil {
			view.HeadscaleErr = live.HeadscaleErr.Error()
			status = http.StatusBadGateway
		}
		if live.ZitadelErr != nil {
			view.ZitadelErr = live.ZitadelErr.Error()
		}
		view.Uncertain = live.Uncertain
		view.Editable = view.HeadscaleErr == "" && view.ZitadelErr == "" && view.Uncertain == ""
		if mode == "fresh" {
			view.Revalidated = revalidateCleared
			if live.Uncertain != "" {
				view.Revalidated = revalidateStill
			}
		}
	}
	h.render(w, r, status, view)
}

// formText reads the editor's text, normalising the CRLF line ends a browser puts in a textarea
// submission to LF, so the hash and the saved text do not depend on the browser.
func formText(r *http.Request) string {
	return strings.ReplaceAll(r.PostFormValue("text"), "\r\n", "\n")
}

func (h *PolicyHandler) preview(w http.ResponseWriter, r *http.Request) {
	actor, ok := operatorActor(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "geçersiz form", http.StatusBadRequest)
		return
	}
	text, base := formText(r), r.PostFormValue("base_hash")
	res, err := h.cfg.Editor.Preview(r.Context(), policywriter.SaveRequest{Actor: actor, Text: text, BaseHash: base})
	view := policyPageView{Text: text, BaseHash: base}
	if err != nil {
		status := h.refusal(&view, res, err)
		h.render(w, r, status, view)
		return
	}
	pv := policyPreviewView{
		Report:        res.Report,
		Raw:           rawDiffRows(res.RawDiff),
		Semantic:      semanticRows(res.Semantic),
		GroupsRebuilt: res.GroupsRebuilt,
		Confirm:       res.Report.Valid(),
		Text:          text,
		ReportHash:    policyrev.HashRaw(text),
	}
	for _, c := range res.Locked {
		pv.Locked = append(pv.Locked, string(c.Kind)+" "+c.Rule)
	}
	pv.AutoApprovers = hasSection(pv.Semantic, "autoApprovers")
	view.Preview = &pv
	view.Editable = true
	view.Groups = groupsSection(res.Current)
	h.render(w, r, http.StatusOK, view)
}

func (h *PolicyHandler) save(w http.ResponseWriter, r *http.Request) {
	actor, ok := operatorActor(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "geçersiz form", http.StatusBadRequest)
		return
	}
	text, base := formText(r), r.PostFormValue("base_hash")
	view := policyPageView{Text: text, BaseHash: base}
	// The report belongs to the text it was made for: a save carrying another text's hash (an old
	// response, an edited text) never reaches the writer. The writer validates again either way.
	if got := r.PostFormValue("report_hash"); got == "" || got != policyrev.HashRaw(text) {
		view.Notice = "Preview bu metne ait değil: metin preview'dan sonra değişmiş veya eski bir yanıt kullanıldı. Yeniden preview edin."
		view.Editable = true
		h.render(w, r, http.StatusConflict, view)
		return
	}
	res, err := h.cfg.Editor.Save(r.Context(), policywriter.SaveRequest{Actor: actor, Text: text, BaseHash: base})
	switch {
	case err == nil:
		h.renderResult(w, r, http.StatusOK, res)
	case res.Change.Applied:
		// The policy is live; an error alongside it is bookkeeping (revision, audit, sync run) that
		// failed after the apply. Say so, never "nothing written".
		h.renderResult(w, r, http.StatusOK, withBookkeepingError(res, err))
	case errors.Is(err, policywriter.ErrNotApplied):
		h.renderResult(w, r, http.StatusBadGateway, res)
	default:
		status := h.refusal(&view, res, err)
		h.render(w, r, status, view)
	}
}

// withBookkeepingError appends the post-apply bookkeeping error to the revision's detail, so the
// result page shows it next to the applied outcome.
func withBookkeepingError(res policywriter.SaveResult, err error) policywriter.SaveResult {
	note := "kayıt hatası: " + err.Error()
	if d := res.Revision.ApplyDetail; d != "" {
		note = d + "; " + note
	}
	res.Revision.ApplyDetail = note
	return res
}

// refusal fills the view for an error the writer returned before writing anything and returns the
// status code. The text stays in the editor so nothing the operator typed is lost.
func (h *PolicyHandler) refusal(v *policyPageView, res policywriter.SaveResult, err error) int {
	switch {
	case errors.Is(err, policywriter.ErrStale):
		v.Stale = true
		return http.StatusConflict
	case errors.Is(err, policywriter.ErrZitadelUnavailable):
		v.ZitadelErr = err.Error()
		return http.StatusServiceUnavailable
	case errors.Is(err, policywriter.ErrHeadscaleUnavailable):
		v.HeadscaleErr = err.Error()
		return http.StatusBadGateway
	case errors.Is(err, policywriter.ErrUncertain):
		v.Uncertain = err.Error()
		return http.StatusConflict
	case errors.Is(err, policywriter.ErrSyncPending):
		v.SyncPending = err.Error()
		return http.StatusConflict
	case errors.Is(err, policywriter.ErrRollbackTarget):
		v.Notice = "Geri alınamadı; hiçbir şey yazılmadı: " + err.Error()
		return http.StatusConflict
	case errors.Is(err, policywriter.ErrInvalid):
		v.Notice = "Policy kaydedilmedi; hiçbir şey yazılmadı: " + err.Error()
		if len(res.Report.Stages) > 0 {
			v.Report = &res.Report
			v.Editable = true
		}
		return http.StatusUnprocessableEntity
	default:
		v.Notice = "Policy işlenemedi; hiçbir şey yazılmadı: " + err.Error()
		return http.StatusInternalServerError
	}
}

func (h *PolicyHandler) render(w http.ResponseWriter, r *http.Request, status int, v policyPageView) {
	dryRun, err := h.cfg.DryRun.DryRun(r.Context())
	if err != nil {
		http.Error(w, "dry-run durumu okunamadı", http.StatusInternalServerError)
		return
	}
	v.DryRun = dryRun
	// The form tables always come from the text on the page; a form handler passes only the
	// feedback of its action (or a table it already built for that text), which survives.
	if v.Text != "" {
		v.Rules = withRulesTable(v.Rules, v.Text)
		if h.cfg.Nodes != nil && h.cfg.Protected != nil {
			v.Tags = h.withTagsTable(r.Context(), v.Tags, v.Text)
		}
	}
	if v.Groups == "" {
		v.Groups = groupsSection(v.Text)
	}
	actor, _ := ActorFrom(r.Context())
	noStore(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = Layout(actor, h.cfg.CSRF.Token(), "headscale", "ACL / policy", PolicyPage(v, h.cfg.CSRF.Token())).Render(r.Context(), w)
}

// renderResult shows the outcome of a save: the revision id, its status and the git revision. Only an
// applied revision says success; a failed or unknown one never does.
func (h *PolicyHandler) renderResult(w http.ResponseWriter, r *http.Request, status int, res policywriter.SaveResult) {
	dryRun, err := h.cfg.DryRun.DryRun(r.Context())
	if err != nil {
		http.Error(w, "dry-run durumu okunamadı", http.StatusInternalServerError)
		return
	}
	v := policyResultView{
		DryRun:      dryRun,
		RevisionID:  res.Revision.ID,
		Status:      string(res.Revision.ApplyStatus),
		Detail:      res.Revision.ApplyDetail,
		GitRevision: res.Change.Revision,
		GitFailed:   res.Change.GitFailed,
	}
	switch {
	case res.Change.Status == change.StatusDryRun || res.Revision.ApplyStatus == policyrev.StatusDryRun:
		v.Outcome = "dry_run"
	case res.Change.Applied && res.Revision.ApplyStatus == policyrev.StatusApplied:
		v.Outcome = "applied"
	case res.Revision.ApplyStatus == policyrev.StatusUnknown:
		v.Outcome = "unknown"
	default:
		v.Outcome = "failed"
		if status == http.StatusOK {
			// An outcome the writer called success but the revision does not confirm is not shown as one.
			status = http.StatusBadGateway
		}
	}
	actor, _ := ActorFrom(r.Context())
	noStore(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = Layout(actor, h.cfg.CSRF.Token(), "headscale", "ACL / policy", PolicyResultPage(v)).Render(r.Context(), w)
}

// groupsSection returns the policy's groups section as written, for the read-only display; "" when
// the text has none or cannot be parsed (the validation reports that).
func groupsSection(text string) string {
	root, err := hujson.Parse([]byte(text))
	if err != nil {
		return ""
	}
	obj, ok := root.Value.(*hujson.Object)
	if !ok {
		return ""
	}
	for _, m := range obj.Members {
		if lit, ok := m.Name.Value.(hujson.Literal); ok && lit.String() == "groups" {
			return string(bytes.TrimSpace(m.Value.Pack()))
		}
	}
	return ""
}
