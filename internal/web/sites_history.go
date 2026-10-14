package web

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/a-h/templ"

	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/site"
)

// The site history screens (F2-020, A-03, ADR 0017): the durable source versions of a site, the
// read-only preview of a rollback to one of them, and the approval that applies it as a new change
// through the site pipeline. The handler holds no state of its own: the preview's live base hash
// travels in the approval form and the pipeline compares it with a fresh read.

// SiteVersionReader lists a site's durable versions, newest first (satisfied by *site.Store).
type SiteVersionReader interface {
	ListVersions(ctx context.Context, siteID int64) ([]site.Version, error)
}

// SiteRollbacker previews and applies a rollback (satisfied by *change.SitePipeline).
type SiteRollbacker interface {
	PreviewRollback(ctx context.Context, actor string, versionID int64) (change.RollbackPreview, error)
	ApplyRollback(ctx context.Context, a change.RollbackApproval) (change.SiteResult, error)
}

// SiteHistoryConfig wires the history screens.
type SiteHistoryConfig struct {
	Versions SiteVersionReader
	Rollback SiteRollbacker
	CSRF     *CSRF
}

// SiteHistoryHandler serves the history and rollback pages. It is mounted behind RequireDevops and
// CSRF.Protect, like the other pages.
type SiteHistoryHandler struct {
	cfg SiteHistoryConfig
}

// NewSiteHistoryHandler validates the wiring.
func NewSiteHistoryHandler(cfg SiteHistoryConfig) (*SiteHistoryHandler, error) {
	switch {
	case cfg.Versions == nil:
		return nil, errors.New("web: site history needs a version reader")
	case cfg.Rollback == nil:
		return nil, errors.New("web: site history needs a rollback pipeline")
	case cfg.CSRF == nil:
		return nil, errors.New("web: site history needs a CSRF signer")
	}
	return &SiteHistoryHandler{cfg: cfg}, nil
}

// Register adds the history routes. There is deliberately no policy route: the F2 interface does
// not apply or roll back the Headscale policy (A-03.3).
func (h *SiteHistoryHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /sites/{id}/history", h.history)
	mux.HandleFunc("GET /sites/{id}/history/{version}/rollback", h.preview)
	mux.HandleFunc("POST /sites/{id}/history/{version}/rollback", h.approve)
}

// VersionRow is one version in the history list.
type VersionRow struct {
	ID         int64
	Op         string
	Hosts      string
	Actor      string
	At         time.Time
	Revision   string
	Rollback   bool // the version re-applied an earlier one
	RollbackOf int64
	Deleted    bool
}

// SiteHistoryView is the data of the history page.
type SiteHistoryView struct {
	SiteID   int64
	Hosts    string
	Versions []VersionRow
}

// DiffBlock is the diff of one artifact in unified diff form; Diff is empty when the artifact
// does not change (ui.Diff then says so).
type DiffBlock struct {
	Title string
	Diff  string
}

// RollbackPreviewView is the data of the preview page.
type RollbackPreviewView struct {
	SiteID   int64
	Version  VersionRow
	Op       string
	Diffs    []DiffBlock
	Widens   []string
	BaseHash string
	NoChange bool
}

// NoticeView is a result or error page: a level (success, warning, danger, info) and a message.
type NoticeView struct {
	Level    string
	Title    string
	Message  string
	Revision string
	// RevisionPending is set when the change was applied but its revision is not committed yet.
	RevisionPending bool
	ChangeID        int64
	BackHref        string
	BackLabel       string
}

func (h *SiteHistoryHandler) history(w http.ResponseWriter, r *http.Request) {
	id, ok := historySiteID(w, r)
	if !ok {
		return
	}
	versions, err := h.cfg.Versions.ListVersions(r.Context(), id)
	if err != nil {
		http.Error(w, "sürümler okunamadı", http.StatusInternalServerError)
		return
	}
	if len(versions) == 0 {
		http.NotFound(w, r)
		return
	}
	view := SiteHistoryView{SiteID: id, Hosts: strings.Join(versions[0].Hosts, ", ")}
	for _, v := range versions {
		view.Versions = append(view.Versions, versionRow(v))
	}
	h.render(w, r, http.StatusOK, "Site geçmişi", SiteHistoryPage(view))
}

func (h *SiteHistoryHandler) preview(w http.ResponseWriter, r *http.Request) {
	id, versionID, ok := h.selected(w, r)
	if !ok {
		return
	}
	actor, ok := operatorActor(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	p, err := h.cfg.Rollback.PreviewRollback(r.Context(), actor, versionID)
	if err != nil {
		h.fail(w, r, id, err)
		return
	}
	view := RollbackPreviewView{
		SiteID: id, Version: versionRow(p.Version), Op: p.Op, Widens: p.Widens,
		BaseHash: p.BaseHash, NoChange: p.NoChange,
		Diffs: []DiffBlock{
			{Title: "Caddyfile", Diff: p.Plan.Diff.Caddy},
			{Title: "MagicDNS", Diff: p.Plan.Diff.DNS},
			{Title: "Zitadel redirect URI", Diff: p.Plan.Diff.Zitadel},
		},
	}
	h.render(w, r, http.StatusOK, "Rollback preview'u", RollbackPreviewPage(view, h.cfg.CSRF.Token()))
}

func (h *SiteHistoryHandler) approve(w http.ResponseWriter, r *http.Request) {
	id, versionID, ok := h.selected(w, r)
	if !ok {
		return
	}
	actor, ok := operatorActor(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "geçersiz form", http.StatusBadRequest)
		return
	}
	res, err := h.cfg.Rollback.ApplyRollback(r.Context(), change.RollbackApproval{
		Actor:            actor,
		VersionID:        versionID,
		BaseHash:         strings.TrimSpace(r.PostFormValue("base_hash")),
		AcknowledgeWiden: r.PostFormValue("ack_widen") != "",
	})
	if err != nil && res.Status == "" {
		h.fail(w, r, id, err)
		return
	}
	h.result(w, r, id, versionID, res, err)
}

// selected parses the ids and checks the version belongs to the site in the path; a version of
// another site is not found, so a crafted URL cannot apply it under the wrong page.
func (h *SiteHistoryHandler) selected(w http.ResponseWriter, r *http.Request) (siteID, versionID int64, ok bool) {
	siteID, ok = historySiteID(w, r)
	if !ok {
		return 0, 0, false
	}
	versionID, err := strconv.ParseInt(strings.TrimSpace(r.PathValue("version")), 10, 64)
	if err != nil || versionID <= 0 {
		http.Error(w, "geçersiz sürüm", http.StatusBadRequest)
		return 0, 0, false
	}
	versions, err := h.cfg.Versions.ListVersions(r.Context(), siteID)
	if err != nil {
		http.Error(w, "sürümler okunamadı", http.StatusInternalServerError)
		return 0, 0, false
	}
	for _, v := range versions {
		if v.ID == versionID {
			return siteID, versionID, true
		}
	}
	http.NotFound(w, r)
	return 0, 0, false
}

// fail renders a refusal of the preview or the approval with the status that tells it apart.
func (h *SiteHistoryHandler) fail(w http.ResponseWriter, r *http.Request, siteID int64, err error) {
	back := "/sites/" + strconv.FormatInt(siteID, 10) + "/history"
	notice := NoticeView{Level: "danger", BackHref: back, BackLabel: "Geçmişe dön"}
	status := http.StatusUnprocessableEntity
	switch {
	case errors.Is(err, site.ErrNotFound):
		http.NotFound(w, r)
		return
	case errors.Is(err, change.ErrRollbackStale):
		status = http.StatusConflict
		notice.Level, notice.Title = "warning", "Canlı durum değişti"
		notice.Message = "Preview'dan sonra canlı durum değişti (başka bir değişiklik ya da elle düzenleme). Hiçbir şey apply edilmedi; preview'u yeniden açın."
	case errors.Is(err, change.ErrRollbackWidens):
		status = http.StatusConflict
		notice.Level, notice.Title = "warning", "Erişimi genişletme onaylanmadı"
		notice.Message = "Bu rollback erişimi genişletiyor ve açık onay verilmedi: " + err.Error()
	case errors.Is(err, change.ErrRollbackNoChange):
		status = http.StatusConflict
		notice.Level, notice.Title = "info", "Değişecek bir şey yok"
		notice.Message = "Site zaten seçilen sürümde."
	case errors.Is(err, site.ErrSystemLocked):
		status = http.StatusConflict
		notice.Title = "Sistem sitesi kilitli"
		notice.Message = "Bu rollback sistem sitesinin kilitli alanlarını değiştireceği için reddedildi: " + err.Error()
	default:
		notice.Title = "Rollback reddedildi"
		notice.Message = err.Error()
	}
	h.render(w, r, status, notice.Title, NoticePage(notice))
}

// result renders the outcome of an applied (or attempted) rollback.
func (h *SiteHistoryHandler) result(w http.ResponseWriter, r *http.Request, siteID, versionID int64, res change.SiteResult, err error) {
	notice := NoticeView{
		Level: "danger", ChangeID: res.ChangeID, Revision: res.Revision,
		BackHref: "/sites/" + strconv.FormatInt(siteID, 10) + "/history", BackLabel: "Geçmişe dön",
	}
	status := http.StatusOK
	switch res.Status {
	case change.StatusApplied:
		notice.Level, notice.Title = "success", "Rollback yapıldı"
		notice.Message = "Seçilen sürüm yeni bir değişiklik olarak apply edildi ve audit'e yazıldı."
		notice.RevisionPending = res.Revision == ""
		if err != nil {
			notice.Level = "warning"
			notice.Message += " Bazı kayıtlar yazılamadı (kritik uyarı verildi): " + err.Error()
		}
	case change.StatusDryRun:
		notice.Level, notice.Title = "info", "Kuru çalışma açık"
		notice.Message = "Kuru çalışma (dry-run) modu açık olduğu için hiçbir şey apply edilmedi."
	case change.StatusBlocked:
		status = http.StatusConflict
		notice.Level, notice.Title = "warning", "Rollback yapılmadı"
		notice.Message = "Mevcut durum okunamadı ya da kayıtlardan farklı olduğu için hiçbir şey apply edilmedi. Neden audit kaydında."
	case change.StatusRolledBack:
		status = http.StatusBadGateway
		notice.Title = "Rollback başarısız"
		notice.Message = "Apply başarısız oldu; apply edilen adımlar geri alındı. Neden audit kaydında."
	default:
		status = http.StatusBadGateway
		notice.Title = "Rollback başarısız"
		notice.Message = "Apply başarısız oldu; son iyi durum korundu ve kritik uyarı verildi. Neden audit kaydında."
	}
	h.render(w, r, status, notice.Title, NoticePage(notice))
}

func (h *SiteHistoryHandler) render(w http.ResponseWriter, r *http.Request, status int, title string, body templ.Component) {
	actor, _ := ActorFrom(r.Context())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = Layout(actor, h.cfg.CSRF.Token(), "siteler", title, body).Render(r.Context(), w)
}

func historySiteID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := formSiteID(r)
	if err != nil {
		http.Error(w, "geçersiz site", http.StatusBadRequest)
		return 0, false
	}
	return id, true
}

func versionRow(v site.Version) VersionRow {
	return VersionRow{
		ID: v.ID, Op: v.Op, Hosts: strings.Join(v.Hosts, ", "), Actor: v.Actor, At: v.CreatedAt,
		Revision: v.Revision, Rollback: v.RollbackOf != 0, RollbackOf: v.RollbackOf, Deleted: v.Deleted,
	}
}

// shortRevision is the first twelve characters of a Git revision.
func shortRevision(rev string) string {
	if len(rev) > 12 {
		return rev[:12]
	}
	return rev
}

func opLabel(op string) string {
	switch op {
	case site.VersionAdd:
		return "eklendi"
	case site.VersionUpdate:
		return "güncellendi"
	case site.VersionDelete:
		return "silindi"
	case site.VersionResync:
		return "import edildi"
	default:
		return op
	}
}
