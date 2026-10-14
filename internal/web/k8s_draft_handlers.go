package web

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/k8s"
	"github.com/nesiler/tagcess/internal/site"
)

// The k8s draft screen (F4-012): save an incomplete host draft and resume it later. The draft holds
// the user's private access choice (all VPN users = open/intentional, or selected roles = role with at
// least one role), a note and the route provenance it was prepared from. Saving writes only the draft
// store (F4-009 tables); the handler has no site, Caddy, DNS, URI or cluster dependency, so a stored
// draft can never change the running access settings (fail safe, R3-AC-13). A review request (route
// conflict/ambiguity) is never dropped by a save, and a newer snapshot or profile is shown as a
// provenance difference that the user's choices survive. Applying a draft is F4-013's job; mounting
// behind RequireDevops + CSRF is the caller's (F4-031), tested here in a controlled router.

const (
	maxDraftNote  = 500
	maxDraftRoles = 50
	maxDraftRole  = 64
)

// K8sDraftStore is the draft persistence seam (k8s.DraftStore).
type K8sDraftStore interface {
	Get(ctx context.Context, host string) (k8s.SavedDraft, bool, error)
	Save(ctx context.Context, d k8s.SavedDraft, now time.Time) (k8s.SavedDraft, error)
}

// K8sDraftConfig wires the draft screen. Every field is required.
type K8sDraftConfig struct {
	// Discovery supplies the current mapping and snapshot freshness (the F4-011 seam).
	Discovery K8sDiscoveryReader
	Drafts    K8sDraftStore
	// Auditor records every draft mutation; a failed "requested" write refuses the save.
	Auditor SiteAuditor
	CSRF    *CSRF
	Now     func() time.Time
	// Review is the existing site review handler (F2-014). Optional: without it the draft cannot be
	// sent to review. Approval happens on its screen (the same SitePipeline.Submit).
	Review *SiteReviewHandler
	// Roles lists the Zitadel vpn project roles the roles field suggests. Optional: when it is nil
	// or fails, the field still takes any typed role (validated at apply).
	Roles RoleLister
	// K8sUpstream is the (k8s) snippet upstream (sites.k8s_upstream) a role draft must target; empty:
	// the renderer's default.
	K8sUpstream string
}

// K8sDraftHandler serves the draft screen.
type K8sDraftHandler struct {
	cfg K8sDraftConfig
}

// NewK8sDraftHandler validates the wiring.
func NewK8sDraftHandler(cfg K8sDraftConfig) (*K8sDraftHandler, error) {
	switch {
	case cfg.Discovery == nil:
		return nil, errors.New("web: k8s draft needs a discovery reader")
	case cfg.Drafts == nil:
		return nil, errors.New("web: k8s draft needs a draft store")
	case cfg.Auditor == nil:
		return nil, errors.New("web: k8s draft needs an auditor")
	case cfg.CSRF == nil:
		return nil, errors.New("web: k8s draft needs a CSRF signer")
	case cfg.Now == nil:
		return nil, errors.New("web: k8s draft needs a clock")
	}
	return &K8sDraftHandler{cfg: cfg}, nil
}

// Register adds the draft routes to mux. The caller mounts them behind RequireDevops and CSRF.
func (h *K8sDraftHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /k8s/drafts/{host}", h.page)
	mux.HandleFunc("POST /k8s/drafts/{host}", h.save)
	mux.HandleFunc("POST /k8s/drafts/{host}/refresh", h.refresh)
	if h.cfg.Review != nil {
		mux.HandleFunc("POST /k8s/drafts/{host}/review", h.review)
	}
}

// review hands the stored, complete draft to the site review screen (F4-013). Nothing is written
// here: the review preview plans only, and approval is the existing /sites/review/approve.
func (h *K8sDraftHandler) review(w http.ResponseWriter, r *http.Request) {
	c, ok := h.load(w, r)
	if !ok {
		return
	}
	if !c.hasSave {
		http.Error(w, "kayıtlı draft yok; önce kaydedin", http.StatusConflict)
		return
	}
	if h.view(c, "").Source != draftSourceCurrent {
		http.Error(w, "draft'ın kaynağı güncel değil; önce kaynağı yenileyin", http.StatusConflict)
		return
	}
	d := c.saved.Draft
	escalateReview(&d, c.cur)
	req, err := draftSiteRequest(d, h.cfg.K8sUpstream)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	h.cfg.Review.previewForm(w, r, req, func(w http.ResponseWriter, r *http.Request, perr error) {
		http.Error(w, perr.Error(), statusFor(perr))
	})
}

// Source states of the draft page: whether the saved provenance matches the current discovery.
const (
	draftSourceCurrent = "current"
	draftSourceStale   = "stale"
	draftSourceUnknown = "unknown"
)

// K8sDraftView is the page data.
type K8sDraftView struct {
	Host     string
	Saved    bool
	Draft    k8s.Draft
	Complete bool
	// Provenance is what the draft was prepared from; Current is the snapshot discovery now reports.
	Provenance  k8s.Provenance
	Current     *k8s.Snapshot
	Source      string
	StaleReason []string
	Diff        k8s.RouteDiff
	LastAttempt *k8s.Attempt
	Error       string
	Notice      string
	// PublicNotChecked is true when no public listener is declared, so the internet-exposure check
	// was not performed (F5 I3).
	PublicNotChecked bool
	// KnownRoles are the suggested vpn roles; empty when they could not be read.
	KnownRoles []string
}

// draftContext is the stored draft and the current discovery of one host.
type draftContext struct {
	host    string
	saved   k8s.SavedDraft
	hasSave bool
	disc    K8sDiscovery
	discErr error
	cur     *k8s.Draft // the current discovery proposal, nil when absent or unreadable
}

func (c draftContext) snapshot() *k8s.Snapshot {
	if c.discErr != nil {
		return nil
	}
	return c.disc.State.Current
}

// load resolves the host and reads the stored draft and the current discovery. A discovery failure is
// kept (the saved draft still resumes); only a store failure or an invalid host stops the request.
func (h *K8sDraftHandler) load(w http.ResponseWriter, r *http.Request) (draftContext, bool) {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(r.PathValue("host")), "."))
	if !site.ValidHostname(host) {
		http.NotFound(w, r)
		return draftContext{}, false
	}
	c := draftContext{host: host}
	var err error
	c.saved, c.hasSave, err = h.cfg.Drafts.Get(r.Context(), host)
	if err != nil {
		slog.Default().Warn("k8s draft: read failed", "host", host, "err", err)
		http.Error(w, "draft okunamadı", http.StatusInternalServerError)
		return draftContext{}, false
	}
	c.disc, c.discErr = h.cfg.Discovery.Discovery(r.Context())
	if c.discErr == nil {
		for i := range c.disc.Report.Drafts {
			if c.disc.Report.Drafts[i].Host == host {
				c.cur = &c.disc.Report.Drafts[i]
				break
			}
		}
	}
	if !c.hasSave && c.cur == nil {
		http.NotFound(w, r)
		return draftContext{}, false
	}
	return c, true
}

// base is the draft a mutation starts from: the stored one, or the current proposal on first save.
func (c draftContext) base() k8s.SavedDraft {
	if c.hasSave {
		return c.saved
	}
	d := *c.cur
	if d.Roles == nil {
		d.Roles = []string{}
	}
	out := k8s.SavedDraft{Draft: d}
	if s := c.snapshot(); s != nil {
		out.Provenance = k8s.Provenance{ProfileVersion: s.ProfileVersion, SnapshotID: s.ID, ObservedAt: s.ObservedAt}
	}
	return out
}

// escalateReview raises the draft's review request from the current discovery. It never lowers one:
// a stored request stays until the user answers it (R3-AC-14).
func escalateReview(d *k8s.Draft, cur *k8s.Draft) {
	if cur == nil || cur.ReviewState != k8s.ReviewStateNeeded {
		return
	}
	d.ReviewState = k8s.ReviewStateNeeded
	d.ReviewReason = cur.ReviewReason
	d.ReviewCandidates = cur.ReviewCandidates
	d.ReviewDefault = "" // no proven controller winner in the first profile
}

func (h *K8sDraftHandler) page(w http.ResponseWriter, r *http.Request) {
	c, ok := h.load(w, r)
	if !ok {
		return
	}
	h.render(w, r, http.StatusOK, h.view(c, ""))
}

func (h *K8sDraftHandler) view(c draftContext, notice string) K8sDraftView {
	b := c.base()
	escalateReview(&b.Draft, c.cur)
	v := K8sDraftView{
		Host: c.host, Saved: c.hasSave, Draft: b.Draft, Complete: b.Draft.Complete(),
		Provenance: b.Provenance, Current: c.snapshot(), Notice: notice,
	}
	if c.discErr != nil {
		if errors.Is(c.discErr, k8s.ErrNotSet) {
			slog.Default().Info("k8s draft: no connection profile yet", "host", c.host)
		} else {
			slog.Default().Warn("k8s draft: discovery read failed", "host", c.host, "err", c.discErr)
		}
		v.Error = "discovery okunamadı; kayıtlı draft olduğu gibi gösteriliyor, erişim değişmedi"
		v.Source = draftSourceUnknown
		return v
	}
	v.LastAttempt = c.disc.State.LastAttempt
	v.PublicNotChecked = !c.disc.PublicChecked
	v.Source = draftSourceCurrent
	stale := func(reason string) {
		v.Source = draftSourceStale
		v.StaleReason = append(v.StaleReason, reason)
	}
	if v.Current == nil {
		v.Source = draftSourceUnknown
		v.StaleReason = append(v.StaleReason, "bu namespace listesiyle güncel başarılı tarama yok")
	} else {
		if c.hasSave && (b.Provenance.SnapshotID != v.Current.ID || b.Provenance.ProfileVersion != v.Current.ProfileVersion) {
			stale("draft daha eski bir taramadan veya bağlantı ayarından hazırlandı")
		}
		if c.disc.State.Stale {
			stale("son tarama başarısız oldu; gösterilen veri güncel olmayabilir")
		}
	}
	if c.hasSave {
		if c.cur != nil {
			v.Diff = k8s.DiffRoutes(b.Draft.Routes, c.cur.Routes)
		} else if v.Current != nil {
			stale("kaynak route güncel discovery'de bulunmuyor")
		}
	}
	return v
}

func (h *K8sDraftHandler) render(w http.ResponseWriter, r *http.Request, status int, v K8sDraftView) {
	actor, _ := ActorFrom(r.Context())
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if h.cfg.Roles != nil {
		if roles, err := h.cfg.Roles.ListRoles(r.Context()); err == nil {
			v.KnownRoles = roles
		}
	}
	_ = Layout(actor, h.cfg.CSRF.Token(), "k8s", "k8s draft'ı",
		K8sDraftPage(v, h.cfg.CSRF.Token())).Render(r.Context(), w)
}

// save stores the user's choices. The stored provenance is kept (no silent source refresh) and a
// pending review request survives.
func (h *K8sDraftHandler) save(w http.ResponseWriter, r *http.Request) {
	c, ok := h.load(w, r)
	if !ok {
		return
	}
	choice := r.PostFormValue("access_choice")
	roles, err := parseDraftRoles(r.PostFormValue("roles"))
	note := strings.TrimSpace(r.PostFormValue("note"))
	switch {
	case choice != "" && choice != k8s.AccessChoiceOpen && choice != k8s.AccessChoiceRole:
		err = fmt.Errorf("erişim seçimi geçersiz: %q", choice)
	case utf8.RuneCountInString(note) > maxDraftNote:
		err = fmt.Errorf("not en fazla %d karakter olabilir", maxDraftNote)
	}
	if err != nil {
		v := h.view(c, "")
		v.Error = err.Error()
		h.render(w, r, http.StatusBadRequest, v)
		return
	}

	d := c.base()
	if choice == "" {
		d.Draft.AccessChoice, d.Draft.Roles = "", []string{}
	} else if d.Draft, err = k8s.SetPrivateAccess(d.Draft, choice, roles); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	d.Draft.Note = note
	escalateReview(&d.Draft, c.cur)

	diff := audit.Diff{
		{Field: "access_choice", Before: c.base().Draft.AccessChoice, After: d.Draft.AccessChoice},
		{Field: "roles", After: strconv.Itoa(len(d.Draft.Roles))},
	}
	h.persist(w, r, c, "k8s.draft.save", d, diff)
}

// refresh takes the current discovery provenance and routes into a stored draft; the user's choices
// are untouched. It needs a stored draft and a current proposal.
func (h *K8sDraftHandler) refresh(w http.ResponseWriter, r *http.Request) {
	c, ok := h.load(w, r)
	if !ok {
		return
	}
	snap := c.snapshot()
	if !c.hasSave || c.cur == nil || snap == nil {
		http.Error(w, "kaynak yenilenemedi: kayıtlı draft veya güncel discovery yok", http.StatusConflict)
		return
	}
	d := c.saved
	d.Provenance = k8s.Provenance{ProfileVersion: snap.ProfileVersion, SnapshotID: snap.ID, ObservedAt: snap.ObservedAt}
	d.Draft.Routes = c.cur.Routes
	// The proposal's target and certificate come from the current profile: a refreshed source must not
	// carry the old upstream.
	d.Draft.Target, d.Draft.Cert = c.cur.Target, c.cur.Cert
	escalateReview(&d.Draft, c.cur)
	diff := audit.Diff{
		{Field: "snapshot", Before: strconv.FormatInt(c.saved.Provenance.SnapshotID, 10), After: strconv.FormatInt(snap.ID, 10)},
		{Field: "target", Before: c.saved.Draft.Target, After: d.Draft.Target},
	}
	h.persist(w, r, c, "k8s.draft.refresh", d, diff)
}

// persist audits "requested" (a failure refuses the action), stores the draft and records the outcome.
func (h *K8sDraftHandler) persist(w http.ResponseWriter, r *http.Request, c draftContext, event string, d k8s.SavedDraft, diff audit.Diff) {
	actor, _ := ActorFrom(r.Context())
	if _, err := h.cfg.Auditor.Write(r.Context(), audit.Entry{Actor: actor.User, Event: event, Target: c.host, Diff: diff, Result: "requested"}); err != nil {
		slog.Default().Warn("k8s draft: audit write failed", "event", event, "host", c.host, "err", err)
		http.Error(w, "audit kaydı yazılamadı; draft değiştirilmedi", http.StatusInternalServerError)
		return
	}
	result := "ok"
	_, err := h.cfg.Drafts.Save(r.Context(), d, h.cfg.Now())
	if err != nil {
		result = "error"
		slog.Default().Warn("k8s draft: save failed", "event", event, "host", c.host, "err", err)
	}
	if _, aerr := h.cfg.Auditor.Write(r.Context(), audit.Entry{Actor: actor.User, Event: event, Target: c.host, Result: result}); aerr != nil {
		slog.Default().Warn("k8s draft: audit outcome write failed", "event", event, "host", c.host, "err", aerr)
	}
	if err != nil {
		http.Error(w, "draft kaydedilemedi", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/k8s/drafts/"+c.host, http.StatusSeeOther)
}

// parseDraftRoles reads the role textarea (one per line, comma or space separated). Existence of a
// role is the site validator's check at apply time (F4-013).
func parseDraftRoles(s string) ([]string, error) {
	roles := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || unicode.IsSpace(r) })
	if len(roles) > maxDraftRoles {
		return nil, fmt.Errorf("en fazla %d rol seçilebilir", maxDraftRoles)
	}
	for _, role := range roles {
		if utf8.RuneCountInString(role) > maxDraftRole || strings.ContainsFunc(role, unicode.IsControl) {
			return nil, fmt.Errorf("rol adı geçersiz: %q", role)
		}
	}
	return roles, nil
}

// draftRouteDiffLabel renders a route for the provenance difference list.
func draftRouteDiffLabel(r k8s.Route) string {
	return fmt.Sprintf("%s/%s [%s] %s -> %s", r.Namespace, r.Ingress, r.UID, r.Path, backendLabel(r.Backend))
}
