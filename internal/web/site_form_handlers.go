package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/a-h/templ"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/site"
	"github.com/nesiler/tagcess/internal/web/ui"
)

// SiteStore is the site CRUD surface the form needs. It is satisfied by *site.Store; every write
// passes the F2-003 validator and the F2-005 system locks inside the store, so the form cannot
// bypass them.
type SiteStore interface {
	GetSite(ctx context.Context, id int64) (site.Site, error)
	CreateSite(ctx context.Context, in site.Site) (site.Site, error)
	UpdateSite(ctx context.Context, id int64, in site.Site) (site.Site, error)
	DeleteSite(ctx context.Context, id int64) error
}

// SiteAuditor writes the form's operator actions to the append-only log (A-01).
type SiteAuditor interface {
	Write(ctx context.Context, e audit.Entry) (audit.Event, error)
}

// RoleLister reads the vpn project roles for the form's role list (S-02.3). It is satisfied by
// *zitadel.Client.
type RoleLister interface {
	ListRoles(ctx context.Context) ([]string, error)
}

// TargetAllowlist is the UI-editable custom target host allowlist (F2-013 AC5). It is satisfied by
// *site.AllowedTargets.
type TargetAllowlist interface {
	ListTargets(ctx context.Context) ([]string, error)
	Set(ctx context.Context, list []string) error
}

// SiteFormConfig wires the site form and CRUD routes.
type SiteFormConfig struct {
	Store   SiteStore
	Targets TargetAllowlist
	Auditor SiteAuditor
	// Roles is optional; when set the form hints the current vpn project roles.
	Roles RoleLister
	// Lock optionally serializes the allowlist change with site writes (change.WithWriterLock).
	Lock func(fn func() error) error
	// Review hands the parsed change to the review flow (F2-014): the form never writes directly;
	// the change goes through preview → approval → apply in the site change pipeline.
	Review *SiteReviewHandler
	CSRF   *CSRF
}

// SiteFormHandler serves the site create/edit form and its CRUD and allowlist actions. It is
// mounted behind RequireDevops and CSRF.Protect, so the actor and the token are enforced before a
// handler runs.
type SiteFormHandler struct {
	cfg SiteFormConfig
}

// NewSiteFormHandler validates the wiring.
func NewSiteFormHandler(cfg SiteFormConfig) (*SiteFormHandler, error) {
	switch {
	case cfg.Store == nil:
		return nil, errors.New("web: site form needs a store")
	case cfg.Targets == nil:
		return nil, errors.New("web: site form needs a target allowlist")
	case cfg.Auditor == nil:
		return nil, errors.New("web: site form needs an auditor")
	case cfg.Review == nil:
		return nil, errors.New("web: site form needs the review flow (F2-014)")
	case cfg.CSRF == nil:
		return nil, errors.New("web: site form needs a CSRF signer")
	}
	return &SiteFormHandler{cfg: cfg}, nil
}

// Register adds the form routes.
func (h *SiteFormHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /sites/new", h.newForm)
	mux.HandleFunc("POST /sites", h.create)
	mux.HandleFunc("GET /sites/{id}/edit", h.editForm)
	mux.HandleFunc("POST /sites/{id}", h.update)
	mux.HandleFunc("POST /sites/{id}/delete", h.delete)
	mux.HandleFunc("POST /sites/targets", h.setTargets)
}

// newForm renders an empty form.
func (h *SiteFormHandler) newForm(w http.ResponseWriter, r *http.Request) {
	s := site.Site{Kind: site.KindRole, Cert: "auto", TargetKind: site.TargetK8s, MagicDNS: true}
	s.Hosts = prefillHosts(r.URL.Query()["host"])
	h.render(r, w, s, true, http.StatusOK, nil)
}

// maxPrefillHosts bounds the hosts a /sites/new?host=... link may prefill.
const maxPrefillHosts = 20

// prefillHosts keeps the valid hostnames of a prefill link (the discovery candidate card, M5).
// It only fills the form: the hosts are validated again on submit and nothing is applied.
func prefillHosts(raw []string) []string {
	var hosts []string
	for _, h := range raw {
		h = strings.ToLower(strings.TrimSpace(h))
		if site.ValidHostname(h) && !slices.Contains(hosts, h) && len(hosts) < maxPrefillHosts {
			hosts = append(hosts, h)
		}
	}
	return hosts
}

// siteNewURL is the site form link that prefills host.
func siteNewURL(host string) templ.SafeURL {
	return templ.SafeURL("/sites/new?" + url.Values{"host": {host}}.Encode())
}

// editForm renders the stored site.
func (h *SiteFormHandler) editForm(w http.ResponseWriter, r *http.Request) {
	id, err := formSiteID(r)
	if err != nil {
		http.Error(w, "geçersiz site", http.StatusBadRequest)
		return
	}
	stored, err := h.cfg.Store.GetSite(r.Context(), id)
	if errors.Is(err, site.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "site okunamadı", http.StatusInternalServerError)
		return
	}
	h.render(r, w, stored, false, http.StatusOK, nil)
}

// create hands a valid role/open site to the review flow as a previewable change (AC1/AC2): the
// form never writes; the change applies only through preview → approval → apply (F2-014).
func (h *SiteFormHandler) create(w http.ResponseWriter, r *http.Request) {
	if _, ok := operatorActor(r); !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	in, err := parseSiteForm(r)
	if err != nil {
		http.Error(w, "geçersiz form", http.StatusBadRequest)
		return
	}
	if in.Kind != site.KindRole && in.Kind != site.KindOpen {
		http.Error(w, "yeni site yalnız rol kontrollü ya da rolsüz olabilir", http.StatusBadRequest)
		return
	}
	h.cfg.Review.previewForm(w, r, change.SiteRequest{Op: change.SiteAdd, Site: in},
		func(w http.ResponseWriter, r *http.Request, err error) {
			h.render(r, w, in, true, statusFor(err), err)
		})
}

// update hands a changed site to the review flow; a system site only carries the fields its
// template opens (AC1/AC2/AC4).
func (h *SiteFormHandler) update(w http.ResponseWriter, r *http.Request) {
	if _, ok := operatorActor(r); !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id, err := formSiteID(r)
	if err != nil {
		http.Error(w, "geçersiz site", http.StatusBadRequest)
		return
	}
	stored, err := h.cfg.Store.GetSite(r.Context(), id)
	if errors.Is(err, site.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "site okunamadı", http.StatusInternalServerError)
		return
	}
	in := stored
	if stored.Kind == site.KindSystem {
		in, err = applySystemForm(stored, r)
	} else {
		in, err = parseSiteForm(r)
		in.ID = id
	}
	if err != nil {
		http.Error(w, "geçersiz form", http.StatusBadRequest)
		return
	}
	h.cfg.Review.previewForm(w, r, change.SiteRequest{Op: change.SiteUpdate, ID: id, Site: in},
		func(w http.ResponseWriter, r *http.Request, err error) {
			h.render(r, w, in, false, statusFor(err), err)
		})
}

// delete hands a site removal to the review flow; a system site is refused by the pipeline's
// store checks and shown on the review page (AC2).
func (h *SiteFormHandler) delete(w http.ResponseWriter, r *http.Request) {
	_, ok := operatorActor(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id, err := formSiteID(r)
	if err != nil {
		http.Error(w, "geçersiz site", http.StatusBadRequest)
		return
	}
	h.cfg.Review.previewForm(w, r, change.SiteRequest{Op: change.SiteDelete, ID: id},
		func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, "site silinemedi: "+siteErrorText(err), statusFor(err))
		})
}

// setTargets replaces the custom target allowlist (F2-013 AC5). The check and write run under the
// writer lock, so a concurrent site write cannot leave a stored target outside the new list.
func (h *SiteFormHandler) setTargets(w http.ResponseWriter, r *http.Request) {
	actor, ok := operatorActor(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	list := splitLines(r.PostFormValue("allowed_targets"))
	if err := h.auditAction(r.Context(), actor, "site.allowed_targets", "sites", "requested", ""); err != nil {
		http.Error(w, "işlem kaydedilemedi", http.StatusInternalServerError)
		return
	}
	err := h.withLock(func() error { return h.cfg.Targets.Set(r.Context(), list) })
	if err != nil {
		h.auditOutcome(r.Context(), actor, "site.allowed_targets", "sites", "failed", err.Error())
		h.render(r, w, site.Site{Kind: site.KindRole, Cert: "auto", TargetKind: site.TargetK8s, MagicDNS: true}, true, statusFor(err), err)
		return
	}
	h.auditOutcome(r.Context(), actor, "site.allowed_targets", "sites", "applied", "")
	http.Redirect(w, r, "/sites", http.StatusSeeOther)
}

// withLock runs fn under the writer lock when one is configured. It serializes site writes and
// the allowlist change, so a site cannot be created against a target that is being removed at the
// same time (F2-013 AC5).
func (h *SiteFormHandler) withLock(fn func() error) error {
	if h.cfg.Lock != nil {
		return h.cfg.Lock(fn)
	}
	return fn()
}

// render builds the view (stored or submitted site) and writes the form.
func (h *SiteFormHandler) render(r *http.Request, w http.ResponseWriter, in site.Site, isNew bool, status int, formErr error) {
	actor, _ := ActorFrom(r.Context())
	knownRoles := h.knownRoles(r.Context())
	targets, err := h.cfg.Targets.ListTargets(r.Context())
	if err != nil {
		targets = nil
	}
	msg := ""
	if formErr != nil {
		msg = formErrorText(formErr)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = Layout(actor, h.cfg.CSRF.Token(), "siteler", "Site",
		SiteFormPage(newSiteFormView(in, isNew, knownRoles, targets, msg), h.cfg.CSRF.Token())).Render(r.Context(), w)
}

// knownRoles reads the vpn project roles for the form hint; a failed read leaves the hint empty,
// and the store's validator still refuses an unknown role on write (fail closed).
func (h *SiteFormHandler) knownRoles(ctx context.Context) []string {
	if h.cfg.Roles == nil {
		return nil
	}
	roles, err := h.cfg.Roles.ListRoles(ctx)
	if err != nil {
		return nil
	}
	return roles
}

// auditAction writes one operator action and returns the write error. Every mutating handler writes
// a "requested" entry before it changes anything: if that entry cannot be written the action is
// refused with 500 and nothing is mutated, so a site write or an allowlist change is never applied
// unaudited (security.md §9).
func (h *SiteFormHandler) auditAction(ctx context.Context, actor, event, target, result, reason string) error {
	var diff audit.Diff
	if reason != "" {
		diff = audit.Diff{{Field: "error", After: reason}}
	}
	_, err := h.cfg.Auditor.Write(ctx, audit.Entry{
		Actor:  actor,
		Event:  event,
		Target: target,
		Diff:   diff,
		Result: result,
	})
	return err
}

// auditOutcome writes the post-mutation result. The "requested" entry written before the mutation
// already records the action, so unlike that critical write a failed outcome write cannot leave a
// change unaudited; it is reported to the server log and the action stays recorded.
func (h *SiteFormHandler) auditOutcome(ctx context.Context, actor, event, target, result, reason string) {
	if err := h.auditAction(ctx, actor, event, target, result, reason); err != nil {
		slog.Default().Warn("site form: audit outcome write failed", "event", event, "target", target, "err", err)
	}
}

// SiteFormView is the data the form renders. Textareas carry one value per line; the repeatable
// groups are parallel arrays.
type SiteFormView struct {
	ID                int64
	IsNew             bool
	Kind              string
	SystemTemplate    string
	Hosts             string
	OpenReason        string
	Roles             string
	TargetRoles       string
	Cert              string
	TargetKind        string
	TargetURL         string
	TargetTLSInsecure bool
	MagicDNS          bool
	Maintenance       bool
	Note              string
	Owner             string
	APIRules          []site.APIRule
	Redirects         []site.Redirect
	Headers           []site.Header
	SystemEnabled     bool
	SystemHeadplane   bool
	InternalSources   string
	LoginPaths        string
	KnownRoles        []string
	AllowedTargets    []string
	Error             string
}

// IsSystem reports whether the form is editing a locked system site.
func (v SiteFormView) IsSystem() bool { return v.Kind == site.KindSystem }

// IsOpen reports whether the form is editing a role-less site.
func (v SiteFormView) IsOpen() bool { return v.Kind == site.KindOpen }

// newSiteFormView builds the render view from a site (stored or submitted).
func newSiteFormView(s site.Site, isNew bool, knownRoles, targets []string, errMsg string) SiteFormView {
	v := SiteFormView{
		ID:                s.ID,
		IsNew:             isNew,
		Kind:              s.Kind,
		SystemTemplate:    s.SystemTemplate,
		Hosts:             strings.Join(s.Hosts, "\n"),
		OpenReason:        s.OpenReason,
		Roles:             strings.Join(s.Roles, "\n"),
		TargetRoles:       strings.Join(s.TargetRoles, "\n"),
		Cert:              s.Cert,
		TargetKind:        s.TargetKind,
		TargetURL:         s.TargetURL,
		TargetTLSInsecure: s.TargetTLSInsecure,
		MagicDNS:          s.MagicDNS,
		Maintenance:       s.Maintenance,
		Note:              s.Note,
		Owner:             s.Owner,
		APIRules:          appendBlankAPIRule(s.APIRules),
		Redirects:         appendBlankRedirect(s.Redirects),
		Headers:           appendBlankHeader(s.Headers),
		KnownRoles:        knownRoles,
		AllowedTargets:    targets,
		Error:             errMsg,
		SystemEnabled:     true,
		SystemHeadplane:   true,
	}
	if s.Kind == site.KindSystem {
		if cfg, err := site.ParseSystemConfig(s.SystemTemplate, s.SystemConfig); err == nil {
			v.SystemEnabled = cfg.Enabled
			v.SystemHeadplane = cfg.Headplane
			v.InternalSources = strings.Join(cfg.InternalSources, "\n")
			v.LoginPaths = strings.Join(cfg.LoginPaths, "\n")
		}
	}
	return v
}

// appendBlankAPIRule / appendBlankRedirect / appendBlankHeader add one empty row after the stored
// rows, so the template can always index the arrays and the operator has a row to fill in.
func appendBlankAPIRule(in []site.APIRule) []site.APIRule {
	out := append(append([]site.APIRule{}, in...), site.APIRule{Type: site.APIRuleHeaderPresent})
	return out
}

func appendBlankRedirect(in []site.Redirect) []site.Redirect {
	return append(append([]site.Redirect{}, in...), site.Redirect{Code: 308})
}

func appendBlankHeader(in []site.Header) []site.Header {
	return append(append([]site.Header{}, in...), site.Header{})
}

// formSiteID parses the {id} path value; a missing or non-positive id is refused.
func formSiteID(r *http.Request) (int64, error) {
	id, err := strconv.ParseInt(strings.TrimSpace(r.PathValue("id")), 10, 64)
	if err != nil || id <= 0 {
		return 0, errors.New("web: invalid site id")
	}
	return id, nil
}

// statusFor maps a store error to an HTTP status: a locked system site is a conflict, anything
// else is a bad request.
func statusFor(err error) int {
	if errors.Is(err, site.ErrSystemLocked) {
		return http.StatusConflict
	}
	return http.StatusBadRequest
}

// siteErrorText is a short operator-facing message.
func siteErrorText(err error) string {
	if errors.Is(err, site.ErrSystemLocked) {
		return "sistem sitesi kilitli"
	}
	if errors.Is(err, site.ErrTargetInUse) {
		return "hedef hâlâ bir site tarafından kullanılıyor"
	}
	if errors.Is(err, site.ErrHostTaken) {
		return "host başka bir sitede kullanılıyor"
	}
	return "kayıt reddedildi"
}

// formErrorText maps a write error to the message shown on the form.
func formErrorText(err error) string {
	if errors.Is(err, site.ErrSystemLocked) {
		return "Sistem sitesi kilitli: " + err.Error()
	}
	if errors.Is(err, site.ErrTargetInUse) {
		return "Hedef hâlâ bir site tarafından kullanılıyor; önce o siteyi değiştirin. " + err.Error()
	}
	if errors.Is(err, site.ErrHostTaken) {
		return "Host başka bir sitede kullanılıyor. " + err.Error()
	}
	return err.Error()
}

// parseSiteForm reads a role/open site from the form.
func parseSiteForm(r *http.Request) (site.Site, error) {
	if err := r.ParseForm(); err != nil {
		return site.Site{}, err
	}
	rules, err := parseAPIRules(r)
	if err != nil {
		return site.Site{}, err
	}
	redirects, err := parseRedirects(r)
	if err != nil {
		return site.Site{}, err
	}
	headers, err := parseHeaders(r)
	if err != nil {
		return site.Site{}, err
	}
	kind := strings.TrimSpace(r.PostFormValue("kind"))
	// The open reason belongs only to open sites; the form always carries the select (its default
	// is intentional), so it is read only when the kind is open.
	openReason := ""
	if kind == site.KindOpen {
		openReason = strings.TrimSpace(r.PostFormValue("open_reason"))
	}
	return site.Site{
		Hosts:             splitLines(r.PostFormValue("hosts")),
		Kind:              kind,
		OpenReason:        openReason,
		Roles:             splitLines(r.PostFormValue("roles")),
		TargetRoles:       splitLines(r.PostFormValue("target_roles")),
		Cert:              strings.TrimSpace(r.PostFormValue("cert")),
		TargetKind:        strings.TrimSpace(r.PostFormValue("target_kind")),
		TargetURL:         strings.TrimSpace(r.PostFormValue("target_url")),
		TargetTLSInsecure: r.PostFormValue("target_tls_insecure") == "1",
		MagicDNS:          r.PostFormValue("magicdns") == "1",
		Maintenance:       r.PostFormValue("maintenance") == "1",
		Note:              r.PostFormValue("note"),
		Owner:             r.PostFormValue("owner"),
		APIRules:          rules,
		Redirects:         redirects,
		Headers:           headers,
	}, nil
}

// applySystemForm keeps the stored system record and changes only the fields its template opens
// (note/owner everywhere; one switch or the zitadel lists). The store re-checks the lock.
func applySystemForm(stored site.Site, r *http.Request) (site.Site, error) {
	if err := r.ParseForm(); err != nil {
		return site.Site{}, err
	}
	out := stored
	out.Note = r.PostFormValue("note")
	out.Owner = r.PostFormValue("owner")
	switch stored.SystemTemplate {
	case site.TemplateWireGuardUI:
		out.SystemConfig = fmt.Sprintf(`{"enabled":%t}`, r.PostFormValue("system_enabled") == "1")
	case site.TemplateHeadscale:
		out.SystemConfig = fmt.Sprintf(`{"headplane":%t}`, r.PostFormValue("system_headplane") == "1")
	case site.TemplateZitadel:
		body, err := json.Marshal(struct {
			InternalSources []string `json:"internal_sources"`
			LoginPaths      []string `json:"login_paths"`
		}{splitLines(r.PostFormValue("internal_sources")), splitLines(r.PostFormValue("login_paths"))})
		if err != nil {
			return site.Site{}, err
		}
		out.SystemConfig = string(body)
	case site.TemplateTagcess:
		// Only note/owner change.
	default:
		return site.Site{}, fmt.Errorf("web: unknown system template %q", stored.SystemTemplate)
	}
	return out, nil
}

// parseAPIRules reads the parallel api rule rows; the arrays must line up.
func parseAPIRules(r *http.Request) ([]site.APIRule, error) {
	types, values := r.PostForm["api_rule_type"], r.PostForm["api_rule_value"]
	n, err := rowCount(types, values)
	if err != nil {
		return nil, err
	}
	out := make([]site.APIRule, 0, n)
	for i := range n {
		t, v := strings.TrimSpace(types[i]), strings.TrimSpace(values[i])
		// The type is a select, so an untouched row still carries its default type: only the
		// free-text value tells whether the row was filled in.
		if v == "" {
			continue
		}
		out = append(out, site.APIRule{Type: t, Value: v})
	}
	return out, nil
}

// parseRedirects reads the parallel redirect rows.
func parseRedirects(r *http.Request) ([]site.Redirect, error) {
	sources, targets, codes := r.PostForm["redirect_source"], r.PostForm["redirect_target"], r.PostForm["redirect_code"]
	n, err := rowCount(sources, targets, codes)
	if err != nil {
		return nil, err
	}
	out := make([]site.Redirect, 0, n)
	for i := range n {
		src, tgt, code := strings.TrimSpace(sources[i]), strings.TrimSpace(targets[i]), strings.TrimSpace(codes[i])
		// The code is a select with a default; an untouched row has no source and no target.
		if src == "" && tgt == "" {
			continue
		}
		c, err := strconv.Atoi(code)
		if err != nil {
			return nil, fmt.Errorf("web: redirect code %q is not a number", code)
		}
		out = append(out, site.Redirect{Source: src, Target: tgt, Code: c})
	}
	return out, nil
}

// parseHeaders reads the parallel extra header rows.
func parseHeaders(r *http.Request) ([]site.Header, error) {
	names, values := r.PostForm["header_name"], r.PostForm["header_value"]
	n, err := rowCount(names, values)
	if err != nil {
		return nil, err
	}
	out := make([]site.Header, 0, n)
	for i := range n {
		name, value := strings.TrimSpace(names[i]), strings.TrimSpace(values[i])
		if name == "" && value == "" {
			continue
		}
		out = append(out, site.Header{Name: name, Value: value})
	}
	return out, nil
}

// rowCount checks that the parallel arrays of a repeated form group have the same length and
// returns it; misaligned rows mean a tampered form and are refused.
func rowCount(arrays ...[]string) (int, error) {
	n := -1
	for _, a := range arrays {
		if n == -1 {
			n = len(a)
			continue
		}
		if len(a) != n {
			return 0, errors.New("web: form rows do not line up")
		}
	}
	if n < 0 {
		n = 0
	}
	return n, nil
}

// splitLines turns a textarea into a trimmed, non-empty line list.
func splitLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}

// siteFormTitle is the form's page title: "Yeni site", or the first host of the edited site.
func siteFormTitle(f SiteFormView) string {
	if f.IsNew {
		return "Yeni site"
	}
	if host, _, _ := strings.Cut(f.Hosts, "\n"); strings.TrimSpace(host) != "" {
		return strings.TrimSpace(host)
	}
	return "Site düzenle"
}

// siteFormSub says what saving does for the kind of form shown.
func siteFormSub(f SiteFormView) string {
	switch {
	case f.IsNew:
		return "Yeni bir iç site tanımlayın; kayıt önce preview edilir."
	case f.IsSystem():
		return "Sistem sitesi; şablondan üretilir."
	default:
		return "Site düzenle; kayıt önce preview edilir."
	}
}

// siteRolesHelp is the roles field help. The known vpn project roles are offered in the field
// itself; when they cannot be listed the person types the role name, and the store's validator
// still refuses an unknown role on write.
func siteRolesHelp(f SiteFormView) string {
	if len(f.KnownRoles) == 0 {
		return "Zitadel rolleri şu an listelenemiyor; rol adını yazıp Enter'a basın."
	}
	return "Listeden seçin ya da rol adını yazıp Enter'a basın."
}

// redirectCodeOptions are the HTTP redirect codes a site redirect may use.
func redirectCodeOptions() []ui.Opt {
	codes := []int{301, 302, 307, 308}
	out := make([]ui.Opt, 0, len(codes))
	for _, c := range codes {
		out = append(out, ui.Opt{Value: strconv.Itoa(c), Label: strconv.Itoa(c)})
	}
	return out
}
