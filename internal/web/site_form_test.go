package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/site"
	"github.com/nesiler/tagcess/internal/store/db"
)

// fakeSiteStore is an in-memory SiteStore recording every write.
type fakeSiteStore struct {
	sites     map[int64]site.Site
	created   []site.Site
	updated   []site.Site
	deleted   []int64
	createErr error
	updateErr error
	deleteErr error
}

func (f *fakeSiteStore) GetSite(_ context.Context, id int64) (site.Site, error) {
	s, ok := f.sites[id]
	if !ok {
		return site.Site{}, site.ErrNotFound
	}
	return s, nil
}

func (f *fakeSiteStore) CreateSite(_ context.Context, in site.Site) (site.Site, error) {
	if f.createErr != nil {
		return site.Site{}, f.createErr
	}
	in.ID = int64(len(f.created) + 1)
	f.created = append(f.created, in)
	if f.sites == nil {
		f.sites = map[int64]site.Site{}
	}
	f.sites[in.ID] = in
	return in, nil
}

func (f *fakeSiteStore) UpdateSite(_ context.Context, id int64, in site.Site) (site.Site, error) {
	if f.updateErr != nil {
		return site.Site{}, f.updateErr
	}
	in.ID = id
	f.updated = append(f.updated, in)
	if f.sites == nil {
		f.sites = map[int64]site.Site{}
	}
	f.sites[id] = in
	return in, nil
}

func (f *fakeSiteStore) DeleteSite(_ context.Context, id int64) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	f.deleted = append(f.deleted, id)
	delete(f.sites, id)
	return nil
}

// fakeTargetAllowlist records Set calls and can simulate a refusal.
type fakeTargetAllowlist struct {
	list     []string
	setErr   error
	setCalls [][]string
}

func (f *fakeTargetAllowlist) ListTargets(context.Context) ([]string, error) { return f.list, nil }
func (f *fakeTargetAllowlist) Set(_ context.Context, list []string) error {
	f.setCalls = append(f.setCalls, list)
	if f.setErr != nil {
		return f.setErr
	}
	f.list = list
	return nil
}

// fakeRoleLister returns a fixed role list.
type fakeRoleLister struct{ roles []string }

func (f fakeRoleLister) ListRoles(context.Context) ([]string, error) { return f.roles, nil }

// fakeSiteAuditor captures audit entries and can simulate a failing log.
type fakeSiteAuditor struct {
	events   []audit.Entry
	writeErr error
}

func (f *fakeSiteAuditor) Write(_ context.Context, e audit.Entry) (audit.Event, error) {
	if f.writeErr != nil {
		return audit.Event{}, f.writeErr
	}
	f.events = append(f.events, e)
	return audit.Event{}, nil
}

// event returns the newest audit entry with the given event name. A mutation writes the action as
// "requested" before it runs and the outcome afterwards, so the newest entry carries the result.
func (f *fakeSiteAuditor) event(name string) (audit.Entry, bool) {
	for i := len(f.events) - 1; i >= 0; i-- {
		if f.events[i].Event == name {
			return f.events[i], true
		}
	}
	return audit.Entry{}, false
}

// hasEvent reports whether any entry of the given event name carries the result substring.
func (f *fakeSiteAuditor) hasEvent(name, result string) bool {
	for _, e := range f.events {
		if e.Event == name && strings.Contains(e.Result, result) {
			return true
		}
	}
	return false
}

// siteFormHarness wires the form behind the production identity + CSRF chain with fakes. The
// form never writes since F2-014: create/update/delete hand the parsed change to the review flow
// (a fake reviewer here), so the assertions check the request the pipeline receives.
type siteFormHarness struct {
	store     *fakeSiteStore
	targets   *fakeTargetAllowlist
	auditor   *fakeSiteAuditor
	reviewer  *fakeSiteReviewer
	csrf      *CSRF
	chain     http.Handler
	lockCalls int
}

func newSiteFormHarness(t *testing.T) *siteFormHarness {
	t.Helper()
	h := &siteFormHarness{
		store:    &fakeSiteStore{sites: map[int64]site.Site{}},
		targets:  &fakeTargetAllowlist{list: []string{"100.64.0.5"}},
		auditor:  &fakeSiteAuditor{},
		reviewer: &fakeSiteReviewer{},
		csrf:     testCSRF(t),
	}
	h.reviewer.previewPlans = []change.SitePlan{{Op: change.SiteAdd}}
	review, err := NewSiteReviewHandler(SiteReviewConfig{
		Reviewer: h.reviewer,
		Lister:   fakeReviewLister{},
		URIs:     &fakeSiteDriftReader{},
		Settings: fakeReviewSettings{},
		Changes:  &fakeChangeReader{rows: map[int64]db.Change{}},
		Auditor:  h.auditor,
		CSRF:     h.csrf,
	})
	if err != nil {
		t.Fatalf("NewSiteReviewHandler: %v", err)
	}
	handler, err := NewSiteFormHandler(SiteFormConfig{
		Store:   h.store,
		Targets: h.targets,
		Auditor: h.auditor,
		Roles:   fakeRoleLister{roles: []string{"devops", "developer"}},
		Lock:    func(fn func() error) error { h.lockCalls++; return fn() },
		Review:  review,
		CSRF:    h.csrf,
	})
	if err != nil {
		t.Fatalf("NewSiteFormHandler: %v", err)
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	review.Register(mux)
	h.chain = RequireDevops(h.csrf.Protect(mux))
	return h
}

func (h *siteFormHarness) get(t *testing.T, target string) *httptest.ResponseRecorder {
	t.Helper()
	return h.do(t, http.MethodGet, target, nil)
}

func (h *siteFormHarness) post(t *testing.T, target string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	if form == nil {
		form = url.Values{}
	}
	form.Set(CSRFParam, h.csrf.Token())
	return h.do(t, http.MethodPost, target, form)
}

func (h *siteFormHarness) do(t *testing.T, method, target string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	req := httptest.NewRequestWithContext(context.Background(), method, target, body)
	req.Header.Set(headerUser, "devops-user")
	req.Header.Set(headerEmail, "devops@example.com")
	req.Header.Set(headerGroups, "devops")
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	rec := httptest.NewRecorder()
	h.chain.ServeHTTP(rec, req)
	return rec
}

func validSiteForm() url.Values {
	return url.Values{
		"hosts": {"git.example.com"},
		"kind":  {"role"},
		// A browser submits the open-reason select even for a role site; the handler must ignore it.
		"open_reason":     {"intentional"},
		"roles":           {"developer\ndevops"},
		"cert":            {"le:example.com"},
		"target_kind":     {"k8s"},
		"magicdns":        {"1"},
		"note":            {"git"},
		"api_rule_type":   {"header_present", "path_regex"},
		"api_rule_value":  {"Authorization", "^/api/x$"},
		"redirect_source": {"/setup"},
		"redirect_target": {"/admin"},
		"redirect_code":   {"308"},
		"header_name":     {"X-Note"},
		"header_value":    {"v"},
	}
}

// AC1: a valid form becomes a previewable change of the site pipeline (F2-014); the form itself
// writes nothing. Edit and delete reach the pipeline the same way.
func TestSiteForm_CRUD(t *testing.T) {
	h := newSiteFormHarness(t)
	h.store.sites[1] = roleSiteStored()

	if rec := h.get(t, "/sites/new"); rec.Code != http.StatusOK {
		t.Fatalf("GET /sites/new = %d, want 200", rec.Code)
	}
	rec := h.post(t, "/sites", validSiteForm())
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /sites = %d, want 200 (review screen, body %q)", rec.Code, rec.Body.String())
	}
	if len(h.reviewer.previewCalls) != 1 {
		t.Fatalf("preview calls = %d, want 1", len(h.reviewer.previewCalls))
	}
	if len(h.store.created) != 0 {
		t.Error("the form wrote the site directly; it must go through review and approval")
	}
	req := h.reviewer.previewCalls[0]
	if req.Op != change.SiteAdd {
		t.Errorf("op = %q, want add", req.Op)
	}
	got := req.Site
	if got.Hosts[0] != "git.example.com" || len(got.Roles) != 2 || got.Note != "git" {
		t.Errorf("submitted site = %+v", got)
	}
	if len(got.APIRules) != 2 || got.APIRules[1].Type != site.APIRulePathRegex {
		t.Errorf("api rules = %+v", got.APIRules)
	}
	if len(got.Redirects) != 1 || got.Redirects[0].Code != 308 {
		t.Errorf("redirects = %+v", got.Redirects)
	}
	if len(got.Headers) != 1 || got.Headers[0].Name != "X-Note" {
		t.Errorf("headers = %+v", got.Headers)
	}
	if !h.auditor.hasEvent("site.preview", "requested") {
		t.Error("site.preview was not audited")
	}
	if !strings.Contains(rec.Body.String(), `action="/sites/review/approve"`) {
		t.Error("the review screen does not offer the approval")
	}

	if rec := h.get(t, "/sites/1/edit"); rec.Code != http.StatusOK {
		t.Fatalf("GET edit = %d, want 200", rec.Code)
	}
	upd := validSiteForm()
	upd.Set("note", "changed")
	if rec := h.post(t, "/sites/1", upd); rec.Code != http.StatusOK {
		t.Fatalf("POST update = %d, want 200 (review screen)", rec.Code)
	}
	if len(h.reviewer.previewCalls) != 2 {
		t.Fatalf("preview calls = %d, want 2", len(h.reviewer.previewCalls))
	}
	req = h.reviewer.previewCalls[1]
	if req.Op != change.SiteUpdate || req.ID != 1 || req.Site.Note != "changed" {
		t.Errorf("update request = %+v", req)
	}
	if !h.auditor.hasEvent("site.preview", "requested") {
		t.Error("the update preview was not audited")
	}

	if rec := h.post(t, "/sites/1/delete", nil); rec.Code != http.StatusOK {
		t.Fatalf("POST delete = %d, want 200 (review screen)", rec.Code)
	}
	if len(h.reviewer.previewCalls) != 3 {
		t.Fatalf("preview calls = %d, want 3", len(h.reviewer.previewCalls))
	}
	req = h.reviewer.previewCalls[2]
	if req.Op != change.SiteDelete || req.ID != 1 {
		t.Errorf("delete request = %+v", req)
	}
	if !h.auditor.hasEvent("site.preview", "requested") {
		t.Error("the delete preview was not audited")
	}
}

// AC2: a missing CSRF token, a missing role, an invalid record or a locked system site is refused
// and the outcome is audited; nothing is applied. Since F2-014 the refusal comes from the review
// flow's preview (the pipeline re-runs the store rules); here the fake reviewer carries them.
func TestSiteForm_RejectsUnsafe(t *testing.T) {
	h := newSiteFormHarness(t)

	// No CSRF token: the middleware refuses before the handler runs.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/sites",
		strings.NewReader(validSiteForm().Encode()))
	req.Header.Set(headerUser, "devops-user")
	req.Header.Set(headerGroups, "devops")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.chain.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("POST without CSRF = %d, want 403", rec.Code)
	}
	if len(h.reviewer.previewCalls) != 0 {
		t.Error("a CSRF-less request reached the review flow")
	}

	// No devops group: the identity middleware refuses.
	noRole := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/sites/new", nil)
	noRole.Header.Set(headerUser, "someone")
	noRoleRec := httptest.NewRecorder()
	h.chain.ServeHTTP(noRoleRec, noRole)
	if noRoleRec.Code != http.StatusForbidden {
		t.Errorf("GET without devops = %d, want 403", noRoleRec.Code)
	}

	// An invalid record: the pipeline preview refuses, the form is shown again with the error and
	// the failure is audited; nothing is applied.
	h.reviewer.previewErrs = []error{errors.New("site validation: hosts[0]: invalid")}
	rec = h.post(t, "/sites", validSiteForm())
	if rec.Code != http.StatusBadRequest {
		t.Errorf("invalid create = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "site validation") {
		t.Errorf("the form does not show the error: %q", rec.Body.String())
	}
	if !h.auditor.hasEvent("site.preview", "failed") {
		t.Error("failed preview not audited")
	}
	if len(h.reviewer.submitCalls) != 0 {
		t.Error("an invalid record was submitted")
	}

	// A locked system site: the pipeline refuses with ErrSystemLocked; the form is shown again.
	h.reviewer.previewErrs = append(h.reviewer.previewErrs, fmt.Errorf("site: system site is locked: %w", site.ErrSystemLocked))
	sys := site.Site{
		ID: 9, Hosts: []string{"auth.example.com"}, Kind: site.KindSystem,
		SystemTemplate: site.TemplateTagcess, SystemConfig: `{}`, Cert: "auto", TargetKind: site.TargetK8s,
		Roles: []string{}, TargetRoles: []string{}, APIRules: []site.APIRule{}, Redirects: []site.Redirect{}, Headers: []site.Header{},
	}
	h.store.sites[9] = sys
	rec = h.post(t, "/sites/9", validSiteForm())
	if rec.Code != http.StatusBadRequest && rec.Code != http.StatusConflict {
		t.Errorf("locked update = %d, want 400/409", rec.Code)
	}
	if !h.auditor.hasEvent("site.preview", "failed") {
		t.Error("failed update preview not audited")
	}
}

// AC3: the form makes the API exemption's scope and the empty-header behaviour visible, and marks
// the header/url-target restriction.
func TestSiteForm_APIWarning(t *testing.T) {
	h := newSiteFormHarness(t)
	body := h.get(t, "/sites/new").Body.String()
	for _, want := range []string{
		"API bypass'ı",
		"boş",
		"rol kontrolünü atlar",
		"url",
		"header",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the form does not contain %q", want)
		}
	}
}

// AC4: a system site form shows only the fields its template opens, and none for tagcess.
func TestSiteForm_SystemAllowedFields(t *testing.T) {
	h := newSiteFormHarness(t)
	mk := func(id int64, tmpl, config string) {
		h.store.sites[id] = site.Site{
			ID: id, Hosts: []string{"h.example.com"}, Kind: site.KindSystem,
			SystemTemplate: tmpl, SystemConfig: config, Cert: "auto", TargetKind: site.TargetK8s,
			Roles: []string{}, TargetRoles: []string{}, APIRules: []site.APIRule{}, Redirects: []site.Redirect{}, Headers: []site.Header{},
		}
	}
	mk(1, site.TemplateZitadel, `{"internal_sources":["10.1.0.0/16"],"login_paths":["/ui/login"]}`)
	mk(2, site.TemplateHeadscale, `{"headplane":true}`)
	mk(3, site.TemplateWireGuardUI, `{"enabled":true}`)
	mk(4, site.TemplateTagcess, `{}`)

	zitadel := h.get(t, "/sites/1/edit").Body.String()
	for _, want := range []string{`name="internal_sources"`, `name="login_paths"`, "10.1.0.0/16", "/ui/login"} {
		if !strings.Contains(zitadel, want) {
			t.Errorf("zitadel form lacks %q", want)
		}
	}
	for _, bad := range []string{`name="system_enabled"`, `name="system_headplane"`, `name="roles"`, `name="api_rule_type"`} {
		if strings.Contains(zitadel, bad) {
			t.Errorf("zitadel form shows the unrelated field %q", bad)
		}
	}

	headscale := h.get(t, "/sites/2/edit").Body.String()
	if !strings.Contains(headscale, `name="system_headplane"`) || strings.Contains(headscale, `name="internal_sources"`) || strings.Contains(headscale, `name="system_enabled"`) {
		t.Errorf("headscale form fields are wrong")
	}

	wireguard := h.get(t, "/sites/3/edit").Body.String()
	if !strings.Contains(wireguard, `name="system_enabled"`) || strings.Contains(wireguard, `name="internal_sources"`) || strings.Contains(wireguard, `name="system_headplane"`) {
		t.Errorf("wireguard_ui form fields are wrong")
	}

	tagcess := h.get(t, "/sites/4/edit").Body.String()
	for _, bad := range []string{`name="system_enabled"`, `name="system_headplane"`, `name="internal_sources"`, `name="login_paths"`, `name="roles"`} {
		if strings.Contains(tagcess, bad) {
			t.Errorf("tagcess form shows an editable field %q", bad)
		}
	}
	if !strings.Contains(tagcess, "düzenlenecek alan yok") {
		t.Error("tagcess form does not say it has no editable template fields")
	}

	// The zitadel lists submitted from the form land on the request the review flow carries, and
	// note/owner change with them; nothing else moves (F2-014: the form never writes).
	rec := h.post(t, "/sites/1", url.Values{
		"internal_sources": {"10.8.0.0/24\n127.0.0.1/32"},
		"login_paths":      {"/ui/login\n/.well-known/*"},
		"note":             {"zitadel notu"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST system zitadel = %d, want 200 (review screen, body %q)", rec.Code, rec.Body.String())
	}
	if len(h.reviewer.previewCalls) != 1 {
		t.Fatalf("preview calls = %d, want 1", len(h.reviewer.previewCalls))
	}
	req := h.reviewer.previewCalls[0]
	if req.Op != change.SiteUpdate || req.ID != 1 {
		t.Fatalf("request = %+v", req)
	}
	upd := req.Site
	settings, err := site.ParseSystemConfig(site.TemplateZitadel, upd.SystemConfig)
	if err != nil {
		t.Fatalf("stored system_config invalid: %v (%q)", err, upd.SystemConfig)
	}
	if len(settings.InternalSources) != 2 || settings.InternalSources[0] != "10.8.0.0/24" {
		t.Errorf("internal sources = %v", settings.InternalSources)
	}
	if len(settings.LoginPaths) != 2 || settings.LoginPaths[1] != "/.well-known/*" {
		t.Errorf("login paths = %v", settings.LoginPaths)
	}
	if upd.Note != "zitadel notu" {
		t.Errorf("note = %q", upd.Note)
	}
}

// AC5: the target allowlist is shown and editable; a refusal is surfaced and audited.
func TestSiteForm_TargetAllowlistUI(t *testing.T) {
	h := newSiteFormHarness(t)
	body := h.get(t, "/sites/new").Body.String()
	if !strings.Contains(body, `name="allowed_targets"`) || !strings.Contains(body, "100.64.0.5") {
		t.Error("the form does not show the current target allowlist")
	}

	rec := h.post(t, "/sites/targets", url.Values{"allowed_targets": {"100.64.0.5\n10.0.0.7"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST targets = %d, want 303", rec.Code)
	}
	if len(h.targets.setCalls) != 1 || len(h.targets.setCalls[0]) != 2 || h.targets.setCalls[0][1] != "10.0.0.7" {
		t.Errorf("set calls = %v", h.targets.setCalls)
	}
	if entry, ok := h.auditor.event("site.allowed_targets"); !ok || !strings.Contains(entry.Result, "applied") {
		t.Errorf("successful allowlist change not audited: %+v (present %v)", entry, ok)
	}

	h.targets.setErr = site.ErrTargetInUse
	rec = h.post(t, "/sites/targets", url.Values{"allowed_targets": {"10.0.0.7"}})
	if rec.Code != http.StatusBadRequest && rec.Code != http.StatusConflict {
		t.Errorf("rejected targets = %d, want 400/409", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "kullan") {
		t.Errorf("the form does not explain the refusal: %q", rec.Body.String())
	}
	last := h.auditor.events[len(h.auditor.events)-1]
	if !strings.Contains(last.Result, "failed") {
		t.Errorf("failed allowlist change not audited: %+v", last)
	}
}

// A mutation is never applied without an audit record: when the append-only log cannot be written
// the handler refuses with 500 before it touches the store or the allowlist (security.md §9).
func TestSiteForm_AuditFailureBlocksMutation(t *testing.T) {
	h := newSiteFormHarness(t)
	h.store.sites[7] = site.Site{
		ID: 7, Hosts: []string{"git.example.com"}, Kind: site.KindRole, Cert: "auto",
		TargetKind: site.TargetK8s, Roles: []string{"developer"}, TargetRoles: []string{},
		APIRules: []site.APIRule{}, Redirects: []site.Redirect{}, Headers: []site.Header{},
	}
	h.auditor.writeErr = errors.New("audit log unavailable")

	rec := h.post(t, "/sites", validSiteForm())
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("create without an audit record = %d, want 500", rec.Code)
	}
	if len(h.store.created) != 0 {
		t.Error("a site was created without an audit record")
	}

	rec = h.post(t, "/sites/7", validSiteForm())
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("update without an audit record = %d, want 500", rec.Code)
	}
	if len(h.store.updated) != 0 {
		t.Error("a site was updated without an audit record")
	}

	rec = h.post(t, "/sites/7/delete", nil)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("delete without an audit record = %d, want 500", rec.Code)
	}
	if len(h.store.deleted) != 0 {
		t.Error("a site was deleted without an audit record")
	}

	rec = h.post(t, "/sites/targets", url.Values{"allowed_targets": {"10.0.0.7"}})
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("allowlist change without an audit record = %d, want 500", rec.Code)
	}
	if len(h.targets.setCalls) != 0 {
		t.Error("the allowlist changed without an audit record")
	}

	if h.lockCalls != 0 {
		t.Errorf("an unaudited write reached the store under the writer lock: lockCalls = %d", h.lockCalls)
	}
}

// The list and form routes share the /sites namespace; registering them both must not panic
// (Go's ServeMux rejects ambiguous patterns).
func TestSitesRoutes_NoConflict(t *testing.T) {
	mux := http.NewServeMux()
	lister, err := NewSitesHandler(SitesHandlerConfig{Lister: fakeSiteLister{}, CSRF: testCSRF(t)})
	if err != nil {
		t.Fatalf("NewSitesHandler: %v", err)
	}
	lister.Register(mux)
	review, err := NewSiteReviewHandler(SiteReviewConfig{
		Reviewer: &fakeSiteReviewer{previewPlans: []change.SitePlan{{}}},
		Lister:   fakeReviewLister{},
		URIs:     &fakeSiteDriftReader{},
		Settings: fakeReviewSettings{},
		Changes:  &fakeChangeReader{rows: map[int64]db.Change{}},
		Auditor:  &fakeSiteAuditor{},
		CSRF:     testCSRF(t),
	})
	if err != nil {
		t.Fatalf("NewSiteReviewHandler: %v", err)
	}
	form, err := NewSiteFormHandler(SiteFormConfig{
		Store:   &fakeSiteStore{sites: map[int64]site.Site{}},
		Targets: &fakeTargetAllowlist{list: []string{"100.64.0.5"}},
		Auditor: &fakeSiteAuditor{},
		Review:  review,
		CSRF:    testCSRF(t),
	})
	if err != nil {
		t.Fatalf("NewSiteFormHandler: %v", err)
	}
	form.Register(mux) // panics if the patterns conflict
}

// I1: a browser always submits the select defaults of an untouched row; a row whose free-text
// fields are all empty is ignored, a half-filled row is kept so that validation can reject it.
func TestSiteForm_IgnoresUntouchedRows(t *testing.T) {
	h := newSiteFormHarness(t)
	form := validSiteForm()
	form.Set("api_rule_type", "header_present")
	form.Set("api_rule_value", "")
	form.Set("redirect_source", "")
	form.Set("redirect_target", "")
	form.Set("redirect_code", "301")
	form.Set("header_name", "")
	form.Set("header_value", "")
	if rec := h.post(t, "/sites", form); rec.Code != http.StatusOK {
		t.Fatalf("POST /sites = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	if len(h.reviewer.previewCalls) != 1 {
		t.Fatalf("preview calls = %d, want 1", len(h.reviewer.previewCalls))
	}
	got := h.reviewer.previewCalls[0].Site
	if len(got.APIRules) != 0 || len(got.Redirects) != 0 || len(got.Headers) != 0 {
		t.Errorf("untouched rows were kept: %+v %+v %+v", got.APIRules, got.Redirects, got.Headers)
	}
}

func TestParseRows_HalfFilledRowIsKept(t *testing.T) {
	post := func(v url.Values) *http.Request {
		r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/sites", nil)
		r.PostForm = v
		return r
	}
	red, err := parseRedirects(post(url.Values{"redirect_source": {"/a"}, "redirect_target": {""}, "redirect_code": {"301"}}))
	if err != nil || len(red) != 1 || red[0].Source != "/a" {
		t.Errorf("half-filled redirect = %+v, %v; want the row kept", red, err)
	}
	red, err = parseRedirects(post(url.Values{"redirect_source": {""}, "redirect_target": {"/b"}, "redirect_code": {"301"}}))
	if err != nil || len(red) != 1 {
		t.Errorf("target-only redirect = %+v, %v; want the row kept", red, err)
	}
	rules, err := parseAPIRules(post(url.Values{"api_rule_type": {"path_regex"}, "api_rule_value": {"^/x$"}}))
	if err != nil || len(rules) != 1 {
		t.Errorf("filled api rule = %+v, %v; want the row kept", rules, err)
	}
	hdr, err := parseHeaders(post(url.Values{"header_name": {"X-A"}, "header_value": {""}}))
	if err != nil || len(hdr) != 1 {
		t.Errorf("half-filled header = %+v, %v; want the row kept", hdr, err)
	}
}

// M5 (F5 live findings): /sites/new?host=... prefills the hosts; every value is validated server
// side and an invalid one is dropped, never echoed.
func TestSiteForm_NewPrefillsHosts(t *testing.T) {
	h := newSiteFormHarness(t)
	q := url.Values{"host": {"New.App.example.test", "bad host<script>", "second.example.test"}}
	rec := h.get(t, "/sites/new?"+q.Encode())
	if rec.Code != http.StatusOK {
		t.Fatalf("GET = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "new.app.example.test\nsecond.example.test</textarea>") {
		t.Errorf("hosts not prefilled:\n%s", body)
	}
	if strings.Contains(body, "bad host") || strings.Contains(body, "<script>") {
		t.Errorf("an invalid host reached the page:\n%s", body)
	}
}
