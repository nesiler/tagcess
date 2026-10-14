package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/internal/change"
	caddyrender "github.com/nesiler/tagcess/internal/render"
	"github.com/nesiler/tagcess/internal/site"
	"github.com/nesiler/tagcess/internal/store"
	"github.com/nesiler/tagcess/internal/store/db"
	"github.com/nesiler/tagcess/internal/zitadel"
)

// Fakes and harness of the site review screens (F2-014): the form hands its parsed change to the
// site change pipeline (F2-011), the review page shows the three-artifact diff and the approve
// form, and the approve runs the replan-and-apply flow of the pipeline.

// fakeSiteReviewer records the pipeline calls and returns fixed plans and results.
type fakeSiteReviewer struct {
	previewPlans []change.SitePlan
	previewErrs  []error
	previewCalls []change.SiteRequest
	previewRuns  int

	submitResults []change.SiteResult
	submitErrs    []error
	submitCalls   []change.SiteRequest

	firstImportResults []change.SiteResult
	firstImportErrs    []error
	firstImportSeed    []byte
	firstImportOpts    []site.SeedOptions
	firstImportActors  []string
}

func (f *fakeSiteReviewer) Preview(_ context.Context, req change.SiteRequest) (change.SitePlan, error) {
	i := f.previewRuns
	f.previewRuns++
	f.previewCalls = append(f.previewCalls, req)
	if i < len(f.previewErrs) && f.previewErrs[i] != nil {
		return change.SitePlan{}, f.previewErrs[i]
	}
	if i < len(f.previewPlans) {
		return f.previewPlans[i], nil
	}
	// Beyond the configured list the last plan repeats, so a harness with one plan serves any
	// number of previews.
	if n := len(f.previewPlans); n > 0 {
		return f.previewPlans[n-1], nil
	}
	return change.SitePlan{}, errors.New("web: no preview plan configured")
}

func (f *fakeSiteReviewer) Submit(_ context.Context, req change.SiteRequest) (change.SiteResult, error) {
	f.submitCalls = append(f.submitCalls, req)
	if len(f.submitErrs) > 0 && f.submitErrs[0] != nil {
		err := f.submitErrs[0]
		res := change.SiteResult{}
		if len(f.submitResults) > 0 {
			res = f.submitResults[0]
			f.submitResults = f.submitResults[1:]
		}
		f.submitErrs = f.submitErrs[1:]
		return res, err
	}
	if len(f.submitResults) > 0 {
		res := f.submitResults[0]
		f.submitResults = f.submitResults[1:]
		return res, nil
	}
	return change.SiteResult{}, errors.New("web: no submit result configured")
}

func (f *fakeSiteReviewer) FirstImport(_ context.Context, actor string, seed []byte, opts site.SeedOptions) (change.SiteResult, error) {
	f.firstImportActors = append(f.firstImportActors, actor)
	f.firstImportSeed = seed
	f.firstImportOpts = append(f.firstImportOpts, opts)
	if len(f.firstImportErrs) > 0 && f.firstImportErrs[0] != nil {
		err := f.firstImportErrs[0]
		f.firstImportErrs = f.firstImportErrs[1:]
		return change.SiteResult{}, err
	}
	if len(f.firstImportResults) > 0 {
		res := f.firstImportResults[0]
		f.firstImportResults = f.firstImportResults[1:]
		return res, nil
	}
	return change.SiteResult{}, errors.New("web: no first-import result configured")
}

// fakeSiteDriftReader returns a fixed URI result.
type fakeSiteDriftReader struct {
	res   zitadel.URIResult
	err   error
	sites [][]site.Site
}

func (f *fakeSiteDriftReader) CheckDrift(_ context.Context, sites []site.Site) (zitadel.URIResult, error) {
	f.sites = append(f.sites, sites)
	return f.res, f.err
}

// fakeReviewSettings returns fixed render inputs.
type fakeReviewSettings struct{ settings change.SiteSettings }

func (f fakeReviewSettings) Settings(context.Context) (change.SiteSettings, error) {
	return f.settings, nil
}

// fakeReviewLister returns the stored sites (the last known good state).
type fakeReviewLister struct{ sites []site.Site }

func (f fakeReviewLister) ListSites(context.Context) ([]site.Site, error) { return f.sites, nil }

// fakeChangeReader returns the stored change rows by id.
type fakeChangeReader struct {
	rows map[int64]db.Change
	err  error
}

func (f *fakeChangeReader) GetChange(_ context.Context, id int64) (db.Change, error) {
	if f.err != nil {
		return db.Change{}, f.err
	}
	row, ok := f.rows[id]
	if !ok {
		return db.Change{}, errors.New("no such change")
	}
	return row, nil
}

// fakeFirstImportGate reports the first-import gate state.
type fakeFirstImportGate struct {
	pending bool
	done    bool
	err     error
}

func (f *fakeFirstImportGate) FirstImportPending(context.Context) (bool, error) {
	return f.pending, f.err
}

func (f *fakeFirstImportGate) FirstImportDone(context.Context) (bool, error) {
	return f.done, f.err
}

// staticRoleList is a fixed role list for the real-store gate validator.
type staticRoleList struct{}

func (staticRoleList) ListRoles(context.Context) ([]string, error) {
	return []string{"devops", "developer"}, nil
}

// newRealGateStore opens a real site store over a fresh temporary database: no LoadSeed has run,
// so the first-import gate is absent (neither pending nor done) — the state every real
// installation starts in.
func newRealGateStore(t *testing.T) *site.Store {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "tagcess.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	v, err := site.NewValidator(site.ValidatorConfig{
		AllowedDomains: []string{"example.com"},
		AllowedTargets: []string{"100.64.0.4"},
	}, staticRoleList{})
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	s, err := site.New(st.DB(), st.Queries(), v)
	if err != nil {
		t.Fatalf("site.New: %v", err)
	}
	return s
}

// fakeSeedCaddy is the SiteCaddy of the first import preview: Current is today's file, AdaptJSON
// either folds both inputs into one JSON (parity passes) or encodes the input (a difference shows).
type fakeSeedCaddy struct {
	current   string
	adaptSame bool
}

func (f *fakeSeedCaddy) Current(context.Context) (string, error) { return f.current, nil }

func (f *fakeSeedCaddy) AdaptJSON(_ context.Context, caddyfile string) ([]byte, error) {
	if f.adaptSame {
		return []byte(`{"same":true}`), nil
	}
	return []byte(fmt.Sprintf(`{"text":%q}`, caddyfile)), nil
}

// fakeSeedDNS is today's extra-records file as the first-import preview reads it.
type fakeSeedDNS struct {
	content string
	exists  bool
	err     error
}

func (f *fakeSeedDNS) Current(context.Context) (string, bool, error) {
	return f.content, f.exists, f.err
}

// seedJSON is a minimal valid seed file with one role site.
func seedJSON() string {
	return `{"sites":[{"hosts":["git.example.com"],"kind":"role","roles":["devops"],
		"target_roles":[],"cert":"le:example","target":"k8s","magicdns":true,
		"api_rules":[],"redirects":[],"headers":[]}]}`
}

type siteReviewHarness struct {
	// seed is the seed file the first import reads; empty means seedJSON().
	seed     string
	reviewer *fakeSiteReviewer
	drift    *fakeSiteDriftReader
	auditor  *fakeSiteAuditor
	changes  *fakeChangeReader
	gate     *fakeFirstImportGate
	dryRun   change.DryRun
	dnsFile  *fakeSeedDNS
	csrf     *CSRF
	chain    http.Handler
}

func newSiteReviewHarness(t *testing.T) *siteReviewHarness {
	t.Helper()
	h := &siteReviewHarness{
		reviewer: &fakeSiteReviewer{},
		drift:    &fakeSiteDriftReader{},
		auditor:  &fakeSiteAuditor{},
		changes:  &fakeChangeReader{rows: map[int64]db.Change{}},
		gate:     &fakeFirstImportGate{pending: true},
		dnsFile:  &fakeSeedDNS{content: "[]\n", exists: true},
		csrf:     testCSRF(t),
	}
	h.build(t)
	return h
}

func (h *siteReviewHarness) build(t *testing.T) {
	h.buildWith(t, h.gate, &fakeSeedCaddy{current: "# today's file\n", adaptSame: true})
}

// buildWithCaddy rebuilds the handler with a different parity adapter.
func (h *siteReviewHarness) buildWithCaddy(t *testing.T, c *fakeSeedCaddy) {
	h.buildWith(t, h.gate, c)
}

// buildWith rebuilds the handler with an explicit first-import gate and parity adapter.
func (h *siteReviewHarness) buildWith(t *testing.T, gate SiteFirstImportGate, caddy SiteSeedCaddy) {
	var dnsSource SiteSeedDNS // a nil *fakeSeedDNS must stay a nil interface
	if h.dnsFile != nil {
		dnsSource = h.dnsFile
	}
	handler, err := NewSiteReviewHandler(SiteReviewConfig{
		Reviewer: h.reviewer,
		Lister:   fakeReviewLister{sites: []site.Site{roleSiteStored()}},
		URIs:     h.drift,
		Settings: fakeReviewSettings{settings: change.SiteSettings{
			Caddy: caddyrender.CaddyConfig{ACMEEmail: "admin@example.com", S06Open: true, Certs: []string{"example.com"}},
			DNS:   caddyrender.DNSConfig{AValue: "100.64.0.4"},
		}},
		Changes: h.changes,
		Gate:    gate,
		Seed: &SiteSeedSource{
			Read: func(context.Context) ([]byte, error) {
				if h.seed != "" {
					return []byte(h.seed), nil
				}
				return []byte(seedJSON()), nil
			},
			Caddy:                  caddy,
			DNS:                    dnsSource,
			TagcessHost:            "tagcess.example.com",
			ZitadelInternalSources: []string{"10.8.0.0/24"},
		},
		DryRun:  h.dryRun,
		Auditor: h.auditor,
		CSRF:    h.csrf,
	})
	if err != nil {
		t.Fatalf("NewSiteReviewHandler: %v", err)
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	h.chain = RequireDevops(h.csrf.Protect(mux))
}

func roleSiteStored() site.Site {
	return site.Site{
		ID: 1, Hosts: []string{"git.example.com"}, Kind: site.KindRole,
		Roles: []string{"devops"}, TargetRoles: []string{},
		Cert: "le:example", TargetKind: site.TargetK8s, MagicDNS: true,
		APIRules: []site.APIRule{}, Redirects: []site.Redirect{}, Headers: []site.Header{},
	}
}

func (h *siteReviewHarness) post(t *testing.T, target string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	if form == nil {
		form = url.Values{}
	}
	form.Set(CSRFParam, h.csrf.Token())
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, target, strings.NewReader(form.Encode()))
	req.Header.Set(headerUser, "devops-user")
	req.Header.Set(headerEmail, "devops@example.com")
	req.Header.Set(headerGroups, "devops")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.chain.ServeHTTP(rec, req)
	return rec
}

func (h *siteReviewHarness) get(t *testing.T, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	req.Header.Set(headerUser, "devops-user")
	req.Header.Set(headerGroups, "devops")
	rec := httptest.NewRecorder()
	h.chain.ServeHTTP(rec, req)
	return rec
}

func planFor(op string, hosts []string, caddyDiff string) change.SitePlan {
	return change.SitePlan{
		Op:    op,
		Hosts: hosts,
		Diff: change.SiteDiff{
			Caddy:   caddyDiff,
			DNS:     "- old\n+ new",
			Zitadel: "+ https://git.example.com/oauth2/callback",
		},
	}
}

// reviewRequestJSON encodes a SiteRequest the way the review form carries it.
func reviewRequestJSON(t *testing.T, req change.SiteRequest) string {
	t.Helper()
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return string(b)
}

// AC1: the review page shows the three artifact diffs, the apply order and the approve form with
// the proposal version.
func TestSiteReview_Preview(t *testing.T) {
	h := newSiteReviewHarness(t)
	h.reviewer.previewPlans = []change.SitePlan{
		planFor(change.SiteAdd, []string{"git.example.com"}, "+git.example.com {"),
	}

	rec := h.post(t, "/sites/review", url.Values{
		"request": {reviewRequestJSON(t, change.SiteRequest{Op: change.SiteAdd, Site: roleSiteStored()})},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /sites/review = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		"+git.example.com {",
		"- old",
		"+ new",
		"+ https://git.example.com/oauth2/callback",
		"DNS → Caddy → Zitadel",
		`name="plan_version"`,
		`name="request"`,
		"Onayla",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("review page lacks %q", want)
		}
	}
}

// The pipeline refuses a request without an actor ("actor is required"). The review screen must
// plan as the signed-in operator, never as the empty actor of a freshly parsed form: the real
// pipeline refused every form submission before this (found by the F2-016 e2e run).
func TestSiteReview_PreviewPlansAsTheOperator(t *testing.T) {
	h := newSiteReviewHarness(t)
	h.reviewer.previewPlans = []change.SitePlan{
		planFor(change.SiteAdd, []string{"git.example.com"}, "+git.example.com {"),
	}
	// A forged actor in the carried request must not survive either.
	req := change.SiteRequest{Op: change.SiteAdd, Site: roleSiteStored(), Actor: "someone-else"}
	rec := h.post(t, "/sites/review", url.Values{"request": {reviewRequestJSON(t, req)}})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /sites/review = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	if len(h.reviewer.previewCalls) != 1 || h.reviewer.previewCalls[0].Actor != "devops@example.com" {
		t.Errorf("preview requests = %+v, want one planned as the signed-in operator", h.reviewer.previewCalls)
	}
}

// AC1: a delete shows the reversed order.
func TestSiteReview_DeleteOrder(t *testing.T) {
	h := newSiteReviewHarness(t)
	h.reviewer.previewPlans = []change.SitePlan{
		planFor(change.SiteDelete, []string{"git.example.com"}, "-git.example.com {"),
	}
	rec := h.post(t, "/sites/review", url.Values{
		"request": {reviewRequestJSON(t, change.SiteRequest{Op: change.SiteDelete, ID: 1})},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /sites/review = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Zitadel → Caddy → DNS") {
		t.Errorf("the delete order is not shown reversed: %q", rec.Body.String())
	}
}

// AC2: the approve re-plans; a matching version applies with the operator as the actor, a stale
// version is refused with 409 and nothing is applied.
func TestSiteReview_Replan(t *testing.T) {
	h := newSiteReviewHarness(t)
	req := change.SiteRequest{Op: change.SiteAdd, Site: roleSiteStored()}
	first := planFor(change.SiteAdd, req.Site.Hosts, "+git...")
	h.reviewer.previewPlans = []change.SitePlan{first, first}
	h.reviewer.submitResults = []change.SiteResult{{Result: change.Result{ChangeID: 7, Status: change.StatusApplied, Applied: true}}}
	h.changes.rows[7] = db.Change{ID: 7, Status: change.StatusApplied}

	rec := h.post(t, "/sites/review/approve", url.Values{
		"request":      {reviewRequestJSON(t, req)},
		"plan_version": {SitePlanVersion(first)},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("approve = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	if len(h.reviewer.submitCalls) != 1 {
		t.Fatalf("submit calls = %d, want 1", len(h.reviewer.submitCalls))
	}
	got := h.reviewer.submitCalls[0]
	if got.Op != change.SiteAdd || got.Site.Hosts[0] != "git.example.com" {
		t.Errorf("submitted request = %+v", got)
	}
	if got.Actor != "devops@example.com" {
		t.Errorf("actor = %q, want the signed-in operator", got.Actor)
	}
	if !h.auditor.hasEvent("site.approve", "requested") {
		t.Error("the approval was not audited as requested before the apply")
	}
	if !h.auditor.hasEvent("site.approve", "applied") {
		t.Error("the approval outcome was not audited")
	}
	if !strings.Contains(rec.Body.String(), "applied") {
		t.Errorf("the result page does not show the status: %q", rec.Body.String())
	}

	// A stale form: the plan moved on between preview and approval, so the approve-time replan
	// returns a different plan; the approval is refused with 409, nothing is applied and the
	// refusal is audited.
	h2 := newSiteReviewHarness(t)
	h2.reviewer.previewPlans = []change.SitePlan{planFor(change.SiteAdd, req.Site.Hosts, "+CHANGED {")}
	rec = h2.post(t, "/sites/review/approve", url.Values{
		"request":      {reviewRequestJSON(t, req)},
		"plan_version": {SitePlanVersion(first)},
	})
	if rec.Code != http.StatusConflict {
		t.Fatalf("stale approve = %d, want 409 (body %q)", rec.Code, rec.Body.String())
	}
	if len(h2.reviewer.submitCalls) != 0 {
		t.Error("a stale plan was applied")
	}
	if _, ok := h2.auditor.event("site.approve"); !ok {
		t.Error("the refused approval was not audited")
	}
}

// SitePlanVersion is stable for the same plan and moves with every diff change.
func TestSitePlanVersion(t *testing.T) {
	a := planFor(change.SiteAdd, []string{"a.x.com"}, "+a")
	same := planFor(change.SiteAdd, []string{"a.x.com"}, "+a")
	b := planFor(change.SiteAdd, []string{"a.x.com"}, "+b")
	if SitePlanVersion(a) != SitePlanVersion(same) {
		t.Error("the version is not stable for the same plan")
	}
	if SitePlanVersion(a) == SitePlanVersion(b) {
		t.Error("a changed diff kept the version")
	}
	if SitePlanVersion(a) == SitePlanVersion(change.SitePlan{Op: change.SiteDelete, Hosts: a.Hosts, Diff: a.Diff}) {
		t.Error("a changed operation kept the version")
	}
}

// AC3: a failed apply shows the reason, the recorded outcome and the last known good state.
func TestSiteReview_Failure(t *testing.T) {
	h := newSiteReviewHarness(t)
	req := change.SiteRequest{Op: change.SiteAdd, Site: roleSiteStored()}
	first := planFor(change.SiteAdd, req.Site.Hosts, "+git...")
	h.reviewer.previewPlans = []change.SitePlan{first, first}
	h.reviewer.submitResults = []change.SiteResult{{
		Result: change.Result{ChangeID: 9, Status: change.StatusFailed},
		Plan:   first,
	}}
	h.changes.rows[9] = db.Change{ID: 9, Status: change.StatusFailed, Error: "caddy adımı başarısız: /load reddetti"}

	rec := h.post(t, "/sites/review/approve", url.Values{
		"request":      {reviewRequestJSON(t, req)},
		"plan_version": {SitePlanVersion(first)},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("failed approve = %d, want 200 (result screen)", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"başarısız",
		"/load reddetti",
		"git.example.com",
		"son iyi",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the failure page lacks %q:\n%s", want, body)
		}
	}
}

// AC3: a submit that never reached a change row (a plan failure) still shows the reason.
func TestSiteReview_FailureWithoutChangeRow(t *testing.T) {
	h := newSiteReviewHarness(t)
	req := change.SiteRequest{Op: change.SiteAdd, Site: roleSiteStored()}
	first := planFor(change.SiteAdd, req.Site.Hosts, "+git...")
	h.reviewer.previewPlans = []change.SitePlan{first, first}
	h.reviewer.submitErrs = []error{errors.New("Caddyfile üretilemedi: cert yok")}

	rec := h.post(t, "/sites/review/approve", url.Values{
		"request":      {reviewRequestJSON(t, req)},
		"plan_version": {SitePlanVersion(first)},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("failed approve = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Caddyfile üretilemedi") {
		t.Errorf("the reason is not shown: %q", rec.Body.String())
	}
}

// AC4: foreign redirect URIs are shown as a warning and never offered for deletion.
func TestSiteReview_ForeignURIs(t *testing.T) {
	h := newSiteReviewHarness(t)
	h.drift.res = zitadel.URIResult{Foreign: []string{"https://someone-else.example/callback"}}
	h.reviewer.previewPlans = []change.SitePlan{
		planFor(change.SiteAdd, []string{"git.example.com"}, "+git..."),
	}

	rec := h.post(t, "/sites/review", url.Values{
		"request": {reviewRequestJSON(t, change.SiteRequest{Op: change.SiteAdd, Site: roleSiteStored()})},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /sites/review = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "https://someone-else.example/callback") {
		t.Error("the review page does not show the foreign URI")
	}
	if !strings.Contains(body, "silinmez") {
		t.Error("the review page does not say foreign URIs are kept")
	}
	if strings.Count(body, "<form") != 1 {
		t.Errorf("the review page has %d forms, want 1 (only approve); no delete may be offered", strings.Count(body, "<form"))
	}
}

// A preview that hits a problem of the existing state is shown blocked, with the reason and no
// approve form. A request-invalid preview goes back to the caller as an error instead.
func TestSiteReview_BlockedVsInvalidPreview(t *testing.T) {
	h := newSiteReviewHarness(t)
	h.reviewer.previewErrs = []error{
		fmt.Errorf("Caddyfile kayıtlardan farklı: %w", change.ErrBlocked),
		errors.New("site validation: hosts[0]: invalid"),
	}

	rec := h.post(t, "/sites/review", url.Values{
		"request": {reviewRequestJSON(t, change.SiteRequest{Op: change.SiteAdd, Site: roleSiteStored()})},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("blocked preview = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "kayıtlardan farklı") {
		t.Errorf("the blocked reason is not shown: %q", body)
	}
	if strings.Contains(body, `action="/sites/review/approve"`) {
		t.Error("a blocked change still offers the approve form")
	}

	rec = h.post(t, "/sites/review", url.Values{
		"request": {reviewRequestJSON(t, change.SiteRequest{Op: change.SiteAdd, Site: roleSiteStored()})},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid preview = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "site validation") {
		t.Errorf("the error is not shown: %q", rec.Body.String())
	}
}

// The approve refuses a malformed or tampered request payload before anything runs.
func TestSiteReview_ApproveRefusesBadPayload(t *testing.T) {
	h := newSiteReviewHarness(t)
	rec := h.post(t, "/sites/review/approve", url.Values{
		"request":      {`{"op":"delete","id":1,"nonsense":true}`},
		"plan_version": {"x"},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("tampered payload = %d, want 400", rec.Code)
	}
	if len(h.reviewer.previewCalls) != 0 || len(h.reviewer.submitCalls) != 0 {
		t.Error("a tampered payload reached the pipeline")
	}
}

// The first-import screen shows the seed summary and the parity result; the approval runs the
// pipeline first import with the configured seed options.
func TestSiteReview_FirstImport(t *testing.T) {
	h := newSiteReviewHarness(t)

	// The GET page offers the preview action while the gate is open.
	rec := h.get(t, "/sites/first-import")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /sites/first-import = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "İlk import") {
		t.Errorf("the first-import page is not shown: %q", rec.Body.String())
	}

	// The preview shows the parity result (equivalent here) and carries the version.
	h.gate.pending = true
	rec = h.post(t, "/sites/first-import/preview", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST first-import/preview = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"eşdeğer", `name="parity_version"`, "Onayla"} {
		if !strings.Contains(body, want) {
			t.Errorf("the parity review lacks %q:\n%s", want, body)
		}
	}
	version := parityVersionFromBody(t, body)

	// The approval loads the seed and applies it through the pipeline.
	h.reviewer.firstImportResults = []change.SiteResult{{Result: change.Result{ChangeID: 3, Status: change.StatusApplied, Applied: true}}}
	h.changes.rows[3] = db.Change{ID: 3, Status: change.StatusApplied}
	rec = h.post(t, "/sites/first-import", url.Values{"parity_version": {version}})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST first-import = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	if len(h.reviewer.firstImportActors) != 1 || h.reviewer.firstImportActors[0] != "devops@example.com" {
		t.Errorf("first import actors = %v", h.reviewer.firstImportActors)
	}
	if string(h.reviewer.firstImportSeed) != seedJSON() {
		t.Errorf("first import seed = %q", h.reviewer.firstImportSeed)
	}
	if len(h.reviewer.firstImportOpts) != 1 {
		t.Fatalf("first import runs = %d, want 1", len(h.reviewer.firstImportOpts))
	}
	opts := h.reviewer.firstImportOpts[0]
	if opts.TagcessHost != "tagcess.example.com" {
		t.Errorf("tagcess host = %q", opts.TagcessHost)
	}
	if len(opts.ZitadelInternalSources) != 1 || opts.ZitadelInternalSources[0] != "10.8.0.0/24" {
		t.Errorf("internal sources = %v", opts.ZitadelInternalSources)
	}

	// A stale parity version is refused and nothing runs.
	rec = h.post(t, "/sites/first-import", url.Values{"parity_version": {"stale"}})
	if rec.Code != http.StatusConflict {
		t.Fatalf("stale first-import approve = %d, want 409", rec.Code)
	}
	if len(h.reviewer.firstImportActors) != 1 {
		t.Error("a stale first import ran anyway")
	}
}

// A parity mismatch blocks the first import: the difference is shown and no approval is offered.
func TestSiteReview_FirstImportParityMismatch(t *testing.T) {
	h := newSiteReviewHarness(t)
	h.buildWithCaddy(t, &fakeSeedCaddy{current: "# today's file\n", adaptSame: false})

	rec := h.post(t, "/sites/first-import/preview", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("parity preview = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "eşdeğer değil") {
		t.Errorf("the parity mismatch is not announced: %q", body)
	}
	if strings.Contains(body, `action="/sites/first-import"`) {
		t.Error("a parity mismatch still offers the approval")
	}

	// An approval attempt is refused; the pipeline first import never runs.
	rec = h.post(t, "/sites/first-import", url.Values{"parity_version": {"whatever"}})
	if rec.Code != http.StatusConflict {
		t.Fatalf("approve on mismatch = %d, want 409", rec.Code)
	}
	if len(h.reviewer.firstImportActors) != 0 {
		t.Error("the first import ran despite the parity mismatch")
	}
}

// The real first import starts on a store with no first-import state: the gate is neither
// pending nor done until the seed load inside the pipeline's FirstImport opens it — and that
// load runs only after the approval. So the approval must be offered and must run exactly in
// this state: approvability is the parity plus "not done", not the pending flag.
func TestSiteReview_FirstImportFreshStore(t *testing.T) {
	h := newSiteReviewHarness(t)
	h.buildWith(t, newRealGateStore(t), &fakeSeedCaddy{current: "# today's file\n", adaptSame: true})

	rec := h.post(t, "/sites/first-import/preview", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("fresh-store parity preview = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "eşdeğer") {
		t.Errorf("the fresh-store preview does not show the parity result: %q", body)
	}
	if !strings.Contains(body, `action="/sites/first-import"`) {
		t.Fatal("the fresh-store preview offers no approval; the real first import could never be approved")
	}
	version := parityVersionFromBody(t, body)

	h.reviewer.firstImportResults = []change.SiteResult{{Result: change.Result{ChangeID: 4, Status: change.StatusApplied, Applied: true}}}
	h.changes.rows[4] = db.Change{ID: 4, Status: change.StatusApplied}
	rec = h.post(t, "/sites/first-import", url.Values{"parity_version": {version}})
	if rec.Code != http.StatusOK {
		t.Fatalf("fresh-store approve = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	if len(h.reviewer.firstImportActors) != 1 || h.reviewer.firstImportActors[0] != "devops@example.com" {
		t.Errorf("first import actors = %v, want one run as the signed-in operator", h.reviewer.firstImportActors)
	}
}

// The seed fixture keeps the zitadel record's system_config empty: the loader fills it from the
// zitadel_internal_sources setting. The parity preview renders the seed before that load, so it
// has to fill the record the same way or a real seed can never be previewed (found by the F2-016
// e2e run against the real fixture).
func TestSiteReview_FirstImportPreviewFillsZitadelConfig(t *testing.T) {
	h := newSiteReviewHarness(t)
	h.seed = `{"sites":[{"hosts":["auth.example.com"],"kind":"system","system_template":"zitadel",
		"system_config":{},"cert":"le:example.com","target":"k8s","magicdns":true,"note":""}]}`
	h.build(t)

	rec := h.post(t, "/sites/first-import/preview", nil)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || strings.Contains(body, "Parity karşılaştırması yapılamadı") {
		t.Fatalf("the zitadel record could not be rendered for the parity check (status %d): %s", rec.Code, body)
	}
	if !strings.Contains(body, "eşdeğer") || !strings.Contains(body, `action="/sites/first-import"`) {
		t.Errorf("the preview shows no parity result or approval: %s", body)
	}
}

// recordingSeedCaddy reports today's file as serving the tagcess host (the installer's caddy_ui phase
// ran) and records every generated Caddyfile the parity check adapts.
type recordingSeedCaddy struct{ generated []string }

const servedTagcessJSON = `{"apps":{"http":{"servers":{"srv0":{"routes":[{"match":[{"host":["tagcess.example.com"]}]}]}}}}}`

func (f *recordingSeedCaddy) Current(context.Context) (string, error) { return "# today's file\n", nil }

func (f *recordingSeedCaddy) AdaptJSON(_ context.Context, caddyfile string) ([]byte, error) {
	if caddyfile != "# today's file\n" {
		f.generated = append(f.generated, caddyfile)
	}
	return []byte(servedTagcessJSON), nil
}

// The preview compares the records the approval stores: the seed plus the tagcess system record
// (site.WithTagcess, as -import-preview and the pipeline's gate do). Once caddy_ui added the UI block
// to today's file, a preview without that record reported a difference and refused the approval.
func TestSiteReview_FirstImportPreviewComparesTagcessBlock(t *testing.T) {
	h := newSiteReviewHarness(t)
	rc := &recordingSeedCaddy{}
	h.buildWith(t, h.gate, rc)

	rec := h.post(t, "/sites/first-import/preview", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("parity preview = %d, want 200", rec.Code)
	}
	if len(rc.generated) == 0 {
		t.Fatal("the preview adapted no generated Caddyfile")
	}
	for _, g := range rc.generated {
		if !strings.Contains(g, "\ntagcess.example.com {\n") {
			t.Errorf("the generated Caddyfile lacks the tagcess block today's file serves:\n%s", g)
		}
	}
	if body := rec.Body.String(); !strings.Contains(body, `action="/sites/first-import"`) {
		t.Errorf("an equivalent preview offers no approval: %s", body)
	}
}

// parityVersionFromBody reads the parity version hidden field of the review page.
func parityVersionFromBody(t *testing.T, body string) string {
	t.Helper()
	const marker = `name="parity_version" value="`
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatal("the parity review has no version field")
	}
	rest := body[i+len(marker):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		t.Fatal("the parity version field is unterminated")
	}
	return rest[:j]
}

// F2-022 AC1: the first-import preview shows the manual DNS records it will keep (today's records
// that are not derived from a site); the approval is bound to that set.
func TestSiteReview_FirstImportShowsManualDNS(t *testing.T) {
	h := newSiteReviewHarness(t)
	h.dnsFile.content = `[
  {"name":"git.example.com","type":"A","value":"100.64.0.4"},
  {"name":"old-db.example.com","type":"A","value":"100.64.0.9"}
]`

	rec := h.post(t, "/sites/first-import/preview", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("preview = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"Elle DNS kayıtları", "old-db.example.com", "100.64.0.9", `action="/sites/first-import"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the preview lacks %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "<code>git.example.com") || strings.Contains(body, "git.example.com A") {
		t.Errorf("the preview lists a site-derived record as manual:\n%s", body)
	}
	version := parityVersionFromBody(t, body)

	// The approval is bound to the shown records: a different file makes the version stale.
	h.dnsFile.content = `[{"name":"old-db.example.com","type":"A","value":"100.64.0.10"}]`
	rec = h.post(t, "/sites/first-import", url.Values{"parity_version": {version}})
	if rec.Code != http.StatusConflict {
		t.Fatalf("approve after the dns file changed = %d, want 409", rec.Code)
	}
	if len(h.reviewer.firstImportActors) != 0 {
		t.Error("the first import ran on a stale manual record set")
	}
}

// F2-022 AC3: a manual record that collides with a site host, an invalid record or a file that
// cannot be read blocks the first import: the difference is shown and no approval is offered.
func TestSiteReview_FirstImportManualDNSConflict(t *testing.T) {
	cases := map[string]struct {
		dns      fakeSeedDNS
		wantInUI []string
	}{
		"different value for a site host": {
			dns:      fakeSeedDNS{content: `[{"name":"git.example.com","type":"A","value":"10.9.9.9"}]`, exists: true},
			wantInUI: []string{"git.example.com", "10.9.9.9"},
		},
		"invalid record": {
			dns:      fakeSeedDNS{content: `[{"name":"Bad Name","type":"A","value":"100.64.0.9"}]`, exists: true},
			wantInUI: []string{"Bad Name"},
		},
		"corrupt file": {
			dns: fakeSeedDNS{content: "{not json", exists: true},
		},
		"unreadable file": {
			dns:      fakeSeedDNS{err: errors.New("permission denied")},
			wantInUI: []string{"permission denied"},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := newSiteReviewHarness(t)
			*h.dnsFile = tc.dns

			rec := h.post(t, "/sites/first-import/preview", nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("preview = %d, want 200", rec.Code)
			}
			body := rec.Body.String()
			if !strings.Contains(body, "Elle DNS kayıtları alınamadı") {
				t.Errorf("the blocked import is not announced:\n%s", body)
			}
			for _, want := range tc.wantInUI {
				if !strings.Contains(body, want) {
					t.Errorf("the preview does not show %q:\n%s", want, body)
				}
			}
			if strings.Contains(body, `action="/sites/first-import"`) {
				t.Error("a blocked manual record set still offers the approval")
			}
			rec = h.post(t, "/sites/first-import", url.Values{"parity_version": {"whatever"}})
			if rec.Code != http.StatusConflict {
				t.Fatalf("approve = %d, want 409", rec.Code)
			}
			if len(h.reviewer.firstImportActors) != 0 {
				t.Error("the first import ran despite the manual record problem")
			}
		})
	}
}

// Without a DNS source the preview cannot know what the import would keep: it fails closed.
func TestSiteReview_FirstImportNeedsDNSSource(t *testing.T) {
	h := newSiteReviewHarness(t)
	h.dnsFile = nil
	h.buildWith(t, h.gate, &fakeSeedCaddy{current: "# today's file\n", adaptSame: true})
	rec := h.post(t, "/sites/first-import/preview", nil)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), `action="/sites/first-import"`) {
		t.Errorf("a preview without a DNS source offers the approval (status %d)", rec.Code)
	}
}

type fixedDryRun bool

func (f fixedDryRun) DryRun(context.Context) (bool, error) { return bool(f), nil }

// A1: with dry-run on, the first-import page and its result say that nothing was applied and link
// to /sync; with dry-run off (positive control) the box is absent.
func TestSiteReview_FirstImportDryRunWarning(t *testing.T) {
	const warning = "Dry-run açık: hiçbir şey apply edilmedi"
	for _, tc := range []struct {
		name   string
		dryRun change.DryRun
		want   bool
	}{
		{"dry-run on", fixedDryRun(true), true},
		{"dry-run off", fixedDryRun(false), false},
		{"no source", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newSiteReviewHarness(t)
			h.dryRun = tc.dryRun
			h.build(t)

			page := h.get(t, "/sites/first-import").Body.String()
			preview := h.post(t, "/sites/first-import/preview", nil).Body.String()
			status := change.StatusApplied
			if tc.want {
				status = change.StatusDryRun
			}
			h.reviewer.firstImportResults = []change.SiteResult{{Result: change.Result{ChangeID: 3, Status: status, Applied: !tc.want}}}
			h.changes.rows[3] = db.Change{ID: 3, Status: status}
			result := h.post(t, "/sites/first-import", url.Values{"parity_version": {parityVersionFromBody(t, preview)}}).Body.String()
			for name, body := range map[string]string{"page": page, "preview": preview, "result": result} {
				if got := strings.Contains(body, warning); got != tc.want {
					t.Errorf("%s: warning present = %v, want %v", name, got, tc.want)
				}
				if tc.want && !strings.Contains(body, `href="/sync"`) {
					t.Errorf("%s: no link to /sync", name)
				}
			}
		})
	}
}

// F5 I6: the preview names the site's target (and its change), because the Caddy diff of a k8s
// site only shows "import vpn_site", never where the traffic goes.
func TestSiteReview_PreviewShowsTarget(t *testing.T) {
	h := newSiteReviewHarness(t)
	h.reviewer.previewPlans = []change.SitePlan{planFor(change.SiteUpdate, []string{"git.example.com"}, "~import vpn_site")}
	preview := func(req change.SiteRequest) string {
		rec := h.post(t, "/sites/review", url.Values{"request": {reviewRequestJSON(t, req)}})
		if rec.Code != http.StatusOK {
			t.Fatalf("POST /sites/review = %d: %s", rec.Code, rec.Body.String())
		}
		return rec.Body.String()
	}

	// A new k8s site: the target and the shared upstream are named.
	add := roleSiteStored()
	add.ID = 0
	body := preview(change.SiteRequest{Op: change.SiteAdd, Site: add})
	for _, want := range []string{`data-target-change="true"`, "k8s", caddyrender.K8sUpstream} {
		if !strings.Contains(body, want) {
			t.Errorf("add preview lacks %q", want)
		}
	}

	// k8s -> url: both sides are shown.
	upd := roleSiteStored()
	upd.TargetKind, upd.TargetURL = site.TargetURL, "http://100.64.0.5:8080"
	body = preview(change.SiteRequest{Op: change.SiteUpdate, ID: 1, Site: upd})
	for _, want := range []string{caddyrender.K8sUpstream, "http://100.64.0.5:8080", "→"} {
		if !strings.Contains(body, want) {
			t.Errorf("update preview lacks %q", want)
		}
	}

	// Unchanged target (positive control): said so, no arrow.
	same := roleSiteStored()
	same.Note = "only a note changed"
	body = preview(change.SiteRequest{Op: change.SiteUpdate, ID: 1, Site: same})
	if !strings.Contains(body, "Hedef değişmiyor") || strings.Contains(body, "http://100.64.0.5:8080") {
		t.Errorf("an unchanged target must be reported as unchanged:\n%s", body)
	}
}

// The preview names the (k8s) upstream the Caddyfile really uses: the configured sites.k8s_upstream
// (an existing installation's :8443 internal entrypoint), the renderer's default only when none is set.
func TestTargetDescriptionNamesConfiguredK8sUpstream(t *testing.T) {
	s := site.Site{Kind: site.KindRole, TargetKind: site.TargetK8s}
	if got := targetDescription(s, "https://100.64.0.5:8443"); !strings.Contains(got, "https://100.64.0.5:8443") {
		t.Errorf("description = %q, want the configured upstream", got)
	}
	if got := targetDescription(s, ""); !strings.Contains(got, caddyrender.K8sUpstream) {
		t.Errorf("description = %q, want the default upstream", got)
	}
}
