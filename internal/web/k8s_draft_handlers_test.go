package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/k8s"
	caddyrender "github.com/nesiler/tagcess/internal/render"
	"github.com/nesiler/tagcess/internal/store"
)

// Harness of the k8s draft save/resume screen (F4-012): a real temporary SQLite draft store (F4-009
// queries), a seam discovery reader (F4-010/011 value) and the production devops + CSRF chain. The
// handler has no site/Caddy/DNS/URI/cluster dependency; the harness counts the apply-side tables
// before and after to prove a save never reaches them.

const draftHost = "new.app.example.test"

var (
	draftNow     = time.Date(2026, 10, 5, 10, 0, 0, 0, time.UTC)
	draftObsOld  = time.Date(2026, 10, 5, 8, 0, 0, 0, time.UTC)
	draftObsNew  = time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)
	applySideSQL = []string{"sites", "site_hosts", "site_versions", "changes", "applied_artifacts", "zitadel_owned_uris"}
)

type k8sDraftHarness struct {
	t       *testing.T
	st      *store.Store
	drafts  *k8s.DraftStore
	reader  *fakeK8sDiscovery
	auditor *fakeSiteAuditor
	csrf    *CSRF
	chain   http.Handler
}

func newK8sDraftHarness(t *testing.T, d K8sDiscovery, rerr error) *k8sDraftHarness {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "tagcess.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	h := &k8sDraftHarness{
		t: t, st: st, drafts: k8s.NewDraftStore(st.DB(), st.Queries(), "lab"),
		reader: &fakeK8sDiscovery{discovery: d, err: rerr}, auditor: &fakeSiteAuditor{}, csrf: testCSRF(t),
	}
	// The draft's snapshot_id is a real foreign key: seed the snapshot rows discovery refers to.
	for _, id := range []int64{12, 13} {
		if _, err := st.DB().ExecContext(context.Background(),
			`INSERT INTO k8s_snapshots (id, scope, profile_version, observed_at, payload) VALUES (?, 'web', 'pv', ?, '{}')`,
			id, draftObsOld.Format("2006-01-02T15:04:05.000Z")); err != nil {
			t.Fatalf("seed snapshot %d: %v", id, err)
		}
	}
	h.rewire()
	return h
}

// rewire builds a fresh handler over the same database, which is how a page reopen is modelled.
func (h *k8sDraftHarness) rewire() {
	handler, err := NewK8sDraftHandler(K8sDraftConfig{
		Discovery: h.reader, Drafts: h.drafts, Auditor: h.auditor, CSRF: h.csrf,
		Now: func() time.Time { return draftNow },
	})
	if err != nil {
		h.t.Fatalf("NewK8sDraftHandler: %v", err)
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	h.chain = RequireDevops(h.csrf.Protect(mux))
}

type draftRequest struct {
	method, target, groups string
	form                   url.Values
	noCSRF                 bool
}

func (h *k8sDraftHarness) do(r draftRequest) *httptest.ResponseRecorder {
	h.t.Helper()
	if r.groups == "" {
		r.groups = "devops"
	}
	var body *strings.Reader
	if r.form != nil {
		if !r.noCSRF {
			r.form.Set(CSRFParam, h.csrf.Token())
		}
		body = strings.NewReader(r.form.Encode())
	} else {
		body = strings.NewReader("")
	}
	req := httptest.NewRequestWithContext(context.Background(), r.method, r.target, body)
	req.Header.Set(headerUser, "devops-user")
	req.Header.Set(headerEmail, "devops@example.com")
	req.Header.Set(headerGroups, r.groups)
	if r.form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	rec := httptest.NewRecorder()
	h.chain.ServeHTTP(rec, req)
	return rec
}

func (h *k8sDraftHarness) get() *httptest.ResponseRecorder {
	h.t.Helper()
	return h.do(draftRequest{method: http.MethodGet, target: "/k8s/drafts/" + draftHost})
}

func (h *k8sDraftHarness) save(form url.Values) *httptest.ResponseRecorder {
	h.t.Helper()
	return h.do(draftRequest{method: http.MethodPost, target: "/k8s/drafts/" + draftHost, form: form})
}

func (h *k8sDraftHarness) stored() k8s.SavedDraft {
	h.t.Helper()
	d, ok, err := h.drafts.Get(context.Background(), draftHost)
	if err != nil || !ok {
		h.t.Fatalf("stored draft: ok=%v err=%v", ok, err)
	}
	return d
}

// applySideCounts is the row count of every table a real apply would write.
func (h *k8sDraftHarness) applySideCounts() map[string]int {
	h.t.Helper()
	out := map[string]int{}
	for _, tbl := range applySideSQL {
		var n int
		if err := h.st.DB().QueryRowContext(context.Background(), "SELECT COUNT(*) FROM "+tbl).Scan(&n); err != nil { //nolint:gosec // G202: fixed table names
			h.t.Fatalf("count %s: %v", tbl, err)
		}
		out[tbl] = n
	}
	return out
}

func (h *k8sDraftHarness) assertNoApplySideWrites(before map[string]int) {
	h.t.Helper()
	after := h.applySideCounts()
	for tbl, n := range before {
		if after[tbl] != n {
			h.t.Errorf("table %s changed from %d to %d rows: a draft save reached the apply side", tbl, n, after[tbl])
		}
	}
}

func draftRoute(uid, path, service string) k8s.Route {
	r := discoveryRoute("web", "app-ing", uid, draftHost, path, service)
	r.Backend = k8s.Backend{Service: service, PortName: "http"}
	return r
}

// draftProposal is the F4-010 draft suggestion of the host as discovery currently reports it.
func draftProposal(routes ...k8s.Route) k8s.Draft {
	return k8s.Draft{
		Host: draftHost, Target: caddyrender.K8sUpstream, Cert: k8s.CertAuto,
		Roles: []string{}, Routes: routes,
	}
}

func discoveryOf(snapID int64, version string, obs time.Time, d ...k8s.Draft) K8sDiscovery {
	return K8sDiscovery{
		Report: k8s.DraftReport{Complete: true, Scope: k8s.FirstProfileScope(), Drafts: d},
		State: k8s.State{Current: &k8s.Snapshot{
			ID: snapID, Scope: "web", ProfileVersion: version, ObservedAt: obs,
		}},
	}
}

var checkedChoice = regexp.MustCompile(`name="access_choice" value="(\w*)" checked`)

func checkedAccess(body string) string {
	m := checkedChoice.FindStringSubmatch(body)
	if m == nil {
		return "<none>"
	}
	return m[1]
}

// AC1: an incomplete draft is saved and the reopened page resumes it with the user's choices and the
// provenance, even while discovery is unreadable; nothing is applied.
func TestK8sDraftUI_SaveAndResumeWithoutApplying(t *testing.T) {
	route := draftRoute("uid-1", "/", "api")
	h := newK8sDraftHarness(t, discoveryOf(12, "pv1", draftObsOld, draftProposal(route)), nil)
	before := h.applySideCounts()

	rec := h.save(url.Values{
		"access_choice": {"role"}, "roles": {""}, "note": {"waiting for the ops owner"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("save status = %d, body %s", rec.Code, rec.Body.String())
	}

	got := h.stored()
	if got.Draft.AccessChoice != k8s.AccessChoiceRole || len(got.Draft.Roles) != 0 ||
		got.Draft.Note != "waiting for the ops owner" {
		t.Errorf("stored choices = %+v", got.Draft)
	}
	if got.Provenance.SnapshotID != 12 || got.Provenance.ProfileVersion != "pv1" || !got.Provenance.ObservedAt.Equal(draftObsOld) {
		t.Errorf("stored provenance = %+v", got.Provenance)
	}
	if len(got.Draft.Routes) != 1 || got.Draft.Routes[0].UID != "uid-1" {
		t.Errorf("stored route provenance = %+v", got.Draft.Routes)
	}

	// Reopen (new handler) while discovery cannot be read: the saved draft still resumes.
	h.reader.err = errors.New("snapshot store unavailable")
	h.rewire()
	rec = h.get()
	if rec.Code != http.StatusOK {
		t.Fatalf("resume status = %d, body %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "snapshot store unavailable") { // C-L7: the raw error never reaches the page
		t.Error("the raw discovery error is rendered")
	}
	if checkedAccess(body) != k8s.AccessChoiceRole {
		t.Errorf("resumed access choice = %q, want role", checkedAccess(body))
	}
	for _, want := range []string{"waiting for the ops owner", "web/app-ing", "uid-1", "tarama #12", "pv1", "tamamlanmadı", "en az bir rol gerekli"} {
		if !strings.Contains(body, want) {
			t.Errorf("resumed page is missing %q", want)
		}
	}
	h.assertNoApplySideWrites(before)
}

// AC2: all VPN users maps to open/intentional, selected roles to role with at least one role; a missing
// role list never becomes open, and an unknown choice is refused without touching the stored draft.
func TestK8sDraftUI_ExplicitPrivateAccessSelection(t *testing.T) {
	h := newK8sDraftHarness(t, discoveryOf(12, "pv1", draftObsOld, draftProposal(draftRoute("uid-1", "/", "api"))), nil)

	// Nothing is preselected on a fresh draft, and both options explain what they mean.
	body := h.get().Body.String()
	if checkedAccess(body) != "" && checkedAccess(body) != "<none>" {
		t.Errorf("fresh draft preselected %q", checkedAccess(body))
	}
	for _, want := range []string{"tüm VPN kullanıcıları", "intentional", "seçili roller", "en az bir rol"} {
		if !strings.Contains(body, want) {
			t.Errorf("fresh draft page does not explain %q", want)
		}
	}

	cases := []struct {
		name         string
		form         url.Values
		wantChoice   string
		wantRoles    string
		wantComplete bool
		wantText     string
	}{
		{"open_clears_roles", url.Values{"access_choice": {"open"}, "roles": {"developer"}}, "open", "", true, "intentional"},
		{"role_with_roles", url.Values{"access_choice": {"role"}, "roles": {"developer"}}, "role", "developer", true, "en az bir rol"},
		{"role_without_roles_stays_role", url.Values{"access_choice": {"role"}, "roles": {""}}, "role", "", false, "en az bir rol gerekli"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if rec := h.save(tc.form); rec.Code != http.StatusSeeOther {
				t.Fatalf("save status = %d, body %s", rec.Code, rec.Body.String())
			}
			got := h.stored()
			if got.Draft.AccessChoice != tc.wantChoice || strings.Join(got.Draft.Roles, ",") != tc.wantRoles {
				t.Errorf("stored = %q %v, want %q %q", got.Draft.AccessChoice, got.Draft.Roles, tc.wantChoice, tc.wantRoles)
			}
			if got.Draft.Complete() != tc.wantComplete {
				t.Errorf("Complete() = %v, want %v", got.Draft.Complete(), tc.wantComplete)
			}
			page := h.get().Body.String()
			if checkedAccess(page) != tc.wantChoice {
				t.Errorf("page checked %q, want %q", checkedAccess(page), tc.wantChoice)
			}
			if !strings.Contains(page, tc.wantText) {
				t.Errorf("page is missing %q", tc.wantText)
			}
		})
	}

	// An unknown choice is a bad request; the last stored choice stays.
	if rec := h.save(url.Values{"access_choice": {"public"}}); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown choice status = %d, want 400", rec.Code)
	}
	if got := h.stored(); got.Draft.AccessChoice != k8s.AccessChoiceRole {
		t.Errorf("a refused save changed the stored choice to %q", got.Draft.AccessChoice)
	}
}

// AC3: a real route conflict keeps showing its candidates and the unknown default, and the review
// request survives every save; waiting for an answer changes no access.
func TestK8sDraftUI_ConflictAlwaysRequestsReview(t *testing.T) {
	conflicted := draftProposal(draftRoute("uid-1", "/", "svc-a"), draftRoute("uid-1", "/", "svc-b"))
	conflicted.ReviewState = k8s.ReviewStateNeeded
	conflicted.ReviewReason = string(k8s.ReasonRouteConflict)
	conflicted.ReviewCandidates = []string{"web/app-ing new.app.example.test/ -> svc-a:http", "web/app-ing new.app.example.test/ -> svc-b:http"}
	h := newK8sDraftHarness(t, discoveryOf(12, "pv1", draftObsOld, conflicted), nil)
	before := h.applySideCounts()

	body := h.get().Body.String()
	for _, want := range []string{"svc-a", "svc-b", "route çelişkisi", "bilinmiyor", "inceleme isteği"} {
		if !strings.Contains(body, want) {
			t.Errorf("conflict page is missing %q", want)
		}
	}

	// Saving a complete-looking choice does not answer the review.
	for _, form := range []url.Values{
		{"access_choice": {"open"}},
		{"access_choice": {"role"}, "roles": {"developer"}},
		{"access_choice": {""}},
	} {
		if rec := h.save(form); rec.Code != http.StatusSeeOther {
			t.Fatalf("save status = %d, body %s", rec.Code, rec.Body.String())
		}
		got := h.stored()
		if got.Draft.ReviewState != k8s.ReviewStateNeeded || !strings.Contains(got.Draft.ReviewReason, string(k8s.ReasonRouteConflict)) {
			t.Errorf("review request lost after save %v: %q %q", form, got.Draft.ReviewState, got.Draft.ReviewReason)
		}
		if got.Draft.ReviewDefault != "" {
			t.Errorf("a default target %q was chosen without proof", got.Draft.ReviewDefault)
		}
		if got.Draft.Complete() {
			t.Error("a draft with an open review request reads as complete")
		}
		if len(got.Draft.ReviewCandidates) != 2 {
			t.Errorf("stored candidates = %v", got.Draft.ReviewCandidates)
		}
	}
	page := h.get().Body.String()
	if !strings.Contains(page, "svc-a") || !strings.Contains(page, "inceleme isteği") {
		t.Error("reopened conflict page lost the candidates or the review request")
	}
	h.assertNoApplySideWrites(before)

	// A later discovery without the conflict does not silently drop a stored review request.
	h.reader.discovery = discoveryOf(13, "pv1", draftObsNew, draftProposal(draftRoute("uid-1", "/", "svc-a")))
	h.rewire()
	if rec := h.save(url.Values{"access_choice": {"open"}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("save status = %d", rec.Code)
	}
	if got := h.stored(); got.Draft.ReviewState != k8s.ReviewStateNeeded {
		t.Errorf("review request dropped by a later discovery: %q", got.Draft.ReviewState)
	}
}

// A conflict that appears after the draft was first saved is raised on the next save and on the page.
func TestK8sDraftUI_ConflictAppearingLaterRequestsReview(t *testing.T) {
	h := newK8sDraftHarness(t, discoveryOf(12, "pv1", draftObsOld, draftProposal(draftRoute("uid-1", "/", "svc-a"))), nil)
	if rec := h.save(url.Values{"access_choice": {"open"}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("save status = %d", rec.Code)
	}
	conflicted := draftProposal(draftRoute("uid-1", "/", "svc-a"), draftRoute("uid-1", "/", "svc-b"))
	conflicted.ReviewState = k8s.ReviewStateNeeded
	conflicted.ReviewReason = string(k8s.ReasonRouteConflict)
	conflicted.ReviewCandidates = []string{"svc-a", "svc-b"}
	h.reader.discovery = discoveryOf(13, "pv1", draftObsNew, conflicted)
	h.rewire()
	if !strings.Contains(h.get().Body.String(), "inceleme isteği") {
		t.Error("a newly found conflict is not shown on the saved draft")
	}
	if rec := h.save(url.Values{"access_choice": {"open"}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("save status = %d", rec.Code)
	}
	if got := h.stored(); got.Draft.ReviewState != k8s.ReviewStateNeeded || got.Draft.Complete() {
		t.Errorf("a later conflict was not stored as a review request: %+v", got.Draft)
	}
}

// AC4: a newer snapshot or profile is shown as a provenance difference and a not-current state; the
// user's choices stay, a plain save does not refresh the source, the explicit refresh does.
func TestK8sDraftUI_StaleSourcePreservesChoices(t *testing.T) {
	h := newK8sDraftHarness(t, discoveryOf(12, "pv1", draftObsOld, draftProposal(draftRoute("uid-1", "/", "api"))), nil)
	if rec := h.save(url.Values{"access_choice": {"role"}, "roles": {"developer"}, "note": {"keep me"}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("seed save status = %d", rec.Code)
	}
	seed := h.stored()

	// Discovery moved on: new snapshot, new profile version, the backend changed and a path appeared.
	moved := draftProposal(draftRoute("uid-1", "/", "api-v2"), draftRoute("uid-1", "/admin", "admin"))
	moved.Target = "https://10.99.0.9:8443" // C-M3: profile v2 moved the internal listener
	h.reader.discovery = discoveryOf(13, "pv2", draftObsNew, moved)
	h.rewire()

	rec := h.get()
	body := rec.Body.String()
	for _, want := range []string{
		`data-source="stale"`, "güncel değil", "tarama #12", "tarama #13", "pv1", "pv2",
		"2026-10-05T08:00:00Z", "2026-10-05T09:00:00Z", "api-v2", "/admin", "yeni route", "değişen route",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("stale page is missing %q", want)
		}
	}
	if checkedAccess(body) != k8s.AccessChoiceRole || !strings.Contains(body, "keep me") || !strings.Contains(body, "developer") {
		t.Error("the stale page does not show the user's saved choices")
	}
	// Viewing changed nothing.
	if got := h.stored(); !got.UpdatedAt.Equal(seed.UpdatedAt) || got.Provenance != seed.Provenance || got.Draft.Note != "keep me" {
		t.Errorf("a GET changed the stored draft: %+v", got)
	}

	// A plain save keeps the old provenance (no silent source refresh) and the other choices.
	if rec := h.save(url.Values{"access_choice": {"role"}, "roles": {"developer\nops"}, "note": {"keep me"}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("save status = %d", rec.Code)
	}
	if got := h.stored(); got.Provenance.SnapshotID != 12 || got.Provenance.ProfileVersion != "pv1" || len(got.Draft.Routes) != 1 {
		t.Errorf("a plain save refreshed the provenance: %+v", got.Provenance)
	}

	// The explicit refresh updates the provenance and routes only; choices are untouched.
	rec = h.do(draftRequest{method: http.MethodPost, target: "/k8s/drafts/" + draftHost + "/refresh", form: url.Values{}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("refresh status = %d, body %s", rec.Code, rec.Body.String())
	}
	got := h.stored()
	if got.Provenance.SnapshotID != 13 || got.Provenance.ProfileVersion != "pv2" || len(got.Draft.Routes) != 2 {
		t.Errorf("refresh did not take the new provenance: %+v routes=%d", got.Provenance, len(got.Draft.Routes))
	}
	if got.Draft.AccessChoice != k8s.AccessChoiceRole || strings.Join(got.Draft.Roles, ",") != "developer,ops" || got.Draft.Note != "keep me" {
		t.Errorf("refresh overwrote the user's choices: %+v", got.Draft)
	}
	if got.Draft.Target != "https://10.99.0.9:8443" || got.Draft.Cert != k8s.CertAuto {
		t.Errorf("refresh kept the old target %q, want the current proposal's", got.Draft.Target)
	}
	if !slices.ContainsFunc(h.auditor.events, func(e audit.Entry) bool {
		return e.Event == "k8s.draft.refresh" && e.Result == "requested" && slices.ContainsFunc(e.Diff, func(f audit.Change) bool {
			return f.Field == "target" && f.Before == caddyrender.K8sUpstream && f.After == "https://10.99.0.9:8443"
		})
	}) {
		t.Errorf("refresh audit entries = %+v, want a requested entry with the target change", h.auditor.events)
	}
	if !strings.Contains(h.get().Body.String(), `data-source="current"`) {
		t.Error("the page is still not current after the refresh")
	}

	// A failed last read is shown as not current even with the same snapshot.
	h.reader.discovery.State.Stale = true
	h.reader.discovery.State.LastAttempt = &k8s.Attempt{AttemptedAt: draftNow, Outcome: k8s.OutcomeFailed, Class: k8s.ClassConnect, Message: "connect failed"}
	h.rewire()
	if b := h.get().Body.String(); !strings.Contains(b, `data-source="stale"`) || !strings.Contains(b, "connect failed") {
		t.Error("a failed read was not shown as not current")
	}
}

// AC5: a mutation without the devops identity or a valid CSRF token is refused and nothing is stored;
// an audit failure refuses the save as well.
func TestK8sDraftUI_RequiresDevopsAndCSRF(t *testing.T) {
	h := newK8sDraftHarness(t, discoveryOf(12, "pv1", draftObsOld, draftProposal(draftRoute("uid-1", "/", "api"))), nil)
	before := h.applySideCounts()
	form := func() url.Values { return url.Values{"access_choice": {"open"}, "note": {"x"}} }
	target := "/k8s/drafts/" + draftHost

	cases := []struct {
		name string
		req  draftRequest
	}{
		{"non_devops", draftRequest{method: http.MethodPost, target: target, groups: "developer", form: form()}},
		{"no_csrf", draftRequest{method: http.MethodPost, target: target, form: form(), noCSRF: true}},
		{"non_devops_refresh", draftRequest{method: http.MethodPost, target: target + "/refresh", groups: "developer", form: url.Values{}}},
		{"no_csrf_refresh", draftRequest{method: http.MethodPost, target: target + "/refresh", form: url.Values{}, noCSRF: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if rec := h.do(tc.req); rec.Code != http.StatusForbidden {
				t.Errorf("status = %d, want 403", rec.Code)
			}
		})
	}
	// A bad CSRF value is refused too.
	bad := form()
	bad.Set(CSRFParam, "forged.token")
	if rec := h.do(draftRequest{method: http.MethodPost, target: target, form: bad, noCSRF: true}); rec.Code != http.StatusForbidden {
		t.Errorf("forged token status = %d, want 403", rec.Code)
	}
	// A non-devops reader cannot even read the draft.
	if rec := h.do(draftRequest{method: http.MethodGet, target: target, groups: "developer"}); rec.Code != http.StatusForbidden {
		t.Errorf("non-devops GET status = %d, want 403", rec.Code)
	}
	if _, ok, err := h.drafts.Get(context.Background(), draftHost); err != nil || ok {
		t.Errorf("a refused request stored a draft: ok=%v err=%v", ok, err)
	}
	if len(h.auditor.events) != 0 {
		t.Errorf("refused requests wrote %d audit events", len(h.auditor.events))
	}

	// A valid save is audited without secrets; a failing audit log refuses the save.
	if rec := h.save(form()); rec.Code != http.StatusSeeOther {
		t.Fatalf("valid save status = %d, body %s", rec.Code, rec.Body.String())
	}
	if !h.auditor.hasEvent("k8s.draft.save", "") {
		t.Error("the save was not audited")
	}
	h.auditor.writeErr = errors.New("audit log down")
	if rec := h.save(url.Values{"access_choice": {"role"}, "roles": {"ops"}}); rec.Code != http.StatusInternalServerError {
		t.Errorf("save with a failing audit log status = %d, want 500", rec.Code)
	}
	if got := h.stored(); got.Draft.AccessChoice != k8s.AccessChoiceOpen {
		t.Errorf("an unaudited save changed the draft to %q", got.Draft.AccessChoice)
	}
	h.assertNoApplySideWrites(before)

	// A host with neither a stored draft nor a discovery proposal is not found.
	rec := h.do(draftRequest{method: http.MethodGet, target: "/k8s/drafts/unknown.example.test"})
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown host status = %d, want 404", rec.Code)
	}
}

// F5 I3: the draft page also says the internet-exposure check was not performed when no public
// listener is declared, and stays quiet when one is (positive control).
func TestK8sDraftUI_PublicCheckNotPerformedNote(t *testing.T) {
	const note = "internete açıklık kontrolü yapılmadı"
	d := discoveryOf(12, "pv1", draftObsOld, draftProposal(draftRoute("uid-1", "/", "api")))
	if got := newK8sDraftHarness(t, d, nil).get().Body.String(); !strings.Contains(got, note) {
		t.Errorf("no public listener: draft page lacks %q", note)
	}
	d.PublicChecked = true
	if got := newK8sDraftHarness(t, d, nil).get().Body.String(); strings.Contains(got, note) {
		t.Errorf("public listener declared: draft page must not say %q", note)
	}
}
