package web

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/k8s"
)

// Harness of the k8s discovery screen (F4-011): a seam reader that stands in for the F4-010
// host-based mapping (draft.go) and the F4-007 snapshot freshness (snapshot.go). The screen itself
// holds no credential and reads no cluster; the seam records how often it was asked, so the test can
// prove that a refused request never reaches it and that a valid GET reads only.

type k8sDiscoveryHarness struct {
	t      *testing.T
	reader *fakeK8sDiscovery
	chain  http.Handler
}

type fakeK8sDiscovery struct {
	discovery K8sDiscovery
	err       error
	calls     int
	lastCtx   context.Context
}

func (f *fakeK8sDiscovery) Discovery(ctx context.Context) (K8sDiscovery, error) {
	f.calls++
	f.lastCtx = ctx
	return f.discovery, f.err
}

func newK8sDiscoveryHarness(t *testing.T, d K8sDiscovery, rerr error) *k8sDiscoveryHarness {
	t.Helper()
	h := &k8sDiscoveryHarness{t: t, reader: &fakeK8sDiscovery{discovery: d, err: rerr}}
	handler, err := NewK8sDiscoveryHandler(K8sDiscoveryConfig{Reader: h.reader, CSRF: testCSRF(t)})
	if err != nil {
		t.Fatalf("NewK8sDiscoveryHandler: %v", err)
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	h.chain = RequireDevops(mux)
	return h
}

func (h *k8sDiscoveryHarness) request(method, target, groups string) *httptest.ResponseRecorder {
	h.t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), method, target, nil)
	req.Header.Set(headerUser, "devops-user")
	req.Header.Set(headerEmail, "devops@example.com")
	req.Header.Set(headerGroups, groups)
	rec := httptest.NewRecorder()
	h.chain.ServeHTTP(rec, req)
	return rec
}

func (h *k8sDiscoveryHarness) get(target string) *httptest.ResponseRecorder {
	h.t.Helper()
	return h.request(http.MethodGet, target, "devops")
}

// discoveryTimes are the fixed clock values the freshness assertions use.
var (
	discoveryGoodTime = time.Date(2026, 10, 5, 8, 0, 0, 0, time.UTC)
	discoveryBadTime  = time.Date(2026, 10, 5, 9, 30, 0, 0, time.UTC)
	discoveryOldTime  = time.Date(2026, 10, 4, 18, 0, 0, 0, time.UTC)
)

// route is a small route fixture with the given backend service.
func discoveryRoute(ns, ingress, uid, host, path, service string) k8s.Route {
	return k8s.Route{
		Namespace: ns, Ingress: ingress, UID: uid, Host: host, Path: path, PathType: k8s.PathPrefix,
		Backend:  k8s.Backend{Service: service, PortNumber: 8080},
		Listener: k8s.Listener{Address: "10.30.0.1", Port: 443, EntryPoint: "websecure-internal"},
		Basis:    k8s.BasisDeclaredProfile,
	}
}

// AC1: the screen shows new host candidates, existing site mappings and ambiguous/conflicting
// routes, each with provenance and a review reason.
func TestK8sDiscoveryUI_CandidatesMappingsAndReview(t *testing.T) {
	report := k8s.DraftReport{
		Complete: true,
		Scope:    k8s.FirstProfileScope(),
		Drafts: []k8s.Draft{{
			Host:             "new.app.example.test",
			Target:           "https://10.30.0.1:443",
			Cert:             k8s.CertAuto,
			AccessChoice:     k8s.AccessChoiceRole,
			Roles:            []string{"developer"},
			Note:             "<script>alert(1)</script>",
			ReviewState:      k8s.ReviewStateNeeded,
			ReviewReason:     string(k8s.ReasonRouteConflict),
			ReviewCandidates: []string{"web/app-ing new.app.example.test/ -> api:8080"},
			Routes:           []k8s.Route{discoveryRoute("web", "app-ing", "uid-1", "new.app.example.test", "/", "api")},
		}},
		Managed: []k8s.ManagedObservation{{
			SiteID: 7, Hosts: []string{"projects.example.test"}, Status: k8s.ManagedMatched,
			AccessChoice: k8s.AccessChoiceRole, Roles: []string{"devops"},
		}},
		Uncertainties: []k8s.Uncertainty{{
			Namespace: "web", Ingress: "bad-ing", UID: "uid-2", Host: "*.wild.example.test",
			Reasons: []k8s.Reason{k8s.ReasonWildcardHost},
		}},
		Conflicts: []k8s.Conflict{{
			Namespace: "web", Ingress: "conf-ing", UID: "uid-3", Host: "conf.example.test",
			Candidates: []k8s.Route{
				discoveryRoute("web", "conf-ing", "uid-3", "conf.example.test", "/", "svc-a"),
				discoveryRoute("web", "conf-ing", "uid-3", "conf.example.test", "/", "svc-b"),
			},
			Default: nil,
		}},
	}
	h := newK8sDiscoveryHarness(t, K8sDiscovery{Report: report, State: k8s.State{
		Current: &k8s.Snapshot{ID: 12, Scope: "web", ObservedAt: discoveryGoodTime},
	}}, nil)

	rec := h.get("/k8s/discovery")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /k8s/discovery status = %d, body %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()

	// New host candidate with its target, access choice, roles and review reason.
	for _, want := range []string{
		"new.app.example.test", "https://10.30.0.1:443", "auto", "developer",
		"route_conflict", "route çelişkisi", "web/app-ing",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("candidate view is missing %q", want)
		}
	}
	// Existing site mapping with its preserved access choice and roles.
	for _, want := range []string{"projects.example.test", "devops", "eşleşti"} {
		if !strings.Contains(body, want) {
			t.Errorf("managed mapping is missing %q", want)
		}
	}
	// Ambiguous route with provenance and reason.
	for _, want := range []string{"bad-ing", "uid-2", "*.wild.example.test", "wildcard_host", "wildcard host"} {
		if !strings.Contains(body, want) {
			t.Errorf("uncertainty view is missing %q", want)
		}
	}
	// Conflict with both candidates and an unknown default (never a list-order winner).
	for _, want := range []string{"conf-ing", "uid-3", "conf.example.test", "svc-a", "svc-b", "bilinmiyor"} {
		if !strings.Contains(body, want) {
			t.Errorf("conflict view is missing %q", want)
		}
	}

	// A draft note is HTML-escaped: the markup is shown as text, not injected.
	if !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("draft note was not HTML-escaped")
	}
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Error("draft note reached the page as live markup")
	}
}

// AC2: when the last read failed or the scope changed, the last good observation and its scope time,
// the last attempt/error and the not-current state are shown separately; the old data is never
// presented as current.
func TestK8sDiscoveryUI_ShowsStaleSnapshotAndScope(t *testing.T) {
	t.Run("stale_after_failed_read", func(t *testing.T) {
		h := newK8sDiscoveryHarness(t, K8sDiscovery{Report: k8s.DraftReport{Complete: false}, State: k8s.State{
			Current: &k8s.Snapshot{ID: 12, Scope: "web", ObservedAt: discoveryGoodTime},
			LastAttempt: &k8s.Attempt{
				AttemptedAt: discoveryBadTime, Outcome: k8s.OutcomeFailed,
				Class: k8s.ClassCredentialExpired, Message: "the stored credential is not usable",
			},
			Stale: true,
		}}, nil)

		rec := h.get("/k8s/discovery")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
		}
		body := rec.Body.String()
		for _, want := range []string{
			"2026-10-05T08:00:00Z", // last good observation
			"web",                  // its scope
			"2026-10-05T09:30:00Z", // last attempt
			k8s.ClassCredentialExpired,
			"the stored credential is not usable",
			"güncel değil",
			`data-freshness="stale"`,
		} {
			if !strings.Contains(body, want) {
				t.Errorf("stale view is missing %q", want)
			}
		}
		if strings.Contains(body, `data-freshness="current"`) {
			t.Error("stale snapshot was presented as current")
		}
	})

	t.Run("old_scope_not_current", func(t *testing.T) {
		h := newK8sDiscoveryHarness(t, K8sDiscovery{Report: k8s.DraftReport{Complete: false}, State: k8s.State{
			Previous: &k8s.Snapshot{ID: 5, Scope: "apps,web", ObservedAt: discoveryOldTime},
			LastAttempt: &k8s.Attempt{
				AttemptedAt: discoveryBadTime, Outcome: k8s.OutcomeFailed, Class: k8s.ClassConnect, Message: "connect failed",
			},
		}}, nil)

		rec := h.get("/k8s/discovery")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
		}
		body := rec.Body.String()
		for _, want := range []string{
			"2026-10-04T18:00:00Z", ">apps<", ">web<", "önceki tarama", "güncel değil", `data-freshness="previous"`,
		} {
			if !strings.Contains(body, want) {
				t.Errorf("old-scope view is missing %q", want)
			}
		}
		if strings.Contains(body, `data-freshness="current"`) {
			t.Error("old-scope data was presented as current")
		}
	})
}

// AC3: a managed site with no matching route keeps its record, access choice and roles; the screen
// starts no delete or automatic access change and explains the unscanned CRD/Gateway scope.
func TestK8sDiscoveryUI_MissingRoutePreservesSite(t *testing.T) {
	report := k8s.DraftReport{
		Complete: true,
		Scope:    k8s.FirstProfileScope(),
		Managed: []k8s.ManagedObservation{{
			SiteID: 7, Hosts: []string{"projects.example.test"}, Status: k8s.ManagedNoRoute,
			AccessChoice: k8s.AccessChoiceRole, Roles: []string{"devops", "ops"},
		}},
	}
	h := newK8sDiscoveryHarness(t, K8sDiscovery{Report: report, State: k8s.State{
		Current: &k8s.Snapshot{ID: 12, Scope: "web", ObservedAt: discoveryGoodTime},
	}}, nil)

	rec := h.get("/k8s/discovery")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()

	// The site, its access choice and roles survive the missing route.
	for _, want := range []string{"projects.example.test", "devops", "ops", "route eşleşmesi yok", "rol"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing-route view is missing %q", want)
		}
	}
	// The read-only guarantee and the explicitly unscanned scope.
	for _, want := range []string{
		"silme", "otomatik", "gateway.networking.k8s.io", "traefik.io CRDs", "taranmadı",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing-route view is missing the guarantee/scope note %q", want)
		}
	}
	// The discovery screen has no action that could delete or widen access.
	if strings.Contains(strings.ToLower(body), "<form") {
		t.Error("discovery screen rendered a form (a write path)")
	}
}

// AC4: a request without the devops identity is refused, the screen answers GET only, a valid GET is
// read-only, and no credential value is carried onto the page.
func TestK8sDiscoveryUI_AuthorizationAndReadOnly(t *testing.T) {
	h := newK8sDiscoveryHarness(t, K8sDiscovery{Report: k8s.DraftReport{Complete: true}, State: k8s.State{
		Current: &k8s.Snapshot{ID: 12, Scope: "web", ObservedAt: discoveryGoodTime},
	}}, nil)

	// No devops identity: refused before the seam is reached.
	if rec := h.request(http.MethodGet, "/k8s/discovery", "developer"); rec.Code != http.StatusForbidden {
		t.Errorf("non-devops GET status = %d, want 403", rec.Code)
	}
	if h.reader.calls != 0 {
		t.Fatalf("a refused request reached the seam %d times", h.reader.calls)
	}

	// A state-changing method is not served: only GET exists.
	if rec := h.request(http.MethodPost, "/k8s/discovery", "devops"); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST status = %d, want 405", rec.Code)
	}
	if h.reader.calls != 0 {
		t.Fatalf("a rejected POST reached the seam %d times", h.reader.calls)
	}

	// A valid GET reads exactly once and returns the page.
	rec := h.get("/k8s/discovery")
	if rec.Code != http.StatusOK {
		t.Fatalf("devops GET status = %d, body %s", rec.Code, rec.Body.String())
	}
	if h.reader.calls != 1 {
		t.Errorf("valid GET reached the seam %d times, want 1", h.reader.calls)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "k8s discovery") {
		t.Error("valid GET did not render the discovery page")
	}
	// No credential material reaches the page: no token/CA/kubeconfig inputs and no PEM/bearer text.
	for _, forbidden := range []string{
		`name="token"`, `name="ca_data"`, `name="kubeconfig"`, "BEGIN CERTIFICATE", "BEGIN RSA PRIVATE KEY",
		"Bearer ", "authorization:",
	} {
		if strings.Contains(body, forbidden) {
			t.Errorf("discovery page carries credential material %q", forbidden)
		}
	}
}

// C-L7: a discovery read failure shows fixed text; the raw error (an API URL, a path) is only logged.
func TestK8sDiscoveryUI_ReadFailureShowsFixedText(t *testing.T) {
	h := newK8sDiscoveryHarness(t, K8sDiscovery{}, errors.New("get https://10.9.9.9:6443/apis: dial tcp refused"))
	body := h.get("/k8s/discovery").Body.String()
	if !strings.Contains(body, "discovery verisi okunamadı") {
		t.Error("the read failure is not shown")
	}
	if strings.Contains(body, "10.9.9.9") || strings.Contains(body, "dial tcp") {
		t.Error("the raw discovery error is rendered")
	}
}

// F5 I3: without a declared public listener the screen says the internet-exposure check was not
// performed; with one it stays quiet (positive control).
func TestK8sDiscoveryUI_PublicCheckNotPerformedNote(t *testing.T) {
	const note = "internete açıklık kontrolü yapılmadı"
	body := func(d K8sDiscovery) string {
		return newK8sDiscoveryHarness(t, d, nil).get("/k8s/discovery").Body.String()
	}
	if got := body(K8sDiscovery{PublicChecked: false}); !strings.Contains(got, note) {
		t.Errorf("no public listener: page lacks %q", note)
	}
	if got := body(K8sDiscovery{PublicChecked: true}); strings.Contains(got, note) {
		t.Errorf("public listener declared: page must not say %q", note)
	}
}

// F5 G3/G4: with no connection profile the page asks for the setup instead of "could not be read".
func TestK8sDiscoveryUI_NoProfileIsSetupPending(t *testing.T) {
	rec := newK8sDiscoveryHarness(t, K8sDiscovery{}, k8s.ErrNotSet).get("/k8s/discovery")
	got := rec.Body.String()
	for _, want := range []string{"Kurulum bekleniyor", `href="/k8s/connection"`} {
		if !strings.Contains(got, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if strings.Contains(got, "discovery verisi okunamadı") {
		t.Error("an unconfigured cluster must not be shown as a read failure")
	}
}

// F5 G4: an unconfigured cluster is logged at INFO, never as a recurring WARN; a real read failure
// still warns (positive control).
func TestK8sDiscoveryUI_NoProfileDoesNotWarn(t *testing.T) {
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	newK8sDiscoveryHarness(t, K8sDiscovery{}, k8s.ErrNotSet).get("/k8s/discovery")
	if strings.Contains(logs.String(), "level=WARN") {
		t.Errorf("an unconfigured cluster logged a warning: %s", logs.String())
	}
	newK8sDiscoveryHarness(t, K8sDiscovery{}, errors.New("boom")).get("/k8s/discovery")
	if !strings.Contains(logs.String(), "level=WARN") {
		t.Error("a real read failure no longer warns")
	}
}

// F5 L5: a system-template site without a route has its own label, not "rota eşleşmesi yok".
func TestManagedStatusLabelSystem(t *testing.T) {
	if got := managedStatusLabel(k8s.ManagedSystem); got != "sistem şablonu (k8s dışı)" {
		t.Errorf("system label = %q", got)
	}
	if got := managedStatusLabel(k8s.ManagedNoRoute); got != "route eşleşmesi yok" {
		t.Errorf("control: no_route label = %q", got)
	}
}

// M5 (F5 live findings): a new host candidate links to the site form with its host prefilled;
// the link only opens the form (GET), nothing is applied.
func TestK8sDiscoveryUI_CandidateLinksPrefilledSiteForm(t *testing.T) {
	report := k8s.DraftReport{
		Complete: true,
		Scope:    k8s.FirstProfileScope(),
		Drafts: []k8s.Draft{{
			Host: "new.app.example.test", Target: "https://10.30.0.1:443", Cert: k8s.CertAuto,
			AccessChoice: k8s.AccessChoiceRole, ReviewState: k8s.ReviewStateNeeded,
		}},
	}
	h := newK8sDiscoveryHarness(t, K8sDiscovery{Report: report, State: k8s.State{
		Current: &k8s.Snapshot{ID: 12, Scope: "web", ObservedAt: discoveryGoodTime},
	}}, nil)
	body := h.get("/k8s/discovery").Body.String()
	if !strings.Contains(body, `href="/sites/new?host=new.app.example.test"`) {
		t.Fatalf("candidate has no prefilled site form link:\n%s", body)
	}
}

// M6 (F5 live findings): the managed-mapping status shows the Turkish label only, not the label
// followed by its English identifier.
func TestK8sDiscoveryUI_ManagedStatusSingleLabel(t *testing.T) {
	report := k8s.DraftReport{
		Complete: true,
		Scope:    k8s.FirstProfileScope(),
		Managed: []k8s.ManagedObservation{{
			SiteID: 3, Hosts: []string{"auth.example.test"}, Status: k8s.ManagedSystem,
		}},
	}
	h := newK8sDiscoveryHarness(t, K8sDiscovery{Report: report, State: k8s.State{
		Current: &k8s.Snapshot{ID: 12, Scope: "web", ObservedAt: discoveryGoodTime},
	}}, nil)
	body := h.get("/k8s/discovery").Body.String()
	if !strings.Contains(body, "sistem şablonu (k8s dışı)") {
		t.Fatalf("system label missing:\n%s", body)
	}
	if strings.Contains(body, "<code>system</code>") {
		t.Errorf("status shown in two languages:\n%s", body)
	}
}
