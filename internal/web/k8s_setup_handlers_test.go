package web

import (
	"context"
	"errors"
	"html"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/k8s"
	"github.com/nesiler/tagcess/internal/netpolicy"
	"github.com/nesiler/tagcess/internal/store"
)

// Harness of the k8s setup screen (F4-041): a real settings store, the F4-002 profile store over
// it, the real F4-043 policy store and a real audit log. The F4-005 permission review is a seam:
// the harness records the namespaces it is asked about and answers with a canned review, because
// building a live client is F4-030's connection screen.

const (
	k8sSetupActor = "devops@example.com"
)

var k8sSetupTime = time.Date(2026, 10, 4, 12, 30, 15, 0, time.UTC)

type k8sSetupHarness struct {
	t        *testing.T
	store    *store.Store
	policy   *netpolicy.Store
	profiles *k8s.ProfileStore
	audit    *audit.Logger
	csrf     *CSRF
	chain    http.Handler
	auditor  *k8sSetupAuditor
	saved    atomic.Int32 // OnSaved calls (F5 I4)

	reviewNamespaces [][]string
	reviewResult     k8s.Review
	reviewErr        error
}

// k8sSetupAuditor is the SiteAuditor seam; a non-nil fail makes every write fail so the
// "audit before write" path can be exercised.
type k8sSetupAuditor struct {
	inner *audit.Logger
	fail  error
}

func (a *k8sSetupAuditor) Write(ctx context.Context, e audit.Entry) (audit.Event, error) {
	if a.fail != nil {
		return audit.Event{}, a.fail
	}
	return a.inner.Write(ctx, e)
}

func newK8sSetupHarness(t *testing.T) *k8sSetupHarness {
	t.Helper()
	s, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "tagcess.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	h := &k8sSetupHarness{
		t: t, store: s, csrf: testCSRF(t),
		reviewResult: k8s.Review{
			Principal:  "system:serviceaccount:tagcess:tagcess-reader",
			At:         k8sSetupTime,
			Namespaces: []string{"web"},
			Required: []k8s.Check{{
				Namespace: "web", Group: "networking.k8s.io", Resource: "ingresses",
				Verb: "list", Want: true, Answered: true, Allowed: true,
			}},
			Forbidden: []k8s.Check{{
				Namespace: "web", Resource: "secrets", Verb: "get",
				Want: false, Answered: true, Allowed: false,
			}},
		},
	}
	h.policy = netpolicy.New(s.DB(), s.Queries())
	h.profiles = k8s.NewProfileStore(s.DB(), s.Queries(), h.policy, func() time.Time { return k8sSetupTime })
	h.audit = audit.New(s.Queries())
	h.auditor = &k8sSetupAuditor{inner: h.audit}

	handler, err := NewK8sSetupHandler(K8sSetupConfig{
		Profiles: h.profiles,
		Policy:   h.policy,
		Review: func(_ context.Context, namespaces []string) (k8s.Review, error) {
			h.reviewNamespaces = append(h.reviewNamespaces, namespaces)
			return h.reviewResult, h.reviewErr
		},
		Auditor: h.auditor,
		CSRF:    h.csrf,
		Creds:   k8s.NewCredentialStore(filepath.Join(t.TempDir(), "credentials")),
		Now:     func() time.Time { return k8sSetupTime },
		OnSaved: func() { h.saved.Add(1) },
	})
	if err != nil {
		t.Fatalf("NewK8sSetupHandler: %v", err)
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	h.chain = RequireDevops(h.csrf.Protect(mux))
	return h
}

// setAPIPolicy stores a valid API policy so a profile can pass the F4-043 check.
func (h *k8sSetupHarness) setAPIPolicy() {
	h.t.Helper()
	if err := h.policy.Set(context.Background(), netpolicy.ScopeAPI, netpolicy.Input{
		Addresses: []string{"10.20.0.0/24"}, Ports: []int{6443},
	}); err != nil {
		h.t.Fatalf("set API policy: %v", err)
	}
}

// setProfile saves a valid F4-002 profile over the given namespaces.
func (h *k8sSetupHarness) setProfile(namespaces ...string) k8s.Profile {
	h.t.Helper()
	p := k8s.Profile{
		Endpoint:       "https://10.20.0.9:6443",
		Namespaces:     namespaces,
		Controller:     "traefik.io/ingress-controller",
		IngressClasses: []string{"traefik"},
		Internal:       []k8s.Listener{{Address: "10.30.0.1", Port: 80}},
		Public:         []k8s.Listener{{Address: "203.0.113.10", Port: 443}},
	}
	if err := h.profiles.Save(context.Background(), p); err != nil {
		h.t.Fatalf("save profile: %v", err)
	}
	got, err := h.profiles.Get(context.Background())
	if err != nil {
		h.t.Fatalf("get profile: %v", err)
	}
	return got
}

func (h *k8sSetupHarness) request(method, target string, form url.Values, groups string, csrf bool, headers map[string]string) *httptest.ResponseRecorder {
	h.t.Helper()
	body := strings.NewReader("")
	if form != nil {
		clone := url.Values{}
		for k, v := range form {
			clone[k] = v
		}
		if csrf {
			clone.Set(CSRFParam, h.csrf.Token())
		}
		body = strings.NewReader(clone.Encode())
	}
	req := httptest.NewRequestWithContext(context.Background(), method, target, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set(headerUser, "devops-user")
	req.Header.Set(headerEmail, k8sSetupActor)
	req.Header.Set(headerGroups, groups)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.chain.ServeHTTP(rec, req)
	return rec
}

func (h *k8sSetupHarness) get(target string) *httptest.ResponseRecorder {
	h.t.Helper()
	return h.request(http.MethodGet, target, nil, "devops", false, nil)
}

func (h *k8sSetupHarness) post(target string, form url.Values) *httptest.ResponseRecorder {
	h.t.Helper()
	return h.request(http.MethodPost, target, form, "devops", true, nil)
}

func (h *k8sSetupHarness) storedPolicy(scope netpolicy.Scope) (netpolicy.Policy, error) {
	h.t.Helper()
	return h.policy.Get(context.Background(), scope)
}

func (h *k8sSetupHarness) auditEvents(event string) []audit.Event {
	h.t.Helper()
	evs, err := h.audit.List(context.Background(), audit.Filter{Event: event, Limit: 100})
	if err != nil {
		h.t.Fatalf("audit.List: %v", err)
	}
	return evs
}

// AC1: the download is the F4-005 narrow manifest for the profile scope, deterministic, and the
// screen neither applies it nor asks the cluster for anything.
func TestK8sSetupUI_ExportsReadOnlyBootstrap(t *testing.T) {
	h := newK8sSetupHarness(t)
	h.setAPIPolicy()
	prof := h.setProfile("web", "apps")

	want, err := k8s.RBACManifest(prof.Namespaces, k8s.ServiceAccountRef{
		Namespace: "tagcess", Name: k8s.DefaultServiceAccountName,
	})
	if err != nil {
		t.Fatalf("RBACManifest: %v", err)
	}

	rec := h.get("/k8s/setup/manifest?sa_namespace=tagcess")
	if rec.Code != http.StatusOK {
		t.Fatalf("manifest status = %d, body %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Disposition"); !strings.HasPrefix(got, "attachment") {
		t.Errorf("Content-Disposition = %q, want an attachment", got)
	}
	if got := rec.Header().Get("Content-Type"); !strings.Contains(got, "yaml") {
		t.Errorf("Content-Type = %q, want yaml", got)
	}
	if body := rec.Body.String(); body != string(want) {
		t.Errorf("manifest body does not match k8s.RBACManifest:\n got: %s\nwant: %s", body, want)
	}

	if !strings.Contains(rec.Body.String(), "delete it manually") { // A-L9
		t.Error("manifest header does not say a removed namespace's RoleBinding must be deleted")
	}
	if page := h.get("/k8s/setup"); !strings.Contains(page.Body.String(), "elle silmelidir") {
		t.Error("setup page does not say a removed namespace's RoleBinding must be deleted")
	}

	// Deterministic: the same request yields the same bytes.
	again := h.get("/k8s/setup/manifest?sa_namespace=tagcess")
	if again.Body.String() != rec.Body.String() {
		t.Error("manifest is not deterministic across requests")
	}

	// The narrow manifest carries no Secret/token rule and no wildcard verb.
	body := strings.ToLower(rec.Body.String())
	for _, forbidden := range []string{"secret", "token", `"*"`, "*"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("manifest contains %q", forbidden)
		}
	}
	for _, verb := range []string{"create", "update", "patch", "delete"} {
		if strings.Contains(body, `"`+verb+`"`) {
			t.Errorf("manifest contains the write verb %q", verb)
		}
	}
	if !strings.Contains(body, "get") || !strings.Contains(body, "list") {
		t.Error("manifest is missing get/list")
	}
	// Nothing was asked of the cluster: the review seam stayed untouched.
	if len(h.reviewNamespaces) != 0 {
		t.Errorf("manifest download ran the permission review: %v", h.reviewNamespaces)
	}
}

// AC2: the permission evidence shows the principal, scope, time and only the tested operations,
// and never a universal read-only claim.
func TestK8sSetupUI_PermissionEvidenceIsScoped(t *testing.T) {
	h := newK8sSetupHarness(t)
	h.setAPIPolicy()
	h.setProfile("web")

	rec := h.post("/k8s/setup/review", url.Values{})
	if rec.Code != http.StatusOK {
		t.Fatalf("review status = %d, body %s", rec.Code, rec.Body.String())
	}
	if len(h.reviewNamespaces) != 1 || len(h.reviewNamespaces[0]) != 1 || h.reviewNamespaces[0][0] != "web" {
		t.Fatalf("review namespaces = %v, want the profile scope [[web]]", h.reviewNamespaces)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"system:serviceaccount:tagcess:tagcess-reader",
		"2026-10-04T12:30:15Z",
		"web",
		"ingresses.networking.k8s.io",
		"secrets",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("permission evidence is missing %q", want)
		}
	}
	for _, forbidden := range []string{"read-only doğrulandı", "salt okur doğrulandı", "read-only verified"} {
		if strings.Contains(strings.ToLower(body), forbidden) {
			t.Errorf("permission evidence makes a universal claim: %q", forbidden)
		}
	}
	for _, want := range []string{"diğer bağlar", "bu işlemler sınandı", "doğrulanmamış"} { // A-L8
		if !strings.Contains(body, want) {
			t.Errorf("permission evidence is missing the scope disclaimer %q", want)
		}
	}
}

// AC3: the shared F4-043 policy is saved per scope and read back, a refused field keeps the old
// policy, and no credential is ever sent for a policy save.
func TestK8sSetupUI_SharedPolicySaveAndNextTransport(t *testing.T) {
	h := newK8sSetupHarness(t)

	api := url.Values{"scope": {"api"}, "addresses": {"10.20.0.0/24\n10.21.0.7"}, "ports": {"6443, 8443"}}
	if rec := h.post("/k8s/setup/policy", api); rec.Code != http.StatusOK {
		t.Fatalf("api policy status = %d, body %s", rec.Code, rec.Body.String())
	}
	gotAPI, err := h.storedPolicy(netpolicy.ScopeAPI)
	if err != nil {
		t.Fatalf("stored API policy: %v", err)
	}
	if len(gotAPI.Addresses) != 2 || len(gotAPI.Ports) != 2 {
		t.Fatalf("API policy = %+v, want the two addresses and two ports", gotAPI)
	}
	// The typed stored policy is the value the next API transport reads.
	if err := h.policy.Check(context.Background(), netpolicy.ScopeAPI, netip.MustParseAddr("10.21.0.7"), 8443); err != nil {
		t.Errorf("next transport cannot reach the saved address: %v", err)
	}

	probe := url.Values{"scope": {"probe"}, "addresses": {"10.30.0.0/24"}, "ports": {"443"}}
	if rec := h.post("/k8s/setup/policy", probe); rec.Code != http.StatusOK {
		t.Fatalf("probe policy status = %d, body %s", rec.Code, rec.Body.String())
	}
	gotProbe, err := h.storedPolicy(netpolicy.ScopeProbe)
	if err != nil {
		t.Fatalf("stored probe policy: %v", err)
	}
	if len(gotProbe.Addresses) != 1 || gotProbe.Addresses[0] != "10.30.0.0/24" {
		t.Fatalf("probe policy = %+v", gotProbe)
	}
	// Scopes stay separate: re-read the API scope after the probe save and compare.
	apiAfterProbe, err := h.storedPolicy(netpolicy.ScopeAPI)
	if err != nil {
		t.Fatalf("stored API policy after probe save: %v", err)
	}
	if !reflect.DeepEqual(apiAfterProbe, gotAPI) {
		t.Errorf("API policy changed when the probe scope was saved: before %+v after %+v", gotAPI, apiAfterProbe)
	}

	// The screen shows the stored values again.
	page := h.get("/k8s/setup")
	if !strings.Contains(page.Body.String(), "10.21.0.7") || !strings.Contains(page.Body.String(), "10.30.0.0/24") {
		t.Error("setup page does not show the stored policies")
	}

	// A refused field keeps the stored policy byte for byte and sends no credential.
	bad := url.Values{"scope": {"api"}, "addresses": {"127.0.0.1"}, "ports": {"6443"}}
	rec := h.post("/k8s/setup/policy", bad)
	if rec.Code == http.StatusOK {
		t.Fatalf("loopback address was accepted: %s", rec.Body.String())
	}
	after, err := h.storedPolicy(netpolicy.ScopeAPI)
	if err != nil {
		t.Fatalf("stored API policy after refusal: %v", err)
	}
	if len(after.Addresses) != 2 || after.Addresses[0] != "10.20.0.0/24" {
		t.Errorf("refused input changed the API policy: %+v", after)
	}
	if len(h.reviewNamespaces) != 0 {
		t.Errorf("a policy save ran the permission review (credential sent?): %v", h.reviewNamespaces)
	}
}

// AC4: without devops, without CSRF or with a spoofed actor nothing changes, and the trusted actor
// comes from the request context only.
func TestK8sSetupUI_AuthorizationAndAudit(t *testing.T) {
	h := newK8sSetupHarness(t)
	h.setAPIPolicy()
	h.setProfile("web")

	// No devops group: forbidden before anything runs. The address differs from the stored one, so a
	// write would be visible.
	foreign := url.Values{"scope": {"api"}, "addresses": {"10.99.0.0/24"}, "ports": {"6443"}}
	rec := h.request(http.MethodPost, "/k8s/setup/policy", foreign, "developer", true, nil)
	if rec.Code != http.StatusForbidden {
		t.Errorf("non-devops POST status = %d, want 403", rec.Code)
	}
	if got, _ := h.storedPolicy(netpolicy.ScopeAPI); strings.Contains(strings.Join(got.Addresses, ","), "10.99.0.0/24") {
		t.Errorf("non-devops POST changed the policy: %+v", got)
	}
	if evs := h.auditEvents(k8sSetupPolicyEvent); len(evs) != 0 {
		t.Errorf("non-devops POST was audited: %+v", evs)
	}
	// The permission review makes outbound calls: neither a non-devops nor a CSRF-less POST may run it.
	if rec := h.request(http.MethodPost, "/k8s/setup/review", url.Values{}, "developer", true, nil); rec.Code != http.StatusForbidden {
		t.Errorf("non-devops review status = %d, want 403", rec.Code)
	}
	if rec := h.request(http.MethodPost, "/k8s/setup/review", url.Values{}, "devops", false, nil); rec.Code != http.StatusForbidden {
		t.Errorf("review without CSRF status = %d, want 403", rec.Code)
	}
	if len(h.reviewNamespaces) != 0 {
		t.Errorf("a refused review POST reached the runner: %v", h.reviewNamespaces)
	}
	if rec := h.request(http.MethodGet, "/k8s/setup", nil, "developer", false, nil); rec.Code != http.StatusForbidden {
		t.Errorf("non-devops GET status = %d, want 403", rec.Code)
	}

	// Missing CSRF token: forbidden, nothing written.
	change := url.Values{"scope": {"api"}, "addresses": {"10.21.0.0/24"}, "ports": {"6443"}}
	rec = h.request(http.MethodPost, "/k8s/setup/policy", change, "devops", false, nil)
	if rec.Code != http.StatusForbidden {
		t.Errorf("POST without CSRF status = %d, want 403", rec.Code)
	}
	if got, _ := h.storedPolicy(netpolicy.ScopeAPI); !strings.Contains(strings.Join(got.Addresses, ","), "10.20.0.0/24") {
		t.Errorf("POST without CSRF changed the policy: %+v", got)
	}

	// A form field and a custom header claiming another actor do not change who is recorded.
	spoof := url.Values{
		"scope": {"api"}, "addresses": {"10.22.0.0/24"}, "ports": {"6443"},
		"actor": {"attacker@example.com"},
	}
	rec = h.request(http.MethodPost, "/k8s/setup/policy", spoof, "devops", true, map[string]string{"X-Tagcess-Actor": "attacker@example.com"})
	if rec.Code != http.StatusOK {
		t.Fatalf("spoofed actor POST status = %d, body %s", rec.Code, rec.Body.String())
	}
	events := h.auditEvents(k8sSetupPolicyEvent)
	if len(events) == 0 {
		t.Fatal("policy change was not audited")
	}
	for _, e := range events {
		if e.Actor == "attacker@example.com" {
			t.Errorf("audit recorded the spoofed actor: %+v", e)
		}
		if e.Actor != k8sSetupActor {
			t.Errorf("audit actor = %q, want the request-context identity %q", e.Actor, k8sSetupActor)
		}
	}

	// A failing audit write must stop the policy change.
	before, err := h.storedPolicy(netpolicy.ScopeAPI)
	if err != nil {
		t.Fatalf("stored policy: %v", err)
	}
	h.auditor.fail = errors.New("audit down")
	rec = h.post("/k8s/setup/policy", url.Values{"scope": {"api"}, "addresses": {"10.23.0.0/24"}, "ports": {"6443"}})
	if rec.Code == http.StatusOK {
		t.Fatalf("policy was saved although the audit write failed: %s", rec.Body.String())
	}
	after, err := h.storedPolicy(netpolicy.ScopeAPI)
	if err != nil {
		t.Fatalf("stored policy after audit failure: %v", err)
	}
	if strings.Join(before.Addresses, ",") != strings.Join(after.Addresses, ",") {
		t.Errorf("audit failure changed the policy: before %v after %v", before.Addresses, after.Addresses)
	}
}

// F5 I2: the ServiceAccount namespace input is always on the page, and a manifest request without
// the query parameters uses the documented defaults instead of failing with 400.
func TestK8sSetupUI_ManifestDefaultsServiceAccount(t *testing.T) {
	h := newK8sSetupHarness(t)
	if !strings.Contains(h.get("/k8s/setup").Body.String(), `name="sa_namespace"`) {
		t.Error("setup page without a profile has no sa_namespace input")
	}
	h.setAPIPolicy()
	prof := h.setProfile("web")
	want, err := k8s.RBACManifest(prof.Namespaces, k8s.ServiceAccountRef{Namespace: "tagcess", Name: k8s.DefaultServiceAccountName})
	if err != nil {
		t.Fatalf("RBACManifest: %v", err)
	}
	rec := h.get("/k8s/setup/manifest")
	if rec.Code != http.StatusOK || rec.Body.String() != string(want) {
		t.Fatalf("manifest without parameters = %d, want the default-ServiceAccount manifest", rec.Code)
	}
	// Control: an explicit namespace still wins.
	other := h.get("/k8s/setup/manifest?sa_namespace=ops")
	if other.Code != http.StatusOK || !strings.Contains(other.Body.String(), "ops") {
		t.Fatalf("manifest with sa_namespace=ops = %d", other.Code)
	}
}

// F5 G1: the setup page names the next step with a link, in the order the stores need it:
// API policy, connection profile, credential.
func TestK8sSetupUI_NamesTheNextStep(t *testing.T) {
	h := newK8sSetupHarness(t)
	page := func() string { return html.UnescapeString(h.get("/k8s/setup").Body.String()) }
	if got := page(); !strings.Contains(got, "Sıradaki adım") || !strings.Contains(got, "API IP policy'si") {
		t.Errorf("fresh install: want the API policy as the next step")
	}
	h.setAPIPolicy()
	if got := page(); !strings.Contains(got, `href="/k8s/connection"`) || !strings.Contains(got, "bağlantı profilini") {
		t.Errorf("API policy set: want the connection profile as the next step")
	}
	h.setProfile("web")
	if got := page(); !strings.Contains(got, "credential") || strings.Contains(got, "bağlantı profilini kaydedin") {
		t.Errorf("profile set: want the credential as the next step")
	}
}

// F5 I4: a saved policy triggers the monitoring loops; a refused one does not.
func TestK8sSetupUI_PolicySaveTriggersLoops(t *testing.T) {
	h := newK8sSetupHarness(t)
	if rec := h.post("/k8s/setup/policy", url.Values{"scope": {"probe"}, "addresses": {"not-an-ip"}, "ports": {"443"}}); rec.Code == http.StatusOK {
		t.Fatalf("invalid policy accepted")
	}
	if got := h.saved.Load(); got != 0 {
		t.Fatalf("OnSaved after a refused policy = %d, want 0", got)
	}
	if rec := h.post("/k8s/setup/policy", url.Values{"scope": {"probe"}, "addresses": {"10.0.0.0/8"}, "ports": {"443"}}); rec.Code != http.StatusOK {
		t.Fatalf("policy POST = %d, body %s", rec.Code, rec.Body.String())
	}
	if got := h.saved.Load(); got != 1 {
		t.Fatalf("OnSaved after a saved policy = %d, want 1", got)
	}
}
