package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/alert"
	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/k8s"
	"github.com/nesiler/tagcess/internal/maintenance"
	"github.com/nesiler/tagcess/internal/monitor"
	"github.com/nesiler/tagcess/internal/netpolicy"
	"github.com/nesiler/tagcess/internal/site"
	"github.com/nesiler/tagcess/internal/store"
	"github.com/nesiler/tagcess/internal/store/db"
	"github.com/nesiler/tagcess/internal/web"
)

// The F4-031 wiring tests below run the real composition (buildF4, newUIHandler) against a stand-in
// Kubernetes API behind the real API address policy: the guard only swaps the resolver and the dial
// target, so every request still goes through netpolicy.

const (
	labHost    = "app.example.test"
	labToken   = "lab-token-new"
	labOldTok  = "lab-token-old"
	labAPIIP   = "10.20.0.5"
	labAPIPort = 6443
)

type labResolver struct{}

func (labResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr(labAPIIP)}, nil
}

// shiftedConn reports the checked API address as the remote one, so the guard accepts the stand-in.
type shiftedConn struct {
	net.Conn
	remote net.Addr
}

func (c shiftedConn) RemoteAddr() net.Addr { return c.remote }

type f4Lab struct {
	t        *testing.T
	st       *store.Store
	srv      *httptest.Server
	allow    atomic.Bool  // lists are answered; otherwise 403 (TLS and token still fine)
	lists    atomic.Int32 // list requests that reached the API
	f        *f4
	profiles *k8s.ProfileStore
	creds    *k8s.CredentialStore
	cred     k8s.Credential
	h        http.Handler
}

func labIngressJSON(t *testing.T) []byte {
	t.Helper()
	ing := k8s.Ingress{Metadata: k8s.ObjectMeta{Name: "app", Namespace: "web", UID: "uid-app", ResourceVersion: "1",
		Annotations: map[string]string{"traefik.ingress.kubernetes.io/router.entrypoints": "websecure"}}}
	ing.Spec.IngressClassName = "traefik"
	ing.Spec.Rules = []k8s.IngressRule{{Host: labHost, HTTP: &k8s.HTTPRuleValue{Paths: []k8s.HTTPPath{{
		Path: "/", PathType: "Prefix",
		Backend: k8s.IngressBackend{Service: &k8s.ServiceBackend{Name: "app", Port: k8s.ServiceBackendPort{Number: 8080}}},
	}}}}}
	b, err := json.Marshal(ing)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// newF4Lab builds the composition with one profile, one stored credential and the given sites.
func newF4Lab(t *testing.T, fk f4Fakes) *f4Lab {
	t.Helper()
	l := &f4Lab{t: t, st: openF4Store(t)}
	l.allow.Store(true)
	ingress := labIngressJSON(t)
	class, _ := json.Marshal(map[string]any{"metadata": map[string]any{"name": "traefik", "uid": "uid-class"}, "spec": map[string]any{"controller": "traefik.io/ingress-controller"}})
	l.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a := r.Header.Get("Authorization"); a != "Bearer "+labToken && a != "Bearer "+labOldTok {
			http.Error(w, `{"kind":"Status","code":401}`, http.StatusUnauthorized)
			return
		}
		l.lists.Add(1)
		if !l.allow.Load() {
			http.Error(w, `{"kind":"Status","code":403}`, http.StatusForbidden)
			return
		}
		var kind, item string
		switch {
		case strings.HasSuffix(r.URL.Path, "/ingressclasses"):
			kind, item = "IngressClassList", string(class)
		case strings.HasSuffix(r.URL.Path, "/ingresses"):
			kind, item = "IngressList", string(ingress)
		case strings.HasSuffix(r.URL.Path, "/services"):
			kind, item = "ServiceList", `{"metadata":{"name":"app","namespace":"web","uid":"uid-svc"},"spec":{"type":"ClusterIP","ports":[{"name":"http","port":8080}]}}`
		default:
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"kind":"` + kind + `","metadata":{},"items":[` + item + `]}`))
	}))
	l.srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	l.srv.StartTLS()
	t.Cleanup(l.srv.Close)

	pol := netpolicy.New(l.st.DB(), l.st.Queries())
	if err := pol.Set(context.Background(), netpolicy.ScopeAPI, netpolicy.Input{Addresses: []string{"10.20.0.0/24"}, Ports: []int{labAPIPort}}); err != nil {
		t.Fatalf("API policy: %v", err)
	}
	// The health cycle waits (monitor.ErrSetupPending) until the probe policy exists (F5 C2).
	if err := pol.Set(context.Background(), netpolicy.ScopeProbe, netpolicy.Input{Addresses: []string{"10.20.0.0/24"}, Ports: []int{443}}); err != nil {
		t.Fatalf("probe policy: %v", err)
	}
	backend := l.srv.Listener.Addr().String()
	guard := netpolicy.NewGuard(pol, labResolver{}, func(ctx context.Context, network, address string) (net.Conn, error) {
		c, err := (&net.Dialer{}).DialContext(ctx, network, backend)
		if err != nil {
			return nil, err
		}
		return shiftedConn{Conn: c, remote: net.TCPAddrFromAddrPort(netip.MustParseAddrPort(address))}, nil
	})

	in := newF4Inputs(t, l.st, fk)
	in.Cfg.K8sAuthDir = filepath.Join(t.TempDir(), "k8s")
	if err := os.Mkdir(in.Cfg.K8sAuthDir, 0o700); err != nil {
		t.Fatal(err)
	}
	in.K8sGuard = guard
	f, err := buildF4(in)
	if err != nil {
		t.Fatalf("buildF4: %v", err)
	}
	l.f = f
	l.h = newUIHandler(f.csrf, f.Pages)

	l.profiles = k8s.NewProfileStore(l.st.DB(), l.st.Queries(), pol, time.Now)
	l.creds = k8s.NewCredentialStore(in.Cfg.K8sAuthDir)
	endpoint := "https://" + net.JoinHostPort(labAPIIP, "6443")
	if err := l.profiles.Save(context.Background(), k8s.Profile{
		Endpoint: endpoint, TLSServerName: "example.com", Namespaces: []string{"web"},
		Controller: "traefik.io/ingress-controller", IngressClasses: []string{"traefik"},
		Internal: []k8s.Listener{{Address: "10.0.0.10", Port: 443, EntryPoint: "websecure-internal"}},
		Public:   []k8s.Listener{{Address: "203.0.113.10", Port: 443, EntryPoint: "websecure"}},
	}); err != nil {
		t.Fatalf("profile: %v", err)
	}
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: l.srv.Certificate().Raw}))
	l.cred = k8s.Credential{Endpoint: endpoint, TLSServerName: "example.com", CAData: ca, Token: labOldTok}
	if _, err := l.creds.Replace(l.cred); err != nil {
		t.Fatalf("credential: %v", err)
	}
	return l
}

func labSite() site.Site {
	return site.Site{ID: 1, Hosts: []string{labHost}, Kind: site.KindRole, Roles: []string{"developer"}}
}

// post sends a form to the full UI chain.
func (l *f4Lab) post(path string, form url.Values, groups string, csrf bool) *httptest.ResponseRecorder {
	return postForm(l.h, l.f.csrf, path, form, groups, csrf)
}

func postForm(h http.Handler, c *web.CSRF, path string, form url.Values, groups string, withCSRF bool) *httptest.ResponseRecorder {
	if form == nil {
		form = url.Values{}
	}
	if withCSRF {
		form.Set(web.CSRFParam, c.Token())
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if groups != "" {
		req.Header.Set("X-Auth-Request-User", "dev")
		req.Header.Set("X-Auth-Request-Email", "dev@example.com")
		req.Header.Set("X-Auth-Request-Groups", groups)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func (l *f4Lab) credForm(token string) url.Values {
	return url.Values{
		"endpoint": {l.cred.Endpoint}, "tls_server_name": {l.cred.TLSServerName},
		"ca_data": {l.cred.CAData}, "token": {token},
	}
}

// AC5 (B-M-2a): the connection test of a credential upload really lists through the guarded client.
// A server that accepts TLS and the token but forbids lists refuses the upload and the previous
// credential stays; a listing server accepts it.
func TestF4ConnectorRefusesTokenThatCannotList(t *testing.T) {
	l := newF4Lab(t, f4Fakes{})
	l.allow.Store(false)
	rec := l.post("/k8s/connection/credential", l.credForm(labToken), "devops", true)
	if rec.Code == http.StatusOK {
		t.Fatalf("upload of a token that cannot list = 200, want a refusal")
	}
	if l.lists.Load() == 0 {
		t.Error("no list request reached the API: the connection test did not read anything")
	}
	got, err := l.creds.Load()
	if err != nil || got.Token != labOldTok {
		t.Fatalf("credential after refused upload = token %q, %v; want the previous one untouched", got.Token, err)
	}

	l.allow.Store(true)
	rec = l.post("/k8s/connection/credential", l.credForm(labToken), "devops", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("upload with a listing API = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if got, err := l.creds.Load(); err != nil || got.Token != labToken {
		t.Fatalf("credential after accepted upload = token %q, %v; want the new one", got.Token, err)
	}
}

// AC6 (B-M-2b): every F4 POST route is behind RequireDevops(csrf.Protect(...)).
func TestF4PostRoutesNeedDevopsAndCSRF(t *testing.T) {
	l := newF4Lab(t, f4Fakes{sites: []site.Site{labSite()}})
	routes := []string{
		"/k8s/connection/profile", "/k8s/connection/credential", "/k8s/setup/review", "/k8s/setup/policy",
		"/monitor/settings", "/alerts/ack", "/alerts/maintenance",
		"/k8s/drafts/" + labHost, "/k8s/drafts/" + labHost + "/refresh",
	}
	for _, path := range routes {
		cases := []struct {
			name   string
			groups string
			csrf   bool
		}{
			{"no identity", "", true},
			{"not devops", "staff", true},
			{"no csrf token", "devops", false},
		}
		for _, c := range cases {
			if got := l.post(path, nil, c.groups, c.csrf).Code; got != http.StatusForbidden {
				t.Errorf("POST %s (%s) = %d, want 403", path, c.name, got)
			}
		}
		// Positive control: the same request as devops with the token is not stopped by the chain.
		if got := l.post(path, nil, "devops", true).Code; got == http.StatusForbidden {
			t.Errorf("POST %s as devops with CSRF = 403: the control is blocked for another reason", path)
		}
	}
}

// AC9 (C-L10): a request from outside the trusted proxy chain (no identity, or not devops) is refused
// on the discovery screen and the draft routes.
func TestF4DiscoveryRefusesUntrustedSource(t *testing.T) {
	l := newF4Lab(t, f4Fakes{sites: []site.Site{labSite()}})
	for _, target := range []string{"/k8s/discovery", "/k8s/drafts/" + labHost} {
		rec := httptest.NewRecorder()
		l.h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, nil))
		if rec.Code != http.StatusForbidden {
			t.Errorf("GET %s without identity = %d, want 403", target, rec.Code)
		}
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
		req.Header.Set("X-Auth-Request-User", "dev")
		req.Header.Set("X-Auth-Request-Email", "dev@example.com")
		req.Header.Set("X-Auth-Request-Groups", "staff")
		rec = httptest.NewRecorder()
		l.h.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("GET %s as non-devops = %d, want 403", target, rec.Code)
		}
	}
	if got := devopsGet(l.h, "/k8s/discovery").Code; got != http.StatusOK {
		t.Errorf("GET /k8s/discovery as devops = %d, want 200", got)
	}
}

// publish stores the current snapshot through the real reader.
func (l *f4Lab) publish() {
	l.t.Helper()
	if _, err := l.f.reader.Read(context.Background()); err != nil {
		l.t.Fatalf("snapshot read: %v", err)
	}
}

// AC7 (B-M-2c): the two-gate candidates come from EvaluateGates over the site records and the
// snapshot, each is recorded as a config_risk row every cycle, and the dashboard card shows it. A
// measurement cycle never clears it.
func TestF4TwoGateRiskRecordedAndKeptByMeasurement(t *testing.T) {
	l := newF4Lab(t, f4Fakes{sites: []site.Site{labSite()}})
	l.publish()
	ctx := context.Background()

	cands, err := l.f.candidates(ctx)
	if err != nil || len(cands) == 0 {
		t.Fatalf("candidates = %v, %v; want the wrong-entrypoint exposure of %s", cands, err, labHost)
	}
	risk := func() int {
		rows, err := l.st.Queries().ListObservationsBySite(ctx, labHost)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, r := range rows {
			if r.Category == "config_risk" {
				n++
			}
		}
		return n
	}
	if risk() == 0 {
		t.Fatal("no config_risk observation after the candidates were built: RecordRisk is not called")
	}

	// A full measurement cycle (the runner measures every candidate) leaves the risk in place.
	runCycles(t, l.f, 1)
	if risk() == 0 {
		t.Error("config_risk row gone after a measurement cycle")
	}
	body := devopsGet(l.h, "/").Body.String()
	if !strings.Contains(body, `data-two-gate="risk"`) {
		t.Error("dashboard two-gate card shows no risk group for the exposure")
	}
}

// runCycles runs the real runner until n cycles were reported to the loops, then stops it.
func runCycles(t *testing.T, f *f4, n int) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = f.runner.Run(ctx); close(done) }()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if st := healthStatus(f); !st.LastAttempt.IsZero() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	_ = n
}

func healthStatus(f *f4) monitor.JobStatus {
	for _, st := range f.loops.Status() {
		if st.Job == monitor.JobHealth {
			return st
		}
	}
	return monitor.JobStatus{}
}

// AC8 (B-M-2d): the discovery screen shows the routes of the stored snapshot; without a current
// snapshot it shows unknown, and after a failed read the stale notice, never current data.
func TestF4DiscoveryFromSnapshotAndStale(t *testing.T) {
	l := newF4Lab(t, f4Fakes{sites: []site.Site{labSite()}})
	before := devopsGet(l.h, "/k8s/discovery").Body.String()
	if !strings.Contains(before, "Başarılı tarama yok.") || strings.Contains(before, "eşleşti") ||
		!strings.Contains(before, "Tarama eksik") {
		t.Errorf("discovery without a snapshot does not show unknown: %s", before)
	}

	l.publish()
	body := devopsGet(l.h, "/k8s/discovery").Body.String()
	if !strings.Contains(body, "eşleşti") || strings.Contains(body, "Tarama eksik") {
		t.Errorf("discovery does not show the route of the fixture snapshot as matched: %s", body)
	}
	if strings.Contains(body, "Güncel değil: son tarama başarısız") {
		t.Error("a fresh snapshot is shown stale")
	}

	l.allow.Store(false)
	if _, err := l.f.reader.Read(context.Background()); err == nil {
		t.Fatal("read of a forbidding API succeeded")
	}
	if body := devopsGet(l.h, "/k8s/discovery").Body.String(); !strings.Contains(body, "Güncel değil: son tarama başarısız") {
		t.Errorf("discovery after a failed read does not say stale: %s", body)
	}
}

// AC10 (fix-1 hand-over a): the runner's cycle report reaches the health job. A failed cycle shows
// an error, a good one fresh.
func TestF4HealthCycleReportReachesLoops(t *testing.T) {
	bad := newF4Lab(t, f4Fakes{down: true}) // the site list cannot be read: the cycle fails
	runCycles(t, bad.f, 1)
	if st := healthStatus(bad.f); st.Err == nil || st.State == monitor.StateFresh {
		t.Errorf("health job after a failed cycle = %+v, want an error and not fresh", st)
	}

	good := newF4Lab(t, f4Fakes{sites: []site.Site{labSite()}})
	good.publish()
	runCycles(t, good.f, 1)
	if st := healthStatus(good.f); st.State != monitor.StateFresh || st.Err != nil {
		t.Errorf("health job after a good cycle = %+v, want fresh", st)
	}
}

// AC11 (fix-1 hand-over b): the dashboard judges a row against the saved monitor interval: with a
// one-hour interval a 30-minute-old success is fresh and a 3-hour-old one is stale (2x interval).
func TestF4DashboardUsesSavedIntervalForFreshness(t *testing.T) {
	for _, tc := range []struct {
		age  time.Duration
		want string
	}{{30 * time.Minute, "fresh"}, {3 * time.Hour, "stale"}} {
		l := newF4Lab(t, f4Fakes{sites: []site.Site{labSite()}})
		ctx := context.Background()
		s, err := l.f.settingsStore.Get(ctx)
		if err != nil {
			t.Fatal(err)
		}
		s.TargetInterval = time.Hour
		if err := l.f.settingsStore.Set(ctx, s); err != nil {
			t.Fatal(err)
		}
		at := time.Now().Add(-tc.age).UTC().Format(obsTimeLayout)
		if _, err := l.st.Queries().UpsertObservationGood(ctx, db.UpsertObservationGoodParams{
			Category: "target", Site: labHost, Host: labHost, Source: "probe", Vantage: probeVantage,
			Endpoint: "10.1.1.1:80", Path: "/", ObservedAt: at, HttpStatus: 200, LastAttemptAt: at,
		}); err != nil {
			t.Fatal(err)
		}
		want := `<tr data-freshness="` + tc.want + `" data-source="probe"><td>` + labHost
		if body := devopsGet(l.h, "/").Body.String(); !strings.Contains(body, want) {
			t.Errorf("row %v old with a 1h interval: dashboard lacks %q", tc.age, want)
		}
	}
}

// AC12 (fix-1 hand-over d): the drift check holds while the site writer lock is held, and f4Hold
// also holds for an open or unreadable H-07 maintenance.
func TestF4DriftHoldsWhileWriterLockHeld(t *testing.T) {
	l := newF4Lab(t, f4Fakes{down: true})
	if _, err := l.f.drift.Check(context.Background()); err == nil {
		t.Fatal("control: a drift check over down sources returned no error")
	}
	var findings []alert.DriftFinding
	var err error
	_ = change.WithWriterLock(func() error {
		findings, err = l.f.drift.Check(context.Background())
		return nil
	})
	if err != nil || len(findings) == 0 {
		t.Fatalf("drift check under the writer lock = %v, %v; want uncertain findings", findings, err)
	}
	for _, f := range findings {
		if f.Status != alert.DriftUncertain {
			t.Errorf("%s = %v under the writer lock, want uncertain", f.Subject, f.Status)
		}
	}

	ctx := context.Background()
	for name, tc := range map[string]struct {
		m    fakeMaint
		hold bool
	}{
		"off":        {fakeMaint{st: maintenance.Off}, false},
		"active":     {fakeMaint{st: maintenance.Active}, true},
		"reconcile":  {fakeMaint{st: maintenance.ReconcilePending}, true},
		"unreadable": {fakeMaint{err: errF4Down}, true},
	} {
		got, err := f4Hold(tc.m)(ctx)
		if got != tc.hold {
			t.Errorf("f4Hold(%s) = %v, want %v", name, got, tc.hold)
		}
		if (err != nil) != (name == "unreadable") {
			t.Errorf("f4Hold(%s) err = %v, want an error only for unreadable", name, err)
		}
	}
}

type fakeMaint struct {
	st  maintenance.State
	err error
}

func (m fakeMaint) Get(context.Context) (maintenance.Status, error) {
	return maintenance.Status{State: m.st}, m.err
}

// AC13 (fix-1 hand-over c): the dashboard alert carries the alert's source key.
func TestF4OpenAlertsFillSource(t *testing.T) {
	l := newF4Lab(t, f4Fakes{})
	ctx := context.Background()
	if _, err := l.f.alerts.RecordSource(ctx, alert.SourceSample{Subject: "sync", Source: "sync_runs", Failed: true, SampleID: "s1"}); err != nil {
		t.Fatal(err)
	}
	got, err := f4OpenAlerts{l.f.alerts, time.Now}.OpenAlerts(ctx)
	if err != nil || len(got.Alerts) == 0 {
		t.Fatalf("OpenAlerts = %+v, %v; want the recorded alert", got, err)
	}
	if got.Alerts[0].Source != "sync_runs" {
		t.Errorf("dashboard alert source = %q, want sync_runs", got.Alerts[0].Source)
	}
}

// M2/L4 in the binary: a drift check that cannot compare (held, or local state unreadable) never
// leaves the drift card saying "Açık drift uyarısı yok"; the loops block is on the page.
func TestF4DashboardDriftCardNeverSaysCleanWhenNotCompared(t *testing.T) {
	l := newF4Lab(t, f4Fakes{})
	ctx := context.Background()

	// Unreadable local state (the fakes' first-import read fails): recorded as uncertain.
	if _, err := l.f.drift.Check(ctx); err == nil {
		t.Fatal("control: drift check over an unreadable site store returned no error")
	}
	body := devopsGet(l.h, "/").Body.String()
	if strings.Contains(body, "Açık drift uyarısı yok") || !strings.Contains(body, "bilinmiyor/temel yok") {
		t.Errorf("unreadable site state: the drift card reads clean:\n%s", body)
	}

	// Held by the writer lock: quiet, but the card says so.
	l2 := newF4Lab(t, f4Fakes{})
	_ = change.WithWriterLock(func() error {
		if _, err := l2.f.drift.Check(ctx); err != nil {
			t.Errorf("held drift check = %v, want nil", err)
		}
		return nil
	})
	body = devopsGet(l2.h, "/").Body.String()
	if strings.Contains(body, "Açık drift uyarısı yok") || !strings.Contains(body, "karşılaştırma bekletiliyor (bakım/apply)") {
		t.Errorf("held drift check: the drift card reads clean or lacks the hold line:\n%s", body)
	}
	if !strings.Contains(body, `data-card="loops"`) {
		t.Error("the dashboard has no loops block")
	}
}

// otherEndpoint is a second API address inside the same API policy as the profile's endpoint.
const otherEndpoint = "https://10.20.0.99:6443"

// M4 (A-M2 in the binary): a credential whose endpoint differs from the profile never sends its
// token anywhere, although both endpoints are inside the API policy. The stand-in API sees nothing.
func TestF4ReviewRefusesCredentialForAnotherEndpoint(t *testing.T) {
	l := newF4Lab(t, f4Fakes{})
	other := l.cred
	other.Endpoint = otherEndpoint
	if _, err := l.creds.Replace(other); err != nil {
		t.Fatalf("store the mismatching credential: %v", err)
	}
	rec := l.post("/k8s/setup/review", nil, "devops", true)
	if body := rec.Body.String(); !strings.Contains(body, "differs from the profile") {
		t.Fatalf("review with a mismatching credential: want the mismatch error, got %d:\n%s", rec.Code, body)
	}
	if n := l.lists.Load(); n != 0 {
		t.Fatalf("the stand-in API got %d requests from a credential the profile does not name, want 0", n)
	}

	// Positive control: the matching credential reaches the API.
	if _, err := l.creds.Replace(l.cred); err != nil {
		t.Fatal(err)
	}
	l.post("/k8s/setup/review", nil, "devops", true)
	if l.lists.Load() == 0 {
		t.Error("control: a matching credential did not reach the API; the zero above proves nothing")
	}
}

// M4: the connection test of a credential candidate goes through the profile check as well.
func TestF4ConnectorRefusesCandidateForAnotherEndpoint(t *testing.T) {
	l := newF4Lab(t, f4Fakes{})
	form := l.credForm(labToken)
	form.Set("endpoint", otherEndpoint)
	rec := l.post("/k8s/connection/credential", form, "devops", true)
	if rec.Code == http.StatusOK {
		t.Fatalf("upload of a candidate for another endpoint = 200, want a refusal")
	}
	if !strings.Contains(rec.Body.String(), "differs from the profile") {
		t.Errorf("want the mismatch error in the refusal:\n%s", rec.Body.String())
	}
	if n := l.lists.Load(); n != 0 {
		t.Fatalf("the stand-in API got %d requests from the candidate, want 0", n)
	}
	if got, err := l.creds.Load(); err != nil || got.Token != labOldTok {
		t.Fatalf("stored credential after the refused candidate = %q, %v; want the previous one", got.Token, err)
	}
}

// L2 in the binary: without k8s_auth_dir the connection page shows the setup error and nothing is
// created under data_dir.
func TestF4EmptyCredentialDirIsNotDefaultedIntoDataDir(t *testing.T) {
	in := newF4Inputs(t, openF4Store(t), f4Fakes{})
	f, err := buildF4(in)
	if err != nil {
		t.Fatalf("buildF4: %v", err)
	}
	h := newUIHandler(f.csrf, f.Pages)
	body := devopsGet(h, "/k8s/connection").Body.String()
	if !strings.Contains(body, "k8s_auth_dir ayarlanmamış") {
		t.Errorf("connection page lacks the setup error:\n%s", body)
	}
	if strings.Contains(body, in.Cfg.DataDir) {
		t.Error("the connection page names a path")
	}
	if _, err := os.Stat(filepath.Join(in.Cfg.DataDir, "k8s")); err == nil {
		t.Error("<data_dir>/k8s exists: the credential directory was defaulted into data_dir")
	}
}

// countedBody counts the bytes a handler pulled from the request body.
type countedBody struct {
	io.Reader
	n *atomic.Int64
}

func (b countedBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	b.n.Add(int64(n))
	return n, err
}

func (countedBody) Close() error { return nil }

// L3 (B-M1): the generic body cap of csrf.Protect covers the routes that have no cap of their own.
// A header-token POST of more than 2 MiB is refused and changes nothing: the settings keep their
// value, and the setup policy stays as it was. A declared length is answered 413; an undeclared one
// (chunked) is cut off by the reader after the cap.
func TestF4OversizeHeaderTokenPostIsRefusedWithoutEffect(t *testing.T) {
	l := newF4Lab(t, f4Fakes{sites: []site.Site{labSite()}})
	ctx := context.Background()
	before, err := l.f.settingsStore.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pad := strings.Repeat("a", 3<<20)
	const capBytes = 2 << 20
	for _, tc := range []struct {
		path string
		form url.Values
	}{
		{"/monitor/settings", url.Values{"path": {"/x"}, "pad": {pad}}},
		{"/alerts/ack", url.Values{"id": {"1"}, "pad": {pad}}},
		{"/alerts/maintenance", url.Values{"site": {labHost}, "pad": {pad}}},
		{"/k8s/setup/policy", url.Values{"scope": {"api"}, "addresses": {"10.99.0.0/24"}, "ports": {"6443"}, "pad": {pad}}},
		{"/k8s/drafts/" + labHost, url.Values{"pad": {pad}}},
	} {
		send := func(chunked bool) (int, int64) {
			var read atomic.Int64
			req := httptest.NewRequestWithContext(ctx, http.MethodPost, tc.path, strings.NewReader(tc.form.Encode()))
			if chunked {
				req.Body = countedBody{Reader: strings.NewReader(tc.form.Encode()), n: &read}
				req.ContentLength = -1
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set(web.CSRFHeader, l.f.csrf.Token())
			req.Header.Set("X-Auth-Request-User", "dev")
			req.Header.Set("X-Auth-Request-Email", "dev@example.com")
			req.Header.Set("X-Auth-Request-Groups", "devops")
			rec := httptest.NewRecorder()
			l.h.ServeHTTP(rec, req)
			return rec.Code, read.Load()
		}
		if code, _ := send(false); code != http.StatusRequestEntityTooLarge {
			t.Errorf("POST %s with a declared >2 MiB body = %d, want 413", tc.path, code)
		}
		code, read := send(true)
		if code == http.StatusOK || code == http.StatusSeeOther {
			t.Errorf("POST %s with an undeclared >2 MiB body = %d, want a refusal", tc.path, code)
		}
		if read > capBytes+4096 {
			t.Errorf("POST %s: the handler read %d body bytes, cap is %d", tc.path, read, capBytes)
		}
	}
	after, err := l.f.settingsStore.Get(ctx)
	if err != nil || !reflect.DeepEqual(after, before) {
		t.Errorf("settings after the oversize POSTs = %+v, %v; want %+v unchanged", after, err, before)
	}
	pol, err := netpolicy.New(l.st.DB(), l.st.Queries()).Get(ctx, netpolicy.ScopeAPI)
	if err != nil || len(pol.Addresses) != 1 || pol.Addresses[0] != "10.20.0.0/24" {
		t.Errorf("API policy after the oversize POSTs = %+v, %v; want the original", pol, err)
	}
}
