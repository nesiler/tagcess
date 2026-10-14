package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/alert"
	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/config"
	"github.com/nesiler/tagcess/internal/headscale"
	"github.com/nesiler/tagcess/internal/headscale/admin"
	"github.com/nesiler/tagcess/internal/health"
	"github.com/nesiler/tagcess/internal/k8s"
	"github.com/nesiler/tagcess/internal/monitor"
	"github.com/nesiler/tagcess/internal/netpolicy"
	"github.com/nesiler/tagcess/internal/site"
	"github.com/nesiler/tagcess/internal/store"
	"github.com/nesiler/tagcess/internal/web"
)

// f4Fakes are the external surfaces of the F4 composition. Every read fails when down is set;
// writes do not exist on these types, so the counters below prove no access write is reachable.
type f4Fakes struct {
	down  bool
	sites []site.Site
}

var errF4Down = errors.New("source down")

func (f f4Fakes) ListNodes(context.Context) ([]admin.AdminNode, error) {
	if f.down {
		return nil, errF4Down
	}
	return []admin.AdminNode{{Name: "laptop", UserName: "ali", Online: true}}, nil
}

func (f f4Fakes) ListRoles(context.Context) ([]string, error) {
	if f.down {
		return nil, errF4Down
	}
	return []string{"developer"}, nil
}

func (f f4Fakes) GetPolicy(context.Context) (headscale.Policy, error) {
	return headscale.Policy{}, errF4Down
}

func (f f4Fakes) Current(context.Context) (string, error) { return "", errF4Down }
func (f f4Fakes) Live(context.Context) ([]byte, error)    { return nil, errF4Down }
func (f f4Fakes) AdaptJSON(context.Context, string) ([]byte, error) {
	return nil, errF4Down
}
func (f4Fakes) CurrentDNS(context.Context) (string, bool, error) { return "", false, errF4Down }
func (f f4Fakes) Redirects(context.Context) ([]string, error)    { return nil, errF4Down }
func (f f4Fakes) Owned(context.Context) ([]string, bool, error)  { return nil, false, errF4Down }
func (f f4Fakes) FirstImportPending(context.Context) (bool, error) {
	return false, errF4Down
}
func (f f4Fakes) ListSites(context.Context) ([]site.Site, error) {
	if f.down {
		return nil, errF4Down
	}
	return f.sites, nil
}
func (f f4Fakes) ListTargets(context.Context) ([]string, error) { return nil, nil }

type dnsFake struct{ f4Fakes }

func (dnsFake) Current(context.Context) (string, bool, error) { return "", false, errF4Down }

func newF4Inputs(t *testing.T, st *store.Store, fk f4Fakes) f4Inputs {
	t.Helper()
	csrf, err := web.NewCSRF([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("NewCSRF: %v", err)
	}
	return f4Inputs{
		Cfg:      &config.Config{DataDir: t.TempDir()},
		Store:    st,
		CSRF:     csrf,
		Auditor:  audit.New(st.Queries()),
		Sites:    fk,
		Targets:  fk,
		Nodes:    fk,
		Roles:    fk,
		Policy:   fk,
		Caddy:    fk,
		DNS:      dnsFake{fk},
		URIs:     fk,
		Settings: func(context.Context) (change.SiteSettings, error) { return change.SiteSettings{}, nil },
	}
}

func openF4Store(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func devopsGet(h http.Handler, target string) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	req.Header.Set("X-Auth-Request-User", "dev")
	req.Header.Set("X-Auth-Request-Email", "dev@example.com")
	req.Header.Set("X-Auth-Request-Groups", "devops")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// AC1: the root dashboard and the F4 pages are mounted in the devops-protected mux and the old
// pages keep working.
func TestF4RoutesRegisteredWithExistingPages(t *testing.T) {
	st := openF4Store(t)
	f, err := buildF4(newF4Inputs(t, st, f4Fakes{}))
	if err != nil {
		t.Fatalf("buildF4: %v", err)
	}
	pages := f.Pages
	pages.Audit = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	h := newUIHandler(f.csrf, pages)

	for _, target := range []string{"/", "/alerts", "/monitor/settings", "/k8s/discovery", "/k8s/connection", "/k8s/setup"} {
		if got := devopsGet(h, target).Code; got != http.StatusOK {
			t.Errorf("GET %s as devops = %d, want 200", target, got)
		}
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("GET %s without identity = %d, want 403", target, rec.Code)
		}
	}
	if got := devopsGet(h, "/audit").Code; got != http.StatusTeapot {
		t.Errorf("existing /audit page = %d, want it still served", got)
	}
	if got := devopsGet(h, "/no-such-page").Code; got != http.StatusNotFound {
		t.Errorf("unknown path = %d, want 404 (the dashboard owns only the exact root)", got)
	}
}

type fakeLoops struct {
	mu      sync.Mutex
	runs    int
	stopped int
	started chan struct{}
}

func (f *fakeLoops) Run(ctx context.Context) error {
	f.mu.Lock()
	f.runs++
	f.mu.Unlock()
	f.started <- struct{}{}
	<-ctx.Done()
	f.mu.Lock()
	f.stopped++
	f.mu.Unlock()
	return ctx.Err()
}

// AC2: the existing start callback starts the ready loop service exactly once and the loop
// configuration carries live getters; no reconcile/apply callback exists in it.
func TestF4RuntimeStartsReadyLoopsOnce(t *testing.T) {
	loops := &fakeLoops{started: make(chan struct{}, 2)}
	rt := newF4Runtime(loops)
	rt.Start(context.Background())
	rt.Start(context.Background())
	<-loops.started
	rt.Stop()

	if loops.runs != 1 {
		t.Errorf("loops started %d times, want 1", loops.runs)
	}

	// The getters are live: a changed setting and a saved profile are seen without a restart.
	st := openF4Store(t)
	in := newF4Inputs(t, st, f4Fakes{})
	f, err := buildF4(in)
	if err != nil {
		t.Fatalf("buildF4: %v", err)
	}
	cfg := f.loopsConfig
	if err := cfg.ProfileReady(context.Background()); !errors.Is(err, k8s.ErrNotSet) {
		t.Fatalf("ProfileReady before any profile = %v, want k8s.ErrNotSet", err)
	}
	s, err := cfg.Settings(context.Background())
	if err != nil {
		t.Fatalf("Settings: %v", err)
	}
	s.TargetInterval = 90 * time.Second
	if err := f.settingsStore.Set(context.Background(), s); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := cfg.Settings(context.Background())
	if err != nil || got.TargetInterval != 90*time.Second {
		t.Errorf("Settings after UI change = %v, %v, want 90s", got.TargetInterval, err)
	}
}

// AC3: without a k8s profile or with unreadable sources the UI stays up, shows the missing/stale
// state and nothing is written to access.
func TestF4RuntimeMissingSourceKeepsAccess(t *testing.T) {
	st := openF4Store(t)
	f, err := buildF4(newF4Inputs(t, st, f4Fakes{down: true}))
	if err != nil {
		t.Fatalf("buildF4: %v", err)
	}
	h := newUIHandler(f.csrf, f.Pages)
	rec := devopsGet(h, "/")
	if rec.Code != http.StatusOK {
		t.Fatalf("dashboard with down sources = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "bilinmiyor") {
		t.Error("dashboard does not show the unknown state of the unreadable sources")
	}

	cfg := f.loopsConfig
	invCalls := 0
	cfg.Inventory = func(context.Context) error { invCalls++; return nil }
	cfg.Health = idleHealth{}
	loops, err := monitor.NewLoops(cfg)
	if err != nil {
		t.Fatalf("NewLoops: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = loops.Run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if loops.Status()[0].State == monitor.StateMissing {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if got := loops.Status()[0]; got.State != monitor.StateMissing {
		t.Errorf("inventory state = %q, want missing", got.State)
	}
	if invCalls != 0 {
		t.Errorf("inventory read ran %d times without a profile", invCalls)
	}
}

type idleHealth struct{}

func (idleHealth) Run(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }

// AC4: stop calls the loop stop once and a restarted composition reads the same persistent
// snapshots and alerts.
func TestF4RuntimeStopAndRestart(t *testing.T) {
	loops := &fakeLoops{started: make(chan struct{}, 2)}
	rt := newF4Runtime(loops)
	rt.Start(context.Background())
	<-loops.started
	rt.Stop()
	rt.Stop()
	if loops.stopped != 1 {
		t.Errorf("loops stopped %d times, want 1", loops.stopped)
	}

	st := openF4Store(t)
	first, err := buildF4(newF4Inputs(t, st, f4Fakes{}))
	if err != nil {
		t.Fatalf("buildF4 #1: %v", err)
	}
	if _, err := first.alerts.RecordSource(context.Background(), alert.SourceSample{
		Subject: "sync", Source: "sync_runs", Failed: true, SampleID: "s1",
	}); err != nil {
		t.Fatalf("RecordSource: %v", err)
	}
	second, err := buildF4(newF4Inputs(t, st, f4Fakes{}))
	if err != nil {
		t.Fatalf("buildF4 #2: %v", err)
	}
	list, err := second.alerts.List(context.Background())
	if err != nil || len(list) == 0 {
		t.Errorf("restarted composition alerts = %v, %v, want the persisted alert", list, err)
	}
	if _, err := second.reader.State(context.Background()); !errors.Is(err, k8s.ErrNotSet) {
		t.Errorf("restarted composition snapshot state = %v, want the persisted (empty) profile state", err)
	}
}

// I7: a managed site's own name and the VPN address are approved probe targets without a custom
// allowlist entry; any other name is still refused before a connection.
func TestProbeTargetsApproveManagedHostsOnly(t *testing.T) {
	st := openF4Store(t)
	fk := f4Fakes{sites: []site.Site{{Hosts: []string{"app.example.test"}}}}
	pt := probeTargets{custom: fk, sites: fk, vpnAddr: "100.64.0.1"}
	tr := health.New(pt, netpolicy.New(st.DB(), st.Queries()))

	for _, req := range []health.Request{
		{Host: "100.64.0.1", Port: 443, TLS: true, ServerName: "app.example.test"},
		{Host: "app.example.test", Port: 443},
	} {
		_, err := tr.Get(context.Background(), req)
		if errors.Is(err, health.ErrRejected) {
			t.Errorf("%+v: refused by the allowlist: %v", req, err)
		}
	}
	for _, req := range []health.Request{
		{Host: "evil.example.test", Port: 443},
		{Host: "100.64.0.1", Port: 443, ServerName: "evil.example.test"},
	} {
		if _, err := tr.Get(context.Background(), req); !errors.Is(err, health.ErrRejected) {
			t.Errorf("%+v: err = %v, want ErrRejected", req, err)
		}
	}
}

// F5 A2/C2: on a fresh install the dashboard lists the open steps in one box, the health cycle waits
// (ErrSetupPending) instead of probing, and no probe is refused; once the probe policy is saved the
// subjects are listed and the step is gone (positive control).
func TestF4SetupPendingFreshInstall(t *testing.T) {
	st := openF4Store(t)
	fk := f4Fakes{sites: []site.Site{{Hosts: []string{"app.example.test"}, Kind: site.KindOpen}}}
	f, err := buildF4(newF4Inputs(t, st, fk))
	if err != nil {
		t.Fatalf("buildF4: %v", err)
	}
	h := newUIHandler(f.csrf, f.Pages)
	body := devopsGet(h, "/").Body.String()
	for _, want := range []string{`data-setup-box="true"`, `data-setup-step="probe_policy"`, `data-setup-step="k8s_profile"`} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard lacks %s on a fresh install", want)
		}
	}

	setup := f4Setup{sites: fk, policy: netpolicy.New(st.DB(), st.Queries()), profiles: k8s.NewProfileStore(st.DB(), st.Queries(), netpolicy.New(st.DB(), st.Queries()), time.Now), creds: k8s.NewCredentialStore(t.TempDir())}
	subjects := f4Subjects(fk, "100.64.0.1", "", setup.probeReady)
	if _, err := subjects(context.Background()); !errors.Is(err, monitor.ErrSetupPending) {
		t.Fatalf("subjects without a probe policy = %v, want ErrSetupPending", err)
	}
	if err := setup.policy.Set(context.Background(), netpolicy.ScopeProbe, netpolicy.Input{Addresses: []string{"100.64.0.0/10"}, Ports: []int{443}}); err != nil {
		t.Fatalf("set probe policy: %v", err)
	}
	got, err := subjects(context.Background())
	if err != nil || len(got) != 1 {
		t.Fatalf("subjects with a probe policy = %v, %v, want one subject", got, err)
	}
	for _, step := range setup.Pending(context.Background()) {
		if step.Key == web.SetupProbePolicy {
			t.Error("the probe policy step is still pending after it was saved")
		}
	}
}

// F5 C3: a wireguard_ui system site whose switch is off renders no Caddy block, so nothing is
// probed or alerted for it; an enabled one is measured like any other site (positive control).
func TestF4SubjectsSkipDisabledWireGuardSite(t *testing.T) {
	wg := func(enabled bool) site.Site {
		return site.Site{
			Hosts: []string{"wg.example.test"}, Kind: site.KindSystem, SystemTemplate: site.TemplateWireGuardUI,
			SystemConfig: `{"enabled":` + map[bool]string{true: "true", false: "false"}[enabled] + `}`, TargetKind: site.TargetK8s,
		}
	}
	other := site.Site{Hosts: []string{"app.example.test"}, Kind: site.KindOpen, TargetKind: site.TargetK8s}
	for _, tc := range []struct {
		enabled bool
		want    int
	}{{false, 1}, {true, 2}} {
		got, err := f4Subjects(f4Fakes{sites: []site.Site{wg(tc.enabled), other}}, "100.64.0.1", "", nil)(context.Background())
		if err != nil || len(got) != tc.want {
			t.Errorf("enabled=%v: subjects = %d (%v), want %d", tc.enabled, len(got), err, tc.want)
		}
	}
}
