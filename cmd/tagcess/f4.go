package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/nesiler/tagcess/internal/alert"
	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/config"
	"github.com/nesiler/tagcess/internal/dashboard"
	"github.com/nesiler/tagcess/internal/headscale/admin"
	"github.com/nesiler/tagcess/internal/health"
	"github.com/nesiler/tagcess/internal/k8s"
	"github.com/nesiler/tagcess/internal/maintenance"
	"github.com/nesiler/tagcess/internal/monitor"
	"github.com/nesiler/tagcess/internal/netpolicy"
	caddyrender "github.com/nesiler/tagcess/internal/render"
	"github.com/nesiler/tagcess/internal/site"
	"github.com/nesiler/tagcess/internal/store"
	"github.com/nesiler/tagcess/internal/store/db"
	"github.com/nesiler/tagcess/internal/web"
)

// f4.go composes the F4 services (F4-031): the k8s profile/credential/snapshot stores, the read
// model and screens, and the monitoring loops. It only reads. No reconcile, apply or access-write
// callback is passed into anything built here; the loops start with the process and stop with it.

const (
	// k8sCluster identifies the single cluster of the draft store (one profile, ADR 0030).
	k8sCluster = "default"
	// probeVantage labels where tagcess measures from; it never claims the internet.
	probeVantage = "tagcess-net"
	// gatePort is the Caddy listener the gate probe asks (the VPN address, [Ö]).
	gatePort = 443
)

// obsTimeLayout is the observation store's fixed-width UTC format.
const obsTimeLayout = "2006-01-02T15:04:05.000Z"

type f4Nodes interface {
	ListNodes(ctx context.Context) ([]admin.AdminNode, error)
}

type f4Roles interface {
	ListRoles(ctx context.Context) ([]string, error)
}

type f4Sites interface {
	ListSites(ctx context.Context) ([]site.Site, error)
	FirstImportPending(ctx context.Context) (bool, error)
}

// f4Inputs are the already-built dependencies of the F4 composition.
type f4Inputs struct {
	Cfg     *config.Config
	Log     *slog.Logger
	Store   *store.Store
	CSRF    *web.CSRF
	Auditor *audit.Logger
	Sites   f4Sites
	Targets site.TargetSource
	Nodes   f4Nodes
	Roles   f4Roles
	// Drift sources (read-only clients).
	Policy alert.PolicySource
	Caddy  alert.CaddyReader
	DNS    alert.DNSReader
	URIs   alert.URIReader
	// Settings is the site render input reader the artifacts were applied with.
	Settings func(ctx context.Context) (change.SiteSettings, error)
	// Maintenance is the H-07 gate state; optional (nil: only the writer lock holds the drift check).
	Maintenance interface {
		Get(ctx context.Context) (maintenance.Status, error)
	}
	// K8sGuard is the dial guard of every k8s API client; nil is the production guard (system
	// resolver and dialer behind the API policy). Tests pass one over a stand-in API.
	K8sGuard *netpolicy.Guard
	// Review is the S-04 review handler the k8s drafts are handed over to; optional.
	Review *web.SiteReviewHandler
}

// f4 is the composition. Pages carries only the F4 pages; the caller merges it into its uiPages.
type f4 struct {
	Pages         uiPages
	Runtime       *f4Runtime
	csrf          *web.CSRF
	loopsConfig   monitor.LoopsConfig
	settingsStore *monitor.SettingsStore
	alerts        *alert.Service
	reader        *k8s.Reader
	runner        *health.Runner
	loops         *monitor.Loops
	drift         *alert.Drift
	candidates    func(ctx context.Context) ([]k8s.GateCandidate, error)
}

// buildF4 builds every F4 service over the open store. Nothing here reads a remote system: a
// missing profile or an unreadable source shows up later as state, never as a startup failure.
func buildF4(in f4Inputs) (*f4, error) {
	q, sqldb := in.Store.Queries(), in.Store.DB()
	now := time.Now
	policy := netpolicy.New(sqldb, q)
	profiles := k8s.NewProfileStore(sqldb, q, policy, now)
	// An empty k8s_auth_dir is not defaulted into data_dir: the store then refuses to hold a credential
	// and the connection page shows the setup error.
	creds := k8s.NewCredentialStore(in.Cfg.K8sAuthDir)
	snaps := k8s.NewSnapshotStore(sqldb, q)
	guard := in.K8sGuard
	if guard == nil {
		guard = netpolicy.NewGuard(policy, nil, nil)
	}
	reader := k8s.NewReaderWithGuard(profiles, creds, snaps, guard, now)
	settings := monitor.NewSettingsStore(sqldb, q)
	alerts := alert.New(alert.NewStore(sqldb, q), settings)

	obs := &f4Observations{sites: in.Sites, q: q}
	model, err := dashboard.New(dashboard.Config{
		Devices:      f4Devices{in.Nodes, now},
		Roles:        f4VpnRoles{in.Roles, now},
		Sites:        f4SiteRead{in.Sites, now},
		Observations: f4ObsSummary{obs},
		Alerts:       f4OpenAlerts{alerts, now},
		Sync:         f4Sync{q},
		S06:          f4S06{in.Settings, now},
	})
	if err != nil {
		return nil, err
	}
	// The dashboard reads the drift hold and the loop states, which are built further down.
	var drift *alert.Drift
	var loops *monitor.Loops
	setup := f4Setup{sites: in.Sites, policy: policy, profiles: profiles, creds: creds}
	dash, err := web.NewDashboardHandler(web.DashboardHandlerConfig{Model: model, Observations: obs, Snapshot: reader, CSRF: in.CSRF, Settings: settings.Get,
		DriftHeld: func() bool { return drift != nil && drift.Held() },
		Loops:     func() []monitor.JobStatus { return loops.Status() },
		Setup:     setup.Pending,
	})
	if err != nil {
		return nil, err
	}
	alertsPage, err := web.NewAlertsHandler(web.AlertsHandlerConfig{Alerts: alerts, Auditor: in.Auditor, CSRF: in.CSRF})
	if err != nil {
		return nil, err
	}
	settingsPage, err := web.NewMonitorSettingsHandler(web.MonitorSettingsConfig{Settings: settings, Auditor: in.Auditor, CSRF: in.CSRF})
	if err != nil {
		return nil, err
	}
	discovery := &f4Discovery{reader: reader, profiles: profiles, sites: in.Sites}
	discoveryPage, err := web.NewK8sDiscoveryHandler(web.K8sDiscoveryConfig{Reader: discovery, CSRF: in.CSRF})
	if err != nil {
		return nil, err
	}
	connectionPage, err := web.NewK8sConnectionHandler(web.K8sConnectionConfig{
		Profiles: profiles, Creds: creds, Connector: f4Connector{guard, profiles}, Auditor: in.Auditor, CSRF: in.CSRF,
		OnSaved: func() { loops.Trigger() },
	})
	if err != nil {
		return nil, err
	}
	setupPage, err := web.NewK8sSetupHandler(web.K8sSetupConfig{
		Profiles: profiles, Policy: policy, Auditor: in.Auditor, CSRF: in.CSRF, Creds: creds,
		OnSaved: func() { loops.Trigger() },
		Review: func(ctx context.Context, namespaces []string) (k8s.Review, error) {
			cred, err := creds.Load()
			if err != nil {
				return k8s.Review{}, err
			}
			prof, err := profiles.Get(ctx)
			if err != nil {
				return k8s.Review{}, err
			}
			c, err := k8s.ClientForProfileWithGuard(prof, cred, guard)
			if err != nil {
				return k8s.Review{}, err
			}
			defer c.Close()
			return k8s.ReviewPermissions(ctx, c, namespaces, now)
		},
	})
	if err != nil {
		return nil, err
	}
	draftPage, err := web.NewK8sDraftHandler(web.K8sDraftConfig{
		Discovery: discovery, Drafts: k8s.NewDraftStore(sqldb, q, k8sCluster), Auditor: in.Auditor,
		CSRF: in.CSRF, Now: now, Review: in.Review, Roles: in.Roles, K8sUpstream: in.Cfg.Sites.K8sUpstream,
	})
	if err != nil {
		return nil, err
	}

	sources, err := alert.NewSources(alerts, alert.SourcesConfig{
		Sites: obs.siteNames, Observations: q, LegacyAlerts: q, SyncRuns: q, Pending: q, Settings: settings.Get,
	})
	if err != nil {
		return nil, err
	}
	drift, err = alert.NewDrift(alerts, alert.DriftConfig{
		Policy: in.Policy, Baseline: alert.NewPolicyBaseline(q), Sites: in.Sites, Settings: in.Settings,
		Caddy: in.Caddy, DNS: in.DNS, URIs: in.URIs, Hold: f4Hold(in.Maintenance),
	})
	if err != nil {
		return nil, err
	}
	transport := health.New(probeTargets{custom: in.Targets, sites: in.Sites, vpnAddr: in.Cfg.Sites.VPNAddress, k8sUpstream: in.Cfg.Sites.K8sUpstream}, policy)
	gates := &health.GateMeasurer{Transport: transport, Store: q, Vantage: probeVantage}
	candidates := func(ctx context.Context) ([]k8s.GateCandidate, error) {
		return f4Candidates(ctx, reader, profiles, in.Sites, gates)
	}
	// The runner reports every finished cycle to the loops, and the loops need the runner: the
	// report closure reads loops only after NewLoops has set it.
	runner := health.NewRunner(health.Config{
		Settings:   settings.Get,
		Subjects:   f4Subjects(in.Sites, in.Cfg.Sites.VPNAddress, in.Cfg.Sites.K8sUpstream, setup.probeReady),
		Candidates: candidates,
		Prober:     transport,
		Gates:      gates,
		Store:      health.NewStore(q),
		Clock:      f4Clock{},
		Vantage:    probeVantage,
		Report:     func(r health.CycleReport) { loops.ReportHealthCycle(r.At, r.Err) },
	})
	loopsCfg := monitor.LoopsConfig{
		Settings: settings.Get,
		ProfileReady: func(ctx context.Context) error {
			_, err := profiles.Get(ctx)
			return err
		},
		Inventory: func(ctx context.Context) error { _, err := reader.Read(ctx); return err },
		Alerts:    func(ctx context.Context) error { _, err := sources.Evaluate(ctx); return err },
		Drift: func(ctx context.Context) error {
			if _, err := drift.Check(ctx); err != nil {
				return err
			}
			if drift.Pending() {
				return fmt.Errorf("first import is pending: %w", monitor.ErrSetupPending)
			}
			return nil
		},
		Health: runner,
	}
	loops, err = monitor.NewLoops(loopsCfg)
	if err != nil {
		return nil, err
	}

	return &f4{
		Pages: uiPages{
			Dashboard: dash, Alerts: alertsPage, MonitorSettings: settingsPage, K8sDiscovery: discoveryPage,
			K8sConnection: connectionPage, K8sSetup: setupPage, K8sDraft: draftPage,
		},
		Runtime:       newF4Runtime(loops),
		csrf:          in.CSRF,
		loopsConfig:   loopsCfg,
		settingsStore: settings,
		alerts:        alerts,
		reader:        reader,
		runner:        runner,
		loops:         loops,
		drift:         drift,
		candidates:    candidates,
	}, nil
}

// f4Loops is the F4-038 life cycle: Run blocks until ctx is done.
type f4Loops interface {
	Run(ctx context.Context) error
}

// f4Runtime starts the loops once with the process and stops them once, waiting for them to end.
type f4Runtime struct {
	loops   f4Loops
	mu      sync.Mutex
	started bool
	cancel  context.CancelFunc
	done    chan struct{}
}

func newF4Runtime(loops f4Loops) *f4Runtime { return &f4Runtime{loops: loops} }

// Start runs the loops in the background. A second call does nothing.
func (r *f4Runtime) Start(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.started {
		return
	}
	r.started = true
	ctx, r.cancel = context.WithCancel(ctx)
	r.done = make(chan struct{})
	go func() {
		defer close(r.done)
		_ = r.loops.Run(ctx)
	}()
}

// Stop cancels the loops and waits for them. It is safe before Start and after a Stop.
func (r *f4Runtime) Stop() {
	r.mu.Lock()
	cancel, done := r.cancel, r.done
	r.cancel = nil
	r.mu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	<-done
}

type f4Clock struct{}

func (f4Clock) Now() time.Time                         { return time.Now() }
func (f4Clock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// f4Connector is the F4-004 connection attempt: with the candidate credential it reads what the
// Reader reads (IngressClasses, plus the Ingresses and Services of every profile namespace), so a
// token that cannot list is refused. A TLS handshake alone proves nothing about the token.
type f4Connector struct {
	guard    *netpolicy.Guard
	profiles *k8s.ProfileStore
}

func (c f4Connector) Connect(ctx context.Context, cred k8s.Credential) error {
	prof, err := c.profiles.Get(ctx)
	if err != nil {
		return err
	}
	cl, err := k8s.ClientForProfileWithGuard(prof, cred, c.guard)
	if err != nil {
		return err
	}
	defer cl.Close()
	if _, err := cl.ListIngressClasses(ctx); err != nil {
		return err
	}
	for _, ns := range prof.Namespaces {
		if _, err := cl.ListIngresses(ctx, ns); err != nil {
			return err
		}
		if _, err := cl.ListServices(ctx, ns); err != nil {
			return err
		}
	}
	return nil
}

// f4Hold reports that the drift check must not compare: the site writer lock is held (an apply is
// between its writes) or the H-07 maintenance is not off. An unreadable maintenance state is an
// error, which the drift check records as uncertainty.
func f4Hold(m interface {
	Get(ctx context.Context) (maintenance.Status, error)
}) func(context.Context) (bool, error) {
	return func(ctx context.Context) (bool, error) {
		if change.WriterLockBusy() {
			return true, nil
		}
		if m == nil {
			return false, nil
		}
		st, err := m.Get(ctx)
		if err != nil {
			return true, err
		}
		return st.State != maintenance.Off, nil
	}
}

// siteKey is how a site is named in observations: its first host.
func siteKey(s site.Site) string {
	if len(s.Hosts) == 0 {
		return ""
	}
	return s.Hosts[0]
}

// f4Discovery maps the stored snapshot to drafts (F4-010/F4-011) without reading the cluster.
type f4Discovery struct {
	reader   *k8s.Reader
	profiles *k8s.ProfileStore
	sites    f4Sites
}

func (d *f4Discovery) Discovery(ctx context.Context) (web.K8sDiscovery, error) {
	profile, err := d.profiles.Get(ctx)
	if err != nil {
		return web.K8sDiscovery{}, err
	}
	state, err := d.reader.State(ctx)
	if err != nil {
		return web.K8sDiscovery{}, err
	}
	sites, err := d.sites.ListSites(ctx)
	if err != nil {
		return web.K8sDiscovery{}, err
	}
	managed := make([]k8s.ManagedSite, 0, len(sites))
	for _, s := range sites {
		managed = append(managed, k8s.ManagedSite{ID: s.ID, Hosts: s.Hosts, AccessChoice: accessChoice(s), Roles: s.Roles,
			System: s.Kind == site.KindSystem})
	}
	var inv k8s.Inventory
	if state.Current != nil {
		inv = state.Current.Inventory
	}
	rep := k8s.InterpretRoutes(inv, profile)
	return web.K8sDiscovery{
		Report:        k8s.BuildDrafts(k8s.DraftInputs{Report: rep, Profile: profile, Managed: managed, Complete: state.Current != nil}),
		State:         state,
		PublicChecked: len(profile.Public) > 0,
	}, nil
}

func accessChoice(s site.Site) string {
	if s.Kind == site.KindOpen {
		return k8s.AccessChoiceOpen
	}
	return k8s.AccessChoiceRole
}

// f4Candidates builds the two-gate candidates from the current snapshot and records each one as a
// configuration-risk row (RecordRisk), so the "İki kapı" card shows the declared risk whatever a
// later measurement says. Without a current snapshot there is nothing true to measure, so it is an
// error rather than an empty list. NodeAddresses are the profile's declared listener addresses [Ö].
func f4Candidates(ctx context.Context, reader *k8s.Reader, profiles *k8s.ProfileStore, sites f4Sites, gates *health.GateMeasurer) ([]k8s.GateCandidate, error) {
	profile, err := profiles.Get(ctx)
	if err != nil {
		return nil, err
	}
	state, err := reader.State(ctx)
	if err != nil {
		return nil, err
	}
	if state.Current == nil {
		return nil, errors.New("no current k8s snapshot")
	}
	list, err := sites.ListSites(ctx)
	if err != nil {
		return nil, err
	}
	var hosts []k8s.ManagedHost
	for _, s := range list {
		for _, h := range s.Hosts {
			hosts = append(hosts, k8s.ManagedHost{Site: siteKey(s), Host: h, IntentionalOpen: s.Kind == site.KindOpen})
		}
	}
	var nodes []string
	for _, l := range slices.Concat(profile.Internal, profile.Public) {
		if !slices.Contains(nodes, l.Address) {
			nodes = append(nodes, l.Address)
		}
	}
	rep := k8s.EvaluateGates(k8s.GateInput{Inventory: state.Current.Inventory, Profile: profile, Hosts: hosts, NodeAddresses: nodes})
	for _, c := range rep.Candidates {
		if err := gates.RecordRisk(ctx, c, rep.Scope); err != nil {
			return nil, fmt.Errorf("record config risk: %w", err)
		}
	}
	return rep.Candidates, nil
}

// probeTargets is the probe's approved Host/SNI/target list: the custom allowlist plus the managed
// site hostnames and the VPN address. A site's own name never needs a manual allowlist entry; the
// url target of a site is not added, so the allowlist still decides where else a probe may go.
type probeTargets struct {
	custom      site.TargetSource
	sites       f4Sites
	vpnAddr     string
	k8sUpstream string // sites.k8s_upstream; empty: the renderer's default
}

func (p probeTargets) ListTargets(ctx context.Context) ([]string, error) {
	out, err := p.custom.ListTargets(ctx)
	if err != nil {
		return nil, err
	}
	list, err := p.sites.ListSites(ctx)
	if err != nil {
		return nil, err
	}
	out = slices.Clone(out)
	for _, s := range list {
		out = append(out, s.Hosts...)
	}
	if p.vpnAddr != "" {
		out = append(out, p.vpnAddr)
	}
	// The ingress every k8s site is proxied to: Caddy's own (k8s) upstream, measured directly so a
	// dead backend is seen behind the gate's login redirect (G-2).
	if up, ok := k8sUpstreamRequest(p.k8sUpstream); ok {
		out = append(out, up.Host)
	}
	return out, nil
}

// k8sUpstreamRequest is the address of Caddy's (k8s) snippet upstream as a probe request: the
// configured sites.k8s_upstream, or the renderer's default when it is empty (as the Caddyfile).
func k8sUpstreamRequest(configured string) (health.Request, bool) {
	if configured == "" {
		configured = caddyrender.K8sUpstream
	}
	return targetRequest(configured)
}

// f4Subjects lists the managed hosts to measure: the site target (its URL, or for a k8s site the
// ingress behind Caddy's (k8s) upstream), the Caddy gate on the VPN address and the presented
// certificate.
//
// ready, when set, must return nil before anything is measured. While the probe policy is not saved
// every probe would be refused before any connection, so the cycle waits (monitor.ErrSetupPending)
// instead of recording a refusal per site.
func f4Subjects(sites f4Sites, vpnAddr, k8sUpstream string, ready func(context.Context) error) func(context.Context) ([]health.Subject, error) {
	return func(ctx context.Context) ([]health.Subject, error) {
		if ready != nil {
			if err := ready(ctx); err != nil {
				return nil, err
			}
		}
		list, err := sites.ListSites(ctx)
		if err != nil {
			return nil, err
		}
		var out []health.Subject
		for _, s := range list {
			if disabledSystemSite(s) {
				continue
			}
			for _, h := range s.Hosts {
				sub := health.Subject{Site: siteKey(s), Host: h, Kind: s.Kind, Template: s.SystemTemplate, Maintenance: s.Maintenance}
				if vpnAddr != "" {
					sub.Gate = &health.Request{Host: vpnAddr, Port: gatePort, TLS: true, ServerName: h}
					sub.TLS = &health.TLSRequest{Host: vpnAddr, Port: gatePort, ServerName: h}
				}
				switch s.TargetKind {
				case site.TargetURL:
					if req, ok := targetRequest(s.TargetURL); ok {
						sub.Target = &health.TargetRequest{Request: req}
					}
				case site.TargetK8s:
					// The backend is measured where Caddy sends it: the ingress, with the site's
					// host as Host/SNI and the certificate unverified exactly as in the (k8s)
					// snippet. A gate check alone only sees the login redirect (G-2). A system
					// template has no adapter: it is listed but never measured (stays unknown).
					if req, ok := k8sUpstreamRequest(k8sUpstream); ok {
						req.ServerName, req.SkipVerify, req.Template = h, true, s.SystemTemplate
						sub.Target = &health.TargetRequest{Request: req}
					}
				}
				out = append(out, sub)
			}
		}
		return out, nil
	}
}

// disabledSystemSite is a wireguard_ui system site whose switch is off: Caddy renders no block for
// it (internal/render), so there is nothing to probe and an alert would only be noise (F5 C3).
func disabledSystemSite(s site.Site) bool {
	if s.Kind != site.KindSystem || s.SystemTemplate != site.TemplateWireGuardUI {
		return false
	}
	cfg, err := site.ParseSystemConfig(s.SystemTemplate, s.SystemConfig)
	return err == nil && !cfg.Enabled
}

func targetRequest(raw string) (health.Request, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return health.Request{}, false
	}
	port := 80
	if u.Scheme == "https" {
		port = 443
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil {
			return health.Request{}, false
		}
		port = n
	}
	return health.Request{Host: u.Hostname(), Port: port, TLS: u.Scheme == "https"}, true
}

// --- dashboard sources (F4-027): thin read-only adapters ---

type f4Devices struct {
	nodes f4Nodes
	now   func() time.Time
}

func (d f4Devices) Devices(ctx context.Context) (dashboard.DevicesRead, error) {
	nodes, err := d.nodes.ListNodes(ctx)
	if err != nil {
		return dashboard.DevicesRead{}, err
	}
	out := dashboard.DevicesRead{ObservedAt: d.now()}
	for _, n := range nodes {
		// The given name is Headscale's unique device name (the one the device list shows); the
		// machine's host name repeats across devices of one person.
		name := n.GivenName
		if name == "" {
			name = n.Name
		}
		dev := dashboard.Device{Name: name, Owner: n.UserName, Online: n.Online}
		if n.LastSeen != nil {
			dev.LastSeen = *n.LastSeen
		}
		out.Devices = append(out.Devices, dev)
	}
	return out, nil
}

type f4VpnRoles struct {
	roles f4Roles
	now   func() time.Time
}

func (r f4VpnRoles) VpnRoles(ctx context.Context) (dashboard.RolesRead, error) {
	roles, err := r.roles.ListRoles(ctx)
	if err != nil {
		return dashboard.RolesRead{}, err
	}
	return dashboard.RolesRead{Roles: roles, ObservedAt: r.now()}, nil
}

type f4SiteRead struct {
	sites f4Sites
	now   func() time.Time
}

func (s f4SiteRead) ListSites(ctx context.Context) (dashboard.SitesRead, error) {
	list, err := s.sites.ListSites(ctx)
	if err != nil {
		return dashboard.SitesRead{}, err
	}
	return dashboard.SitesRead{Sites: list, ObservedAt: s.now()}, nil
}

type f4OpenAlerts struct {
	svc *alert.Service
	now func() time.Time
}

func (a f4OpenAlerts) OpenAlerts(ctx context.Context) (dashboard.AlertsRead, error) {
	list, err := a.svc.ListOpen(ctx)
	if err != nil {
		return dashboard.AlertsRead{}, err
	}
	out := dashboard.AlertsRead{ObservedAt: a.now()}
	for _, al := range list {
		out.Alerts = append(out.Alerts, dashboard.Alert{
			Kind: al.Kind, Subject: al.Subject, Severity: string(al.Severity), State: string(al.State),
			Source: al.Source, Muted: al.Muted, Freshness: al.Freshness,
		})
	}
	return out, nil
}

type f4Sync struct{ q *db.Queries }

func (s f4Sync) Sync(ctx context.Context) (dashboard.SyncRead, error) {
	run, err := s.q.GetLatestSyncRun(ctx)
	if err != nil {
		return dashboard.SyncRead{}, err
	}
	at, _ := parseStoredTime(run.StartedAt)
	return dashboard.SyncRead{ObservedAt: at, Result: run.Result, Summary: run.DiffSummary}, nil
}

type f4S06 struct {
	settings func(context.Context) (change.SiteSettings, error)
	now      func() time.Time
}

func (s f4S06) S06(ctx context.Context) (dashboard.S06Read, error) {
	v, err := s.settings(ctx)
	if err != nil {
		return dashboard.S06Read{}, err
	}
	return dashboard.S06Read{Open: v.Caddy.S06Open, ObservedAt: s.now()}, nil
}

func parseStoredTime(s string) (time.Time, bool) {
	for _, layout := range []string{obsTimeLayout, time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// f4Observations reads the stored measurement rows of every current site. Any failure fails the
// whole read, so a partial inventory is never shown as green.
type f4Observations struct {
	sites f4Sites
	q     *db.Queries
}

func (o *f4Observations) siteNames(ctx context.Context) ([]string, error) {
	list, err := o.sites.ListSites(ctx)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(list))
	for _, s := range list {
		names = append(names, siteKey(s))
	}
	return names, nil
}

func (o *f4Observations) Observations(ctx context.Context) ([]db.Observation, error) {
	names, err := o.siteNames(ctx)
	if err != nil {
		return nil, err
	}
	var rows []db.Observation
	for _, name := range names {
		r, err := o.q.ListObservationsBySite(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("observations of %s: %w", name, err)
		}
		rows = append(rows, r...)
	}
	return rows, nil
}

// f4ObsSummary aggregates the rows per site for the dashboard model: newest good time, newest attempt,
// whether every category's last attempt succeeded and the categories seen.
type f4ObsSummary struct{ *f4Observations }

func (o f4ObsSummary) Observations(ctx context.Context) (dashboard.ObservationsRead, error) {
	obs := o.f4Observations
	names, err := obs.siteNames(ctx)
	if err != nil {
		return dashboard.ObservationsRead{}, err
	}
	out := dashboard.ObservationsRead{ObservedAt: time.Now()}
	for _, name := range names {
		rows, err := obs.q.ListObservationsBySite(ctx, name)
		if err != nil {
			return dashboard.ObservationsRead{}, fmt.Errorf("observations of %s: %w", name, err)
		}
		agg := dashboard.ObservationSite{Site: name, Success: len(rows) > 0}
		for _, r := range rows {
			if t, ok := parseStoredTime(r.ObservedAt); ok && t.After(agg.ObservedAt) {
				agg.ObservedAt = t
			}
			if t, ok := parseStoredTime(r.LastAttemptAt); ok && t.After(agg.LastAttemptAt) {
				agg.LastAttemptAt = t
			}
			if r.Success == 0 {
				agg.Success = false
			}
			if !slices.Contains(agg.Categories, r.Category) {
				agg.Categories = append(agg.Categories, r.Category)
			}
		}
		slices.Sort(agg.Categories)
		out.Sites = append(out.Sites, agg)
	}
	return out, nil
}

// f4Setup reports which installation steps are still open (F5 A2). It only reads local state.
type f4Setup struct {
	sites    f4Sites
	policy   *netpolicy.Store
	profiles *k8s.ProfileStore
	creds    *k8s.CredentialStore
}

// probeReady is nil once the probe IP policy is saved. A missing policy is a waiting state;
// any other read failure is returned as is.
func (s f4Setup) probeReady(ctx context.Context) error {
	_, err := s.policy.Get(ctx, netpolicy.ScopeProbe)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, netpolicy.ErrNotSet):
		return fmt.Errorf("probe IP policy: %w", monitor.ErrSetupPending)
	default:
		return err
	}
}

// Pending lists the open steps in the order they should be done. An unreadable store is not listed:
// "unknown" is not "unfinished", and the cards show their own read errors.
func (s f4Setup) Pending(ctx context.Context) []web.SetupStep {
	var out []web.SetupStep
	if pending, err := s.sites.FirstImportPending(ctx); err == nil && pending {
		out = append(out, web.SetupStep{Key: web.SetupFirstImport, Label: "İlk import apply edilmedi", Href: "/sites/first-import"})
	}
	if errors.Is(s.probeReady(ctx), monitor.ErrSetupPending) {
		out = append(out, web.SetupStep{Key: web.SetupProbePolicy, Label: "Probe IP policy'si kayıtlı değil", Href: "/k8s/setup"})
	}
	_, perr := s.profiles.Get(ctx)
	switch {
	case errors.Is(perr, k8s.ErrNotSet):
		out = append(out, web.SetupStep{Key: web.SetupK8sProfile, Label: "k8s bağlantı profili kayıtlı değil", Href: "/k8s/setup"})
	case perr == nil:
		if _, cerr := s.creds.Info(); errors.Is(cerr, k8s.ErrCredentialNotSet) {
			out = append(out, web.SetupStep{Key: web.SetupK8sAccess, Label: "k8s credential yüklenmedi", Href: "/k8s/connection"})
		}
	}
	return out
}
