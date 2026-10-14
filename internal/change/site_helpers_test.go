package change

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/caddy"
	"github.com/nesiler/tagcess/internal/dns"
	"github.com/nesiler/tagcess/internal/render"
	"github.com/nesiler/tagcess/internal/site"
	"github.com/nesiler/tagcess/internal/store"
	"github.com/nesiler/tagcess/internal/zitadel"
)

// Fixtures of the F2-011 site change pipeline tests: a real SQLite site store (so the store rules
// run for real) and fakes for the three external artifacts. Every fake appends to one shared call
// log, so a test can assert the exact order of the writes.

// siteCalls is the shared, ordered call log of the fakes.
type siteCalls struct {
	mu   sync.Mutex
	list []string
}

func (c *siteCalls) add(s string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.list = append(c.list, s)
}

func (c *siteCalls) get() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.list)
}

func (c *siteCalls) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.list = nil
}

type fakeRoles struct {
	mu    sync.Mutex
	roles []string
	err   error
}

func (f *fakeRoles) ListRoles(context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return slices.Clone(f.roles), nil
}

func (f *fakeRoles) setErr(err error) {
	f.mu.Lock()
	f.err = err
	f.mu.Unlock()
}

// fakeCaddy models the Caddyfile on disk and the running config. A successful Apply moves both to
// the target; the failure knobs model the outcomes caddy.Apply can report.
type fakeCaddy struct {
	calls *siteCalls
	mu    sync.Mutex

	initial string
	disk    string
	live    string

	diskErr error
	liveErr error
	// liveErrAfterApply makes the running config unreadable once an Apply was attempted.
	liveErrAfterApply error
	applied           bool

	// applyErr is returned by Apply; liveMovesOnError says the config was loaded anyway (an
	// ambiguous failure such as a response timeout after the load).
	applyErr         error
	liveMovesOnError bool
	// fileWrite is returned by Apply after the target was loaded but not written to disk.
	fileWrite *caddy.FileWriteError
	// applyBlock holds every Apply until closed (serialization test).
	applyBlock chan struct{}
	inFlight   int
	maxFlight  int

	// restoreErr fails an Apply of the previous content (the rollback of an add).
	restoreErr error

	adaptErr error
	// adapted maps a Caddyfile to its adapted JSON for the parity gate.
	adapted map[string]string
	// adaptTexts records every Caddyfile handed to /adapt (the rollback preview's check).
	adaptTexts []string
}

func newFakeCaddy(calls *siteCalls, disk string) *fakeCaddy {
	return &fakeCaddy{calls: calls, initial: disk, disk: disk, live: "live:" + disk}
}

func (f *fakeCaddy) Current(context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.diskErr != nil {
		return "", f.diskErr
	}
	return f.disk, nil
}

func (f *fakeCaddy) Live(context.Context) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.liveErr != nil {
		return nil, f.liveErr
	}
	if f.applied && f.liveErrAfterApply != nil {
		return nil, f.liveErrAfterApply
	}
	return []byte(f.live), nil
}

func (f *fakeCaddy) Apply(_ context.Context, sites []site.Site, target string) error {
	if err := caddy.RequireSystemSites(sites); err != nil {
		return err
	}
	name := "caddy"
	if target == f.initial {
		name = "caddy-restore"
	}
	f.calls.add(name)
	f.mu.Lock()
	f.inFlight++
	f.maxFlight = max(f.maxFlight, f.inFlight)
	block := f.applyBlock
	f.mu.Unlock()
	if block != nil {
		<-block
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.inFlight--
	f.applied = true
	switch {
	case name == "caddy-restore" && f.restoreErr != nil:
		return f.restoreErr
	case f.applyErr != nil:
		if f.liveMovesOnError {
			f.live = "live:" + target
		}
		return f.applyErr
	case f.fileWrite != nil:
		if f.fileWrite.Restored {
			// The previous content is live again, the disk never changed.
			return f.fileWrite
		}
		f.live = "live:" + target
		return f.fileWrite
	}
	f.disk = target
	f.live = "live:" + target
	return nil
}

func (f *fakeCaddy) AdaptJSON(_ context.Context, text string) ([]byte, error) {
	f.mu.Lock()
	f.adaptTexts = append(f.adaptTexts, text)
	f.mu.Unlock()
	if f.adaptErr != nil {
		return nil, f.adaptErr
	}
	if doc, ok := f.adapted[text]; ok {
		return []byte(doc), nil
	}
	return []byte(`{"apps":{"http":{"servers":{"srv0":{"routes":[]}}}}}`), nil
}

func (f *fakeCaddy) state() (disk, live string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.disk, f.live
}

// fakeDNS models the extra-records file.
type fakeDNS struct {
	calls *siteCalls
	mu    sync.Mutex

	content string
	exists  bool

	readErr    error
	applyErr   error
	restoreErr error
	mismatches []dns.Mismatch
}

func (f *fakeDNS) Current(context.Context) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.readErr != nil {
		return "", false, f.readErr
	}
	return f.content, f.exists, nil
}

func (f *fakeDNS) Apply(_ context.Context, records []dns.Record) ([]dns.Mismatch, error) {
	f.calls.add("dns")
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.applyErr != nil {
		return nil, f.applyErr
	}
	body, err := dns.Marshal(records)
	if err != nil {
		return nil, err
	}
	f.content, f.exists = body, true
	return f.mismatches, nil
}

func (f *fakeDNS) Restore(_ context.Context, content string) error {
	f.calls.add("dns-restore")
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.restoreErr != nil {
		return f.restoreErr
	}
	f.content, f.exists = content, true
	return nil
}

func (f *fakeDNS) body() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.content
}

// fakeURIs models the oauth2-proxy redirect URI sync.
type fakeURIs struct {
	calls *siteCalls
	mu    sync.Mutex

	syncRes   zitadel.URIResult
	syncErr   error
	driftRes  zitadel.URIResult
	driftErr  error
	driftRuns int
	syncSites [][]site.Site
	// owned is O, the set the last successful Sync recorded (nil = no record yet), like URISync.
	owned []string
}

func (f *fakeURIs) Sync(_ context.Context, sites []site.Site) (zitadel.URIResult, error) {
	f.calls.add("zitadel")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.syncSites = append(f.syncSites, slices.Clone(sites))
	if f.syncErr == nil {
		d, err := zitadel.DesiredURIs(sites)
		if err != nil {
			return f.syncRes, err
		}
		f.owned = d
	}
	return f.syncRes, f.syncErr
}

func (f *fakeURIs) OwnedURIs(context.Context) ([]string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.owned), f.owned != nil, nil
}

func (f *fakeURIs) CheckDrift(context.Context, []site.Site) (zitadel.URIResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.driftRuns++
	return f.driftRes, f.driftErr
}

// siteHarness wires a SitePipeline over a real site store and the fakes.
type siteHarness struct {
	t     *testing.T
	st    *store.Store
	sites *site.Store
	roles *fakeRoles
	calls *siteCalls
	caddy *fakeCaddy
	dns   *fakeDNS
	uris  *fakeURIs
	dry   *fakeDryRun
	sp    *SitePipeline
	// git is the optional history of the wiring tests (F2-019); nil means none.
	git ArtifactGit
	// maint overrides the maintenance gate of the wiring; nil uses the gate over the real store, so
	// the pipeline reads the same DB the test drives (F3b-017).
	maint MaintenanceGate
	// baseline is the optional first-import policy-baseline hook (F5 I9); nil means none.
	baseline func(ctx context.Context, actor string) error
	// onApplied is the optional after-apply hook (F5 L3); nil means none.
	onApplied func()

	settings    SiteSettings
	settingsErr error
	settingsMu  sync.Mutex
	// before is the store state the baseline artifacts were rendered from.
	before []site.Site
}

const siteActor = "dev@example.com"

func systemSiteRecord(tmpl, host, cert, config string) site.Site {
	return site.Site{
		Hosts: []string{host}, Kind: site.KindSystem, SystemTemplate: tmpl, SystemConfig: config,
		Cert: cert, TargetKind: site.TargetK8s,
		Roles: []string{}, TargetRoles: []string{},
		APIRules: []site.APIRule{}, Redirects: []site.Redirect{}, Headers: []site.Header{},
	}
}

// roleSiteRecord is a valid role site under the allowed domain.
func roleSiteRecord(name string, roles ...string) site.Site {
	if len(roles) == 0 {
		roles = []string{"devops"}
	}
	return site.Site{
		Hosts: []string{name + ".example.com"}, Kind: site.KindRole, Roles: roles,
		TargetRoles: []string{}, Cert: "le:example", TargetKind: site.TargetK8s, MagicDNS: true,
		APIRules: []site.APIRule{}, Redirects: []site.Redirect{}, Headers: []site.Header{},
	}
}

func newSiteHarness(t *testing.T) *siteHarness {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "tagcess.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	roles := &fakeRoles{roles: []string{"devops", "developer", "standart"}}
	v, err := site.NewValidator(site.ValidatorConfig{
		AllowedDomains: []string{"example.com"},
		AllowedTargets: []string{"100.64.0.5"},
	}, roles)
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	ss, err := site.New(st.DB(), st.Queries(), v)
	if err != nil {
		t.Fatalf("site.New: %v", err)
	}
	for _, s := range []site.Site{
		systemSiteRecord(site.TemplateTagcess, "tagcess.example.com", "auto", `{}`),
		systemSiteRecord(site.TemplateWireGuardUI, "vpn.example.com", "auto", `{"enabled":true}`),
		systemSiteRecord(site.TemplateHeadscale, "hs.example.com", "auto", `{"headplane":true}`),
		systemSiteRecord(site.TemplateZitadel, "auth.example.com", "le:example", zitadelTestConfig(t)),
		roleSiteRecord("git"),
	} {
		if _, err := ss.CreateSite(ctx, s); err != nil {
			t.Fatalf("seed %v: %v", s.Hosts, err)
		}
	}

	h := &siteHarness{t: t, st: st, sites: ss, roles: roles, calls: &siteCalls{}, dry: &fakeDryRun{}}
	h.settings = SiteSettings{
		Caddy: render.CaddyConfig{ACMEEmail: "admin@example.invalid", S06Open: true},
		DNS:   render.DNSConfig{AValue: "100.64.0.4"},
	}
	h.before, err = ss.ListSites(ctx)
	if err != nil {
		t.Fatalf("ListSites: %v", err)
	}
	caddyText, err := render.RenderCaddyfile(h.before, h.settings.Caddy)
	if err != nil {
		t.Fatalf("RenderCaddyfile: %v", err)
	}
	recs, err := render.RenderDNSRecords(h.before, nil, h.settings.DNS)
	if err != nil {
		t.Fatalf("RenderDNSRecords: %v", err)
	}
	dnsBody, err := dns.Marshal(recs)
	if err != nil {
		t.Fatalf("dns.Marshal: %v", err)
	}
	h.caddy = newFakeCaddy(h.calls, caddyText)
	h.dns = &fakeDNS{calls: h.calls, content: dnsBody, exists: true}
	h.uris = &fakeURIs{calls: h.calls}
	h.build()
	return h
}

// build (re)creates the pipeline; tests that change the wiring call it again.
func (h *siteHarness) build() {
	h.t.Helper()
	sp, err := NewSite(SiteConfig{
		Queries:        h.st.Queries(),
		Audit:          audit.New(h.st.Queries()),
		DryRun:         h.dry,
		Sites:          h.sites,
		Caddy:          h.caddy,
		DNS:            h.dns,
		URIs:           h.uris,
		Git:            h.git,
		Maintenance:    h.maint,
		PolicyBaseline: h.baseline,
		OnApplied:      h.onApplied,
		Settings: func(ctx context.Context) (SiteSettings, error) {
			h.settingsMu.Lock()
			defer h.settingsMu.Unlock()
			set := h.settings
			if set.ManualDNS == nil && h.settingsErr == nil {
				// Like the real reader (cmd/tagcess): the manual records come from the store, where
				// the first import writes them (F2-022).
				var err error
				if set.ManualDNS, err = h.sites.ManualDNS(ctx); err != nil {
					return SiteSettings{}, err
				}
			}
			return set, h.settingsErr
		},
	})
	if err != nil {
		h.t.Fatalf("NewSite: %v", err)
	}
	h.sp = sp
}

func (h *siteHarness) callLog() *siteCalls { return h.calls }

func (h *siteHarness) hosts() []string {
	h.t.Helper()
	list, err := h.sites.ListSites(context.Background())
	if err != nil {
		h.t.Fatalf("ListSites: %v", err)
	}
	var out []string
	for _, s := range list {
		out = append(out, s.Hosts...)
	}
	slices.Sort(out)
	return out
}

func (h *siteHarness) siteID(host string) int64 {
	h.t.Helper()
	list, err := h.sites.ListSites(context.Background())
	if err != nil {
		h.t.Fatalf("ListSites: %v", err)
	}
	for _, s := range list {
		if slices.Contains(s.Hosts, host) {
			return s.ID
		}
	}
	h.t.Fatalf("no site with host %s", host)
	return 0
}

func (h *siteHarness) hasHost(host string) bool { return slices.Contains(h.hosts(), host) }

// alerts returns the kinds of the open alerts, sorted.
func (h *siteHarness) alerts() []string {
	h.t.Helper()
	rows, err := h.st.Queries().ListOpenAlerts(context.Background())
	if err != nil {
		h.t.Fatalf("ListOpenAlerts: %v", err)
	}
	var kinds []string
	for _, r := range rows {
		kinds = append(kinds, r.Kind)
	}
	slices.Sort(kinds)
	return kinds
}

type changeRow struct {
	Kind, Actor, Status, Before, After, Error string
}

func (h *siteHarness) changes() []changeRow {
	h.t.Helper()
	rows, err := h.st.DB().QueryContext(context.Background(),
		`SELECT kind, actor, status, before_summary, after_summary, error FROM changes WHERE kind = ? ORDER BY id`, KindSite)
	if err != nil {
		h.t.Fatalf("query changes: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []changeRow
	for rows.Next() {
		var c changeRow
		if err := rows.Scan(&c.Kind, &c.Actor, &c.Status, &c.Before, &c.After, &c.Error); err != nil {
			h.t.Fatalf("scan change: %v", err)
		}
		out = append(out, c)
	}
	return out
}

func (h *siteHarness) audits() []audit.Event {
	h.t.Helper()
	evs, err := audit.New(h.st.Queries()).List(context.Background(), audit.Filter{Limit: 100})
	if err != nil {
		h.t.Fatalf("audit list: %v", err)
	}
	var out []audit.Event
	for _, e := range slices.Backward(evs) {
		if strings.HasPrefix(e.Event, "site.") {
			out = append(out, e)
		}
	}
	return out
}

func auditByName(evs []audit.Event, name string) []audit.Event {
	var out []audit.Event
	for _, e := range evs {
		if e.Event == name {
			out = append(out, e)
		}
	}
	return out
}

func diffField(d audit.Diff, field string) (audit.Change, bool) {
	for _, c := range d {
		if c.Field == field {
			return c, true
		}
	}
	return audit.Change{}, false
}

func addReq(s site.Site) SiteRequest { return SiteRequest{Actor: siteActor, Op: SiteAdd, Site: s} }

func (h *siteHarness) deleteReq(host string) SiteRequest {
	return SiteRequest{Actor: siteActor, Op: SiteDelete, ID: h.siteID(host)}
}

func equalStrings(a, b []string) bool { return slices.Equal(a, b) }

var errBoom = errors.New("boom")

// importHarness is a siteHarness over an empty store whose artifacts are today's hand-written
// files: the G-01 first import loads the seed fixture and replaces them.
type importHarness struct {
	*siteHarness
	seed     []byte
	seedOpts site.SeedOptions
}

func newImportHarness(t *testing.T) *importHarness {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "tagcess.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	roles := &fakeRoles{roles: []string{"devops", "developer", "standart"}}
	v, err := site.NewValidator(site.ValidatorConfig{
		AllowedDomains: []string{"example.com", "internal.example.org", "example.net"},
		AllowedTargets: []string{"100.64.0.5"},
	}, roles)
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	ss, err := site.New(st.DB(), st.Queries(), v)
	if err != nil {
		t.Fatalf("site.New: %v", err)
	}
	seed, err := os.ReadFile("../../test/fixtures/seed-sites.json")
	if err != nil {
		t.Fatalf("read seed: %v", err)
	}
	current, err := os.ReadFile("../../test/fixtures/caddyfile-current.caddy")
	if err != nil {
		t.Fatalf("read current Caddyfile: %v", err)
	}
	extra, err := os.ReadFile("../../test/fixtures/extra-records-current.json")
	if err != nil {
		t.Fatalf("read extra records: %v", err)
	}

	h := &siteHarness{t: t, st: st, sites: ss, roles: roles, calls: &siteCalls{}, dry: &fakeDryRun{}}
	h.settings = SiteSettings{
		Caddy: render.CaddyConfig{
			ACMEEmail: "admin@example.invalid",
			S06Open:   true,
		},
		DNS: render.DNSConfig{AValue: "100.64.0.4"},
	}
	opts := site.SeedOptions{
		TagcessHost: "tagcess.example.com",
		// The zitadel record carries its internal sources since F2-013 (seed option, not fixture).
		ZitadelInternalSources: []string{
			"198.51.100.0/24", "127.0.0.1/32", "::1/128",
			"192.0.2.10/32", "2001:db8:10::/64", "192.0.2.20/32", "2001:db8:20::/64",
		},
	}

	h.caddy = newFakeCaddy(h.calls, string(current))
	h.dns = &fakeDNS{calls: h.calls, content: string(extra), exists: true}
	h.uris = &fakeURIs{calls: h.calls}
	h.build()
	return &importHarness{siteHarness: h, seed: seed, seedOpts: opts}
}

// zitadelTestConfig is the zitadel system_config since F2-013: no internal sources (narrowest) and
// the default login paths.
func zitadelTestConfig(t *testing.T) string {
	t.Helper()
	b, err := json.Marshal(struct {
		InternalSources []string `json:"internal_sources"`
		LoginPaths      []string `json:"login_paths"`
	}{InternalSources: []string{}, LoginPaths: site.DefaultZitadelLoginPaths})
	if err != nil {
		t.Fatalf("zitadel config: %v", err)
	}
	return string(b)
}
