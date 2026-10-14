package dashboard

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/site"
)

// The dashboard read model (F4-027, P-01, R3 B-07) is tested with typed provider fakes so each
// source's own time and freshness can be controlled independently. The real adapters are wired in
// F4-031; the model itself never reads or writes anywhere.

// --- typed provider fakes (mutable so a test can make a source fail between reads) ---

type fakeDevices struct {
	read DevicesRead
	err  error
}

func (f *fakeDevices) Devices(context.Context) (DevicesRead, error) {
	if f.err != nil {
		return DevicesRead{}, f.err
	}
	return f.read, nil
}

type fakeRoles struct {
	read RolesRead
	err  error
}

func (f *fakeRoles) VpnRoles(context.Context) (RolesRead, error) {
	if f.err != nil {
		return RolesRead{}, f.err
	}
	return f.read, nil
}

type fakeSites struct {
	read SitesRead
	err  error
}

func (f *fakeSites) ListSites(context.Context) (SitesRead, error) {
	if f.err != nil {
		return SitesRead{}, f.err
	}
	return f.read, nil
}

type fakeObservations struct {
	read ObservationsRead
	err  error
}

func (f *fakeObservations) Observations(context.Context) (ObservationsRead, error) {
	if f.err != nil {
		return ObservationsRead{}, f.err
	}
	return f.read, nil
}

type fakeAlerts struct {
	read AlertsRead
	err  error
}

func (f *fakeAlerts) OpenAlerts(context.Context) (AlertsRead, error) {
	if f.err != nil {
		return AlertsRead{}, f.err
	}
	return f.read, nil
}

type fakeSync struct {
	read SyncRead
	err  error
}

func (f *fakeSync) Sync(context.Context) (SyncRead, error) {
	if f.err != nil {
		return SyncRead{}, f.err
	}
	return f.read, nil
}

type fakeS06 struct {
	read S06Read
	err  error
}

func (f *fakeS06) S06(context.Context) (S06Read, error) {
	if f.err != nil {
		return S06Read{}, f.err
	}
	return f.read, nil
}

// healthyConfig is a complete, all-sources-fresh wiring; tests override the source under test.
func healthyConfig() Config {
	at := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	return Config{
		Devices:      &fakeDevices{read: DevicesRead{ObservedAt: at}},
		Roles:        &fakeRoles{read: RolesRead{ObservedAt: at}},
		Sites:        &fakeSites{read: SitesRead{ObservedAt: at}},
		Observations: &fakeObservations{read: ObservationsRead{ObservedAt: at}},
		Alerts:       &fakeAlerts{read: AlertsRead{ObservedAt: at}},
		Sync:         &fakeSync{read: SyncRead{ObservedAt: at}},
		S06:          &fakeS06{read: S06Read{ObservedAt: at}},
	}
}

func newTestModel(t *testing.T, cfg Config) *Model {
	t.Helper()
	m, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m
}

// AC1: a successful Headscale read yields the connected device count/list and last-seen times with
// that source's own observed_at, and the card never claims a physical access guarantee.
func TestDashboardDeviceCountsAndLastSeen(t *testing.T) {
	at := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	seen := at.Add(-5 * time.Minute)
	older := at.Add(-90 * time.Minute)

	cfg := healthyConfig()
	cfg.Devices = &fakeDevices{read: DevicesRead{
		ObservedAt: at,
		Devices: []Device{
			{ID: 2, Name: "phone", Owner: "ada", Online: false, LastSeen: older},
			{ID: 1, Name: "laptop", Owner: "ada", Online: true, LastSeen: seen},
			{ID: 3, Name: "server", Owner: "ops"}, // never seen
		},
	}}

	v := newTestModel(t, cfg).View(context.Background())

	if v.Devices.Count != 3 || len(v.Devices.Devices) != 3 {
		t.Fatalf("devices count=%d list=%d, want 3/3", v.Devices.Count, len(v.Devices.Devices))
	}
	if v.Devices.Online != 1 {
		t.Errorf("online devices = %d, want 1", v.Devices.Online)
	}
	if v.Devices.Freshness != FreshnessFresh {
		t.Errorf("freshness = %q, want fresh", v.Devices.Freshness)
	}
	if !v.Devices.ObservedAt.Equal(at) {
		t.Errorf("observed_at = %v, want the Headscale source time %v", v.Devices.ObservedAt, at)
	}
	// Deterministic id order.
	for i, want := range []uint64{1, 2, 3} {
		if v.Devices.Devices[i].ID != want {
			t.Errorf("device[%d].ID = %d, want %d", i, v.Devices.Devices[i].ID, want)
		}
	}
	if !v.Devices.Devices[0].LastSeen.Equal(seen) || !v.Devices.Devices[1].LastSeen.Equal(older) {
		t.Errorf("last seen not preserved: %v %v", v.Devices.Devices[0].LastSeen, v.Devices.Devices[1].LastSeen)
	}
	if !v.Devices.Devices[2].LastSeen.IsZero() {
		t.Errorf("never-seen device LastSeen = %v, want zero", v.Devices.Devices[2].LastSeen)
	}
	// Connectivity is not a physical access guarantee: the card must carry the caveat.
	if !strings.Contains(v.Devices.Caveat, "fiziksel") {
		t.Errorf("device caveat = %q, want the physical-access disclaimer", v.Devices.Caveat)
	}
}

// AC2: with the Zitadel roles and the site rules read completely, the model derives only the
// expected Caddy role access (Zitadel vpn roles x role sites); it copies no identity and offers no
// user/role write path.
func TestDashboardExpectedCaddyRoleMatrix(t *testing.T) {
	at := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)

	cfg := healthyConfig()
	cfg.Roles = &fakeRoles{read: RolesRead{ObservedAt: at, Roles: []string{"devops", "developer"}}}
	cfg.Sites = &fakeSites{read: SitesRead{ObservedAt: at, Sites: []site.Site{
		{ID: 1, Hosts: []string{"app.example"}, Kind: site.KindRole, Roles: []string{"developer"}},
		{ID: 2, Hosts: []string{"ops.example"}, Kind: site.KindRole, Roles: []string{"devops", "developer"}},
		{ID: 3, Hosts: []string{"open.example"}, Kind: site.KindOpen, OpenReason: site.OpenReasonIntentional},
		{ID: 4, Hosts: []string{"hs.example"}, Kind: site.KindSystem, SystemTemplate: site.TemplateHeadscale},
	}}}

	v := newTestModel(t, cfg).View(context.Background())

	if v.Matrix.Freshness != FreshnessFresh {
		t.Fatalf("matrix freshness = %q, want fresh", v.Matrix.Freshness)
	}
	if !v.Matrix.ObservedAt.Equal(at) {
		t.Errorf("matrix role source time = %v, want %v", v.Matrix.ObservedAt, at)
	}
	// Rows: the Zitadel vpn roles, sorted.
	if want := []string{"developer", "devops"}; !reflect.DeepEqual(v.Matrix.Roles, want) {
		t.Errorf("matrix roles = %v, want %v", v.Matrix.Roles, want)
	}
	// Columns: role-controlled sites only, in host order. Open/system sites are not matrix columns.
	if len(v.Matrix.Sites) != 2 {
		t.Fatalf("matrix sites = %+v, want the two role sites", v.Matrix.Sites)
	}
	if got := v.Matrix.Sites[0].Hosts; len(got) != 1 || got[0] != "app.example" {
		t.Errorf("matrix site[0] = %v, want app.example", got)
	}
	if got := v.Matrix.Sites[1].Hosts; len(got) != 1 || got[0] != "ops.example" {
		t.Errorf("matrix site[1] = %v, want ops.example", got)
	}
	// Allowed[role][site] is the expected Caddy role access: role is one of the site's roles.
	want := [][]bool{
		{true, true},  // developer: app (yes), ops (yes)
		{false, true}, // devops: app (no), ops (yes)
	}
	if !reflect.DeepEqual(v.Matrix.Allowed, want) {
		t.Errorf("matrix allowed = %v, want %v", v.Matrix.Allowed, want)
	}
	// It is expected access, not a guarantee of effective end-to-end access.
	if !strings.Contains(v.Matrix.Caveat, "beklenen") || !strings.Contains(v.Matrix.Caveat, "etkili") {
		t.Errorf("matrix caveat = %q, want the expected-vs-effective disclaimer", v.Matrix.Caveat)
	}
}

// AC3: when the role source cannot be read the model keeps the previous matrix with its original
// source time and a not-current label; a process with no earlier read shows it as unknown and never
// as effective access.
func TestDashboardRoleMatrixStaleSource(t *testing.T) {
	at := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)

	roles := &fakeRoles{read: RolesRead{ObservedAt: at, Roles: []string{"devops"}}}
	cfg := healthyConfig()
	cfg.Roles = roles
	cfg.Sites = &fakeSites{read: SitesRead{ObservedAt: at, Sites: []site.Site{
		{ID: 1, Hosts: []string{"ops.example"}, Kind: site.KindRole, Roles: []string{"devops"}},
	}}}
	m := newTestModel(t, cfg)

	first := m.View(context.Background())
	if first.Matrix.Freshness != FreshnessFresh || !first.Matrix.ObservedAt.Equal(at) {
		t.Fatalf("first matrix freshness=%q at=%v, want fresh at %v", first.Matrix.Freshness, first.Matrix.ObservedAt, at)
	}

	// The role source goes down: keep the old matrix, its original time, and label it not current.
	roles.err = errors.New("zitadel okunamadı")
	stale := m.View(context.Background())
	if stale.Matrix.Freshness != FreshnessStale {
		t.Errorf("stale matrix freshness = %q, want stale", stale.Matrix.Freshness)
	}
	if !stale.Matrix.ObservedAt.Equal(at) {
		t.Errorf("stale matrix source time = %v, want the original %v", stale.Matrix.ObservedAt, at)
	}
	if want := []string{"devops"}; !reflect.DeepEqual(stale.Matrix.Roles, want) {
		t.Errorf("stale matrix roles = %v, want the previous %v", stale.Matrix.Roles, want)
	}
	if !strings.Contains(stale.Matrix.Caveat, "beklenen") {
		t.Errorf("stale matrix caveat = %q, want the expected-access disclaimer", stale.Matrix.Caveat)
	}

	// Restart: no previous read, the role source fails, the matrix is unknown, not effective access.
	restarted := newTestModel(t, cfg).View(context.Background())
	if restarted.Matrix.Freshness != FreshnessUnknown {
		t.Errorf("cold matrix freshness = %q, want unknown", restarted.Matrix.Freshness)
	}
	if len(restarted.Matrix.Roles) != 0 {
		t.Errorf("cold matrix roles = %v, want none", restarted.Matrix.Roles)
	}
	if !restarted.Matrix.ObservedAt.IsZero() {
		t.Errorf("cold matrix source time = %v, want zero (no source read)", restarted.Matrix.ObservedAt)
	}
}

// AC4: S-06/source rule, API exemption, open intentional/transition, system template and the
// Headscale ACL/device/route limit are explained separately from the role matrix; a private (role)
// intent never hides a broader source rule or API exemption.
func TestPrivateIntentDoesNotHideSourceOrAPIExemption(t *testing.T) {
	at := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)

	cfg := healthyConfig()
	cfg.S06 = &fakeS06{read: S06Read{ObservedAt: at, Open: true}}
	cfg.Sites = &fakeSites{read: SitesRead{ObservedAt: at, Sites: []site.Site{
		{ID: 1, Hosts: []string{"app.example"}, Kind: site.KindRole, Roles: []string{"developer"},
			APIRules: []site.APIRule{{Type: site.APIRuleHeaderPresent, Value: "X-Requested-With"}}},
		{ID: 2, Hosts: []string{"vpn.example"}, Kind: site.KindOpen, OpenReason: site.OpenReasonIntentional},
		{ID: 3, Hosts: []string{"hs.example"}, Kind: site.KindSystem, SystemTemplate: site.TemplateHeadscale},
	}}}

	v := newTestModel(t, cfg).View(context.Background())

	present := map[string]AccessBoundary{}
	for _, b := range v.Boundaries.Boundaries {
		present[b.Kind] = b
	}
	for _, kind := range []string{
		BoundaryS06Source, BoundaryAPIExemption, BoundaryOpenIntent, BoundarySystemTemplate, BoundaryHeadscaleACL,
	} {
		if _, ok := present[kind]; !ok {
			t.Errorf("boundary %q missing from %+v", kind, v.Boundaries.Boundaries)
		}
	}
	// The private role site still exposes its API exemption and the open S-06 source rule.
	if b := present[BoundaryAPIExemption]; b.Subject != "app.example" || !strings.Contains(b.Detail, "bypass") {
		t.Errorf("api exemption boundary = %+v, want app.example with the exemption note", b)
	}
	if b := present[BoundaryS06Source]; !strings.Contains(b.Detail, "kayna") {
		t.Errorf("S-06 boundary = %+v, want the source rule note", b)
	}
	// The matrix stays role-only; the boundaries are not folded into it.
	if len(v.Matrix.Sites) != 1 || v.Matrix.Sites[0].Hosts[0] != "app.example" {
		t.Errorf("matrix sites = %+v, want only the role site", v.Matrix.Sites)
	}
}

// AC5: observation/alert/sync sources with different or missing times each keep their own last-good
// time and freshness; the model never claims one fresh snapshot.
func TestDashboardKeepsIndependentSourceFreshness(t *testing.T) {
	base := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	t1 := base
	t2 := base.Add(1 * time.Minute)
	t3 := base.Add(2 * time.Minute)
	t4 := base.Add(3 * time.Minute)
	t5 := base.Add(4 * time.Minute)

	obs := &fakeObservations{read: ObservationsRead{ObservedAt: t4, Sites: []ObservationSite{
		{Site: "app.example", ObservedAt: t4, Success: true, Categories: []string{"target", "tls"}},
	}}}
	alerts := &fakeAlerts{err: errors.New("alerts okunamadı")} // never read successfully: unknown

	cfg := Config{
		Devices:      &fakeDevices{read: DevicesRead{ObservedAt: t1, Devices: []Device{{ID: 1, Name: "a"}}}},
		Roles:        &fakeRoles{read: RolesRead{ObservedAt: t2, Roles: []string{"devops"}}},
		Sites:        &fakeSites{read: SitesRead{ObservedAt: t3, Sites: []site.Site{{ID: 1, Hosts: []string{"app.example"}, Kind: site.KindRole, Roles: []string{"devops"}}}}},
		Observations: obs,
		Alerts:       alerts,
		Sync:         &fakeSync{read: SyncRead{ObservedAt: t5, Result: "ok", Summary: "değişiklik yok"}},
		S06:          &fakeS06{read: S06Read{ObservedAt: base, Open: false}},
	}
	m := newTestModel(t, cfg)

	// Prime the observation source so it has a last-good value, then let it fail.
	if got := m.View(context.Background()); got.Observations.Freshness != FreshnessFresh {
		t.Fatalf("primed observations freshness = %q, want fresh", got.Observations.Freshness)
	}
	obs.err = errors.New("observer okunamadı")

	v := m.View(context.Background())

	checks := []struct {
		name    string
		state   SourceState
		fresh   Freshness
		wantAt  time.Time
		wantErr bool
	}{
		{"devices", v.Devices.SourceState, FreshnessFresh, t1, false},
		{"matrix", v.Matrix.SourceState, FreshnessFresh, t2, false},
		{"observations", v.Observations.SourceState, FreshnessStale, t4, true},
		{"alerts", v.Alerts.SourceState, FreshnessUnknown, time.Time{}, true},
		{"sync", v.Sync.SourceState, FreshnessFresh, t5, false},
	}
	for _, c := range checks {
		if c.state.Freshness != c.fresh {
			t.Errorf("%s freshness = %q, want %q", c.name, c.state.Freshness, c.fresh)
		}
		if !c.state.ObservedAt.Equal(c.wantAt) {
			t.Errorf("%s observed_at = %v, want %v", c.name, c.state.ObservedAt, c.wantAt)
		}
		if (c.state.Err != nil) != c.wantErr {
			t.Errorf("%s err = %v, wantErr=%v", c.name, c.state.Err, c.wantErr)
		}
	}
	// Each card keeps its own source time; there is no single "fresh snapshot" claim.
	if !v.Matrix.SiteObservedAt.Equal(t3) {
		t.Errorf("matrix site source time = %v, want %v", v.Matrix.SiteObservedAt, t3)
	}
	if v.Devices.ObservedAt.Equal(v.Matrix.ObservedAt) || v.Matrix.ObservedAt.Equal(v.Observations.ObservedAt) {
		t.Errorf("source times are not independent: devices=%v matrix=%v observations=%v",
			v.Devices.ObservedAt, v.Matrix.ObservedAt, v.Observations.ObservedAt)
	}
}

// The matrix freshness is the worse of its two sources across the fresh/stale/unknown combinations
// (the test plan's table-driven matrix). A cold source must never look fresh.
func TestDashboardMatrixFreshnessTable(t *testing.T) {
	at := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name      string
		roleErr   bool
		siteErr   bool
		prime     bool
		want      Freshness
		wantRoles int
	}{
		{"both fresh", false, false, false, FreshnessFresh, 1},
		{"role stale", true, false, true, FreshnessStale, 1},
		{"site stale", false, true, true, FreshnessStale, 1},
		{"role unknown", true, false, false, FreshnessUnknown, 0},
		{"site unknown", false, true, false, FreshnessUnknown, 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			roles := &fakeRoles{read: RolesRead{ObservedAt: at, Roles: []string{"devops"}}}
			sites := &fakeSites{read: SitesRead{ObservedAt: at, Sites: []site.Site{
				{ID: 1, Hosts: []string{"app.example"}, Kind: site.KindRole, Roles: []string{"devops"}},
			}}}
			cfg := healthyConfig()
			cfg.Roles = roles
			cfg.Sites = sites
			m := newTestModel(t, cfg)
			if tc.prime {
				m.View(context.Background())
			}
			if tc.roleErr {
				roles.err = errors.New("zitadel okunamadı")
			}
			if tc.siteErr {
				sites.err = errors.New("site okunamadı")
			}

			v := m.View(context.Background())
			if v.Matrix.Freshness != tc.want {
				t.Errorf("matrix freshness = %q, want %q", v.Matrix.Freshness, tc.want)
			}
			if len(v.Matrix.Roles) != tc.wantRoles {
				t.Errorf("matrix roles = %v, want %d rows", v.Matrix.Roles, tc.wantRoles)
			}
		})
	}
}

// B-L-18: the observations source is optional (the screen reads db.Observation itself). Without it
// the card is unknown, never fresh, and the other cards are unaffected.
func TestDashboardObservationsSourceIsOptional(t *testing.T) {
	cfg := healthyConfig()
	cfg.Observations = nil
	m := newTestModel(t, cfg)
	v := m.View(context.Background())
	if v.Observations.Freshness != FreshnessUnknown || v.Observations.Err == nil {
		t.Fatalf("observations card without a source = %+v, want unknown with a reason", v.Observations.SourceState)
	}
	if v.Devices.Freshness != FreshnessFresh {
		t.Fatalf("a missing observations source changed the devices card: %+v", v.Devices.SourceState)
	}
}
