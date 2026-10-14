package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/alert"
	"github.com/nesiler/tagcess/internal/dashboard"
	"github.com/nesiler/tagcess/internal/health"
	"github.com/nesiler/tagcess/internal/k8s"
	"github.com/nesiler/tagcess/internal/monitor"
	"github.com/nesiler/tagcess/internal/site"
	"github.com/nesiler/tagcess/internal/store/db"
)

// The dashboard screen (F4-028): the devops start page built from the F4-027 read model plus the
// stored measurement observations and the k8s snapshot state. The tests drive the production
// identity middleware chain and the real F4-027 model over typed provider fakes, so each source's
// own time and freshness can be controlled independently. The screen never writes anywhere.

// --- typed F4-027 provider fakes (mutable so a test can make one source fail between reads) ---

type dashDevices struct {
	read dashboard.DevicesRead
	err  error
}

func (f *dashDevices) Devices(context.Context) (dashboard.DevicesRead, error) {
	if f.err != nil {
		return dashboard.DevicesRead{}, f.err
	}
	return f.read, nil
}

type dashRoles struct {
	read dashboard.RolesRead
	err  error
}

func (f *dashRoles) VpnRoles(context.Context) (dashboard.RolesRead, error) {
	if f.err != nil {
		return dashboard.RolesRead{}, f.err
	}
	return f.read, nil
}

type dashSites struct {
	read dashboard.SitesRead
	err  error
}

func (f *dashSites) ListSites(context.Context) (dashboard.SitesRead, error) {
	if f.err != nil {
		return dashboard.SitesRead{}, f.err
	}
	return f.read, nil
}

type dashModelObservations struct {
	read dashboard.ObservationsRead
	err  error
}

func (f *dashModelObservations) Observations(context.Context) (dashboard.ObservationsRead, error) {
	if f.err != nil {
		return dashboard.ObservationsRead{}, f.err
	}
	return f.read, nil
}

type dashAlerts struct {
	read dashboard.AlertsRead
	err  error
}

func (f *dashAlerts) OpenAlerts(context.Context) (dashboard.AlertsRead, error) {
	if f.err != nil {
		return dashboard.AlertsRead{}, f.err
	}
	return f.read, nil
}

type dashSync struct {
	read dashboard.SyncRead
	err  error
}

func (f *dashSync) Sync(context.Context) (dashboard.SyncRead, error) {
	if f.err != nil {
		return dashboard.SyncRead{}, f.err
	}
	return f.read, nil
}

type dashS06 struct {
	read dashboard.S06Read
	err  error
}

func (f *dashS06) S06(context.Context) (dashboard.S06Read, error) {
	if f.err != nil {
		return dashboard.S06Read{}, f.err
	}
	return f.read, nil
}

// fakeDashboardObservations is the raw observation reader (F4-017) the screen groups into cards.
type fakeDashboardObservations struct {
	rows []db.Observation
	err  error
}

func (f *fakeDashboardObservations) Observations(context.Context) ([]db.Observation, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.rows, nil
}

// fakeDashboardSnapshot is the F4-007 snapshot reader.
type fakeDashboardSnapshot struct {
	state k8s.State
	err   error
}

func (f *fakeDashboardSnapshot) State(context.Context) (k8s.State, error) {
	return f.state, f.err
}

// --- harness ---

type dashboardHarness struct {
	t        *testing.T
	devices  *dashDevices
	roles    *dashRoles
	sites    *dashSites
	modelObs *dashModelObservations
	alerts   *dashAlerts
	sync     *dashSync
	s06      *dashS06
	obs      *fakeDashboardObservations
	snapshot *fakeDashboardSnapshot
	csrf     *CSRF
	chain    http.Handler
	now      time.Time // the page clock; rows dated later than it are never over-age

	driftHeld bool
	loops     []monitor.JobStatus
	setup     []SetupStep // pending installation steps (F5 A2)
}

func newDashboardHarness(t *testing.T) *dashboardHarness {
	t.Helper()
	at := time.Date(2026, 10, 5, 10, 0, 0, 0, time.UTC)
	h := &dashboardHarness{
		now:      at.Add(30 * time.Second),
		t:        t,
		devices:  &dashDevices{read: dashboard.DevicesRead{ObservedAt: at}},
		roles:    &dashRoles{read: dashboard.RolesRead{ObservedAt: at}},
		sites:    &dashSites{read: dashboard.SitesRead{ObservedAt: at}},
		modelObs: &dashModelObservations{read: dashboard.ObservationsRead{ObservedAt: at}},
		alerts:   &dashAlerts{read: dashboard.AlertsRead{ObservedAt: at}},
		sync:     &dashSync{read: dashboard.SyncRead{ObservedAt: at}},
		s06:      &dashS06{read: dashboard.S06Read{ObservedAt: at}},
		obs:      &fakeDashboardObservations{},
		snapshot: &fakeDashboardSnapshot{},
	}
	model, err := dashboard.New(dashboard.Config{
		Devices:      h.devices,
		Roles:        h.roles,
		Sites:        h.sites,
		Observations: h.modelObs,
		Alerts:       h.alerts,
		Sync:         h.sync,
		S06:          h.s06,
	})
	if err != nil {
		t.Fatalf("dashboard.New: %v", err)
	}
	h.csrf = testCSRF(t)
	handler, err := NewDashboardHandler(DashboardHandlerConfig{
		Model: model, Observations: h.obs, Snapshot: h.snapshot, CSRF: h.csrf,
		Now:       func() time.Time { return h.now },
		DriftHeld: func() bool { return h.driftHeld },
		Loops:     func() []monitor.JobStatus { return h.loops },
		Setup:     func(context.Context) []SetupStep { return h.setup },
	})
	if err != nil {
		t.Fatalf("NewDashboardHandler: %v", err)
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	h.chain = RequireDevops(mux)
	return h
}

// get drives the production chain with an explicit groups header.
func (h *dashboardHarness) get(groups string) *httptest.ResponseRecorder {
	h.t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.Header.Set(headerUser, "devops-user")
	req.Header.Set(headerEmail, "devops@example.com")
	req.Header.Set(headerGroups, groups)
	rec := httptest.NewRecorder()
	h.chain.ServeHTTP(rec, req)
	return rec
}

// devopsPage fetches the page as a devops operator and fails the test on a non-200.
func (h *dashboardHarness) devopsPage() string {
	h.t.Helper()
	rec := h.get(devopsGroup)
	if rec.Code != http.StatusOK {
		h.t.Fatalf("GET / = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

// cardFragment returns the HTML of one data-card section, up to the next card. It lets a test prove
// that a value landed in the right card instead of somewhere on the page.
func cardFragment(body, card string) string {
	marker := `data-card="` + card + `"`
	i := strings.Index(body, marker)
	if i < 0 {
		return ""
	}
	rest := body[i:]
	j := strings.Index(rest[len(marker):], `data-card="`)
	if j < 0 {
		return rest
	}
	return rest[:len(marker)+j]
}

// obsAt formats a time as the observation store's canonical fixed-width UTC text.
func obsAt(t time.Time) string { return t.UTC().Format(obsTimeFormat) }

// goodRow builds a successful observation row for the given category.
func goodRow(id int64, category, host string, at time.Time) db.Observation {
	return db.Observation{
		ID: id, Category: category, Site: "s1", Host: host, Source: category,
		ObservedAt: obsAt(at), LastAttemptAt: obsAt(at), Success: 1, HttpStatus: 200,
	}
}

// AC1: the page shows distinct cards for devices/last-seen, sync, target, Caddy gate, TLS, drift and
// the k8s snapshot freshness.
func TestDashboardPageShowsDistinctHealthCards(t *testing.T) {
	h := newDashboardHarness(t)
	at := time.Date(2026, 10, 5, 10, 0, 0, 0, time.UTC)

	h.devices.read = dashboard.DevicesRead{ObservedAt: at, Devices: []dashboard.Device{
		{ID: 1, Name: "laptop", Owner: "enes", Online: true, LastSeen: at},
		{ID: 2, Name: "server", Owner: "enes"},
	}}
	h.sync.read = dashboard.SyncRead{ObservedAt: at, Result: "applied", Summary: "değişiklik yok"}
	h.roles.read = dashboard.RolesRead{ObservedAt: at, Roles: []string{"developer"}}
	h.sites.read = dashboard.SitesRead{ObservedAt: at, Sites: []site.Site{
		{ID: 1, Kind: site.KindRole, Hosts: []string{"app.example"}, Roles: []string{"developer"}},
	}}
	h.alerts.read = dashboard.AlertsRead{ObservedAt: at, Alerts: []dashboard.Alert{
		{Kind: alert.KindDrift, Subject: "policy", Severity: "critical", State: "active", Freshness: "fresh"},
	}}

	target := goodRow(1, obsCategoryTarget, "app.example", at)
	gate := goodRow(2, obsCategoryGate, "app.example", at)
	tls := goodRow(3, obsCategoryTLS, "app.example", at)
	tls.TlsNotAfter = obsAt(at.Add(60 * 24 * time.Hour))
	risk := goodRow(4, obsCategoryRisk, "app.example", at)
	risk.Source = obsSourceConfig
	risk.Route = "app.example/"
	risk.RiskFinding = "alternate_path_candidate"
	risk.UnscannedScope = "internet"
	probe := goodRow(5, obsCategoryRisk, "app.example", at)
	probe.Source = obsSourceProbe
	probe.Route = "app.example/"
	probe.Vantage = "tagcess-net"
	probe.Endpoint = "10.0.0.9:8443"
	h.obs.rows = []db.Observation{target, gate, tls, risk, probe}
	h.snapshot.state = k8s.State{Current: &k8s.Snapshot{ID: 1, Scope: "ns-a", ObservedAt: at}}

	body := h.devopsPage()

	for _, card := range []string{
		"devices", "matrix", "boundaries", "sync", "alerts", "drift",
		"target", "caddy_gate", "tls", "two_gate", "k8s_snapshot",
	} {
		if !strings.Contains(body, `data-card="`+card+`"`) {
			t.Errorf("the page is missing the %q card", card)
		}
	}

	// The cards are distinct: the device appears in the device card, the target host in the target
	// card, the drift artifact in the drift card and the snapshot time in the snapshot card.
	if got := cardFragment(body, "devices"); !strings.Contains(got, "laptop") {
		t.Errorf("the device card does not show the device:\n%s", got)
	}
	if got := cardFragment(body, "sync"); !strings.Contains(got, "applied") {
		t.Errorf("the sync card does not show the result:\n%s", got)
	}
	if got := cardFragment(body, "target"); !strings.Contains(got, "app.example") {
		t.Errorf("the target card does not show the observed host:\n%s", got)
	}
	if got := cardFragment(body, "caddy_gate"); !strings.Contains(got, "caddy_gate") {
		t.Errorf("the Caddy gate card does not show its source:\n%s", got)
	}
	if got := cardFragment(body, "tls"); !strings.Contains(got, "bitiş:") {
		t.Errorf("the TLS card does not show the leaf expiry:\n%s", got)
	}
	if got := cardFragment(body, "drift"); !strings.Contains(got, "policy") {
		t.Errorf("the drift card does not show the drifted artifact:\n%s", got)
	}
	if got := cardFragment(body, "k8s_snapshot"); !strings.Contains(got, at.Format("2006-01-02 15:04:05")) {
		t.Errorf("the snapshot card does not show the snapshot time:\n%s", got)
	}
}

// AC2: the configuration risk and the measurement of the same route are shown together; vantage,
// endpoint and time stay visible, the internet is always listed as not tested, and the risk is never
// cleared by a measurement.
func TestDashboardPageShowsScopedTwoGateEvidence(t *testing.T) {
	h := newDashboardHarness(t)
	at := time.Date(2026, 10, 5, 11, 0, 0, 0, time.UTC)

	risk := goodRow(1, obsCategoryRisk, "app.example", at)
	risk.Source = obsSourceConfig
	risk.Route = "app.example/"
	risk.RiskFinding = "alternate_path_candidate"
	risk.RiskContext = "raw-risk-context-must-not-leak"
	risk.UnscannedScope = "internet,gateway"
	probe := goodRow(2, obsCategoryRisk, "app.example", at)
	probe.Source = obsSourceProbe
	probe.Route = "app.example/"
	probe.Vantage = "tagcess-net"
	probe.Endpoint = "10.0.0.9:8443"
	probe.LastError = "raw-error-must-not-leak"
	h.obs.rows = []db.Observation{risk, probe}

	body := h.devopsPage()
	two := cardFragment(body, "two_gate")
	for _, want := range []string{
		"alternatif yol adayı", "tagcess-net", "10.0.0.9:8443",
		at.Format("2006-01-02 15:04:05"), "İnternet erişimi test edilmedi", "Gateway API taranmadı",
		`data-risk="preserved"`,
	} {
		if !strings.Contains(two, want) {
			t.Errorf("the two-gate card is missing %q:\n%s", want, two)
		}
	}
	for _, leak := range []string{"raw-error-must-not-leak", "raw-risk-context-must-not-leak"} {
		if strings.Contains(body, leak) {
			t.Errorf("stored raw text %q reached the page", leak)
		}
	}

	// A failed measurement keeps the risk visible and is shown with a fixed label, never as healthy.
	probe.ObservedAt = ""
	probe.Success = 0
	probe.LastResult = "timeout"
	probe.HttpStatus = 0
	h.obs.rows = []db.Observation{risk, probe}
	two = cardFragment(h.devopsPage(), "two_gate")
	if !strings.Contains(two, `data-risk="preserved"`) || !strings.Contains(two, "alternatif yol adayı") {
		t.Errorf("a failed measurement hid the configuration risk:\n%s", two)
	}
	if !strings.Contains(two, "zaman aşımı") {
		t.Errorf("the failed measurement's fixed label is missing:\n%s", two)
	}
	if !strings.Contains(two, `data-freshness="never"`) {
		t.Errorf("a never-good measurement is not shown as never:\n%s", two)
	}

	// A risk row with no measurement is never shown as fresh.
	risk.RiskFinding = "unknown"
	h.obs.rows = []db.Observation{risk}
	two = cardFragment(h.devopsPage(), "two_gate")
	if strings.Contains(two, `data-freshness="fresh"`) {
		t.Errorf("a lone configuration-risk row was shown as fresh:\n%s", two)
	}
	if !strings.Contains(two, "belirsiz config riski") {
		t.Errorf("the unknown risk finding is not shown:\n%s", two)
	}
}

// AC3: a stale role source keeps the matrix on its ORIGINAL source time and must not be shown as
// current effective access.
func TestDashboardPageShowsStaleExpectedMatrix(t *testing.T) {
	h := newDashboardHarness(t)
	good := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	h.roles.read = dashboard.RolesRead{ObservedAt: good, Roles: []string{"developer"}}
	h.sites.read = dashboard.SitesRead{ObservedAt: good, Sites: []site.Site{
		{ID: 1, Kind: site.KindRole, Hosts: []string{"app.example"}, Roles: []string{"developer"}},
	}}

	// Prime the last-good role source, then make it fail.
	first := cardFragment(h.devopsPage(), "matrix")
	if !strings.Contains(first, `data-freshness="fresh"`) {
		t.Fatalf("the first matrix read is not fresh:\n%s", first)
	}

	h.roles.err = errors.New("zitadel okunamadı")
	stale := cardFragment(h.devopsPage(), "matrix")
	if !strings.Contains(stale, `data-freshness="stale"`) {
		t.Errorf("a failed role source did not mark the matrix stale:\n%s", stale)
	}
	if !strings.Contains(stale, "güncel değil") {
		t.Errorf("the stale matrix is not labelled:\n%s", stale)
	}
	if !strings.Contains(stale, good.Format("2006-01-02 15:04:05")) {
		t.Errorf("the stale matrix lost its original source time:\n%s", stale)
	}
	if !strings.Contains(stale, "etkili erişim iddiası değildir") {
		t.Errorf("the stale matrix claims effective access:\n%s", stale)
	}
}

// AC4: open/intentional, system, API-exempt and S-06/ACL boundaries are explained separately from
// the role matrix, so a broader access rule never hides inside a "private" intent.
func TestDashboardPageExplainsAccessBoundaries(t *testing.T) {
	h := newDashboardHarness(t)
	at := time.Date(2026, 10, 5, 13, 0, 0, 0, time.UTC)
	h.s06.read = dashboard.S06Read{Open: true, ObservedAt: at}
	h.roles.read = dashboard.RolesRead{ObservedAt: at, Roles: []string{"developer"}}
	h.sites.read = dashboard.SitesRead{ObservedAt: at, Sites: []site.Site{
		{ID: 1, Kind: site.KindRole, Hosts: []string{"role.example"}, Roles: []string{"developer"},
			APIRules: []site.APIRule{{Type: "header", Value: "X-Api-Key"}}},
		{ID: 2, Kind: site.KindOpen, Hosts: []string{"open.example"}, OpenReason: site.OpenReasonIntentional},
		{ID: 3, Kind: site.KindSystem, Hosts: []string{"sys.example"}, SystemTemplate: "tagcess"},
	}}

	body := h.devopsPage()
	boundaries := cardFragment(body, "boundaries")
	for _, want := range []string{"s06_source", "api_exemption", "open_intent", "system_template", "headscale_acl"} {
		if !strings.Contains(boundaries, want) {
			t.Errorf("the boundaries card is missing %q:\n%s", want, boundaries)
		}
	}
	matrix := cardFragment(body, "matrix")
	if strings.Contains(matrix, "open.example") || strings.Contains(matrix, "sys.example") {
		t.Errorf("a boundary-only site was mixed into the role matrix:\n%s", matrix)
	}
	if !strings.Contains(matrix, "role.example") {
		t.Errorf("the role-controlled site is missing from the matrix:\n%s", matrix)
	}
}

// AC5: only a devops actor reaches the page, and HTML in a source value is escaped.
func TestDashboardPageDevopsOnlyAndEscaped(t *testing.T) {
	h := newDashboardHarness(t)

	for _, groups := range []string{"", "users", "vpn"} {
		if rec := h.get(groups); rec.Code != http.StatusForbidden {
			t.Errorf("GET / with groups %q = %d, want 403", groups, rec.Code)
		}
	}

	at := time.Date(2026, 10, 5, 14, 0, 0, 0, time.UTC)
	const payload = `<script>alert("x")</script>`
	row := goodRow(1, obsCategoryTarget, payload, at)
	row.Site = payload
	row.Endpoint = payload
	h.obs.rows = []db.Observation{row}

	body := h.devopsPage()
	if strings.Contains(body, payload) {
		t.Errorf("the raw payload reached the page unescaped:\n%s", body)
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Errorf("the observation value was not HTML-escaped:\n%s", body)
	}
	lower := strings.ToLower(body)
	for _, forbidden := range []string{"mailto:", `action="/webhook`, `action="/email`, `action="/push`, `action="/notify`} {
		if strings.Contains(lower, forbidden) {
			t.Errorf("the dashboard offers a notification affordance %q", forbidden)
		}
	}
}

// AC6: when a source errors or was never read, its card stays visible as unknown instead of the page
// assuming every card is healthy.
func TestDashboardPageUnknownSourcesRemainVisible(t *testing.T) {
	h := newDashboardHarness(t)
	fail := errors.New("kaynak yok")
	h.devices.err = fail
	h.roles.err = fail
	h.sites.err = fail
	h.modelObs.err = fail
	h.alerts.err = fail
	h.sync.err = fail
	h.s06.err = fail
	h.obs.err = fail
	h.snapshot.err = fail

	body := h.devopsPage()
	cards := []string{
		"devices", "matrix", "boundaries", "sync", "alerts", "drift",
		"target", "caddy_gate", "tls", "two_gate", "k8s_snapshot",
	}
	for _, card := range cards {
		frag := cardFragment(body, card)
		if frag == "" {
			t.Errorf("the %q card disappeared on a failed source", card)
			continue
		}
		if !strings.Contains(frag, `data-freshness="unknown"`) {
			t.Errorf("the %q card is not unknown on a failed source:\n%s", card, frag)
		}
	}
	if strings.Contains(body, `data-freshness="fresh"`) {
		t.Errorf("a failed source was reported as fresh:\n%s", body)
	}
	if !strings.Contains(body, "bilinmiyor") {
		t.Errorf("the page does not show the unknown state:\n%s", body)
	}
	// The S-06 boundary is still explained as unreadable, never as closed.
	b := cardFragment(body, "boundaries")
	if row := b[strings.Index(b, `data-boundary="s06_source"`)+1:]; !strings.Contains(b, `data-boundary="s06_source"`) ||
		!strings.Contains(row[:strings.Index(row, "</tr>")], "<td>bilinmiyor</td>") || strings.Contains(row[:strings.Index(row, "</tr>")], "<td>kapalı</td>") {
		t.Errorf("the unreadable S-06 boundary is not shown as unknown")
	}
	if !strings.Contains(b, "s06_source") {
		t.Errorf("the unreadable S-06 boundary is not explained")
	}
}

// cardFreshnessOf is the freshness on the card's own section tag (rows carry their own).
func cardFreshnessOf(body, card string) string {
	frag := cardFragment(body, card)
	i := strings.Index(frag, `data-freshness="`)
	if i < 0 {
		return ""
	}
	rest := frag[i+len(`data-freshness="`):]
	return rest[:strings.Index(rest, `"`)]
}

// C-H1/B-H-3: an old green row of a changed path must not hide the current failing row.
func TestDashboardOldRowDoesNotMaskFailingTarget(t *testing.T) {
	h := newDashboardHarness(t)
	at := time.Date(2026, 10, 5, 10, 0, 0, 0, time.UTC)
	old := goodRow(1, obsCategoryTarget, "app.example", at.Add(-time.Hour))
	old.Path = "/"
	cur := goodRow(2, obsCategoryTarget, "app.example", at)
	cur.Path = "/healthz"
	cur.Success, cur.LastResult, cur.HttpStatus = 0, "unexpected_status", 0
	h.obs.rows = []db.Observation{old, cur}
	h.now = at.Add(10 * time.Second)

	card := cardFragment(h.devopsPage(), obsCategoryTarget)
	if got := cardFreshnessOf(h.devopsPage(), obsCategoryTarget); got != "stale" {
		t.Fatalf("the target card must follow the current failing row (stale):\n%s", card)
	}
	if !strings.Contains(card, "/healthz") {
		t.Fatalf("the current row is not shown:\n%s", card)
	}

	// The reverse: an old failing row must not keep a recovered target looking stale.
	old.Success, old.LastResult = 0, "unexpected_status"
	cur.Success, cur.LastResult, cur.HttpStatus = 1, "ok", 200
	h.obs.rows = []db.Observation{old, cur}
	if got := cardFreshnessOf(h.devopsPage(), obsCategoryTarget); got != "fresh" {
		t.Fatalf("a recovered target card is %q, want fresh despite the old failing row", got)
	}
}

// C-M1/B-M-7: a success older than twice its interval is "güncel değil"; a TLS row uses the TLS
// interval; a recent success stays fresh.
func TestDashboardOverAgeRowIsStale(t *testing.T) {
	h := newDashboardHarness(t)
	at := time.Date(2026, 10, 5, 10, 0, 0, 0, time.UTC)
	h.obs.rows = []db.Observation{
		goodRow(1, obsCategoryTarget, "app.example", at),
		goodRow(2, obsCategoryTLS, "app.example", at),
	}

	h.now = at.Add(110 * time.Second) // under 2 x 60 s
	body := h.devopsPage()
	if cardFreshnessOf(body, obsCategoryTarget) != "fresh" {
		t.Fatal("a recent success must be fresh")
	}

	h.now = at.Add(3 * time.Minute) // over 2 x 60 s; far under the 6 h TLS interval
	body = h.devopsPage()
	if got := cardFreshnessOf(body, obsCategoryTarget); got != "stale" {
		t.Errorf("a success older than twice the target interval is %q, want stale", got)
	}
	if got := cardFreshnessOf(body, obsCategoryTLS); got != "fresh" {
		t.Errorf("a TLS row is judged by the TLS interval: %q, want fresh", got)
	}

	h.now = at.Add(13 * time.Hour)
	if cardFreshnessOf(h.devopsPage(), obsCategoryTLS) != "stale" {
		t.Error("a TLS success older than twice the TLS interval must be stale")
	}
}

// A-M3: an artifact whose drift could not be evaluated is listed as unknown, and the card never says
// "no open drift alert" in that state.
func TestDashboardDriftCardShowsUnknownArtifacts(t *testing.T) {
	h := newDashboardHarness(t)
	at := time.Date(2026, 10, 5, 10, 0, 0, 0, time.UTC)
	h.alerts.read = dashboard.AlertsRead{ObservedAt: at, Alerts: []dashboard.Alert{
		{Kind: alert.KindSourceStale, Subject: "policy", Source: alert.SourceDrift, Severity: "warning", State: "active", Freshness: "stale"},
		{Kind: alert.KindSourceStale, Subject: "app.example", Source: alert.AlertSourceTarget, Severity: "warning", State: "active", Freshness: "stale"},
	}}
	card := cardFragment(h.devopsPage(), "drift")
	if strings.Contains(card, "Açık drift uyarısı yok") {
		t.Fatalf("the drift card says there is no drift while it could not be evaluated:\n%s", card)
	}
	if !strings.Contains(card, `data-drift-unknown-subject="policy"`) || !strings.Contains(card, "bilinmiyor/temel yok") {
		t.Fatalf("the unknown policy artifact is not listed:\n%s", card)
	}
	if strings.Contains(card, "app.example") {
		t.Fatalf("a target freshness alert leaked into the drift card:\n%s", card)
	}

	h.alerts.read = dashboard.AlertsRead{ObservedAt: at}
	if card := cardFragment(h.devopsPage(), "drift"); !strings.Contains(card, "Açık drift uyarısı yok") {
		t.Fatalf("an evaluated, clean state must still say so:\n%s", card)
	}
}

// C-L13: the Turkish failure labels cover exactly the runner's label set.
func TestDashboardResultLabelsCoverTheRunnerLabels(t *testing.T) {
	for _, l := range health.FailureLabels() {
		if _, ok := observationResultText[l]; !ok {
			t.Errorf("no Turkish text for the failure label %q", l)
		}
	}
	if len(observationResultText) != len(health.FailureLabels()) {
		t.Errorf("web has %d failure labels, health has %d", len(observationResultText), len(health.FailureLabels()))
	}
}

// M2: a drift check held by an apply or maintenance window is quiet, but the card says so instead of
// "no open drift alert".
func TestDashboardDriftCardShowsHold(t *testing.T) {
	h := newDashboardHarness(t)
	h.driftHeld = true
	card := cardFragment(h.devopsPage(), "drift")
	if strings.Contains(card, "Açık drift uyarısı yok") {
		t.Fatalf("a held drift check reads as no drift:\n%s", card)
	}
	if !strings.Contains(card, "karşılaştırma bekletiliyor (bakım/apply)") {
		t.Fatalf("the hold line is missing:\n%s", card)
	}
	h.driftHeld = false
	if card := cardFragment(h.devopsPage(), "drift"); !strings.Contains(card, "Açık drift uyarısı yok") || strings.Contains(card, "bekletiliyor") {
		t.Fatalf("positive control (not held, good sources) lost its text:\n%s", card)
	}
}

// L4: the loops block lists every job with its state and last run, from monitor.Loops.Status.
func TestDashboardShowsLoopStatus(t *testing.T) {
	h := newDashboardHarness(t)
	last := time.Date(2026, 10, 5, 9, 59, 0, 0, time.UTC)
	h.loops = []monitor.JobStatus{
		{Job: monitor.JobInventory, State: monitor.StateFresh, LastAttempt: last, LastSuccess: last},
		{Job: monitor.JobHealth, State: monitor.StateStale, LastAttempt: last, Err: errors.New("secret-raw-error")},
		{Job: monitor.JobDrift, State: monitor.StateUnknown},
	}
	page := h.devopsPage()
	card := cardFragment(page, "loops")
	for _, want := range []string{
		`data-loop="` + monitor.JobInventory + `"`, `data-loop-state="fresh"`, "2026-10-05 09:59:00",
		`data-loop="` + monitor.JobHealth + `"`, `data-loop-state="stale"`, `data-loop-state="unknown"`,
	} {
		if !strings.Contains(card, want) {
			t.Errorf("loops card lacks %q:\n%s", want, card)
		}
	}
	if strings.Contains(page, "secret-raw-error") {
		t.Error("the loops block echoed a raw job error")
	}
}

// F5 A2/D1-D3/C2: while the installation is unfinished the page shows ONE "kurulum bekliyor" box with
// a link per pending step, and the cards that wait for those steps say "Kurulum bekleniyor: <step>"
// instead of an unexplained "bilinmiyor". Once the steps are done the box and the notes are gone.
func TestDashboardSetupPendingIsOneState(t *testing.T) {
	h := newDashboardHarness(t)
	h.snapshot.err = k8s.ErrNotSet
	h.setup = []SetupStep{
		{Key: SetupFirstImport, Label: "İlk import apply edilmedi", Href: "/sites/first-import"},
		{Key: SetupProbePolicy, Label: "Probe IP policy'si kayıtlı değil", Href: "/k8s/setup"},
		{Key: SetupK8sProfile, Label: "k8s bağlantı profili kayıtlı değil", Href: "/k8s/setup"},
	}
	h.loops = []monitor.JobStatus{
		{Job: monitor.JobInventory, State: monitor.StateMissing, Err: k8s.ErrNotSet},
		{Job: monitor.JobHealth, State: monitor.StateMissing, Err: monitor.ErrSetupPending},
	}
	body := h.devopsPage()

	if n := strings.Count(body, `data-setup-box="true"`); n != 1 {
		t.Fatalf("setup boxes = %d, want exactly one", n)
	}
	box := body[strings.Index(body, `data-setup-box="true"`):]
	for _, want := range []string{"Kurulum bekliyor", `href="/sites/first-import"`, `href="/k8s/setup"`, "İlk import apply edilmedi"} {
		if !strings.Contains(box, want) {
			t.Errorf("setup box lacks %q", want)
		}
	}
	for _, card := range []string{"drift", "target", "caddy_gate", "tls", "k8s_snapshot"} {
		if !strings.Contains(cardFragment(body, card), "Kurulum bekleniyor") {
			t.Errorf("the %q card does not say what it waits for:\n%s", card, cardFragment(body, card))
		}
	}
	if !strings.Contains(cardFragment(body, "loops"), "Kurulum bekleniyor") {
		t.Errorf("the loops card does not say why a job is missing")
	}

	// Positive control: nothing pending → no box, no waiting notes, the usual unknown text.
	h.setup = nil
	h.snapshot.err = nil
	h.loops = nil
	body = h.devopsPage()
	if strings.Contains(body, `data-setup-box`) || strings.Contains(body, "Kurulum bekleniyor") {
		t.Error("a finished installation still shows the setup state")
	}
}

// F5 D2: the empty role matrix names the next step.
func TestDashboardEmptyMatrixNamesNextStep(t *testing.T) {
	h := newDashboardHarness(t)
	card := cardFragment(h.devopsPage(), "matrix")
	if !strings.Contains(card, `href="/sites/new"`) {
		t.Errorf("the empty matrix does not link to the next step:\n%s", card)
	}
}

// F5 D4: Headscale's last_seen of a connected node can be old (assumed: written on disconnect), so a connected device must not
// show that old timestamp as if it were "last seen"; an offline device still shows it.
func TestDashboardOnlineDeviceIsNotShownWithStaleLastSeen(t *testing.T) {
	h := newDashboardHarness(t)
	stale := time.Date(2026, 10, 5, 8, 12, 0, 0, time.UTC)
	h.devices.read = dashboard.DevicesRead{ObservedAt: stale, Devices: []dashboard.Device{
		{ID: 1, Name: "online-box", Owner: "enes", Online: true, LastSeen: stale},
		{ID: 2, Name: "offline-box", Owner: "enes", LastSeen: stale},
	}}
	card := cardFragment(h.devopsPage(), "devices")
	online := rowContaining(t, card, "online-box")
	offline := rowContaining(t, card, "offline-box")
	if strings.Contains(online, "2026-10-05 08:12") || !strings.Contains(online, "şu an bağlı") {
		t.Errorf("online device row = %q, want \"şu an bağlı\" and no stale timestamp", online)
	}
	if !strings.Contains(offline, "2026-10-05 08:12") {
		t.Errorf("offline device row = %q, want its last seen time", offline)
	}
}

// F5 L3: an acknowledged drift alert is shown as "okundu", not as an active critical; the alerts card
// says how many of the open alerts are read. The control: an active row keeps its severity.
func TestDashboardDriftCardAcknowledgedNotCritical(t *testing.T) {
	h := newDashboardHarness(t)
	at := time.Date(2026, 10, 5, 10, 0, 0, 0, time.UTC)
	h.alerts.read = dashboard.AlertsRead{ObservedAt: at, Alerts: []dashboard.Alert{
		{Kind: alert.KindDrift, Subject: "caddyfile", Source: alert.SourceDrift, Severity: "critical", State: string(alert.StateAcknowledged), Freshness: "fresh"},
		{Kind: alert.KindDrift, Subject: "caddy_live", Source: alert.SourceDrift, Severity: "critical", State: string(alert.StateActive), Freshness: "fresh"},
	}}
	page := h.devopsPage()
	card := cardFragment(page, "drift")
	row := func(subject string) string {
		i := strings.Index(card, `data-drift-subject="`+subject+`"`)
		if i < 0 {
			t.Fatalf("no row for %s:\n%s", subject, card)
		}
		end := strings.Index(card[i:], "</tr>")
		return card[i : i+end]
	}
	acked := row("caddyfile")
	if strings.Contains(acked, "critical") || !strings.Contains(acked, "okundu") || !strings.Contains(acked, `data-drift-state="acknowledged"`) {
		t.Errorf("acknowledged row reads as critical or lacks okundu:\n%s", acked)
	}
	active := row("caddy_live")
	if !strings.Contains(active, "critical") || strings.Contains(active, "okundu") {
		t.Errorf("control: active row lost its severity:\n%s", active)
	}
	if alerts := cardFragment(page, "alerts"); !strings.Contains(alerts, "Açık uyarı: 2") || !strings.Contains(alerts, "1 okundu") {
		t.Errorf("alerts card does not split the read alerts:\n%s", alerts)
	}
}
