// Package dashboard builds the read-only F4 dashboard model (P-01, R3 B-07, ADR 0032 proposal).
//
// The model combines narrow, typed, read-only sources: the Headscale devices, the Zitadel vpn
// roles, the stored site rules, the measurement observations (F4-017), the monitor alerts (F4-023),
// the last sync run and the S-06 source-rule key. It never writes anywhere and copies no identity:
// Zitadel stays the only user/role store (AGENTS.md rule 3).
//
// Every card carries its OWN last-good source time and freshness. A failed read keeps the previous
// value with its ORIGINAL observed_at and marks it stale; a source that never read successfully is
// unknown. A stale cache is never re-stamped with the time of the failed attempt, and the matrix is
// labelled "expected Caddy role access", never effective end-to-end access.
//
// The real adapters (Headscale admin reader, vpnuser resolver, site store, observation/alert/sync
// readers and the settings reader) are wired in F4-031; this package only defines the small read
// interfaces so the model is testable with fakes.
package dashboard

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/nesiler/tagcess/internal/site"
)

// Freshness is the label of one card's own source evidence. It is per source, never global: the
// dashboard never claims that one fresh snapshot covers every card.
type Freshness string

const (
	// FreshnessFresh means the source was read successfully in this cycle.
	FreshnessFresh Freshness = "fresh"
	// FreshnessStale means the source could not be read but a previous last-good value is kept,
	// with its original observed_at.
	FreshnessStale Freshness = "stale"
	// FreshnessUnknown means the source could not be read and no last-good value exists.
	FreshnessUnknown Freshness = "unknown"
)

// SourceState is the per-card source evidence: the last-good observed_at, the freshness and the
// read error (if any). On stale/unknown the time is the ORIGINAL source time, never the failed
// attempt's.
type SourceState struct {
	ObservedAt time.Time
	Freshness  Freshness
	Err        error
}

// Device is one Headscale node as the device card shows it. A zero LastSeen means the node was
// never seen. Connectivity here is NOT a physical access guarantee.
type Device struct {
	ID       uint64
	Name     string
	Owner    string
	Online   bool
	LastSeen time.Time
}

// DevicesRead is one successful Headscale device read with the source's own observation time.
type DevicesRead struct {
	Devices    []Device
	ObservedAt time.Time
}

// DevicesSource reads the Headscale device list. It is read-only by construction.
type DevicesSource interface {
	Devices(ctx context.Context) (DevicesRead, error)
}

// RolesRead is one successful Zitadel vpn role read with its own observation time. It carries only
// role keys, never user identities.
type RolesRead struct {
	Roles      []string
	ObservedAt time.Time
}

// RolesSource reads the distinct Zitadel vpn roles. It is read-only: the model creates no user and
// assigns no role.
type RolesSource interface {
	VpnRoles(ctx context.Context) (RolesRead, error)
}

// SitesRead is one successful site-rule read with its own observation time. It reuses the stored
// site records (internal/site) so the matrix is derived from the same rules the Caddyfile renderer
// uses.
type SitesRead struct {
	Sites      []site.Site
	ObservedAt time.Time
}

// SitesSource reads the managed site records. It is read-only (satisfied by *site.Store.ListSites
// through a thin adapter); the model never changes a site.
type SitesSource interface {
	ListSites(ctx context.Context) (SitesRead, error)
}

// ObservationSite is the aggregated observation state of one site (F4-017): the newest last-good
// time, the last attempt and whether it succeeded, and the categories observed.
type ObservationSite struct {
	Site          string
	ObservedAt    time.Time
	LastAttemptAt time.Time
	Success       bool
	Categories    []string
}

// ObservationsRead is one read of the stored measurement observations.
type ObservationsRead struct {
	ObservedAt time.Time
	Sites      []ObservationSite
}

// ObservationsSource reads the stored measurement observations (F4-017). It is read-only.
type ObservationsSource interface {
	Observations(ctx context.Context) (ObservationsRead, error)
}

// Alert is one open monitor alert as the dashboard shows it (F4-023). It carries no secret, body or
// header content.
type Alert struct {
	Kind      string
	Subject   string
	Source    string // the alert's source key; the drift card tells drift-freshness rows apart by it
	Severity  string
	State     string
	Muted     bool
	Freshness string
}

// AlertsRead is one read of the open monitor alerts.
type AlertsRead struct {
	ObservedAt time.Time
	Alerts     []Alert
}

// AlertsSource reads the open monitor alerts (F4-023). It is read-only.
type AlertsSource interface {
	OpenAlerts(ctx context.Context) (AlertsRead, error)
}

// SyncRead is the last sync run as the dashboard shows it.
type SyncRead struct {
	ObservedAt time.Time
	Result     string
	Summary    string
}

// SyncSource reads the last sync run. It is read-only.
type SyncSource interface {
	Sync(ctx context.Context) (SyncRead, error)
}

// S06Read is the S-06 source-rule key state.
type S06Read struct {
	Open       bool
	ObservedAt time.Time
}

// S06Source reads the S-06 key. It is read-only; the key changes only through the F2-015 flow.
type S06Source interface {
	S06(ctx context.Context) (S06Read, error)
}

// AccessBoundary kinds. They are kept SEPARATE from the expected role matrix: they explain what the
// matrix does not model (source rule, API exemption, open intent, system template, Headscale ACL).
const (
	// BoundaryS06Source is the WireGuard/S-06 source rule.
	BoundaryS06Source = "s06_source"
	// BoundaryAPIExemption is a site's @api exemption, which bypasses role control from any source.
	BoundaryAPIExemption = "api_exemption"
	// BoundaryOpenIntent is an open site's intentional/transition VPN-wide intent.
	BoundaryOpenIntent = "open_intent"
	// BoundarySystemTemplate is a locked system template with its own access rule.
	BoundarySystemTemplate = "system_template"
	// BoundaryHeadscaleACL is the ACL/device/route limit the matrix does not compute.
	BoundaryHeadscaleACL = "headscale_acl"
)

// AccessBoundary is one access limit the role matrix does not model, shown separately.
type AccessBoundary struct {
	Kind    string
	Subject string
	// State is the boundary in a few words (the S-06 switch position, what an exemption does);
	// Detail is the full sentence.
	State  string
	Detail string
}

// DevicesCard is the Headscale device card. Count is every known device; Online is how many the
// Headscale source currently reports connected.
type DevicesCard struct {
	SourceState
	Count   int
	Online  int
	Devices []Device
	Caveat  string
}

// MatrixSite is one role-controlled site (a matrix column). APIRuleCount exposes that the site
// carries an API exemption even when its intent is private.
type MatrixSite struct {
	SiteID       int64
	Hosts        []string
	APIRuleCount int
}

// MatrixCard is the expected Caddy role access matrix: Zitadel vpn roles (rows) x role-controlled
// sites (columns). It is expected access, not effective end-to-end access.
type MatrixCard struct {
	SourceState
	// SiteObservedAt is the site-rule source time; ObservedAt (SourceState) is the role source time.
	SiteObservedAt time.Time
	Roles          []string
	Sites          []MatrixSite
	// Allowed[roleIndex][siteIndex] is true when the role is one of the site's roles.
	Allowed [][]bool
	Caveat  string
}

// BoundariesCard lists the access limits explained separately from the matrix.
type BoundariesCard struct {
	SourceState
	Boundaries []AccessBoundary
}

// ObservationsCard is the measurement-observation card.
type ObservationsCard struct {
	SourceState
	Sites []ObservationSite
}

// AlertsCard is the open-alert card.
type AlertsCard struct {
	SourceState
	Alerts []Alert
}

// SyncCard is the last-sync card.
type SyncCard struct {
	SourceState
	Result  string
	Summary string
}

// View is the whole dashboard snapshot. Every card carries its own source time and freshness; there
// is deliberately no view-level "observed at".
type View struct {
	Devices      DevicesCard
	Matrix       MatrixCard
	Boundaries   BoundariesCard
	Observations ObservationsCard
	Alerts       AlertsCard
	Sync         SyncCard
}

// Caveats. Connectivity is not access; the matrix is expected, not effective.
const (
	deviceAccessCaveat = "Bağlı görünmek fiziksel erişim ya da erişim yetkisi garantisi değildir."
	matrixCaveat       = "Zitadel vpn rolleri ve site kurallarından beklenen erişim; etkili uçtan uca erişim garantisi değildir."
	headscaleACLNote   = "Cihaz ve route erişimi Headscale ACL'de ayrıca sınırlanır."
	apiExemptionNote   = "Kurala uyan istek her kaynaktan gelir ve rol kontrolünü atlar (API bypass)."
	openIntentNote     = "Tüm VPN kullanıcılarına açık."
	systemTemplateNote = "Kendi sabit erişim kuralı var."
)

// Config wires the read-only sources. Every source is required; a missing source is a wiring error
// rather than a silently healthy card.
type Config struct {
	Devices      DevicesSource
	Roles        RolesSource
	Sites        SitesSource
	Observations ObservationsSource // optional: nil reports the observations card as unknown
	Alerts       AlertsSource
	Sync         SyncSource
	S06          S06Source
}

// Model is the read model. It is safe for concurrent use. It caches each source's last-good value
// in memory only, so a restarted process with an unreadable source reports unknown instead of
// inventing a fresh snapshot.
type Model struct {
	cfg Config
	mu  sync.Mutex
	c   cache
}

type cache struct {
	devices      cached[DevicesRead]
	roles        cached[RolesRead]
	sites        cached[SitesRead]
	observations cached[ObservationsRead]
	alerts       cached[AlertsRead]
	sync         cached[SyncRead]
	s06          cached[S06Read]
}

type cached[T any] struct {
	v  T
	ok bool
}

// New validates the wiring and returns the model.
func New(cfg Config) (*Model, error) {
	switch {
	case cfg.Devices == nil:
		return nil, errors.New("dashboard: a devices source is required")
	case cfg.Roles == nil:
		return nil, errors.New("dashboard: a roles source is required")
	case cfg.Sites == nil:
		return nil, errors.New("dashboard: a sites source is required")
	case cfg.Alerts == nil:
		return nil, errors.New("dashboard: an alerts source is required")
	case cfg.Sync == nil:
		return nil, errors.New("dashboard: a sync source is required")
	case cfg.S06 == nil:
		return nil, errors.New("dashboard: an S-06 source is required")
	}
	return &Model{cfg: cfg}, nil
}

// View reads every source once and builds the snapshot. A failed source keeps its last-good value
// with its original time (stale) or reports unknown; it never fails the whole view and never
// re-stamps an old value with a new time.
func (m *Model) View(ctx context.Context) View {
	m.mu.Lock()
	defer m.mu.Unlock()

	dev, devFresh, devErr := load(&m.c.devices, func() (DevicesRead, error) { return m.cfg.Devices.Devices(ctx) })
	roles, roleFresh, roleErr := load(&m.c.roles, func() (RolesRead, error) { return m.cfg.Roles.VpnRoles(ctx) })
	sites, siteFresh, siteErr := load(&m.c.sites, func() (SitesRead, error) { return m.cfg.Sites.ListSites(ctx) })
	// The observations source is optional: the access matrix screen reads the stored rows itself.
	// Without it the card reports unknown rather than an empty healthy list.
	obs, obsFresh, obsErr := load(&m.c.observations, func() (ObservationsRead, error) {
		if m.cfg.Observations == nil {
			return ObservationsRead{}, errors.New("observations source not configured")
		}
		return m.cfg.Observations.Observations(ctx)
	})
	alerts, alertFresh, alertErr := load(&m.c.alerts, func() (AlertsRead, error) { return m.cfg.Alerts.OpenAlerts(ctx) })
	syncRead, syncFresh, syncErr := load(&m.c.sync, func() (SyncRead, error) { return m.cfg.Sync.Sync(ctx) })
	s06, s06Fresh, s06Err := load(&m.c.s06, func() (S06Read, error) { return m.cfg.S06.S06(ctx) })

	return View{
		Devices:      buildDevices(dev, devFresh, devErr),
		Matrix:       buildMatrix(roles, roleFresh, roleErr, sites, siteFresh, siteErr),
		Boundaries:   buildBoundaries(sites, siteFresh, siteErr, s06, s06Fresh, s06Err),
		Observations: buildObservations(obs, obsFresh, obsErr),
		Alerts:       buildAlerts(alerts, alertFresh, alertErr),
		Sync:         buildSync(syncRead, syncFresh, syncErr),
	}
}

// load reads one source into its cache. A failed read keeps the cached value (stale) or reports
// unknown when nothing was ever read; a successful read replaces the cache and is fresh.
func load[T any](c *cached[T], read func() (T, error)) (T, Freshness, error) {
	v, err := read()
	if err != nil {
		if c.ok {
			return c.v, FreshnessStale, err
		}
		var zero T
		return zero, FreshnessUnknown, err
	}
	c.v, c.ok = v, true
	return v, FreshnessFresh, nil
}

func buildDevices(r DevicesRead, freshness Freshness, err error) DevicesCard {
	devices := append([]Device(nil), r.Devices...)
	sort.SliceStable(devices, func(i, j int) bool { return devices[i].ID < devices[j].ID })
	online := 0
	for _, d := range devices {
		if d.Online {
			online++
		}
	}
	return DevicesCard{
		SourceState: SourceState{ObservedAt: r.ObservedAt, Freshness: freshness, Err: err},
		Count:       len(devices),
		Online:      online,
		Devices:     devices,
		Caveat:      deviceAccessCaveat,
	}
}

// buildMatrix derives the expected Caddy role access from the Zitadel vpn roles and the stored
// role-controlled sites. Open and system sites are not columns; they are explained as boundaries.
// The freshness is the worse of the two sources, and the role source time stays the matrix time.
func buildMatrix(roles RolesRead, roleFresh Freshness, roleErr error, sites SitesRead, siteFresh Freshness, siteErr error) MatrixCard {
	card := MatrixCard{
		SourceState:    SourceState{ObservedAt: roles.ObservedAt, Freshness: worst(roleFresh, siteFresh), Err: errors.Join(roleErr, siteErr)},
		SiteObservedAt: sites.ObservedAt,
		Caveat:         matrixCaveat,
	}

	rows := uniqueSorted(roles.Roles)
	cols := roleSites(sites.Sites)

	card.Roles = rows
	card.Sites = make([]MatrixSite, 0, len(cols))
	for _, s := range cols {
		card.Sites = append(card.Sites, MatrixSite{
			SiteID:       s.ID,
			Hosts:        append([]string(nil), s.Hosts...),
			APIRuleCount: len(s.APIRules),
		})
	}
	card.Allowed = make([][]bool, 0, len(rows))
	for _, role := range rows {
		line := make([]bool, 0, len(cols))
		for _, s := range cols {
			line = append(line, containsString(s.Roles, role))
		}
		card.Allowed = append(card.Allowed, line)
	}
	return card
}

// buildBoundaries explains the access limits the matrix does not model. The S-06 source rule and
// the Headscale ACL limit are always present; open/system sites and API exemptions are added per
// site. A private (role) site's API exemption is shown even though the site is role-controlled.
func buildBoundaries(sites SitesRead, siteFresh Freshness, siteErr error, s06 S06Read, s06Fresh Freshness, s06Err error) BoundariesCard {
	card := BoundariesCard{
		SourceState: SourceState{ObservedAt: sites.ObservedAt, Freshness: worst(siteFresh, s06Fresh), Err: errors.Join(siteErr, s06Err)},
	}

	card.Boundaries = append(card.Boundaries, AccessBoundary{Kind: BoundaryS06Source, State: s06State(s06, s06Fresh), Detail: s06Detail(s06, s06Fresh)})

	for _, s := range sortedSites(sites.Sites) {
		switch s.Kind {
		case site.KindRole:
			if len(s.APIRules) > 0 {
				card.Boundaries = append(card.Boundaries, AccessBoundary{
					Kind:    BoundaryAPIExemption,
					Subject: firstHost(s),
					State:   "rol kontrolü atlanır",
					Detail:  apiExemptionNote,
				})
			}
		case site.KindOpen:
			card.Boundaries = append(card.Boundaries, AccessBoundary{
				Kind:    BoundaryOpenIntent,
				Subject: firstHost(s),
				State:   "tüm VPN kullanıcıları",
				Detail:  openIntentDetail(s.OpenReason),
			})
		case site.KindSystem:
			card.Boundaries = append(card.Boundaries, AccessBoundary{
				Kind:    BoundarySystemTemplate,
				Subject: firstHost(s),
				State:   "kendi erişim kuralı",
				Detail:  systemTemplateDetail(s.SystemTemplate),
			})
		}
	}

	card.Boundaries = append(card.Boundaries, AccessBoundary{Kind: BoundaryHeadscaleACL, State: "ayrıca sınırlanır", Detail: headscaleACLNote})
	return card
}

func buildObservations(r ObservationsRead, freshness Freshness, err error) ObservationsCard {
	sites := append([]ObservationSite(nil), r.Sites...)
	sort.SliceStable(sites, func(i, j int) bool { return sites[i].Site < sites[j].Site })
	return ObservationsCard{
		SourceState: SourceState{ObservedAt: r.ObservedAt, Freshness: freshness, Err: err},
		Sites:       sites,
	}
}

func buildAlerts(r AlertsRead, freshness Freshness, err error) AlertsCard {
	alerts := append([]Alert(nil), r.Alerts...)
	return AlertsCard{
		SourceState: SourceState{ObservedAt: r.ObservedAt, Freshness: freshness, Err: err},
		Alerts:      alerts,
	}
}

func buildSync(r SyncRead, freshness Freshness, err error) SyncCard {
	return SyncCard{
		SourceState: SourceState{ObservedAt: r.ObservedAt, Freshness: freshness, Err: err},
		Result:      r.Result,
		Summary:     r.Summary,
	}
}

// worst returns the less trustworthy freshness. unknown is worse than stale, which is worse than
// fresh, so a combined card never looks healthier than its weakest source.
func worst(a, b Freshness) Freshness {
	if rank(b) > rank(a) {
		return b
	}
	return a
}

func rank(f Freshness) int {
	switch f {
	case FreshnessFresh:
		return 0
	case FreshnessStale:
		return 1
	default:
		return 2
	}
}

// s06State is the switch position in one word; an unreadable source is "bilinmiyor", never "kapalı".
func s06State(s06 S06Read, freshness Freshness) string {
	switch {
	case freshness == FreshnessUnknown:
		return "bilinmiyor"
	case s06.Open:
		return "açık"
	default:
		return "kapalı"
	}
}

func s06Detail(s06 S06Read, freshness Freshness) string {
	switch {
	case freshness == FreshnessUnknown:
		return "Tailnet dışı erişim ayarı okunamadı; kaynak durumu bilinmiyor."
	case s06.Open:
		return "Açık: tailnet dışı geçiş kaynağından gelen istek rol kontrolünü atlar."
	default:
		return "Kapalı: tailnet dışı kaynaktan gelen istek 403 alır (API bypass hariç)."
	}
}

func openIntentDetail(reason string) string {
	switch reason {
	case site.OpenReasonTransition:
		return openIntentNote + " Neden: geçiş dönemi."
	case site.OpenReasonIntentional:
		return openIntentNote + " Neden: kasıtlı."
	default:
		return openIntentNote
	}
}

func systemTemplateDetail(template string) string {
	if template == "" {
		return systemTemplateNote
	}
	return systemTemplateNote + " Şablon: " + template + "."
}

// roleSites returns the role-controlled sites, sorted by first host for a deterministic matrix.
func roleSites(sites []site.Site) []site.Site {
	out := make([]site.Site, 0, len(sites))
	for _, s := range sites {
		if s.Kind == site.KindRole {
			out = append(out, s)
		}
	}
	sortSites(out)
	return out
}

func sortedSites(sites []site.Site) []site.Site {
	out := append([]site.Site(nil), sites...)
	sortSites(out)
	return out
}

func sortSites(sites []site.Site) {
	sort.SliceStable(sites, func(i, j int) bool {
		hi, hj := firstHost(sites[i]), firstHost(sites[j])
		if hi != hj {
			return hi < hj
		}
		return sites[i].ID < sites[j].ID
	})
}

func firstHost(s site.Site) string {
	if len(s.Hosts) == 0 {
		return ""
	}
	return s.Hosts[0]
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func containsString(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
