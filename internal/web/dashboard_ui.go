package web

import (
	"strconv"
	"strings"
	"time"

	"github.com/nesiler/tagcess/internal/dashboard"
	"github.com/nesiler/tagcess/internal/web/ui"
)

// dashboardFreshnessTone never gives an absent or unrecognised source a healthy colour.
func dashboardFreshnessTone(state string) ui.Tone {
	switch state {
	case freshnessFresh, "current":
		return ui.OK
	case freshnessStale, "previous":
		return ui.Stale
	case freshnessNever, "error":
		return ui.Err
	case "missing":
		return ui.Info
	default:
		return ui.Off
	}
}

func dashboardDeviceTone(online bool, freshness string) ui.Tone {
	if freshness != freshnessFresh {
		return dashboardFreshnessTone(freshness)
	}
	if online {
		return ui.OK
	}
	return ui.Off
}

// Expected access is configuration information, not evidence of effective connectivity.
func dashboardAccessTone(m dashboard.MatrixCard, row, col int) ui.Tone {
	if string(m.Freshness) != freshnessFresh {
		return dashboardFreshnessTone(string(m.Freshness))
	}
	if cellAllowed(m.Allowed, row, col) {
		return ui.Info
	}
	return ui.Off
}

func dashboardHealthTone(row HealthRow) ui.Tone {
	if row.Source == obsSourceConfig || row.TLSUnverified {
		return ui.Warn
	}
	if row.Freshness != freshnessFresh {
		return dashboardFreshnessTone(row.Freshness)
	}
	if !row.Success {
		return ui.Err
	}
	return ui.OK
}

func dashboardSeverityTone(severity string) ui.Tone {
	switch severity {
	case "critical":
		return ui.Err
	case "warning":
		return ui.Warn
	case "info":
		return ui.Info
	default:
		return ui.Off
	}
}

func dashboardSyncTone(c dashboard.SyncCard) ui.Tone {
	if string(c.Freshness) != freshnessFresh {
		return dashboardFreshnessTone(string(c.Freshness))
	}
	switch c.Result {
	case "applied", "no_change":
		return ui.OK
	case "failed", "read_failed":
		return ui.Err
	case "dry_run", "blocked", "held", "needs_reapproval", "pending_approval":
		return ui.Warn
	default:
		return ui.Off
	}
}

// dashboardTiles summarises the existing cards without inferring any new measurements. Stale
// values keep an explicit stale label; missing sources never turn into zero counts or a success.
func dashboardTiles(v DashboardPageView) []ui.Tile {
	out := []ui.Tile{
		{Icon: "device", Label: "Bağlı cihaz", Value: "bilinmiyor", Sub: freshnessLabel(string(v.Model.Devices.Freshness)), Href: "/headscale/devices"},
		{Icon: "bell", Label: "Açık uyarı", Value: "bilinmiyor", Sub: freshnessLabel(string(v.Model.Alerts.Freshness)), Href: "/alerts"},
		{Icon: "sync", Label: "Son sync", Value: "bilinmiyor", Sub: freshnessLabel(string(v.Model.Sync.Freshness)), Href: "/sync"},
		{Icon: "k8s", Label: "k8s envanteri", Value: freshnessLabel(v.Snapshot.State()), Sub: "k8s discovery", Href: "/k8s/discovery"},
	}
	known := func(s dashboard.SourceState) bool {
		return s.Freshness == dashboard.FreshnessFresh || s.Freshness == dashboard.FreshnessStale
	}
	if known(v.Model.Devices.SourceState) {
		out[0].Value = strconv.Itoa(v.Model.Devices.Online) + " / " + strconv.Itoa(v.Model.Devices.Count)
	}
	if known(v.Model.Alerts.SourceState) {
		out[1].Value = strconv.Itoa(len(v.Model.Alerts.Alerts))
	}
	if known(v.Model.Sync.SourceState) && v.Model.Sync.Result != "" {
		out[2].Value = syncResultLabel(v.Model.Sync.Result)
	}
	if v.Snapshot.Waiting != nil {
		out[3].Value = "Kurulum bekleniyor"
	}
	return out
}

// dashTime is the dashboard's one time format; the zero time is shown as a dash.
func dashTime(t time.Time) string {
	if t.IsZero() {
		return "–"
	}
	return t.Format("2006-01-02 15:04:05")
}

// healthAddress is the checked address on one line: host and path.
func healthAddress(host, path string) string {
	if path == "" || path == "/" {
		return host
	}
	return host + path
}

// healthRowDetail is the secondary detail of a check (where it ran from, which endpoint, SNI,
// route), shown in a tooltip so the row stays one line.
func healthRowDetail(r HealthRow) string {
	var parts []string
	if r.Source != "" {
		parts = append(parts, "Kaynak: "+observationSourceLabel(r.Source))
	}
	if r.Vantage != "" {
		parts = append(parts, "Kontrol yeri: "+r.Vantage)
	}
	if r.Endpoint != "" {
		parts = append(parts, "Hedef: "+r.Endpoint)
	}
	if r.SNI != "" && r.SNI != r.Host {
		parts = append(parts, "SNI: "+r.SNI)
	}
	if r.Route != "" {
		parts = append(parts, "Route: "+r.Route)
	}
	return strings.Join(parts, " · ")
}

// healthRowText is the one status text of a check: the fixed failure label (with the HTTP code when
// there is one), or what a good result means. A stale good result never reads as current.
func healthRowText(r HealthRow) string {
	code := ""
	if r.HTTPStatus != 0 {
		code = " (HTTP " + strconv.FormatInt(r.HTTPStatus, 10) + ")"
	}
	switch {
	case r.Source == obsSourceConfig:
		if r.RiskFinding != "" {
			return r.RiskFinding
		}
		return "config riski"
	case r.TLSUnverified:
		return "sertifika doğrulanamadı"
	case r.Result != "":
		return r.Result + code
	case !r.Success:
		return "kontrol başarısız" + code
	case r.Freshness == freshnessStale:
		return "güncel değil" + code
	default:
		return "başarılı" + code
	}
}

// healthRowTime is the time of the last check: the last attempt when known, else the last good one.
func healthRowTime(r HealthRow) time.Time {
	if !r.LastAttemptAt.IsZero() {
		return r.LastAttemptAt
	}
	return r.ObservedAt
}

// twoGateRows are the table rows of one two-gate route: one per measurement, or a single row
// without one, so the risk is listed even when nothing was measured.
func twoGateRows(g TwoGateGroup) []*HealthRow {
	if len(g.Measurements) == 0 {
		return []*HealthRow{nil}
	}
	out := make([]*HealthRow, len(g.Measurements))
	for i := range g.Measurements {
		out[i] = &g.Measurements[i]
	}
	return out
}

// twoGateAddress names a two-gate route: the host and the route when it adds something.
func twoGateAddress(g TwoGateGroup) string {
	if g.Route == "" || g.Route == g.Host || g.Route == g.Host+"/" {
		return g.Host
	}
	if strings.HasPrefix(g.Route, "/") {
		return g.Host + g.Route
	}
	return g.Host + " · " + g.Route
}

// joinUntested is the tooltip of what a two-gate check did not cover.
func joinUntested(labels []string) string {
	return strings.Join(labels, " · ")
}

// namespaceList renders a stored namespace scope ("a,b") as a readable list.
func namespaceList(scope string) string {
	var out []string
	for _, p := range strings.Split(scope, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return "tümü"
	}
	return strings.Join(out, ", ")
}

// snapshotTime is the time of the last good inventory scan, or of the previous scope's scan.
func snapshotTime(c SnapshotCard) string {
	switch {
	case c.Freshness.Current != nil:
		return dashTime(c.Freshness.Current.ObservedAt)
	case c.Freshness.Previous != nil:
		return dashTime(c.Freshness.Previous.ObservedAt)
	}
	return ""
}

// driftStateText is a drift row's state, saying so when the row itself is not current.
func driftStateText(a dashboard.Alert) string {
	text := alertStateText(a.State)
	if a.Freshness != freshnessFresh {
		text += " (" + freshnessLabel(a.Freshness) + ")"
	}
	return text
}

// boundaryState is a boundary's short state; a row without one (older data) shows its sentence.
func boundaryState(b dashboard.AccessBoundary) string {
	if b.State != "" {
		return b.State
	}
	return b.Detail
}
