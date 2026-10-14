package web

import (
	"net/http"
	"time"

	"github.com/a-h/templ"

	"github.com/nesiler/tagcess/internal/alert"
	"github.com/nesiler/tagcess/internal/dashboard"
	"github.com/nesiler/tagcess/internal/k8s"
	"github.com/nesiler/tagcess/internal/monitor"
)

func init() {
	previewPages = append(previewPages, previewPage{"/", "pano", "Pano", func(r *http.Request) templ.Component {
		return DashboardPage(previewDashboard(r.URL.Query().Get("state")))
	}})
}

// previewDashboard covers populated, empty, unreadable, stale, setup and dry-run views without
// reaching any external system. All times and samples are fixed so screenshots are repeatable.
func previewDashboard(state string) DashboardPageView {
	at := time.Date(2026, 10, 5, 14, 2, 0, 0, time.UTC)
	fresh := dashboard.SourceState{Freshness: dashboard.FreshnessFresh, ObservedAt: at}
	v := DashboardPageView{
		Model: dashboard.View{
			Devices: dashboard.DevicesCard{SourceState: fresh, Count: 3, Online: 2,
				Caveat: "Bağlı görünmek fiziksel erişim ya da erişim yetkisi garantisi değildir.",
				Devices: []dashboard.Device{
					{ID: 1, Name: "vpn-gw", Owner: "tag:server", Online: true},
					{ID: 2, Name: "carol-laptop", Owner: "carol", Online: true},
					{ID: 3, Name: "lab-node", Owner: "tag:lab", LastSeen: at.Add(-2 * time.Hour)},
				}},
			Matrix: dashboard.MatrixCard{SourceState: fresh, SiteObservedAt: at,
				Caveat: "Zitadel vpn rolleri ve site kurallarından beklenen erişim; etkili uçtan uca erişim garantisi değildir.",
				Roles:  []string{"devops", "yazilim"}, Sites: []dashboard.MatrixSite{
					{SiteID: 1, Hosts: []string{"git.example.com"}, APIRuleCount: 1},
					{SiteID: 2, Hosts: []string{"wiki.example.com"}},
				}, Allowed: [][]bool{{true, true}, {true, false}}},
			Boundaries: dashboard.BoundariesCard{SourceState: fresh, Boundaries: []dashboard.AccessBoundary{
				{Kind: dashboard.BoundaryS06Source, State: "kapalı", Detail: "Kapalı: tailnet dışı kaynaktan gelen istek 403 alır (API bypass hariç)."},
				{Kind: dashboard.BoundaryAPIExemption, Subject: "git.example.com", State: "rol kontrolü atlanır", Detail: "Kurala uyan istek her kaynaktan gelir ve rol kontrolünü atlar (API bypass)."},
				{Kind: dashboard.BoundaryHeadscaleACL, State: "ayrıca sınırlanır", Detail: "Cihaz ve route erişimi Headscale ACL'de ayrıca sınırlanır."},
			}},
			Sync: dashboard.SyncCard{SourceState: fresh, Result: "applied", Summary: "Son iyi durum korundu; kayıtlı kurallar apply edildi."},
			Alerts: dashboard.AlertsCard{SourceState: fresh, Alerts: []dashboard.Alert{
				{Kind: alert.KindDrift, Subject: "caddy", Severity: "warning", State: string(alert.StateActive), Freshness: freshnessFresh},
			}},
		},
		Snapshot: SnapshotCard{Loaded: true, Freshness: K8sFreshnessView{
			Current:     &k8s.Snapshot{Scope: "default,internal", ObservedAt: at},
			LastAttempt: &k8s.Attempt{AttemptedAt: at, Outcome: k8s.OutcomeOK},
		}},
		Health: []HealthCard{
			{Kind: obsCategoryTarget, Title: "Hedef sağlığı", Freshness: freshnessFresh, ObservedAt: at,
				Rows: []HealthRow{{Site: "Git", Host: "git.example.com", Source: obsSourceProbe, Vantage: "tailnet", Endpoint: "100.64.0.5:8080", Path: "/", Success: true, HTTPStatus: 200, Freshness: freshnessFresh, ObservedAt: at}}},
			{Kind: obsCategoryGate, Title: "Caddy gate'i", Freshness: freshnessFresh, ObservedAt: at,
				Rows: []HealthRow{{Site: "Git", Host: "git.example.com", Source: obsSourceProbe, Success: true, HTTPStatus: 302, Freshness: freshnessFresh, ObservedAt: at}, {Site: "Wiki", Host: "wiki.example.com", Source: obsSourceProbe, Vantage: "tailnet", Result: "zaman aşımı", Freshness: freshnessStale, ObservedAt: at.Add(-3 * time.Hour), LastAttemptAt: at}}},
			{Kind: obsCategoryTLS, Title: "TLS sertifikaları", Freshness: freshnessFresh, ObservedAt: at,
				Rows: []HealthRow{{Site: "Git", Host: "git.example.com", Source: obsSourceProbe, Success: true, Freshness: freshnessFresh, ObservedAt: at, TLSNotAfter: at.Add(6 * 24 * time.Hour), Result: "sertifika süresi yaklaşıyor", TLSUnverified: true}}},
			{Kind: cardTwoGate, Title: "İki gate", Freshness: freshnessFresh, ObservedAt: at, Note: twoGateNote,
				Groups: []TwoGateGroup{{Site: "Git", Host: "git.example.com", Route: "/api/*",
					Risk:         &HealthRow{RiskFinding: "alternatif yol adayı (config riski)"},
					Measurements: []HealthRow{{Freshness: freshnessFresh, Success: true, Vantage: "tailnet", Endpoint: "100.64.0.5:443", ObservedAt: at, HTTPStatus: 200}},
					Untested:     []string{"İnternet erişimi test edilmedi"},
				}}},
		},
		Loops: []LoopRow{
			{Job: monitor.JobInventory, State: freshnessFresh, LastAttempt: at},
			{Job: monitor.JobHealth, State: freshnessFresh, LastAttempt: at},
			{Job: monitor.JobDrift, State: freshnessFresh, LastAttempt: at},
		},
	}
	switch state {
	case "empty", "setup", "error":
		v.Model.Devices.Devices, v.Model.Devices.Count, v.Model.Devices.Online = nil, 0, 0
		v.Model.Matrix.Roles, v.Model.Matrix.Sites, v.Model.Matrix.Allowed = nil, nil, nil
		v.Model.Boundaries.Boundaries, v.Model.Alerts.Alerts = nil, nil
		v.Model.Sync.Result, v.Model.Sync.Summary = "", ""
		v.Snapshot = SnapshotCard{Loaded: state != "error"}
		for i := range v.Health {
			v.Health[i].Rows, v.Health[i].Groups = nil, nil
			v.Health[i].ObservedAt = time.Time{}
			v.Health[i].Freshness = freshnessUnknown
		}
		if state == "error" {
			unknown := dashboard.SourceState{Freshness: dashboard.FreshnessUnknown, Err: errPreviewStatus}
			v.Model.Devices.SourceState, v.Model.Matrix.SourceState = unknown, unknown
			v.Model.Boundaries.SourceState, v.Model.Alerts.SourceState, v.Model.Sync.SourceState = unknown, unknown, unknown
			for i := range v.Health {
				v.Health[i].Err = "kaynak okunamadı"
			}
			for i := range v.Loops {
				v.Loops[i].State = "error"
			}
		}
		if state == "setup" {
			v.Setup = []SetupStep{
				{Key: SetupFirstImport, Label: "İlk import", Href: "/sites/first-import"},
				{Key: SetupProbePolicy, Label: "Probe IP policy'si", Href: "/monitor/settings"},
				{Key: SetupK8sProfile, Label: "k8s bağlantı profili", Href: "/k8s/connection"},
			}
			v.DriftWaiting, v.Snapshot.Waiting = &v.Setup[0], &v.Setup[2]
			for i := range v.Health {
				v.Health[i].Waiting = &v.Setup[1]
			}
			for i := range v.Loops {
				v.Loops[i].State, v.Loops[i].LastAttempt = "missing", time.Time{}
				v.Loops[i].Reason = loopMissingReason(v.Loops[i].Job)
			}
		}
	case "stale":
		stale := dashboard.SourceState{Freshness: dashboard.FreshnessStale, ObservedAt: at, Err: errPreviewStatus}
		v.Model.Devices.SourceState, v.Model.Matrix.SourceState = stale, stale
		v.Model.Boundaries.SourceState, v.Model.Alerts.SourceState, v.Model.Sync.SourceState = stale, stale, stale
		v.Snapshot.Freshness.Stale = true
		v.Snapshot.Freshness.LastAttempt = &k8s.Attempt{AttemptedAt: at.Add(time.Hour), Outcome: k8s.OutcomeFailed}
		for i := range v.Health {
			v.Health[i].Freshness = freshnessStale
			for j := range v.Health[i].Rows {
				v.Health[i].Rows[j].Freshness = freshnessStale
			}
			for j := range v.Health[i].Groups {
				for k := range v.Health[i].Groups[j].Measurements {
					v.Health[i].Groups[j].Measurements[k].Freshness = freshnessStale
				}
			}
		}
		for i := range v.Loops {
			v.Loops[i].State = freshnessStale
		}
	case "dry":
		v.Model.Sync.Result = "dry_run"
		v.Model.Sync.Summary = "Dry-run: değişiklik apply edilmedi; son iyi durum korundu."
		v.DriftHeld = true
	}
	v.Drift = driftAlerts(v.Model.Alerts.Alerts)
	return v
}
