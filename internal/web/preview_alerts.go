package web

import (
	"net/http"
	"time"

	"github.com/a-h/templ"

	"github.com/nesiler/tagcess/internal/alert"
	"github.com/nesiler/tagcess/internal/monitor"
)

// preview_alerts.go adds the samples of this work area to the preview server: the settings index, the
// monitoring settings form and the alerts screen, with their empty, refused, unreadable and success
// states. Each sample uses the real route path so the sidebar marks the right entry.

func init() {
	previewPages = append(previewPages,
		previewPage{"/settings", "ayarlar", "Ayarlar", func(*http.Request) templ.Component {
			return SettingsIndexPage()
		}},
		previewPage{"/monitor/settings", "pano", "İzleme ayarları", func(r *http.Request) templ.Component {
			return MonitorSettingsPage(previewMonitorSettings(r), previewCSRF)
		}},
		previewPage{"/alerts", "pano", "Uyarılar", func(r *http.Request) templ.Component {
			return AlertsPage(previewAlerts(r), previewCSRF)
		}},
	)
}

// previewMonitorSettings builds the monitoring settings sample. ?state=saved shows the success
// banner, ?state=invalid a refused form with field errors and ?state=corrupt the unreadable warning.
func previewMonitorSettings(r *http.Request) MonitorSettingsView {
	v := MonitorSettingsView{
		Form:    monitorSettingsFormFromSettings(monitor.DefaultSettings()),
		Default: true,
		Loaded:  true,
	}
	switch r.URL.Query().Get("state") {
	case "saved":
		v.Default = false
		v.Notice = "İzleme ayarları kaydedildi; sonraki kontrol çevrimi yeni değerleri kullanır."
	case "invalid":
		v.Form.TargetInterval = "0"
		v.Form.TLSWarn = "40"
		v.Errors = map[string]string{
			"target_interval": "hedef kontrol aralığı 1 sn ile 30 gün arasında olmalı",
			"tls":             "tls thresholds: bilgi > uyarı > kritik olmalı",
		}
		v.Refusal = "girilen değerler geçersiz; hiçbir şey kaydedilmedi."
	case "corrupt":
		v.Warning = "kayıtlı izleme ayarları okunamadı veya bozuk (bad value: not-a-duration); form varsayılanlarla dolu, doğrulanmış bir kayıt bozuk ayarların üzerine yazar"
	}
	return v
}

// previewAlerts builds the alerts sample. ?state=empty shows the empty screen, ?state=unreadable the
// failed listing, ?state=notice an acknowledgement confirmation and ?state=many a paged resolved list.
func previewAlerts(r *http.Request) AlertsView {
	at := time.Date(2026, 10, 5, 14, 2, 0, 0, time.UTC)
	v := AlertsView{
		Loaded:      true,
		Maintenance: []string{"muhasebe.example.com"},
		Open: []AlertRow{
			{
				ID: 1, Kind: alert.KindTargetHealth, Subject: "git.example.com", Source: alert.AlertSourceTarget,
				Severity: string(alert.SeverityCritical), State: string(alert.StateActive), StateLabel: "aktif",
				Freshness: alert.FreshnessFresh, SiteMaintenance: true, LastSeen: at, Evidence: "HTTP 503",
			},
			{
				ID: 2, Kind: alert.KindTargetHealth, Subject: "muhasebe.example.com", Source: alert.AlertSourceTarget,
				Severity: string(alert.SeverityWarning), State: string(alert.StateAcknowledged), StateLabel: "okundu",
				Muted: true, Freshness: alert.FreshnessStale, SiteMaintenance: true,
				LastSeen: at.Add(-2 * time.Hour), Evidence: "check failed",
			},
			{
				ID: 3, Kind: alert.KindSourceStale, Subject: alert.SubjectCaddyLive, Source: alert.SourceDrift,
				Severity: string(alert.SeverityCritical), State: string(alert.StateActive), StateLabel: "aktif",
				Freshness: alert.FreshnessFresh, LastSeen: at.Add(-5 * time.Minute),
				Evidence: "running Caddy config differs from the applied records.",
			},
		},
		Resolved: []AlertRow{
			{
				ID: 4, Kind: alert.KindTLSExpiry, Subject: "wiki.example.com", Source: alert.AlertSourceTLS,
				Severity: string(alert.SeverityInfo), State: string(alert.StateResolved), StateLabel: "çözüldü",
				Freshness: alert.FreshnessStale, Resolved: true,
				LastSeen: at.Add(-24 * time.Hour), ResolvedAt: at.Add(-2 * time.Hour),
			},
		},
	}
	switch r.URL.Query().Get("state") {
	case "empty":
		v = AlertsView{Loaded: true}
	case "unreadable":
		v = AlertsView{Loaded: false, Err: "uyarılar okunamadı: kontrol kayıtları okunamadı"}
	case "notice":
		v.Notice = "Uyarı okundu işaretlendi."
	case "many":
		// More resolved alerts than one page: the pager under the resolved list (U-13).
		var rows []AlertRow
		for i := range 32 {
			row := v.Resolved[0]
			row.ID = int64(100 + i)
			row.LastSeen = row.LastSeen.Add(-time.Duration(i) * time.Hour)
			rows = append(rows, row)
		}
		v.Resolved, v.ResolvedPage = pageResolved(rows, r.URL.Query().Get("resolved"))
	}
	return v
}
