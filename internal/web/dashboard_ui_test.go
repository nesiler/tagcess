package web

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/dashboard"
	"github.com/nesiler/tagcess/internal/monitor"
	"github.com/nesiler/tagcess/internal/store/db"
	"github.com/nesiler/tagcess/internal/web/ui"
)

func TestDashboardHealthToneUsesObservationSource(t *testing.T) {
	at := time.Date(2026, 10, 5, 14, 2, 0, 0, time.UTC)
	judge := obsJudge{now: at, settings: monitor.DefaultSettings()}
	for _, tc := range []struct {
		name string
		row  db.Observation
		want ui.Tone
	}{
		{"healthy probe", db.Observation{Category: obsCategoryTarget, Source: obsSourceProbe, Success: 1, ObservedAt: at.Format(obsTimeFormat), LastAttemptAt: at.Format(obsTimeFormat)}, ui.OK},
		{"failed probe", db.Observation{Category: obsCategoryTarget, Source: obsSourceProbe, LastAttemptAt: at.Format(obsTimeFormat)}, ui.Err},
		{"old probe", db.Observation{Category: obsCategoryTarget, Source: obsSourceProbe, Success: 1, ObservedAt: at.Add(-24 * time.Hour).Format(obsTimeFormat), LastAttemptAt: at.Add(-24 * time.Hour).Format(obsTimeFormat)}, ui.Stale},
		{"configuration risk", db.Observation{Category: obsCategoryRisk, Source: obsSourceConfig, Success: 1, ObservedAt: at.Format(obsTimeFormat), LastAttemptAt: at.Format(obsTimeFormat)}, ui.Warn},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cards := buildHealthCards([]db.Observation{tc.row}, nil, judge)
			var row HealthRow
			if tc.row.Category == obsCategoryRisk {
				row = *cards[3].Groups[0].Risk
			} else {
				row = cards[0].Rows[0]
			}
			if got := dashboardHealthTone(row); got != tc.want {
				t.Errorf("converted observation tone = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDashboardPreviewStates(t *testing.T) {
	for _, tc := range []struct {
		query string
		want  []string
	}{
		{"", []string{"Cihazlar ve son görülme", "vpn-gw", `data-risk="preserved"`, "aria-current=\"page\"", "Arka plan işleri"}},
		{"?state=empty", []string{"Gösterilecek rol veya rol kontrollü site yok.", "Açık drift uyarısı yok.", "henüz taranmadı"}},
		{"?state=error&err=1", []string{"bilinmiyor: cihaz kaynağı okunamadı.", "kaynak okunamadı", "bilinmiyor: envanter durumu okunamadı."}},
		{"?state=stale", []string{"güncel değil", "Son okuma başarısız; son başarılı tarama gösteriliyor.", "vpn-gw"}},
		{"?state=setup", []string{"Kurulum bekliyor", "data-setup-step=\"first_import\"", "Kurulum bekleniyor:"}},
		{"?state=dry&dry=1", []string{"deneme (dry-run)", "Dry-run"}},
	} {
		t.Run(tc.query, func(t *testing.T) {
			rr := httptest.NewRecorder()
			PreviewHandler().ServeHTTP(rr, httptest.NewRequestWithContext(t.Context(), "GET", "/"+tc.query, nil))
			if rr.Code != 200 {
				t.Fatalf("preview status = %d", rr.Code)
			}
			body := rr.Body.String()
			for _, want := range tc.want {
				if !strings.Contains(body, want) {
					t.Errorf("preview missing %q", want)
				}
			}
			if strings.Contains(body, "Preview yok") || !strings.Contains(body, "<h1>Pano</h1>") {
				t.Error("root must render the dashboard sample")
			}
		})
	}
}

func TestDashboardTonesPreserveUncertainty(t *testing.T) {
	for _, tc := range []struct {
		state string
		want  ui.Tone
	}{
		{"fresh", ui.OK}, {"current", ui.OK}, {"stale", ui.Stale},
		{"never", ui.Err}, {"error", ui.Err}, {"missing", ui.Info},
		{"previous", ui.Stale}, {"unknown", ui.Off}, {"none", ui.Off}, {"", ui.Off}, {"future", ui.Off},
	} {
		t.Run(tc.state, func(t *testing.T) {
			if got := dashboardFreshnessTone(tc.state); got != tc.want {
				t.Errorf("freshness %q tone = %q, want %q", tc.state, got, tc.want)
			}
		})
	}
	for _, state := range []string{"stale", "unknown", "", "future"} {
		if got := dashboardDeviceTone(true, state); got == ui.OK {
			t.Errorf("connected device with %q source must not look current", state)
		}
	}
	for _, tc := range []struct {
		row  HealthRow
		want ui.Tone
	}{
		{HealthRow{Freshness: "fresh", Success: true}, ui.OK},
		{HealthRow{Freshness: "stale", Success: true}, ui.Stale},
		{HealthRow{Freshness: "fresh", Success: false}, ui.Err},
		{HealthRow{Freshness: "unknown"}, ui.Off},
		{HealthRow{Freshness: "fresh", Success: true, TLSUnverified: true}, ui.Warn},
		{HealthRow{Freshness: "fresh", Success: true, Source: obsSourceConfig, RiskFinding: "risk"}, ui.Warn},
	} {
		if got := dashboardHealthTone(tc.row); got != tc.want {
			t.Errorf("health row %+v tone = %q, want %q", tc.row, got, tc.want)
		}
	}
}

func TestDashboardSummaryKeepsUnknownAndStaleSources(t *testing.T) {
	v := DashboardPageView{}
	tiles := dashboardTiles(v)
	for _, tile := range tiles {
		if tile.Value != "bilinmiyor" {
			t.Errorf("missing source: %s summary = %q, want bilinmiyor", tile.Label, tile.Value)
		}
	}
	v.Model.Devices = dashboard.DevicesCard{SourceState: dashboard.SourceState{Freshness: dashboard.FreshnessStale}, Online: 2, Count: 3}
	v.Model.Alerts = dashboard.AlertsCard{SourceState: dashboard.SourceState{Freshness: dashboard.FreshnessStale}, Alerts: []dashboard.Alert{{State: "acknowledged"}}}
	v.Model.Sync = dashboard.SyncCard{SourceState: dashboard.SourceState{Freshness: dashboard.FreshnessStale}, Result: "applied"}
	tiles = dashboardTiles(v)
	for _, i := range []int{0, 1, 2} {
		if tiles[i].Sub != "güncel değil" {
			t.Errorf("stale source: %s summary lost the stale label: %+v", tiles[i].Label, tiles[i])
		}
	}
	if tiles[0].Value != "2 / 3" || tiles[1].Value != "1" || tiles[2].Value != "apply edildi" {
		t.Errorf("stale summary lost last-good data: %+v", tiles)
	}
	if got := dashboardSyncTone(v.Model.Sync); got == ui.OK {
		t.Error("an old applied sync result must not look current")
	}
	v.Model.Sync.Freshness = dashboard.FreshnessFresh
	for _, result := range []string{"", "dry_run", "failed", "pending_approval", "future"} {
		v.Model.Sync.Result = result
		if got := dashboardSyncTone(v.Model.Sync); got == ui.OK {
			t.Errorf("sync result %q must not look applied", result)
		}
	}
}
