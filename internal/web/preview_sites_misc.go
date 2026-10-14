package web

import (
	"net/http"
	"time"

	"github.com/a-h/templ"

	"github.com/nesiler/tagcess/internal/change"
)

// Preview samples of the site history/rollback, resync and settings screens (UI Faz 1 T13). The
// notice page is rendered after a POST in the real flow; its sample lives at /sites/rollback/notice
// with ?state= choosing the outcome.

func init() {
	previewPages = append(previewPages,
		previewPage{"/sites/7/history", "siteler", "Site geçmişi", func(*http.Request) templ.Component {
			return SiteHistoryPage(previewSiteHistory())
		}},
		previewPage{"/sites/7/history/11/rollback", "siteler", "Rollback preview'u", func(r *http.Request) templ.Component {
			v := previewRollbackPreview()
			switch r.URL.Query().Get("state") {
			case "widen":
				v.Widens = []string{
					"yeni roller erişebilecek: developer",
					"kapalı olan /debug yolu yeniden açılacak",
				}
			case "nochange":
				v.NoChange = true
			}
			return RollbackPreviewPage(v, previewCSRF)
		}},
		previewPage{"/sites/rollback/notice", "siteler", "Rollback sonucu", func(r *http.Request) templ.Component {
			v := NoticeView{BackHref: "/sites/7/history", BackLabel: "Geçmişe dön"}
			switch r.URL.Query().Get("state") {
			case "pending":
				v.Level, v.Title = "success", "Rollback yapıldı"
				v.Message = "Seçilen sürüm yeni bir değişiklik olarak apply edildi ve audit'e yazıldı."
				v.ChangeID, v.RevisionPending = 41, true
			case "dry":
				v.Level, v.Title = "info", "Kuru çalışma açık"
				v.Message = "Kuru çalışma (dry-run) modu açık olduğu için hiçbir şey apply edilmedi."
			case "stale":
				v.Level, v.Title = "warning", "Canlı durum değişti"
				v.Message = "Preview'dan sonra canlı durum değişti (başka bir değişiklik ya da elle düzenleme). Hiçbir şey apply edilmedi; preview'u yeniden açın."
			default:
				v.Level, v.Title = "success", "Rollback yapıldı"
				v.Message = "Seçilen sürüm yeni bir değişiklik olarak apply edildi ve audit'e yazıldı."
				v.ChangeID, v.Revision = 41, "0123456789abcdef0123456789abcdef01234567"
			}
			return NoticePage(v)
		}},
		previewPage{"/sites/resync/preview", "siteler", "Kayıtlardan yeniden apply", func(r *http.Request) templ.Component {
			v := SiteResyncReviewView{
				Order:   "DNS → Caddy → Zitadel",
				Version: "plan-2026-10-05T14:02:00Z",
				Diff: change.SiteDiff{
					Caddy: "--- a\n+++ b\n@@ -1,4 +1,4 @@\n wiki.example.com {\n-\treverse_proxy https://100.64.0.5\n+\treverse_proxy http://100.64.0.5:8080\n \timport gate devops\n }\n",
					DNS:   "-wiki.example.com. 300 IN A 100.64.0.5\n+wiki.example.com. 300 IN A 100.64.0.9\n",
				},
			}
			if r.URL.Query().Get("blocked") == "1" {
				v.Blocked = "Caddyfile okunamadı: caddy adapt çıktısı çözümlenemedi"
			}
			return SiteResyncReviewPage(v, previewCSRF)
		}},
		previewPage{"/sites/settings", "siteler", "Site ayarları", func(r *http.Request) templ.Component {
			v := SiteSettingsView{S06Open: true, S06State: "açık"}
			switch {
			case r.URL.Query().Get("err") == "1":
				v = SiteSettingsView{GateErr: "settings tablosu okunamadı: disk hatası"}
			case r.URL.Query().Get("closed") == "1":
				v = SiteSettingsView{S06Open: false, S06State: "kapalı"}
			}
			return SiteSettingsPage(v, previewCSRF)
		}},
		previewPage{"/sites/s06/preview", "siteler", "Switch değişikliği", func(r *http.Request) templ.Component {
			v := SiteS06ReviewView{
				Open:    r.URL.Query().Get("s06") == "open",
				Order:   "DNS → Caddy → Zitadel",
				Version: "plan-2026-10-05T14:02:00Z",
				Diff: change.SiteDiff{
					Caddy:   "--- a\n+++ b\n@@ -2,3 +2,2 @@\n \timport gate devops\n- import k8s\n+ respond 403\n",
					Zitadel: "",
				},
			}
			if r.URL.Query().Get("blocked") == "1" {
				v.Blocked = "Caddyfile okunamadı: caddy adapt çıktısı çözümlenemedi"
			}
			return SiteS06ReviewPage(v, previewCSRF)
		}},
	)
}

func previewSiteHistory() SiteHistoryView {
	at := time.Date(2026, 10, 1, 9, 30, 0, 0, time.UTC)
	return SiteHistoryView{
		SiteID: 7,
		Hosts:  "wiki.example.com",
		Versions: []VersionRow{
			{ID: 12, Op: "update", Hosts: "wiki.example.com", Actor: "dev@example.com", At: at.Add(time.Hour), Revision: ""},
			{ID: 11, Op: "add", Hosts: "wiki.example.com", Actor: "carol.example@example.com", At: at,
				Revision: "0123456789abcdef0123456789abcdef01234567", Rollback: true, RollbackOf: 9},
		},
	}
}

func previewRollbackPreview() RollbackPreviewView {
	return RollbackPreviewView{
		SiteID: 7,
		Version: VersionRow{ID: 11, Op: "add", Hosts: "wiki.example.com", Actor: "carol.example@example.com",
			At: time.Date(2026, 10, 1, 9, 30, 0, 0, time.UTC)},
		BaseHash: "5f1a15d24a6b9c2e0d7f4a3b8c6d5e4f9a8b7c6d",
		Diffs: []DiffBlock{
			{Title: "Caddyfile", Diff: "--- a\n+++ b\n@@ -1,4 +1,4 @@\n wiki.example.com {\n-\treverse_proxy https://100.64.0.5\n+\treverse_proxy http://100.64.0.5:8080\n \timport gate devops\n }\n"},
			{Title: "MagicDNS", Diff: "-wiki.example.com. 300 IN A 100.64.0.5\n+wiki.example.com. 300 IN A 100.64.0.9\n"},
			{Title: "Zitadel redirect URI", Diff: ""},
		},
	}
}
