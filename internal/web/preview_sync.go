package web

import (
	"net/http"
	"time"

	"github.com/a-h/templ"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/sync"
)

// The preview samples of the sync and audit pages (docs/ui-guide.md). Every state the page can show
// gets a sample: the full snapshot, the empty plan, a blocked plan, a read failure and the dry-run
// state for sync; a full log and the empty result for audit. Query flags pick the state.
func init() {
	previewPages = append(previewPages,
		previewPage{"/sync", "sync", "Sync", func(r *http.Request) templ.Component {
			switch r.URL.Query().Get("state") {
			case "empty":
				return SyncPage(SyncOverview{IntervalMin: 5}, previewCSRF)
			case "blocked":
				ov := previewSyncOverview()
				ov.Plan = sync.Plan{Blocked: true, Reason: "policy okunamadı: beklenmeyen üye biçimi"}
				return SyncPage(ov, previewCSRF)
			case "readfail":
				ov := previewSyncOverview()
				ov.Plan = sync.Plan{Reason: "okuma hatası: zitadel: list grants: unavailable"}
				return SyncPage(ov, previewCSRF)
			case "dry":
				ov := previewSyncOverview()
				ov.DryRun = true
				return SyncPage(ov, previewCSRF)
			}
			return SyncPage(previewSyncOverview(), previewCSRF)
		}},
		previewPage{"/audit", "audit", "Audit", func(r *http.Request) templ.Component {
			if r.URL.Query().Get("empty") == "1" {
				return AuditPage(nil, "", "", 1, false)
			}
			return AuditPage(previewAuditEvents(), "", "", 1, true)
		}},
	)
}

// previewSyncOverview is the fixed full snapshot the sync sample renders.
func previewSyncOverview() SyncOverview {
	at := time.Date(2026, 10, 5, 17, 42, 10, 0, time.UTC)
	return SyncOverview{
		Alerts: []SyncAlertView{{
			Kind:     sync.AlertReadFailed,
			Source:   sync.SourceZitadel,
			LastSeen: at.Add(-90 * time.Minute),
		}},
		LastRun: &SyncRunView{
			At:      at,
			Trigger: sync.TriggerWebhook,
			Result:  "applied",
			Summary: "2 üye eklendi, 1 çıkarıldı, 0 hata",
		},
		DryRun:      false,
		IntervalMin: 5,
		Pending: []SyncPendingView{
			{ID: 7, Actor: "system:sync", Summary: "group:yazilim üye değişikliği", Version: "v7"},
		},
		Plan: sync.Plan{
			GroupDiff: sync.GroupDiff{
				Groups: []sync.GroupChange{{
					Group:   "group:yazilim",
					Added:   []string{"https://auth.example.com/42@"},
					Removed: []string{"https://auth.example.com/7@"},
				}},
				RemovedGroups: []string{"group:old"},
			},
			ExpireNodes: []sync.NodeExpiry{{
				NodeID: 201, Node: "erin-laptop", UserID: "23", Why: "artık izinli rolde değil",
			}},
			NeedsApproval: true,
			Warnings:      []string{"kullanıcı 9: Headscale kullanıcısı yok, rol gruplarına yazılmadı."},
			Identity: &sync.IdentityConversion{
				Mappings: []sync.IdentityMapping{{
					Old:    "alice@example.com",
					New:    "https://auth.example.com/42@",
					UserID: "42",
				}},
				Unmatched: []string{"bob@example.com"},
				Dropped:   []string{"legacy@example.com"},
			},
		},
	}
}

// previewAuditEvents is the fixed log the audit sample renders, newest first.
func previewAuditEvents() []audit.Event {
	at := time.Date(2026, 10, 5, 17, 42, 10, 0, time.UTC)
	return []audit.Event{
		{ID: 6, At: at, Actor: "system", Event: "sync.run", Target: "role-sync", Result: "applied", Diff: audit.Diff{{Field: "members", Before: "1", After: "3"}}},
		{ID: 5, At: at.Add(-3 * time.Minute), Actor: "carol@example.com", Event: "policy.preview", Target: "headscale/acl", Result: "requested"},
		{ID: 4, At: at.Add(-11 * time.Minute), Actor: "system", Event: "caddy.reconcile", Target: "minio.example.com", Result: "error"},
		{ID: 3, At: at.Add(-47 * time.Minute), Actor: "carol@example.com", Event: "site.update", Target: "grafana.example.com", Result: "applied", Diff: audit.Diff{{Field: "roles", Before: "", After: "+devops"}}},
		{ID: 2, At: at.Add(-90 * time.Minute), Actor: "dave@example.com", Event: "device.expire", Target: "grace-air", Result: "applied"},
		{ID: 1, At: at.Add(-115 * time.Minute), Actor: "carol@example.com", Event: "apikey.create", Target: "headscale/api", Result: "applied"},
	}
}
