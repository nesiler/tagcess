package web

import (
	"errors"
	"net/http"

	"github.com/a-h/templ"

	"github.com/nesiler/tagcess/internal/hsadmin"
	"github.com/nesiler/tagcess/internal/vpnuser"
	"github.com/nesiler/tagcess/internal/zitadel"
)

// The devices preview samples: the list (normal, empty, error, dry-run), the detail (normal,
// protected, unreadable protected list, expired personal, error), the delete confirm, the reopen
// confirm (eligible and ineligible) and the two outcome screens. Every screen the T07 migration
// touches has a sample so the interface can be looked at and screenshotted in isolation.

func init() {
	previewPages = append(previewPages,
		previewPage{"/headscale/devices", "headscale", "Headscale cihazları", previewDevicesPage},
		previewPage{"/headscale/devices/1", "headscale", "Cihaz ayrıntısı", previewDeviceDetailPage},
		previewPage{"/headscale/devices/1/delete", "headscale", "Silme onayı", previewDeviceDeletePage},
		previewPage{"/headscale/devices/1/reopen", "headscale", "Yeniden açma onayı", previewDeviceReopenPage},
		previewPage{"/headscale/devices/1/result", "headscale", "İşlem sonucu", previewDeviceResultPage},
		previewPage{"/headscale/devices/1/reopen/result", "headscale", "İşlem sonucu", previewDeviceReopenResultPage},
	)
}

// previewDeviceRows is a fixed device list: personal online/offline, tagged and expired rows.
func previewDeviceRows() []DeviceRowView {
	return []DeviceRowView{
		{ID: 1, Name: "carol-mbp", Owner: "carol", IPs: []string{"100.64.0.4"}, Online: true,
			LastSeen: "2026-10-06 09:30", Expiry: "2099-01-02 03:04", ExpiryRaw: "2099-01-02T03:04:00Z"},
		{ID: 2, Name: "dave-thinkpad", Owner: "dave", IPs: []string{"100.64.0.7"}, Online: true,
			LastSeen: "2026-10-06 09:26", Expiry: "yok"},
		{ID: 3, Name: "grace-air", Owner: "grace", IPs: []string{"100.64.0.9"}, Online: false,
			LastSeen: "2026-10-04 12:10", Expiry: "2099-04-04 08:00", ExpiryRaw: "2099-04-04T08:00:00Z"},
		{ID: 4, Name: "rke-node-1", Owner: "tag'li", Tagged: true, Tags: []string{"tag:k8s"},
			IPs: []string{"100.64.0.30"}, Online: true, LastSeen: "2026-10-06 09:29", Expiry: "yok"},
		{ID: 5, Name: "old-laptop", Owner: "can", IPs: []string{"100.64.0.12"}, Online: false,
			LastSeen: "2026-09-28 18:02", Expiry: "geçmiş", ExpiryRaw: "2026-09-30T00:00:00Z", Expired: true},
	}
}

func previewDevicesPage(r *http.Request) templ.Component {
	q := r.URL.Query()
	dry := q.Get("dry") == "1"
	switch q.Get("state") {
	case "error":
		return DevicesPage(DevicesView{Err: errors.New("headscale/admin: ListNodes: unavailable"), DryRun: dry})
	case "empty":
		return DevicesPage(DevicesView{DryRun: dry})
	}
	return DevicesPage(DevicesView{Rows: previewDeviceRows(), DryRun: dry})
}

func previewDeviceDetailPage(r *http.Request) templ.Component {
	q := r.URL.Query()
	if q.Get("state") == "error" {
		return DeviceDetailPage(DeviceDetailView{Err: errors.New("headscale/admin: ListNodes: unavailable")}, previewCSRF)
	}
	detail := DeviceDetailView{
		Row:             previewDeviceRows()[0],
		CreatedAt:       "2026-09-01 08:00",
		AvailableRoutes: []string{"10.0.0.0/24", "0.0.0.0/0"},
		ApprovedRoutes:  []string{"10.0.0.0/24"},
		ActiveRoutes:    []string{"10.0.0.0/24"},
		Version:         "v1",
		Actions:         &DeviceActionsPanel{},
		DryRun:          q.Get("dry") == "1",
	}
	switch q.Get("state") {
	case "protected":
		detail.Row = previewDeviceRows()[3]
		detail.Actions = &DeviceActionsPanel{Protected: true}
	case "warning":
		detail.Actions = &DeviceActionsPanel{Warning: "korumalı tag listesi okunamadı; silme ve expire işlemleri gizli. Neden: store: setting okunamadı"}
	case "expired":
		detail.Row = previewDeviceRows()[4]
		detail.Actions = &DeviceActionsPanel{Reopenable: true}
	}
	return DeviceDetailPage(detail, previewCSRF)
}

func previewDeviceDeletePage(r *http.Request) templ.Component {
	if r.URL.Query().Get("state") == "error" {
		return DeviceDeleteConfirmPage(DeviceDeleteConfirmView{Err: errors.New("headscale/admin: ListNodes: unavailable")}, previewCSRF)
	}
	return DeviceDeleteConfirmPage(DeviceDeleteConfirmView{Row: previewDeviceRows()[0], Version: "v1"}, previewCSRF)
}

func previewDeviceReopenPage(r *http.Request) templ.Component {
	row := previewDeviceRows()[4]
	if r.URL.Query().Get("state") == "ineligible" {
		return DeviceReopenConfirmPage(DeviceReopenConfirmView{
			Row: row, Version: "v1",
			Err: errors.New("zitadel kullanıcısı u10 vpn projesinde rolü yok"),
		}, previewCSRF)
	}
	return DeviceReopenConfirmPage(DeviceReopenConfirmView{
		Row: row, Version: "v1",
		Evidence: vpnuser.Eligibility{UserID: "u10", State: zitadel.UserActive, Roles: []string{"vpn-user"}},
	}, previewCSRF)
}

func previewDeviceResultPage(r *http.Request) templ.Component {
	v := DeviceActionResultView{DeviceID: 1, DeviceName: "carol-mbp", Action: actionRename, Status: hsadmin.StatusApplied}
	switch r.URL.Query().Get("state") {
	case "failed":
		v.Status = hsadmin.StatusFailed
		v.Note = "headscale: RenameNode: unavailable"
	case "unknown":
		v.Status = hsadmin.StatusUnknown
		v.Note = "yazma apply edildi; geri okuma başarısız"
	case "stale":
		v.Action = actionSetExpiry
		v.Status = hsadmin.StatusStale
		v.Note = "form sürümü güncel değil; sayfayı yenileyin"
	case "blocked":
		v.Action = actionDisableExpiry
		v.Status = hsadmin.StatusBlocked
		v.Note = "bakım sürüyor; genişleten bu işlem devre dışı, daraltan işlemler açık"
	}
	return DeviceActionResultPage(v)
}

func previewDeviceReopenResultPage(r *http.Request) templ.Component {
	v := DeviceReopenResultView{
		DeviceActionResultView: DeviceActionResultView{
			DeviceID: 5, DeviceName: "old-laptop", Action: "Cihazı yeniden açma", Status: hsadmin.StatusApplied,
		},
		ReconcileTriggered: true,
	}
	if r.URL.Query().Get("state") == "blocked" {
		v.Status = hsadmin.StatusBlocked
		v.ReconcileTriggered = false
		v.Note = "zitadel kullanıcısı u10 vpn projesinde rolü yok"
	}
	return DeviceReopenResultPage(v)
}
