package web

import (
	"errors"
	"net/http"

	"github.com/a-h/templ"
)

// Preview samples for the device routes, device tags and users screens (F3-015/016/007). They use
// the real route paths so the sidebar marks the right entry. Query flags branch into the states a
// page has: ?empty=1 (no data), ?err=1 (read failure), ?policy=1 (unreadable policy) and ?dry=1
// (dry-run note) on the routes page; ?mode=error|protected|warn|confirm|done on the tags page;
// ?empty=1 and ?zitadel=1 on the users page.
func init() {
	previewPages = append(previewPages,
		previewPage{"/headscale/devices/7/routes", "headscale", "Cihaz route'ları", previewDeviceRoutes},
		previewPage{"/headscale/devices/2/tags", "headscale", "Cihaz tag'leri", previewDeviceTags},
		previewPage{"/headscale/users", "headscale", "Headscale kullanıcıları", previewUsers},
	)
}

func previewDeviceRoutes(r *http.Request) templ.Component {
	q := r.URL.Query()
	v := DeviceRoutesView{
		Row:     DeviceRowView{ID: 7, Name: "srv-routes", Owner: "alice", Online: true},
		Version: "preview-version",
		DryRun:  q.Get("dry") == "1",
	}
	if q.Get("err") == "1" {
		return DeviceRoutesPage(DeviceRoutesView{DryRun: v.DryRun, Err: errors.New("headscale: ListNodes: connection refused")}, previewCSRF)
	}
	if q.Get("policy") == "1" {
		v.PolicyErr = true
	}
	if q.Get("empty") != "1" {
		v.AvailableRoutes = []string{"10.0.0.0/24", "10.0.1.0/24", "0.0.0.0/0"}
		v.ApprovedRoutes = []string{"10.0.0.0/24"}
		v.ActiveRoutes = []string{"10.0.0.0/24"}
		v.SubnetRows = []RouteRowView{
			{Prefix: "10.0.0.0/24", Approved: true, Active: true, AutoApprovers: "tag:server"},
			{Prefix: "10.0.1.0/24"},
		}
		v.Exit = &ExitRouteView{AutoApprovers: "tag:server"}
	}
	return DeviceRoutesPage(v, previewCSRF)
}

func previewDeviceTags(r *http.Request) templ.Component {
	q := r.URL.Query()
	dry := q.Get("dry") == "1"
	options := []tagOption{
		{Name: "tag:web", Checked: true},
		{Name: "tag:db"},
		{Name: "tag:k8s"},
	}
	switch q.Get("mode") {
	case "error":
		return DeviceTagsPage(deviceTagsView{DryRun: dry, NodeID: 2, Name: "build-box", Mode: tagsModeError,
			Notice: "headscale policy okunamadı: connection refused"}, previewCSRF)
	case "protected":
		return DeviceTagsPage(deviceTagsView{DryRun: dry, NodeID: 3, Name: "gw", Mode: tagsModeProtected}, previewCSRF)
	case "warn":
		return DeviceTagsPage(deviceTagsView{DryRun: dry, NodeID: 1, Name: "alice-laptop", Mode: tagsModeWarn,
			Version: "preview-version", Options: options}, previewCSRF)
	case "confirm":
		return DeviceTagsPage(deviceTagsView{DryRun: dry, NodeID: 1, Name: "alice-laptop", Mode: tagsModeConfirm,
			Version: "preview-version", Selected: []string{"tag:web", "tag:db"}}, previewCSRF)
	case "done":
		return DeviceTagsPage(deviceTagsView{DryRun: dry, NodeID: 1, Name: "alice-laptop", Mode: tagsModeDone,
			Current: []string{"tag:web"}, OwnerNow: "tag'li", ExpiryNow: "yok"}, previewCSRF)
	default:
		return DeviceTagsPage(deviceTagsView{DryRun: dry, NodeID: 2, Name: "build-box", Mode: tagsModeEdit,
			Version: "preview-version", Current: []string{"tag:web"}, Options: options}, previewCSRF)
	}
}

func previewUsers(r *http.Request) templ.Component {
	q := r.URL.Query()
	v := UsersView{DryRun: q.Get("dry") == "1"}
	if q.Get("zitadel") == "1" {
		v.ZitadelErr = errors.New("zitadel: list grants: unavailable")
	}
	if q.Get("empty") == "1" {
		return UsersPage(v)
	}
	v.Rows = []UsersRowView{
		{ID: 1, Name: "carol", DisplayName: "Carol Example", Email: "carol.example@example.com",
			ProviderID: "https://auth.example.com/101", Matched: true, Verified: true, ZitadelID: "101",
			Roles: []string{"devops", "vpn-user"}, State: "active", PersonalDevices: 2, TaggedDevices: 1},
		{ID: 2, Name: "dave", Email: "dave@example.com",
			ProviderID: "https://auth.example.com/102", Matched: true, Verified: true, ZitadelID: "102",
			Roles: []string{"vpn-user"}, State: "active", PersonalDevices: 1, TaggedDevices: 0},
		{ID: 3, Name: "router", ProviderID: "https://auth.example.com/103",
			Verified: true, ZitadelID: "103", PersonalDevices: 0, TaggedDevices: 3},
		{ID: 4, Name: "erin", Email: "erin@example.com", ProviderID: "https://auth.example.com/104",
			Verified: false, PersonalDevices: 0, TaggedDevices: 0},
	}
	return UsersPage(v)
}
