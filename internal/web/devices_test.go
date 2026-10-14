package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/a-h/templ"

	"github.com/nesiler/tagcess/internal/headscale/admin"
)

// Harness of the devices screens (F3-012, H-01 read side): the /headscale/devices list with its
// 30 s htmx poll, the /headscale/devices/{id} detail page and the /headscale redirect. The tests
// drive the production DevicesService over a fixed admin read, so the mapping from AdminNode to
// the rendered page is covered end to end.

// fakeAdminNodes is a fixed admin read surface for the devices service.
type fakeAdminNodes struct {
	nodes []admin.AdminNode
	err   error
}

func (f *fakeAdminNodes) ListNodes(context.Context) ([]admin.AdminNode, error) {
	return f.nodes, f.err
}

// fakeDryRunReader is a fixed dry-run source for the Headscale page configs.
type fakeDryRunReader struct {
	on  bool
	err error
}

func (f *fakeDryRunReader) DryRun(context.Context) (bool, error) { return f.on, f.err }

type devicesHarness struct {
	hs    *fakeAdminNodes
	dry   *fakeDryRunReader
	csrf  *CSRF
	chain http.Handler
}

func newDevicesHarness(t *testing.T, nodes []admin.AdminNode, listErr error) *devicesHarness {
	t.Helper()
	h := &devicesHarness{
		hs:   &fakeAdminNodes{nodes: nodes, err: listErr},
		dry:  &fakeDryRunReader{},
		csrf: testCSRF(t),
	}
	svc, err := NewDevicesService(h.hs)
	if err != nil {
		t.Fatalf("NewDevicesService: %v", err)
	}
	handler, err := NewDevicesHandler(DevicesHandlerConfig{Reader: svc, DryRun: h.dry, CSRF: h.csrf})
	if err != nil {
		t.Fatalf("NewDevicesHandler: %v", err)
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	h.chain = RequireDevops(h.csrf.Protect(mux))
	return h
}

// do issues a request with the given groups header ("" sends none). Only safe methods are used
// here: the devices screens are read-only.
func (h *devicesHarness) do(t *testing.T, method, target, groups string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), method, target, strings.NewReader(""))
	if groups != "" {
		req.Header.Set(headerUser, "devops-user")
		req.Header.Set(headerEmail, "devops@example.com")
		req.Header.Set(headerGroups, groups)
	}
	rec := httptest.NewRecorder()
	h.chain.ServeHTTP(rec, req)
	return rec
}

func (h *devicesHarness) get(t *testing.T, target string) *httptest.ResponseRecorder {
	t.Helper()
	return h.do(t, http.MethodGet, target, "devops")
}

// Fixed instants for the fixture nodes; the display texts are the UTC-formatted values, so the
// assertions hold in every timezone.
var (
	deviceExpiryFuture = time.Date(2099, 1, 2, 3, 4, 0, 0, time.UTC)
	deviceExpiryPast   = time.Date(2020, 5, 6, 7, 8, 0, 0, time.UTC)
	deviceSeen         = time.Date(2026, 10, 1, 9, 30, 0, 0, time.UTC)
	deviceMade         = time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
)

// AC1: the list shows, per device, the name, the owner (personal) or the tags, the IPs, the
// online state, the last seen instant and the expiry state (moment / none / expired).
func TestDevicesPage_ListsNodes(t *testing.T) {
	nodes := []admin.AdminNode{
		{
			ID: 1, GivenName: "alice-laptop", UserName: "alice",
			IPs: []string{"100.64.0.10"}, Online: true,
			LastSeen: &deviceSeen, Expiry: &deviceExpiryFuture, CreatedAt: deviceMade,
		},
		{
			ID: 2, GivenName: "bob-old", UserName: "bob",
			IPs: []string{"100.64.0.11"}, Online: false,
			LastSeen: &deviceSeen, Expiry: &deviceExpiryPast,
		},
		{
			ID: 3, GivenName: "carol-pc", UserName: "carol",
			IPs: []string{"100.64.0.12"}, Online: false,
			Expiry: nil,
		},
	}
	h := newDevicesHarness(t, nodes, nil)

	rec := h.get(t, "/headscale/devices")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"alice-laptop", "alice", "100.64.0.10",
		"çevrimiçi",
		deviceSeen.Format(deviceTimeLayout),
		deviceExpiryFuture.Format(deviceTimeLayout),
		"bob-old", "çevrimdışı", "geçmiş",
		"carol-pc", "yok",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page does not contain %q", want)
		}
	}
}

// AC2: a tagged device shows its tags as badges and the owner column says "tag'li"; a personal
// device shows its owner's name.
func TestDevicesPage_MarksTagged(t *testing.T) {
	nodes := []admin.AdminNode{
		{
			ID: 1, GivenName: "srv-01", UserID: 7, UserName: "alice",
			Tags: []string{"tag:k8s", "tag:vpn-server"}, IPs: []string{"100.64.0.20"},
			CreatedAt: deviceMade,
		},
		{
			ID: 2, GivenName: "alice-laptop", UserName: "alice",
			IPs: []string{"100.64.0.10"}, CreatedAt: deviceMade,
		},
	}
	h := newDevicesHarness(t, nodes, nil)

	body := h.get(t, "/headscale/devices").Body.String()
	for _, want := range []string{"tag&#39;li", "tag:k8s", "tag:vpn-server", "alice-laptop", "alice"} {
		if !strings.Contains(body, want) {
			t.Errorf("page does not contain %q", want)
		}
	}
	// The tagged row's owner cell says "tag'li", never the user name; the user name appears only
	// as the personal row's owner.
	if strings.Count(body, ">alice<") != 1 {
		t.Errorf("the owner name is shown %d times, want once (personal row only):\n%s", strings.Count(body, ">alice<"), body)
	}
}

// AC3: the detail page shows the advertised, approved and active routes, the registration time
// and the expiry. Unknown or malformed ids answer 404.
func TestDevicePage_ShowsRoutesAndExpiry(t *testing.T) {
	nodes := []admin.AdminNode{
		{
			ID: 5, GivenName: "srv-01", UserName: "svc", IPs: []string{"100.64.0.20"},
			CreatedAt: deviceMade, Expiry: &deviceExpiryFuture,
			AvailableRoutes: []string{"10.0.0.0/24", "0.0.0.0/0"},
			ApprovedRoutes:  []string{"10.0.0.0/24"},
			SubnetRoutes:    []string{"10.0.0.0/24"},
		},
	}
	h := newDevicesHarness(t, nodes, nil)

	rec := h.get(t, "/headscale/devices/5")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"srv-01",
		"İlan edilen", "10.0.0.0/24", "0.0.0.0/0",
		"Onaylı",
		"Aktif",
		deviceMade.Format(deviceTimeLayout),
		deviceExpiryFuture.Format(deviceTimeLayout),
	} {
		if !strings.Contains(body, want) {
			t.Errorf("detail page does not contain %q", want)
		}
	}
	if rec := h.get(t, "/headscale/devices/99"); rec.Code != http.StatusNotFound {
		t.Errorf("unknown id = %d, want 404", rec.Code)
	}
	if rec := h.get(t, "/headscale/devices/nope"); rec.Code != http.StatusNotFound {
		t.Errorf("non-numeric id = %d, want 404", rec.Code)
	}
}

// AC4: the fragment route returns only the table fragment (no layout, no navigation) and both the
// page and the fragment carry the 30 s htmx periodic refresh trigger.
func TestDevicesPage_PeriodicRefreshFragment(t *testing.T) {
	h := newDevicesHarness(t, []admin.AdminNode{
		{ID: 1, GivenName: "alice-laptop", UserName: "alice", IPs: []string{"100.64.0.10"}, CreatedAt: deviceMade},
	}, nil)

	rec := h.get(t, "/headscale/devices/table")
	if rec.Code != http.StatusOK {
		t.Fatalf("fragment status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"alice-laptop",
		`id="device-list"`,
		`hx-get="/headscale/devices/table"`,
		`hx-trigger="every 30s"`,
		`hx-swap="outerHTML"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("fragment does not contain %q", want)
		}
	}
	for _, unwanted := range []string{"<html", "navbar-brand"} {
		if strings.Contains(body, unwanted) {
			t.Errorf("fragment contains layout content %q:\n%s", unwanted, body)
		}
	}

	page := h.get(t, "/headscale/devices")
	if page.Code != http.StatusOK {
		t.Fatalf("page status = %d, want 200", page.Code)
	}
	if !strings.Contains(page.Body.String(), `hx-trigger="every 30s"`) {
		t.Errorf("page does not carry the periodic refresh trigger:\n%s", page.Body.String())
	}
}

// AC5: when Headscale cannot be read, the page and the fragment show the error and no rows — no
// stale or fabricated data. The fragment stays a 2xx body so htmx swaps the error in instead of
// keeping the old table on screen.
func TestDevicesPage_HeadscaleDown(t *testing.T) {
	h := newDevicesHarness(t, nil, errors.New("headscale/admin: ListNodes: unavailable"))

	for _, target := range []string{"/headscale/devices", "/headscale/devices/table"} {
		rec := h.get(t, target)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s = %d, want 200", target, rec.Code)
		}
		body := rec.Body.String()
		if !strings.Contains(body, "Cihazlar okunamadı") || !strings.Contains(body, "ListNodes: unavailable") {
			t.Errorf("%s does not show the failure reason:\n%s", target, body)
		}
		if strings.Contains(body, "<table") || strings.Contains(body, "alice-laptop") {
			t.Errorf("%s shows device data although Headscale is down:\n%s", target, body)
		}
	}
}

// The section root /headscale redirects to the default tab.
func TestDevicesPage_SectionRootRedirects(t *testing.T) {
	h := newDevicesHarness(t, nil, nil)

	rec := h.get(t, "/headscale")
	if rec.Code != http.StatusFound {
		t.Fatalf("GET /headscale = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/headscale/devices" {
		t.Errorf("Location = %q, want /headscale/devices", loc)
	}
}

// AC6: the sidebar lists the Headscale screens in the defined order and marks the one that owns
// the request path, and only that one.
func TestHeadscaleTabs(t *testing.T) {
	page := renderAt(t, "/headscale/dns", Layout(Actor{User: "jdoe"}, "token", "headscale", "DNS", templ.Raw("")))

	tabs := []struct{ label, href string }{
		{"Cihazlar", "/headscale/devices"},
		{"Kullanıcılar", "/headscale/users"},
		{"Key'ler", "/headscale/keys"},
		{"ACL", "/headscale/policy"},
		{"DNS", "/headscale/dns"},
		{"Ayarlar", "/headscale/settings"},
		{"Config", "/headscale/config"},
	}
	last := -1
	for _, tab := range tabs {
		i := strings.Index(page, `href="`+tab.href+`"`)
		if i < 0 {
			t.Fatalf("sidebar lacks %q:\n%s", tab.href, page)
		}
		if i < last {
			t.Errorf("sidebar entry %q is out of order", tab.label)
		}
		last = i
		marked := strings.Contains(page, `href="`+tab.href+`" aria-current="page"`)
		if want := tab.href == "/headscale/dns"; marked != want {
			t.Errorf("sidebar entry %q marked = %v, want %v", tab.label, marked, want)
		}
	}
}

// AC7: the devices screens are behind the devops middleware; no group or a foreign group gets 403.
func TestDevicesPage_RequiresDevops(t *testing.T) {
	h := newDevicesHarness(t, nil, nil)

	if rec := h.do(t, http.MethodGet, "/headscale/devices", ""); rec.Code != http.StatusForbidden {
		t.Errorf("no identity = %d, want 403", rec.Code)
	}
	if rec := h.do(t, http.MethodGet, "/headscale/devices", "viewer"); rec.Code != http.StatusForbidden {
		t.Errorf("non-devops group = %d, want 403", rec.Code)
	}
	if rec := h.do(t, http.MethodGet, "/headscale/devices/table", "viewer"); rec.Code != http.StatusForbidden {
		t.Errorf("fragment, non-devops group = %d, want 403", rec.Code)
	}
	if rec := h.do(t, http.MethodGet, "/headscale/devices/5", "viewer"); rec.Code != http.StatusForbidden {
		t.Errorf("detail, non-devops group = %d, want 403", rec.Code)
	}
	if rec := h.get(t, "/headscale/devices"); rec.Code != http.StatusOK {
		t.Errorf("devops = %d, want 200", rec.Code)
	}
}

// AC8: the users (F3-007) and DNS (F3-008) pages show the section's screens and mark their own.
func TestHeadscaleTabs_WiredIntoUsersAndDNS(t *testing.T) {
	uh := newUsersHarness(t, UsersView{Rows: []UsersRowView{{ID: 1, Name: "alice"}}})
	rec := uh.get(t, "/headscale/users")
	if rec.Code != http.StatusOK {
		t.Fatalf("users page = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, tab := range headscaleTabs {
		if !strings.Contains(body, `href="`+tab.Href+`"`) {
			t.Errorf("users page lacks tab link %q", tab.Href)
		}
	}
	if !strings.Contains(body, `href="/headscale/users" aria-current="page"`) {
		t.Errorf("users page does not mark its tab:\n%s", body)
	}

	dh := newDNSRecordsHarness(t)
	rec = dh.get(t, "/headscale/dns")
	if rec.Code != http.StatusOK {
		t.Fatalf("dns page = %d, want 200", rec.Code)
	}
	body = rec.Body.String()
	for _, tab := range headscaleTabs {
		if !strings.Contains(body, `href="`+tab.Href+`"`) {
			t.Errorf("dns page lacks tab link %q", tab.Href)
		}
	}
	if !strings.Contains(body, `href="/headscale/dns" aria-current="page"`) {
		t.Errorf("dns page does not mark its tab:\n%s", body)
	}
}

// AC9: the keys sub-navigation shows Pre-auth, personal key and API links, in order.
func TestKeysSubNav(t *testing.T) {
	page := render(t, KeysSubNav("personal"))

	sub := []struct{ label, href string }{
		{"Pre-auth", "/headscale/keys/preauth"},
		{"Kişisel key", "/headscale/keys/personal"},
		{"API", "/headscale/keys/api"},
	}
	last := -1
	for _, tab := range sub {
		if !strings.Contains(page, `href="`+tab.href+`"`) {
			t.Errorf("keys sub-nav lacks link %q:\n%s", tab.href, page)
		}
		i := strings.Index(page, tab.label)
		if i < 0 {
			t.Fatalf("keys sub-nav label %q missing:\n%s", tab.label, page)
		}
		if i < last {
			t.Errorf("keys sub-nav label %q is out of order", tab.label)
		}
		last = i
	}
	if !strings.Contains(page, `href="/headscale/keys/personal" aria-current="page"`) {
		t.Error("keys sub-nav does not mark the active entry")
	}
}

// AC10: while dry-run is on, the tab bar shows the note that automatic sync and policy writes
// stop while manual device/key actions still apply; it is absent otherwise.
func TestHeadscaleTabs_DryRunNote(t *testing.T) {
	const note = "dry-run açık: otomatik sync ve policy yazmaları durur; elle cihaz/key eylemleri apply edilir"

	if page := render(t, HeadscaleTabs("devices", true)); !strings.Contains(page, note) {
		t.Errorf("tab bar with dry-run on lacks the note:\n%s", page)
	}
	if page := render(t, HeadscaleTabs("devices", false)); strings.Contains(page, note) {
		t.Errorf("tab bar with dry-run off shows the note:\n%s", page)
	}

	// The note reaches the devices page through the handler's dry-run source.
	h := newDevicesHarness(t, []admin.AdminNode{{ID: 1, GivenName: "alice-laptop", CreatedAt: deviceMade}}, nil)
	h.dry.on = true
	if body := h.get(t, "/headscale/devices").Body.String(); !strings.Contains(body, note) {
		t.Errorf("devices page with dry-run on lacks the note:\n%s", body)
	}
}

// The service maps AdminNodes to rows: sorted by id, the owner split (personal name vs "tag'li"),
// the three expiry states and the "never seen" dash.
func TestDevicesService_BuildsView(t *testing.T) {
	nodes := []admin.AdminNode{
		{
			ID: 2, GivenName: "carol-pc", UserName: "carol", IPs: []string{"100.64.0.12"},
			LastSeen: nil, Expiry: nil, CreatedAt: deviceMade,
		},
		{
			ID: 1, GivenName: "srv-01", UserID: 7, UserName: "alice",
			Tags: []string{"tag:k8s"}, IPs: []string{"100.64.0.20"},
			LastSeen: &deviceSeen, Expiry: &deviceExpiryPast, CreatedAt: deviceMade,
		},
		{
			ID: 3, GivenName: "alice-laptop", UserName: "alice", IPs: []string{"100.64.0.10"},
			LastSeen: &deviceSeen, Expiry: &deviceExpiryFuture, CreatedAt: deviceMade,
		},
	}
	svc, err := NewDevicesService(&fakeAdminNodes{nodes: nodes})
	if err != nil {
		t.Fatalf("NewDevicesService: %v", err)
	}

	view, err := svc.Devices(context.Background())
	if err != nil {
		t.Fatalf("Devices(): %v", err)
	}
	if len(view.Rows) != 3 {
		t.Fatalf("got %d rows, want 3", len(view.Rows))
	}
	tagged, personal, future := view.Rows[0], view.Rows[1], view.Rows[2]
	if tagged.ID != 1 || personal.ID != 2 || future.ID != 3 {
		t.Fatalf("rows are not sorted by id: %d, %d, %d", tagged.ID, personal.ID, future.ID)
	}
	if !tagged.Tagged || tagged.Owner != "tag'li" || len(tagged.Tags) != 1 || tagged.Tags[0] != "tag:k8s" {
		t.Errorf("tagged row = %+v, want owner tag'li with tag:k8s", tagged)
	}
	if personal.Tagged || personal.Owner != "carol" {
		t.Errorf("personal row = %+v, want owner carol", personal)
	}
	if personal.LastSeen != "—" {
		t.Errorf("never-seen row LastSeen = %q, want \"—\"", personal.LastSeen)
	}
	if personal.Expiry != "yok" || personal.Expired {
		t.Errorf("no-expiry row = %q/%v, want yok/false", personal.Expiry, personal.Expired)
	}
	if tagged.Expiry != "geçmiş" || !tagged.Expired {
		t.Errorf("expired row = %q/%v, want geçmiş/true", tagged.Expiry, tagged.Expired)
	}
	if future.Expiry != deviceExpiryFuture.Format(deviceTimeLayout) || future.Expired {
		t.Errorf("future row = %q/%v, want %s/false", future.Expiry, future.Expired, deviceExpiryFuture.Format(deviceTimeLayout))
	}
}

// The detail lookup finds the node by id and reports unknown ids as errDeviceNotFound.
func TestDevicesService_Device(t *testing.T) {
	nodes := []admin.AdminNode{{ID: 5, GivenName: "srv-01", CreatedAt: deviceMade}}
	svc, err := NewDevicesService(&fakeAdminNodes{nodes: nodes})
	if err != nil {
		t.Fatalf("NewDevicesService: %v", err)
	}

	detail, err := svc.Device(context.Background(), 5)
	if err != nil {
		t.Fatalf("Device(5): %v", err)
	}
	if detail.Row.Name != "srv-01" || detail.CreatedAt != deviceMade.Format(deviceTimeLayout) {
		t.Errorf("detail = %+v, want srv-01 at %s", detail, deviceMade.Format(deviceTimeLayout))
	}
	if _, err := svc.Device(context.Background(), 6); !errors.Is(err, errDeviceNotFound) {
		t.Errorf("Device(6) = %v, want errDeviceNotFound", err)
	}
}

// A failed read fails the snapshot; the handler turns it into the page error.
func TestDevicesService_ReadFails(t *testing.T) {
	svc, err := NewDevicesService(&fakeAdminNodes{err: errors.New("down")})
	if err != nil {
		t.Fatalf("NewDevicesService: %v", err)
	}
	if _, err := svc.Devices(context.Background()); err == nil {
		t.Error("Devices() = nil error, want the read failure")
	}
	if _, err := svc.Device(context.Background(), 5); err == nil {
		t.Error("Device(5) = nil error, want the read failure")
	}
}

// NewDevicesService and NewDevicesHandler refuse an incomplete wiring.
func TestDevicesWiring(t *testing.T) {
	if _, err := NewDevicesService(nil); err == nil {
		t.Error("NewDevicesService accepted a nil reader")
	}
	if _, err := NewDevicesHandler(DevicesHandlerConfig{}); err == nil {
		t.Error("NewDevicesHandler accepted an empty config")
	}
	svc, err := NewDevicesService(&fakeAdminNodes{})
	if err != nil {
		t.Fatalf("NewDevicesService: %v", err)
	}
	if _, err := NewDevicesHandler(DevicesHandlerConfig{Reader: svc, CSRF: testCSRF(t)}); err == nil {
		t.Error("NewDevicesHandler accepted a missing dry-run source")
	}
	if _, err := NewDevicesHandler(DevicesHandlerConfig{Reader: svc, DryRun: &fakeDryRunReader{}}); err == nil {
		t.Error("NewDevicesHandler accepted a missing CSRF signer")
	}
}
