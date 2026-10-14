package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/headscale"
	"github.com/nesiler/tagcess/internal/headscale/admin"
	"github.com/nesiler/tagcess/internal/hostapply"
	"github.com/nesiler/tagcess/internal/hostpatch"
	"github.com/nesiler/tagcess/internal/hsadmin"
	"github.com/nesiler/tagcess/internal/maintenance"
	"github.com/nesiler/tagcess/internal/site"
	"github.com/nesiler/tagcess/internal/store"
	"github.com/nesiler/tagcess/internal/web"
)

type stubVersions struct{}

func (stubVersions) ListVersions(context.Context, int64) ([]site.Version, error) {
	return []site.Version{{ID: 1, SiteID: 7, Op: "add", Site: site.Site{ID: 7, Hosts: []string{"wiki.example.com"}}}}, nil
}

type stubRollback struct{}

func (stubRollback) PreviewRollback(context.Context, string, int64) (change.RollbackPreview, error) {
	return change.RollbackPreview{}, change.ErrRollbackNoChange
}

func (stubRollback) ApplyRollback(context.Context, change.RollbackApproval) (change.SiteResult, error) {
	return change.SiteResult{}, change.ErrRollbackNoChange
}

// errUsers always fails, so a 500 proves the route (and only the middleware's 403 path) is live.
type errUsers struct{}

func (errUsers) Users(context.Context) (web.UsersView, error) {
	return web.UsersView{}, errors.New("down")
}

// stubDryRun is a fixed dry-run source for the page configs.
type stubDryRun struct{}

func (stubDryRun) DryRun(context.Context) (bool, error) { return false, nil }

// stubDevices is a fixed devices reader for the route test.
type stubDevices struct{}

func (stubDevices) Devices(context.Context) (web.DevicesView, error) {
	return web.DevicesView{}, nil
}

func (stubDevices) Device(context.Context, uint64) (web.DeviceDetailView, error) {
	return web.DeviceDetailView{}, nil
}

// The users screen route (F3-007) is mounted behind RequireDevops and CSRF: a devops request
// reaches the handler (whose reader fails → 500), a request without the group is refused 403.
func TestUIHandler_UsersRoute(t *testing.T) {
	csrf, err := web.NewCSRF([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("NewCSRF: %v", err)
	}
	users, err := web.NewUsersHandler(web.UsersHandlerConfig{Reader: errUsers{}, DryRun: stubDryRun{}, CSRF: csrf})
	if err != nil {
		t.Fatalf("NewUsersHandler: %v", err)
	}
	h := newUIHandler(csrf, uiPages{Users: users})

	do := func(devops bool) int {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/headscale/users", nil)
		if devops {
			req.Header.Set("X-Auth-Request-User", "dev")
			req.Header.Set("X-Auth-Request-Email", "dev@example.com")
			req.Header.Set("X-Auth-Request-Groups", "devops")
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	if got := do(true); got != http.StatusInternalServerError {
		t.Errorf("users as devops = %d, want 500 (route mounted, reader failed)", got)
	}
	if got := do(false); got != http.StatusForbidden {
		t.Errorf("users without identity = %d, want 403", got)
	}
}

// The devices screens (F3-012) are mounted behind RequireDevops: the section root /headscale
// redirects to the device list, the list and the polled fragment answer for devops only.
func TestUIHandler_DevicesRoutes(t *testing.T) {
	csrf, err := web.NewCSRF([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("NewCSRF: %v", err)
	}
	devices, err := web.NewDevicesHandler(web.DevicesHandlerConfig{Reader: stubDevices{}, DryRun: stubDryRun{}, CSRF: csrf})
	if err != nil {
		t.Fatalf("NewDevicesHandler: %v", err)
	}
	h := newUIHandler(csrf, uiPages{Devices: devices})

	do := func(target string, devops bool) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
		if devops {
			req.Header.Set("X-Auth-Request-User", "dev")
			req.Header.Set("X-Auth-Request-Email", "dev@example.com")
			req.Header.Set("X-Auth-Request-Groups", "devops")
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	rec := do("/headscale", true)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/headscale/devices" {
		t.Errorf("GET /headscale = %d (%q), want 302 to /headscale/devices", rec.Code, rec.Header().Get("Location"))
	}
	for _, target := range []string{"/headscale/devices", "/headscale/devices/table", "/headscale/devices/1"} {
		if got := do(target, true).Code; got != http.StatusOK {
			t.Errorf("GET %s as devops = %d, want 200", target, got)
		}
		if got := do(target, false).Code; got != http.StatusForbidden {
			t.Errorf("GET %s without identity = %d, want 403", target, got)
		}
	}
}

// The site history and rollback routes (F2-020) are mounted behind RequireDevops and CSRF.
func TestUIHandler_SiteHistoryRoutes(t *testing.T) {
	csrf, err := web.NewCSRF([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("NewCSRF: %v", err)
	}
	history, err := web.NewSiteHistoryHandler(web.SiteHistoryConfig{Versions: stubVersions{}, Rollback: stubRollback{}, CSRF: csrf})
	if err != nil {
		t.Fatalf("NewSiteHistoryHandler: %v", err)
	}
	h := newUIHandler(csrf, uiPages{SiteHistory: history})

	do := func(method, target string, devops bool, form url.Values) int {
		req := httptest.NewRequestWithContext(context.Background(), method, target, strings.NewReader(form.Encode()))
		if devops {
			req.Header.Set("X-Auth-Request-User", "dev")
			req.Header.Set("X-Auth-Request-Email", "dev@example.com")
			req.Header.Set("X-Auth-Request-Groups", "devops")
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	if got := do(http.MethodGet, "/sites/7/history", true, nil); got != http.StatusOK {
		t.Errorf("history as devops = %d, want 200", got)
	}
	if got := do(http.MethodGet, "/sites/7/history", false, nil); got != http.StatusForbidden {
		t.Errorf("history without identity = %d, want 403", got)
	}
	if got := do(http.MethodGet, "/sites/7/history/1/rollback", true, nil); got == http.StatusNotFound {
		t.Error("rollback preview route is not mounted")
	}
	if got := do(http.MethodPost, "/sites/7/history/1/rollback", true, url.Values{}); got != http.StatusForbidden {
		t.Errorf("rollback approval without CSRF token = %d, want 403", got)
	}
}

// tagsDown is a Headscale that cannot be read: the tag screens must then refuse (503) and never
// reach a write; the stubs below panic if a write is attempted.
type tagsDown struct{}

func (tagsDown) ListNodes(context.Context) ([]admin.AdminNode, error) { return nil, errors.New("down") }
func (tagsDown) GetPolicy(context.Context) (headscale.Policy, error) {
	return headscale.Policy{}, errors.New("down")
}
func (tagsDown) SetTags(context.Context, uint64, []string) (admin.AdminNode, error) {
	panic("SetTags must not run")
}
func (tagsDown) Do(context.Context, hsadmin.Op) (hsadmin.Result, error) { panic("Do must not run") }
func (tagsDown) ProtectedTags(context.Context) ([]string, error)        { return nil, nil }

// The device tag routes (F3-016) are mounted behind RequireDevops and CSRF.
func TestUIHandler_DeviceTagsRoutes(t *testing.T) {
	csrf, err := web.NewCSRF([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("NewCSRF: %v", err)
	}
	tags, err := web.NewDeviceTagsHandler(web.DeviceTagsConfig{
		Nodes: tagsDown{}, Policy: tagsDown{}, Setter: tagsDown{}, Executor: tagsDown{}, DryRun: stubDryRun{}, CSRF: csrf,
	})
	if err != nil {
		t.Fatalf("NewDeviceTagsHandler: %v", err)
	}
	h := newUIHandler(csrf, uiPages{DeviceTags: tags})

	do := func(method string, devops bool) int {
		req := httptest.NewRequestWithContext(context.Background(), method, "/headscale/devices/1/tags", strings.NewReader("tag=tag:web"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if devops {
			req.Header.Set("X-Auth-Request-User", "dev")
			req.Header.Set("X-Auth-Request-Email", "dev@example.com")
			req.Header.Set("X-Auth-Request-Groups", "devops")
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if got := do(http.MethodGet, true); got != http.StatusServiceUnavailable {
		t.Errorf("GET as devops = %d, want 503 (route live, Headscale unreadable)", got)
	}
	if got := do(http.MethodGet, false); got != http.StatusForbidden {
		t.Errorf("GET without identity = %d, want 403", got)
	}
	if got := do(http.MethodPost, true); got != http.StatusForbidden {
		t.Errorf("POST without CSRF token = %d, want 403", got)
	}
}

// stubKeys is a key service with nothing to show; the route test only needs the pages to render.
type stubKeys struct{}

func (stubKeys) Keys(context.Context) web.KeysView { return web.KeysView{} }
func (stubKeys) Confirm(context.Context, uint64, string) (web.KeyConfirmView, error) {
	return web.KeyConfirmView{}, nil
}
func (stubKeys) Expire(context.Context, string, uint64, string) web.KeyOutcome {
	return web.KeyOutcome{}
}
func (stubKeys) Delete(context.Context, string, uint64, string) web.KeyOutcome {
	return web.KeyOutcome{}
}
func (stubKeys) CreateTagKey(context.Context, string, web.TagKeyInput) web.KeyOutcome {
	return web.KeyOutcome{}
}

// The pre-auth key screens (F3-017) are mounted behind RequireDevops and CSRF: the list answers
// for devops only and a POST without the CSRF token is refused.
func TestUIHandler_KeysRoutes(t *testing.T) {
	csrf, err := web.NewCSRF([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("NewCSRF: %v", err)
	}
	keys, err := web.NewKeysHandler(web.KeysHandlerConfig{Service: stubKeys{}, DryRun: stubDryRun{}, CSRF: csrf})
	if err != nil {
		t.Fatalf("NewKeysHandler: %v", err)
	}
	h := newUIHandler(csrf, uiPages{Keys: keys})

	do := func(method, target string, devops bool) int {
		req := httptest.NewRequestWithContext(context.Background(), method, target, nil)
		if devops {
			req.Header.Set("X-Auth-Request-User", "dev")
			req.Header.Set("X-Auth-Request-Email", "dev@example.com")
			req.Header.Set("X-Auth-Request-Groups", "devops")
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	for _, target := range []string{"/headscale/keys", "/headscale/keys/preauth"} {
		if got := do(http.MethodGet, target, true); got != http.StatusOK {
			t.Errorf("GET %s as devops = %d, want 200", target, got)
		}
		if got := do(http.MethodGet, target, false); got != http.StatusForbidden {
			t.Errorf("GET %s without identity = %d, want 403", target, got)
		}
	}
	if got := do(http.MethodPost, "/headscale/keys/preauth/create", true); got != http.StatusForbidden {
		t.Errorf("POST create without a CSRF token = %d, want 403", got)
	}
}

// stubPersonalKey is a personal key service with no users; the route test only needs the page.
type stubPersonalKey struct{}

func (stubPersonalKey) Options(context.Context) web.PersonalKeyView { return web.PersonalKeyView{} }
func (stubPersonalKey) Create(context.Context, string, web.PersonalKeyInput) web.KeyOutcome {
	return web.KeyOutcome{}
}

// The personal key screen (F3-022) is mounted behind RequireDevops and CSRF.
func TestUIHandler_PersonalKeyRoutes(t *testing.T) {
	csrf, err := web.NewCSRF([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("NewCSRF: %v", err)
	}
	page, err := web.NewPersonalKeyHandler(web.PersonalKeyHandlerConfig{Service: stubPersonalKey{}, DryRun: stubDryRun{}, CSRF: csrf})
	if err != nil {
		t.Fatalf("NewPersonalKeyHandler: %v", err)
	}
	h := newUIHandler(csrf, uiPages{PersonalKey: page})

	do := func(method string, devops bool) int {
		req := httptest.NewRequestWithContext(context.Background(), method, "/headscale/keys/personal", nil)
		if devops {
			req.Header.Set("X-Auth-Request-User", "dev")
			req.Header.Set("X-Auth-Request-Email", "dev@example.com")
			req.Header.Set("X-Auth-Request-Groups", "devops")
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if got := do(http.MethodGet, true); got != http.StatusOK {
		t.Errorf("GET as devops = %d, want 200", got)
	}
	if got := do(http.MethodGet, false); got != http.StatusForbidden {
		t.Errorf("GET without identity = %d, want 403", got)
	}
	if got := do(http.MethodPost, true); got != http.StatusForbidden {
		t.Errorf("POST without a CSRF token = %d, want 403", got)
	}
}

func TestListenPort(t *testing.T) {
	if n, err := listenPort("100.64.0.4:9000"); err != nil || n != 9000 {
		t.Errorf("listenPort = %d, %v", n, err)
	}
	for _, bad := range []string{"", "100.64.0.4", "100.64.0.4:x"} {
		if _, err := listenPort(bad); err == nil {
			t.Errorf("listenPort(%q) accepted", bad)
		}
	}
}

// The Headscale settings screen (F3-020) is mounted behind RequireDevops and CSRF.
func TestUIHandler_HSSettingsRoutes(t *testing.T) {
	csrf, err := web.NewCSRF([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("NewCSRF: %v", err)
	}
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "tagcess.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	page, err := web.NewHSSettingsHandler(web.HSSettingsConfig{
		Store: st.Queries(), Policy: stubPolicyReader{}, Checker: stubChecker{}, Auditor: audit.New(st.Queries()),
		WebhookPort: 9000, DryRun: stubDryRun{}, CSRF: csrf,
	})
	if err != nil {
		t.Fatalf("NewHSSettingsHandler: %v", err)
	}
	h := newUIHandler(csrf, uiPages{HSSettings: page})

	do := func(method string, devops bool) int {
		req := httptest.NewRequestWithContext(context.Background(), method, "/headscale/settings", nil)
		if method == http.MethodPost {
			req = httptest.NewRequestWithContext(context.Background(), method, "/headscale/settings/tags", nil)
		}
		if devops {
			req.Header.Set("X-Auth-Request-User", "dev")
			req.Header.Set("X-Auth-Request-Email", "dev@example.com")
			req.Header.Set("X-Auth-Request-Groups", "devops")
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if got := do(http.MethodGet, true); got != http.StatusOK {
		t.Errorf("GET as devops = %d, want 200", got)
	}
	if got := do(http.MethodGet, false); got != http.StatusForbidden {
		t.Errorf("GET without identity = %d, want 403", got)
	}
	if got := do(http.MethodPost, true); got != http.StatusForbidden {
		t.Errorf("POST without a CSRF token = %d, want 403", got)
	}
}

type stubPolicyReader struct{}

func (stubPolicyReader) GetPolicy(context.Context) (headscale.Policy, error) {
	return headscale.Policy{}, nil
}

type stubChecker struct{}

func (stubChecker) CheckPolicy(context.Context, string) error { return nil }

// The H-07 config screen (F3b-020) is mounted behind RequireDevops and CSRF like the other
// Headscale pages.
func TestUIHandler_HSConfigRoutes(t *testing.T) {
	csrf, err := web.NewCSRF([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("NewCSRF: %v", err)
	}
	page, err := web.NewHSConfigHandler(web.HSConfigConfig{
		Service: stubHSConfigService{}, Maintenance: stubHSConfigMaint{}, Host: stubHSConfigHost{},
		Switch: stubHSConfigSwitch{}, DryRun: stubDryRun{}, CSRF: csrf,
	})
	if err != nil {
		t.Fatalf("NewHSConfigHandler: %v", err)
	}
	h := newUIHandler(csrf, uiPages{HSConfig: page})

	do := func(method, target string, devops bool) int {
		req := httptest.NewRequestWithContext(context.Background(), method, target, nil)
		if devops {
			req.Header.Set("X-Auth-Request-User", "dev")
			req.Header.Set("X-Auth-Request-Email", "dev@example.com")
			req.Header.Set("X-Auth-Request-Groups", "devops")
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if got := do(http.MethodGet, "/headscale/config", true); got != http.StatusOK {
		t.Errorf("GET as devops = %d, want 200", got)
	}
	if got := do(http.MethodGet, "/headscale/config", false); got != http.StatusForbidden {
		t.Errorf("GET without identity = %d, want 403", got)
	}
	if got := do(http.MethodPost, "/headscale/config/preview", true); got != http.StatusForbidden {
		t.Errorf("POST without a CSRF token = %d, want 403", got)
	}
}

type stubHSConfigService struct{}

func (stubHSConfigService) Preview(context.Context, []string) (hostapply.Preview, error) {
	return hostapply.Preview{}, nil
}

func (stubHSConfigService) Apply(context.Context, hostapply.ApplyRequest) (hostapply.ApplyResult, error) {
	return hostapply.ApplyResult{}, nil
}

func (stubHSConfigService) CloseMaintenance(context.Context, hostapply.CloseRequest) (hostapply.CloseResult, error) {
	return hostapply.CloseResult{}, nil
}

type stubHSConfigMaint struct{}

func (stubHSConfigMaint) Get(context.Context) (maintenance.Status, error) {
	return maintenance.Status{State: maintenance.Off}, nil
}

type stubHSConfigHost struct{}

func (stubHSConfigHost) Status() (hostpatch.Status, error) { return hostpatch.Status{}, nil }

type stubHSConfigSwitch struct{}

func (stubHSConfigSwitch) GetSetting(context.Context, string) (string, error) { return "false", nil }
