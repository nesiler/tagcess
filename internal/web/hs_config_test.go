package web

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/a-h/templ"

	"github.com/nesiler/tagcess/internal/hostapply"
	"github.com/nesiler/tagcess/internal/hostpatch"
	"github.com/nesiler/tagcess/internal/maintenance"
)

// Harness of the H-07 config screen (F3b-020, H-07): the secret-free status of the host helper, the
// preview/approval flow and the "close the maintenance" action, over fakes for the F3b-018/019
// service, the maintenance row, the helper status and the write switch.

const (
	hsConfigActor = "devops@example.com"
	// hsConfigBaseRev is a stand-in for the helper's base_rev; the fake host is not validated.
	hsConfigBaseRev = "740a57b59f3878100ec9dd17b117f5239adbb93bd7686cb4cce8a1645bc49ad5"
	hsConfigReqID   = "0b7f4c1e-52d3-4a8e-9c61-3f2d8a7e5b10"
)

type fakeHSConfigService struct {
	mu          sync.Mutex
	preview     hostapply.Preview
	previewErr  error
	applyRes    hostapply.ApplyResult
	applyErr    error
	closeRes    hostapply.CloseResult
	closeErr    error
	previewArgs [][]string
	applyArgs   []hostapply.ApplyRequest
	closeArgs   []hostapply.CloseRequest
}

func (f *fakeHSConfigService) Preview(_ context.Context, wanted []string) (hostapply.Preview, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.previewArgs = append(f.previewArgs, wanted)
	return f.preview, f.previewErr
}

func (f *fakeHSConfigService) Apply(_ context.Context, req hostapply.ApplyRequest) (hostapply.ApplyResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applyArgs = append(f.applyArgs, req)
	return f.applyRes, f.applyErr
}

func (f *fakeHSConfigService) CloseMaintenance(_ context.Context, req hostapply.CloseRequest) (hostapply.CloseResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closeArgs = append(f.closeArgs, req)
	if f.closeErr != nil {
		return hostapply.CloseResult{}, f.closeErr
	}
	if !req.Confirm {
		return hostapply.CloseResult{}, hostapply.ErrConfirmRequired
	}
	if req.RequestID == "" {
		return hostapply.CloseResult{}, hostapply.ErrStaleRequestID
	}
	return f.closeRes, nil
}

func (f *fakeHSConfigService) calls() (previews, applies, closes int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.previewArgs), len(f.applyArgs), len(f.closeArgs)
}

type fakeHSConfigMaint struct {
	st  maintenance.Status
	err error
}

func (f *fakeHSConfigMaint) Get(context.Context) (maintenance.Status, error) { return f.st, f.err }

type fakeHSConfigHost struct {
	st  hostpatch.Status
	err error
}

func (f *fakeHSConfigHost) Status() (hostpatch.Status, error) { return f.st, f.err }

// fakeHSConfigSwitch is the settings row the write switch reads; an empty value is "no row".
type fakeHSConfigSwitch struct {
	v   string
	err error
}

func (f *fakeHSConfigSwitch) GetSetting(context.Context, string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	if f.v == "" {
		return "", sql.ErrNoRows
	}
	return f.v, nil
}

type hsConfigHarness struct {
	t       *testing.T
	csrf    *CSRF
	svc     *fakeHSConfigService
	maint   *fakeHSConfigMaint
	host    *fakeHSConfigHost
	switchr *fakeHSConfigSwitch
	dry     *fakeDryRunReader
	chain   http.Handler
}

func newHSConfigHarness(t *testing.T) *hsConfigHarness {
	t.Helper()
	h := &hsConfigHarness{
		t:     t,
		csrf:  testCSRF(t),
		svc:   &fakeHSConfigService{},
		maint: &fakeHSConfigMaint{st: maintenance.Status{State: maintenance.Off}},
		host: &fakeHSConfigHost{st: hostpatch.Status{
			Version: 1, AllowedGroups: []string{hostpatch.GroupDevops, hostpatch.GroupDeveloper}, BaseRev: hsConfigBaseRev,
		}},
		switchr: &fakeHSConfigSwitch{v: "true"},
		dry:     &fakeDryRunReader{},
	}
	handler, err := NewHSConfigHandler(HSConfigConfig{
		Service: h.svc, Maintenance: h.maint, Host: h.host, Switch: h.switchr, DryRun: h.dry, CSRF: h.csrf,
	})
	if err != nil {
		t.Fatalf("NewHSConfigHandler: %v", err)
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	h.chain = WithMaintenanceBanner(h.maint, RequireDevops(h.csrf.Protect(mux)))
	return h
}

// request sends a request as devops (or another group) with the CSRF token when asked.
func (h *hsConfigHarness) request(method, target string, form url.Values, groups string, csrf bool) *httptest.ResponseRecorder {
	h.t.Helper()
	var body *strings.Reader
	if form != nil {
		form = cloneValues(form)
		if csrf {
			form.Set(CSRFParam, h.csrf.Token())
		}
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	req := httptest.NewRequestWithContext(context.Background(), method, target, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set(headerUser, "devops-user")
	req.Header.Set(headerEmail, hsConfigActor)
	req.Header.Set(headerGroups, groups)
	rec := httptest.NewRecorder()
	h.chain.ServeHTTP(rec, req)
	return rec
}

func cloneValues(v url.Values) url.Values {
	out := make(url.Values, len(v))
	for k, vals := range v {
		out[k] = append([]string(nil), vals...)
	}
	return out
}

func (h *hsConfigHarness) get() *httptest.ResponseRecorder {
	h.t.Helper()
	return h.request(http.MethodGet, "/headscale/config", nil, "devops", false)
}

func (h *hsConfigHarness) post(target string, form url.Values) *httptest.ResponseRecorder {
	h.t.Helper()
	return h.request(http.MethodPost, target, form, "devops", true)
}

const (
	hsPreviewPath = "/headscale/config/preview"
	hsApplyPath   = "/headscale/config/apply"
	hsClosePath   = "/headscale/config/close"
)

func hsGroupsForm(groups ...string) url.Values {
	v := url.Values{}
	for _, g := range groups {
		v.Add("group", g)
	}
	return v
}

// AC1: the page shows only the secret-free status summary (current list, base_rev, last request
// ID/state/phase/time) and never config content or a secret; an unreadable status.json shows the
// reason and offers no patch form.
func TestHSConfigPage_ShowsStatusOnly(t *testing.T) {
	h := newHSConfigHarness(t)
	h.maint.st = maintenance.Status{
		State: maintenance.Off,
		LastHostResult: `{"status":"succeeded","request_id":"` + hsConfigReqID + `","phase":"check",` +
			`"config_changed":true,"health_verified":true,"finished_at":"2026-10-02T09:00:00Z"}`,
	}
	h.host.st = hostpatch.Status{
		Version: 1, RequestID: hsConfigReqID, State: hostpatch.StateSucceeded, Phase: hostpatch.PhaseCheck,
		AllowedGroups: []string{hostpatch.GroupDevops, hostpatch.GroupDeveloper}, BaseRev: hsConfigBaseRev,
	}

	rec := h.get()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"devops", "developer", hsConfigBaseRev, hsConfigReqID, "succeeded", "check", "2026-10-02",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks status summary %q:\n%s", want, body)
		}
	}
	// No raw/masked config content and no secret reaches the page.
	for _, leak := range []string{"client_secret", "server_url", "private_key", "BEGIN", "config.yaml"} {
		if strings.Contains(body, leak) {
			t.Errorf("page leaks %q:\n%s", leak, body)
		}
	}

	// Unreadable status.json: the reason is shown and no patch form is offered.
	h.host.err = errors.New("status.json okunamadı: no such file")
	rec = h.get()
	if rec.Code != http.StatusOK {
		t.Fatalf("unreadable status: status = %d", rec.Code)
	}
	body = rec.Body.String()
	if !strings.Contains(body, "okunamadı") {
		t.Errorf("unreadable status does not show the reason:\n%s", body)
	}
	if strings.Contains(body, `action="/headscale/config/preview"`) || strings.Contains(body, `action="/headscale/config/apply"`) {
		t.Errorf("unreadable status still offers the patch form:\n%s", body)
	}
}

// AC2: a preview shows the old/new difference and the restart warning, refuses a list without
// devops, and writes nothing.
func TestHSConfigPage_PreviewDiff(t *testing.T) {
	h := newHSConfigHarness(t)
	h.svc.preview = hostapply.Preview{
		Current: []string{hostpatch.GroupDevops, hostpatch.GroupDeveloper},
		Wanted:  []string{hostpatch.GroupDevops, hostpatch.GroupStandart},
		Added:   []string{hostpatch.GroupStandart},
		Removed: []string{hostpatch.GroupDeveloper},
		BaseRev: hsConfigBaseRev,
	}

	rec := h.post(hsPreviewPath, hsGroupsForm(hostpatch.GroupDevops, hostpatch.GroupStandart))
	if rec.Code != http.StatusOK {
		t.Fatalf("preview status = %d: %s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"standart", "developer", "restart", "~120", "mevcut oturumlar", "yeni girişler",
		hsConfigBaseRev, `action="/headscale/config/apply"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("preview lacks %q:\n%s", want, body)
		}
	}
	if _, _, closes := h.svc.calls(); closes != 0 {
		t.Errorf("preview called close %d times", closes)
	}

	// A list without devops is refused by the shared rules, before the service is asked.
	rec = h.post(hsPreviewPath, hsGroupsForm(hostpatch.GroupDeveloper, hostpatch.GroupStandart))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("devops-less preview = %d, want 400:\n%s", rec.Code, rec.Body)
	}
	if previews, _, _ := h.svc.calls(); previews != 1 {
		t.Errorf("devops-less preview reached the service (%d previews)", previews)
	}
}

// AC3: a confirmed apply with CSRF and base_rev goes through the service and redirects to the
// status page; an unconfirmed or stale request is refused and nothing is applied.
func TestHSConfigPage_ApplyConfirmed(t *testing.T) {
	h := newHSConfigHarness(t)
	h.svc.applyRes = hostapply.ApplyResult{RequestID: hsConfigReqID}

	rec := h.post(hsApplyPath, url.Values{
		"group":    {hostpatch.GroupDevops, hostpatch.GroupDeveloper},
		"base_rev": {hsConfigBaseRev},
		"confirm":  {"1"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("apply = %d, want 303:\n%s", rec.Code, rec.Body)
	}
	if loc := rec.Header().Get("Location"); loc != "/headscale/config" {
		t.Errorf("Location = %q, want /headscale/config", loc)
	}
	if h.svc.applyArgs[0].BaseRev != hsConfigBaseRev || h.svc.applyArgs[0].Actor != hsConfigActor {
		t.Errorf("apply args = %+v", h.svc.applyArgs[0])
	}

	// Unconfirmed: refused, the service is not asked again.
	rec = h.post(hsApplyPath, url.Values{
		"group": {hostpatch.GroupDevops}, "base_rev": {hsConfigBaseRev},
	})
	if rec.Code < 400 {
		t.Errorf("unconfirmed apply = %d, want a refusal", rec.Code)
	}
	if len(h.svc.applyArgs) != 1 {
		t.Errorf("unconfirmed apply reached the service (%d calls)", len(h.svc.applyArgs))
	}

	// Stale base_rev: the service refuses; the page shows it and does not redirect.
	h.svc.applyErr = hostapply.ErrStale
	rec = h.post(hsApplyPath, url.Values{
		"group": {hostpatch.GroupDevops}, "base_rev": {"deadbeef"}, "confirm": {"1"},
	})
	if rec.Code != http.StatusConflict {
		t.Errorf("stale apply = %d, want 409:\n%s", rec.Code, rec.Body)
	}
}

// AC3/LOW: when ErrUnknownOutcome blocks opening the maintenance, the refusal keeps and lists the
// unresolved outcomes the service named, so the operator sees what is in the way.
func TestHSConfigPage_UnknownOutcomeListsUnknowns(t *testing.T) {
	h := newHSConfigHarness(t)
	h.svc.applyRes = hostapply.ApplyResult{Unknowns: []hostapply.Unknown{
		{Kind: "policy", Detail: "son policy yazımı belirsiz"},
		{Kind: "key_revoke_failed", Detail: "key iptali doğrulanamadı"},
	}}
	h.svc.applyErr = hostapply.ErrUnknownOutcome

	rec := h.post(hsApplyPath, url.Values{
		"group":    {hostpatch.GroupDevops, hostpatch.GroupDeveloper},
		"base_rev": {hsConfigBaseRev},
		"confirm":  {"1"},
	})
	if rec.Code != http.StatusConflict {
		t.Fatalf("apply with unknowns = %d, want 409:\n%s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	for _, want := range []string{"policy", "son policy yazımı belirsiz", "key_revoke_failed", "key iptali doğrulanamadı"} {
		if !strings.Contains(body, want) {
			t.Errorf("refusal does not list unknown %q:\n%s", want, body)
		}
	}
}

// AC4: while the maintenance is open every Headscale tab shows the band with the state, the time
// since it began and the request ID.
func TestHeadscaleTabs_MaintenanceBanner(t *testing.T) {
	h := newHSConfigHarness(t)
	h.maint.st = maintenance.Status{
		State: maintenance.Active, RequestID: hsConfigReqID,
		StartedAt: time.Now().Add(-3 * time.Minute), Elapsed: 3*time.Minute + 12*time.Second,
	}

	body := h.get().Body.String()
	for _, want := range []string{"bakım sürüyor", "active", "3 dk", hsConfigReqID, "Genişleten"} {
		if !strings.Contains(body, want) {
			t.Errorf("config page band lacks %q:\n%s", want, body)
		}
	}

	// The band lives in HeadscaleTabs, so every tab carries it. Render the component directly with
	// a source bound to the context (as WithMaintenanceBanner does).
	page := renderWithBanner(t, h.maint, HeadscaleTabs("devices", false))
	for _, want := range []string{"bakım sürüyor", hsConfigReqID} {
		if !strings.Contains(page, want) {
			t.Errorf("tab band lacks %q:\n%s", want, page)
		}
	}

	// Off: no band.
	h.maint.st = maintenance.Status{State: maintenance.Off}
	if page := renderWithBanner(t, h.maint, HeadscaleTabs("devices", false)); strings.Contains(page, "bakım sürüyor") {
		t.Errorf("off maintenance shows a band:\n%s", page)
	}

	// An unreadable row never reads as "no maintenance": the band warns (fail safe).
	h.maint.err = errors.New("db down")
	page = renderWithBanner(t, h.maint, HeadscaleTabs("devices", false))
	if !strings.Contains(page, "bakım durumu okunamadı") || !strings.Contains(page, "durduruldu") {
		t.Errorf("unreadable maintenance does not warn:\n%s", page)
	}
}

func renderWithBanner(t *testing.T, src MaintenanceBannerSource, c templ.Component) string {
	t.Helper()
	ctx := context.WithValue(context.Background(), maintenanceBannerKey{}, src)
	var b bytes.Buffer
	if err := c.Render(ctx, &b); err != nil {
		t.Fatalf("render component: %v", err)
	}
	return b.String()
}

// AC5: a failed or interrupted last result is never shown as success or as "the last good state";
// when config_changed is unknown the page says so and offers a new patch and closing the
// maintenance.
func TestHSConfigPage_FailureShowsNextSteps(t *testing.T) {
	for _, status := range []string{"failed", "interrupted"} {
		t.Run(status, func(t *testing.T) {
			h := newHSConfigHarness(t)
			h.maint.st = maintenance.Status{
				State: maintenance.Active, RequestID: hsConfigReqID,
				LastHostResult: `{"status":"` + status + `","request_id":"` + hsConfigReqID + `",` +
					`"error_code":"configtest_failed","config_changed":null,"finished_at":"2026-10-02T09:00:00Z"}`,
			}
			h.host.st = hostpatch.Status{
				Version: 1, RequestID: hsConfigReqID, State: hostpatch.State(status),
				AllowedGroups: []string{hostpatch.GroupDevops}, BaseRev: hsConfigBaseRev,
			}

			body := h.get().Body.String()
			if strings.Contains(body, "son iyi durum") || strings.Contains(body, "başarılı") {
				t.Errorf("failure shown as success:\n%s", body)
			}
			for _, want := range []string{"bilinmiyor", "yeni patch", "bakımı kapat"} {
				if !strings.Contains(body, want) {
					t.Errorf("failure page lacks %q:\n%s", want, body)
				}
			}
		})
	}
}

// AC6: "close the maintenance" shows the host state, warns while it is still applying, and calls
// the F3b-019 service with the seen request ID and an explicit confirmation.
func TestHSConfigPage_CloseMaintenance(t *testing.T) {
	h := newHSConfigHarness(t)
	h.maint.st = maintenance.Status{
		State: maintenance.Active, RequestID: hsConfigReqID,
		LastHostResult: `{"status":"failed","request_id":"` + hsConfigReqID + `"}`,
	}
	h.svc.closeRes = hostapply.CloseResult{
		HostRequestID: hsConfigReqID, HostState: hostpatch.StateApplying, HostPhase: hostpatch.PhaseReplace,
		Warning: "host işlemi hâlâ sürüyor (applying); config yarım kalmış olabilir",
	}

	rec := h.post(hsClosePath, url.Values{"request_id": {hsConfigReqID}, "confirm": {"1"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("close = %d:\n%s", rec.Code, rec.Body)
	}
	if len(h.svc.closeArgs) != 1 {
		t.Fatalf("close calls = %d, want 1", len(h.svc.closeArgs))
	}
	got := h.svc.closeArgs[0]
	if got.RequestID != hsConfigReqID || !got.Confirm || got.Actor != hsConfigActor {
		t.Errorf("close args = %+v", got)
	}
	body := rec.Body.String()
	for _, want := range []string{"applying", "sürüyor"} {
		if !strings.Contains(body, want) {
			t.Errorf("close result lacks %q:\n%s", want, body)
		}
	}

	// Without confirmation the request is refused.
	h.svc.closeArgs = nil
	if rec := h.post(hsClosePath, url.Values{"request_id": {hsConfigReqID}}); rec.Code < 400 {
		t.Errorf("unconfirmed close = %d, want a refusal", rec.Code)
	}
	// A stale request ID is refused.
	h.svc.closeErr = hostapply.ErrStaleRequestID
	if rec := h.post(hsClosePath, url.Values{"request_id": {"bogus"}, "confirm": {"1"}}); rec.Code != http.StatusConflict {
		t.Errorf("stale close = %d, want 409", rec.Code)
	}
}

// AC7: while the write switch is off the page is read-only, keeps the groups-claim matrix note and
// refuses the patch POSTs; closing the maintenance (the way out) still works.
func TestHSConfigPage_WriteSwitchOff(t *testing.T) {
	h := newHSConfigHarness(t)
	h.switchr.v = "" // no row: off
	h.maint.st = maintenance.Status{State: maintenance.Active, RequestID: hsConfigReqID}

	body := h.get().Body.String()
	if !strings.Contains(body, "Lab groups-claim kabul/ret matrisi") || !strings.Contains(body, "read-only") {
		t.Errorf("read-only page lacks the matrix note:\n%s", body)
	}
	if strings.Contains(body, `action="/headscale/config/preview"`) || strings.Contains(body, `action="/headscale/config/apply"`) {
		t.Errorf("read-only page still offers the patch form:\n%s", body)
	}

	for _, target := range []string{hsPreviewPath, hsApplyPath} {
		rec := h.post(target, url.Values{"group": {hostpatch.GroupDevops}, "base_rev": {hsConfigBaseRev}, "confirm": {"1"}})
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s with the switch off = %d, want 403", target, rec.Code)
		}
	}
	if previews, applies, _ := h.svc.calls(); previews != 0 || applies != 0 {
		t.Errorf("switch off reached the service: previews %d applies %d", previews, applies)
	}

	// The exit path is not gated by the write switch.
	h.svc.closeRes = hostapply.CloseResult{HostState: hostpatch.StateFailed}
	if rec := h.post(hsClosePath, url.Values{"request_id": {hsConfigReqID}, "confirm": {"1"}}); rec.Code != http.StatusOK {
		t.Errorf("close with the switch off = %d, want 200:\n%s", rec.Code, rec.Body)
	}
}

// AC8: when the last maintenance was closed by a dry-run reconcile the page and the band say the
// dry run applied no difference.
func TestHSConfigPage_DryRunNote(t *testing.T) {
	h := newHSConfigHarness(t)
	h.dry.on = true
	h.maint.st = maintenance.Status{State: maintenance.Off, CloseNote: "dry_run_skipped"}

	body := h.get().Body.String()
	if !strings.Contains(body, dryRunSkippedNote) {
		t.Errorf("page lacks the dry-run close note %q:\n%s", dryRunSkippedNote, body)
	}
	// The band keeps the note visible too.
	if page := renderWithBanner(t, h.maint, HeadscaleTabs("devices", false)); !strings.Contains(page, dryRunSkippedNote) {
		t.Errorf("band lacks the dry-run close note:\n%s", page)
	}
}

// AC9: only devops reaches the page or its POSTs.
func TestHSConfigPage_DevopsOnly(t *testing.T) {
	h := newHSConfigHarness(t)

	if rec := h.request(http.MethodGet, "/headscale/config", nil, "developer", false); rec.Code != http.StatusForbidden {
		t.Errorf("GET as non-devops = %d, want 403", rec.Code)
	}
	for _, target := range []string{hsPreviewPath, hsApplyPath, hsClosePath} {
		rec := h.request(http.MethodPost, target, url.Values{"group": {hostpatch.GroupDevops}, "confirm": {"1"}}, "developer", true)
		if rec.Code != http.StatusForbidden {
			t.Errorf("POST %s as non-devops = %d, want 403", target, rec.Code)
		}
	}
	if previews, applies, closes := h.svc.calls(); previews != 0 || applies != 0 || closes != 0 {
		t.Errorf("non-devops reached the service: %d/%d/%d", previews, applies, closes)
	}
}
