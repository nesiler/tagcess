package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/monitor"
	"github.com/nesiler/tagcess/internal/store"
)

// The monitoring settings screen (F4-029, K-02/P-02/A-01, R3-AC-17): devops reads and edits the F4-024
// typed durations/thresholds and the target check path/expected status codes. The tests drive the real
// settings store over a real SQLite database, the production identity + CSRF middleware and the shared
// fake auditor, so a failing audit and the trusted actor are both exercised.

// monitorSettingsSpy wraps the real F4-024 store: it counts reads (the "next cycle" assertion
// re-reads through the same getter the loops (F4-038) will use) and captures the auditor entries seen
// when the persistent write runs, so the audit-before-write order can be proven.
type monitorSettingsSpy struct {
	*monitor.SettingsStore
	gets       int
	auditor    *fakeSiteAuditor
	auditAtSet *int
}

func (s *monitorSettingsSpy) Get(ctx context.Context) (monitor.Settings, error) {
	s.gets++
	return s.SettingsStore.Get(ctx)
}

func (s *monitorSettingsSpy) Set(ctx context.Context, in monitor.Settings) error {
	n := 0
	if s.auditor != nil {
		n = len(s.auditor.events)
	}
	s.auditAtSet = &n
	return s.SettingsStore.Set(ctx, in)
}

// monitorSettingsHarness wires the settings handler over a real database and the production chain.
type monitorSettingsHarness struct {
	st       *store.Store
	settings *monitorSettingsSpy
	auditor  *fakeSiteAuditor
	csrf     *CSRF
	chain    http.Handler
}

func newMonitorSettingsHarness(t *testing.T) *monitorSettingsHarness {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "tagcess.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	settings := &monitorSettingsSpy{SettingsStore: monitor.NewSettingsStore(st.DB(), st.Queries())}

	h := &monitorSettingsHarness{st: st, auditor: &fakeSiteAuditor{}, csrf: testCSRF(t)}
	settings.auditor = h.auditor
	h.settings = settings
	handler, err := NewMonitorSettingsHandler(MonitorSettingsConfig{Settings: settings, Auditor: h.auditor, CSRF: h.csrf})
	if err != nil {
		t.Fatalf("NewMonitorSettingsHandler: %v", err)
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	h.chain = RequireDevops(h.csrf.Protect(mux))
	return h
}

// request drives the full production chain with explicit headers.
func (h *monitorSettingsHarness) request(t *testing.T, method, target string, form url.Values, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	if form == nil {
		form = url.Values{}
	}
	req := httptest.NewRequestWithContext(context.Background(), method, target, strings.NewReader(form.Encode()))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	rec := httptest.NewRecorder()
	h.chain.ServeHTTP(rec, req)
	return rec
}

func (h *monitorSettingsHarness) get(t *testing.T, target string) *httptest.ResponseRecorder {
	t.Helper()
	return h.request(t, http.MethodGet, target, nil, devopsHeaders())
}

func (h *monitorSettingsHarness) post(t *testing.T, target string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	if form == nil {
		form = url.Values{}
	}
	form.Set(CSRFParam, h.csrf.Token())
	return h.request(t, http.MethodPost, target, form, devopsHeaders())
}

// validMonitorSettingsForm is a complete, valid edit of every field.
func validMonitorSettingsForm() url.Values {
	return url.Values{
		"target_interval":    {"90"},
		"inventory_interval": {"600"},
		"tls_interval":       {"21600"},
		"health_fail":        {"4"},
		"health_ok":          {"2"},
		"tls_info":           {"30"},
		"tls_warn":           {"14"},
		"tls_critical":       {"7"},
		"path":               {"/healthz"},
		"expected_statuses":  {"200, 204"},
		"timeout":            {"4"},
		"concurrency":        {"3"},
	}
}

// assertSetting reports whether the input with the given data-setting carries the expected value.
// It reads the whole input tag, so the attribute order does not matter.
func assertSetting(t *testing.T, body, key, want string) {
	t.Helper()
	tag := regexp.MustCompile(`<input[^>]*data-setting="` + regexp.QuoteMeta(key) + `"[^>]*>`).FindString(body)
	value := regexp.MustCompile(`\bvalue="` + regexp.QuoteMeta(want) + `"`)
	if tag == "" || !value.MatchString(tag) {
		t.Errorf("the page does not show %s = %q (input %q)", key, want, tag)
	}
}

// AC1: the page shows the documented defaults on a fresh database and the stored overrides afterwards.
func TestMonitorUI_DefaultsAndOverrides(t *testing.T) {
	h := newMonitorSettingsHarness(t)

	rec := h.get(t, "/monitor/settings")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /monitor/settings = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []struct{ key, value string }{
		{"monitor.target_interval_seconds", "60"},
		{"monitor.inventory_interval_seconds", "300"},
		{"monitor.tls_interval_seconds", "21600"},
		{"monitor.health_fail_threshold", "3"},
		{"monitor.health_success_threshold", "2"},
		{"monitor.tls_info_days", "30"},
		{"monitor.tls_warn_days", "14"},
		{"monitor.tls_critical_days", "7"},
		{"monitor.check_path", "/"},
		{"monitor.expected_statuses", "200"},
		{"monitor.timeout_seconds", "5"},
		{"monitor.concurrency", "4"},
	} {
		assertSetting(t, body, want.key, want.value)
	}
	if !strings.Contains(body, `data-default="1"`) {
		t.Errorf("a fresh page is not marked as showing the defaults:\n%s", body)
	}

	// A stored override is what the page shows next time.
	override := monitor.DefaultSettings()
	override.TargetInterval = 120 * time.Second
	override.Path = "/health"
	override.ExpectedStatuses = []int{200, 204}
	override.TLSInfoDays, override.TLSWarnDays, override.TLSCriticalDays = 45, 20, 10
	if err := h.settings.Set(context.Background(), override); err != nil {
		t.Fatalf("seed override: %v", err)
	}

	rec = h.get(t, "/monitor/settings")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /monitor/settings after override = %d, want 200", rec.Code)
	}
	body = rec.Body.String()
	for _, want := range []struct{ key, value string }{
		{"monitor.target_interval_seconds", "120"},
		{"monitor.check_path", "/health"},
		{"monitor.expected_statuses", "200, 204"},
		{"monitor.tls_info_days", "45"},
	} {
		assertSetting(t, body, want.key, want.value)
	}
	if !strings.Contains(body, `data-override="1"`) {
		t.Errorf("a page with stored overrides is not marked as such:\n%s", body)
	}
}

// AC2: a valid POST audits the verified actor and writes the persistent setting; the next-cycle getter
// returns the new values without a restart.
func TestMonitoringSettingsSaveAndReload(t *testing.T) {
	h := newMonitorSettingsHarness(t)

	rec := h.post(t, "/monitor/settings", validMonitorSettingsForm())
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /monitor/settings = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}

	got, err := h.settings.Get(context.Background()) // the getter the next measurement cycle reads
	if err != nil {
		t.Fatalf("Get after save: %v", err)
	}
	if got.TargetInterval != 90*time.Second || got.InventoryInterval != 600*time.Second || got.TLSInterval != 21600*time.Second {
		t.Errorf("intervals after save = %v/%v/%v", got.TargetInterval, got.InventoryInterval, got.TLSInterval)
	}
	if got.HealthFailThreshold != 4 || got.HealthOKThreshold != 2 {
		t.Errorf("health thresholds after save = %d/%d", got.HealthFailThreshold, got.HealthOKThreshold)
	}
	if got.TLSInfoDays != 30 || got.TLSWarnDays != 14 || got.TLSCriticalDays != 7 {
		t.Errorf("tls days after save = %d/%d/%d", got.TLSInfoDays, got.TLSWarnDays, got.TLSCriticalDays)
	}
	if got.Path != "/healthz" {
		t.Errorf("path after save = %q, want /healthz", got.Path)
	}
	if len(got.ExpectedStatuses) != 2 || got.ExpectedStatuses[0] != 200 || got.ExpectedStatuses[1] != 204 {
		t.Errorf("expected statuses after save = %v, want [200 204]", got.ExpectedStatuses)
	}
	if got.Timeout != 4*time.Second || got.Concurrency != 3 {
		t.Errorf("timeout/concurrency after save = %v/%d", got.Timeout, got.Concurrency)
	}
	if h.settings.gets == 0 {
		t.Errorf("the handler never read the settings through the getter")
	}

	// The actor audit entry is written before the persistent write (AC2).
	if h.settings.auditAtSet == nil || *h.settings.auditAtSet < 1 {
		t.Errorf("the persistent write ran before the actor audit entry was recorded")
	} else if first := h.auditor.events[0]; first.Event != monitorSettingsEvent || first.Result != "requested" || first.Actor != "devops@example.com" {
		t.Errorf("the entry written before the setting is not the requested actor record: %+v", first)
	}

	if !auditActor(h.auditEvents(), monitorSettingsEvent, "devops@example.com") {
		t.Errorf("the save was not audited with the verified actor: %+v", h.auditEvents())
	}
	if !strings.Contains(rec.Body.String(), "kaydedildi") {
		t.Errorf("the save result is not shown:\n%s", rec.Body.String())
	}
}

// auditEvents flattens the fake auditor's entries for the assertions above.
func (h *monitorSettingsHarness) auditEvents() []auditEntryView {
	out := make([]auditEntryView, 0, len(h.auditor.events))
	for _, e := range h.auditor.events {
		v := auditEntryView{Actor: e.Actor, Event: e.Event, Target: e.Target, Result: e.Result}
		for _, c := range e.Diff {
			v.Diff = append(v.Diff, auditChangeView{Field: c.Field, After: c.After})
		}
		out = append(out, v)
	}
	return out
}

// AC3: an invalid path/code/duration/threshold is refused with a field error and the previous settings
// are kept; an unwritable audit blocks the write.
func TestMonitoringSettingsRejectKeepsPrevious(t *testing.T) {
	h := newMonitorSettingsHarness(t)
	ctx := context.Background()

	base := monitor.DefaultSettings()
	base.TargetInterval = 120 * time.Second
	base.Path = "/health"
	if err := h.settings.Set(ctx, base); err != nil {
		t.Fatalf("seed base: %v", err)
	}

	cases := []struct {
		name  string
		field string
		value string
	}{
		{"path traversal", "path", "/../etc/passwd"},
		{"path scheme", "path", "http://evil.example/"},
		{"relative path", "path", "health"},
		{"bad status", "expected_statuses", "200,999"},
		{"zero duration", "target_interval", "0"},
		{"negative threshold", "health_fail", "-1"},
		{"tls order", "tls_warn", "40"},
		{"bad concurrency", "concurrency", "99"},
		{"interval over 30 days", "target_interval", "2592001"},
		{"seconds overflow", "target_interval", "36028797018964028"},
		{"timeout above the probe limit", "timeout", "10"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			form := validMonitorSettingsForm()
			form.Set(tc.field, tc.value)
			rec := h.post(t, "/monitor/settings", form)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("invalid %s = %d, want 400 (body %q)", tc.field, rec.Code, rec.Body.String())
			}
			// The refused field is marked, not silently dropped.
			marker := tc.field
			if tc.field == "tls_warn" || tc.field == "tls_info" || tc.field == "tls_critical" {
				marker = "tls"
			}
			// A numeric field carries data-error; a text field uses the shared field error (id "<field>-err").
			if !strings.Contains(rec.Body.String(), `data-error="`+marker+`"`) && !strings.Contains(rec.Body.String(), `id="`+marker+`-err"`) {
				t.Errorf("the %s error is not shown as a field error:\n%s", tc.field, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "İzleme ayarları kaydedildi") {
				t.Errorf("a refusal is rendered as a success banner:\n%s", rec.Body.String())
			}
			got, err := h.settings.Get(ctx)
			if err != nil {
				t.Fatalf("Get after refusal: %v", err)
			}
			if !sameMonitorSettings(got, base) {
				t.Errorf("a refused %s changed the stored settings: got %+v", tc.field, got)
			}
		})
	}

	// An audit pre-write failure blocks the change and keeps the previous settings (AC3).
	h.auditor.writeErr = errors.New("audit kapalı")
	rec := h.post(t, "/monitor/settings", validMonitorSettingsForm())
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("save without audit = %d, want 500 (body %q)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "işlem kaydedilemedi") {
		t.Errorf("the audit failure is not shown:\n%s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "İzleme ayarları kaydedildi") || !strings.Contains(rec.Body.String(), `role="alert"`) {
		t.Errorf("the audit failure is not rendered as an error:\n%s", rec.Body.String())
	}
	got, err := h.settings.Get(ctx)
	if err != nil {
		t.Fatalf("Get after audit failure: %v", err)
	}
	if !sameMonitorSettings(got, base) {
		t.Errorf("an unaudited save changed the stored settings: got %+v", got)
	}
}

// sameMonitorSettings compares two settings including the status slice.
func sameMonitorSettings(a, b monitor.Settings) bool {
	if a.Path != b.Path || a.Concurrency != b.Concurrency {
		return false
	}
	if a.TargetInterval != b.TargetInterval || a.InventoryInterval != b.InventoryInterval || a.TLSInterval != b.TLSInterval || a.Timeout != b.Timeout {
		return false
	}
	if a.HealthFailThreshold != b.HealthFailThreshold || a.HealthOKThreshold != b.HealthOKThreshold {
		return false
	}
	if a.TLSInfoDays != b.TLSInfoDays || a.TLSWarnDays != b.TLSWarnDays || a.TLSCriticalDays != b.TLSCriticalDays {
		return false
	}
	if len(a.ExpectedStatuses) != len(b.ExpectedStatuses) {
		return false
	}
	for i := range a.ExpectedStatuses {
		if a.ExpectedStatuses[i] != b.ExpectedStatuses[i] {
			return false
		}
	}
	return true
}

// AC4: a non-devops actor or an invalid CSRF token cannot change the settings or the monitoring
// maintenance, and the audit actor comes only from the trusted identity context.
func TestMonitoringSettingsAuthorization(t *testing.T) {
	h := newMonitorSettingsHarness(t)
	form := validMonitorSettingsForm()

	// Not devops: rejected before the handler and nothing is written or audited. The request carries a
	// valid CSRF token, so only RequireDevops can reject it.
	withToken := url.Values{}
	for k, vs := range form {
		withToken[k] = vs
	}
	withToken.Set(CSRFParam, h.csrf.Token())
	rec := h.request(t, http.MethodPost, "/monitor/settings", withToken, map[string]string{headerUser: "outsider", headerEmail: "outsider@example.com"})
	if rec.Code != http.StatusForbidden {
		t.Errorf("non-devops save = %d, want 403", rec.Code)
	}
	if len(h.auditor.events) != 0 {
		t.Errorf("a rejected save was audited: %+v", h.auditor.events)
	}
	if got, _ := h.settings.Get(context.Background()); !sameMonitorSettings(got, monitor.DefaultSettings()) {
		t.Errorf("a rejected save changed the settings: got %+v", got)
	}

	// Devops with an invalid CSRF token: rejected.
	bad := url.Values{}
	for k, vs := range form {
		bad[k] = vs
	}
	bad.Set(CSRFParam, "not-a-token")
	rec = h.request(t, http.MethodPost, "/monitor/settings", bad, devopsHeaders())
	if rec.Code != http.StatusForbidden {
		t.Errorf("bad-CSRF save = %d, want 403", rec.Code)
	}
	if len(h.auditor.events) != 0 {
		t.Errorf("a bad-CSRF save was audited: %+v", h.auditor.events)
	}

	// A spoofed actor form field must not reach the audit.
	spoofed := url.Values{}
	for k, vs := range form {
		spoofed[k] = vs
	}
	spoofed.Set("actor", "hacker@evil.example")
	rec = h.post(t, "/monitor/settings", spoofed)
	if rec.Code != http.StatusOK {
		t.Fatalf("save = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	if !auditActor(h.auditEvents(), monitorSettingsEvent, "devops@example.com") {
		t.Errorf("the audit actor is not the trusted context actor: %+v", h.auditEvents())
	}
	for _, e := range h.auditEvents() {
		if e.Actor == "hacker@evil.example" {
			t.Errorf("a form actor field reached the audit: %+v", e)
		}
	}

	// The monitoring maintenance action (F4-026) is behind the same devops + CSRF boundary.
	a := newAlertsHarness(t)
	rec = a.request(t, http.MethodPost, "/alerts/maintenance", url.Values{"subject": {"app.example"}, "muted": {"1"}, CSRFParam: {a.csrf.Token()}}, map[string]string{headerUser: "outsider", headerEmail: "outsider@example.com"})
	if rec.Code != http.StatusForbidden {
		t.Errorf("non-devops maintenance = %d, want 403", rec.Code)
	}
	badMaint := url.Values{"subject": {"app.example"}, "muted": {"1"}, CSRFParam: {"not-a-token"}}
	rec = a.request(t, http.MethodPost, "/alerts/maintenance", badMaint, devopsHeaders())
	if rec.Code != http.StatusForbidden {
		t.Errorf("bad-CSRF maintenance = %d, want 403", rec.Code)
	}
	if _, ok := a.settingsRows(t)["monitor.maintenance.app.example"]; ok {
		t.Errorf("a rejected maintenance request wrote a preference")
	}
}

// L-12: corrupt stored settings are fixable from the UI: GET shows the defaults form with an error,
// and a fully validated POST overwrites them with an audit entry whose before is "okunamadı".
func TestMonitoringSettingsCorruptStoredSettingsAreFixable(t *testing.T) {
	h := newMonitorSettingsHarness(t)
	ctx := context.Background()
	if err := h.settings.Set(ctx, monitor.DefaultSettings()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := h.st.DB().ExecContext(ctx,
		`UPDATE settings SET value = 'not-a-duration' WHERE key = 'monitor.target_interval_seconds'`); err != nil {
		t.Fatalf("corrupt: %v", err)
	}

	rec := h.get(t, "/monitor/settings")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET with corrupt settings = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "okunamadı") || !strings.Contains(body, `name="target_interval"`) {
		t.Fatalf("no error plus defaults form on corrupt settings:\n%s", body)
	}
	assertSetting(t, body, "monitor.target_interval_seconds", "60")

	rec = h.post(t, "/monitor/settings", validMonitorSettingsForm())
	if rec.Code != http.StatusOK {
		t.Fatalf("overwrite of corrupt settings = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	got, err := h.settings.Get(ctx)
	if err != nil || got.TargetInterval != 90*time.Second {
		t.Fatalf("settings after overwrite = %+v, %v", got, err)
	}
	var sawUnreadable bool
	for _, e := range h.auditor.events {
		for _, c := range e.Diff {
			if c.Field == "monitor.target_interval_seconds" && c.Before == "okunamadı" {
				sawUnreadable = true
			}
		}
	}
	if !sawUnreadable {
		t.Fatalf("audit does not record before=okunamadı: %+v", h.auditor.events)
	}

	// An invalid overwrite is still refused.
	if _, err := h.st.DB().ExecContext(ctx,
		`UPDATE settings SET value = 'x' WHERE key = 'monitor.target_interval_seconds'`); err != nil {
		t.Fatalf("corrupt again: %v", err)
	}
	bad := validMonitorSettingsForm()
	bad.Set("path", "health")
	if rec := h.post(t, "/monitor/settings", bad); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid overwrite = %d, want 400", rec.Code)
	}
}
