package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/internal/alert"
	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/monitor"
	"github.com/nesiler/tagcess/internal/store"
	"github.com/nesiler/tagcess/internal/store/db"
)

// The alerts screen (F4-026): devops reads the monitor-alert lifecycle, acknowledges a raised alert
// and toggles site monitoring maintenance. The tests drive the real F4-023 service over a real
// SQLite database and the audit log through the production identity + CSRF middleware chain.

// alertsHarness wires the alerts handler with the real alert service, a real database and the
// production middleware. The auditor is a fake so a failing audit can be simulated and the written
// entries inspected.
type alertsHarness struct {
	st      *store.Store
	svc     *alert.Service
	auditor *fakeSiteAuditor
	csrf    *CSRF
	chain   http.Handler
}

func newAlertsHarness(t *testing.T) *alertsHarness {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "tagcess.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	settings := monitor.NewSettingsStore(st.DB(), st.Queries())
	svc := alert.New(alert.NewStore(st.DB(), st.Queries()), settings)

	h := &alertsHarness{st: st, svc: svc, auditor: &fakeSiteAuditor{}, csrf: testCSRF(t)}
	handler, err := NewAlertsHandler(AlertsHandlerConfig{Alerts: svc, Auditor: h.auditor, CSRF: h.csrf})
	if err != nil {
		t.Fatalf("NewAlertsHandler: %v", err)
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	h.chain = RequireDevops(h.csrf.Protect(mux))
	return h
}

// raise seeds a raised (active) target-health alert with the configured hysteresis.
func (h *alertsHarness) raise(t *testing.T, subject, source string) alert.Alert {
	t.Helper()
	var got alert.Alert
	for i := 1; i <= 3; i++ {
		a, err := h.svc.RecordHealth(context.Background(), alert.HealthSample{
			Subject: subject, Source: source,
			SampleID: fmt.Sprintf("%s/%s/f%d", subject, source, i),
			Success:  false, Evidence: "HTTP 503",
		})
		if err != nil {
			t.Fatalf("RecordHealth %s: %v", subject, err)
		}
		got = a
	}
	return got
}

// resolve feeds the two consecutive successes that close a health alert.
func (h *alertsHarness) resolve(t *testing.T, subject, source string) alert.Alert {
	t.Helper()
	var got alert.Alert
	for i := 1; i <= 2; i++ {
		a, err := h.svc.RecordHealth(context.Background(), alert.HealthSample{
			Subject: subject, Source: source,
			SampleID: fmt.Sprintf("%s/%s/ok%d", subject, source, i),
			Success:  true,
		})
		if err != nil {
			t.Fatalf("RecordHealth ok %s: %v", subject, err)
		}
		got = a
	}
	return got
}

// request drives the full production chain with explicit headers.
func (h *alertsHarness) request(t *testing.T, method, target string, form url.Values, headers map[string]string) *httptest.ResponseRecorder {
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

// devopsHeaders is the trusted identity the proxy sets for a devops operator.
func devopsHeaders() map[string]string {
	return map[string]string{
		headerUser:   "devops-user",
		headerEmail:  "devops@example.com",
		headerGroups: "devops",
	}
}

// get reads a page as devops.
func (h *alertsHarness) get(t *testing.T, target string) *httptest.ResponseRecorder {
	t.Helper()
	return h.request(t, http.MethodGet, target, nil, devopsHeaders())
}

// post submits a state-changing form as devops with a valid CSRF token.
func (h *alertsHarness) post(t *testing.T, target string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	if form == nil {
		form = url.Values{}
	}
	form.Set(CSRFParam, h.csrf.Token())
	return h.request(t, http.MethodPost, target, form, devopsHeaders())
}

// settingsRows returns the settings key/value pairs so a test can prove maintenance wrote only its
// own key and never an access/write gate.
func (h *alertsHarness) settingsRows(t *testing.T) map[string]string {
	t.Helper()
	rows, err := h.st.DB().QueryContext(context.Background(), `SELECT key, value FROM settings ORDER BY key`)
	if err != nil {
		t.Fatalf("settings query: %v", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			t.Fatalf("settings scan: %v", err)
		}
		out[k] = v
	}
	return out
}

// headscaleMaintenanceCount returns the H-07 maintenance row count: monitoring maintenance must not
// touch it.
func (h *alertsHarness) headscaleMaintenanceCount(t *testing.T) int {
	t.Helper()
	var n int
	if err := h.st.DB().QueryRowContext(context.Background(), `SELECT COUNT(*) FROM headscale_maintenance`).Scan(&n); err != nil {
		t.Fatalf("headscale_maintenance count: %v", err)
	}
	return n
}

// auditField reports whether any written audit entry carries a diff field with the given name.
func auditField(events []auditEntryView, event, field string) bool {
	for _, e := range events {
		if e.Event != event {
			continue
		}
		for _, c := range e.Diff {
			if c.Field == field {
				return true
			}
		}
	}
	return false
}

// auditEntryView is a flat view of one audit entry for the assertions below.
type auditEntryView struct {
	Actor  string
	Event  string
	Target string
	Diff   []auditChangeView
	Result string
}

type auditChangeView struct {
	Field string
	After string
}

// auditEvents flattens the fake auditor's entries.
func (h *alertsHarness) auditEvents() []auditEntryView {
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

// AC1: the page shows the active/acknowledged/resolved lifecycle separately with the muted and
// freshness labels and the source/subject/last-seen fields; pending counters and legacy pipeline
// alerts are not listed.
func TestAlertsPageShowsLifecycleAndFreshness(t *testing.T) {
	h := newAlertsHarness(t)
	ctx := context.Background()

	active := h.raise(t, "app.example", "target")

	h.raise(t, "api.example", "target")
	if _, err := h.svc.Acknowledge(ctx, alert.KindTargetHealth, "api.example", "target"); err != nil {
		t.Fatalf("Acknowledge: %v", err)
	}

	h.raise(t, "web.example", "target")
	h.resolve(t, "web.example", "target")

	if err := h.svc.SetMaintenance(ctx, "maint.example", true); err != nil {
		t.Fatalf("SetMaintenance: %v", err)
	}
	h.raise(t, "maint.example", "target")

	h.raise(t, "stale.example", "target")
	if _, err := h.svc.RecordSource(ctx, alert.SourceSample{Subject: "stale.example", Source: "target", SampleID: "src1", Failed: true, Error: "kaynak kesildi"}); err != nil {
		t.Fatalf("RecordSource: %v", err)
	}

	// A pending counter below the opening threshold and a legacy pipeline alert must stay hidden.
	if _, err := h.svc.RecordHealth(ctx, alert.HealthSample{Subject: "pending.example", Source: "target", SampleID: "p1", Success: false}); err != nil {
		t.Fatalf("pending RecordHealth: %v", err)
	}
	if _, err := h.st.Queries().InsertAlert(ctx, db.InsertAlertParams{
		Kind: change.AlertPolicyMismatch, Source: "headscale",
		FirstSeenAt: "2026-10-04T12:00:00.000Z", LastSeenAt: "2026-10-04T12:00:00.000Z",
	}); err != nil {
		t.Fatalf("legacy InsertAlert: %v", err)
	}

	rec := h.get(t, "/alerts")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /alerts = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()

	// All three lifecycle states are shown, each as its own state badge.
	for _, want := range []string{
		`data-state="active"`, `data-state="acknowledged"`, `data-state="resolved"`,
		"aktif", "okundu", "çözüldü",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the alerts page lacks %q:\n%s", want, body)
		}
	}
	// M6 (F5 live findings): the state badge is not followed by its English identifier.
	for _, dup := range []string{`ms-1">resolved</span>`, `ms-1">active</span>`, `ms-1">acknowledged</span>`} {
		if strings.Contains(body, dup) {
			t.Errorf("state shown in two languages (%s)", dup)
		}
	}
	// Source, subject and the last observation time are shown.
	if !strings.Contains(body, "app.example") || !strings.Contains(body, "target") {
		t.Errorf("the alerts page lacks the source/subject fields:\n%s", body)
	}
	if stamp := active.LastSeen.Format("2006-01-02 15:04:05"); !strings.Contains(body, stamp) {
		t.Errorf("the alerts page lacks the last-seen time %q:\n%s", stamp, body)
	}
	// Muted and freshness labels are shown.
	for _, want := range []string{`data-muted="1"`, `data-freshness="fresh"`, `data-freshness="stale"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the alerts page lacks the %q label:\n%s", want, body)
		}
	}
	// Pending and legacy rows are not listed.
	if strings.Contains(body, "pending.example") {
		t.Errorf("a pending counter leaked onto the alerts page:\n%s", body)
	}
	if strings.Contains(body, change.AlertPolicyMismatch) {
		t.Errorf("a legacy pipeline alert leaked onto the alerts page:\n%s", body)
	}
}

// AC2: acknowledging marks acknowledged_at and the verified actor in the audit without resolving the
// alert or touching the measurement.
func TestAlertsPageAcknowledgesWithoutResolving(t *testing.T) {
	h := newAlertsHarness(t)
	raised := h.raise(t, "app.example", "target")

	rec := h.post(t, "/alerts/ack", url.Values{
		"kind":    {alert.KindTargetHealth},
		"subject": {"app.example"},
		"source":  {"target"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /alerts/ack = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}

	got, err := h.svc.Get(context.Background(), alert.KindTargetHealth, "app.example", "target")
	if err != nil {
		t.Fatalf("Get after ack: %v", err)
	}
	if !got.Acknowledged || got.Resolved {
		t.Fatalf("after ack = %+v, want acknowledged and still open", got)
	}
	if got.ResolvedAt.IsZero() == false {
		t.Errorf("ack set resolved_at: %+v", got.ResolvedAt)
	}
	if got.ConsecutiveFailures != raised.ConsecutiveFailures {
		t.Errorf("ack changed the measurement: failures %d, want %d", got.ConsecutiveFailures, raised.ConsecutiveFailures)
	}

	events := h.auditEvents()
	if !auditActor(events, "alert.acknowledge", "devops@example.com") {
		t.Errorf("ack audit does not carry the verified actor: %+v", events)
	}
	if !auditField(events, "alert.acknowledge", "acknowledged_at") {
		t.Errorf("ack audit does not carry acknowledged_at: %+v", events)
	}
	if !strings.Contains(rec.Body.String(), `data-state="acknowledged"`) {
		t.Errorf("the page does not show the acknowledged state:\n%s", rec.Body.String())
	}
}

// AC3: opening or closing site monitoring maintenance persists the preference and audits it, and
// changes neither the measurement nor the H-07 access/write gate.
func TestAlertsPageMaintenanceOnlyMutesMonitoring(t *testing.T) {
	h := newAlertsHarness(t)
	ctx := context.Background()
	raised := h.raise(t, "app.example", "target")

	before := h.settingsRows(t)
	beforeH07 := h.headscaleMaintenanceCount(t)

	rec := h.post(t, "/alerts/maintenance", url.Values{"subject": {"app.example"}, "muted": {"1"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /alerts/maintenance on = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	got, err := h.svc.Get(ctx, alert.KindTargetHealth, "app.example", "target")
	if err != nil {
		t.Fatalf("Get after maintenance: %v", err)
	}
	if !got.Muted {
		t.Errorf("maintenance did not mute the alert: %+v", got)
	}
	if got.ConsecutiveFailures != raised.ConsecutiveFailures || got.Resolved {
		t.Errorf("maintenance changed the measurement: %+v", got)
	}
	after := h.settingsRows(t)
	if after["monitor.maintenance.app.example"] != "1" {
		t.Errorf("maintenance preference = %q, want 1", after["monitor.maintenance.app.example"])
	}
	// Only the maintenance key was added; no access/write gate (S-06, dry-run, ...) changed.
	for k, v := range before {
		if after[k] != v {
			t.Errorf("maintenance changed setting %s: %q -> %q", k, v, after[k])
		}
	}
	if len(after) != len(before)+1 {
		t.Errorf("maintenance wrote extra settings: before %v after %v", before, after)
	}
	if h.headscaleMaintenanceCount(t) != beforeH07 {
		t.Errorf("maintenance touched the H-07 headscale maintenance gate")
	}
	if !auditActor(h.auditEvents(), "alert.maintenance", "devops@example.com") {
		t.Errorf("maintenance was not audited with the verified actor: %+v", h.auditEvents())
	}

	// Turning it off is symmetric.
	rec = h.post(t, "/alerts/maintenance", url.Values{"subject": {"app.example"}, "muted": {"0"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /alerts/maintenance off = %d, want 200", rec.Code)
	}
	got, _ = h.svc.Get(ctx, alert.KindTargetHealth, "app.example", "target")
	if got.Muted {
		t.Errorf("maintenance off left the alert muted: %+v", got)
	}
	if h.settingsRows(t)["monitor.maintenance.app.example"] != "0" {
		t.Errorf("maintenance preference after off != 0")
	}
}

// AC4: only a devops actor with a valid CSRF token may mutate, and the actor comes from the trusted
// request context, never from a form field.
func TestAlertsPageDevopsCSRFAndAuthenticatedActor(t *testing.T) {
	h := newAlertsHarness(t)
	ctx := context.Background()
	h.raise(t, "app.example", "target")

	ackForm := url.Values{
		"kind":    {alert.KindTargetHealth},
		"subject": {"app.example"},
		"source":  {"target"},
	}

	// Not devops: rejected before the handler and nothing is written.
	rec := h.request(t, http.MethodPost, "/alerts/ack", ackForm, map[string]string{headerUser: "outsider", headerEmail: "outsider@example.com"})
	if rec.Code != http.StatusForbidden {
		t.Errorf("non-devops ack = %d, want 403", rec.Code)
	}
	if len(h.auditor.events) != 0 {
		t.Errorf("a rejected request was audited: %+v", h.auditor.events)
	}

	// Devops but an invalid CSRF token: rejected, nothing written.
	bad := url.Values{}
	for k, vs := range ackForm {
		bad[k] = vs
	}
	bad.Set(CSRFParam, "not-a-token")
	rec = h.request(t, http.MethodPost, "/alerts/ack", bad, devopsHeaders())
	if rec.Code != http.StatusForbidden {
		t.Errorf("bad-CSRF ack = %d, want 403", rec.Code)
	}
	if len(h.auditor.events) != 0 {
		t.Errorf("a bad-CSRF request was audited: %+v", h.auditor.events)
	}

	// A spoofed actor form field must not override the trusted context.
	spoofed := url.Values{}
	for k, vs := range ackForm {
		spoofed[k] = vs
	}
	spoofed.Set("actor", "hacker@evil.example")
	rec = h.post(t, "/alerts/ack", spoofed)
	if rec.Code != http.StatusOK {
		t.Fatalf("ack = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	if !auditActor(h.auditEvents(), "alert.acknowledge", "devops@example.com") {
		t.Errorf("the audit actor is not the trusted context actor: %+v", h.auditEvents())
	}
	for _, e := range h.auditEvents() {
		if e.Actor == "hacker@evil.example" {
			t.Errorf("a form actor field reached the audit: %+v", e)
		}
	}
	if got, _ := h.svc.Get(ctx, alert.KindTargetHealth, "app.example", "target"); !got.Acknowledged {
		t.Errorf("the spoofed form did not acknowledge: %+v", got)
	}
}

// AC5: when the audit pre-write fails or the service mutation fails, the mutation is blocked and the
// error is shown.
func TestAlertsPageAuditFailureBlocksMutation(t *testing.T) {
	h := newAlertsHarness(t)
	h.raise(t, "app.example", "target")

	h.auditor.writeErr = errors.New("audit kapalı")

	rec := h.post(t, "/alerts/ack", url.Values{
		"kind":    {alert.KindTargetHealth},
		"subject": {"app.example"},
		"source":  {"target"},
	})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("ack without audit = %d, want 500 (body %q)", rec.Code, rec.Body.String())
	}
	if got, _ := h.svc.Get(context.Background(), alert.KindTargetHealth, "app.example", "target"); got.Acknowledged {
		t.Errorf("an unaudited ack was applied: %+v", got)
	}
	if !strings.Contains(rec.Body.String(), "işlem kaydedilemedi") {
		t.Errorf("the audit failure is not shown: %q", rec.Body.String())
	}

	rec = h.post(t, "/alerts/maintenance", url.Values{"subject": {"app.example"}, "muted": {"1"}})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("maintenance without audit = %d, want 500 (body %q)", rec.Code, rec.Body.String())
	}
	if got := h.settingsRows(t)["monitor.maintenance.app.example"]; got != "" {
		t.Errorf("an unaudited maintenance wrote %q", got)
	}

	// A failing service mutation (no open alert to acknowledge) is also blocked and shown, while the
	// audit records the failed attempt.
	h.auditor.writeErr = nil
	rec = h.post(t, "/alerts/ack", url.Values{
		"kind":    {alert.KindTargetHealth},
		"subject": {"ghost.example"},
		"source":  {"target"},
	})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("failing ack = %d, want 500 (body %q)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "okundu işaretlenemedi") {
		t.Errorf("the service failure is not shown: %q", rec.Body.String())
	}
	if !hasResult(h.auditEvents(), "alert.acknowledge", "failed") {
		t.Errorf("the failed ack was not audited: %+v", h.auditEvents())
	}
}

// AC6: source/subject/evidence text is escaped and the screen offers no e-mail/webhook/push output.
func TestAlertsPageEscapesEvidenceAndDashboardOnly(t *testing.T) {
	h := newAlertsHarness(t)
	const payload = `<script>alert("x")</script>`
	for i := 1; i <= 3; i++ {
		if _, err := h.svc.RecordHealth(context.Background(), alert.HealthSample{
			Subject: "app<x>.example", Source: "target",
			SampleID: fmt.Sprintf("esc/f%d", i),
			Success:  false, Evidence: payload,
		}); err != nil {
			t.Fatalf("RecordHealth: %v", err)
		}
	}

	rec := h.get(t, "/alerts")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /alerts = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, payload) {
		t.Errorf("the raw evidence payload reached the page unescaped:\n%s", body)
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Errorf("the evidence was not HTML-escaped:\n%s", body)
	}
	lower := strings.ToLower(body)
	for _, forbidden := range []string{"mailto:", `action="/webhook`, `action="/email`, `action="/push`, `action="/notify`} {
		if strings.Contains(lower, forbidden) {
			t.Errorf("the page offers an external notification affordance %q:\n%s", forbidden, body)
		}
	}
}

// auditActor reports whether any entry of the named event has the exact actor.
func auditActor(events []auditEntryView, event, actor string) bool {
	for _, e := range events {
		if e.Event == event && e.Actor == actor {
			return true
		}
	}
	return false
}

// hasResult reports whether any entry of the named event carries the result substring.
func hasResult(events []auditEntryView, event, result string) bool {
	for _, e := range events {
		if e.Event == event && strings.Contains(e.Result, result) {
			return true
		}
	}
	return false
}

// A-L2: site maintenance is offered and accepted only for health/TLS alert subjects that exist.
func TestAlertsMaintenanceOnlyForHealthAndTLSSites(t *testing.T) {
	h := newAlertsHarness(t)
	h.raise(t, "app.example", "target")
	if _, err := h.svc.RecordSource(context.Background(), alert.SourceSample{
		Subject: "stale.example", Source: "target", SampleID: "src1", Failed: true, Error: "kaynak kesildi",
	}); err != nil {
		t.Fatalf("RecordSource: %v", err)
	}

	body := h.get(t, "/alerts").Body.String()
	maint := func(subject string) bool {
		re := regexp.MustCompile(`action="/alerts/maintenance"[^>]*><input[^>]*>\s*<input type="hidden" name="subject" value="` + regexp.QuoteMeta(subject) + `">`)
		return re.MatchString(body)
	}
	if !maint("app.example") {
		t.Fatalf("positive control: a health alert does not offer maintenance:\n%s", body)
	}
	if !strings.Contains(body, "stale.example") || maint("stale.example") {
		t.Fatalf("a source-stale row offers site maintenance:\n%s", body)
	}

	for _, subject := range []string{"stale.example", "policy", "unknown.example"} {
		rec := h.post(t, "/alerts/maintenance", url.Values{"subject": {subject}, "muted": {"1"}})
		if rec.Code != http.StatusBadRequest {
			t.Errorf("maintenance for %q = %d, want 400", subject, rec.Code)
		}
		if _, ok := h.settingsRows(t)["monitor.maintenance."+subject]; ok {
			t.Errorf("maintenance for %q wrote a preference", subject)
		}
	}
}

// A-L3: the sites in maintenance stay listed on /alerts after their alerts resolve.
func TestAlertsPageListsSitesInMaintenance(t *testing.T) {
	h := newAlertsHarness(t)
	h.raise(t, "app.example", "target")
	if rec := h.post(t, "/alerts/maintenance", url.Values{"subject": {"app.example"}, "muted": {"1"}}); rec.Code != http.StatusOK {
		t.Fatalf("maintenance on = %d", rec.Code)
	}
	h.resolve(t, "app.example", "target")
	body := h.get(t, "/alerts").Body.String()
	if !strings.Contains(body, `data-maintenance="app.example"`) {
		t.Fatalf("a site in maintenance is not listed once its alert resolved:\n%s", body)
	}
	// Closing the maintenance removes it from the list.
	if rec := h.post(t, "/alerts/maintenance", url.Values{"subject": {"app.example"}, "muted": {"0"}}); rec.Code != http.StatusOK {
		t.Fatalf("maintenance off = %d", rec.Code)
	}
	if strings.Contains(h.get(t, "/alerts").Body.String(), `data-maintenance="app.example"`) {
		t.Fatalf("a closed maintenance is still listed")
	}
}
