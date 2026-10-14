package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/sync"
)

// fakeOverview returns a fixed snapshot.
type fakeOverview struct {
	ov  SyncOverview
	err error
}

func (f fakeOverview) Overview(context.Context) (SyncOverview, error) { return f.ov, f.err }

// fakeApprover records approvals.
type fakeApprover struct {
	calls []approveCall
	res   SyncApproval
	err   error
}

type approveCall struct {
	actor   string
	id      int64
	version string
}

func (f *fakeApprover) Approve(_ context.Context, actor string, id int64, version string) (SyncApproval, error) {
	f.calls = append(f.calls, approveCall{actor: actor, id: id, version: version})
	return f.res, f.err
}

// fakeRejecter records rejections.
type fakeRejecter struct {
	ids []int64
	err error
}

func (f *fakeRejecter) Reject(_ context.Context, id int64) error {
	f.ids = append(f.ids, id)
	return f.err
}

// fakeDryRun records dry-run changes.
type fakeDryRun struct {
	ons []bool
	err error
}

func (f *fakeDryRun) SetDryRun(_ context.Context, on bool) error {
	f.ons = append(f.ons, on)
	return f.err
}

// fakeInterval records stored intervals.
type fakeInterval struct {
	minutes []int
	err     error
}

func (f *fakeInterval) SetInterval(_ context.Context, minutes int) error {
	f.minutes = append(f.minutes, minutes)
	return f.err
}

// fakeTrigger counts manual triggers.
type fakeTrigger struct{ n int }

func (f *fakeTrigger) RequestManual() { f.n++ }

// fakeAuditor captures audit entries.
type fakeAuditor struct{ events []audit.Entry }

func (f *fakeAuditor) Write(_ context.Context, e audit.Entry) (audit.Event, error) {
	f.events = append(f.events, e)
	return audit.Event{}, nil
}

// syncHarness wires the sync handler behind the production identity + CSRF chain with fake
// dependencies, so the tests exercise the same trust boundary as main.go.
type syncHarness struct {
	overview *fakeOverview
	approver *fakeApprover
	rejecter *fakeRejecter
	dryRun   *fakeDryRun
	interval *fakeInterval
	trigger  *fakeTrigger
	auditor  *fakeAuditor
	csrf     *CSRF
	chain    http.Handler
}

func newSyncHarness(t *testing.T, ov SyncOverview) *syncHarness {
	t.Helper()
	h := &syncHarness{
		overview: &fakeOverview{ov: ov},
		approver: &fakeApprover{res: SyncApproval{ChangeID: 7, Status: "applied", Applied: true}},
		rejecter: &fakeRejecter{},
		dryRun:   &fakeDryRun{},
		interval: &fakeInterval{},
		trigger:  &fakeTrigger{},
		auditor:  &fakeAuditor{},
		csrf:     testCSRF(t),
	}
	handler, err := NewSyncHandler(SyncHandlerConfig{
		Overview: h.overview,
		Approver: h.approver,
		Rejecter: h.rejecter,
		DryRun:   h.dryRun,
		Interval: h.interval,
		Trigger:  h.trigger,
		Auditor:  h.auditor,
		CSRF:     h.csrf,
	})
	if err != nil {
		t.Fatalf("NewSyncHandler: %v", err)
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	h.chain = RequireDevops(h.csrf.Protect(mux))
	return h
}

// get issues an authenticated GET.
func (h *syncHarness) get(t *testing.T, target string) *httptest.ResponseRecorder {
	t.Helper()
	return h.do(t, http.MethodGet, target, nil)
}

// post issues an authenticated POST with a valid CSRF token in the form.
func (h *syncHarness) post(t *testing.T, target string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	if form == nil {
		form = url.Values{}
	}
	form.Set(CSRFParam, h.csrf.Token())
	return h.do(t, http.MethodPost, target, form)
}

func (h *syncHarness) do(t *testing.T, method, target string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	req := httptest.NewRequestWithContext(context.Background(), method, target, body)
	req.Header.Set(headerUser, "devops-user")
	req.Header.Set(headerEmail, "devops@example.com")
	req.Header.Set(headerGroups, "devops")
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	rec := httptest.NewRecorder()
	h.chain.ServeHTTP(rec, req)
	return rec
}

// auditEvent finds the audit entry with the given event name.
func (h *syncHarness) auditEvent(event string) (audit.Entry, bool) {
	for _, e := range h.auditor.events {
		if e.Event == event {
			return e, true
		}
	}
	return audit.Entry{}, false
}

// AC1: the page shows the last run's time, trigger and result plus the current Zitadel-Headscale
// diff (missing/extra members and unmatched users).
func TestSyncPage_ShowsStatusAndDiff(t *testing.T) {
	h := newSyncHarness(t, SyncOverview{
		LastRun: &SyncRunView{
			At:      time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC),
			Trigger: sync.TriggerWebhook,
			Result:  "applied",
			Summary: "2 üye eklendi, 1 çıkarıldı",
		},
		DryRun:      true,
		IntervalMin: 5,
		Plan: sync.Plan{
			GroupDiff: sync.GroupDiff{Groups: []sync.GroupChange{{
				Group:   "group:ops",
				Added:   []string{"https://auth.example.com/1001@"},
				Removed: []string{"https://auth.example.com/1002@"},
			}}},
			Warnings: []string{"node 5: Headscale kullanıcısı 9 Zitadel kullanıcısıyla eşleşmiyor, expire edilmedi"},
		},
	})

	rec := h.get(t, "/sync")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"2026-09-30 10:00:00", sync.TriggerWebhook, "applied", "2 üye eklendi, 1 çıkarıldı",
		"group:ops", "https://auth.example.com/1001@", "https://auth.example.com/1002@",
		"eşleşmiyor",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page does not contain %q", want)
		}
	}
}

// AC2: approving a pending plan runs the recalculation flow and writes the approval to the audit log.
func TestSyncPage_Approve(t *testing.T) {
	h := newSyncHarness(t, SyncOverview{Pending: []SyncPendingView{{ID: 7, Actor: "system:sync"}}})

	rec := h.post(t, "/sync/approve", url.Values{"change_id": {"7"}, "proposal_version": {"v7"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
	if len(h.approver.calls) != 1 || h.approver.calls[0].id != 7 {
		t.Fatalf("approver calls = %+v, want one call for change 7", h.approver.calls)
	}
	if got := h.approver.calls[0].actor; got != "devops@example.com" {
		t.Errorf("approver actor = %q, want the signed-in user", got)
	}
	if got := h.approver.calls[0].version; got != "v7" {
		t.Errorf("approver version = %q, want the version from the form", got)
	}
	entry, ok := h.auditEvent("sync.approve")
	if !ok {
		t.Fatal("approval was not audited")
	}
	if entry.Actor != "devops@example.com" || entry.Target != "change:7" {
		t.Errorf("audit = %+v, want actor devops@example.com target change:7", entry)
	}
}

// An approval without the displayed proposal version is refused before anything changes: the form is
// stale or forged, so the pipeline must not be asked to apply (Y-03.4).
func TestSyncPage_ApproveRequiresVersion(t *testing.T) {
	h := newSyncHarness(t, SyncOverview{Pending: []SyncPendingView{{ID: 7, Actor: "system:sync"}}})

	rec := h.post(t, "/sync/approve", url.Values{"change_id": {"7"}})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if len(h.approver.calls) != 0 {
		t.Fatalf("a versionless approval reached the approver: %+v", h.approver.calls)
	}
}

// A stale form whose proposal was replaced is refused with a clear conflict and applies nothing.
func TestSyncPage_ApproveStaleProposal(t *testing.T) {
	h := newSyncHarness(t, SyncOverview{Pending: []SyncPendingView{{ID: 7, Actor: "system:sync"}}})
	h.approver.err = ErrApprovalStale

	rec := h.post(t, "/sync/approve", url.Values{"change_id": {"7"}, "proposal_version": {"old"}})
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "teklif değişti") {
		t.Errorf("body = %q, want a clear stale-proposal message", rec.Body.String())
	}
}

// AC3: rejecting a pending plan applies nothing and writes the rejection to the audit log.
func TestSyncPage_Reject(t *testing.T) {
	h := newSyncHarness(t, SyncOverview{Pending: []SyncPendingView{{ID: 8, Actor: "system:sync"}}})

	rec := h.post(t, "/sync/reject", url.Values{"change_id": {"8"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
	if len(h.rejecter.ids) != 1 || h.rejecter.ids[0] != 8 {
		t.Fatalf("rejecter ids = %v, want [8]", h.rejecter.ids)
	}
	if len(h.approver.calls) != 0 {
		t.Error("reject went through the approver")
	}
	if _, ok := h.auditEvent("sync.reject"); !ok {
		t.Error("rejection was not audited")
	}
}

// AC4: switching dry-run asks for confirmation and audits the change; an unconfirmed request is
// refused before anything changes.
func TestSyncPage_DryRunToggleAudited(t *testing.T) {
	h := newSyncHarness(t, SyncOverview{DryRun: true})

	unconfirmed := h.post(t, "/sync/dry-run", url.Values{"dry_run": {"false"}})
	if unconfirmed.Code != http.StatusBadRequest {
		t.Fatalf("unconfirmed status = %d, want 400", unconfirmed.Code)
	}
	if len(h.dryRun.ons) != 0 {
		t.Error("unconfirmed toggle changed the setting")
	}

	rec := h.post(t, "/sync/dry-run", url.Values{"dry_run": {"false"}, "confirm": {"1"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
	if len(h.dryRun.ons) != 1 || h.dryRun.ons[0] {
		t.Fatalf("dry-run calls = %v, want [false]", h.dryRun.ons)
	}
	if _, ok := h.auditEvent("sync.dry_run"); !ok {
		t.Error("dry-run change was not audited")
	}
}

// AC5: the manual trigger button sends a manual signal to the trigger and records who asked.
func TestSyncPage_ManualTrigger(t *testing.T) {
	h := newSyncHarness(t, SyncOverview{})

	rec := h.post(t, "/sync/trigger", nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
	if h.trigger.n != 1 {
		t.Errorf("manual triggers = %d, want 1", h.trigger.n)
	}
	if entry, ok := h.auditEvent("sync.trigger"); !ok || entry.Actor != "devops@example.com" {
		t.Errorf("manual trigger audit = %+v (present=%v), want actor devops@example.com", entry, ok)
	}
}

// AC6: open alerts are shown at the top of the page.
func TestSyncPage_ShowsAlerts(t *testing.T) {
	h := newSyncHarness(t, SyncOverview{
		Alerts: []SyncAlertView{{
			Kind:     sync.AlertReadFailed,
			Source:   sync.SourceZitadel,
			LastSeen: time.Date(2026, 9, 30, 9, 30, 0, 0, time.UTC),
		}},
	})

	body := h.get(t, "/sync").Body.String()
	for _, want := range []string{"Açık uyarılar", sync.AlertReadFailed, sync.SourceZitadel} {
		if !strings.Contains(body, want) {
			t.Errorf("page does not contain %q", want)
		}
	}
}

// AC7: the interval is validated to 1-60 minutes, stored and audited; an out-of-range value is
// refused.
func TestSyncPage_IntervalSetting(t *testing.T) {
	h := newSyncHarness(t, SyncOverview{IntervalMin: 5})

	for _, bad := range []string{"0", "61", "abc", ""} {
		rec := h.post(t, "/sync/interval", url.Values{"minutes": {bad}})
		if rec.Code != http.StatusBadRequest {
			t.Errorf("minutes=%q status = %d, want 400", bad, rec.Code)
		}
	}
	if len(h.interval.minutes) != 0 {
		t.Fatalf("invalid intervals were stored: %v", h.interval.minutes)
	}

	rec := h.post(t, "/sync/interval", url.Values{"minutes": {"30"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
	if len(h.interval.minutes) != 1 || h.interval.minutes[0] != 30 {
		t.Fatalf("interval calls = %v, want [30]", h.interval.minutes)
	}
	if _, ok := h.auditEvent("sync.interval"); !ok {
		t.Error("interval change was not audited")
	}
}

// AC8: a pending G-03 conversion is shown person by person with the unmatched members.
func TestSyncPage_G03Mapping(t *testing.T) {
	h := newSyncHarness(t, SyncOverview{
		Plan: sync.Plan{Identity: &sync.IdentityConversion{
			Mappings: []sync.IdentityMapping{{
				Old:    "alice@example.com",
				New:    "https://auth.example.com/42@",
				UserID: "42",
			}},
			Unmatched: []string{"bob@example.com"},
		}},
	})

	body := h.get(t, "/sync").Body.String()
	for _, want := range []string{"Kimlik dönüşümü", "alice@example.com", "https://auth.example.com/42@", "42", "bob@example.com"} {
		if !strings.Contains(body, want) {
			t.Errorf("page does not contain %q", want)
		}
	}
}

// Every pending change is reachable, not just the newest: a proposal that a later reconcile
// superseded must still be approvable or rejectable from the page.
func TestSyncPage_ShowsAllPending(t *testing.T) {
	h := newSyncHarness(t, SyncOverview{Pending: []SyncPendingView{
		{ID: 11, Actor: "system:sync", Summary: "eski teklif", Version: "v11"},
		{ID: 12, Actor: "system:sync", Summary: "yeni teklif", Version: "v12"},
	}})

	body := h.get(t, "/sync").Body.String()
	for _, want := range []string{"#11", "#12", "eski teklif", "yeni teklif", "v11", "v12"} {
		if !strings.Contains(body, want) {
			t.Errorf("page does not contain %q", want)
		}
	}
	if !strings.Contains(body, `name="proposal_version"`) {
		t.Error("the approval form does not bind the proposal version")
	}
}

// An action without a usable actor is refused: an audit entry must name who acted, so an unnamed
// request must not change anything (A-01.1, security.md §9).
func TestSyncPage_ActionRequiresActor(t *testing.T) {
	h := newSyncHarness(t, SyncOverview{Pending: []SyncPendingView{{ID: 7}}})

	form := url.Values{"change_id": {"7"}}
	form.Set(CSRFParam, h.csrf.Token())
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/sync/approve",
		strings.NewReader(form.Encode()))
	req.Header.Set(headerGroups, "devops") // group present, but no user/e-mail header
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.chain.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for an actor-less request", rec.Code)
	}
	if len(h.approver.calls) != 0 {
		t.Error("an actor-less request reached the approver")
	}
}

// The state-changing actions are only reachable with a valid CSRF token, and the page only answers
// GET. This is the production trust boundary (NFR-03, T7).
func TestSyncPage_ActionGuards(t *testing.T) {
	h := newSyncHarness(t, SyncOverview{})

	// No CSRF token: the middleware refuses before the handler runs.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/sync/approve",
		strings.NewReader("change_id=7"))
	req.Header.Set(headerUser, "devops-user")
	req.Header.Set(headerGroups, "devops")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.chain.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("POST without CSRF status = %d, want 403", rec.Code)
	}
	if len(h.approver.calls) != 0 {
		t.Error("an unauthenticated request reached the approver")
	}

	// The page itself refuses non-GET (with a valid CSRF token, so the middleware lets it through).
	if got := h.post(t, "/sync", nil); got.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /sync status = %d, want 405", got.Code)
	}
}
