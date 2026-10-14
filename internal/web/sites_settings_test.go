package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/internal/change"
	caddyrender "github.com/nesiler/tagcess/internal/render"
	"github.com/nesiler/tagcess/internal/site"
	"github.com/nesiler/tagcess/internal/store/db"
)

// Fakes and harness of the site settings screen (F2-015): the S-06 key toggle goes through
// preview → approval → apply (the site change pipeline), and the review screen warns when a
// submitted site's certificate cannot be resolved (S-07.1).

// fakeSettingsPreviewer records PreviewSettings calls and returns fixed plans.
type fakeSettingsPreviewer struct {
	previewSettings []change.SiteSettings
	previewPlans    []change.SitePlan
	previewErrs     []error
	previewRuns     int
	reviewer        *fakeSiteReviewer
}

func (f *fakeSettingsPreviewer) PreviewSettings(_ context.Context, settings change.SiteSettings) (change.SitePlan, error) {
	i := f.previewRuns
	f.previewRuns++
	f.previewSettings = append(f.previewSettings, settings)
	if i < len(f.previewErrs) && f.previewErrs[i] != nil {
		return change.SitePlan{}, f.previewErrs[i]
	}
	if i < len(f.previewPlans) {
		return f.previewPlans[i], nil
	}
	if n := len(f.previewPlans); n > 0 {
		return f.previewPlans[n-1], nil
	}
	return change.SitePlan{}, errors.New("web: no settings plan configured")
}

func (f *fakeSettingsPreviewer) Submit(ctx context.Context, req change.SiteRequest) (change.SiteResult, error) {
	return f.reviewer.Submit(ctx, req)
}

// fakeS06Setter records the key writes; errs holds per-call failures (nil entries succeed).
type fakeS06Setter struct {
	calls []bool
	errs  []error
}

func (f *fakeS06Setter) SetS06Open(_ context.Context, on bool) error {
	i := len(f.calls)
	f.calls = append(f.calls, on)
	if i < len(f.errs) {
		return f.errs[i]
	}
	return nil
}

// fakeSettingsDryRun is the dry-run source of the settings approval.
type fakeSettingsDryRun struct{ on bool }

func (f *fakeSettingsDryRun) DryRun(context.Context) (bool, error) { return f.on, nil }

type siteSettingsHarness struct {
	previewer *fakeSettingsPreviewer
	reviewer  *fakeSiteReviewer
	setter    *fakeS06Setter
	dry       *fakeSettingsDryRun
	auditor   *fakeSiteAuditor
	changes   *fakeChangeReader
	csrf      *CSRF
	chain     http.Handler
}

func settingsForHarness() change.SiteSettings {
	return change.SiteSettings{
		Caddy: caddyrender.CaddyConfig{
			ACMEEmail: "admin@example.com",
			S06Open:   true,
			Certs:     []string{"example.com"},
		},
		DNS: caddyrender.DNSConfig{AValue: "100.64.0.4"},
	}
}

func newSiteSettingsHarness(t *testing.T) *siteSettingsHarness {
	t.Helper()
	h := &siteSettingsHarness{
		previewer: &fakeSettingsPreviewer{},
		reviewer:  &fakeSiteReviewer{},
		setter:    &fakeS06Setter{},
		dry:       &fakeSettingsDryRun{},
		auditor:   &fakeSiteAuditor{},
		changes:   &fakeChangeReader{rows: map[int64]db.Change{}},
		csrf:      testCSRF(t),
	}
	h.previewer.reviewer = h.reviewer
	h.reviewer.previewPlans = []change.SitePlan{{Op: change.SiteResync}}
	h.build(t)
	return h
}

func (h *siteSettingsHarness) build(t *testing.T) {
	h.buildWithSettings(t, settingsForHarness())
}

// buildWithSettings rebuilds the handler with an explicit stored settings snapshot.
func (h *siteSettingsHarness) buildWithSettings(t *testing.T, settings change.SiteSettings) {
	handler, err := NewSiteSettingsHandler(SiteSettingsHandlerConfig{
		Previewer: h.previewer,
		Settings:  fakeReviewSettings{settings: settings},
		DryRun:    h.dry,
		Setter:    h.setter,
		Changes:   h.changes,
		Lister:    fakeReviewLister{sites: []site.Site{roleSiteStored()}},
		Auditor:   h.auditor,
		CSRF:      h.csrf,
	})
	if err != nil {
		t.Fatalf("NewSiteSettingsHandler: %v", err)
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	h.chain = RequireDevops(h.csrf.Protect(mux))
}

func (h *siteSettingsHarness) post(t *testing.T, target string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	if form == nil {
		form = url.Values{}
	}
	form.Set(CSRFParam, h.csrf.Token())
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, target, strings.NewReader(form.Encode()))
	req.Header.Set(headerUser, "devops-user")
	req.Header.Set(headerEmail, "devops@example.com")
	req.Header.Set(headerGroups, "devops")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.chain.ServeHTTP(rec, req)
	return rec
}

func (h *siteSettingsHarness) get(t *testing.T, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	req.Header.Set(headerUser, "devops-user")
	req.Header.Set(headerGroups, "devops")
	rec := httptest.NewRecorder()
	h.chain.ServeHTTP(rec, req)
	return rec
}

// AC2: the key change goes through the diff/onay/audit pipeline: the preview shows the plan, the
// approval stores the value and applies the resync, and every step is audited.
func TestSiteSettings_UIChange(t *testing.T) {
	h := newSiteSettingsHarness(t)

	// The settings page shows the current state and the toggle.
	rec := h.get(t, "/sites/settings")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /sites/settings = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	// Item 12: one switch, no chip; it shows the current state and posts the other one.
	if !strings.Contains(body, `role="switch" aria-checked="true"`) || !strings.Contains(body, ">Açık<") ||
		!strings.Contains(body, `name="s06" value="closed"`) || !strings.Contains(body, `action="/sites/s06/preview"`) {
		t.Errorf("the settings page lacks the key state or the toggle: %s", body)
	}
	if strings.Contains(body, "S-06") || strings.Contains(body, "pill") {
		t.Errorf("the settings page shows a project id or a state chip: %s", body)
	}

	// The preview plans the flip and carries the version.
	plan := change.SitePlan{Op: change.SiteResync, Diff: change.SiteDiff{Caddy: "-import k8s\n+respond 403"}}
	h.previewer.previewPlans = []change.SitePlan{plan}
	rec = h.post(t, "/sites/s06/preview", url.Values{"s06": {"closed"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST s06/preview = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	body = rec.Body.String()
	if !strings.Contains(body, "+respond 403") || !strings.Contains(body, `action="/sites/s06/approve"`) {
		t.Errorf("the S-06 review lacks the diff or the approval: %s", body)
	}
	if !h.auditor.hasEvent("site.s06_preview", "requested") {
		t.Error("the S-06 preview was not audited")
	}
	version := SitePlanVersion(plan)
	if !strings.Contains(body, `value="`+version+`"`) {
		t.Errorf("the S-06 review does not carry the plan version %s: %s", version, body)
	}

	// The approval re-plans, stores the value and applies the resync.
	h.reviewer.submitResults = []change.SiteResult{{Result: change.Result{ChangeID: 5, Status: change.StatusApplied, Applied: true}}}
	rec = h.post(t, "/sites/s06/approve", url.Values{"s06": {"closed"}, "plan_version": {version}})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST s06/approve = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	if len(h.setter.calls) != 1 || h.setter.calls[0] {
		t.Errorf("setter calls = %v, want one closed write", h.setter.calls)
	}
	if len(h.reviewer.submitCalls) != 1 || h.reviewer.submitCalls[0].Op != change.SiteResync {
		t.Fatalf("submit calls = %+v", h.reviewer.submitCalls)
	}
	if h.reviewer.submitCalls[0].Actor != "devops@example.com" {
		t.Errorf("actor = %q", h.reviewer.submitCalls[0].Actor)
	}
	if !h.auditor.hasEvent("site.s06", "requested") || !h.auditor.hasEvent("site.s06", "applied") {
		t.Error("the S-06 change was not audited before and after")
	}

	// The preview saw the target key state, not the stored one.
	if len(h.previewer.previewSettings) != 2 {
		t.Fatalf("PreviewSettings runs = %d, want 2", len(h.previewer.previewSettings))
	}
	if got := h.previewer.previewSettings[0].Caddy.S06Open; got {
		t.Error("the preview planned with the stored key instead of the target")
	}
	if got := h.previewer.previewSettings[1].Caddy.S06Open; got {
		t.Error("the approval replanned with the stored key instead of the target")
	}
}

// A stale S-06 approval is refused; nothing is stored and nothing is applied.
func TestSiteSettings_UIChangeStale(t *testing.T) {
	h := newSiteSettingsHarness(t)
	plan := change.SitePlan{Op: change.SiteResync, Diff: change.SiteDiff{Caddy: "-import k8s\n+respond 403"}}
	h.previewer.previewPlans = []change.SitePlan{plan}

	rec := h.post(t, "/sites/s06/approve", url.Values{"s06": {"closed"}, "plan_version": {"stale"}})
	if rec.Code != http.StatusConflict {
		t.Fatalf("stale approve = %d, want 409", rec.Code)
	}
	if len(h.setter.calls) != 0 || len(h.reviewer.submitCalls) != 0 {
		t.Error("a stale approval stored the key or applied the resync")
	}
	if !h.auditor.hasEvent("site.s06", "failed") {
		t.Error("the refused approval was not audited")
	}
}

// An audit write failure blocks the S-06 change before anything is stored.
func TestSiteSettings_AuditFailureBlocks(t *testing.T) {
	h := newSiteSettingsHarness(t)
	h.auditor.writeErr = errors.New("audit unavailable")

	rec := h.post(t, "/sites/s06/preview", url.Values{"s06": {"closed"}})
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("preview without audit = %d, want 500", rec.Code)
	}
	rec = h.post(t, "/sites/s06/approve", url.Values{"s06": {"closed"}, "plan_version": {"x"}})
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("approve without audit = %d, want 500", rec.Code)
	}
	if len(h.setter.calls) != 0 || len(h.reviewer.submitCalls) != 0 {
		t.Error("an unaudited S-06 change was stored or applied")
	}
}

// Dry-run stays honest: the approval records the run and stores nothing.
func TestSiteSettings_DryRunStoresNothing(t *testing.T) {
	h := newSiteSettingsHarness(t)
	plan := change.SitePlan{Op: change.SiteResync, Diff: change.SiteDiff{Caddy: "-a\n+b"}}
	h.previewer.previewPlans = []change.SitePlan{plan}
	h.dry.on = true

	rec := h.post(t, "/sites/s06/approve", url.Values{"s06": {"closed"}, "plan_version": {SitePlanVersion(plan)}})
	if rec.Code != http.StatusOK {
		t.Fatalf("dry-run approve = %d, want 200", rec.Code)
	}
	if len(h.setter.calls) != 0 {
		t.Error("dry-run stored the key")
	}
	if len(h.reviewer.submitCalls) != 0 {
		t.Error("dry-run applied the resync")
	}
	if !strings.Contains(rec.Body.String(), "dry-run") {
		t.Errorf("the dry-run outcome is not shown: %q", rec.Body.String())
	}
}

// A failed (or blocked, or rolled back) apply must not leave the key at the target value: the
// stored key would claim a state the live Caddy never reached — a closed key while the tail is
// still open reads as "access is closed", an open key widens the next unrelated resync. The
// approval restores the previous value under the writer lock and the result page says so.
func TestSiteSettings_FailedApplyRestoresKey(t *testing.T) {
	plan := change.SitePlan{Op: change.SiteResync, Diff: change.SiteDiff{Caddy: "-import k8s\n+respond 403"}}
	tests := []struct {
		name   string
		target string
		stored bool
	}{
		{"failed close restores open", "closed", true},
		{"failed open restores closed", "open", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newSiteSettingsHarness(t)
			settings := settingsForHarness()
			settings.Caddy.S06Open = tt.stored
			h.buildWithSettings(t, settings)
			h.previewer.previewPlans = []change.SitePlan{plan}
			h.reviewer.submitResults = []change.SiteResult{{Result: change.Result{ChangeID: 6, Status: change.StatusFailed}}}
			h.changes.rows[6] = db.Change{ID: 6, Status: change.StatusFailed, Error: "caddy /load reddetti"}

			rec := h.post(t, "/sites/s06/approve", url.Values{"s06": {tt.target}, "plan_version": {SitePlanVersion(plan)}})
			if rec.Code != http.StatusOK {
				t.Fatalf("failed apply approve = %d, want 200 (body %q)", rec.Code, rec.Body.String())
			}
			if len(h.setter.calls) != 2 {
				t.Fatalf("setter calls = %v, want the target write and the restore", h.setter.calls)
			}
			targetOpen := tt.target == "open"
			if h.setter.calls[0] != targetOpen || h.setter.calls[1] != tt.stored {
				t.Errorf("setter calls = %v, want %v then restore to %v", h.setter.calls, targetOpen, tt.stored)
			}
			if !strings.Contains(rec.Body.String(), "eski değerine") {
				t.Errorf("the result page does not say the key was restored:\n%s", rec.Body.String())
			}
			if !h.auditor.hasEvent("site.s06", "restored") {
				t.Error("the restore was not audited")
			}
		})
	}
}

// A restore that itself fails must not hide behind the apply failure: the stored key then
// differs from the live matrix, so the result page names the failure and the audit records it.
func TestSiteSettings_RestoreFailureShown(t *testing.T) {
	h := newSiteSettingsHarness(t)
	plan := change.SitePlan{Op: change.SiteResync, Diff: change.SiteDiff{Caddy: "-import k8s\n+respond 403"}}
	h.previewer.previewPlans = []change.SitePlan{plan}
	h.setter.errs = []error{nil, errors.New("settings db kapalı")}
	h.reviewer.submitResults = []change.SiteResult{{Result: change.Result{ChangeID: 7, Status: change.StatusFailed}}}
	h.changes.rows[7] = db.Change{ID: 7, Status: change.StatusFailed, Error: "caddy /load reddetti"}

	rec := h.post(t, "/sites/s06/approve", url.Values{"s06": {"closed"}, "plan_version": {SitePlanVersion(plan)}})
	if rec.Code != http.StatusOK {
		t.Fatalf("restore-failure approve = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "geri alınamadı") {
		t.Errorf("the result page does not say the restore failed:\n%s", rec.Body.String())
	}
	if !h.auditor.hasEvent("site.s06", "restore_failed") {
		t.Error("the failed restore was not audited")
	}
}

// AC3: the review warns when a submitted site's certificate cannot be resolved, and stays silent
// for covered hosts (an edit of an existing domain).
func TestSiteSettings_CertWarning(t *testing.T) {
	h := newSiteReviewHarness(t)
	h.reviewer.previewPlans = []change.SitePlan{planFor(change.SiteAdd, []string{"newtool.newdomain.example"}, "+new...")}

	uncovered := roleSiteStored()
	uncovered.Hosts = []string{"newtool.newdomain.example"}
	uncovered.Cert = "auto"
	rec := h.post(t, "/sites/review", url.Values{
		"request": {reviewRequestJSON(t, change.SiteRequest{Op: change.SiteAdd, Site: uncovered})},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /sites/review = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Sertifika uyarısı") {
		t.Errorf("the uncovered host produced no certificate warning:\n%s", rec.Body.String())
	}

	// A covered host shows no warning.
	h2 := newSiteReviewHarness(t)
	h2.reviewer.previewPlans = []change.SitePlan{planFor(change.SiteUpdate, []string{"git.example.com"}, "+git...")}
	covered := roleSiteStored()
	covered.Cert = "auto"
	rec = h2.post(t, "/sites/review", url.Values{
		"request": {reviewRequestJSON(t, change.SiteRequest{Op: change.SiteUpdate, ID: 1, Site: covered})},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /sites/review covered = %d, want 200", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "Sertifika uyarısı") {
		t.Errorf("a covered host produced a certificate warning:\n%s", rec.Body.String())
	}
}
