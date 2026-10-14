package web

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/site"
	"github.com/nesiler/tagcess/internal/store/db"
)

// Harness of the resync action (F2-021): the sites screen's "kayıtlardan yeniden uygula" button
// goes through preview → version-bound approval → apply, all through the F2-011 site pipeline
// (the same flow as the S-06 key screen, without a stored key).

type siteResyncHarness struct {
	reviewer *fakeSiteReviewer
	auditor  *fakeSiteAuditor
	changes  *fakeChangeReader
	csrf     *CSRF
	chain    http.Handler
}

func newSiteResyncHarness(t *testing.T) *siteResyncHarness {
	t.Helper()
	h := &siteResyncHarness{
		reviewer: &fakeSiteReviewer{},
		auditor:  &fakeSiteAuditor{},
		changes:  &fakeChangeReader{rows: map[int64]db.Change{}},
		csrf:     testCSRF(t),
	}
	handler, err := NewSiteResyncHandler(SiteResyncConfig{
		Reviewer: h.reviewer,
		Changes:  h.changes,
		Lister:   fakeReviewLister{sites: []site.Site{roleSiteStored()}},
		Auditor:  h.auditor,
		CSRF:     h.csrf,
	})
	if err != nil {
		t.Fatalf("NewSiteResyncHandler: %v", err)
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	h.chain = RequireDevops(h.csrf.Protect(mux))
	return h
}

func (h *siteResyncHarness) post(t *testing.T, target string, form url.Values) *httptest.ResponseRecorder {
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

// AC1: the preview plans the resync read-only: it shows the Caddy/DNS/URI diff and the
// version-bound approval, plans as the signed-in operator with the resync operation, and never
// calls Submit.
func TestSiteResync_PreviewReadOnly(t *testing.T) {
	h := newSiteResyncHarness(t)
	plan := change.SitePlan{
		Op:    change.SiteResync,
		Hosts: []string{"git.example.com"},
		Diff:  change.SiteDiff{Caddy: "-respond 403\n+import k8s", DNS: "-git 100.64.0.9\n+git 100.64.0.4"},
	}
	h.reviewer.previewPlans = []change.SitePlan{plan}

	rec := h.post(t, "/sites/resync/preview", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /sites/resync/preview = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "+import k8s") || !strings.Contains(body, "+git 100.64.0.4") {
		t.Errorf("the resync preview lacks the Caddy/DNS diff:\n%s", body)
	}
	if !strings.Contains(body, `action="/sites/resync/approve"`) {
		t.Errorf("the resync preview lacks the approval form:\n%s", body)
	}
	version := SitePlanVersion(plan)
	if !strings.Contains(body, `value="`+version+`"`) {
		t.Errorf("the resync preview does not carry the plan version %s:\n%s", version, body)
	}

	// The plan was made as the signed-in operator with the resync operation.
	if len(h.reviewer.previewCalls) != 1 {
		t.Fatalf("preview calls = %d, want 1", len(h.reviewer.previewCalls))
	}
	call := h.reviewer.previewCalls[0]
	if call.Op != change.SiteResync {
		t.Errorf("preview op = %q, want %q", call.Op, change.SiteResync)
	}
	if call.Actor != "devops@example.com" {
		t.Errorf("preview actor = %q, want the signed-in operator", call.Actor)
	}
	// Read-only: the preview never applies.
	if len(h.reviewer.submitCalls) != 0 {
		t.Errorf("the preview submitted %d changes, want none", len(h.reviewer.submitCalls))
	}
	if !h.auditor.hasEvent("site.resync_preview", "requested") {
		t.Error("the resync preview was not audited")
	}

	// The button lives on the sites screen.
	sitesBody := getSites(t, newSitesHarness(t, fakeSiteLister{sites: []site.Site{roleSiteStored()}}, nil), "/sites")
	if !strings.Contains(sitesBody, `action="/sites/resync/preview"`) {
		t.Errorf("the sites screen lacks the resync button:\n%s", sitesBody)
	}
}

// AC2: the approval applies through the site change pipeline as the signed-in operator, is
// audited before and after, and a stale plan version is refused without applying.
func TestSiteResync_ApproveVersioned(t *testing.T) {
	t.Run("applies the shown plan", func(t *testing.T) {
		h := newSiteResyncHarness(t)
		plan := change.SitePlan{Op: change.SiteResync, Diff: change.SiteDiff{Caddy: "-a\n+b"}}
		h.reviewer.previewPlans = []change.SitePlan{plan}
		h.reviewer.submitResults = []change.SiteResult{
			{Result: change.Result{ChangeID: 5, Status: change.StatusApplied, Applied: true}},
		}

		rec := h.post(t, "/sites/resync/approve", url.Values{"plan_version": {SitePlanVersion(plan)}})
		if rec.Code != http.StatusOK {
			t.Fatalf("POST /sites/resync/approve = %d, want 200 (body %q)", rec.Code, rec.Body.String())
		}
		if len(h.reviewer.submitCalls) != 1 {
			t.Fatalf("submit calls = %d, want 1", len(h.reviewer.submitCalls))
		}
		call := h.reviewer.submitCalls[0]
		if call.Op != change.SiteResync {
			t.Errorf("submit op = %q, want %q", call.Op, change.SiteResync)
		}
		if call.Actor != "devops@example.com" {
			t.Errorf("submit actor = %q, want the signed-in operator", call.Actor)
		}
		if !h.auditor.hasEvent("site.resync", "requested") || !h.auditor.hasEvent("site.resync", "applied") {
			t.Error("the resync approval was not audited before and after")
		}
		if !strings.Contains(rec.Body.String(), "apply edildi") {
			t.Errorf("the result screen does not show the applied outcome:\n%s", rec.Body.String())
		}
	})

	t.Run("refuses a stale version", func(t *testing.T) {
		h := newSiteResyncHarness(t)
		plan := change.SitePlan{Op: change.SiteResync, Diff: change.SiteDiff{Caddy: "-a\n+b"}}
		h.reviewer.previewPlans = []change.SitePlan{plan}

		rec := h.post(t, "/sites/resync/approve", url.Values{"plan_version": {"stale"}})
		if rec.Code != http.StatusConflict {
			t.Fatalf("stale approve = %d, want 409", rec.Code)
		}
		if len(h.reviewer.submitCalls) != 0 {
			t.Error("a stale approval applied the resync")
		}
		if !h.auditor.hasEvent("site.resync", "failed") {
			t.Error("the refused approval was not audited")
		}
	})
}

// AC3: when Caddy (or Zitadel) cannot be read, the preview shows the block without an approval
// and nothing is applied; an apply-time read failure is recorded and the last known good state
// is kept and said so.
func TestSiteResync_BlockedOnReadFailure(t *testing.T) {
	t.Run("preview blocks without approval", func(t *testing.T) {
		h := newSiteResyncHarness(t)
		h.reviewer.previewErrs = []error{fmt.Errorf("Caddyfile okunamadı: %w", change.ErrBlocked)}

		rec := h.post(t, "/sites/resync/preview", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("blocked preview = %d, want 200 (body %q)", rec.Code, rec.Body.String())
		}
		body := rec.Body.String()
		if !strings.Contains(body, "Caddyfile okunamadı") {
			t.Errorf("the blocked preview does not name the reason:\n%s", body)
		}
		if strings.Contains(body, `action="/sites/resync/approve"`) {
			t.Errorf("the blocked preview still offers the approval:\n%s", body)
		}
		if len(h.reviewer.submitCalls) != 0 {
			t.Error("a blocked preview applied the resync")
		}
		if !h.auditor.hasEvent("site.resync_preview", "blocked") {
			t.Error("the blocked preview was not audited")
		}
	})

	t.Run("apply-time read failure keeps the last good state", func(t *testing.T) {
		h := newSiteResyncHarness(t)
		plan := change.SitePlan{Op: change.SiteResync, Diff: change.SiteDiff{Zitadel: "+z\n"}}
		h.reviewer.previewPlans = []change.SitePlan{plan}
		h.reviewer.submitResults = []change.SiteResult{
			{Result: change.Result{ChangeID: 9, Status: change.StatusFailed}},
		}
		h.changes.rows[9] = db.Change{
			ID: 9, Status: change.StatusFailed,
			Error: "zitadel adımı başarısız: Zitadel redirect URI listesi güncellenemedi: read failed",
		}

		rec := h.post(t, "/sites/resync/approve", url.Values{"plan_version": {SitePlanVersion(plan)}})
		if rec.Code != http.StatusOK {
			t.Fatalf("failed approve = %d, want 200 (body %q)", rec.Code, rec.Body.String())
		}
		body := rec.Body.String()
		if !strings.Contains(body, "başarısız") || !strings.Contains(body, "Zitadel redirect URI listesi güncellenemedi") {
			t.Errorf("the result screen does not show the failure and its reason:\n%s", body)
		}
		if !strings.Contains(body, "son iyi durum korundu") {
			t.Errorf("the result screen does not say the last good state is kept:\n%s", body)
		}
		if !h.auditor.hasEvent("site.resync", "failed") {
			t.Error("the failed apply was not audited")
		}
	})
}
