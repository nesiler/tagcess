package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/k8s"
	caddyrender "github.com/nesiler/tagcess/internal/render"
	"github.com/nesiler/tagcess/internal/site"
	"github.com/nesiler/tagcess/internal/store/db"
)

// F4-013: the complete draft is handed to the existing site review pipeline. The pipeline is the
// F2-014 fake reviewer; the harness proves the adapter's mapping, gates and the absence of any
// second apply path.

type draftHandoff struct {
	*k8sDraftHarness
	sites *siteReviewHarness
}

func newDraftHandoff(t *testing.T, d K8sDiscovery) *draftHandoff {
	t.Helper()
	h := &draftHandoff{k8sDraftHarness: newK8sDraftHarness(t, d, nil), sites: newSiteReviewHarness(t)}
	review, err := NewSiteReviewHandler(SiteReviewConfig{
		Reviewer: h.sites.reviewer, Lister: fakeReviewLister{}, URIs: h.sites.drift,
		Settings: fakeReviewSettings{}, Changes: h.sites.changes, Auditor: h.auditor, CSRF: h.csrf,
	})
	if err != nil {
		t.Fatalf("NewSiteReviewHandler: %v", err)
	}
	handler, err := NewK8sDraftHandler(K8sDraftConfig{
		Discovery: h.reader, Drafts: h.drafts, Auditor: h.auditor, CSRF: h.csrf,
		Now: func() time.Time { return draftNow }, Review: review,
	})
	if err != nil {
		t.Fatalf("NewK8sDraftHandler: %v", err)
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	review.Register(mux)
	h.chain = RequireDevops(h.csrf.Protect(mux))
	return h
}

func (h *draftHandoff) completeDraft() {
	h.t.Helper()
	if rec := h.save(url.Values{"access_choice": {"role"}, "roles": {"developer"}}); rec.Code != http.StatusSeeOther {
		h.t.Fatalf("save = %d %s", rec.Code, rec.Body.String())
	}
}

func (h *draftHandoff) review() string {
	return h.do(draftRequest{method: http.MethodPost, target: "/k8s/drafts/" + draftHost + "/review", form: url.Values{}}).Body.String()
}

var (
	reqField = regexp.MustCompile(`name="request" value="([^"]*)"`)
	verField = regexp.MustCompile(`name="plan_version" value="([^"]*)"`)
)

// approveForm reads the carried request and version off the review page, like the browser would.
func approveForm(t *testing.T, body string) url.Values {
	t.Helper()
	r, v := reqField.FindStringSubmatch(body), verField.FindStringSubmatch(body)
	if r == nil || v == nil {
		t.Fatalf("no approval form on the review page: %s", body)
	}
	return url.Values{"request": {htmlUnescape(r[1])}, "plan_version": {htmlUnescape(v[1])}}
}

func readyDiscovery() K8sDiscovery {
	return discoveryOf(12, "pv1", draftObsOld, draftProposal(draftRoute("uid-1", "/", "api")))
}

func draftPlan() change.SitePlan {
	return planFor(change.SiteAdd, []string{draftHost}, "+"+draftHost+" {")
}

func TestIngressDraftPreviewHasNoWrites(t *testing.T) {
	h := newDraftHandoff(t, readyDiscovery())
	h.completeDraft()
	h.sites.reviewer.previewPlans = []change.SitePlan{draftPlan()}
	before := h.applySideCounts()

	body := h.review()
	if !strings.Contains(body, "+"+draftHost+" {") || !strings.Contains(body, "- old") || !strings.Contains(body, "oauth2/callback") {
		t.Errorf("preview lacks the Caddy/DNS/URI diffs: %s", body)
	}
	got := h.sites.reviewer.previewCalls
	if len(got) != 1 || got[0].Op != change.SiteAdd || got[0].Site.Hosts[0] != draftHost ||
		got[0].Site.Kind != "role" || got[0].Site.TargetKind != site.TargetK8s || got[0].Site.TargetURL != "" || got[0].Actor != "devops@example.com" {
		t.Errorf("preview request = %+v", got)
	}
	if len(h.sites.reviewer.submitCalls) != 0 {
		t.Error("preview submitted a change")
	}
	h.assertNoApplySideWrites(before)
}

func TestIngressDraftApplyUsesSiteWorkflow(t *testing.T) {
	h := newDraftHandoff(t, readyDiscovery())
	h.completeDraft()
	plan := draftPlan()
	h.sites.reviewer.previewPlans = []change.SitePlan{plan}
	h.sites.reviewer.submitResults = []change.SiteResult{{Result: change.Result{ChangeID: 5, Status: change.StatusApplied, Applied: true}, Plan: plan}}
	h.sites.changes.rows[5] = db.Change{ID: 5, Status: change.StatusApplied}

	form := approveForm(t, h.review())
	rec := h.do(draftRequest{method: http.MethodPost, target: "/sites/review/approve", form: form})
	if rec.Code != http.StatusOK {
		t.Fatalf("approve = %d %s", rec.Code, rec.Body.String())
	}
	if len(h.sites.reviewer.submitCalls) != 1 || h.sites.reviewer.submitCalls[0].Actor != "devops@example.com" ||
		h.sites.reviewer.submitCalls[0].Site.Hosts[0] != draftHost {
		t.Errorf("submit calls = %+v", h.sites.reviewer.submitCalls)
	}
	if !h.auditor.hasEvent("site.approve", "requested") || !h.auditor.hasEvent("site.approve", "applied") {
		t.Error("approval not audited through the site flow")
	}
}

func TestIngressDraft_FreshValidationAndReviewRequired(t *testing.T) {
	t.Run("incomplete", func(t *testing.T) {
		h := newDraftHandoff(t, readyDiscovery())
		h.save(url.Values{"access_choice": {"role"}, "roles": {""}})
		if rec := h.do(draftRequest{method: http.MethodPost, target: "/k8s/drafts/" + draftHost + "/review", form: url.Values{}}); rec.Code != http.StatusConflict {
			t.Errorf("incomplete review = %d", rec.Code)
		}
		if len(h.sites.reviewer.previewCalls) != 0 {
			t.Error("an incomplete draft reached the pipeline")
		}
	})
	t.Run("review_open", func(t *testing.T) {
		d := draftProposal(draftRoute("uid-1", "/", "a"), draftRoute("uid-1", "/", "b"))
		d.ReviewState, d.ReviewReason = k8s.ReviewStateNeeded, string(k8s.ReasonRouteConflict)
		h := newDraftHandoff(t, discoveryOf(12, "pv1", draftObsOld, d))
		h.completeDraft()
		if rec := h.do(draftRequest{method: http.MethodPost, target: "/k8s/drafts/" + draftHost + "/review", form: url.Values{}}); rec.Code != http.StatusConflict {
			t.Errorf("open review = %d", rec.Code)
		}
		if len(h.sites.reviewer.previewCalls) != 0 {
			t.Error("a draft with an open review reached the pipeline")
		}
	})
	t.Run("source_not_current", func(t *testing.T) { // C-L5
		for name, mutate := range map[string]func(h *draftHandoff){
			"newer snapshot": func(h *draftHandoff) {
				h.reader.discovery = discoveryOf(13, "pv2", draftObsNew, draftProposal(draftRoute("uid-1", "/", "api")))
			},
			"discovery unreadable": func(h *draftHandoff) { h.reader.err = errors.New("snapshot store unavailable") },
			"host gone from discovery": func(h *draftHandoff) {
				h.reader.discovery = discoveryOf(12, "pv1", draftObsOld)
			},
		} {
			t.Run(name, func(t *testing.T) {
				h := newDraftHandoff(t, readyDiscovery())
				h.completeDraft()
				mutate(h)
				if rec := h.do(draftRequest{method: http.MethodPost, target: "/k8s/drafts/" + draftHost + "/review", form: url.Values{}}); rec.Code != http.StatusConflict {
					t.Errorf("review of a draft with a non-current source = %d, want 409", rec.Code)
				}
				if len(h.sites.reviewer.previewCalls) != 0 {
					t.Error("a draft with a non-current source reached the pipeline")
				}
			})
		}
	})
	t.Run("roles_unreadable_or_gone", func(t *testing.T) {
		h := newDraftHandoff(t, readyDiscovery())
		h.completeDraft()
		h.sites.reviewer.previewErrs = []error{errors.New("site validation: roles: role \"developer\" does not exist")}
		rec := h.do(draftRequest{method: http.MethodPost, target: "/k8s/drafts/" + draftHost + "/review", form: url.Values{}})
		if rec.Code != http.StatusBadRequest || strings.Contains(rec.Body.String(), `name="plan_version"`) {
			t.Errorf("role failure = %d, approval offered: %s", rec.Code, rec.Body.String())
		}
		if len(h.sites.reviewer.submitCalls) != 0 {
			t.Error("submit ran")
		}
	})
	t.Run("stale_plan", func(t *testing.T) {
		h := newDraftHandoff(t, readyDiscovery())
		h.completeDraft()
		h.sites.reviewer.previewPlans = []change.SitePlan{draftPlan()}
		form := approveForm(t, h.review())
		h.sites.reviewer.previewPlans = []change.SitePlan{planFor(change.SiteAdd, []string{draftHost}, "+CHANGED {")}
		h.sites.reviewer.previewRuns = 0
		if rec := h.do(draftRequest{method: http.MethodPost, target: "/sites/review/approve", form: form}); rec.Code != http.StatusConflict {
			t.Errorf("stale approve = %d", rec.Code)
		}
		if len(h.sites.reviewer.submitCalls) != 0 {
			t.Error("stale plan applied")
		}
	})
}

func TestIngressDraft_DryRunPreservesAllArtifacts(t *testing.T) {
	h := newDraftHandoff(t, readyDiscovery())
	h.completeDraft()
	plan := draftPlan()
	h.sites.reviewer.previewPlans = []change.SitePlan{plan}
	h.sites.reviewer.submitResults = []change.SiteResult{{Result: change.Result{ChangeID: 6, Status: change.StatusDryRun}, Plan: plan}}
	h.sites.changes.rows[6] = db.Change{ID: 6, Status: change.StatusDryRun}
	before := h.applySideCounts()

	rec := h.do(draftRequest{method: http.MethodPost, target: "/sites/review/approve", form: approveForm(t, h.review())})
	if !strings.Contains(rec.Body.String(), "dry-run") || strings.Contains(rec.Body.String(), "apply edildi") {
		t.Errorf("dry-run result: %s", rec.Body.String())
	}
	h.assertNoApplySideWrites(before)
}

func approveWith(t *testing.T, h *draftHandoff, res change.SiteResult, row db.Change, err error) string {
	t.Helper()
	plan := draftPlan()
	h.sites.reviewer.previewPlans = []change.SitePlan{plan}
	h.sites.reviewer.submitResults = []change.SiteResult{res}
	if err != nil {
		h.sites.reviewer.submitErrs = []error{err}
	}
	if row.ID != 0 {
		h.sites.changes.rows[row.ID] = row
	}
	return h.do(draftRequest{method: http.MethodPost, target: "/sites/review/approve", form: approveForm(t, h.review())}).Body.String()
}

func TestIngressDraftValidationFailureNotApplied(t *testing.T) {
	h := newDraftHandoff(t, readyDiscovery())
	h.completeDraft()
	body := approveWith(t, h, change.SiteResult{Result: change.Result{ChangeID: 7, Status: change.StatusFailed}},
		db.Change{ID: 7, Status: change.StatusFailed, Error: "caddy validate reddetti"}, nil)
	if !strings.Contains(body, "başarısız") || !strings.Contains(body, "caddy validate reddetti") || strings.Contains(body, "apply edildi") {
		t.Errorf("failure page: %s", body)
	}
}

func TestIngressDraftURIErrorRollsBack(t *testing.T) {
	h := newDraftHandoff(t, readyDiscovery())
	h.completeDraft()
	body := approveWith(t, h, change.SiteResult{Result: change.Result{ChangeID: 8, Status: change.StatusRolledBack}},
		db.Change{ID: 8, Status: change.StatusRolledBack, Error: "uri adımı başarısız"}, nil)
	if !strings.Contains(body, "geri alındı") || strings.Contains(body, ">apply edildi<") {
		t.Errorf("rollback page: %s", body)
	}
}

func TestIngressDraft_UnknownOrEditDoesNotBlindlyRollback(t *testing.T) {
	// The adapter only ever asks for an add; the unknown outcome is shown as recorded and nothing
	// else (no second submit, no update/delete) follows.
	h := newDraftHandoff(t, readyDiscovery())
	h.completeDraft()
	body := approveWith(t, h, change.SiteResult{Result: change.Result{ChangeID: 9, Status: "unknown"}},
		db.Change{ID: 9, Status: "unknown", Error: "sonuç doğrulanamadı"}, nil)
	if !strings.Contains(body, "sonuç doğrulanamadı") || strings.Contains(body, "apply edildi") {
		t.Errorf("unknown page: %s", body)
	}
	if n := len(h.sites.reviewer.submitCalls); n != 1 {
		t.Errorf("submit calls = %d, want exactly 1", n)
	}
	for _, c := range append(h.sites.reviewer.previewCalls, h.sites.reviewer.submitCalls...) {
		if c.Op != change.SiteAdd {
			t.Errorf("adapter issued %q", c.Op)
		}
	}
}

func TestIngressDraftRollbackFailureIsCritical(t *testing.T) {
	h := newDraftHandoff(t, readyDiscovery())
	h.completeDraft()
	body := approveWith(t, h, change.SiteResult{Result: change.Result{ChangeID: 10, Status: change.StatusFailed}},
		db.Change{ID: 10, Status: change.StatusFailed, Error: "geri alma doğrulanamadı: kritik"}, errors.New("rollback failed"))
	if !strings.Contains(body, "kritik") || strings.Contains(body, ">apply edildi<") {
		t.Errorf("critical page: %s", body)
	}
	d := h.stored()
	if d.Draft.Host != draftHost {
		t.Errorf("draft changed: %+v", d)
	}
	_ = context.Background
}

type draftRoleSource []string

func (r draftRoleSource) ListRoles(context.Context) ([]string, error) { return r, nil }

// C-L4: the request draftSiteRequest builds for each access choice passes the real site validator
// (kind/open_reason/roles/target shape), with the draft target allow-listed. The unknown-role row is
// the negative control.
func TestDraftSiteRequestPassesSiteValidator(t *testing.T) {
	validator, err := site.NewValidator(site.ValidatorConfig{
		AllowedDomains: []string{"example.test"}, AllowedTargets: []string{"10.1.2.10", "100.64.0.5"},
	}, draftRoleSource{"ops", "dev"})
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	base := k8s.Draft{
		Host: "app.example.test", Target: "https://10.1.2.10:443", Cert: k8s.CertAuto,
		ReviewState: k8s.ReviewStateResolved,
	}
	roleBase := base
	roleBase.Target = caddyrender.K8sUpstream
	cases := []struct {
		name    string
		mutate  func(*k8s.Draft)
		wantErr bool
	}{
		{"role choice", func(d *k8s.Draft) { d.AccessChoice, d.Roles = k8s.AccessChoiceRole, []string{"ops", "dev"} }, false},
		{"open choice", func(d *k8s.Draft) { d.AccessChoice = k8s.AccessChoiceOpen }, false},
		{"unknown role", func(d *k8s.Draft) { d.AccessChoice, d.Roles = k8s.AccessChoiceRole, []string{"ghost"} }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := base
			if strings.Contains(tc.name, "role") {
				d = roleBase
			}
			tc.mutate(&d)
			req, err := draftSiteRequest(d, "")
			if err != nil {
				t.Fatalf("draftSiteRequest: %v", err)
			}
			err = validator.Validate(context.Background(), req.Site)
			if tc.wantErr != (err != nil) {
				t.Fatalf("Validate = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// F4-035: the request built for each choice goes through the real Caddy renderer. A role draft whose
// target is the k8s upstream itself maps to the k8s target; any other listener is refused as not
// ready, never silently rewritten (R3: tagcess invents no target). An open draft keeps its URL target.
func TestDraftSiteRequestRendersThroughRealRenderer(t *testing.T) {
	base := k8s.Draft{Host: "app.example.test", Cert: k8s.CertAuto, ReviewState: k8s.ReviewStateResolved}
	cases := []struct {
		name      string
		upstream  string // sites.k8s_upstream; empty: the renderer's default
		target    string
		choice    string
		wantErr   bool
		wantProxy string
	}{
		{"role on the k8s upstream", "", caddyrender.K8sUpstream, k8s.AccessChoiceRole, false, "import vpn_site"},
		{"role on the k8s upstream with :443", "", caddyrender.K8sUpstream + ":443", k8s.AccessChoiceRole, false, "import vpn_site"},
		{"role on another listener", "", "https://10.1.2.10:8443", k8s.AccessChoiceRole, true, ""},
		{"open on another listener", "", "https://10.1.2.10:8443", k8s.AccessChoiceOpen, false, "reverse_proxy https://10.1.2.10:8443"},
		// The existing installation's (k8s) upstream is the Traefik internal entrypoint on :8443 (sites.k8s_upstream).
		{"role on the configured upstream", "https://100.64.0.5:8443", "https://100.64.0.5:8443", k8s.AccessChoiceRole, false, "import vpn_site"},
		{"role on the default when another is configured", "https://100.64.0.5:8443", caddyrender.K8sUpstream, k8s.AccessChoiceRole, true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := base
			d.Target, d.AccessChoice = tc.target, tc.choice
			if tc.choice == k8s.AccessChoiceRole {
				d.Roles = []string{"ops"}
			}
			req, err := draftSiteRequest(d, tc.upstream)
			if tc.wantErr {
				if !errors.Is(err, errDraftNotReady) {
					t.Fatalf("draftSiteRequest = %v, want errDraftNotReady", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("draftSiteRequest: %v", err)
			}
			out, err := caddyrender.RenderCaddyfile([]site.Site{req.Site}, caddyrender.CaddyConfig{ACMEEmail: "a@example.test", S06Open: true})
			if err != nil {
				t.Fatalf("real renderer refused the request: %v", err)
			}
			if !strings.Contains(out, tc.wantProxy) {
				t.Errorf("rendered Caddyfile lacks %q:\n%s", tc.wantProxy, out)
			}
		})
	}
}
