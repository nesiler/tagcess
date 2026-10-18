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
	"github.com/nesiler/tagcess/internal/dns"
	caddyrender "github.com/nesiler/tagcess/internal/render"
	"github.com/nesiler/tagcess/internal/site"
	"github.com/nesiler/tagcess/internal/store/db"
)

// Harness of the manual MagicDNS records screen (F3-008, H-06): the /headscale/dns page lists the
// site-derived records (read-only) next to the manual ones, and an add/edit/delete goes through
// the F2-014 preview → version-bound approval → result flow over the F2-011 site pipeline's
// manual_dns operation.

type fakeManualDNS struct {
	recs []dns.Record
	err  error
}

func (f *fakeManualDNS) ManualDNS(context.Context) ([]dns.Record, error) { return f.recs, f.err }

type dnsRecordsHarness struct {
	reviewer *fakeSiteReviewer
	auditor  *fakeSiteAuditor
	changes  *fakeChangeReader
	manual   *fakeManualDNS
	csrf     *CSRF
	chain    http.Handler
}

var (
	dnsManualRecord = dns.Record{Name: "old-db.example.com", Type: dns.TypeA, Value: "100.64.0.9"}
	dnsSiteHost     = "git.example.com"
)

func newDNSRecordsHarness(t *testing.T) *dnsRecordsHarness {
	t.Helper()
	return newDNSRecordsHarnessCIDR(t, "")
}

// newDNSRecordsHarnessCIDR is the harness with a configured tailnet.cidr.
func newDNSRecordsHarnessCIDR(t *testing.T, cidr string) *dnsRecordsHarness {
	t.Helper()
	h := &dnsRecordsHarness{
		reviewer: &fakeSiteReviewer{},
		auditor:  &fakeSiteAuditor{},
		changes:  &fakeChangeReader{rows: map[int64]db.Change{}},
		manual:   &fakeManualDNS{},
		csrf:     testCSRF(t),
	}
	handler, err := NewDNSRecordsHandler(DNSRecordsConfig{
		Reviewer: h.reviewer,
		Lister:   fakeReviewLister{sites: []site.Site{roleSiteStored()}},
		Manual:   h.manual,
		Settings: fakeReviewSettings{settings: change.SiteSettings{
			DNS:   caddyrender.DNSConfig{AValue: "100.64.0.4"},
			Caddy: caddyrender.CaddyConfig{TailnetCIDR: cidr},
		}},
		Changes: h.changes,
		Auditor: h.auditor,
		DryRun:  &fakeDryRunReader{},
		CSRF:    h.csrf,
	})
	if err != nil {
		t.Fatalf("NewDNSRecordsHandler: %v", err)
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	h.chain = WithShell(nil, RequireDevops(h.csrf.Protect(mux)))
	return h
}

func (h *dnsRecordsHarness) get(t *testing.T, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	req.Header.Set(headerUser, "devops-user")
	req.Header.Set(headerEmail, "devops@example.com")
	req.Header.Set(headerGroups, "devops")
	rec := httptest.NewRecorder()
	h.chain.ServeHTTP(rec, req)
	return rec
}

func (h *dnsRecordsHarness) post(t *testing.T, target string, form url.Values) *httptest.ResponseRecorder {
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

// AC1: the page lists the site-derived records (with the "site: <name>" link, without edit or
// delete) and the manual records separately, with the add form.
func TestDNSPage_ListsSiteAndManual(t *testing.T) {
	h := newDNSRecordsHarness(t)
	h.manual.recs = []dns.Record{dnsManualRecord}

	rec := h.get(t, "/headscale/dns")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /headscale/dns = %d (body %q)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	// The site-derived record with its source link.
	if !strings.Contains(body, dnsSiteHost) || !strings.Contains(body, "100.64.0.4") {
		t.Errorf("the page lacks the site-derived record:\n%s", body)
	}
	if !strings.Contains(body, `href="/sites/1/edit"`) || !strings.Contains(body, "site: "+dnsSiteHost) {
		t.Errorf("the site record does not carry the site link:\n%s", body)
	}
	// The manual record with its edit affordance.
	if !strings.Contains(body, dnsManualRecord.Name) || !strings.Contains(body, dnsManualRecord.Value) {
		t.Errorf("the page lacks the manual record:\n%s", body)
	}
	if !strings.Contains(body, `name="old_name" value="`+dnsManualRecord.Name+`"`) {
		t.Errorf("the manual record does not carry an edit form:\n%s", body)
	}
	// The add form and the preview route.
	if !strings.Contains(body, `action="/headscale/dns/preview"`) {
		t.Errorf("the page lacks the add form:\n%s", body)
	}
	// A site record is never offered for edit or delete.
	if strings.Contains(body, `name="old_name" value="`+dnsSiteHost+`"`) {
		t.Errorf("the site record carries an edit form:\n%s", body)
	}
}

// AC3 (interface side): an invalid record or a collision with a site host is refused with the
// error next to the form, and nothing is planned or written.
func TestManualDNS_Validation(t *testing.T) {
	t.Run("a name that is not a hostname", func(t *testing.T) {
		h := newDNSRecordsHarness(t)
		rec := h.post(t, "/headscale/dns/preview", url.Values{
			"action": {"add"}, "name": {"Bad Name"}, "value": {"100.64.0.9"},
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("preview = %d (body %q)", rec.Code, rec.Body.String())
		}
		if body := rec.Body.String(); !strings.Contains(body, "Bad Name") || !strings.Contains(body, "RFC 1123") {
			t.Errorf("the page does not show the name error:\n%s", body)
		}
		if len(h.reviewer.previewCalls) != 0 || len(h.reviewer.submitCalls) != 0 {
			t.Error("an invalid record reached the pipeline")
		}
	})

	t.Run("a value that is not an IP", func(t *testing.T) {
		h := newDNSRecordsHarness(t)
		rec := h.post(t, "/headscale/dns/preview", url.Values{
			"action": {"add"}, "name": {"old-db.example.com"}, "value": {"not-an-ip"},
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("preview = %d (body %q)", rec.Code, rec.Body.String())
		}
		if body := rec.Body.String(); !strings.Contains(body, "not-an-ip") {
			t.Errorf("the page does not show the value error:\n%s", body)
		}
		if len(h.reviewer.previewCalls) != 0 || len(h.reviewer.submitCalls) != 0 {
			t.Error("an invalid record reached the pipeline")
		}
	})

	t.Run("a collision with a site host", func(t *testing.T) {
		h := newDNSRecordsHarness(t)
		rec := h.post(t, "/headscale/dns/preview", url.Values{
			"action": {"add"}, "name": {dnsSiteHost}, "value": {"10.9.9.9"},
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("preview = %d (body %q)", rec.Code, rec.Body.String())
		}
		if body := rec.Body.String(); !strings.Contains(body, dnsSiteHost) || !strings.Contains(body, "site host") {
			t.Errorf("the page does not show the collision error:\n%s", body)
		}
		if len(h.reviewer.previewCalls) != 0 || len(h.reviewer.submitCalls) != 0 {
			t.Error("a colliding record reached the pipeline")
		}
	})
}

// AC6: an edit or delete aimed at a site-derived record is refused: only the stored manual set
// is editable.
func TestManualDNS_SiteRecordsReadOnly(t *testing.T) {
	h := newDNSRecordsHarness(t)
	h.manual.recs = []dns.Record{dnsManualRecord}

	for name, form := range map[string]url.Values{
		"edit":   {"action": {"edit"}, "old_name": {dnsSiteHost}, "old_type": {dns.TypeA}, "name": {dnsSiteHost}, "value": {"10.9.9.9"}},
		"delete": {"action": {"delete"}, "name": {dnsSiteHost}, "type": {dns.TypeA}},
	} {
		rec := h.post(t, "/headscale/dns/preview", form)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s of a site record = %d, want 400 (body %q)", name, rec.Code, rec.Body.String())
		}
	}
	if len(h.reviewer.previewCalls) != 0 || len(h.reviewer.submitCalls) != 0 {
		t.Error("a site-record edit reached the pipeline")
	}
}

// AC2 (interface side): the preview shows the dns diff with the version-bound approval, the
// approval submits the carried set as the signed-in operator, and a blocked preview offers the
// resync way out without an approval.
func TestManualDNS_PreviewAndApprove(t *testing.T) {
	plan := change.SitePlan{
		Op:   change.SiteManualDNS,
		Diff: change.SiteDiff{DNS: "-" + dnsSiteHost + " 100.64.0.4\n+" + dnsManualRecord.Name + " " + dnsManualRecord.Value},
	}

	t.Run("preview shows the dns diff only", func(t *testing.T) {
		h := newDNSRecordsHarness(t)
		h.reviewer.previewPlans = []change.SitePlan{plan}
		rec := h.post(t, "/headscale/dns/preview", url.Values{
			"action": {"add"}, "name": {dnsManualRecord.Name}, "value": {dnsManualRecord.Value},
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("preview = %d (body %q)", rec.Code, rec.Body.String())
		}
		body := rec.Body.String()
		if !strings.Contains(body, dnsManualRecord.Name) || !strings.Contains(body, `action="/headscale/dns/approve"`) {
			t.Errorf("the preview lacks the dns diff or the approval form:\n%s", body)
		}
		if !strings.Contains(body, `value="`+SitePlanVersion(plan)+`"`) {
			t.Errorf("the preview does not carry the plan version:\n%s", body)
		}
		if len(h.reviewer.previewCalls) != 1 {
			t.Fatalf("preview calls = %d, want 1", len(h.reviewer.previewCalls))
		}
		call := h.reviewer.previewCalls[0]
		if call.Op != change.SiteManualDNS {
			t.Errorf("preview op = %q, want %q", call.Op, change.SiteManualDNS)
		}
		if len(call.ManualDNS) != 1 || call.ManualDNS[0] != dnsManualRecord {
			t.Errorf("preview set = %+v, want the new record", call.ManualDNS)
		}
		if call.Actor != "devops@example.com" {
			t.Errorf("preview actor = %q, want the signed-in operator", call.Actor)
		}
		if len(h.reviewer.submitCalls) != 0 {
			t.Error("the preview submitted the change")
		}
	})

	t.Run("approve applies the carried set", func(t *testing.T) {
		h := newDNSRecordsHarness(t)
		req := change.SiteRequest{Op: change.SiteManualDNS, ManualDNS: []dns.Record{dnsManualRecord}}
		h.reviewer.previewPlans = []change.SitePlan{plan}
		h.reviewer.submitResults = []change.SiteResult{
			{Result: change.Result{ChangeID: 7, Status: change.StatusApplied, Applied: true}},
		}
		h.changes.rows[7] = db.Change{
			ID: 7, Status: change.StatusApplied,
		}

		form := url.Values{
			"request":      {reviewRequestJSON(t, req)},
			"plan_version": {SitePlanVersion(plan)},
		}
		rec := h.post(t, "/headscale/dns/approve", form)
		if rec.Code != http.StatusOK {
			t.Fatalf("approve = %d (body %q)", rec.Code, rec.Body.String())
		}
		if body := rec.Body.String(); !strings.Contains(body, "apply edildi") {
			t.Errorf("the result screen does not show the outcome:\n%s", body)
		}
		if len(h.reviewer.submitCalls) != 1 {
			t.Fatalf("submit calls = %d, want 1", len(h.reviewer.submitCalls))
		}
		call := h.reviewer.submitCalls[0]
		if call.Op != change.SiteManualDNS || call.Actor != "devops@example.com" {
			t.Errorf("submit = %+v, want the manual_dns op as the signed-in operator", call)
		}
		if len(call.ManualDNS) != 1 || call.ManualDNS[0] != dnsManualRecord {
			t.Errorf("submit set = %+v, want the carried set", call.ManualDNS)
		}
		if !h.auditor.hasEvent("dns.manual", "requested") || !h.auditor.hasEvent("dns.manual", "applied") {
			t.Error("the approval was not audited before and after")
		}
	})

	t.Run("a blocked preview offers the resync way out", func(t *testing.T) {
		h := newDNSRecordsHarness(t)
		h.reviewer.previewErrs = []error{fmt.Errorf("DNS dosyası kayıtlardan farklı: %w", change.ErrBlocked)}
		rec := h.post(t, "/headscale/dns/preview", url.Values{
			"action": {"add"}, "name": {dnsManualRecord.Name}, "value": {dnsManualRecord.Value},
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("preview = %d (body %q)", rec.Code, rec.Body.String())
		}
		body := rec.Body.String()
		if !strings.Contains(body, "DNS dosyası kayıtlardan farklı") {
			t.Errorf("the blocked preview does not name the reason:\n%s", body)
		}
		if strings.Contains(body, `action="/headscale/dns/approve"`) {
			t.Errorf("the blocked preview still offers the approval:\n%s", body)
		}
		if !strings.Contains(body, `action="/sites/resync/preview"`) {
			t.Errorf("the blocked preview does not show the resync path:\n%s", body)
		}
		if len(h.reviewer.submitCalls) != 0 {
			t.Error("a blocked preview applied the change")
		}
		if !h.auditor.hasEvent("dns.manual_preview", "blocked") {
			t.Error("the blocked preview was not audited")
		}
	})
}

// AC7: an approval from a stale preview (the file or the settings moved) is refused with 409 and
// never applied.
func TestManualDNS_StalePreviewRejected(t *testing.T) {
	t.Run("the plan moved", func(t *testing.T) {
		h := newDNSRecordsHarness(t)
		old := change.SitePlan{Op: change.SiteManualDNS, Diff: change.SiteDiff{DNS: "-a\n+b"}}
		moved := change.SitePlan{Op: change.SiteManualDNS, Diff: change.SiteDiff{DNS: "-a\n+c"}}
		h.reviewer.previewPlans = []change.SitePlan{old, moved}

		// The operator previews (the old plan is shown), the state moves, the approval re-plans
		// into the moved plan and is refused.
		if rec := h.post(t, "/headscale/dns/preview", url.Values{
			"action": {"add"}, "name": {dnsManualRecord.Name}, "value": {dnsManualRecord.Value},
		}); rec.Code != http.StatusOK {
			t.Fatalf("preview = %d (body %q)", rec.Code, rec.Body.String())
		}
		req := change.SiteRequest{Op: change.SiteManualDNS, ManualDNS: []dns.Record{dnsManualRecord}}
		rec := h.post(t, "/headscale/dns/approve", url.Values{
			"request":      {reviewRequestJSON(t, req)},
			"plan_version": {SitePlanVersion(old)},
		})
		if rec.Code != http.StatusConflict {
			t.Fatalf("stale approve = %d, want 409 (body %q)", rec.Code, rec.Body.String())
		}
		if len(h.reviewer.submitCalls) != 0 {
			t.Error("a stale approval applied the change")
		}
		if !h.auditor.hasEvent("dns.manual", "failed") {
			t.Error("the refused approval was not audited")
		}
	})

	t.Run("the replan fails", func(t *testing.T) {
		h := newDNSRecordsHarness(t)
		plan := change.SitePlan{Op: change.SiteManualDNS, Diff: change.SiteDiff{DNS: "-a\n+b"}}
		h.reviewer.previewPlans = []change.SitePlan{plan}
		h.reviewer.previewErrs = []error{nil, fmt.Errorf("DNS dosyası okunamadı: %w", change.ErrBlocked)}

		if rec := h.post(t, "/headscale/dns/preview", url.Values{
			"action": {"add"}, "name": {dnsManualRecord.Name}, "value": {dnsManualRecord.Value},
		}); rec.Code != http.StatusOK {
			t.Fatalf("preview = %d (body %q)", rec.Code, rec.Body.String())
		}
		req := change.SiteRequest{Op: change.SiteManualDNS, ManualDNS: []dns.Record{dnsManualRecord}}
		rec := h.post(t, "/headscale/dns/approve", url.Values{
			"request":      {reviewRequestJSON(t, req)},
			"plan_version": {SitePlanVersion(plan)},
		})
		if rec.Code != http.StatusConflict {
			t.Fatalf("failed replan approve = %d, want 409 (body %q)", rec.Code, rec.Body.String())
		}
		if len(h.reviewer.submitCalls) != 0 {
			t.Error("an approval over a failed replan applied the change")
		}
	})
}

// F5 H1/I11: the manual record's value is readable text (not only an input value) and a private
// address outside the tailnet is flagged on the page and in the preview; tailnet addresses are not.
func TestDNSPage_ManualValueTextAndOffTailnetWarning(t *testing.T) {
	h := newDNSRecordsHarness(t)
	h.manual.recs = []dns.Record{
		{Name: "auth.example.com", Type: dns.TypeA, Value: "10.0.0.3"},
		dnsManualRecord, // 100.64.0.9
	}
	body := h.get(t, "/headscale/dns").Body.String()
	if !strings.Contains(body, `<code data-manual-value="true">10.0.0.3</code>`) {
		t.Errorf("the manual value is not readable text:\n%s", body)
	}
	if n := strings.Count(body, `data-off-tailnet="true"`); n != 1 {
		t.Errorf("off-tailnet warnings = %d, want 1 (only the 10.0.0.3 record)", n)
	}

	// The preview of a new record warns before approval; a tailnet value does not.
	h.reviewer.previewPlans = []change.SitePlan{{Op: change.SiteManualDNS, Diff: change.SiteDiff{DNS: "+x"}}, {Op: change.SiteManualDNS, Diff: change.SiteDiff{DNS: "+y"}}}
	warn := h.post(t, "/headscale/dns/preview", url.Values{"action": {"add"}, "name": {"x.example.com"}, "value": {"192.168.5.5"}})
	if !strings.Contains(warn.Body.String(), `data-off-tailnet="true"`) {
		t.Errorf("the preview of a private address has no warning: %d\n%s", warn.Code, warn.Body.String())
	}
	ok := h.post(t, "/headscale/dns/preview", url.Values{"action": {"add"}, "name": {"y.example.com"}, "value": {"100.64.0.20"}})
	if strings.Contains(ok.Body.String(), `data-off-tailnet="true"`) {
		t.Error("a tailnet address was flagged in the preview")
	}
}

// F5 I11: the first-import preview flags a kept manual record whose address is private and outside
// the tailnet (the lab's auth.* 10.0.0.3 case) and leaves a tailnet record alone.
func TestFirstImportPreview_FlagsOffTailnetManualRecord(t *testing.T) {
	v := SiteFirstImportView{
		Pending: true, SeedCount: 3, ParityOK: true,
		ManualDNS: []dns.Record{
			{Name: "auth.example.test", Type: dns.TypeA, Value: "10.0.0.3"},
			{Name: "ok.example.test", Type: dns.TypeA, Value: "100.64.0.9"},
		},
	}
	body := render(t, SiteFirstImportPage(v, "token", true))
	if n := strings.Count(body, `data-off-tailnet="true"`); n != 1 {
		t.Fatalf("off-tailnet warnings in the first-import preview = %d, want 1:\n%s", n, body)
	}
}

// Issue #6 AC4: the off-tailnet warning follows the configured prefix and names it.
func TestDNSPage_OffTailnetWarningUsesConfiguredPrefix(t *testing.T) {
	h := newDNSRecordsHarnessCIDR(t, "10.200.0.0/16")
	h.manual.recs = []dns.Record{
		{Name: "in.example.com", Type: dns.TypeA, Value: "10.200.1.1"},  // inside the configured tailnet
		{Name: "out.example.com", Type: dns.TypeA, Value: "10.201.1.1"}, // private, outside it
	}
	body := h.get(t, "/headscale/dns").Body.String()
	if n := strings.Count(body, `data-off-tailnet="true"`); n != 1 {
		t.Errorf("off-tailnet warnings = %d, want 1 (only 10.201.1.1)\n%s", n, body)
	}

	h.reviewer.previewPlans = []change.SitePlan{{Op: change.SiteManualDNS, Diff: change.SiteDiff{DNS: "+x"}}}
	warn := h.post(t, "/headscale/dns/preview", url.Values{"action": {"add"}, "name": {"x.example.com"}, "value": {"10.201.5.5"}}).Body.String()
	if !strings.Contains(warn, "10.200.0.0/16") || strings.Contains(warn, "100.64.0.0/10") {
		t.Errorf("the preview warning does not name the configured prefix:\n%s", warn)
	}
}
