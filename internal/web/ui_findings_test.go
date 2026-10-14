package web

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/a-h/templ"

	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/hsadmin"
	"github.com/nesiler/tagcess/internal/k8s"
	"github.com/nesiler/tagcess/internal/policydoc"
	"github.com/nesiler/tagcess/internal/site"
	"github.com/nesiler/tagcess/internal/sync"
)

// Tests for the lab UI findings of 2026-10-06.

// U-1 (K-3): the list screens use the sortable, searchable ListTable; Audit stays server-filtered.
func TestListScreensUseListTable(t *testing.T) {
	for _, f := range []string{"sites.templ", "devices.templ", "users.templ", "keys.templ", "apikeys.templ",
		"alerts.templ", "policy_history.templ", "sites_history.templ", "k8s.templ", "dns_records.templ"} {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(src), "@ui.ListTable(") {
			t.Errorf("%s: the list is not a ui.ListTable", f)
		}
		if strings.Contains(string(src), "@ui.Table()") {
			t.Errorf("%s: still has a plain ui.Table", f)
		}
	}
	src, err := os.ReadFile("audit.templ")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(src), "@ui.ListTable(") {
		t.Error("audit.templ: Audit is filtered and paged on the server, not in the browser (K-3)")
	}
}

// U-1, U-3, U-4, U-10: the browser hooks the components emit are handled by ui.js and styled by
// components.css: sort/search, the narrow-screen menu button, the sticky first column with the
// right-edge scroll shadow, the tab bar without a vertical scrollbar and grids that never push the
// page wider than the screen.
func TestUIAssetsHandleTheHooks(t *testing.T) {
	js, err := os.ReadFile("static/ui.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, hook := range []string{"table[data-sortable]", "data-table-search", "data-table-count", "data-table-none",
		"aria-sort", "data-nav-toggle", "aria-expanded", "Escape", "htmx:load", "textarea[data-code-editor]", "/static/editor.js"} {
		if !strings.Contains(string(js), hook) {
			t.Errorf("ui.js does not handle %q", hook)
		}
	}
	css, err := os.ReadFile("static/components.css")
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range []string{
		".tscroll th:first-child, .tscroll td:first-child { position: sticky; left: 0;",
		"no-repeat local", "no-repeat scroll",
		"overflow-x: auto; overflow-y: hidden; }",
		".grid > * { min-width: 0; }", "repeat(2, minmax(0, 1fr))",
		".js .navbtn { display: inline-grid; }", ".js .shell.nav-open .sidebar",
		"[hidden] { display: none !important; }",
	} {
		if !strings.Contains(string(css), rule) {
			t.Errorf("components.css lacks %q", rule)
		}
	}
	page := render(t, Layout(Actor{User: "jdoe"}, "token", "pano", "Pano", templ.Raw("")))
	if !strings.Contains(page, `data-nav-toggle aria-controls="sidebar" aria-expanded="false" aria-label="Menü"`) ||
		!strings.Contains(page, `<aside class="sidebar" id="sidebar">`) {
		t.Error("the layout has no labelled menu button controlling the sidebar")
	}
	// The menu button comes before the logo, so on a phone the top bar is first.
	if strings.Index(page, "data-nav-toggle") > strings.Index(page, `class="logo"`) {
		t.Error("the menu button is not before the logo")
	}
}

// U-13: the explanation is said once, and the resolved list is paged.
func TestAlertsPageTextAndResolvedPager(t *testing.T) {
	var resolved []AlertRow
	for i := range 30 {
		resolved = append(resolved, AlertRow{ID: int64(i), Kind: "monitor_target_health", Subject: "a.example", Source: "target", State: "resolved", Resolved: true, LastSeen: time.Unix(int64(1000-i), 0)})
	}
	rows, pager := pageResolved(resolved, "")
	if len(rows) != resolvedPerPage || pager.Pages != 2 || pager.Page != 1 {
		t.Fatalf("page 1 = %d rows, %+v", len(rows), pager)
	}
	out := render(t, AlertsPage(AlertsView{Loaded: true, Resolved: rows, ResolvedPage: pager}, "tok"))
	if n := strings.Count(out, "Okundu işaretlemek uyarıyı çözmez"); n != 1 {
		t.Errorf("the explanation appears %d times, want once", n)
	}
	if !strings.Contains(out, `aria-label="Çözülmüş uyarı sayfaları"`) || !strings.Contains(out, `href="/alerts?resolved=2"`) {
		t.Error("the resolved list has no pager to page 2")
	}

	cases := []struct {
		raw        string
		page, rows int
		prev, next string
	}{
		{"2", 2, 5, "/alerts?resolved=1", ""},
		{"99", 2, 5, "/alerts?resolved=1", ""},
		{"x", 1, resolvedPerPage, "", "/alerts?resolved=2"},
		{"-3", 1, resolvedPerPage, "", "/alerts?resolved=2"},
	}
	for _, c := range cases {
		rows, p := pageResolved(resolved, c.raw)
		if p.Page != c.page || len(rows) != c.rows || p.prev() != c.prev || p.next() != c.next {
			t.Errorf("page %q = %d rows, %+v (prev %q next %q)", c.raw, len(rows), p, p.prev(), p.next())
		}
	}
	if _, p := pageResolved(nil, ""); p.Pages != 1 || len(render(t, alertsResolvedPager(p))) != 0 {
		t.Error("an empty or single-page resolved list must have no pager")
	}
}

// U-7: the shared result page returns to the screen the change came from, shows the status in
// words only and lists the sites as separate items; a device rename names the new name.
func TestResultPagesU7(t *testing.T) {
	v := SiteResultView{ChangeID: 3, Status: change.StatusApplied, Applied: true, Sites: []string{"auth.example.com", "hs.example.com"}, Back: resultBackDNS}
	out := render(t, SiteResultPage(v))
	for _, w := range []string{`<a href="/headscale/dns">MagicDNS kayıtları</a>`, `data-status="applied"`, `<li><code>auth.example.com</code></li><li><code>hs.example.com</code></li>`} {
		if !strings.Contains(out, w) {
			t.Errorf("result lacks %q", w)
		}
	}
	if strings.Contains(out, "<code>applied</code>") || strings.Contains(out, `<a href="/sites">Siteler</a>`) {
		t.Error("the DNS result shows the raw status or the site list breadcrumb")
	}
	v.Back = ResultBack{}
	if out := render(t, SiteResultPage(v)); !strings.Contains(out, `<a href="/sites">Siteler</a>`) {
		t.Error("a site change result does not return to the site list")
	}

	dev := render(t, DeviceActionResultPage(DeviceActionResultView{DeviceID: 7, DeviceName: "jerrym", NewName: "jerrym-laptop", Action: actionRename, Status: hsadmin.StatusApplied}))
	if !strings.Contains(dev, `yeni ad: <strong data-new-name>jerrym-laptop</strong>`) || !strings.Contains(dev, "<strong>jerrym</strong>") {
		t.Errorf("rename result does not show old and new name:\n%s", dev)
	}
}

// U-12: when every key has expired the active list shows an empty state, not a bare header row.
func TestKeysAllExpiredShowsEmptyState(t *testing.T) {
	out := render(t, KeysPage(KeysView{Rows: []KeyRowView{{ID: 1, Owner: "carol", Expired: true}}}, "tok"))
	if !strings.Contains(out, "Kullanılabilir pre-auth key yok.") {
		t.Error("no empty state for the active keys")
	}
	if strings.Count(out, "data-sortable") != 1 {
		t.Error("want only the expired keys table")
	}
}

// U-11: an empty diff says so; a plan whose read failed (Reason) is never "no difference".
func TestSyncPlanEmpty(t *testing.T) {
	cases := []struct {
		name string
		plan sync.Plan
		want bool
	}{
		{"nothing to do", sync.Plan{WillApply: true}, true},
		{"read failed", sync.Plan{Reason: "okuma hatası"}, false},
		{"blocked", sync.Plan{Blocked: true}, false},
		{"needs approval", sync.Plan{NeedsApproval: true}, false},
		{"expiry", sync.Plan{ExpireNodes: []sync.NodeExpiry{{NodeID: 1}}}, false},
		{"warning", sync.Plan{Warnings: []string{"x"}}, false},
	}
	for _, c := range cases {
		if got := syncPlanEmpty(c.plan); got != c.want {
			t.Errorf("%s: empty = %v, want %v", c.name, got, c.want)
		}
		out := render(t, SyncPage(SyncOverview{Plan: c.plan, IntervalMin: 5}, "tok"))
		if strings.Contains(out, "Fark yok") != c.want {
			t.Errorf("%s: page shows 'Fark yok' = %v, want %v", c.name, !c.want, c.want)
		}
	}
}

// U-8: after a syntax error there is no diff to show, so the page says so instead of "same as live";
// the editor marks the reported line.
func TestPolicySyntaxErrorHasNoDiffClaim(t *testing.T) {
	p := policyPreviewView{Report: policydoc.Report{Stages: []policydoc.StageResult{
		{Stage: policydoc.StageInput, State: policydoc.StatePass},
		{Stage: policydoc.StageSyntax, State: policydoc.StateFail, Line: 4, Column: 3, Message: "bad"},
	}}}
	out := render(t, PolicyPage(policyPageView{Text: "{\n}\n", Editable: true, Preview: &p}, "tok"))
	if strings.Contains(out, "Canlı policy ile aynı") || !strings.Contains(out, "Fark hesaplanmadı") {
		t.Error("a syntax error still claims the text equals the live policy")
	}
	if !strings.Contains(out, `data-code-editor="hujson"`) || !strings.Contains(out, `data-error-line="4"`) || !strings.Contains(out, `name="text"`) {
		t.Error("the editor textarea lacks the editor hooks or the form field")
	}
	p.Report.Stages[1] = policydoc.StageResult{Stage: policydoc.StageSyntax, State: policydoc.StatePass}
	out = render(t, PolicyPage(policyPageView{Text: "{}", Editable: true, Preview: &p}, "tok"))
	if !strings.Contains(out, "Canlı policy ile aynı") || strings.Contains(out, "data-error-line") {
		t.Error("a readable text with no change must say it equals the live policy, with no error mark")
	}
}

// U-9: every repeated-row input of the site form has an accessible name.
func TestSiteFormRowInputsHaveNames(t *testing.T) {
	s := site.Site{Kind: site.KindRole, TargetKind: site.TargetURL, TargetURL: "http://100.64.0.5:8080",
		APIRules:  []site.APIRule{{Type: site.APIRuleHeaderPresent, Value: "Authorization"}},
		Redirects: []site.Redirect{{Source: "/a", Target: "/b", Code: 301}},
		Headers:   []site.Header{{Name: "X-A", Value: "1"}}}
	out := render(t, SiteFormPage(previewSiteForm(s, false, ""), "tok"))
	for _, w := range []string{
		`aria-label="API bypass kuralı 1: tür"`, `aria-label="API bypass kuralı 1: değer"`,
		`aria-label="Redirect 1: kaynak path"`, `aria-label="Redirect 1: hedef"`, `aria-label="Redirect 1: HTTP kodu"`,
		`aria-label="Ek header 1: ad"`, `aria-label="Ek header 1: değer"`,
	} {
		if !strings.Contains(out, w) {
			t.Errorf("site form lacks %s", w)
		}
	}
}

// D-1, D-2: the site menu's history entry is capitalised; the device owner column reads "Sahip".
func TestWordingD1D2(t *testing.T) {
	out := render(t, SitesPage(previewSites(), "tok"))
	if !strings.Contains(out, ">Geçmiş\n") && !strings.Contains(out, ">Geçmiş<") {
		t.Error(`the site menu has no "Geçmiş" entry`)
	}
	for _, f := range []string{"devices.templ", "dashboard.templ", "device_reopen.templ", "keys.templ"} {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(src), ">Owner<") || strings.Contains(string(src), "Owner /") {
			t.Errorf("%s still labels the owner column in English", f)
		}
	}
}

// U-17: a managed site in a route conflict is not labelled matched, and a candidate's catch-all
// reason says it comes from a catch-all Ingress rule, not from the host's own rules.
func TestDiscoveryU17Labels(t *testing.T) {
	if got := managedStatusLabel(k8s.ManagedConflict); got == managedStatusLabel(k8s.ManagedMatched) || !strings.Contains(got, "çelişki") {
		t.Errorf("conflict label = %q", got)
	}
	for _, r := range []k8s.Reason{k8s.ReasonDefaultBackend, k8s.ReasonEmptyHost} {
		if got := reviewReasonLabel(string(r)); !strings.Contains(got, "catch-all") {
			t.Errorf("%s: candidate reason %q does not name the catch-all source", r, got)
		}
	}
	if got := reviewReasonLabel(string(k8s.ReasonRouteConflict)); strings.Contains(got, "catch-all") {
		t.Errorf("a host's own reason got the catch-all note: %q", got)
	}
}
