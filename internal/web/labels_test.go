package web

import (
	"context"
	"html"
	"io"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/alert"
	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/dashboard"
	"github.com/nesiler/tagcess/internal/health"
	"github.com/nesiler/tagcess/internal/hostpatch"
	"github.com/nesiler/tagcess/internal/hsadmin"
	"github.com/nesiler/tagcess/internal/k8s"
	"github.com/nesiler/tagcess/internal/maintenance"
	"github.com/nesiler/tagcess/internal/site"
)

// N1/N2 (F5 fix7): the screens show Turkish labels; the stable codes stay in the data model and in
// title/data-* attributes. Unknown codes fall back to the raw value so nothing is hidden.

func TestAlertCodeLabels(t *testing.T) {
	cases := []struct {
		name string
		fn   func(string) string
		in   string
		want string
	}{
		{"kind health", alertKindLabel, alert.KindTargetHealth, "Sağlık kontrolü"},
		{"kind tls", alertKindLabel, alert.KindTLSExpiry, "TLS sertifika süresi"},
		{"kind stale", alertKindLabel, alert.KindSourceStale, "Kaynak güncel değil"},
		{"kind drift", alertKindLabel, alert.KindDrift, "Config drift"},
		{"kind unknown", alertKindLabel, "monitor_new_thing", "monitor_new_thing"},
		{"source target", alertSourceLabel, alert.AlertSourceTarget, "Hedef sağlığı"},
		{"source gate", alertSourceLabel, alert.AlertSourceGate, "Caddy erişim gate'i"},
		{"source tls", alertSourceLabel, alert.AlertSourceTLS, "TLS sertifikası"},
		{"source store", alertSourceLabel, alert.AlertSourceStore, "Kontrol kayıtları"},
		{"source drift", alertSourceLabel, alert.SourceDrift, "Apply edilen temel"},
		{"source unknown", alertSourceLabel, "other_source", "other_source"},
		{"severity critical", severityLabel, string(alert.SeverityCritical), "kritik"},
		{"severity warning", severityLabel, string(alert.SeverityWarning), "uyarı"},
		{"severity info", severityLabel, string(alert.SeverityInfo), "bilgi"},
		{"severity unknown", severityLabel, "weird", "weird"},
		{"drift subject policy", driftSubjectLabel, alert.SubjectPolicy, "Headscale policy"},
		{"drift subject caddyfile", driftSubjectLabel, alert.SubjectCaddyFile, "Caddyfile (disk)"},
		{"drift subject live", driftSubjectLabel, alert.SubjectCaddyLive, "Çalışan Caddy config'i"},
		{"drift subject dns", driftSubjectLabel, alert.SubjectDNS, "DNS kayıtları"},
		{"drift subject uris", driftSubjectLabel, alert.SubjectURIs, "Zitadel redirect URI'leri"},
		{"drift subject unknown", driftSubjectLabel, "other", "other"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.fn(c.in); got != c.want {
				t.Errorf("label(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// The subject is a drift artifact name only for the drift source; a site host named like an
// artifact is shown as-is.
func TestAlertSubjectLabelOnlyForDriftSource(t *testing.T) {
	if got := alertSubjectLabel(alert.KindSourceStale, alert.SourceDrift, "caddy_live"); got != "Çalışan Caddy config'i" {
		t.Errorf("drift subject = %q", got)
	}
	if got := alertSubjectLabel(alert.KindTargetHealth, alert.AlertSourceTarget, "policy"); got != "policy" {
		t.Errorf("site subject = %q, want it unchanged", got)
	}
}

func TestAlertEvidenceText(t *testing.T) {
	hint := " Olası neden: şablon güncellendi; /sites sayfasında \"Kayıtlardan yeniden apply et\" ile çözülür."
	cases := []struct{ in, want string }{
		{"", ""},
		{"running Caddy config differs from the applied records." + hint, "Çalışan Caddy config'i apply edilen kayıtlardan farklı." + hint},
		{"Caddyfile on disk differs from the applied records (3 lines)." + hint, "Diskteki Caddyfile apply edilen kayıtlardan farklı (3 satır)." + hint},
		{"live policy differs from applied revision #7", "Canlı policy, apply edilen #7 revision'ından farklı"},
		{"DNS records file differs from the applied records (2 lines)", "DNS kayıt dosyası apply edilen kayıtlardan farklı (2 satır)"},
		{"redirect URIs: 1 desired missing, 2 stale owned still present", "Redirect URI'leri: 1 istenen eksik, 2 eski kayıt hâlâ duruyor"},
		{"site removed", "site kaldırıldı"},
		{"no applied policy revision to compare with", "karşılaştırılacak apply edilmiş policy revision'ı yok"},
		{"first import is pending: no applied baseline yet", "ilk import bekleniyor: henüz apply edilmiş temel yok"},
		{"source could not be read", "kaynak okunamadı"},
		{"no recent measurement", "yakın zamanda kontrol yok"},
		{"network measurement failed: no answer within the time limit", "ağ kontrolü başarısız: zaman aşımı"},
		{"unknown observation category", "bilinmeyen kontrol türü"},
		{"HTTP 503", "HTTP 503"},
		{"something new and unknown", "something new and unknown"},
	}
	for _, c := range cases {
		if got := alertEvidenceText(c.in); got != c.want {
			t.Errorf("alertEvidenceText(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// Every failure text the health runner stores as evidence has a Turkish rendering.
func TestAlertEvidenceTextCoversHealthFailures(t *testing.T) {
	for _, l := range health.FailureLabels() {
		en, _ := health.FailureText(l)
		if got := alertEvidenceText(en); got != observationResultText[l] {
			t.Errorf("failure %q: evidence %q renders %q, want %q", l, en, got, observationResultText[l])
		}
	}
}

// tagRE strips markup so a test can read only the text a user sees (attributes are dropped).
var tagRE = regexp.MustCompile(`(?s)<[^>]*>`)

func visibleText(body string) string {
	return html.UnescapeString(strings.Join(strings.Fields(tagRE.ReplaceAllString(body, " ")), " "))
}

// N2: the alerts screen shows Turkish kind/source/subject/evidence text; the codes stay in data-*.
func TestAlertsPageShowsTurkishLabelsNotCodes(t *testing.T) {
	h := newAlertsHarness(t)
	ctx := context.Background()
	if _, err := h.svc.RecordSource(ctx, alert.SourceSample{
		Subject: alert.SubjectCaddyLive, Source: alert.SourceDrift, Failed: true,
		Error: "running Caddy config differs from the applied records.",
	}); err != nil {
		t.Fatalf("RecordSource: %v", err)
	}
	if _, err := h.svc.RecordSource(ctx, alert.SourceSample{
		Subject: alert.SubjectPolicy, Source: alert.SourceDrift, Failed: true,
		Error: "no applied policy revision to compare with",
	}); err != nil {
		t.Fatalf("RecordSource: %v", err)
	}
	h.raise(t, "app.example", alert.AlertSourceGate)

	rec := h.get(t, "/alerts")
	body := rec.Body.String()
	text := visibleText(body)
	for _, want := range []string{
		"Kaynak güncel değil", "Apply edilen temel", "Çalışan Caddy config'i",
		"Çalışan Caddy config'i apply edilen kayıtlardan farklı.",
		"karşılaştırılacak apply edilmiş policy revision'ı yok", "Caddy erişim gate'i", "Sağlık kontrolü",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("visible text lacks %q", want)
		}
	}
	for _, raw := range []string{
		"caddy_live", "applied-baseline", "monitor_source_stale", "monitor_target_health", "caddy_gate",
		"running Caddy config", "no applied policy revision", "critical", "warning",
	} {
		if strings.Contains(text, raw) {
			t.Errorf("visible text still shows raw %q", raw)
		}
	}
	for _, attr := range []string{`data-subject="caddy_live"`, `data-source="applied-baseline"`, `data-kind="monitor_source_stale"`, `data-source="caddy_gate"`} {
		if !strings.Contains(body, attr) {
			t.Errorf("code attribute %s missing", attr)
		}
	}
}

// N1: the dashboard boundaries and drift cards show Turkish headings and sentences; the boundary
// kinds and drift subjects stay in title/data-* attributes.
func TestDashboardShowsTurkishLabelsNotCodes(t *testing.T) {
	h := newDashboardHarness(t)
	at := time.Date(2026, 10, 5, 13, 0, 0, 0, time.UTC)
	h.s06.read = dashboard.S06Read{Open: true, ObservedAt: at}
	h.sites.read = dashboard.SitesRead{ObservedAt: at, Sites: []site.Site{
		{ID: 1, Kind: site.KindRole, Hosts: []string{"role.example"}, Roles: []string{"developer"},
			APIRules: []site.APIRule{{Type: "header", Value: "X-Api-Key"}}},
		{ID: 2, Kind: site.KindOpen, Hosts: []string{"open.example"}, OpenReason: site.OpenReasonTransition},
		{ID: 3, Kind: site.KindSystem, Hosts: []string{"sys.example"}, SystemTemplate: "tagcess"},
	}}
	h.alerts.read = dashboard.AlertsRead{ObservedAt: at, Alerts: []dashboard.Alert{
		{Kind: alert.KindDrift, Subject: alert.SubjectCaddyLive, Source: alert.SourceDrift, Severity: "critical", State: "active", Freshness: "fresh"},
		{Kind: alert.KindSourceStale, Subject: alert.SubjectDNS, Source: alert.SourceDrift, Severity: "warning", State: "active", Freshness: "stale"},
	}}
	body := h.devopsPage()

	boundaries := cardFragment(body, "boundaries")
	btext := visibleText("<section " + boundaries)
	for _, want := range []string{
		"Tailnet dışı erişim", "API bypass", "Rolsüz site", "Sistem sitesi", "sys.example",
		"Headscale ACL", "Neden: geçiş dönemi",
	} {
		if !strings.Contains(btext, want) {
			t.Errorf("boundaries text lacks %q:\n%s", want, btext)
		}
	}
	for _, raw := range []string{"s06_source", "api_exemption", "open_intent", "system_template", "headscale_acl", "S-06", "transition"} {
		if strings.Contains(btext, raw) {
			t.Errorf("boundaries text still shows raw %q:\n%s", raw, btext)
		}
	}
	for _, attr := range []string{`data-boundary="s06_source"`, `data-boundary="system_template"`, `data-boundary="open_intent"`} {
		if !strings.Contains(boundaries, attr) {
			t.Errorf("boundaries lack code attribute %s", attr)
		}
	}

	drift := cardFragment(body, "drift")
	dtext := visibleText("<section " + drift)
	for _, want := range []string{"Çalışan Caddy config'i", "DNS kayıtları", "aktif", "kritik", "güncel"} {
		if !strings.Contains(dtext, want) {
			t.Errorf("drift text lacks %q:\n%s", want, dtext)
		}
	}
	for _, raw := range []string{"caddy_live", "critical", "active", "fresh"} {
		if strings.Contains(dtext, raw) {
			t.Errorf("drift text still shows raw %q:\n%s", raw, dtext)
		}
	}
	if !strings.Contains(drift, `data-drift-subject="caddy_live"`) || !strings.Contains(drift, `data-drift-unknown-subject="dns"`) {
		t.Errorf("drift card lost the code attributes:\n%s", drift)
	}
}

// Sweep (F5 fix7): the same pattern on the sync, k8s, audit and site review screens.
func TestSweepCodeLabels(t *testing.T) {
	cases := []struct {
		name string
		fn   func(string) string
		in   string
		want string
	}{
		{"sync result", syncResultLabel, "no_change", "değişiklik yok"},
		{"sync trigger", syncTriggerLabel, "periodic", "periyodik"},
		{"legacy kind", legacyAlertKindLabel, "policy_mismatch", "Canlı policy apply edilen revision'la uyuşmuyor"},
		{"legacy kind unknown", legacyAlertKindLabel, "brand_new", "brand_new"},
		{"system source", systemSourceLabel, "zitadel", "Zitadel"},
		{"snapshot outcome", snapshotOutcomeLabel, "failed", "başarısız"},
		{"k8s class", k8sClassLabel, "credential_expired", "credential'ın süresi dolmuş (401)"},
		{"k8s class unknown", k8sClassLabel, "odd", "odd"},
		{"audit result", auditResultLabel, "requested", "istendi"},
		{"audit result unknown", auditResultLabel, "odd", "odd"},
		{"site op", siteOpLabel, "manual_dns", "Elle DNS kayıtları"},
		{"site op unknown", siteOpLabel, "odd", "odd"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.fn(c.in); got != c.want {
				t.Errorf("label(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func renderText(t *testing.T, c interface {
	Render(context.Context, io.Writer) error
}) (string, string) {
	t.Helper()
	var b strings.Builder
	if err := c.Render(context.Background(), &b); err != nil {
		t.Fatalf("render: %v", err)
	}
	return b.String(), visibleText(b.String())
}

func TestSyncPageShowsTurkishLabels(t *testing.T) {
	at := time.Date(2026, 10, 5, 13, 0, 0, 0, time.UTC)
	html, text := renderText(t, SyncPage(SyncOverview{
		LastRun: &SyncRunView{At: at, Trigger: "periodic", Result: "no_change"},
		Alerts:  []SyncAlertView{{Kind: "reconcile_read_failed", Source: "headscale", LastSeen: at}},
	}, "tok"))
	for _, want := range []string{"periyodik", "değişiklik yok", "Headscale"} {
		if !strings.Contains(text, want) {
			t.Errorf("sync text lacks %q:\n%s", want, text)
		}
	}
	for _, raw := range []string{"periodic", "no_change", "reconcile_read_failed"} {
		if strings.Contains(text, raw) {
			t.Errorf("sync text shows raw %q", raw)
		}
	}
	if !strings.Contains(html, `data-kind="reconcile_read_failed"`) {
		t.Errorf("sync page lost the alert kind attribute")
	}
}

func TestAuditPageShowsTurkishResult(t *testing.T) {
	html, text := renderText(t, AuditPage([]audit.Event{{Actor: "a", Event: "alert.acknowledge", Result: "requested"}}, "", "", 1, false))
	if !strings.Contains(text, "istendi") || strings.Contains(text, "requested") {
		t.Errorf("audit result not labelled:\n%s", text)
	}
	if !strings.Contains(html, `data-result="requested"`) {
		t.Errorf("audit result code attribute missing")
	}
}

// producedAuditResults enumerates every result string the code writes to the audit log: the change
// pipeline statuses, the hsadmin executor statuses, the host patch states, the maintenance state
// and the literals of the git log, hostapply and web handlers. A new result must be added here
// and in auditResultLabels.
func producedAuditResults() []string {
	out := []string{
		change.StatusPendingApproval, change.StatusApplied, change.StatusFailed, change.StatusRolledBack,
		change.StatusBlocked, change.StatusDryRun, change.StatusNeedsReapproval, change.StatusHeld,
		change.StatusNoChange,
		string(hsadmin.StatusStarted), string(hsadmin.StatusApplied), string(hsadmin.StatusFailed),
		string(hsadmin.StatusUnknown), string(hsadmin.StatusBlocked), string(hsadmin.StatusStale),
		string(hostpatch.StateAccepted), string(hostpatch.StateApplying), string(hostpatch.StateSucceeded),
		string(hostpatch.StateFailed), string(hostpatch.StateInterrupted),
		string(maintenance.Off),
		"requested", "started", "ok", "error", "skipped", "quarantined", "warning", "reconcile_pending",
	}
	return out
}

func TestAuditResultLabelsCoverProducedValues(t *testing.T) {
	for _, r := range producedAuditResults() {
		if l := auditResultLabel(r); l == r {
			t.Errorf("audit result %q has no Turkish label", r)
		}
	}
}

func TestFreshnessLabel(t *testing.T) {
	for in, want := range map[string]string{
		"fresh": "güncel", "current": "güncel", "stale": "güncel değil", "never": "hiç iyi olmadı",
		"previous": "önceki tarama", "none": "henüz taranmadı", "unknown": "bilinmiyor", "": "bilinmiyor",
		"weird_value": "weird_value",
	} {
		if got := freshnessLabel(in); got != want {
			t.Errorf("freshnessLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

const hostile = "<script>alert(1)</script>"

func TestLabelFallbacksEscapeHostileInput(t *testing.T) {
	// Unknown codes fall back to the raw value, which templ must escape.
	html, _ := renderText(t, AuditPage([]audit.Event{{Actor: "a", Event: "e", Result: hostile}}, "", "", 1, false))
	if strings.Contains(html, hostile) || !strings.Contains(html, "&lt;script&gt;") {
		t.Errorf("audit result not escaped:\n%s", html)
	}
	html, _ = renderText(t, K8sDiscoveryPage(K8sDiscoveryView{Freshness: K8sFreshnessView{
		LastAttempt: &k8s.Attempt{Outcome: hostile, Class: hostile},
	}}, "tok"))
	if strings.Contains(html, hostile) || !strings.Contains(html, "&lt;script&gt;") {
		t.Errorf("k8s attempt labels not escaped:\n%s", html)
	}
	html, _ = renderText(t, SiteReviewPage(SiteReviewView{Op: hostile}, "tok"))
	if strings.Contains(html, hostile) || !strings.Contains(html, "&lt;script&gt;") {
		t.Errorf("site op label not escaped:\n%s", html)
	}
	if got := freshnessLabel(hostile); got != hostile {
		t.Errorf("freshnessLabel changed hostile text: %q", got)
	}
}

func TestK8sPageShowsTurkishLabels(t *testing.T) {
	at := time.Date(2026, 10, 5, 13, 0, 0, 0, time.UTC)
	html, text := renderText(t, K8sDiscoveryPage(K8sDiscoveryView{Freshness: K8sFreshnessView{
		LastAttempt: &k8s.Attempt{AttemptedAt: at, Outcome: k8s.OutcomeFailed, Class: k8s.ClassRead},
	}}, "tok"))
	for _, want := range []string{"başarısız", "okuma başarısız"} {
		if !strings.Contains(text, want) {
			t.Errorf("k8s text lacks %q:\n%s", want, text)
		}
	}
	if !strings.Contains(html, `data-failure="`+k8s.ClassRead+`"`) {
		t.Errorf("k8s page lost the class attribute")
	}
}

func TestSiteReviewPageShowsTurkishOp(t *testing.T) {
	html, text := renderText(t, SiteReviewPage(SiteReviewView{Op: change.SiteAdd}, "tok"))
	if !strings.Contains(text, "Ekleme") {
		t.Errorf("site review lacks the Turkish op:\n%s", text)
	}
	if !strings.Contains(html, `data-op="`+change.SiteAdd+`"`) {
		t.Errorf("site review lost the op code attribute")
	}
}
