package installer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/test/adopttarget"
)

// verifyRun runs the verify role on the controller with canned -import-preview and unroled outputs and returns the
// result and the report text.
func verifyRun(t *testing.T, preview, unroled string, guides map[string]string) (adopttarget.Result, string) {
	t.Helper()
	home := t.TempDir()
	dir := t.TempDir()
	pf := filepath.Join(dir, "preview.json")
	uf := filepath.Join(dir, "unroled.json")
	_ = os.WriteFile(pf, []byte(preview), 0o600)
	_ = os.WriteFile(uf, []byte(unroled), 0o600)
	gd := filepath.Join(envDir(home, "vtest"), "guide")
	_ = os.MkdirAll(gd, 0o700)
	for phase, body := range guides {
		_ = os.WriteFile(filepath.Join(gd, phase+".json"), []byte(body), 0o600)
	}
	res := adopttarget.RunPlaybook(t, adopttarget.PlaybookOpts{Playbook: "testdata/verify.yml", Inventories: []string{localInventory(t)}, ConfigHome: home,
		Vars: map[string]any{"install_env": "vtest", "install_mode": "adopt", "tagcess_domain": "c.example.test", "verify_host_checks": false,
			"verify_preview_cmd": "cat " + pf, "verify_unroled_cmd": "cat " + uf, "verify_report_name": "report.md"}})
	report, _ := os.ReadFile(filepath.Join(envDir(home, "vtest"), "report.md")) // #nosec G304 -- test temp dir
	return res, string(report)
}

const equalPreview = `{"imported": false, "parity": "equal", "diff_count": 0, "seed_sites": 23, "manual_dns": []}`

// AC6 (F6-008): the user-without-role count is information: written with the guidance, no user name, and not a
// failure on its own.
func TestVerify_UnroledUsersInfoOnly(t *testing.T) {
	t.Parallel()
	res, report := verifyRun(t, equalPreview, `{"report": {"unroled_users": 3}}`, nil)
	if res.ExitCode != 0 {
		t.Fatalf("unroled users alone must not fail:\n%s", res.Output)
	}
	for _, w := range []string{"3 aktif kullanıcının vpn projesinde rolü yok", "Rolleri Zitadel'de vpn projesinde sen verirsin", "role geçir"} {
		if !strings.Contains(report, w) {
			t.Errorf("report lacks %q:\n%s", w, report)
		}
	}
	if strings.Contains(report, "@") {
		t.Fatal("the report names a user")
	}
}

// AC5 (F6-008): after the first import the parity line says imported and the report is not "not ready".
func TestVerify_AfterImportNoParityFailure(t *testing.T) {
	t.Parallel()
	res, report := verifyRun(t, `{"imported": true, "parity": "not_compared"}`, `{"report": {"unroled_users": 0}}`, nil)
	if res.ExitCode != 0 || !strings.Contains(report, "içe aktarıldı (Caddyfile tagcess'te") || strings.Contains(report, "uygulamaya hazır değil") {
		t.Fatalf("exit %d:\n%s", res.ExitCode, report)
	}
}

// AC7 (F6-008): every phase's guide items are in the report, in phases.yml order, with their check results.
func TestVerify_CollectsGuideItems(t *testing.T) {
	t.Parallel()
	guides := map[string]string{
		"g02":          `{"phase": "g02", "items": [{"id": "g02-confirm", "title": "G-02 onay bekliyor", "steps": [], "status": "pending"}]}`,
		"host":         `{"phase": "host", "items": [{"id": "h", "title": "Host adımı", "steps": [], "status": "done"}]}`,
		"zitadel_seed": `{"phase": "zitadel_seed", "items": [{"id": "z", "title": "Servis kullanıcısı", "steps": [], "status": "manual"}]}`,
	}
	res, report := verifyRun(t, equalPreview, `{"report": {"unroled_users": 0}}`, guides)
	if res.ExitCode != 0 {
		t.Fatal(res.Output)
	}
	z := strings.Index(report, "**zitadel_seed** · Servis kullanıcısı: elle kontrol et")
	h := strings.Index(report, "**host** · Host adımı: yapıldı")
	g := strings.Index(report, "**g02** · G-02 onay bekliyor: bekliyor")
	if z < 0 || h < 0 || g < 0 || z >= h || h >= g {
		t.Fatalf("guide items missing or out of phase order (%d %d %d):\n%s", z, h, g, report)
	}
}

// AC2 (F6-008, controller part): a parity difference ends the report with "uygulamaya hazır değil" and a non-zero
// exit; AC4 (controller part): the report lists the manual checks.
func TestVerify_ParityDiffReport(t *testing.T) {
	t.Parallel()
	res, report := verifyRun(t, `{"imported": false, "parity": "diff", "diff_count": 2, "first_diffs": ["/apps/x: today 1, generated 2"]}`,
		`{"report": {"unroled_users": 0}}`, nil)
	if res.ExitCode == 0 || !strings.Contains(res.Output, "uygulamaya hazır değil") || !strings.Contains(report, "uygulamaya hazır değil") {
		t.Fatalf("exit %d:\n%s", res.ExitCode, report)
	}
	if !strings.Contains(report, "FARK: 2 fark") || !strings.Contains(report, "(elle)") {
		t.Fatalf("report:\n%s", report)
	}
}

// s06Preview is -import-preview's report when only the accepted class differs (developer decision 2026-10-07).
const s06Preview = `{"imported": false, "parity": "accepted", "diff_count": 0, "seed_sites": 23, "manual_dns": [],
 "accepted": [
  {"class": "s06_open_start", "description": "S-06 açık başlangıç: kaynak kısıtı (tailnet + serbest kaynaklar, diğerleri 403) tagcess'te yok",
   "hosts": ["docs.c.example.test"], "open_reason": "transition", "today_sources": ["100.64.0.0/10", "10.8.0.0/24"]},
  {"class": "s06_open_start", "description": "S-06 açık başlangıç: kaynak kısıtı (tailnet + serbest kaynaklar, diğerleri 403) tagcess'te yok",
   "hosts": ["storage-api.c.example.test"], "open_reason": "intentional", "today_sources": ["100.64.0.0/10", "10.8.0.0/24"]}]}`

// The S-06 open start (developer decision 2026-10-07, [K] F6): verify is ready to apply, and the report, the run
// output and the verify guide carry a prominent warning: the internal sites become reachable from the internet
// until S-06 is closed, with the exact UI step to close it.
func TestVerify_S06OpenStartWarning(t *testing.T) {
	t.Parallel()
	res, report := verifyRunGuide(t, s06Preview)
	if res.ExitCode != 0 || strings.Contains(report, "uygulamaya hazır değil") {
		t.Fatalf("the accepted class alone is ready to apply: exit %d\n%s\n%s", res.ExitCode, report, res.Output)
	}
	warning := []string{"UYARI", "s06_open_start", "internetten de erişilebilir", "2 site", "docs.c.example.test", "storage-api.c.example.test",
		"/sites/settings", "Switch'i kapat", "Onayla ve apply et", "yalnız tailnet"}
	for _, w := range warning {
		if !strings.Contains(report, w) {
			t.Errorf("report lacks %q:\n%s", w, report)
		}
	}
	if w := strings.Index(report, "UYARI"); w < 0 || w > strings.Index(report, "## İlk içe aktarma paritesi") {
		t.Errorf("the warning must come before everything else in the report:\n%s", report)
	}
	if !strings.Contains(res.Output, "UYARI") || !strings.Contains(res.Output, "s06_open_start") {
		t.Errorf("the run output lacks the warning:\n%s", res.Output)
	}
	guide := res.Guide["verify.md"]
	for _, w := range []string{"S-06 açık başlangıç", "internetten de erişilebilir", "/sites/settings", "Switch'i kapat", "Onayla ve apply et", "(önemli)"} {
		if !strings.Contains(guide, w) {
			t.Errorf("verify guide lacks %q:\n%s", w, guide)
		}
	}
}

// Only the named class is accepted: an unknown accepted class is not ready to apply.
func TestVerify_UnknownAcceptedClassNotReady(t *testing.T) {
	t.Parallel()
	unknown := strings.ReplaceAll(s06Preview, `"class": "s06_open_start"`, `"class": "something_else"`)
	res, report := verifyRunGuide(t, unknown)
	if res.ExitCode == 0 || !strings.Contains(report, "uygulamaya hazır değil") {
		t.Fatalf("an unknown accepted class must not be ready: exit %d\n%s", res.ExitCode, report)
	}
}

type verifyGuideResult struct {
	adopttarget.Result
	Guide map[string]string
}

// verifyRunGuide is verifyRun that also returns the verify guide files.
func verifyRunGuide(t *testing.T, preview string) (verifyGuideResult, string) {
	t.Helper()
	home := t.TempDir()
	dir := t.TempDir()
	pf := filepath.Join(dir, "preview.json")
	_ = os.WriteFile(pf, []byte(preview), 0o600)
	_ = os.MkdirAll(envDir(home, "vtest"), 0o700)
	res := adopttarget.RunPlaybook(t, adopttarget.PlaybookOpts{Playbook: "testdata/verify.yml", Inventories: []string{localInventory(t)}, ConfigHome: home,
		Vars: map[string]any{"install_env": "vtest", "install_mode": "adopt", "tagcess_domain": "c.example.test", "verify_host_checks": false,
			"verify_preview_cmd": "cat " + pf, "verify_unroled_cmd": "", "verify_report_name": "report.md"}})
	report, _ := os.ReadFile(filepath.Join(envDir(home, "vtest"), "report.md")) // #nosec G304 -- test temp dir
	out := verifyGuideResult{Result: res, Guide: map[string]string{}}
	for _, name := range []string{"verify.md", "verify.json"} {
		b, _ := os.ReadFile(filepath.Join(envDir(home, "vtest"), "guide", name)) // #nosec G304 -- test temp dir
		out.Guide[name] = string(b)
	}
	return out, string(report)
}
