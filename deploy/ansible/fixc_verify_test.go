package installer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/test/adopttarget"
)

// fixC_goodProbe is what the host probes print on a healthy installation (F6-008 verify role).
var fixC_goodProbe = map[string]string{
	"tagcess_started": "1", "tagcess_errors": "0", "sock": "srw-rw---- 10001 caddy", "sock_code": "403", "healthz_code": "200", "hook_code": "401",
	"ui_code": "403", "ping_code": "200", "headscale": "active", "caddy": "active",
}

// fixC_verifyHealthRun runs the verify role with the host checks on, a canned probe output (the probe command is
// replaced) and the given parity preview; it returns the result and the report text.
func fixC_verifyHealthRun(t *testing.T, preview string, probe map[string]string, extra map[string]any) (adopttarget.Result, string) {
	t.Helper()
	home := t.TempDir()
	dir := t.TempDir()
	pf := filepath.Join(dir, "preview.json")
	if err := os.MkdirAll(filepath.Join(envDir(home, "vtest"), "guide"), 0o700); err != nil {
		t.Fatal(err)
	}
	probeFile := filepath.Join(dir, "probe.json")
	if err := os.WriteFile(pf, []byte(preview), 0o600); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	b.WriteString("{")
	i := 0
	for k, v := range probe {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%q: %q", k, v)
		i++
	}
	b.WriteString("}")
	if err := os.WriteFile(probeFile, []byte(strings.NewReplacer(`"1"`, "1", `"0"`, "0").Replace(b.String())), 0o600); err != nil {
		t.Fatal(err)
	}
	vars := map[string]any{"install_env": "vtest", "install_mode": "adopt", "tagcess_domain": "c.example.test", "verify_host_checks": true,
		"verify_probe_cmd": "cat " + probeFile, "verify_preview_cmd": "cat " + pf, "verify_unroled_cmd": "", "verify_report_name": "report.md"}
	for k, v := range extra {
		vars[k] = v
	}
	res := adopttarget.RunPlaybook(t, adopttarget.PlaybookOpts{Playbook: "testdata/verify.yml", Inventories: []string{localInventory(t)}, ConfigHome: home, Vars: vars})
	report, _ := os.ReadFile(filepath.Join(envDir(home, "vtest"), "report.md")) // #nosec G304 -- test temp dir
	return res, string(report)
}

// AC (F6-008, fix M4): a failing mandatory security/health probe ends the run non-zero even when the parity is equal or
// imported; the report is still written and marks the check.
func TestVerify_FailedHealthCheckFailsRun(t *testing.T) {
	t.Parallel()
	previews := map[string]string{
		"equal":    `{"imported": false, "parity": "equal", "diff_count": 0}`,
		"imported": `{"imported": true, "parity": "not_compared"}`,
	}
	for pname, preview := range previews {
		t.Run(pname+"/healthy", func(t *testing.T) {
			t.Parallel()
			res, report := fixC_verifyHealthRun(t, preview, fixC_goodProbe, nil)
			checks, _, _ := strings.Cut(report, "## Rolsüz")
			if res.ExitCode != 0 || !strings.Contains(checks, "## Kontroller") || strings.Contains(checks, "- [ ]") {
				t.Fatalf("a healthy host must pass (exit %d):\n%s\n%s", res.ExitCode, fixC_tail(res.Output, 20), report)
			}
		})
		for _, c := range []struct{ name, key, bad, check string }{
			{"healthz-down", "healthz_code", "503", "Soket /healthz 200 (başlıksız)"},
			{"hook-not-401", "hook_code", "200", "İmzasız hook POST 401"},
			{"socket-not-403", "sock_code", "200", "Başlıksız soket isteği 403"},
			{"ui-not-403", "ui_code", "200", "Tailnet dışı kaynaktan arayüz 403"},
			{"ping-down", "ping_code", "000", "oauth2-proxy /ping 200"},
			{"errors-in-log", "tagcess_errors", "3", "tagcess başladı, ERROR yok"},
			{"not-started", "tagcess_started", "0", "tagcess başladı, ERROR yok"},
			{"socket-mode", "sock", "srw-rw-rw- 10001 caddy", "ui.sock srw-rw---- 10001 caddy"},
			{"headscale-down", "headscale", "inactive", "headscale ve caddy çalışıyor"},
			{"caddy-down", "caddy", "failed", "headscale ve caddy çalışıyor"},
		} {
			t.Run(pname+"/"+c.name, func(t *testing.T) {
				t.Parallel()
				probe := map[string]string{}
				for k, v := range fixC_goodProbe {
					probe[k] = v
				}
				probe[c.key] = c.bad
				res, report := fixC_verifyHealthRun(t, preview, probe, nil)
				if res.ExitCode == 0 {
					t.Fatalf("a failed %q check must fail the run:\n%s", c.check, fixC_tail(res.Output, 20))
				}
				if !strings.Contains(res.Output, "sağlık/güvenlik kontrolü başarısız") || !strings.Contains(res.Output, c.check) {
					t.Fatalf("the failure does not name the check %q:\n%s", c.check, fixC_tail(res.Output, 20))
				}
				if !strings.Contains(report, "- [ ] "+c.check) {
					t.Fatalf("the report was not written or lacks the open check %q:\n%s", c.check, report)
				}
			})
		}
	}
	// verify_strict: false only relaxes the parity gate; a failed health check still fails.
	t.Run("lax-still-fails-on-health", func(t *testing.T) {
		t.Parallel()
		probe := map[string]string{}
		for k, v := range fixC_goodProbe {
			probe[k] = v
		}
		probe["hook_code"] = "200"
		res, _ := fixC_verifyHealthRun(t, previews["equal"], probe, map[string]any{"verify_strict": false})
		if res.ExitCode == 0 {
			t.Fatal("verify_strict=false must not hide a failed health check")
		}
	})
}

func fixC_tail(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
