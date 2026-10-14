//go:build installer

package installer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/test/adopttarget"
)

// unmanagedRoots are the untouchables of the adopt shape (Headplane, WireGuard): never changed by the installer.
var unmanagedRoots = []string{"/etc/headplane", "/etc/wireguard", "/etc/systemd/system/wireguard-ui.service", "/var/lib/headplane"}

// installAll runs the whole adopt sequence like install.sh: every phase with its confirmation, then g02 on its own
// with the policy hash read at that time.
func installAll(t *testing.T, tg *adopttarget.Target, home string, f fullAdopt, over map[string]any) adopttarget.Result {
	t.Helper()
	res := runFull(t, tg, home, f, over, confirmAll)
	if res.ExitCode != 0 {
		return res
	}
	sha := strings.Fields(tg.Sh(t, "sha256sum /etc/headscale/policy.hujson"))[0]
	g02 := runFull(t, tg, home, f, over, map[string]string{"confirm_g02": "yes", "expected_policy_sha256": sha}, "g02")
	// The verify phase ran in the first run: keep both outputs so the assertions see its parity line and warning.
	g02.Output = res.Output + "\n" + g02.Output
	return g02
}

// AC1 (F6-010): the whole adopt sequence on the adopt shape ends with verify parity 0 apart from the one accepted
// class (developer decision 2026-10-07: s06_open_start, all 20 open sites, reported with its warning), without
// changing the Caddy role snippet or the 20 site files, and without touching Headplane/WireGuard.
func TestSiteYml_AdoptEndToEndOnAdoptShape(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	f := fullAdoptSetup(t, tg)
	sites := tg.Checksums(t, []string{"/etc/caddy/sites"}, "/etc/caddy/sites/tagcess.caddy")
	snippet := tg.Sh(t, "sed -n '/^(rol_kontrolu) {/,/^}/p' /etc/caddy/Caddyfile")
	unmanaged := tg.Checksums(t, unmanagedRoots)
	home := t.TempDir()
	res := installAll(t, tg, home, f, nil)
	if res.ExitCode != 0 {
		t.Fatalf("the adopt run did not finish (verify parity must be 0 apart from s06_open_start):\n%s\n%s", tail(res.Output, 60), verifyReports(t, home))
	}
	if !strings.Contains(res.Output, "Parite: kabul edilen fark s06_open_start (20 site), başka fark yok") {
		t.Fatalf("verify did not report parity 0 apart from the accepted class on the 20 sites:\n%s", tail(res.Output, 40))
	}
	if !strings.Contains(res.Output, "UYARI: İlk içe aktarmadan sonra bu 20 site internetten de erişilebilir") ||
		!strings.Contains(res.Output, "/sites/settings") {
		t.Fatalf("verify did not warn about the S-06 open start:\n%s", tail(res.Output, 40))
	}
	if d := adopttarget.DiffChecksums(sites, tg.Checksums(t, []string{"/etc/caddy/sites"}, "/etc/caddy/sites/tagcess.caddy")); len(d) > 0 {
		t.Errorf("site files changed:\n%s", strings.Join(d, "\n"))
	}
	if got := tg.Sh(t, "sed -n '/^(rol_kontrolu) {/,/^}/p' /etc/caddy/Caddyfile"); got != snippet {
		t.Errorf("the role snippet changed")
	}
	if d := adopttarget.DiffChecksums(unmanaged, tg.Checksums(t, unmanagedRoots)); len(d) > 0 {
		t.Errorf("Headplane/WireGuard changed:\n%s", strings.Join(d, "\n"))
	}
}

// verifyReports returns the verify reports written under home (the first differences), for a failure message.
func verifyReports(t *testing.T, home string) string {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(home, "*", "*", "report-*.md"))
	var b strings.Builder
	for _, f := range files {
		body, err := os.ReadFile(f) // #nosec G304 -- test temp dir
		if err == nil {
			b.WriteString("--- " + filepath.Base(f) + "\n" + string(body))
		}
	}
	return b.String()
}

func tail(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) <= n {
		return s
	}
	return strings.Join(lines[len(lines)-n:], "\n")
}

// AC2, AC3, AC4 (F6-010): after the whole adopt sequence (parity reported, not enforced here: that is AC1) a second run
// reports changed=0; rollback.yml with confirm_remove_data=yes returns the host to its pre-install checksums (backup
// directory aside) with Headscale and Caddy running, and never touches Headplane/WireGuard.
func TestSiteYml_SecondRunNoChanges(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	f := fullAdoptSetup(t, tg)
	lax := map[string]any{"verify_strict": false}
	// The pre-install state: everything a rollback must give back (volatile runtime paths and the backup dir aside).
	roots := []string{"/etc", "/var/lib", "/run", "/usr/local/bin"}
	before := tg.Checksums(t, roots, "/var/backups")
	unmanaged := tg.Checksums(t, unmanagedRoots)
	home := t.TempDir()
	if res := installAll(t, tg, home, f, lax); res.ExitCode != 0 {
		t.Fatalf("install:\n%s", tail(res.Output, 60))
	}
	second := runFull(t, tg, home, f, lax, confirmAll)
	if second.ExitCode != 0 {
		t.Fatalf("second run:\n%s", tail(second.Output, 60))
	}
	noChanges(t, tg, second)

	t.Run("TestRollback_ReturnsToPreInstall", func(t *testing.T) {
		res := adopttarget.RunPlaybook(t, adopttarget.PlaybookOpts{Playbook: "rollback.yml", Inventories: []string{tg.Inventory}, ConfigHome: home,
			Vars: adopttarget.Merge(f.Vars, lax), ExtraVars: map[string]string{"confirm_remove_data": "yes"}, Env: f.Env})
		if res.ExitCode != 0 {
			t.Fatalf("rollback:\n%s", tail(res.Output, 60))
		}
		after := tg.Checksums(t, roots, "/var/backups")
		if d := adopttarget.DiffChecksums(before, after); len(d) > 0 {
			t.Fatalf("not back to the pre-install state:\n%s", strings.Join(d, "\n"))
		}
		tg.Sh(t, `systemctl is-active -q headscale && systemctl is-active -q caddy && test "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/health)" = 200`)
	})
	t.Run("TestRollback_NeverTouchesUnmanaged", func(t *testing.T) {
		if d := adopttarget.DiffChecksums(unmanaged, tg.Checksums(t, unmanagedRoots)); len(d) > 0 {
			t.Fatalf("Headplane/WireGuard changed:\n%s", strings.Join(d, "\n"))
		}
		tg.Sh(t, "systemctl is-enabled -q wireguard-ui")
	})
}
