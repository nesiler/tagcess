//go:build installer

package installer

import (
	"strings"
	"testing"

	"github.com/nesiler/tagcess/test/adopttarget"
)

// AC11, AC13 (F6-005): the helper is built, verified and installed through deploy/hshelper/install.sh: binary, three
// units, the .path unit enabled, status.json published; the second run changes nothing and Headscale is never
// restarted.
func TestHshelperRole_InstallsAndPublishesStatus(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	started := tg.Sh(t, "systemctl show headscale -p ActiveEnterTimestamp --value")
	home := t.TempDir()
	mustRun(t, tg, home, adopttarget.AdoptVars(), nil, "hshelper")
	tg.Sh(t, `set -e
		test -x /usr/local/bin/tagcess-hshelper
		for u in tagcess-hshelper.path tagcess-hshelper.service tagcess-hshelper-boot.service; do test -f /etc/systemd/system/$u; done
		systemctl is-enabled -q tagcess-hshelper.path && systemctl is-active -q tagcess-hshelper.path
		test -s /var/lib/tagcess-headscale/results/status.json
		grep -q -- '--request-uid 10001' /etc/systemd/system/tagcess-hshelper.service
		test "$(stat -c '%a %U' /var/lib/tagcess-headscale/private)" = "700 root"`)
	if _, err := tg.ShErr("test ! -e /var/lib/tagcess-install/hshelper-stage"); err != nil {
		t.Fatal("the stage directory was left behind")
	}
	t.Run("TestHshelperRole_IdempotentNoRestart", func(t *testing.T) {
		noChanges(t, tg, mustRun(t, tg, home, adopttarget.AdoptVars(), nil, "hshelper"))
		if after := tg.Sh(t, "systemctl show headscale -p ActiveEnterTimestamp --value"); after != started {
			t.Fatalf("Headscale was restarted: %s -> %s", started, after)
		}
	})
}

// AC12 (F6-005): a sha256 that does not match the binary stops before any file changes.
func TestHshelperRole_ShaMismatchStops(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	before := tg.Checksums(t, hostRoots)
	vars := adopttarget.Merge(adopttarget.AdoptVars(), map[string]any{"hshelper_sha256": strings.Repeat("0", 64)})
	res := runSite(t, tg, t.TempDir(), vars, nil, "hshelper")
	if res.ExitCode == 0 || !strings.Contains(res.Output, "hiçbir dosya değiştirilmedi") {
		t.Fatalf("want a sha256 stop:\n%s", res.Output)
	}
	if d := adopttarget.DiffChecksums(before, tg.Checksums(t, hostRoots)); len(d) > 0 {
		t.Fatalf("files changed:\n%s", strings.Join(d, "\n"))
	}
}
