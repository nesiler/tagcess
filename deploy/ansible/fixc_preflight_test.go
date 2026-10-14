//go:build installer

package installer

import (
	"testing"

	"github.com/nesiler/tagcess/test/adopttarget"
)

// Fix H4 (F6-002): a running Caddy whose live config cannot be read (admin API unreachable) leaves the disk/live
// parity unproven, so it is a blocker: no writing phase may run (fail safe, rule 7).
func TestPreflight_BlocksWhenRunningCaddyConfigUnreadable(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	vars := adopttarget.Merge(adopttarget.AdoptVars(), map[string]any{"caddy_admin_url": "http://127.0.0.1:1"})
	tg.Sh(t, "systemctl is-active -q caddy")
	home := t.TempDir()
	res := runSite(t, tg, home, vars, nil, "preflight")
	p, _ := readPreflight(t, home, "adopttest")
	if res.ExitCode == 0 || !hasBlocker(p, "çalışan config okunamadı") {
		t.Fatalf("want the unreadable-running-config blocker, got exit %d blockers %v warnings %v", res.ExitCode, p.Blockers, p.Warnings)
	}
	mustNotRunWritingPhase(t, tg, home, vars, nil)
}
