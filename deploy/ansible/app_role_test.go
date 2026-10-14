//go:build installer

package installer

import (
	"strings"
	"testing"

	"github.com/nesiler/tagcess/test/adopttarget"
)

func dryRun(t *testing.T, tg *adopttarget.Target) string {
	t.Helper()
	return strings.TrimSpace(tg.Sh(t, `setpriv --reuid 10001 --regid 10001 --clear-groups sqlite3 -readonly /var/lib/tagcess/tagcess.db "select value from settings where key='dry_run'"`))
}

// AC17, AC16, AC15 (F6-005): host + hshelper + app on the adopt shape start tagcess for real ("tagcess started",
// ui.sock srw-rw---- 10001 caddy), a new database starts in dry-run, the second run changes nothing; an existing
// installation's dry-run setting survives a config change; a config that fails tagcess -check replaces neither the
// running config nor the container.
func TestAppRole_StartsAndIdempotent(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	vars := appVars(t, tg)
	home := t.TempDir()
	mustRun(t, tg, home, vars, nil, "host", "hshelper", "app")
	tg.Sh(t, "docker logs tagcess 2>&1 | grep -q 'tagcess started'")
	if got := strings.TrimSpace(tg.Sh(t, "stat -c '%A %u %G' /run/tagcess/ui.sock")); got != "srw-rw---- 10001 caddy" {
		t.Fatalf("ui.sock: %q", got)
	}
	noChanges(t, tg, mustRun(t, tg, home, vars, nil, "app"))

	t.Run("TestAppRole_FirstInstallDryRunOn", func(t *testing.T) {
		if got := dryRun(t, tg); got != "true" {
			t.Fatalf("dry_run %q on a first install, want true (Y-06.2)", got)
		}
		// The operator turned dry-run off in the UI; a later config change keeps it off.
		tg.Sh(t, `docker stop tagcess >/dev/null && setpriv --reuid 10001 --regid 10001 --clear-groups sqlite3 /var/lib/tagcess/tagcess.db "update settings set value='false' where key='dry_run'" && docker start tagcess >/dev/null`)
		changed := adopttarget.Merge(vars, map[string]any{"app_sync_interval": "6m"})
		mustRun(t, tg, home, changed, nil, "app")
		tg.Sh(t, "grep -q 'interval: 6m' /etc/tagcess/config.yaml")
		if got := dryRun(t, tg); got != "false" {
			t.Fatalf("dry_run %q after a config change, want the operator's false", got)
		}
	})
	t.Run("TestAppRole_CheckGateKeepsLastGood", func(t *testing.T) {
		before := tg.Sh(t, "sha256sum /etc/tagcess/config.yaml; docker inspect -f '{{.Id}} {{.State.StartedAt}}' tagcess")
		bad := adopttarget.Merge(vars, map[string]any{"zitadel_issuer": "http://not-https.example.test"})
		res := runSite(t, tg, home, bad, nil, "app")
		if res.ExitCode == 0 || !strings.Contains(res.Output, "tagcess -check'ten geçmedi") {
			t.Fatalf("want the check gate to stop:\n%s", res.Output)
		}
		if after := tg.Sh(t, "sha256sum /etc/tagcess/config.yaml; docker inspect -f '{{.Id}} {{.State.StartedAt}}' tagcess"); after != before {
			t.Fatalf("config or container changed: %q -> %q", before, after)
		}
		if _, err := tg.ShErr("test ! -e /etc/tagcess/config.yaml.candidate"); err != nil {
			t.Fatal("the failed candidate was left behind")
		}
	})
}
