//go:build installer

package installer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/test/adopttarget"
)

// AC7 (F6-005): without confirm_host_system=yes nothing changes; the plan is shown and a guide item waits.
func TestHostSystem_NeedsConfirm(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	tg.WriteFile(t, "/etc/caddy/cf.env", "CF_API_TOKEN=HOSTSYSTEM-MARKER-1\n", "0600", "root:root")
	before := tg.Checksums(t, hostRoots)
	home := t.TempDir()
	res := mustRun(t, tg, home, adopttarget.AdoptVars(), nil, "host_system")
	if d := adopttarget.DiffChecksums(before, tg.Checksums(t, hostRoots)); len(d) > 0 {
		t.Fatalf("changed without confirmation:\n%s", strings.Join(d, "\n"))
	}
	for _, w := range []string{"host_system onay bekliyor", "preserve.conf", "cf.env"} {
		if !strings.Contains(res.Output, w) {
			t.Errorf("plan lacks %q", w)
		}
	}
	g, _ := os.ReadFile(filepath.Join(envDir(home, "adopttest"), "guide", "host_system.json")) // #nosec G304 -- test temp dir
	if !strings.Contains(string(g), "host-system-confirm") {
		t.Fatalf("guide: %s", g)
	}
}

// AC8, AC9, AC10 (F6-005): confirmed: the drop-in is installed with a daemon-reload and no Headscale restart (the next
// manual restart keeps /var/run/headscale's inode); the token moves byte for byte to /etc/caddy-secrets 0600 and
// Caddy validates and reloads; nothing is shown; the second run changes nothing.
func TestHostSystem_PreserveDropInNoRestart(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	token := "CF_API_TOKEN=HOSTSYSTEM-MARKER-2a7c\n"
	tg.WriteFile(t, "/etc/caddy/cf.env", token, "0600", "root:root")
	started := tg.Sh(t, "systemctl show headscale -p ActiveEnterTimestamp --value")
	home := t.TempDir()
	yes := map[string]string{"confirm_host_system": "yes"}
	res := mustRun(t, tg, home, adopttarget.AdoptVars(), yes, "host_system")
	if strings.Contains(res.Output, "HOSTSYSTEM-MARKER") {
		t.Fatal("the token content reached the output")
	}
	if after := tg.Sh(t, "systemctl show headscale -p ActiveEnterTimestamp --value"); after != started {
		t.Fatalf("Headscale was restarted: %s -> %s", started, after)
	}
	ref, err := os.ReadFile(filepath.Join(adopttarget.RepoRoot(), "deploy", "headscale-preserve.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if got := tg.ReadFile(t, "/etc/systemd/system/headscale.service.d/preserve.conf"); got != string(ref) {
		t.Fatal("the drop-in is not deploy/headscale-preserve.conf")
	}
	tg.Sh(t, "systemctl show headscale -p DropInPaths --value | grep -q preserve.conf")
	if got := strings.TrimSpace(tg.Sh(t, "stat -c '%a %u %G' /etc/caddy")); got != "755 10001 caddy" {
		t.Errorf("/etc/caddy: %q", got)
	}

	t.Run("inode survives the next restart", func(t *testing.T) {
		inode := tg.Sh(t, "stat -c %i /var/run/headscale")
		tg.Sh(t, "systemctl restart headscale && sleep 2")
		if got := tg.Sh(t, "stat -c %i /var/run/headscale"); got != inode {
			t.Fatalf("/var/run/headscale inode %s -> %s", inode, got)
		}
	})
	t.Run("TestHostSystem_TokenMovedByteExact", func(t *testing.T) {
		if _, err := tg.ShErr("test ! -e /etc/caddy/cf.env"); err != nil {
			t.Fatal("the token is still in /etc/caddy")
		}
		if got := tg.ReadFile(t, "/etc/caddy-secrets/cf.env"); got != token {
			t.Fatal("the moved token is not byte-exact")
		}
		if got := strings.TrimSpace(tg.Sh(t, "stat -c '%a %U' /etc/caddy-secrets/cf.env /etc/caddy-secrets")); got != "600 root\n700 root" {
			t.Fatalf("modes: %q", got)
		}
		tg.Sh(t, "systemctl show caddy -p EnvironmentFiles --value | grep -q /etc/caddy-secrets/cf.env && systemctl is-active -q caddy")
	})
	t.Run("TestHostSystem_Idempotent", func(t *testing.T) {
		noChanges(t, tg, mustRun(t, tg, home, adopttarget.AdoptVars(), yes, "host_system"))
	})
}
