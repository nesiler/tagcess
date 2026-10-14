//go:build installer

package adopttarget

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fixtureRoots are the files the adopt shape is made of (TestAdoptTarget_ResetIsDeterministic).
var fixtureRoots = []string{"/etc/caddy", "/etc/headscale", "/etc/oauth2-proxy", "/etc/letsencrypt", "/etc/headplane",
	"/etc/wireguard", "/etc/systemd/system/oauth2-proxy.service", "/etc/systemd/system/wireguard-ui.service"}

// AC5 (F6-001): the adopt shape matches the existing installation's vpn-host and writes its connection details outside the repo.
func TestAdoptTarget_UpMatchesAdoptShape(t *testing.T) {
	tg := Up(t, "adopt")
	if strings.HasPrefix(tg.State, RepoRoot()) {
		t.Fatalf("state dir %s is inside the repo", tg.State)
	}
	for _, f := range []string{"target.env", "inventory.yml", "id_ed25519"} {
		if _, err := os.Stat(filepath.Join(tg.State, f)); err != nil {
			t.Fatalf("%s missing in the state dir: %v", f, err)
		}
	}
	checks := map[string]string{
		"headscale configtest":    "headscale configtest >/dev/null 2>&1",
		"headscale 0.29.4":        "headscale version | grep -q v0.29.4",
		"caddy validate":          "caddy validate --config /etc/caddy/Caddyfile >/dev/null 2>&1",
		"caddy 2.8.4":             "caddy version | grep -q '^v2.8.4'",
		"policy file mode":        "grep -Eq '^ +mode: +file' /etc/headscale/config.yaml",
		"extra_records_path":      "grep -q 'extra_records_path: /etc/headscale/extra-records.json' /etc/headscale/config.yaml",
		"oauth2-proxy stopped":    "! systemctl is-active -q oauth2-proxy",
		"oauth2-proxy _vpn_auth":  "grep -q '_vpn_auth' /etc/oauth2-proxy/oauth2-proxy.cfg && grep -q 'cookie_expire = \"12h\"' /etc/oauth2-proxy/oauth2-proxy.cfg",
		"20 site files":           "test $(ls /etc/caddy/sites/*.caddy | wc -l) -eq 20",
		"11 vpn_site":             "test $(grep -l 'import vpn_site ' /etc/caddy/sites/*.caddy | wc -l) -eq 11",
		"5 vpn_site_api":          "test $(grep -l 'import vpn_site_api ' /etc/caddy/sites/*.caddy | wc -l) -eq 5",
		"4 vpn_only":              "test $(grep -l 'import vpn_only ' /etc/caddy/sites/*.caddy | wc -l) -eq 4",
		"role check suspended":    "grep -A2 '^(rol_kontrolu) {' /etc/caddy/Caddyfile | grep -q 'import k8s'",
		"import sites":            "grep -q '^import sites/\\*.caddy' /etc/caddy/Caddyfile",
		"three cert groups":       "for n in internal.a.example.test b.example.test c.example.test; do test -s /etc/letsencrypt/live/$n/fullchain.pem || exit 1; done",
		"headplane present":       "test -f /etc/headplane/config.yaml",
		"wireguard present":       "test -d /etc/wireguard && systemctl is-enabled -q wireguard-ui",
		"tagged tailnet node":     "tailscale ip -4 | grep -q '^100\\.'",
		"docker":                  "docker info >/dev/null 2>&1",
		"21 MagicDNS records":     "test $(grep -c '\"name\"' /etc/headscale/extra-records.json) -eq 21",
		"headscale and caddy run": "systemctl is-active -q headscale && systemctl is-active -q caddy",
	}
	for name, script := range checks {
		if out, err := tg.ShErr(script); err != nil {
			t.Errorf("%s: %v\n%s", name, err, out)
		}
	}
	// ssh with the generated key (the Ansible connection).
	out, err := exec.Command("ssh", "-i", tg.SSHKey, "-p", tg.SSHPort, "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
		"-o", "IdentityAgent=none", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
		"root@127.0.0.1", "python3 -c 'print(42)'").CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "42" {
		t.Fatalf("ssh + python3: %v %s", err, out)
	}
}

// AC6 (F6-001): down removes the container, its temporary directory and the ssh key.
func TestAdoptTarget_DownCleans(t *testing.T) {
	tg := Up(t, "bare")
	key := tg.SSHKey
	tg.Down(t)
	if out, err := exec.Command("docker", "inspect", tg.Name).CombinedOutput(); err == nil {
		t.Fatalf("container %s still exists: %s", tg.Name, out)
	}
	for _, p := range []string{tg.State, key} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("%s still exists after down (err %v)", p, err)
		}
	}
}

// AC7 (F6-001): two ups in a row replace the container and produce the same starting files.
func TestAdoptTarget_ResetIsDeterministic(t *testing.T) {
	name := "tagcess-at-reset-" + randHex(4)
	first := UpNamed(t, "adopt", name)
	sumsA := first.Checksums(t, fixtureRoots)
	first.Sh(t, "echo drift >>/etc/caddy/sites/monitor.c.example.test.caddy")
	second := UpNamed(t, "adopt", name)
	if _, err := os.Stat(first.State); !os.IsNotExist(err) {
		t.Fatalf("the first run's state dir %s was not removed", first.State)
	}
	sumsB := second.Checksums(t, fixtureRoots)
	if len(sumsA) < 40 {
		t.Fatalf("only %d fixture paths were measured", len(sumsA))
	}
	if d := DiffChecksums(sumsA, sumsB); len(d) > 0 {
		t.Fatalf("the second up does not reproduce the first:\n%s", strings.Join(d, "\n"))
	}
}

// AC8 (F6-001): the bare shape has none of the components, and ssh + Python 3 work.
func TestAdoptTarget_BareHasNoComponents(t *testing.T) {
	tg := Up(t, "bare")
	for _, c := range []string{"headscale", "caddy", "oauth2-proxy", "docker", "tailscale", "tailscaled", "certbot"} {
		if out, err := tg.ShErr("command -v " + c); err == nil {
			t.Errorf("%s is installed in the bare shape: %s", c, out)
		}
	}
	for _, unit := range []string{"headscale", "caddy", "oauth2-proxy", "docker", "tailscaled"} {
		if out, _ := tg.ShErr("systemctl list-unit-files " + unit + ".service --no-legend | wc -l"); strings.TrimSpace(out) != "0" {
			t.Errorf("unit %s exists in the bare shape", unit)
		}
	}
	tg.Sh(t, "systemctl is-active -q ssh && python3 -c 'import sys'")
	res := RunPlaybook(t, PlaybookOpts{Playbook: "testdata/ping.yml", Inventories: []string{tg.Inventory}})
	if res.ExitCode != 0 || res.Recap[tg.Name].Ok == 0 {
		t.Fatalf("ansible cannot reach the bare target:\n%s", res.Output)
	}
}
