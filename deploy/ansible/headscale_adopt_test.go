//go:build installer

package installer

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/test/adopttarget"
)

const hookRule = `{"action": "accept", "src": ["tag:k8s"], "dst": ["tag:vpn-server:9443"]}`

// AC1, AC2 (F6-007): without confirm_hs_hook_acl the policy file stays; confirmed, the rule is added once, checked,
// reloaded and served by `headscale policy get`; a second run adds nothing.
func TestHeadscaleAdopt_HookACLNeedsConfirm(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	home := t.TempDir()
	before := tg.Sh(t, "sha256sum /etc/headscale/policy.hujson")
	mustRun(t, tg, home, adopttarget.AdoptVars(), nil, "hs_hook_acl")
	if after := tg.Sh(t, "sha256sum /etc/headscale/policy.hujson"); after != before {
		t.Fatal("the policy changed without confirmation")
	}
	t.Run("TestHeadscaleAdopt_HookACLAddedOnceChecked", func(t *testing.T) {
		yes := map[string]string{"confirm_hs_hook_acl": "yes"}
		mustRun(t, tg, home, adopttarget.AdoptVars(), yes, "hs_hook_acl")
		if n := strings.Count(tg.ReadFile(t, "/etc/headscale/policy.hujson"), hookRule); n != 1 {
			t.Fatalf("rule count %d", n)
		}
		if !strings.Contains(tg.Sh(t, "headscale policy get"), hookRule) {
			t.Fatal("the running policy lacks the rule")
		}
		tg.Sh(t, "test \"$(stat -c '%a %U' /etc/headscale/policy.hujson)\" = '644 root' && ! test -e /etc/headscale/policy.hujson.candidate")
		noChanges(t, tg, mustRun(t, tg, home, adopttarget.AdoptVars(), yes, "hs_hook_acl"))
		if n := strings.Count(tg.ReadFile(t, "/etc/headscale/policy.hujson"), hookRule); n != 1 {
			t.Fatalf("rule count %d after the second run", n)
		}
	})
}

// AC3 (F6-007): a candidate that fails `headscale policy check` leaves the file and does not reload.
func TestHeadscaleAdopt_HookACLInvalidKeepsOld(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	before := tg.Sh(t, "sha256sum /etc/headscale/policy.hujson; systemctl show headscale -p ExecMainStartTimestamp --value")
	vars := adopttarget.Merge(adopttarget.AdoptVars(), map[string]any{"hs_hook_src": "tag:undefined-owner"})
	res := runSite(t, tg, t.TempDir(), vars, map[string]string{"confirm_hs_hook_acl": "yes"}, "hs_hook_acl")
	if res.ExitCode == 0 || !strings.Contains(res.Output, "Aday policy headscale policy check'ten geçmedi") {
		t.Fatalf("want a check stop:\n%s", res.Output)
	}
	if after := tg.Sh(t, "sha256sum /etc/headscale/policy.hujson; systemctl show headscale -p ExecMainStartTimestamp --value"); after != before {
		t.Fatal("policy or Headscale changed")
	}
	if strings.Contains(res.Output, "Headscale reloads the policy") && !strings.Contains(res.Output, "skipping") {
		t.Fatal("reloaded")
	}
}

// AC4 (F6-007): the DNS path moves to tagcess's file only when both hold the same records; configtest, restart and
// health follow.
func TestHeadscaleAdopt_DNSPathSwitchKeepsRecords(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	vars, _ := hostVars(t)
	home := t.TempDir()
	mustRun(t, tg, home, vars, nil, "host")
	yes := map[string]string{"confirm_hs_dns_path": "yes"}
	// Different records: refused, nothing changes.
	tg.Sh(t, `echo '[]' > /var/lib/tagcess/dns/extra-records.json`)
	cfg := tg.Sh(t, "sha256sum /etc/headscale/config.yaml")
	res := runSite(t, tg, home, vars, yes, "hs_dns_path")
	if res.ExitCode == 0 || !strings.Contains(res.Output, "kayıtları") || tg.Sh(t, "sha256sum /etc/headscale/config.yaml") != cfg {
		t.Fatalf("different records must stop the switch:\n%s", res.Output)
	}
	tg.Sh(t, "cp /etc/headscale/extra-records.json /var/lib/tagcess/dns/extra-records.json && chown 10001:headscale /var/lib/tagcess/dns/extra-records.json")
	mustRun(t, tg, home, vars, yes, "hs_dns_path")
	tg.Sh(t, `set -e
		grep -q 'extra_records_path: /var/lib/tagcess/dns/extra-records.json' /etc/headscale/config.yaml
		systemctl is-active -q headscale
		test "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/health)" = 200
		runuser -u headscale -- headscale configtest >/dev/null 2>&1`)
	noChanges(t, tg, mustRun(t, tg, home, vars, yes, "hs_dns_path"))
}

// AC5 (F6-007): the expected node tags are reported; a missing one is applied only with confirm_hs_tags=yes.
func TestHeadscaleAdopt_TagsVerifiedNotForced(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	// A second, untagged node named like the k8s host (userspace tailscaled; the real one is never reached).
	tg.Sh(t, `set -e
		mkdir -p /var/lib/ts2
		systemd-run --unit=ts2 tailscaled --tun=userspace-networking --state=/var/lib/ts2/tailscaled.state --socket=/run/ts2.sock --port=41642
		headscale users create k8s >/dev/null
		uid=$(headscale users list -o json | python3 -c 'import json,sys;print([u["id"] for u in json.load(sys.stdin) if u["name"]=="k8s"][0])')
		key=$(headscale preauthkeys create --user "$uid" --expiration 10m 2>/dev/null | tail -1)
		sleep 2
		tailscale --socket=/run/ts2.sock up --login-server http://127.0.0.1:8080 --authkey "$key" --hostname k8s-host-like --accept-dns=false >/dev/null`)
	vars := adopttarget.Merge(adopttarget.AdoptVars(), map[string]any{"hs_k8s_node": "k8s-host-like"})
	home := t.TempDir()
	res := mustRun(t, tg, home, vars, nil, "hs_tags")
	if !strings.Contains(res.Output, "k8s-host-like tag:k8s False") || !strings.Contains(res.Output, "vpn-host-like tag:vpn-server True") {
		t.Fatalf("report:\n%s", res.Output)
	}
	if strings.Contains(tg.Sh(t, "headscale nodes list -o json"), `"tag:k8s"`) {
		t.Fatal("a tag was applied without confirmation")
	}
	mustRun(t, tg, home, vars, map[string]string{"confirm_hs_tags": "yes"}, "hs_tags")
	if !strings.Contains(tg.Sh(t, "headscale nodes list -o json"), `"tag:k8s"`) {
		t.Fatal("the confirmed tag was not applied")
	}
	if !strings.Contains(tg.ReadFile(t, "/var/lib/tagcess-install/state.json"), "k8s-host-like") {
		t.Fatal("the added tag is not recorded for rollback")
	}
}

func headscaleStart(t *testing.T, tg *adopttarget.Target) string {
	t.Helper()
	return tg.Sh(t, "systemctl show headscale -p ExecMainStartTimestamp --value")
}

// AC6 (F6-007): without confirm_g02=yes and the matching expected_policy_sha256 Headscale is not stopped and nothing
// changes.
func TestG02_RequiresConfirmAndHash(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	before := tg.Checksums(t, []string{"/etc/headscale"})
	started := headscaleStart(t, tg)
	for _, extra := range []map[string]string{
		nil,
		{"confirm_g02": "yes"},
		{"confirm_g02": "yes", "expected_policy_sha256": strings.Repeat("a", 64)},
	} {
		res := runSite(t, tg, t.TempDir(), adopttarget.AdoptVars(), extra, "g02")
		if extra != nil && (res.ExitCode == 0 || !strings.Contains(res.Output, "Headscale durdurulmadı")) {
			t.Fatalf("%v: want a stop:\n%s", extra, res.Output)
		}
		if d := adopttarget.DiffChecksums(before, tg.Checksums(t, []string{"/etc/headscale"})); len(d) > 0 || headscaleStart(t, tg) != started {
			t.Fatalf("%v: changed %v", extra, d)
		}
	}
}

func policySHA(t *testing.T, tg *adopttarget.Target) string {
	t.Helper()
	return strings.Fields(tg.Sh(t, "sha256sum /etc/headscale/policy.hujson"))[0]
}

// AC7, AC10 (F6-007): the confirmed switch ends in database mode with `headscale policy get` equal to the file; a
// second run says "already database" and changes nothing.
func TestG02_SwitchesWithEqualPolicy(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	extra := map[string]string{"confirm_g02": "yes", "expected_policy_sha256": policySHA(t, tg)}
	home := t.TempDir()
	mustRun(t, tg, home, adopttarget.AdoptVars(), extra, "g02")
	tg.Sh(t, `set -e
		grep -Eq '^[[:space:]]+mode: database' /etc/headscale/config.yaml
		! grep -Eq '^[[:space:]]+mode: file' /etc/headscale/config.yaml
		headscale policy get > /tmp/db-policy
		test ! -e /etc/headscale/config.g02-candidate.yaml && test ! -e /etc/headscale/config.yaml.tagcess-prev
		test "$(stat -c '%a %U' /etc/headscale/config.yaml)" = "644 root"`)
	// Headscale stores the policy with comments blanked: the same policy, compared by meaning.
	helper := filepath.Join(adopttarget.AnsibleDir(), "roles", "headscale_adopt", "files", "hujson_acl.py")
	if out, err := exec.Command("docker", "cp", helper, tg.Name+":/root/hujson_acl.py").CombinedOutput(); err != nil {
		t.Fatalf("docker cp: %v %s", err, out)
	}
	tg.Sh(t, "python3 /root/hujson_acl.py --equal /tmp/db-policy /etc/headscale/policy.hujson")
	t.Run("TestG02_IdempotentWhenDone", func(t *testing.T) {
		res := mustRun(t, tg, home, adopttarget.AdoptVars(), extra, "g02")
		if !strings.Contains(res.Output, "zaten database") {
			t.Fatalf("not reported:\n%s", res.Output)
		}
		noChanges(t, tg, res)
	})
}

// AC9 (F6-007): a read-back that differs aborts: the real config stays in file mode and Headscale runs again.
func TestG02_DiffAbortsToFileMode(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	cfg := tg.Sh(t, "sha256sum /etc/headscale/config.yaml")
	extra := map[string]string{"confirm_g02": "yes", "expected_policy_sha256": policySHA(t, tg), "g02_test_corrupt_readback": "true"}
	res := runSite(t, tg, t.TempDir(), adopttarget.AdoptVars(), extra, "g02")
	if res.ExitCode == 0 || !strings.Contains(res.Output, "geri okunan policy dosyayla aynı değil") {
		t.Fatalf("want the abort:\n%s", res.Output)
	}
	if tg.Sh(t, "sha256sum /etc/headscale/config.yaml") != cfg {
		t.Fatal("the real config changed")
	}
	tg.Sh(t, `systemctl is-active -q headscale && test "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/health)" = 200 && test ! -e /etc/headscale/config.g02-candidate.yaml`)
	if got := strings.TrimSpace(tg.Sh(t, "stat -c '%a %U' /etc/headscale/config.yaml")); got != "644 root" {
		t.Fatalf("config mode after the abort: %s", got)
	}
}
