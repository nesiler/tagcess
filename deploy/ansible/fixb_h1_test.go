//go:build installer

package installer

import (
	"strings"
	"testing"

	"github.com/nesiler/tagcess/test/adopttarget"
)

// fixB_oldCandidates are the fixed candidate and saved-copy names the roles used to write (and delete) on the host.
// A foreign file at one of them must survive every run, and a --check run must not create or change any of them.
var fixB_oldCandidates = []string{
	"/etc/headscale/config.dns-candidate.yaml",
	"/etc/headscale/config.g02-candidate.yaml",
	"/etc/headscale/config.yaml.tagcess-prev",
	"/etc/headscale/policy.hujson.candidate",
	"/etc/headscale/config.candidate.yaml",
	"/etc/headscale/policy.candidate.hujson",
	"/etc/caddy/Caddyfile.candidate",
	"/tmp/tagcess-hs-hook-acl.candidate.hujson",
	"/tmp/tagcess-Caddyfile.candidate",
	"/tmp/config.candidate.yaml",
	"/tmp/policy.candidate.hujson",
}

// fixB_checkRoots are the roots a --check run must leave alone: the usual host roots plus the temp directories the
// old --check candidates went to.
var fixB_checkRoots = append(append([]string{}, hostRoots...), "/tmp", "/var/tmp")

func fixB_plant(t *testing.T, tg *adopttarget.Target, paths []string) map[string]string {
	t.Helper()
	want := map[string]string{}
	for _, p := range paths {
		want[p] = "SENTINEL of someone else: " + p + "\n"
		tg.WriteFile(t, p, want[p], "0644", "root:root")
	}
	return want
}

func fixB_intact(t *testing.T, tg *adopttarget.Target, want map[string]string, when string) {
	t.Helper()
	for p, c := range want {
		got, err := tg.ShErr("cat " + p)
		if err != nil || got != c {
			t.Errorf("%s: the foreign file %s was changed or removed (%q, %v)", when, p, got, err)
		}
	}
}

func fixB_volatileTmp(d []string) []string {
	var out []string
	for _, l := range d {
		if strings.Contains(l, " /tmp/systemd-private-") || strings.Contains(l, " /tmp/.") {
			continue
		}
		out = append(out, l)
	}
	return out
}

// H1: --check on the adopt shape writes nothing for hs_dns_path and hs_hook_acl, with the tagcess DNS file in place
// (host phase) and foreign files at the old candidate names.
func TestFixB_CheckModeWritesNoCandidates_Adopt(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	vars, _ := hostVars(t)
	home := t.TempDir()
	mustRun(t, tg, home, vars, nil, "host")
	want := fixB_plant(t, tg, fixB_oldCandidates)
	before := tg.Checksums(t, fixB_checkRoots)
	res := adopttarget.RunPlaybook(t, adopttarget.PlaybookOpts{Playbook: "site.yml", Inventories: []string{tg.Inventory}, ConfigHome: home,
		Vars: vars, ExtraVars: map[string]string{"confirm_hs_dns_path": "yes", "confirm_hs_hook_acl": "yes"},
		Tags: []string{"hs_dns_path", "hs_hook_acl"}, Check: true, Diff: true})
	if res.ExitCode != 0 {
		t.Fatalf("--check run:\n%s", tail(res.Output, 60))
	}
	if d := fixB_volatileTmp(adopttarget.DiffChecksums(before, tg.Checksums(t, fixB_checkRoots))); len(d) > 0 {
		t.Fatalf("--check changed the host:\n%s", strings.Join(d, "\n"))
	}
	fixB_intact(t, tg, want, "--check")
}

// H1: --check on Headscale and Caddy installed by the installer (bare target) writes nothing either.
func TestFixB_CheckModeWritesNoCandidates_Fresh(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "bare")
	vars := freshVars(t)
	home := t.TempDir()
	discoveryStub(t, tg)
	mustRun(t, tg, home, vars, nil, "certbot", "headscale_install", "caddy_install")
	want := fixB_plant(t, tg, fixB_oldCandidates)
	before := tg.Checksums(t, fixB_checkRoots)
	res := adopttarget.RunPlaybook(t, adopttarget.PlaybookOpts{Playbook: "site.yml", Inventories: []string{tg.Inventory}, ConfigHome: home,
		Vars: vars, Tags: []string{"headscale_install", "caddy_install"}, Check: true, Diff: true})
	if res.ExitCode != 0 {
		t.Fatalf("--check run:\n%s", tail(res.Output, 60))
	}
	if d := fixB_volatileTmp(adopttarget.DiffChecksums(before, tg.Checksums(t, fixB_checkRoots))); len(d) > 0 {
		t.Fatalf("--check changed the host:\n%s", strings.Join(d, "\n"))
	}
	fixB_intact(t, tg, want, "--check")
	// A real run neither overwrites nor deletes them.
	mustRun(t, tg, home, vars, nil, "headscale_install", "caddy_install")
	fixB_intact(t, tg, want, "real run")
}

// H1: a real run of hs_dns_path, hs_hook_acl, g02 and the g02 rollback never overwrites or deletes a foreign file at
// the old fixed candidate / saved-copy names.
func TestFixB_RealRunKeepsForeignCandidates(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	vars, _ := hostVars(t)
	home := t.TempDir()
	mustRun(t, tg, home, vars, nil, "host")
	want := fixB_plant(t, tg, fixB_oldCandidates)
	mustRun(t, tg, home, vars, map[string]string{"confirm_hs_dns_path": "yes"}, "hs_dns_path")
	fixB_intact(t, tg, want, "hs_dns_path")
	mustRun(t, tg, home, vars, map[string]string{"confirm_hs_hook_acl": "yes"}, "hs_hook_acl")
	fixB_intact(t, tg, want, "hs_hook_acl")
	if n := strings.Count(tg.ReadFile(t, "/etc/headscale/policy.hujson"), hookRule); n != 1 {
		t.Fatalf("the hook rule was not added once (%d)", n)
	}
	mustRun(t, tg, home, vars, map[string]string{"confirm_g02": "yes", "expected_policy_sha256": policySHA(t, tg)}, "g02")
	fixB_intact(t, tg, want, "g02")
	rb := adopttarget.RunPlaybook(t, adopttarget.PlaybookOpts{Playbook: "rollback.yml", Inventories: []string{tg.Inventory}, ConfigHome: home,
		Vars: vars, Tags: []string{"g02"}})
	if rb.ExitCode != 0 {
		t.Fatalf("rollback g02:\n%s", tail(rb.Output, 40))
	}
	fixB_intact(t, tg, want, "rollback g02")
}
