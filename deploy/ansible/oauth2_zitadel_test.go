package installer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/test/adopttarget"
)

// zitadelSeedRun runs testdata/zitadel_seed.yml with the fake tool; it returns the result, the recorded tool
// arguments and the controller home.
func zitadelSeedRun(t *testing.T, vars map[string]any, check bool, env ...string) (adopttarget.Result, string, string) {
	t.Helper()
	home := t.TempDir()
	logf := filepath.Join(t.TempDir(), "args.log")
	admin := filepath.Join(t.TempDir(), "admin-key.json")
	if err := os.WriteFile(admin, []byte(`{"type":"serviceaccount","key":"ADMIN-KEY-MARKER-55c1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	base := map[string]any{
		"install_env": "seedtest", "install_mode": "adopt", "tagcess_domain": "c.example.test", "vpn_tailnet_ip": "100.64.0.4",
		"zitadel_seed_tool": filepath.Join(adopttarget.AnsibleDir(), "testdata", "fake-zitadel-adopt.sh"), "zitadel_admin_key_file": admin,
	}
	res := adopttarget.RunPlaybook(t, adopttarget.PlaybookOpts{Playbook: "testdata/zitadel_seed.yml", Inventories: []string{localInventory(t)},
		ConfigHome: home, Vars: adopttarget.Merge(base, vars), Check: check, Env: append([]string{"FAKE_ZITADEL_LOG=" + logf}, env...)})
	args, _ := os.ReadFile(logf) // #nosec G304 -- test temp dir
	return res, string(args), home
}

// AC6 (F6-006): --check or zitadel_seed_apply false call the tool with --dry-run and write nothing.
func TestZitadelSeedRole_PlanInCheckMode(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name  string
		vars  map[string]any
		check bool
	}{{"apply false", map[string]any{"zitadel_seed_apply": false}, false}, {"--check with apply true", map[string]any{"zitadel_seed_apply": true}, true}} {
		res, args, home := zitadelSeedRun(t, c.vars, c.check)
		if res.ExitCode != 0 || !strings.Contains(args, "--dry-run") {
			t.Fatalf("%s: exit %d args %q\n%s", c.name, res.ExitCode, args, res.Output)
		}
		if _, err := os.Stat(filepath.Join(envDir(home, "seedtest"), "zitadel.json")); !os.IsNotExist(err) {
			t.Fatalf("%s: zitadel.json written by a plan run", c.name)
		}
		if !strings.Contains(res.Output, "planı (yazma yok)") {
			t.Fatalf("%s: plan not shown", c.name)
		}
	}
}

// AC7 (F6-006): an applied run writes the ids to zitadel.json, and the later phases (this run and the next ones)
// see zitadel_project_id, oauth2_proxy_client_id, headscale_oidc_client_id and the Headscale OIDC secret path.
func TestZitadelSeedRole_PassesIdsToApp(t *testing.T) {
	t.Parallel()
	res, args, home := zitadelSeedRun(t, map[string]any{"zitadel_seed_apply": true}, false)
	if res.ExitCode != 0 || strings.Contains(args, "--dry-run") {
		t.Fatalf("apply: exit %d args %q\n%s", res.ExitCode, args, res.Output)
	}
	secret := filepath.Join(envDir(home, "seedtest"), "secrets", "headscale_oidc_client_secret")
	want := "NEXT project=p-777 op=op-client-2 hs=hs-client-1 hssecret=" + secret
	if !strings.Contains(res.Output, want) {
		t.Fatalf("this run's later phases do not see the ids:\n%s", res.Output)
	}
	data, err := os.ReadFile(filepath.Join(envDir(home, "seedtest"), "zitadel.json")) // #nosec G304 -- test temp dir
	if err != nil || !strings.Contains(string(data), `"zitadel_project_id": "p-777"`) || strings.Contains(string(data), "MARKER") {
		t.Fatalf("zitadel.json: %v\n%s", err, data)
	}
	// A later, separate run (another phase) reads zitadel.json.
	res2 := adopttarget.RunPlaybook(t, adopttarget.PlaybookOpts{Playbook: "testdata/guide.yml", Inventories: []string{localInventory(t)}, ConfigHome: home,
		Vars:      map[string]any{"install_env": "seedtest", "install_mode": "adopt", "tagcess_domain": "c.example.test"},
		ExtraJSON: map[string]any{"guide_phase": "probe", "guide_items": []map[string]any{{"id": "v", "title": "{{ zitadel_project_id }}/{{ headscale_oidc_client_id }}", "steps": []string{"x"}}}}})
	g, _ := readGuideIn(t, home, "seedtest", "probe")
	if res2.ExitCode != 0 || !strings.Contains(g, "p-777/hs-client-1") {
		t.Fatalf("a later run does not read zitadel.json:\n%s\n%s", g, res2.Output)
	}
}

func readGuideIn(t *testing.T, home, env, phase string) (string, string) {
	t.Helper()
	j, _ := os.ReadFile(filepath.Join(home, "tagcess-install", env, "guide", phase+".json")) // #nosec G304 -- test temp dir
	m, _ := os.ReadFile(filepath.Join(home, "tagcess-install", env, "guide", phase+".md"))   // #nosec G304 -- test temp dir
	return string(j), string(m)
}

// AC8 (F6-006): neither the admin credential nor a created secret reaches the Ansible output.
func TestZitadelSeedRole_NoSecretInOutput(t *testing.T) {
	t.Parallel()
	res, _, _ := zitadelSeedRun(t, map[string]any{"zitadel_seed_apply": true}, false)
	if res.ExitCode != 0 {
		t.Fatal(res.Output)
	}
	for _, m := range []string{"ADMIN-KEY-MARKER", "FAKE-CLIENT-SECRET-MARKER"} {
		if strings.Contains(res.Output, m) {
			t.Fatalf("%s reached the output", m)
		}
	}
}

// AC9 (F6-006): the tool's report items become guide items without stopping the phase; the adopt settings call the
// tool without --groups-execution and without --create-actions (unless confirmed); the lab settings pass both.
func TestZitadelSeedRole_GuideAndAdoptFlags(t *testing.T) {
	t.Parallel()
	res, args, home := zitadelSeedRun(t, map[string]any{"zitadel_seed_apply": true}, false)
	if res.ExitCode != 0 || strings.Contains(args, "--groups-execution") || strings.Contains(args, "--create-actions") {
		t.Fatalf("adopt: exit %d args %q", res.ExitCode, args)
	}
	j, md := readGuideIn(t, home, "seedtest", "zitadel_seed")
	for _, w := range []string{"zitadel-service-user", "zitadel-groups-v1-to-v2"} {
		if !strings.Contains(j, w) {
			t.Errorf("guide lacks %s: %s", w, j)
		}
	}
	if !strings.Contains(md, "ADR 0009") {
		t.Errorf("guide md: %s", md)
	}
	_, args, _ = zitadelSeedRun(t, map[string]any{"zitadel_seed_apply": true, "zitadel_seed_create_actions": true, "zitadel_groups_execution": true,
		"install_mode": "fresh"}, false)
	if !strings.Contains(args, "--create-actions") || !strings.Contains(args, "--groups-execution") {
		t.Fatalf("lab: args %q", args)
	}
	_, args, _ = zitadelSeedRun(t, map[string]any{"zitadel_seed_apply": true}, false, "UNUSED=1")
	if !strings.Contains(args, "--webhook-url http://100.64.0.4:9443/hook") || !strings.Contains(args, "--report-unroled") {
		t.Fatalf("args %q", args)
	}
}

// AC10 (F6-006): a failing tool stops the run with its (secret-free) error line; nothing after it runs.
func TestZitadelSeedRole_ToolFailureStops(t *testing.T) {
	t.Parallel()
	res, _, _ := zitadelSeedRun(t, map[string]any{"zitadel_seed_apply": true}, false, "FAKE_ZITADEL_FAIL=1")
	if res.ExitCode == 0 || !strings.Contains(res.Output, "Zitadel adopt aracı durdu: tagcess-zitadel-adopt: zitadel unreachable") {
		t.Fatalf("want a stop with the tool's line:\n%s", res.Output)
	}
	if strings.Contains(res.Output, "NEXT project=") || strings.Contains(res.Output, "TASK [guide") {
		t.Fatal("tasks ran after the failure")
	}
}

// oauth2ProxySets are the four golden variable sets: runtime x cookie profile.
func oauth2ProxySets() map[string]map[string]any {
	existingCookie := map[string]any{"cookie_name": "_vpn_auth", "cookie_expire": "12h", "cookie_refresh": "1h",
		"cookie_domains": []string{".c.example.test", ".b.example.test", ".a.example.test"}, "cookie_samesite": "lax", "cookie_secure": true,
		"whitelist_domains": []string{".c.example.test", ".b.example.test", ".a.example.test"}, "insecure_oidc_allow_unverified_email": true}
	adopt := map[string]any{"install_env": "prod", "install_mode": "adopt", "tagcess_domain": "c.example.test", "oauth2_proxy_client_id": "100000000000000002",
		"cert_names":      []string{"internal.a.example.test", "b.example.test", "c.example.test"},
		"preflight_probe": map[string]any{"oauth2_proxy": map[string]any{"settings": existingCookie}}}
	lab := map[string]any{"install_env": "lab", "install_mode": "fresh", "tagcess_domain": "lab.example.com", "oauth2_proxy_client_id": "339000000000000002",
		"cert_names": []string{"lab.example.com"}}
	return map[string]map[string]any{
		"container-tagcess": adopttarget.Merge(lab, map[string]any{"oauth2_proxy_runtime": "container"}),
		"systemd-existing":  adopttarget.Merge(adopt, map[string]any{"oauth2_proxy_runtime": "systemd"}),
		"systemd-tagcess": adopttarget.Merge(adopt, map[string]any{"oauth2_proxy_runtime": "systemd", "oauth2_proxy_cookie_profile": "tagcess",
			"confirm_oauth2_cookie": "yes"}),
		"container-existing": adopttarget.Merge(adopt, map[string]any{"oauth2_proxy_runtime": "container"}),
	}
}

// AC1 (F6-006): the four runtime x cookie-profile sets render the golden oauth2-proxy.cfg; secrets are only *_file
// paths in it.
func TestOAuth2ProxyRole_ConfigGolden(t *testing.T) {
	t.Parallel()
	for name, vars := range oauth2ProxySets() {
		out := t.TempDir()
		res := adopttarget.RunPlaybook(t, adopttarget.PlaybookOpts{Playbook: "testdata/oauth2_proxy_render.yml", Inventories: []string{localInventory(t)},
			Vars: adopttarget.Merge(vars, map[string]any{"oauth2_proxy_render_dir": out})})
		if res.ExitCode != 0 {
			t.Fatalf("%s: render:\n%s", name, res.Output)
		}
		got, err := os.ReadFile(filepath.Join(out, "oauth2-proxy.cfg")) // #nosec G304 -- test temp dir
		if err != nil {
			t.Fatal(err)
		}
		golden := filepath.Join(adopttarget.AnsibleDir(), "testdata", "oauth2_proxy", name+".cfg")
		if *updateGolden {
			_ = os.MkdirAll(filepath.Dir(golden), 0o755)
			if err := os.WriteFile(golden, got, 0o644); err != nil { // #nosec G306 -- golden file
				t.Fatal(err)
			}
		}
		want, err := os.ReadFile(golden) // #nosec G304 -- repo golden
		if err != nil || string(got) != string(want) {
			t.Fatalf("%s differs from %s (%v):\n%s", name, golden, err, got)
		}
		for _, line := range strings.Split(string(got), "\n") {
			if strings.HasPrefix(line, "#") {
				continue
			}
			k, _, _ := strings.Cut(line, " =")
			if strings.Contains(k, "secret") && !strings.HasSuffix(k, "_file") {
				t.Errorf("%s: secret value line %q", name, line)
			}
		}
	}
}
