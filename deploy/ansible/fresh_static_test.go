package installer

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/nesiler/tagcess/test/adopttarget"
)

// labHeadscaleVars are the lab settings of the Headscale golden files; withOIDC adds the second pass's client.
func labHeadscaleVars(t *testing.T, withOIDC bool) map[string]any {
	t.Helper()
	v := map[string]any{
		"install_env": "lab", "install_mode": "fresh", "tagcess_domain": "lab.example.com", "vpn_private_cidr": "10.0.0.0/16",
		"headscale_policy_devops": []string{"devops@tagcess.test"}, "headscale_derp_ipv4": "203.0.113.10",
	}
	if withOIDC {
		v["headscale_oidc_client_id"] = "339000000000000003"
		v["secret_files"] = map[string]string{"headscale_oidc_client_secret": filepath.Join(t.TempDir(), "hs-oidc")}
	}
	return v
}

func golden(t *testing.T, got []byte, path string) {
	t.Helper()
	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil { // #nosec G306 -- golden file
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path) // #nosec G304 -- repo golden
	if err != nil {
		t.Fatalf("golden %s: %v (run with -update once)", path, err)
	}
	if string(got) != string(want) {
		t.Fatalf("differs from %s:\n%s", path, got)
	}
}

// AC1 (F6-012, golden part): the lab settings render the Headscale config (without and with the OIDC block) and the
// initial policy byte for byte like the golden files.
func TestHeadscaleInstall_ConfigPolicyGolden(t *testing.T) {
	t.Parallel()
	adopttarget.RequireAnsible(t)
	for name, oidc := range map[string]bool{"lab": false, "lab-oidc": true} {
		t.Run(name, func(t *testing.T) {
			out := t.TempDir()
			res := adopttarget.RunPlaybook(t, adopttarget.PlaybookOpts{Playbook: "testdata/headscale_render.yml", Inventories: []string{localInventory(t)},
				Vars: adopttarget.Merge(labHeadscaleVars(t, oidc), map[string]any{"hs_render_dir": out})})
			if res.ExitCode != 0 {
				t.Fatalf("render:\n%s", res.Output)
			}
			for _, f := range []string{"config.yaml", "policy.hujson"} {
				got, err := os.ReadFile(filepath.Join(out, f)) // #nosec G304 -- test temp dir
				if err != nil {
					t.Fatal(err)
				}
				golden(t, got, filepath.Join(adopttarget.AnsibleDir(), "testdata", "headscale", name, f))
			}
		})
	}
}

// AC10 (F6-012, static part): the certbot role never talks to Cloudflare itself (only certbot's DNS-01 plugin, which
// writes the _acme-challenge TXT record); the A records are a guide step.
func TestCertbotRole_NoCloudflareAPI(t *testing.T) {
	t.Parallel()
	err := filepath.WalkDir(filepath.Join(adopttarget.AnsibleDir(), "roles", "certbot"), func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p) // #nosec G304 -- repo files
		if err != nil {
			return err
		}
		for _, bad := range []string{"api.cloudflare.com", "uri:", "ansible.builtin.uri", "community.general.cloudflare_dns", "curl"} {
			if strings.Contains(string(b), bad) {
				t.Errorf("%s contains %q", p, bad)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// AC24 (F6-012): zitadel_install uses the test/lab files and chart version of test/lab/up.sh; it keeps no copy of the
// values, and its production patterns cover the Bash guard's production words.
func TestZitadelInstall_UsesLabValuesSingleSource(t *testing.T) {
	t.Parallel()
	role := filepath.Join(adopttarget.AnsibleDir(), "roles", "zitadel_install")
	var d struct {
		LabDir   string   `yaml:"zitadel_lab_dir"`
		Version  string   `yaml:"zitadel_chart_version"`
		PAT      string   `yaml:"zitadel_bootstrap_credential_name"`
		Patterns []string `yaml:"zitadel_forbidden_context_patterns"`
	}
	b, err := os.ReadFile(filepath.Join(role, "defaults", "main.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	if d.LabDir != "{{ tagcess_repo_root }}/test/lab" {
		t.Errorf("zitadel_lab_dir %q", d.LabDir)
	}
	up, _ := os.ReadFile(filepath.Join(adopttarget.RepoRoot(), "test", "lab", "up.sh"))
	if m := regexp.MustCompile(`zitadel/zitadel --version (\S+)`).FindSubmatch(up); m == nil || string(m[1]) != d.Version {
		t.Errorf("chart version %q, up.sh %q", d.Version, m)
	}
	lib, _ := os.ReadFile(filepath.Join(adopttarget.RepoRoot(), "test", "lab", "lib.sh"))
	if !strings.Contains(string(lib), `LAB_PAT_SECRET="`+d.PAT+`"`) {
		t.Errorf("PAT secret %q is not lib.sh's LAB_PAT_SECRET", d.PAT)
	}
	tasks, _ := os.ReadFile(filepath.Join(role, "tasks", "main.yml"))
	for _, f := range []string{"namespace.yaml", "quota.yaml", "postgres.yaml", "zitadel-values.yaml"} {
		if !strings.Contains(string(tasks), f) {
			t.Errorf("the role does not use test/lab/%s", f)
		}
		if _, err := os.Stat(filepath.Join(role, "files", f)); err == nil {
			t.Errorf("the role keeps its own copy of %s", f)
		}
	}
	if _, err := os.Stat(filepath.Join(role, "templates")); err == nil {
		t.Error("the role keeps templates (values must come from test/lab)")
	}
	// The role's default production words are install.sh's default, so both refuse the same contexts when the
	// environment's vars.yml sets no list of its own.
	inst, _ := os.ReadFile(filepath.Join(adopttarget.RepoRoot(), "deploy", "install.sh"))
	m := regexp.MustCompile(`(?m)^DEFAULT_FORBIDDEN_CONTEXTS="\[([^\]]*)\]"$`).FindSubmatch(inst)
	if m == nil {
		t.Fatal("install.sh has no DEFAULT_FORBIDDEN_CONTEXTS; update this test")
	}
	var shDefault []string
	for _, p := range strings.Split(string(m[1]), ",") {
		shDefault = append(shDefault, strings.TrimSpace(p))
	}
	if !slices.Equal(shDefault, d.Patterns) {
		t.Errorf("role default patterns %v, install.sh default %v", d.Patterns, shDefault)
	}
	for _, w := range []string{"prod", "production"} {
		if !slices.Contains(d.Patterns, w) {
			t.Errorf("the default patterns lack %q", w)
		}
	}
	if !strings.Contains(string(inst), "get_var zitadel_forbidden_context_patterns") {
		t.Error("install.sh does not read zitadel_forbidden_context_patterns from vars.yml")
	}
}

type zitadelInstallRun struct {
	adopttarget.Result
	calls []string
	home  string
}

// runZitadelInstall runs zitadel_install on the controller with fake kubectl/helm.
func runZitadelInstall(t *testing.T, vars map[string]any, discovery int) zitadelInstallRun {
	t.Helper()
	bin := t.TempDir()
	fake := filepath.Join(adopttarget.AnsibleDir(), "testdata", "fake-kube.sh")
	for _, n := range []string{"kubectl", "helm"} {
		if err := os.Symlink(fake, filepath.Join(bin, n)); err != nil {
			t.Fatal(err)
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"issuer":"x"}`)) }))
	t.Cleanup(srv.Close)
	logf := filepath.Join(t.TempDir(), "kube.log")
	home := t.TempDir()
	base := map[string]any{
		"install_env": "lab", "install_mode": "fresh", "tagcess_domain": "lab.example.test", "zitadel_install_enabled": true,
		"zitadel_kube_context": "lab-cluster", "zitadel_expected_nodes": []string{"lab-k8s"}, "zitadel_kubectl": filepath.Join(bin, "kubectl"), "zitadel_helm": filepath.Join(bin, "helm"),
		"zitadel_discovery_url": srv.URL + "/.well-known/openid-configuration", "zi_test_discovery_status": discovery,
	}
	res := adopttarget.RunPlaybook(t, adopttarget.PlaybookOpts{Playbook: "testdata/zitadel_install.yml", Inventories: []string{localInventory(t)},
		ConfigHome: home, Vars: adopttarget.Merge(base, vars), Env: []string{"FAKE_KUBE_LOG=" + logf, "FAKE_PAT=pat-" + strings.Repeat("Ab1", 12),
			"FAKE_NODES=" + fmt.Sprint(adopttarget.Merge(map[string]any{"zi_test_nodes": "node/lab-k8s"}, vars)["zi_test_nodes"])}})
	r := zitadelInstallRun{Result: res, home: home}
	if b, err := os.ReadFile(logf); err == nil { // #nosec G304 -- test temp file
		r.calls = strings.Split(strings.TrimSpace(string(b)), "\n")
	}
	return r
}

// AC22 (F6-012): an empty or production-looking context stops before helm/kubectl run.
func TestZitadelInstall_RefusesProdOrEmptyContext(t *testing.T) {
	t.Parallel()
	adopttarget.RequireAnsible(t)
	cases := []struct {
		ctx  string
		vars map[string]any
	}{
		{"", nil}, {"  ", nil}, {"prod", nil}, {"k8s-PROD-1", nil}, {"Production-main", nil},
		// The environment's own list (vars.yml) replaces the default, case-insensitively.
		{"corp-main-k8s", map[string]any{"zitadel_forbidden_context_patterns": []string{"Corp-Main", "live"}}},
	}
	for _, tc := range cases {
		r := runZitadelInstall(t, adopttarget.Merge(map[string]any{"zitadel_kube_context": tc.ctx}, tc.vars), 0)
		if r.ExitCode == 0 || !strings.Contains(r.Output, "helm/kubectl çağrılmadı") {
			t.Errorf("context %q: want a refusal:\n%s", tc.ctx, r.Output)
		}
		if len(r.calls) > 0 && r.calls[0] != "" {
			t.Errorf("context %q: helm/kubectl ran: %v", tc.ctx, r.calls)
		}
	}
}

// AC22 (F6-012, positive check): a context whose nodes are not the expected lab nodes (a production cluster behind an
// innocent name such as "default") or an empty expectation stops after the read-only node list, before any write.
func TestZitadelInstall_RefusesUnexpectedCluster(t *testing.T) {
	t.Parallel()
	adopttarget.RequireAnsible(t)
	for name, vars := range map[string]map[string]any{
		"other nodes": {"zitadel_kube_context": "default", "zi_test_nodes": "node/k8s-host-1"},
		"no expected": {"zitadel_expected_nodes": []string{}},
	} {
		t.Run(name, func(t *testing.T) {
			r := runZitadelInstall(t, vars, 0)
			if r.ExitCode == 0 || !strings.Contains(r.Output, "hiçbir şey yazılmadı") {
				t.Fatalf("want a refusal:\n%s", r.Output)
			}
			for _, c := range r.calls {
				if !strings.Contains(c, "get nodes") {
					t.Fatalf("a call besides the node list ran: %q", c)
				}
			}
		})
	}
}

// AC23 (F6-012): adopt, a disabled install or an answering discovery: no helm/kubectl write, "atlandı".
func TestZitadelInstall_SkippedUnlessFreshAndAbsent(t *testing.T) {
	t.Parallel()
	adopttarget.RequireAnsible(t)
	cases := map[string]struct {
		vars      map[string]any
		discovery int
	}{
		"adopt":     {map[string]any{"install_mode": "adopt"}, 0},
		"disabled":  {map[string]any{"zitadel_install_enabled": false}, 0},
		"answering": {nil, 200},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			r := runZitadelInstall(t, c.vars, c.discovery)
			if r.ExitCode != 0 || !strings.Contains(r.Output, "zitadel_install atlandı") {
				t.Fatalf("want a skip:\n%s", r.Output)
			}
			if len(r.calls) > 0 && r.calls[0] != "" {
				t.Fatalf("helm/kubectl ran: %v", r.calls)
			}
		})
	}
}

// AC25 (F6-012): the PAT goes only into a 0600 file, never into the output; zitadel_admin_pat_file points at it. The
// install itself uses the lab files with the given context.
// The lab values name a placeholder host; an environment's own zitadel_lab_host installs a copy with that host
// (ExternalDomain and both Ingress hosts), and the repo file is left as it is.
func TestZitadelInstall_LabHostFromEnvironment(t *testing.T) {
	t.Parallel()
	adopttarget.RequireAnsible(t)
	requireInstallTools(t)
	const host = "tagcess-zitadel.dev.example.net"
	r := runZitadelInstall(t, map[string]any{"zitadel_lab_host": host}, 0)
	if r.ExitCode != 0 {
		t.Fatalf("install:\n%s", r.Output)
	}
	copyPath := filepath.Join(r.home, "tagcess-install", "lab", "zitadel-values.yaml")
	if all := strings.Join(r.calls, "\n"); !strings.Contains(all, "-f "+copyPath+" ") {
		t.Errorf("helm does not use the environment's values copy %s:\n%s", copyPath, all)
	}
	b, err := os.ReadFile(copyPath) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "lab.example.com") || strings.Count(string(b), host) != 5 {
		t.Errorf("values copy does not carry %s everywhere:\n%s", host, b)
	}
	orig, _ := os.ReadFile(filepath.Join(adopttarget.RepoRoot(), "test", "lab", "zitadel-values.yaml"))
	if strings.Contains(string(orig), host) {
		t.Error("the repo values file was changed")
	}
}

func TestZitadelInstall_PATToFileNoLog(t *testing.T) {
	t.Parallel()
	adopttarget.RequireAnsible(t)
	requireInstallTools(t)
	r := runZitadelInstall(t, nil, 0)
	if r.ExitCode != 0 {
		t.Fatalf("install:\n%s", r.Output)
	}
	pat := "pat-" + strings.Repeat("Ab1", 12)
	if strings.Contains(r.Output, pat) {
		t.Fatal("the PAT reached the output")
	}
	dest := filepath.Join(r.home, "tagcess-install", "lab", "secrets", "zitadel-admin.pat")
	b, err := os.ReadFile(dest) // #nosec G304 -- test temp dir
	if err != nil || string(b) != pat {
		t.Fatalf("PAT file: %q %v", b, err)
	}
	if st, _ := os.Stat(dest); st.Mode().Perm() != 0o600 {
		t.Fatalf("PAT file mode %v", st.Mode().Perm())
	}
	if !strings.Contains(r.Output, "NEXT pat="+dest) {
		t.Fatalf("zitadel_admin_pat_file not set:\n%s", r.Output)
	}
	all := strings.Join(r.calls, "\n")
	for _, w := range []string{"--context lab-cluster", "test/lab/namespace.yaml", "test/lab/quota.yaml", "test/lab/postgres.yaml",
		"helm --kube-context lab-cluster --namespace tagcess-lab upgrade --install zitadel zitadel/zitadel --version 10.0.6 -f",
		"test/lab/zitadel-values.yaml"} {
		if !strings.Contains(all, w) {
			t.Errorf("calls lack %q:\n%s", w, all)
		}
	}
	g, _ := os.ReadFile(filepath.Join(r.home, "tagcess-install", "lab", "guide", "zitadel_install.json")) // #nosec G304 -- test temp dir
	if !strings.Contains(string(g), "zitadel-admin-pat") || strings.Contains(string(g), pat) {
		t.Fatalf("guide: %s", g)
	}
}

// requireInstallTools skips (never passes) when a tool the zitadel_install shell tasks use is missing on the host.
func requireInstallTools(t *testing.T) {
	t.Helper()
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		t.Skip("the zitadel_install shell tasks do not run on the CI runner; a skip is not a PASS")
	}
	for _, tool := range []string{"bash", "openssl", "base64"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed; a skip is not a PASS", tool)
		}
	}
}
