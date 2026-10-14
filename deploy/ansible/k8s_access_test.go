package installer

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/nesiler/tagcess/test/adopttarget"
)

// k8sAccessRun runs the k8s_access role on the controller with the fake manifest command and a kubectl/helm on PATH
// that records any call.
func k8sAccessRun(t *testing.T, vars map[string]any, check bool) (adopttarget.Result, string, string) {
	t.Helper()
	home := t.TempDir()
	bin := t.TempDir()
	calls := filepath.Join(t.TempDir(), "calls.log")
	for _, tool := range []string{"kubectl", "helm"} {
		if err := os.WriteFile(filepath.Join(bin, tool), []byte("#!/bin/sh\necho \""+tool+" $*\" >>"+calls+"\n"), 0o755); err != nil { // #nosec G306 -- test stub
			t.Fatal(err)
		}
	}
	base := map[string]any{"install_env": "k8stest", "install_mode": "adopt", "tagcess_domain": "c.example.test", "k8s_context": "dev-ctx",
		"k8s_access_manifest_cmd": filepath.Join(adopttarget.AnsibleDir(), "testdata", "fake-k8s-manifest.sh")}
	res := adopttarget.RunPlaybook(t, adopttarget.PlaybookOpts{Playbook: "testdata/k8s_access.yml", Inventories: []string{localInventory(t)}, ConfigHome: home,
		Vars: adopttarget.Merge(base, vars), Check: check, Env: []string{"PATH=" + bin + ":" + os.Getenv("PATH")}})
	c, _ := os.ReadFile(calls) // #nosec G304 -- test temp dir
	return res, home, string(c)
}

// AC11 (F6-007): the manifest file is tagcess -k8s-manifest's output byte for byte; the commands carry the settings.
func TestK8sAccess_RendersManifestAndCommands(t *testing.T) {
	t.Parallel()
	res, home, _ := k8sAccessRun(t, nil, false)
	if res.ExitCode != 0 {
		t.Fatal(res.Output)
	}
	want, err := fakeManifest(filepath.Join(adopttarget.AnsibleDir(), "testdata", "fake-k8s-manifest.sh"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(envDir(home, "k8stest"), "k8s-rbac.yaml")) // #nosec G304 -- test temp dir
	if err != nil || string(got) != want {
		t.Fatalf("manifest differs (%v):\n%s\n---\n%s", err, got, want)
	}
	cmds, _ := os.ReadFile(filepath.Join(envDir(home, "k8stest"), "k8s-commands.txt")) // #nosec G304 -- test temp dir
	for _, w := range []string{"kubectl --context dev-ctx apply -f " + envDir(home, "k8stest") + "/k8s-rbac.yaml",
		"-n tagcess create token tagcess-reader --duration 720h", "https://tagcess.c.example.test", "API https://100.64.0.5:6443"} {
		if !strings.Contains(string(cmds), w) {
			t.Errorf("commands lack %q:\n%s", w, cmds)
		}
	}
}

func fakeManifest(path string) (string, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- repo test file
	if err != nil {
		return "", err
	}
	body := string(data)
	start := strings.Index(body, "<<'YAML'\n") + len("<<'YAML'\n")
	end := strings.LastIndex(body, "YAML\n")
	return body[start:end], nil
}

// AC12 (F6-007): the role's tasks never run kubectl/helm, never use a kubernetes.core module or a kubeconfig; a run
// (and a --check run) calls neither.
func TestK8sAccess_NeverAppliesToCluster(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(adopttarget.AnsibleDir(), "roles", "k8s_access", "tasks")
	files, _ := filepath.Glob(filepath.Join(dir, "*.yml"))
	cmdModules := regexp.MustCompile(`^(ansible\.builtin\.)?(command|shell|script|raw)$`)
	for _, f := range files {
		data, err := os.ReadFile(f) // #nosec G304 -- repo file
		if err != nil {
			t.Fatal(err)
		}
		var tasks []map[string]any
		if err := yaml.Unmarshal(data, &tasks); err != nil {
			t.Fatal(err)
		}
		for _, task := range tasks {
			for k, v := range task {
				if strings.HasPrefix(k, "kubernetes.core") || strings.Contains(k, "k8s") && k != "name" || k == "environment" && strings.Contains(strings.ToUpper(yamlString(v)), "KUBECONFIG") {
					t.Errorf("%s: task %q uses %s", f, task["name"], k)
				}
				if cmdModules.MatchString(k) && regexp.MustCompile(`\b(kubectl|helm)\b|kubeconfig`).MatchString(yamlString(v)) {
					t.Errorf("%s: task %q runs %v", f, task["name"], v)
				}
			}
		}
	}
	for _, check := range []bool{false, true} {
		res, _, calls := k8sAccessRun(t, nil, check)
		if res.ExitCode != 0 || calls != "" {
			t.Fatalf("check=%v: exit %d, kubectl/helm calls %q", check, res.ExitCode, calls)
		}
	}
}

func yamlString(v any) string {
	b, _ := yaml.Marshal(v)
	return string(b)
}

// AC13 (F6-007): the commands are guide items of phase k8s_access without secret-shaped values.
func TestK8sAccess_CommandsAsGuide(t *testing.T) {
	t.Parallel()
	res, home, _ := k8sAccessRun(t, nil, false)
	if res.ExitCode != 0 {
		t.Fatal(res.Output)
	}
	j, md := readGuideIn(t, home, "k8stest", "k8s_access")
	for _, w := range []string{`"phase": "k8s_access"`, "k8s-apply-rbac", "k8s-token-ca", "create token tagcess-reader"} {
		if !strings.Contains(j, w) {
			t.Errorf("guide lacks %q:\n%s", w, j)
		}
	}
	if regexp.MustCompile(`-----BEGIN|eyJ[A-Za-z0-9_-]{20,}`).MatchString(j + md) {
		t.Fatal("secret-shaped value in the guide")
	}
}

// AC14 (F6-007): the adopt (internal:8443) and lab (websecure:443) settings reach the commands and the guide.
func TestK8sAccess_EntrypointVars(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		vars map[string]any
		want string
	}{
		{map[string]any{"traefik_entrypoint": "internal", "traefik_port": 8443, "k8s_target_addr": "https://100.64.0.5:8443"}, "internal:8443"},
		{map[string]any{"traefik_entrypoint": "websecure", "traefik_port": 443}, "websecure:443"},
	} {
		res, home, _ := k8sAccessRun(t, c.vars, false)
		cmds, _ := os.ReadFile(filepath.Join(envDir(home, "k8stest"), "k8s-commands.txt")) // #nosec G304 -- test temp dir
		j, _ := readGuideIn(t, home, "k8stest", "k8s_access")
		if res.ExitCode != 0 || !strings.Contains(string(cmds), "entrypoint "+c.want) || !strings.Contains(j, c.want) {
			t.Fatalf("%s missing:\n%s\n%s", c.want, cmds, j)
		}
	}
}
