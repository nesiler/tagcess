package installer

import (
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/nesiler/tagcess/internal/config"
	"github.com/nesiler/tagcess/test/adopttarget"
)

var updateGolden = flag.Bool("update", false, "rewrite the installer golden files")

// appVarSets are the two environments of the golden tests (lab/fresh and adopt).
func appVarSets(t *testing.T) map[string]map[string]any {
	t.Helper()
	dir := t.TempDir()
	return map[string]map[string]any{
		"lab": {
			"install_env": "lab", "install_mode": "fresh", "tagcess_domain": "lab.example.com", "vpn_tailnet_ip_effective": "100.64.0.1",
			"k8s_tailnet_ip": "100.64.0.5", "cert_names": []string{"lab.example.com"}, "zitadel_project_id": "339000000000000001",
			"oauth2_proxy_client_id": "339000000000000002", "site_seed_file": filepath.Join(adopttarget.RepoRoot(), "deploy", "f5", "seed-sites.json"),
			"app_zitadel_internal_sources": []string{"10.0.0.0/16", "127.0.0.1/32", "::1/128"}, "tagcess_image": "tagcess:latest",
			"secret_files":   map[string]string{"webhook_signing_key": dir + "/w", "groups_signing_key": dir + "/g", "zitadel_key": dir + "/z"},
			"app_render_dir": "",
		},
		"prod": {
			"install_env": "prod", "install_mode": "adopt", "tagcess_domain": "c.example.test", "vpn_tailnet_ip_effective": "100.64.0.4",
			"k8s_tailnet_ip": "100.64.0.5", "cert_names": []string{"internal.a.example.test", "b.example.test", "c.example.test"},
			"zitadel_project_id": "100000000000000003", "oauth2_proxy_client_id": "100000000000000002", "caddy_sites_dir": "/etc/caddy/sites",
			"k8s_target_addr":              "https://100.64.0.5:8443",
			"site_seed_file":               filepath.Join(adopttarget.AnsibleDir(), "examples", "seed.example.json"),
			"app_zitadel_internal_sources": []string{"10.8.0.0/24", "127.0.0.1/32", "::1/128", "192.0.2.10/32", "192.0.2.20/32"},
			"secret_files":                 map[string]string{"webhook_signing_key": dir + "/w", "zitadel_key": dir + "/z"},
			"app_render_dir":               "",
		},
	}
}

func renderApp(t *testing.T, vars map[string]any) (adopttarget.Result, string) {
	t.Helper()
	out := t.TempDir()
	vars["app_render_dir"] = out
	res := adopttarget.RunPlaybook(t, adopttarget.PlaybookOpts{Playbook: "testdata/app_render.yml", Inventories: []string{localInventory(t)}, Vars: vars})
	return res, out
}

// AC14 (F6-005): the lab and adopt settings render config.yaml and compose byte for byte like the golden files;
// the rendered config passes tagcess's own config validation.
func TestAppRole_ConfigGolden(t *testing.T) {
	t.Parallel()
	for name, vars := range appVarSets(t) {
		t.Run(name, func(t *testing.T) {
			res, out := renderApp(t, vars)
			if res.ExitCode != 0 {
				t.Fatalf("render:\n%s", res.Output)
			}
			for _, f := range []string{"config.yaml", "compose.yaml"} {
				got, err := os.ReadFile(filepath.Join(out, f)) // #nosec G304 -- test temp dir
				if err != nil {
					t.Fatal(err)
				}
				golden := filepath.Join(adopttarget.AnsibleDir(), "testdata", "app", name, f)
				if *updateGolden {
					if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(golden, got, 0o644); err != nil { // #nosec G306 -- golden file
						t.Fatal(err)
					}
				}
				want, err := os.ReadFile(golden) // #nosec G304 -- repo golden
				if err != nil {
					t.Fatalf("golden %s: %v (run with -update once)", golden, err)
				}
				if string(got) != string(want) {
					t.Fatalf("%s differs from %s:\n%s", f, golden, got)
				}
			}
			if _, err := config.Load(filepath.Join(out, "config.yaml")); err != nil {
				t.Fatalf("the rendered config does not load: %v", err)
			}
			// Secrets appear only as paths in either file.
			cfg, _ := os.ReadFile(filepath.Join(out, "config.yaml")) // #nosec G304 -- test temp dir
			if regexp.MustCompile(`(?i)(secret|key|token):\s*[^/\s"]`).Match(cfg) {
				t.Fatalf("the config carries a secret value:\n%s", cfg)
			}
		})
	}
}

// AC18 (F6-005): a seed that does not match the schema stops before anything is copied; the adopt seed example
// and the lab seed pass.
func TestAppRole_SeedSchemaRejected(t *testing.T) {
	t.Parallel()
	base := appVarSets(t)["lab"]
	for _, ok := range []string{filepath.Join(adopttarget.RepoRoot(), "deploy", "f5", "seed-sites.json"),
		filepath.Join(adopttarget.AnsibleDir(), "examples", "seed.example.json")} {
		v := adopttarget.Merge(base, map[string]any{"site_seed_file": ok})
		delete(v, "app_render_dir")
		res := adopttarget.RunPlaybook(t, adopttarget.PlaybookOpts{Playbook: "testdata/app_render.yml", Inventories: []string{localInventory(t)}, Vars: v})
		if res.ExitCode != 0 {
			t.Fatalf("%s must pass the schema:\n%s", ok, res.Output)
		}
	}
	bad := map[string]string{
		"unknown field":   `{"sites":[{"hosts":["a.example.test"],"kind":"open","open_reason":"transition","cert":"auto","target":"k8s","colour":"red"}]}`,
		"no sites":        `{"sites":[]}`,
		"bad kind":        `{"sites":[{"hosts":["a.example.test"],"kind":"public","cert":"auto","target":"k8s"}]}`,
		"open no reason":  `{"sites":[{"hosts":["a.example.test"],"kind":"open","cert":"auto","target":"k8s"}]}`,
		"role no roles":   `{"sites":[{"hosts":["a.example.test"],"kind":"role","cert":"auto","target":"k8s"}]}`,
		"extra top level": `{"sites":[{"hosts":["a.example.test"],"kind":"open","open_reason":"intentional","cert":"auto","target":"k8s"}],"x":1}`,
		"no hosts":        `{"sites":[{"kind":"open","open_reason":"intentional","cert":"auto","target":"k8s"}]}`,
	}
	for name, body := range bad {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "seed.json")
			if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			v := adopttarget.Merge(base, map[string]any{"site_seed_file": p})
			delete(v, "app_render_dir")
			res := adopttarget.RunPlaybook(t, adopttarget.PlaybookOpts{Playbook: "testdata/app_render.yml", Inventories: []string{localInventory(t)}, Vars: v})
			if res.ExitCode == 0 || !strings.Contains(res.Output, "Seed dosyası tagcess şemasına uymuyor") {
				t.Fatalf("want a schema failure:\n%s", res.Output)
			}
		})
	}
}

// The seed keys the app role accepts are exactly tagcess's seed fields (internal/site/seed.go json tags).
func TestAppRole_SeedKeysMatchGo(t *testing.T) {
	t.Parallel()
	src, err := os.ReadFile(filepath.Join(adopttarget.RepoRoot(), "internal", "site", "seed.go"))
	if err != nil {
		t.Fatal(err)
	}
	block := regexp.MustCompile(`(?s)type seedSite struct \{(.*?)\n\}`).FindSubmatch(src)
	if block == nil {
		t.Fatal("seedSite not found")
	}
	var goKeys []string
	for _, m := range regexp.MustCompile(`json:"([a-z_]+)"`).FindAllSubmatch(block[1], -1) {
		goKeys = append(goKeys, string(m[1]))
	}
	data, err := os.ReadFile(filepath.Join(adopttarget.AnsibleDir(), "roles", "app", "defaults", "main.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		Keys []string `yaml:"app_seed_keys"`
	}
	if err := yaml.Unmarshal(data, &d); err != nil {
		t.Fatal(err)
	}
	slices.Sort(goKeys)
	slices.Sort(d.Keys)
	if !reflect.DeepEqual(goKeys, d.Keys) {
		t.Fatalf("app_seed_keys %v, seed.go %v", d.Keys, goKeys)
	}
}

// AC19 (F6-005): the UI block is deploy/caddy/tagcess.caddy with the host replaced, byte for byte.
func TestCaddyUI_MatchesReferenceTemplate(t *testing.T) {
	t.Parallel()
	out := filepath.Join(t.TempDir(), "block.caddy")
	res := adopttarget.RunPlaybook(t, adopttarget.PlaybookOpts{Playbook: "testdata/caddy_ui_block.yml", Inventories: []string{localInventory(t)},
		Vars: map[string]any{"install_env": "t", "tagcess_domain": "c.example.test", "install_mode": "adopt", "caddy_ui_out": out}})
	if res.ExitCode != 0 {
		t.Fatalf("render:\n%s", res.Output)
	}
	got, err := os.ReadFile(out) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	ref, err := os.ReadFile(filepath.Join(adopttarget.RepoRoot(), "deploy", "caddy", "tagcess.caddy"))
	if err != nil {
		t.Fatal(err)
	}
	want := strings.ReplaceAll(string(ref), "tagcess.example.com", "tagcess.c.example.test")
	if string(got) != want {
		t.Fatalf("block differs from the reference:\n%s", got)
	}
}
