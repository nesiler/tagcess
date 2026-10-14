package installer

import (
	"bytes"
	"encoding/json"
	"fmt"
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

// envDir is the controller directory of an environment under a test's XDG_CONFIG_HOME.
func envDir(home, env string) string { return filepath.Join(home, "tagcess-install", env) }

// localInventory writes an inventory whose `vpn` host is this machine over the local connection: the static
// tests run the playbooks without any target, and every controller file goes to a temp XDG_CONFIG_HOME.
func localInventory(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "local.yml")
	inv := "all:\n  children:\n    vpn:\n      hosts:\n        local-target:\n          ansible_connection: local\n" +
		"          ansible_python_interpreter: \"{{ ansible_playbook_python }}\"\n"
	if err := os.WriteFile(p, []byte(inv), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// AC1 : every playbook passes ansible-playbook --syntax-check with the example inventory.
func TestInstaller_SkeletonSyntaxCheck(t *testing.T) {
	t.Parallel()
	adopttarget.RequireAnsible(t)
	books, err := filepath.Glob(filepath.Join(adopttarget.AnsibleDir(), "*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, b := range books {
		if base := filepath.Base(b); base != "inventory.example.yml" {
			names = append(names, base)
		}
	}
	if !slices.Contains(names, "site.yml") {
		t.Fatalf("site.yml is missing (found %v)", names)
	}
	for _, b := range names {
		cmd := exec.CommandContext(t.Context(), "ansible-playbook", "--syntax-check", b, "-i", "inventory.example.yml")
		cmd.Dir = adopttarget.AnsibleDir()
		cmd.Env = append(os.Environ(), "ANSIBLE_CONFIG=ansible.cfg", "ANSIBLE_NOCOLOR=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("%s: --syntax-check failed: %v\n%s", b, err, out)
		}
	}
}

// secretKey reports whether a variable name names a secret: one of its _-separated words is secret-like.
func secretKey(k string) bool {
	for _, w := range strings.Split(strings.ToLower(k), "_") {
		switch w {
		case "secret", "secrets", "token", "password", "passwd", "key", "apikey", "pat", "privkey":
			return true
		}
	}
	return false
}

// inlineSecrets walks a YAML document and returns key paths whose secret-like key carries a value that is not
// a path variable: allowed are names ending in _file/_path/_dir, every entry under secret_files, and empty values.
func inlineSecrets(node *yaml.Node, path string, underSecretFiles bool) []string {
	var out []string
	switch node.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for i, c := range node.Content {
			out = append(out, inlineSecrets(c, fmt.Sprintf("%s[%d]", path, i), underSecretFiles)...)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			k, v := node.Content[i].Value, node.Content[i+1]
			p := strings.TrimPrefix(path+"."+k, ".")
			pathLike := strings.HasSuffix(k, "_file") || strings.HasSuffix(k, "_path") || strings.HasSuffix(k, "_dir") ||
				strings.HasSuffix(k, "_files")
			if v.Kind == yaml.ScalarNode && secretKey(k) && !pathLike && !underSecretFiles && strings.TrimSpace(v.Value) != "" && v.Tag != "!!null" {
				out = append(out, p)
			}
			// secret_files (and lists of them, e.g. host_secret_files) name secrets by key and hold only paths.
			out = append(out, inlineSecrets(v, p, underSecretFiles || strings.HasSuffix(k, "secret_files"))...)
		}
	}
	return out
}

func checkInlineSecrets(data []byte) ([]string, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	return inlineSecrets(&doc, "", false), nil
}

// AC2 : no vars or inventory file in the repo carries a secret value; secrets are file paths only.
func TestInstaller_NoInlineSecrets(t *testing.T) {
	t.Parallel()
	// The rule itself, on inputs that must and must not pass.
	cases := []struct {
		name, yaml string
		bad        bool
	}{
		{"inline signing key", "webhook_signing_key: 3f9a0c", true},
		{"inline client secret", "oauth2:\n  client_secret: s3cr3t", true},
		{"inline token in inventory vars", "all:\n  vars:\n    cloudflare_token: abc", true},
		{"path under secret_files", "secret_files:\n  webhook_signing_key: ~/.config/x/key", false},
		{"_file path", "zitadel_admin_key_file: /x/key.json", false},
		{"empty", "headscale_oidc_client_secret: \"\"", false},
		{"not secret-like", "backup_keep: 10\nmonkey_key_count_dir: /x", false},
	}
	for _, c := range cases {
		got, err := checkInlineSecrets([]byte(c.yaml))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if (len(got) > 0) != c.bad {
			t.Errorf("%s: violations %v, want bad=%v", c.name, got, c.bad)
		}
	}

	var files []string
	root := adopttarget.AnsibleDir()
	if err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == ".ansible" {
			return filepath.SkipDir
		}
		rel, _ := filepath.Rel(root, p)
		isVars := strings.Contains(rel, "group_vars") || strings.Contains(rel, "host_vars") ||
			strings.Contains(rel, "/defaults/") || strings.Contains(rel, "/vars/") || strings.HasPrefix(filepath.Base(rel), "inventory") ||
			strings.HasPrefix(rel, "testdata")
		if !d.IsDir() && isVars && (strings.HasSuffix(p, ".yml") || strings.HasSuffix(p, ".yaml")) {
			files = append(files, p)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(files) < 3 {
		t.Fatalf("only %d vars/inventory files found", len(files))
	}
	for _, f := range files {
		data, err := os.ReadFile(f) // #nosec G304 -- repo file
		if err != nil {
			t.Fatal(err)
		}
		bad, err := checkInlineSecrets(data)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		for _, b := range bad {
			t.Errorf("%s: %s carries a value; secrets are file paths only (secret_files.* or *_file)", f, b)
		}
	}
}

// AC3 : a missing required setting or a wrong install_mode stops the run at the first task, naming it.
func TestInstaller_RequiredVarsAssert(t *testing.T) {
	t.Parallel()
	inv := localInventory(t)
	cases := []struct {
		name string
		vars map[string]any
		tags []string
		want string
		ok   bool
	}{
		{"empty domain", map[string]any{"install_env": "t", "install_mode": "adopt", "tagcess_domain": ""}, nil, "Zorunlu değişken boş: tagcess_domain", false},
		{"empty env", map[string]any{"install_mode": "adopt", "tagcess_domain": "example.test"}, nil, "Zorunlu değişken boş: install_env", false},
		{"empty mode for a writing phase", map[string]any{"install_env": "t", "tagcess_domain": "example.test"}, []string{"host"}, "Zorunlu değişken boş: install_mode", false},
		{"unknown mode", map[string]any{"install_env": "t", "tagcess_domain": "example.test", "install_mode": "upgrade"}, []string{"host"}, "install_mode 'upgrade' geçersiz", false},
		{"preflight proposes the mode", map[string]any{"install_env": "t", "tagcess_domain": "example.test"}, []string{"preflight"}, "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := adopttarget.RunPlaybook(t, adopttarget.PlaybookOpts{Playbook: "site.yml", Inventories: []string{inv}, Vars: c.vars, Tags: c.tags})
			if c.ok {
				if strings.Contains(res.Output, "Zorunlu değişken boş") {
					t.Fatalf("a preflight-only run must not require install_mode:\n%s", res.Output)
				}
				return
			}
			if res.ExitCode == 0 || !strings.Contains(res.Output, c.want) {
				t.Fatalf("want a failure naming %q, exit %d:\n%s", c.want, res.ExitCode, res.Output)
			}
			first := regexp.MustCompile(`(?m)^TASK \[(.*?)\]`).FindStringSubmatch(res.Output)
			if first == nil || !strings.HasPrefix(first[1], "config : ") {
				t.Fatalf("the first task must be the settings check, got %v", first)
			}
			if strings.Contains(res.Output, "TASK [state") || strings.Contains(res.Output, "TASK [preflight") {
				t.Fatalf("tasks ran after the failed settings check:\n%s", res.Output)
			}
		})
	}
}

// AC4 : make installer-lint runs ansible-lint and shellcheck when installed and reports "skipped" (no ok,
// never a PASS) when they are missing. `make check` depends on it.
func TestInstaller_LintWiring(t *testing.T) {
	t.Parallel()
	root := adopttarget.RepoRoot()
	mk, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`(?m)^check:.*\binstaller-lint\b`).Match(mk) {
		t.Fatal("make check does not depend on installer-lint")
	}
	run := func(withTools bool) (string, string) {
		bin := t.TempDir()
		logf := filepath.Join(t.TempDir(), "calls.log")
		if withTools {
			for _, tool := range []string{"ansible-lint", "shellcheck"} {
				script := "#!/bin/sh\necho \"" + tool + " $*\" >>" + logf + "\nexit 0\n"
				if err := os.WriteFile(filepath.Join(bin, tool), []byte(script), 0o755); err != nil { // #nosec G306 -- test stub
					t.Fatal(err)
				}
			}
		}
		cmd := exec.CommandContext(t.Context(), "/usr/bin/make", "-s", "installer-lint")
		cmd.Dir = root
		path := bin + ":/usr/bin:/bin"
		if !withTools {
			// A hermetic PATH: a runner may ship its own shellcheck in /usr/bin.
			for _, c := range []string{"env", "bash", "find", "sort", "dirname", "wc", "tr", "cat", "make"} {
				p, err := exec.LookPath(c)
				if err != nil {
					t.Skipf("%s is not installed; a skip is not a PASS", c)
				}
				if err := os.Symlink(p, filepath.Join(bin, c)); err != nil {
					t.Fatal(err)
				}
			}
			path = bin
		}
		cmd.Env = []string{"PATH=" + path, "HOME=" + t.TempDir()}
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		if err := cmd.Run(); err != nil {
			t.Fatalf("make installer-lint (tools=%v): %v\n%s", withTools, err, out.String())
		}
		calls, _ := os.ReadFile(logf) // #nosec G304 -- test file
		return out.String(), string(calls)
	}
	out, calls := run(true)
	for _, want := range []string{"ansible-lint ok", "shellcheck ok"} {
		if !strings.Contains(out, want) {
			t.Errorf("with the tools: %q missing:\n%s", want, out)
		}
	}
	if !strings.Contains(calls, "ansible-lint") || !strings.Contains(calls, "deploy/install.sh") && !strings.Contains(calls, "test/adopttarget/adopttarget.sh") {
		t.Errorf("the tools were not called on deploy/ansible and the shell scripts:\n%s", calls)
	}
	out, calls = run(false)
	if calls != "" || strings.Contains(out, " ok") {
		t.Errorf("without the tools nothing may run or claim ok:\n%s\n%s", out, calls)
	}
	for _, want := range []string{"ansible-lint skipped", "shellcheck skipped", "not a PASS"} {
		if !strings.Contains(out, want) {
			t.Errorf("without the tools: %q missing:\n%s", want, out)
		}
	}
}

// phasesYML reads group_vars/all/phases.yml.
func phasesYML(t *testing.T) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(adopttarget.AnsibleDir(), "group_vars", "all", "phases.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Phases []map[string]any `yaml:"tagcess_phases"`
	}
	if err := yaml.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	return v.Phases
}

// guideRun runs the guide role alone (testdata/guide.yml) on the local connection.
func guideRun(t *testing.T, home string, items []map[string]any, check bool) adopttarget.Result {
	t.Helper()
	itemsJSON, err := json.Marshal(items)
	if err != nil {
		t.Fatal(err)
	}
	return adopttarget.RunPlaybook(t, adopttarget.PlaybookOpts{
		Playbook: "testdata/guide.yml", Inventories: []string{localInventory(t)}, ConfigHome: home, Check: check,
		Vars:      map[string]any{"install_env": "guidetest", "tagcess_domain": "example.test", "install_mode": "adopt"},
		ExtraJSON: map[string]any{"guide_phase": "demo", "guide_items": json.RawMessage(itemsJSON)},
	})
}

type guideFile struct {
	Phase string `json:"phase"`
	Items []struct {
		ID     string   `json:"id"`
		Title  string   `json:"title"`
		Steps  []string `json:"steps"`
		Status string   `json:"status"`
	} `json:"items"`
}

func readGuide(t *testing.T, home, phase string) (guideFile, string) {
	t.Helper()
	dir := filepath.Join(home, "tagcess-install", "guidetest", "guide")
	data, err := os.ReadFile(filepath.Join(dir, phase+".json")) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatalf("guide json: %v", err)
	}
	var g guideFile
	if err := json.Unmarshal(data, &g); err != nil {
		t.Fatal(err)
	}
	md, err := os.ReadFile(filepath.Join(dir, phase+".md")) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatalf("guide md: %v", err)
	}
	return g, string(md)
}

var demoItems = []map[string]any{
	{"id": "dns-a-records", "title": "DNS A kayıtlarını ekle", "steps": []string{"hs.example.test → 203.0.113.10", "auth.example.test → 203.0.113.10"}},
	{"id": "done-check", "title": "Zaten yapılmış", "steps": []string{"x"}, "check": map[string]string{"cmd": "true"}},
	{"id": "pending-check", "title": "Bekleyen", "steps": []string{"y"}, "check": map[string]string{"cmd": "exit 1"}},
	{"id": "broken-check", "title": "Kontrol bozuk", "steps": []string{"z"}, "check": map[string]string{"cmd": "exit 7"}},
	{"id": "url-check", "title": "Erişilemez URL", "steps": []string{"w"}, "check": map[string]string{"url": "http://127.0.0.1:9/never"}},
}

// AC11 : a rerun rewrites the guide files (no duplicate items) and reports no change.
func TestGuide_RerunReplacesNoDuplicates(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	if res := guideRun(t, home, demoItems, false); res.ExitCode != 0 {
		t.Fatalf("first run:\n%s", res.Output)
	}
	res := guideRun(t, home, demoItems[:2], false)
	if res.ExitCode != 0 {
		t.Fatalf("second run:\n%s", res.Output)
	}
	if r := res.Recap["local-target"]; r.Changed != 0 {
		t.Fatalf("second run changed=%d (%v)", r.Changed, adopttarget.ChangedTasks(res.Output))
	}
	g, md := readGuide(t, home, "demo")
	if len(g.Items) != 2 || strings.Count(md, "## ") != 2 {
		t.Fatalf("the rerun must replace the file: %d items, md:\n%s", len(g.Items), md)
	}
}

// AC12 : checks set done / pending / unknown; a failing check never fails the phase.
func TestGuide_CheckStatus(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	res := guideRun(t, home, demoItems, false)
	if res.ExitCode != 0 {
		t.Fatalf("a failing check failed the phase:\n%s", res.Output)
	}
	g, md := readGuide(t, home, "demo")
	want := map[string]string{"dns-a-records": "manual", "done-check": "done", "pending-check": "pending", "broken-check": "unknown", "url-check": "unknown"}
	for _, it := range g.Items {
		if want[it.ID] != it.Status {
			t.Errorf("%s: status %q, want %q", it.ID, it.Status, want[it.ID])
		}
	}
	if g.Phase != "demo" || len(g.Items) != len(want) {
		t.Fatalf("guide file %+v", g)
	}
	for _, w := range []string{"# demo: elle yapılacaklar", "## DNS A kayıtlarını ekle", "Durum: yapıldı", "Durum: bekliyor", "1. hs.example.test"} {
		if !strings.Contains(md, w) {
			t.Errorf("md lacks %q:\n%s", w, md)
		}
	}
}

// AC14 : --check still writes the guide files (they are the plan output).
func TestGuide_CheckModeStillWrites(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	res := guideRun(t, home, demoItems[:1], true)
	if res.ExitCode != 0 {
		t.Fatalf("check run:\n%s", res.Output)
	}
	g, _ := readGuide(t, home, "demo")
	if len(g.Items) != 1 || g.Items[0].ID != "dns-a-records" {
		t.Fatalf("guide in check mode: %+v", g)
	}
}

// guideItemsSources are the role files that define guide items (set_fact guide_items_<phase>).
func guideItemsSources(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	roles := filepath.Join(adopttarget.AnsibleDir(), "roles")
	if err := filepath.WalkDir(roles, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || (!strings.HasSuffix(p, ".yml") && !strings.HasSuffix(p, ".j2")) {
			return err
		}
		data, err := os.ReadFile(p) // #nosec G304 -- repo file
		if err != nil {
			return err
		}
		if strings.Contains(string(data), "guide_items_") {
			out[p] = string(data)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// guideBlock returns the text of every `guide_items_<phase>:` value in a role file (up to the next task).
var guideBlockRE = regexp.MustCompile(`(?ms)guide_items_\w+:.*?(?:^- name:|\z)`)

// secretRef: a Jinja reference to a secret-like variable or a content-reading lookup.
var (
	secretVarRE   = regexp.MustCompile(`\{\{[^}]*\b\w*(secret|token|password|passwd|privkey|_key|apikey|_pat)\w*\b[^}]*\}\}`)
	contentReadRE = regexp.MustCompile(`lookup\(\s*['"](ansible\.builtin\.)?(file|password|pipe|env|template|unvault)['"]|slurp|b64decode`)
)

// AC13 : no guide item template refers to a secret-like variable or reads a file's content.
func TestGuide_NoSecretInTemplates(t *testing.T) {
	t.Parallel()
	// The rule on inputs that must and must not pass.
	for _, c := range []struct {
		text string
		bad  bool
	}{
		{"guide_items_x:\n  - steps: ['{{ secret_files.webhook_signing_key | basename }}']", true},
		{"guide_items_x:\n  - steps: [\"{{ lookup('ansible.builtin.file', p) }}\"]", true},
		{"guide_items_x:\n  - steps: ['{{ hs_host }} → {{ vpn_public_ip }}']", false},
		{"guide_items_x:\n  - steps: ['ADR 0009 anahtarını konsoldan oluştur']", false},
	} {
		blocks := guideBlockRE.FindAllString(c.text, -1)
		bad := false
		for _, b := range blocks {
			bad = bad || secretVarRE.MatchString(b) || contentReadRE.MatchString(b)
		}
		if bad != c.bad {
			t.Errorf("rule on %q: bad=%v, want %v", c.text, bad, c.bad)
		}
	}
	for path, text := range guideItemsSources(t) {
		for _, b := range guideBlockRE.FindAllString(text, -1) {
			if m := secretVarRE.FindString(b); m != "" {
				t.Errorf("%s: guide items refer to a secret-like variable: %s", path, m)
			}
			if m := contentReadRE.FindString(b); m != "" {
				t.Errorf("%s: guide items read file content: %s", path, m)
			}
		}
	}
}

// site.yml imports the phase roles in the order of phases.yml, each tagged with its phase name and guarded by
// its modes (F6 öneri 8: phases.yml is the single source of the order).
func TestSiteYml_PhaseOrderMatchesPhasesYml(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join(adopttarget.AnsibleDir(), "site.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var plays []struct {
		PreTasks []map[string]any `yaml:"pre_tasks"`
		Tasks    []map[string]any `yaml:"tasks"`
	}
	if err := yaml.Unmarshal(data, &plays); err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, task := range append(plays[0].PreTasks, plays[0].Tasks...) {
		name, _ := task["name"].(string)
		if strings.HasPrefix(name, "Preflight") {
			order = append(order, "preflight")
		}
		if n, ok := strings.CutPrefix(name, "Phase "); ok && !strings.Contains(n, ":") {
			order = append(order, n)
			tags, _ := task["tags"].([]any)
			if len(tags) != 1 || tags[0] != n {
				t.Errorf("phase %s is tagged %v, want [%s]", n, tags, n)
			}
			if w, _ := task["when"].(string); w != "install_mode in tagcess_phase_modes['"+n+"']" {
				t.Errorf("phase %s: when %q does not use its modes", n, w)
			}
		}
	}
	var want []string
	for _, p := range phasesYML(t) {
		want = append(want, p["name"].(string))
	}
	if !slices.Equal(order, want) {
		t.Fatalf("site.yml phase order\n %v\nphases.yml\n %v", order, want)
	}
}
