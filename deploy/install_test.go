// install.sh tests (F6-009). The script never reaches a host here: ANSIBLE_PLAYBOOK is a fake that logs its
// calls and plays the phase outputs (preflight.json, guide files, exit codes) from a fixture directory. The
// developer's answers come on stdin. Run with /bin/bash when it exists (macOS: bash 3.2, the oldest supported).
package deploy

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

type installRun struct {
	out   string
	code  int
	calls []string // one ansible-playbook call per entry (its arguments)
	env   string   // the environment directory
	home  string   // XDG_CONFIG_HOME
}

type installOpts struct {
	args     []string
	stdin    string
	env      string            // environment name (default "t")
	home     string            // XDG_CONFIG_HOME (default: a temp dir)
	fixtures map[string]string // FAKE_AP_DIR files
	askEnv   bool              // do not pass --env: the script asks for the name
}

func installBash() string {
	if _, err := os.Stat("/bin/bash"); err == nil {
		return "/bin/bash"
	}
	return "bash"
}

func runInstall(t *testing.T, o installOpts) installRun {
	t.Helper()
	if o.env == "" {
		o.env = "t"
	}
	if o.home == "" {
		o.home = t.TempDir()
	}
	if !o.askEnv && !slices.Contains(o.args, "--env") {
		o.args = append([]string{"--env", o.env}, o.args...)
	}
	fake := t.TempDir()
	for name, body := range o.fixtures {
		if err := os.WriteFile(filepath.Join(fake, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	logf := filepath.Join(t.TempDir(), "calls.log")
	script, err := filepath.Abs("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	fakeAP, _ := filepath.Abs(filepath.Join("testdata", "install", "fake-ansible-playbook.sh"))
	cmd := exec.CommandContext(t.Context(), installBash(), append([]string{script}, o.args...)...) // #nosec G204 -- test runs the repo script
	cmd.Env = append(os.Environ(), "XDG_CONFIG_HOME="+o.home, "ANSIBLE_PLAYBOOK="+fakeAP, "FAKE_AP_DIR="+fake, "FAKE_AP_LOG="+logf,
		"ANSIBLE_CONFIG=/nonexistent")
	cmd.Stdin = strings.NewReader(o.stdin)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := errors.AsType[*exec.ExitError](err); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	r := installRun{out: string(out), code: code, env: filepath.Join(o.home, "tagcess-install", o.env), home: o.home}
	if b, err := os.ReadFile(logf); err == nil { // #nosec G304 -- test temp file
		r.calls = strings.Split(strings.TrimSpace(string(b)), "\n")
	}
	return r
}

// callsWith returns the calls whose --tags is phase.
func (r installRun) callsWith(phase string) []string {
	var out []string
	for _, c := range r.calls {
		if strings.Contains(c+" ", "--tags "+phase+" ") {
			out = append(out, c)
		}
	}
	return out
}

func (r installRun) state(t *testing.T) string {
	t.Helper()
	b, _ := os.ReadFile(filepath.Join(r.env, "state")) // #nosec G304 -- test temp dir
	return string(b)
}

// preflightFixture is a preflight.json like the preflight role writes (to_nice_json, indent 2).
func preflightFixture(t *testing.T, proposed string, components map[string]bool, blockers []string) string {
	t.Helper()
	core := []string{}
	for _, c := range []string{"headscale", "caddy"} {
		if components[c] {
			core = append(core, c)
		}
	}
	if blockers == nil {
		blockers = []string{}
	}
	b, err := json.MarshalIndent(map[string]any{
		"proposed_mode": proposed, "install_mode": "", "components": components, "core_present": core,
		"blockers": blockers, "warnings": []string{},
		"headscale": map[string]any{"policy_sha256": policySHA, "version": "0.29.4"},
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return string(b) + "\n"
}

const policySHA = "3f2a6c1b9e8d7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a"

func allPresent() map[string]bool {
	return map[string]bool{"headscale": true, "caddy": true, "certbot": true, "oauth2_proxy": true, "docker": true,
		"tailscale": true, "hshelper": false, "tagcess": false, "zitadel": true}
}

// writeEnv creates an environment the script reuses without asking the settings questions.
func writeEnv(t *testing.T, home, env, mode string) {
	t.Helper()
	dir := filepath.Join(home, "tagcess-install", env)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	inv := "all:\n  children:\n    vpn:\n      hosts:\n        vpn-host:\n          ansible_host: \"192.0.2.4\"\n"
	vars := "all:\n  vars:\n    install_env: \"" + env + "\"\n    tagcess_domain: \"example.test\"\n"
	if mode != "" {
		vars += "    install_mode: \"" + mode + "\"\n"
	}
	// The tagcess secrets are asked when the host phase starts (M1); this environment already names them (an earlier
	// answer or a hand edit of vars.yml), so full runs here do not stop at those questions.
	sec := filepath.Join(home, "secrets-fixture")
	if err := os.MkdirAll(sec, 0o700); err != nil {
		t.Fatal(err)
	}
	var entries []string
	for _, k := range []string{"webhook_signing_key", "groups_signing_key", "zitadel_key"} {
		p := filepath.Join(sec, k)
		if err := os.WriteFile(p, []byte("fixture-"+k), 0o600); err != nil {
			t.Fatal(err)
		}
		entries = append(entries, `"`+k+`": "`+p+`"`)
	}
	vars += "    secret_files: {" + strings.Join(entries, ", ") + "}\n"
	for name, body := range map[string]string{"inventory.yml": inv, "vars.yml": vars} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func answers(lines ...string) string { return strings.Join(lines, "\n") + "\n" }

func repeat(s string, n int) string { return strings.Repeat(s+"\n", n) }

func secretFile(t *testing.T, dir, name string, mode os.FileMode) (string, string) {
	t.Helper()
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	val := "S3cr3t" + hex.EncodeToString(b)
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(val), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p, val
}

// settingsAnswers answers ask_settings in order (vpn host .. zitadel admin key). The tagcess secret files are not part of
// it: the host phase asks for them (M1, install_secrets_test.go).
func settingsAnswers(seed string) []string {
	return []string{"192.0.2.4", "", "", "example.test", "", "", "", "", "", "", "/etc/caddy/sites", "systemd", seed, ""}
}

// AC1 (F6-009): shellcheck finds nothing; bash 3.2 parses the script.
func TestInstallSh_Shellcheck(t *testing.T) {
	t.Parallel()
	sc, err := exec.LookPath("shellcheck")
	if err != nil {
		t.Skip("shellcheck not installed (skip is not a pass)")
	}
	for _, f := range []string{"install.sh", filepath.Join("testdata", "install", "fake-ansible-playbook.sh")} {
		if out, err := exec.CommandContext(t.Context(), sc, "-s", "bash", f).CombinedOutput(); err != nil { // #nosec G204 -- fixed repo files
			t.Fatalf("shellcheck %s:\n%s", f, out)
		}
	}
	if out, err := exec.CommandContext(t.Context(), installBash(), "-n", "install.sh").CombinedOutput(); err != nil { // #nosec G204 -- fixed repo file
		t.Fatalf("bash -n:\n%s", out)
	}
}

// AC2 (F6-009): the answers land only in the config directory outside the repo; a config directory or a secret file
// inside the repo is refused.
func TestInstallSh_WritesOutsideRepo(t *testing.T) {
	t.Parallel()
	seed, _ := filepath.Abs(filepath.Join("f5", "seed-sites.json"))
	inRepoSecret, _ := filepath.Abs(filepath.Join("testdata", "install", "fake-ansible-playbook.sh"))
	a := settingsAnswers(seed)
	// The settings still ask for the optional Zitadel administrator key: a file inside the repo is refused, asked again.
	a = append(a[:13], append([]string{inRepoSecret}, a[13:]...)...)
	r := runInstall(t, installOpts{env: "lab", stdin: answers(append(a, "vazgeç")...),
		fixtures: map[string]string{"preflight.json": preflightFixture(t, "adopt", allPresent(), nil)}})
	if r.code != 3 {
		t.Fatalf("want a stop at the mode question (3), got %d:\n%s", r.code, r.out)
	}
	if !strings.Contains(r.out, "repo içinde secret dosyası olmaz") {
		t.Errorf("a secret file in the repo was not refused:\n%s", r.out)
	}
	for _, f := range []string{"inventory.yml", "vars.yml"} {
		st, err := os.Stat(filepath.Join(r.env, f))
		if err != nil {
			t.Fatalf("%s not written: %v", f, err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v", f, st.Mode().Perm())
		}
	}
	vars, _ := os.ReadFile(filepath.Join(r.env, "vars.yml")) // #nosec G304 -- test temp dir
	for _, w := range []string{`install_env: "lab"`, `cert_names: ["example.test"]`, `traefik_port: 443`, `secret_files: {}`} {
		if !strings.Contains(string(vars), w) {
			t.Errorf("vars.yml lacks %q:\n%s", w, vars)
		}
	}

	t.Run("config dir inside the repo", func(t *testing.T) {
		home, _ := filepath.Abs(filepath.Join("testdata", "install", "xdg-must-not-exist"))
		r := runInstall(t, installOpts{home: home, stdin: answers("x"), askEnv: true})
		if r.code != 1 || !strings.Contains(r.out, "repo içinde olamaz") {
			t.Fatalf("want a refusal:\n%s", r.out)
		}
		if _, err := os.Stat(home); err == nil {
			_ = os.RemoveAll(home)
			t.Fatal("the script created a config directory inside the repo")
		}
		if len(r.calls) > 0 {
			t.Fatalf("ansible-playbook was called: %v", r.calls)
		}
	})
}

// AC3 (F6-009): the first call is --tags preflight only; a blocker stops before any writing phase.
func TestInstallSh_PreflightFirst(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	writeEnv(t, home, "t", "adopt")
	r := runInstall(t, installOpts{home: home, stdin: repeat("evet", 5), fixtures: map[string]string{
		"preflight.json": preflightFixture(t, "adopt", allPresent(), []string{"Hook portu 9443 dolu"}), "rc-preflight": "2"}})
	if r.code != 1 {
		t.Fatalf("want exit 1, got %d:\n%s", r.code, r.out)
	}
	if len(r.calls) != 1 || !strings.Contains(r.calls[0], "--tags preflight") {
		t.Fatalf("want exactly one preflight call, got %q", r.calls)
	}
	if !strings.Contains(r.out, "Hook portu 9443 dolu") || !strings.Contains(r.out, "hiçbir faz çağrılmadı") {
		t.Errorf("the blocker is not shown:\n%s", r.out)
	}

	ok := runInstall(t, installOpts{home: home, stdin: answers("hayır"),
		fixtures: map[string]string{"preflight.json": preflightFixture(t, "adopt", allPresent(), nil)}})
	if len(ok.calls) == 0 || !strings.HasSuffix(strings.Fields(ok.calls[0])[len(strings.Fields(ok.calls[0]))-1], "preflight") {
		t.Fatalf("the first call is not the preflight: %q", ok.calls)
	}
}

// AC4 (F6-009): a writing phase runs only after "evet"; any other answer skips it and stops.
func TestInstallSh_ConfirmBeforeEachWritingPhase(t *testing.T) {
	t.Parallel()
	pf := map[string]string{"preflight.json": preflightFixture(t, "adopt", allPresent(), nil)}
	for _, no := range []string{"hayır", "e", "EVET", "yes", ""} {
		home := t.TempDir()
		writeEnv(t, home, "t", "adopt")
		r := runInstall(t, installOpts{home: home, stdin: answers(no), fixtures: pf})
		if r.code != 3 {
			t.Fatalf("%q: want a stop (3), got %d:\n%s", no, r.code, r.out)
		}
		if len(r.calls) != 1 {
			t.Fatalf("%q: a phase ran without evet: %q", no, r.calls)
		}
		if !strings.Contains(r.state(t), "skipped certbot") {
			t.Errorf("%q: state: %s", no, r.state(t))
		}
	}
	home := t.TempDir()
	writeEnv(t, home, "t", "adopt")
	r := runInstall(t, installOpts{home: home, stdin: answers("evet", "hayır"), fixtures: pf})
	if len(r.callsWith("certbot")) != 1 || len(r.callsWith("headscale_install")) != 0 {
		t.Fatalf("want certbot only: %q", r.calls)
	}
	// Every writing phase of a full run was asked for.
	home = t.TempDir()
	writeEnv(t, home, "t", "adopt")
	full := runInstall(t, installOpts{home: home, stdin: repeat("evet", 80), fixtures: pf})
	if full.code != 0 {
		t.Fatalf("full run %d:\n%s", full.code, full.out)
	}
	for _, p := range []string{"certbot", "headscale_install", "caddy_install", "tailscale_join", "headscale_oidc", "backup", "host",
		"host_system", "hshelper", "oauth2_proxy", "caddy_ui", "app", "hs_tags", "hs_hook_acl", "hs_dns_path", "g02", "k8s_access"} {
		if !strings.Contains(full.out, "Faz '"+p+"' host'a yazacak") {
			t.Errorf("no confirmation asked for %s", p)
		}
	}
	for _, p := range []string{"verify", "verify_final"} {
		if strings.Contains(full.out, "Faz '"+p+"' host'a yazacak") {
			t.Errorf("read-only %s asked for a confirmation", p)
		}
	}
}

// AC5 (F6-009): --resume skips the phases the state records as done and goes on with the next one.
func TestInstallSh_Resume(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	writeEnv(t, home, "t", "adopt")
	pf := map[string]string{"preflight.json": preflightFixture(t, "adopt", allPresent(), nil)}
	// Interrupted: certbot, headscale_install done; caddy_install not confirmed.
	first := runInstall(t, installOpts{home: home, stdin: answers("evet", "evet", "hayır"), fixtures: pf})
	if first.code != 3 {
		t.Fatalf("first run %d:\n%s", first.code, first.out)
	}
	r := runInstall(t, installOpts{home: home, args: []string{"--resume"}, stdin: repeat("evet", 80), fixtures: pf})
	if r.code != 0 {
		t.Fatalf("resume %d:\n%s", r.code, r.out)
	}
	if len(r.callsWith("certbot")) != 0 || len(r.callsWith("headscale_install")) != 0 {
		t.Fatalf("done phases ran again: %q", r.calls)
	}
	if !strings.Contains(r.calls[0], "--tags preflight") || !strings.Contains(r.calls[1], "--tags caddy_install") {
		t.Fatalf("want preflight then caddy_install: %q", r.calls[:2])
	}
	if !strings.Contains(r.out, "certbot: tamamlanmış, atlandı") {
		t.Errorf("skip not shown:\n%s", r.out)
	}
	t.Run("no environment", func(t *testing.T) {
		r := runInstall(t, installOpts{args: []string{"--resume"}})
		if r.code != 1 || len(r.calls) != 0 {
			t.Fatalf("want a refusal: %d %q\n%s", r.code, r.calls, r.out)
		}
	})
}

// AC6 (F6-009): secret contents appear in no output and no written file; a secret file with a wide mode is refused.
func TestInstallSh_NeverPrintsSecrets(t *testing.T) {
	t.Parallel()
	sec := t.TempDir()
	webhook, wv := secretFile(t, sec, "webhook", 0o600)
	zkey, zv := secretFile(t, sec, "zkey", 0o640)
	wide, _ := secretFile(t, sec, "wide", 0o644)
	seed, _ := filepath.Abs(filepath.Join("f5", "seed-sites.json"))
	// adopt, everything present: certbot, headscale_install, caddy_install, tailscale_join, zitadel_seed (plan, Actions),
	// headscale_oidc, backup = 8 answers; then the host phase asks for the files (a 0644 one first), then evet for the rest.
	r := runInstall(t, installOpts{env: "lab", args: []string{"--env", "lab"},
		stdin:    answers(settingsAnswers(seed)...) + answers("adopt") + repeat("evet", 8) + answers(wide, webhook, "", zkey) + repeat("evet", 80),
		fixtures: map[string]string{"preflight.json": preflightFixture(t, "adopt", allPresent(), nil)}})
	if r.code != 0 {
		t.Fatalf("run %d:\n%s", r.code, r.out)
	}
	if !strings.Contains(r.out, "dosya modu 644") {
		t.Errorf("a 0644 secret file was not refused:\n%s", r.out)
	}
	for _, v := range []string{wv, zv} {
		if strings.Contains(r.out, v) || strings.Contains(strings.Join(r.calls, "\n"), v) {
			t.Fatal("a secret value reached the output or an ansible-playbook argument")
		}
		_ = filepath.WalkDir(r.home, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			if b, _ := os.ReadFile(p); strings.Contains(string(b), v) { // #nosec G304 -- test temp dir
				t.Errorf("secret value in %s", p)
			}
			return nil
		})
	}
}

// AC7 (F6-009): --dry-run passes --check --diff to every call, zitadel_seed_apply=false to zitadel_seed, asks nothing.
func TestInstallSh_DryRunUsesCheck(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"adopt", ""} {
		home := t.TempDir()
		writeEnv(t, home, "t", mode)
		r := runInstall(t, installOpts{home: home, args: []string{"--dry-run"}, stdin: "",
			fixtures: map[string]string{"preflight.json": preflightFixture(t, "adopt", allPresent(), nil),
				"guide-host.md": "# host\n- adım\n", "guide-host.json": `{"items":[{"id":"host-x"}]}`}})
		if r.code != 0 {
			t.Fatalf("mode %q: dry-run %d:\n%s", mode, r.code, r.out)
		}
		if len(r.calls) < 15 {
			t.Fatalf("mode %q: too few calls: %q", mode, r.calls)
		}
		for _, c := range r.calls {
			if !strings.Contains(c, "--check --diff") {
				t.Errorf("no --check --diff: %s", c)
			}
			if strings.Contains(c, "confirm_") || strings.Contains(c, "zitadel_seed_apply=true") {
				t.Errorf("a dry-run call carries a confirmation: %s", c)
			}
		}
		z := r.callsWith("zitadel_seed")
		if len(z) != 1 || !strings.Contains(z[0], "zitadel_seed_apply=false") {
			t.Errorf("zitadel_seed: %q", z)
		}
		if mode == "" {
			vars, _ := os.ReadFile(filepath.Join(r.env, "vars.yml")) // #nosec G304 -- test temp dir
			if strings.Contains(string(vars), "install_mode") {
				t.Errorf("dry-run wrote the mode:\n%s", vars)
			}
		}
		if strings.Contains(r.state(t), "done ") {
			t.Errorf("dry-run recorded phases as done: %s", r.state(t))
		}
	}
}

// AC8 (F6-009): --env selects tagcess-install/<name>/ only; a name with a path separator or .. is refused.
func TestInstallSh_EnvSelectsConfigDir(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	writeEnv(t, home, "prod", "adopt")
	r := runInstall(t, installOpts{home: home, env: "prod", args: []string{"--env", "prod"}, stdin: answers("hayır"),
		fixtures: map[string]string{"preflight.json": preflightFixture(t, "adopt", allPresent(), nil)}})
	if !strings.Contains(r.calls[0], filepath.Join(home, "tagcess-install", "prod", "inventory.yml")) {
		t.Fatalf("not the prod inventory: %q", r.calls[0])
	}
	entries, _ := os.ReadDir(filepath.Join(home, "tagcess-install"))
	if len(entries) != 1 || entries[0].Name() != "prod" {
		t.Fatalf("other directories were created: %v", entries)
	}
	for _, bad := range []string{"../x", "a/b", "..", ".hidden", "x..y", "a b", "x;rm"} {
		r := runInstall(t, installOpts{args: []string{"--env", bad}})
		if r.code != 1 || !strings.Contains(r.out, "geçersiz ortam adı") || len(r.calls) != 0 {
			t.Errorf("%q not refused: %d\n%s", bad, r.code, r.out)
		}
	}
}

var confirmVarRE = regexp.MustCompile(`(confirm_[a-z0-9_]+)=`)

// AC9 (F6-009): each confirmation reaches only its own phase call (g02 also gets the preflight policy hash); never
// in bulk, never in vars.yml.
func TestInstallSh_PassesConfirmOnlyToConfirmedPhase(t *testing.T) {
	t.Parallel()
	comps := allPresent()
	comps["docker"] = false
	home := t.TempDir()
	writeEnv(t, home, "t", "adopt")
	r := runInstall(t, installOpts{home: home, stdin: repeat("evet", 80),
		fixtures: map[string]string{"preflight.json": preflightFixture(t, "adopt", comps, nil)}})
	if r.code != 0 {
		t.Fatalf("run %d:\n%s", r.code, r.out)
	}
	want := map[string][]string{
		"host_system": {"confirm_host_system"}, "hs_tags": {"confirm_hs_tags"}, "hs_hook_acl": {"confirm_hs_hook_acl"},
		"hs_dns_path": {"confirm_hs_dns_path"}, "g02": {"confirm_g02"}, "oauth2_proxy": {"confirm_oauth2_cookie"},
		"host": {"confirm_add_missing"},
	}
	for _, c := range r.calls {
		f := strings.Fields(c)
		phase := ""
		for i := range f {
			if f[i] == "--tags" && i+1 < len(f) {
				phase = f[i+1]
			}
		}
		var got []string
		for _, m := range confirmVarRE.FindAllStringSubmatch(c, -1) {
			got = append(got, m[1])
		}
		if strings.Join(got, ",") != strings.Join(want[phase], ",") {
			t.Errorf("%s call confirmations %v, want %v: %s", phase, got, want[phase], c)
		}
	}
	if g := r.callsWith("g02"); len(g) != 1 || !strings.Contains(g[0], "expected_policy_sha256="+policySHA) {
		t.Errorf("g02: %q", g)
	}
	if h := r.callsWith("host"); len(h) != 1 || !strings.Contains(h[0], "confirm_add_missing=docker") {
		t.Errorf("host: %q", h)
	}
	if !strings.Contains(r.out, "'docker' hedefte yok") {
		t.Errorf("the missing component was not named:\n%s", r.out)
	}
	vars, _ := os.ReadFile(filepath.Join(r.env, "vars.yml")) // #nosec G304 -- test temp dir
	if strings.Contains(string(vars), "confirm_") {
		t.Errorf("vars.yml carries a confirmation:\n%s", vars)
	}

	t.Run("declined cookie switch", func(t *testing.T) {
		home := t.TempDir()
		writeEnv(t, home, "t", "adopt")
		// certbot..hshelper (11 evet incl. zitadel_seed apply + actions), oauth2_proxy evet, cookie hayır.
		in := repeat("evet", 11) + answers("evet", "hayır") + repeat("evet", 40)
		r := runInstall(t, installOpts{home: home, stdin: in, fixtures: map[string]string{"preflight.json": preflightFixture(t, "adopt", allPresent(), nil)}})
		o := r.callsWith("oauth2_proxy")
		if len(o) != 1 || strings.Contains(o[0], "confirm_oauth2_cookie") || strings.Contains(o[0], "cookie_profile") {
			t.Fatalf("oauth2_proxy: %q\n%s", o, r.out)
		}
	})
}

// AC10 (F6-009): the proposal and its reason are shown; nothing writes before the developer types fresh or adopt;
// the choice lands in vars.yml as install_mode.
func TestInstallSh_ModeProposedAndConfirmed(t *testing.T) {
	t.Parallel()
	pf := map[string]string{"preflight.json": preflightFixture(t, "adopt", allPresent(), nil)}
	home := t.TempDir()
	writeEnv(t, home, "t", "")
	r := runInstall(t, installOpts{home: home, stdin: answers("evet"), fixtures: pf})
	if r.code != 3 || len(r.calls) != 1 {
		t.Fatalf("want a stop before any phase: %d %q\n%s", r.code, r.calls, r.out)
	}
	for _, w := range []string{"Önerilen kip: adopt", "Gerekçe: hedefte çekirdek bileşen var (headscale caddy"} {
		if !strings.Contains(r.out, w) {
			t.Errorf("output lacks %q:\n%s", w, r.out)
		}
	}
	r = runInstall(t, installOpts{home: home, stdin: answers("adopt", "hayır"), fixtures: pf})
	vars, _ := os.ReadFile(filepath.Join(r.env, "vars.yml")) // #nosec G304 -- test temp dir
	if !strings.Contains(string(vars), `install_mode: "adopt"`) {
		t.Fatalf("mode not written:\n%s", vars)
	}
	if len(r.calls) != 2 || !strings.Contains(r.calls[1], "--tags preflight") {
		t.Fatalf("want the mode gate preflight again: %q", r.calls)
	}

	t.Run("fresh asks the fresh settings and refuses a production context", func(t *testing.T) {
		empty := map[string]bool{"headscale": false, "caddy": false}
		fpf := map[string]string{"preflight.json": preflightFixture(t, "fresh", empty, nil)}
		tok, _ := secretFile(t, t.TempDir(), "cf", 0o600)
		// The default production words (prod, production) refuse a context, case-insensitively.
		for _, ctx := range []string{"prod", "My-Production-Cluster", "k8s-prod-1"} {
			home := t.TempDir()
			writeEnv(t, home, "t", "")
			r := runInstall(t, installOpts{home: home, stdin: answers("fresh", tok, "evet", ctx), fixtures: fpf})
			if r.code != 1 || !strings.Contains(r.out, "üretim bağlamı reddedilir") {
				t.Fatalf("context %q: want a refusal:\n%s", ctx, r.out)
			}
		}
		// The environment's own list (vars.yml zitadel_forbidden_context_patterns) replaces the default.
		home := t.TempDir()
		writeEnv(t, home, "t", "")
		vf := filepath.Join(home, "tagcess-install", "t", "vars.yml")
		vb, err := os.ReadFile(vf) // #nosec G304 -- test temp dir
		if err != nil {
			t.Fatal(err)
		}
		vb = append(vb, []byte("    zitadel_forbidden_context_patterns: [\"Corp-Main\", live]\n")...)
		if err := os.WriteFile(vf, vb, 0o600); err != nil {
			t.Fatal(err)
		}
		r := runInstall(t, installOpts{home: home, stdin: answers("fresh", tok, "evet", "corp-main-k8s"), fixtures: fpf})
		if r.code != 1 || !strings.Contains(r.out, "üretim bağlamı reddedilir") {
			t.Fatalf("custom pattern: want a refusal:\n%s", r.out)
		}
		home = t.TempDir()
		writeEnv(t, home, "t", "")
		r = runInstall(t, installOpts{home: home, stdin: answers("fresh", tok, "evet", "lab-cluster", "lab-k8s", "hayır"), fixtures: fpf})
		vars, _ := os.ReadFile(filepath.Join(r.env, "vars.yml")) // #nosec G304 -- test temp dir
		for _, w := range []string{`install_mode: "fresh"`, `zitadel_install_enabled: true`, `zitadel_kube_context: "lab-cluster"`, `zitadel_expected_nodes: ["lab-k8s"]`, `"cloudflare_token": "` + tok} {
			if !strings.Contains(string(vars), w) {
				t.Errorf("vars.yml lacks %q:\n%s", w, vars)
			}
		}
	})
	t.Run("adopt on an empty host needs its own evet", func(t *testing.T) {
		empty := map[string]bool{"headscale": false, "caddy": false, "tagcess": false}
		fpf := map[string]string{"preflight.json": preflightFixture(t, "fresh", empty, nil)}
		home := t.TempDir()
		writeEnv(t, home, "t", "")
		r := runInstall(t, installOpts{home: home, stdin: answers("adopt", "hayır"), fixtures: fpf})
		vars, _ := os.ReadFile(filepath.Join(r.env, "vars.yml")) // #nosec G304 -- test temp dir
		if r.code != 3 || strings.Contains(string(vars), "install_mode") {
			t.Fatalf("adopt on an empty host went on: %d\n%s\n%s", r.code, r.out, vars)
		}
	})
}

// AC11 (F6-009): after a phase its guide is shown and the answer recorded; a guide with a secret-looking value stops.
func TestInstallSh_ShowsGuideAfterPhase(t *testing.T) {
	t.Parallel()
	pf := preflightFixture(t, "adopt", allPresent(), nil)
	home := t.TempDir()
	writeEnv(t, home, "t", "adopt")
	r := runInstall(t, installOpts{home: home, stdin: answers("evet", "y", "evet", "s", "hayır"), fixtures: map[string]string{"preflight.json": pf,
		"guide-certbot.md": "# certbot\n\nSertifika yenileme kancasını denetle.\n", "guide-certbot.json": `{"items":[{"id":"certbot-x"}]}`,
		"guide-headscale_install.md": "# hs\n\nAdım.\n", "guide-headscale_install.json": `{"items":[{"id":"hs-x"}]}`}})
	if !strings.Contains(r.out, "Sertifika yenileme kancasını denetle.") {
		t.Fatalf("guide not shown:\n%s", r.out)
	}
	st := r.state(t)
	if !strings.Contains(st, "guide certbot yapildi") || !strings.Contains(st, "guide headscale_install sonra") {
		t.Fatalf("state: %s", st)
	}
	home = t.TempDir()
	writeEnv(t, home, "t", "adopt")
	r = runInstall(t, installOpts{home: home, stdin: repeat("evet", 3), fixtures: map[string]string{"preflight.json": pf,
		"guide-certbot.md": "# certbot\n\ntoken: Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z\n", "guide-certbot.json": `{"items":[{"id":"certbot-x"}]}`}}) // gitleaks:allow (fake token: the test asserts it is rejected)
	if r.code != 1 || !strings.Contains(r.out, "secret biçimli") || strings.Contains(r.out, "Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z") {
		t.Fatalf("a secret-looking guide was shown or accepted: %d\n%s", r.code, r.out)
	}
	t.Run("hashes and paths are fine", func(t *testing.T) {
		home := t.TempDir()
		writeEnv(t, home, "t", "adopt")
		r := runInstall(t, installOpts{home: home, stdin: answers("evet", "y", "hayır"), fixtures: map[string]string{"preflight.json": pf,
			"guide-certbot.md": "# certbot\n\nsha256 " + policySHA + " /var/folders/Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z/x\n", "guide-certbot.json": `{"items":[{"id":"c"}]}`}})
		if strings.Contains(r.out, "secret biçimli") {
			t.Fatalf("false positive:\n%s", r.out)
		}
	})
}

// AC12 (F6-009): zitadel_seed: plan first, apply only after evet; Actions on an existing Zitadel only after their own evet; the
// groups execution is never enabled in an existing installation.
func TestInstallSh_ZitadelSeedPlanThenApply(t *testing.T) {
	t.Parallel()
	pf := map[string]string{"preflight.json": preflightFixture(t, "adopt", allPresent(), nil)}
	// adopt phases before zitadel_seed: certbot, headscale_install, caddy_install, tailscale_join (4 evet).
	cases := []struct {
		name, in        string
		apply           bool
		actions, groups string
	}{
		{"declined", repeat("evet", 4) + answers("hayır"), false, "", ""},
		{"apply without actions", repeat("evet", 5) + answers("hayır", "hayır"), true, "false", "false"},
		{"apply with actions", repeat("evet", 6) + answers("hayır"), true, "true", "false"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			home := t.TempDir()
			writeEnv(t, home, "t", "adopt")
			r := runInstall(t, installOpts{home: home, stdin: c.in, fixtures: pf})
			z := r.callsWith("zitadel_seed")
			if len(z) == 0 || !strings.Contains(z[0], "zitadel_seed_apply=false") {
				t.Fatalf("no plan call first: %q\n%s", z, r.out)
			}
			if !c.apply {
				if len(z) != 1 || r.code != 3 {
					t.Fatalf("applied without evet: %q", z)
				}
				return
			}
			if len(z) != 2 || !strings.Contains(z[1], "zitadel_seed_apply=true") ||
				!strings.Contains(z[1], "zitadel_seed_create_actions="+c.actions) || !strings.Contains(z[1], "zitadel_groups_execution="+c.groups) {
				t.Fatalf("apply call: %q", z)
			}
		})
	}
	t.Run("fresh lab creates actions and the groups execution", func(t *testing.T) {
		home := t.TempDir()
		writeEnv(t, home, "t", "fresh")
		empty := map[string]bool{"headscale": false, "caddy": false}
		// fresh phases before zitadel_seed: certbot, headscale_install, caddy_install, tailscale_join, zitadel_install.
		r := runInstall(t, installOpts{home: home, stdin: repeat("evet", 6) + answers("hayır"),
			fixtures: map[string]string{"preflight.json": preflightFixture(t, "fresh", empty, nil)}})
		z := r.callsWith("zitadel_seed")
		if len(z) != 2 || !strings.Contains(z[1], "zitadel_seed_create_actions=true") || !strings.Contains(z[1], "zitadel_groups_execution=true") {
			t.Fatalf("fresh apply: %q\n%s", z, r.out)
		}
	})
}

// --phase runs the preflight and then only that phase; a phase of the other mode is refused.
func TestInstallSh_PhaseRunsOnlyThatPhase(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	writeEnv(t, home, "t", "adopt")
	pf := map[string]string{"preflight.json": preflightFixture(t, "adopt", allPresent(), nil)}
	r := runInstall(t, installOpts{home: home, args: []string{"--phase", "verify"}, fixtures: pf})
	if r.code != 0 || len(r.calls) != 2 || !strings.Contains(r.calls[1], "--tags verify") {
		t.Fatalf("want preflight + verify: %d %q\n%s", r.code, r.calls, r.out)
	}
	r = runInstall(t, installOpts{home: home, args: []string{"--phase", "zitadel_install"}, fixtures: pf})
	if r.code != 1 || !strings.Contains(r.out, "adopt kipinde yok") || len(r.calls) != 1 {
		t.Fatalf("want a refusal after the preflight: %d %q\n%s", r.code, r.calls, r.out)
	}
	r = runInstall(t, installOpts{home: home, args: []string{"--phase", "nope"}, fixtures: pf})
	if r.code != 1 || len(r.calls) != 0 {
		t.Fatalf("unknown phase: %d %q", r.code, r.calls)
	}
}

// The domain and certificate names are host names; anything else (quotes, paths, spaces) stops before a file is written.
func TestInstallSh_RejectsBadNames(t *testing.T) {
	t.Parallel()
	seed, _ := filepath.Abs(filepath.Join("f5", "seed-sites.json"))
	for name, mutate := range map[string]func([]string){
		"domain quote": func(a []string) { a[3] = "x'y.test" },
		"domain path":  func(a []string) { a[3] = "../etc" },
		"cert dots":    func(a []string) { a[4] = "a..test" },
		"cert slash":   func(a []string) { a[4] = "a.test,b/c.test" },
	} {
		t.Run(name, func(t *testing.T) {
			a := settingsAnswers(seed)
			mutate(a)
			r := runInstall(t, installOpts{stdin: answers(a...)})
			if r.code != 1 || !strings.Contains(r.out, "geçersiz") || len(r.calls) != 0 {
				t.Fatalf("want a refusal: %d\n%s", r.code, r.out)
			}
			if _, err := os.Stat(filepath.Join(r.env, "vars.yml")); err == nil {
				t.Fatal("vars.yml was written")
			}
		})
	}
}
