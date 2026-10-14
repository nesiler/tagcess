// M1 (F6 fix round): the secrets only the host phase needs (webhook/groups signing keys and the tagcess service user key,
// ADR 0009) are not asked for with the first settings. A fresh install has no Zitadel then, so the service user does not
// exist yet; install.sh asks when it enters the host phase, after zitadel_install and zitadel_seed.
package deploy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixE_settings answers ask_settings (vpn host .. site seed, then the optional Zitadel administrator key): no tagcess secret.
func fixE_settings(seed string) []string {
	return []string{"192.0.2.4", "", "", "example.test", "", "", "", "", "", "", "/etc/caddy/sites", "systemd", seed, ""}
}

// fixE_bareEnv writes an environment whose vars.yml names no secret file (an install that has not reached the host phase).
func fixE_bareEnv(t *testing.T, home, mode string) {
	t.Helper()
	dir := filepath.Join(home, "tagcess-install", "t")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	inv := "all:\n  children:\n    vpn:\n      hosts:\n        vpn-host:\n          ansible_host: \"192.0.2.4\"\n"
	vars := "all:\n  vars:\n    install_env: \"t\"\n    tagcess_domain: \"example.test\"\n    install_mode: \"" + mode + "\"\n"
	for name, body := range map[string]string{"inventory.yml": inv, "vars.yml": vars} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func fixE_vars(t *testing.T, r installRun) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(r.env, "vars.yml")) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

var fixE_freshEmpty = map[string]bool{"headscale": false, "caddy": false}

// A fresh install from an empty environment reaches its first phase without a service user key, signing key or any
// other Zitadel-dependent file, and asks for them only when the host phase starts (after zitadel_seed).
func TestInstallSh_FreshBareEnvDefersZitadelSecretsToHostPhase(t *testing.T) {
	t.Parallel()
	sec := t.TempDir()
	cf, _ := secretFile(t, sec, "cloudflare.ini", 0o600)
	webhook, wv := secretFile(t, sec, "webhook", 0o600)
	zkey, zv := secretFile(t, sec, "zkey", 0o600)
	seed, _ := filepath.Abs(filepath.Join("f5", "seed-sites.json"))
	pf := map[string]string{"preflight.json": preflightFixture(t, "fresh", fixE_freshEmpty, nil)}
	home := t.TempDir()

	// 1. Settings, mode, fresh settings, the first phase's confirmation: declined. Nothing about Zitadel secrets was asked.
	first := runInstall(t, installOpts{env: "t", home: home, fixtures: pf,
		stdin: answers(append(fixE_settings(seed), "fresh", cf, "hayır", "hayır")...)})
	if first.code != 3 || len(first.callsWith("certbot")) != 0 {
		t.Fatalf("want a stop at the first phase's confirmation (3), got %d:\n%s", first.code, first.out)
	}
	for _, asked := range []string{"Webhook imza anahtarı", "Groups imza anahtarı", "servis kullanıcısı anahtarı"} {
		if strings.Contains(first.out, asked) {
			t.Errorf("%q was asked before the host phase:\n%s", asked, first.out)
		}
	}
	v := fixE_vars(t, first)
	for _, k := range []string{"webhook_signing_key", "groups_signing_key", "zitadel_key"} {
		if strings.Contains(v, `"`+k+`"`) {
			t.Errorf("vars.yml names %s before the host phase:\n%s", k, v)
		}
	}
	if !strings.Contains(v, `"cloudflare_token"`) {
		t.Errorf("the phase-one secret (certbot) is not recorded:\n%s", v)
	}

	// 2. Resume through certbot .. backup (8 confirmations: zitadel_seed asks once in fresh); the host phase asks for the
	// files, then its own confirmation is declined.
	second := runInstall(t, installOpts{env: "t", home: home, args: []string{"--resume"}, fixtures: pf,
		stdin: repeat("evet", 8) + answers(webhook, "", zkey, "hayır")})
	if second.code != 3 || len(second.callsWith("host")) != 0 {
		t.Fatalf("want a stop at the host confirmation (3), got %d calls %q:\n%s", second.code, second.callsWith("host"), second.out)
	}
	hostAt := strings.Index(second.out, "== host ==")
	askAt := strings.Index(second.out, "Webhook imza anahtarı")
	zAt := strings.Index(second.out, "tagcess servis kullanıcısı anahtarı")
	if hostAt < 0 || askAt < hostAt || zAt < hostAt {
		t.Fatalf("the secrets are not asked inside the host phase (host %d, webhook %d, service user %d):\n%s", hostAt, askAt, zAt, second.out)
	}
	for _, p := range []string{"zitadel_seed", "backup"} {
		if len(second.callsWith(p)) == 0 {
			t.Errorf("phase %s did not run before the host phase", p)
		}
	}
	v = fixE_vars(t, second)
	for _, w := range []string{`"webhook_signing_key": "` + webhook + `"`, `"zitadel_key": "` + zkey + `"`, `"cloudflare_token"`} {
		if !strings.Contains(v, w) {
			t.Errorf("vars.yml lacks %q:\n%s", w, v)
		}
	}
	if strings.Contains(v, `"groups_signing_key"`) {
		t.Errorf("an empty optional answer was recorded:\n%s", v)
	}
	for _, sv := range []string{wv, zv} {
		if strings.Contains(second.out, sv) {
			t.Fatal("a secret value reached the output")
		}
	}

	// 3. The answers are kept: the next run asks again only for the optional groups key that was left empty.
	third := runInstall(t, installOpts{env: "t", home: home, args: []string{"--phase", "host"}, fixtures: pf, stdin: answers("", "evet")})
	if third.code != 0 || len(third.callsWith("host")) != 1 || strings.Contains(third.out, "Webhook imza anahtarı") ||
		strings.Contains(third.out, "servis kullanıcısı anahtarı") {
		t.Fatalf("host phase with the recorded files: %d %q\n%s", third.code, third.calls, third.out)
	}
}

// A key the zitadel_seed phase created (Actions target) is in <env>/zitadel.json: it is not asked again; the service user
// key never comes from there.
func TestInstallSh_HostSecretsSkipWhatSeedProduced(t *testing.T) {
	t.Parallel()
	sec := t.TempDir()
	zkey, _ := secretFile(t, sec, "zkey", 0o600)
	home := t.TempDir()
	fixE_bareEnv(t, home, "fresh")
	zj := "{\n  \"zitadel_project_id\": \"p1\",\n  \"secret_files\": {\n    \"groups_signing_key\": \"/x/groups\",\n    \"webhook_signing_key\": \"/x/webhook\"\n  }\n}\n"
	if err := os.WriteFile(filepath.Join(home, "tagcess-install", "t", "zitadel.json"), []byte(zj), 0o600); err != nil {
		t.Fatal(err)
	}
	r := runInstall(t, installOpts{home: home, args: []string{"--phase", "host"}, stdin: answers(zkey, "evet"),
		fixtures: map[string]string{"preflight.json": preflightFixture(t, "fresh", fixE_freshEmpty, nil)}})
	if r.code != 0 || len(r.callsWith("host")) != 1 {
		t.Fatalf("want the host call: %d %q\n%s", r.code, r.calls, r.out)
	}
	if strings.Contains(r.out, "Webhook imza anahtarı") || strings.Contains(r.out, "Groups imza anahtarı") {
		t.Errorf("a key the seed produced was asked again:\n%s", r.out)
	}
	if !strings.Contains(r.out, "servis kullanıcısı anahtarı") {
		t.Errorf("the service user key was not asked:\n%s", r.out)
	}
}

// The same checks as before apply when the host phase asks: no file inside the repo, no wide mode, an existing file.
func TestInstallSh_HostSecretsRefuseBadFiles(t *testing.T) {
	t.Parallel()
	sec := t.TempDir()
	webhook, _ := secretFile(t, sec, "webhook", 0o600)
	zkey, _ := secretFile(t, sec, "zkey", 0o600)
	wide, _ := secretFile(t, sec, "wide", 0o644)
	inRepo, _ := filepath.Abs(filepath.Join("testdata", "install", "fake-ansible-playbook.sh"))
	home := t.TempDir()
	fixE_bareEnv(t, home, "adopt")
	r := runInstall(t, installOpts{home: home, args: []string{"--phase", "host"},
		stdin:    answers(inRepo, wide, filepath.Join(sec, "missing"), webhook, "", zkey, "hayır"),
		fixtures: map[string]string{"preflight.json": preflightFixture(t, "adopt", allPresent(), nil)}})
	if r.code != 3 {
		t.Fatalf("want the host confirmation declined (3), got %d:\n%s", r.code, r.out)
	}
	for _, w := range []string{"repo içinde secret dosyası olmaz", "dosya modu 644", "dosya yok"} {
		if !strings.Contains(r.out, w) {
			t.Errorf("%q missing:\n%s", w, r.out)
		}
	}
	if v := fixE_vars(t, r); !strings.Contains(v, `"webhook_signing_key": "`+webhook+`"`) || strings.Contains(v, wide) {
		t.Errorf("vars.yml:\n%s", v)
	}
}

// --dry-run asks nothing, the host phase's secrets included.
func TestInstallSh_DryRunDoesNotAskHostSecrets(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	fixE_bareEnv(t, home, "adopt")
	r := runInstall(t, installOpts{home: home, args: []string{"--dry-run", "--phase", "host"},
		fixtures: map[string]string{"preflight.json": preflightFixture(t, "adopt", allPresent(), nil)}})
	if r.code != 0 || strings.Contains(r.out, "imza anahtarı") || strings.Contains(r.out, "servis kullanıcısı") {
		t.Fatalf("dry-run: %d\n%s", r.code, r.out)
	}
	if h := r.callsWith("host"); len(h) != 1 || !strings.Contains(h[0], "--check") {
		t.Fatalf("want one --check host call: %q", r.calls)
	}
}
