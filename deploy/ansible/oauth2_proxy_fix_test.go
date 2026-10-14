//go:build installer

package installer

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/test/adopttarget"
)

const fixDDir = "/etc/oauth2-proxy"

// fixD_secretFile writes a secret file with the given content and returns its path.
func fixD_secretFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// fixD_random is a random printable token of n characters.
func fixD_random(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)[:n]
}

// fixD_withSecrets adds secret_files entries to a vars map (the others stay).
func fixD_withSecrets(vars map[string]any, add map[string]string) map[string]any {
	sf := map[string]string{}
	for k, v := range vars["secret_files"].(map[string]string) {
		sf[k] = v
	}
	for k, v := range add {
		sf[k] = v
	}
	return adopttarget.Merge(vars, map[string]any{"secret_files": sf})
}

// fixD_state is everything a rollback must put back: the config, both secret files (byte for byte, with mode and
// owner), the service state and its main PID, and the leftovers a run must not leave.
func fixD_state(t *testing.T, tg *adopttarget.Target) string {
	t.Helper()
	return tg.Sh(t, `set -e
		cd `+fixDDir+`
		sha256sum oauth2-proxy.cfg client_secret cookie_secret
		stat -c '%n %a %U %G' oauth2-proxy.cfg client_secret cookie_secret
		systemctl is-active oauth2-proxy
		systemctl show oauth2-proxy -p MainPID --value`)
}

// fixD_noLeftovers asserts no candidate, check or saved copy stays behind in the config or the installer state dir.
func fixD_noLeftovers(t *testing.T, tg *adopttarget.Target) {
	t.Helper()
	out := tg.Sh(t, `ls -A `+fixDDir+`; ls -A /var/lib/tagcess-install 2>/dev/null || true`)
	for _, bad := range []string{".candidate", ".check", "oauth2-proxy-prev"} {
		if strings.Contains(out, bad) {
			t.Fatalf("leftover %q:\n%s", bad, out)
		}
	}
}

// H6 (F6-006): a secret-only rotation (the config text is identical) is applied by a restart; the live secret
// files change only at the commit, together with the restart.
func TestOAuth2ProxyRole_SecretRotationRestarts(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	vars := oauth2Vars(t)
	home := t.TempDir()
	mustRun(t, tg, home, vars, nil, "oauth2_proxy")
	pid := tg.Sh(t, "systemctl show oauth2-proxy -p MainPID --value")

	newCookie := fixD_random(32)
	rot := fixD_withSecrets(vars, map[string]string{"oauth2_proxy_cookie_secret": fixD_secretFile(t, "cookie_secret", newCookie)})
	mustRun(t, tg, home, rot, nil, "oauth2_proxy")
	if got := tg.ReadFile(t, fixDDir+"/cookie_secret"); got != newCookie {
		t.Fatalf("the rotated cookie secret is not on the host: %q", got)
	}
	if after := tg.Sh(t, "systemctl show oauth2-proxy -p MainPID --value"); after == pid {
		t.Fatal("a secret-only rotation did not restart oauth2-proxy (it still runs with the old secret)")
	}
	tg.Sh(t, `test "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:4180/ping)" = 200
		test "$(stat -c '%a %U %G' `+fixDDir+`/cookie_secret)" = "640 root oauth2-proxy"`)
	fixD_noLeftovers(t, tg)
	noChanges(t, tg, mustRun(t, tg, home, rot, nil, "oauth2_proxy"))
}

// H6 (F6-006): a new secret the candidate cannot start with (a cookie secret of the wrong length) never reaches the
// live files, and a restart whose /ping fails puts config, both secrets and the service state back as one unit.
func TestOAuth2ProxyRole_SecretRotationFailureRestoresOld(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	vars := oauth2Vars(t)
	home := t.TempDir()
	mustRun(t, tg, home, vars, nil, "oauth2_proxy")
	good := fixD_state(t, tg)

	// The candidate does not start (a 5-byte cookie secret): the live files and the service are untouched.
	bad := fixD_withSecrets(vars, map[string]string{
		"oauth2_proxy_client_secret": fixD_secretFile(t, "client_secret", fixD_random(24)),
		"oauth2_proxy_cookie_secret": fixD_secretFile(t, "cookie_secret", "short"),
	})
	res := runSite(t, tg, home, bad, nil, "oauth2_proxy")
	if res.ExitCode == 0 || !strings.Contains(res.Output, "Aday oauth2-proxy config'i başlamadı") {
		t.Fatalf("want the candidate check to stop:\n%s", tail(res.Output, 30))
	}
	if now := fixD_state(t, tg); now != good {
		t.Fatalf("the invalid secret reached the live files or the service changed:\n%s\n--- before\n%s", now, good)
	}
	fixD_noLeftovers(t, tg)

	// The candidate starts, the committed restart fails its /ping: everything goes back.
	newClient := fixD_random(24)
	ping := fixD_withSecrets(vars, map[string]string{
		"oauth2_proxy_client_secret": fixD_secretFile(t, "client_secret", newClient),
		"oauth2_proxy_cookie_secret": fixD_secretFile(t, "cookie_secret", fixD_random(32)),
	})
	ping["oauth2_proxy_ping_url"] = "http://127.0.0.1:4199/ping"
	ping["oauth2_proxy_cookie_profile"] = "tagcess"
	res = runSite(t, tg, home, ping, map[string]string{"confirm_oauth2_cookie": "yes"}, "oauth2_proxy")
	if res.ExitCode == 0 || !strings.Contains(res.Output, "eski config ve servis durumu geri konuldu") {
		t.Fatalf("want a rollback:\n%s", tail(res.Output, 30))
	}
	if strings.Contains(res.Output, newClient) {
		t.Fatal("the new client secret is in the output")
	}
	// Same files, but the restored service was restarted: compare everything except the PID line.
	strip := func(s string) string { return s[:strings.LastIndex(strings.TrimRight(s, "\n"), "\n")] }
	if now := fixD_state(t, tg); strip(now) != strip(good) {
		t.Fatalf("the previous config, secrets and state are not back:\n%s\n--- before\n%s", now, good)
	}
	tg.Sh(t, `test "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:4180/ping)" = 200`)
	fixD_noLeftovers(t, tg)
}

// fixD_leaks reports where a legacy inline secret (plain or base64 in any alignment) appears in the output.
func fixD_leaks(out string, secrets ...string) []string {
	var found []string
	for _, s := range secrets {
		if strings.Contains(out, s) {
			found = append(found, s)
		}
		for off := 0; off < 3; off++ {
			enc := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", off) + s))
			if len(enc) > 12 && strings.Contains(out, enc[4:len(enc)-4]) {
				found = append(found, "base64("+s+")")
				break
			}
		}
	}
	return found
}

// M3 (F6-006): an adopted config with inline client_secret/cookie_secret never reaches the output: not with -vvv,
// not with --diff, not on the failure path that puts the config back; that config comes back byte for byte.
func TestOAuth2ProxyRole_InlineSecretsNeverLogged(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	vars := oauth2Vars(t)
	home := t.TempDir()
	mustRun(t, tg, home, vars, nil, "oauth2_proxy")
	inlineClient, inlineCookie := "INLINE-CLIENT-"+fixD_random(24), "INLINE-COOKIE-"+fixD_random(24)
	legacy := tg.ReadFile(t, fixDDir+"/oauth2-proxy.cfg") + "client_secret = \"" + inlineClient + "\"\ncookie_secret = \"" + inlineCookie + "\"\n"
	tg.WriteFile(t, fixDDir+"/oauth2-proxy.cfg", legacy, "640", "root:oauth2-proxy")
	before := tg.Sh(t, "sha256sum "+fixDDir+"/oauth2-proxy.cfg")
	loud := []string{"ANSIBLE_VERBOSITY=3"}
	run := func(vars map[string]any, extra map[string]string) adopttarget.Result {
		return adopttarget.RunPlaybook(t, adopttarget.PlaybookOpts{Playbook: "site.yml", Inventories: []string{tg.Inventory}, ConfigHome: home,
			Vars: vars, ExtraVars: extra, Tags: []string{"oauth2_proxy"}, Diff: true, Env: loud})
	}
	switchCookie := adopttarget.Merge(vars, map[string]any{"oauth2_proxy_cookie_profile": "tagcess"})
	yes := map[string]string{"confirm_oauth2_cookie": "yes"}

	// --check --diff -vvv
	chk := adopttarget.RunPlaybook(t, adopttarget.PlaybookOpts{Playbook: "site.yml", Inventories: []string{tg.Inventory}, ConfigHome: home,
		Vars: switchCookie, ExtraVars: yes, Tags: []string{"oauth2_proxy"}, Diff: true, Check: true, Env: loud})
	if chk.ExitCode != 0 {
		t.Fatalf("--check:\n%s", tail(chk.Output, 30))
	}
	if l := fixD_leaks(chk.Output, inlineClient, inlineCookie); len(l) > 0 {
		t.Fatalf("--check --diff -vvv leaks %v", l)
	}

	// The failure path: the committed restart fails its /ping, the legacy config is put back.
	failing := adopttarget.Merge(switchCookie, map[string]any{"oauth2_proxy_ping_url": "http://127.0.0.1:4199/ping"})
	res := run(failing, yes)
	if res.ExitCode == 0 || !strings.Contains(res.Output, "eski config ve servis durumu geri konuldu") {
		t.Fatalf("want a rollback:\n%s", tail(res.Output, 30))
	}
	if l := fixD_leaks(res.Output, inlineClient, inlineCookie); len(l) > 0 {
		t.Fatalf("the failure path leaks %v", l)
	}
	if after := tg.Sh(t, "sha256sum "+fixDDir+"/oauth2-proxy.cfg"); after != before {
		t.Fatal("the legacy config is not back byte for byte")
	}

	// The success path.
	res = run(switchCookie, yes)
	if res.ExitCode != 0 {
		t.Fatalf("switch:\n%s", tail(res.Output, 30))
	}
	if l := fixD_leaks(res.Output, inlineClient, inlineCookie); len(l) > 0 {
		t.Fatalf("the success path leaks %v", l)
	}
}
