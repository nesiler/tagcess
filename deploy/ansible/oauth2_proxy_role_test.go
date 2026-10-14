//go:build installer

package installer

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/test/adopttarget"
)

// oauth2Vars are the adopt settings with the lab Zitadel's oauth2-proxy app (its discovery answers, so oauth2-proxy
// really starts) and its client secret as a file.
func oauth2Vars(t *testing.T) map[string]any {
	t.Helper()
	z := needLabZitadel(t)
	env, err := os.ReadFile(filepath.Join(adopttarget.RepoRoot(), "test", "compose", ".env"))
	if err != nil {
		t.Skip("test/compose/.env missing")
	}
	var secret string
	sc := bufio.NewScanner(strings.NewReader(string(env)))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "OAUTH2_PROXY_CLIENT_SECRET="); ok {
			secret = strings.Trim(v, `"'`)
		}
	}
	if secret == "" || z.GateClientID == "" {
		t.Skip("lab oauth2-proxy app not in test/compose/.env")
	}
	p := filepath.Join(t.TempDir(), "client_secret")
	if err := os.WriteFile(p, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	return adopttarget.Merge(adopttarget.AdoptVars(), map[string]any{
		"zitadel_issuer": z.Issuer, "oauth2_proxy_client_id": z.GateClientID,
		"secret_files": map[string]string{"oauth2_proxy_client_secret": p},
	})
}

// AC2, AC5 (F6-006): oauth2-proxy runs (/ping 200, enabled), secrets are 0640 files, no Caddy file changes; the
// second run changes nothing and does not restart the service.
func TestOAuth2ProxyRole_RunsAndNeverTouchesCaddy(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	vars := oauth2Vars(t)
	caddy := tg.Checksums(t, caddyRoot)
	home := t.TempDir()
	res := mustRun(t, tg, home, vars, nil, "oauth2_proxy")
	if strings.Contains(res.Output, vars["secret_files"].(map[string]string)["oauth2_proxy_client_secret"]) {
		t.Log("(path shown, fine)")
	}
	tg.Sh(t, `set -e
		systemctl is-active -q oauth2-proxy && systemctl is-enabled -q oauth2-proxy
		test "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:4180/ping)" = 200
		test "$(stat -c '%a %U %G' /etc/oauth2-proxy/client_secret)" = "640 root oauth2-proxy"
		test "$(stat -c '%a %U %G' /etc/oauth2-proxy/cookie_secret)" = "640 root oauth2-proxy"
		! grep -Eq '^(client_secret|cookie_secret) =' /etc/oauth2-proxy/oauth2-proxy.cfg`)
	if d := adopttarget.DiffChecksums(caddy, tg.Checksums(t, caddyRoot)); len(d) > 0 {
		t.Fatalf("Caddy files changed:\n%s", strings.Join(d, "\n"))
	}
	t.Run("TestOAuth2ProxyRole_Idempotent", func(t *testing.T) {
		pid := tg.Sh(t, "systemctl show oauth2-proxy -p MainPID --value")
		noChanges(t, tg, mustRun(t, tg, home, vars, nil, "oauth2_proxy"))
		if after := tg.Sh(t, "systemctl show oauth2-proxy -p MainPID --value"); after != pid {
			t.Fatalf("oauth2-proxy restarted: %s -> %s", pid, after)
		}
	})
}

// AC3 (F6-006): adopt + cookie profile tagcess without confirm_oauth2_cookie keeps today's cookie and writes the
// guide step; with the confirmation the shared _tagcess_gate cookie is used.
func TestOAuth2ProxyRole_CookieSwitchNeedsConfirm(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	vars := adopttarget.Merge(oauth2Vars(t), map[string]any{"oauth2_proxy_cookie_profile": "tagcess"})
	home := t.TempDir()
	mustRun(t, tg, home, vars, nil, "oauth2_proxy")
	cfg := tg.ReadFile(t, "/etc/oauth2-proxy/oauth2-proxy.cfg")
	if !strings.Contains(cfg, `cookie_name = "_vpn_auth"`) || !strings.Contains(cfg, `cookie_expire = "12h"`) {
		t.Fatalf("the cookie changed without confirmation:\n%s", cfg)
	}
	g, _ := os.ReadFile(filepath.Join(envDir(home, "adopttest"), "guide", "oauth2_proxy.json")) // #nosec G304 -- test temp dir
	if !strings.Contains(string(g), "oauth2-proxy-cookie-switch") {
		t.Fatalf("guide: %s", g)
	}
	mustRun(t, tg, home, vars, map[string]string{"confirm_oauth2_cookie": "yes"}, "oauth2_proxy")
	cfg = tg.ReadFile(t, "/etc/oauth2-proxy/oauth2-proxy.cfg")
	if !strings.Contains(cfg, `cookie_name = "_tagcess_gate"`) || !strings.Contains(cfg, `cookie_expire = "1h"`) {
		t.Fatalf("confirmed switch not applied:\n%s", cfg)
	}
}

// AC4 (F6-006): a candidate that does not start, or a restart whose /ping is not 200, puts the previous config and
// service state back.
func TestOAuth2ProxyRole_InvalidConfigKeepsOld(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	vars := oauth2Vars(t)
	home := t.TempDir()
	mustRun(t, tg, home, vars, nil, "oauth2_proxy")
	state := func() string {
		return tg.Sh(t, "sha256sum /etc/oauth2-proxy/oauth2-proxy.cfg; systemctl is-active oauth2-proxy")
	}
	good := state()
	pid := tg.Sh(t, "systemctl show oauth2-proxy -p MainPID --value")

	// The candidate itself does not start (its issuer has no discovery): nothing changes, no restart.
	res := runSite(t, tg, home, adopttarget.Merge(vars, map[string]any{"zitadel_issuer": "https://discovery.invalid"}), nil, "oauth2_proxy")
	if res.ExitCode == 0 || !strings.Contains(res.Output, "Aday oauth2-proxy config'i başlamadı") {
		t.Fatalf("want the candidate check to stop:\n%s", res.Output)
	}
	if state() != good || tg.Sh(t, "systemctl show oauth2-proxy -p MainPID --value") != pid {
		t.Fatal("config or service changed after a failed candidate")
	}

	// The candidate starts but the restarted service does not answer the expected /ping: rolled back.
	bad := adopttarget.Merge(vars, map[string]any{"oauth2_proxy_ping_url": "http://127.0.0.1:4199/ping", "oauth2_proxy_cookie_profile": "tagcess"})
	res = runSite(t, tg, home, bad, map[string]string{"confirm_oauth2_cookie": "yes"}, "oauth2_proxy")
	if res.ExitCode == 0 || !strings.Contains(res.Output, "eski config ve servis durumu geri konuldu") {
		t.Fatalf("want a rollback:\n%s", res.Output)
	}
	if state() != good {
		t.Fatalf("the previous config/state is not back: %s vs %s", state(), good)
	}
}
