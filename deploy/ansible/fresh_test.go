//go:build installer

package installer

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/internal/render"
	"github.com/nesiler/tagcess/internal/site"
	"github.com/nesiler/tagcess/test/adopttarget"
)

// freshVars are the fresh settings of the empty target: test certificates (no Let's Encrypt), the bare seed, the
// target's own Headscale as the login server and a private network route.
func freshVars(t *testing.T) map[string]any {
	t.Helper()
	tok := filepath.Join(t.TempDir(), "cloudflare.ini")
	if err := os.WriteFile(tok, []byte("dns_cloudflare_api_token = "+strings.Repeat("Zx9", 14)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return adopttarget.Merge(adopttarget.BareVars(), map[string]any{
		"certbot_test_authenticator":   true,
		"secret_files":                 map[string]string{"cloudflare_token": tok},
		"site_seed_file":               filepath.Join(adopttarget.AnsibleDir(), "testdata", "seed-bare.json"),
		"app_zitadel_internal_sources": []string{"127.0.0.1/32", "::1/128"},
		"headscale_login_url":          "http://127.0.0.1:8080",
		"vpn_private_cidr":             "10.99.0.0/24",
	})
}

func secretOf(t *testing.T, vars map[string]any, key string) string {
	t.Helper()
	b, err := os.ReadFile(vars["secret_files"].(map[string]string)[key]) // #nosec G304 -- test temp file
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// discoveryStub answers Zitadel's discovery on the bare target (127.0.0.1:18080, BareVars), so preflight does not
// block once Caddy is installed (the real Zitadel is the lab's).
func discoveryStub(t *testing.T, tg *adopttarget.Target) {
	t.Helper()
	tg.Sh(t, `set -e
		mkdir -p /var/tmp/zstub/.well-known
		echo '{"issuer":"https://auth.lab.example.test"}' >/var/tmp/zstub/.well-known/openid-configuration
		systemd-run --unit zstub python3 -m http.server 18080 --bind 127.0.0.1 --directory /var/tmp/zstub >/dev/null
		for i in $(seq 1 50); do curl -sf -o /dev/null http://127.0.0.1:18080/.well-known/openid-configuration && exit 0; sleep 0.2; done; exit 1`)
}

func mainPID(t *testing.T, tg *adopttarget.Target, unit string) string {
	t.Helper()
	return tg.Sh(t, "systemctl show "+unit+" -p MainPID --value")
}

// AC1, AC4, AC5, AC6 (F6-012): Headscale on the empty target: the pinned package, the golden config and policy, both
// checks and /health; the OIDC second pass; a failing candidate keeps the old files; the second run changes nothing.
func TestHeadscaleInstall_FreshInstallsPinned(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "bare")
	vars := freshVars(t)
	home := t.TempDir()
	mustRun(t, tg, home, vars, nil, "headscale_install")
	tg.Sh(t, `set -e
		test "$(dpkg-query -W -f='${Version}' headscale)" = 0.29.4
		runuser -u headscale -- headscale configtest >/dev/null 2>&1
		headscale policy check -f /etc/headscale/policy.hujson >/dev/null 2>&1
		test "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/health)" = 200
		test "$(stat -c '%u:%G %a' /var/lib/tagcess/dns/extra-records.json)" = "10001:headscale 640"`)
	// The files on the host are the role's render with these settings.
	out := t.TempDir()
	if res := adopttarget.RunPlaybook(t, adopttarget.PlaybookOpts{Playbook: "testdata/headscale_render.yml", Inventories: []string{localInventory(t)},
		Vars: adopttarget.Merge(vars, map[string]any{"hs_render_dir": out})}); res.ExitCode != 0 {
		t.Fatalf("render:\n%s", res.Output)
	}
	for f, host := range map[string]string{"config.yaml": "/etc/headscale/config.yaml", "policy.hujson": "/etc/headscale/policy.hujson"} {
		want, _ := os.ReadFile(filepath.Join(out, f)) // #nosec G304 -- test temp dir
		if got := tg.ReadFile(t, host); got != string(want) {
			t.Errorf("%s on the host differs from the render:\n%s", host, got)
		}
	}

	t.Run("TestHeadscaleInstall_Idempotent", func(t *testing.T) {
		pid := mainPID(t, tg, "headscale")
		noChanges(t, tg, mustRun(t, tg, home, vars, nil, "headscale_install"))
		if mainPID(t, tg, "headscale") != pid {
			t.Fatal("Headscale restarted on a run without changes")
		}
	})
	t.Run("TestHeadscaleInstall_InvalidConfigKeepsOld", func(t *testing.T) {
		before := tg.Sh(t, "sha256sum /etc/headscale/config.yaml /etc/headscale/policy.hujson")
		pid := mainPID(t, tg, "headscale")
		res := runSite(t, tg, home, adopttarget.Merge(vars, map[string]any{"headscale_prefix_v4": "300.64.0.0/10"}), nil, "headscale_install")
		if res.ExitCode == 0 || !strings.Contains(res.Output, "configtest'ten geçmedi") {
			t.Fatalf("want the configtest stop:\n%s", tail(res.Output, 30))
		}
		if tg.Sh(t, "sha256sum /etc/headscale/config.yaml /etc/headscale/policy.hujson") != before || mainPID(t, tg, "headscale") != pid {
			t.Fatal("a failed candidate changed the files or restarted Headscale")
		}
		tg.Sh(t, "test ! -e /etc/headscale/config.candidate.yaml")
	})
	t.Run("TestHeadscaleInstall_OIDCSecondPass", func(t *testing.T) {
		sec, val := randomSecret(t, "hs-oidc-secret")
		v := adopttarget.Merge(vars, map[string]any{"headscale_oidc_client_id": "339000000000000003",
			"secret_files": map[string]string{"cloudflare_token": vars["secret_files"].(map[string]string)["cloudflare_token"], "headscale_oidc_client_secret": sec}})
		pid := mainPID(t, tg, "headscale")
		res := mustRun(t, tg, home, v, nil, "headscale_oidc")
		if strings.Contains(res.Output, val) {
			t.Fatal("the OIDC secret reached the output")
		}
		cfg := tg.ReadFile(t, "/etc/headscale/config.yaml")
		if !strings.Contains(cfg, `client_id: "339000000000000003"`) || !strings.Contains(cfg, "client_secret_path: /etc/headscale/oidc_client_secret") ||
			strings.Contains(cfg, val) {
			t.Fatalf("config:\n%s", cfg)
		}
		if got := tg.ReadFile(t, "/etc/headscale/oidc_client_secret"); got != val {
			t.Fatal("the secret file is not the controller file byte for byte")
		}
		tg.Sh(t, `test "$(stat -c '%U:%G %a' /etc/headscale/oidc_client_secret)" = "root:headscale 640"
			test "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/health)" = 200`)
		if mainPID(t, tg, "headscale") == pid {
			t.Fatal("Headscale did not restart with the OIDC block")
		}
		noChanges(t, tg, mustRun(t, tg, home, v, nil, "headscale_oidc"))
	})
}

// AC2 (F6-012): a .deb whose sha256 does not match stops before any package or file changes.
func TestHeadscaleInstall_ShaMismatchStops(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "bare")
	before := tg.Checksums(t, hostRoots)
	bad := strings.Repeat("0", 64)
	res := runSite(t, tg, t.TempDir(), adopttarget.Merge(freshVars(t), map[string]any{"headscale_deb_sha256": map[string]string{"amd64": bad, "arm64": bad}}),
		nil, "headscale_install")
	if res.ExitCode == 0 {
		t.Fatalf("a wrong sha256 went through:\n%s", tail(res.Output, 20))
	}
	tg.Sh(t, "! dpkg-query -W headscale >/dev/null 2>&1 && test ! -e /var/cache/tagcess-install/headscale_0.29.4_linux_$(dpkg --print-architecture).deb")
	if d := adopttarget.DiffChecksums(before, tg.Checksums(t, hostRoots)); len(d) > 0 {
		t.Fatalf("files changed:\n%s", strings.Join(d, "\n"))
	}
}

// AC3, AC9, AC14 (F6-012): on the adopt shape the install roles adopt Headscale, certbot and Caddy untouched: no
// file, package or service change, "devralındı". One run of the four phases; each AC checks its own component.
func TestFreshRoles_ExistingAdoptedUntouched(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	roots := map[string][]string{
		"headscale": {"/etc/headscale", "/usr/bin/headscale"},
		"certbot":   {"/etc/letsencrypt", "/usr/bin/certbot"},
		"caddy":     {"/etc/caddy", "/usr/bin/caddy"},
	}
	before := map[string]map[string]string{}
	for c, r := range roots {
		before[c] = tg.Checksums(t, r)
	}
	dpkg := tg.Sh(t, "dpkg-query -W headscale caddy certbot")
	hsPID, caddyPID := mainPID(t, tg, "headscale"), mainPID(t, tg, "caddy")
	caddyCfg := tg.Sh(t, "curl -s localhost:2019/config/ | sha256sum")
	res := mustRun(t, tg, t.TempDir(), adopttarget.AdoptVars(), nil, "certbot", "headscale_install", "caddy_install", "headscale_oidc")
	noChanges(t, tg, res)
	if tg.Sh(t, "dpkg-query -W headscale caddy certbot") != dpkg {
		t.Fatal("a package changed")
	}
	same := func(t *testing.T, c string) {
		t.Helper()
		if d := adopttarget.DiffChecksums(before[c], tg.Checksums(t, roots[c])); len(d) > 0 {
			t.Fatalf("%s files changed:\n%s", c, strings.Join(d, "\n"))
		}
	}
	t.Run("TestHeadscaleInstall_ExistingIsAdoptedUntouched", func(t *testing.T) {
		same(t, "headscale")
		if !strings.Contains(res.Output, "Headscale zaten kurulu ve bu araçla kurulmadı: devralındı") || strings.Contains(res.Output, "headscale_install : Config]") {
			t.Fatal("Headscale was not reported as adopted, or its config task ran")
		}
		if mainPID(t, tg, "headscale") != hsPID {
			t.Fatal("Headscale restarted")
		}
	})
	t.Run("TestCertbotRole_ExistingUntouched", func(t *testing.T) {
		same(t, "certbot")
		for _, w := range []string{"certbot zaten kurulu ve bu araçla kurulmadı: devralındı", "internal.a.example.test → "} {
			if !strings.Contains(res.Output, w) {
				t.Errorf("output lacks %q (expiry report)", w)
			}
		}
		if strings.Contains(res.Output, "certbot : Certificate") {
			t.Fatal("a certificate task ran")
		}
	})
	t.Run("TestCaddyInstall_ExistingIsAdoptedUntouched", func(t *testing.T) {
		same(t, "caddy")
		if !strings.Contains(res.Output, "Caddy zaten kurulu ve bu araçla kurulmadı: devralındı") || strings.Contains(res.Output, "caddy_install : Bootstrap Caddyfile in place") {
			t.Fatal("Caddy was not reported as adopted, or the bootstrap task ran")
		}
		if mainPID(t, tg, "caddy") != caddyPID || tg.Sh(t, "curl -s localhost:2019/config/ | sha256sum") != caddyCfg {
			t.Fatal("Caddy restarted or reloaded another config")
		}
	})
}

// AC7, AC8, AC10, AC11 (F6-012): certbot with the test authenticator: certificates per name, the deploy hook, the
// token byte for byte 0600 root outside /etc/caddy and never shown, the DNS guide item; the second run asks for nothing.
func TestCertbotRole_FreshIssuesCerts(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "bare")
	vars := adopttarget.Merge(freshVars(t), map[string]any{"cert_names": []string{"lab.example.test", "b.lab.example.test"}})
	home := t.TempDir()
	res := mustRun(t, tg, home, vars, nil, "certbot")
	tg.Sh(t, `set -e
		dpkg-query -W certbot python3-certbot-dns-cloudflare >/dev/null
		for n in lab.example.test b.lab.example.test; do
			test -s /etc/letsencrypt/live/$n/fullchain.pem && test -s /etc/letsencrypt/live/$n/privkey.pem
		done
		test "$(stat -c '%a %U' /etc/letsencrypt/renewal-hooks/deploy/tagcess-caddy.sh)" = "755 root"`)

	t.Run("TestCertbotRole_TokenOutsideCaddyNoLog", func(t *testing.T) {
		tok := secretOf(t, vars, "cloudflare_token")
		if got := tg.ReadFile(t, "/root/.secrets/certbot/cloudflare.ini"); got != tok {
			t.Fatal("the credentials file is not the controller file byte for byte")
		}
		tg.Sh(t, `test "$(stat -c '%a %U:%G' /root/.secrets/certbot/cloudflare.ini)" = "600 root:root" && ! grep -rqs dns_cloudflare_api_token /etc/caddy`)
		if strings.Contains(res.Output, strings.Repeat("Zx9", 14)) {
			t.Fatal("the token reached the output")
		}
	})
	t.Run("TestCertbotRole_DNSRecordsAsGuide", func(t *testing.T) {
		g, _ := os.ReadFile(filepath.Join(envDir(home, "baretest"), "guide", "certbot.json")) // #nosec G304 -- test temp dir
		for _, w := range []string{"certbot-dns-records", "hs.lab.example.test", "auth.lab.example.test", "tagcess.lab.example.test"} {
			if !strings.Contains(string(g), w) {
				t.Errorf("guide lacks %q: %s", w, g)
			}
		}
	})
	t.Run("TestCertbotRole_Idempotent", func(t *testing.T) {
		before := tg.Checksums(t, []string{"/etc/letsencrypt", "/root/.secrets"})
		noChanges(t, tg, mustRun(t, tg, home, vars, nil, "certbot"))
		if d := adopttarget.DiffChecksums(before, tg.Checksums(t, []string{"/etc/letsencrypt", "/root/.secrets"})); len(d) > 0 {
			t.Fatalf("a new certificate was requested:\n%s", strings.Join(d, "\n"))
		}
	})
}

// containerAdapter adapts a Caddyfile with the target's own Caddy (POST /adapt), as tagcess does.
func containerAdapter(t *testing.T, tg *adopttarget.Target) render.Adapter {
	return func(_ context.Context, caddyfile string) ([]byte, error) {
		tg.WriteFile(t, "/var/tmp/adapt.caddyfile", caddyfile, "0644", "root")
		out, err := tg.ShErr("curl -sf -X POST -H 'Content-Type: text/caddyfile' --data-binary @/var/tmp/adapt.caddyfile http://127.0.0.1:2019/adapt")
		if err != nil {
			return nil, fmt.Errorf("adapt: %v %s", err, out)
		}
		var w struct {
			Result json.RawMessage `json:"result"`
		}
		if err := json.Unmarshal([]byte(out), &w); err != nil {
			return nil, err
		}
		return w.Result, nil
	}
}

// AC12, AC13, AC15, AC16 (F6-012): Caddy on the empty target with the bootstrap Caddyfile (validate passes, running);
// the file is at first-import parity with the seed; a failing candidate changes nothing; the second run changes nothing.
func TestCaddyInstall_FreshInstallsAndRuns(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "bare")
	vars := freshVars(t)
	home := t.TempDir()
	mustRun(t, tg, home, vars, nil, "certbot", "headscale_install", "caddy_install")
	tg.Sh(t, `set -e
		test "$(dpkg-query -W -f='${Version}' caddy)" = 2.8.4
		caddy validate --adapter caddyfile --config /etc/caddy/Caddyfile >/dev/null 2>&1
		systemctl is-active -q caddy && systemctl is-enabled -q caddy
		test -d /etc/caddy/sites
		tail -1 /etc/caddy/Caddyfile | grep -qx 'import sites/\*\.caddy'`)

	t.Run("TestCaddyInstall_BootstrapParityEqual", func(t *testing.T) {
		seed, err := os.ReadFile(vars["site_seed_file"].(string)) // #nosec G304 -- repo testdata
		if err != nil {
			t.Fatal(err)
		}
		sites, err := site.PrepareSeed(seed, site.SeedOptions{ZitadelInternalSources: []string{"127.0.0.1/32", "::1/128"}})
		if err != nil {
			t.Fatal(err)
		}
		current := tg.ReadFile(t, "/etc/caddy/Caddyfile")
		cfg := render.CaddyConfig{ACMEEmail: "admin@lab.example.test", Certs: []string{"lab.example.test"}, ZitadelIssuer: "https://auth.lab.example.test"}
		if err := render.CheckSeedParity(context.Background(), containerAdapter(t, tg), current, sites, cfg); err != nil {
			t.Fatalf("bootstrap vs seed: %v", err)
		}
	})
	t.Run("TestCaddyInstall_Idempotent", func(t *testing.T) {
		discoveryStub(t, tg)
		noChanges(t, tg, mustRun(t, tg, home, vars, nil, "caddy_install"))
	})
	t.Run("TestCaddyInstall_ValidateFailKeepsOld", func(t *testing.T) {
		before := tg.Sh(t, "sha256sum /etc/caddy/Caddyfile; curl -s localhost:2019/config/ | sha256sum")
		res := runSite(t, tg, home, adopttarget.Merge(vars, map[string]any{"caddy_bootstrap_extra": "bozuk.example.test {\n\tnot_a_directive\n}"}), nil, "caddy_install")
		if res.ExitCode == 0 || !strings.Contains(res.Output, "caddy validate'ten geçmedi") {
			t.Fatalf("want the validate stop:\n%s", tail(res.Output, 30))
		}
		if tg.Sh(t, "sha256sum /etc/caddy/Caddyfile; curl -s localhost:2019/config/ | sha256sum") != before {
			t.Fatal("a failed candidate changed the file or the running config")
		}
		tg.Sh(t, "test ! -e /etc/caddy/Caddyfile.candidate")
	})
}

// AC17-AC21 (F6-012): tailscale joins the VPN host tagged with a one-time 10-minute key that is never kept, the private
// route is approved; an already joined node is left alone; without a k8s inventory group no k8s connection is tried.
func TestTailscaleJoin_FreshJoinsTagged(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "bare")
	vars := freshVars(t)
	home := t.TempDir()
	mustRun(t, tg, home, vars, nil, "headscale_install")
	res := mustRun(t, tg, home, vars, nil, "tailscale_join")
	nodes := tg.Sh(t, "headscale nodes list -o json")
	var list []struct {
		Name           string   `json:"name"`
		Tags           []string `json:"tags"`
		ApprovedRoutes []string `json:"approved_routes"`
	}
	if err := json.Unmarshal([]byte(nodes), &list); err != nil || len(list) != 1 {
		t.Fatalf("nodes: %v %s", err, nodes)
	}
	if strings.Join(list[0].Tags, ",") != "tag:vpn-server" {
		t.Errorf("tags %v", list[0].Tags)
	}
	t.Run("TestTailscaleJoin_RouteApproved", func(t *testing.T) {
		if strings.Join(list[0].ApprovedRoutes, ",") != "10.99.0.0/24" {
			t.Fatalf("approved routes %v", list[0].ApprovedRoutes)
		}
	})
	t.Run("TestTailscaleJoin_PreauthKeyNeverPersisted", func(t *testing.T) {
		keys := tg.Sh(t, "headscale preauthkeys list -o json")
		var ks []struct {
			Reusable   bool `json:"reusable"`
			Used       bool `json:"used"`
			Expiration struct {
				Seconds int64 `json:"seconds"`
			} `json:"expiration"`
			CreatedAt struct {
				Seconds int64 `json:"seconds"`
			} `json:"created_at"`
		}
		if err := json.Unmarshal([]byte(keys), &ks); err != nil || len(ks) != 1 {
			t.Fatalf("keys: %v %s", err, keys)
		}
		if ks[0].Reusable || !ks[0].Used || ks[0].Expiration.Seconds-ks[0].CreatedAt.Seconds > 600 {
			t.Fatalf("key is not one-time and short-lived: %+v", ks[0])
		}
		keyRE := regexp.MustCompile(`hskey-auth-[A-Za-z0-9_-]+|\b[0-9a-f]{48}\b`)
		if m := keyRE.FindString(res.Output); m != "" {
			t.Fatalf("a key reached the output: %s", m)
		}
		if out := tg.Sh(t, "grep -rlsE 'hskey-auth-' /etc /root /run /var/lib/tailscale /var/lib/tagcess-install /tmp /var/tmp || true"); out != "" {
			t.Fatalf("a key is kept on the host: %s", out)
		}
		if m := keyRE.FindString(readAll(t, home)); m != "" {
			t.Fatalf("a key is kept on the controller: %s", m)
		}
	})
	t.Run("TestTailscaleJoin_AlreadyJoinedNoOp", func(t *testing.T) {
		noChanges(t, tg, mustRun(t, tg, home, vars, nil, "tailscale_join"))
		var ks []any
		if err := json.Unmarshal([]byte(tg.Sh(t, "headscale preauthkeys list -o json")), &ks); err != nil || len(ks) != 1 {
			t.Fatalf("a new key was made (%d keys, %v)", len(ks), err)
		}
	})
	t.Run("TestTailscaleJoin_NoK8sHostWithoutGroup", func(t *testing.T) {
		if strings.Contains(res.Output, "(k8s") || strings.Contains(res.Output, "k8s-host") {
			t.Fatalf("a k8s connection was tried:\n%s", res.Output)
		}
		g, _ := os.ReadFile(filepath.Join(envDir(home, "baretest"), "guide", "tailscale_join.json")) // #nosec G304 -- test temp dir
		if !strings.Contains(string(g), "tailscale-k8s-join") {
			t.Fatalf("guide: %s", g)
		}
	})
}

// readAll concatenates every file under dir (controller-side leftovers check).
func readAll(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			c, _ := os.ReadFile(p) // #nosec G304 -- test temp dir
			b.Write(c)
		}
		return nil
	})
	return b.String()
}
