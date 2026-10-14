//go:build installer

package installer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/test/adopttarget"
)

type preflightJSON struct {
	ProposedMode string          `json:"proposed_mode"`
	Components   map[string]bool `json:"components"`
	Present      []string        `json:"present"`
	Missing      []string        `json:"missing"`
	Blockers     []string        `json:"blockers"`
	Warnings     []string        `json:"warnings"`
	Untouched    map[string]struct {
		Present bool   `json:"present"`
		Detail  string `json:"detail"`
	} `json:"untouched"`
	Headscale struct {
		PolicyMode       string `json:"policy_mode"`
		ExtraRecordsPath string `json:"extra_records_path"`
		PolicySHA256     string `json:"policy_sha256"`
		Version          string `json:"version"`
	} `json:"headscale"`
	OAuth2Proxy struct {
		Running  bool           `json:"running"`
		Unit     bool           `json:"unit"`
		Settings map[string]any `json:"settings"`
	} `json:"oauth2_proxy"`
}

// runSite runs site.yml against a target with settings and extra vars.
func runSite(t *testing.T, tg *adopttarget.Target, home string, vars map[string]any, extra map[string]string, tags ...string) adopttarget.Result {
	t.Helper()
	return adopttarget.RunPlaybook(t, adopttarget.PlaybookOpts{Playbook: "site.yml", Inventories: []string{tg.Inventory},
		ConfigHome: home, Vars: vars, ExtraVars: extra, Tags: tags})
}

func readPreflight(t *testing.T, home, env string) (preflightJSON, string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(envDir(home, env), "preflight.json")) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatalf("preflight.json: %v", err)
	}
	var p preflightJSON
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatalf("preflight.json: %v\n%s", err, data)
	}
	md, err := os.ReadFile(filepath.Join(envDir(home, env), "preflight.md")) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatalf("preflight.md: %v", err)
	}
	return p, string(md)
}

func hasBlocker(p preflightJSON, sub string) bool {
	return slices.ContainsFunc(p.Blockers, func(b string) bool { return strings.Contains(b, sub) })
}

// mustNotRunWritingPhase runs a writing phase and proves the run stopped in preflight before it.
func mustNotRunWritingPhase(t *testing.T, tg *adopttarget.Target, home string, vars map[string]any, extra map[string]string) {
	t.Helper()
	res := runSite(t, tg, home, vars, extra, "host")
	if res.ExitCode == 0 || !strings.Contains(res.Output, "Preflight engeli") {
		t.Fatalf("a writing phase ran past a preflight blocker (exit %d):\n%s", res.ExitCode, res.Output)
	}
	if strings.Contains(res.Output, "TASK [host :") || strings.Contains(res.Output, "TASK [state : State:") {
		t.Fatalf("host-phase tasks ran after the blocker:\n%s", res.Output)
	}
}

// AC1 (F6-002): preflight leaves /etc, /var/lib and /run unchanged.
func TestPreflight_ReadOnly(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	before := tg.Checksums(t, hostRoots)
	res := runSite(t, tg, t.TempDir(), adopttarget.AdoptVars(), nil, "preflight")
	if res.ExitCode != 0 || res.Recap[tg.Name].Changed != 0 {
		t.Fatalf("preflight: exit %d recap %+v\n%s", res.ExitCode, res.Recap[tg.Name], res.Output)
	}
	if d := adopttarget.DiffChecksums(before, tg.Checksums(t, hostRoots)); len(d) > 0 {
		t.Fatalf("preflight changed the host:\n%s", strings.Join(d, "\n"))
	}
	// --check gives the same report without writing either.
	res = adopttarget.RunPlaybook(t, adopttarget.PlaybookOpts{Playbook: "site.yml", Inventories: []string{tg.Inventory},
		Vars: adopttarget.AdoptVars(), Tags: []string{"preflight"}, Check: true})
	if res.ExitCode != 0 {
		t.Fatalf("preflight --check:\n%s", res.Output)
	}
	if d := adopttarget.DiffChecksums(before, tg.Checksums(t, hostRoots)); len(d) > 0 {
		t.Fatalf("preflight --check changed the host:\n%s", strings.Join(d, "\n"))
	}
}

// AC2 (F6-002): the adopt shape is reported (components, policy mode, DNS path, untouchables).
func TestPreflight_ReportsAdoptShape(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	home := t.TempDir()
	res := runSite(t, tg, home, adopttarget.AdoptVars(), nil, "preflight")
	if res.ExitCode != 0 {
		t.Fatalf("preflight:\n%s", res.Output)
	}
	p, md := readPreflight(t, home, "adopttest")
	for _, c := range []string{"headscale", "caddy", "oauth2_proxy", "certbot", "docker", "tailscale"} {
		if !p.Components[c] {
			t.Errorf("component %s not detected", c)
		}
	}
	if p.OAuth2Proxy.Running || !p.OAuth2Proxy.Unit || p.OAuth2Proxy.Settings["cookie_name"] != "_vpn_auth" {
		t.Errorf("oauth2-proxy: %+v", p.OAuth2Proxy)
	}
	if p.Headscale.PolicyMode != "file" || p.Headscale.ExtraRecordsPath != "/etc/headscale/extra-records.json" || len(p.Headscale.PolicySHA256) != 64 {
		t.Errorf("headscale: %+v", p.Headscale)
	}
	for _, u := range []string{"headplane", "wireguard", "wireguard-ui"} {
		if !p.Untouched[u].Present {
			t.Errorf("untouchable %s not reported", u)
		}
	}
	for _, w := range []string{"policy modu `file`", "/etc/headscale/extra-records.json", "headplane: var", "wireguard: var",
		"oauth2-proxy: var, durdurulmuş", "Dokunulmayacaklar"} {
		if !strings.Contains(md, w) {
			t.Errorf("report lacks %q:\n%s", w, md)
		}
	}
}

// AC3 (F6-002): on the empty target every core component is "to install" and nothing blocks.
func TestPreflight_BareReportsMissingNotBlocked(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "bare")
	home := t.TempDir()
	res := runSite(t, tg, home, adopttarget.BareVars(), nil, "preflight")
	if res.ExitCode != 0 {
		t.Fatalf("preflight on bare:\n%s", res.Output)
	}
	p, md := readPreflight(t, home, "baretest")
	if len(p.Blockers) != 0 {
		t.Fatalf("blockers on bare: %v", p.Blockers)
	}
	for _, c := range []string{"headscale", "caddy", "oauth2_proxy", "docker", "tailscale", "certbot"} {
		if !slices.Contains(p.Missing, c) {
			t.Errorf("%s not reported missing: %v", c, p.Missing)
		}
	}
	if !strings.Contains(md, "| headscale | eksik, kurulacak |") {
		t.Errorf("report:\n%s", md)
	}
}

// AC4 (F6-002): a version, certificate path or port mismatch on an existing component is a named blocker and
// stops every later phase.
func TestPreflight_BlocksOnMismatch(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	cases := []struct {
		name  string
		vars  map[string]any
		setup string
		want  string
	}{
		{"headscale version", map[string]any{"headscale_version": "0.29.3"}, "", "Headscale sürümü 0.29.4, beklenen 0.29.3"},
		{"certificate path", map[string]any{"cert_names": []string{"c.example.test", "missing.example.test"}}, "", "Sertifika yolu yok: /etc/letsencrypt/live/missing.example.test/"},
		{"hook port taken", nil, "systemd-run --unit=porthog python3 -m http.server 9443 --bind 127.0.0.1 && sleep 2", "Hook portu 9443 dolu"},
		{"headscale port", map[string]any{"headscale_health_url": "http://127.0.0.1:8081/health"}, "", "Headscale listen_addr 127.0.0.1:8080, beklenen 127.0.0.1:8081"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.setup != "" {
				tg.Sh(t, c.setup)
				defer tg.ShErr("systemctl stop porthog 2>/dev/null")
			}
			home := t.TempDir()
			vars := adopttarget.Merge(adopttarget.AdoptVars(), c.vars)
			res := runSite(t, tg, home, vars, nil, "preflight")
			p, _ := readPreflight(t, home, "adopttest")
			if res.ExitCode == 0 || !hasBlocker(p, c.want) {
				t.Fatalf("want blocker %q, got exit %d %v", c.want, res.ExitCode, p.Blockers)
			}
			mustNotRunWritingPhase(t, tg, home, vars, nil)
		})
	}
}

// AC5 (F6-002): secret files are only stat()ed: the output and the report carry mode/owner, never content.
func TestPreflight_NoSecretContent(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	marker := "PREFLIGHT-SECRET-MARKER-7f3a9c"
	tg.WriteFile(t, "/etc/oauth2-proxy/client_secret", marker, "0640", "root:oauth2-proxy")
	ctrl := filepath.Join(t.TempDir(), "webhook-signing-key")
	if err := os.WriteFile(ctrl, []byte(marker), 0o600); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	vars := adopttarget.Merge(adopttarget.AdoptVars(), map[string]any{"secret_files": map[string]string{"webhook_signing_key": ctrl}})
	res := runSite(t, tg, home, vars, nil, "preflight")
	if res.ExitCode != 0 {
		t.Fatalf("preflight:\n%s", res.Output)
	}
	_, md := readPreflight(t, home, "adopttest")
	raw, _ := os.ReadFile(filepath.Join(envDir(home, "adopttest"), "preflight.json")) // #nosec G304 -- test temp dir
	for name, text := range map[string]string{"output": res.Output, "report": md, "json": string(raw)} {
		if strings.Contains(text, marker) {
			t.Fatalf("the secret content reached the %s", name)
		}
	}
	for _, w := range []string{"host /etc/oauth2-proxy/client_secret: 0640 root:oauth2-proxy", "denetim makinesi webhook_signing_key: 0600 var"} {
		if !strings.Contains(md, w) {
			t.Errorf("report lacks %q:\n%s", w, md)
		}
	}
}

// AC6 (F6-002): a Caddyfile changed on disk without a reload (disk != running config) is a blocker.
func TestPreflight_BlocksOnCaddyDiskRuntimeDrift(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	tg.Sh(t, `printf 'extra.c.example.test {\n\timport vpn_only c.example.test\n}\n' >/etc/caddy/sites/extra.c.example.test.caddy`)
	home := t.TempDir()
	res := runSite(t, tg, home, adopttarget.AdoptVars(), nil, "preflight")
	p, _ := readPreflight(t, home, "adopttest")
	if res.ExitCode == 0 || !hasBlocker(p, "disk ve çalışan config ayrışmış") {
		t.Fatalf("want the drift blocker, got exit %d %v", res.ExitCode, p.Blockers)
	}
	mustNotRunWritingPhase(t, tg, home, adopttarget.AdoptVars(), nil)
	// After the reload the two agree again.
	tg.Sh(t, "systemctl reload caddy")
	if res := runSite(t, tg, t.TempDir(), adopttarget.AdoptVars(), nil, "preflight"); res.ExitCode != 0 {
		t.Fatalf("after reload:\n%s", res.Output)
	}
}

// AC7 (F6-002): an unreachable Zitadel discovery (zitadel_install_enabled false) or Headscale gRPC socket is a
// named blocker.
func TestPreflight_BlocksOnUnreachableDependency(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	for _, c := range []struct{ name, stop, start, want string }{
		{"zitadel", "systemctl stop zitadel-discovery-stub", "systemctl start zitadel-discovery-stub", "Zitadel OIDC discovery erişilemez"},
		{"headscale socket", "systemctl stop headscale", "systemctl start headscale", "Headscale gRPC soketi erişilemez"},
	} {
		t.Run(c.name, func(t *testing.T) {
			tg.Sh(t, c.stop)
			defer tg.Sh(t, c.start+" && sleep 2")
			home := t.TempDir()
			res := runSite(t, tg, home, adopttarget.AdoptVars(), nil, "preflight")
			p, _ := readPreflight(t, home, "adopttest")
			if res.ExitCode == 0 || !hasBlocker(p, c.want) {
				t.Fatalf("want %q, got exit %d %v", c.want, res.ExitCode, p.Blockers)
			}
			mustNotRunWritingPhase(t, tg, home, adopttarget.AdoptVars(), nil)
		})
	}
}

// AC10 (F6-002): fresh over an existing Headscale/Caddy is a named blocker; no writing phase runs.
func TestInstallMode_FreshOverExistingBlocked(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	home := t.TempDir()
	vars := adopttarget.Merge(adopttarget.AdoptVars(), map[string]any{"install_mode": "fresh"})
	res := runSite(t, tg, home, vars, nil, "preflight")
	p, _ := readPreflight(t, home, "adopttest")
	if res.ExitCode == 0 || !hasBlocker(p, "install_mode fresh, ama headscale, caddy zaten kurulu") {
		t.Fatalf("want the mode blocker, got exit %d %v", res.ExitCode, p.Blockers)
	}
	mustNotRunWritingPhase(t, tg, home, vars, nil)
}

// AC11 (F6-002): adopt on a host without any core component needs confirm_adopt_empty=yes.
func TestInstallMode_AdoptOnEmptyNeedsConfirm(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "bare")
	home := t.TempDir()
	vars := adopttarget.Merge(adopttarget.BareVars(), map[string]any{"install_mode": "adopt"})
	res := runSite(t, tg, home, vars, nil, "preflight")
	p, _ := readPreflight(t, home, "baretest")
	if res.ExitCode == 0 || !hasBlocker(p, "confirm_adopt_empty=yes") {
		t.Fatalf("want the empty-adopt blocker, got exit %d %v", res.ExitCode, p.Blockers)
	}
	mustNotRunWritingPhase(t, tg, home, vars, nil)
	res = runSite(t, tg, home, vars, map[string]string{"confirm_adopt_empty": "yes"}, "preflight")
	if res.ExitCode != 0 {
		t.Fatalf("with confirm_adopt_empty=yes:\n%s", res.Output)
	}
}

// AC12 (F6-002): only Headscale present (Caddy stopped and removed) proposes adopt and lists Caddy as added in adopt.
func TestInstallMode_PartialProposesAdoptWithMissing(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	tg.Sh(t, "systemctl stop caddy && DEBIAN_FRONTEND=noninteractive dpkg -r caddy >/dev/null")
	home := t.TempDir()
	vars := adopttarget.Merge(adopttarget.AdoptVars(), map[string]any{"cert_names": []string{}})
	res := runSite(t, tg, home, vars, nil, "preflight")
	if res.ExitCode != 0 {
		t.Fatalf("preflight:\n%s", res.Output)
	}
	p, md := readPreflight(t, home, "adopttest")
	if p.ProposedMode != "adopt" || !slices.Contains(p.Missing, "caddy") || slices.Contains(p.Present, "caddy") {
		t.Fatalf("proposal %q present %v missing %v", p.ProposedMode, p.Present, p.Missing)
	}
	if !strings.Contains(md, "| caddy | eksik, adopt'ta eklenecek |") {
		t.Fatalf("report:\n%s", md)
	}
}

// AC8 (F6-002): the empty target proposes fresh and lists the missing components.
func TestInstallMode_BareProposesFresh(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "bare")
	home := t.TempDir()
	vars := adopttarget.Merge(adopttarget.BareVars(), map[string]any{"install_mode": ""})
	if res := runSite(t, tg, home, vars, nil, "preflight"); res.ExitCode != 0 {
		t.Fatalf("preflight:\n%s", res.Output)
	}
	p, md := readPreflight(t, home, "baretest")
	if p.ProposedMode != "fresh" || !strings.Contains(md, "## Önerilen kip: `fresh`") || !slices.Contains(p.Missing, "headscale") || !slices.Contains(p.Missing, "caddy") {
		t.Fatalf("proposal %q missing %v:\n%s", p.ProposedMode, p.Missing, md)
	}
}

// AC9 (F6-002): the adopt shape proposes adopt and lists the components that exist.
func TestInstallMode_AdoptShapeProposesAdopt(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	home := t.TempDir()
	vars := adopttarget.Merge(adopttarget.AdoptVars(), map[string]any{"install_mode": ""})
	if res := runSite(t, tg, home, vars, nil, "preflight"); res.ExitCode != 0 {
		t.Fatalf("preflight:\n%s", res.Output)
	}
	p, md := readPreflight(t, home, "adopttest")
	if p.ProposedMode != "adopt" || !slices.Contains(p.Present, "headscale") || !slices.Contains(p.Present, "caddy") ||
		!strings.Contains(md, "## Önerilen kip: `adopt`") || !strings.Contains(md, "| headscale | var, devralınacak |") {
		t.Fatalf("proposal %q present %v:\n%s", p.ProposedMode, p.Present, md)
	}
}
