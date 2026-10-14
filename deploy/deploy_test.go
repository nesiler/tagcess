// Static checks for F1-019 deploy artifacts: the prod compose mounts match architecture.md §8 (with
// their modes), the Caddy snippet strips client identity headers before forward_auth, and the example
// config carries secret file paths only. Nothing here talks to docker; the image build test lives in
// image_test.go behind the `image` build tag and runs via `make image-test`.
package deploy_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/nesiler/tagcess/internal/config"
)

const caddyImage = "caddy:2.8.4"

// AC2: the prod compose runs on host networking read-only and defines every architecture.md §8 mount
// with its mode.
func TestDeploy_ComposeMatchesArchitecture(t *testing.T) {
	want := architectureMounts(t)
	if len(want) == 0 {
		t.Fatal("parsed no mounts from architecture.md §8; the table format changed")
	}

	var doc struct {
		Services map[string]struct {
			NetworkMode string   `yaml:"network_mode"`
			ReadOnly    bool     `yaml:"read_only"`
			Restart     string   `yaml:"restart"`
			Volumes     []string `yaml:"volumes"`
			CapDrop     []string `yaml:"cap_drop"`
			SecurityOpt []string `yaml:"security_opt"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(readFile(t, "compose.yaml")), &doc); err != nil {
		t.Fatalf("parse compose.yaml: %v", err)
	}
	svc, ok := doc.Services["tagcess"]
	if !ok {
		t.Fatal("compose.yaml has no tagcess service")
	}
	if svc.NetworkMode != "host" {
		t.Errorf("network_mode = %q, want host", svc.NetworkMode)
	}
	if !svc.ReadOnly {
		t.Error("read_only must be true")
	}
	if svc.Restart != "unless-stopped" {
		t.Errorf("restart = %q, want unless-stopped", svc.Restart)
	}
	if len(svc.CapDrop) != 1 || svc.CapDrop[0] != "ALL" {
		t.Errorf("cap_drop = %v, want [ALL]", svc.CapDrop)
	}
	if !slices.Contains(svc.SecurityOpt, "no-new-privileges:true") {
		t.Errorf("security_opt = %v, want to include no-new-privileges:true", svc.SecurityOpt)
	}

	got := map[string]string{}
	for _, v := range svc.Volumes {
		src, dst, mode := splitMount(t, v)
		if src != dst {
			t.Errorf("mount %q binds a different target; tagcess mounts host paths at the same path", v)
		}
		if _, dup := got[dst]; dup {
			t.Errorf("mount target %q is defined twice", dst)
		}
		got[dst] = mode
	}

	// The config file is not in the §8 table (it is passed with -config); it is the one allowed extra.
	allowedExtra := map[string]string{"/etc/tagcess/config.yaml": "ro"}
	for target, mode := range want {
		gotMode, ok := got[target]
		if !ok {
			t.Errorf("architecture mount %q (%s) is missing from compose.yaml", target, mode)
			continue
		}
		if gotMode != mode {
			t.Errorf("mount %q mode = %s, want %s", target, gotMode, mode)
		}
	}
	for target, mode := range got {
		if _, ok := want[target]; ok {
			continue
		}
		if m, ok := allowedExtra[target]; !ok || m != mode {
			t.Errorf("unexpected mount %q (%s): not in architecture.md §8", target, mode)
		}
	}
}

// AC1 (F3b-012): the prod compose mounts only the two ADR 0021 b directories: requests rw for the
// patch request and results ro for result/status. The helper's private dir, the real Headscale
// config and the old hostapply dir are not mounted.
func TestDeployCompose_HostApplyMounts(t *testing.T) {
	got := composeVolumes(t)
	for target, mode := range map[string]string{
		"/var/lib/tagcess-headscale/requests": "rw",
		"/var/lib/tagcess-headscale/results":  "ro",
	} {
		if got[target] != mode {
			t.Errorf("compose mount %q = %q, want %q", target, got[target], mode)
		}
	}
	for _, banned := range []string{
		"/var/lib/tagcess-headscale/private",
		"/var/lib/tagcess-hostapply",
		"/etc/headscale/config.yaml",
	} {
		if _, ok := got[banned]; ok {
			t.Errorf("compose must not mount %q (ADR 0021 b)", banned)
		}
	}
}

// AC2 (F3b-012): the example config carries the F3b-011 hostapply settings as clean absolute paths
// that are exactly the directories compose mounts, and no secret values.
func TestDeployConfigExample_HostApplyPaths(t *testing.T) {
	cfg, err := config.Load("config.example.yaml")
	if err != nil {
		t.Fatalf("example config must load with the strict loader: %v", err)
	}
	if !cfg.HostApply.Enabled() {
		t.Fatal("example config must show the hostapply settings (F3b-011)")
	}
	mounts := composeVolumes(t)
	for name, pair := range map[string]struct{ got, target string }{
		"hostapply.requests_dir": {cfg.HostApply.RequestsDir, "/var/lib/tagcess-headscale/requests"},
		"hostapply.results_dir":  {cfg.HostApply.ResultsDir, "/var/lib/tagcess-headscale/results"},
	} {
		if !filepath.IsAbs(pair.got) || filepath.Clean(pair.got) != pair.got {
			t.Errorf("%s = %q, want a clean absolute path", name, pair.got)
		}
		if _, ok := mounts[pair.got]; !ok {
			t.Errorf("%s = %q is not a compose mount path", name, pair.got)
		}
		if pair.got != pair.target {
			t.Errorf("%s = %q, want the compose path %q", name, pair.got, pair.target)
		}
	}
	raw := readFile(t, "config.example.yaml")
	for _, marker := range []string{"-----BEGIN", "PRIVATE KEY", "clientSecret", `"password"`} {
		if strings.Contains(raw, marker) {
			t.Errorf("example config contains a secret value (%q)", marker)
		}
	}
}

// AC3: the snippet is valid and removes the client's X-Auth-Request-* headers before the
// forward_auth subrequest, so only oauth2-proxy can set them (security.md §3.1).
func TestDeploy_CaddySnippetStripsHeaders(t *testing.T) {
	raw := readFile(t, filepath.Join("caddy", "tagcess.caddy"))

	for _, want := range []string{
		"remote_ip 100.64.0.0/10",
		"respond 403",
		"allowed_groups=devops",
		"reverse_proxy unix//run/tagcess/ui.sock",
		"copy_headers X-Auth-Request-User X-Auth-Request-Email X-Auth-Request-Groups",
		"handle /oauth2/*",
		"redir * /oauth2/start?rd={http.request.uri}",
	} {
		if !strings.Contains(raw, want) {
			t.Errorf("snippet is missing %q", want)
		}
	}

	code := nonCommentLines(raw)
	forward := indexContaining(code, "forward_auth ")
	if forward < 0 {
		t.Fatal("snippet has no forward_auth directive")
	}
	for _, h := range []string{"X-Auth-Request-User", "X-Auth-Request-Email", "X-Auth-Request-Groups"} {
		strip := indexContaining(code, "request_header -"+h)
		if strip < 0 {
			t.Errorf("snippet does not delete client header %s (want `request_header -%s`)", h, h)
			continue
		}
		if strip > forward {
			t.Errorf("delete of %s runs after forward_auth (%d > %d)", h, strip, forward)
		}
	}

	t.Run("caddy adapt", func(t *testing.T) {
		adapted := adaptCaddy(t, raw)
		auth := bytes.Index(adapted, []byte("allowed_groups=devops"))
		if auth < 0 {
			t.Fatal("adapted config has no auth subrequest")
		}
		for _, h := range []string{"X-Auth-Request-User", "X-Auth-Request-Email", "X-Auth-Request-Groups"} {
			del := bytes.Index(adapted, []byte(`"delete":["`+h+`"]`))
			if del < 0 || del > auth {
				t.Errorf("adapted config: delete of %s (at %d) must run before the auth subrequest (at %d)", h, del, auth)
			}
		}
		if !bytes.Contains(adapted, []byte("/oauth2/start?rd=")) {
			t.Error("adapted config is missing the 401 -> /oauth2/start redirect")
		}
	})
}

// AC4: the example config holds secret file paths, never secret values. The strict loader rejects any
// unknown field, so a plaintext secret added to the file fails this test.
func TestDeploy_ExampleConfigNoSecrets(t *testing.T) {
	cfg, err := config.Load("config.example.yaml")
	if err != nil {
		t.Fatalf("example config must load with the strict loader: %v", err)
	}
	for name, p := range map[string]string{
		"hook.signing_key_file": string(cfg.Hook.SigningKeyFile),
		"zitadel.key_file":      string(cfg.Zitadel.KeyFile),
	} {
		if !filepath.IsAbs(p) {
			t.Errorf("%s = %q, want a clean absolute file path", name, p)
		}
	}
	raw := readFile(t, "config.example.yaml")
	for _, marker := range []string{"-----BEGIN", "PRIVATE KEY", "clientSecret", `"password"`} {
		if strings.Contains(raw, marker) {
			t.Errorf("example config contains a secret value (%q)", marker)
		}
	}
}

// adaptCaddy runs `caddy adapt` over a Caddyfile (snippet) and returns the adapted JSON. It uses a
// caddy binary if present or a cached caddy image, and skips when neither is available so `make
// check` needs no docker or network.
func adaptCaddy(t *testing.T, caddyfile string) []byte {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "snippet.caddy")
	if err := os.WriteFile(path, []byte(caddyfile), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	var cmd *exec.Cmd
	if bin, err := exec.LookPath("caddy"); err == nil {
		cmd = exec.CommandContext(ctx, bin, "adapt", "--config", path, "--adapter", "caddyfile")
	} else if bin, err := exec.LookPath("docker"); err == nil && exec.CommandContext(ctx, bin, "image", "inspect", caddyImage).Run() == nil {
		cmd = exec.CommandContext(ctx, bin, "run", "--rm", "-v", dir+":/w:ro", caddyImage,
			"caddy", "adapt", "--config", "/w/snippet.caddy", "--adapter", "caddyfile")
	} else {
		t.Skipf("no caddy binary and no cached %s image; skipping adapt", caddyImage)
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("caddy adapt rejected the snippet: %v\n%s", err, out)
	}
	if !json.Valid(out) {
		t.Fatalf("caddy adapt did not return JSON: %s", out)
	}
	return out
}

// architectureMounts reads the mount table of architecture.md §8 as target -> mode (rw/ro).
func architectureMounts(t *testing.T) map[string]string {
	t.Helper()
	raw := readFile(t, filepath.Join("..", "docs", "architecture.md"))
	mounts := map[string]string{}
	inTable := false
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "| Path | Mode") {
			inTable = true
			continue
		}
		if !inTable {
			continue
		}
		if !strings.HasPrefix(line, "|") {
			break
		}
		cells := tableCells(line)
		if len(cells) < 2 {
			continue
		}
		mode := cells[1]
		if mode != "rw" && mode != "ro" {
			continue
		}
		// A cell may list several backticked paths (e.g. config.yaml and policy.hujson).
		for _, path := range backticked(cells[0]) {
			mounts[path] = mode
		}
	}
	return mounts
}

func backticked(cell string) []string {
	var out []string
	for {
		start := strings.Index(cell, "`")
		if start < 0 {
			break
		}
		rest := cell[start+1:]
		end := strings.Index(rest, "`")
		if end < 0 {
			break
		}
		out = append(out, rest[:end])
		cell = rest[end+1:]
	}
	return out
}

func tableCells(line string) []string {
	line = strings.Trim(line, "|")
	parts := strings.Split(line, "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// composeVolumes reads the tagcess service's short-syntax mounts from compose.yaml as target -> mode.
func composeVolumes(t *testing.T) map[string]string {
	t.Helper()
	var doc struct {
		Services map[string]struct {
			Volumes []string `yaml:"volumes"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(readFile(t, "compose.yaml")), &doc); err != nil {
		t.Fatalf("parse compose.yaml: %v", err)
	}
	svc, ok := doc.Services["tagcess"]
	if !ok {
		t.Fatal("compose.yaml has no tagcess service")
	}
	got := map[string]string{}
	for _, v := range svc.Volumes {
		_, dst, mode := splitMount(t, v)
		got[dst] = mode
	}
	return got
}

// splitMount parses a compose short-syntax mount (host:target[:ro]) into source, target and mode.
func splitMount(t *testing.T, mount string) (src, dst, mode string) {
	t.Helper()
	parts := strings.Split(mount, ":")
	switch len(parts) {
	case 2:
		return parts[0], parts[1], "rw"
	case 3:
		return parts[0], parts[1], parts[2]
	default:
		t.Fatalf("cannot parse mount %q", mount)
		return "", "", ""
	}
}

func nonCommentLines(raw string) []string {
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		if strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}
	return out
}

func indexContaining(lines []string, sub string) int {
	for i, line := range lines {
		if strings.Contains(line, sub) {
			return i
		}
	}
	return -1
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// F4-032 AC1: the k8s credential lives in its own rw directory at a fixed runtime path, outside the
// data directory (SQLite/git/backup tree), and the example carries no token value.
func TestF4DeploymentCredentialIsolation(t *testing.T) {
	const credDir = "/var/lib/tagcess-credentials"

	mode, ok := composeVolumes(t)[credDir]
	if !ok || mode != "rw" {
		t.Errorf("compose mount %s = %q (present %v), want rw", credDir, mode, ok)
	}

	cfg, err := config.Load("config.example.yaml")
	if err != nil {
		t.Fatalf("load example config: %v", err)
	}
	if cfg.K8sAuthDir != credDir {
		t.Errorf("k8s_auth_dir = %q, want %q", cfg.K8sAuthDir, credDir)
	}
	if cfg.K8sAuthDir == cfg.DataDir || strings.HasPrefix(cfg.K8sAuthDir, cfg.DataDir+"/") {
		t.Errorf("credential dir %q must be outside data_dir %q", cfg.K8sAuthDir, cfg.DataDir)
	}

	raw := readFile(t, "config.example.yaml")
	for _, marker := range []string{"eyJ", "-----BEGIN", "token:"} {
		if strings.Contains(raw, marker) {
			t.Errorf("example config contains a token-like value (%q)", marker)
		}
	}
	if !strings.Contains(raw, "backup") {
		t.Error("example config must state that the credential directory is excluded from backups")
	}
}

// F5 I12: the recommended oauth2-proxy settings give ONE shared gate cookie (a cookie_domains parent
// domain) with a short lifetime and no refresh, so revocation takes effect within that lifetime.
func TestDeploy_OAuth2ProxyExampleSharedShortCookie(t *testing.T) {
	cfg := readFile(t, "oauth2-proxy.example.cfg")
	for _, want := range []string{
		`cookie_domains = [".example.com"]`,
		`cookie_expire = "1h"`,
		`cookie_refresh = "0"`,
		`cookie_secure = true`,
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("oauth2-proxy.example.cfg is missing %q", want)
		}
	}
	for _, secret := range []string{"client_secret =", "cookie_secret ="} {
		if strings.Contains(cfg, secret) {
			t.Errorf("oauth2-proxy.example.cfg must not set %q (secrets come from the environment)", secret)
		}
	}
}

// K1: the Headscale drop-in keeps the runtime directory (and so the container's bind mount) across
// restarts, and compose.yaml still mounts the directory it protects.
func TestDeploy_HeadscaleRuntimeDirPreserved(t *testing.T) {
	conf := readFile(t, "headscale-preserve.conf")
	var active []string
	for _, l := range strings.Split(conf, "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			active = append(active, l)
		}
	}
	if want := []string{"[Service]", "RuntimeDirectoryPreserve=yes"}; !slices.Equal(active, want) {
		t.Errorf("drop-in directives = %v, want %v", active, want)
	}
	if !strings.Contains(readFile(t, "compose.yaml"), "- /var/run/headscale:/var/run/headscale") {
		t.Error("compose.yaml no longer mounts the Headscale socket directory")
	}
}
