package stack

import (
	"bytes"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

const testDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000001"

func testManifest() Manifest {
	m := Manifest{Release: "v0.0.0-test", Images: map[Component]Image{}}
	for _, c := range AllComponents() {
		m.Images[c] = Image{Name: "registry.example.com/" + string(c), Tag: "1.2.3", Digest: testDigest}
	}
	return m
}

func baseParams() Params {
	return Params{
		Components:        AllComponents(),
		HeadscaleHost:     "hs.example.com",
		MagicDNSDomain:    "vpn.example.net",
		PrefixV4:          "100.64.0.0/10",
		PrefixV6:          "fd7a:115c:a1e0::/48",
		HeadscalePort:     8080,
		HeadscaleMetrics:  9090,
		OAuth2ProxyPort:   4180,
		SetupPort:         9180,
		IssuerURL:         "https://idp.example.com",
		HeadscaleClientID: "headscale-client",
		ProxyClientID:     "proxy-client",
		ProxyHost:         "auth.example.com",
		CookieDomain:      "example.com",
		CookieLifetime:    "1h",
		AdminGroup:        "admins",
		CaddyGID:          990,
		HeadscaleGID:      991,
		SocketGID:         992,
	}
}

func TestRender_Golden(t *testing.T) {
	all := AllComponents()
	cases := map[string]func(*Params){
		"all":       func(p *Params) {},
		"derp":      func(p *Params) { p.EmbeddedDERP = true },
		"no-tsnode": func(p *Params) { p.Components = all[:len(all)-1] },
		"hs-only":   func(p *Params) { p.Components = []Component{Headscale} },
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			p := baseParams()
			mod(&p)
			files, err := Render(p, testManifest())
			if err != nil {
				t.Fatal(err)
			}
			again, _ := Render(p, testManifest())
			for path, b := range files {
				if !bytes.Equal(b, again[path]) {
					t.Fatalf("%s not deterministic", path)
				}
				g := filepath.Join("testdata", name, filepath.FromSlash(path)+".golden")
				if *update {
					if err := os.MkdirAll(filepath.Dir(g), 0o755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(g, b, 0o644); err != nil {
						t.Fatal(err)
					}
				}
				want, err := os.ReadFile(g)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(b, want) {
					t.Errorf("%s differs from golden %s", path, g)
				}
			}
			entries, _ := filepath.Glob(filepath.Join("testdata", name, "*", "*"))
			top, _ := filepath.Glob(filepath.Join("testdata", name, "*.golden"))
			if len(entries)+len(top) != len(files) {
				t.Errorf("golden count %d != output files %d", len(entries)+len(top), len(files))
			}
		})
	}
}

func TestRender_NoSecretsAndPinned(t *testing.T) {
	files, err := Render(baseParams(), testManifest())
	if err != nil {
		t.Fatal(err)
	}
	c := string(files["compose.yaml"])
	if !strings.Contains(c, "registry.example.com/caddy:1.2.3@"+testDigest) {
		t.Error("image not referenced by tag and digest")
	}
	for p, b := range files {
		if strings.Contains(strings.ToLower(string(b)), "secret:") && !strings.Contains(string(b), "_file") && !strings.Contains(string(b), "_path") {
			t.Errorf("%s may carry a secret value", p)
		}
	}
}

func TestRender_BadInput(t *testing.T) {
	cases := map[string]func(*Params){
		"host upper":       func(p *Params) { p.HeadscaleHost = "HS.example.com" },
		"host injection":   func(p *Params) { p.HeadscaleHost = "hs.example.com\nevil: 1" },
		"host empty":       func(p *Params) { p.HeadscaleHost = "" },
		"host underscore":  func(p *Params) { p.HeadscaleHost = "h_s.example.com" },
		"magic dns bad":    func(p *Params) { p.MagicDNSDomain = "a b" },
		"v4 outside cgnat": func(p *Params) { p.PrefixV4 = "10.0.0.0/8" },
		"v4 not canonical": func(p *Params) { p.PrefixV4 = "100.64.0.1/10" },
		"v6 outside":       func(p *Params) { p.PrefixV6 = "fd00::/48" },
		"port low":         func(p *Params) { p.HeadscalePort = 80 },
		"port high":        func(p *Params) { p.OAuth2ProxyPort = 70000 },
		"port duplicate":   func(p *Params) { p.SetupPort = p.HeadscalePort },
		"issuer http":      func(p *Params) { p.IssuerURL = "http://idp.example.com" },
		"issuer path":      func(p *Params) { p.IssuerURL = "https://idp.example.com/x" },
		"issuer userinfo":  func(p *Params) { p.IssuerURL = "https://u@idp.example.com" },
		"client id quote":  func(p *Params) { p.ProxyClientID = `a"b` },
		"cookie too long":  func(p *Params) { p.CookieLifetime = "100h" },
		"cookie too short": func(p *Params) { p.CookieLifetime = "1s" },
		"cookie garbage":   func(p *Params) { p.CookieLifetime = "soon" },
		"admin group":      func(p *Params) { p.AdminGroup = "a\nb" },
		"admin empty":      func(p *Params) { p.AdminGroup = "" },
		"unknown comp":     func(p *Params) { p.Components = []Component{"redis"} },
		"dup comp":         func(p *Params) { p.Components = []Component{Caddy, Caddy} },
		"no comps":         func(p *Params) { p.Components = nil },
		"gid negative":     func(p *Params) { p.SocketGID = -1 },
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			p := baseParams()
			mod(&p)
			files, err := Render(p, testManifest())
			if err == nil {
				t.Fatal("expected an error")
			}
			if files != nil {
				t.Errorf("expected no output, got %d files", len(files))
			}
		})
	}
	t.Run("missing manifest image", func(t *testing.T) {
		m := testManifest()
		delete(m.Images, Caddy)
		files, err := Render(baseParams(), m)
		if err == nil || files != nil {
			t.Fatal("expected error and no output")
		}
	})
}

func TestManifest_Validate(t *testing.T) {
	good := Image{Name: "docker.io/caddy", Tag: "2.11.7", Digest: testDigest}
	cases := map[string]Image{
		"no tag":     {Name: good.Name, Digest: good.Digest},
		"no digest":  {Name: good.Name, Tag: good.Tag},
		"short hash": {Name: good.Name, Tag: good.Tag, Digest: "sha256:abc"},
		"md5":        {Name: good.Name, Tag: good.Tag, Digest: "md5:" + strings.Repeat("a", 64)},
		"bad name":   {Name: "Caddy Evil", Tag: good.Tag, Digest: good.Digest},
		"bad tag":    {Name: good.Name, Tag: "a b", Digest: good.Digest},
	}
	for name, img := range cases {
		t.Run(name, func(t *testing.T) {
			if err := img.Validate(); err == nil {
				t.Error("expected error")
			}
		})
	}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestEmbeddedManifest_EveryServicePinned(t *testing.T) {
	m, err := Load(manifestJSONForTest(t), true)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range AllComponents() {
		img, ok := m.Images[c]
		if !ok {
			t.Errorf("manifest has no image for %s", c)
			continue
		}
		if err := img.Validate(); err != nil {
			t.Errorf("%s: %v", c, err)
		}
	}
	if len(m.Images) != len(AllComponents()) {
		t.Errorf("manifest has %d images, want %d", len(m.Images), len(AllComponents()))
	}
	if !strings.HasPrefix(m.Images[Tagcess].Name, "ghcr.io/nesiler/tagcess") {
		t.Errorf("tagcess image = %q", m.Images[Tagcess].Name)
	}
}

func manifestJSONForTest(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("manifest", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The manifest is embedded only in the helper binary (setup-flow.md §5.5).
func TestTagcessBinaryHasNoManifest(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go tool not available")
	}
	for _, cmd := range []string{"./cmd/tagcess", "./cmd/tagcess-ui"} {
		c := exec.CommandContext(t.Context(), "go", "list", "-deps", cmd)
		c.Dir = "../.."
		out, err := c.CombinedOutput()
		if err != nil {
			t.Fatalf("go list %s: %v\n%s", cmd, err, out)
		}
		for _, line := range strings.Fields(string(out)) {
			if strings.Contains(line, "tagcess/internal/stack") {
				t.Errorf("%s depends on %s", cmd, line)
			}
		}
	}
}

func TestLoad_RejectsPlaceholderDigest(t *testing.T) {
	b := manifestJSONForTest(t)
	if _, err := Load(b, false); err == nil || !strings.Contains(err.Error(), "placeholder") {
		t.Fatalf("Load without allow: err = %v", err)
	}
	m, err := Load(b, true)
	if err != nil {
		t.Fatal(err)
	}
	m.AllowPlaceholder = false
	if _, err := Render(baseParams(), m); err == nil {
		t.Fatal("Render accepted the placeholder digest")
	}
	m.AllowPlaceholder = true
	if _, err := Render(baseParams(), m); err != nil {
		t.Fatal(err)
	}
}

func TestRender_RuntimeWiring(t *testing.T) {
	files, err := Render(baseParams(), testManifest())
	if err != nil {
		t.Fatal(err)
	}
	c := string(files["compose.yaml"])
	for _, want := range []string{
		`command: ["serve"]`,
		`command: ["--config=/etc/oauth2-proxy/oauth2-proxy.cfg"]`,
		`/etc/tagcess/stack/secrets/headscale:/etc/headscale/secrets:ro`,
		`"/run/tagcess:/run/tagcess"`,
		`["CMD", "/usr/local/bin/tagcess", "-config", "/etc/tagcess/config.yaml", "-check"]`,
	} {
		if !strings.Contains(c, want) {
			t.Errorf("compose.yaml lacks %s", want)
		}
	}
	if strings.Contains(string(files["oauth2-proxy/oauth2-proxy.cfg"]), "allowed_groups") {
		t.Error("oauth2-proxy config sets a global allowed_groups")
	}
	df, err := os.ReadFile("../../deploy/Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(df), tagcessBinary) {
		t.Errorf("Dockerfile does not install %s", tagcessBinary)
	}
}
