// Static checks for F1-025/F1-020: the local compose stack holds Headscale, Caddy and oauth2-proxy.
// Zitadel lives in the lab (ADR 0014, test/lab); nothing here talks to docker or a cluster.
package compose_test

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const labIssuer = "https://tagcess-zitadel.lab.example.com"

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestComposeStack_NoLocalZitadel(t *testing.T) {
	raw := readFile(t, "compose.yaml")
	var c struct {
		Services map[string]any `yaml:"services"`
		Volumes  map[string]any `yaml:"volumes"`
	}
	if err := yaml.Unmarshal([]byte(raw), &c); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"headscale": true, "headscale-relay": true, "caddy": true, "oauth2-proxy": true}
	if len(c.Services) != len(want) {
		t.Errorf("services = %v, want headscale, headscale-relay, caddy and oauth2-proxy", keys(c.Services))
	}
	for name := range want {
		if c.Services[name] == nil {
			t.Errorf("compose.yaml lost the %q service", name)
		}
	}
	for name := range c.Volumes {
		if strings.Contains(name, "zitadel") {
			t.Errorf("volume %q belongs to a local Zitadel", name)
		}
	}
	// Ignore comments (they explain why Zitadel is gone) and the lab issuer URL itself.
	code := regexp.MustCompile(`(?m)#.*$`).ReplaceAllString(raw, "")
	code = strings.ReplaceAll(code, labIssuer, "")
	for _, bad := range []string{"ZITADEL_", "postgres"} {
		if strings.Contains(strings.ToLower(code), strings.ToLower(bad)) {
			t.Errorf("compose.yaml still mentions %q outside comments", bad)
		}
	}
}

func TestComposeStack_HeadscaleIssuerIsLab(t *testing.T) {
	var cfg struct {
		OIDC struct {
			Issuer string `yaml:"issuer"`
		} `yaml:"oidc"`
	}
	if err := yaml.Unmarshal([]byte(readFile(t, "headscale/config.yaml")), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.OIDC.Issuer != labIssuer {
		t.Errorf("headscale/config.yaml oidc.issuer = %q, want %q", cfg.OIDC.Issuer, labIssuer)
	}
	if want := "HEADSCALE_OIDC_ISSUER: ${HEADSCALE_OIDC_ISSUER:-" + labIssuer + "}"; !strings.Contains(readFile(t, "compose.yaml"), want) {
		t.Errorf("compose.yaml must default HEADSCALE_OIDC_ISSUER to the lab: want line %q", want)
	}
}

func TestMakefile_NoLocalZitadel(t *testing.T) {
	mk := readFile(t, "../../Makefile")
	for _, bad := range []string{"compose-up", "compose-down", "postgres zitadel", "localhost:8080", "up -d --wait postgres"} {
		if strings.Contains(mk, bad) {
			t.Errorf("Makefile still contains %q", bad)
		}
	}
	if regexp.MustCompile(`(?m)^integration:`).MatchString(mk) {
		t.Errorf("Makefile has an `integration` target; the only integration run is lab-integration")
	}
	for _, want := range []string{"lab-up:", "lab-down:", "lab-integration:"} {
		if !strings.Contains(mk, want) {
			t.Errorf("Makefile lost target %q", want)
		}
	}
}

func keys(m map[string]any) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}
