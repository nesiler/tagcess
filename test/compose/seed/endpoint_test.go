package seed

import (
	"path/filepath"
	"testing"

	"github.com/nesiler/tagcess/test/labenv"
)

func TestEndpointFromEnv_Defaults(t *testing.T) {
	t.Setenv(labenv.EnvFile, filepath.Join(t.TempDir(), "none.env"))
	for _, k := range []string{EnvZitadelAddr, EnvZitadelTLS, EnvSecretsDir, labenv.EnvDomain, labenv.EnvZitadelHost} {
		t.Setenv(k, "")
	}
	ep, err := EndpointFromEnv("/base")
	if err != nil {
		t.Fatalf("EndpointFromEnv: %v", err)
	}
	want := Endpoint{
		Addr:       "tagcess-zitadel.lab.example.com:443",
		Host:       "tagcess-zitadel.lab.example.com",
		Port:       "443",
		TLS:        true,
		SecretsDir: filepath.Join("/base", ".secrets", "lab"),
		PATFile:    filepath.Join("/base", ".secrets", "lab", "bootstrap-pat"),
	}
	if ep != want {
		t.Fatalf("defaults = %+v, want %+v", ep, want)
	}
}

func TestEndpointFromEnv_Lab(t *testing.T) {
	// Overrides work: a different lab host, another secrets dir.
	t.Setenv(EnvZitadelAddr, "lab2.example.test:8443")
	t.Setenv(EnvZitadelTLS, "true")
	t.Setenv(EnvSecretsDir, ".secrets/other")
	ep, err := EndpointFromEnv("/base")
	if err != nil {
		t.Fatalf("EndpointFromEnv: %v", err)
	}
	if ep.Host != "lab2.example.test" || ep.Port != "8443" || !ep.TLS {
		t.Fatalf("lab endpoint = %+v", ep)
	}
	if want := filepath.Join("/base", ".secrets", "other"); ep.SecretsDir != want {
		t.Fatalf("SecretsDir = %q, want %q (relative paths resolve against the compose dir)", ep.SecretsDir, want)
	}
	if want := filepath.Join("/base", ".secrets", "other", "bootstrap-pat"); ep.PATFile != want {
		t.Fatalf("PATFile = %q, want %q", ep.PATFile, want)
	}
}

func TestEndpointFromEnv_Invalid(t *testing.T) {
	cases := []struct{ name, addr, tls string }{
		{"no port", "tagcess-zitadel.lab.example.com", ""},
		{"bad tls flag", "tagcess-zitadel.lab.example.com:443", "maybe"},
		{"plaintext to a remote host would send the PAT in clear", "tagcess-zitadel.lab.example.com:443", "false"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(EnvZitadelAddr, tc.addr)
			t.Setenv(EnvZitadelTLS, tc.tls)
			t.Setenv(EnvSecretsDir, "")
			if _, err := EndpointFromEnv("/base"); err == nil {
				t.Fatalf("want an error for addr=%q tls=%q", tc.addr, tc.tls)
			}
		})
	}
}

func TestEndpointFromEnv_LoopbackPlaintextAllowed(t *testing.T) {
	t.Setenv(EnvZitadelAddr, "127.0.0.1:8080")
	t.Setenv(EnvZitadelTLS, "false")
	t.Setenv(EnvSecretsDir, "")
	ep, err := EndpointFromEnv("/base")
	if err != nil || ep.TLS {
		t.Fatalf("loopback plaintext: ep=%+v err=%v, want accepted with TLS off", ep, err)
	}
}
