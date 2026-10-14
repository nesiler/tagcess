package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRun_Check(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		wantCode int
		wantOut  string
		wantErr  string
	}{
		{"valid config", []string{"-config", "../../deploy/config.example.yaml", "-check"}, 0, "config ok", ""},
		{"missing -config", []string{"-check"}, 2, "", "-config is required"},
		{"missing file", []string{"-config", "does-not-exist.yaml", "-check"}, 1, "", "does-not-exist.yaml"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			code := run(tc.args, &out, &errb)
			if code != tc.wantCode {
				t.Errorf("exit code = %d, want %d (stderr: %s)", code, tc.wantCode, errb.String())
			}
			if !strings.Contains(out.String(), tc.wantOut) {
				t.Errorf("stdout = %q, want %q", out.String(), tc.wantOut)
			}
			if !strings.Contains(errb.String(), tc.wantErr) {
				t.Errorf("stderr = %q, want %q", errb.String(), tc.wantErr)
			}
		})
	}
}

// A missing secret must stop startup before anything is opened (fail safe).
func TestRun_MissingSigningKeyStopsStartup(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	body := fmt.Sprintf(`data_dir: %s
ui:
  socket: %s
  socket_group: tagcess
hook:
  listen: 100.64.0.4:9443
  signing_key_file: %s
headscale:
  socket: %s
zitadel:
  issuer: https://auth.example.com
  project_id: "000000000000000000"
  key_file: %s
  oauth2_proxy_app: oauth2-proxy
caddy:
  admin_url: http://127.0.0.1:2019
  caddyfile_path: /etc/caddy/Caddyfile
dns:
  records_path: /var/lib/headscale/dns-extra.json
sites:
  allowed_domains:
    - example.com
  allowed_targets:
    - 100.64.0.5
  acme_email: admin@example.com
  certificates:
    - example.com
  vpn_address: 100.64.0.4
`,
		dir,
		filepath.Join(dir, "ui.sock"),
		filepath.Join(dir, "missing-signing-key"),
		filepath.Join(dir, "headscale.sock"),
		filepath.Join(dir, "zitadel-key.json"),
	)
	if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	var out, errb bytes.Buffer
	code := run([]string{"-config", configPath}, &out, &errb)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (stderr: %s)", code, errb.String())
	}
	if !strings.Contains(errb.String(), "signing key") {
		t.Fatalf("stderr = %q, want it to name the signing key", errb.String())
	}
}
