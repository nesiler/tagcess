package config

import (
	"io/fs"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

const validYAML = `
data_dir: /var/lib/tagcess
ui:
  socket: /run/tagcess/ui.sock
  socket_group: caddy
  socket_mode: "0660"
hook:
  listen: 100.64.0.4:9443
  signing_key_file: /etc/tagcess/secrets/webhook-signing-key
headscale:
  socket: /var/run/headscale/headscale.sock
zitadel:
  issuer: https://auth.example.com
  project_id: "123"
  key_file: /etc/tagcess/secrets/zitadel-key.json
  oauth2_proxy_app: oauth2-proxy
caddy:
  admin_url: http://127.0.0.1:2019
  caddyfile_path: /etc/caddy/Caddyfile
dns:
  records_path: /var/lib/headscale/dns-extra.json
sync:
  interval: 2m
sites:
  allowed_domains:
    - example.com
  allowed_targets:
    - 100.64.0.5
  zitadel_internal_sources:
    - 10.8.0.0/24
  acme_email: admin@example.com
  certificates:
    - example.com
  vpn_address: 100.64.0.4
  tagcess_host: tagcess.example.com
`

func parse(t *testing.T, s string) (*Config, error) {
	t.Helper()
	return Parse(strings.NewReader(s), "test.yaml")
}

// without removes the line that starts with the given key prefix (after indentation).
func without(s, key string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), key+":") {
			continue
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

func TestConfig_LoadValid(t *testing.T) {
	t.Run("inline", func(t *testing.T) {
		c, err := parse(t, validYAML)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if c.DataDir != "/var/lib/tagcess" || c.UI.Socket != "/run/tagcess/ui.sock" || c.UI.SocketGroup != "caddy" {
			t.Errorf("unexpected values: %+v", c)
		}
		if c.UI.SocketMode.Perm() != 0o660 {
			t.Errorf("socket_mode = %o, want 660", c.UI.SocketMode.Perm())
		}
		if c.Hook.Listen != "100.64.0.4:9443" || c.Headscale.Socket != "/var/run/headscale/headscale.sock" {
			t.Errorf("unexpected values: %+v", c)
		}
		if c.Zitadel.Issuer != "https://auth.example.com" || c.Zitadel.ProjectID != "123" {
			t.Errorf("unexpected zitadel: %+v", c.Zitadel)
		}
		if c.Sync.Interval != 2*time.Minute {
			t.Errorf("interval = %v, want 2m", c.Sync.Interval)
		}
	})

	t.Run("defaults", func(t *testing.T) {
		c, err := parse(t, without(without(validYAML, "socket_mode"), "interval"))
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if c.UI.SocketMode.Perm() != 0o660 {
			t.Errorf("default socket_mode = %o, want 660", c.UI.SocketMode.Perm())
		}
		if c.Sync.Interval != 5*time.Minute {
			t.Errorf("default interval = %v, want 5m", c.Sync.Interval)
		}
	})

	t.Run("example file", func(t *testing.T) {
		if _, err := Load("../../deploy/config.example.yaml"); err != nil {
			t.Fatalf("example config does not load: %v", err)
		}
	})
}

func TestConfig_GroupsSigningKeyFile(t *testing.T) {
	const line = "  signing_key_file: /etc/tagcess/secrets/webhook-signing-key\n"
	if !strings.Contains(validYAML, line) {
		t.Fatal("validYAML layout changed")
	}
	t.Run("unset is allowed", func(t *testing.T) {
		c, err := parse(t, validYAML)
		if err != nil || c.Hook.GroupsSigningKeyFile != "" {
			t.Fatalf("err=%v key=%q", err, c.Hook.GroupsSigningKeyFile)
		}
	})
	t.Run("set", func(t *testing.T) {
		c, err := parse(t, strings.Replace(validYAML, line, line+"  groups_signing_key_file: /etc/tagcess/secrets/groups-signing-key\n", 1))
		if err != nil || c.Hook.GroupsSigningKeyFile != "/etc/tagcess/secrets/groups-signing-key" {
			t.Fatalf("err=%v key=%q", err, c.Hook.GroupsSigningKeyFile)
		}
	})
	t.Run("relative refused", func(t *testing.T) {
		_, err := parse(t, strings.Replace(validYAML, line, line+"  groups_signing_key_file: secrets/groups\n", 1))
		if err == nil || !strings.Contains(err.Error(), "hook.groups_signing_key_file") {
			t.Fatalf("error %v does not reject relative hook.groups_signing_key_file", err)
		}
	})
	t.Run("unknown field stays strict", func(t *testing.T) {
		if _, err := parse(t, strings.Replace(validYAML, line, line+"  groups_signing_key: abc\n", 1)); err == nil {
			t.Fatal("unknown hook field accepted")
		}
	})
}

func TestConfig_MissingField(t *testing.T) {
	cases := []struct{ key, path string }{
		{"data_dir", "data_dir"},
		{"  socket", "ui.socket"},
		{"socket_group", "ui.socket_group"},
		{"listen", "hook.listen"},
		{"signing_key_file", "hook.signing_key_file"},
		{"issuer", "zitadel.issuer"},
		{"project_id", "zitadel.project_id"},
		{"key_file", "zitadel.key_file"},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			_, err := parse(t, without(validYAML, strings.TrimSpace(tc.key)))
			if err == nil {
				t.Fatalf("expected error for missing %s", tc.path)
			}
			if !strings.Contains(err.Error(), tc.path) {
				t.Errorf("error %q does not name %s", err, tc.path)
			}
		})
	}

	t.Run("headscale.socket", func(t *testing.T) {
		s := strings.Replace(validYAML, "  socket: /var/run/headscale/headscale.sock\n", "", 1)
		_, err := parse(t, s)
		if err == nil || !strings.Contains(err.Error(), "headscale.socket") {
			t.Fatalf("error %v does not name headscale.socket", err)
		}
	})

	t.Run("sites allowlists", func(t *testing.T) {
		// Removing the whole sites block names both required allowlists.
		i := strings.Index(validYAML, "\nsites:")
		if i < 0 {
			t.Fatal("test setup: no sites block in validYAML")
		}
		_, err := parse(t, validYAML[:i]+"\n")
		if err == nil {
			t.Fatal("expected error without the sites block")
		}
		for _, p := range []string{"sites.allowed_domains", "sites.allowed_targets"} {
			if !strings.Contains(err.Error(), p) {
				t.Errorf("error %q does not name %s", err, p)
			}
		}

		// An empty allowed_targets list is refused too.
		empty := strings.Replace(validYAML, "  allowed_targets:\n    - 100.64.0.5\n", "  allowed_targets: []\n", 1)
		if _, err := parse(t, empty); err == nil || !strings.Contains(err.Error(), "sites.allowed_targets") {
			t.Errorf("empty allowed_targets: error %v", err)
		}
	})

	t.Run("all missing listed", func(t *testing.T) {
		_, err := parse(t, "sync:\n  interval: 1m\n")
		if err == nil {
			t.Fatal("expected error")
		}
		for _, p := range []string{"data_dir", "ui.socket", "zitadel.key_file"} {
			if !strings.Contains(err.Error(), p) {
				t.Errorf("error %q does not name %s", err, p)
			}
		}
	})
}

var secretName = regexp.MustCompile(`(?i)secret|key|token|password|credential`)

func TestConfig_SecretsArePaths(t *testing.T) {
	secretType := reflect.TypeFor[SecretFile]()
	var walk func(t reflect.Type, path string)
	walk = func(typ reflect.Type, path string) {
		for i := range typ.NumField() {
			f := typ.Field(i)
			p := path + "." + f.Name
			if f.Type.Kind() == reflect.Struct && f.Type != secretType {
				walk(f.Type, p)
				continue
			}
			if secretName.MatchString(f.Name) && f.Type != secretType {
				t.Errorf("%s looks like a secret but has type %s, want SecretFile", p, f.Type)
			}
		}
	}
	walk(reflect.TypeFor[Config](), "Config")

	t.Run("secret files are not read", func(t *testing.T) {
		s := strings.Replace(validYAML, "/etc/tagcess/secrets/zitadel-key.json", "/nonexistent/zitadel-key.json", 1)
		c, err := parse(t, s)
		if err != nil {
			t.Fatalf("Parse must not open secret files: %v", err)
		}
		if c.Zitadel.KeyFile != "/nonexistent/zitadel-key.json" {
			t.Errorf("key_file = %q", c.Zitadel.KeyFile)
		}
	})

	t.Run("relative secret path rejected", func(t *testing.T) {
		s := strings.Replace(validYAML, "/etc/tagcess/secrets/webhook-signing-key", "secrets/key", 1)
		_, err := parse(t, s)
		if err == nil || !strings.Contains(err.Error(), "hook.signing_key_file") {
			t.Fatalf("error %v does not reject relative hook.signing_key_file", err)
		}
	})
}

func TestConfig_UnknownFieldRejected(t *testing.T) {
	s := strings.Replace(validYAML, "project_id:", "projct_id:", 1)
	_, err := parse(t, s)
	if err == nil {
		t.Fatal("expected error for unknown field")
	}
	msg := err.Error()
	if !strings.Contains(msg, "projct_id") || !strings.Contains(msg, "line 14") {
		t.Errorf("error %q must name the field and its line (14)", msg)
	}
}

func TestConfig_FileModeString(t *testing.T) {
	cases := []struct {
		value string
		want  fs.FileMode
		ok    bool
	}{
		{`"0660"`, 0o660, true},
		{`"0600"`, 0o600, true},
		{`"660"`, 0o660, true},
		{`0660`, 0, false},
		{`660`, 0, false},
		{`"0999"`, 0, false},
		{`"1777"`, 0, false},
		{`"abc"`, 0, false},
		{`""`, 0, false},
		{`"0666"`, 0, false}, // other bits: any local process could reach the UI socket
		{`"0662"`, 0, false},
		{`"0770"`, 0o770, true},
	}
	for _, tc := range cases {
		t.Run(tc.value, func(t *testing.T) {
			s := strings.Replace(validYAML, `socket_mode: "0660"`, "socket_mode: "+tc.value, 1)
			c, err := parse(t, s)
			if !tc.ok {
				if err == nil {
					t.Fatalf("expected error for %s", tc.value)
				}
				if !strings.Contains(err.Error(), "line 6") && !strings.Contains(err.Error(), "ui.socket_mode") {
					t.Errorf("error %q does not point at socket_mode", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if c.UI.SocketMode.Perm() != tc.want {
				t.Errorf("mode = %o, want %o", c.UI.SocketMode.Perm(), tc.want)
			}
		})
	}
}

func TestConfig_InvalidValues(t *testing.T) {
	cases := []struct {
		name, old, new, want string
	}{
		{"listen without host", "listen: 100.64.0.4:9443", "listen: :9443", "hook.listen"},
		{"listen on all interfaces", "listen: 100.64.0.4:9443", "listen: 0.0.0.0:9443", "hook.listen"},
		{"listen on all v6 interfaces", "listen: 100.64.0.4:9443", `listen: "[::]:9443"`, "hook.listen"},
		{"listen on hostname", "listen: 100.64.0.4:9443", "listen: example.com:9443", "hook.listen"},
		{"issuer with userinfo", "https://auth.example.com", "https://svc:pw@auth.example.com", "zitadel.issuer"},
		{"issuer with query", "https://auth.example.com", "https://auth.example.com?x=1", "zitadel.issuer"},
		{"issuer over http", "https://auth.example.com", "http://auth.example.com", "zitadel.issuer"},
		{"secret path not clean", "/etc/tagcess/secrets/zitadel-key.json", "/etc/tagcess/../shadow", "zitadel.key_file"},
		{"secret path control char", "/etc/tagcess/secrets/zitadel-key.json", `"/etc/tagcess/a\nb"`, "zitadel.key_file"},
		{"interval not positive", "interval: 2m", "interval: 0s", "sync.interval"},
		{"k8s upstream over http", "vpn_address: 100.64.0.4", "vpn_address: 100.64.0.4\n  k8s_upstream: http://100.64.0.5:8443", "sites.k8s_upstream"},
		{"k8s upstream with a path", "vpn_address: 100.64.0.4", "vpn_address: 100.64.0.4\n  k8s_upstream: https://100.64.0.5:8443/x", "sites.k8s_upstream"},
		{"k8s upstream without scheme", "vpn_address: 100.64.0.4", "vpn_address: 100.64.0.4\n  k8s_upstream: 100.64.0.5:8443", "sites.k8s_upstream"},
		{"k8s upstream with a placeholder", "vpn_address: 100.64.0.4", "vpn_address: 100.64.0.4\n  k8s_upstream: \"https://{env.K8S}\"", "sites.k8s_upstream"},
		{"k8s upstream with an empty fragment", "vpn_address: 100.64.0.4", "vpn_address: 100.64.0.4\n  k8s_upstream: \"https://100.64.0.5:8443#\"", "sites.k8s_upstream"},
		{"k8s upstream with an empty query", "vpn_address: 100.64.0.4", "vpn_address: 100.64.0.4\n  k8s_upstream: \"https://100.64.0.5:8443?\"", "sites.k8s_upstream"},
		{"k8s upstream with an empty port", "vpn_address: 100.64.0.4", "vpn_address: 100.64.0.4\n  k8s_upstream: \"https://100.64.0.5:\"", "sites.k8s_upstream"},
		{"k8s upstream with a port out of range", "vpn_address: 100.64.0.4", "vpn_address: 100.64.0.4\n  k8s_upstream: https://100.64.0.5:65536", "sites.k8s_upstream"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := strings.Replace(validYAML, tc.old, tc.new, 1)
			if s == validYAML {
				t.Fatalf("replacement %q not applied", tc.old)
			}
			_, err := parse(t, s)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v does not reject %s", err, tc.want)
			}
		})
	}

	t.Run("k8s upstream with a port ok", func(t *testing.T) {
		c, err := parse(t, strings.Replace(validYAML, "vpn_address: 100.64.0.4", "vpn_address: 100.64.0.4\n  k8s_upstream: https://100.64.0.5:8443", 1))
		if err != nil || c.Sites.K8sUpstream != "https://100.64.0.5:8443" {
			t.Fatalf("Parse: %v, %+v", err, c)
		}
	})

	t.Run("listen on loopback ok", func(t *testing.T) {
		if _, err := parse(t, strings.Replace(validYAML, "100.64.0.4:9443", "127.0.0.1:9443", 1)); err != nil {
			t.Fatalf("Parse: %v", err)
		}
	})

	t.Run("second document rejected", func(t *testing.T) {
		_, err := parse(t, validYAML+"---\ndata_dir: /other\n")
		if err == nil || !strings.Contains(err.Error(), "document") {
			t.Fatalf("error %v does not reject a second YAML document", err)
		}
	})
}

func TestConfig_HostApplyPaths(t *testing.T) {
	t.Run("absent means H-07 is off", func(t *testing.T) {
		c, err := parse(t, validYAML)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if c.HostApply.Enabled() {
			t.Fatal("HostApply enabled without settings")
		}
	})

	const set = validYAML + "hostapply:\n  requests_dir: /var/lib/tagcess-headscale/requests\n  results_dir: /var/lib/tagcess-headscale/results\n"
	t.Run("both set", func(t *testing.T) {
		c, err := parse(t, set)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if !c.HostApply.Enabled() ||
			c.HostApply.RequestsDir != "/var/lib/tagcess-headscale/requests" ||
			c.HostApply.ResultsDir != "/var/lib/tagcess-headscale/results" {
			t.Fatalf("HostApply = %+v", c.HostApply)
		}
	})

	cases := []struct{ name, old, new, want string }{
		{"relative requests_dir", "/var/lib/tagcess-headscale/requests", "requests", "hostapply.requests_dir"},
		{"relative results_dir", "/var/lib/tagcess-headscale/results", "./results", "hostapply.results_dir"},
		{"not clean", "/var/lib/tagcess-headscale/requests", "/var/lib/x/../requests", "hostapply.requests_dir"},
		{"trailing slash", "/var/lib/tagcess-headscale/results", "/var/lib/tagcess-headscale/results/", "hostapply.results_dir"},
		{"control char", "/var/lib/tagcess-headscale/results", `"/var/lib/a\nb"`, "hostapply.results_dir"},
		{"same dir", "/var/lib/tagcess-headscale/results", "/var/lib/tagcess-headscale/requests", "hostapply"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := strings.Replace(set, tc.old, tc.new, 1)
			if s == set {
				t.Fatalf("replacement %q not applied", tc.old)
			}
			if _, err := parse(t, s); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v does not reject %s", err, tc.want)
			}
		})
	}

	t.Run("only one set", func(t *testing.T) {
		for _, key := range []string{"requests_dir", "results_dir"} {
			_, err := parse(t, without(set, key))
			if err == nil || !strings.Contains(err.Error(), "hostapply."+key) {
				t.Fatalf("without %s: error %v", key, err)
			}
		}
	})
}

func TestConfig_GateClientID(t *testing.T) {
	line := "sync:\n"
	if c, err := parse(t, validYAML); err != nil || c.Gate.ClientID != "" {
		t.Fatalf("default: %v %+v", err, c)
	}
	c, err := parse(t, strings.Replace(validYAML, line, "gate:\n  client_id: \"123456789@vpn\"\n"+line, 1))
	if err != nil || c.Gate.ClientID != "123456789@vpn" {
		t.Fatalf("valid client id: %v %+v", err, c)
	}
	for _, bad := range []string{"a&b=c", "a b", "x/y", "a%20b"} {
		if _, err := parse(t, strings.Replace(validYAML, line, "gate:\n  client_id: \""+bad+"\"\n"+line, 1)); err == nil {
			t.Errorf("client id %q accepted", bad)
		}
	}
	noHost := without(strings.Replace(validYAML, line, "gate:\n  client_id: abc\n"+line, 1), "tagcess_host")
	if _, err := parse(t, noHost); err == nil || !strings.Contains(err.Error(), "tagcess_host") {
		t.Errorf("client_id without tagcess_host: %v", err)
	}
}

// TestConfig_GateUpstream is AC3 of issue #5: gate.upstream is optional and must be host:port.
func TestConfig_GateUpstream(t *testing.T) {
	line := "sync:\n"
	with := func(v string) string {
		return strings.Replace(validYAML, line, "gate:\n  upstream: \""+v+"\"\n"+line, 1)
	}
	if c, err := parse(t, validYAML); err != nil || c.Gate.Upstream != "" {
		t.Fatalf("default: %v %+v", err, c)
	}
	for _, ok := range []string{"127.0.0.1:4181", "oauth2-proxy:4180", "[::1]:4180"} {
		c, err := parse(t, with(ok))
		if err != nil || c.Gate.Upstream != ok {
			t.Errorf("%q: %v %+v", ok, err, c)
		}
	}
	for _, bad := range []string{"nohost", "host:", ":4180", "host:0", "host:70000", "host:abc", "a b:1", "http://h:1", "h:1/x", "h:1 {", "::1:4180"} {
		if _, err := parse(t, with(bad)); err == nil || !strings.Contains(err.Error(), "gate.upstream") {
			t.Errorf("%q accepted or wrong error: %v", bad, err)
		}
	}
}
