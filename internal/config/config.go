// Package config loads tagcess's own YAML settings file.
//
// Loading is strict: unknown fields are rejected with their line number, required fields are checked,
// and secrets appear only as file paths (SecretFile); this package never opens them.
package config

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"go.yaml.in/yaml/v3"
)

const (
	defaultSocketMode   = FileMode(0o660)
	defaultSyncInterval = 5 * time.Minute
)

var validClientID = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,128}$`)

// Config is the tagcess settings file.
type Config struct {
	DataDir string `yaml:"data_dir"`
	// K8sAuthDir holds the UI-imported k8s credential (F4-032): a separate directory outside the
	// SQLite/git/backup tree. Empty means no credential can be stored (the UI shows a setup error);
	// it never defaults into data_dir.
	K8sAuthDir string    `yaml:"k8s_auth_dir"`
	UI         UI        `yaml:"ui"`
	Hook       Hook      `yaml:"hook"`
	Headscale  Headscale `yaml:"headscale"`
	Zitadel    Zitadel   `yaml:"zitadel"`
	Caddy      Caddy     `yaml:"caddy"`
	DNS        DNS       `yaml:"dns"`
	Sync       Sync      `yaml:"sync"`
	Sites      Sites     `yaml:"sites"`
	HostApply  HostApply `yaml:"hostapply"`
	Gate       Gate      `yaml:"gate"`
}

// Gate describes the oauth2-proxy gate to the sign-out links (J1). ClientID is the public client id of
// the OIDC application named zitadel.oauth2_proxy_app (not a secret). Optional: while it is empty the
// links only clear the oauth2-proxy cookie, which leaves the Zitadel session open.
type Gate struct {
	ClientID string `yaml:"client_id"`
	// Upstream is the oauth2-proxy address (host:port) the generated Caddyfile's reverse_proxy and
	// forward_auth lines use. Optional: unset is 127.0.0.1:4180.
	Upstream string `yaml:"upstream"`
}

// HostApply is the pair of directories shared with the Headscale host helper (ADR 0021 b):
// tagcess writes requests into RequestsDir and reads the helper's result/status from ResultsDir
// (mounted read-only). Both unset means H-07 is off; the container never sees the helper's
// private directory or the real Headscale config.
type HostApply struct {
	RequestsDir string `yaml:"requests_dir"`
	ResultsDir  string `yaml:"results_dir"`
}

// Enabled reports whether H-07 is configured. Validation guarantees both directories are set then.
func (h HostApply) Enabled() bool { return h.RequestsDir != "" && h.ResultsDir != "" }

// Sites carries the site inputs (S-02, security.md §5). allowed_domains stays config-only;
// allowed_targets seeds the UI-editable setting on first start (F2-013); the zitadel internal
// sources and the tagcess host feed the first import (F2-014); the certificates resolve
// cert:auto (F2-004) and their coverage drives the S-07 warning (F2-015).
type Sites struct {
	AllowedDomains         []string `yaml:"allowed_domains"`
	AllowedTargets         []string `yaml:"allowed_targets"`
	ZitadelInternalSources []string `yaml:"zitadel_internal_sources"`
	// ACMEEmail is the email of the Caddyfile global block.
	ACMEEmail string `yaml:"acme_email"`
	// Certificates are the certbot certificate names under /etc/letsencrypt/live that
	// cert:auto may resolve to. They are listed here (not read from disk) because the
	// tagcess container does not see the certificate directory.
	Certificates []string `yaml:"certificates"`
	// VPNAddress is the MagicDNS A value every site host points at (ADR 0013).
	VPNAddress string `yaml:"vpn_address"`
	// K8sUpstream is the upstream of the Caddyfile's (k8s) snippet, https://host[:port]. Optional:
	// empty keeps the render default (https://100.64.0.5); the existing installation's Traefik internal
	// entrypoint is :8443.
	K8sUpstream string `yaml:"k8s_upstream"`
	// TagcessHost is the host of the tagcess system site, added by the first import.
	TagcessHost string `yaml:"tagcess_host"`
	// SeedFile is the first-import seed (G-01). Optional: until it is set the first-import
	// action is hidden in the interface.
	SeedFile string `yaml:"seed_file"`
}

// Caddy is the Caddy admin API connection and the file a restart reads (ADR 0005).
type Caddy struct {
	AdminURL      string `yaml:"admin_url"`
	CaddyfilePath string `yaml:"caddyfile_path"`
}

// DNS is the MagicDNS extra-records file and the resolver that verifies changed names (ADR 0013).
type DNS struct {
	RecordsPath string `yaml:"records_path"`
	// Resolver is the "host:port" UDP address asked about changed names. Empty means the
	// dns package default (100.100.100.100:53).
	Resolver string `yaml:"resolver"`
}

// UI is the web interface, served on a unix socket that Caddy proxies to.
type UI struct {
	Socket      string   `yaml:"socket"`
	SocketGroup string   `yaml:"socket_group"`
	SocketMode  FileMode `yaml:"socket_mode"`
}

// Hook is the Zitadel webhook listener.
type Hook struct {
	Listen         string     `yaml:"listen"`
	SigningKeyFile SecretFile `yaml:"signing_key_file"`
	// GroupsSigningKeyFile is optional. When set, the same listener also serves the Zitadel
	// preuserinfo `groups` claim endpoint at /groups, verified with this key (F1-026).
	GroupsSigningKeyFile SecretFile `yaml:"groups_signing_key_file"`
}

// Headscale is the Headscale gRPC unix socket.
type Headscale struct {
	Socket string `yaml:"socket"`
}

// Zitadel is the Zitadel API connection.
type Zitadel struct {
	Issuer    string     `yaml:"issuer"`
	ProjectID string     `yaml:"project_id"`
	KeyFile   SecretFile `yaml:"key_file"`
	// OAuth2ProxyApp is the name of the OIDC application whose redirect URIs the site
	// pipeline keeps in line with the site records (ADR 0012). The app id is resolved by
	// name at startup.
	OAuth2ProxyApp string `yaml:"oauth2_proxy_app"`
}

// Sync controls the periodic reconcile.
type Sync struct {
	Interval time.Duration `yaml:"interval"`
}

// SecretFile is the path of a file that holds a secret. The secret itself never enters Config.
type SecretFile string

// FileMode is a permission written as a quoted octal string ("0660"), so YAML does not turn it into a number.
type FileMode fs.FileMode

// Perm returns the mode as fs.FileMode.
func (m FileMode) Perm() fs.FileMode { return fs.FileMode(m) }

// UnmarshalYAML accepts only a quoted octal string between "0" and "0777".
func (m *FileMode) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode || n.Tag != "!!str" {
		return fmt.Errorf("line %d: file mode must be a quoted octal string like \"0660\", got %s", n.Line, n.Value)
	}
	v, err := strconv.ParseUint(n.Value, 8, 32)
	if err != nil || v > 0o777 {
		return fmt.Errorf("line %d: invalid file mode %q, want an octal permission like \"0660\"", n.Line, n.Value)
	}
	*m = FileMode(v)
	return nil
}

// Load reads and validates the config file at path.
func Load(path string) (*Config, error) {
	f, err := os.Open(path) // #nosec G304 -- the operator passes the config path
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	defer func() { _ = f.Close() }()
	return Parse(f, path)
}

// Parse reads and validates a config from r; name is used in error messages.
func Parse(r io.Reader, name string) (*Config, error) {
	c := Config{
		UI:   UI{SocketMode: defaultSocketMode},
		Sync: Sync{Interval: defaultSyncInterval},
	}
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("config %s: %w", name, err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("config %s: must contain a single YAML document", name)
	}
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("config %s: %w", name, err)
	}
	return &c, nil
}

func (c *Config) validate() error {
	var missing, invalid []string
	required := []struct {
		path, value string
	}{
		{"data_dir", c.DataDir},
		{"ui.socket", c.UI.Socket},
		{"ui.socket_group", c.UI.SocketGroup},
		{"hook.listen", c.Hook.Listen},
		{"hook.signing_key_file", string(c.Hook.SigningKeyFile)},
		{"headscale.socket", c.Headscale.Socket},
		{"zitadel.issuer", c.Zitadel.Issuer},
		{"zitadel.project_id", c.Zitadel.ProjectID},
		{"zitadel.key_file", string(c.Zitadel.KeyFile)},
	}
	for _, f := range required {
		if strings.TrimSpace(f.value) == "" {
			missing = append(missing, f.path)
		}
	}
	if d := c.K8sAuthDir; d != "" {
		if !filepath.IsAbs(d) || filepath.Clean(d) != d {
			invalid = append(invalid, "k8s_auth_dir: must be a clean absolute path")
		} else if d == c.DataDir || strings.HasPrefix(d, strings.TrimSuffix(c.DataDir, "/")+"/") {
			invalid = append(invalid, "k8s_auth_dir: must be outside data_dir")
		}
	}
	// The site allowlists must be non-empty: an empty list would block every site or, if treated
	// as open, allow every one (security.md §5 fail-closed rule).
	if len(c.Sites.AllowedDomains) == 0 {
		missing = append(missing, "sites.allowed_domains")
	}
	if len(c.Sites.AllowedTargets) == 0 {
		missing = append(missing, "sites.allowed_targets")
	}
	// The render inputs of the site pipeline: without them no Caddyfile can be produced, so a
	// change could never be applied (fail safe: refuse to start).
	if strings.TrimSpace(c.Sites.ACMEEmail) == "" {
		missing = append(missing, "sites.acme_email")
	}
	if len(c.Sites.Certificates) == 0 {
		missing = append(missing, "sites.certificates")
	}
	if strings.TrimSpace(c.Sites.VPNAddress) == "" {
		missing = append(missing, "sites.vpn_address")
	}
	if strings.TrimSpace(c.Caddy.AdminURL) == "" {
		missing = append(missing, "caddy.admin_url")
	}
	if strings.TrimSpace(c.Caddy.CaddyfilePath) == "" {
		missing = append(missing, "caddy.caddyfile_path")
	}
	if strings.TrimSpace(c.DNS.RecordsPath) == "" {
		missing = append(missing, "dns.records_path")
	}
	if strings.TrimSpace(c.Zitadel.OAuth2ProxyApp) == "" {
		missing = append(missing, "zitadel.oauth2_proxy_app")
	}
	// The seed file needs the tagcess host to complete the canonical system set (F2-007).
	if strings.TrimSpace(c.Sites.SeedFile) != "" && strings.TrimSpace(c.Sites.TagcessHost) == "" {
		invalid = append(invalid, "sites.tagcess_host: required when sites.seed_file is set")
	}

	for _, s := range []struct {
		path string
		file SecretFile
	}{
		{"hook.signing_key_file", c.Hook.SigningKeyFile},
		{"hook.groups_signing_key_file", c.Hook.GroupsSigningKeyFile},
		{"zitadel.key_file", c.Zitadel.KeyFile},
	} {
		p := string(s.file)
		if p != "" && (!filepath.IsAbs(p) || filepath.Clean(p) != p || strings.ContainsFunc(p, unicode.IsControl)) {
			invalid = append(invalid, s.path+": must be a clean absolute path")
		}
	}
	// H-07 is optional, but a half-set or sloppy pair must not start: the helper trusts only these two directories.
	for _, d := range []struct{ path, value string }{
		{"hostapply.requests_dir", c.HostApply.RequestsDir},
		{"hostapply.results_dir", c.HostApply.ResultsDir},
	} {
		switch p := d.value; {
		case p == "" && c.HostApply != (HostApply{}):
			missing = append(missing, d.path)
		case p != "" && (!filepath.IsAbs(p) || filepath.Clean(p) != p || strings.ContainsFunc(p, unicode.IsControl)):
			invalid = append(invalid, d.path+": must be a clean absolute path")
		}
	}
	if c.HostApply.Enabled() && c.HostApply.RequestsDir == c.HostApply.ResultsDir {
		invalid = append(invalid, "hostapply: requests_dir and results_dir must differ")
	}
	// Other bits would let any local process reach the UI socket and forge identity headers.
	if c.UI.SocketMode.Perm()&0o007 != 0 {
		invalid = append(invalid, fmt.Sprintf("ui.socket_mode: %04o gives access to others, use socket_group", c.UI.SocketMode.Perm()))
	}
	if c.Hook.Listen != "" {
		host, _, err := net.SplitHostPort(c.Hook.Listen)
		ip := net.ParseIP(host)
		if err != nil || ip == nil || ip.IsUnspecified() {
			invalid = append(invalid, "hook.listen: must be ip:port with a specific IP (not all interfaces)")
		}
	}
	if c.Zitadel.Issuer != "" {
		u, err := url.Parse(c.Zitadel.Issuer)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			invalid = append(invalid, "zitadel.issuer: must be a plain https URL")
		}
	}
	if up := c.Sites.K8sUpstream; up != "" {
		u, err := url.Parse(up)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" ||
			u.Fragment != "" || strings.ContainsAny(up, "{}\"'`\\ #?") || strings.HasSuffix(u.Host, ":") || !validPort(u.Port()) {
			invalid = append(invalid, "sites.k8s_upstream: must be https://host[:port]")
		}
	}
	if id := c.Gate.ClientID; id != "" {
		if !validClientID.MatchString(id) {
			invalid = append(invalid, "gate.client_id: must be a plain client id (letters, digits, . _ @ -)")
		}
		if strings.TrimSpace(c.Sites.TagcessHost) == "" {
			invalid = append(invalid, "sites.tagcess_host: required when gate.client_id is set (post-logout return page)")
		}
	}
	if up := c.Gate.Upstream; up != "" && !validHostPort(up) {
		invalid = append(invalid, "gate.upstream: must be host:port")
	}
	if c.Sync.Interval <= 0 {
		invalid = append(invalid, "sync.interval: must be positive")
	}

	var errs []error
	if len(missing) > 0 {
		errs = append(errs, fmt.Errorf("missing required field(s): %s", strings.Join(missing, ", ")))
	}
	for _, s := range invalid {
		errs = append(errs, errors.New(s))
	}
	return errors.Join(errs...)
}

// validPort reports whether p is empty (no port) or a plain decimal port in 1..65535.
// validHostPort reports whether s is host:port with a plain DNS name or IP literal host (IPv6 in
// brackets) and a port 1-65535, so it is safe to write into a Caddyfile line.
func validHostPort(s string) bool {
	host, port, err := net.SplitHostPort(s)
	if err != nil || host == "" || port == "" || !validPort(port) {
		return false
	}
	for _, r := range host {
		letter := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'
		if !letter && (r < '0' || r > '9') && !strings.ContainsRune("._:-", r) {
			return false
		}
	}
	return true
}

func validPort(p string) bool {
	if p == "" {
		return true
	}
	n, err := strconv.Atoi(p)
	return err == nil && n >= 1 && n <= 65535 && strconv.Itoa(n) == p
}
