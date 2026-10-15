package stack

import (
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Params are the typed settings of setup-flow.md §5.3.1. Paths of the managed stack are not parameters: they are
// fixed per release in the templates.
type Params struct {
	Components []Component // enabled services; order does not matter

	HeadscaleHost    string // public host of Headscale, e.g. hs.example.com
	MagicDNSDomain   string // MagicDNS base domain
	PrefixV4         string // inside 100.64.0.0/10, canonical
	PrefixV6         string // inside fd7a:115c:a1e0::/48, canonical
	HeadscalePort    int    // loopback listener behind Caddy
	HeadscaleMetrics int    // loopback metrics listener
	OAuth2ProxyPort  int    // loopback listener
	SetupPort        int    // tagcess setup listener on 127.0.0.1 until sealed
	EmbeddedDERP     bool

	IssuerURL         string // https://host of the OIDC provider
	HeadscaleClientID string
	ProxyClientID     string
	ProxyHost         string // public host of the auth proxy (redirect URL)
	CookieDomain      string
	CookieLifetime    string // Go duration, 5m to 24h
	AdminGroup        string

	CaddyGID     int // host group IDs passed as group_add
	HeadscaleGID int
	SocketGID    int // dedicated group of the Headscale socket directory
}

var (
	hostLabelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	clientIDRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@._-]{0,127}$`)
	groupRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

	cgnat   = netip.MustParsePrefix("100.64.0.0/10")
	ulaTail = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
)

func validHostname(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for _, l := range strings.Split(h, ".") {
		if !hostLabelRe.MatchString(l) {
			return false
		}
	}
	return true
}

func validPrefix(s string, parent netip.Prefix, want4 bool) error {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return fmt.Errorf("prefix %q: %w", s, err)
	}
	if p.Addr().Is4() != want4 || p != p.Masked() || p.Addr().Is4In6() {
		return fmt.Errorf("prefix %q is not a canonical prefix of the right family", s)
	}
	if p.Bits() < parent.Bits() || !parent.Contains(p.Addr()) {
		return fmt.Errorf("prefix %q is outside %s", s, parent)
	}
	return nil
}

func (p Params) has(c Component) bool {
	for _, x := range p.Components {
		if x == c {
			return true
		}
	}
	return false
}

// Validate returns the first problem found; nothing is rendered for invalid parameters.
func (p Params) Validate() error {
	if len(p.Components) == 0 {
		return fmt.Errorf("no components enabled")
	}
	known := map[Component]bool{}
	for _, c := range AllComponents() {
		known[c] = true
	}
	seen := map[Component]bool{}
	for _, c := range p.Components {
		if !known[c] {
			return fmt.Errorf("unknown component %q", c)
		}
		if seen[c] {
			return fmt.Errorf("component %q listed twice", c)
		}
		seen[c] = true
	}
	for name, gid := range map[string]int{"caddy gid": p.CaddyGID, "headscale gid": p.HeadscaleGID, "socket gid": p.SocketGID} {
		if gid < 0 || gid > 65535 {
			return fmt.Errorf("%s %d out of range", name, gid)
		}
	}
	if p.has(Headscale) {
		if !validHostname(p.HeadscaleHost) {
			return fmt.Errorf("headscale host %q is not a valid hostname", p.HeadscaleHost)
		}
		if !validHostname(p.MagicDNSDomain) {
			return fmt.Errorf("magicdns domain %q is not a valid hostname", p.MagicDNSDomain)
		}
		if err := validPrefix(p.PrefixV4, cgnat, true); err != nil {
			return err
		}
		if err := validPrefix(p.PrefixV6, ulaTail, false); err != nil {
			return err
		}
		if err := validIssuer(p.IssuerURL); err != nil {
			return err
		}
		if !clientIDRe.MatchString(p.HeadscaleClientID) {
			return fmt.Errorf("headscale client id is invalid")
		}
		if !groupRe.MatchString(p.AdminGroup) {
			return fmt.Errorf("admin group is invalid")
		}
	}
	if p.has(OAuth2Proxy) {
		if err := validIssuer(p.IssuerURL); err != nil {
			return err
		}
		if !clientIDRe.MatchString(p.ProxyClientID) {
			return fmt.Errorf("proxy client id is invalid")
		}
		if !validHostname(p.ProxyHost) || !validHostname(p.CookieDomain) {
			return fmt.Errorf("proxy host or cookie domain is not a valid hostname")
		}
		d, err := time.ParseDuration(p.CookieLifetime)
		if err != nil || d < 5*time.Minute || d > 24*time.Hour {
			return fmt.Errorf("cookie lifetime %q must be a duration from 5m to 24h", p.CookieLifetime)
		}
		if !groupRe.MatchString(p.AdminGroup) {
			return fmt.Errorf("admin group is invalid")
		}
	}
	ports := map[int]string{}
	check := func(name string, port int, used bool) error {
		if !used {
			return nil
		}
		if port < 1024 || port > 65535 {
			return fmt.Errorf("%s port %d must be 1024-65535", name, port)
		}
		if other, dup := ports[port]; dup {
			return fmt.Errorf("%s port %d is also used by %s", name, port, other)
		}
		ports[port] = name
		return nil
	}
	for _, e := range []struct {
		n    string
		p    int
		used bool
	}{
		{"headscale", p.HeadscalePort, p.has(Headscale)},
		{"headscale metrics", p.HeadscaleMetrics, p.has(Headscale)},
		{"oauth2-proxy", p.OAuth2ProxyPort, p.has(OAuth2Proxy)},
		{"setup", p.SetupPort, p.has(Tagcess)},
	} {
		if err := check(e.n, e.p, e.used); err != nil {
			return err
		}
	}
	return nil
}

func validIssuer(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		(u.Path != "" && u.Path != "/") || !validHostname(u.Hostname()) {
		return fmt.Errorf("issuer %q must be https://<hostname> without path, query or credentials", s)
	}
	if u.Port() != "" {
		var n int
		if _, err := fmt.Sscanf(u.Port(), "%d", &n); err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("issuer port is invalid")
		}
	}
	return nil
}
