package adopttarget

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
)

// The adopt-shaped fixture may only carry example.test names, documentation or non-routable addresses and no
// secret-shaped value (decision 4 [K]: real names stay out of the repo).
var (
	hostnameRE = regexp.MustCompile(`\b(?:[a-z0-9-]+\.)+(?:test|com|net|org|io|site|de|tr|dev|app|cloud)\b`)
	ipv4RE     = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	ipv6RE     = regexp.MustCompile(`\b[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7}\b`)
	pemRE      = regexp.MustCompile(`-----BEGIN [A-Z ]*(PRIVATE KEY|CERTIFICATE)-----`)
	tokenRE    = regexp.MustCompile(`[A-Za-z0-9+/_-]{32,}`)
)

// allowedPrefixes: documentation ranges (RFC 5737/3849), loopback, private, CGNAT (the tailnet), Tailscale ULA.
var allowedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("fd00::/8"), netip.MustParsePrefix("0.0.0.0/32"),
}

func allowedAddr(s string) bool {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return true // not an address (a version string, a time)
	}
	for _, p := range allowedPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// mixedToken reports whether s looks like a key/token: long, with upper- and lower-case letters and digits.
func mixedToken(s string) bool {
	return strings.ContainsAny(s, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") && strings.ContainsAny(s, "abcdefghijklmnopqrstuvwxyz") &&
		strings.ContainsAny(s, "0123456789")
}

func scanSanitized(t *testing.T, name, text string) {
	t.Helper()
	for _, h := range hostnameRE.FindAllString(text, -1) {
		if !strings.HasSuffix(h, "example.test") {
			t.Errorf("%s: host name %q is not under example.test", name, h)
		}
	}
	for _, ip := range ipv4RE.FindAllString(text, -1) {
		if !allowedAddr(ip) {
			t.Errorf("%s: address %s is not a documentation or non-routable address", name, ip)
		}
	}
	for _, ip := range ipv6RE.FindAllString(text, -1) {
		if strings.Count(ip, ":") >= 2 && !allowedAddr(strings.TrimSuffix(ip, "::")) && !allowedAddr(ip+"0") && !allowedAddr(ip) {
			t.Errorf("%s: address %s is not a documentation or non-routable address", name, ip)
		}
	}
	if pemRE.MatchString(text) {
		t.Errorf("%s: carries a PEM block", name)
	}
	for _, tok := range tokenRE.FindAllString(text, -1) {
		if mixedToken(tok) {
			t.Errorf("%s: secret-shaped value %q", name, tok)
		}
	}
}

// fixtureSite is one parsed fixture site file.
type fixtureSite struct {
	host, snippet, cert string
	roles               []string
	redirect            bool
}

var importRE = regexp.MustCompile(`(?m)^\s*import (vpn_site|vpn_site_api|vpn_only) (\S+)(?: (\S+))?\s*$`)

func readFixtureSites(t *testing.T) map[string]fixtureSite {
	t.Helper()
	dir := filepath.Join(RepoRoot(), "test", "adopttarget", "fixtures", "adopt", "etc", "caddy", "sites")
	files, err := filepath.Glob(filepath.Join(dir, "*.caddy"))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]fixtureSite{}
	for _, f := range files {
		data, err := os.ReadFile(f) // #nosec G304 -- repo fixture
		if err != nil {
			t.Fatal(err)
		}
		host := strings.TrimSuffix(filepath.Base(f), ".caddy")
		if !strings.HasPrefix(string(data), host+" {") {
			t.Fatalf("%s: the file must hold exactly the site %s", f, host)
		}
		m := importRE.FindStringSubmatch(string(data))
		if m == nil {
			t.Fatalf("%s: no vpn_site/vpn_site_api/vpn_only import", f)
		}
		s := fixtureSite{host: host, snippet: m[1], cert: m[2], redirect: strings.Contains(string(data), "redir ")}
		if m[3] != "" {
			s.roles = strings.Split(m[3], ",")
		}
		out[host] = s
	}
	return out
}

// AC9 (F6-001): the fixture and the adopt seed example are sanitized, and the seed maps the fixture's 20 sites
// one to one (kind, roles, certificate group).
func TestAdoptTarget_FixtureSanitizedAndSeedConsistent(t *testing.T) {
	root := filepath.Join(RepoRoot(), "test", "adopttarget", "fixtures")
	seedPath := filepath.Join(RepoRoot(), "deploy", "ansible", "examples", "seed.example.json")
	paths := []string{seedPath}
	if err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			paths = append(paths, p)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for _, p := range paths {
		data, err := os.ReadFile(p) // #nosec G304 -- repo fixture
		if err != nil {
			t.Fatal(err)
		}
		scanSanitized(t, strings.TrimPrefix(p, RepoRoot()+"/"), string(data))
	}

	fx := readFixtureSites(t)
	if len(fx) != 20 {
		t.Fatalf("fixture has %d site files, want 20", len(fx))
	}
	var counts = map[string]int{}
	for _, s := range fx {
		counts[s.snippet]++
	}
	if counts["vpn_site"]+counts["vpn_site_api"] != 16 || counts["vpn_site_api"] != 5 || counts["vpn_only"] != 4 {
		t.Fatalf("fixture shape %v, want 16 role sites (5 api) and 4 vpn_only", counts)
	}

	var seed struct {
		Sites []struct {
			Hosts          []string `json:"hosts"`
			Kind           string   `json:"kind"`
			OpenReason     string   `json:"open_reason"`
			SystemTemplate string   `json:"system_template"`
			Roles          []string `json:"roles"`
			TargetRoles    []string `json:"target_roles"`
			Cert           string   `json:"cert"`
			Redirects      []struct {
				Source string `json:"source"`
			} `json:"redirects"`
		} `json:"sites"`
	}
	data, err := os.ReadFile(seedPath) // #nosec G304 -- repo example
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &seed); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	var systems []string
	intentional := []string{"projects-auth.c.example.test", "storage-api.c.example.test"}
	for _, s := range seed.Sites {
		if s.Kind == "system" {
			systems = append(systems, s.SystemTemplate)
			continue
		}
		for _, h := range s.Hosts {
			f, ok := fx[h]
			if !ok {
				t.Errorf("seed site %s has no fixture file", h)
				continue
			}
			seen[h] = true
			if s.Kind != "open" || len(s.Roles) != 0 {
				t.Errorf("%s: seed kind %q roles %v, want open without roles (decision 1 [K])", h, s.Kind, s.Roles)
			}
			if s.Cert != "le:"+f.cert {
				t.Errorf("%s: seed cert %q, fixture certificate group %q", h, s.Cert, f.cert)
			}
			switch f.snippet {
			case "vpn_site", "vpn_site_api":
				if s.OpenReason != "transition" || !slices.Equal(s.TargetRoles, f.roles) {
					t.Errorf("%s: seed %s target_roles %v, fixture roles %v (want transition + the same roles)", h, s.OpenReason, s.TargetRoles, f.roles)
				}
			case "vpn_only":
				want := "transition"
				if slices.Contains(intentional, h) {
					want = "intentional"
				}
				if s.OpenReason != want || len(s.TargetRoles) != 0 {
					t.Errorf("%s: seed open_reason %q target_roles %v, want %s and none (00 §9 Kapanan-8)", h, s.OpenReason, s.TargetRoles, want)
				}
			}
			if f.redirect != (len(s.Redirects) > 0) {
				t.Errorf("%s: redirect in fixture %v, in seed %v", h, f.redirect, len(s.Redirects) > 0)
			}
		}
	}
	for h := range fx {
		if !seen[h] {
			t.Errorf("fixture site %s is not in the seed", h)
		}
	}
	sort.Strings(systems)
	if !slices.Equal(systems, []string{"headscale", "wireguard_ui", "zitadel"}) {
		t.Errorf("seed system sites %v, want headscale, wireguard_ui, zitadel (auth, hs, vpn)", systems)
	}
}
