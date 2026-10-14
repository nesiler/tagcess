package render

import (
	"strings"
	"testing"

	"github.com/nesiler/tagcess/internal/site"
)

// F2-015 (S-07.1): a host no certificate covers must not block the record. cert:auto without a
// covering certificate renders the block WITHOUT a tls line (Caddy provisions nothing it cannot
// load; a missing cert file would fail /load for the whole config) and the interface warns
// (web layer). le:<name> stays an explicit operator choice and always renders the tls line.

// uncoveredRoleSite is a role site under a domain no certificate covers.
func uncoveredRoleSite() site.Site {
	s := roleSite()
	s.Hosts = []string{"newtool.newdomain.example"}
	s.Cert = "auto"
	return s
}

// uncoveredAPISite is a role site with an API exemption whose host is uncovered.
func uncoveredAPISite() site.Site {
	s := uncoveredRoleSite()
	s.APIRules = []site.APIRule{{Type: site.APIRuleHeaderPresent, Value: "X-Api"}}
	return s
}

// uncoveredOpenSite is an open url site whose host is uncovered.
func uncoveredOpenSite() site.Site {
	s := openURLSite()
	s.Hosts = []string{"newtool.newdomain.example"}
	s.Cert = "auto"
	return s
}

// A cert:auto role site with no covering certificate renders through the no-tls snippet variant;
// its own block carries no certificate path.
func TestCaddyRender_CertAutoUncoveredOmitsTLS(t *testing.T) {
	block, err := renderCaddySite(uncoveredRoleSite(), caddyCfg(true))
	if err != nil {
		t.Fatalf("an uncovered host blocked the record: %v", err)
	}
	if !strings.Contains(block, "import vpn_site_nt devops,developer") {
		t.Errorf("the no-tls role snippet is not used:\n%s", block)
	}
	if strings.Contains(block, "/etc/letsencrypt/live/") {
		t.Errorf("the uncovered site references a certificate path:\n%s", block)
	}

	// The full render carries the no-tls snippets exactly once, each.
	out, err := RenderCaddyfile([]site.Site{uncoveredRoleSite()}, caddyCfg(true))
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if strings.Count(out, "(vpn_site_nt) {") != 1 || strings.Count(out, "(vpn_site_api_nt) {") != 1 {
		t.Errorf("the no-tls snippet variants are missing or duplicated:\n%s", out)
	}

	// Without a no-tls site the snippets stay out and the text is what F2-004 produced.
	plain, err := RenderCaddyfile([]site.Site{roleSite()}, caddyCfg(true))
	if err != nil {
		t.Fatalf("render plain: %v", err)
	}
	if strings.Contains(plain, "(vpn_site_nt)") {
		t.Errorf("the no-tls snippets appeared without a no-tls site:\n%s", plain)
	}
}

// A role site with an API exemption renders through the api no-tls variant: the @api exemption
// stays reachable from every source even without a certificate.
func TestCaddyRender_CertAutoUncoveredAPISite(t *testing.T) {
	out, err := RenderCaddyfile([]site.Site{uncoveredAPISite()}, caddyCfg(true))
	if err != nil {
		t.Fatalf("an uncovered host blocked the record: %v", err)
	}
	if !strings.Contains(out, "import vpn_site_api_nt") {
		t.Errorf("the no-tls api snippet is not used:\n%s", out)
	}
}

// An open site with no covering certificate renders without the tls line, target intact.
func TestCaddyRender_CertAutoUncoveredOpenSite(t *testing.T) {
	block, err := renderCaddySite(uncoveredOpenSite(), caddyCfg(true))
	if err != nil {
		t.Fatalf("an uncovered host blocked the record: %v", err)
	}
	if strings.Contains(block, "tls /etc/letsencrypt/live/") {
		t.Errorf("the uncovered open site kept a tls line:\n%s", block)
	}
	if !strings.Contains(block, "reverse_proxy https://100.64.0.5:30443") {
		t.Errorf("the open site lost its target:\n%s", block)
	}
}

// le:<name> is explicit: it keeps the tls snippet (the name as its certificate argument)
// regardless of coverage.
func TestCaddyRender_CertNameAlwaysRendersTLS(t *testing.T) {
	s := uncoveredRoleSite()
	s.Cert = "le:newdomain.example"
	block, err := renderCaddySite(s, caddyCfg(true))
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(block, "import vpn_site newdomain.example devops,developer") {
		t.Errorf("the explicit certificate name lost its tls snippet:\n%s", block)
	}
	if strings.Contains(block, "_nt") {
		t.Errorf("an explicit certificate rendered through the no-tls variant:\n%s", block)
	}
}

// The no-tls snippets carry the same auth flow and S-06 tail as the tls ones, minus the tls line.
func TestCaddyRender_NoTLSSnippetsFollowKeyState(t *testing.T) {
	open, err := RenderCaddyfile([]site.Site{uncoveredRoleSite()}, caddyCfg(true))
	if err != nil {
		t.Fatalf("render open: %v", err)
	}
	closed, err := RenderCaddyfile([]site.Site{uncoveredRoleSite()}, caddyCfg(false))
	if err != nil {
		t.Fatalf("render closed: %v", err)
	}
	for _, body := range []string{open, closed} {
		if !strings.Contains(body, "(vpn_site_nt) {") {
			t.Fatalf("no-tls snippet missing:\n%s", body)
		}
	}
	if !strings.Contains(open, "\thandle {\n\t\timport k8s\n\t}\n") {
		t.Errorf("the open tail is missing from the no-tls snippet:\n%s", open)
	}
	if !strings.Contains(closed, "\thandle {\n\t\trespond 403\n\t}\n") {
		t.Errorf("the closed tail is missing from the no-tls snippet:\n%s", closed)
	}
}

// UncoveredHosts lists the hosts no configured certificate covers (the web warning, S-07.1).
func TestUncoveredHosts(t *testing.T) {
	certs := []string{"example.com", "internal.example.org"}
	got := UncoveredHosts(certs, []string{
		"monitor.example.com",
		"deep.internal.example.org",
		"other.newdomain.example",
	})
	if len(got) != 1 || got[0] != "other.newdomain.example" {
		t.Errorf("UncoveredHosts = %v", got)
	}
	if got := UncoveredHosts(certs, []string{"monitor.example.com"}); len(got) != 0 {
		t.Errorf("covered hosts reported uncovered: %v", got)
	}
}

// CertCoversAll is the render coverage rule the web review warning reuses (so the warning and
// the render cannot drift apart): the certificate name itself or a direct subdomain covers a
// host; a name that is not a safe certificate name and an empty host list cover nothing.
func TestCertCoversAll(t *testing.T) {
	tests := []struct {
		name  string
		cert  string
		hosts []string
		want  bool
	}{
		{"apex covers its subdomain", "example.com", []string{"git.example.com"}, true},
		{"exact name", "git.example.com", []string{"git.example.com"}, true},
		{"other domain", "example.com", []string{"git.example.net"}, false},
		{"lookalike without dot", "example.com", []string{"evilexample.com"}, false},
		{"dot traversal name", "..", []string{"git.example.com"}, false},
		{"name with a space", "a b.com", []string{"a b.com"}, false},
		{"no hosts", "example.com", nil, false},
	}
	for _, tt := range tests {
		if got := CertCoversAll(tt.cert, tt.hosts); got != tt.want {
			t.Errorf("%s: CertCoversAll(%q, %v) = %v, want %v", tt.name, tt.cert, tt.hosts, got, tt.want)
		}
	}
}
