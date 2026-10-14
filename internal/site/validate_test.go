package site

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/internal/store"
)

// staticRoles is a RoleSource that always returns the same complete role list.
type staticRoles []string

func (s staticRoles) ListRoles(ctx context.Context) ([]string, error) {
	return []string(s), nil
}

// funcRoles is a RoleSource for generated role names ("role-0".."role-{n-1}").
type funcRoles struct{ n int }

func (f funcRoles) ListRoles(ctx context.Context) ([]string, error) {
	out := make([]string, 0, f.n)
	for i := 0; i < f.n; i++ {
		out = append(out, fmt.Sprintf("role-%d", i))
	}
	return out, nil
}

// failingRoles is a RoleSource whose read always fails (Zitadel outage).
type failingRoles struct{ err error }

func (f failingRoles) ListRoles(ctx context.Context) ([]string, error) {
	return nil, f.err
}

// testRoles is the vpn project role list the fixtures assume.
var testRoles = staticRoles{"devops", "developer", "standart"}

// newTestValidator returns the validator the fixtures assume: the example domain and the test
// domain as allowed hosts, and the default k8s node as the only url-target host.
func newTestValidator(t *testing.T) *Validator {
	t.Helper()
	v, err := NewValidator(ValidatorConfig{
		AllowedDomains: []string{"example.com", "example.com"},
		AllowedTargets: []string{"100.64.0.5"},
	}, testRoles)
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	return v
}

// validRoleSite is a role-controlled site that passes every rule.
func validRoleSite() Site {
	return Site{
		Hosts:      []string{"git.example.com"},
		Kind:       KindRole,
		Roles:      []string{"developer", "devops"},
		Cert:       "le:example",
		TargetKind: TargetK8s,
		MagicDNS:   true,
		APIRules:   []APIRule{},
		Redirects:  []Redirect{},
		Headers:    []Header{},
	}
}

// TestNewValidator_RejectsEmptyConfig: an empty allowlist would be a misconfiguration that
// either blocks everything or (worse, if defaulted open) allows everything; refuse it.
func TestNewValidator_RejectsEmptyConfig(t *testing.T) {
	ok := ValidatorConfig{
		AllowedDomains: []string{"example.com"},
		AllowedTargets: []string{"100.64.0.5"},
	}
	if _, err := NewValidator(ok, testRoles); err != nil {
		t.Fatalf("NewValidator with full config: %v", err)
	}
	noDomains := ok
	noDomains.AllowedDomains = nil
	if _, err := NewValidator(noDomains, testRoles); err == nil {
		t.Error("NewValidator accepted an empty allowed-domain list")
	}
	noTargets := ok
	noTargets.AllowedTargets = nil
	if _, err := NewValidator(noTargets, testRoles); err == nil {
		t.Error("NewValidator accepted an empty allowed-target list")
	}
	if _, err := NewValidator(ok, nil); err == nil {
		t.Error("NewValidator accepted a nil role source")
	}
}

// TestSiteValidation_AcceptsValid is the positive anchor for AC1..AC4: the three site kinds
// with representative fields pass.
func TestSiteValidation_AcceptsValid(t *testing.T) {
	v := newTestValidator(t)
	ctx := context.Background()

	role := validRoleSite()
	role.APIRules = []APIRule{{Type: APIRuleHeaderPresent, Value: "Authorization"}}
	if err := v.Validate(ctx, role); err != nil {
		t.Errorf("valid role site: %v", err)
	}

	open := Site{
		Hosts:             []string{"blog-admin.example.com"},
		Kind:              KindOpen,
		OpenReason:        OpenReasonTransition,
		TargetRoles:       []string{"developer"},
		Cert:              "auto",
		TargetKind:        TargetURL,
		TargetURL:         "https://100.64.0.5:30443",
		TargetTLSInsecure: true,
		APIRules:          []APIRule{},
		Redirects: []Redirect{
			{Source: "/old", Target: "/new", Code: 302},
			// Today's shape (R1 B-01, projects): an absolute target to the site's
			// own allowed domain with a site path.
			{Source: "/setup", Target: "https://blog-admin.example.com/setup/", Code: 308},
		},
		Headers: []Header{{Name: "X-Frame-Options", Value: "DENY"}},
	}
	if err := v.Validate(ctx, open); err != nil {
		t.Errorf("valid open site: %v", err)
	}

	system := Site{
		Hosts:          []string{"auth.example.com"},
		Kind:           KindSystem,
		SystemTemplate: TemplateZitadel,
		Cert:           "le:example",
		APIRules:       []APIRule{},
		Redirects:      []Redirect{},
		Headers:        []Header{},
	}
	if err := v.Validate(ctx, system); err != nil {
		t.Errorf("valid system site: %v", err)
	}
}

// TestSiteValidation_RejectsInvalid is AC1: an invalid host, role, target, cert, redirect or
// header field refuses the record. Every case mutates one field of a valid site.
func TestSiteValidation_RejectsInvalid(t *testing.T) {
	v := newTestValidator(t)
	ctx := context.Background()

	cases := []struct {
		name   string
		mutate func(s *Site)
		want   string // substring the error must contain (the field name)
	}{
		// hosts
		{"hosts empty", func(s *Site) { s.Hosts = nil }, "hosts"},
		{"hosts uppercase", func(s *Site) { s.Hosts = []string{"Git.example.com"} }, "hosts"},
		{"hosts wildcard", func(s *Site) { s.Hosts = []string{"*.example.com"} }, "hosts"},
		{"hosts label too long", func(s *Site) {
			s.Hosts = []string{strings.Repeat("a", 64) + ".example.com"}
		}, "hosts"},
		{"hosts total too long", func(s *Site) {
			s.Hosts = []string{strings.Repeat("a.", 127) + "com"}
		}, "hosts"},
		{"hosts label starts with hyphen", func(s *Site) {
			s.Hosts = []string{"-git.example.com"}
		}, "hosts"},
		{"hosts trailing hyphen", func(s *Site) {
			s.Hosts = []string{"git-.example.com"}
		}, "hosts"},
		{"hosts outside allowed domains", func(s *Site) {
			s.Hosts = []string{"git.evil.example"}
		}, "hosts"},
		{"hosts duplicate in list", func(s *Site) {
			s.Hosts = []string{"git.example.com", "git.example.com"}
		}, "hosts"},
		// roles
		{"roles empty on role site", func(s *Site) { s.Roles = nil }, "roles"},
		{"roles bad format", func(s *Site) { s.Roles = []string{"DevOps!"} }, "roles"},
		{"roles unknown", func(s *Site) { s.Roles = []string{"ghost"} }, "roles"},
		// cert
		{"cert unknown kind", func(s *Site) { s.Cert = "bogus" }, "cert"},
		{"cert empty", func(s *Site) { s.Cert = "" }, "cert"},
		{"cert le with empty name", func(s *Site) { s.Cert = "le:" }, "cert"},
		{"cert le with path traversal", func(s *Site) { s.Cert = "le:../secrets" }, "cert"},
		{"cert le with slash", func(s *Site) { s.Cert = "le:a/b" }, "cert"},
		{"cert le with uppercase", func(s *Site) { s.Cert = "le:Example" }, "cert"},
		// target
		{"target url bad scheme", func(s *Site) {
			s.TargetKind = TargetURL
			s.TargetURL = "ftp://100.64.0.5/x"
		}, "target"},
		{"target url no host", func(s *Site) {
			s.TargetKind = TargetURL
			s.TargetURL = "http:///path"
		}, "target"},
		{"target url with userinfo", func(s *Site) {
			s.TargetKind = TargetURL
			s.TargetURL = "http://user@100.64.0.5"
		}, "target"},
		{"target k8s with url set", func(s *Site) { s.TargetURL = "https://100.64.0.5" }, "target"},
		{"target unknown kind", func(s *Site) { s.TargetKind = "proxy" }, "target"},
		// redirects
		{"redirect source without slash", func(s *Site) {
			s.Redirects = []Redirect{{Source: "old", Target: "/new", Code: 301}}
		}, "redirects"},
		{"redirect source with space", func(s *Site) {
			s.Redirects = []Redirect{{Source: "/ol d", Target: "/new", Code: 301}}
		}, "redirects"},
		{"redirect source with backslash", func(s *Site) {
			s.Redirects = []Redirect{{Source: `/ol\d`, Target: "/new", Code: 301}}
		}, "redirects"},
		{"redirect target neither path nor host", func(s *Site) {
			s.Redirects = []Redirect{{Source: "/old", Target: "javascript:alert(1)", Code: 301}}
		}, "redirects"},
		{"redirect target outside domains", func(s *Site) {
			s.Redirects = []Redirect{{Source: "/old", Target: "other.evil.example", Code: 301}}
		}, "redirects"},
		{"redirect absolute target outside domains", func(s *Site) {
			s.Redirects = []Redirect{{Source: "/old", Target: "https://other.evil.example/new", Code: 301}}
		}, "redirects"},
		{"redirect absolute target with userinfo", func(s *Site) {
			s.Redirects = []Redirect{{Source: "/old", Target: "https://user@projects.example.com/new", Code: 301}}
		}, "redirects"},
		{"redirect absolute target with query", func(s *Site) {
			s.Redirects = []Redirect{{Source: "/old", Target: "https://projects.example.com/new?x=1", Code: 301}}
		}, "redirects"},
		{"redirect absolute target with bad path", func(s *Site) {
			s.Redirects = []Redirect{{Source: "/old", Target: `https://projects.example.com/ne"w`, Code: 301}}
		}, "redirects"},
		{"redirect absolute target with plus port", func(s *Site) {
			s.Redirects = []Redirect{{Source: "/old", Target: "https://projects.example.com:+80/x", Code: 301}}
		}, "redirects"},
		{"redirect protocol-relative target", func(s *Site) {
			s.Redirects = []Redirect{{Source: "/old", Target: "//evil.example.com", Code: 301}}
		}, "redirects"},
		{"redirect bad code", func(s *Site) {
			s.Redirects = []Redirect{{Source: "/old", Target: "/new", Code: 304}}
		}, "redirects"},
		// headers
		{"header name with space", func(s *Site) {
			s.Headers = []Header{{Name: "X Frame", Value: "DENY"}}
		}, "headers"},
		{"header name empty", func(s *Site) {
			s.Headers = []Header{{Name: "", Value: "DENY"}}
		}, "headers"},
		{"header name delete prefix", func(s *Site) {
			s.Headers = []Header{{Name: "-X-Note", Value: "DENY"}}
		}, "headers"},
		{"header name add prefix", func(s *Site) {
			s.Headers = []Header{{Name: "+X-Note", Value: "DENY"}}
		}, "headers"},
		{"header name comment prefix", func(s *Site) {
			s.Headers = []Header{{Name: "#X-Note", Value: "DENY"}}
		}, "headers"},
		{"header name with backtick", func(s *Site) {
			s.Headers = []Header{{Name: "X`N", Value: "DENY"}}
		}, "headers"},
		{"header name too long", func(s *Site) {
			s.Headers = []Header{{Name: strings.Repeat("X", 129), Value: "DENY"}}
		}, "headers"},
		{"header value with quote", func(s *Site) {
			s.Headers = []Header{{Name: "X-Note", Value: `say "hi"`}}
		}, "headers"},
		{"header value with brace", func(s *Site) {
			s.Headers = []Header{{Name: "X-Note", Value: "{bad}"}}
		}, "headers"},
		{"header value with newline", func(s *Site) {
			s.Headers = []Header{{Name: "X-Note", Value: "a\nb"}}
		}, "headers"},
		{"header value trailing backslash", func(s *Site) {
			s.Headers = []Header{{Name: "X-Note", Value: `token2024\`}}
		}, "headers"},
		{"header value non-ascii", func(s *Site) {
			s.Headers = []Header{{Name: "X-Note", Value: "café"}}
		}, "headers"},
		// kind pairings
		{"role site with target roles", func(s *Site) { s.TargetRoles = []string{"devops"} }, "target_roles"},
		{"role site with open reason", func(s *Site) { s.OpenReason = OpenReasonIntentional }, "open_reason"},
		{"role site with template", func(s *Site) { s.SystemTemplate = TemplateZitadel }, "system_template"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := validRoleSite()
			tc.mutate(&s)
			err := v.Validate(ctx, s)
			if err == nil {
				t.Fatalf("Validate accepted an invalid site")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name the field %q", err, tc.want)
			}
		})
	}

	// open-site pairings: target roles only on open+transition, roles never on open/system.
	openIntentional := Site{
		Hosts: []string{"projects-auth.example.com"}, Kind: KindOpen,
		OpenReason: OpenReasonIntentional, Cert: "auto", TargetKind: TargetK8s,
		TargetRoles: []string{"devops"}, APIRules: []APIRule{}, Redirects: []Redirect{}, Headers: []Header{},
	}
	if err := v.Validate(ctx, openIntentional); err == nil {
		t.Error("Validate accepted target_roles on an intentional open site")
	}
	openWithRoles := openIntentional
	openWithRoles.TargetRoles = nil
	openWithRoles.Roles = []string{"devops"}
	if err := v.Validate(ctx, openWithRoles); err == nil {
		t.Error("Validate accepted roles on an open site")
	}

	// An unknown target role must be reported under its own field name.
	openUnknownTargetRole := Site{
		Hosts: []string{"blog-admin.example.com"}, Kind: KindOpen,
		OpenReason: OpenReasonTransition, TargetRoles: []string{"ghost"},
		Cert: "auto", TargetKind: TargetK8s, APIRules: []APIRule{}, Redirects: []Redirect{}, Headers: []Header{},
	}
	err := v.Validate(ctx, openUnknownTargetRole)
	if err == nil {
		t.Fatal("Validate accepted an unknown target role")
	}
	if !strings.Contains(err.Error(), "target_roles") {
		t.Errorf("unknown target role error %q does not name target_roles", err)
	}
}

// TestSiteValidation_APIRules is AC2: only header_present and path_regex exist, and the regex
// must compile as Go regexp (RE2, the engine Caddy uses) within the character limits.
func TestSiteValidation_APIRules(t *testing.T) {
	v := newTestValidator(t)
	ctx := context.Background()

	valid := []APIRule{
		{Type: APIRuleHeaderPresent, Value: "Authorization"},
		{Type: APIRuleHeaderPresent, Value: "X-Api-Key"},
		{Type: APIRulePathRegex, Value: `^/api/v[0-9]+/[^/]+$`},
	}
	s := validRoleSite()
	for i, rule := range valid {
		s.APIRules = []APIRule{rule}
		if err := v.Validate(ctx, s); err != nil {
			t.Errorf("rule %d (%s %q) rejected: %v", i, rule.Type, rule.Value, err)
		}
	}

	invalid := []struct {
		name string
		rule APIRule
	}{
		{"unknown type", APIRule{Type: "expression", Value: "true"}},
		{"empty type", APIRule{Value: "Authorization"}},
		{"header name with dot", APIRule{Type: APIRuleHeaderPresent, Value: "X.Api.Key"}},
		{"header name with underscore", APIRule{Type: APIRuleHeaderPresent, Value: "X_Api_Key"}},
		{"header name empty", APIRule{Type: APIRuleHeaderPresent, Value: ""}},
		{"header name too long", APIRule{Type: APIRuleHeaderPresent, Value: strings.Repeat("A", 65)}},
		{"regex does not compile", APIRule{Type: APIRulePathRegex, Value: "(unclosed"}},
		{"regex too long", APIRule{Type: APIRulePathRegex, Value: "a" + strings.Repeat("b", 200)}},
		{"regex with backtick", APIRule{Type: APIRulePathRegex, Value: "a`b"}},
		{"regex with brace", APIRule{Type: APIRulePathRegex, Value: "a{b}"}},
		{"regex with quote", APIRule{Type: APIRulePathRegex, Value: "a'b"}},
		{"regex with newline", APIRule{Type: APIRulePathRegex, Value: "a\nb"}},
		{"regex with control char", APIRule{Type: APIRulePathRegex, Value: "a\x00b"}},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			s := validRoleSite()
			s.APIRules = []APIRule{tc.rule}
			if err := v.Validate(ctx, s); err == nil {
				t.Errorf("Validate accepted rule %s %q", tc.rule.Type, tc.rule.Value)
			}
		})
	}

	// API rules only exist on role sites (R1).
	s = validRoleSite()
	s.Kind = KindOpen
	s.OpenReason = OpenReasonIntentional
	s.Roles = nil
	s.APIRules = []APIRule{{Type: APIRuleHeaderPresent, Value: "Authorization"}}
	if err := v.Validate(ctx, s); err == nil {
		t.Error("Validate accepted api rules on an open site")
	}
}

// TestSiteValidation_RoleReadFailure is AC3: a role read that fails (or comes back empty)
// refuses the change, so the last known-good state is kept (security.md §8).
func TestSiteValidation_RoleReadFailure(t *testing.T) {
	ctx := context.Background()
	base := validRoleSite()

	v := newTestValidator(t)
	if err := v.Validate(ctx, base); err != nil {
		t.Fatalf("precondition failed: %v", err)
	}

	broken, err := NewValidator(ValidatorConfig{
		AllowedDomains: []string{"example.com"},
		AllowedTargets: []string{"100.64.0.5"},
	}, failingRoles{err: errors.New("zitadel: read failed")})
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	if err := broken.Validate(ctx, base); err == nil {
		t.Error("Validate accepted a site while the role read failed")
	} else if !strings.Contains(err.Error(), "roles") {
		t.Errorf("read-failure error %q does not mention roles", err)
	}

	// A read that comes back empty cannot confirm any role: a role site is refused.
	empty, err := NewValidator(ValidatorConfig{
		AllowedDomains: []string{"example.com"},
		AllowedTargets: []string{"100.64.0.5"},
	}, staticRoles{})
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	if err := empty.Validate(ctx, base); err == nil {
		t.Error("Validate accepted a role site against an empty role list")
	}

	// A site that references no roles needs no read and still validates during an outage.
	openNoRoles := Site{
		Hosts: []string{"projects-auth.example.com"}, Kind: KindOpen,
		OpenReason: OpenReasonIntentional, Cert: "auto", TargetKind: TargetK8s,
		APIRules: []APIRule{}, Redirects: []Redirect{}, Headers: []Header{},
	}
	if err := broken.Validate(ctx, openNoRoles); err != nil {
		t.Errorf("Validate refused a role-free site during a read outage: %v", err)
	}

	// But a transition site with target roles must not slip through during the same outage.
	openTransition := openNoRoles
	openTransition.OpenReason = OpenReasonTransition
	openTransition.TargetRoles = []string{"developer"}
	if err := broken.Validate(ctx, openTransition); err == nil {
		t.Error("Validate accepted target roles while the role read failed")
	}
}

// TestSiteValidation_TargetBoundary is AC4: user sites may only target allowlisted hosts, and
// never loopback addresses or unix sockets; those stay reserved for the fixed system templates.
func TestSiteValidation_TargetBoundary(t *testing.T) {
	v := newTestValidator(t)
	ctx := context.Background()

	base := validRoleSite()

	rejected := []struct {
		name string
		url  string
	}{
		{"host outside allowlist", "https://10.0.0.9:8080"},
		{"hostname outside allowlist", "http://internal.local/x"},
		{"loopback ip", "http://127.0.0.1:8080"},
		{"loopback ip alt", "http://127.9.9.9/"},
		{"ipv6 loopback", "http://[::1]:9000/"},
		{"localhost name", "http://localhost:3000/"},
		{"localhost subdomain", "http://api.localhost/"},
		{"unix scheme", "unix//run/tagcess/ui.sock"},
		{"unix in host", "http://unix/run/tagcess/ui.sock"},
		{"no scheme", "//100.64.0.5/x"},
		// Caddy v2.8.4 accepts only scheme://host:port upstreams; a stored path, query or
		// fragment would fail /load after the record is already written (verified locally:
		// "parsing upstream ... only support scheme, host, and port components"). A trailing
		// slash is a path and is rejected too.
		{"upstream path", "http://100.64.0.5/ingress"},
		{"upstream trailing slash", "https://100.64.0.5:30443/"},
		{"upstream query", "https://100.64.0.5:30443?x=1"},
		{"upstream fragment", "https://100.64.0.5:30443#f"},
		// Caddy v2.8.4 rejects out-of-range upstream ports ("invalid start port") and :0 is
		// not dialable; only 1..65535 survive /load (verified locally).
		{"port zero", "http://100.64.0.5:0"},
		{"port above range", "https://100.64.0.5:65536"},
		{"port far above range", "http://100.64.0.5:99999"},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			s := base
			s.TargetKind = TargetURL
			s.TargetURL = tc.url
			if err := v.Validate(ctx, s); err == nil {
				t.Errorf("Validate accepted target %q", tc.url)
			}
		})
	}

	accepted := []struct {
		name string
		url  string
	}{
		{"allowlisted host with port", "https://100.64.0.5:30443"},
		{"allowlisted host plain", "http://100.64.0.5"},
	}
	for _, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			s := base
			s.TargetKind = TargetURL
			s.TargetURL = tc.url
			if err := v.Validate(ctx, s); err != nil {
				t.Errorf("Validate rejected target %q: %v", tc.url, err)
			}
		})
	}

	// Only the fixed system templates may leave the boundary (ADR 0010: loopback and socket
	// targets are constants in template code, which owns their shape — F2-005).
	system := Site{
		Hosts:          []string{"vpn.example.com"},
		Kind:           KindSystem,
		SystemTemplate: TemplateWireGuardUI,
		Cert:           "auto",
		APIRules:       []APIRule{},
		Redirects:      []Redirect{},
		Headers:        []Header{},
	}
	systemTargets := []string{
		"http://127.0.0.1:8080",
		"unix//run/wireguard-ui/ui.sock",
		"http://100.64.0.4:8080",
	}
	for _, tgt := range systemTargets {
		s := system
		s.TargetKind = TargetURL
		s.TargetURL = tgt
		if err := v.Validate(ctx, s); err != nil {
			t.Errorf("Validate rejected system template target %q: %v", tgt, err)
		}
	}
}

// TestSiteStore_RejectsInvalidCreate is AC1 at system level: the store itself refuses to
// store an invalid record, and nothing is left behind.
func TestSiteStore_RejectsInvalidCreate(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	bad := validRoleSite()
	bad.Hosts = []string{"git.evil.example"}
	if _, err := s.CreateSite(ctx, bad); err == nil {
		t.Fatal("CreateSite stored an invalid site")
	}
	sites, err := s.ListSites(ctx)
	if err != nil {
		t.Fatalf("ListSites: %v", err)
	}
	if len(sites) != 0 {
		t.Errorf("refused create left %d site(s) behind, want 0", len(sites))
	}
	if _, err := s.CreateSite(ctx, validRoleSite()); err != nil {
		t.Errorf("CreateSite refused a valid site: %v", err)
	}
}

// TestSiteStore_RejectsInvalidUpdate is AC1 at system level: a refused update leaves the
// stored record untouched.
func TestSiteStore_RejectsInvalidUpdate(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	stored, err := s.CreateSite(ctx, validRoleSite())
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}
	bad := stored
	bad.Roles = []string{"ghost"}
	if _, err := s.UpdateSite(ctx, stored.ID, bad); err == nil {
		t.Fatal("UpdateSite accepted an invalid site")
	}
	got, err := s.GetSite(ctx, stored.ID)
	if err != nil {
		t.Fatalf("GetSite: %v", err)
	}
	if !reflect.DeepEqual(got, stored) {
		t.Errorf("refused update changed the site:\n got %#v\nwant %#v", got, stored)
	}
}

// TestSiteStore_RoleReadFailureBlocksWrite is AC3 at system level: a failing role read stops
// the write, so the last known-good state is kept. A role-free site still writes during the
// outage; adding roles to it does not.
func TestSiteStore_RoleReadFailureBlocksWrite(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "tagcess.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	v, err := NewValidator(ValidatorConfig{
		AllowedDomains: []string{"example.com", "example.com"},
		AllowedTargets: []string{"100.64.0.5"},
	}, failingRoles{err: errors.New("zitadel: read failed")})
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	s, err := New(st.DB(), st.Queries(), v)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	roleFree := Site{
		Hosts: []string{"projects-auth.example.com"}, Kind: KindOpen,
		OpenReason: OpenReasonIntentional, Cert: "auto", TargetKind: TargetK8s,
		APIRules: []APIRule{}, Redirects: []Redirect{}, Headers: []Header{},
	}
	stored, err := s.CreateSite(ctx, roleFree)
	if err != nil {
		t.Fatalf("CreateSite of a role-free site during a read outage: %v", err)
	}

	withRoles := roleFree
	withRoles.OpenReason = OpenReasonTransition
	withRoles.TargetRoles = []string{"developer"}
	if _, err := s.UpdateSite(ctx, stored.ID, withRoles); err == nil {
		t.Fatal("UpdateSite added target roles while the role read failed")
	}
	got, err := s.GetSite(ctx, stored.ID)
	if err != nil {
		t.Fatalf("GetSite: %v", err)
	}
	if !reflect.DeepEqual(got, stored) {
		t.Errorf("refused update changed the site:\n got %#v\nwant %#v", got, stored)
	}
}

// mutableTargets is a TargetSource whose value can change between checks, like the settings-backed
// allowlist the interface edits (F2-013 AC5).
type mutableTargets struct {
	list []string
	err  error
}

func (m *mutableTargets) ListTargets(context.Context) ([]string, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.list, nil
}

// TestSiteValidation_TargetSource is AC5's validator side: the allowed target list is read on
// every check, so a UI change takes effect at once; a failed read or an empty list refuses the
// change (fail closed).
func TestSiteValidation_TargetSource(t *testing.T) {
	ctx := context.Background()
	src := &mutableTargets{list: []string{"100.64.0.5"}}
	v, err := NewValidator(ValidatorConfig{
		AllowedDomains: []string{"example.com"},
		TargetSource:   src,
	}, testRoles)
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	urlSite := func(host string) Site {
		s := validRoleSite()
		s.TargetKind = TargetURL
		s.TargetURL = "http://" + host + ":8080"
		return s
	}
	if err := v.Validate(ctx, urlSite("100.64.0.5")); err != nil {
		t.Fatalf("allowed host refused: %v", err)
	}
	// A UI change takes effect on the next check.
	src.list = []string{"10.0.0.9"}
	if err := v.Validate(ctx, urlSite("100.64.0.5")); err == nil {
		t.Error("a host removed from the allowlist was still accepted")
	}
	if err := v.Validate(ctx, urlSite("10.0.0.9")); err != nil {
		t.Errorf("a host added to the allowlist was refused: %v", err)
	}
	// An empty list and a failed read both refuse.
	src.list = nil
	if err := v.Validate(ctx, urlSite("10.0.0.9")); err == nil {
		t.Error("an empty target allowlist was accepted")
	}
	src.err = errors.New("settings unreadable")
	if err := v.Validate(ctx, urlSite("10.0.0.9")); err == nil {
		t.Error("a failed target allowlist read was accepted")
	}
}
