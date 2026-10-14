package site

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
)

// canonical system records (ADR 0010): one host, no roles, no extras. The target is a code
// constant of the template, so the record carries the k8s placeholder and no url.
func systemRecord(template string) Site {
	s := Site{
		Kind:           KindSystem,
		SystemTemplate: template,
		Roles:          []string{},
		TargetRoles:    []string{},
		Cert:           "auto",
		TargetKind:     TargetK8s,
		APIRules:       []APIRule{},
		Redirects:      []Redirect{},
		Headers:        []Header{},
	}
	switch template {
	case TemplateZitadel:
		s.Hosts = []string{"auth.example.com"}
		s.Cert = "le:example.com"
		s.SystemConfig = `{"internal_sources":["10.8.0.0/24"],"login_paths":["/ui/login"]}`
	case TemplateHeadscale:
		s.Hosts = []string{"hs.example.com"}
		s.SystemConfig = `{"headplane":true}`
	case TemplateWireGuardUI:
		s.Hosts = []string{"vpn.example.com"}
		s.SystemConfig = `{"enabled":true}`
	case TemplateTagcess:
		s.Hosts = []string{"tagcess.example.com"}
		s.SystemConfig = `{}`
		s.MagicDNS = true
	}
	return s
}

var systemTemplates = []string{TemplateZitadel, TemplateHeadscale, TemplateWireGuardUI, TemplateTagcess}

// seedSystemSites creates the four canonical system sites and returns them by template.
func seedSystemSites(t *testing.T, s *Store) map[string]Site {
	t.Helper()
	out := make(map[string]Site, len(systemTemplates))
	for _, tmpl := range systemTemplates {
		created, err := s.CreateSite(context.Background(), systemRecord(tmpl))
		if err != nil {
			t.Fatalf("CreateSite(%s): %v", tmpl, err)
		}
		out[tmpl] = created
	}
	return out
}

// assertUnchanged fails if the stored site differs from before in any way, including the
// update timestamp: a refused lock attempt must not touch the record.
func assertUnchanged(t *testing.T, s *Store, before Site) {
	t.Helper()
	after, err := s.GetSite(context.Background(), before.ID)
	if err != nil {
		t.Fatalf("GetSite(%d) after refused write: %v", before.ID, err)
	}
	if !reflect.DeepEqual(after, before) {
		t.Errorf("a refused write changed the record\nbefore: %+v\nafter:  %+v", before, after)
	}
}

// TestParseSystemConfig_Zitadel is the F2-013 shape of the zitadel template: the internal source
// list and the login path list are read from the record and held to the strict rules.
func TestParseSystemConfig_Zitadel(t *testing.T) {
	valid := map[string]string{
		"typical":       `{"internal_sources":["10.8.0.0/24","127.0.0.1/32","::1/128","192.0.2.10/32","2001:db8:10::/64"],"login_paths":["/.well-known/*","/oauth/v2/*","/oidc/v1/*","/ui/v2/login","/ui/v2/login/*","/ui/login","/ui/login/*","/assets/v1/*"]}`,
		"empty sources": `{"internal_sources":[],"login_paths":["/ui/login"]}`,
		"single path":   `{"internal_sources":["10.1.0.0/16"],"login_paths":["/a"]}`,
		"wildcard tail": `{"internal_sources":["2001:db8::/48"],"login_paths":["/a/b/*"]}`,
	}
	for name, raw := range valid {
		if _, err := ParseSystemConfig(TemplateZitadel, raw); err != nil {
			t.Errorf("%s: valid config refused: %v", name, err)
		}
	}

	invalid := map[string]string{
		"missing internal_sources": `{"login_paths":["/ui/login"]}`,
		"missing login_paths":      `{"internal_sources":[]}`,
		"unknown key":              `{"internal_sources":[],"login_paths":["/a"],"x":1}`,
		"wrong type":               `{"internal_sources":[],"login_paths":"/a"}`,
		"null":                     `null`,
		"empty":                    ``,
		"not an object":            `true`,
		"trailing data":            `{"internal_sources":[],"login_paths":["/a"]}{}`,
		"domain source":            `{"internal_sources":["example.com"],"login_paths":["/a"]}`,
		"source with host bits":    `{"internal_sources":["10.0.0.1/24"],"login_paths":["/a"]}`,
		"source too broad v4":      `{"internal_sources":["10.0.0.0/8"],"login_paths":["/a"]}`,
		"source too broad v6":      `{"internal_sources":["2001:db8::/32"],"login_paths":["/a"]}`,
		"source default route":     `{"internal_sources":["0.0.0.0/0"],"login_paths":["/a"]}`,
		"source v4-mapped cidr":    `{"internal_sources":["::ffff:10.0.0.0/120"],"login_paths":["/a"]}`,
		"source v4-mapped addr":    `{"internal_sources":["::ffff:10.0.0.0"],"login_paths":["/a"]}`,
		"source zone":              `{"internal_sources":["fe80::1%eth0"],"login_paths":["/a"]}`,
		"source uppercase":         `{"internal_sources":["2001:DB8::/64"],"login_paths":["/a"]}`,
		"source injection":         `{"internal_sources":["1.2.3.4; respond 200"],"login_paths":["/a"]}`,
		"source duplicate":         `{"internal_sources":["10.1.0.0/16","10.1.0.0/16"],"login_paths":["/a"]}`,
		"login empty list":         `{"internal_sources":[],"login_paths":[]}`,
		"login root":               `{"internal_sources":[],"login_paths":["/"]}`,
		"login star only":          `{"internal_sources":[],"login_paths":["/*"]}`,
		"login star no slash":      `{"internal_sources":[],"login_paths":["/a*"]}`,
		"login star suffix":        `{"internal_sources":[],"login_paths":["*.js"]}`,
		"login mid star":           `{"internal_sources":[],"login_paths":["/a/*/b"]}`,
		"login no slash":           `{"internal_sources":[],"login_paths":["ui/login"]}`,
		"login dotdot":             `{"internal_sources":[],"login_paths":["/a/../b"]}`,
		"login double slash":       `{"internal_sources":[],"login_paths":["/a//b"]}`,
		"login whitespace":         `{"internal_sources":[],"login_paths":["/a b"]}`,
		"login quote":              `{"internal_sources":[],"login_paths":["/a\""]}`,
		"login brace":              `{"internal_sources":[],"login_paths":["/a{"]}`,
		"login hash":               `{"internal_sources":[],"login_paths":["/a#b"]}`,
		"login duplicate":          `{"internal_sources":[],"login_paths":["/a","/a"]}`,
	}
	for name, raw := range invalid {
		if _, err := ParseSystemConfig(TemplateZitadel, raw); err == nil {
			t.Errorf("%s: invalid config accepted: %s", name, raw)
		}
	}

	// The list bounds are enforced: 33 sources / 33 paths are refused, 32 accepted.
	thirtyTwoSources := make([]string, 32)
	for i := range thirtyTwoSources {
		thirtyTwoSources[i] = fmt.Sprintf("10.%d.0.0/16", i)
	}
	tooManySources := append(append([]string{}, thirtyTwoSources...), "11.0.0.0/16")
	if _, err := ParseSystemConfig(TemplateZitadel, mustJSON(t, thirtyTwoSources, []string{"/a"})); err != nil {
		t.Errorf("32 sources refused: %v", err)
	}
	if _, err := ParseSystemConfig(TemplateZitadel, mustJSON(t, tooManySources, []string{"/a"})); err == nil {
		t.Error("33 sources accepted")
	}
	thirtyTwoPaths := make([]string, 32)
	for i := range thirtyTwoPaths {
		thirtyTwoPaths[i] = fmt.Sprintf("/p%d", i)
	}
	if _, err := ParseSystemConfig(TemplateZitadel, mustJSON(t, nil, thirtyTwoPaths)); err != nil {
		t.Errorf("32 paths refused: %v", err)
	}
	tooManyPaths := append(append([]string{}, thirtyTwoPaths...), "/p32")
	if _, err := ParseSystemConfig(TemplateZitadel, mustJSON(t, nil, tooManyPaths)); err == nil {
		t.Error("33 paths accepted")
	}
}

// mustJSON marshals the zitadel config shape for the boundary test.
func mustJSON(t *testing.T, sources, paths []string) string {
	t.Helper()
	if sources == nil {
		sources = []string{}
	}
	body, err := json.Marshal(struct {
		InternalSources []string `json:"internal_sources"`
		LoginPaths      []string `json:"login_paths"`
	}{sources, paths})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(body)
}

// TestSystemSite_Locks is AC1: a system site cannot be deleted, cannot change kind, template
// or roles, zitadel/tagcess cannot be closed, and no field the template does not open (host,
// cert, target, header, redirect, API rule, MagicDNS) can change through the service layer.
// Every refused write leaves the record untouched. Role/user sites cannot be promoted either.
func TestSystemSite_Locks(t *testing.T) {
	ctx := context.Background()

	t.Run("delete is refused", func(t *testing.T) {
		s := openTestStore(t)
		sites := seedSystemSites(t, s)
		for tmpl, site := range sites {
			err := s.DeleteSite(ctx, site.ID)
			if !errors.Is(err, ErrSystemLocked) {
				t.Errorf("DeleteSite(%s) = %v, want ErrSystemLocked", tmpl, err)
			}
			assertUnchanged(t, s, site)
		}
	})

	// lockedUpdates are updates whose record is itself valid; the lock layer must refuse them.
	lockedUpdates := []struct {
		name     string
		template string
		mutate   func(s *Site)
	}{
		{"kind to role", TemplateTagcess, func(s *Site) {
			s.Kind, s.SystemTemplate, s.SystemConfig = KindRole, "", ""
			s.Roles = []string{"standart"}
		}},
		{"kind to open", TemplateZitadel, func(s *Site) {
			s.Kind, s.SystemTemplate, s.SystemConfig = KindOpen, "", ""
			s.OpenReason = OpenReasonIntentional
		}},
		{"template swap", TemplateHeadscale, func(s *Site) {
			s.SystemTemplate, s.SystemConfig = TemplateWireGuardUI, `{"enabled":true}`
		}},
		{"host change", TemplateTagcess, func(s *Site) { s.Hosts = []string{"other.example.com"} }},
		{"host change zitadel", TemplateZitadel, func(s *Site) { s.Hosts = []string{"auth2.example.com"} }},
		{"cert change zitadel", TemplateZitadel, func(s *Site) { s.Cert = "auto" }},
		{"magicdns off tagcess", TemplateTagcess, func(s *Site) { s.MagicDNS = false }},
		{"magicdns on headscale", TemplateHeadscale, func(s *Site) { s.MagicDNS = true }},
		{"maintenance", TemplateZitadel, func(s *Site) { s.Maintenance = true }},
	}
	for _, tc := range lockedUpdates {
		t.Run("update refused: "+tc.name, func(t *testing.T) {
			s := openTestStore(t)
			sites := seedSystemSites(t, s)
			before := sites[tc.template]
			in := before
			tc.mutate(&in)
			_, err := s.UpdateSite(ctx, before.ID, in)
			if !errors.Is(err, ErrSystemLocked) {
				t.Fatalf("UpdateSite = %v, want ErrSystemLocked", err)
			}
			assertUnchanged(t, s, before)
		})
	}

	// shapeUpdates are not a canonical system record at all: refused before the lock compare.
	shapeUpdates := []struct {
		name     string
		template string
		mutate   func(s *Site)
	}{
		{"cert on a template without tls", TemplateTagcess, func(s *Site) { s.Cert = "le:example.com" }},
		{"tls insecure", TemplateHeadscale, func(s *Site) { s.TargetTLSInsecure = true }},
		{"roles on system site", TemplateTagcess, func(s *Site) { s.Roles = []string{"standart"} }},
		{"close zitadel", TemplateZitadel, func(s *Site) { s.SystemConfig = `{"enabled":false}` }},
		{"close tagcess", TemplateTagcess, func(s *Site) { s.SystemConfig = `{"enabled":false}` }},
		{"zitadel config null", TemplateZitadel, func(s *Site) { s.SystemConfig = `null` }},
		{"zitadel config empty", TemplateZitadel, func(s *Site) { s.SystemConfig = `` }},
		{"url target", TemplateWireGuardUI, func(s *Site) {
			s.TargetKind, s.TargetURL = TargetURL, "http://100.64.0.5:8080"
		}},
		{"loopback target", TemplateHeadscale, func(s *Site) {
			s.TargetKind, s.TargetURL = TargetURL, "http://127.0.0.1:2019"
		}},
		{"header", TemplateTagcess, func(s *Site) { s.Headers = []Header{{Name: "X-Note", Value: "v"}} }},
		{"redirect", TemplateTagcess, func(s *Site) {
			s.Redirects = []Redirect{{Source: "/a", Target: "/b", Code: 301}}
		}},
		{"api rule", TemplateZitadel, func(s *Site) {
			s.APIRules = []APIRule{{Type: APIRuleHeaderPresent, Value: "Authorization"}}
		}},
		{"extra host", TemplateHeadscale, func(s *Site) {
			s.Hosts = []string{"hs.example.com", "hs2.example.com"}
		}},
		{"headscale unknown key", TemplateHeadscale, func(s *Site) { s.SystemConfig = `{"headplane":true,"extra":1}` }},
		{"headscale wrong type", TemplateHeadscale, func(s *Site) { s.SystemConfig = `{"headplane":"yes"}` }},
		{"headscale missing key", TemplateHeadscale, func(s *Site) { s.SystemConfig = `{}` }},
		{"headscale other template key", TemplateHeadscale, func(s *Site) { s.SystemConfig = `{"enabled":true}` }},
		{"wireguard missing key", TemplateWireGuardUI, func(s *Site) { s.SystemConfig = `{}` }},
		{"wireguard trailing data", TemplateWireGuardUI, func(s *Site) { s.SystemConfig = `{"enabled":true}{}` }},
		{"wireguard not an object", TemplateWireGuardUI, func(s *Site) { s.SystemConfig = `true` }},
	}
	for _, tc := range shapeUpdates {
		t.Run("update refused: "+tc.name, func(t *testing.T) {
			s := openTestStore(t)
			sites := seedSystemSites(t, s)
			before := sites[tc.template]
			in := before
			tc.mutate(&in)
			if _, err := s.UpdateSite(ctx, before.ID, in); err == nil {
				t.Fatalf("UpdateSite accepted %+v", in)
			}
			assertUnchanged(t, s, before)
		})
	}

	t.Run("user site cannot become a system site", func(t *testing.T) {
		s := openTestStore(t)
		seedSystemSites(t, s)
		user, err := s.CreateSite(ctx, validRoleSite())
		if err != nil {
			t.Fatalf("CreateSite: %v", err)
		}
		in := systemRecord(TemplateTagcess)
		in.Hosts = user.Hosts
		_, err = s.UpdateSite(ctx, user.ID, in)
		if !errors.Is(err, ErrSystemLocked) {
			t.Fatalf("UpdateSite = %v, want ErrSystemLocked", err)
		}
		assertUnchanged(t, s, user)
	})

	t.Run("create refuses a second site of a template", func(t *testing.T) {
		s := openTestStore(t)
		seedSystemSites(t, s)
		dup := systemRecord(TemplateTagcess)
		dup.Hosts = []string{"tagcess2.example.com"}
		if _, err := s.CreateSite(ctx, dup); !errors.Is(err, ErrSystemLocked) {
			t.Fatalf("CreateSite(second tagcess) = %v, want ErrSystemLocked", err)
		}
		sites, err := s.ListSites(ctx)
		if err != nil {
			t.Fatalf("ListSites: %v", err)
		}
		if len(sites) != len(systemTemplates) {
			t.Errorf("ListSites = %d sites, want %d", len(sites), len(systemTemplates))
		}
	})

	t.Run("create refuses a non-canonical system record", func(t *testing.T) {
		s := openTestStore(t)
		bad := systemRecord(TemplateTagcess)
		bad.Headers = []Header{{Name: "X-Note", Value: "v"}}
		if _, err := s.CreateSite(ctx, bad); err == nil {
			t.Fatal("CreateSite accepted a system record with a header")
		}
		bad = systemRecord(TemplateTagcess)
		bad.SystemConfig = `{"enabled":false}`
		if _, err := s.CreateSite(ctx, bad); err == nil {
			t.Fatal("CreateSite accepted a closed tagcess record")
		}
	})

	t.Run("a missing site stays not found", func(t *testing.T) {
		s := openTestStore(t)
		if err := s.DeleteSite(ctx, 999); !errors.Is(err, ErrNotFound) {
			t.Errorf("DeleteSite(999) = %v, want ErrNotFound", err)
		}
		if _, err := s.UpdateSite(ctx, 999, validRoleSite()); !errors.Is(err, ErrNotFound) {
			t.Errorf("UpdateSite(999) = %v, want ErrNotFound", err)
		}
	})

	t.Run("user sites keep deleting and updating", func(t *testing.T) {
		s := openTestStore(t)
		seedSystemSites(t, s)
		user, err := s.CreateSite(ctx, validRoleSite())
		if err != nil {
			t.Fatalf("CreateSite: %v", err)
		}
		in := user
		in.Note = "changed"
		if _, err := s.UpdateSite(ctx, user.ID, in); err != nil {
			t.Errorf("UpdateSite of a user site: %v", err)
		}
		if err := s.DeleteSite(ctx, user.ID); err != nil {
			t.Errorf("DeleteSite of a user site: %v", err)
		}
	})
}

// TestSystemSite_LocksAllowedChanges is the other side of AC1/AC3: the switches a template
// opens and the note/owner metadata do change through the store, and nothing else moves.
func TestSystemSite_LocksAllowedChanges(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name     string
		template string
		mutate   func(s *Site)
	}{
		{"wireguard off", TemplateWireGuardUI, func(s *Site) { s.SystemConfig = `{"enabled":false}` }},
		{"headplane off", TemplateHeadscale, func(s *Site) { s.SystemConfig = `{"headplane":false}` }},
		{"note and owner", TemplateZitadel, func(s *Site) { s.Note, s.Owner = "gate", "devops@example.com" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := openTestStore(t)
			sites := seedSystemSites(t, s)
			before := sites[tc.template]
			in := before
			tc.mutate(&in)
			got, err := s.UpdateSite(ctx, before.ID, in)
			if err != nil {
				t.Fatalf("UpdateSite: %v", err)
			}
			want := in
			want.UpdatedAt = got.UpdatedAt
			if !reflect.DeepEqual(got, want) {
				t.Errorf("stored form differs\ngot:  %+v\nwant: %+v", got, want)
			}
		})
	}
}
