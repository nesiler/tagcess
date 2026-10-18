package render

import (
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/internal/site"
)

var updateGoldens = flag.Bool("update", false, "rewrite the golden files instead of comparing")

// caddyCfg returns a render config with today's ACME email and the four certbot
// certificate names of the current setup.
func caddyCfg(s06open bool) CaddyConfig {
	return CaddyConfig{
		ACMEEmail: "admin@example.com",
		S06Open:   s06open,
		Certs: []string{
			"example.com",
			"example.net",
			"example.org",
			"internal.example.org",
		},
	}
}

// goldSiteSet returns the golden fixture sites: every user-site shape the
// renderer supports (role with and without api rules, redirects, multi-host,
// open k8s and open url with headers). The order here is NOT the render order.
func goldSiteSet() []site.Site {
	return []site.Site{
		{
			Hosts:      []string{"monitor.example.com"},
			Kind:       site.KindRole,
			Roles:      []string{"devops", "developer"},
			Cert:       "le:example.com",
			TargetKind: site.TargetK8s,
			APIRules:   []site.APIRule{}, Redirects: []site.Redirect{}, Headers: []site.Header{},
		},
		{
			Hosts:      []string{"docs.example.com"},
			Kind:       site.KindRole,
			Roles:      []string{"devops", "developer", "standart"},
			Cert:       "le:example.com",
			TargetKind: site.TargetK8s,
			APIRules:   []site.APIRule{{Type: site.APIRuleHeaderPresent, Value: "Authorization"}},
			Redirects:  []site.Redirect{}, Headers: []site.Header{},
		},
		{
			Hosts:      []string{"errors.example.com"},
			Kind:       site.KindRole,
			Roles:      []string{"devops", "developer"},
			Cert:       "le:example.com",
			TargetKind: site.TargetK8s,
			APIRules: []site.APIRule{
				{Type: site.APIRuleHeaderPresent, Value: "Authorization"},
				{Type: site.APIRulePathRegex, Value: `^/api/[0-9]+/(envelope|store|security)/`},
			},
			Redirects: []site.Redirect{}, Headers: []site.Header{},
		},
		{
			Hosts:      []string{"projects.example.com"},
			Kind:       site.KindRole,
			Roles:      []string{"devops", "developer", "standart"},
			Cert:       "le:example.com",
			TargetKind: site.TargetK8s,
			APIRules: []site.APIRule{
				{Type: site.APIRuleHeaderPresent, Value: "Authorization"},
				{Type: site.APIRuleHeaderPresent, Value: "X-Api-Key"},
			},
			Redirects: []site.Redirect{{
				Source: "/setup",
				Target: "https://projects.example.com/setup/",
				Code:   308,
			}},
			Headers: []site.Header{},
		},
		{
			Hosts:      []string{"projects-auth.example.com", "storage-api.example.com"},
			Kind:       site.KindOpen,
			OpenReason: site.OpenReasonTransition,
			Cert:       "le:example.com",
			TargetKind: site.TargetK8s,
			APIRules:   []site.APIRule{}, Redirects: []site.Redirect{}, Headers: []site.Header{},
		},
		{
			Hosts:             []string{"gitlab.internal.example.org"},
			Kind:              site.KindOpen,
			OpenReason:        site.OpenReasonTransition,
			Cert:              "le:internal.example.org",
			TargetKind:        site.TargetURL,
			TargetURL:         "https://100.64.0.5:30443",
			TargetTLSInsecure: true,
			Headers:           []site.Header{{Name: "X-Gitlab-Token", Value: "secret token"}},
			APIRules:          []site.APIRule{}, Redirects: []site.Redirect{},
		},
		{
			Hosts:      []string{"status.internal.example.org"},
			Kind:       site.KindOpen,
			OpenReason: site.OpenReasonIntentional,
			Cert:       "le:internal.example.org",
			TargetKind: site.TargetURL,
			TargetURL:  "http://100.64.0.4:8080",
			Headers:    []site.Header{},
			APIRules:   []site.APIRule{}, Redirects: []site.Redirect{},
		},
	}
}

func renderSites(t *testing.T, s06open bool, sites []site.Site) string {
	t.Helper()
	out, err := RenderCaddyfile(sites, caddyCfg(s06open))
	if err != nil {
		t.Fatalf("RenderCaddyfile: %v", err)
	}
	return out
}

// TestCaddyRender_Golden is AC1: the same site set in a different insertion
// order renders the same text, and that text is pinned by golden files for
// both S-06 key states.
func TestCaddyRender_Golden(t *testing.T) {
	set := goldSiteSet()
	shuffled := slices.Clone(set)
	// A permutation that differs from both the input order and the sorted
	// render order.
	slices.Reverse(shuffled)

	for _, tc := range []struct {
		name    string
		s06open bool
		golden  string
	}{
		{"s06_open", true, "caddy-users-open.golden"},
		{"s06_closed", false, "caddy-users-closed.golden"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := renderSites(t, tc.s06open, set)
			b := renderSites(t, tc.s06open, shuffled)
			if a != b {
				t.Fatalf("rendered output depends on insertion order:\n--- order A ---\n%s\n--- order B ---\n%s", a, b)
			}
			if *updateGoldens {
				if err := os.WriteFile(filepath.Join("testdata", tc.golden), []byte(a), 0o644); err != nil {
					t.Fatalf("write golden: %v", err)
				}
				return
			}
			want, err := os.ReadFile(filepath.Join("testdata", tc.golden))
			if err != nil {
				t.Fatalf("read golden: %v", err)
			}
			if a != string(want) {
				t.Errorf("rendered Caddyfile does not match %s\n--- got ---\n%s\n--- want ---\n%s", tc.golden, a, want)
			}
		})
	}
}

// TestCaddyRender_SnippetsMatchReference pins the fixed snippet section
// against the reference text from the current Caddyfile (ADR 0010: snippets
// keep today's text).
func TestCaddyRender_SnippetsMatchReference(t *testing.T) {
	out := renderSites(t, true, nil)

	marker := "# Generated by tagcess. Do not edit; every apply rewrites this file from the site records.\n"
	global := "{\n\temail admin@example.com\n}\n"
	if !strings.HasPrefix(out, marker+global+"\n") {
		t.Fatalf("unexpected file header:\n%s", out)
	}
	want, err := os.ReadFile(filepath.Join("testdata", "caddy-reference-snippets.caddy"))
	if err != nil {
		t.Fatalf("read reference snippets: %v", err)
	}
	if got := out[len(marker+global+"\n"):]; got != string(want) {
		t.Errorf("snippet section does not match the reference\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// siteBlock returns the rendered block of the site with the given first host.
func siteBlock(t *testing.T, file, host string) string {
	t.Helper()
	start := strings.Index(file, host+" {")
	if start < 0 {
		if startAlt := strings.Index(file, host+",\n"); startAlt >= 0 {
			start = startAlt
		} else {
			t.Fatalf("no block for host %s in:\n%s", host, file)
		}
	}
	end := strings.Index(file[start:], "\n}\n")
	if end < 0 {
		t.Fatalf("block for host %s is not terminated in:\n%s", host, file)
	}
	return file[start : start+end+len("\n}\n")]
}

// TestCaddyRender_AccessMatrix is AC2: role/API/open shapes combined with the
// S-06 key states keep the ADR 0010 source and exemption order.
func TestCaddyRender_AccessMatrix(t *testing.T) {
	tailOpen := "\thandle {\n\t\timport k8s\n\t}\n}"
	tailClosed := "\thandle {\n\t\trespond 403\n\t}\n}"
	apiBranch := "\thandle @api {\n\t\timport k8s\n\t}"

	t.Run("role open key keeps today's tail branch", func(t *testing.T) {
		out := renderSites(t, true, []site.Site{roleSite()})
		if !strings.Contains(out, tailOpen) {
			t.Errorf("vpn_site snippet tail is not import k8s:\n%s", out)
		}
		if block := siteBlock(t, out, "monitor.example.com"); block !=
			"monitor.example.com {\n\timport vpn_site example.com devops,developer\n}\n" {
			t.Errorf("unexpected role block:\n%s", block)
		}
	})

	t.Run("role closed key turns the tail branch into 403", func(t *testing.T) {
		out := renderSites(t, false, []site.Site{roleSite()})
		if !strings.Contains(out, tailClosed) {
			t.Errorf("vpn_site snippet tail is not respond 403:\n%s", out)
		}
		if strings.Contains(out, tailOpen) {
			t.Errorf("closed key still renders the open tail branch:\n%s", out)
		}
		if block := siteBlock(t, out, "monitor.example.com"); block !=
			"monitor.example.com {\n\timport vpn_site example.com devops,developer\n}\n" {
			t.Errorf("role block must not depend on the key state:\n%s", block)
		}
	})

	t.Run("single header rule uses the native matcher", func(t *testing.T) {
		s := roleSite()
		s.Hosts = []string{"k8s-api.example.com"}
		s.APIRules = []site.APIRule{{Type: site.APIRuleHeaderPresent, Value: "Authorization"}}
		out := renderSites(t, true, []site.Site{s})
		block := siteBlock(t, out, "k8s-api.example.com")
		want := "k8s-api.example.com {\n" +
			"\t@api header Authorization *\n" +
			"\timport vpn_site_api example.com devops,developer\n}\n"
		if block != want {
			t.Errorf("unexpected api block:\n--- got ---\n%s\n--- want ---\n%s", block, want)
		}
	})

	t.Run("expression form keeps the stored rule order from every source", func(t *testing.T) {
		s := roleSite()
		s.Hosts = []string{"errors.example.com"}
		s.APIRules = []site.APIRule{
			{Type: site.APIRuleHeaderPresent, Value: "Authorization"},
			{Type: site.APIRulePathRegex, Value: `^/api/[0-9]+/(envelope|store|security)/`},
		}
		out := renderSites(t, false, []site.Site{s})
		block := siteBlock(t, out, "errors.example.com")
		want := "errors.example.com {\n" +
			"\t@api expression `header({'Authorization': '*'}) || path_regexp('^/api/[0-9]+/(envelope|store|security)/')`\n" +
			"\timport vpn_site_api example.com devops,developer\n}\n"
		if block != want {
			t.Errorf("unexpected api block:\n--- got ---\n%s\n--- want ---\n%s", block, want)
		}
		// The exemption branch stays on every source even with the key closed.
		if !strings.Contains(out, apiBranch) {
			t.Errorf("closed key removed the @api branch:\n%s", out)
		}
	})

	t.Run("single path regex rule uses the expression form", func(t *testing.T) {
		s := roleSite()
		s.Hosts = []string{"partner-api.example.com"}
		s.APIRules = []site.APIRule{{Type: site.APIRulePathRegex, Value: `^/api/[0-9]+/events/`}}
		out := renderSites(t, true, []site.Site{s})
		block := siteBlock(t, out, "partner-api.example.com")
		want := "partner-api.example.com {\n" +
			"\t@api expression `path_regexp('^/api/[0-9]+/events/')`\n" +
			"\timport vpn_site_api example.com devops,developer\n}\n"
		if block != want {
			t.Errorf("unexpected expression block:\n--- got ---\n%s\n--- want ---\n%s", block, want)
		}
	})

	t.Run("redirects come before the matcher and the import", func(t *testing.T) {
		s := roleSite()
		s.Hosts = []string{"projects.example.com"}
		s.Redirects = []site.Redirect{{
			Source: "/setup",
			Target: "https://projects.example.com/setup/",
			Code:   308,
		}}
		s.APIRules = []site.APIRule{{Type: site.APIRuleHeaderPresent, Value: "X-Api-Key"}}
		out := renderSites(t, true, []site.Site{s})
		block := siteBlock(t, out, "projects.example.com")
		redir := strings.Index(block, "\tredir /setup https://projects.example.com/setup/ 308\n")
		api := strings.Index(block, "\t@api header X-Api-Key *\n")
		imp := strings.Index(block, "\timport vpn_site_api ")
		if redir < 0 || api < 0 || imp < 0 || redir > api || api > imp {
			t.Errorf("redirect/api/import order is wrong:\n%s", block)
		}
	})

	t.Run("multi-host blocks list hosts comma separated", func(t *testing.T) {
		out := renderSites(t, true, []site.Site{openK8sSite()})
		if block := siteBlock(t, out, "projects-auth.example.com"); block !=
			"projects-auth.example.com,\n"+
				"storage-api.example.com {\n"+
				"\ttls /etc/letsencrypt/live/example.com/fullchain.pem /etc/letsencrypt/live/example.com/privkey.pem\n"+
				"\n"+
				"\timport k8s\n}\n" {
			t.Errorf("unexpected open k8s block:\n%s", block)
		}
	})

	t.Run("open k8s site adds the tailnet branch when the key is closed", func(t *testing.T) {
		out := renderSites(t, false, []site.Site{openK8sSite()})
		if block := siteBlock(t, out, "projects-auth.example.com"); block !=
			"projects-auth.example.com,\n"+
				"storage-api.example.com {\n"+
				"\ttls /etc/letsencrypt/live/example.com/fullchain.pem /etc/letsencrypt/live/example.com/privkey.pem\n"+
				"\n"+
				"\t@tailnet remote_ip 100.64.0.0/10\n"+
				"\thandle @tailnet {\n"+
				"\t\timport k8s\n"+
				"\t}\n"+
				"\thandle {\n"+
				"\t\trespond 403\n"+
				"\t}\n}\n" {
			t.Errorf("unexpected closed open block:\n%s", block)
		}
	})

	t.Run("open url site proxies the url directly", func(t *testing.T) {
		out := renderSites(t, true, []site.Site{openURLSite()})
		if block := siteBlock(t, out, "gitlab.internal.example.org"); block !=
			"gitlab.internal.example.org {\n"+
				"\ttls /etc/letsencrypt/live/internal.example.org/fullchain.pem /etc/letsencrypt/live/internal.example.org/privkey.pem\n"+
				"\n"+
				"\treverse_proxy https://100.64.0.5:30443 {\n"+
				"\t\theader_up X-Gitlab-Token \"secret token\"\n"+
				"\t\ttransport http {\n"+
				"\t\t\ttls_insecure_skip_verify\n"+
				"\t\t}\n"+
				"\t}\n}\n" {
			t.Errorf("unexpected open url block:\n%s", block)
		}
	})

	t.Run("open url site without insecure flag and headers is a single line", func(t *testing.T) {
		s := openURLSite()
		s.TargetURL = "http://100.64.0.4:8080"
		s.TargetTLSInsecure = false
		s.Headers = nil
		out := renderSites(t, true, []site.Site{s})
		if block := siteBlock(t, out, "gitlab.internal.example.org"); block !=
			"gitlab.internal.example.org {\n"+
				"\ttls /etc/letsencrypt/live/internal.example.org/fullchain.pem /etc/letsencrypt/live/internal.example.org/privkey.pem\n"+
				"\n"+
				"\treverse_proxy http://100.64.0.4:8080\n}\n" {
			t.Errorf("unexpected plain url block:\n%s", block)
		}
	})

	t.Run("closed open url site keeps the url target behind the tailnet branch", func(t *testing.T) {
		out := renderSites(t, false, []site.Site{openURLSite()})
		if block := siteBlock(t, out, "gitlab.internal.example.org"); block !=
			"gitlab.internal.example.org {\n"+
				"\ttls /etc/letsencrypt/live/internal.example.org/fullchain.pem /etc/letsencrypt/live/internal.example.org/privkey.pem\n"+
				"\n"+
				"\t@tailnet remote_ip 100.64.0.0/10\n"+
				"\thandle @tailnet {\n"+
				"\t\treverse_proxy https://100.64.0.5:30443 {\n"+
				"\t\t\theader_up X-Gitlab-Token \"secret token\"\n"+
				"\t\t\ttransport http {\n"+
				"\t\t\t\ttls_insecure_skip_verify\n"+
				"\t\t\t}\n"+
				"\t\t}\n"+
				"\t}\n"+
				"\thandle {\n"+
				"\t\trespond 403\n"+
				"\t}\n}\n" {
			t.Errorf("unexpected closed open url block:\n%s", block)
		}
	})

	t.Run("role closed key puts redirects behind the tailnet source", func(t *testing.T) {
		s := roleSite()
		s.Hosts = []string{"projects.example.com"}
		s.APIRules = []site.APIRule{{Type: site.APIRuleHeaderPresent, Value: "X-Api-Key"}}
		s.Redirects = []site.Redirect{{
			Source: "/setup",
			Target: "https://projects.example.com/setup/",
			Code:   308,
		}}
		out := renderSites(t, false, []site.Site{s})
		block := siteBlock(t, out, "projects.example.com")
		// With the key closed a bare redir would run before the 403 catch-all,
		// so it answers a non-tailnet source with a 308. The redirect must be
		// restricted to the tailnet source (remote_ip + path) and stay before
		// the @api exemption and the import.
		want := "projects.example.com {\n" +
			"\t@redir0 {\n" +
			"\t\tremote_ip 100.64.0.0/10\n" +
			"\t\tpath /setup\n" +
			"\t}\n" +
			"\tredir @redir0 https://projects.example.com/setup/ 308\n" +
			"\t@api header X-Api-Key *\n" +
			"\timport vpn_site_api example.com devops,developer\n}\n"
		if block != want {
			t.Errorf("unexpected closed redirect block:\n--- got ---\n%s\n--- want ---\n%s", block, want)
		}
	})

	t.Run("open closed key puts redirects behind the tailnet branch", func(t *testing.T) {
		s := openURLSite()
		s.TargetURL = "http://100.64.0.4:8080"
		s.TargetTLSInsecure = false
		s.Headers = nil
		s.Redirects = []site.Redirect{{Source: "/old", Target: "/new", Code: 301}}
		out := renderSites(t, false, []site.Site{s})
		block := siteBlock(t, out, "gitlab.internal.example.org")
		want := "gitlab.internal.example.org {\n" +
			"\ttls /etc/letsencrypt/live/internal.example.org/fullchain.pem /etc/letsencrypt/live/internal.example.org/privkey.pem\n" +
			"\n" +
			"\t@tailnet remote_ip 100.64.0.0/10\n" +
			"\thandle @tailnet {\n" +
			"\t\tredir /old /new 301\n" +
			"\t\treverse_proxy http://100.64.0.4:8080\n" +
			"\t}\n" +
			"\thandle {\n" +
			"\t\trespond 403\n" +
			"\t}\n}\n"
		if block != want {
			t.Errorf("unexpected closed open redirect block:\n--- got ---\n%s\n--- want ---\n%s", block, want)
		}
	})

	t.Run("open blocks sorted with role blocks by first host", func(t *testing.T) {
		out := renderSites(t, true, []site.Site{openK8sSite(), roleSite()})
		mon := strings.Index(out, "monitor.example.com {")
		pauth := strings.Index(out, "projects-auth.example.com,")
		if mon < 0 || pauth < 0 || mon >= pauth {
			t.Errorf("blocks are not sorted by first host:\n%s", out)
		}
	})
}

func roleSite() site.Site {
	return site.Site{
		Hosts:      []string{"monitor.example.com"},
		Kind:       site.KindRole,
		Roles:      []string{"devops", "developer"},
		Cert:       "le:example.com",
		TargetKind: site.TargetK8s,
		APIRules:   []site.APIRule{}, Redirects: []site.Redirect{}, Headers: []site.Header{},
	}
}

func openK8sSite() site.Site {
	return site.Site{
		Hosts:      []string{"projects-auth.example.com", "storage-api.example.com"},
		Kind:       site.KindOpen,
		OpenReason: site.OpenReasonTransition,
		Cert:       "le:example.com",
		TargetKind: site.TargetK8s,
		APIRules:   []site.APIRule{}, Redirects: []site.Redirect{}, Headers: []site.Header{},
	}
}

func openURLSite() site.Site {
	return site.Site{
		Hosts:             []string{"gitlab.internal.example.org"},
		Kind:              site.KindOpen,
		OpenReason:        site.OpenReasonTransition,
		Cert:              "le:internal.example.org",
		TargetKind:        site.TargetURL,
		TargetURL:         "https://100.64.0.5:30443",
		TargetTLSInsecure: true,
		Headers:           []site.Header{{Name: "X-Gitlab-Token", Value: "secret token"}},
		APIRules:          []site.APIRule{}, Redirects: []site.Redirect{},
	}
}

// TestCaddyRender_RegexEscape is AC3: a backslash in a path regex is written
// twice into the CEL string (R1 B-02: a single backslash is a CEL error).
func TestCaddyRender_RegexEscape(t *testing.T) {
	s := roleSite()
	s.Hosts = []string{"errors.example.com"}
	s.APIRules = []site.APIRule{{Type: site.APIRulePathRegex, Value: `^/api/\d+/`}}
	out := renderSites(t, true, []site.Site{s})

	want := "\t@api expression `path_regexp('^/api/\\\\d+/')`\n"
	if !strings.Contains(out, want) {
		t.Errorf("backslash not doubled for CEL; want %q in:\n%s", want, out)
	}
	if strings.Contains(out, `path_regexp('^/api/\d+/')`) {
		t.Errorf("single backslash reached the CEL string:\n%s", out)
	}
}

// TestCaddyRender_HeaderEscape covers the task note: header fields may enter
// the template only through the escape function; hostile input is refused,
// never written raw (security.md §5).
func TestCaddyRender_HeaderEscape(t *testing.T) {
	bad := []string{
		`say "hi"`,
		"a{b}c",
		"{http.request.host}",
		"a}b",
		"line1\nline2",
		"a\tb",
		"a\x00b",
		"a\x7fb",
		"caf\xc3\xa9",
		// A trailing backslash lands in front of the closing quote, where the
		// caddy v2.8.4 lexer reads \" as an escaped quote and the token never
		// closes (whole file unparseable).
		`token2024\`,
		`a\\`,
	}
	for _, v := range bad {
		s := openURLSite()
		s.Headers = []site.Header{{Name: "X-Note", Value: v}}
		out, err := RenderCaddyfile([]site.Site{s}, caddyCfg(true))
		if err == nil {
			t.Errorf("header value %q was accepted; output:\n%s", v, out)
		} else if strings.Contains(out, v) {
			t.Errorf("header value %q leaked into the output", v)
		}
	}

	badNames := []string{"X Y", "-X-Note", "+X-Note", "#X-Note", "@X-Note", "X{N}", "X`N", `"X"`, strings.Repeat("X", 129)}
	for _, n := range badNames {
		s := openURLSite()
		s.Headers = []site.Header{{Name: n, Value: "v"}}
		if _, err := RenderCaddyfile([]site.Site{s}, caddyCfg(true)); err == nil {
			t.Errorf("header name %q was accepted", n)
		}
	}

	// The token rule mirrors the store rule (RFC 7230 tchar with a safe first
	// character); mid-token "#" is literal in a Caddyfile token (verified with
	// caddy v2.8.4 adapt).
	goodNames := []string{"X-Note", "X_Y", "X.Y", "X#Y", "X'Y", strings.Repeat("X", 128)}
	for _, n := range goodNames {
		s := openURLSite()
		s.Headers = []site.Header{{Name: n, Value: "v"}}
		if _, err := RenderCaddyfile([]site.Site{s}, caddyCfg(true)); err != nil {
			t.Errorf("header name %q was rejected: %v", n, err)
		}
	}

	s := openURLSite()
	s.Headers = []site.Header{
		{Name: "X-Path", Value: `/app/\d+`},
		{Name: "X-Plain", Value: "DENY"},
	}
	out, err := RenderCaddyfile([]site.Site{s}, caddyCfg(true))
	if err != nil {
		t.Fatalf("valid header values rejected: %v", err)
	}
	// Backslash passes through verbatim inside Caddyfile double quotes
	// (verified against caddy v2.8.4 adapt); the quote would end the token,
	// so it is refused above.
	if !strings.Contains(out, "\t\theader_up X-Path \"/app/\\d+\"\n") {
		t.Errorf("backslash value not rendered verbatim:\n%s", out)
	}
	if !strings.Contains(out, "\t\theader_up X-Plain \"DENY\"\n") {
		t.Errorf("plain value not quoted:\n%s", out)
	}
}

// TestCaddyRender_RejectsUnsafe collects the structural re-checks the
// renderer applies on top of the store validation: a record that cannot be
// rendered safely is refused, never widened (fail safe).
func TestCaddyRender_RejectsUnsafe(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(s *site.Site)
		cfg    *CaddyConfig
	}{
		{"system site", func(s *site.Site) {
			s.Kind = site.KindSystem
			s.SystemTemplate = site.TemplateZitadel
			s.Hosts = []string{"auth.example.com"}
		}, nil},
		{"role site with url target", func(s *site.Site) {
			s.TargetKind = site.TargetURL
			s.TargetURL = "https://100.64.0.5:30443"
		}, nil},
		{"k8s target with headers", func(s *site.Site) {
			s.Headers = []site.Header{{Name: "X-Note", Value: "v"}}
		}, nil},
		{"empty hosts", func(s *site.Site) { s.Hosts = nil }, nil},
		{"host uppercase", func(s *site.Site) {
			s.Hosts = []string{"Mon.example.com"}
		}, nil},
		{"host wildcard", func(s *site.Site) {
			s.Hosts = []string{"*.example.com"}
		}, nil},
		{"host with space", func(s *site.Site) {
			s.Hosts = []string{"mo n.example.com"}
		}, nil},
		{"bad role format", func(s *site.Site) { s.Roles = []string{"DevOps!"} }, nil},
		{"bad cert value", func(s *site.Site) { s.Cert = "bogus" }, nil},
		{"cert path traversal", func(s *site.Site) { s.Cert = "le:../secrets" }, nil},
		{"bad redirect source", func(s *site.Site) {
			s.Kind = site.KindOpen
			s.OpenReason = site.OpenReasonIntentional
			s.Redirects = []site.Redirect{{Source: "old", Target: "/new", Code: 301}}
		}, nil},
		{"redirect absolute target with bad path", func(s *site.Site) {
			s.Kind = site.KindOpen
			s.OpenReason = site.OpenReasonIntentional
			s.Redirects = []site.Redirect{{Source: "/old", Target: `https://monitor.example.com/ne"w`, Code: 301}}
		}, nil},
		{"redirect absolute target with plus port", func(s *site.Site) {
			s.Kind = site.KindOpen
			s.OpenReason = site.OpenReasonIntentional
			s.Redirects = []site.Redirect{{Source: "/old", Target: "https://monitor.example.com:+80/x", Code: 301}}
		}, nil},
		{"redirect protocol-relative target", func(s *site.Site) {
			s.Kind = site.KindOpen
			s.OpenReason = site.OpenReasonIntentional
			s.Redirects = []site.Redirect{{Source: "/old", Target: "//evil.example.com", Code: 301}}
		}, nil},
		{"redirect bad code", func(s *site.Site) {
			s.Redirects = []site.Redirect{{Source: "/old", Target: "/new", Code: 304}}
		}, nil},
		{"open site with roles", func(s *site.Site) {
			s.Kind = site.KindOpen
			s.OpenReason = site.OpenReasonIntentional
		}, nil},
		{"role site without roles", func(s *site.Site) {
			s.Roles = nil
		}, nil},
		{"api rule on open site", func(s *site.Site) {
			s.Kind = site.KindOpen
			s.OpenReason = site.OpenReasonIntentional
			s.Roles = nil
			s.APIRules = []site.APIRule{{Type: site.APIRuleHeaderPresent, Value: "Authorization"}}
		}, nil},
		{"url target with path", func(s *site.Site) {
			s.Kind = site.KindOpen
			s.OpenReason = site.OpenReasonIntentional
			s.TargetKind = site.TargetURL
			s.TargetURL = "https://100.64.0.5:30443/ingress"
		}, nil},
		{"url target with quote", func(s *site.Site) {
			s.Kind = site.KindOpen
			s.OpenReason = site.OpenReasonIntentional
			s.TargetKind = site.TargetURL
			s.TargetURL = `https://100.64.0.5:30443"`
		}, nil},
		{"url target with plus port", func(s *site.Site) {
			s.Kind = site.KindOpen
			s.OpenReason = site.OpenReasonIntentional
			s.TargetKind = site.TargetURL
			s.TargetURL = "https://100.64.0.5:+30443"
		}, nil},
		// S-07.1 (F2-015): an uncovered cert:auto no longer refuses the record; it renders
		// through the no-tls snippet variant instead (the previous fail-closed contract held
		// until DNS-01 policy landed — the warning now lives in the review screen).
		{"auto cert without covering cert", func(s *site.Site) { s.Cert = "auto" }, &CaddyConfig{
			ACMEEmail: "admin@example.com",
			S06Open:   true,
			Certs:     []string{"other.example.com"},
		}},
		{"empty acme email", func(s *site.Site) { s.Cert = "auto" }, &CaddyConfig{
			S06Open: true,
			Certs:   []string{"example.com"},
		}},
		{"empty cert list", func(s *site.Site) { s.Cert = "auto" }, &CaddyConfig{
			ACMEEmail: "admin@example.com",
			S06Open:   true,
		}},
	}
	// The S-07.1 cases render instead of refusing; their no-tls contract has its own test.
	noTLSNames := map[string]bool{"auto cert without covering cert": true, "empty cert list": true}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := roleSite()
			tc.mutate(&s)
			cfg := caddyCfg(true)
			if tc.cfg != nil {
				cfg = *tc.cfg
			}
			out, err := RenderCaddyfile([]site.Site{s}, cfg)
			if noTLSNames[tc.name] {
				if err != nil {
					t.Fatalf("an uncovered cert:auto blocked the record: %v", err)
				}
				if !strings.Contains(out, "import vpn_site_nt") {
					t.Errorf("the uncovered site did not render through the no-tls variant:\n%s", out)
				}
				return
			}
			if err == nil {
				t.Errorf("unsafe site was rendered:\n%s", out)
			}
		})
	}
}

// TestCaddyRender_RejectsDuplicateHost refuses two sites that claim the same
// host: the store enforces global host uniqueness; the renderer refuses to
// guess which block would win.
func TestCaddyRender_RejectsDuplicateHost(t *testing.T) {
	a := roleSite()
	b := roleSite()
	b.Hosts = []string{"monitor.example.com"}
	if _, err := RenderCaddyfile([]site.Site{a, b}, caddyCfg(true)); err == nil {
		t.Fatal("two sites with the same host were rendered")
	}
}

// TestCaddyRender_CertAuto resolves cert:auto to the longest wildcard
// certificate that covers every host of the site.
func TestCaddyRender_CertAuto(t *testing.T) {
	s := openK8sSite()
	s.Cert = "auto"
	out, err := RenderCaddyfile([]site.Site{s}, caddyCfg(true))
	if err != nil {
		t.Fatalf("cert auto not resolved: %v", err)
	}
	if !strings.Contains(out, "/etc/letsencrypt/live/example.com/") {
		t.Errorf("auto did not resolve to example.com:\n%s", out)
	}

	// A deeper certificate wins over the shorter one.
	single := roleSite()
	single.Cert = "auto"
	single.Hosts = []string{"blog.internal.example.org"}
	out, err = RenderCaddyfile([]site.Site{single}, caddyCfg(true))
	if err != nil {
		t.Fatalf("cert auto not resolved: %v", err)
	}
	// A role site writes the cert as the snippet argument.
	if !strings.Contains(out, "import vpn_site internal.example.org devops,developer") {
		t.Errorf("longest covering cert not chosen:\n%s", out)
	}
}

// TestCaddyRender_EmptySet renders only the fixed header.
func TestCaddyRender_EmptySet(t *testing.T) {
	out := renderSites(t, true, nil)
	if !strings.Contains(out, "(vpn_site_api)") {
		t.Fatalf("snippets missing:\n%s", out)
	}
	if strings.Contains(out, "example.com {") {
		t.Errorf("empty set rendered a site block:\n%s", out)
	}
}

// The (k8s) snippet's upstream is a setting (F6 parity, M6): empty keeps the lab default K8sUpstream byte for
// byte, a configured https://host[:port] replaces only that line (an existing installation: the Traefik internal entrypoint,
// :8443), and anything that is not a plain https origin is refused, never written.
func TestCaddyRender_K8sUpstream(t *testing.T) {
	cfg := caddyCfg(true)
	def, err := RenderCaddyfile(nil, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(def, "\treverse_proxy "+K8sUpstream+" {\n") {
		t.Fatalf("default upstream missing:\n%s", def)
	}
	cfg.K8sUpstream = "https://100.64.0.5:8443"
	got, err := RenderCaddyfile(nil, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.Replace(def, "\treverse_proxy "+K8sUpstream+" {\n", "\treverse_proxy https://100.64.0.5:8443 {\n", 1); got != want {
		t.Errorf("configured upstream changed more than the (k8s) line:\n%s", got)
	}
	cfg.K8sUpstream = K8sUpstream
	if same, err := RenderCaddyfile(nil, cfg); err != nil || same != def {
		t.Errorf("the default written out must render the same file: %v", err)
	}
	for _, bad := range []string{
		"http://100.64.0.5", "100.64.0.5:8443", "https://100.64.0.5:8443/x", "https://100.64.0.5:0", "https://a b",
		"https://100.64.0.5:8443 {\n}\nevil.example {", "https://u@100.64.0.5", "https://100.64.0.5?x=1", "https://{env.X}",
		"https://100.64.0.5:8443#", "https://100.64.0.5:8443?", "https://100.64.0.5:", "https://100.64.0.5#x",
	} {
		cfg.K8sUpstream = bad
		if _, err := RenderCaddyfile(nil, cfg); err == nil {
			t.Errorf("upstream %q was rendered, want a refusal", bad)
		}
	}
}

// F3: the role-less 403 is a fixed, friendly Turkish page with the status kept at 403. It echoes
// no request value and holds no braces (Caddy would read them as placeholders).
func TestCaddyRender_ForbiddenPage(t *testing.T) {
	out := renderSites(t, true, nil)
	for _, want := range []string{
		"@yetki_yok status 403",
		"handle_response @yetki_yok {",
		`header Content-Type "text/html; charset=utf-8"`,
		"Bu siteye erişim yetkiniz yok",
		"yetkili rol",
		`href="/oauth2/sign_out?rd=%2F">Başka hesapla giriş yap</a>`,
		"</html>` 403",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered snippets lack %q", want)
		}
	}
	if strings.ContainsAny(caddyForbiddenPage("/oauth2/sign_out?rd=%2F"), "{}") {
		t.Error("the page holds braces; Caddy would treat them as placeholders")
	}
}

// TestCaddyRender_GateUpstream is AC1 and AC2 of issue #5: a configured gate upstream replaces
// every oauth2-proxy address (the snippets' reverse_proxy and forward_auth, and the tagcess block);
// unset keeps 127.0.0.1:4180, byte for byte.
func TestCaddyRender_GateUpstream(t *testing.T) {
	const def = "127.0.0.1:4180"
	render := func(t *testing.T, up string) string {
		t.Helper()
		cfg := systemCfg(true)
		cfg.GateUpstream = up
		out, err := RenderCaddyfile(append(goldSiteSet(), systemSites()...), cfg)
		if err != nil {
			t.Fatalf("RenderCaddyfile(%q): %v", up, err)
		}
		return out
	}
	base := render(t, "")
	if n := strings.Count(base, "reverse_proxy "+def) + strings.Count(base, "forward_auth "+def); n < 3 {
		t.Fatalf("default output names %s %d times, want at least 3", def, n)
	}

	t.Run("unset equals the default", func(t *testing.T) {
		if got := render(t, def); got != base {
			t.Error("explicit 127.0.0.1:4180 differs from the unset output")
		}
	})
	t.Run("set replaces every address", func(t *testing.T) {
		for _, up := range []string{"127.0.0.1:4181", "oauth2-proxy:4180", "[::1]:4180"} {
			got := render(t, up)
			if strings.Contains(got, def) {
				t.Errorf("%s: output still names %s", up, def)
			}
			want := strings.ReplaceAll(base, def, up)
			if got != want {
				t.Errorf("%s: output differs from the default with the address swapped", up)
			}
		}
	})
	t.Run("invalid is refused", func(t *testing.T) {
		for _, up := range []string{"nohost", "host:0", "host:99999", "a b:1", "host:80 {", "http://h:1", "h:1/x", ":4180", "h:1\nrespond 200"} {
			cfg := systemCfg(true)
			cfg.GateUpstream = up
			if _, err := RenderCaddyfile(systemSites(), cfg); err == nil {
				t.Errorf("gate upstream %q accepted", up)
			}
		}
	})
}

// TestCaddyRender_TailnetCIDR is AC1 and AC2 of issue #6: tailnet.cidr replaces every source-range
// matcher (snippets, redirects, the tagcess and zitadel blocks); unset or the default keeps the
// existing output; an invalid value fails the render.
func TestCaddyRender_TailnetCIDR(t *testing.T) {
	const def, custom = "100.64.0.0/10", "10.200.0.0/16"
	sites := func() []site.Site { return append(goldSiteSet(), systemSites()...) }
	render := func(t *testing.T, s06open bool, cidr string) string {
		t.Helper()
		cfg := systemCfg(s06open)
		cfg.TailnetCIDR = cidr
		out, err := RenderCaddyfile(sites(), cfg)
		if err != nil {
			t.Fatalf("RenderCaddyfile(%q): %v", cidr, err)
		}
		return out
	}
	for _, open := range []bool{true, false} {
		base := render(t, open, "")
		if n := strings.Count(base, def); n < 4 {
			t.Fatalf("s06open=%v: default output names %s %d times, want at least 4", open, def, n)
		}
		if got := render(t, open, def); got != base {
			t.Errorf("s06open=%v: explicit default differs from the unset output", open)
		}
		got := render(t, open, custom)
		if strings.Contains(got, def) {
			t.Errorf("s06open=%v: output still names %s", open, def)
		}
		if want := strings.ReplaceAll(base, def, custom); got != want {
			t.Errorf("s06open=%v: output differs from the default with the prefix swapped", open)
		}
		if !open {
			golden := filepath.Join("testdata", "caddy-tailnet-cidr.golden")
			if *updateGoldens {
				if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatal(err)
			}
			if got != string(want) {
				t.Errorf("custom-prefix output does not match %s", golden)
			}
		}
	}
	for _, bad := range []string{"nope", "100.64.0.1/10", "10.0.0.0/7", "0.0.0.0/0", "fd7a:115c:a1e0::/48", "10.0.0.0/8\nrespond 200"} {
		cfg := systemCfg(true)
		cfg.TailnetCIDR = bad
		if _, err := RenderCaddyfile(sites(), cfg); err == nil {
			t.Errorf("TailnetCIDR %q accepted", bad)
		}
	}
}
