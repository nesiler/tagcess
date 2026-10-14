package render

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/internal/site"
)

// zitadelSystemConfig is the canonical zitadel record config: the internal source list and the
// login paths both live on the record (F2-013 decision). The sources are documentation addresses
// standing in for the real server IPs.
const zitadelSystemConfig = `{"internal_sources":["10.8.0.0/24","127.0.0.1/32","::1/128","192.0.2.10/32","2001:db8:1::/64"],"login_paths":["/.well-known/*","/oauth/v2/*","/oidc/v1/*","/ui/v2/login","/ui/v2/login/*","/ui/login","/ui/login/*","/assets/v1/*"]}`

// zitadelConfigWith builds a zitadel system_config with the given sources and the default paths.
func zitadelConfigWith(sources []string) string {
	if sources == nil {
		sources = []string{}
	}
	body, err := json.Marshal(struct {
		InternalSources []string `json:"internal_sources"`
		LoginPaths      []string `json:"login_paths"`
	}{sources, site.DefaultZitadelLoginPaths})
	if err != nil {
		panic(err)
	}
	return string(body)
}

// systemSites returns the four canonical system sites in a deliberately non-render order.
func systemSites() []site.Site {
	base := func(tmpl, host, cert, config string) site.Site {
		return site.Site{
			Hosts:          []string{host},
			Kind:           site.KindSystem,
			SystemTemplate: tmpl,
			SystemConfig:   config,
			Cert:           cert,
			TargetKind:     site.TargetK8s,
			Roles:          []string{}, TargetRoles: []string{},
			APIRules: []site.APIRule{}, Redirects: []site.Redirect{}, Headers: []site.Header{},
		}
	}
	return []site.Site{
		base(site.TemplateTagcess, "tagcess.example.test", "auto", `{}`),
		base(site.TemplateWireGuardUI, "vpn.example.net", "auto", `{"enabled":true}`),
		base(site.TemplateHeadscale, "hs.example.net", "auto", `{"headplane":true}`),
		base(site.TemplateZitadel, "auth.example.net", "le:example.net", zitadelSystemConfig),
	}
}

// systemCfg is the render config of the system tests: today's ACME email and certificate names.
// The zitadel internal sources and login paths come from the record now (F2-013).
func systemCfg(s06open bool) CaddyConfig {
	return caddyCfg(s06open)
}

func renderSystem(t *testing.T, s06open bool, sites []site.Site) string {
	t.Helper()
	out, err := RenderCaddyfile(sites, systemCfg(s06open))
	if err != nil {
		t.Fatalf("RenderCaddyfile: %v", err)
	}
	assertTopLevelBalanced(t, out)
	return out
}

// assertTopLevelBalanced checks the column-zero structure of the whole file: every top-level
// opener ("... {") is closed by exactly one "}" line before the next one. siteBlock only looks at
// one block, so a stray or missing closing brace elsewhere would pass the block comparisons.
func assertTopLevelBalanced(t *testing.T, out string) {
	t.Helper()
	open := false
	for i, line := range strings.Split(out, "\n") {
		switch {
		case line == "" || line[0] == '#' || line[0] == '\t':
		case line == "}":
			if !open {
				t.Fatalf("line %d: a closing brace without an open block", i+1)
			}
			open = false
		case line == "{" || strings.HasSuffix(line, " {") || strings.HasSuffix(line, ","):
			if open && (line == "{" || strings.HasSuffix(line, " {")) {
				t.Fatalf("line %d: %q opens a block inside an open block", i+1, line)
			}
			open = open || line == "{" || strings.HasSuffix(line, " {")
		default:
			t.Fatalf("line %d: unexpected top-level text %q", i+1, line)
		}
	}
	if open {
		t.Fatal("the file ends inside an open block")
	}
}

// withSystem returns the canonical system set with one template's record changed.
func withSystem(tmpl string, mutate func(s *site.Site)) []site.Site {
	sites := systemSites()
	for i := range sites {
		if sites[i].SystemTemplate == tmpl {
			mutate(&sites[i])
		}
	}
	return sites
}

// f1TagcessSnippet reads deploy/caddy/tagcess.caddy and drops its leading comment header:
// ADR 0010 makes that file the reference text of the tagcess template. The snippet's placeholder
// host is swapped for tagcess.example.test, a name none of the test certificates covers.
func f1TagcessSnippet(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "deploy", "caddy", "tagcess.caddy"))
	if err != nil {
		t.Fatalf("read F1 snippet: %v", err)
	}
	if !strings.Contains(string(raw), "tagcess.example.com {\n") {
		t.Fatal("the F1 snippet no longer uses the tagcess.example.com placeholder host")
	}
	raw = []byte(strings.Replace(string(raw), "tagcess.example.com {\n", "tagcess.example.test {\n", 1))
	lines := strings.SplitAfter(string(raw), "\n")
	for len(lines) > 0 && strings.HasPrefix(lines[0], "#") {
		lines = lines[1:]
	}
	return strings.Join(lines, "")
}

// TestSystemSite_TagcessGolden is AC2: the tagcess template renders the F1 snippet's text, with
// the fixed devops group and the identity-header stripping in front of forward_auth.
func TestSystemSite_TagcessGolden(t *testing.T) {
	want := f1TagcessSnippet(t)

	for _, open := range []bool{true, false} {
		out := renderSystem(t, open, systemSites())
		got := siteBlock(t, out, "tagcess.example.test")
		if !strings.HasSuffix(out, "\n"+want) {
			t.Errorf("S-06 open=%v: the tagcess block is not the last, exact block of the file:\n%s", open, out)
		}
		if got != want {
			t.Errorf("S-06 open=%v: tagcess block differs from the F1 snippet\n--- got ---\n%s\n--- want ---\n%s", open, got, want)
		}
	}

	t.Run("fixed rules", func(t *testing.T) {
		got := siteBlock(t, renderSystem(t, true, systemSites()), "tagcess.example.test")
		for _, line := range []string{
			"@tailnet remote_ip 100.64.0.0/10",
			"request_header -X-Auth-Request-User",
			"request_header -X-Auth-Request-Email",
			"request_header -X-Auth-Request-Groups",
			"uri /oauth2/auth?allowed_groups=devops",
			"copy_headers X-Auth-Request-User X-Auth-Request-Email X-Auth-Request-Groups",
			"reverse_proxy unix//run/tagcess/ui.sock",
			"respond 403",
		} {
			if !strings.Contains(got, line) {
				t.Errorf("tagcess block lacks %q", line)
			}
		}
		// The header stripping must come before forward_auth, inside the route.
		strip := strings.Index(got, "request_header -X-Auth-Request-Groups")
		auth := strings.Index(got, "\n\t\t\tforward_auth 127.0.0.1:4180")
		if strip < 0 || auth < 0 || strip > auth {
			t.Error("identity headers are not stripped before forward_auth")
		}
	})

	t.Run("host is the only variable", func(t *testing.T) {
		sites := withSystem(site.TemplateTagcess, func(s *site.Site) { s.Hosts = []string{"ui.example.net"} })
		got := siteBlock(t, renderSystem(t, true, sites), "ui.example.net")
		// The covering wildcard adds exactly one tls line after the host line (cert auto); the
		// rest is the F1 snippet with the host.
		wantOther := strings.Replace(want, "tagcess.example.test {\n", "ui.example.net {\n"+
			"\ttls /etc/letsencrypt/live/example.net/fullchain.pem /etc/letsencrypt/live/example.net/privkey.pem\n", 1)
		if got != wantOther {
			t.Errorf("host substitution changed more than the host and the tls line\n%s", got)
		}
	})

	t.Run("an uncovered host gets no tls line", func(t *testing.T) {
		got := siteBlock(t, renderSystem(t, true, systemSites()), "tagcess.example.test")
		if strings.Contains(got, "\ttls ") {
			t.Errorf("tls line for a host no certificate covers:\n%s", got)
		}
	})

	t.Run("a deeper subdomain gets no tls line", func(t *testing.T) {
		// A wildcard certificate covers one label only: ui.vpn.example.net would fail TLS
		// with the example.net certificate, and the record cannot pick another one.
		sites := withSystem(site.TemplateTagcess, func(s *site.Site) { s.Hosts = []string{"ui.vpn.example.net"} })
		got := siteBlock(t, renderSystem(t, true, sites), "ui.vpn.example.net")
		if strings.Contains(got, "\ttls ") {
			t.Errorf("tls line for a host the wildcard does not cover:\n%s", got)
		}
	})

	t.Run("record cannot change the fixed rules", func(t *testing.T) {
		for name, mutate := range map[string]func(s *site.Site){
			"roles":         func(s *site.Site) { s.Roles = []string{"standart"} },
			"target roles":  func(s *site.Site) { s.TargetRoles = []string{"standart"} },
			"closed config": func(s *site.Site) { s.SystemConfig = `{"enabled":false}` },
			"empty config":  func(s *site.Site) { s.SystemConfig = `` },
			"header":        func(s *site.Site) { s.Headers = []site.Header{{Name: "X-Note", Value: "v"}} },
			"redirect": func(s *site.Site) {
				s.Redirects = []site.Redirect{{Source: "/a", Target: "/b", Code: 301}}
			},
			"api rule": func(s *site.Site) {
				s.APIRules = []site.APIRule{{Type: site.APIRuleHeaderPresent, Value: "Authorization"}}
			},
			"url target": func(s *site.Site) {
				s.TargetKind, s.TargetURL = site.TargetURL, "http://127.0.0.1:2019"
			},
			"two hosts":     func(s *site.Site) { s.Hosts = []string{"a.example.com", "b.example.com"} },
			"open reason":   func(s *site.Site) { s.OpenReason = site.OpenReasonIntentional },
			"injected host": func(s *site.Site) { s.Hosts = []string{"x.example.com {\n\trespond 200\n}\nevil.example.com"} },
		} {
			if _, err := RenderCaddyfile(withSystem(site.TemplateTagcess, mutate), systemCfg(true)); err == nil {
				t.Errorf("%s: the record was rendered", name)
			}
		}
	})
}

// TestSystemSite_Templates pins the text of the other three templates and the section order
// (ADR 0010: system blocks in a fixed order at the end, after the sorted user sites), for both
// S-06 key states: system templates keep their own source rules.
func TestSystemSite_Templates(t *testing.T) {
	zitadel := "auth.example.net {\n" +
		"\ttls /etc/letsencrypt/live/example.net/fullchain.pem /etc/letsencrypt/live/example.net/privkey.pem\n" +
		"\t@tailnet remote_ip 100.64.0.0/10\n" +
		"\t@serbest remote_ip 10.8.0.0/24 127.0.0.1/32 ::1/128 192.0.2.10/32 2001:db8:1::/64\n" +
		"\t@giris path /.well-known/* /oauth/v2/* /oidc/v1/* /ui/v2/login /ui/v2/login/* /ui/login /ui/login/* /assets/v1/*\n" +
		"\n" +
		"\thandle @tailnet {\n\t\timport k8s\n\t}\n" +
		"\thandle @serbest {\n\t\timport k8s\n\t}\n" +
		"\thandle @giris {\n\t\timport k8s\n\t}\n" +
		"\thandle {\n\t\trespond \"Forbidden\" 403\n\t}\n" +
		"}\n"
	headscale := "hs.example.net {\n" +
		"\thandle /admin* {\n\t\treverse_proxy 127.0.0.1:3000\n\t}\n" +
		"\n" +
		"\thandle {\n\t\treverse_proxy 127.0.0.1:8080\n\t}\n" +
		"}\n"
	wireguard := "vpn.example.net {\n\treverse_proxy [::1]:5000\n}\n"

	user := roleSite()
	user.Hosts = []string{"zzz.example.net"} // sorts after every system host

	for _, open := range []bool{true, false} {
		out := renderSystem(t, open, append(systemSites(), user))
		if got := siteBlock(t, out, "auth.example.net"); got != zitadel {
			t.Errorf("open=%v zitadel block\n--- got ---\n%s\n--- want ---\n%s", open, got, zitadel)
		}
		if got := siteBlock(t, out, "hs.example.net"); got != headscale {
			t.Errorf("open=%v headscale block\n--- got ---\n%s\n--- want ---\n%s", open, got, headscale)
		}
		if got := siteBlock(t, out, "vpn.example.net"); got != wireguard {
			t.Errorf("open=%v wireguard_ui block\n--- got ---\n%s\n--- want ---\n%s", open, got, wireguard)
		}

		// user sites first, then system blocks in the fixed template order.
		order := []string{
			"zzz.example.net {",
			"auth.example.net {",
			"hs.example.net {",
			"vpn.example.net {",
			"tagcess.example.test {",
		}
		last := -1
		for _, marker := range order {
			i := strings.Index(out, "\n"+marker)
			if i < 0 || i < last {
				t.Fatalf("open=%v: block %q missing or out of order:\n%s", open, marker, out)
			}
			last = i
		}
	}

	// Deterministic: any input order renders the same text.
	a := renderSystem(t, true, systemSites())
	reversed := systemSites()
	slices.Reverse(reversed)
	if b := renderSystem(t, true, reversed); a != b {
		t.Error("system rendering depends on the input order")
	}
}

// TestSystemSite_AllowedSwitches is AC3: the headplane and wireguard_ui switches change only
// their own template branch; every other byte of the Caddyfile stays the same.
func TestSystemSite_AllowedSwitches(t *testing.T) {
	base := renderSystem(t, true, systemSites())

	t.Run("headplane off drops only the /admin branch", func(t *testing.T) {
		sites := withSystem(site.TemplateHeadscale, func(s *site.Site) { s.SystemConfig = `{"headplane":false}` })
		got := renderSystem(t, true, sites)
		want := strings.Replace(base,
			"\thandle /admin* {\n\t\treverse_proxy 127.0.0.1:3000\n\t}\n\n", "", 1)
		if want == base {
			t.Fatal("test setup: the /admin branch was not in the base output")
		}
		if got != want {
			t.Errorf("headplane switch changed more than its branch\n--- got ---\n%s\n--- want ---\n%s", got, want)
		}
		if !strings.Contains(got, "reverse_proxy 127.0.0.1:8080") {
			t.Error("the headscale proxy branch must stay")
		}
	})

	t.Run("wireguard_ui off drops only its block", func(t *testing.T) {
		sites := withSystem(site.TemplateWireGuardUI, func(s *site.Site) { s.SystemConfig = `{"enabled":false}` })
		got := renderSystem(t, true, sites)
		want := strings.Replace(base, "\nvpn.example.net {\n\treverse_proxy [::1]:5000\n}\n", "", 1)
		if want == base {
			t.Fatal("test setup: the vpn block was not in the base output")
		}
		if got != want {
			t.Errorf("wireguard switch changed more than its block\n--- got ---\n%s\n--- want ---\n%s", got, want)
		}
	})

	t.Run("switches are independent", func(t *testing.T) {
		sites := systemSites()
		for i := range sites {
			switch sites[i].SystemTemplate {
			case site.TemplateHeadscale:
				sites[i].SystemConfig = `{"headplane":false}`
			case site.TemplateWireGuardUI:
				sites[i].SystemConfig = `{"enabled":false}`
			}
		}
		got := renderSystem(t, true, sites)
		for _, host := range []string{"auth.example.net", "tagcess.example.test"} {
			if siteBlock(t, got, host) != siteBlock(t, base, host) {
				t.Errorf("%s block changed with unrelated switches", host)
			}
		}
		if strings.Contains(got, "/admin*") || strings.Contains(got, "[::1]:5000") {
			t.Error("a switched-off branch is still rendered")
		}
	})

	t.Run("invalid switch values are refused", func(t *testing.T) {
		for name, cfg := range map[string]string{
			"headscale null":      `null`,
			"headscale string":    `{"headplane":"true"}`,
			"headscale unknown":   `{"headplane":true,"x":1}`,
			"headscale empty":     `{}`,
			"headscale no config": ``,
			"headscale enabled":   `{"enabled":true}`,
		} {
			sites := withSystem(site.TemplateHeadscale, func(s *site.Site) { s.SystemConfig = cfg })
			if _, err := RenderCaddyfile(sites, systemCfg(true)); err == nil {
				t.Errorf("%s: rendered", name)
			}
		}
		for name, cfg := range map[string]string{
			"wireguard null":      `null`,
			"wireguard string":    `{"enabled":"false"}`,
			"wireguard unknown":   `{"enabled":false,"x":1}`,
			"wireguard empty":     `{}`,
			"wireguard headplane": `{"headplane":false}`,
		} {
			sites := withSystem(site.TemplateWireGuardUI, func(s *site.Site) { s.SystemConfig = cfg })
			if _, err := RenderCaddyfile(sites, systemCfg(true)); err == nil {
				t.Errorf("%s: rendered", name)
			}
		}
	})
}

// TestSystemSite_ZitadelSources: the internal source list comes from the record; every entry
// must be a canonical IP/CIDR (a bad entry would widen or break the matcher). An empty list
// leaves only the tailnet handle (no @serbest), so access only narrows.
func TestSystemSite_ZitadelSources(t *testing.T) {
	t.Run("bad entries are refused", func(t *testing.T) {
		for _, bad := range []string{
			"example.com", "1.2.3.4; respond 200", "1.2.3.4/33", "", "10.0.0.1/24", "10.0.0.1 ",
			"fe80::1%eth0", "0.0.0.0/0", "::/0", "2001:DB8::/64", "1.2.3.4\n/32", "{env.X}",
			"10.0.0.0/8", "2001:db8::/32",
		} {
			sites := withSystem(site.TemplateZitadel, func(s *site.Site) {
				s.SystemConfig = zitadelConfigWith([]string{"10.8.0.0/24", bad})
			})
			if _, err := RenderCaddyfile(sites, systemCfg(true)); err == nil {
				t.Errorf("source %q was rendered", bad)
			}
		}
	})

	t.Run("bad login paths are refused", func(t *testing.T) {
		for _, bad := range []string{"/", "/*", "/a*", "*.js", "/a/*/b", "/a/../b", "/a//b", "no-slash"} {
			sites := withSystem(site.TemplateZitadel, func(s *site.Site) {
				body, _ := json.Marshal(struct {
					InternalSources []string `json:"internal_sources"`
					LoginPaths      []string `json:"login_paths"`
				}{[]string{}, []string{bad}})
				s.SystemConfig = string(body)
			})
			if _, err := RenderCaddyfile(sites, systemCfg(true)); err == nil {
				t.Errorf("login path %q was rendered", bad)
			}
		}
	})

	t.Run("empty list keeps only the tailnet range", func(t *testing.T) {
		sites := withSystem(site.TemplateZitadel, func(s *site.Site) {
			s.SystemConfig = zitadelConfigWith(nil)
		})
		out, err := RenderCaddyfile(sites, systemCfg(true))
		if err != nil {
			t.Fatalf("RenderCaddyfile: %v", err)
		}
		block := siteBlock(t, out, "auth.example.net")
		if !strings.Contains(block, "\t@tailnet remote_ip 100.64.0.0/10\n") || strings.Contains(block, "@serbest") || !strings.Contains(block, `respond "Forbidden" 403`) {
			t.Errorf("tailnet branch or the 403 catch-all is missing:\n%s", block)
		}
	})

	t.Run("cert auto resolves, bad cert is refused", func(t *testing.T) {
		sites := withSystem(site.TemplateZitadel, func(s *site.Site) { s.Cert = "auto" })
		out := renderSystem(t, true, sites)
		if !strings.Contains(siteBlock(t, out, "auth.example.net"), "/live/example.net/fullchain.pem") {
			t.Error("cert auto did not resolve to the covering certificate")
		}
		for _, bad := range []string{"le:../x", "le:a b", "static", ""} {
			sites := withSystem(site.TemplateZitadel, func(s *site.Site) { s.Cert = bad })
			if _, err := RenderCaddyfile(sites, systemCfg(true)); err == nil {
				t.Errorf("cert %q was rendered", bad)
			}
		}
	})
}

// TestSystemSite_RenderRefusals: a record that does not fit its template is an error, never a
// block (fail closed): unknown template, a user kind carrying a template, a duplicate template,
// a host shared with a user site, a malformed host, a non-system record with system fields.
func TestSystemSite_RenderRefusals(t *testing.T) {
	cases := map[string]func() []site.Site{
		"unknown template": func() []site.Site {
			return withSystem(site.TemplateTagcess, func(s *site.Site) { s.SystemTemplate = "evil" })
		},
		"duplicate template": func() []site.Site {
			dup := systemSites()[0]
			dup.Hosts = []string{"tagcess2.example.com"}
			return append(systemSites(), dup)
		},
		"host shared with a user site": func() []site.Site {
			u := roleSite()
			u.Hosts = []string{"tagcess.example.test"}
			return append(systemSites(), u)
		},
		"user site with a template": func() []site.Site {
			u := roleSite()
			u.SystemTemplate = site.TemplateTagcess
			return []site.Site{u}
		},
		"user site with system config": func() []site.Site {
			u := roleSite()
			u.SystemConfig = `{"enabled":true}`
			return []site.Site{u}
		},
		"zitadel with a header": func() []site.Site {
			return withSystem(site.TemplateZitadel, func(s *site.Site) {
				s.Headers = []site.Header{{Name: "X-Note", Value: "v"}}
			})
		},
		"headscale with roles": func() []site.Site {
			return withSystem(site.TemplateHeadscale, func(s *site.Site) { s.Roles = []string{"devops"} })
		},
		"zitadel closed": func() []site.Site {
			return withSystem(site.TemplateZitadel, func(s *site.Site) { s.SystemConfig = `{"enabled":false}` })
		},
		"headscale host injection": func() []site.Site {
			return withSystem(site.TemplateHeadscale, func(s *site.Site) { s.Hosts = []string{"hs.example.com {\n\trespond 200\n}\nx.example.com"} })
		},
		"wireguard uppercase host": func() []site.Site {
			return withSystem(site.TemplateWireGuardUI, func(s *site.Site) { s.Hosts = []string{"VPN.example.com"} })
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := RenderCaddyfile(build(), systemCfg(true)); err == nil {
				t.Error("the record was rendered")
			}
		})
	}
}
