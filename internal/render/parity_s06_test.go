package render

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/internal/site"
)

// The shapes below are what Caddy 2.8.4 adapts the existing installation's site blocks to (F6 fixture, checked with
// `caddy adapt`): a site block is a host route around a subroute; `handle @x {...}` blocks of one level share a
// group; `import k8s` is a reverse_proxy route; `respond 403` is a static_response.

const s06Upstream = "100.64.0.5:8443"

var s06Serbest = []string{"10.8.0.0/24", "127.0.0.1", "::1", "192.0.2.10"}

// s06Branch is `handle @src { inner }` with @src a remote_ip matcher.
func s06Branch(group string, ranges []string, inner ...any) map[string]any {
	rs := make([]any, len(ranges))
	for i, r := range ranges {
		rs[i] = r
	}
	return map[string]any{
		"group":  group,
		"match":  []any{map[string]any{"remote_ip": map[string]any{"ranges": rs}}},
		"handle": []any{map[string]any{"handler": "subroute", "routes": inner}},
	}
}

// s06Deny is the catch-all `handle { respond 403 }`.
func s06Deny(group string) map[string]any {
	return map[string]any{
		"group":  group,
		"handle": []any{map[string]any{"handler": "subroute", "routes": []any{map[string]any{"handle": []any{map[string]any{"handler": "static_response", "status_code": 403}}}}}},
	}
}

// s06Handle is `handle { inner }` inside a group (the @api else branch).
func s06Handle(group string, match any, inner ...any) map[string]any {
	r := map[string]any{"group": group, "handle": []any{map[string]any{"handler": "subroute", "routes": inner}}}
	if match != nil {
		r["match"] = match
	}
	return r
}

func s06Redirect() map[string]any {
	return map[string]any{
		"match":  []any{map[string]any{"path": []any{"/setup"}}},
		"handle": []any{map[string]any{"handler": "static_response", "status_code": 308, "headers": map[string]any{"Location": []any{"https://a.example/setup/"}}}},
	}
}

// s06Today is today's existing block: tailnet (the suspended role check imports k8s; with api, the @api and the
// else branch both import k8s) and the free sources to k8s, everything else 403.
func s06Today(host string, api, redirect bool, tailnetDial string) map[string]any {
	tail := []any{proxyTo(tailnetDial)}
	if api {
		apiMatch := []any{map[string]any{"header": map[string]any{"Authorization": []any{"*"}}}}
		tail = []any{s06Handle("group2", apiMatch, proxyTo(tailnetDial)), s06Handle("group2", nil, proxyTo(tailnetDial))}
	}
	var routes []any
	if redirect {
		routes = append(routes, s06Redirect())
	}
	routes = append(routes,
		s06Branch("group9", []string{"100.64.0.0/10"}, tail...),
		s06Branch("group9", s06Serbest, proxyTo(s06Upstream)),
		s06Deny("group9"))
	return hostRoute([]string{host}, routes...)
}

// s06Generated is the open block tagcess renders with S-06 open: tls + redirects + import k8s.
func s06Generated(host string, redirect bool, dial string) map[string]any {
	var routes []any
	if redirect {
		routes = append(routes, s06Redirect())
	}
	return hostRoute([]string{host}, append(routes, proxyTo(dial))...)
}

// s06Closed is the open block with S-06 closed (or any source-gated block): only the tailnet reaches the target.
func s06Closed(host string, ranges []string) map[string]any {
	return hostRoute([]string{host}, s06Branch("group0", ranges, proxyTo(s06Upstream)), s06Deny("group0"))
}

func s06Site(host, reason string) site.Site {
	return site.Site{Hosts: []string{host}, Kind: site.KindOpen, OpenReason: reason, TargetKind: site.TargetK8s, Cert: "le:example"}
}

// s06Parity runs SeedParity with a stub adapter: "TODAY" adapts to today, every generated text to gen.
func s06Parity(t *testing.T, sites []site.Site, today, gen []any) (SeedParityResult, error) {
	t.Helper()
	adapt := func(_ context.Context, caddyfile string) ([]byte, error) {
		if caddyfile == "TODAY" {
			return []byte(serverDoc(today...)), nil
		}
		return []byte(serverDoc(gen...)), nil
	}
	return SeedParity(context.Background(), adapt, "TODAY", sites, seedParityCfg())
}

// TestParity_S06OpenStartAccepted (developer decision 2026-10-07, [K] F6): an open/transition site whose today's
// block restricts the sources (tailnet + free sources to the target, everything else 403) and whose generated
// block sends every source to the same target is the one accepted difference, reported by name with its hosts and
// today's sources, never silently.
func TestParity_S06OpenStartAccepted(t *testing.T) {
	// b.example is open/intentional (the existing installation's vpn_only sites): the same S-06 rule renders it, [Ö] 2026-10-07.
	sites := []site.Site{s06Site("a.example", site.OpenReasonTransition), s06Site("b.example", site.OpenReasonIntentional)}
	today := []any{s06Today("a.example", false, false, s06Upstream), s06Today("b.example", true, true, s06Upstream)}
	gen := []any{s06Generated("a.example", false, s06Upstream), s06Generated("b.example", true, s06Upstream)}
	res, err := s06Parity(t, sites, today, gen)
	if err != nil {
		t.Fatalf("the S-06 open start must be accepted: %v", err)
	}
	if len(res.Accepted) != 2 {
		t.Fatalf("accepted = %+v, want both sites", res.Accepted)
	}
	if AcceptedS06OpenStart != "s06_open_start" {
		t.Fatalf("the class name is part of the report contract: %q", AcceptedS06OpenStart)
	}
	wantSources := append([]string{"100.64.0.0/10"}, s06Serbest...)
	slices.Sort(wantSources)
	for i, host := range []string{"a.example", "b.example"} {
		a := res.Accepted[i]
		if a.Class != AcceptedS06OpenStart || !slices.Equal(a.Hosts, []string{host}) {
			t.Errorf("accepted[%d] = %+v, want class s06_open_start for %s", i, a, host)
		}
		if wantReason := []string{site.OpenReasonTransition, site.OpenReasonIntentional}[i]; a.OpenReason != wantReason {
			t.Errorf("accepted[%d] open reason = %q, want %q", i, a.OpenReason, wantReason)
		}
		if !slices.Equal(a.TodaySources, wantSources) {
			t.Errorf("accepted[%d] today sources = %v, want %v", i, a.TodaySources, wantSources)
		}
		if !strings.Contains(a.Description, "S-06 açık başlangıç") {
			t.Errorf("accepted[%d] description = %q, want the named class", i, a.Description)
		}
	}
	// The gate passes (the UI's first import and the apply gate see no error).
	adapt := func(_ context.Context, caddyfile string) ([]byte, error) {
		if caddyfile == "TODAY" {
			return []byte(serverDoc(today...)), nil
		}
		return []byte(serverDoc(gen...)), nil
	}
	if err := CheckSeedParity(context.Background(), adapt, "TODAY", sites, seedParityCfg()); err != nil {
		t.Errorf("CheckSeedParity: %v", err)
	}
}

// TestParity_S06OpenStartOnlyThatClass: every other difference still fails the gate, also next to an accepted
// site; the accepted sites stay listed in the error so nothing is hidden.
func TestParity_S06OpenStartOnlyThatClass(t *testing.T) {
	transition := []site.Site{s06Site("a.example", site.OpenReasonTransition)}
	roleCheck := hostRoute([]string{"a.example"},
		s06Branch("group9", []string{"100.64.0.0/10"}, map[string]any{"handle": []any{map[string]any{"handler": "forward_auth_stub"}}}),
		s06Branch("group9", s06Serbest, proxyTo(s06Upstream)),
		s06Deny("group9"))
	cases := []struct {
		name      string
		sites     []site.Site
		today     []any
		gen       []any
		wantInErr string
	}{
		{"a role site is not an open site",
			[]site.Site{{Hosts: []string{"a.example"}, Kind: site.KindRole, Roles: []string{"devops"}, TargetKind: site.TargetK8s, Cert: "le:example"}},
			[]any{s06Today("a.example", false, false, s06Upstream)}, []any{s06Generated("a.example", false, s06Upstream)}, "a.example"},
		{"no site record for the block", []site.Site{s06Site("z.example", site.OpenReasonTransition)},
			[]any{s06Today("a.example", false, false, s06Upstream)}, []any{s06Generated("a.example", false, s06Upstream)}, "a.example"},
		{"another target", transition,
			[]any{s06Today("a.example", false, false, s06Upstream)}, []any{s06Generated("a.example", false, "100.64.0.5:443")}, "100.64.0.5:443"},
		{"tailnet branch to another target than the free sources", transition,
			[]any{s06Today("a.example", true, false, "100.64.0.5:443")}, []any{s06Generated("a.example", false, s06Upstream)}, "a.example"},
		{"active role check on the tailnet branch", transition,
			[]any{roleCheck}, []any{s06Generated("a.example", false, s06Upstream)}, "a.example"},
		{"no tailnet branch today", transition,
			[]any{s06Closed("a.example", s06Serbest)}, []any{s06Generated("a.example", false, s06Upstream)}, "a.example"},
		{"redirect only on one side", transition,
			[]any{s06Today("a.example", false, true, s06Upstream)}, []any{s06Generated("a.example", false, s06Upstream)}, "a.example"},
		{"site only in today's file", transition,
			[]any{s06Today("a.example", false, false, s06Upstream), s06Today("c.example", false, false, s06Upstream)},
			[]any{s06Generated("a.example", false, s06Upstream)}, "host=c.example: only in today's file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := s06Parity(t, tc.sites, tc.today, tc.gen)
			var perr *ParityError
			if !errors.As(err, &perr) {
				t.Fatalf("err = %v (result %+v), want *ParityError", err, res)
			}
			if !strings.Contains(perr.Diff, tc.wantInErr) {
				t.Errorf("diff does not name %q:\n%s", tc.wantInErr, perr.Diff)
			}
			if len(perr.Narrower) != 0 {
				t.Errorf("not a narrowing: %+v", perr.Narrower)
			}
		})
	}

	// An unrelated difference next to an accepted site: the gate fails on it, the accepted site is still listed and
	// is not part of the diff.
	sites := []site.Site{s06Site("a.example", site.OpenReasonTransition), s06Site("b.example", site.OpenReasonTransition)}
	_, err := s06Parity(t, sites,
		[]any{s06Today("a.example", false, false, s06Upstream), s06Generated("b.example", false, "10.0.0.1:443")},
		[]any{s06Generated("a.example", false, s06Upstream), s06Generated("b.example", false, "10.0.0.2:443")})
	var perr *ParityError
	if !errors.As(err, &perr) {
		t.Fatalf("err = %v, want *ParityError", err)
	}
	if !strings.Contains(perr.Diff, "b.example") || strings.Contains(perr.Diff, "host=a.example") {
		t.Errorf("diff must name only the unrelated difference:\n%s", perr.Diff)
	}
	if len(perr.Accepted) != 1 || perr.Accepted[0].Class != AcceptedS06OpenStart || perr.Accepted[0].Hosts[0] != "a.example" {
		t.Errorf("accepted next to a failure = %+v, want a.example listed", perr.Accepted)
	}
}

// TestParity_NarrowerAccessReportedSeparately: a generated block that lets fewer sources reach the same target
// than today's still fails the gate and is reported as a narrowing, with both source sets.
func TestParity_NarrowerAccessReportedSeparately(t *testing.T) {
	transition := []site.Site{s06Site("a.example", site.OpenReasonTransition)}
	cases := []struct {
		name               string
		today, gen         []any
		wantToday, wantGen []string
	}{
		{"open today, source-gated generated",
			[]any{s06Generated("a.example", false, s06Upstream)}, []any{s06Closed("a.example", []string{"100.64.0.0/10"})},
			[]string{"*"}, []string{"100.64.0.0/10"}},
		{"tailnet + free sources today, tailnet only generated",
			[]any{s06Today("a.example", false, false, s06Upstream)}, []any{s06Closed("a.example", []string{"100.64.0.0/10"})},
			append([]string{"100.64.0.0/10"}, s06Serbest...), []string{"100.64.0.0/10"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s06Parity(t, transition, tc.today, tc.gen)
			var perr *ParityError
			if !errors.As(err, &perr) {
				t.Fatalf("err = %v, want *ParityError", err)
			}
			if perr.Diff == "" || len(perr.Accepted) != 0 {
				t.Errorf("a narrowing is a failure, never accepted: diff %q accepted %+v", perr.Diff, perr.Accepted)
			}
			if len(perr.Narrower) != 1 || !slices.Equal(perr.Narrower[0].Hosts, []string{"a.example"}) {
				t.Fatalf("narrower = %+v, want a.example", perr.Narrower)
			}
			slices.Sort(tc.wantToday)
			if n := perr.Narrower[0]; !slices.Equal(n.TodaySources, tc.wantToday) || !slices.Equal(n.GeneratedSources, tc.wantGen) {
				t.Errorf("narrower = %+v, want today %v generated %v", n, tc.wantToday, tc.wantGen)
			}
			if !strings.Contains(perr.Error(), "narrower") || !strings.Contains(perr.Error(), "a.example") {
				t.Errorf("the error must name the narrowing separately: %v", perr)
			}
		})
	}
}

// TestParity_S06OutsideRoutesMustStayEqual (review R2-M1): the accepted class covers the routes inside the site block's
// subroute only. A difference in the block's own fields (terminal, match, other handler fields) is not part of it: it
// stays a diff instead of being replaced by today's whole block.
func TestParity_S06OutsideRoutesMustStayEqual(t *testing.T) {
	transition := []site.Site{s06Site("a.example", site.OpenReasonTransition)}
	mut := func(f func(m map[string]any)) map[string]any {
		g := s06Generated("a.example", false, s06Upstream)
		f(g)
		return g
	}
	cases := []struct {
		name string
		gen  map[string]any
	}{
		{"terminal changed", mut(func(m map[string]any) { m["terminal"] = false })},
		{"terminal missing", mut(func(m map[string]any) { delete(m, "terminal") })},
		{"another host matcher", mut(func(m map[string]any) {
			m["match"] = []any{map[string]any{"host": []any{"a.example", "extra.example"}}}
		})},
		{"extra field on the subroute handler", mut(func(m map[string]any) {
			m["handle"].([]any)[0].(map[string]any)["errors"] = map[string]any{"routes": []any{}}
		})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := s06Parity(t, transition, []any{s06Today("a.example", false, false, s06Upstream)}, []any{tc.gen})
			var perr *ParityError
			if !errors.As(err, &perr) {
				t.Fatalf("err = %v (result %+v), want *ParityError: a change outside the routes must not be accepted", err, res)
			}
			if len(perr.Accepted) != 0 || len(res.Accepted) != 0 {
				t.Errorf("nothing may be accepted for %s: %+v", tc.name, perr.Accepted)
			}
			if !strings.Contains(perr.Diff, "a.example") {
				t.Errorf("the diff must name the site:\n%s", perr.Diff)
			}
		})
	}
}
