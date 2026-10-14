package render

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// hostRoute is one top-level site block route as Caddy's adapter writes it: a host matcher, a subroute and
// terminal.
func hostRoute(hosts []string, inner ...any) map[string]any {
	hs := make([]any, len(hosts))
	for i, h := range hosts {
		hs[i] = h
	}
	return map[string]any{
		"match":    []any{map[string]any{"host": hs}},
		"handle":   []any{map[string]any{"handler": "subroute", "routes": inner}},
		"terminal": true,
	}
}

func proxyTo(dial string) map[string]any {
	return map[string]any{"handle": []any{map[string]any{"handler": "reverse_proxy", "upstreams": []any{map[string]any{"dial": dial}}}}}
}

func grouped(group string, inner map[string]any) map[string]any {
	inner["group"] = group
	return inner
}

func serverDoc(routes ...any) string {
	b, _ := json.Marshal(map[string]any{"apps": map[string]any{"http": map[string]any{"servers": map[string]any{
		"srv0": map[string]any{"listen": []any{":443"}, "routes": routes},
	}}}})
	return string(b)
}

// TestParity_HostRoutesPairedByHost (F6 parity, M6): the top-level site routes are compared per host. A site
// block on one side only is exactly one difference named by its host; it never shifts the comparison of the
// other blocks (positional cascade) or renumbers their group labels. A real difference inside a block is still
// reported, with the host in its path.
func TestParity_HostRoutesPairedByHost(t *testing.T) {
	a := func() map[string]any {
		return hostRoute([]string{"a.example"}, grouped("group3", proxyTo("10.0.0.1:443")), grouped("group3", proxyTo("10.0.0.9:443")))
	}
	b := func(dial string) map[string]any {
		return hostRoute([]string{"b.example"}, grouped("group7", proxyTo(dial)), grouped("group7", proxyTo("10.0.0.8:443")))
	}
	extra := hostRoute([]string{"aa.example"}, grouped("group0", proxyTo("127.0.0.1:3000")), grouped("group0", proxyTo("127.0.0.1:8080")))
	adapt := stubAdapter(map[string]string{
		"today":       serverDoc(a(), extra, b("10.0.0.2:443")),
		"generated":   serverDoc(b("10.0.0.2:443"), a()),
		"changed":     serverDoc(b("10.0.0.3:443"), a()),
		"onlyGen":     serverDoc(a(), b("10.0.0.2:443"), hostRoute([]string{"z.example"}, proxyTo("10.0.0.4:443"))),
		"sameAsToday": serverDoc(b("10.0.0.2:443"), extra, a()),
	})
	ctx := context.Background()

	diff, err := ParityDiff(ctx, adapt, "today", "generated")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(diff, "\n")
	if len(lines) != 1 || !strings.Contains(lines[0], "aa.example") || !strings.Contains(lines[0], "only in today's file") {
		t.Fatalf("a block only in today's file must be one difference named by its host, got:\n%s", diff)
	}

	diff, err = ParityDiff(ctx, adapt, "today", "changed")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(diff, "b.example") || !strings.Contains(diff, `"10.0.0.2:443"`) || !strings.Contains(diff, `"10.0.0.3:443"`) {
		t.Fatalf("a changed upstream must be reported with its host and both values, got:\n%s", diff)
	}
	if n := len(strings.Split(diff, "\n")); n != 2 {
		t.Fatalf("want the missing block and the changed dial (2 lines), got %d:\n%s", n, diff)
	}

	diff, err = ParityDiff(ctx, adapt, "generated", "onlyGen")
	if err != nil {
		t.Fatal(err)
	}
	if lines := strings.Split(diff, "\n"); len(lines) != 1 || !strings.Contains(diff, "z.example") || !strings.Contains(diff, "only in the generated file") {
		t.Fatalf("a block only in the generated file must be one difference named by its host, got:\n%s", diff)
	}

	if diff, err := ParityDiff(ctx, adapt, "today", "sameAsToday"); err != nil || diff != "" {
		t.Fatalf("the same blocks in another order are equal: diff %q, err %v", diff, err)
	}
}

// TestParity_HostRoutesKeepGroupMeaning: renaming group labels per block keeps which routes share a group; a
// block whose routes are split into different groups on one side is still a difference.
func TestParity_HostRoutesKeepGroupMeaning(t *testing.T) {
	shared := hostRoute([]string{"a.example"}, grouped("group1", proxyTo("10.0.0.1:443")), grouped("group1", proxyTo("10.0.0.2:443")))
	split := hostRoute([]string{"a.example"}, grouped("group1", proxyTo("10.0.0.1:443")), grouped("group2", proxyTo("10.0.0.2:443")))
	adapt := stubAdapter(map[string]string{"shared": serverDoc(shared), "split": serverDoc(split)})
	diff, err := ParityDiff(context.Background(), adapt, "shared", "split")
	if err != nil || !strings.Contains(diff, "a.example") || !strings.Contains(diff, "group") {
		t.Fatalf("a different grouping must stay a difference: diff %q, err %v", diff, err)
	}
}

// TestParity_DuplicateHostRoutesStayPositional: routes that share a host list are not keyed (the first match
// wins, so their order matters); swapping them stays a difference.
func TestParity_DuplicateHostRoutesStayPositional(t *testing.T) {
	x := hostRoute([]string{"a.example"}, proxyTo("10.0.0.1:443"))
	y := hostRoute([]string{"a.example"}, proxyTo("10.0.0.2:443"))
	adapt := stubAdapter(map[string]string{"xy": serverDoc(x, y), "yx": serverDoc(y, x)})
	if diff, err := ParityDiff(context.Background(), adapt, "xy", "yx"); err != nil || diff == "" {
		t.Fatalf("swapped routes of the same host must differ: diff %q, err %v", diff, err)
	}
}

// TestCheckSeedParity_TagcessBlockOnlyWhenServed (F6 parity, M6): the generated tagcess block takes part in the
// comparison exactly when today's file serves the tagcess host (the installer's caddy_ui phase adds it); a
// today's file without it is compared without it, as before.
func TestCheckSeedParity_TagcessBlockOnlyWhenServed(t *testing.T) {
	ctx := context.Background()
	s := openSeededStore(t)
	sites, err := s.ListSites(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cfg := seedParityCfg()
	route := func(host string) map[string]any { return hostRoute([]string{host}, proxyTo("x")) }
	// The stub adapts every text to its block hosts, which is all this rule looks at.
	adapt := func(_ context.Context, caddyfile string) ([]byte, error) {
		var routes []any
		switch caddyfile {
		case "TODAY":
			routes = []any{route("docs.example.com")}
		case "TODAY+TAGCESS":
			routes = []any{route("docs.example.com"), route(seedTagcessHost)}
		default:
			routes = []any{route("docs.example.com")}
			if strings.Contains(caddyfile, "\n"+seedTagcessHost+" {\n") {
				routes = append(routes, route(seedTagcessHost))
			}
		}
		return []byte(serverDoc(routes...)), nil
	}
	if err := CheckSeedParity(ctx, adapt, "TODAY", sites, cfg); err != nil {
		t.Errorf("today's file without the tagcess block: %v", err)
	}
	if err := CheckSeedParity(ctx, adapt, "TODAY+TAGCESS", sites, cfg); err != nil {
		t.Errorf("today's file with the installed tagcess block: %v", err)
	}
	// Without the tagcess record the installed block is a difference, never ignored.
	err = CheckSeedParity(ctx, adapt, "TODAY+TAGCESS", sitesWithoutTagcess(sites), cfg)
	var perr *ParityError
	if !errors.As(err, &perr) || !strings.Contains(perr.Diff, "host="+seedTagcessHost+": only in today's file") {
		t.Errorf("a tagcess block without a record must be reported: %v", err)
	}
}

// TestParity_RemoteIPRangesAreASet: remote_ip/client_ip ranges match when any range contains the address, so
// their order carries no meaning (the installer writes the zitadel internal sources in the operator's order);
// a different range is still a difference.
func TestParity_RemoteIPRangesAreASet(t *testing.T) {
	gate := func(ranges ...any) map[string]any {
		r := proxyTo("10.0.0.1:443")
		r["match"] = []any{map[string]any{"remote_ip": map[string]any{"ranges": ranges}}}
		return hostRoute([]string{"auth.example"}, r)
	}
	adapt := stubAdapter(map[string]string{
		"a": serverDoc(gate("100.64.0.0/10", "192.0.2.10/32", "2001:db8:10::/64")),
		"b": serverDoc(gate("2001:db8:10::/64", "100.64.0.0/10", "192.0.2.10/32")),
		"c": serverDoc(gate("100.64.0.0/10", "192.0.2.11/32", "2001:db8:10::/64")),
	})
	ctx := context.Background()
	if diff, err := ParityDiff(ctx, adapt, "a", "b"); err != nil || diff != "" {
		t.Errorf("reordered ranges: diff %q, err %v, want equal", diff, err)
	}
	if diff, err := ParityDiff(ctx, adapt, "a", "c"); err != nil || !strings.Contains(diff, "192.0.2.11/32") || !strings.Contains(diff, "auth.example") {
		t.Errorf("a different range must be reported with its host: diff %q, err %v", diff, err)
	}
}

// TestParity_NestedHostRoutesStayPositional (review D2): only the servers' top-level route lists are keyed by
// host. Host-only routes nested inside a site block keep their order: swapping them is a difference.
func TestParity_NestedHostRoutesStayPositional(t *testing.T) {
	route := func(host, dial string) map[string]any {
		r := proxyTo(dial)
		r["match"] = []any{map[string]any{"host": []any{host}}}
		return r
	}
	a, b := route("a.example", "10.0.0.1:443"), route("b.example", "10.0.0.2:443")
	adapt := stubAdapter(map[string]string{
		"ab": serverDoc(hostRoute([]string{"outer.example"}, a, b)),
		"ba": serverDoc(hostRoute([]string{"outer.example"}, b, a)),
	})
	diff, err := ParityDiff(context.Background(), adapt, "ab", "ba")
	if err != nil || diff == "" {
		t.Fatalf("swapped nested host routes must differ: diff %q, err %v", diff, err)
	}
	if strings.Contains(diff, "host=a.example") || strings.Contains(diff, "host=b.example") {
		t.Errorf("nested routes must not be keyed by host:\n%s", diff)
	}
}
