package render

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/nesiler/tagcess/internal/site"
)

// First-import parity (G-01, S-03.2, ADR 0010 m.6/m.8). Before the first apply, the Caddyfile
// generated from the seeded records must mean the same as today's file: both go through
// `caddy adapt` and the JSON documents are compared after the one normalization Caddy's adapter
// needs (multi-host lists come out in map order). The gate is the first apply only; once it has
// passed, later site changes are never compared with today's file. A mismatch, or any failure to
// adapt or compare, blocks the apply and shows the difference (fail closed).

// Adapter turns a Caddyfile into Caddy's JSON config, as `caddy adapt` does. A real adapter
// runs the pinned Caddy (v2.8.4); tests pass a stub.
type Adapter func(ctx context.Context, caddyfile string) ([]byte, error)

// ParityError is returned when the generated Caddyfile is not equivalent to today's. Diff lists
// the differing JSON paths for the operator. Narrower names the sites whose generated block lets
// fewer sources reach the same target than today's (their lines are in Diff too); Accepted lists
// the sites of the accepted difference class found next to the failure, so nothing is hidden.
type ParityError struct {
	Diff     string
	Narrower []NarrowerDifference
	Accepted []AcceptedDifference
}

func (e *ParityError) Error() string {
	msg := "caddy parity: the generated Caddyfile differs from today's file; the first apply is blocked:\n"
	for _, n := range e.Narrower {
		msg += fmt.Sprintf("access would be narrower for %s: today %s, generated %s\n",
			strings.Join(n.Hosts, ","), strings.Join(n.TodaySources, " "), strings.Join(n.GeneratedSources, " "))
	}
	return msg + e.Diff
}

// AcceptedS06OpenStart is the one difference class the first-import gate accepts (developer
// decision 2026-10-07): adoption starts with the S-06 key open, and tagcess
// has no source restriction for open sites. Today's existing installation block lets the tailnet and the free
// sources (WireGuard, the servers' own addresses) through and answers every other source with 403;
// the generated open block sends every source to the same target. The class is decided for the
// open/transition sites; it covers open/intentional sites too ([Ö] 2026-10-07: the existing installation's two
// vpn_only sites, rendered by the same S-06 rule, so the consequence is the same). During the
// transition the internal sites are therefore reachable from the internet too, until the
// developer closes S-06 from the UI (then the tailnet only).
const AcceptedS06OpenStart = "s06_open_start"

// s06OpenStartDescription names the class for the operator (verify report, guide, CLI).
const s06OpenStartDescription = "S-06 açık başlangıç: kaynak kısıtı (tailnet + serbest kaynaklar, diğerleri 403) tagcess'te yok"

// tailnetRange is the tailnet source today's existing blocks match first.
const tailnetRange = "100.64.0.0/10"

// AcceptedDifference is one site block whose only difference is the accepted class.
type AcceptedDifference struct {
	Class        string   `json:"class"`
	Description  string   `json:"description"`
	Hosts        []string `json:"hosts"`
	OpenReason   string   `json:"open_reason"`   // the site record's open reason (transition or intentional)
	TodaySources []string `json:"today_sources"` // the sources that reach the target today; every other gets 403
}

// NarrowerDifference is one site block whose generated form lets fewer sources reach the same
// target than today's. It is never accepted; it is named so the operator sees that access would
// shrink, not only that the text differs. "*" stands for every source.
type NarrowerDifference struct {
	Hosts            []string `json:"hosts"`
	TodaySources     []string `json:"today_sources"`
	GeneratedSources []string `json:"generated_sources"`
}

// SeedParityResult is a passed first-import comparison: Accepted lists the site blocks that differ
// only by the accepted class (empty when the files are equal).
type SeedParityResult struct {
	Accepted []AcceptedDifference
}

// FirstImportState is the persisted gate state (site.Store implements it).
type FirstImportState interface {
	FirstImportPending(ctx context.Context) (bool, error)
}

// maxParityDiffLines bounds the diff shown to the operator.
const maxParityDiffLines = 40

// What Caddy's adapter emits in an order or with labels that carry no meaning, and so is
// normalized away before comparing (R1 B-02 and the first real comparison, F2-007):
//   - string lists of multi-host blocks come out in map order: sorted;
//   - the top-level server routes (one per host block, hosts are unique across blocks, each is
//     terminal) are ordered by the adapter from the block order: keyed or sorted by their host
//     list (keyHostRoutes; nested route lists keep their order);
//   - TLS connection policies (one per host block) are ordered like the routes: sorted by their SNI
//     list; certificate tags (cert0, cert1, ...) are numbered by the order the blocks name their
//     certificates, so each tag is replaced by the certificate file it stands for;
//   - route "group" labels are numbered by the adapter's internal counters: renamed g0, g1, ...
//     in order of first appearance. Only which routes share a group matters (the first match in
//     a group wins), and the renaming preserves exactly that;
//   - the top-level host routes are then keyed by their host list (F6 parity, M6), so the two
//     documents are compared site block by site block: a block on one side only is one
//     difference named by its host instead of a positional cascade through every later block,
//     and the group labels are renamed afresh inside each block so an extra block cannot
//     renumber the others (a group only relates routes of the same list).
//
// Everything else, including the order of handlers and nested routes, stays significant.
//
// listKeysToSort are the JSON keys whose string arrays carry no order: the ones Caddy's adapter
// emits in map order for multi-host blocks (R1 B-02: route host matchers, TLS connection policy
// SNI lists and automation policy subjects) and IP range lists (remote_ip/client_ip "ranges"
// match when any range contains the address; the zitadel internal sources come in the
// operator's order, M6).
var listKeysToSort = map[string]bool{"host": true, "sni": true, "subjects": true, "ranges": true}

// ParityDiff adapts both Caddyfiles and returns the differences between the normalized JSON
// documents, empty when they are equal.
func ParityDiff(ctx context.Context, adapt Adapter, current, generated string) (string, error) {
	return parityDiff(ctx, adapt, current, generated, nil)
}

// parityDiff is ParityDiff with an optional filter that runs on both normalized documents
// before they are compared (today's file read-only, the generated one may be edited).
func parityDiff(ctx context.Context, adapt Adapter, current, generated string, filter func(cur, gen any)) (string, error) {
	if adapt == nil {
		return "", fmt.Errorf("caddy parity: no adapter: refusing to skip the comparison")
	}
	cur, err := adaptNormalized(ctx, adapt, current)
	if err != nil {
		return "", fmt.Errorf("caddy parity: today's file: %w", err)
	}
	return parityDiffAdapted(ctx, adapt, cur, generated, filter)
}

// parityDiffAdapted is parityDiff with today's document already adapted and normalized.
func parityDiffAdapted(ctx context.Context, adapt Adapter, cur any, generated string, filter func(cur, gen any)) (string, error) {
	gen, err := adaptNormalized(ctx, adapt, generated)
	if err != nil {
		return "", fmt.Errorf("caddy parity: generated file: %w", err)
	}
	if filter != nil {
		filter(cur, gen)
	}
	var diffs []string
	diffJSON("", cur, gen, &diffs)
	if len(diffs) == 0 {
		return "", nil
	}
	if len(diffs) > maxParityDiffLines {
		more := len(diffs) - maxParityDiffLines
		diffs = append(diffs[:maxParityDiffLines], fmt.Sprintf("... and %d more differences", more))
	}
	return strings.Join(diffs, "\n"), nil
}

func adaptNormalized(ctx context.Context, adapt Adapter, caddyfile string) (any, error) {
	raw, err := adapt(ctx, caddyfile)
	if err != nil {
		return nil, fmt.Errorf("adapt: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("adapt output is not JSON: %w", err)
	}
	if obj, ok := doc.(map[string]any); !ok || len(obj) == 0 {
		return nil, fmt.Errorf("adapt output is not a non-empty JSON object")
	}
	resolveCertTags(doc)
	normalizeLists("", doc)
	renameGroups(doc, map[string]string{})
	keyHostRoutes(doc)
	return doc, nil
}

// hostRouteKeyPrefix starts the key of a keyed host route; it reads as the route's matcher in a
// diff path (".../routes/host=a.example,b.example/handle/0/...").
const hostRouteKeyPrefix = "host="

// keyHostRoutes replaces, in place, the top-level routes list of every HTTP server
// (apps.http.servers.*.routes) that holds host routes only (allHostRoutes: one route per site
// block, matched by its host list alone) with unique host lists by an object keyed by
// hostRouteKeyPrefix + the sorted host list. Inside each keyed route the group labels are renamed
// from g0 again. Routes that share a host list are left as an ordered list: their order decides
// which one matches first. Nested route lists are never keyed: inside a site block the route
// order is significant.
func keyHostRoutes(doc any) {
	root, _ := doc.(map[string]any)
	apps, _ := root["apps"].(map[string]any)
	httpApp, _ := apps["http"].(map[string]any)
	servers, _ := httpApp["servers"].(map[string]any)
	for _, srv := range servers {
		obj, _ := srv.(map[string]any)
		list, ok := obj["routes"].([]any)
		if !ok || !allHostRoutes(list) {
			continue
		}
		if keyed, ok := hostRouteMap(list); ok {
			obj["routes"] = keyed
			for _, route := range keyed {
				renameGroups(route, map[string]string{})
			}
			continue
		}
		// Shared host lists: the blocks are still ordered by host; routes of one host list keep their order.
		sort.SliceStable(list, func(i, j int) bool { return routeHostKey(list[i]) < routeHostKey(list[j]) })
		renameGroups(list, map[string]string{})
	}
}

// hostRouteMap keys host routes by their host list; false when two routes share one.
func hostRouteMap(list []any) (map[string]any, bool) {
	keyed := make(map[string]any, len(list))
	for _, route := range list {
		key := hostRouteKeyPrefix + routeHostKey(route)
		if _, dup := keyed[key]; dup {
			return nil, false
		}
		keyed[key] = route
	}
	return keyed, true
}

// normalizeLists sorts the string arrays under listKeysToSort, in place, anywhere in the tree.
func normalizeLists(key string, v any) {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			normalizeLists(k, child)
		}
	case []any:
		if listKeysToSort[key] && allStrings(t) {
			sort.Slice(t, func(i, j int) bool { return t[i].(string) < t[j].(string) })
			return
		}
		for _, child := range t {
			normalizeLists("", child)
		}
		if key == "tls_connection_policies" {
			sort.SliceStable(t, func(i, j int) bool { return policySNIKey(t[i]) < policySNIKey(t[j]) })
		}
	}
}

// routeHostKey is the joined (already sorted) host list of a host route, "" for any other value.
func routeHostKey(route any) string {
	obj, _ := route.(map[string]any)
	matches, _ := obj["match"].([]any)
	if len(matches) != 1 {
		return ""
	}
	m, _ := matches[0].(map[string]any)
	hosts, _ := m["host"].([]any)
	parts := make([]string, 0, len(hosts))
	for _, h := range hosts {
		str, _ := h.(string)
		parts = append(parts, str)
	}
	return strings.Join(parts, ",")
}

// policySNIKey is the joined (already sorted) SNI list of a TLS connection policy.
func policySNIKey(policy any) string {
	obj, _ := policy.(map[string]any)
	match, _ := obj["match"].(map[string]any)
	sni, _ := match["sni"].([]any)
	parts := make([]string, 0, len(sni))
	for _, h := range sni {
		str, _ := h.(string)
		parts = append(parts, str)
	}
	return strings.Join(parts, ",")
}

// resolveCertTags replaces the adapter's numbered certificate tags by the certificate file they
// name: the load_files entries lose their "tags", every any_tag list in a connection policy
// becomes the sorted list of certificate paths, and load_files is sorted by path.
func resolveCertTags(doc any) {
	root, _ := doc.(map[string]any)
	apps, _ := root["apps"].(map[string]any)
	tlsApp, _ := apps["tls"].(map[string]any)
	certs, _ := tlsApp["certificates"].(map[string]any)
	files, _ := certs["load_files"].([]any)
	byTag := make(map[string]string)
	for _, f := range files {
		entry, _ := f.(map[string]any)
		path, _ := entry["certificate"].(string)
		tags, _ := entry["tags"].([]any)
		for _, tag := range tags {
			if name, ok := tag.(string); ok {
				byTag[name] = path
			}
		}
		delete(entry, "tags")
	}
	sort.SliceStable(files, func(i, j int) bool {
		a, _ := files[i].(map[string]any)
		b, _ := files[j].(map[string]any)
		return fmt.Sprint(a["certificate"], a["key"]) < fmt.Sprint(b["certificate"], b["key"])
	})
	replaceAnyTag(doc, byTag)
}

func replaceAnyTag(v any, byTag map[string]string) {
	switch t := v.(type) {
	case map[string]any:
		if tags, ok := t["any_tag"].([]any); ok {
			for i, tag := range tags {
				if name, ok := tag.(string); ok {
					if path, found := byTag[name]; found {
						tags[i] = path
					}
				}
			}
			sort.Slice(tags, func(i, j int) bool { return fmt.Sprint(tags[i]) < fmt.Sprint(tags[j]) })
		}
		for _, child := range t {
			replaceAnyTag(child, byTag)
		}
	case []any:
		for _, child := range t {
			replaceAnyTag(child, byTag)
		}
	}
}

// allHostRoutes reports whether every element is a route matched by a host list alone.
func allHostRoutes(list []any) bool {
	if len(list) == 0 {
		return false
	}
	for _, r := range list {
		obj, ok := r.(map[string]any)
		if !ok {
			return false
		}
		matches, _ := obj["match"].([]any)
		if len(matches) != 1 {
			return false
		}
		m, _ := matches[0].(map[string]any)
		if _, ok := m["host"]; !ok || len(m) != 1 {
			return false
		}
		if routeHostKey(r) == "" {
			return false
		}
	}
	return true
}

// renameGroups replaces every route "group" label by its order of first appearance.
func renameGroups(v any, names map[string]string) {
	switch t := v.(type) {
	case map[string]any:
		if g, ok := t["group"].(string); ok {
			if _, seen := names[g]; !seen {
				names[g] = fmt.Sprintf("g%d", len(names))
			}
			t["group"] = names[g]
		}
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			renameGroups(t[k], names)
		}
	case []any:
		for _, child := range t {
			renameGroups(child, names)
		}
	}
}

func allStrings(list []any) bool {
	for _, e := range list {
		if _, ok := e.(string); !ok {
			return false
		}
	}
	return true
}

// diffJSON appends one line per difference between a (today's) and b (generated).
func diffJSON(path string, a, b any, out *[]string) {
	switch av := a.(type) {
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok {
			*out = append(*out, fmt.Sprintf("%s: today %s, generated %s", pathName(path), brief(a), brief(b)))
			return
		}
		keys := make([]string, 0, len(av)+len(bv))
		for k := range av {
			keys = append(keys, k)
		}
		for k := range bv {
			if _, dup := av[k]; !dup {
				keys = append(keys, k)
			}
		}
		slices.Sort(keys)
		for _, k := range keys {
			sub := path + "/" + k
			x, inA := av[k]
			y, inB := bv[k]
			switch {
			case !inB:
				*out = append(*out, fmt.Sprintf("%s: only in today's file: %s", sub, brief(x)))
			case !inA:
				*out = append(*out, fmt.Sprintf("%s: only in the generated file: %s", sub, brief(y)))
			default:
				diffJSON(sub, x, y, out)
			}
		}
	case []any:
		bv, ok := b.([]any)
		if !ok {
			*out = append(*out, fmt.Sprintf("%s: today %s, generated %s", pathName(path), brief(a), brief(b)))
			return
		}
		for i := 0; i < len(av) || i < len(bv); i++ {
			sub := fmt.Sprintf("%s/%d", path, i)
			switch {
			case i >= len(bv):
				*out = append(*out, fmt.Sprintf("%s: only in today's file: %s", sub, brief(av[i])))
			case i >= len(av):
				*out = append(*out, fmt.Sprintf("%s: only in the generated file: %s", sub, brief(bv[i])))
			default:
				diffJSON(sub, av[i], bv[i], out)
			}
		}
	default:
		if !jsonEqual(a, b) {
			*out = append(*out, fmt.Sprintf("%s: today %s, generated %s", pathName(path), brief(a), brief(b)))
		}
	}
}

func pathName(p string) string {
	if p == "" {
		return "/"
	}
	return p
}

func jsonEqual(a, b any) bool {
	x, errA := json.Marshal(a)
	y, errB := json.Marshal(b)
	return errA == nil && errB == nil && bytes.Equal(x, y)
}

func brief(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return "?"
	}
	if len(raw) > 160 {
		return string(raw[:160]) + "..."
	}
	return string(raw)
}

// dropKnownAdditions removes from the generated document the one difference the developer
// accepted as an exception to S-03.2/G-01.1 (2026-10-06, proposal [Ö] in ADR 0010 m.6): the
// friendly 403 page. It is dropped only from a reverse_proxy handler's handle_response list, only
// when it is exactly the page the renderer writes (match.status_code [403]; routes holding exactly
// a headers handler with the HTML Content-Type and a static_response with status 403 and body
// caddyForbiddenPage(signOut)), and only where today's document has no entry at that position.
// Any other deviation stays in the document and is reported by the normal comparison.
func dropKnownAdditions(cur, gen any, signOut string) {
	switch g := gen.(type) {
	case map[string]any:
		c, _ := cur.(map[string]any)
		if g["handler"] == "reverse_proxy" {
			if list, ok := g["handle_response"].([]any); ok {
				var curList []any
				if c != nil {
					curList, _ = c["handle_response"].([]any)
				}
				kept := make([]any, 0, len(list))
				for i, entry := range list {
					if i >= len(curList) && isFriendlyForbidden(entry, signOut) {
						continue
					}
					kept = append(kept, entry)
				}
				if len(kept) != len(list) {
					if len(kept) == 0 {
						delete(g, "handle_response")
					} else {
						g["handle_response"] = kept
					}
				}
			}
		}
		for k, child := range g {
			var cc any
			if c != nil {
				cc = c[k]
			}
			dropKnownAdditions(cc, child, signOut)
		}
	case []any:
		c, _ := cur.([]any)
		for i, child := range g {
			var cc any
			if i < len(c) {
				cc = c[i]
			}
			dropKnownAdditions(cc, child, signOut)
		}
	}
}

// isFriendlyForbidden reports whether entry is exactly the generated friendly 403 response.
func isFriendlyForbidden(entry any, signOut string) bool {
	want := map[string]any{
		"match": map[string]any{"status_code": []any{json.Number("403")}},
		"routes": []any{map[string]any{"handle": []any{
			map[string]any{
				"handler":  "headers",
				"response": map[string]any{"set": map[string]any{"Content-Type": []any{"text/html; charset=utf-8"}}},
			},
			map[string]any{
				"handler":     "static_response",
				"status_code": json.Number("403"),
				"body":        caddyForbiddenPage(signOut),
			},
		}}},
	}
	return jsonEqual(entry, want)
}

// CheckSeedParity renders the Caddyfile for the given records the way today's file is written
// (S-06 key open, the first-import state) and compares it with today's file. The tagcess system
// block is compared only when today's file already serves one of its hosts (the installer's
// caddy_ui phase adds deploy/caddy/tagcess.caddy before the first import, F6-005); otherwise it
// does not exist in today's file and is left out; its text has its own golden test (F2-005).
// A nil result means equivalent, or different only by the accepted class (SeedParity reports
// which sites); *ParityError carries the difference; any other error means the comparison could
// not be made, which blocks the apply as well.
func CheckSeedParity(ctx context.Context, adapt Adapter, current string, sites []site.Site, cfg CaddyConfig) error {
	_, err := SeedParity(ctx, adapt, current, sites, cfg)
	return err
}

// SeedParity is CheckSeedParity with the passed result: the site blocks that differ only by the
// accepted class (AcceptedS06OpenStart). Every other difference fails; a narrowing is named in
// ParityError.Narrower as well.
func SeedParity(ctx context.Context, adapt Adapter, current string, sites []site.Site, cfg CaddyConfig) (SeedParityResult, error) {
	cfg.S06Open = true
	if adapt == nil {
		return SeedParityResult{}, fmt.Errorf("caddy parity: no adapter: refusing to skip the comparison")
	}
	cur, err := adaptNormalized(ctx, adapt, current)
	if err != nil {
		return SeedParityResult{}, fmt.Errorf("caddy parity: today's file: %w", err)
	}
	served := make(map[string]bool)
	collectHosts(cur, served)
	compared := make([]site.Site, 0, len(sites))
	openReason := make(map[string]string)
	for _, s := range sites {
		if s.Kind == site.KindSystem && s.SystemTemplate == site.TemplateTagcess && !slices.ContainsFunc(s.Hosts, func(h string) bool { return served[h] }) {
			continue
		}
		if s.Kind == site.KindOpen {
			hosts := slices.Clone(s.Hosts)
			slices.Sort(hosts)
			openReason[hostRouteKeyPrefix+strings.Join(hosts, ",")] = s.OpenReason
		}
		compared = append(compared, s)
	}
	generated, err := RenderCaddyfile(compared, cfg)
	if err != nil {
		return SeedParityResult{}, fmt.Errorf("caddy parity: render: %w", err)
	}
	signOut, err := SignOutPath(cfg.ZitadelIssuer, cfg.GateClientID, cfg.LogoutReturnURL)
	if err != nil {
		return SeedParityResult{}, fmt.Errorf("caddy parity: %w", err)
	}
	var accepted []AcceptedDifference
	var narrower []NarrowerDifference
	diff, err := parityDiffAdapted(ctx, adapt, cur, generated, func(cur, gen any) {
		dropKnownAdditions(cur, gen, signOut)
		accepted, narrower = classifySourceGates(cur, gen, openReason)
	})
	if err != nil {
		return SeedParityResult{}, err
	}
	if diff != "" {
		return SeedParityResult{}, &ParityError{Diff: diff, Narrower: narrower, Accepted: accepted}
	}
	return SeedParityResult{Accepted: accepted}, nil
}

// classifySourceGates compares today's and the generated top-level site routes (keyed by
// keyHostRoutes) by who may reach the target. A block of an open site (openReason, by route key;
// both reasons render through the same S-06 rule, [Ö] 2026-10-07) that differs only because today's restricts the sources to the tailnet and the free
// sources (403 for every other) while the generated one sends every source to the same target is
// the accepted class: the generated block's routes are replaced by today's (so it leaves no diff line; match,
// terminal and the handler's other fields must already be equal) and the block is returned in accepted. A generated block that lets fewer sources reach the same
// target is returned in narrower and left as it is (it stays a diff). Today's document is only
// read.
func classifySourceGates(cur, gen any, openReason map[string]string) ([]AcceptedDifference, []NarrowerDifference) {
	var accepted []AcceptedDifference
	var narrower []NarrowerDifference
	curRoutes, genRoutes := serverRouteMaps(cur), serverRouteMaps(gen)
	servers := make([]string, 0, len(curRoutes))
	for name := range curRoutes {
		servers = append(servers, name)
	}
	slices.Sort(servers)
	for _, name := range servers {
		c, g := curRoutes[name], genRoutes[name]
		if g == nil {
			continue
		}
		keys := make([]string, 0, len(c))
		for k := range c {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, key := range keys {
			gr, ok := g[key]
			if !ok || jsonEqual(c[key], gr) {
				continue
			}
			hosts := strings.Split(strings.TrimPrefix(key, hostRouteKeyPrefix), ",")
			todayInner, ok1 := siteInnerRoutes(c[key])
			genInner, ok2 := siteInnerRoutes(gr)
			if !ok1 || !ok2 {
				continue
			}
			todayGate, todayIsGate := parseSourceGate(todayInner)
			genGate, genIsGate := parseSourceGate(genInner)
			todayOpen, todayIsOpen := parseOpenTail(todayInner)
			genOpen, genIsOpen := parseOpenTail(genInner)
			switch {
			case todayIsGate && genIsOpen && sameAccess(todayGate.prefix, todayGate.target, genOpen.prefix, genOpen.target):
				// Everything outside the routes list (match, terminal, handler fields) must already be equal: only the
				// verified routes subtree is normalized, never the whole block.
				if reason, open := openReason[key]; open && slices.Contains(todayGate.sources, tailnetRange) && sameSiteShell(c[key], gr) {
					accepted = append(accepted, AcceptedDifference{
						Class: AcceptedS06OpenStart, Description: s06OpenStartDescription,
						Hosts: hosts, OpenReason: reason, TodaySources: todayGate.sources,
					})
					replaceSiteRoutes(gr, todayInner)
				}
			case todayIsOpen && genIsGate && sameAccess(todayOpen.prefix, todayOpen.target, genGate.prefix, genGate.target):
				narrower = append(narrower, NarrowerDifference{Hosts: hosts, TodaySources: []string{"*"}, GeneratedSources: genGate.sources})
			case todayIsGate && genIsGate && sameAccess(todayGate.prefix, todayGate.target, genGate.prefix, genGate.target) &&
				strictSubset(genGate.sources, todayGate.sources):
				narrower = append(narrower, NarrowerDifference{Hosts: hosts, TodaySources: todayGate.sources, GeneratedSources: genGate.sources})
			}
		}
	}
	return accepted, narrower
}

// serverRouteMaps returns each HTTP server's keyed top-level routes (keyHostRoutes), by server name.
func serverRouteMaps(doc any) map[string]map[string]any {
	out := make(map[string]map[string]any)
	root, _ := doc.(map[string]any)
	apps, _ := root["apps"].(map[string]any)
	httpApp, _ := apps["http"].(map[string]any)
	servers, _ := httpApp["servers"].(map[string]any)
	for name, srv := range servers {
		obj, _ := srv.(map[string]any)
		if routes, ok := obj["routes"].(map[string]any); ok {
			out[name] = routes
		}
	}
	return out
}

// siteInnerRoutes returns the routes of a site block's subroute: a host route is exactly
// {match, handle: [subroute{routes}], terminal}; anything else is not classified.
func siteInnerRoutes(route any) ([]any, bool) {
	obj, ok := route.(map[string]any)
	if !ok || !onlyKeys(obj, "match", "handle", "terminal") {
		return nil, false
	}
	return subrouteRoutes(obj["handle"])
}

// sameSiteShell reports whether two host routes (both accepted by siteInnerRoutes) are equal in everything but the routes
// inside their subroute: match, terminal and the subroute handler's other fields.
func sameSiteShell(a, b any) bool {
	return jsonEqual(siteShell(a), siteShell(b))
}

// siteShell is a copy of a host route with the subroute's routes emptied.
func siteShell(route any) any {
	cp := deepCopyJSON(route)
	if obj, ok := cp.(map[string]any); ok {
		if list, ok := obj["handle"].([]any); ok && len(list) == 1 {
			if h, ok := list[0].(map[string]any); ok {
				h["routes"] = nil
			}
		}
	}
	return cp
}

// replaceSiteRoutes sets the routes inside the host route's subroute (a block siteInnerRoutes accepted) to a copy of routes.
func replaceSiteRoutes(route any, routes []any) {
	obj, _ := route.(map[string]any)
	list, _ := obj["handle"].([]any)
	h, _ := list[0].(map[string]any)
	h["routes"] = deepCopyJSON(routes)
}

// subrouteRoutes returns the routes of a handler list that is exactly one subroute.
func subrouteRoutes(handle any) ([]any, bool) {
	list, _ := handle.([]any)
	if len(list) != 1 {
		return nil, false
	}
	h, _ := list[0].(map[string]any)
	if h["handler"] != "subroute" || !onlyKeys(h, "handler", "routes") {
		return nil, false
	}
	routes, ok := h["routes"].([]any)
	return routes, ok
}

// sourceGate is a site block that ends in a source gate: routes (prefix) and then one group of
// `handle @src {...}` branches, each matched by remote_ip alone, closed by an unmatched branch that
// answers 403. Every allowed branch leads to target; sources are their ranges, sorted.
type sourceGate struct {
	prefix  []any
	sources []string
	target  any
}

func parseSourceGate(routes []any) (sourceGate, bool) {
	n := len(routes)
	if n < 2 {
		return sourceGate{}, false
	}
	last, _ := routes[n-1].(map[string]any)
	group, _ := last["group"].(string)
	if group == "" || !onlyKeys(last, "group", "handle") || !isForbidden(routeEffect(last)) {
		return sourceGate{}, false
	}
	i := n - 1
	for i > 0 {
		r, _ := routes[i-1].(map[string]any)
		if r["group"] != group {
			break
		}
		i--
	}
	if i == n-1 {
		return sourceGate{}, false
	}
	for _, r := range routes[:i] {
		if obj, _ := r.(map[string]any); obj["group"] == group {
			return sourceGate{}, false
		}
	}
	gate := sourceGate{prefix: routes[:i]}
	for _, r := range routes[i : n-1] {
		obj, _ := r.(map[string]any)
		ranges, ok := remoteIPOnly(obj["match"])
		if !ok || !onlyKeys(obj, "group", "match", "handle") {
			return sourceGate{}, false
		}
		effect := routeEffect(obj)
		if isForbidden(effect) {
			continue
		}
		if gate.target == nil {
			gate.target = effect
		} else if !effectEqual(gate.target, effect) {
			return sourceGate{}, false
		}
		gate.sources = append(gate.sources, ranges...)
	}
	if gate.target == nil {
		return sourceGate{}, false
	}
	slices.Sort(gate.sources)
	gate.sources = slices.Compact(gate.sources)
	return gate, true
}

// openTail is a site block whose last route, unmatched and ungrouped, serves every source that the
// routes before it (prefix) did not answer.
type openTail struct {
	prefix []any
	target any
}

func parseOpenTail(routes []any) (openTail, bool) {
	n := len(routes)
	if n == 0 {
		return openTail{}, false
	}
	last, _ := routes[n-1].(map[string]any)
	if last == nil || !onlyKeys(last, "handle") {
		return openTail{}, false
	}
	target := routeEffect(last)
	if isForbidden(target) {
		return openTail{}, false
	}
	return openTail{prefix: routes[:n-1], target: target}, true
}

// sameAccess reports whether two blocks have the same routes before their source decision and
// the same target behind it.
func sameAccess(prefixA []any, targetA any, prefixB []any, targetB any) bool {
	return effectEqual(prefixA, prefixB) && effectEqual(targetA, targetB)
}

// routeEffect is what a route does once its matchers passed: its handler list, or, for a handler
// list that is one subroute, the effect of that subroute's routes (routeListEffect).
func routeEffect(route map[string]any) any {
	if routes, ok := subrouteRoutes(route["handle"]); ok {
		return routeListEffect(routes)
	}
	return route["handle"]
}

// routeListEffect is the one effect every request gets from routes when there is one: a single
// unmatched, ungrouped route, or a group of mutually exclusive branches closed by an unmatched
// branch (so every request takes exactly one) whose effects are all equal. Otherwise it is the
// routes themselves.
func routeListEffect(routes []any) any {
	objs := make([]map[string]any, len(routes))
	for i, r := range routes {
		obj, ok := r.(map[string]any)
		if !ok || !onlyKeys(obj, "group", "match", "handle") {
			return routes
		}
		objs[i] = obj
	}
	switch {
	case len(objs) == 1 && objs[0]["match"] == nil && objs[0]["group"] == nil:
		return routeEffect(objs[0])
	case len(objs) >= 2:
		group, _ := objs[0]["group"].(string)
		if group == "" || objs[len(objs)-1]["match"] != nil {
			return routes
		}
		first := routeEffect(objs[0])
		for _, obj := range objs[1:] {
			if obj["group"] != group || !effectEqual(first, routeEffect(obj)) {
				return routes
			}
		}
		return first
	}
	return routes
}

// effectEqual compares two effects with their group labels renumbered from g0 on copies (labels
// only say which routes share a group).
func effectEqual(a, b any) bool {
	x, y := deepCopyJSON(a), deepCopyJSON(b)
	renameGroups(x, map[string]string{})
	renameGroups(y, map[string]string{})
	return jsonEqual(x, y)
}

// isForbidden reports whether an effect is exactly a 403 static response (an optional body).
func isForbidden(effect any) bool {
	list, _ := effect.([]any)
	if len(list) != 1 {
		return false
	}
	h, _ := list[0].(map[string]any)
	code, _ := h["status_code"].(json.Number)
	return h["handler"] == "static_response" && code.String() == "403" && onlyKeys(h, "handler", "status_code", "body")
}

// remoteIPOnly returns the ranges of a matcher list that is exactly one remote_ip matcher.
func remoteIPOnly(match any) ([]string, bool) {
	list, _ := match.([]any)
	if len(list) != 1 {
		return nil, false
	}
	m, _ := list[0].(map[string]any)
	rip, _ := m["remote_ip"].(map[string]any)
	if len(m) != 1 || !onlyKeys(rip, "ranges") {
		return nil, false
	}
	ranges, _ := rip["ranges"].([]any)
	out := make([]string, 0, len(ranges))
	for _, r := range ranges {
		str, ok := r.(string)
		if !ok {
			return nil, false
		}
		out = append(out, str)
	}
	return out, len(out) > 0
}

// onlyKeys reports whether obj is non-nil and has no key outside keys.
func onlyKeys(obj map[string]any, keys ...string) bool {
	if obj == nil {
		return false
	}
	for k := range obj {
		if !slices.Contains(keys, k) {
			return false
		}
	}
	return true
}

// strictSubset reports whether a is a proper subset of b (both sorted, unique).
func strictSubset(a, b []string) bool {
	if len(a) >= len(b) {
		return false
	}
	for _, x := range a {
		if !slices.Contains(b, x) {
			return false
		}
	}
	return true
}

// deepCopyJSON copies a decoded JSON value (numbers stay json.Number).
func deepCopyJSON(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, child := range t {
			out[k] = deepCopyJSON(child)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, child := range t {
			out[i] = deepCopyJSON(child)
		}
		return out
	default:
		return v
	}
}

// collectHosts adds every host of a "host" matcher anywhere in the document to hosts.
func collectHosts(v any, hosts map[string]bool) {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			if list, ok := child.([]any); ok && k == "host" {
				for _, h := range list {
					if str, ok := h.(string); ok {
						hosts[str] = true
					}
				}
				continue
			}
			collectHosts(child, hosts)
		}
	case []any:
		for _, child := range t {
			collectHosts(child, hosts)
		}
	}
}

// GateFirstImport is the apply-time check. While the first-import gate is open it runs
// CheckSeedParity and returns its error, which blocks the apply. When the gate is closed (the
// first apply already passed, or the store was never seeded) it returns nil without comparing
// anything: ordinary site edits are never held against today's file. An unreadable gate state
// is an error and blocks the apply. The caller closes the gate (CompleteFirstImport) after the
// first apply has succeeded.
func GateFirstImport(ctx context.Context, state FirstImportState, adapt Adapter, current string, sites []site.Site, cfg CaddyConfig) error {
	pending, err := state.FirstImportPending(ctx)
	if err != nil {
		return fmt.Errorf("caddy parity: %w", err)
	}
	if !pending {
		return nil
	}
	return CheckSeedParity(ctx, adapt, current, sites, cfg)
}
