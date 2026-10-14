package render

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/internal/dns"
	"github.com/nesiler/tagcess/internal/site"
)

// stubAdapter returns canned JSON per Caddyfile text, so the comparison logic is tested without
// Caddy. Real Caddy runs in the integration test (seed_parity_integration_test.go).
func stubAdapter(docs map[string]string) Adapter {
	return func(_ context.Context, caddyfile string) ([]byte, error) {
		doc, ok := docs[caddyfile]
		if !ok {
			return nil, errors.New("stub: unexpected caddyfile")
		}
		return []byte(doc), nil
	}
}

type fakeState struct {
	pending bool
	err     error
	reads   int
}

func (f *fakeState) FirstImportPending(context.Context) (bool, error) {
	f.reads++
	return f.pending, f.err
}

// TestSiteSeed_ParityNormalization: multi-host lists that only differ in order are equal (R1
// B-02), every other difference is reported with its JSON path.
func TestSiteSeed_ParityNormalization(t *testing.T) {
	const base = `{"apps":{"http":{"servers":{"srv0":{"routes":[{"match":[{"host":["%s"]}],"handle":[{"handler":"x","n":1}]}]}}},` +
		`"tls":{"automation":{"policies":[{"subjects":["a.example","b.example"]}]}}}}`
	mk := func(hosts, subjects string) string {
		s := strings.Replace(base, "%s", hosts, 1)
		return strings.Replace(s, `"a.example","b.example"`, subjects, 1)
	}
	adapt := stubAdapter(map[string]string{
		"cur":        mk(`a.example","b.example`, `"a.example","b.example"`),
		"reordered":  mk(`b.example","a.example`, `"b.example","a.example"`),
		"otherhosts": mk(`a.example","c.example`, `"a.example","b.example"`),
		"handler":    strings.Replace(mk(`a.example","b.example`, `"a.example","b.example"`), `"n":1`, `"n":2`, 1),
	})
	ctx := context.Background()

	if diff, err := ParityDiff(ctx, adapt, "cur", "reordered"); err != nil || diff != "" {
		t.Errorf("reordered host lists: diff %q, err %v, want equal", diff, err)
	}
	// Site routes are paired by host list (M6): a changed host list is the old block missing and the new
	// block added, both named by their hosts.
	diff, err := ParityDiff(ctx, adapt, "cur", "otherhosts")
	if err != nil || !strings.Contains(diff, "routes/host=a.example,b.example: only in today's file") ||
		!strings.Contains(diff, "routes/host=a.example,c.example: only in the generated file") {
		t.Errorf("a different host: diff %q, err %v", diff, err)
	}
	diff, err = ParityDiff(ctx, adapt, "cur", "handler")
	if err != nil || !strings.Contains(diff, `"n"`) && !strings.Contains(diff, "/n:") {
		t.Errorf("a different handler value: diff %q, err %v", diff, err)
	}
	// Order of non-host arrays (routes, handlers) is meaningful and stays compared.
	two := func(first, second string) string {
		return `{"routes":[{"handle":[{"h":"` + first + `"}]},{"handle":[{"h":"` + second + `"}]}]}`
	}
	adapt = stubAdapter(map[string]string{"ab": two("a", "b"), "ba": two("b", "a")})
	if diff, err := ParityDiff(ctx, adapt, "ab", "ba"); err != nil || diff == "" {
		t.Errorf("route order must stay significant: diff %q, err %v", diff, err)
	}
}

// TestSiteSeed_ParityCertTags: the adapter numbers certificate tags by first use, so the numbers
// carry no meaning; which certificate file a policy selects does.
func TestSiteSeed_ParityCertTags(t *testing.T) {
	mk := func(tagA, tagB, pathA, pathB string) string {
		return `{"apps":{"tls":{"certificates":{"load_files":[` +
			`{"certificate":"` + pathA + `","key":"k1","tags":["` + tagA + `"]},` +
			`{"certificate":"` + pathB + `","key":"k2","tags":["` + tagB + `"]}]}},` +
			`"http":{"servers":{"srv0":{"tls_connection_policies":[` +
			`{"match":{"sni":["b.example"]},"certificate_selection":{"any_tag":["` + tagB + `"]}},` +
			`{"match":{"sni":["a.example"]},"certificate_selection":{"any_tag":["` + tagA + `"]}}]}}}}}`
	}
	adapt := stubAdapter(map[string]string{
		"x":       mk("cert0", "cert1", "/p/a.pem", "/p/b.pem"),
		"renamed": mk("cert1", "cert0", "/p/a.pem", "/p/b.pem"),
		"swapped": `{"apps":{"tls":{"certificates":{"load_files":[` +
			`{"certificate":"/p/a.pem","key":"k1","tags":["cert0"]},{"certificate":"/p/b.pem","key":"k2","tags":["cert1"]}]}},` +
			`"http":{"servers":{"srv0":{"tls_connection_policies":[` +
			`{"match":{"sni":["b.example"]},"certificate_selection":{"any_tag":["cert0"]}},` +
			`{"match":{"sni":["a.example"]},"certificate_selection":{"any_tag":["cert1"]}}]}}}}}`,
	})
	ctx := context.Background()
	if diff, err := ParityDiff(ctx, adapt, "x", "renamed"); err != nil || diff != "" {
		t.Errorf("renumbered tags: diff %q, err %v, want equal", diff, err)
	}
	if diff, err := ParityDiff(ctx, adapt, "x", "swapped"); err != nil || !strings.Contains(diff, "/p/") {
		t.Errorf("a different certificate per host must differ: diff %q, err %v", diff, err)
	}
}

// TestSiteSeed_ParityAdapterFailures: anything that stops the comparison is an error, never a
// pass.
func TestSiteSeed_ParityAdapterFailures(t *testing.T) {
	ctx := context.Background()
	if _, err := ParityDiff(ctx, nil, "a", "b"); err == nil {
		t.Error("a nil adapter was accepted")
	}
	for name, out := range map[string]string{"not json": "oops", "empty object": "{}", "array": "[1]", "empty": ""} {
		adapt := stubAdapter(map[string]string{"a": out, "b": `{"apps":{}}`})
		if diff, err := ParityDiff(ctx, adapt, "a", "b"); err == nil {
			t.Errorf("%s: adapter output accepted, diff %q", name, diff)
		}
		if diff, err := ParityDiff(ctx, adapt, "b", "a"); err == nil {
			t.Errorf("%s (generated side): adapter output accepted, diff %q", name, diff)
		}
	}
	failing := func(context.Context, string) ([]byte, error) { return nil, errors.New("caddy not reachable") }
	if _, err := ParityDiff(ctx, failing, "a", "b"); err == nil || !strings.Contains(err.Error(), "caddy not reachable") {
		t.Errorf("adapter error not surfaced: %v", err)
	}
}

// TestSiteSeed_CaddyfileGolden: the Caddyfile generated from the seed (key open, tagcess block
// included as it will be applied) is deterministic and reviewable.
func TestSiteSeed_CaddyfileGolden(t *testing.T) {
	s := openSeededStore(t)
	sites, err := s.ListSites(context.Background())
	if err != nil {
		t.Fatalf("ListSites: %v", err)
	}
	out, err := RenderCaddyfile(sites, seedParityCfg())
	if err != nil {
		t.Fatalf("RenderCaddyfile: %v", err)
	}
	assertTopLevelBalanced(t, out)
	compareGolden(t, "caddy-seed.golden", out)

	// The same set in reverse order renders the same file.
	rev := make([]site.Site, len(sites))
	for i, st := range sites {
		rev[len(sites)-1-i] = st
	}
	again, err := RenderCaddyfile(rev, seedParityCfg())
	if err != nil || again != out {
		t.Errorf("render depends on the input order (err %v)", err)
	}
}

// TestSiteSeed_ParityGate is AC3: while the first import is pending a mismatch blocks the apply
// and shows the difference; once the first import is complete, the same mismatch (an ordinary
// edit) is not compared with today's file at all.
func TestSiteSeed_ParityGate(t *testing.T) {
	ctx := context.Background()
	s := openSeededStore(t)
	sites, err := s.ListSites(ctx)
	if err != nil {
		t.Fatalf("ListSites: %v", err)
	}
	cfg := seedParityCfg()
	current := "CURRENT"

	// The stub adapts a Caddyfile to a digest of its text; today's file ("CURRENT") adapts like the
	// file generated from the unedited seed, so only an edited record can make them differ.
	docFor := func(caddyfile string) string {
		sum := sha256.Sum256([]byte(caddyfile))
		raw, _ := json.Marshal(map[string]any{"apps": map[string]any{"digest": hex.EncodeToString(sum[:])}})
		return string(raw)
	}
	adapt := func(_ context.Context, caddyfile string) ([]byte, error) {
		if caddyfile == current {
			generated, err := RenderCaddyfile(sitesWithoutTagcess(sites), cfg)
			if err != nil {
				return nil, err
			}
			return []byte(docFor(generated)), nil
		}
		return []byte(docFor(caddyfile)), nil
	}

	t.Run("equal while pending passes", func(t *testing.T) {
		if err := GateFirstImport(ctx, &fakeState{pending: true}, adapt, current, sites, cfg); err != nil {
			t.Errorf("gate blocked an equivalent file: %v", err)
		}
	})

	edited := append([]site.Site(nil), sites...)
	for i := range edited {
		if edited[i].Hosts[0] == "monitor.example.com" {
			edited[i].Roles = []string{"devops"}
			edited[i].APIRules = []site.APIRule{{Type: site.APIRuleHeaderPresent, Value: "Authorization"}}
		}
	}

	t.Run("mismatch while pending blocks and shows the diff", func(t *testing.T) {
		err := GateFirstImport(ctx, &fakeState{pending: true}, adapt, current, edited, cfg)
		var perr *ParityError
		if !errors.As(err, &perr) {
			t.Fatalf("error = %v, want *ParityError", err)
		}
		if !strings.Contains(perr.Diff, "/apps/digest") || !strings.Contains(err.Error(), "blocked") {
			t.Errorf("the error does not show the difference: %v", err)
		}
	})

	t.Run("mismatch after the first import is not a gate", func(t *testing.T) {
		state := &fakeState{pending: false}
		called := false
		spy := func(ctx context.Context, c string) ([]byte, error) { called = true; return adapt(ctx, c) }
		if err := GateFirstImport(ctx, state, spy, current, edited, cfg); err != nil {
			t.Errorf("an ordinary edit was held against today's file: %v", err)
		}
		if called {
			t.Error("the adapter ran although the gate is closed")
		}
	})

	t.Run("an unreadable gate state blocks", func(t *testing.T) {
		err := GateFirstImport(ctx, &fakeState{err: errors.New("db down")}, adapt, current, sites, cfg)
		if err == nil || !strings.Contains(err.Error(), "db down") {
			t.Errorf("gate state error not surfaced: %v", err)
		}
	})

	t.Run("a failing adapter blocks while pending", func(t *testing.T) {
		failing := func(context.Context, string) ([]byte, error) { return nil, errors.New("adapt down") }
		err := GateFirstImport(ctx, &fakeState{pending: true}, failing, current, sites, cfg)
		if err == nil {
			t.Error("the gate passed although nothing could be compared")
		}
		var perr *ParityError
		if errors.As(err, &perr) {
			t.Error("an adapter failure was reported as a parity diff")
		}
	})

	t.Run("a render error blocks", func(t *testing.T) {
		bad := append([]site.Site(nil), sites...)
		bad[0].Roles = []string{"x{y"}
		if err := GateFirstImport(ctx, &fakeState{pending: true}, adapt, current, bad, cfg); err == nil {
			t.Error("the gate passed a record that cannot be rendered")
		}
	})

	t.Run("the state really follows the store", func(t *testing.T) {
		if err := GateFirstImport(ctx, s, adapt, current, edited, cfg); err == nil {
			t.Error("the freshly seeded store did not gate the mismatch")
		}
		if err := s.CompleteFirstImport(ctx); err != nil {
			t.Fatalf("CompleteFirstImport: %v", err)
		}
		if err := GateFirstImport(ctx, s, adapt, current, edited, cfg); err != nil {
			t.Errorf("after the first import the same edit is still gated: %v", err)
		}
	})
}

func sitesWithoutTagcess(sites []site.Site) []site.Site {
	var out []site.Site
	for _, s := range sites {
		if s.SystemTemplate != site.TemplateTagcess {
			out = append(out, s)
		}
	}
	return out
}

// TestSiteSeed_DNSRecordsMatch: the MagicDNS records rendered from the seed equal today's
// extra-records file, and manual (non-site) records survive the import (ADR 0010 "İçe aktarma" 3).
func TestSiteSeed_DNSRecordsMatch(t *testing.T) {
	ctx := context.Background()
	s := openSeededStore(t)
	all, err := s.ListSites(ctx)
	if err != nil {
		t.Fatalf("ListSites: %v", err)
	}
	// Today's file has no tagcess host yet.
	sites := sitesWithoutTagcess(all)
	old, err := dns.Unmarshal([]byte(readFixture(t, seedExtraRecords)))
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(old) != 21 {
		t.Fatalf("fixture has %d records, want 21 (R1 B-05)", len(old))
	}
	manual, err := site.SplitDNSRecords(old, sites, "100.64.0.4")
	if err != nil {
		t.Fatalf("SplitDNSRecords: %v", err)
	}
	if len(manual) != 0 {
		t.Errorf("today's file is entirely site-derived, manual = %+v", manual)
	}
	got, err := RenderDNSRecords(sites, manual, DNSConfig{AValue: "100.64.0.4"})
	if err != nil {
		t.Fatalf("RenderDNSRecords: %v", err)
	}
	dns.Sort(old)
	gotJSON, _ := dns.Marshal(got)
	wantJSON, _ := dns.Marshal(old)
	if gotJSON != wantJSON {
		t.Errorf("rendered records differ from today's file\n got: %s\nwant: %s", gotJSON, wantJSON)
	}

	// A record outside the sites survives the round trip as a manual record.
	extra := append(append([]dns.Record(nil), old...), dns.Record{Name: "old-db.example.com", Type: dns.TypeA, Value: "100.64.0.9"})
	manual, err = site.SplitDNSRecords(extra, sites, "100.64.0.4")
	if err != nil || len(manual) != 1 || manual[0].Name != "old-db.example.com" {
		t.Fatalf("manual = %+v, err %v", manual, err)
	}
	got, err = RenderDNSRecords(sites, manual, DNSConfig{AValue: "100.64.0.4"})
	if err != nil || len(got) != 22 {
		t.Errorf("rendered %d records (err %v), want 22 with the manual one", len(got), err)
	}
}
