// Tests for the MagicDNS record render (F2-006, ADR 0013): the deterministic
// two-space JSON body (AC1), the merge rules for site hosts and manual extra
// records (H-06) and the fail-closed re-checks every record passes before it
// may reach the file (security.md §5).
package render

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/internal/dns"
	"github.com/nesiler/tagcess/internal/site"
)

const testAValue = "100.64.0.4"

// goldSiteSet returns the DNS golden fixture: user sites of both kinds, all
// four system templates and a site with MagicDNS off. The order here is NOT
// the render order.
func dnsGoldSiteSet() []site.Site {
	return []site.Site{
		{
			Hosts: []string{"errors.example.com"}, Kind: site.KindOpen,
			OpenReason: site.OpenReasonTransition, Cert: "le:example.com",
			TargetKind: site.TargetURL, TargetURL: "https://100.64.0.5:30443",
			MagicDNS: true,
		},
		{
			Hosts: []string{"auth.example.com"}, Kind: site.KindSystem,
			SystemTemplate: site.TemplateZitadel, SystemConfig: "{}",
			MagicDNS: true,
		},
		{
			Hosts: []string{"gitlab.internal.example.org"}, Kind: site.KindOpen,
			OpenReason: site.OpenReasonIntentional, Cert: "le:internal.example.org",
			TargetKind: site.TargetURL, TargetURL: "http://100.64.0.4:8080",
			MagicDNS: false, // excluded from the records
		},
		{
			Hosts: []string{"grafana.example.com", "monitor.example.com"},
			Kind:  site.KindRole, Roles: []string{"devops", "developer"},
			Cert: "le:example.com", TargetKind: site.TargetK8s,
			MagicDNS: true,
		},
		{
			Hosts: []string{"wg.example.com"}, Kind: site.KindSystem,
			SystemTemplate: site.TemplateWireGuardUI, SystemConfig: `{"enabled":true}`,
			MagicDNS: true,
		},
		{
			Hosts: []string{"tagcess.example.com"}, Kind: site.KindSystem,
			SystemTemplate: site.TemplateTagcess, SystemConfig: "{}",
			MagicDNS: true,
		},
		{
			Hosts: []string{"hs.example.com"}, Kind: site.KindSystem,
			SystemTemplate: site.TemplateHeadscale, SystemConfig: `{"headplane":true}`,
			MagicDNS: true,
		},
	}
}

func goldManual() []dns.Record {
	return []dns.Record{
		{Name: "gitlab.internal.example.org", Type: "A", Value: "100.64.0.5"},
		{Name: "wiki.example.net", Type: "AAAA", Value: "fd7a:115c:a1e0::1"},
	}
}

func renderDNS(t *testing.T, sites []site.Site, manual []dns.Record) string {
	t.Helper()
	recs, err := RenderDNSRecords(sites, manual, DNSConfig{AValue: testAValue})
	if err != nil {
		t.Fatalf("RenderDNSRecords: %v", err)
	}
	body, err := dns.Marshal(recs)
	if err != nil {
		t.Fatalf("dns.Marshal: %v", err)
	}
	return body
}

// TestDNSRender_Golden is AC1: the same inputs in a different order produce
// the same two-space JSON, and that JSON is pinned by a golden file.
func TestDNSRender_Golden(t *testing.T) {
	set := dnsGoldSiteSet()
	manual := goldManual()

	// A permutation that differs from both the input order and the sorted
	// render order.
	shuffledSites := slices.Clone(set)
	shuffledManual := slices.Clone(manual)
	shuffledSites[0], shuffledSites[4] = shuffledSites[4], shuffledSites[0]
	shuffledSites[1], shuffledSites[6] = shuffledSites[6], shuffledSites[1]
	shuffledManual[0], shuffledManual[1] = shuffledManual[1], shuffledManual[0]

	want := renderDNS(t, set, manual)
	if got := renderDNS(t, shuffledSites, shuffledManual); got != want {
		t.Fatalf("permuted inputs render differently:\n%s\nvs\n%s", got, want)
	}

	golden := "dns-records.golden"
	if *updateGoldens {
		if err := os.WriteFile(filepath.Join("testdata", golden), []byte(want), 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
	}
	file, err := os.ReadFile(filepath.Join("testdata", golden))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if string(file) != want {
		t.Errorf("render does not match the golden file (diff):\n got:\n%s\nwant:\n%s", want, file)
	}

	t.Run("two_space_json_and_sorted", func(t *testing.T) {
		if !strings.Contains(want, "\n  {\n") && !strings.Contains(want, "\n  \"") {
			t.Errorf("body is not two-space indented:\n%s", want)
		}
		recs, err := dns.Unmarshal([]byte(want))
		if err != nil {
			t.Fatalf("own body does not parse: %v", err)
		}
		if !slices.IsSortedFunc(recs, compareRecords) {
			t.Errorf("records are not sorted by name, type, value:\n%s", want)
		}
		if len(recs) == 0 {
			t.Fatal("golden render produced no records")
		}
	})
}

// TestDNSRender_MergeRules pins what the record set contains: every host of a
// magicdns site (system templates included), nothing from a site with
// MagicDNS off, manual extra records merged in, and same-name-same-value
// duplicates collapsed.
func TestDNSRender_MergeRules(t *testing.T) {
	recs, err := RenderDNSRecords(dnsGoldSiteSet(), goldManual(), DNSConfig{AValue: testAValue})
	if err != nil {
		t.Fatalf("RenderDNSRecords: %v", err)
	}
	want := map[string]string{
		"grafana.example.com":         "A " + testAValue,
		"monitor.example.com":         "A " + testAValue,
		"errors.example.com":          "A " + testAValue,
		"auth.example.com":            "A " + testAValue,
		"hs.example.com":              "A " + testAValue,
		"wg.example.com":              "A " + testAValue,
		"tagcess.example.com":         "A " + testAValue,
		"gitlab.internal.example.org": "A 100.64.0.5",
		"wiki.example.net":            "AAAA fd7a:115c:a1e0::1",
	}
	got := map[string]string{}
	for _, r := range recs {
		if _, dup := got[r.Name]; dup {
			t.Errorf("record %q appears twice", r.Name)
		}
		got[r.Name] = r.Type + " " + r.Value
	}
	for name, wantEntry := range want {
		if got[name] != wantEntry {
			t.Errorf("record %s = %q, want %q", name, got[name], wantEntry)
		}
	}
	for name := range got {
		if _, ok := want[name]; !ok {
			t.Errorf("unexpected record %s", name)
		}
	}

	t.Run("same_name_same_value_collapses", func(t *testing.T) {
		manual := append(goldManual(), dns.Record{
			Name: "grafana.example.com", Type: "A", Value: testAValue,
		})
		recs, err := RenderDNSRecords(dnsGoldSiteSet(), manual, DNSConfig{AValue: testAValue})
		if err != nil {
			t.Fatalf("RenderDNSRecords: %v", err)
		}
		n := 0
		for _, r := range recs {
			if r.Name == "grafana.example.com" {
				n++
			}
		}
		if n != 1 {
			t.Errorf("grafana record appears %d times, want exactly once", n)
		}
	})
}

// TestDNSRender_FailClosed refuses every input that could not be written
// safely (security.md §5): conflicts, invalid names, non-IP values, unknown
// types and an invalid global A value are errors, never repaired.
func TestDNSRender_FailClosed(t *testing.T) {
	base := []site.Site{{
		Hosts: []string{"grafana.example.com"}, Kind: site.KindRole,
		Roles: []string{"devops"}, Cert: "le:example.com",
		TargetKind: site.TargetK8s, MagicDNS: true,
	}}
	cases := []struct {
		name   string
		sites  []site.Site
		manual []dns.Record
		cfg    DNSConfig
	}{
		{"conflicting_value", base, []dns.Record{
			{Name: "grafana.example.com", Type: "A", Value: "10.0.0.1"},
		}, DNSConfig{AValue: testAValue}},
		{"manual_name_not_hostname", base, []dns.Record{
			{Name: "not_a_hostname", Type: "A", Value: "10.0.0.1"},
		}, DNSConfig{AValue: testAValue}},
		{"manual_name_trailing_dot", base, []dns.Record{
			{Name: "wiki.example.net.", Type: "A", Value: "10.0.0.1"},
		}, DNSConfig{AValue: testAValue}},
		{"manual_name_uppercase", base, []dns.Record{
			{Name: "Wiki.example.net", Type: "A", Value: "10.0.0.1"},
		}, DNSConfig{AValue: testAValue}},
		{"manual_value_not_an_ip", base, []dns.Record{
			{Name: "wiki.example.net", Type: "A", Value: "not-an-ip"},
		}, DNSConfig{AValue: testAValue}},
		{"manual_type_unsupported", base, []dns.Record{
			{Name: "wiki.example.net", Type: "CNAME", Value: "wiki.example.com"},
		}, DNSConfig{AValue: testAValue}},
		{"manual_value_family_mismatch", base, []dns.Record{
			{Name: "wiki.example.net", Type: "AAAA", Value: "100.64.0.4"},
		}, DNSConfig{AValue: testAValue}},
		{"a_value_not_an_ip", base, nil, DNSConfig{AValue: "vpn-server"}},
		{"a_value_ipv6_for_a_records", base, nil, DNSConfig{AValue: "fd7a:115c:a1e0::1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := RenderDNSRecords(tc.sites, tc.manual, tc.cfg)
			if err == nil {
				t.Fatal("want error, got nil")
			}
		})
	}

	t.Run("conflict_between_two_manual_records", func(t *testing.T) {
		manual := []dns.Record{
			{Name: "wiki.example.net", Type: "A", Value: "10.0.0.1"},
			{Name: "wiki.example.net", Type: "A", Value: "10.0.0.2"},
		}
		if _, err := RenderDNSRecords(nil, manual, DNSConfig{AValue: testAValue}); err == nil {
			t.Fatal("want error, got nil")
		}
	})
}

// compareRecords is the ADR 0013 sort order: name, then type, then value.
func compareRecords(a, b dns.Record) int {
	if c := compareStrings(a.Name, b.Name); c != 0 {
		return c
	}
	if c := compareStrings(a.Type, b.Type); c != 0 {
		return c
	}
	return compareStrings(a.Value, b.Value)
}

func compareStrings(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}
