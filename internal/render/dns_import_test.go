package render

import (
	"reflect"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/internal/dns"
	"github.com/nesiler/tagcess/internal/site"
)

// TestImportManualDNS: the first import reads today's extra-records file and keeps what is not
// derived from a site as manual records. A file tagcess cannot trust is an error (fail closed):
// invalid records and a manual record that collides with a site host are refused with a message
// that names the record.
func TestImportManualDNS(t *testing.T) {
	const vpn = "100.64.0.4"
	cfg := DNSConfig{AValue: vpn}
	sites := []site.Site{
		{Hosts: []string{"monitor.example.com"}, Kind: site.KindRole, MagicDNS: true},
		{Hosts: []string{"hs.example.com"}, Kind: site.KindSystem, MagicDNS: false},
	}
	body := func(recs ...dns.Record) string {
		s, err := dns.Marshal(recs)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		return s
	}
	a := func(name, value string) dns.Record { return dns.Record{Name: name, Type: dns.TypeA, Value: value} }

	t.Run("keeps the non-site records", func(t *testing.T) {
		content := body(a("monitor.example.com", vpn), a("legacy.example.com", "100.64.0.9"))
		got, err := ImportManualDNS(content, true, sites, cfg)
		if err != nil {
			t.Fatalf("ImportManualDNS: %v", err)
		}
		want := []dns.Record{a("legacy.example.com", "100.64.0.9")}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("manual = %+v, want %+v", got, want)
		}
	})

	t.Run("a missing or blank file has no manual records", func(t *testing.T) {
		for name, tc := range map[string]struct {
			content string
			exists  bool
		}{"missing": {"", false}, "blank": {" \n", true}} {
			got, err := ImportManualDNS(tc.content, tc.exists, sites, cfg)
			if err != nil || len(got) != 0 {
				t.Errorf("%s: manual = %+v, %v, want none", name, got, err)
			}
		}
	})

	t.Run("a file that does not parse is an error", func(t *testing.T) {
		if _, err := ImportManualDNS("{not json", true, sites, cfg); err == nil {
			t.Error("accepted a corrupt file")
		}
	})

	t.Run("an invalid record is an error", func(t *testing.T) {
		content := `[{"name":"Bad Name","type":"A","value":"100.64.0.9"}]`
		if _, err := ImportManualDNS(content, true, sites, cfg); err == nil {
			t.Error("accepted an invalid record")
		}
	})

	t.Run("a different value for a MagicDNS site host is a conflict", func(t *testing.T) {
		content := body(a("monitor.example.com", "10.9.9.9"))
		_, err := ImportManualDNS(content, true, sites, cfg)
		if err == nil {
			t.Fatal("accepted a record that disagrees with a site host")
		}
		if !strings.Contains(err.Error(), "monitor.example.com") || !strings.Contains(err.Error(), "10.9.9.9") {
			t.Errorf("error %q does not show the difference", err)
		}
	})

	t.Run("two values for one manual name are a conflict", func(t *testing.T) {
		content := body(a("legacy.example.com", "100.64.0.9"), a("legacy.example.com", "100.64.0.8"))
		if _, err := ImportManualDNS(content, true, sites, cfg); err == nil {
			t.Error("accepted two values for one name")
		}
	})

	t.Run("a bad vpn address is an error", func(t *testing.T) {
		if _, err := ImportManualDNS("[]", true, sites, DNSConfig{AValue: "nope"}); err == nil {
			t.Error("accepted a non-IPv4 vpn address")
		}
	})
}
