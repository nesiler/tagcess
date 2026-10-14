// MagicDNS record rendering (F2-006, ADR 0013, S-03.4): every host of a site
// with MagicDNS on becomes an A record pointing at the global VPN address, the
// manual extra records (H-06) are merged in, and the merged set is refused
// rather than repaired when two records disagree. Like the Caddyfile renderer,
// it re-checks every value before it can reach the file (security.md §5).
package render

import (
	"fmt"
	"strings"

	"github.com/nesiler/tagcess/internal/dns"
	"github.com/nesiler/tagcess/internal/site"
)

// DNSConfig carries the MagicDNS render inputs that do not come from site
// records (ADR 0013 m.3).
type DNSConfig struct {
	// AValue is the IPv4 address every magicdns site host points at
	// (today the vpn-host address 100.64.0.4). It is a global setting: one
	// address for the whole tailnet.
	AValue string
}

// RenderDNSRecords merges the site hosts with the manual extra records and
// returns the sorted, deduplicated record set (ADR 0013 m.3). Every site kind
// contributes (system templates are sites like any other); a site with
// MagicDNS off contributes nothing. The same name and type with two different
// values is an error — Headscale does not check for it (stack-notes), so
// tagcess refuses before anything is written.
func RenderDNSRecords(sites []site.Site, manual []dns.Record, cfg DNSConfig) ([]dns.Record, error) {
	if err := checkAValue(cfg.AValue); err != nil {
		return nil, fmt.Errorf("dns render: %w", err)
	}

	merged := make(map[string]dns.Record)
	add := func(r dns.Record) error {
		if err := r.Validate(); err != nil {
			return err
		}
		key := r.Name + "/" + r.Type
		if old, ok := merged[key]; ok && old.Value != r.Value {
			return fmt.Errorf("dns render: name %s has records with different values (%s and %s); the same name must not point at two addresses (ADR 0013 m.3)",
				r.Name, old.Value, r.Value)
		}
		merged[key] = r
		return nil
	}

	for i, s := range sites {
		switch s.Kind {
		case site.KindRole, site.KindOpen, site.KindSystem:
		default:
			return nil, fmt.Errorf("dns render: site %d: kind %q is not a site kind", i, s.Kind)
		}
		if !s.MagicDNS {
			continue
		}
		for _, h := range s.Hosts {
			if err := add(dns.Record{Name: h, Type: dns.TypeA, Value: cfg.AValue}); err != nil {
				return nil, fmt.Errorf("dns render: site %d: %w", i, err)
			}
		}
	}
	for i, r := range manual {
		if err := add(r); err != nil {
			return nil, fmt.Errorf("dns render: manual record %d: %w", i, err)
		}
	}

	recs := make([]dns.Record, 0, len(merged))
	for _, r := range merged {
		recs = append(recs, r)
	}
	dns.Sort(recs)
	return recs, nil
}

// checkAValue refuses a global A value that is not a plain IPv4 address: the
// site records are all A records, so an IPv6 value can never be written.
func checkAValue(v string) error {
	if err := (dns.Record{Name: "check.example.com", Type: dns.TypeA, Value: v}).Validate(); err != nil {
		return fmt.Errorf("a_value: %q is not an IPv4 address", v)
	}
	return nil
}

// ImportManualDNS reads today's extra-records file for the first import (G-01.1, F2-022) and
// returns the manual records: everything that is not an A record of a MagicDNS site host pointing
// at the VPN address (site.SplitDNSRecords). A missing or blank file has none. The result is
// checked against the sites the way the next render will merge it, so a record that collides with
// a site host (a different value for the same name) is refused here, with the names and values in
// the message, instead of after the first write. A file that does not parse, an invalid record and
// a bad VPN address are refused too (fail closed): importing a guess would drop live records.
func ImportManualDNS(content string, exists bool, sites []site.Site, cfg DNSConfig) ([]dns.Record, error) {
	if err := checkAValue(cfg.AValue); err != nil {
		return nil, fmt.Errorf("dns import: %w", err)
	}
	var old []dns.Record
	if exists && strings.TrimSpace(content) != "" {
		var err error
		if old, err = dns.Unmarshal([]byte(content)); err != nil {
			return nil, fmt.Errorf("dns import: today's file: %w", err)
		}
	}
	manual, err := site.SplitDNSRecords(old, sites, cfg.AValue)
	if err != nil {
		return nil, fmt.Errorf("dns import: %w", err)
	}
	if _, err := RenderDNSRecords(sites, manual, cfg); err != nil {
		return nil, fmt.Errorf("dns import: %w", err)
	}
	return manual, nil
}
