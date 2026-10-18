// Package dns owns the MagicDNS extra-records file (F2-006, ADR 0013, S-03.4): the
// record shape Headscale v0.29.4 reads from dns.extra_records_path, the atomic
// write that keeps the previous file on any error, and the resolver verification
// of the changed names. Rendering the record set from the site records lives in
// internal/render; this package never widens access: a failed write or an
// unconfirmed name is surfaced, never silently ignored.
package dns

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
)

// Record mirrors tailcfg.DNSRecord, the JSON shape Headscale unmarshals from the
// extra-records file (v0.29.4 hscontrol/dns/extrarecords.go readExtraRecordsFromPath).
// The trailing dot of Name is optional for Headscale; tagcess writes names without it.
type Record struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

// The record types tagcess writes. Headscale ignores every other type; tagcess
// refuses them instead, so the file never carries something the VPN clients
// would silently drop (security.md §5 DNS record rule: IPv4 or IPv6 value).
const (
	TypeA    = "A"
	TypeAAAA = "AAAA"
)

var nameLabelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// Validate re-checks a record: a lowercase RFC 1123 hostname (the same rule the
// site store enforces, no trailing dot, no wildcard), a supported type and a
// value that is a plain IP of the record's own family. netip.ParseAddr keeps
// the families apart exactly: an IPv4-mapped IPv6 value ("::ffff:a.b.c.d") is
// neither — as an A value it would hide a v6 address behind a v4 name — and a
// zoned IPv6 value is a local-scope address a DNS record must not carry.
func (r Record) Validate() error {
	if !validName(r.Name) {
		return fmt.Errorf("dns record: name %q is not a lowercase RFC 1123 hostname", r.Name)
	}
	addr, err := netip.ParseAddr(r.Value)
	if err != nil {
		return fmt.Errorf("dns record: %s %s: value %q is not an IP address", r.Name, r.Type, r.Value)
	}
	switch r.Type {
	case TypeA:
		if !addr.Is4() {
			return fmt.Errorf("dns record: %s: value %q is not an IPv4 address", r.Name, r.Value)
		}
	case TypeAAAA:
		if !addr.Is6() || addr.Is4In6() || addr.Zone() != "" {
			return fmt.Errorf("dns record: %s: value %q is not an IPv6 address", r.Name, r.Value)
		}
	default:
		return fmt.Errorf("dns record: %s: type %q is not A or AAAA", r.Name, r.Type)
	}
	return nil
}

// validName mirrors the site store's hostname rule: a lowercase RFC 1123 hostname
// of at most 253 characters with no wildcard and no trailing dot.
func validName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if !nameLabelRE.MatchString(label) {
			return false
		}
	}
	return true
}

// Sort orders records by name, then type, then value (ADR 0013 m.3), so the file
// body is deterministic regardless of input order.
func Sort(recs []Record) {
	slices.SortFunc(recs, compare)
}

func compare(a, b Record) int {
	if c := strings.Compare(a.Name, b.Name); c != 0 {
		return c
	}
	if c := strings.Compare(a.Type, b.Type); c != 0 {
		return c
	}
	return strings.Compare(a.Value, b.Value)
}

// Marshal renders the records as the two-space-indented JSON file body with a
// trailing newline. The output is deterministic for an equal record set.
func Marshal(recs []Record) (string, error) {
	if recs == nil {
		recs = []Record{}
	}
	body, err := json.MarshalIndent(recs, "", "  ")
	if err != nil {
		return "", fmt.Errorf("dns marshal: %w", err)
	}
	return string(body) + "\n", nil
}

// Unmarshal parses and validates a stored extra-records body. Unknown JSON
// fields are ignored (Headscale ignores them too), but a record tagcess could
// not have written is an error, not a silent pass-through.
func Unmarshal(data []byte) ([]Record, error) {
	var recs []Record
	if err := json.Unmarshal(data, &recs); err != nil {
		return nil, fmt.Errorf("dns unmarshal: %w", err)
	}
	for i, r := range recs {
		if err := r.Validate(); err != nil {
			return nil, fmt.Errorf("dns unmarshal: record %d: %w", i, err)
		}
	}
	return recs, nil
}

// DefaultTailnetCIDR is the IPv4 tailnet range while tailnet.cidr is unset (Headscale's default,
// the Tailscale CGNAT range).
const DefaultTailnetCIDR = "100.64.0.0/10"

// tailnetV6 is the Tailscale IPv6 ULA every tailnet node can reach (IPv6 prefixes are not configurable yet).
var tailnetV6 = netip.MustParsePrefix("fd7a:115c:a1e0::/48")

// ParseTailnetCIDR checks a tailnet.cidr value: an IPv4 prefix in canonical form (host bits zero), not
// wider than /8, because a wide prefix would let far more source addresses through the site matchers.
// An empty value is the default, DefaultTailnetCIDR. The returned string is the canonical text.
func ParseTailnetCIDR(s string) (netip.Prefix, error) {
	if s == "" {
		s = DefaultTailnetCIDR
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("tailnet cidr %q: not a CIDR prefix", s)
	}
	if !p.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("tailnet cidr %q: only IPv4 prefixes are supported", s)
	}
	if p.Bits() < 8 {
		return netip.Prefix{}, fmt.Errorf("tailnet cidr %q: prefixes wider than /8 are refused", s)
	}
	if p != p.Masked() {
		return netip.Prefix{}, fmt.Errorf("tailnet cidr %q: host bits are set (want %s)", s, p.Masked())
	}
	return p, nil
}

// PrivateOutsideTailnet reports whether value is a private, loopback or link-local address that is
// not a tailnet address (F5 I11). tailnetV4 is the configured IPv4 tailnet prefix; the zero value
// means DefaultTailnetCIDR. A MagicDNS record with such a value hands every client an address
// only some of them can route to, so the user gets a connection that silently fails. Public
// addresses and non-IP values are not flagged.
func PrivateOutsideTailnet(value string, tailnetV4 netip.Prefix) bool {
	if !tailnetV4.IsValid() {
		tailnetV4 = netip.MustParsePrefix(DefaultTailnetCIDR)
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	if tailnetV4.Contains(addr) || tailnetV6.Contains(addr) {
		return false
	}
	return addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast()
}
