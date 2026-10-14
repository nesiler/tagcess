// Package netpolicy is the one IP/CIDR/port allow policy shared by the Kubernetes API client and the
// credentialless health probe (F4-043, security §13). Each scope stores its own typed list in
// settings; nothing granted to one scope carries over to the other. An address is reachable only
// when a stored entry and a stored port both match; a missing, empty or unreadable policy allows
// nothing. Loopback, link-local, unspecified, multicast and metadata targets are refused whatever
// the policy says, IPv4-mapped IPv6 included.
package netpolicy

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nesiler/tagcess/internal/store/db"
)

// Scope names one consumer of the policy. Scopes never share permissions.
type Scope string

const (
	ScopeAPI   Scope = "api"   // Kubernetes API client (F4-004)
	ScopeProbe Scope = "probe" // credentialless health probe (F4-014)
)

const (
	maxEntries = 32 // per list; [Ö] keeps the allowlist reviewable in the UI
	timeFormat = "2006-01-02T15:04:05.000Z"
)

var (
	// ErrNotSet means the scope has no stored policy yet.
	ErrNotSet = errors.New("netpolicy: policy is not set")
	// ErrDenied wraps every refusal to reach an address: no policy, unreadable policy or no match.
	ErrDenied = errors.New("netpolicy: destination not allowed")
)

// Input is what a caller (the UI) submits: address or CIDR strings and ports.
type Input struct {
	Addresses []string
	Ports     []int
}

// Policy is the canonical stored form: sorted, deduplicated CIDR strings and ports.
type Policy struct {
	Addresses []string `json:"addresses"`
	Ports     []int    `json:"ports"`
}

// FieldError ties one rejected value to its input field ("addresses[2]", "ports[0]", "addresses").
type FieldError struct {
	Field   string
	Message string
}

// ValidationError lists every rejected field; nothing is stored when it is returned.
type ValidationError struct{ Fields []FieldError }

func (e *ValidationError) Error() string {
	parts := make([]string, len(e.Fields))
	for i, f := range e.Fields {
		parts[i] = f.Field + ": " + f.Message
	}
	return "netpolicy: invalid policy: " + strings.Join(parts, "; ")
}

func settingKey(scope Scope) string { return "netpolicy." + string(scope) }

func validScope(scope Scope) bool { return scope == ScopeAPI || scope == ScopeProbe }

// forbiddenRanges are refused as entries (any overlap) and as destinations.
var forbiddenRanges = mustPrefixes(
	"0.0.0.0/8",      // unspecified / "this network"
	"127.0.0.0/8",    // loopback
	"169.254.0.0/16", // link-local, incl. the cloud metadata address 169.254.169.254
	"224.0.0.0/4",    // multicast
	"255.255.255.255/32",
	"::/96",     // unspecified, loopback and deprecated IPv4-compatible addresses
	"fe80::/10", // link-local
	"ff00::/8",  // multicast
)

// forbiddenHosts are single metadata addresses inside otherwise usable ranges (100.64.0.0/10 is the
// Headscale range): refused as a destination and as an exact entry, but a range holding them is allowed.
var forbiddenHosts = mustPrefixes(
	"100.100.100.200/32", // Alibaba Cloud metadata
	"fd00:ec2::254/128",  // AWS IPv6 metadata
)

// mapped4 is the IPv4-mapped IPv6 block; entries are normalised to IPv4 before any check.
var mapped4 = netip.MustParsePrefix("::ffff:0:0/96")

func mustPrefixes(list ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(list))
	for i, s := range list {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

func forbiddenAddr(a netip.Addr) bool {
	for _, p := range forbiddenRanges {
		if p.Contains(a) {
			return true
		}
	}
	for _, p := range forbiddenHosts {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// parseEntry turns one input string into a canonical prefix, or a message saying why not.
func parseEntry(raw string) (netip.Prefix, string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return netip.Prefix{}, "an IP address or CIDR is required"
	}
	if strings.Contains(raw, "%") {
		return netip.Prefix{}, "zones are not allowed"
	}
	var p netip.Prefix
	if strings.Contains(raw, "/") {
		var err error
		if p, err = netip.ParsePrefix(raw); err != nil {
			return netip.Prefix{}, "not a valid CIDR"
		}
	} else {
		a, err := netip.ParseAddr(raw)
		if err != nil {
			return netip.Prefix{}, "not a valid IP address or CIDR"
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if a := p.Addr(); a.Is4In6() { // ::ffff:a.b.c.d/n -> a.b.c.d/(n-96)
		if p.Bits() < 96 {
			return netip.Prefix{}, "an IPv4-mapped IPv6 range must be /96 or longer"
		}
		p = netip.PrefixFrom(a.Unmap(), p.Bits()-96)
	} else if p.Addr().Is6() && p.Bits() < 96 && p.Masked().Overlaps(mapped4) {
		return netip.Prefix{}, "range covers IPv4-mapped addresses"
	}
	if p.Bits() == 0 {
		return netip.Prefix{}, "a /0 range is not allowed"
	}
	p = p.Masked()
	if slices.ContainsFunc(forbiddenRanges, p.Overlaps) {
		return netip.Prefix{}, "range covers loopback, link-local, unspecified or multicast addresses"
	}
	if slices.Contains(forbiddenHosts, p) {
		return netip.Prefix{}, "metadata addresses are not allowed"
	}
	return p, ""
}

// canonicalize validates the input and returns the canonical policy, or a *ValidationError.
func canonicalize(in Input) (Policy, error) {
	var verr ValidationError
	fail := func(field, msg string) { verr.Fields = append(verr.Fields, FieldError{field, msg}) }

	var prefixes []netip.Prefix
	seen := map[netip.Prefix]bool{}
	if len(in.Addresses) > maxEntries {
		fail("addresses", fmt.Sprintf("at most %d entries", maxEntries))
	} else {
		for i, raw := range in.Addresses {
			field := fmt.Sprintf("addresses[%d]", i)
			p, msg := parseEntry(raw)
			switch {
			case msg != "":
				fail(field, msg)
			case seen[p]:
				fail(field, "duplicate entry")
			default:
				seen[p] = true
				prefixes = append(prefixes, p)
			}
		}
	}

	var ports []int
	seenPort := map[int]bool{}
	if len(in.Ports) > maxEntries {
		fail("ports", fmt.Sprintf("at most %d entries", maxEntries))
	} else {
		for i, port := range in.Ports {
			field := fmt.Sprintf("ports[%d]", i)
			switch {
			case port < 1 || port > 65535:
				fail(field, "port must be between 1 and 65535")
			case seenPort[port]:
				fail(field, "duplicate port")
			default:
				seenPort[port] = true
				ports = append(ports, port)
			}
		}
	}
	if len(verr.Fields) > 0 {
		return Policy{}, &verr
	}

	sort.Slice(prefixes, func(i, j int) bool {
		if c := prefixes[i].Addr().Compare(prefixes[j].Addr()); c != 0 {
			return c < 0
		}
		return prefixes[i].Bits() < prefixes[j].Bits()
	})
	sort.Ints(ports)
	out := Policy{Addresses: make([]string, len(prefixes)), Ports: ports}
	for i, p := range prefixes {
		out.Addresses[i] = p.String()
	}
	if out.Ports == nil {
		out.Ports = []int{}
	}
	return out, nil
}

// allows reports whether the destination matches an entry and a port. Forbidden classes are
// refused first, so no stored entry can widen them.
func (p Policy) allows(addr netip.Addr, port int) error {
	if !addr.IsValid() || addr.Zone() != "" { // before Unmap, which drops the zone
		return fmt.Errorf("%w: invalid address", ErrDenied)
	}
	addr = addr.Unmap()
	switch {
	case forbiddenAddr(addr):
		return fmt.Errorf("%w: %s is a forbidden address", ErrDenied, addr)
	case !p.portAllowed(port):
		return fmt.Errorf("%w: port %d", ErrDenied, port)
	}
	for _, raw := range p.Addresses {
		if pre, err := netip.ParsePrefix(raw); err == nil && pre.Contains(addr) {
			return nil
		}
	}
	return fmt.Errorf("%w: %s", ErrDenied, addr)
}

func (p Policy) portAllowed(port int) bool {
	return slices.Contains(p.Ports, port)
}

// Store keeps the per-scope policies in the settings table.
type Store struct {
	db *sql.DB
	q  *db.Queries
}

// New returns the policy store over an open database and its queries.
func New(sqldb *sql.DB, q *db.Queries) *Store { return &Store{db: sqldb, q: q} }

// Set validates the input and replaces the scope's policy in one write. On any field error the
// stored policy is untouched.
func (s *Store) Set(ctx context.Context, scope Scope, in Input) error {
	if !validScope(scope) {
		return fmt.Errorf("netpolicy: unknown scope %q", scope)
	}
	pol, err := canonicalize(in)
	if err != nil {
		return err
	}
	body, err := json.Marshal(pol)
	if err != nil {
		return fmt.Errorf("netpolicy: marshal %s: %w", settingKey(scope), err)
	}
	if err := s.q.UpsertSetting(ctx, db.UpsertSettingParams{
		Key: settingKey(scope), Value: string(body), UpdatedAt: time.Now().UTC().Format(timeFormat),
	}); err != nil {
		return fmt.Errorf("netpolicy: write %s: %w", settingKey(scope), err)
	}
	return nil
}

// Get reads and re-validates the scope's policy on every call. A missing policy is ErrNotSet; any
// other failure (read error, bad JSON, a value that is not canonical or fails validation) is an
// error too, never an empty or default policy. Nothing is rewritten on a failed read.
func (s *Store) Get(ctx context.Context, scope Scope) (Policy, error) {
	if !validScope(scope) {
		return Policy{}, fmt.Errorf("netpolicy: unknown scope %q", scope)
	}
	raw, err := s.q.GetSetting(ctx, settingKey(scope))
	if errors.Is(err, sql.ErrNoRows) {
		return Policy{}, ErrNotSet
	}
	if err != nil {
		return Policy{}, fmt.Errorf("netpolicy: read %s: %w", settingKey(scope), err)
	}
	var stored Policy
	dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&stored); err != nil {
		return Policy{}, fmt.Errorf("netpolicy: parse %s: %w", settingKey(scope), err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Policy{}, fmt.Errorf("netpolicy: parse %s: trailing data", settingKey(scope))
	}
	canon, err := canonicalize(Input(stored))
	if err != nil {
		return Policy{}, fmt.Errorf("netpolicy: %s is invalid: %w", settingKey(scope), err)
	}
	if stored.Addresses == nil {
		stored.Addresses = []string{}
	}
	if stored.Ports == nil {
		stored.Ports = []int{}
	}
	if !reflect.DeepEqual(canon, stored) {
		return Policy{}, fmt.Errorf("netpolicy: %s is not in canonical form", settingKey(scope))
	}
	return canon, nil
}

// Check reports whether the scope's current policy allows addr:port. Any failure is ErrDenied.
func (s *Store) Check(ctx context.Context, scope Scope, addr netip.Addr, port int) error {
	pol, err := s.Get(ctx, scope)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDenied, err)
	}
	return pol.allows(addr, port)
}

// Resolver is the name lookup the guard uses; *net.Resolver satisfies it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// DialFunc opens a connection to a literal "ip:port"; (*net.Dialer).DialContext satisfies it.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// Guard turns a scope's policy into a dial function: the resolved addresses and the address
// actually dialled are checked against the same policy snapshot, and the connection is made to
// the checked IP literal so the name cannot resolve differently at dial time.
type Guard struct {
	store    *Store
	resolver Resolver
	dial     DialFunc
}

// NewGuard returns a guard. A nil resolver or dial uses the system ones.
func NewGuard(store *Store, resolver Resolver, dial DialFunc) *Guard {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	return &Guard{store: store, resolver: resolver, dial: dial}
}

// DialContext returns a dial function bound to scope, usable as http.Transport.DialContext.
// Nothing is dialled unless every resolved address and the port are allowed.
func (g *Guard) DialContext(scope Scope) func(ctx context.Context, network, address string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := g.dialChecked(ctx, scope, network, address)
		if err != nil && !errors.Is(err, errDial) && !errors.Is(err, ErrDenied) {
			return nil, fmt.Errorf("%w: %w", ErrDenied, err)
		}
		return conn, err
	}
}

// errDial marks a plain connection failure to an allowed address (not a policy refusal).
var errDial = errors.New("netpolicy: dial failed")

func (g *Guard) dialChecked(ctx context.Context, scope Scope, network, address string) (net.Conn, error) {
	want4, want6 := true, true
	switch network {
	case "tcp":
	case "tcp4":
		want6 = false
	case "tcp6":
		want4 = false
	default:
		return nil, fmt.Errorf("network %q is not tcp", network)
	}
	host, portStr, err := net.SplitHostPort(address)
	if err != nil || host == "" {
		return nil, fmt.Errorf("bad address %q", address)
	}
	port64, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("bad port in %q", address)
	}
	port := int(port64)

	pol, err := g.store.Get(ctx, scope)
	if err != nil {
		return nil, err
	}
	if !pol.portAllowed(port) { // before any lookup: a refused port starts no network call
		return nil, fmt.Errorf("%w: port %d", ErrDenied, port)
	}

	var addrs []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{ip}
	} else if addrs, err = g.resolver.LookupNetIP(ctx, "ip", host); err != nil {
		return nil, fmt.Errorf("resolve %q: %w", host, err)
	}
	var candidates []netip.Addr
	for _, a := range addrs {
		if err := pol.allows(a, port); err != nil { // one bad answer refuses the whole name
			return nil, err
		}
		a = a.Unmap()
		if (a.Is4() && want4) || (a.Is6() && want6) {
			candidates = append(candidates, a)
		}
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no usable address for %q", host)
	}

	var lastErr error
	for _, a := range candidates {
		target := netip.AddrPortFrom(a, uint16(port))
		conn, err := g.dial(ctx, network, target.String())
		if err != nil {
			lastErr = err
			continue
		}
		remote, err := netip.ParseAddrPort(conn.RemoteAddr().String())
		if err != nil || remote.Addr().Unmap() != a || int(remote.Port()) != port {
			_ = conn.Close()
			return nil, fmt.Errorf("%w: connection did not reach the checked address", ErrDenied)
		}
		return conn, nil
	}
	return nil, fmt.Errorf("%w: %w", errDial, lastErr)
}
