// Package k8s holds the first Kubernetes connection profile (F4-002): secretless metadata about the
// external API endpoint, the explicit namespace scope, the ingress class/controller and the
// internal/public listeners. The profile is declared by an operator; nothing here contacts a
// cluster, so none of it is evidence that a route or an identity actually works. Credentials
// (token, CA) live in the runtime credential file (F4-003), never in the profile. A missing,
// unreadable or invalid profile is an error and never turns into "all namespaces" or default
// listeners.
package k8s

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"path"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nesiler/tagcess/internal/netpolicy"
	"github.com/nesiler/tagcess/internal/store/db"
)

const (
	settingKey = "k8s.profile"
	timeFormat = "2006-01-02T15:04:05.000Z" // settings.updated_at, as in netpolicy
	maxEntries = 32                         // [Ö] per list; keeps the scope reviewable in the UI
)

// ErrNotSet means no profile has been saved yet.
var ErrNotSet = errors.New("k8s: connection profile is not set")

// Listener is one declared ingress listener address and port. EntryPoint optionally names the
// Traefik entryPoint behind it.
type Listener struct {
	Address    string // IP literal
	Port       int
	EntryPoint string
}

// Profile is the canonical connection metadata. There is deliberately no TLS switch: the API
// certificate is always verified, against the endpoint host or, when set, TLSServerName.
type Profile struct {
	Endpoint      string   // https://host[:port][/path]
	TLSServerName string   // optional DNS name for certificate verification when Endpoint is an IP
	Namespaces    []string // explicit scope, never "all"

	Controller     string   // IngressClass spec.controller, e.g. traefik.io/ingress-controller
	IngressClasses []string // IngressClass names this profile covers
	Internal       []Listener
	Public         []Listener

	// DeclaredTokenExpiry is what the operator says the token's expiry is. It is not read from the
	// token and is not proof of anything.
	DeclaredTokenExpiry time.Time
	// LastIdentityCheck is the time of the last successful identity check. Only RecordIdentityCheck
	// sets it; Save ignores the value passed in.
	LastIdentityCheck time.Time

	// PolicyScope references the F4-043 policy that governs reaching Endpoint. Empty means
	// netpolicy.ScopeAPI on Save; the stored form is always explicit.
	PolicyScope netpolicy.Scope
}

// FieldError ties one rejected value to its field.
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
	return "k8s: invalid profile: " + strings.Join(parts, "; ")
}

// PolicyChecker is the F4-043 policy surface the profile relies on; *netpolicy.Store satisfies it.
type PolicyChecker interface {
	Get(ctx context.Context, scope netpolicy.Scope) (netpolicy.Policy, error)
	Check(ctx context.Context, scope netpolicy.Scope, addr netip.Addr, port int) error
}

// ProfileStore keeps the profile as secretless JSON in the settings table.
type ProfileStore struct {
	db     *sql.DB
	q      *db.Queries
	policy PolicyChecker
	now    func() time.Time
}

// NewProfileStore returns the store over an open database. A nil now uses time.Now.
func NewProfileStore(sqldb *sql.DB, q *db.Queries, policy PolicyChecker, now func() time.Time) *ProfileStore {
	if now == nil {
		now = time.Now
	}
	return &ProfileStore{db: sqldb, q: q, policy: policy, now: now}
}

// stored is the JSON shape; unknown keys make a stored value unreadable.
type stored struct {
	Endpoint       string           `json:"endpoint"`
	TLSServerName  string           `json:"tls_server_name,omitempty"`
	Namespaces     []string         `json:"namespaces"`
	Controller     string           `json:"controller"`
	IngressClasses []string         `json:"ingress_classes"`
	Internal       []storedListener `json:"internal"`
	Public         []storedListener `json:"public"`
	TokenExpiry    string           `json:"declared_token_expiry,omitempty"`
	IdentityCheck  string           `json:"last_identity_check,omitempty"`
	PolicyScope    string           `json:"policy_scope"`
}

type storedListener struct {
	Address    string `json:"address"`
	Port       int    `json:"port"`
	EntryPoint string `json:"entry_point,omitempty"`
}

const storedTime = time.RFC3339 // second precision, UTC

// Save validates the profile and the endpoint against the shared API policy, then replaces the
// stored profile in one write. On any error the stored profile is untouched.
func (s *ProfileStore) Save(ctx context.Context, p Profile) error {
	canon, err := normalize(p)
	if err != nil {
		return err
	}
	if err := s.checkPolicy(ctx, canon); err != nil {
		return err
	}
	return s.update(ctx, false, func(old *Profile) Profile {
		// The check belongs to the credential it was made with; keep it only if nothing that
		// identifies that credential's target changed. A caller cannot supply one.
		canon.LastIdentityCheck = time.Time{}
		if old != nil && old.Endpoint == canon.Endpoint && old.TLSServerName == canon.TLSServerName &&
			old.DeclaredTokenExpiry.Equal(canon.DeclaredTokenExpiry) {
			canon.LastIdentityCheck = old.LastIdentityCheck
		}
		return canon
	})
}

// RecordIdentityCheck stamps the successful identity check at the current time. It needs a
// readable stored profile.
func (s *ProfileStore) RecordIdentityCheck(ctx context.Context) error {
	return s.update(ctx, true, func(old *Profile) Profile {
		p := *old
		p.LastIdentityCheck = s.now().UTC().Truncate(time.Second)
		return p
	})
}

// Get reads and re-validates the stored profile on every call. A missing profile is ErrNotSet;
// a read error, bad JSON, an unknown field or a value that is invalid or not canonical is an
// error too, always with the zero Profile. Nothing is rewritten on a failed read.
func (s *ProfileStore) Get(ctx context.Context) (Profile, error) {
	return load(ctx, s.q)
}

// checkPolicy applies the F4-043 policy: it must be stored and readable; an IP endpoint must also
// be allowed on its port. A hostname endpoint is checked at dial time by the netpolicy guard.
func (s *ProfileStore) checkPolicy(ctx context.Context, p Profile) error {
	if _, err := s.policy.Get(ctx, p.PolicyScope); err != nil {
		return fmt.Errorf("%w: %w", netpolicy.ErrDenied, err)
	}
	host, port := endpointHostPort(p.Endpoint)
	if addr, err := netip.ParseAddr(host); err == nil {
		return s.policy.Check(ctx, p.PolicyScope, addr, port)
	}
	return nil
}

// update runs read-modify-write in one transaction. With needOld the stored profile must be
// readable and is passed to fn; without it an unreadable or corrupt value is replaced, so a valid
// Save can repair it (old is nil when nothing readable is stored).
func (s *ProfileStore) update(ctx context.Context, needOld bool, fn func(old *Profile) Profile) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("k8s: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	q := s.q.WithTx(tx)

	var old *Profile
	if cur, err := load(ctx, q); err == nil {
		old = &cur
	} else if needOld {
		return err
	}
	body, err := json.Marshal(toStored(fn(old)))
	if err != nil {
		return fmt.Errorf("k8s: marshal profile: %w", err)
	}
	if err := q.UpsertSetting(ctx, db.UpsertSettingParams{
		Key: settingKey, Value: string(body), UpdatedAt: s.now().UTC().Format(timeFormat),
	}); err != nil {
		return fmt.Errorf("k8s: write profile: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("k8s: commit profile: %w", err)
	}
	return nil
}

// loadError marks a stored value that exists but cannot be used.
type loadError struct{ err error }

func (e *loadError) Error() string { return e.err.Error() }
func (e *loadError) Unwrap() error { return e.err }

func load(ctx context.Context, q *db.Queries) (Profile, error) {
	raw, err := q.GetSetting(ctx, settingKey)
	if errors.Is(err, sql.ErrNoRows) {
		return Profile{}, ErrNotSet
	}
	if err != nil {
		return Profile{}, &loadError{fmt.Errorf("k8s: read profile: %w", err)}
	}
	bad := func(format string, a ...any) (Profile, error) {
		return Profile{}, &loadError{fmt.Errorf("k8s: stored profile "+format, a...)}
	}
	var st stored
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&st); err != nil {
		return bad("is not readable: %v", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return bad("is not readable: trailing data")
	}
	p, err := fromStored(st)
	if err != nil {
		return bad("is not readable: %v", err)
	}
	canon, err := normalize(p)
	if err != nil {
		return bad("is invalid: %v", err)
	}
	if !reflect.DeepEqual(canon, p) {
		return bad("is not in canonical form")
	}
	return canon, nil
}

func toStored(p Profile) stored {
	st := stored{
		Endpoint: p.Endpoint, TLSServerName: p.TLSServerName, Namespaces: p.Namespaces,
		Controller: p.Controller, IngressClasses: p.IngressClasses,
		Internal: toStoredListeners(p.Internal), Public: toStoredListeners(p.Public),
		PolicyScope: string(p.PolicyScope),
	}
	if !p.DeclaredTokenExpiry.IsZero() {
		st.TokenExpiry = p.DeclaredTokenExpiry.UTC().Format(storedTime)
	}
	if !p.LastIdentityCheck.IsZero() {
		st.IdentityCheck = p.LastIdentityCheck.UTC().Format(storedTime)
	}
	return st
}

func toStoredListeners(in []Listener) []storedListener {
	out := make([]storedListener, len(in))
	for i, l := range in {
		out[i] = storedListener(l)
	}
	return out
}

func fromStored(st stored) (Profile, error) {
	p := Profile{
		Endpoint: st.Endpoint, TLSServerName: st.TLSServerName, Namespaces: st.Namespaces,
		Controller: st.Controller, IngressClasses: st.IngressClasses,
		PolicyScope: netpolicy.Scope(st.PolicyScope),
	}
	for _, l := range st.Internal {
		p.Internal = append(p.Internal, Listener(l))
	}
	for _, l := range st.Public {
		p.Public = append(p.Public, Listener(l))
	}
	var err error
	if st.TokenExpiry != "" {
		if p.DeclaredTokenExpiry, err = time.Parse(storedTime, st.TokenExpiry); err != nil {
			return Profile{}, fmt.Errorf("declared_token_expiry: %w", err)
		}
	}
	if st.IdentityCheck != "" {
		if p.LastIdentityCheck, err = time.Parse(storedTime, st.IdentityCheck); err != nil {
			return Profile{}, fmt.Errorf("last_identity_check: %w", err)
		}
	}
	return p, nil
}

var (
	dnsLabel = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	entryPt  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)
	ctrlPath = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)
)

// validDNSName reports whether s is a dot-separated list of DNS-1123 labels (max 253 characters).
func validDNSName(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for l := range strings.SplitSeq(s, ".") {
		if len(l) > 63 || !dnsLabel.MatchString(l) {
			return false
		}
	}
	return true
}

// normalizeServerName lower-cases a TLS server name and reports whether it is a DNS name (not an IP).
func normalizeServerName(s string) (string, bool) {
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
	_, err := netip.ParseAddr(name)
	return name, err != nil && validDNSName(name)
}

// normalize validates p and returns its canonical form. LastIdentityCheck is only normalised
// here; Save replaces it.
func normalize(p Profile) (Profile, error) {
	var verr ValidationError
	fail := func(field, msg string) { verr.Fields = append(verr.Fields, FieldError{field, msg}) }
	out := Profile{}

	endpoint, msg := parseEndpoint(p.Endpoint)
	if msg != "" {
		fail("endpoint", msg)
	}
	out.Endpoint = endpoint

	if p.TLSServerName != "" {
		name, ok := normalizeServerName(p.TLSServerName)
		if !ok {
			fail("tls_server_name", "must be a DNS name, not an IP address")
		}
		out.TLSServerName = name
	}

	out.Namespaces = names("namespaces", p.Namespaces, func(s string) bool { return len(s) <= 63 && dnsLabel.MatchString(s) }, fail)
	out.IngressClasses = names("ingress_classes", p.IngressClasses, validDNSName, fail)

	switch c := p.Controller; {
	case c == "":
		fail("controller", "is required")
	case len(c) > 250 || !strings.Contains(c, "/") || !validDNSName(c[:strings.Index(c, "/")]) ||
		len(c) == strings.Index(c, "/")+1 || !ctrlPath.MatchString(c[strings.Index(c, "/")+1:]):
		fail("controller", "must look like example.com/name")
	default:
		out.Controller = c
	}

	out.Internal = listeners("internal", p.Internal, true, fail)
	// Public listeners are optional (F5 I3): a cluster only reachable over the tailnet has none, and
	// the internet-exposure check is then reported as not performed instead of inventing a result.
	out.Public = listeners("public", p.Public, false, fail)
	for _, i := range out.Internal {
		if slices.ContainsFunc(out.Public, func(l Listener) bool { return l.Address == i.Address && l.Port == i.Port }) {
			fail("public", fmt.Sprintf("%s:%d is also an internal listener", i.Address, i.Port))
		}
	}

	if !p.DeclaredTokenExpiry.IsZero() {
		out.DeclaredTokenExpiry = p.DeclaredTokenExpiry.UTC().Truncate(time.Second)
	}
	out.LastIdentityCheck = p.LastIdentityCheck.UTC().Truncate(time.Second)

	switch p.PolicyScope {
	case "", netpolicy.ScopeAPI:
		out.PolicyScope = netpolicy.ScopeAPI
	default:
		fail("policy_scope", "must be the api scope")
	}

	if len(verr.Fields) > 0 {
		return Profile{}, &verr
	}
	return out, nil
}

// parseEndpoint returns the canonical https endpoint, or a message saying why not.
func parseEndpoint(raw string) (endpoint, msg string) {
	if raw == "" || strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, "#\\") {
		return "", "must be an https URL without fragment"
	}
	u, err := url.Parse(raw)
	switch {
	case err != nil:
		return "", "is not a valid URL"
	case u.Scheme != "https":
		return "", "must use https"
	case u.User != nil:
		return "", "must not contain user info"
	case u.RawQuery != "" || u.ForceQuery || u.Fragment != "":
		return "", "must not contain a query or fragment"
	case u.Opaque != "" || u.Host == "" || strings.HasSuffix(u.Host, ":") || u.RawPath != "":
		return "", "is not a valid https URL"
	}
	host, portStr := u.Hostname(), u.Port()
	port := 443
	if portStr != "" {
		n, err := strconv.Atoi(portStr)
		if err != nil || n < 1 || n > 65535 {
			return "", "has an invalid port"
		}
		port = n
	}
	if strings.Contains(host, "%") {
		return "", "must not contain an IP zone"
	}
	hostPort := ""
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		host = ip.String()
		hostPort = host
		if ip.Is6() {
			hostPort = "[" + host + "]"
		}
	} else {
		host = strings.TrimSuffix(strings.ToLower(host), ".")
		if !validDNSName(host) {
			return "", "has an invalid host"
		}
		hostPort = host
	}
	if portStr != "" {
		hostPort += ":" + strconv.Itoa(port)
	}
	// Validate the decoded path, but keep the escaped form: a decoded "?", "#" or "%" would turn
	// into a query, fragment or bad escape when the stored endpoint is parsed again.
	dec := strings.TrimSuffix(u.Path, "/")
	if dec != "" && (!strings.HasPrefix(dec, "/") || path.Clean(dec) != dec ||
		strings.ContainsFunc(dec, func(r rune) bool { return r < 0x20 || r == 0x7f })) {
		return "", "has an invalid path"
	}
	return "https://" + hostPort + strings.TrimSuffix(u.EscapedPath(), "/"), ""
}

// endpointHostPort splits an endpoint that parseEndpoint already produced.
func endpointHostPort(endpoint string) (string, int) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", 0
	}
	port := 443
	if n, err := strconv.Atoi(u.Port()); err == nil {
		port = n
	}
	return u.Hostname(), port
}

// names validates a required, duplicate-free list and returns it sorted.
func names(field string, in []string, valid func(string) bool, fail func(field, msg string)) []string {
	if len(in) == 0 {
		fail(field, "at least one entry is required")
		return nil
	}
	if len(in) > maxEntries {
		fail(field, fmt.Sprintf("at most %d entries", maxEntries))
		return nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for i, s := range in {
		f := fmt.Sprintf("%s[%d]", field, i)
		switch {
		case !valid(s):
			fail(f, "is not a valid name")
		case seen[s]:
			fail(f, "duplicate entry")
		default:
			seen[s] = true
			out = append(out, s)
		}
	}
	slices.Sort(out)
	return out
}

// listeners validates a required, duplicate-free listener list and returns it sorted.
func listeners(field string, in []Listener, required bool, fail func(field, msg string)) []Listener {
	if len(in) == 0 {
		if required {
			fail(field, "at least one listener is required")
		}
		return nil
	}
	if len(in) > maxEntries {
		fail(field, fmt.Sprintf("at most %d entries", maxEntries))
		return nil
	}
	type key struct {
		addr netip.Addr
		port int
	}
	seen := map[key]bool{}
	out := make([]Listener, 0, len(in))
	for i, l := range in {
		f := fmt.Sprintf("%s[%d]", field, i)
		a, err := netip.ParseAddr(l.Address)
		switch {
		case err != nil || a.Zone() != "":
			fail(f, "address must be an IP address")
		case a.Unmap().IsUnspecified() || a.IsMulticast():
			fail(f, "address must be a concrete unicast address")
		case l.Port < 1 || l.Port > 65535:
			fail(f, "port must be between 1 and 65535")
		case l.EntryPoint != "" && !entryPt.MatchString(l.EntryPoint):
			fail(f, "entry point is not a valid name")
		case seen[key{a.Unmap(), l.Port}]:
			fail(f, "duplicate listener")
		default:
			a = a.Unmap()
			seen[key{a, l.Port}] = true
			out = append(out, Listener{Address: a.String(), Port: l.Port, EntryPoint: l.EntryPoint})
		}
	}
	slices.SortFunc(out, func(x, y Listener) int {
		if c := netip.MustParseAddr(x.Address).Compare(netip.MustParseAddr(y.Address)); c != 0 {
			return c
		}
		return x.Port - y.Port
	})
	return out
}
