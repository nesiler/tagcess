package site

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// RoleSource reads the role keys currently defined in the Zitadel vpn project (S-02.3). A
// read that cannot be proven complete (every page 2xx, collected count == totalResult,
// security.md §8) must return an error; the validator then refuses the change and the last
// known-good state is kept (AC3).
type RoleSource interface {
	ListRoles(ctx context.Context) ([]string, error)
}

// TargetSource reads the custom target host allowlist that the interface edits (F2-013 AC5). It
// is read on every check, so a change made in the UI takes effect at once; a read that fails
// must return an error, and the validator then refuses the change (fail closed).
type TargetSource interface {
	ListTargets(ctx context.Context) ([]string, error)
}

// ValidatorConfig carries the allowlists the validator enforces. The allowed domains list must
// be non-empty, and either the allowed targets list or a TargetSource must be set: an empty
// allowlist is a misconfiguration, and the validator fails closed.
type ValidatorConfig struct {
	// AllowedDomains: a site hostname must be one of these domains or a subdomain of one
	// (security.md §5 hostname rule).
	AllowedDomains []string
	// AllowedTargets: hosts (IP or name, without port) a url target may point at
	// (security.md §5 target rule). Used when TargetSource is nil; a static seed.
	AllowedTargets []string
	// TargetSource is the settings-backed allowlist the UI edits. When set it is read on every
	// check and takes precedence over AllowedTargets (F2-013 AC5).
	TargetSource TargetSource
}

// Validator checks site records structurally and security-wise before they reach the store and
// the render (F2-003). The rule is deny-by-default: a value that does not pass its explicit
// rule is rejected, never repaired (security.md §5).
type Validator struct {
	domains      []string
	targets      []string
	targetSource TargetSource
	roles        RoleSource
}

// field-level rules (security.md §5, ADR 0011, R1 data model).
var (
	// RFC 1123 label: lowercase letters, digits, inner hyphens, 1..63 characters.
	labelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	// Role keys: security.md §5.
	roleRE = regexp.MustCompile(`^[a-z0-9_-]{1,32}$`)
	// API exemption header names: ADR 0011.
	apiHeaderNameRE = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
	// Redirect source and path targets: security.md §5.
	redirectPathRE = regexp.MustCompile(`^/[A-Za-z0-9/_.-]*$`)
	// Certificate names under /etc/letsencrypt/live: a single safe path segment.
	certNameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`)
	// Extra header names: RFC 7230 token (security.md §5), with the first
	// character restricted so a stored name can never double as a Caddyfile
	// operation prefix ("+" add, "-" delete), a comment start ("#") or a
	// quote/backtick that would break out of the token (F2-004 review). The
	// backtick is excluded entirely: the caddyfile lexer starts a quoted
	// string at every backtick.
	headerNameRE = regexp.MustCompile(`^[A-Za-z0-9!$%&'.^_|~][A-Za-z0-9!#$%&'*+\-.^_|~]{0,127}$`)
)

// redirectCodes are the redirect codes security.md §5 allows.
var redirectCodes = map[int]bool{301: true, 302: true, 307: true, 308: true}

// NewValidator checks the configuration and returns a validator.
func NewValidator(cfg ValidatorConfig, roles RoleSource) (*Validator, error) {
	if len(cfg.AllowedDomains) == 0 {
		return nil, fmt.Errorf("site validation: config: allowed domains must not be empty")
	}
	if cfg.TargetSource == nil && len(cfg.AllowedTargets) == 0 {
		return nil, fmt.Errorf("site validation: config: allowed target hosts must not be empty")
	}
	if roles == nil {
		return nil, fmt.Errorf("site validation: config: role source must not be nil")
	}
	for _, d := range cfg.AllowedDomains {
		if !validHostname(d) {
			return nil, fmt.Errorf("site validation: config: allowed domain %q is not a lowercase hostname", d)
		}
	}
	if cfg.TargetSource == nil {
		for _, h := range cfg.AllowedTargets {
			if strings.TrimSpace(h) == "" {
				return nil, fmt.Errorf("site validation: config: allowed target host must not be empty")
			}
		}
	}
	return &Validator{
		domains:      cfg.AllowedDomains,
		targets:      cfg.AllowedTargets,
		targetSource: cfg.TargetSource,
		roles:        roles,
	}, nil
}

// ValidateTargetList checks the UI-editable custom target host allowlist (F2-013 AC5): at least
// one entry, each a plain hostname or IP (no scheme, port, path or wildcard), no duplicates.
// A read-only structural rule; it never widens access on its own.
func ValidateTargetList(list []string) error {
	if len(list) == 0 {
		return errors.New("site validation: allowed target hosts must not be empty")
	}
	seen := make(map[string]bool, len(list))
	for i, h := range list {
		if !validAllowedTarget(h) {
			return fmt.Errorf("site validation: allowed_targets[%d]: %q is not a plain hostname or IP (no scheme, port or wildcard)", i, h)
		}
		key := strings.ToLower(h)
		if seen[key] {
			return fmt.Errorf("site validation: allowed_targets[%d]: %q is listed twice", i, h)
		}
		seen[key] = true
	}
	return nil
}

// validAllowedTarget reports whether h is an IP address or a lowercase RFC 1123 hostname.
func validAllowedTarget(h string) bool {
	if h == "" {
		return false
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return true
	}
	return validHostname(h)
}

// Validate reports whether the site record may be stored and rendered. Every failure names the
// offending field ("site validation: hosts[0]: ..."), so the interface can show the error next
// to the field (S-02.4). An error from Validate means the record and its application are
// refused and the last known-good state is kept.
func (v *Validator) Validate(ctx context.Context, s Site) error {
	if err := v.validateKindPairings(s); err != nil {
		return err
	}
	if err := v.validateHosts(s); err != nil {
		return err
	}
	if err := v.validateCert(s); err != nil {
		return err
	}
	// System templates carry their targets as code constants; their shape is the template
	// layer's job (F2-005). Everything else follows the target boundary rules (AC4).
	if s.Kind != KindSystem {
		if err := v.validateTarget(ctx, s); err != nil {
			return err
		}
	}
	if err := v.validateRedirects(s); err != nil {
		return err
	}
	if err := v.validateHeaders(s); err != nil {
		return err
	}
	if err := v.validateAPIRules(s); err != nil {
		return err
	}
	return v.validateRoles(ctx, s)
}

// validateKindPairings re-checks the kind pairings the store also pins: it is cheap and keeps
// the validator usable without a database.
func (v *Validator) validateKindPairings(s Site) error {
	switch s.Kind {
	case KindRole:
		if s.OpenReason != "" {
			return fmt.Errorf("site validation: open_reason: only open sites carry an open reason")
		}
		if s.SystemTemplate != "" {
			return fmt.Errorf("site validation: system_template: only system sites carry a template")
		}
		if len(s.TargetRoles) > 0 {
			return fmt.Errorf("site validation: target_roles: only open transition sites carry target roles")
		}
		if len(s.Roles) == 0 {
			return fmt.Errorf("site validation: roles: a role-controlled site needs at least one role")
		}
	case KindOpen:
		if s.SystemTemplate != "" {
			return fmt.Errorf("site validation: system_template: only system sites carry a template")
		}
		if s.OpenReason != OpenReasonIntentional && s.OpenReason != OpenReasonTransition {
			return fmt.Errorf("site validation: open_reason: must be %s or %s, got %q",
				OpenReasonIntentional, OpenReasonTransition, s.OpenReason)
		}
		if len(s.Roles) > 0 {
			return fmt.Errorf("site validation: roles: an open site must not carry roles")
		}
		if len(s.TargetRoles) > 0 && s.OpenReason != OpenReasonTransition {
			return fmt.Errorf("site validation: target_roles: only open transition sites carry target roles")
		}
	case KindSystem:
		if s.OpenReason != "" {
			return fmt.Errorf("site validation: open_reason: only open sites carry an open reason")
		}
		switch s.SystemTemplate {
		case TemplateZitadel, TemplateHeadscale, TemplateWireGuardUI, TemplateTagcess:
		default:
			return fmt.Errorf("site validation: system_template: unknown template %q", s.SystemTemplate)
		}
		if len(s.Roles) > 0 {
			return fmt.Errorf("site validation: roles: a system site must not carry roles")
		}
		if len(s.TargetRoles) > 0 {
			return fmt.Errorf("site validation: target_roles: only open transition sites carry target roles")
		}
	default:
		return fmt.Errorf("site validation: kind: unknown kind %q", s.Kind)
	}
	return nil
}

// ValidHostname reports whether host is a lowercase RFC 1123 hostname of at most 253
// characters with no wildcard (security.md §5). Other artifacts built from a host (the Zitadel
// redirect URIs, F2-010) check it again before using it.
func ValidHostname(host string) bool { return validHostname(host) }

// validHostname is ValidHostname for callers inside the package.
func validHostname(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if !labelRE.MatchString(label) {
			return false
		}
	}
	return true
}

// underAllowedDomain reports whether host is an allowed domain itself or a subdomain of one.
func (v *Validator) underAllowedDomain(host string) bool {
	for _, d := range v.domains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

func (v *Validator) validateHosts(s Site) error {
	if len(s.Hosts) == 0 {
		return fmt.Errorf("site validation: hosts: at least one host is required")
	}
	seen := make(map[string]bool, len(s.Hosts))
	for i, host := range s.Hosts {
		if !validHostname(host) {
			return fmt.Errorf("site validation: hosts[%d]: %q is not a lowercase RFC 1123 hostname (no wildcard)", i, host)
		}
		if !v.underAllowedDomain(host) {
			return fmt.Errorf("site validation: hosts[%d]: %q is not under an allowed domain", i, host)
		}
		if seen[host] {
			return fmt.Errorf("site validation: hosts[%d]: %q is listed twice", i, host)
		}
		seen[host] = true
	}
	return nil
}

func (v *Validator) validateCert(s Site) error {
	switch {
	case s.Cert == "":
		return fmt.Errorf("site validation: cert: must be auto or le:<name>")
	case s.Cert == "auto":
		return nil
	case strings.HasPrefix(s.Cert, "le:"):
		name := strings.TrimPrefix(s.Cert, "le:")
		if name == "" || len(name) > 253 || !certNameRE.MatchString(name) || strings.Contains(name, "..") {
			return fmt.Errorf("site validation: cert: le:%q is not a safe certificate name", name)
		}
		return nil
	default:
		return fmt.Errorf("site validation: cert: %q is neither auto nor le:<name>", s.Cert)
	}
}

func (v *Validator) validateTarget(ctx context.Context, s Site) error {
	switch s.TargetKind {
	case TargetK8s:
		if s.TargetURL != "" {
			return fmt.Errorf("site validation: target: a k8s target must not carry a url, got %q", s.TargetURL)
		}
		return nil
	case TargetURL:
		return v.validateTargetURL(ctx, s.TargetURL)
	default:
		return fmt.Errorf("site validation: target: unknown target kind %q", s.TargetKind)
	}
}

// validateTargetURL enforces security.md §5: scheme http/https, no userinfo, host on the
// allowed list, never loopback. Unix sockets are unreachable here: their scheme or empty host
// fails first (AC4).
func (v *Validator) validateTargetURL(ctx context.Context, raw string) error {
	if strings.ContainsFunc(raw, func(r rune) bool { return r < 0x20 || r == 0x7f || r == '`' }) {
		return fmt.Errorf("site validation: target: url %q contains a control character or backtick", raw)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("site validation: target: url %q does not parse: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("site validation: target: scheme must be http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("site validation: target: url %q has no host", raw)
	}
	if u.User != nil {
		return fmt.Errorf("site validation: target: url %q carries userinfo", raw)
	}
	// Caddy v2.8.4 accepts only scheme://host:port upstreams (caddy adapt rejects path and
	// query components, including a trailing slash), so anything beyond host[:port] would fail
	// /load after the record is already stored. Reject it here.
	if u.Path != "" {
		return fmt.Errorf("site validation: target: upstream path %q is not allowed (scheme://host:port only)", u.Path)
	}
	if u.RawQuery != "" {
		return fmt.Errorf("site validation: target: upstream query %q is not allowed", u.RawQuery)
	}
	if u.Fragment != "" {
		return fmt.Errorf("site validation: target: upstream fragment %q is not allowed", u.Fragment)
	}
	// Caddy v2.8.4 rejects out-of-range upstream ports and :0 is not dialable; only 1..65535
	// survive /load (verified locally with caddy adapt).
	if p := u.Port(); p != "" {
		n, perr := strconv.Atoi(p)
		if perr != nil || n < 1 || n > 65535 {
			return fmt.Errorf("site validation: target: port %q is not in 1..65535", p)
		}
	}
	host := u.Hostname()
	if isLoopbackHost(host) {
		return fmt.Errorf("site validation: target: loopback host %q is not allowed", host)
	}
	targets := v.targets
	if v.targetSource != nil {
		got, err := v.targetSource.ListTargets(ctx)
		if err != nil {
			return fmt.Errorf("site validation: target: reading the allowed target list failed, refusing the change: %w", err)
		}
		if len(got) == 0 {
			return fmt.Errorf("site validation: target: the allowed target list is empty, refusing the change")
		}
		targets = got
	}
	for _, allowed := range targets {
		if strings.EqualFold(host, allowed) {
			return nil
		}
	}
	return fmt.Errorf("site validation: target: host %q is not on the allowed target list", host)
}

// isLoopbackHost reports whether host is a loopback address or localhost name.
func isLoopbackHost(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

func (v *Validator) validateRedirects(s Site) error {
	for i, r := range s.Redirects {
		if !redirectPathRE.MatchString(r.Source) {
			return fmt.Errorf("site validation: redirects[%d].source: %q does not match the path rule", i, r.Source)
		}
		if !redirectCodes[r.Code] {
			return fmt.Errorf("site validation: redirects[%d].code: %d is not 301/302/307/308", i, r.Code)
		}
		// A protocol-relative target ("//host") is a path to the regex but renders as a
		// Location header pointing at an external site: an open redirect. Reject it before
		// the path rule.
		if strings.HasPrefix(r.Target, "//") {
			return fmt.Errorf("site validation: redirects[%d].target: %q is not a site path", i, r.Target)
		}
		switch {
		case strings.HasPrefix(r.Target, "/"):
			if !redirectPathRE.MatchString(r.Target) {
				return fmt.Errorf("site validation: redirects[%d].target: %q does not match the path rule", i, r.Target)
			}
		case strings.HasPrefix(r.Target, "http://"), strings.HasPrefix(r.Target, "https://"):
			// Today's shape (R1 B-01, projects): an absolute target to an
			// allowed domain with a site path (F2-004 review alignment).
			if err := v.validateRedirectURL(r.Target); err != nil {
				return fmt.Errorf("site validation: redirects[%d].target: %w", i, err)
			}
		default:
			if !validHostname(r.Target) || !v.underAllowedDomain(r.Target) {
				return fmt.Errorf("site validation: redirects[%d].target: %q is neither a site path nor an allowed hostname", i, r.Target)
			}
		}
	}
	return nil
}

// redirectPortInRange reports whether p is a plain decimal port in 1..65535.
// strconv.Atoi alone would accept "+80" and " 80" (F2-004 review).
func redirectPortInRange(p string) bool {
	if p == "" || len(p) > 5 || strings.IndexFunc(p, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return false
	}
	n, err := strconv.Atoi(p)
	return err == nil && n >= 1 && n <= 65535
}

// validateRedirectURL checks an absolute redirect target: scheme, an allowed
// lowercase hostname, an optional port and a site path — nothing else.
func (v *Validator) validateRedirectURL(raw string) error {
	rest, ok := strings.CutPrefix(raw, "https://")
	if !ok {
		rest, ok = strings.CutPrefix(raw, "http://")
	}
	if !ok || rest == "" {
		return fmt.Errorf("%q is not an absolute http(s) target", raw)
	}
	if strings.ContainsFunc(raw, func(r rune) bool {
		return r < 0x20 || r > 0x7e || r == '"' || r == '\'' || r == '`' || r == '{' || r == '}' || r == '\\'
	}) {
		return fmt.Errorf("%q contains a forbidden character", raw)
	}
	host := rest
	if i := strings.IndexByte(host, '/'); i >= 0 {
		host, rest = host[:i], rest[i:]
	} else {
		rest = ""
	}
	if i := strings.LastIndexByte(host, ':'); i >= 0 {
		port := host[i+1:]
		if !redirectPortInRange(port) || strings.Contains(host[:i], ":") {
			return fmt.Errorf("port %q is not in 1..65535", port)
		}
		host = host[:i]
	}
	if !validHostname(host) || !v.underAllowedDomain(host) {
		return fmt.Errorf("host %q is not an allowed hostname", host)
	}
	if rest != "" && !redirectPathRE.MatchString(rest) {
		return fmt.Errorf("path %q does not match the path rule", rest)
	}
	return nil
}

func (v *Validator) validateHeaders(s Site) error {
	for i, h := range s.Headers {
		if !headerNameRE.MatchString(h.Name) {
			return fmt.Errorf("site validation: headers[%d].name: %q is not an RFC 7230 token", i, h.Name)
		}
		if strings.ContainsFunc(h.Value, func(r rune) bool { return r < 0x20 || r > 0x7e }) {
			return fmt.Errorf("site validation: headers[%d].value: %q is not printable ASCII", i, h.Value)
		}
		if strings.ContainsAny(h.Value, `"{}"`) {
			return fmt.Errorf("site validation: headers[%d].value: %q contains a forbidden character", i, h.Value)
		}
		// A value ending in "\" would end up in front of the closing quote of
		// the Caddyfile token ("value\""), where the lexer reads \" as an
		// escaped quote and the token never closes (F2-004 review).
		if strings.HasSuffix(h.Value, `\`) {
			return fmt.Errorf("site validation: headers[%d].value: %q must not end with a backslash", i, h.Value)
		}
	}
	return nil
}

// validateAPIRules enforces ADR 0011: only header_present and path_regex, OR-combined, and
// only on role sites. The regex is compiled with Go regexp (RE2), the engine Caddy uses.
func (v *Validator) validateAPIRules(s Site) error {
	if len(s.APIRules) == 0 {
		return nil
	}
	if s.Kind != KindRole {
		return fmt.Errorf("site validation: api_rules: only role-controlled sites carry api rules")
	}
	for i, rule := range s.APIRules {
		switch rule.Type {
		case APIRuleHeaderPresent:
			if !apiHeaderNameRE.MatchString(rule.Value) {
				return fmt.Errorf("site validation: api_rules[%d]: header name %q must match ^[A-Za-z0-9-]{1,64}$", i, rule.Value)
			}
		case APIRulePathRegex:
			if len(rule.Value) > 200 {
				return fmt.Errorf("site validation: api_rules[%d]: regex is longer than 200 characters", i)
			}
			if strings.ContainsAny(rule.Value, "`{}'") ||
				strings.ContainsFunc(rule.Value, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
				return fmt.Errorf("site validation: api_rules[%d]: regex contains a forbidden character", i)
			}
			if _, err := regexp.Compile(rule.Value); err != nil {
				return fmt.Errorf("site validation: api_rules[%d]: regex does not compile: %w", i, err)
			}
		default:
			return fmt.Errorf("site validation: api_rules[%d]: unknown rule type %q", i, rule.Type)
		}
	}
	return nil
}

// validateRoles checks the role format and, when the site references roles, reads the vpn
// project's current roles and refuses the site unless every referenced role exists. A failed
// read refuses the change (AC3); a site that references no roles needs no read. Errors name
// roles[i] or target_roles[i] so the interface can point at the right field.
func (v *Validator) validateRoles(ctx context.Context, s Site) error {
	if len(s.Roles) == 0 && len(s.TargetRoles) == 0 {
		return nil
	}
	label := func(i int) string {
		if i < len(s.Roles) {
			return fmt.Sprintf("roles[%d]", i)
		}
		return fmt.Sprintf("target_roles[%d]", i-len(s.Roles))
	}
	referenced := append(append([]string{}, s.Roles...), s.TargetRoles...)
	for i, role := range referenced {
		if !roleRE.MatchString(role) {
			return fmt.Errorf("site validation: %s: %q does not match ^[a-z0-9_-]{1,32}$", label(i), role)
		}
	}
	current, err := v.roles.ListRoles(ctx)
	if err != nil {
		return fmt.Errorf("site validation: roles: reading the vpn project roles failed, refusing the change: %w", err)
	}
	existing := make(map[string]bool, len(current))
	for _, role := range current {
		existing[role] = true
	}
	for i, role := range referenced {
		if !existing[role] {
			return fmt.Errorf("site validation: %s: %q is not a vpn project role", label(i), role)
		}
	}
	return nil
}
