package site

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
)

// System sites are the four locked blocks of the Caddyfile (ADR 0010, S-05): zitadel, headscale,
// wireguard_ui and tagcess. Their text is fixed template code, so a record only carries the
// switches a template opens; everything else is held to one canonical shape and, once stored,
// cannot change through the service layer. Both rules deny by default: a record that is not
// exactly the canonical shape is refused, never repaired.

// ErrSystemLocked is returned when a write would break a system site lock (S-05): deleting a
// system site, changing its kind, template, host or any other field the template does not
// open, or creating a system site that already exists. The refused write changes nothing.
var ErrSystemLocked = errors.New("site: system site is locked")

// DefaultZitadelLoginPaths is the login-flow path list of the zitadel template at first import
// (today's file, R1 B-01). It is the seed default; after the seed the record is the source of
// truth (F2-013 decision).
var DefaultZitadelLoginPaths = []string{
	"/.well-known/*", "/oauth/v2/*", "/oidc/v1/*",
	"/ui/v2/login", "/ui/v2/login/*", "/ui/login", "/ui/login/*", "/assets/v1/*",
}

// Lists the zitadel template carries are bounded (F2-013).
const (
	maxInternalSources = 32
	maxLoginPaths      = 32
)

// SystemSettings are the switches and lists the system templates open (ADR 0010, S-02.2). Only
// the fields of the record's own template are meaningful; Enabled and Headplane default to true,
// the rendered default.
type SystemSettings struct {
	// Enabled is the wireguard_ui switch: false removes the block (WireGuard is shut down).
	Enabled bool
	// Headplane is the headscale switch: false removes the /admin* branch.
	Headplane bool
	// InternalSources is the zitadel template's remote_ip list: canonical IPs/CIDRs that reach
	// the full Zitadel site. Empty is allowed and only narrows access.
	InternalSources []string
	// LoginPaths is the zitadel template's always-through login-flow path list.
	LoginPaths []string
}

// ParseSystemConfig reads and strictly checks the SystemConfig JSON of a system template. The
// accepted shape per template is exactly:
//
//	wireguard_ui  {"enabled": <bool>}
//	headscale     {"headplane": <bool>}
//	zitadel       {"internal_sources": ["<ip|cidr>", ...], "login_paths": ["<path>", ...]}
//	tagcess       {}   (cannot be closed)
//
// An unknown key, a missing key, a wrong type, trailing data or anything that is not a JSON
// object is an error. The zitadel lists are validated here, so the store and the render use the
// same rules (F2-013).
func ParseSystemConfig(template, raw string) (SystemSettings, error) {
	settings := SystemSettings{Enabled: true, Headplane: true}
	if !strings.HasPrefix(strings.TrimSpace(raw), "{") {
		return settings, fmt.Errorf("site validation: system_config: %q is not a JSON object", raw)
	}
	var cfg struct {
		Enabled         *bool     `json:"enabled"`
		Headplane       *bool     `json:"headplane"`
		InternalSources *[]string `json:"internal_sources"`
		LoginPaths      *[]string `json:"login_paths"`
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return settings, fmt.Errorf("site validation: system_config: %w", err)
	}
	if dec.More() {
		return settings, fmt.Errorf("site validation: system_config: trailing data after the object")
	}
	switch template {
	case TemplateWireGuardUI:
		if cfg.Enabled == nil || cfg.Headplane != nil || cfg.InternalSources != nil || cfg.LoginPaths != nil {
			return settings, fmt.Errorf(`site validation: system_config: the wireguard_ui template takes exactly {"enabled": <bool>}`)
		}
		settings.Enabled = *cfg.Enabled
	case TemplateHeadscale:
		if cfg.Headplane == nil || cfg.Enabled != nil || cfg.InternalSources != nil || cfg.LoginPaths != nil {
			return settings, fmt.Errorf(`site validation: system_config: the headscale template takes exactly {"headplane": <bool>}`)
		}
		settings.Headplane = *cfg.Headplane
	case TemplateZitadel:
		if cfg.Enabled != nil || cfg.Headplane != nil || cfg.InternalSources == nil || cfg.LoginPaths == nil {
			return settings, fmt.Errorf(`site validation: system_config: the zitadel template takes exactly {"internal_sources": [...], "login_paths": [...]}`)
		}
		if err := validateInternalSources(*cfg.InternalSources); err != nil {
			return settings, err
		}
		if err := validateLoginPaths(*cfg.LoginPaths); err != nil {
			return settings, err
		}
		settings.InternalSources = nonNil(*cfg.InternalSources)
		settings.LoginPaths = nonNil(*cfg.LoginPaths)
	case TemplateTagcess:
		if cfg.Enabled != nil || cfg.Headplane != nil || cfg.InternalSources != nil || cfg.LoginPaths != nil {
			return settings, fmt.Errorf("site validation: system_config: the %s template has no switches and cannot be closed", template)
		}
	default:
		return settings, fmt.Errorf("site validation: system_template: unknown template %q", template)
	}
	return settings, nil
}

// validateInternalSources checks the zitadel internal source list: canonical IPs/CIDRs, no
// duplicates, at most maxInternalSources, and no prefix broader than /16 (IPv4) or /48 (IPv6).
// The breadth bound keeps one entry from opening the whole internet (F2-013 [Ö]).
func validateInternalSources(list []string) error {
	if len(list) > maxInternalSources {
		return fmt.Errorf("site validation: system_config: internal_sources has %d entries, at most %d allowed", len(list), maxInternalSources)
	}
	seen := make(map[string]bool, len(list))
	for i, e := range list {
		if err := validateInternalSource(e); err != nil {
			return fmt.Errorf("site validation: system_config: internal_sources[%d]: %w", i, err)
		}
		if seen[e] {
			return fmt.Errorf("site validation: system_config: internal_sources[%d]: %q is listed twice", i, e)
		}
		seen[e] = true
	}
	return nil
}

// validateInternalSource checks one canonical IP or CIDR, exactly as netip prints it.
func validateInternalSource(e string) error {
	if p, err := netip.ParsePrefix(e); err == nil {
		if p.Bits() == 0 || p.Masked() != p || p.Addr().Zone() != "" || p.Addr().Is4In6() || p.Addr().IsUnspecified() || p.String() != e {
			return fmt.Errorf("%q is not a canonical, non-empty CIDR", e)
		}
		if p.Addr().Is4() && p.Bits() < 16 {
			return fmt.Errorf("%q is broader than /16", e)
		}
		if p.Addr().Is6() && p.Bits() < 48 {
			return fmt.Errorf("%q is broader than /48", e)
		}
		return nil
	}
	a, err := netip.ParseAddr(e)
	if err != nil || a.Zone() != "" || a.Is4In6() || a.IsUnspecified() || a.String() != e {
		return fmt.Errorf("%q is not a canonical IP or CIDR", e)
	}
	return nil
}

// loginPathRE is the character rule of a login path prefix: a leading slash and plain path
// characters only. It rejects whitespace, quotes, braces, "#" and backslashes.
var loginPathRE = regexp.MustCompile(`^/[A-Za-z0-9._~/-]*$`)

// validateLoginPaths checks the zitadel login path list: 1..maxLoginPaths unique, safe patterns.
func validateLoginPaths(list []string) error {
	if len(list) < 1 || len(list) > maxLoginPaths {
		return fmt.Errorf("site validation: system_config: login_paths needs 1..%d entries, got %d", maxLoginPaths, len(list))
	}
	seen := make(map[string]bool, len(list))
	for i, p := range list {
		if !validLoginPath(p) {
			return fmt.Errorf("site validation: system_config: login_paths[%d]: %q is not a safe path pattern", i, p)
		}
		if seen[p] {
			return fmt.Errorf("site validation: system_config: login_paths[%d]: %q is listed twice", i, p)
		}
		seen[p] = true
	}
	return nil
}

// validLoginPath reports whether p is a fixed path ("/ui/login") or a single trailing-wildcard
// pattern ("/ui/v2/login/*"). The wildcard must follow a non-empty segment, so "/", "/*" and
// "/a/*/b" are refused; "..", "//" and any character outside loginPathRE are refused too.
func validLoginPath(p string) bool {
	if len(p) < 2 || p[0] != '/' {
		return false
	}
	body := p
	if strings.HasSuffix(p, "*") {
		if strings.Count(p, "*") != 1 {
			return false
		}
		body = strings.TrimSuffix(p, "*")
		if !strings.HasSuffix(body, "/") {
			return false
		}
		body = strings.TrimSuffix(body, "/")
	} else if strings.Contains(p, "*") {
		return false
	}
	if body == "" || !loginPathRE.MatchString(body) || strings.Contains(body, "..") || strings.Contains(body, "//") {
		return false
	}
	return true
}

// checkSystemShape holds a system record to the canonical shape: one host, no roles, no
// target, no headers, redirects or API rules, the template's own config. Targets are code
// constants of the template (loopback and socket targets live only there), so the record
// carries the k8s placeholder and no url. Cert is free only for zitadel, which writes a tls
// line; the other templates render none and keep "auto".
func checkSystemShape(s Site) error {
	if s.Kind != KindSystem {
		return nil
	}
	if len(s.Hosts) != 1 {
		return fmt.Errorf("site validation: hosts: a system site has exactly one host, got %d", len(s.Hosts))
	}
	if s.TargetKind != TargetK8s || s.TargetURL != "" || s.TargetTLSInsecure {
		return fmt.Errorf("site validation: target: a system site carries no target of its own (the template fixes it)")
	}
	if len(s.Redirects) > 0 {
		return fmt.Errorf("site validation: redirects: a system site takes no redirects")
	}
	if len(s.Headers) > 0 {
		return fmt.Errorf("site validation: headers: a system site takes no extra headers")
	}
	if len(s.APIRules) > 0 {
		return fmt.Errorf("site validation: api_rules: a system site takes no api rules")
	}
	if s.SystemTemplate != TemplateZitadel && s.Cert != "auto" {
		return fmt.Errorf("site validation: cert: the %s template renders no tls line, cert must be auto", s.SystemTemplate)
	}
	_, err := ParseSystemConfig(s.SystemTemplate, s.SystemConfig)
	return err
}

// checkSystemUpdate refuses an update of the stored site old to the record in when it would
// break a lock. A system site keeps its kind, template and every field except its switches
// (SystemConfig) and the note/owner metadata; a user site cannot become a system site. The
// compared fields are the same ones the renderer and the DNS/URI artefacts read, so a field
// the template does not open cannot move (host, cert, MagicDNS, maintenance, target, ...).
func checkSystemUpdate(old, in Site) error {
	if old.Kind != KindSystem {
		if in.Kind == KindSystem {
			return fmt.Errorf("%w: a %s site cannot become a system site", ErrSystemLocked, old.Kind)
		}
		return nil
	}
	if in.Kind != KindSystem {
		return fmt.Errorf("%w: a system site cannot change its kind to %q", ErrSystemLocked, in.Kind)
	}
	fields := []struct {
		name string
		same bool
	}{
		{"system_template", old.SystemTemplate == in.SystemTemplate},
		{"hosts", slices.Equal(old.Hosts, in.Hosts)},
		{"roles", slices.Equal(old.Roles, in.Roles)},
		{"target_roles", slices.Equal(old.TargetRoles, in.TargetRoles)},
		{"open_reason", old.OpenReason == in.OpenReason},
		{"cert", old.Cert == in.Cert},
		{"target", old.TargetKind == in.TargetKind && old.TargetURL == in.TargetURL &&
			old.TargetTLSInsecure == in.TargetTLSInsecure},
		{"magicdns", old.MagicDNS == in.MagicDNS},
		{"maintenance", old.Maintenance == in.Maintenance},
		{"api_rules", slices.Equal(old.APIRules, in.APIRules)},
		{"redirects", slices.Equal(old.Redirects, in.Redirects)},
		{"headers", slices.Equal(old.Headers, in.Headers)},
	}
	for _, f := range fields {
		if !f.same {
			return fmt.Errorf("%w: field %s of the %s template is not editable", ErrSystemLocked, f.name, old.SystemTemplate)
		}
	}
	return nil
}
