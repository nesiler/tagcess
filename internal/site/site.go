// Package site stores and reads the site records behind tagcess's Caddyfile, MagicDNS and
// Zitadel artifacts (ADR 0010). A site row and its ordered sub-records always change together
// in one transaction, and a hostname belongs to exactly one site (F2-002). Every write passes
// through the validation layer first (F2-003): invalid records and writes during a failed role
// read are refused, so the last known-good state is kept.
package site

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Site kinds (ADR 0010).
const (
	KindRole   = "role"
	KindOpen   = "open"
	KindSystem = "system"
)

// Open reasons; only a site of kind open carries one.
const (
	OpenReasonIntentional = "intentional"
	OpenReasonTransition  = "transition"
)

// Locked system templates (ADR 0010); only a site of kind system carries one.
const (
	TemplateZitadel     = "zitadel"
	TemplateHeadscale   = "headscale"
	TemplateWireGuardUI = "wireguard_ui"
	TemplateTagcess     = "tagcess"
)

// Target kinds.
const (
	TargetK8s = "k8s"
	TargetURL = "url"
)

// API exemption rule types (ADR 0011): header presence or path regex, OR-combined.
const (
	APIRuleHeaderPresent = "header_present"
	APIRulePathRegex     = "path_regex"
)

// APIRule is one API exemption rule: a header presence check or a path regex (ADR 0011).
type APIRule struct {
	Type  string
	Value string
}

// Redirect is one site redirect: a source path, a target path or hostname, a redirect code.
type Redirect struct {
	Source string
	Target string
	Code   int
}

// Header is one extra header the site adds to upstream requests.
type Header struct {
	Name  string
	Value string
}

// Site is one managed site with its ordered sub-records (ADR 0010). Every list field of a Site
// returned by the store is non-nil, so callers can range over it without nil checks and the
// stored form round-trips unchanged. SystemConfig carries the template-specific JSON (Codex
// decision on F2-002); its per-template shape is defined and enforced by the template code.
type Site struct {
	ID                int64
	Hosts             []string
	Kind              string
	OpenReason        string
	SystemTemplate    string
	SystemConfig      string
	Roles             []string
	TargetRoles       []string
	Cert              string
	TargetKind        string
	TargetURL         string
	TargetTLSInsecure bool
	MagicDNS          bool
	Maintenance       bool
	Note              string
	Owner             string
	APIRules          []APIRule
	Redirects         []Redirect
	Headers           []Header
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// ErrNotFound is returned when a site id does not exist.
var ErrNotFound = errors.New("site: not found")

// ErrHostTaken is returned when a write would give a site a hostname that already belongs to
// another site (F2-002 AC2); the rejected write leaves every existing record untouched.
var ErrHostTaken = errors.New("site: hostname already belongs to another site")

// timeFormat matches the audit log and the migration seeds: fixed-width milliseconds, so the
// text sorts chronologically in SQLite.
const timeFormat = "2006-01-02T15:04:05.000Z"

// marshalList stores an ordered name list as JSON text. nil is normalized to an empty list so
// every stored value reads back to the same shape.
func marshalList(list []string) string {
	if list == nil {
		list = []string{}
	}
	body, err := json.Marshal(list)
	if err != nil {
		// json.Marshal of a []string cannot fail; fall back to the empty list rather than
		// storing something unreadable.
		return "[]"
	}
	return string(body)
}

// unmarshalList reads back a stored ordered name list. The result is never nil.
func unmarshalList(stored string) ([]string, error) {
	var list []string
	if err := json.Unmarshal([]byte(stored), &list); err != nil {
		return nil, fmt.Errorf("site: parse stored list %q: %w", stored, err)
	}
	if list == nil {
		list = []string{}
	}
	return list, nil
}
