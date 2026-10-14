package site

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// snapshotVersion is the format of a stored source snapshot. A reader refuses any other value, so a
// snapshot written by a newer format is never applied by a guess.
const snapshotVersion = 1

// snapshotDoc is the stored form of a site's source model (ADR 0017, A-03.4): every field a site
// record carries except the row identity and the stamps. The field order is the JSON order, so the
// same site always yields the same bytes.
type snapshotDoc struct {
	V                 int                `json:"v"`
	Hosts             []string           `json:"hosts"`
	Kind              string             `json:"kind"`
	OpenReason        string             `json:"open_reason"`
	SystemTemplate    string             `json:"system_template"`
	SystemConfig      string             `json:"system_config"`
	Roles             []string           `json:"roles"`
	TargetRoles       []string           `json:"target_roles"`
	Cert              string             `json:"cert"`
	TargetKind        string             `json:"target_kind"`
	TargetURL         string             `json:"target_url"`
	TargetTLSInsecure bool               `json:"target_tls_insecure"`
	MagicDNS          bool               `json:"magicdns"`
	Maintenance       bool               `json:"maintenance"`
	Note              string             `json:"note"`
	Owner             string             `json:"owner"`
	APIRules          []snapshotAPIRule  `json:"api_rules"`
	Redirects         []snapshotRedirect `json:"redirects"`
	Headers           []snapshotHeader   `json:"headers"`
}

type snapshotAPIRule struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type snapshotRedirect struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Code   int    `json:"code"`
}

type snapshotHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// MarshalSnapshot encodes a site's source model: hosts, kind, roles, API rules, redirects, headers,
// certificate, target, magicdns, maintenance and owner. The id and the stamps are not part of it; a
// restored site gets its own.
func MarshalSnapshot(s Site) ([]byte, error) {
	d := snapshotDoc{
		V: snapshotVersion, Hosts: nonNil(s.Hosts), Kind: s.Kind, OpenReason: s.OpenReason,
		SystemTemplate: s.SystemTemplate, SystemConfig: s.SystemConfig,
		Roles: nonNil(s.Roles), TargetRoles: nonNil(s.TargetRoles), Cert: s.Cert,
		TargetKind: s.TargetKind, TargetURL: s.TargetURL, TargetTLSInsecure: s.TargetTLSInsecure,
		MagicDNS: s.MagicDNS, Maintenance: s.Maintenance, Note: s.Note, Owner: s.Owner,
		APIRules:  make([]snapshotAPIRule, 0, len(s.APIRules)),
		Redirects: make([]snapshotRedirect, 0, len(s.Redirects)),
		Headers:   make([]snapshotHeader, 0, len(s.Headers)),
	}
	for _, r := range s.APIRules {
		d.APIRules = append(d.APIRules, snapshotAPIRule(r))
	}
	for _, r := range s.Redirects {
		d.Redirects = append(d.Redirects, snapshotRedirect(r))
	}
	for _, h := range s.Headers {
		d.Headers = append(d.Headers, snapshotHeader(h))
	}
	body, err := json.Marshal(d)
	if err != nil {
		return nil, fmt.Errorf("site: encode snapshot: %w", err)
	}
	return body, nil
}

// ParseSnapshot rebuilds the source model from a stored snapshot. It fails closed: an unknown
// version, an unknown field, a wrong type or trailing data is an error, never a partial site. The
// result has no id and no stamps, and every list is non-nil like a stored site. It does not
// validate the record: the store's own checks run when the site is written.
func ParseSnapshot(body []byte) (Site, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var d snapshotDoc
	if err := dec.Decode(&d); err != nil {
		return Site{}, fmt.Errorf("site: parse snapshot: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Site{}, errors.New("site: parse snapshot: trailing data")
	}
	if d.V != snapshotVersion {
		return Site{}, fmt.Errorf("site: parse snapshot: unsupported version %d", d.V)
	}
	s := Site{
		Hosts: nonNil(d.Hosts), Kind: d.Kind, OpenReason: d.OpenReason,
		SystemTemplate: d.SystemTemplate, SystemConfig: d.SystemConfig,
		Roles: nonNil(d.Roles), TargetRoles: nonNil(d.TargetRoles), Cert: d.Cert,
		TargetKind: d.TargetKind, TargetURL: d.TargetURL, TargetTLSInsecure: d.TargetTLSInsecure,
		MagicDNS: d.MagicDNS, Maintenance: d.Maintenance, Note: d.Note, Owner: d.Owner,
		APIRules:  make([]APIRule, 0, len(d.APIRules)),
		Redirects: make([]Redirect, 0, len(d.Redirects)),
		Headers:   make([]Header, 0, len(d.Headers)),
	}
	for _, r := range d.APIRules {
		s.APIRules = append(s.APIRules, APIRule(r))
	}
	for _, r := range d.Redirects {
		s.Redirects = append(s.Redirects, Redirect(r))
	}
	for _, h := range d.Headers {
		s.Headers = append(s.Headers, Header(h))
	}
	return s, nil
}
