package site

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/nesiler/tagcess/internal/dns"
	"github.com/nesiler/tagcess/internal/store/db"
)

// First-import seed (G-01, ADR 0010 m.8). Today's blocks are written once by hand into a
// structured JSON file and loaded here; no Caddyfile reader exists. Loading only ever adds:
// a site that is already stored (same hosts) is left exactly as it is, so a re-load never
// overwrites an edit. A seed that is malformed, fails validation or collides with a stored site
// is refused as a whole before the first record is written (fail closed). Whether the generated
// Caddyfile may be applied is not decided here: the parity gate (internal/render) holds the
// first apply back until the generated file is equivalent to today's.

// SeedOptions carries the seed inputs that are settings, not seed content.
type SeedOptions struct {
	// TagcessHost is the host of the tagcess system site (R1: "host adı ayardan"). The seed file
	// does not carry the tagcess block; the loader adds the canonical record for this host.
	TagcessHost string
	// ZitadelInternalSources is the internal source list of the zitadel template (server IPs).
	// Like TagcessHost it is a setting, not seed content: the fixture keeps real addresses out.
	// Only the zitadel record built for a fresh store uses it (F2-013); login_paths defaults to
	// DefaultZitadelLoginPaths.
	ZitadelInternalSources []string
}

// zitadelSeedConfig builds the canonical zitadel system_config from the seed options. The store
// validates it like any other record.
func zitadelSeedConfig(sources []string) (string, error) {
	body, err := json.Marshal(struct {
		InternalSources []string `json:"internal_sources"`
		LoginPaths      []string `json:"login_paths"`
	}{InternalSources: nonNil(sources), LoginPaths: slices.Clone(DefaultZitadelLoginPaths)})
	if err != nil {
		return "", fmt.Errorf("site seed: zitadel config: %w", err)
	}
	return string(body), nil
}

// SeedResult counts what a load did.
type SeedResult struct {
	Created  int
	Existing int
}

// settingFirstImport is the settings key of the first-import gate state.
const settingFirstImport = "site.first_import"

// First-import gate states. An absent key means no gate (an ordinary store).
const (
	firstImportPending = "pending"
	firstImportPassed  = "passed"
)

type seedFile struct {
	Sites []seedSite `json:"sites"`
}

type seedSite struct {
	Hosts             []string        `json:"hosts"`
	Kind              string          `json:"kind"`
	OpenReason        string          `json:"open_reason"`
	SystemTemplate    string          `json:"system_template"`
	SystemConfig      json.RawMessage `json:"system_config"`
	Roles             []string        `json:"roles"`
	TargetRoles       []string        `json:"target_roles"`
	Cert              string          `json:"cert"`
	Target            string          `json:"target"`
	TargetURL         string          `json:"target_url"`
	TargetTLSInsecure bool            `json:"target_tls_insecure"`
	MagicDNS          bool            `json:"magicdns"`
	Note              string          `json:"note"`
	Owner             string          `json:"owner"`
	APIRules          []seedAPIRule   `json:"api_rules"`
	Redirects         []seedRedirect  `json:"redirects"`
	Headers           []seedHeader    `json:"headers"`
}

type seedAPIRule struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type seedRedirect struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Code   int    `json:"code"`
}

type seedHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// ParseSeed reads and strictly checks a seed file: unknown fields, trailing data and an empty
// site list are errors. It does not validate the site fields; the store's validation does that
// on load.
func ParseSeed(data []byte) ([]Site, error) {
	var file seedFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&file); err != nil {
		return nil, fmt.Errorf("site seed: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("site seed: trailing data after the seed object")
	}
	if len(file.Sites) == 0 {
		return nil, fmt.Errorf("site seed: the seed has no sites")
	}
	sites := make([]Site, 0, len(file.Sites))
	for i, in := range file.Sites {
		s, err := in.site()
		if err != nil {
			return nil, fmt.Errorf("site seed: site %d: %w", i, err)
		}
		sites = append(sites, s)
	}
	return sites, nil
}

// site converts a seed entry to a Site. Every list is non-nil, like a stored site.
func (in seedSite) site() (Site, error) {
	s := Site{
		Hosts:             nonNil(in.Hosts),
		Kind:              in.Kind,
		OpenReason:        in.OpenReason,
		SystemTemplate:    in.SystemTemplate,
		Roles:             nonNil(in.Roles),
		TargetRoles:       nonNil(in.TargetRoles),
		Cert:              in.Cert,
		TargetKind:        in.Target,
		TargetURL:         in.TargetURL,
		TargetTLSInsecure: in.TargetTLSInsecure,
		MagicDNS:          in.MagicDNS,
		Note:              in.Note,
		Owner:             in.Owner,
		APIRules:          []APIRule{},
		Redirects:         []Redirect{},
		Headers:           []Header{},
	}
	if len(in.SystemConfig) > 0 {
		var compact bytes.Buffer
		if err := json.Compact(&compact, in.SystemConfig); err != nil {
			return Site{}, fmt.Errorf("system_config: %w", err)
		}
		s.SystemConfig = compact.String()
	}
	for _, r := range in.APIRules {
		s.APIRules = append(s.APIRules, APIRule(r))
	}
	for _, r := range in.Redirects {
		s.Redirects = append(s.Redirects, Redirect(r))
	}
	for _, h := range in.Headers {
		s.Headers = append(s.Headers, Header(h))
	}
	return s, nil
}

func nonNil(list []string) []string {
	if list == nil {
		return []string{}
	}
	return list
}

// tagcessSite is the canonical tagcess system record for a host (F2-005 shape).
func tagcessSite(host string) Site {
	return Site{
		Hosts:          []string{host},
		Kind:           KindSystem,
		SystemTemplate: TemplateTagcess,
		SystemConfig:   `{}`,
		Roles:          []string{}, TargetRoles: []string{},
		Cert:       "auto",
		TargetKind: TargetK8s,
		MagicDNS:   true,
		APIRules:   []APIRule{}, Redirects: []Redirect{}, Headers: []Header{},
	}
}

// WithTagcess returns the prepared seed records plus the canonical tagcess system record for host, the
// records LoadSeed stores. The first-import comparison uses it so that a tagcess block the installer already
// added to today's file (render.CheckSeedParity compares it only when today's file serves the host) is
// compared with the generated one.
func WithTagcess(sites []Site, host string) []Site {
	for _, s := range sites {
		if s.SystemTemplate == TemplateTagcess {
			return sites
		}
	}
	return append(slices.Clone(sites), tagcessSite(host))
}

// PrepareSeed parses the seed and fills what the loader fills from settings, so the records are
// exactly the ones LoadSeed stores (without the tagcess record): the zitadel internal source list
// is a setting, not seed content (F2-013). The first-import parity preview renders these before
// the load, so it has to see the filled records. A seed that carries the tagcess site is refused.
func PrepareSeed(data []byte, opts SeedOptions) ([]Site, error) {
	seed, err := ParseSeed(data)
	if err != nil {
		return nil, err
	}
	for i, st := range seed {
		if st.SystemTemplate == TemplateTagcess {
			return nil, fmt.Errorf("site seed: site %d: the tagcess site is added from the tagcess host option, not from the seed file", i)
		}
	}
	for i := range seed {
		if seed[i].SystemTemplate == TemplateZitadel {
			cfg, err := zitadelSeedConfig(opts.ZitadelInternalSources)
			if err != nil {
				return nil, err
			}
			seed[i].SystemConfig = cfg
		}
	}
	return seed, nil
}

// LoadSeed loads the seed and the tagcess system site. It is idempotent: a seed site whose hosts
// are exactly the hosts of a stored site counts as existing and is not touched. A site that
// shares only some of its hosts with a stored site, or a host owned by a different site, is a
// conflict (ErrHostTaken). Everything is checked before the first write, so a refused seed
// leaves the store as it was. The first load into a store without first-import state opens the
// first-import gate (FirstImportPending).
func (s *Store) LoadSeed(ctx context.Context, data []byte, opts SeedOptions) (SeedResult, error) {
	seed, err := PrepareSeed(data, opts)
	if err != nil {
		return SeedResult{}, err
	}
	if !validHostname(opts.TagcessHost) {
		return SeedResult{}, fmt.Errorf("site seed: tagcess host %q is not a lowercase RFC 1123 hostname", opts.TagcessHost)
	}

	existing, err := s.ListSites(ctx)
	if err != nil {
		return SeedResult{}, err
	}
	owner := make(map[string]Site)
	hasTagcess := false
	for _, e := range existing {
		for _, h := range e.Hosts {
			owner[h] = e
		}
		if e.SystemTemplate == TemplateTagcess {
			hasTagcess = true
		}
	}

	all := seed
	if !hasTagcess {
		all = append(slices.Clone(seed), tagcessSite(opts.TagcessHost))
	}
	seen := make(map[string]bool)
	var toCreate []Site
	var found int
	for i, st := range all {
		for _, h := range st.Hosts {
			if seen[h] {
				return SeedResult{}, fmt.Errorf("site seed: site %d: host %q appears twice in the seed", i, h)
			}
			seen[h] = true
		}
		match, err := matchStored(st, owner)
		if err != nil {
			return SeedResult{}, fmt.Errorf("site seed: site %d: %w", i, err)
		}
		if match {
			found++
			continue
		}
		if err := s.precheck(ctx, st); err != nil {
			return SeedResult{}, fmt.Errorf("site seed: site %d (%s): %w", i, st.Hosts[0], err)
		}
		toCreate = append(toCreate, st)
	}
	if hasTagcess {
		found++ // the stored tagcess site counts as existing
	}

	for _, st := range toCreate {
		if _, err := s.CreateSite(ctx, st); err != nil {
			return SeedResult{}, fmt.Errorf("site seed: create %s: %w", st.Hosts[0], err)
		}
	}
	if len(toCreate) > 0 {
		if err := s.openFirstImport(ctx); err != nil {
			return SeedResult{}, err
		}
	}
	return SeedResult{Created: len(toCreate), Existing: found}, nil
}

// matchStored reports whether a seed site is already stored: every host owned by one stored site
// that has exactly the same hosts. All hosts free is not a match (the site is to be created);
// anything in between is a conflict.
func matchStored(st Site, owner map[string]Site) (bool, error) {
	var first Site
	owned := 0
	for _, h := range st.Hosts {
		o, ok := owner[h]
		if !ok {
			continue
		}
		if owned > 0 && o.ID != first.ID {
			return false, fmt.Errorf("host %q: %w (the seed block spans several stored sites)", h, ErrHostTaken)
		}
		first = o
		owned++
	}
	switch {
	case owned == 0:
		return false, nil
	case owned == len(st.Hosts) && len(first.Hosts) == len(st.Hosts):
		return true, nil
	default:
		return false, fmt.Errorf("host %q: %w (the stored site %d has hosts %v, the seed block %v)",
			st.Hosts[0], ErrHostTaken, first.ID, first.Hosts, st.Hosts)
	}
}

// precheck runs the checks CreateSite would run, without writing, so a bad record stops the
// whole load before anything is stored.
func (s *Store) precheck(ctx context.Context, st Site) error {
	if err := s.validate.Validate(ctx, st); err != nil {
		return err
	}
	if err := checkSystemShape(st); err != nil {
		return err
	}
	_, err := normalize(st)
	return err
}

// FirstImportPending reports whether the first-import gate is open: the seed was loaded and the
// first apply has not been verified yet. An absent state means no gate. An unreadable or
// unknown value is an error, never "no gate".
func (s *Store) FirstImportPending(ctx context.Context) (bool, error) {
	v, err := s.q.GetSetting(ctx, settingFirstImport)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("site: read first-import state: %w", err)
	}
	switch v {
	case firstImportPending:
		return true, nil
	case firstImportPassed:
		return false, nil
	default:
		return false, fmt.Errorf("site: first-import state %q is neither %s nor %s", v, firstImportPending, firstImportPassed)
	}
}

// CompleteFirstImport closes the gate for good: later site changes are not compared with
// today's file.
func (s *Store) CompleteFirstImport(ctx context.Context) error {
	return s.setFirstImport(ctx, firstImportPassed)
}

// FirstImportDone reports whether the first import already passed (F2-014: the interface hides the
// action once it is complete). An absent state is not done; an unreadable or unknown value is an
// error, never "not done".
func (s *Store) FirstImportDone(ctx context.Context) (bool, error) {
	v, err := s.q.GetSetting(ctx, settingFirstImport)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("site: read first-import state: %w", err)
	}
	switch v {
	case firstImportPassed:
		return true, nil
	case firstImportPending:
		return false, nil
	default:
		return false, fmt.Errorf("site: first-import state %q is neither %s nor %s", v, firstImportPending, firstImportPassed)
	}
}

// openFirstImport opens the gate unless a state already exists (a completed first import is
// never re-opened by a re-load).
func (s *Store) openFirstImport(ctx context.Context) error {
	_, err := s.q.GetSetting(ctx, settingFirstImport)
	if err == nil {
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("site: read first-import state: %w", err)
	}
	return s.setFirstImport(ctx, firstImportPending)
}

func (s *Store) setFirstImport(ctx context.Context, value string) error {
	err := s.q.UpsertSetting(ctx, db.UpsertSettingParams{
		Key: settingFirstImport, Value: value, UpdatedAt: time.Now().UTC().Format(timeFormat),
	})
	if err != nil {
		return fmt.Errorf("site: write first-import state: %w", err)
	}
	return nil
}

// SplitDNSRecords reads today's extra-records for the first import (ADR 0010 "İçe aktarma",
// G-01.1) and returns the manual ones: every record that is not exactly an A record of a
// MagicDNS site host pointing at the VPN address. Those site-derived records are rebuilt from
// the sites on every render, so copying them would only duplicate; everything else (other
// names, other types, a site host with a different value, a host of a site with MagicDNS off)
// is kept untouched as an H-06 manual record. A divergent value for a site host is therefore
// not dropped: the render then reports the conflict instead of silently picking a side.
func SplitDNSRecords(records []dns.Record, sites []Site, vpnAddr string) ([]dns.Record, error) {
	if err := (dns.Record{Name: "check.example.com", Type: dns.TypeA, Value: vpnAddr}).Validate(); err != nil {
		return nil, fmt.Errorf("site seed: dns: vpn address %q is not an IPv4 address", vpnAddr)
	}
	derived := make(map[string]bool)
	for _, st := range sites {
		if !st.MagicDNS {
			continue
		}
		for _, h := range st.Hosts {
			derived[h] = true
		}
	}
	manual := []dns.Record{}
	for i, r := range records {
		if err := r.Validate(); err != nil {
			return nil, fmt.Errorf("site seed: dns record %d: %w", i, err)
		}
		if r.Type == dns.TypeA && r.Value == vpnAddr && derived[r.Name] {
			continue
		}
		manual = append(manual, r)
	}
	return manual, nil
}
