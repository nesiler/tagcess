package change

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/caddy"
	"github.com/nesiler/tagcess/internal/dns"
	"github.com/nesiler/tagcess/internal/gitlog"
	"github.com/nesiler/tagcess/internal/maintenance"
	"github.com/nesiler/tagcess/internal/render"
	"github.com/nesiler/tagcess/internal/site"
	"github.com/nesiler/tagcess/internal/store/db"
	"github.com/nesiler/tagcess/internal/zitadel"
)

// The site change pipeline (F2-011, architecture §4, ADR 0005/0012/0013). One request changes one
// site record and, through it, three artifacts: the Caddyfile, the MagicDNS file and the
// oauth2-proxy redirect URIs. It runs under the same writer lock as the policy pipeline and records
// ONE change row and one audit trail carrying the diff of all three.
//
// Order follows "narrow first, widen last": an add runs DNS → Caddy → Zitadel (the callback that
// lets people log in arrives last), a delete runs Zitadel → Caddy → DNS (the callback goes first).
// An edit runs like an add. The site record is committed only after every artifact was applied, so
// the database always holds the last known-good state.
//
// Failures never guess (rule 7). A step that fails with a proven "nothing changed" outcome either
// rolls the earlier steps back (only for a pure add, where restoring the previous state removes
// access that did not exist before) or raises an alert and keeps them (edits and deletes: restoring
// the previous state could re-open what the change closed). A step whose outcome is unknown keeps
// the live state and raises a critical alert; nothing is rolled back blindly.

// KindSite is the change kind of a site change.
const KindSite = "site"

// Site operations. SiteResync re-applies the stored records over the live artifacts; it carries the
// first import and is the explicit "overwrite" a drift decision asks for, so it skips the drift
// check by design (its diff shows what is overwritten). SiteManualDNS replaces the manual
// MagicDNS records (H-06, F3-008); the request carries the full new set and only the DNS file
// moves (the site records, and with them the Caddy and Zitadel artifacts, stay as they are).
const (
	SiteAdd       = "add"
	SiteUpdate    = "update"
	SiteDelete    = "delete"
	SiteResync    = "resync"
	SiteManualDNS = "manual_dns"
)

// MaxManualDNSRecords is the upper bound of the manual record set (F3-008): a form that carries
// more is refused before anything is planned.
const MaxManualDNSRecords = 500

// Alert kinds of a site change. The alert table keeps only the kind and the change id as its
// source, so each cause has its own kind; the reason text is on the change row and the audit trail.
const (
	// AlertSiteDrift: the change was stopped before the first write because a system could not be
	// read or an artifact differs from the records (rule 7: keep the last known-good state).
	AlertSiteDrift = "site_drift"
	// AlertSiteUnverified: a write's outcome is unknown; the live state was kept, nothing was
	// restored.
	AlertSiteUnverified = "site_unverified"
	// AlertSitePartial: some steps were applied and the change stopped; they were kept because
	// restoring them could widen access.
	AlertSitePartial = "site_partial"
	// AlertSiteRollbackFailed: a rollback step failed; the remaining state was kept.
	AlertSiteRollbackFailed = "site_rollback_failed"
	// AlertSiteCaddyFile: the Caddyfile was loaded but could not be written to disk (S-04.2): a
	// restart would run the stale file.
	AlertSiteCaddyFile = "site_caddy_file"
	// AlertSiteDNSUnverified: the resolver did not confirm a changed name (ADR 0013 m.5, F2-006);
	// the file was kept.
	AlertSiteDNSUnverified = "site_dns_unverified"
	// AlertSiteBookkeepingFailed: the artifacts were applied but a record (site row, change, audit,
	// ownership set) could not be written.
	AlertSiteBookkeepingFailed = "site_bookkeeping_failed"
)

// siteResolvedAlerts are the alerts a clean apply proves gone: the drift check before it showed the
// artifacts equal the records, the apply then made them equal the new records. The bookkeeping
// alert stays: the record it reports as lost stays lost.
var siteResolvedAlerts = []string{
	AlertSiteDrift, AlertSiteUnverified, AlertSitePartial, AlertSiteRollbackFailed,
	AlertSiteCaddyFile, AlertSiteDNSUnverified,
}

// StatusNoChange is the result of a first import that has nothing left to do.
const StatusNoChange = "no_change"

// SiteRequest is one site change. Site is the full new record for add and update; ID names the
// stored site for update and delete. ManualDNS is the full new manual record set of a
// manual_dns request.
type SiteRequest struct {
	Actor string
	Op    string
	ID    int64
	Site  site.Site
	// ManualDNS is the new manual MagicDNS record set (SiteManualDNS); it replaces the stored set
	// as a whole, so a delete is a set without the record.
	ManualDNS []dns.Record
	// RollbackOf is the site version this request re-applies (F2-020, ADR 0017); 0 for an ordinary
	// change. It only labels the change, the audit trail and the new version: the request runs the
	// same pipeline either way.
	RollbackOf int64
}

// SiteStore is the site record surface the pipeline needs (satisfied by *site.Store). The Preview
// methods run the whole write for its checks without committing.
type SiteStore interface {
	ListSites(ctx context.Context) ([]site.Site, error)
	PreviewCreateSite(ctx context.Context, in site.Site) (site.Site, error)
	PreviewUpdateSite(ctx context.Context, id int64, in site.Site) (site.Site, error)
	PreviewDeleteSite(ctx context.Context, id int64) error
	CreateSite(ctx context.Context, in site.Site) (site.Site, error)
	UpdateSite(ctx context.Context, id int64, in site.Site) (site.Site, error)
	DeleteSite(ctx context.Context, id int64) error
	LoadSeed(ctx context.Context, data []byte, opts site.SeedOptions) (site.SeedResult, error)
	FirstImportPending(ctx context.Context) (bool, error)
	CompleteFirstImport(ctx context.Context) error
	SetManualDNS(ctx context.Context, recs []dns.Record) error
}

// SiteCaddy is the Caddy surface: the file a restart would run, the running config, the apply of
// internal/caddy and the adapter for the first-import parity gate. NewCaddyFile adapts the real
// client.
type SiteCaddy interface {
	Current(ctx context.Context) (string, error)
	Live(ctx context.Context) ([]byte, error)
	Apply(ctx context.Context, sites []site.Site, target string) error
	AdaptJSON(ctx context.Context, caddyfile string) ([]byte, error)
}

// SiteDNS is the MagicDNS file surface: read the file, write the record set (with resolver
// verification) and write previous content back. NewDNSFile adapts internal/dns.
type SiteDNS interface {
	Current(ctx context.Context) (content string, exists bool, err error)
	Apply(ctx context.Context, records []dns.Record) ([]dns.Mismatch, error)
	Restore(ctx context.Context, content string) error
}

// SiteURIs is the oauth2-proxy redirect URI surface (satisfied by *zitadel.URISync).
type SiteURIs interface {
	Sync(ctx context.Context, sites []site.Site) (zitadel.URIResult, error)
	CheckDrift(ctx context.Context, sites []site.Site) (zitadel.URIResult, error)
	// OwnedURIs returns O, the set the last successful Sync wrote; ok is false while none is stored.
	OwnedURIs(ctx context.Context) (uris []string, ok bool, err error)
}

// SiteSettings are the render inputs that do not come from site records. They are read on every
// request so a changed S-06 key or ACME email is used by the next change and by the drift check.
type SiteSettings struct {
	Caddy     render.CaddyConfig
	DNS       render.DNSConfig
	ManualDNS []dns.Record
}

// SiteVersions is the durable version surface (A-03.4, satisfied by *site.Store): every applied
// change records one version per site it touched.
type SiteVersions interface {
	RecordVersion(ctx context.Context, v site.NewVersion) (site.Version, bool, error)
	GetVersion(ctx context.Context, id int64) (site.Version, error)
	BindRevision(ctx context.Context, changeID int64, revision string) error
}

// SiteConfig wires a SitePipeline. Every field except Clock, Git, Versions and Maintenance is
// required. Git is the local history (F2-019, A-02); without it nothing is committed. Versions
// defaults to Sites when it also implements SiteVersions (the real store does); a pipeline without it
// records no versions and cannot roll back. Maintenance defaults to the gate over Queries.
type SiteConfig struct {
	Queries     *db.Queries
	Audit       *audit.Logger
	DryRun      DryRun
	Sites       SiteStore
	Caddy       SiteCaddy
	DNS         SiteDNS
	URIs        SiteURIs
	Git         ArtifactGit
	Versions    SiteVersions
	Settings    func(ctx context.Context) (SiteSettings, error)
	Maintenance MaintenanceGate
	Clock       func() time.Time
	// PolicyBaseline, when set, is called once a first import completed: it records the live policy
	// as the applied baseline so the drift check can compare it (F5 I9). A failure is logged and
	// never fails the import. Optional.
	PolicyBaseline func(ctx context.Context, actor string) error
	// OnApplied, when set, is called after every applied change (add, edit, delete, resync,
	// rollback). It must not block; cmd/tagcess triggers the monitoring loops with it so the drift
	// alerts are re-measured right away (F5 L3). Optional.
	OnApplied func()
}

// SiteDiff is the per-artifact change as "+line" / "-line" text; empty means the artifact does
// not change.
type SiteDiff struct {
	Caddy   string `json:"caddy,omitempty"`
	DNS     string `json:"dns,omitempty"`
	Zitadel string `json:"zitadel,omitempty"`
}

// SitePlan is what a request would do: the operation, the hosts it touches and the diff.
type SitePlan struct {
	Op    string
	Hosts []string
	Diff  SiteDiff
}

// SiteResult is what the pipeline did with a request.
type SiteResult struct {
	Result
	Plan SitePlan
}

// SitePipeline applies site changes. Use NewSite.
type SitePipeline struct {
	base     *Pipeline // change/alert/audit plumbing shared with the policy pipeline
	sites    SiteStore
	caddy    SiteCaddy
	dns      SiteDNS
	uris     SiteURIs
	git      ArtifactGit
	versions SiteVersions
	settings func(ctx context.Context) (SiteSettings, error)
	maint    MaintenanceGate
	baseline func(ctx context.Context, actor string) error
	applied  func()
}

// NewSite validates the wiring and returns the pipeline.
func NewSite(cfg SiteConfig) (*SitePipeline, error) {
	switch {
	case cfg.Queries == nil:
		return nil, errors.New("change: site pipeline needs a query set")
	case cfg.Audit == nil:
		return nil, errors.New("change: site pipeline needs an audit logger")
	case cfg.DryRun == nil:
		return nil, errors.New("change: site pipeline needs a dry-run source")
	case cfg.Sites == nil, cfg.Caddy == nil, cfg.DNS == nil, cfg.URIs == nil:
		return nil, errors.New("change: site pipeline needs the site store and the caddy, dns and zitadel surfaces")
	case cfg.Settings == nil:
		return nil, errors.New("change: site pipeline needs a settings source")
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	versions := cfg.Versions
	if versions == nil {
		versions, _ = cfg.Sites.(SiteVersions)
	}
	maint := cfg.Maintenance
	if maint == nil {
		maint = maintenance.New(cfg.Queries)
	}
	return &SitePipeline{
		base:     &Pipeline{q: cfg.Queries, log: cfg.Audit, dryRun: cfg.DryRun, clock: clock},
		sites:    cfg.Sites,
		caddy:    cfg.Caddy,
		dns:      cfg.DNS,
		uris:     cfg.URIs,
		git:      cfg.Git,
		versions: versions,
		settings: cfg.Settings,
		maint:    maint,
		baseline: cfg.PolicyBaseline,
		applied:  cfg.OnApplied,
	}, nil
}

// ErrBlocked marks a Preview error that describes a problem of the existing state (an unreadable
// system, a drift, a record that no longer renders) rather than of the request: the change is
// refused as blocked, and the operator reconciles the state instead of fixing the form. Every
// blockedError unwraps to it, so callers can tell the two classes apart without this package's
// private types (F2-014 review screens).
var ErrBlocked = errors.New("change: blocked by the existing state")

// blockedError marks a problem with the existing state (an unreadable system, a drift, a record that
// no longer renders). The request is not at fault; the change is recorded as blocked and alerted.
type blockedError struct{ reason string }

func (e *blockedError) Error() string { return e.reason }

func (e *blockedError) Unwrap() error { return ErrBlocked }

func blockedf(format string, args ...any) error {
	return &blockedError{reason: fmt.Sprintf(format, args...)}
}

// TargetManualDNS is the audit target of a manual record change: the DNS file is the only
// artifact it touches.
const TargetManualDNS = "dns:*"

// ValidateManualRecord checks one manual record against the stored sites (security.md §5): the
// name follows the hostname rule, the value is a plain IP of the record's own family, and the
// name is not a MagicDNS site host — that name is owned by the site's own A record, and any
// manual record for it would collide in the next render (the F2-022 import rule).
func ValidateManualRecord(rec dns.Record, sites []site.Site) error {
	if err := rec.Validate(); err != nil {
		return err
	}
	for _, s := range sites {
		if !s.MagicDNS {
			continue
		}
		if slices.Contains(s.Hosts, rec.Name) {
			return fmt.Errorf("dns record: name %s belongs to site %s; a manual record for a site host is refused", rec.Name, s.Hosts[0])
		}
	}
	return nil
}

// ValidateManualSet checks a whole manual record set: the cap, every record, and one record per
// name and type (a name with two values would be refused by the render anyway; refusing here
// keeps the error next to the record, F3-008 AC3).
func ValidateManualSet(recs []dns.Record, sites []site.Site) error {
	if len(recs) > MaxManualDNSRecords {
		return fmt.Errorf("dns records: %d manual records exceed the cap of %d", len(recs), MaxManualDNSRecords)
	}
	seen := make(map[string]dns.Record, len(recs))
	for i, r := range recs {
		if err := ValidateManualRecord(r, sites); err != nil {
			return fmt.Errorf("dns record %d: %w", i, err)
		}
		key := r.Name + "/" + r.Type
		if old, ok := seen[key]; ok {
			return fmt.Errorf("dns record %d: duplicate %s %s (%s and %s)", i, r.Name, r.Type, old.Value, r.Value)
		}
		seen[key] = r
	}
	return nil
}

// sitePlan is a request planned against the current state.
type sitePlan struct {
	SitePlan
	current, after []site.Site
	target         string // audit target
	settings       SiteSettings

	// Caddy: the file a restart runs now, the render of the current records (drift baseline, "" when
	// it was not made) and the target.
	diskCaddy, caddyBaseline, caddyTarget string
	// DNS: the file content now, whether it exists, the render of the current records and the target.
	dnsContent, dnsBaseline string
	dnsExists               bool
	dnsTarget               []dns.Record
	// manual is the size of a manual_dns request's set, for the change summary.
	manual int

	// The verified final artifacts the history is given after the apply.
	dnsTargetBody string
	afterURIs     []string

	needCaddy, needDNS, needZitadel bool
	pending                         bool // the first import is not complete
}

// Preview plans a request without writing anything: it validates the record against the store rules,
// renders the three artifacts and returns their diff (S-04.3). A problem with the existing state is
// an error here.
func (s *SitePipeline) Preview(ctx context.Context, req SiteRequest) (SitePlan, error) {
	if err := validateActor(req.Actor); err != nil {
		return SitePlan{}, err
	}
	writerLock.Lock()
	defer writerLock.Unlock()
	pl, err := s.plan(ctx, req, nil)
	if err != nil {
		return SitePlan{}, err
	}
	return pl.SitePlan, nil
}

// PreviewSettings plans a resync against an explicit settings snapshot without writing anything
// (ADR 0010 m.5, F2-015): a render-input change such as the S-06 key shows the diff it would
// produce before the new value is stored. Like Preview, a problem with the existing state is an
// error here.
func (s *SitePipeline) PreviewSettings(ctx context.Context, settings SiteSettings) (SitePlan, error) {
	writerLock.Lock()
	defer writerLock.Unlock()
	pl, err := s.plan(ctx, SiteRequest{Op: SiteResync}, &settings)
	if err != nil {
		return SitePlan{}, err
	}
	return pl.SitePlan, nil
}

// Submit plans and applies a request. A request the store refuses (invalid record, locked system
// site, taken host) is an error and writes nothing. A problem with the existing state is recorded as
// StatusBlocked. Everything else is a result: applied, failed, rolled_back or dry_run.
func (s *SitePipeline) Submit(ctx context.Context, req SiteRequest) (SiteResult, error) {
	if err := validateActor(req.Actor); err != nil {
		return SiteResult{}, err
	}
	writerLock.Lock()
	defer writerLock.Unlock()
	return s.submitLocked(ctx, req)
}

// FirstImport is the G-01 first import: it loads the seed (adds only, idempotent), then re-applies
// the stored records over today's artifacts. The first apply is held back by the parity gate until
// the generated Caddyfile is equivalent to today's file, and the gate is closed only after that
// apply succeeded. Once the import is complete it returns StatusNoChange.
//
// While the gate is open, every attempt first reads today's DNS file and stores its non-site
// records as the manual set (F2-022): they are written before the first DNS write so no render
// can drop them, and a retry re-derives the same set from its own output because the site-derived
// records are never part of it. A file that cannot be kept faithfully (it does not parse, holds an
// invalid record or one that collides with a site host) is an error before anything is written.
func (s *SitePipeline) FirstImport(ctx context.Context, actor string, seed []byte, opts site.SeedOptions) (SiteResult, error) {
	if err := validateActor(actor); err != nil {
		return SiteResult{}, err
	}
	writerLock.Lock()
	defer writerLock.Unlock()
	if _, err := s.sites.LoadSeed(ctx, seed, opts); err != nil {
		return SiteResult{}, err
	}
	pending, err := s.sites.FirstImportPending(ctx)
	if err != nil {
		return SiteResult{}, err
	}
	if !pending {
		return SiteResult{Result: Result{Status: StatusNoChange}}, nil
	}
	if err := s.importManualDNS(ctx); err != nil {
		return SiteResult{}, err
	}
	return s.submitLocked(ctx, SiteRequest{Actor: actor, Op: SiteResync})
}

// importManualDNS stores the manual records of today's DNS file (see FirstImport). The caller holds
// the writer lock.
func (s *SitePipeline) importManualDNS(ctx context.Context) error {
	stored, err := s.sites.ListSites(ctx)
	if err != nil {
		return fmt.Errorf("change: list sites: %w", err)
	}
	cfg, err := s.settings(ctx)
	if err != nil {
		return fmt.Errorf("change: read settings: %w", err)
	}
	content, exists, err := s.dns.Current(ctx)
	if err != nil {
		return fmt.Errorf("change: read the dns file: %w", err)
	}
	// The file can disappear out of band between two pending attempts. A missing file derives an
	// empty manual set; overwriting one an earlier attempt already stored would drop the live
	// records on the next render. Keep the stored set instead (rule 7).
	if !exists && len(cfg.ManualDNS) > 0 {
		return nil
	}
	manual, err := render.ImportManualDNS(content, exists, stored, cfg.DNS)
	if err != nil {
		return fmt.Errorf("change: manual dns records: %w", err)
	}
	if err := s.sites.SetManualDNS(ctx, manual); err != nil {
		return fmt.Errorf("change: store manual dns records: %w", err)
	}
	return nil
}

// CheckURIDrift is the periodic Y-02 hook (ADR 0012 step 6): it runs the F2-010 comparison of the
// redirect URI list with the site records. The drift alert itself is raised and resolved by that
// check; the returned error names what differs (or why the list could not be read) so the caller
// can log it. It does nothing while the first import is pending: there is no ownership baseline
// before the first apply.
func (s *SitePipeline) CheckURIDrift(ctx context.Context) error {
	writerLock.Lock()
	defer writerLock.Unlock()
	pending, err := s.sites.FirstImportPending(ctx)
	if err != nil {
		return err
	}
	if pending {
		return nil
	}
	sites, err := s.sites.ListSites(ctx)
	if err != nil {
		return err
	}
	res, err := s.uris.CheckDrift(ctx, sites)
	if err != nil {
		return fmt.Errorf("change: redirect URI check: %w", err)
	}
	if len(res.Drift) > 0 {
		return fmt.Errorf("change: redirect URI drift: %s", describeDrift(res.Drift))
	}
	return nil
}

func describeDrift(drift []zitadel.URIDrift) string {
	parts := make([]string, 0, len(drift))
	for _, d := range drift {
		part := d.Kind
		switch {
		case d.URI != "":
			part += " " + d.URI
		case d.Detail != "":
			part += " (" + d.Detail + ")"
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, "; ")
}

// submitLocked is plan → gates → drift check → apply. The caller holds the writer lock.
func (s *SitePipeline) submitLocked(ctx context.Context, req SiteRequest) (SiteResult, error) {
	pl, err := s.plan(ctx, req, nil)
	var blocked *blockedError
	switch {
	case errors.As(err, &blocked):
		return s.conclude(ctx, req, pl, outcome{status: StatusBlocked, reason: blocked.reason, alerts: []string{AlertSiteDrift}})
	case err != nil:
		return SiteResult{}, err
	}

	if pl.pending && req.Op != SiteResync {
		return s.conclude(ctx, req, pl, outcome{
			status: StatusBlocked, alerts: []string{AlertSiteDrift},
			reason: "ilk import tamamlanmadı; önce seed apply edilmeli",
		})
	}
	// Dry run is read under the writer lock right before the first external call (Y-06): it wins
	// over everything below and writes nothing, not even the site record.
	on, derr := s.base.dryRun.DryRun(ctx)
	if derr != nil {
		return SiteResult{}, fmt.Errorf("change: read dry-run: %w", derr)
	}
	if on {
		return SiteResult{Result: Result{Status: StatusDryRun}, Plan: pl.SitePlan}, nil
	}

	// The maintenance gate (H-07, F3b-017): while a host config change is open, a change that would
	// write the MagicDNS file is refused here, before the first external call. It reads the durable
	// flag under the writer lock and fails closed; a change that leaves the DNS records alone still
	// runs. Preview and the dry run above are read-only and stay available.
	if pl.writesDNS() {
		if err := s.maint.CheckWidening(ctx, maintenance.SourceAdmin); err != nil {
			return s.conclude(ctx, req, pl, outcome{status: StatusBlocked, reason: err.Error()})
		}
	}

	if reason := s.gate(ctx, req, pl); reason != "" {
		return s.conclude(ctx, req, pl, outcome{status: StatusBlocked, reason: reason, alerts: []string{AlertSiteDrift}})
	}

	o := s.apply(ctx, req, pl)
	res, err := s.conclude(ctx, req, pl, o)
	if err == nil && res.Status == StatusApplied && s.applied != nil {
		s.applied()
	}
	return res, err
}

// plan validates the request against the store rules, renders the target artifacts and diffs them
// against what is on disk. The first error class (blockedError) is a problem with the existing
// state; any other error is the request's. A non-nil override replaces the settings source for
// this one plan.
func (s *SitePipeline) plan(ctx context.Context, req SiteRequest, override *SiteSettings) (*sitePlan, error) {
	current, err := s.sites.ListSites(ctx)
	if err != nil {
		return nil, fmt.Errorf("change: list sites: %w", err)
	}
	pl := &sitePlan{current: current, SitePlan: SitePlan{Op: req.Op}}
	pl.after, pl.target, pl.Hosts, err = s.propose(ctx, req, current)
	if err != nil {
		return nil, err
	}
	if req.Op == SiteManualDNS {
		pl.manual = len(req.ManualDNS)
	}
	if pl.pending, err = s.sites.FirstImportPending(ctx); err != nil {
		return pl, blockedf("ilk import durumu okunamadı: %v", err)
	}
	if override != nil {
		// An explicit snapshot (PreviewSettings): the S-06 key change plans the diff it would
		// produce before the new value is stored (ADR 0010 m.5, F2-015).
		pl.settings = *override
	} else if pl.settings, err = s.settings(ctx); err != nil {
		return pl, blockedf("ayarlar okunamadı: %v", err)
	}
	cfg := pl.settings

	// Baselines: what the artifacts must look like if nothing drifted. Not made while the first
	// import is pending (there is no baseline yet) or for a resync (it overwrites on purpose).
	haveBaseline := !pl.pending && req.Op != SiteResync
	var curRecords []dns.Record
	var curURIs []string
	if haveBaseline {
		if pl.caddyBaseline, err = render.RenderCaddyfile(current, cfg.Caddy); err != nil {
			return pl, blockedf("kayıtlı siteler Caddyfile'a üretilemiyor: %v", err)
		}
		if curRecords, err = render.RenderDNSRecords(current, cfg.ManualDNS, cfg.DNS); err != nil {
			return pl, blockedf("kayıtlı siteler DNS kayıtlarına üretilemiyor: %v", err)
		}
		if pl.dnsBaseline, err = dns.Marshal(curRecords); err != nil {
			return pl, blockedf("DNS kayıtları yazılamıyor: %v", err)
		}
		if curURIs, err = zitadel.DesiredURIs(current); err != nil {
			return pl, blockedf("kayıtlı siteler redirect URI'lerine üretilemiyor: %v", err)
		}
	}
	if req.Op == SiteResync {
		// A resync's Zitadel baseline is O, what the last successful sync wrote (F5 L2): against
		// nothing, every callback looked like an addition even right after a resync. With no O
		// stored yet the baseline stays empty.
		if curURIs, _, err = s.uris.OwnedURIs(ctx); err != nil {
			return pl, blockedf("Zitadel ownership kaydı okunamadı: %v", err)
		}
	}

	// Targets. For a request that adds or edits, a render failure is the request's fault; for a
	// resync the stored records themselves are what fails.
	renderFail := func(format string, args ...any) error {
		if req.Op == SiteResync {
			return blockedf(format, args...)
		}
		return fmt.Errorf(format, args...)
	}
	if pl.caddyTarget, err = render.RenderCaddyfile(pl.after, cfg.Caddy); err != nil {
		return pl, renderFail("Caddyfile üretilemedi: %v", err)
	}
	// A manual_dns request renders its own set (the stored one is what it replaces); every other
	// operation renders the stored set.
	manual := cfg.ManualDNS
	if req.Op == SiteManualDNS {
		manual = req.ManualDNS
	}
	if pl.dnsTarget, err = render.RenderDNSRecords(pl.after, manual, cfg.DNS); err != nil {
		return pl, renderFail("DNS kayıtları üretilemedi: %v", err)
	}
	// The apply refuses a set without the four locked system records; refusing here, before the DNS
	// step, keeps a broken stored set from leaving a half-applied change behind (S-05). A system
	// site cannot be deleted through the store, so this is always a problem of the stored set.
	if err := caddy.RequireSystemSites(pl.after); err != nil {
		return pl, blockedf("%v", err)
	}
	dnsTargetBody, err := dns.Marshal(pl.dnsTarget)
	if err != nil {
		return pl, renderFail("DNS kayıtları yazılamadı: %v", err)
	}
	afterURIs, err := zitadel.DesiredURIs(pl.after)
	if err != nil {
		return pl, renderFail("redirect URI'leri üretilemedi: %v", err)
	}
	pl.dnsTargetBody, pl.afterURIs = dnsTargetBody, afterURIs

	// What is live now.
	if pl.diskCaddy, err = s.caddy.Current(ctx); err != nil {
		return pl, blockedf("Caddyfile okunamadı: %v", err)
	}
	if pl.dnsContent, pl.dnsExists, err = s.dns.Current(ctx); err != nil {
		return pl, blockedf("DNS dosyası okunamadı: %v", err)
	}

	// The diff is against the file on disk; Zitadel's live list is read by the step itself, so its
	// diff is between the records' desired sets (for a resync: O against the desired set).
	pl.Diff.Caddy = lineDiff(pl.diskCaddy, pl.caddyTarget)
	pl.Diff.DNS = lineDiff(pl.dnsContent, dnsTargetBody)
	pl.Diff.Zitadel = lineDiff(strings.Join(curURIs, "\n"), strings.Join(afterURIs, "\n"))
	resync := req.Op == SiteResync
	pl.needCaddy = pl.Diff.Caddy != "" || resync
	pl.needDNS = pl.Diff.DNS != "" || resync
	pl.needZitadel = pl.Diff.Zitadel != "" || resync
	return pl, nil
}

// propose applies the request to the stored set in memory, through the store's own preview so the
// validation, system locks and host ownership are the ones the commit will use. It returns the new
// set, the audit target and the hosts the change touches.
func (s *SitePipeline) propose(ctx context.Context, req SiteRequest, current []site.Site) (after []site.Site, target string, hosts []string, err error) {
	after = slices.Clone(current)
	switch req.Op {
	case SiteAdd:
		created, err := s.sites.PreviewCreateSite(ctx, req.Site)
		if err != nil {
			return nil, "", nil, err
		}
		return append(after, created), siteTarget(created.Hosts), created.Hosts, nil
	case SiteUpdate:
		updated, err := s.sites.PreviewUpdateSite(ctx, req.ID, req.Site)
		if err != nil {
			return nil, "", nil, err
		}
		i := slices.IndexFunc(after, func(x site.Site) bool { return x.ID == req.ID })
		if i < 0 {
			return nil, "", nil, site.ErrNotFound
		}
		after[i] = updated
		return after, siteTarget(updated.Hosts), updated.Hosts, nil
	case SiteDelete:
		if err := s.sites.PreviewDeleteSite(ctx, req.ID); err != nil {
			return nil, "", nil, err
		}
		i := slices.IndexFunc(after, func(x site.Site) bool { return x.ID == req.ID })
		if i < 0 {
			return nil, "", nil, site.ErrNotFound
		}
		gone := after[i].Hosts
		return slices.Delete(after, i, i+1), siteTarget(gone), gone, nil
	case SiteResync:
		return after, "site:*", nil, nil
	case SiteManualDNS:
		// The manual set replaces the stored one as a whole; the site records do not move. The
		// validation is the request's fault, so it is a plain error, not a block.
		if err := ValidateManualSet(req.ManualDNS, current); err != nil {
			return nil, "", nil, err
		}
		return after, TargetManualDNS, nil, nil
	default:
		return nil, "", nil, fmt.Errorf("change: unknown site operation %q", req.Op)
	}
}

func siteTarget(hosts []string) string {
	if len(hosts) == 0 {
		return "site:*"
	}
	return "site:" + hosts[0]
}

// gate is everything that must hold before the first write and needs a read of an external system:
// the first-import parity gate, or the drift check. It returns the reason that blocks the change,
// "" when the change may proceed.
func (s *SitePipeline) gate(ctx context.Context, req SiteRequest, pl *sitePlan) string {
	if pl.pending {
		// Only a resync gets here. A file that already is the target is this pipeline's own output
		// from an earlier, partial first import; it carries the tagcess block today's file never had,
		// so comparing it with today's meaning would block every retry.
		if pl.diskCaddy == pl.caddyTarget {
			return ""
		}
		// The generated Caddyfile must mean what today's file means.
		err := render.GateFirstImport(ctx, s.sites, s.caddy.AdaptJSON, pl.diskCaddy, pl.after, pl.settings.Caddy)
		if err != nil {
			return err.Error()
		}
		return ""
	}
	if req.Op == SiteResync {
		return ""
	}
	// Drift: every artifact must equal the render of the stored records, and the systems must be
	// readable. A drifted artifact is never silently overwritten (architecture §7).
	var problems []string
	if pl.diskCaddy != pl.caddyBaseline {
		problems = append(problems, "Caddyfile kayıtlardan farklı (elle değiştirilmiş olabilir):\n"+lineDiff(pl.caddyBaseline, pl.diskCaddy))
	}
	if _, err := s.caddy.Live(ctx); err != nil {
		problems = append(problems, "Caddy admin API okunamadı: "+err.Error())
	}
	if pl.dnsContent != pl.dnsBaseline {
		problems = append(problems, "DNS dosyası kayıtlardan farklı veya yok:\n"+lineDiff(pl.dnsBaseline, pl.dnsContent))
	}
	res, err := s.uris.CheckDrift(ctx, pl.current)
	switch {
	case err != nil:
		problems = append(problems, "Zitadel redirect URI listesi okunamadı: "+err.Error())
	case len(res.Drift) > 0:
		problems = append(problems, "Zitadel redirect URI listesi kayıtlardan farklı: "+describeDrift(res.Drift))
	}
	return strings.Join(problems, "\n")
}

// stepOutcome is how one artifact step ended.
type stepOutcome int

const (
	stepApplied stepOutcome = iota
	// stepNothingChanged: the step failed and the artifact is proven unchanged.
	stepNothingChanged
	// stepUnknown: the step failed and the artifact may or may not have changed.
	stepUnknown
	// stepFileNotWritten: Caddy loaded the target but the file write failed and the previous config
	// was not loaded back.
	stepFileNotWritten
	// stepFileRestored: Caddy's file write failed and the previous config is live again.
	stepFileRestored
)

// outcome is the end state of a request, handed to conclude.
type outcome struct {
	status string // StatusApplied, StatusFailed, StatusRolledBack or StatusBlocked
	reason string
	alerts []string
	// dnsWarn are the resolver mismatches of the DNS step (a warning, the file is kept).
	dnsWarn []dns.Mismatch
	// err is returned to the caller next to the result (a record that could not be written).
	err error
	// afterApply runs after the records were written for an applied change (closing the first
	// import); an error there is a bookkeeping failure.
	finalize func(ctx context.Context) error
	// stored is the site record an add or an update committed (the source of its version).
	stored *site.Site
}

// apply runs the steps in order and decides what a failure means. The caller holds the lock.
func (s *SitePipeline) apply(ctx context.Context, req SiteRequest, pl *sitePlan) outcome {
	// Record the intent before the first external write: if it cannot be stored, nothing is written,
	// and a crash mid-apply still leaves a trace (A-01.1).
	if err := s.auditEvent(ctx, req, pl, "site.apply_start", "started", ""); err != nil {
		return outcome{status: StatusFailed, reason: "niyet kaydı yazılamadı, hiçbir şey apply edilmedi: " + err.Error(), err: err}
	}

	order := []string{"dns", "caddy", "zitadel"}
	if req.Op == SiteDelete {
		order = []string{"zitadel", "caddy", "dns"}
	}
	// Only a pure add may roll back: restoring the previous artifacts then removes access that did
	// not exist before. For an edit or a delete the previous state may be wider (rule 7).
	canRollBack := req.Op == SiteAdd

	var o outcome
	var done []string
	for _, step := range order {
		if !pl.needs(step) {
			continue
		}
		res, detail := s.runStep(ctx, step, pl, &o)
		if res == stepApplied {
			done = append(done, step)
			continue
		}
		return s.failStep(ctx, pl, step, res, detail, done, canRollBack, o)
	}

	stored, err := s.commit(ctx, req)
	if err != nil {
		o.status = StatusFailed
		o.reason = "artifact'ler apply edildi ama site kaydı yazılamadı: " + err.Error()
		o.alerts = append(o.alerts, AlertSiteBookkeepingFailed)
		o.err = err
		return o
	}
	o.status = StatusApplied
	o.stored = stored
	if req.Op == SiteResync && pl.pending {
		o.finalize = func(ctx context.Context) error {
			if err := s.sites.CompleteFirstImport(ctx); err != nil {
				return err
			}
			if s.baseline != nil {
				if err := s.baseline(ctx, req.Actor); err != nil {
					slog.Default().Warn("first import: policy baseline not recorded", "err", err)
				}
			}
			return nil
		}
	}
	return o
}

func (pl *sitePlan) needs(step string) bool {
	switch step {
	case "dns":
		return pl.needDNS
	case "caddy":
		return pl.needCaddy
	default:
		return pl.needZitadel
	}
}

// writesDNS reports whether applying the change would write the MagicDNS extra-records file. It is
// needDNS, not the diff: a resync runs the DNS step (which rewrites the file) even when the
// rendered records equal the file on disk, so only a change that leaves needDNS false (a Caddy or
// redirect-URI edit) is free of the Headscale DNS write (F3b-017).
func (pl *sitePlan) writesDNS() bool { return pl.needDNS }

// commit writes the site record and returns it for an add or an update. It runs only after every
// artifact was applied.
func (s *SitePipeline) commit(ctx context.Context, req SiteRequest) (*site.Site, error) {
	rctx, cancel := recovery(ctx)
	defer cancel()
	var (
		stored site.Site
		err    error
	)
	switch req.Op {
	case SiteAdd:
		stored, err = s.sites.CreateSite(rctx, req.Site)
	case SiteUpdate:
		stored, err = s.sites.UpdateSite(rctx, req.ID, req.Site)
	case SiteDelete:
		return nil, s.sites.DeleteSite(rctx, req.ID)
	case SiteManualDNS:
		// The only record a manual_dns change writes: the set every later render merges in.
		return nil, s.sites.SetManualDNS(rctx, req.ManualDNS)
	default:
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &stored, nil
}

// runStep performs one artifact step. A DNS resolver mismatch is added to o as a warning and does
// not fail the step.
func (s *SitePipeline) runStep(ctx context.Context, step string, pl *sitePlan, o *outcome) (stepOutcome, string) {
	switch step {
	case "dns":
		mismatches, err := s.dns.Apply(ctx, pl.dnsTarget)
		if err != nil {
			// dns.Apply writes through a temp file and a rename: an error leaves the previous file.
			return stepNothingChanged, "DNS dosyası yazılamadı: " + err.Error()
		}
		o.dnsWarn = append(o.dnsWarn, mismatches...)
		return stepApplied, ""
	case "caddy":
		return s.runCaddy(ctx, pl)
	default:
		res, err := s.uris.Sync(ctx, pl.after)
		if err == nil {
			return stepApplied, ""
		}
		kinds := map[string]bool{}
		for _, d := range res.Drift {
			kinds[d.Kind] = true
		}
		switch {
		case kinds[zitadel.DriftWriteFailed]:
			// The write may have reached Zitadel even though it could not be verified.
			return stepUnknown, "Zitadel redirect URI yazısı doğrulanamadı: " + err.Error()
		case res.Written && (kinds[zitadel.DriftOwnedNotSaved] || len(res.Drift) == 0):
			// Written and verified, and no step failed before the error: either the ownership set
			// could not be stored, or only the closing bookkeeping (resolving the drift alert) did.
			// The state is the target: carry on and report the lost record, never roll DNS and
			// Caddy back over a verified write.
			o.alerts = append(o.alerts, AlertSiteBookkeepingFailed)
			o.err = errors.Join(o.err, err)
			return stepApplied, ""
		default:
			// Nothing was written: the read, the desired set or the ownership read failed first.
			return stepNothingChanged, "Zitadel redirect URI listesi güncellenemedi: " + err.Error()
		}
	}
}

// runCaddy applies the Caddyfile and classifies a failure. caddy.Apply cannot tell a clean refusal
// from an ambiguous failure (a timeout after the load), so after an error the running config is read
// again: only an unchanged, readable config proves nothing changed.
func (s *SitePipeline) runCaddy(ctx context.Context, pl *sitePlan) (stepOutcome, string) {
	before, err := s.caddy.Live(ctx)
	if err != nil {
		return stepNothingChanged, "Caddy çalışan config'i okunamadı: " + err.Error()
	}
	err = s.caddy.Apply(ctx, pl.after, pl.caddyTarget)
	if err == nil {
		return stepApplied, ""
	}
	var fwe *caddy.FileWriteError
	if errors.As(err, &fwe) {
		if fwe.Restored {
			return stepFileRestored, err.Error()
		}
		return stepFileNotWritten, err.Error()
	}
	rctx, cancel := recovery(ctx)
	defer cancel()
	after, rerr := s.caddy.Live(rctx)
	if rerr != nil || !sameJSON(before, after) {
		return stepUnknown, "Caddy yazısının sonucu belirsiz: " + err.Error()
	}
	return stepNothingChanged, "Caddy reddetti, çalışan config değişmedi: " + err.Error()
}

// failStep decides what a failed step means for the steps already applied.
func (s *SitePipeline) failStep(ctx context.Context, pl *sitePlan, step string, res stepOutcome, detail string, done []string, canRollBack bool, o outcome) outcome {
	o.reason = step + " adımı başarısız: " + detail
	o.status = StatusFailed
	switch res {
	case stepUnknown:
		// Never roll back on a guess (rule 7): keep the live state, ask an operator.
		o.alerts = append(o.alerts, AlertSiteUnverified)
		return o
	case stepFileNotWritten:
		o.alerts = append(o.alerts, AlertSiteCaddyFile)
		return o
	case stepFileRestored:
		o.alerts = append(o.alerts, AlertSiteCaddyFile)
	}
	if len(done) == 0 {
		return o
	}
	if !canRollBack {
		o.alerts = append(o.alerts, AlertSitePartial)
		o.reason += "; apply edilen adımlar (" + strings.Join(done, ", ") + ") erişimi genişletmemek için geri alınmadı"
		return o
	}
	if failed := s.rollBack(ctx, pl, done); failed != "" {
		o.alerts = append(o.alerts, AlertSiteRollbackFailed)
		o.reason += "; geri alma başarısız (" + failed + "), kalan durum korundu"
		return o
	}
	o.status = StatusRolledBack
	o.reason += "; apply edilen adımlar geri alındı"
	return o
}

// rollBack restores the applied steps of a pure add in reverse order and stops at the first failure.
// It returns the name of the step that failed, "" when everything was restored.
func (s *SitePipeline) rollBack(ctx context.Context, pl *sitePlan, done []string) string {
	rctx, cancel := recovery(ctx)
	defer cancel()
	for _, step := range slices.Backward(done) {
		var err error
		switch step {
		case "caddy":
			err = s.caddy.Apply(rctx, pl.current, pl.diskCaddy)
		case "dns":
			previous := pl.dnsContent
			if !pl.dnsExists {
				previous, err = dns.Marshal(nil)
			}
			if err == nil {
				err = s.dns.Restore(rctx, previous)
			}
		}
		if err != nil {
			return step
		}
	}
	return ""
}

// conclude writes the terminal records of a request: the change row, the audit trail, the alerts.
// Every record is attempted even if an earlier one fails, and a missing record raises its own alert,
// so a bookkeeping error never hides an applied write (same rule as the policy pipeline).
func (s *SitePipeline) conclude(ctx context.Context, req SiteRequest, pl *sitePlan, o outcome) (SiteResult, error) {
	rctx, cancel := recovery(ctx)
	defer cancel()

	rowStatus, event, result := StatusFailed, "site.apply_failed", o.status
	switch o.status {
	case StatusApplied:
		rowStatus, event = StatusApplied, "site.apply"
	case StatusRolledBack:
		rowStatus, event = StatusRolledBack, "site.rolled_back"
	case StatusBlocked:
		event = "site.blocked"
	}
	errs := []error{}
	if o.err != nil {
		errs = append(errs, o.err)
	}
	var (
		revision  string
		gitFailed bool
	)
	id, err := s.insertChange(rctx, req, pl, rowStatus, o.reason)
	if err != nil {
		errs = append(errs, err)
	}
	if err := s.auditEvent(rctx, req, pl, event, result, o.reason); err != nil {
		errs = append(errs, err)
	}
	if len(o.dnsWarn) > 0 {
		o.alerts = append(o.alerts, AlertSiteDNSUnverified)
		if err := s.auditDNSWarn(rctx, req, pl, o.dnsWarn); err != nil {
			errs = append(errs, err)
		}
	}
	if o.status == StatusApplied {
		// A clean apply is the proof the earlier critical alerts no longer describe reality.
		if err := s.resolveAlerts(rctx); err != nil {
			errs = append(errs, err)
		}
		if o.finalize != nil {
			if err := o.finalize(rctx); err != nil {
				errs = append(errs, err)
				o.alerts = append(o.alerts, AlertSiteBookkeepingFailed)
			}
		}
		// The durable versions first (revision still empty), then the history: a late retry of the
		// commit can then always find the versions it has to bind (A-03.4).
		if err := s.recordVersions(rctx, req, pl, o, id); err != nil {
			errs = append(errs, err)
			o.alerts = append(o.alerts, AlertSiteBookkeepingFailed)
		}
		revision, gitFailed = s.commitArtifacts(rctx, req, pl, id)
		if revision != "" && id != 0 && s.versions != nil {
			if err := s.versions.BindRevision(rctx, id, revision); err != nil {
				errs = append(errs, err)
				o.alerts = append(o.alerts, AlertSiteBookkeepingFailed)
			}
		}
	}
	for _, kind := range dedupe(o.alerts) {
		if err := s.base.raiseAlert(rctx, id, kind); err != nil {
			errs = append(errs, err)
		}
	}
	// Records that could not be written (change, audit, alerts, first-import state).
	if len(errs) > 0 && !slices.Contains(o.alerts, AlertSiteBookkeepingFailed) {
		if err := s.base.raiseAlert(rctx, id, AlertSiteBookkeepingFailed); err != nil {
			errs = append(errs, err)
		}
	}
	res := SiteResult{
		Result: Result{
			ChangeID: id, Status: o.status, Applied: o.status == StatusApplied,
			Revision: revision, GitFailed: gitFailed,
		},
		Plan: pl.SitePlan,
	}
	if len(errs) > 0 {
		return res, errors.Join(errs...)
	}
	return res, nil
}

func dedupe(kinds []string) []string {
	var out []string
	for _, k := range kinds {
		if !slices.Contains(out, k) {
			out = append(out, k)
		}
	}
	return out
}

// recordVersions stores the durable source version of every site the applied change touched
// (A-03.4): the model after an add or an update, the model it had when it was deleted, every
// stored site for a resync. Identical consecutive states are not stored twice.
func (s *SitePipeline) recordVersions(ctx context.Context, req SiteRequest, pl *sitePlan, o outcome, changeID int64) error {
	if s.versions == nil {
		return nil
	}
	at := s.base.clock()
	record := func(id int64, src site.Site, op string, deleted bool) error {
		_, _, err := s.versions.RecordVersion(ctx, site.NewVersion{
			SiteID: id, ChangeID: changeID, RollbackOf: req.RollbackOf, Op: op, Deleted: deleted,
			Site: src, Actor: strings.TrimSpace(req.Actor), At: at,
		})
		return err
	}
	switch req.Op {
	case SiteAdd, SiteUpdate:
		if o.stored == nil {
			return fmt.Errorf("change: no stored site to version for %s", req.Op)
		}
		return record(o.stored.ID, *o.stored, req.Op, false)
	case SiteDelete:
		i := slices.IndexFunc(pl.current, func(x site.Site) bool { return x.ID == req.ID })
		if i < 0 {
			return site.ErrNotFound
		}
		return record(req.ID, pl.current[i], site.VersionDelete, true)
	case SiteResync:
		var errs []error
		for _, st := range pl.after {
			errs = append(errs, record(st.ID, st, site.VersionResync, false))
		}
		return errors.Join(errs...)
	case SiteManualDNS:
		// No site record moved, so there is no version to keep; the change row, the audit trail
		// and the history revision carry the change.
		return nil
	}
	return nil
}

// commitArtifacts hands the verified final Caddyfile, MagicDNS file and redirect URI list to the
// history (F2-019). Only an applied change gets here, so the artifacts are verified.
func (s *SitePipeline) commitArtifacts(ctx context.Context, req SiteRequest, pl *sitePlan, changeID int64) (string, bool) {
	if s.git == nil {
		return "", false
	}
	creq := gitlog.CommitRequest{
		Actor: strings.TrimSpace(req.Actor), AppliedAt: s.base.clock(),
		Files: []gitlog.File{
			{Name: GitFileCaddyfile, Content: []byte(pl.caddyTarget)},
			{Name: GitFileMagicDNS, Content: []byte(pl.dnsTargetBody)},
			{Name: GitFileRedirectURIs, Content: []byte(uriLines(pl.afterURIs))},
		},
	}
	if changeID != 0 {
		creq.Ref = GitRef(changeID)
	}
	return commitVerified(ctx, s.git, s.base.q, creq)
}

func uriLines(uris []string) string {
	if len(uris) == 0 {
		return ""
	}
	return strings.Join(uris, "\n") + "\n"
}

func (s *SitePipeline) resolveAlerts(ctx context.Context) error {
	now := s.base.stamp()
	for _, kind := range siteResolvedAlerts {
		if _, err := s.base.q.ResolveAlertKind(ctx, db.ResolveAlertKindParams{
			ResolvedAt: sql.NullString{String: now, Valid: true}, Kind: kind,
		}); err != nil {
			return fmt.Errorf("change: resolve %s alert: %w", kind, err)
		}
	}
	return nil
}

// insertChange stores the one change row of the request: the operation and hosts as the "before"
// text and the three-artifact diff as the "after" document.
func (s *SitePipeline) insertChange(ctx context.Context, req SiteRequest, pl *sitePlan, status, errText string) (int64, error) {
	now := s.base.stamp()
	after, err := json.Marshal(struct {
		Op         string   `json:"op"`
		Hosts      []string `json:"hosts,omitempty"`
		RollbackOf int64    `json:"rollback_of,omitempty"`
		SiteDiff
	}{pl.Op, pl.Hosts, req.RollbackOf, pl.Diff})
	if err != nil {
		return 0, fmt.Errorf("change: encode site diff: %w", err)
	}
	var id int64
	err = retryRecord(ctx, func() error {
		row, err := s.base.q.InsertChange(ctx, db.InsertChangeParams{
			Kind:          KindSite,
			Actor:         strings.TrimSpace(req.Actor),
			Status:        status,
			BeforeSummary: pl.opLine(req.RollbackOf),
			AfterSummary:  string(after),
			Error:         errText,
			CreatedAt:     now,
			UpdatedAt:     now,
		})
		if err != nil {
			return err
		}
		id = row.ID
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("change: insert site %s: %w", status, err)
	}
	return id, nil
}

func (pl *sitePlan) opLine(rollbackOf int64) string {
	if pl.Op == SiteManualDNS {
		return fmt.Sprintf("%s: %d record(s)", pl.Op, pl.manual)
	}
	line := pl.Op + ": " + strings.Join(pl.Hosts, ", ")
	if rollbackOf != 0 {
		line += fmt.Sprintf(" (rollback to version %d)", rollbackOf)
	}
	return line
}

// auditEvent writes one audit event carrying the actor and the diff of all three artifacts.
func (s *SitePipeline) auditEvent(ctx context.Context, req SiteRequest, pl *sitePlan, event, result, reason string) error {
	diff := audit.Diff{{Field: "op", After: pl.opLine(req.RollbackOf)}}
	if req.RollbackOf != 0 {
		diff = append(diff, audit.Change{Field: "rollback_of", After: fmt.Sprintf("version %d", req.RollbackOf)})
	}
	for _, f := range []struct{ field, text string }{
		{"caddy", pl.Diff.Caddy}, {"dns", pl.Diff.DNS}, {"zitadel", pl.Diff.Zitadel},
	} {
		if f.text != "" {
			diff = append(diff, audit.Change{Field: f.field, After: f.text})
		}
	}
	if reason != "" {
		diff = append(diff, audit.Change{Field: "reason", After: reason})
	}
	return s.writeAudit(ctx, audit.Entry{Actor: req.Actor, Event: event, Target: pl.target, Diff: diff, Result: result})
}

// auditDNSWarn records the resolver mismatches (F2-006 AC3): the file was kept, the names are
// listed so an operator can see which ones the resolver did not confirm.
func (s *SitePipeline) auditDNSWarn(ctx context.Context, req SiteRequest, pl *sitePlan, mismatches []dns.Mismatch) error {
	lines := make([]string, 0, len(mismatches))
	for _, m := range mismatches {
		lines = append(lines, m.Error())
	}
	return s.writeAudit(ctx, audit.Entry{
		Actor: req.Actor, Event: "site.dns_unverified", Target: pl.target, Result: "warning",
		Diff: audit.Diff{{Field: "dns", After: strings.Join(lines, "\n")}},
	})
}

func (s *SitePipeline) writeAudit(ctx context.Context, e audit.Entry) error {
	err := retryRecord(ctx, func() error {
		_, err := s.base.log.Write(ctx, e)
		return err
	})
	if err != nil {
		return fmt.Errorf("change: audit %s: %w", e.Event, err)
	}
	return nil
}

// sameJSON compares two JSON documents by value; a document that does not parse never equals
// anything, so an unreadable running config is not mistaken for an unchanged one.
func sameJSON(a, b []byte) bool {
	if bytes.Equal(a, b) {
		return len(a) > 0
	}
	var va, vb any
	if json.Unmarshal(a, &va) != nil || json.Unmarshal(b, &vb) != nil {
		return false
	}
	return reflect.DeepEqual(va, vb)
}
