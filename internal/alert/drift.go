package alert

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/dns"
	"github.com/nesiler/tagcess/internal/headscale"
	"github.com/nesiler/tagcess/internal/policyrev"
	"github.com/nesiler/tagcess/internal/render"
	"github.com/nesiler/tagcess/internal/site"
	"github.com/nesiler/tagcess/internal/store/db"
	"github.com/nesiler/tagcess/internal/zitadel"
)

// drift.go is the read-only P-02 drift comparison (F4-039, ADR 0032 proposal): the fully read
// policy, Caddyfile (disk and live), MagicDNS file and owned redirect URIs against the known
// applied baseline. It reads through the existing clients, writes only monitor alerts and never
// calls the legacy CheckDrift/ResolveAlertKind path or any apply. A source it cannot read, a
// missing baseline or a pending first import is uncertainty, never a difference or a recovery.

// KindDrift is the monitor alert of one drifted artifact; SourceDrift is its source. The subject
// names the artifact, so one alert exists per artifact.
const (
	KindDrift   = "monitor_drift"
	SourceDrift = "applied-baseline"
)

// Drift subjects, one per compared artifact.
const (
	SubjectPolicy    = "policy"
	SubjectCaddyFile = "caddyfile"
	SubjectCaddyLive = "caddy_live"
	SubjectDNS       = "dns"
	SubjectURIs      = "redirect_uris"
)

// DriftStatus is the outcome of comparing one artifact.
type DriftStatus string

const (
	// DriftMatch: completely read and equal to the baseline.
	DriftMatch DriftStatus = "match"
	// DriftDiffers: completely read and different from the baseline.
	DriftDiffers DriftStatus = "drift"
	// DriftUncertain: not readable, no baseline or a first import is pending; nothing is concluded.
	DriftUncertain DriftStatus = "uncertain"
)

// legacyKinds are the F1/F2/F3 alarms that already represent a subject's problem. While one is
// open the drift check opens no monitor copy and, by design, never resolves it.
var legacyKinds = map[string][]string{
	SubjectPolicy:    {change.AlertPolicyMismatch, change.AlertPolicyStale},
	SubjectCaddyFile: {change.AlertSiteDrift, change.AlertSiteCaddyFile},
	SubjectCaddyLive: {change.AlertSiteDrift},
	SubjectDNS:       {change.AlertSiteDrift},
	SubjectURIs:      {zitadel.AlertURIDrift, change.AlertSiteDrift},
}

// DriftFinding is what one artifact's comparison concluded. Evidence is a counts-only summary
// without file, policy or response content.
type DriftFinding struct {
	Subject  string
	Status   DriftStatus
	Evidence string
	// LegacyOwned reports that a legacy alarm already covers the difference, so no monitor alert
	// was opened.
	LegacyOwned bool
}

// Read-only source surfaces. The real clients and adapters satisfy them (see the assertions in
// the tests); none of them can write.

// PolicySource reads the policy Headscale currently holds (*headscale.Client).
type PolicySource interface {
	GetPolicy(ctx context.Context) (headscale.Policy, error)
}

// PolicyRef is the applied policy baseline. InFlight reports that a newer revision is pending or
// of unknown outcome, so the live policy may legitimately differ.
type PolicyRef struct {
	ID            int64
	CanonicalHash string
	InFlight      bool
}

// PolicyBaseline returns the newest applied policy revision; found is false before any exists.
type PolicyBaseline interface {
	Applied(ctx context.Context) (ref PolicyRef, found bool, err error)
}

// SiteRecords are the stored (applied) site records and the first-import state (*site.Store).
type SiteRecords interface {
	ListSites(ctx context.Context) ([]site.Site, error)
	FirstImportPending(ctx context.Context) (bool, error)
}

// CaddyReader reads the Caddyfile on disk, the running config and Caddy's adapter (*change.CaddyFile).
type CaddyReader interface {
	Current(ctx context.Context) (string, error)
	Live(ctx context.Context) ([]byte, error)
	AdaptJSON(ctx context.Context, caddyfile string) ([]byte, error)
}

// DNSReader reads the MagicDNS records file (*change.DNSFile).
type DNSReader interface {
	Current(ctx context.Context) (content string, exists bool, err error)
}

// URIReader reads the live redirect URI list of the oauth2-proxy app and tagcess's owned set O.
// Owned reports found=false while no ownership record exists (no baseline yet).
type URIReader interface {
	Redirects(ctx context.Context) ([]string, error)
	Owned(ctx context.Context) (uris []string, found bool, err error)
}

// DriftConfig wires a Drift. Every field is required.
type DriftConfig struct {
	Policy   PolicySource
	Baseline PolicyBaseline
	Sites    SiteRecords
	// Settings supplies the render inputs the artifacts were applied with (the same function the
	// site pipeline uses).
	Settings func(ctx context.Context) (change.SiteSettings, error)
	Caddy    CaddyReader
	DNS      DNSReader
	URIs     URIReader
	// Hold, when set, reports that a site apply or a maintenance window holds the artifacts in an
	// intermediate state (the site writer lock or H-07 maintenance, wired by F4-031). While it is
	// true, Check compares nothing and records nothing: every artifact is uncertain, so a temporary
	// difference never raises a false critical; Held tells the dashboard. A non-nil error means the
	// hold state itself could not be read: that is uncertainty and is recorded like an unreadable source.
	Hold func(ctx context.Context) (held bool, err error)
}

// Drift compares the live artifacts with the applied baseline and keeps one monitor alert per
// drifted artifact.
type Drift struct {
	svc  *Service
	cfg  DriftConfig
	held atomic.Bool // the last Check was held by an apply or maintenance window
	// pending: the last Check found the first import pending (F5 A2).
	pending atomic.Bool
}

// Pending reports that the last Check compared nothing because the first import has not been
// applied, so there is no baseline. It raises no alert: the dashboard shows it once as
// "kurulum bekliyor" instead of one freshness alert per artifact.
func (d *Drift) Pending() bool { return d.pending.Load() }

// Held reports that the last Check compared nothing because an apply or a maintenance window holds
// the artifacts. It is quiet by design; the dashboard shows it so "no alert" is not read as "no drift".
func (d *Drift) Held() bool { return d.held.Load() }

// NewDrift returns a Drift over the alert service.
func NewDrift(svc *Service, cfg DriftConfig) (*Drift, error) {
	if svc == nil || cfg.Policy == nil || cfg.Baseline == nil || cfg.Sites == nil || cfg.Settings == nil ||
		cfg.Caddy == nil || cfg.DNS == nil || cfg.URIs == nil {
		return nil, errors.New("alert: drift needs the alert service and every source")
	}
	return &Drift{svc: svc, cfg: cfg}, nil
}

// result is one artifact's comparison before it is applied to the alerts.
type result struct {
	subject  string
	differs  bool
	evidence string
	// noBaseline is the reason the artifact cannot be judged; the artifact is then not read.
	noBaseline string
	// readErr is why a source could not be read completely.
	readErr error
}

// Check reads every source once and applies the outcome. It returns one finding per artifact
// (always in the same order). An error means the stored records or an alert write failed; the
// findings computed before it are still returned.
func (d *Drift) Check(ctx context.Context) ([]DriftFinding, error) {
	d.held.Store(false)
	d.pending.Store(false)
	if d.cfg.Hold != nil {
		held, err := d.cfg.Hold(ctx)
		if err != nil {
			return d.unreadable(ctx, "the hold state could not be read", err)
		}
		if held {
			d.held.Store(true)
			return uncertainAll("an apply or maintenance window holds the artifacts"), nil
		}
	}
	pending, err := d.cfg.Sites.FirstImportPending(ctx)
	if err != nil {
		return d.unreadable(ctx, "the first import state could not be read", fmt.Errorf("alert: drift: first import state: %w", err))
	}
	if pending {
		// Nothing is recorded: a fresh install has no baseline yet, and that is a setup state, not
		// five warnings. An existing drift alert is neither resolved nor re-raised.
		d.pending.Store(true)
		return uncertainAll("first import is pending: no applied baseline yet"), nil
	}
	sites, err := d.cfg.Sites.ListSites(ctx)
	if err != nil {
		return d.unreadable(ctx, "the site records could not be read", fmt.Errorf("alert: drift: site records: %w", err))
	}
	settings, err := d.cfg.Settings(ctx)
	if err != nil {
		return d.unreadable(ctx, "the render settings could not be read", fmt.Errorf("alert: drift: render settings: %w", err))
	}

	results := []result{
		d.policy(ctx),
		d.caddyFile(ctx, sites, settings),
		d.caddyLive(ctx, sites, settings),
		d.dns(ctx, sites, settings),
		d.uris(ctx, sites),
	}
	findings := make([]DriftFinding, 0, len(results))
	var errs []error
	for _, r := range results {
		if r.readErr != nil && ctx.Err() != nil {
			// The whole run was cancelled: that says nothing about the sources.
			return findings, fmt.Errorf("alert: drift: %w", ctx.Err())
		}
		f, err := d.apply(ctx, r)
		if err != nil {
			errs = append(errs, err)
		}
		findings = append(findings, f)
	}
	return findings, errors.Join(errs...)
}

// unreadable is the outcome of a local read that failed before any artifact was compared: every
// artifact is uncertain with a fixed reason (never the raw error), and err is still returned. A
// cancelled run says nothing and records nothing.
func (d *Drift) unreadable(ctx context.Context, reason string, err error) ([]DriftFinding, error) {
	if ctx.Err() != nil {
		return nil, err
	}
	findings := uncertainAll(reason)
	return findings, errors.Join(err, d.recordUncertain(ctx, findings))
}

// recordUncertain raises the freshness alert of every uncertain artifact (A-M3), with the finding's
// fixed reason as evidence, so "cannot be evaluated" is visible instead of reading as "no drift".
// It resolves nothing; a complete compare later clears it.
func (d *Drift) recordUncertain(ctx context.Context, findings []DriftFinding) error {
	var errs []error
	for _, f := range findings {
		if _, err := d.svc.RecordSource(ctx, SourceSample{
			Subject: f.Subject, Source: SourceDrift, Failed: true, Error: f.Evidence,
		}); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func uncertainAll(reason string) []DriftFinding {
	subjects := []string{SubjectPolicy, SubjectCaddyFile, SubjectCaddyLive, SubjectDNS, SubjectURIs}
	out := make([]DriftFinding, 0, len(subjects))
	for _, s := range subjects {
		out = append(out, DriftFinding{Subject: s, Status: DriftUncertain, Evidence: reason})
	}
	return out
}

// apply records one artifact's outcome in the alerts.
func (d *Drift) apply(ctx context.Context, r result) (DriftFinding, error) {
	f := DriftFinding{Subject: r.subject}
	switch {
	case r.noBaseline != "":
		// No baseline: nothing is concluded, so no drift alert is raised or resolved. The artifact is
		// shown as unknown through the freshness alert, never as drift-free.
		f.Status, f.Evidence = DriftUncertain, r.noBaseline
		return f, d.recordUncertain(ctx, []DriftFinding{f})
	case r.readErr != nil:
		f.Status, f.Evidence = DriftUncertain, safeReadError(r.readErr)
		_, err := d.svc.RecordSource(ctx, SourceSample{
			Subject: r.subject, Source: SourceDrift, Failed: true, Error: f.Evidence,
		})
		return f, err
	}
	f.Status, f.Evidence = DriftMatch, ""
	if r.differs {
		f.Status, f.Evidence = DriftDiffers, sanitizeEvidence(r.evidence)
	}
	legacy, err := d.svc.recordDrift(ctx, r.subject, r.differs, f.Evidence)
	f.LegacyOwned = legacy
	return f, err
}

// safeReadError is the evidence of a failed read. The raw error is never stored: client errors
// can carry URLs, headers or response text.
func safeReadError(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "source read timed out"
	}
	return "source could not be read"
}

// recordDrift raises, refreshes or resolves the monitor drift alert of one artifact, in one
// transaction. A complete read also closes the artifact's freshness alert. It touches no other
// subject and no legacy alarm; while a legacy alarm already covers the subject it opens no copy
// and reports legacy=true.
func (s *Service) recordDrift(ctx context.Context, subject string, differs bool, evidence string) (legacy bool, err error) {
	at := s.at(time.Time{})
	lastSeen := stamp(at)
	err = s.store.withTx(ctx, func(t *tx) error {
		if _, err := t.resolve(ctx, KindSourceStale, subject, SourceDrift, at); err != nil {
			return err
		}
		cur, found, err := t.getOpen(ctx, KindDrift, subject, SourceDrift)
		if err != nil {
			return err
		}
		if !differs {
			if found {
				if _, err := t.resolve(ctx, KindDrift, subject, SourceDrift, at); err != nil {
					return err
				}
			}
			return nil
		}
		if !found {
			owned, err := t.legacyOpen(ctx, subject)
			if err != nil {
				return err
			}
			if owned {
				legacy = true
				return nil
			}
			_, err = t.insert(ctx, db.InsertMonitorAlertParams{
				Kind: KindDrift, Subject: subject, Source: SourceDrift,
				Severity: string(SeverityCritical), Freshness: FreshnessFresh, EvidenceSummary: evidence,
				FirstSeenAt: lastSeen, LastSeenAt: lastSeen,
			})
			return err
		}
		_, err = t.update(ctx, db.UpdateMonitorAlertParams{
			Severity: string(SeverityCritical), Freshness: FreshnessFresh, EvidenceSummary: evidence,
			LastSuccess: cur.LastSuccess, LastConsumedSample: cur.LastConsumedSample,
			ConsecutiveFailures: cur.ConsecutiveFailures, ConsecutiveSuccesses: cur.ConsecutiveSuccesses,
			LastSeenAt: lastSeen, ID: cur.ID,
		})
		return err
	})
	return legacy, err
}

// legacyOpen reports whether an open legacy (empty-subject) alarm already covers the subject.
func (t *tx) legacyOpen(ctx context.Context, subject string) (bool, error) {
	rows, err := t.q.ListOpenAlerts(ctx)
	if err != nil {
		return false, fmt.Errorf("alert: list open: %w", err)
	}
	for _, r := range rows {
		if r.Subject == "" && slices.Contains(legacyKinds[subject], r.Kind) {
			return true, nil
		}
	}
	return false, nil
}

// policy compares the live policy's meaning with the newest applied revision.
func (d *Drift) policy(ctx context.Context) result {
	r := result{subject: SubjectPolicy}
	ref, found, err := d.cfg.Baseline.Applied(ctx)
	switch {
	case err != nil:
		r.readErr = err
		return r
	case !found:
		r.noBaseline = "no applied policy revision to compare with"
		return r
	case ref.InFlight:
		r.noBaseline = "a newer policy revision is pending or unverified"
		return r
	}
	live, err := d.cfg.Policy.GetPolicy(ctx)
	if err != nil {
		r.readErr = err
		return r
	}
	hash, err := policyrev.CanonicalHash(live.Text)
	if err != nil {
		r.readErr = err // not a policy document: the read is unusable, not a difference
		return r
	}
	if hash != ref.CanonicalHash {
		r.differs = true
		r.evidence = fmt.Sprintf("live policy differs from applied revision #%d", ref.ID)
	}
	return r
}

// templateHint is appended to the Caddy drift evidence (J2). A new tagcess version can change the
// generated Caddyfile template, which makes the unchanged records render differently from what is
// on disk. tagcess keeps no earlier template to prove that, so the evidence names the likely cause
// and the fix instead of claiming it.
const templateHint = " Olası neden: şablon güncellendi; /sites sayfasında \"Kayıtlardan yeniden apply et\" ile çözülür."

// caddyFile compares the Caddyfile on disk with the render of the stored records.
func (d *Drift) caddyFile(ctx context.Context, sites []site.Site, s change.SiteSettings) result {
	r := result{subject: SubjectCaddyFile}
	want, err := render.RenderCaddyfile(sites, s.Caddy)
	if err != nil {
		r.noBaseline = "stored sites do not render to a Caddyfile"
		return r
	}
	disk, err := d.cfg.Caddy.Current(ctx)
	if err != nil {
		r.readErr = err
		return r
	}
	if disk != want {
		r.differs = true
		r.evidence = fmt.Sprintf("Caddyfile on disk differs from the applied records (%d lines)."+templateHint, changedLines(want, disk))
	}
	return r
}

// caddyLive compares the running config with the adapted render of the stored records.
func (d *Drift) caddyLive(ctx context.Context, sites []site.Site, s change.SiteSettings) result {
	r := result{subject: SubjectCaddyLive}
	want, err := render.RenderCaddyfile(sites, s.Caddy)
	if err != nil {
		r.noBaseline = "stored sites do not render to a Caddyfile"
		return r
	}
	live, err := d.cfg.Caddy.Live(ctx)
	if err != nil {
		r.readErr = err
		return r
	}
	adapted, err := d.cfg.Caddy.AdaptJSON(ctx, want)
	if err != nil {
		r.readErr = err
		return r
	}
	equal, err := sameConfig(live, adapted)
	if err != nil {
		r.readErr = err // an unparsable config cannot be compared: uncertainty, not a difference
		return r
	}
	if !equal {
		r.differs = true
		r.evidence = "running Caddy config differs from the applied records." + templateHint
	}
	return r
}

// dns compares the records file with the render of the stored records and manual set.
func (d *Drift) dns(ctx context.Context, sites []site.Site, s change.SiteSettings) result {
	r := result{subject: SubjectDNS}
	records, err := render.RenderDNSRecords(sites, s.ManualDNS, s.DNS)
	if err != nil {
		r.noBaseline = "stored sites do not render to DNS records"
		return r
	}
	want, err := dns.Marshal(records)
	if err != nil {
		r.noBaseline = "stored sites do not render to DNS records"
		return r
	}
	content, exists, err := d.cfg.DNS.Current(ctx)
	if err != nil {
		r.readErr = err
		return r
	}
	switch {
	case !exists:
		r.differs = true
		r.evidence = "DNS records file is missing"
	case content != want:
		r.differs = true
		r.evidence = fmt.Sprintf("DNS records file differs from the applied records (%d lines)", changedLines(want, content))
	}
	return r
}

// uris compares the live redirect URIs with the owned set: a desired URI that is missing, or an
// owned URI that is no longer desired but still present. Foreign URIs are ignored.
func (d *Drift) uris(ctx context.Context, sites []site.Site) result {
	r := result{subject: SubjectURIs}
	owned, found, err := d.cfg.URIs.Owned(ctx)
	switch {
	case err != nil:
		r.readErr = err
		return r
	case !found:
		r.noBaseline = "no owned redirect URI record yet"
		return r
	}
	desired, err := zitadel.DesiredURIs(sites)
	if err != nil {
		r.noBaseline = "stored sites do not produce redirect URIs"
		return r
	}
	live, err := d.cfg.URIs.Redirects(ctx)
	if err != nil {
		r.readErr = err
		return r
	}
	missing, stale := 0, 0
	for _, uri := range desired {
		if !slices.Contains(live, uri) {
			missing++
		}
	}
	for _, uri := range live {
		if slices.Contains(owned, uri) && !slices.Contains(desired, uri) {
			stale++
		}
	}
	if missing+stale > 0 {
		r.differs = true
		r.evidence = fmt.Sprintf("redirect URIs: %d desired missing, %d stale owned still present", missing, stale)
	}
	return r
}

// changedLines counts the added and removed lines between two texts.
func changedLines(want, got string) int {
	n := 0
	for _, line := range strings.Split(change.LineDiff(want, got), "\n") {
		if strings.HasPrefix(line, "+") || strings.HasPrefix(line, "-") {
			n++
		}
	}
	return n
}

// sameConfig compares two JSON documents by value; a document that does not parse is an error.
func sameConfig(a, b []byte) (bool, error) {
	var va, vb any
	if err := json.Unmarshal(a, &va); err != nil {
		return false, err
	}
	if err := json.Unmarshal(b, &vb); err != nil {
		return false, err
	}
	return reflect.DeepEqual(va, vb), nil
}

// NewPolicyBaseline returns the applied-policy baseline over the policy revision queries.
func NewPolicyBaseline(q *db.Queries) PolicyBaseline { return &revisionBaseline{q: q} }

type revisionBaseline struct{ q *db.Queries }

func (b *revisionBaseline) Applied(ctx context.Context) (PolicyRef, bool, error) {
	applied, err := b.q.LatestAppliedPolicyRevision(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return PolicyRef{}, false, nil
	}
	if err != nil {
		return PolicyRef{}, false, fmt.Errorf("alert: latest applied policy revision: %w", err)
	}
	newest, err := b.q.ListPolicyRevisions(ctx, 1)
	if err != nil {
		return PolicyRef{}, false, fmt.Errorf("alert: newest policy revision: %w", err)
	}
	ref := PolicyRef{ID: applied.ID, CanonicalHash: applied.CanonicalHash}
	if len(newest) == 1 && newest[0].ID != applied.ID {
		status := policyrev.Status(newest[0].ApplyStatus)
		ref.InFlight = status == policyrev.StatusPending || status == policyrev.StatusUnknown
	}
	return ref, true, nil
}

// ZitadelURIs reads the oauth2-proxy app's redirect URIs through the trusted Zitadel client and
// the owned set from the database. It never writes.
type ZitadelURIs struct {
	client  *zitadel.Client
	appName string
	q       *db.Queries

	mu    sync.Mutex
	appID string
}

// NewZitadelURIs returns the reader of the vpn project's app with that name.
func NewZitadelURIs(c *zitadel.Client, appName string, q *db.Queries) *ZitadelURIs {
	return &ZitadelURIs{client: c, appName: appName, q: q}
}

// Redirects reads the app's live redirect URI list; the app is found by name on first use.
func (z *ZitadelURIs) Redirects(ctx context.Context) ([]string, error) {
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.appID == "" {
		id, err := z.client.FindAppID(ctx, z.appName)
		if err != nil {
			return nil, err
		}
		z.appID = id
	}
	app, err := z.client.AppOIDC(ctx, z.appID)
	if err != nil {
		return nil, err
	}
	return app.RedirectUris, nil
}

// Owned reads O; found is false while no ownership record exists. An unparsable record is an
// error, not an empty set.
func (z *ZitadelURIs) Owned(ctx context.Context) ([]string, bool, error) {
	stored, err := z.q.GetOwnedURIs(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("alert: read owned redirect URIs: %w", err)
	}
	var uris []string
	if err := json.Unmarshal([]byte(stored), &uris); err != nil {
		return nil, false, fmt.Errorf("alert: parse owned redirect URIs: %w", err)
	}
	return uris, true, nil
}
