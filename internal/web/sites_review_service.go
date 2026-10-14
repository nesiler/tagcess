package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/dns"
	caddyrender "github.com/nesiler/tagcess/internal/render"
	"github.com/nesiler/tagcess/internal/site"
	"github.com/nesiler/tagcess/internal/store/db"
	"github.com/nesiler/tagcess/internal/web/ui"
	"github.com/nesiler/tagcess/internal/zitadel"
)

// The site review service (F2-014): the shared types of the preview → approval → result screens
// around the site change pipeline (F2-011). The screens are stateless: the review page carries the
// request and the plan version in its approval form, and the approve re-plans under the same
// pipeline gates before anything is applied (Y-03.4 pattern of the sync page, without a stored
// pending row — a site change is operator-initiated and immediately actionable, and the pipeline
// records every submit in the changes table with the same diff).

// SiteReviewer is the site change pipeline surface the review screens need. It is satisfied by
// *change.SitePipeline.
type SiteReviewer interface {
	Preview(ctx context.Context, req change.SiteRequest) (change.SitePlan, error)
	Submit(ctx context.Context, req change.SiteRequest) (change.SiteResult, error)
	FirstImport(ctx context.Context, actor string, seed []byte, opts site.SeedOptions) (change.SiteResult, error)
}

// SiteURIDriftReader reads the redirect URI comparison for the review warnings (S-03.3). It is
// satisfied by *zitadel.URISync; the same check gates the apply.
type SiteURIDriftReader interface {
	CheckDrift(ctx context.Context, sites []site.Site) (zitadel.URIResult, error)
}

// SiteSettingsSource exposes the render inputs that do not come from site records. It is satisfied
// by the pipeline's own settings function (wrapped in SiteSettingsFunc).
type SiteSettingsSource interface {
	Settings(ctx context.Context) (change.SiteSettings, error)
}

// SiteSettingsFunc adapts the pipeline settings function to SiteSettingsSource.
type SiteSettingsFunc func(ctx context.Context) (change.SiteSettings, error)

// Settings implements SiteSettingsSource.
func (f SiteSettingsFunc) Settings(ctx context.Context) (change.SiteSettings, error) { return f(ctx) }

// SiteFirstImportGate reads the first-import gate state. It is satisfied by *site.Store.
type SiteFirstImportGate interface {
	FirstImportPending(ctx context.Context) (bool, error)
	FirstImportDone(ctx context.Context) (bool, error)
}

// SiteSeedSource provides the first-import inputs that come from the configuration. A nil Seed
// hides the action: no seed file is configured (KISS: the seed is written once per installation
// and read from the operator-provided path).
type SiteSeedSource struct {
	// Read returns the seed file content.
	Read func(ctx context.Context) ([]byte, error)
	// Caddy reads today's Caddyfile and adapts both files for the parity comparison.
	Caddy SiteSeedCaddy
	// DNS reads today's extra-records file: the records the import keeps as manual ones (F2-022).
	DNS SiteSeedDNS
	// TagcessHost and ZitadelInternalSources feed site.SeedOptions on the approval.
	TagcessHost            string
	ZitadelInternalSources []string
}

// SiteSeedCaddy is the Caddy surface the first-import parity needs: today's file and the adapt
// adapter. It is satisfied by *change.CaddyFile.
type SiteSeedCaddy interface {
	Current(ctx context.Context) (string, error)
	AdaptJSON(ctx context.Context, caddyfile string) ([]byte, error)
}

// SiteSeedDNS reads today's MagicDNS extra-records file for the manual-record preview. It is
// satisfied by *change.DNSFile.
type SiteSeedDNS interface {
	Current(ctx context.Context) (content string, exists bool, err error)
}

// SiteChangeReader reads one stored change row (the recorded outcome and its reason, exactly as
// the pipeline wrote them). It is satisfied by *db.Queries; the row type is the store's own model.
type SiteChangeReader interface {
	GetChange(ctx context.Context, id int64) (db.Change, error)
}

// SiteReviewConfig wires the review screens.
type SiteReviewConfig struct {
	Reviewer SiteReviewer
	Lister   SiteLister
	URIs     SiteURIDriftReader
	Settings SiteSettingsSource
	Changes  SiteChangeReader
	// Gate and Seed are required together; a nil Seed hides the first-import action.
	Gate SiteFirstImportGate
	Seed *SiteSeedSource
	// DryRun is optional; with it the first-import screens warn while dry-run is on.
	DryRun change.DryRun
	// Auditor writes the operator actions (preview, approve, first import) before the pipeline runs.
	Auditor SiteAuditor
	CSRF    *CSRF
	// K8sUpstream is the (k8s) snippet upstream (sites.k8s_upstream) the preview names; empty: the
	// renderer's default.
	K8sUpstream string
}

// SitePlanVersion is the stable version of a displayed plan (the sync page's proposal-version
// pattern): the approval form carries it back, and the approve refuses to apply when the fresh
// plan no longer matches (a stale or widened plan, Y-03.4).
func SitePlanVersion(pl change.SitePlan) string {
	b, err := json.Marshal(struct {
		Op    string
		Hosts []string
		Diff  change.SiteDiff
	}{pl.Op, pl.Hosts, pl.Diff})
	if err != nil {
		return "unencodable"
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// encodeSiteRequest serializes the request the review form carries back. The actor never travels
// with the form: the approve overwrites it with the signed-in operator.
func encodeSiteRequest(req change.SiteRequest) (string, error) {
	b, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("web: encode site request: %w", err)
	}
	return string(b), nil
}

// decodeSiteRequest reads the request back strictly; unknown fields mean a tampered or stale form.
func decodeSiteRequest(raw string) (change.SiteRequest, error) {
	var req change.SiteRequest
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return change.SiteRequest{}, fmt.Errorf("web: site request: %w", err)
	}
	switch req.Op {
	case change.SiteAdd, change.SiteUpdate, change.SiteDelete:
	case change.SiteManualDNS:
		// The manual DNS screen reuses this encoding; its endpoint checks the op itself.
	default:
		return change.SiteRequest{}, fmt.Errorf("web: site request: unknown operation %q", req.Op)
	}
	return req, nil
}

// SiteReviewView is the review page data (AC1, AC4): the plan, the order the pipeline applies in,
// the warnings and the version-bound approval form. Blocked carries the reason a problem of the
// existing state makes the change impossible; the approval is then not offered.
type SiteReviewView struct {
	Op       string
	Hosts    []string
	Order    string
	Diff     change.SiteDiff
	Version  string
	Request  string
	Warnings []string
	Foreign  []string
	Blocked  string
	// Target is the site's target before and after the change (F5 I6).
	Target TargetChange
}

// TargetChange is the target of a site before and after a change. Before is empty for an add and
// After for a delete.
type TargetChange struct {
	Before, After string
}

// Changed reports whether the target differs.
func (t TargetChange) Changed() bool { return t.Before != t.After }

// targetDescription says where a site's traffic goes. The Caddy diff only shows `import vpn_site`
// for a k8s site, so the preview names the shared upstream explicitly.
func targetDescription(s site.Site, upstream string) string {
	switch {
	case s.Kind == site.KindSystem:
		return "sistem şablonunun kendi hedefi"
	case s.TargetKind == site.TargetURL:
		d := s.TargetURL
		if s.TargetTLSInsecure {
			d += " (TLS doğrulaması kapalı)"
		}
		return d
	case s.TargetKind == site.TargetK8s:
		if upstream == "" {
			upstream = caddyrender.K8sUpstream
		}
		return "k8s: ortak (k8s) snippet'i → " + upstream + " (Host başlığı korunur)"
	default:
		return s.TargetKind
	}
}

// targetChange derives the target change of a request from the request and the stored sites.
func (h *SiteReviewHandler) targetChange(ctx context.Context, req change.SiteRequest) TargetChange {
	var tc TargetChange
	if req.Op != change.SiteAdd {
		if sites, err := h.cfg.Lister.ListSites(ctx); err == nil {
			for _, s := range sites {
				if s.ID == req.ID {
					tc.Before = targetDescription(s, h.cfg.K8sUpstream)
				}
			}
		}
	}
	if req.Op != change.SiteDelete {
		tc.After = targetDescription(req.Site, h.cfg.K8sUpstream)
	}
	return tc
}

// buildSiteReviewView plans the request read-only and assembles the review view. A request error
// returns the error (the form is shown again); a state block becomes a blocked view (200, no
// approval, the reason on the page).
func (h *SiteReviewHandler) buildSiteReviewView(ctx context.Context, req change.SiteRequest) (SiteReviewView, error) {
	view := SiteReviewView{Op: req.Op}
	pl, err := h.cfg.Reviewer.Preview(ctx, req)
	if err != nil {
		if errors.Is(err, change.ErrBlocked) {
			view.Blocked = err.Error()
			return view, nil
		}
		return SiteReviewView{}, err
	}
	view.Hosts = pl.Hosts
	view.Diff = pl.Diff
	view.Order = applyOrder(pl)
	view.Version = SitePlanVersion(pl)
	view.Request, err = encodeSiteRequest(req)
	if err != nil {
		return SiteReviewView{}, err
	}
	view.Warnings, view.Foreign = h.warnings(ctx, req)
	view.Target = h.targetChange(ctx, req)
	if settings, serr := h.cfg.Settings.Settings(ctx); serr != nil {
		view.Warnings = append(view.Warnings, "ayarlar okunamadı: "+serr.Error())
	} else {
		view.Warnings = append(view.Warnings, certWarnings(req, settings.Caddy)...)
	}
	return view, nil
}

// certWarnings lists the hosts of a submitted site that no configured certificate covers
// (S-07.1): the change is not blocked, but the block renders without a tls line until a
// certificate exists (DNS-01). An explicit le:<name> is the operator's choice and warns not.
func certWarnings(req change.SiteRequest, cfg caddyrender.CaddyConfig) []string {
	if req.Op == change.SiteDelete {
		return nil
	}
	s := req.Site
	if s.Cert != "auto" || len(s.Hosts) == 0 {
		return nil
	}
	for _, c := range cfg.Certs {
		if caddyrender.CertCoversAll(c, s.Hosts) {
			return nil
		}
	}
	uncovered := caddyrender.UncoveredHosts(cfg.Certs, s.Hosts)
	if len(uncovered) == 0 {
		uncovered = s.Hosts
	}
	return []string{
		"Sertifika uyarısı: hiçbir sertifika " + strings.Join(s.Hosts, ", ") +
			" hostlarını kapsamıyor (kapsamayanlar: " + strings.Join(uncovered, ", ") +
			"). Kayıt engellenmez ama site sertifika sağlanana kadar tls satırı olmadan üretilir ve erişilemez kalır (DNS-01).",
	}
}

// applyOrder shows the steps the pipeline runs for this plan, in its order (narrow first, widen
// last); only artifacts that change are listed.
func applyOrder(pl change.SitePlan) string {
	del := pl.Op == change.SiteDelete
	steps := []struct {
		name string
		need bool
	}{
		{"DNS", pl.Diff.DNS != ""},
		{"Caddy", pl.Diff.Caddy != ""},
		{"Zitadel", pl.Diff.Zitadel != ""},
	}
	var out []string
	for _, s := range steps {
		if s.need {
			out = append(out, s.name)
		}
	}
	if del {
		for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
			out[i], out[j] = out[j], out[i]
		}
	}
	if len(out) == 0 {
		return "kayıt güncellemesi (arabirimler değişmiyor)"
	}
	return strings.Join(out, " → ")
}

// warnings collects the review warnings: a failed URI read is a warning; the foreign redirect
// URIs (S-03.3, AC4) are returned separately for their own block. The apply re-checks everything
// under the writer lock; a warning never widens the change.
func (h *SiteReviewHandler) warnings(ctx context.Context, req change.SiteRequest) ([]string, []string) {
	sites, err := h.cfg.Lister.ListSites(ctx)
	if err != nil {
		return []string{"kayıtlı siteler okunamadı: " + err.Error()}, nil
	}
	res, err := h.cfg.URIs.CheckDrift(ctx, sites)
	if err != nil {
		return []string{"Zitadel redirect URI listesi okunamadı: " + err.Error()}, nil
	}
	return nil, res.Foreign
}

// certWarnings (F2-015) will list the hosts of a submitted site that no configured certificate
// covers; it joins the warnings of the review view.

// SiteResultView is the result screen (AC3): the recorded outcome of the approval, its reason and
// the last known good state (the stored sites, which only move after every artifact was applied).
type SiteResultView struct {
	ChangeID int64
	Status   string
	Reason   string
	Applied  bool
	Failed   bool
	DryRun   bool // the outcome is dry_run: nothing was applied (A1)
	Sites    []string
	// Note carries a flow-specific warning next to the outcome, e.g. the S-06 key restore after
	// a failed apply. Empty for the plain flows.
	Note string
	// Back is the screen the change started from (breadcrumb and return button); the zero value is
	// the site list.
	Back ResultBack
}

// ResultBack names the screen a change result returns to.
type ResultBack struct {
	Label string
	Href  string
}

// resultBackSites and resultBackDNS are the two screens that share the change result page.
var (
	resultBackSites = ResultBack{Label: "Siteler", Href: "/sites"}
	resultBackDNS   = ResultBack{Label: "MagicDNS kayıtları", Href: "/headscale/dns"}
)

func (v SiteResultView) back() ResultBack {
	if v.Back.Href == "" {
		return resultBackSites
	}
	return v.Back
}

// statusLabel is the Turkish label of a pipeline status for the result screen.
func statusLabel(status string) string {
	switch status {
	case change.StatusApplied:
		return "apply edildi"
	case change.StatusFailed:
		return "başarısız"
	case change.StatusRolledBack:
		return "geri alındı"
	case change.StatusBlocked:
		return "bloklandı"
	case change.StatusDryRun:
		return "dry-run"
	case change.StatusNoChange:
		return "değişiklik yok"
	default:
		return status
	}
}

// buildSiteResultView reads the recorded change (AC3) and the stored sites. A change id of 0 (the
// apply never reached a change row) shows the caller error as the reason. Shared by the review
// and the settings screens.
func buildSiteResultView(ctx context.Context, changes SiteChangeReader, lister SiteLister, res change.SiteResult, applyErr error) SiteResultView {
	view := SiteResultView{ChangeID: res.ChangeID, Status: res.Status, Applied: res.Applied, Failed: res.Status == change.StatusFailed}
	if res.ChangeID > 0 {
		row, err := changes.GetChange(ctx, res.ChangeID)
		if err != nil {
			view.Reason = "değişiklik kaydı okunamadı: " + err.Error()
		} else {
			view.Status = row.Status
			view.Failed = row.Status == change.StatusFailed
			view.Reason = row.Error
		}
	}
	view.DryRun = view.Status == change.StatusDryRun
	if view.Reason == "" && applyErr != nil {
		view.Reason = applyErr.Error()
	}
	if sites, err := lister.ListSites(ctx); err == nil {
		for _, s := range sites {
			view.Sites = append(view.Sites, s.Hosts...)
		}
	}
	return view
}

// siteResultView builds the result view through the handler's wiring.
func (h *SiteReviewHandler) buildSiteResultView(ctx context.Context, res change.SiteResult, applyErr error) SiteResultView {
	return buildSiteResultView(ctx, h.cfg.Changes, h.cfg.Lister, res, applyErr)
}

// firstImportVersion binds the approval to the seed, the parity result and the gate state the
// operator saw, the manual DNS records included (F2-022).
func firstImportVersion(seed []byte, parityDiff, manual string, pending bool) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d|%s|%t", len(seed), string(seed)+"\x00"+parityDiff+"\x00"+manual, pending)))
	return hex.EncodeToString(sum[:])
}

// SiteFirstImportView is the first-import screen: the gate state, the seed summary and the parity
// result. An approval is offered only while the gate is open and the parity holds.
type SiteFirstImportView struct {
	Pending    bool
	Done       bool
	DryRun     bool // dry-run is on: applying the import changes nothing (A1)
	GateErr    string
	SeedCount  int
	SeedErr    string
	ParityOK   bool
	ParityDiff string
	ParityErr  string
	// ManualDNS are today's non-site DNS records the import keeps (F2-022); ManualDNSErr is why they
	// cannot be kept (unreadable file, invalid record, collision with a site host) and blocks it.
	ManualDNS    []dns.Record
	ManualDNSErr string
	Version      string
}

// buildFirstImportView reads the seed and runs the parity comparison read-only (S-03.2/G-01): the
// generated Caddyfile must mean today's file before the first apply.
func (h *SiteReviewHandler) buildFirstImportView(ctx context.Context) SiteFirstImportView {
	var v SiteFirstImportView
	v.DryRun = h.dryRunOn(ctx)
	if h.cfg.Seed == nil {
		v.SeedErr = "ilk import yapılandırılmadı"
		return v
	}
	pending, err := h.cfg.Gate.FirstImportPending(ctx)
	if err != nil {
		v.GateErr = err.Error()
		return v
	}
	done, err := h.cfg.Gate.FirstImportDone(ctx)
	if err != nil {
		v.GateErr = err.Error()
		return v
	}
	v.Pending, v.Done = pending, done
	seed, err := h.cfg.Seed.Read(ctx)
	if err != nil {
		v.SeedErr = "aktarılacak kayıtlar okunamadı: " + err.Error()
		return v
	}
	sites, err := site.PrepareSeed(seed, site.SeedOptions{
		TagcessHost:            h.cfg.Seed.TagcessHost,
		ZitadelInternalSources: h.cfg.Seed.ZitadelInternalSources,
	})
	if err != nil {
		v.SeedErr = err.Error()
		return v
	}
	v.SeedCount = len(sites)
	settings, err := h.cfg.Settings.Settings(ctx)
	if err != nil {
		v.ParityErr = "ayarlar okunamadı: " + err.Error()
		return v
	}
	current, err := h.cfg.Seed.Caddy.Current(ctx)
	if err != nil {
		v.ParityErr = "bugünkü Caddyfile okunamadı: " + err.Error()
		return v
	}
	// Compare the records the approval stores: the seed plus the tagcess system record (as
	// -import-preview and the pipeline's gate do). CheckSeedParity leaves that block out while
	// today's file does not serve its host.
	compared := site.WithTagcess(sites, h.cfg.Seed.TagcessHost)
	err = caddyrender.CheckSeedParity(ctx, h.cfg.Seed.Caddy.AdaptJSON, current, compared, settings.Caddy)
	var parity *caddyrender.ParityError
	switch {
	case err == nil:
		v.ParityOK = true
	case errors.As(err, &parity):
		v.ParityDiff = parity.Diff
	default:
		v.ParityErr = err.Error()
	}
	v.ManualDNS, v.ManualDNSErr = h.manualDNS(ctx, sites, settings.DNS)
	v.Version = firstImportVersion(seed, v.ParityDiff, manualDNSKey(v), v.Pending)
	return v
}

// manualDNS reads today's DNS file and returns what the import would keep as manual records, or why
// it cannot (fail closed: a missing source counts as a failure, the pipeline would read the file
// anyway).
func (h *SiteReviewHandler) manualDNS(ctx context.Context, sites []site.Site, cfg caddyrender.DNSConfig) ([]dns.Record, string) {
	if h.cfg.Seed.DNS == nil {
		return nil, "DNS dosyası okunamıyor (yapılandırılmadı)"
	}
	content, exists, err := h.cfg.Seed.DNS.Current(ctx)
	if err != nil {
		return nil, "bugünkü DNS dosyası okunamadı: " + err.Error()
	}
	manual, err := caddyrender.ImportManualDNS(content, exists, sites, cfg)
	if err != nil {
		return nil, err.Error()
	}
	return manual, ""
}

// manualDNSKey is the part of the view the approval is bound to besides the seed and the parity.
func manualDNSKey(v SiteFirstImportView) string {
	var b strings.Builder
	b.WriteString(v.ManualDNSErr)
	for _, r := range v.ManualDNS {
		fmt.Fprintf(&b, "\n%s %s %s", r.Name, r.Type, r.Value)
	}
	return b.String()
}

// firstImportApprovable reports whether the view may offer the approval: the seed is readable,
// the parity holds, the manual DNS records can be kept and the first import has not passed yet (fail closed). The pending flag is
// deliberately not required: on a store with no first-import state the gate is neither pending
// nor done until the seed load inside the pipeline's FirstImport opens it — and that load runs
// only after this approval, so requiring it would make the real first import unapprovable.
func firstImportApprovable(v SiteFirstImportView) bool {
	return !v.Done && v.GateErr == "" && v.SeedErr == "" && v.ParityErr == "" && v.ParityDiff == "" && v.ManualDNSErr == ""
}

// dryRunOn reports whether dry-run is on; without a source, or when it cannot be read, no warning
// is shown (the pipeline decides on its own read).
func (h *SiteReviewHandler) dryRunOn(ctx context.Context) bool {
	if h.cfg.DryRun == nil {
		return false
	}
	on, err := h.cfg.DryRun.DryRun(ctx)
	return err == nil && on
}

// resultTone colours a change result: applied is good, failed is an error, anything else (dry run,
// blocked, pending) is a warning that nothing changed.
func resultTone(v SiteResultView) ui.Tone {
	switch {
	case v.Applied:
		return ui.OK
	case v.Failed:
		return ui.Err
	default:
		return ui.Warn
	}
}
