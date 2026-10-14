package change

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/site"
)

// Rollback to an earlier site source snapshot (F2-020, A-03, ADR 0017). A rollback is not an old file
// loaded blindly: it is a new, validated, approved and audited site change. The selected version's
// source model becomes the request of the F2-011 pipeline, so the store's field validation and
// system locks, the drift gate, the apply order, the failure rules, the durable version and the
// history commit all apply unchanged, and the next render keeps the result.
//
// The preview is read-only: it validates the model, renders the artifacts, asks Caddy to /adapt the
// generated file and diffs; it writes nothing and records the live base as a hash. The approval
// re-reads the live base and applies only when the hash is the one the operator saw.
//
// Access is never widened by a guess: a rollback that opens more access than the site has now is
// refused unless the operator acknowledged exactly that, and the S-06 key is a global setting that a
// snapshot does not carry, so a rollback always renders under the key as it is now.

var (
	// ErrRollbackStale means the live base changed after the preview (another change, a hand edit, a
	// setting): nothing was applied.
	ErrRollbackStale = errors.New("change: live state changed since the preview; preview the rollback again")
	// ErrRollbackWidens means the rollback opens more access than the site has now and the approval
	// did not acknowledge it.
	ErrRollbackWidens = errors.New("change: the rollback widens access and was not acknowledged")
	// ErrRollbackNoChange means the selected version is what the site already is.
	ErrRollbackNoChange = errors.New("change: the site already is in the selected version")
	// ErrRollbackUnavailable means the pipeline keeps no durable versions.
	ErrRollbackUnavailable = errors.New("change: no durable site versions are configured")
)

// RollbackPreview is what approving a rollback would do.
type RollbackPreview struct {
	Version site.Version
	// Op is how the version is re-applied: update (the site exists), add (it was deleted since) or
	// delete (the version is a deletion and the site exists).
	Op   string
	Plan SitePlan
	// BaseHash binds the approval to the live state the preview was made on.
	BaseHash string
	// Widens lists, in words, what the rollback opens beyond what the site has now. Empty means the
	// rollback is not wider; otherwise the approval must acknowledge it.
	Widens []string
	// NoChange is set when the site already holds exactly the selected source model.
	NoChange bool
}

// RollbackApproval is the operator's approval of a previewed rollback.
type RollbackApproval struct {
	Actor     string
	VersionID int64
	BaseHash  string
	// AcknowledgeWiden confirms a rollback that widens access (RollbackPreview.Widens).
	AcknowledgeWiden bool
}

type rollbackPlan struct {
	preview RollbackPreview
	req     SiteRequest
	plan    *sitePlan
}

// PreviewRollback shows what re-applying a version would do. It writes nothing to any managed
// system and nothing to the stores: only reads, the store's validation inside a rolled-back
// transaction, and Caddy's /adapt.
func (s *SitePipeline) PreviewRollback(ctx context.Context, actor string, versionID int64) (RollbackPreview, error) {
	if err := validateActor(actor); err != nil {
		return RollbackPreview{}, err
	}
	if s.versions == nil {
		return RollbackPreview{}, ErrRollbackUnavailable
	}
	writerLock.Lock()
	defer writerLock.Unlock()
	rp, err := s.planRollback(ctx, versionID)
	if err != nil {
		return RollbackPreview{}, err
	}
	return rp.preview, nil
}

// ApplyRollback applies an approved rollback. Under the writer lock it re-reads the live base and
// compares it with the previewed one (ErrRollbackStale, nothing applied), refuses a widening
// rollback that was not acknowledged (ErrRollbackWidens), and then runs the F2-011 pipeline as one
// new change. The selected version, the actor and the result are audited.
func (s *SitePipeline) ApplyRollback(ctx context.Context, a RollbackApproval) (SiteResult, error) {
	if err := validateActor(a.Actor); err != nil {
		return SiteResult{}, err
	}
	if s.versions == nil {
		return SiteResult{}, ErrRollbackUnavailable
	}
	writerLock.Lock()
	defer writerLock.Unlock()

	rp, err := s.planRollback(ctx, a.VersionID)
	if err != nil {
		s.auditRollback(ctx, a.Actor, "site:*", "site.rollback_refused", "refused", a.VersionID, err.Error())
		return SiteResult{}, err
	}
	target := siteTarget(rp.preview.Version.Hosts)
	refuse := func(err error) (SiteResult, error) {
		s.auditRollback(ctx, a.Actor, target, "site.rollback_refused", "refused", a.VersionID, err.Error())
		return SiteResult{}, err
	}
	switch {
	case rp.preview.NoChange:
		return refuse(ErrRollbackNoChange)
	case subtle.ConstantTimeCompare([]byte(rp.preview.BaseHash), []byte(a.BaseHash)) != 1:
		return refuse(ErrRollbackStale)
	case len(rp.preview.Widens) > 0 && !a.AcknowledgeWiden:
		return refuse(fmt.Errorf("%w: %s", ErrRollbackWidens, strings.Join(rp.preview.Widens, "; ")))
	}

	rp.req.Actor = a.Actor
	res, err := s.submitLocked(ctx, rp.req)
	reason := ""
	if err != nil {
		reason = err.Error()
	}
	s.auditRollbackResult(ctx, a.Actor, target, a.VersionID, res, reason)
	return res, err
}

// planRollback builds the request of a version and plans it against the current state. The caller
// holds the writer lock.
func (s *SitePipeline) planRollback(ctx context.Context, versionID int64) (*rollbackPlan, error) {
	v, err := s.versions.GetVersion(ctx, versionID)
	if err != nil {
		return nil, err
	}
	current, err := s.sites.ListSites(ctx)
	if err != nil {
		return nil, fmt.Errorf("change: list sites: %w", err)
	}
	var cur *site.Site
	if i := slices.IndexFunc(current, func(x site.Site) bool { return x.ID == v.SiteID }); i >= 0 {
		cur = &current[i]
	}

	req := SiteRequest{RollbackOf: v.ID}
	preview := RollbackPreview{Version: v}
	switch {
	case v.Deleted && cur == nil:
		return nil, fmt.Errorf("%w: the site is already deleted", ErrRollbackNoChange)
	case v.Deleted:
		req.Op, req.ID = SiteDelete, v.SiteID
	case cur != nil:
		req.Op, req.ID, req.Site = SiteUpdate, v.SiteID, v.Site
		same, err := sameSource(*cur, v.Site)
		if err != nil {
			return nil, err
		}
		preview.NoChange = same
	default:
		req.Op, req.Site = SiteAdd, v.Site
	}
	preview.Op = req.Op
	preview.Widens = rollbackWidening(cur, req.Op, v.Site)

	pl, err := s.plan(ctx, req, nil)
	if err != nil {
		return nil, err
	}
	if pl.pending {
		return nil, errors.New("change: the first import is not complete; roll back after it")
	}
	// Caddy's own syntax check of the generated file, before the operator is asked to approve it.
	if _, err := s.caddy.AdaptJSON(ctx, pl.caddyTarget); err != nil {
		return nil, fmt.Errorf("change: Caddy rejected the generated Caddyfile: %w", err)
	}
	preview.Plan = pl.SitePlan
	preview.BaseHash, err = rollbackBaseHash(pl, v.ID)
	if err != nil {
		return nil, err
	}
	return &rollbackPlan{preview: preview, req: req, plan: pl}, nil
}

// sameSource reports whether two site records hold the same source model (id and stamps aside).
func sameSource(a, b site.Site) (bool, error) {
	x, err := site.MarshalSnapshot(a)
	if err != nil {
		return false, err
	}
	y, err := site.MarshalSnapshot(b)
	if err != nil {
		return false, err
	}
	return string(x) == string(y), nil
}

// rollbackBaseHash is the live base of a rollback: every stored site, the Caddyfile and the MagicDNS
// file as they are on disk, the artifacts the rollback would write, and the version. A change to any
// of them between the preview and the approval (another change, a hand edit, a setting that alters
// the render such as the S-06 key) changes the hash.
func rollbackBaseHash(pl *sitePlan, versionID int64) (string, error) {
	h := sha256.New()
	put := func(label, body string) {
		_, _ = fmt.Fprintf(h, "%s:%d\n%s\n", label, len(body), body)
	}
	put("version", strconv.FormatInt(versionID, 10))
	for _, st := range pl.current {
		body, err := site.MarshalSnapshot(st)
		if err != nil {
			return "", err
		}
		put("site:"+strconv.FormatInt(st.ID, 10), string(body))
	}
	put("caddy-disk", pl.diskCaddy)
	put("dns-disk", pl.dnsContent)
	put("dns-exists", strconv.FormatBool(pl.dnsExists))
	put("caddy-target", pl.caddyTarget)
	put("dns-target", pl.dnsTargetBody)
	put("uris-target", uriLines(pl.afterURIs))
	return hex.EncodeToString(h.Sum(nil)), nil
}

// rollbackWidening lists what re-applying target opens beyond cur (nil: the site does not exist now).
// It errs on the side of asking: a new host, a new role, a dropped role check, a new API exemption,
// or maintenance switched off all need the operator's explicit acknowledgement.
func rollbackWidening(cur *site.Site, op string, target site.Site) []string {
	if op == SiteDelete {
		return nil // removing a site never opens access
	}
	if cur == nil {
		return []string{"silinmiş site yeniden açılıyor: " + strings.Join(target.Hosts, ", ")}
	}
	var out []string
	if cur.Kind == site.KindRole && target.Kind == site.KindOpen {
		out = append(out, "rol kontrolü kalkıyor (site rolsüz açık olacak)")
	}
	if added := missingFrom(cur.Roles, target.Roles); len(added) > 0 {
		out = append(out, "yeni roller erişebilecek: "+strings.Join(added, ", "))
	}
	if added := missingFrom(cur.TargetRoles, target.TargetRoles); len(added) > 0 {
		out = append(out, "yeni hedef roller: "+strings.Join(added, ", "))
	}
	if added := missingFrom(cur.Hosts, target.Hosts); len(added) > 0 {
		out = append(out, "yeni host: "+strings.Join(added, ", "))
	}
	if cur.Maintenance && !target.Maintenance {
		out = append(out, "bakım modu kapanıyor")
	}
	for _, r := range target.APIRules {
		if !slices.Contains(cur.APIRules, r) {
			out = append(out, fmt.Sprintf("yeni API bypass kuralı: %s %s", r.Type, r.Value))
		}
	}
	return out
}

// missingFrom returns the items of want that have does not hold.
func missingFrom(have, want []string) []string {
	var out []string
	for _, w := range want {
		if !slices.Contains(have, w) {
			out = append(out, w)
		}
	}
	return out
}

// auditRollback records a refusal. The write is best effort: a refusal changes nothing, so a lost
// refusal record cannot hide a change.
func (s *SitePipeline) auditRollback(ctx context.Context, actor, target, event, result string, versionID int64, reason string) {
	rctx, cancel := recovery(ctx)
	defer cancel()
	diff := audit.Diff{{Field: "version", After: strconv.FormatInt(versionID, 10)}}
	if reason != "" {
		diff = append(diff, audit.Change{Field: "reason", After: reason})
	}
	_ = s.writeAudit(rctx, audit.Entry{Actor: actor, Event: event, Target: target, Diff: diff, Result: result})
}

// auditRollbackResult records which version was applied, by whom, and how it ended.
func (s *SitePipeline) auditRollbackResult(ctx context.Context, actor, target string, versionID int64, res SiteResult, reason string) {
	rctx, cancel := recovery(ctx)
	defer cancel()
	diff := audit.Diff{{Field: "version", After: strconv.FormatInt(versionID, 10)}}
	if res.ChangeID != 0 {
		diff = append(diff, audit.Change{Field: "change", After: strconv.FormatInt(res.ChangeID, 10)})
	}
	switch {
	case res.Revision != "":
		diff = append(diff, audit.Change{Field: "revision", After: res.Revision})
	case res.GitFailed:
		diff = append(diff, audit.Change{Field: "revision", After: "not committed (git failed, queued for retry)"})
	}
	if reason != "" {
		diff = append(diff, audit.Change{Field: "reason", After: reason})
	}
	result := res.Status
	if result == "" {
		result = StatusFailed
	}
	_ = s.writeAudit(rctx, audit.Entry{Actor: actor, Event: "site.rollback", Target: target, Diff: diff, Result: result})
}
