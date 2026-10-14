// Package policywriter applies the policy text a devops edits (H-04, ADR 0020). A save reads the live
// policy, users, nodes and Zitadel roles after the writer lock is taken, rebuilds the Zitadel-owned
// groups, adds the locked mandatory tests, validates the result, and hands it to the change pipeline,
// which applies it, reads it back and records the revision. Zitadel unreadable, a stale editor, a plan
// the sync holds for approval and an uncertain earlier write all stop the save before anything is
// written (rule 7). Preview does the same work read-only.
package policywriter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/tailscale/hujson"

	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/policydoc"
	"github.com/nesiler/tagcess/internal/policyrev"
	"github.com/nesiler/tagcess/internal/sync"
)

var (
	// ErrZitadelUnavailable blocks a save while Zitadel cannot be read completely (R2 decision 14).
	// The CLI emergency path (security §11) stays available.
	ErrZitadelUnavailable = errors.New("Zitadel okunamıyor") //nolint:staticcheck // a product name, and the message the UI shows
	// ErrHeadscaleUnavailable means the live policy, users or nodes could not be read.
	ErrHeadscaleUnavailable = errors.New("Headscale okunamıyor") //nolint:staticcheck // a product name, and the message the UI shows
	// ErrStale means the editor's base hash is not the live policy's; SaveResult.Current holds the
	// live text.
	ErrStale = errors.New("policy editör açıldıktan sonra değişti; güncel metni yükleyin")
	// ErrSyncPending means the groups the sync would write wait for approval or are blocked (Y-03.4,
	// G-03); the editor must not bypass that.
	ErrSyncPending = errors.New("grup değişikliği onay bekliyor veya engelli; /sync sayfasına gidin")
	// ErrInvalid means validation failed; SaveResult.Report says where.
	ErrInvalid = errors.New("policy doğrulaması başarısız")
	// ErrUncertain means an earlier write's outcome is unknown and the live policy is not the last
	// applied revision; no save is accepted until it is (F3-029 recovers it).
	ErrUncertain = errors.New("apply belirsiz: önceki yazımın sonucu doğrulanamadı; canlı policy son apply edilen revision'la eşleşene dek kayıt yapılamaz")
	// ErrRollbackTarget means a rollback names no revision, or one that is not an applied (or external
	// baseline) revision (F3-025, ADR 0020).
	ErrRollbackTarget = errors.New("geri alma hedefi yalnız apply edilmiş bir revision olabilir")
	// ErrNotUncertain means a recovery was asked for while no earlier write is unresolved (F3-029).
	ErrNotUncertain = errors.New("belirsiz durum yok: recovery yalnız belirsiz durum varken açılır")
	// ErrNoRecoveryTarget means no applied revision exists to recover to.
	ErrNoRecoveryTarget = errors.New("recovery hedefi yok: apply edilmiş revision bulunamadı")
	// ErrNotApplied means the pipeline refused or could not complete the write; the revision says how.
	ErrNotApplied = errors.New("policy apply edilemedi")
)

// Evaluator reads the live state and plans the sync; *sync.Reconciler satisfies it.
type Evaluator interface {
	Evaluate(ctx context.Context) (sync.Evaluation, error)
}

// Submitter is the change pipeline's lock-then-build entry; *change.Pipeline satisfies it.
type Submitter interface {
	SubmitBuilt(ctx context.Context, actor string, build func(context.Context) (change.Request, error)) (change.Result, error)
}

// Config wires a Writer. Every field is required.
type Config struct {
	Evaluator Evaluator
	Pipeline  Submitter
	Revisions *policyrev.Repo
	Checker   policydoc.Checker
	// LockedSource returns the locked test parameters; it is read on every save and preview, so a
	// changed setting applies to the next operation (F3-020). Locked is the fixed value used when no
	// source is given. One of the two is required.
	LockedSource func(ctx context.Context) (policydoc.LockedConfig, error)
	Locked       policydoc.LockedConfig
}

// Writer is the policy writer. Use New.
type Writer struct {
	eval    Evaluator
	pipe    Submitter
	revs    *policyrev.Repo
	checker policydoc.Checker
	locked  func(ctx context.Context) (policydoc.LockedConfig, error)
}

// New validates the wiring and returns a Writer.
func New(cfg Config) (*Writer, error) {
	switch {
	case cfg.Evaluator == nil:
		return nil, errors.New("policywriter: an evaluator is required")
	case cfg.Pipeline == nil:
		return nil, errors.New("policywriter: a change pipeline is required")
	case cfg.Revisions == nil:
		return nil, errors.New("policywriter: a revision repo is required")
	case cfg.Checker == nil:
		return nil, errors.New("policywriter: a policy checker is required")
	case cfg.LockedSource == nil && cfg.Locked.DevopsGroup == "":
		return nil, errors.New("policywriter: locked test parameters are required")
	}
	locked := cfg.LockedSource
	if locked == nil {
		fixed := cfg.Locked
		locked = func(context.Context) (policydoc.LockedConfig, error) { return fixed, nil }
	}
	return &Writer{eval: cfg.Evaluator, pipe: cfg.Pipeline, revs: cfg.Revisions, checker: cfg.Checker, locked: locked}, nil
}

// SaveRequest is one editor submission. BaseHash is the policyrev.HashRaw of the live text the editor
// was loaded from. Source defaults to ui; a rollback (F3-025) uses SourceRollback with RollbackOf.
// A recovery (F3-029) uses SourceRecovery with no Text: the writer takes the last applied revision as
// the target and sets Text and RollbackOf itself.
type SaveRequest struct {
	Actor      string
	Text       string
	BaseHash   string
	Source     policyrev.Source
	Reason     string
	RollbackOf int64
}

// SectionChange is the meaning-level difference of one top-level section: the entries (array
// elements, object members, or the value itself) only in the new document and only in the old one.
type SectionChange struct {
	Section string
	Added   []string
	Removed []string
}

// SaveResult is what Save and Preview report. Fields not reached stay zero.
type SaveResult struct {
	// Current is the live policy text, set so a stale editor can show it.
	Current string
	// Text is the document that is (or would be) written: Zitadel's groups, locked tests added.
	Text   string
	Report policydoc.Report
	// GroupsRebuilt says the submitted groups section differed and tagcess replaced it.
	GroupsRebuilt bool
	// Locked lists what tagcess added or reset among the locked tests.
	Locked []policydoc.Change
	// RawDiff is the line diff from the live text to Text; Semantic the meaning-level one.
	RawDiff  string
	Semantic []SectionChange
	// Target is the revision a recovery restores (the last applied one); zero otherwise.
	Target policyrev.Revision
	// Change and Revision are set by Save once the pipeline ran.
	Change   change.Result
	Revision policyrev.Revision
}

// prepared is everything Save and Preview compute from one fresh read.
type prepared struct {
	result SaveResult
	live   string
	// req is the request as prepared: a recovery's Text and RollbackOf are filled in.
	req SaveRequest
}

// Preview does Save's work without writing anything: no lock, no baseline, no revision, no apply. It
// returns the same refusals; a text that fails validation is not an error, its report says why.
func (w *Writer) Preview(ctx context.Context, req SaveRequest) (SaveResult, error) {
	p, err := w.prepare(ctx, req)
	return p.result, err
}

// Save applies the editor's text. The live reads, the group composition, the locked tests and the
// validation all run inside the writer lock (SubmitBuilt), and the lock is held through the apply,
// so no other writer can change the live policy in between (ADR 0020).
func (w *Writer) Save(ctx context.Context, req SaveRequest) (SaveResult, error) {
	var prep prepared
	res, err := w.pipe.SubmitBuilt(ctx, req.Actor, func(ctx context.Context) (change.Request, error) {
		var err error
		prep, err = w.prepare(ctx, req)
		if err != nil {
			return change.Request{}, err
		}
		if !prep.result.Report.Valid() {
			return change.Request{}, fmt.Errorf("%w: %s", ErrInvalid, failureText(prep.result.Report))
		}
		// The live policy is recorded as the baseline revision only now that the save will go ahead.
		// A recovery never records it: the live policy is the unresolved state, not a known-good one.
		if req.Source != policyrev.SourceRecovery {
			if _, _, err := w.revs.EnsureBaseline(ctx, prep.live, req.Actor); err != nil {
				return change.Request{}, fmt.Errorf("policywriter: baseline revision: %w", err)
			}
		}
		return w.request(prep.req, prep), nil
	})
	out := prep.result
	out.Change = res
	if err != nil && res == (change.Result{}) {
		return out, err
	}
	if res.RevisionID != 0 {
		if rev, gerr := w.revs.Get(ctx, res.RevisionID); gerr == nil {
			out.Revision = rev
		}
	}
	switch {
	case res.Applied || res.Status == change.StatusDryRun:
		return out, err
	case err != nil:
		return out, fmt.Errorf("%w: %w", ErrNotApplied, err)
	case out.Revision.ApplyStatus == policyrev.StatusUnknown:
		return out, fmt.Errorf("%w: apply belirsiz: %s", ErrNotApplied, out.Revision.ApplyDetail)
	default:
		return out, fmt.Errorf("%w: %s", ErrNotApplied, out.Revision.ApplyDetail)
	}
}

// prepare reads fresh state and builds the document. It returns an error for every reason the save
// must not go ahead except validation, which is reported in result.Report.
func (w *Writer) prepare(ctx context.Context, req SaveRequest) (prepared, error) {
	var p prepared
	switch req.Source {
	case policyrev.SourceRollback:
		if err := w.checkRollbackTarget(ctx, req.RollbackOf); err != nil {
			return p, err
		}
	case policyrev.SourceRecovery:
		target, err := w.recoveryTarget(ctx)
		if err != nil {
			return p, err
		}
		req.Text, req.RollbackOf = target.Raw, target.ID
		if req.Reason == "" {
			req.Reason = fmt.Sprintf("belirsiz durumdan recovery: revision #%d", target.ID)
		}
		p.result.Target = target
	}
	p.req = req
	// Read per operation; an unreadable setting stops the save (rule 7).
	locked, err := w.locked(ctx)
	if err != nil {
		return p, fmt.Errorf("policywriter: locked test parameters: %w", err)
	}
	ev, err := w.eval.Evaluate(ctx)
	if err != nil {
		return p, fmt.Errorf("policywriter: %w", err)
	}
	if ev.HeadscaleErr != nil {
		return p, fmt.Errorf("%w: %w", ErrHeadscaleUnavailable, ev.HeadscaleErr)
	}
	if err := zitadelBlock(ev); err != nil {
		return p, err
	}
	plan := ev.Plan
	p.live = string(ev.Input.Policy)
	p.result.Current = p.live

	detail, err := w.uncertain(ctx, p.live)
	switch {
	case err != nil:
		return p, err
	case req.Source == policyrev.SourceRecovery && detail == "":
		return p, ErrNotUncertain
	case req.Source != policyrev.SourceRecovery && detail != "":
		return p, fmt.Errorf("%w (%s)", ErrUncertain, detail)
	}
	if req.BaseHash == "" || req.BaseHash != policyrev.HashRaw(p.live) {
		return p, ErrStale
	}
	// The groups come from Zitadel through the sync's own rule, so the sync's gates apply: a plan the
	// sync would hold (Y-03.4 threshold, G-03 conversion) or block must not be written from here.
	if plan.NeedsApproval || plan.Blocked {
		return p, fmt.Errorf("%w: %s", ErrSyncPending, plan.Reason)
	}

	in := ev.Input
	in.Policy = []byte(req.Text)
	composed, err := sync.Target(in)
	if err != nil {
		// Most often the text itself is broken; let the validation say where.
		if rep := policydoc.Validate(ctx, req.Text, locked, w.checker); failedBeforeLocked(rep) {
			p.result.Report = rep
			return p, nil
		}
		return p, fmt.Errorf("%w: gruplar yeniden kurulamadı: %w", ErrInvalid, err)
	}
	injected, err := policydoc.Inject(string(composed), locked)
	if err != nil {
		return p, fmt.Errorf("%w: kilitli testler eklenemedi: %w", ErrInvalid, err)
	}

	p.result.Text = injected.Text
	p.result.GroupsRebuilt = string(composed) != req.Text
	p.result.Locked = injected.Changes
	p.result.Report = policydoc.Validate(ctx, injected.Text, locked, w.checker)
	p.result.RawDiff = change.LineDiff(p.live, injected.Text)
	p.result.Semantic = semanticDiff(p.live, injected.Text)
	return p, nil
}

// checkRollbackTarget accepts only an applied revision (the external baseline is one) as the target
// of a rollback; a failed, unknown, pending or dry-run one never is.
func (w *Writer) checkRollbackTarget(ctx context.Context, id int64) error {
	rev, err := w.revs.Get(ctx, id)
	switch {
	case errors.Is(err, policyrev.ErrNotFound):
		return fmt.Errorf("%w: revision #%d yok", ErrRollbackTarget, id)
	case err != nil:
		return fmt.Errorf("policywriter: read revision %d: %w", id, err)
	case rev.ApplyStatus != policyrev.StatusApplied:
		return fmt.Errorf("%w: revision #%d %s", ErrRollbackTarget, id, rev.ApplyStatus)
	}
	return nil
}

// uncertain reports whether an earlier write's outcome is still unresolved: a pending or unknown
// revision newer than the last applied one, while the live policy is not that applied revision. The
// state is derived from the stored revisions, so it survives a restart. A live policy equal to the
// last applied revision clears it (an operator restored it, or F3-029 recovered it). detail names
// the newest unresolved revision for the editor's banner; it is empty when the state is resolved.
func (w *Writer) uncertain(ctx context.Context, live string) (detail string, err error) {
	revs, err := w.revs.List(ctx, 200)
	if err != nil {
		return "", fmt.Errorf("policywriter: read revisions: %w", err)
	}
	var newest *policyrev.Revision
	for i, r := range revs { // newest first
		switch r.ApplyStatus {
		case policyrev.StatusPending, policyrev.StatusUnknown:
			if newest == nil {
				newest = &revs[i]
			}
		case policyrev.StatusApplied:
			if newest != nil && r.RawHash != policyrev.HashRaw(live) {
				return uncertainDetail(*newest), nil
			}
			return "", nil
		}
	}
	if newest != nil {
		return uncertainDetail(*newest), nil
	}
	return "", nil
}

func uncertainDetail(r policyrev.Revision) string {
	d := fmt.Sprintf("revision #%d (%s)", r.ID, r.ApplyStatus)
	if r.ApplyDetail != "" {
		d += ": " + r.ApplyDetail
	}
	return d
}

// Live is the editor's starting point (F3-019): the live policy text with its base hash, and what
// closes editing. The text is shown even while Zitadel is down (the page opens read-only); a
// Headscale read failure leaves it empty.
type Live struct {
	Text     string
	BaseHash string
	// HeadscaleErr and ZitadelErr wrap ErrHeadscaleUnavailable / ErrZitadelUnavailable.
	HeadscaleErr error
	ZitadelErr   error
	// Uncertain describes an unresolved earlier write; empty when there is none.
	Uncertain string
}

// Live reads the live policy and the editing blockers without writing anything: no lock, no baseline,
// no revision. A failed read is carried in the result; the error is only for a failed dry-run read or
// unreadable revisions.
func (w *Writer) Live(ctx context.Context) (Live, error) {
	var l Live
	ev, err := w.eval.Evaluate(ctx)
	if err != nil {
		return l, fmt.Errorf("policywriter: %w", err)
	}
	if ev.HeadscaleErr != nil {
		l.HeadscaleErr = fmt.Errorf("%w: %w", ErrHeadscaleUnavailable, ev.HeadscaleErr)
		return l, nil
	}
	l.Text = string(ev.Input.Policy)
	l.BaseHash = policyrev.HashRaw(l.Text)
	l.ZitadelErr = zitadelBlock(ev)
	if l.Uncertain, err = w.uncertain(ctx, l.Text); err != nil {
		return l, err
	}
	return l, nil
}

// zitadelBlock is the error for a Zitadel read that failed or came back incomplete, nil when the
// roles can be trusted.
func zitadelBlock(ev sync.Evaluation) error {
	if ev.ZitadelErr != nil {
		return fmt.Errorf("%w: %w", ErrZitadelUnavailable, ev.ZitadelErr)
	}
	// A plan with no gate that cannot be applied is Compute's answer to an incomplete Zitadel read.
	if p := ev.Plan; !p.WillApply && !p.NeedsApproval && !p.Blocked && !p.DryRun {
		return fmt.Errorf("%w: %s", ErrZitadelUnavailable, p.Reason)
	}
	return nil
}

// request builds the pipeline request for a validated, prepared save.
func (w *Writer) request(req SaveRequest, p prepared) change.Request {
	source := req.Source
	if source == "" {
		source = policyrev.SourceUI
	}
	return change.Request{
		Kind:         change.KindPolicy,
		Actor:        req.Actor,
		Trigger:      sync.TriggerManual,
		Summary:      "policy editörü kaydı",
		Target:       []byte(p.result.Text),
		SourcePolicy: []byte(p.live),
		Revision: change.RevisionMeta{
			Source:     string(source),
			Reason:     req.Reason,
			Validation: validationJSON(p.result),
			RollbackOf: req.RollbackOf,
		},
	}
}

// failedBeforeLocked reports a failure in the stages that look at the text alone, before tagcess's own
// additions.
func failedBeforeLocked(rep policydoc.Report) bool {
	for _, s := range []policydoc.Stage{policydoc.StageInput, policydoc.StageSyntax, policydoc.StageStructure} {
		if rep.Stage(s).State == policydoc.StateFail {
			return true
		}
	}
	return false
}

// failureText names the first stage that did not pass.
func failureText(rep policydoc.Report) string {
	for _, s := range rep.Stages {
		switch s.State {
		case policydoc.StateFail:
			return fmt.Sprintf("%s: %s", s.Stage, s.Message)
		case policydoc.StateUnverified:
			return fmt.Sprintf("%s: doğrulanamadı: %s", s.Stage, s.Message)
		}
	}
	return "rapor eksik"
}

type validationRecord struct {
	Validator     string        `json:"validator"`
	Stages        []stageRecord `json:"stages"`
	GroupsRebuilt bool          `json:"groups_rebuilt"`
	Locked        []string      `json:"locked_changes,omitempty"`
}

type stageRecord struct {
	Stage   string `json:"stage"`
	State   string `json:"state"`
	Message string `json:"message,omitempty"`
}

// validationJSON is the stage summary stored with the revision.
func validationJSON(r SaveResult) string {
	rec := validationRecord{Validator: "policydoc/v1", GroupsRebuilt: r.GroupsRebuilt}
	for _, s := range r.Report.Stages {
		rec.Stages = append(rec.Stages, stageRecord{Stage: string(s.Stage), State: string(s.State), Message: s.Message})
	}
	for _, c := range r.Locked {
		rec.Locked = append(rec.Locked, string(c.Kind)+" "+c.Rule)
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// SemanticDiff is semanticDiff for the editor page (F3-019): the meaning-level difference of two
// policy texts.
func SemanticDiff(before, after string) []SectionChange { return semanticDiff(before, after) }

// semanticDiff compares two documents by meaning, section by section: entries only in the new one are
// Added, only in the old one Removed. Comments, formatting and (inside arrays) order do not count. A
// document that cannot be read yields nil; validation reports that.
func semanticDiff(before, after string) []SectionChange {
	b, ok1 := sectionItems(before)
	a, ok2 := sectionItems(after)
	if !ok1 || !ok2 {
		return nil
	}
	names := map[string]bool{}
	for n := range b {
		names[n] = true
	}
	for n := range a {
		names[n] = true
	}
	var out []SectionChange
	for _, n := range sortedNames(names) {
		added, removed := multisetDiff(b[n], a[n])
		if len(added) > 0 || len(removed) > 0 {
			out = append(out, SectionChange{Section: n, Added: added, Removed: removed})
		}
	}
	return out
}

// sectionItems flattens each top-level section into comparable entries: array elements, "key: value"
// for object members, the value itself otherwise. Metadata members ("#...") are skipped.
func sectionItems(text string) (map[string][]string, bool) {
	std, err := hujson.Standardize([]byte(text))
	if err != nil {
		return nil, false
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(std, &root); err != nil {
		return nil, false
	}
	out := map[string][]string{}
	for name, raw := range root {
		if strings.HasPrefix(name, "#") {
			continue
		}
		var arr []json.RawMessage
		var obj map[string]json.RawMessage
		switch {
		case json.Unmarshal(raw, &arr) == nil:
			for _, el := range arr {
				out[name] = append(out[name], compact(el))
			}
		case json.Unmarshal(raw, &obj) == nil:
			for k, v := range obj {
				out[name] = append(out[name], k+": "+compact(v))
			}
		default:
			out[name] = []string{compact(raw)}
		}
	}
	return out, true
}

func compact(raw json.RawMessage) string {
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return strings.TrimSpace(string(raw))
	}
	return buf.String()
}

// multisetDiff returns the entries only in after (added) and only in before (removed), sorted, with
// duplicates counted.
func multisetDiff(before, after []string) (added, removed []string) {
	count := map[string]int{}
	for _, s := range before {
		count[s]++
	}
	for _, s := range after {
		if count[s] > 0 {
			count[s]--
			continue
		}
		added = append(added, s)
	}
	for _, s := range before {
		if count[s] > 0 {
			count[s]--
			removed = append(removed, s)
		}
	}
	slices.Sort(added)
	slices.Sort(removed)
	return added, removed
}

func sortedNames(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for n := range m {
		out = append(out, n)
	}
	slices.Sort(out)
	return out
}
