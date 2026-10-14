// Package hsadmin is the single pipeline for Headscale device, route, tag and key writes (F3-009,
// R2 T-02). Every operation runs under the process-wide writer lock as: fresh read, protection and
// staleness checks, "started" audit, the RPC, read-back, result audit. The RPC is never retried;
// the read-back decides whether it landed. Feature code only builds an Op.
package hsadmin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/headscale/admin"
	"github.com/nesiler/tagcess/internal/maintenance"
	"github.com/nesiler/tagcess/internal/store/db"
)

// Kind names an operation. It is also the audit event, prefixed with "headscale.".
type Kind string

// The operation kinds.
const (
	KindNodeDelete    Kind = "node.delete"
	KindNodeExpire    Kind = "node.expire"
	KindNodeRename    Kind = "node.rename"
	KindNodeExpiry    Kind = "node.expiry"
	KindNodeReopen    Kind = "node.reopen"
	KindNodeTags      Kind = "node.tags"
	KindNodeRoutes    Kind = "node.routes"
	KindPreAuthCreate Kind = "preauth.create"
	KindPreAuthExpire Kind = "preauth.expire"
	KindPreAuthDelete Kind = "preauth.delete"
	KindAPIKeyExpire  Kind = "apikey.expire"
	KindAPIKeyDelete  Kind = "apikey.delete"
)

// Status is the outcome recorded in the audit log's result column.
type Status string

// The audit results. started is the intent record; the others are terminal.
const (
	StatusStarted Status = "started"
	StatusApplied Status = "applied"
	StatusFailed  Status = "failed"
	StatusUnknown Status = "unknown"
	StatusBlocked Status = "blocked"
	StatusStale   Status = "stale"
)

// Alert kinds raised by the executor.
const (
	// AlertUnverified: an RPC's outcome could not be read back; the device or key may or may not
	// have changed.
	AlertUnverified = "headscale_admin_unverified"
	// AlertUnrecorded: the RPC ran but its result could not be written to the audit log.
	AlertUnrecorded = "headscale_admin_unrecorded"
)

// Errors returned by Do.
var (
	ErrActorRequired = errors.New("hsadmin: actor is required")
	ErrInvalidOp     = errors.New("hsadmin: invalid operation")
	ErrBlocked       = errors.New("hsadmin: blocked by server-node protection")
	ErrGuard         = errors.New("hsadmin: refused by the operation's guard")
	ErrStale         = errors.New("hsadmin: target changed since it was read")
	ErrUnknown       = errors.New("hsadmin: outcome unknown")
	// ErrMaintenance marks a widening write refused because the Headscale maintenance is open (H-07).
	// It always comes together with ErrBlocked, so callers that already handle blocked refusals show
	// the reason ("bakım sürüyor") without change.
	ErrMaintenance = maintenance.ErrMaintenance
)

// Reader is the live Headscale view: the executor reads it for the fresh state and passes it to
// Verify for the read-back. *admin.AdminClient satisfies it.
type Reader interface {
	ListNodes(ctx context.Context) ([]admin.AdminNode, error)
	ListPreAuthKeys(ctx context.Context) ([]admin.PreAuthKey, error)
	ListApiKeys(ctx context.Context) ([]admin.APIKey, error)
}

// Gate is the maintenance gate for widening writes. *maintenance.Service satisfies it.
type Gate interface {
	CheckWidening(ctx context.Context, source string) error
}

// Store is the settings and alert storage plus the maintenance state the default gate reads.
// *db.Queries satisfies it.
type Store interface {
	maintenance.Queries
	GetSetting(ctx context.Context, key string) (string, error)
	InsertAlert(ctx context.Context, arg db.InsertAlertParams) (db.Alert, error)
}

// Op is one write. The feature code builds it; the executor owns the order of steps around it.
type Op struct {
	// Actor is the authenticated identity (or system:sync); empty is refused.
	Actor string
	Kind  Kind
	// ID is the node, pre-auth key or API key the operation targets; 0 only for preauth.create.
	ID uint64
	// Target is the audit target text, for example "node:12".
	Target string
	// Expected is the target's version as the caller last saw it (NodeVersion, PreAuthVersion or
	// APIKeyVersion). It is required for every targeted kind; a mismatch with the live state is
	// ErrStale and nothing is written.
	Expected string
	// Tags is the full tag list a node.tags operation would set; it is checked against the
	// protected list before anything is written.
	Tags []string
	// Diff is the allowed before/after summary for the audit log. Secret fields are masked there
	// and scrubbed from every error text.
	Diff audit.Diff
	// Widens is for kinds whose direction depends on the target (node.expiry): it reports, from the
	// freshly read node, whether the write extends or removes access. While the maintenance is open
	// a widening write is refused; an op without Widens counts as widening (fail safe). The other
	// kinds are fixed by their name: reopen, tags, routes and preauth.create widen; the rest narrow.
	Widens func(target admin.AdminNode) bool
	// Precheck, when set, runs under the writer lock after the protection and staleness checks and
	// before the intent record. An error refuses the operation as blocked; no RPC runs. Use it for
	// a condition that must hold at the moment of writing, such as a fresh eligibility read.
	Precheck func(ctx context.Context) error
	// DiffFrom, when set, replaces Diff with one built from the freshly read target, so the audit
	// "before" values are the state the write really replaced and not what a form claimed. It runs
	// right after the fresh read, before any refusal is recorded.
	DiffFrom func(target admin.AdminNode) audit.Diff
	// Guard, when set, is the op's own pre-write condition. It runs inside the writer lock after
	// the fresh read and the staleness check and before the intent audit and the RPC, so what it
	// proves and what the RPC writes cannot drift apart (F3-021: the reopen's eligibility read and
	// its expiry write share the lock, R2 karar 20). It receives the freshly read target and
	// returns the evidence for the audit log; an error refuses the op without any RPC (blocked,
	// ErrGuard) and the error text is the reason to show.
	Guard func(ctx context.Context, target admin.AdminNode) (audit.Diff, error)
	// Apply performs the RPC once. A secret it produces (a new pre-auth key) stays in the caller's
	// closure; the executor never sees it.
	Apply func(ctx context.Context) error
	// Verify reads the live state through r and reports whether the intended change is in place.
	// An error means the state could not be read (outcome unknown). It runs on a context detached
	// from the caller's cancellation.
	Verify func(ctx context.Context, r Reader) (bool, error)
	// Observed is optional. After Verify it returns facts only the read-back knows (for example
	// the expiry a node ended up with); they are appended to the terminal audit row.
	Observed func() audit.Diff
}

// Result is what Do did. Note carries the read-back remark, for example the RPC error that did not
// stop the change from landing.
type Result struct {
	Status Status
	Note   string
}

// Config wires an Executor. Log is optional.
type Config struct {
	Reader Reader
	Audit  *audit.Logger
	Store  Store
	Log    *slog.Logger
	// Maintenance gates widening writes while a host config change is open (F3b-014). New defaults a
	// nil gate to one on the Store, so the executor is never gate-less (F3b-027 AC3).
	Maintenance Gate
}

// Executor runs Ops. Use New.
type Executor struct {
	rd    Reader
	audit *audit.Logger
	store Store
	gate  Gate
	log   *slog.Logger
	clock func() time.Time
}

// New returns an executor. A missing Maintenance gate defaults to one on the Store, the
// change.NewSite pattern: an executor can never run widening writes without a gate (F3b-027 AC3).
func New(cfg Config) *Executor {
	log := cfg.Log
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	gate := cfg.Maintenance
	if gate == nil {
		gate = maintenance.New(cfg.Store)
	}
	return &Executor{rd: cfg.Reader, audit: cfg.Audit, store: cfg.Store, gate: gate, log: log, clock: time.Now}
}

const (
	// recoveryTimeout bounds the read-back and bookkeeping that must still run after the caller's
	// context was canceled.
	recoveryTimeout = 10 * time.Second
	recordAttempts  = 3
	recordBackoff   = 10 * time.Millisecond
	timeFormat      = "2006-01-02T15:04:05.000Z"
)

// Do runs op under the writer lock. A nil error means the change is in place (applied). Blocked,
// stale, failed and unknown outcomes return the matching error together with the Result.
func (e *Executor) Do(ctx context.Context, op Op) (Result, error) {
	if strings.TrimSpace(op.Actor) == "" {
		return Result{}, ErrActorRequired
	}
	if err := validate(op); err != nil {
		return Result{}, err
	}
	var (
		res Result
		err error
	)
	// The writer lock is not reentrant: nothing below calls change.Submit or Approve.
	_ = change.WithWriterLock(func() error {
		res, err = e.run(ctx, op)
		return nil
	})
	return res, err
}

func validate(op Op) error {
	if op.Apply == nil || op.Verify == nil {
		return fmt.Errorf("%w: apply and verify are required", ErrInvalidOp)
	}
	if strings.TrimSpace(op.Target) == "" {
		return fmt.Errorf("%w: target is required", ErrInvalidOp)
	}
	switch op.Kind {
	case KindPreAuthCreate:
		return nil
	case KindNodeDelete, KindNodeExpire, KindNodeRename, KindNodeExpiry, KindNodeReopen, KindNodeTags,
		KindNodeRoutes, KindPreAuthExpire, KindPreAuthDelete, KindAPIKeyExpire, KindAPIKeyDelete:
		if op.ID == 0 || op.Expected == "" {
			return fmt.Errorf("%w: %s needs a target id and an expected version", ErrInvalidOp, op.Kind)
		}
		return nil
	}
	return fmt.Errorf("%w: unknown kind %q", ErrInvalidOp, op.Kind)
}

func (e *Executor) run(ctx context.Context, op Op) (Result, error) {
	scrub := scrubber(op.Diff)
	rctx, cancel := recovery(ctx)
	defer cancel()

	// 1. Fresh read. If it fails nothing is written (rule 7).
	node, live, found, err := e.readTarget(ctx, op)
	if err != nil {
		note := scrub("canlı durum okunamadı: " + err.Error())
		e.recordRefusal(rctx, op, StatusFailed, note)
		return Result{Status: StatusFailed, Note: note}, fmt.Errorf("hsadmin: %s: %s", op.Kind, note)
	}
	if !found {
		return e.reject(rctx, op, StatusStale, "hedef artık yok", ErrStale)
	}

	if op.DiffFrom != nil {
		op.Diff = op.DiffFrom(node)
	}

	// 2. Protection, then staleness. Both reject before any RPC.
	if isNodeKind(op.Kind) {
		tags, terr := e.ProtectedTags(ctx)
		if reason := blockReason(op, node, tags, terr); reason != "" {
			return e.reject(rctx, op, StatusBlocked, reason, ErrBlocked)
		}
	}
	if op.Kind != KindPreAuthCreate && live != op.Expected {
		return e.reject(rctx, op, StatusStale, "hedef okunduktan sonra değişti", ErrStale)
	}

	// Maintenance gate: only widening writes ask it, so narrowing writes run even when the state
	// cannot be read. It runs after the fresh read, still under the lock, before the intent audit.
	if widens(op, node) {
		if merr := e.gate.CheckWidening(ctx, maintenance.SourceAdmin); merr != nil {
			e.recordRefusal(rctx, op, StatusBlocked, merr.Error())
			e.log.Info("headscale admin operation", "kind", op.Kind, "target", op.Target, "actor", op.Actor, "status", StatusBlocked, "reason", "maintenance")
			return Result{Status: StatusBlocked, Note: maintenance.ErrMaintenance.Error()},
				fmt.Errorf("%w: %w: %s", ErrBlocked, ErrMaintenance, op.Kind)
		}
	}

	if op.Precheck != nil {
		if perr := op.Precheck(ctx); perr != nil {
			return e.reject(rctx, op, StatusBlocked, scrub(perr.Error()), ErrBlocked)
		}
	}

	// 2b. The op's own guard, still inside the lock (F3-021: the eligibility proof and the write
	// it enables must not drift apart). Its evidence joins the audit diff.
	if op.Guard != nil {
		evidence, gerr := op.Guard(ctx, node)
		if len(evidence) > 0 {
			op.Diff = append(op.Diff, evidence...)
		}
		if gerr != nil {
			return e.reject(rctx, op, StatusBlocked, "ön koşul sağlanmadı: "+gerr.Error(), ErrGuard)
		}
	}

	// 3. Intent audit. Without it the RPC does not run.
	if _, err := e.audit.Write(ctx, e.entry(op, StatusStarted, "")); err != nil {
		return Result{}, fmt.Errorf("hsadmin: %s not started, intent not recorded: %w", op.Kind, err)
	}

	// 4. The RPC, once.
	applyErr := op.Apply(ctx)

	// 5. Read-back on a detached context: the caller may be gone but the outcome must be known.
	ok, verr := op.Verify(rctx, e.rd)
	if op.Observed != nil {
		op.Diff = append(slices.Clone(op.Diff), op.Observed()...)
	}

	res, err := outcome(op, applyErr, ok, verr, scrub)
	if res.Status == StatusUnknown {
		e.alert(rctx, AlertUnverified, op)
	}

	// 6. Result audit.
	if rerr := e.record(rctx, op, res.Status, res.Note); rerr != nil {
		e.alert(rctx, AlertUnrecorded, op)
		err = errors.Join(err, fmt.Errorf("hsadmin: result %s not recorded: %w", res.Status, rerr))
	}
	e.log.Info("headscale admin operation", "kind", op.Kind, "target", op.Target, "actor", op.Actor, "status", res.Status)
	return res, err
}

// outcome maps the RPC error and the read-back to a result. A nil error means applied.
func outcome(op Op, applyErr error, ok bool, verr error, scrub func(string) string) (Result, error) {
	switch {
	case verr != nil:
		note := scrub(fmt.Sprintf("geri okunamadı: %v", verr))
		if applyErr != nil {
			note += scrub("; RPC hatası: " + applyErr.Error())
		}
		return Result{Status: StatusUnknown, Note: note}, fmt.Errorf("%w: %s %s", ErrUnknown, op.Kind, note)
	case ok && applyErr != nil:
		return Result{Status: StatusApplied, Note: scrub("RPC hata verdi ama istenen durum gerçekleşmiş: " + applyErr.Error())}, nil
	case ok:
		return Result{Status: StatusApplied}, nil
	case applyErr != nil:
		note := scrub("RPC hatası, durum değişmedi: " + applyErr.Error())
		return Result{Status: StatusFailed, Note: note}, fmt.Errorf("hsadmin: %s failed: %s", op.Kind, note)
	}
	// The RPC reported success but the read-back differs: nobody can say what state this is.
	note := "RPC başarılı döndü ama geri okuma istenen durumu göstermiyor"
	return Result{Status: StatusUnknown, Note: note}, fmt.Errorf("%w: %s %s", ErrUnknown, op.Kind, note)
}

// widens reports whether op extends access, which the maintenance gate refuses. The kind decides,
// except node.expiry, where the op's Widens looks at the fresh node.
func widens(op Op, node admin.AdminNode) bool {
	switch op.Kind {
	case KindNodeReopen, KindNodeTags, KindNodeRoutes, KindPreAuthCreate:
		return true
	case KindNodeExpiry:
		return op.Widens == nil || op.Widens(node)
	}
	return false
}

func isNodeKind(k Kind) bool { return strings.HasPrefix(string(k), "node.") }

// readTarget reads the live target. found is false when it does not exist; live is its version.
// preauth.create has no target and always reads as found.
func (e *Executor) readTarget(ctx context.Context, op Op) (node admin.AdminNode, live string, found bool, err error) {
	switch op.Kind {
	case KindPreAuthCreate:
		return node, "", true, nil
	case KindPreAuthExpire, KindPreAuthDelete:
		keys, err := e.rd.ListPreAuthKeys(ctx)
		if err != nil {
			return node, "", false, err
		}
		if i := slices.IndexFunc(keys, func(k admin.PreAuthKey) bool { return k.ID == op.ID }); i >= 0 {
			return node, PreAuthVersion(keys[i]), true, nil
		}
	case KindAPIKeyExpire, KindAPIKeyDelete:
		keys, err := e.rd.ListApiKeys(ctx)
		if err != nil {
			return node, "", false, err
		}
		if i := slices.IndexFunc(keys, func(k admin.APIKey) bool { return k.ID == op.ID }); i >= 0 {
			return node, APIKeyVersion(keys[i]), true, nil
		}
	default:
		nodes, err := e.rd.ListNodes(ctx)
		if err != nil {
			return node, "", false, err
		}
		if i := slices.IndexFunc(nodes, func(n admin.AdminNode) bool { return n.ID == op.ID }); i >= 0 {
			return nodes[i], NodeVersion(nodes[i]), true, nil
		}
	}
	return node, "", false, nil
}

// reject records a pre-RPC refusal and returns it.
func (e *Executor) reject(ctx context.Context, op Op, status Status, note string, sentinel error) (Result, error) {
	e.recordRefusal(ctx, op, status, note)
	e.log.Info("headscale admin operation", "kind", op.Kind, "target", op.Target, "actor", op.Actor, "status", status)
	return Result{Status: status, Note: note}, fmt.Errorf("%w: %s: %s", sentinel, op.Kind, note)
}

func (e *Executor) entry(op Op, status Status, note string) audit.Entry {
	diff := slices.Clone(op.Diff)
	if note != "" {
		diff = append(diff, audit.Change{Field: "note", After: note})
	}
	return audit.Entry{
		Actor:  op.Actor,
		Event:  "headscale." + string(op.Kind),
		Target: op.Target,
		Diff:   diff,
		Result: string(status),
	}
}

// recordRefusal records a pre-RPC outcome. Nothing was written to Headscale, so a failed record is
// logged, not escalated: the refusal stands either way.
func (e *Executor) recordRefusal(ctx context.Context, op Op, status Status, note string) {
	if err := e.record(ctx, op, status, note); err != nil {
		e.log.Error("headscale admin refusal not recorded", "kind", op.Kind, "target", op.Target, "status", status, "error", err)
	}
}

// record writes a terminal audit row, retrying a transient failure: an external write that
// happened must leave a trace.
func (e *Executor) record(ctx context.Context, op Op, status Status, note string) error {
	return retry(ctx, func() error {
		_, err := e.audit.Write(ctx, e.entry(op, status, note))
		return err
	})
}

func (e *Executor) alert(ctx context.Context, kind string, op Op) {
	now := e.clock().UTC().Format(timeFormat)
	err := retry(ctx, func() error {
		_, err := e.store.InsertAlert(ctx, db.InsertAlertParams{
			Kind:        kind,
			Source:      fmt.Sprintf("hsadmin:%s:%s", op.Kind, op.Target),
			FirstSeenAt: now,
			LastSeenAt:  now,
		})
		return err
	})
	if err != nil {
		e.log.Error("headscale admin alert not raised", "kind", kind, "target", op.Target, "error", err)
	}
}

func retry(ctx context.Context, fn func() error) error {
	var err error
	for attempt := 0; attempt < recordAttempts; attempt++ {
		if err = fn(); err == nil {
			return nil
		}
		select {
		case <-time.After(recordBackoff):
		case <-ctx.Done():
			return err
		}
	}
	return err
}

// recovery detaches from the caller's cancellation but stays bounded.
func recovery(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), recoveryTimeout)
}

// scrubber returns a function replacing every secret value of the diff with the mask.
func scrubber(d audit.Diff) func(string) string {
	var secrets []string
	for _, c := range d {
		if !c.Secret {
			continue
		}
		for _, v := range []string{c.Before, c.After} {
			if v != "" {
				secrets = append(secrets, v)
			}
		}
	}
	return func(s string) string {
		for _, v := range secrets {
			s = strings.ReplaceAll(s, v, audit.Mask)
		}
		return s
	}
}

// versionOf marshals the stable identity of a target. Volatile fields (online, last seen) are left
// out so an idle refresh does not make a page stale.
func versionOf(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("unversionable:%v", err)
	}
	return string(b)
}

func sorted(s []string) []string {
	out := slices.Clone(s)
	slices.Sort(out)
	return out
}

func tsOrEmpty(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// NodeVersion is the version string a node operation's Expected must carry.
func NodeVersion(n admin.AdminNode) string {
	return versionOf(struct {
		ID        uint64
		GivenName string
		UserID    uint64
		Tags      []string
		Expiry    string
		Approved  []string
		Available []string
	}{n.ID, n.GivenName, n.UserID, sorted(n.Tags), tsOrEmpty(n.Expiry), sorted(n.ApprovedRoutes), sorted(n.AvailableRoutes)})
}

// PreAuthVersion is the version string for a pre-auth key operation.
func PreAuthVersion(k admin.PreAuthKey) string {
	return versionOf(struct {
		ID         uint64
		UserID     uint64
		Reusable   bool
		Ephemeral  bool
		Expiration string
		Tags       []string
	}{k.ID, k.UserID, k.Reusable, k.Ephemeral, tsOrEmpty(k.Expiration), sorted(k.Tags)})
}

// APIKeyVersion is the version string for an API key operation.
func APIKeyVersion(k admin.APIKey) string {
	return versionOf(struct {
		ID         uint64
		Prefix     string
		Expiration string
	}{k.ID, k.Prefix, tsOrEmpty(k.Expiration)})
}
