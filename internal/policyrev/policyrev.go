// Package policyrev is the durable store of Headscale policy revisions (H-04, A-03, ADR 0020).
// Every applied or attempted policy is kept as the exact raw HuJSON text with its hashes, source
// and outcome. A revision's content never changes; the only update it gets is the one-time move
// from pending to a final apply status (Finish). The writer, history UI and rollback build on it
// (F3-010, F3-019, F3-025); this package only stores and reads.
package policyrev

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/tailscale/hujson"

	"github.com/nesiler/tagcess/internal/store/db"
)

// Source says where a revision came from.
type Source string

const (
	SourceUI       Source = "ui"
	SourceSync     Source = "sync"
	SourceRollback Source = "rollback"
	SourceRecovery Source = "recovery"
	SourceExternal Source = "external"
)

// Status is a revision's apply outcome. A revision starts pending and Finish moves it once.
type Status string

const (
	StatusPending Status = "pending"
	StatusApplied Status = "applied"
	StatusFailed  Status = "failed"
	StatusUnknown Status = "unknown"
	// StatusDryRun is the final state of a revision the dry-run gate stopped before any write.
	StatusDryRun Status = "dry_run"
)

// timeFormat is the fixed-width millisecond layout the audit log uses.
const timeFormat = "2006-01-02T15:04:05.000Z"

var (
	ErrNotFound          = errors.New("policyrev: revision not found")
	ErrNoActor           = errors.New("policyrev: actor is required")
	ErrInvalidSource     = errors.New("policyrev: unknown source")
	ErrInvalidStatus     = errors.New("policyrev: finish needs a final status")
	ErrInvalidRaw        = errors.New("policyrev: raw is not a HuJSON object")
	ErrInvalidValidation = errors.New("policyrev: validation is not JSON")
	ErrInvalidLimit      = errors.New("policyrev: limit must be positive")
	ErrAlreadyFinished   = errors.New("policyrev: revision is already finished")
)

// Revision is a stored policy revision. ParentID, ChangeID and RollbackOf are 0 when absent.
type Revision struct {
	ID            int64
	ParentID      int64
	BaseHash      string // raw hash of the live policy this revision was based on
	Raw           string // exact bytes, comments and formatting included
	RawHash       string
	CanonicalHash string
	Source        Source
	Actor         string
	CreatedAt     time.Time
	Reason        string
	Validation    string // JSON: stage results and validator version
	ApplyStatus   Status
	ApplyDetail   string
	ChangeID      int64
	RollbackOf    int64
}

// NewRevision is what Add stores. ParentID is set by Add to the newest existing revision.
type NewRevision struct {
	BaseHash   string
	Raw        string
	Source     Source
	Actor      string
	Reason     string
	Validation string // JSON; empty means "{}"
	ChangeID   int64
	RollbackOf int64
}

// Repo reads and writes policy revisions.
type Repo struct {
	q     *db.Queries
	clock func() time.Time
	mu    sync.Mutex // makes parent lookup + insert and the baseline check-then-add atomic
}

// New returns a repo over q.
func New(q *db.Queries) *Repo { return &Repo{q: q, clock: time.Now} }

// HashRaw is the sha256 of the exact text, hex encoded.
func HashRaw(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// CanonicalHash hashes the document's meaning: HuJSON is standardized to JSON (comments and
// trailing commas dropped) and re-encoded with sorted object keys and no insignificant space, so
// formatting and key order do not change it. Array order and values do. The root must be an object.
func CanonicalHash(raw string) (string, error) {
	std, err := hujson.Standardize([]byte(raw))
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidRaw, err)
	}
	dec := json.NewDecoder(bytes.NewReader(std))
	dec.UseNumber() // keep numbers exact
	var v any
	if err := dec.Decode(&v); err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidRaw, err)
	}
	if _, ok := v.(map[string]any); !ok {
		return "", fmt.Errorf("%w: the root is not an object", ErrInvalidRaw)
	}
	canon, err := json.Marshal(v) // map keys are sorted
	if err != nil {
		return "", fmt.Errorf("policyrev: canonical json: %w", err)
	}
	return HashRaw(string(canon)), nil
}

// Add stores a new pending revision chained to the newest existing one and returns it.
func (r *Repo) Add(ctx context.Context, n NewRevision) (Revision, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.add(ctx, n)
}

func (r *Repo) add(ctx context.Context, n NewRevision) (Revision, error) {
	actor := strings.TrimSpace(n.Actor)
	if actor == "" {
		return Revision{}, ErrNoActor
	}
	switch n.Source {
	case SourceUI, SourceSync, SourceRollback, SourceRecovery, SourceExternal:
	default:
		return Revision{}, fmt.Errorf("%w %q", ErrInvalidSource, n.Source)
	}
	validation := n.Validation
	if validation == "" {
		validation = "{}"
	}
	if !json.Valid([]byte(validation)) {
		return Revision{}, ErrInvalidValidation
	}
	canonical, err := CanonicalHash(n.Raw)
	if err != nil {
		return Revision{}, err
	}
	parent, err := r.q.LatestPolicyRevisionID(ctx)
	if err != nil {
		return Revision{}, fmt.Errorf("policyrev: parent: %w", err)
	}
	row, err := r.q.InsertPolicyRevision(ctx, db.InsertPolicyRevisionParams{
		ParentID:      parent,
		BaseHash:      n.BaseHash,
		Raw:           n.Raw,
		RawHash:       HashRaw(n.Raw),
		CanonicalHash: canonical,
		Source:        string(n.Source),
		Actor:         actor,
		CreatedAt:     r.clock().UTC().Format(timeFormat),
		Reason:        n.Reason,
		Validation:    validation,
		ChangeID:      n.ChangeID,
		RollbackOf:    n.RollbackOf,
	})
	if err != nil {
		return Revision{}, fmt.Errorf("policyrev: insert: %w", err)
	}
	return fromRow(row)
}

// Finish moves a pending revision to a final status, once. A second call, or a pending target,
// is an error and changes nothing.
func (r *Repo) Finish(ctx context.Context, id int64, status Status, detail string) error {
	switch status {
	case StatusApplied, StatusFailed, StatusUnknown, StatusDryRun:
	default:
		return fmt.Errorf("%w: %q", ErrInvalidStatus, status)
	}
	n, err := r.q.FinishPolicyRevision(ctx, db.FinishPolicyRevisionParams{
		ApplyStatus: string(status), ApplyDetail: detail, ID: id,
	})
	if err != nil {
		return fmt.Errorf("policyrev: finish %d: %w", id, err)
	}
	if n == 1 {
		return nil
	}
	if _, err := r.Get(ctx, id); err != nil {
		return err
	}
	return ErrAlreadyFinished
}

// Get reads one revision; an unknown id is ErrNotFound.
func (r *Repo) Get(ctx context.Context, id int64) (Revision, error) {
	row, err := r.q.GetPolicyRevision(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return Revision{}, ErrNotFound
	}
	if err != nil {
		return Revision{}, fmt.Errorf("policyrev: get %d: %w", id, err)
	}
	return fromRow(row)
}

// List returns up to limit revisions, newest first.
func (r *Repo) List(ctx context.Context, limit int) ([]Revision, error) {
	if limit < 1 {
		return nil, ErrInvalidLimit
	}
	rows, err := r.q.ListPolicyRevisions(ctx, int64(limit))
	if err != nil {
		return nil, fmt.Errorf("policyrev: list: %w", err)
	}
	out := make([]Revision, 0, len(rows))
	for _, row := range rows {
		rev, err := fromRow(row)
		if err != nil {
			return nil, err
		}
		out = append(out, rev)
	}
	return out, nil
}

// EnsureBaseline records the live policy as an external, already applied revision when it differs
// from the newest applied revision (someone changed it outside tagcess, or tagcess has no history
// yet). It reports whether it added one; a live policy equal to the newest applied revision, or
// to a baseline added earlier, adds nothing. The caller passes the live text it read; if it could
// not read it, it must not call this (rule 7).
func (r *Repo) EnsureBaseline(ctx context.Context, live, actor string) (Revision, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, err := CanonicalHash(live); err != nil {
		return Revision{}, false, err
	}
	latest, err := r.q.LatestAppliedPolicyRevision(ctx)
	switch {
	case err == nil:
		if latest.RawHash == HashRaw(live) {
			rev, err := fromRow(latest)
			return rev, false, err
		}
	case errors.Is(err, sql.ErrNoRows):
		latest = db.PolicyRevision{}
	default:
		return Revision{}, false, fmt.Errorf("policyrev: latest applied: %w", err)
	}
	rev, err := r.add(ctx, NewRevision{
		BaseHash: latest.RawHash,
		Raw:      live,
		Source:   SourceExternal,
		Actor:    actor,
		Reason:   "baseline: the live policy differs from the last recorded revision",
	})
	if err != nil {
		return Revision{}, false, err
	}
	if err := r.Finish(ctx, rev.ID, StatusApplied, "recorded as found live"); err != nil {
		return Revision{}, false, err
	}
	rev, err = r.Get(ctx, rev.ID)
	return rev, err == nil, err
}

func fromRow(row db.PolicyRevision) (Revision, error) {
	at, err := time.Parse(timeFormat, row.CreatedAt)
	if err != nil {
		return Revision{}, fmt.Errorf("policyrev: parse time %q: %w", row.CreatedAt, err)
	}
	return Revision{
		ID:            row.ID,
		ParentID:      row.ParentID,
		BaseHash:      row.BaseHash,
		Raw:           row.Raw,
		RawHash:       row.RawHash,
		CanonicalHash: row.CanonicalHash,
		Source:        Source(row.Source),
		Actor:         row.Actor,
		CreatedAt:     at,
		Reason:        row.Reason,
		Validation:    row.Validation,
		ApplyStatus:   Status(row.ApplyStatus),
		ApplyDetail:   row.ApplyDetail,
		ChangeID:      row.ChangeID,
		RollbackOf:    row.RollbackOf,
	}, nil
}
