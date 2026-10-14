package k8s

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nesiler/tagcess/internal/store/db"
)

// The snapshot store is the adapter between one full read (reader.go) and the F4-042 queries. A
// snapshot is the complete, secretless inventory of one (scope, profile_version) pair; it is written
// together with its "ok" attempt in one transaction. A failed read writes only an attempt row, so a
// failure can never read back as an empty or partial inventory. State hands the UI the last good
// snapshot, its observation time and the last attempt separately.

const (
	OutcomeOK     = "ok"
	OutcomeFailed = "failed"

	maxMessageLen = 240 // [Ö] stored error text, already sanitized by the caller
)

// Inventory is what one complete read keeps: every Ingress and Service of the selected namespaces and
// every IngressClass. The types already drop Secret names and arbitrary annotations (types.go).
type Inventory struct {
	Ingresses      []Ingress      `json:"ingresses"`
	Services       []Service      `json:"services"`
	IngressClasses []IngressClass `json:"ingress_classes"`
}

// snapshotPair identifies what a snapshot is a snapshot of. Only the exact pair is "current".
type snapshotPair struct {
	Scope   string // sorted, comma-joined namespaces
	Version string // digest of the other fields that decide what is read and from where
}

// Snapshot is a complete read as stored.
type Snapshot struct {
	ID             int64
	Scope          string
	ProfileVersion string
	ObservedAt     time.Time
	Inventory      Inventory
}

// Attempt is one read attempt. SnapshotID is set only for an ok attempt.
type Attempt struct {
	AttemptedAt time.Time
	Outcome     string // OutcomeOK or OutcomeFailed
	Class       string // short label of a failure, e.g. credential_expired
	Message     string // sanitized, truncated
	SnapshotID  int64
}

// State is what the UI shows about the current profile's inventory.
//
//   - Current is the latest complete snapshot of the exact scope/profile version; nil if that pair
//     has none yet.
//   - LastAttempt is the latest attempt of that pair, successful or not; nil if it was never read.
//   - Stale means Current exists but the last attempt failed, or another scope/profile version has a
//     newer snapshot (a revert), so Current may no longer be true.
//   - Previous is set only while Current is nil: the latest snapshot of another scope/profile
//     version, to be shown as old-scope data and never as the current inventory.
type State struct {
	Current     *Snapshot
	LastAttempt *Attempt
	Stale       bool
	Previous    *Snapshot
}

// SnapshotStore reads and writes snapshots over the F4-042 queries.
type SnapshotStore struct {
	db *sql.DB
	q  *db.Queries
}

// NewSnapshotStore returns the store over an open database.
func NewSnapshotStore(sqldb *sql.DB, q *db.Queries) *SnapshotStore {
	return &SnapshotStore{db: sqldb, q: q}
}

func formatTime(t time.Time) string { return t.UTC().Format(timeFormat) }

// Publish stores the snapshot and its ok attempt in one transaction; on any error neither remains.
func (s *SnapshotStore) Publish(ctx context.Context, pair snapshotPair, at time.Time, inv Inventory) (Snapshot, error) {
	payload, err := json.Marshal(inv)
	if err != nil {
		return Snapshot{}, fmt.Errorf("k8s: encode snapshot: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Snapshot{}, fmt.Errorf("k8s: begin snapshot: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	q := s.q.WithTx(tx)

	row, err := q.InsertK8sSnapshot(ctx, db.InsertK8sSnapshotParams{
		Scope: pair.Scope, ProfileVersion: pair.Version, ObservedAt: formatTime(at), Payload: string(payload),
	})
	if err != nil {
		return Snapshot{}, fmt.Errorf("k8s: write snapshot: %w", err)
	}
	if _, err := q.InsertK8sSnapshotAttempt(ctx, db.InsertK8sSnapshotAttemptParams{
		Scope: pair.Scope, ProfileVersion: pair.Version, AttemptedAt: formatTime(at), Outcome: OutcomeOK,
		SnapshotID: sql.NullInt64{Int64: row.ID, Valid: true},
	}); err != nil {
		return Snapshot{}, fmt.Errorf("k8s: write snapshot attempt: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Snapshot{}, fmt.Errorf("k8s: commit snapshot: %w", err)
	}
	return Snapshot{ID: row.ID, Scope: pair.Scope, ProfileVersion: pair.Version, ObservedAt: at.UTC().Truncate(time.Millisecond), Inventory: inv}, nil
}

// RecordFailure writes a failed attempt. It never touches a snapshot.
func (s *SnapshotStore) RecordFailure(ctx context.Context, pair snapshotPair, at time.Time, class, message string) error {
	if len(message) > maxMessageLen {
		message = message[:maxMessageLen]
	}
	_, err := s.q.InsertK8sSnapshotAttempt(ctx, db.InsertK8sSnapshotAttemptParams{
		Scope: pair.Scope, ProfileVersion: pair.Version, AttemptedAt: formatTime(at), Outcome: OutcomeFailed,
		ErrorClass: class, Error: message,
	})
	if err != nil {
		return fmt.Errorf("k8s: write failed attempt: %w", err)
	}
	return nil
}

// State returns the current snapshot, the last attempt and, when the pair has no snapshot, the
// previous scope's data. A stored payload that cannot be decoded is an error, never an empty inventory.
func (s *SnapshotStore) State(ctx context.Context, pair snapshotPair) (State, error) {
	var st State
	cur, err := s.q.LatestK8sSnapshot(ctx, db.LatestK8sSnapshotParams{Scope: pair.Scope, ProfileVersion: pair.Version})
	switch {
	case err == nil:
		snap, err := toSnapshot(cur)
		if err != nil {
			return State{}, err
		}
		st.Current = &snap
	case !errors.Is(err, sql.ErrNoRows):
		return State{}, fmt.Errorf("k8s: read snapshot: %w", err)
	}

	att, err := s.q.LatestK8sSnapshotAttempt(ctx, db.LatestK8sSnapshotAttemptParams{Scope: pair.Scope, ProfileVersion: pair.Version})
	switch {
	case err == nil:
		a, err := toAttempt(att)
		if err != nil {
			return State{}, err
		}
		st.LastAttempt = &a
	case !errors.Is(err, sql.ErrNoRows):
		return State{}, fmt.Errorf("k8s: read snapshot attempt: %w", err)
	}
	st.Stale = st.Current != nil && st.LastAttempt != nil && st.LastAttempt.Outcome == OutcomeFailed

	prev, err := s.q.LatestK8sSnapshotOtherPair(ctx, db.LatestK8sSnapshotOtherPairParams{Scope: pair.Scope, ProfileVersion: pair.Version})
	switch {
	case err == nil:
		snap, err := toSnapshot(prev)
		if err != nil {
			return State{}, err
		}
		if st.Current == nil {
			st.Previous = &snap
		} else if snap.ObservedAt.After(st.Current.ObservedAt) {
			// The scope was changed and restored: the exact pair's snapshot predates a newer read of
			// another scope, so it may no longer be true.
			st.Stale = true
		}
	case !errors.Is(err, sql.ErrNoRows):
		return State{}, fmt.Errorf("k8s: read previous snapshot: %w", err)
	}
	return st, nil
}

func toSnapshot(row db.K8sSnapshot) (Snapshot, error) {
	at, err := time.Parse(timeFormat, row.ObservedAt)
	if err != nil {
		return Snapshot{}, errors.New("k8s: stored snapshot has an invalid time")
	}
	var inv Inventory
	if err := json.Unmarshal([]byte(row.Payload), &inv); err != nil {
		return Snapshot{}, errors.New("k8s: stored snapshot is not readable") // json errors may quote the input
	}
	return Snapshot{ID: row.ID, Scope: row.Scope, ProfileVersion: row.ProfileVersion, ObservedAt: at, Inventory: inv}, nil
}

func toAttempt(row db.K8sSnapshotAttempt) (Attempt, error) {
	at, err := time.Parse(timeFormat, row.AttemptedAt)
	if err != nil {
		return Attempt{}, errors.New("k8s: stored attempt has an invalid time")
	}
	return Attempt{AttemptedAt: at, Outcome: row.Outcome, Class: row.ErrorClass, Message: row.Error, SnapshotID: row.SnapshotID.Int64}, nil
}
