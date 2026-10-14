package k8s

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/nesiler/tagcess/internal/store/db"
)

// DraftStore persists the incomplete, not-yet-applied host drafts (F4-012) over the F4-009 queries. It
// touches only k8s_drafts and k8s_draft_routes: a stored draft is never a SiteStore row and can never
// change the running access settings, Caddy, DNS, URIs or the cluster (fail safe, R3-AC-13). One draft
// exists per (cluster, host).

// Provenance is the discovery-owned part of a stored draft: which profile version and snapshot the
// proposal came from.
type Provenance struct {
	ProfileVersion string
	SnapshotID     int64 // 0 when the snapshot is gone
	ObservedAt     time.Time
}

// SavedDraft is a stored draft: the choices and review request (Draft), the provenance it was
// prepared from, and its timestamps.
type SavedDraft struct {
	Draft      Draft
	Provenance Provenance
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// DraftStore reads and writes drafts of one cluster.
type DraftStore struct {
	db      *sql.DB
	q       *db.Queries
	cluster string
}

// NewDraftStore returns the store over an open database for one cluster identity.
func NewDraftStore(sqldb *sql.DB, q *db.Queries, cluster string) *DraftStore {
	return &DraftStore{db: sqldb, q: q, cluster: cluster}
}

// Get returns the stored draft of host; ok is false when none exists.
func (s *DraftStore) Get(ctx context.Context, host string) (SavedDraft, bool, error) {
	host = normalizeHost(host)
	row, err := s.q.GetK8sDraft(ctx, db.GetK8sDraftParams{Cluster: s.cluster, Host: host})
	if errors.Is(err, sql.ErrNoRows) {
		return SavedDraft{}, false, nil
	}
	if err != nil {
		return SavedDraft{}, false, fmt.Errorf("k8s: read draft: %w", err)
	}
	routes, err := s.q.ListK8sDraftRoutes(ctx, row.ID)
	if err != nil {
		return SavedDraft{}, false, fmt.Errorf("k8s: read draft routes: %w", err)
	}
	d, err := draftFromRow(row, routes)
	if err != nil {
		return SavedDraft{}, false, err
	}
	return d, true, nil
}

// Save writes the draft and replaces its route provenance in one transaction. The review request in
// the draft is stored as given; callers never drop a pending review.
func (s *DraftStore) Save(ctx context.Context, d SavedDraft, now time.Time) (SavedDraft, error) {
	roles, err := json.Marshal(normalizeRoles(d.Draft.Roles))
	if err != nil {
		return SavedDraft{}, fmt.Errorf("k8s: encode draft roles: %w", err)
	}
	candidates := d.Draft.ReviewCandidates
	if candidates == nil {
		candidates = []string{}
	}
	cand, err := json.Marshal(candidates)
	if err != nil {
		return SavedDraft{}, fmt.Errorf("k8s: encode draft candidates: %w", err)
	}
	var observed string
	if !d.Provenance.ObservedAt.IsZero() {
		observed = formatTime(d.Provenance.ObservedAt)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SavedDraft{}, fmt.Errorf("k8s: begin draft save: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	q := s.q.WithTx(tx)

	row, err := q.UpsertK8sDraft(ctx, db.UpsertK8sDraftParams{
		Cluster: s.cluster, Host: normalizeHost(d.Draft.Host),
		ProfileVersion: d.Provenance.ProfileVersion,
		SnapshotID:     sql.NullInt64{Int64: d.Provenance.SnapshotID, Valid: d.Provenance.SnapshotID != 0},
		ObservedAt:     observed,
		AccessChoice:   d.Draft.AccessChoice, Roles: string(roles),
		Target: d.Draft.Target, Cert: d.Draft.Cert, Note: d.Draft.Note,
		ReviewState: d.Draft.ReviewState, ReviewReason: d.Draft.ReviewReason,
		ReviewCandidates: string(cand), ReviewDefault: d.Draft.ReviewDefault,
		CreatedAt: formatTime(now), UpdatedAt: formatTime(now),
	})
	if err != nil {
		return SavedDraft{}, fmt.Errorf("k8s: write draft: %w", err)
	}
	if _, err := q.DeleteK8sDraftRoutes(ctx, row.ID); err != nil {
		return SavedDraft{}, fmt.Errorf("k8s: clear draft routes: %w", err)
	}
	for _, r := range d.Draft.Routes {
		if _, err := q.UpsertK8sDraftRoute(ctx, db.UpsertK8sDraftRouteParams{
			DraftID: row.ID, Namespace: r.Namespace, IngressName: r.Ingress, IngressUid: r.UID,
			Path: r.Path, PathType: string(r.PathType),
			BackendService: r.Backend.Service, BackendPort: backendPortText(r.Backend),
			ObservedAt: observed,
		}); err != nil {
			return SavedDraft{}, fmt.Errorf("k8s: write draft route: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return SavedDraft{}, fmt.Errorf("k8s: commit draft save: %w", err)
	}
	saved, ok, err := s.Get(ctx, d.Draft.Host)
	if err != nil || !ok {
		return SavedDraft{}, fmt.Errorf("k8s: reread saved draft: %w", err)
	}
	return saved, nil
}

func backendPortText(b Backend) string {
	if b.PortName != "" {
		return b.PortName
	}
	return strconv.Itoa(b.PortNumber)
}

func draftFromRow(row db.K8sDraft, routes []db.K8sDraftRoute) (SavedDraft, error) {
	var roles, candidates []string
	if err := json.Unmarshal([]byte(row.Roles), &roles); err != nil {
		return SavedDraft{}, fmt.Errorf("k8s: stored draft roles: %w", err)
	}
	if err := json.Unmarshal([]byte(row.ReviewCandidates), &candidates); err != nil {
		return SavedDraft{}, fmt.Errorf("k8s: stored draft candidates: %w", err)
	}
	d := Draft{
		Host: row.Host, Target: row.Target, Cert: row.Cert,
		AccessChoice: row.AccessChoice, Roles: normalizeRoles(roles), Note: row.Note,
		ReviewState: row.ReviewState, ReviewReason: row.ReviewReason,
		ReviewCandidates: candidates, ReviewDefault: row.ReviewDefault,
		Routes: []Route{},
	}
	for _, r := range routes {
		b := Backend{Service: r.BackendService}
		if n, err := strconv.Atoi(r.BackendPort); err == nil {
			b.PortNumber = n
		} else {
			b.PortName = r.BackendPort
		}
		d.Routes = append(d.Routes, Route{
			Namespace: r.Namespace, Ingress: r.IngressName, UID: r.IngressUid,
			Host: row.Host, Path: r.Path, PathType: PathType(r.PathType), Backend: b,
		})
	}
	out := SavedDraft{Draft: d, Provenance: Provenance{ProfileVersion: row.ProfileVersion, SnapshotID: row.SnapshotID.Int64}}
	var err error
	if row.ObservedAt != "" {
		if out.Provenance.ObservedAt, err = time.Parse(timeFormat, row.ObservedAt); err != nil {
			return SavedDraft{}, fmt.Errorf("k8s: stored draft observed_at: %w", err)
		}
	}
	if out.CreatedAt, err = time.Parse(timeFormat, row.CreatedAt); err != nil {
		return SavedDraft{}, fmt.Errorf("k8s: stored draft created_at: %w", err)
	}
	if out.UpdatedAt, err = time.Parse(timeFormat, row.UpdatedAt); err != nil {
		return SavedDraft{}, fmt.Errorf("k8s: stored draft updated_at: %w", err)
	}
	return out, nil
}

// RouteDiff is how the stored provenance of a draft differs from the current discovery. Routes are
// matched by their immutable identity (namespace, Ingress UID, path, pathType); a different backend
// under the same identity is Changed.
type RouteDiff struct {
	Added   []Route // in the current discovery, not in the stored draft
	Removed []Route // in the stored draft, no longer discovered
	Changed []Route // same identity, different backend (current value)
}

// Empty reports whether nothing differs.
func (d RouteDiff) Empty() bool { return len(d.Added)+len(d.Removed)+len(d.Changed) == 0 }

// DiffRoutes compares stored route provenance with the current routes of the same host.
func DiffRoutes(stored, current []Route) RouteDiff {
	id := func(r Route) string {
		return r.Namespace + "\x00" + r.UID + "\x00" + r.Path + "\x00" + string(r.PathType)
	}
	storedBy := map[string]Route{}
	for _, r := range stored {
		storedBy[id(r)] = r
	}
	var out RouteDiff
	seen := map[string]bool{}
	for _, r := range current {
		seen[id(r)] = true
		old, ok := storedBy[id(r)]
		switch {
		case !ok:
			out.Added = append(out.Added, r)
		case old.Backend.Service != r.Backend.Service || backendPortText(old.Backend) != backendPortText(r.Backend):
			out.Changed = append(out.Changed, r)
		}
	}
	for _, r := range stored {
		if !seen[id(r)] {
			out.Removed = append(out.Removed, r)
		}
	}
	return out
}
