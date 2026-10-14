package health

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/nesiler/tagcess/internal/store/db"
)

// Observations is the part of the F4-017 store the runner writes; *db.Queries satisfies it.
type Observations interface {
	GateObservations
	GetObservationByKey(ctx context.Context, arg db.GetObservationByKeyParams) (db.Observation, error)
	ListProbeObservationsByVantage(ctx context.Context, vantage string) ([]db.Observation, error)
	DeleteObservation(ctx context.Context, id int64) (int64, error)
}

// Key is one measurement row of the F4-017 store: category (target, caddy_gate, tls), subject,
// source, vantage, dialled endpoint, SNI and path. The route part is unused here.
type Key struct {
	Category, Site, Host, Source, Vantage, Endpoint, SNI, Path string
}

// Good is the evidence of an attempt that met its category's expectation.
type Good struct {
	HTTPStatus  int
	GateClass   string
	TLSNotAfter time.Time // zero unless a verified leaf was read
	TLSFinger   string
}

// Failure is an attempt that did not. Result is a class label, never "ok" or empty; Error is a
// fixed, sanitized text. The TLS fields hold the diagnostic leaf of an unverifiable certificate.
type Failure struct {
	Result      string
	HTTPStatus  int
	Error       string
	TLSNotAfter time.Time
	TLSFinger   string
	TLSVerify   string
}

// Recorded says what a write did. Skipped means a newer attempt was already stored and this one
// was dropped; Freshness and LastGoodAt then describe the stored row.
type Recorded struct {
	Freshness  Freshness
	LastGoodAt time.Time // zero when no good observation is stored
	Skipped    bool
}

// Store writes runner attempts to the observation store. F4-017 upserts are last-writer-wins with
// no time comparison, so a delayed older attempt could roll the attempt time back; Store therefore
// serializes writes and drops an attempt older than the stored one.
type Store struct {
	q  Observations
	mu sync.Mutex
}

// NewStore returns a Store over the observation queries.
func NewStore(q Observations) *Store { return &Store{q: q} }

// RecordGood stores an attempt that met the expectation: both the last-good and attempt groups.
func (s *Store) RecordGood(ctx context.Context, k Key, at time.Time, g Good) (Recorded, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rec, skip, err := s.newer(ctx, k, at); err != nil || skip {
		return rec, err
	}
	ts := formatTime(at)
	p := db.UpsertObservationGoodParams{
		Category: k.Category, Site: k.Site, Host: k.Host, Source: k.Source, Vantage: k.Vantage,
		Endpoint: k.Endpoint, Sni: k.SNI, Path: k.Path,
		ObservedAt: ts, HttpStatus: int64(g.HTTPStatus), GateClass: g.GateClass, TlsFingerprint: g.TLSFinger,
		LastAttemptAt: ts,
	}
	if !g.TLSNotAfter.IsZero() {
		p.TlsNotAfter = formatTime(g.TLSNotAfter)
	}
	if _, err := s.q.UpsertObservationGood(ctx, p); err != nil {
		return Recorded{}, err
	}
	return Recorded{Freshness: FreshnessFresh, LastGoodAt: at}, nil
}

// RecordFailed stores only the attempt group; the last good evidence is never touched.
func (s *Store) RecordFailed(ctx context.Context, k Key, at time.Time, f Failure) (Recorded, error) {
	if f.Result == "" || f.Result == "ok" {
		return Recorded{}, errors.New("health: a failed attempt needs a failure class label")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if rec, skip, err := s.newer(ctx, k, at); err != nil || skip {
		return rec, err
	}
	p := db.UpsertObservationFailedParams{
		Category: k.Category, Site: k.Site, Host: k.Host, Source: k.Source, Vantage: k.Vantage,
		Endpoint: k.Endpoint, Sni: k.SNI, Path: k.Path,
		LastAttemptAt: formatTime(at), LastResult: f.Result, LastHttpStatus: int64(f.HTTPStatus), LastError: f.Error,
		LastTlsFingerprint: f.TLSFinger, LastTlsVerifyError: f.TLSVerify,
	}
	if !f.TLSNotAfter.IsZero() {
		p.LastTlsNotAfter = formatTime(f.TLSNotAfter)
	}
	row, err := s.q.UpsertObservationFailed(ctx, p)
	if err != nil {
		return Recorded{}, err
	}
	return staleOf(row), nil
}

// Prune deletes the probe rows (target, Caddy gate, TLS) of one vantage whose key is not in keep and
// whose category is in categories. It is the runner's cleanup of keys it no longer measures; rows of
// other vantages and sources are never touched. The caller must pass the complete key set of a
// completed cycle.
func (s *Store) Prune(ctx context.Context, vantage string, categories []string, keep map[Key]bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.q.ListProbeObservationsByVantage(ctx, vantage)
	if err != nil {
		return err
	}
	var errs []error
	for _, r := range rows {
		if !slices.Contains(categories, r.Category) || r.Route != "" {
			continue
		}
		k := Key{Category: r.Category, Site: r.Site, Host: r.Host, Source: r.Source, Vantage: r.Vantage,
			Endpoint: r.Endpoint, SNI: r.Sni, Path: r.Path}
		if keep[k] {
			continue
		}
		if _, err := s.q.DeleteObservation(ctx, r.ID); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// newer reports whether the stored row already has a later attempt than at. A missing row is not.
func (s *Store) newer(ctx context.Context, k Key, at time.Time) (Recorded, bool, error) {
	row, err := s.q.GetObservationByKey(ctx, db.GetObservationByKeyParams{
		Category: k.Category, Site: k.Site, Host: k.Host, Source: k.Source, Vantage: k.Vantage,
		Endpoint: k.Endpoint, Sni: k.SNI, Path: k.Path,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return Recorded{}, false, nil
	}
	if err != nil {
		return Recorded{}, false, err
	}
	if row.LastAttemptAt > formatTime(at) { // fixed-width UTC text: string order is time order
		rec := staleOf(row)
		if row.Success == 1 {
			rec.Freshness = FreshnessFresh
		}
		rec.Skipped = true
		return rec, true, nil
	}
	return Recorded{}, false, nil
}

// staleOf reads the freshness a failed attempt leaves: stale when a good observation exists.
func staleOf(row db.Observation) Recorded {
	if row.ObservedAt == "" {
		return Recorded{Freshness: FreshnessNone}
	}
	good, err := time.Parse(timeFormat, row.ObservedAt)
	if err != nil {
		return Recorded{Freshness: FreshnessNone}
	}
	return Recorded{Freshness: FreshnessStale, LastGoodAt: good}
}
