package health

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/store"
	"github.com/nesiler/tagcess/internal/store/db"
)

func openObsStore(t *testing.T) (*store.Store, *Store) {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "tagcess.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st, NewStore(st.Queries())
}

func testKey() Key {
	return Key{Category: "target", Site: "s1", Host: "app.example.test", Source: SourceNetProbe,
		Vantage: "tagcess-net", Endpoint: "10.20.0.5:443", SNI: "app.example.test", Path: "/"}
}

func getRow(t *testing.T, st *store.Store, k Key) db.Observation {
	t.Helper()
	row, err := st.Queries().GetObservationByKey(context.Background(), db.GetObservationByKeyParams{
		Category: k.Category, Site: k.Site, Host: k.Host, Source: k.Source, Vantage: k.Vantage,
		Endpoint: k.Endpoint, Sni: k.SNI, Path: k.Path,
	})
	if err != nil {
		t.Fatalf("GetObservationByKey: %v", err)
	}
	return row
}

// A delayed older attempt must not roll the row's attempt time back (F4-017 writes are
// last-writer-wins); it is skipped and the newer evidence stays.
func TestStoreSkipsStaleAttempt(t *testing.T) {
	ctx := context.Background()
	st, s := openObsStore(t)
	k := testKey()
	t0 := time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)

	if _, err := s.RecordGood(ctx, k, t0.Add(time.Minute), Good{HTTPStatus: 200}); err != nil {
		t.Fatalf("RecordGood: %v", err)
	}
	rec, err := s.RecordFailed(ctx, k, t0, Failure{Result: "timeout", Error: "late"})
	if err != nil {
		t.Fatalf("RecordFailed: %v", err)
	}
	if !rec.Skipped {
		t.Fatalf("an older failed attempt was written, want skipped: %+v", rec)
	}
	rec, err = s.RecordGood(ctx, k, t0.Add(30*time.Second), Good{HTTPStatus: 204})
	if err != nil || !rec.Skipped {
		t.Fatalf("an older good attempt: rec=%+v err=%v, want skipped", rec, err)
	}
	row := getRow(t, st, k)
	if row.LastAttemptAt != formatTime(t0.Add(time.Minute)) || row.HttpStatus != 200 || row.LastResult != "ok" || row.Success != 1 {
		t.Fatalf("row was changed by a stale attempt: %+v", row)
	}
	// A newer attempt still writes.
	rec, err = s.RecordFailed(ctx, k, t0.Add(2*time.Minute), Failure{Result: "timeout", Error: "later"})
	if err != nil || rec.Skipped || rec.Freshness != FreshnessStale || !rec.LastGoodAt.Equal(t0.Add(time.Minute)) {
		t.Fatalf("a newer failed attempt: rec=%+v err=%v", rec, err)
	}
}

func TestStoreRejectsOkAsFailureLabel(t *testing.T) {
	_, s := openObsStore(t)
	for _, label := range []string{"", "ok"} {
		if _, err := s.RecordFailed(context.Background(), testKey(), time.Now(), Failure{Result: label}); err == nil {
			t.Errorf("failure label %q was accepted", label)
		}
	}
}

// failingObs is an observation store whose every call fails.
type failingObs struct{ err error }

func (f failingObs) UpsertObservationGood(context.Context, db.UpsertObservationGoodParams) (db.Observation, error) {
	return db.Observation{}, f.err
}

func (f failingObs) UpsertObservationFailed(context.Context, db.UpsertObservationFailedParams) (db.Observation, error) {
	return db.Observation{}, f.err
}

func (f failingObs) GetObservationByKey(context.Context, db.GetObservationByKeyParams) (db.Observation, error) {
	return db.Observation{}, f.err
}

func (f failingObs) ListProbeObservationsByVantage(context.Context, string) ([]db.Observation, error) {
	return nil, f.err
}

func (f failingObs) DeleteObservation(context.Context, int64) (int64, error) { return 0, f.err }

// A read error while checking for a newer attempt writes nothing; a missing row is not an error.
func TestStoreReadErrorWritesNothing(t *testing.T) {
	boom := errors.New("disk full")
	s := NewStore(failingObs{err: boom})
	if _, err := s.RecordGood(context.Background(), testKey(), time.Now(), Good{HTTPStatus: 200}); !errors.Is(err, boom) {
		t.Fatalf("RecordGood err = %v, want the store error", err)
	}
	if _, err := s.RecordFailed(context.Background(), testKey(), time.Now(), Failure{Result: "timeout"}); !errors.Is(err, boom) {
		t.Fatalf("RecordFailed err = %v, want the store error", err)
	}
}
