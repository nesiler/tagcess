package alert

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/monitor"
	"github.com/nesiler/tagcess/internal/store"
)

// testBaseTime is the fixed instant every fake clock starts from.
var testBaseTime = time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)

// fakeClock is a manually advanced service clock; tests never sleep.
type fakeClock struct{ t time.Time }

func newFakeClock(t time.Time) *fakeClock { return &fakeClock{t: t} }

func (c *fakeClock) now() time.Time { return c.t }

// advance moves the clock forward so timestamp assertions can tell the samples apart.
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

// openService opens a fresh real SQLite database with the alert service and the typed settings
// store over it (F4-024 defaults) and returns the database path for restart tests.
func openService(t *testing.T) (*Service, *store.Store, *monitor.SettingsStore, string) {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "tagcess.db")
	st, err := store.Open(ctx, path)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	settings := monitor.NewSettingsStore(st.DB(), st.Queries())
	return New(NewStore(st.DB(), st.Queries()), settings), st, settings, path
}

// reopenService closes st and opens the same path again, proving persistence across a restart.
func reopenService(t *testing.T, st *store.Store, path string) (*Service, *store.Store) {
	t.Helper()
	ctx := context.Background()
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	reopened, err := store.Open(ctx, path)
	if err != nil {
		t.Fatalf("reopen store.Open: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	settings := monitor.NewSettingsStore(reopened.DB(), reopened.Queries())
	return New(NewStore(reopened.DB(), reopened.Queries()), settings), reopened
}

// tableCounts snapshots the row count of every application table, so a test can prove the service
// wrote nowhere but the alerts table (dashboard-only, no external notification record).
func tableCounts(t *testing.T, st *store.Store) map[string]int {
	t.Helper()
	ctx := context.Background()
	rows, err := st.DB().QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan table: %v", err)
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("table rows: %v", err)
	}
	counts := make(map[string]int, len(names))
	for _, name := range names {
		var n int
		if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM `+name).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", name, err)
		}
		counts[name] = n
	}
	return counts
}

// Positive control for tableCounts: a write to a table other than alerts must change the snapshot,
// otherwise the "dashboard-only" proof in TestAlertRestartDedupAndDashboardOnly could not fail.
func TestTableCountsDetectsWrites(t *testing.T) {
	ctx := context.Background()
	_, st, _, _ := openService(t)
	before := tableCounts(t, st)
	if _, err := st.DB().ExecContext(ctx,
		`INSERT INTO settings (key, value, updated_at) VALUES ('control.probe', '1', '2026-10-04T12:00:00.000Z')`); err != nil {
		t.Fatalf("insert control row: %v", err)
	}
	after := tableCounts(t, st)
	if after["settings"] != before["settings"]+1 {
		t.Fatalf("settings count %d -> %d, want +1: tableCounts cannot see writes", before["settings"], after["settings"])
	}
}
