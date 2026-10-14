package maintenance

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/store"
)

var t0 = time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)

// fakeClock is a settable clock for the service under test.
type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time { return c.now }

func openService(t *testing.T, path string) (*Service, *fakeClock, *store.Store) {
	t.Helper()
	s, err := store.Open(context.Background(), path)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	clk := &fakeClock{now: t0}
	svc := New(s.Queries())
	svc.clock = clk.Now
	return svc, clk, s
}

func newService(t *testing.T) (*Service, *fakeClock, *store.Store) {
	t.Helper()
	return openService(t, filepath.Join(t.TempDir(), "tagcess.db"))
}

const (
	resApplying    = `{"status":"applying","stage":"replace"}`
	resFailed      = `{"status":"failed","stage":"health","code":"health_failed"}`
	resInterrupted = `{"status":"interrupted"}`
	resSucceeded   = `{"status":"succeeded"}`
)

// into drives a fresh service into the wanted state through valid transitions only.
func into(t *testing.T, svc *Service, state State, hostResult string) {
	t.Helper()
	ctx := context.Background()
	if state == Off {
		return
	}
	if _, err := svc.Start(ctx, "req-1", "devops@example.com"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if hostResult != "" {
		if err := svc.SetHostResult(ctx, "req-1", hostResult); err != nil {
			t.Fatalf("SetHostResult: %v", err)
		}
	}
	if state == ReconcilePending {
		if _, err := svc.ToReconcilePending(ctx, "req-1"); err != nil {
			t.Fatalf("ToReconcilePending: %v", err)
		}
	}
}

func mustGet(t *testing.T, svc *Service) Status {
	t.Helper()
	st, err := svc.Get(context.Background())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	return st
}

// AC1: the migration creates the row as off, and the state survives a reopen.
func TestMaintenance_PersistsAcrossRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "tagcess.db")

	svc, clk, s := openService(t, path)
	st := mustGet(t, svc)
	if st.State != Off || st.RequestID != "" || st.PendingReconcile {
		t.Fatalf("fresh status = %+v, want off and empty", st)
	}

	if _, err := svc.Start(ctx, "req-1", "devops@example.com"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := svc.SetHostResult(ctx, "req-1", resFailed); err != nil {
		t.Fatalf("SetHostResult: %v", err)
	}
	if err := svc.MarkPendingReconcile(ctx); err != nil {
		t.Fatalf("MarkPendingReconcile: %v", err)
	}
	before := mustGet(t, svc)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Reopen: migrations run again and must not reset the row.
	svc2, clk2, _ := openService(t, path)
	clk2.now = clk.now
	after := mustGet(t, svc2)
	if after != before {
		t.Fatalf("status after reopen = %+v, want %+v", after, before)
	}
	if after.State != Active || after.RequestID != "req-1" || after.Actor != "devops@example.com" ||
		after.LastHostResult != resFailed || !after.PendingReconcile {
		t.Errorf("reopened status lost fields: %+v", after)
	}
}

// AC2: only off→active, active→active (new ID, terminal host result), active→reconcile_pending and
// reconcile_pending→off are allowed.
func TestMaintenance_Transitions(t *testing.T) {
	ctx := context.Background()
	states := []struct {
		name   string
		state  State
		result string
	}{
		{"off", Off, ""},
		{"active, no host result yet", Active, ""},
		{"active, applying", Active, resApplying},
		{"active, failed", Active, resFailed},
		{"active, interrupted", Active, resInterrupted},
		{"active, succeeded", Active, resSucceeded},
		{"reconcile_pending", ReconcilePending, resSucceeded},
	}
	moves := []struct {
		name string
		do   func(svc *Service) error
		// allowed lists the state names (by states[].name) the move is allowed from.
		allowed map[string]State // value: the state after the move
	}{
		{
			name: "start (off→active)",
			do: func(svc *Service) error {
				_, err := svc.Start(ctx, "req-2", "devops@example.com")
				return err
			},
			allowed: map[string]State{"off": Active},
		},
		{
			name: "renew (active→active, new ID)",
			do: func(svc *Service) error {
				_, err := svc.Renew(ctx, "req-2", "devops@example.com")
				return err
			},
			allowed: map[string]State{
				"active, failed":      Active,
				"active, interrupted": Active,
				"active, succeeded":   Active,
			},
		},
		{
			name: "to reconcile_pending",
			do: func(svc *Service) error {
				_, err := svc.ToReconcilePending(ctx, "req-1")
				return err
			},
			allowed: map[string]State{
				"active, no host result yet": ReconcilePending,
				"active, applying":           ReconcilePending,
				"active, failed":             ReconcilePending,
				"active, interrupted":        ReconcilePending,
				"active, succeeded":          ReconcilePending,
			},
		},
		{
			name:    "off (reconcile_pending→off)",
			do:      func(svc *Service) error { return svc.Off(ctx, "") },
			allowed: map[string]State{"reconcile_pending": Off},
		},
	}

	for _, mv := range moves {
		for _, from := range states {
			t.Run(mv.name+" from "+from.name, func(t *testing.T) {
				svc, _, _ := newService(t)
				into(t, svc, from.state, from.result)
				before := mustGet(t, svc)

				err := mv.do(svc)
				after := mustGet(t, svc)
				want, ok := mv.allowed[from.name]
				if ok {
					if err != nil {
						t.Fatalf("move refused: %v", err)
					}
					if after.State != want {
						t.Errorf("state = %s, want %s", after.State, want)
					}
					return
				}
				if !errors.Is(err, ErrInvalidTransition) {
					t.Fatalf("err = %v, want ErrInvalidTransition", err)
				}
				if after != before {
					t.Errorf("refused move changed the row: %+v -> %+v", before, after)
				}
			})
		}
	}
}

// A renew replaces the request ID and clears the old host result, but the maintenance keeps its
// start time; a stale or wrong request ID never moves the state.
func TestMaintenance_RenewAndStaleIDs(t *testing.T) {
	ctx := context.Background()
	svc, clk, _ := newService(t)
	into(t, svc, Active, resFailed)
	clk.now = t0.Add(10 * time.Minute)

	st, err := svc.Renew(ctx, "req-2", "other@example.com")
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if st.RequestID != "req-2" || st.Actor != "other@example.com" || st.LastHostResult != "" {
		t.Errorf("renewed status = %+v", st)
	}
	if !st.StartedAt.Equal(t0) || !st.UpdatedAt.Equal(clk.now) {
		t.Errorf("started %v updated %v, want %v / %v", st.StartedAt, st.UpdatedAt, t0, clk.now)
	}

	// The close confirmed for the old ID must not close the renewed maintenance.
	if _, err := svc.ToReconcilePending(ctx, "req-1"); !errors.Is(err, ErrInvalidTransition) {
		t.Errorf("ToReconcilePending(old id) = %v, want ErrInvalidTransition", err)
	}
	if err := svc.SetHostResult(ctx, "req-1", resSucceeded); !errors.Is(err, ErrInvalidTransition) {
		t.Errorf("SetHostResult(old id) = %v, want ErrInvalidTransition", err)
	}
	if got := mustGet(t, svc); got.State != Active || got.LastHostResult != "" {
		t.Errorf("stale calls changed the row: %+v", got)
	}

	// Renew needs an actor and a request ID.
	into2, _, _ := newService(t)
	if _, err := into2.Start(ctx, "", "devops@example.com"); err == nil {
		t.Error("Start with empty request ID succeeded")
	}
	if _, err := into2.Start(ctx, "req-1", " "); err == nil {
		t.Error("Start with empty actor succeeded")
	}
}

// Closing records the note and clears the request, and the reconcile intent goes with it.
func TestMaintenance_OffClearsRequest(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newService(t)
	into(t, svc, ReconcilePending, resSucceeded)
	if err := svc.MarkPendingReconcile(ctx); err != nil {
		t.Fatalf("MarkPendingReconcile: %v", err)
	}
	if err := svc.Off(ctx, "dry_run_skipped"); err != nil {
		t.Fatalf("Off: %v", err)
	}
	st := mustGet(t, svc)
	if st.State != Off || st.RequestID != "" || st.Actor != "" || st.LastHostResult != "" ||
		st.PendingReconcile || !st.StartedAt.IsZero() || st.CloseNote != "dry_run_skipped" {
		t.Errorf("status after off = %+v", st)
	}

	// The next maintenance starts clean: the note belongs to the closed one.
	if _, err := svc.Start(ctx, "req-9", "devops@example.com"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if got := mustGet(t, svc); got.CloseNote != "" {
		t.Errorf("close note after new start = %q, want empty", got.CloseNote)
	}
}

// MarkPendingReconcile only records the intent while a maintenance is open.
func TestMaintenance_MarkPendingReconcile(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newService(t)
	if err := svc.MarkPendingReconcile(ctx); err != nil {
		t.Fatalf("MarkPendingReconcile while off: %v", err)
	}
	if mustGet(t, svc).PendingReconcile {
		t.Error("intent recorded while off")
	}
	into(t, svc, Active, "")
	if err := svc.MarkPendingReconcile(ctx); err != nil {
		t.Fatalf("MarkPendingReconcile: %v", err)
	}
	if !mustGet(t, svc).PendingReconcile {
		t.Error("intent not recorded while active")
	}
}

// AC3: the gate decides by state and source.
func TestMaintenance_CheckWidening(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name   string
		state  State
		source string
		allow  bool
	}{
		{"off admin", Off, "admin", true},
		{"off sync", Off, "sync", true},
		{"off ui", Off, "ui", true},
		{"active admin", Active, "admin", false},
		{"active sync", Active, "sync", false},
		{"active ui", Active, "ui", false},
		{"reconcile_pending admin", ReconcilePending, "admin", false},
		{"reconcile_pending ui", ReconcilePending, "ui", false},
		{"reconcile_pending sync", ReconcilePending, "sync", true},
		{"reconcile_pending unknown source", ReconcilePending, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, _, _ := newService(t)
			into(t, svc, tc.state, "")
			err := svc.CheckWidening(ctx, tc.source)
			switch {
			case tc.allow && err != nil:
				t.Errorf("CheckWidening = %v, want nil", err)
			case !tc.allow && !errors.Is(err, ErrMaintenance):
				t.Errorf("CheckWidening = %v, want ErrMaintenance", err)
			}
		})
	}
}

// AC4: a state that cannot be read refuses widening.
func TestMaintenance_UnreadableFailsClosed(t *testing.T) {
	ctx := context.Background()
	svc, _, s := newService(t)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	for _, source := range []string{"admin", "sync", "ui"} {
		if err := svc.CheckWidening(ctx, source); !errors.Is(err, ErrMaintenance) {
			t.Errorf("CheckWidening(%q) on unreadable state = %v, want ErrMaintenance", source, err)
		}
	}
	if _, err := svc.Get(ctx); err == nil {
		t.Error("Get on a closed database succeeded")
	}
}

// AC5: the start time and the elapsed time are returned for the UI band.
func TestMaintenance_Duration(t *testing.T) {
	ctx := context.Background()
	svc, clk, _ := newService(t)

	if st := mustGet(t, svc); st.Elapsed != 0 || !st.StartedAt.IsZero() {
		t.Errorf("off status has a duration: %+v", st)
	}

	st, err := svc.Start(ctx, "req-1", "devops@example.com")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !st.StartedAt.Equal(t0) || st.Elapsed != 0 {
		t.Errorf("start returned %v / %v, want %v / 0", st.StartedAt, st.Elapsed, t0)
	}

	clk.now = t0.Add(90 * time.Second)
	if st := mustGet(t, svc); !st.StartedAt.Equal(t0) || st.Elapsed != 90*time.Second {
		t.Errorf("after 90s: started %v elapsed %v", st.StartedAt, st.Elapsed)
	}

	// A renew keeps counting from the first start; a clock that went backwards never gives a
	// negative duration.
	if err := svc.SetHostResult(ctx, "req-1", resFailed); err != nil {
		t.Fatalf("SetHostResult: %v", err)
	}
	clk.now = t0.Add(5 * time.Minute)
	if _, err := svc.Renew(ctx, "req-2", "devops@example.com"); err != nil {
		t.Fatalf("Renew: %v", err)
	}
	clk.now = t0.Add(7 * time.Minute)
	if st := mustGet(t, svc); st.Elapsed != 7*time.Minute {
		t.Errorf("elapsed after renew = %v, want 7m", st.Elapsed)
	}
	clk.now = t0.Add(-time.Hour)
	if st := mustGet(t, svc); st.Elapsed != 0 {
		t.Errorf("elapsed with a backwards clock = %v, want 0", st.Elapsed)
	}
}
