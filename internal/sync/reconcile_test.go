package sync

import (
	"context"
	"errors"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/headscale"
	"github.com/nesiler/tagcess/internal/maintenance"
	"github.com/nesiler/tagcess/internal/render"
	"github.com/nesiler/tagcess/internal/store"
	"github.com/nesiler/tagcess/internal/zitadel"
)

// fakeZitadelReader is the read-only Zitadel surface the orchestrator uses.
type fakeZitadelReader struct {
	mu        sync.Mutex
	grants    []zitadel.Grant
	states    map[string]zitadel.UserState
	grantsErr error
	statesErr error
	askedIDs  []string
}

func (f *fakeZitadelReader) ListGrants(context.Context) ([]zitadel.Grant, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.grantsErr != nil {
		return nil, f.grantsErr
	}
	return f.grants, nil
}

func (f *fakeZitadelReader) UserStates(_ context.Context, ids []string) (map[string]zitadel.UserState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.askedIDs = append([]string(nil), ids...)
	if f.statesErr != nil {
		return nil, f.statesErr
	}
	out := map[string]zitadel.UserState{}
	for _, id := range ids {
		if st, ok := f.states[id]; ok {
			out[id] = st
		}
	}
	return out, nil
}

// fakeHeadscale is both the read surface (ListUsers/ListNodes/GetPolicy) and the write surface the
// change pipeline needs (CheckPolicy/SetPolicy/ExpireNode).
type fakeHeadscale struct {
	mu        sync.Mutex
	policy    string
	users     []headscale.User
	nodes     []headscale.Node
	policyErr error
	usersErr  error
	nodesErr  error

	checkErr  error
	setErr    error
	expireErr map[uint64]error
	setCalls  []string
	expired   []uint64
}

func newFakeHeadscale(policy string) *fakeHeadscale {
	return &fakeHeadscale{policy: policy, expireErr: map[uint64]error{}}
}

func (f *fakeHeadscale) GetPolicy(context.Context) (headscale.Policy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.policyErr != nil {
		return headscale.Policy{}, f.policyErr
	}
	return headscale.Policy{Text: f.policy}, nil
}

func (f *fakeHeadscale) ListUsers(context.Context) ([]headscale.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.usersErr != nil {
		return nil, f.usersErr
	}
	return f.users, nil
}

func (f *fakeHeadscale) ListNodes(context.Context) ([]headscale.Node, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.nodesErr != nil {
		return nil, f.nodesErr
	}
	return f.nodes, nil
}

func (f *fakeHeadscale) CheckPolicy(context.Context, string) error { return f.checkErr }

func (f *fakeHeadscale) SetPolicy(_ context.Context, policy string) (headscale.Policy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setCalls = append(f.setCalls, policy)
	if f.setErr != nil {
		return headscale.Policy{}, f.setErr
	}
	f.policy = policy
	return headscale.Policy{Text: policy}, nil
}

func (f *fakeHeadscale) ExpireNode(_ context.Context, id uint64) (headscale.Node, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.expireErr[id]; err != nil {
		return headscale.Node{}, err
	}
	f.expired = append(f.expired, id)
	return headscale.Node{ID: id}, nil
}

func (f *fakeHeadscale) SetCalls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.setCalls...)
}

func (f *fakeHeadscale) Expired() []uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]uint64(nil), f.expired...)
}

func (f *fakeHeadscale) Policy() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.policy
}

func setDryRun(t *testing.T, s *store.Store, on bool) {
	t.Helper()
	if _, err := s.DB().ExecContext(context.Background(),
		`UPDATE settings SET value = ? WHERE key = 'dry_run'`, strconv.FormatBool(on)); err != nil {
		t.Fatalf("set dry_run: %v", err)
	}
}

func count(t *testing.T, s *store.Store, query string, args ...any) int {
	t.Helper()
	var n int
	if err := s.DB().QueryRowContext(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("count %q: %v", query, err)
	}
	return n
}

func newTestReconciler(t *testing.T) (*Reconciler, *fakeZitadelReader, *fakeHeadscale, *store.Store) {
	t.Helper()
	s, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "tagcess.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	z := &fakeZitadelReader{
		grants: []zitadel.Grant{{UserID: "1", Role: "dev"}},
		states: map[string]zitadel.UserState{"1": zitadel.UserActive},
	}
	hs := newFakeHeadscale(`{"acls":[],"groups":{"group:dev":[]}}`)
	// Only role holders with a Headscale user enter a group (F3-031).
	hs.users = []headscale.User{{ID: 11, ProviderID: issuer + "/1"}}
	pipe := change.New(hs, s.Queries(), audit.New(s.Queries()), s)
	r, err := NewReconciler(ReconcilerConfig{
		Zitadel:   z,
		Headscale: hs,
		Pipeline:  pipe,
		Queries:   s.Queries(),
		DryRun:    s,
		Issuer:    issuer,
	})
	if err != nil {
		t.Fatalf("NewReconciler: %v", err)
	}
	setDryRun(t, s, false)
	return r, z, hs, s
}

// AC1: reconcile reads both systems, gives the plan to the change pipeline and the run is recorded
// in sync_runs with its trigger, result and diff summary.
func TestReconcile_EndToEndWithFakes(t *testing.T) {
	ctx := context.Background()
	r, _, hs, s := newTestReconciler(t)

	res, err := r.Run(ctx, "manual")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Change.Applied || res.Status != change.StatusApplied {
		t.Fatalf("result = %+v, want applied", res)
	}
	if len(hs.SetCalls()) != 1 {
		t.Fatalf("SetPolicy calls = %v, want 1", hs.SetCalls())
	}
	groups := groupsOf(t, []byte(hs.Policy()))
	if got := groups["group:dev"]; len(got) != 1 || got[0] != member("1") {
		t.Fatalf("group:dev = %v, want [%s]", got, member("1"))
	}
	if n := count(t, s, `SELECT count(*) FROM sync_runs WHERE trigger = 'manual' AND result = 'applied' AND diff_summary <> ''`); n != 1 {
		t.Errorf("applied sync_runs = %d, want 1", n)
	}
	if n := count(t, s, `SELECT count(*) FROM alerts`); n != 0 {
		t.Errorf("alerts = %d, want 0", n)
	}
}

// AC2: a read failure means nothing is applied and the failing system's alert is raised.
func TestReconcile_ReadErrorRaisesAlert(t *testing.T) {
	tests := []struct {
		name   string
		mut    func(*fakeZitadelReader, *fakeHeadscale)
		source string
	}{
		{"zitadel grants", func(z *fakeZitadelReader, _ *fakeHeadscale) { z.grantsErr = errors.New("boom") }, SourceZitadel},
		{"zitadel states", func(z *fakeZitadelReader, _ *fakeHeadscale) { z.statesErr = errors.New("boom") }, SourceZitadel},
		{"headscale", func(_ *fakeZitadelReader, hs *fakeHeadscale) { hs.policyErr = errors.New("boom") }, SourceHeadscale},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			r, z, hs, s := newTestReconciler(t)
			tt.mut(z, hs)

			res, err := r.Run(ctx, "periodic")
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if res.Status != ResultReadFailed {
				t.Fatalf("status = %q, want %q", res.Status, ResultReadFailed)
			}
			if len(hs.SetCalls()) != 0 {
				t.Fatalf("a failed read still wrote to Headscale: %v", hs.SetCalls())
			}
			if n := count(t, s, `SELECT count(*) FROM alerts WHERE kind = ? AND source = ? AND resolved_at IS NULL`,
				AlertReadFailed, tt.source); n != 1 {
				t.Errorf("open %s alerts = %d, want 1", tt.source, n)
			}
			if n := count(t, s, `SELECT count(*) FROM sync_runs WHERE result = ?`, ResultReadFailed); n != 1 {
				t.Errorf("read-failed sync_runs = %d, want 1", n)
			}
		})
	}
}

// A repeated read failure updates the open alert instead of piling up a new row (dedupe).
func TestReconcile_ReadErrorDedupes(t *testing.T) {
	ctx := context.Background()
	r, z, _, s := newTestReconciler(t)
	z.grantsErr = errors.New("boom")

	base := now
	clock := func() time.Time { return base }
	r.clock = clock

	if _, err := r.Run(ctx, "periodic"); err != nil {
		t.Fatalf("first Run: %v", err)
	}
	base = now.Add(time.Minute)
	if _, err := r.Run(ctx, "periodic"); err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if n := count(t, s, `SELECT count(*) FROM alerts WHERE kind = ?`, AlertReadFailed); n != 1 {
		t.Fatalf("alert rows = %d, want 1 (dedupe)", n)
	}
	var first, last string
	if err := s.DB().QueryRowContext(ctx, `SELECT first_seen_at, last_seen_at FROM alerts`).Scan(&first, &last); err != nil {
		t.Fatal(err)
	}
	if first == last {
		t.Errorf("last_seen_at was not updated: first=%q last=%q", first, last)
	}
}

// AC3: when the problem goes away the alert is marked resolved.
func TestReconcile_AlertResolves(t *testing.T) {
	ctx := context.Background()
	r, z, hs, s := newTestReconciler(t)
	z.grantsErr = errors.New("boom")
	if _, err := r.Run(ctx, "periodic"); err != nil {
		t.Fatalf("first Run: %v", err)
	}
	if n := count(t, s, `SELECT count(*) FROM alerts WHERE resolved_at IS NULL`); n != 1 {
		t.Fatalf("open alerts = %d, want 1", n)
	}

	z.grantsErr = nil
	// Second run: the read is healthy and there is nothing to change.
	hs.policy = `{"acls":[],"groups":{"group:dev":["` + member("1") + `"]}}`
	res, err := r.Run(ctx, "periodic")
	if err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if res.Status != ResultNoChange {
		t.Fatalf("status = %q, want %q", res.Status, ResultNoChange)
	}
	if n := count(t, s, `SELECT count(*) FROM alerts WHERE resolved_at IS NOT NULL`); n != 1 {
		t.Errorf("resolved alerts = %d, want 1", n)
	}
	if n := count(t, s, `SELECT count(*) FROM alerts WHERE resolved_at IS NULL`); n != 0 {
		t.Errorf("open alerts = %d, want 0", n)
	}
}

// A run with nothing to do records sync_runs and never reaches the change pipeline.
func TestReconcile_NoChange(t *testing.T) {
	ctx := context.Background()
	r, _, hs, s := newTestReconciler(t)
	hs.policy = `{"acls":[],"groups":{"group:dev":["` + member("1") + `"]}}`

	res, err := r.Run(ctx, "periodic")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Status != ResultNoChange {
		t.Fatalf("status = %q, want %q", res.Status, ResultNoChange)
	}
	if len(hs.SetCalls()) != 0 {
		t.Fatalf("a no-change run wrote to Headscale: %v", hs.SetCalls())
	}
	if n := count(t, s, `SELECT count(*) FROM sync_runs WHERE result = ?`, ResultNoChange); n != 1 {
		t.Errorf("no-change sync_runs = %d, want 1", n)
	}
}

// An untagged node of a user who lost every role is expired through the whole orchestrator.
func TestReconcile_ExpiresNodeOwnerWithoutRoles(t *testing.T) {
	ctx := context.Background()
	r, z, hs, s := newTestReconciler(t)
	z.grants = []zitadel.Grant{
		{UserID: "1", Role: "dev"}, {UserID: "2", Role: "dev"},
		{UserID: "3", Role: "dev"}, {UserID: "4", Role: "dev"},
	}
	z.states = map[string]zitadel.UserState{}
	for _, id := range []string{"1", "2", "3", "4", "5"} {
		z.states[id] = zitadel.UserActive
	}
	hs.policy = `{"acls":[],"groups":{"group:dev":["` + member("1") + `","` + member("2") + `","` + member("3") + `","` + member("4") + `"]}}`
	for i, id := range []string{"1", "2", "3", "4", "5"} {
		hs.users = append(hs.users, headscale.User{ID: uint64(11 + i), ProviderID: issuer + "/" + id})
	}
	hs.nodes = []headscale.Node{{ID: 100, UserID: 15}}

	res, err := r.Run(ctx, "periodic")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Change.Applied || res.Status != change.StatusApplied {
		t.Fatalf("result = %+v, want applied", res)
	}
	if got := hs.Expired(); len(got) != 1 || got[0] != 100 {
		t.Fatalf("expired = %v, want [100]", got)
	}
	if n := count(t, s, `SELECT count(*) FROM sync_runs WHERE result = 'applied'`); n != 1 {
		t.Errorf("applied sync_runs = %d, want 1", n)
	}
}

// A clean apply clears the critical alert an earlier failed apply raised (here: a retried node
// expiry): the alert must not stay open once the problem is gone.
func TestReconcile_ResolvesApplyAlerts(t *testing.T) {
	ctx := context.Background()
	r, z, hs, s := newTestReconciler(t)
	z.grants = []zitadel.Grant{
		{UserID: "1", Role: "dev"}, {UserID: "2", Role: "dev"},
		{UserID: "3", Role: "dev"}, {UserID: "4", Role: "dev"},
	}
	z.states = map[string]zitadel.UserState{}
	for _, id := range []string{"1", "2", "3", "4", "5"} {
		z.states[id] = zitadel.UserActive
	}
	hs.policy = `{"acls":[],"groups":{"group:dev":["` + member("1") + `","` + member("2") + `","` + member("3") + `","` + member("4") + `"]}}`
	for i, id := range []string{"1", "2", "3", "4", "5"} {
		hs.users = append(hs.users, headscale.User{ID: uint64(11 + i), ProviderID: issuer + "/" + id})
	}
	hs.nodes = []headscale.Node{{ID: 100, UserID: 15}}
	hs.expireErr[100] = errors.New("headscale down")

	first, err := r.Run(ctx, "periodic")
	if err != nil {
		t.Fatalf("first Run: %v", err)
	}
	if first.Change.Applied {
		t.Fatal("the first run should fail on the node expiry")
	}
	if n := count(t, s, `SELECT count(*) FROM alerts WHERE kind = ? AND resolved_at IS NULL`, change.AlertPolicyExpireFailed); n != 1 {
		t.Fatalf("open %s alerts = %d, want 1", change.AlertPolicyExpireFailed, n)
	}

	delete(hs.expireErr, 100)
	second, err := r.Run(ctx, "periodic")
	if err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if !second.Change.Applied {
		t.Fatalf("second run did not apply: %+v", second.Change)
	}
	if n := count(t, s, `SELECT count(*) FROM alerts WHERE kind = ? AND resolved_at IS NULL`, change.AlertPolicyExpireFailed); n != 0 {
		t.Errorf("open %s alerts = %d, want 0", change.AlertPolicyExpireFailed, n)
	}
	if n := count(t, s, `SELECT count(*) FROM alerts WHERE kind = ? AND resolved_at IS NOT NULL`, change.AlertPolicyExpireFailed); n != 1 {
		t.Errorf("resolved %s alerts = %d, want 1", change.AlertPolicyExpireFailed, n)
	}
}

// A no-change reconcile still clears a critical alert an earlier failed apply raised: the node that
// could not be expired is gone, so the read is complete and nothing needs to change, which proves
// the old alert no longer describes reality (the no-change path must not leave it open).
func TestReconcile_NoChangeResolvesApplyAlerts(t *testing.T) {
	ctx := context.Background()
	r, z, hs, s := newTestReconciler(t)
	z.grants = []zitadel.Grant{
		{UserID: "1", Role: "dev"}, {UserID: "2", Role: "dev"},
		{UserID: "3", Role: "dev"}, {UserID: "4", Role: "dev"},
	}
	z.states = map[string]zitadel.UserState{}
	for _, id := range []string{"1", "2", "3", "4", "5"} {
		z.states[id] = zitadel.UserActive
	}
	hs.policy = `{"acls":[],"groups":{"group:dev":["` + member("1") + `","` + member("2") + `","` + member("3") + `","` + member("4") + `"]}}`
	for i, id := range []string{"1", "2", "3", "4", "5"} {
		hs.users = append(hs.users, headscale.User{ID: uint64(11 + i), ProviderID: issuer + "/" + id})
	}
	hs.nodes = []headscale.Node{{ID: 100, UserID: 15}}
	hs.expireErr[100] = errors.New("headscale down")

	first, err := r.Run(ctx, "periodic")
	if err != nil {
		t.Fatalf("first Run: %v", err)
	}
	if first.Change.Applied {
		t.Fatal("the first run should fail on the node expiry")
	}
	if n := count(t, s, `SELECT count(*) FROM alerts WHERE kind = ? AND resolved_at IS NULL`, change.AlertPolicyExpireFailed); n != 1 {
		t.Fatalf("open %s alerts = %d, want 1", change.AlertPolicyExpireFailed, n)
	}

	// The faulty node disappeared, so the next run has nothing to do and must resolve the alert.
	hs.nodes = nil
	second, err := r.Run(ctx, "periodic")
	if err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if second.Status != ResultNoChange {
		t.Fatalf("status = %q, want %q", second.Status, ResultNoChange)
	}
	if n := count(t, s, `SELECT count(*) FROM alerts WHERE kind = ? AND resolved_at IS NULL`, change.AlertPolicyExpireFailed); n != 0 {
		t.Errorf("open %s alerts = %d, want 0", change.AlertPolicyExpireFailed, n)
	}
	if n := count(t, s, `SELECT count(*) FROM alerts WHERE kind = ? AND resolved_at IS NOT NULL`, change.AlertPolicyExpireFailed); n != 1 {
		t.Errorf("resolved %s alerts = %d, want 1", change.AlertPolicyExpireFailed, n)
	}
}

// A plan that cannot even be rendered must still be recorded and reported, never silently dropped.
func TestReconcile_RequestBuildFailureIsRecorded(t *testing.T) {
	ctx := context.Background()
	r, z, _, s := newTestReconciler(t)
	z.grants = []zitadel.Grant{{UserID: "1", Role: "BAD ROLE"}}
	z.states = map[string]zitadel.UserState{"1": zitadel.UserActive}

	if _, err := r.Run(ctx, "periodic"); err == nil {
		t.Fatal("Run with an unrenderable role: want error")
	}
	if n := count(t, s, `SELECT count(*) FROM sync_runs WHERE result = ?`, ResultReadFailed); n != 1 {
		t.Errorf("failed sync_runs = %d, want 1", n)
	}
}

// An unknown trigger must not reach the sync_runs CHECK constraint.
func TestReconcile_RejectsUnknownTrigger(t *testing.T) {
	r, _, _, _ := newTestReconciler(t)
	if _, err := r.Run(context.Background(), "bogus"); err == nil {
		t.Fatal("Run with an unknown trigger: want error")
	}
}

// Node owners missing from Headscale and grants must not be looked up; only the users that matter
// are asked of Zitadel.
func TestReconcile_AsksStatesForGrantAndNodeOwners(t *testing.T) {
	ctx := context.Background()
	r, z, hs, _ := newReopenReconciler(t)
	z.grants = []zitadel.Grant{{UserID: "1", Role: "dev"}}
	z.states = map[string]zitadel.UserState{"1": zitadel.UserActive, "2": zitadel.UserActive}
	hs.users = []headscale.User{
		{ID: 11, ProviderID: issuer + "/1"},
		{ID: 12, ProviderID: issuer + "/2"},
		{ID: 13, ProviderID: "https://other/3"}, // foreign issuer: ignored
	}
	hs.nodes = []headscale.Node{
		{ID: 100, UserID: 12},                               // untagged: owner needs a state
		{ID: 101, UserID: 13, Tags: []string{"tag:shared"}}, // tagged: skipped
	}
	if _, err := r.Run(ctx, "manual"); err != nil {
		t.Fatalf("Run: %v", err)
	}
	z.mu.Lock()
	asked := append([]string(nil), z.askedIDs...)
	z.mu.Unlock()
	want := []string{"1", "2"}
	if len(asked) != len(want) || asked[0] != want[0] || asked[1] != want[1] {
		t.Fatalf("asked states for %v, want %v", asked, want)
	}
}

// newReopenReconciler is newTestReconciler with the protection thresholds widened, so the single
// user's role loss applies instead of being held for approval (F3-021 tests watch the node writes,
// not the approval flow).
func newReopenReconciler(t *testing.T) (*Reconciler, *fakeZitadelReader, *fakeHeadscale, *store.Store) {
	t.Helper()
	s, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "tagcess.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	// Users 1 and 2 hold the dev role; user 1 owns the test node and is the one who loses it, so
	// the group keeps a role holder and no removed-group gate trips.
	z := &fakeZitadelReader{
		grants: []zitadel.Grant{{UserID: "1", Role: "dev"}, {UserID: "2", Role: "dev"}},
		states: map[string]zitadel.UserState{"1": zitadel.UserActive, "2": zitadel.UserActive},
	}
	hs := newFakeHeadscale(`{"acls":[],"groups":{"group:dev":[]}}`)
	pipe := change.New(hs, s.Queries(), audit.New(s.Queries()), s)
	r, err := NewReconciler(ReconcilerConfig{
		Zitadel:   z,
		Headscale: hs,
		Pipeline:  pipe,
		Queries:   s.Queries(),
		DryRun:    s,
		Issuer:    issuer,
		Settings:  Settings{MaxRemovedPercent: 100, MaxRemovedUsers: 10},
	})
	if err != nil {
		t.Fatalf("NewReconciler: %v", err)
	}
	setDryRun(t, s, false)
	return r, z, hs, s
}

// F3-021 AC7: Y-04 overrides the admin's expiry settings. A roleless user's personal device is
// expired by the next reconcile whether the admin disabled its expiry (nil) or pushed it into the
// future; a node that is already expired is not written again.
func TestReconcile_Y04OverridesAdminExpiry(t *testing.T) {
	tests := []struct {
		name   string
		expiry *time.Time
	}{
		{"admin disabled the expiry", nil},
		{"admin pushed the expiry forward", func() *time.Time { t := time.Now().Add(365 * 24 * time.Hour); return &t }()},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			r, z, hs, _ := newReopenReconciler(t)
			// User 1 owns the untagged node and holds the dev role for now.
			hs.users = []headscale.User{{ID: 11, ProviderID: issuer + "/1"}}
			hs.nodes = []headscale.Node{{ID: 100, Name: "laptop", UserID: 11, Expiry: tc.expiry}}
			if _, err := r.Run(ctx, "manual"); err != nil {
				t.Fatalf("first Run: %v", err)
			}
			if got := hs.Expired(); len(got) != 0 {
				t.Fatalf("precondition: nodes already expired: %v", got)
			}

			// User 1 loses all roles; the admin's expiry setting does not protect the device.
			z.grants = []zitadel.Grant{{UserID: "2", Role: "dev"}}
			if _, err := r.Run(ctx, "manual"); err != nil {
				t.Fatalf("second Run: %v", err)
			}
			if got := hs.Expired(); len(got) != 1 || got[0] != 100 {
				t.Fatalf("expired = %v, want [100]: the reconcile expires the device regardless of the admin expiry", got)
			}
		})
	}

	t.Run("already expired is not written again", func(t *testing.T) {
		ctx := context.Background()
		r, z, hs, _ := newReopenReconciler(t)
		z.grants = []zitadel.Grant{{UserID: "2", Role: "dev"}} // user 1 roleless from the start
		past := time.Now().Add(-time.Hour)
		hs.users = []headscale.User{{ID: 11, ProviderID: issuer + "/1"}}
		hs.nodes = []headscale.Node{{ID: 100, Name: "laptop", UserID: 11, Expiry: &past}}
		if _, err := r.Run(ctx, "manual"); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if got := hs.Expired(); len(got) != 0 {
			t.Fatalf("expired = %v, want none (the node is already cut off)", got)
		}
	})
}

// F3-021 AC8: regaining the roles never reopens a device. The reconcile plans no node write at
// all; the expired node stays expired until a devops reopens it by hand (F3-014/021 UI).
func TestReconcile_NoAutoReopen(t *testing.T) {
	ctx := context.Background()
	r, z, hs, _ := newReopenReconciler(t)
	past := time.Now().Add(-time.Hour)
	z.grants = []zitadel.Grant{{UserID: "1", Role: "dev"}}
	z.states = map[string]zitadel.UserState{"1": zitadel.UserActive}
	hs.users = []headscale.User{{ID: 11, ProviderID: issuer + "/1"}}
	hs.nodes = []headscale.Node{{ID: 100, Name: "laptop", UserID: 11, Expiry: &past}}

	res, err := r.Run(ctx, "manual")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// The policy change (user 1 back into group:dev) is applied, but no node was touched: no
	// expire and no other node write exists in the pipeline.
	if got := hs.Expired(); len(got) != 0 {
		t.Fatalf("expired = %v, want none", got)
	}
	for _, e := range res.Plan.ExpireNodes {
		if e.NodeID == 100 {
			t.Fatalf("plan expires node 100 although the user holds the role again: %+v", res.Plan)
		}
	}
	groups := groupsOf(t, []byte(hs.Policy()))
	if got := groups["group:dev"]; len(got) != 1 || got[0] != member("1") {
		t.Fatalf("group:dev = %v, want [%s]", got, member("1"))
	}
	// The node keeps its past expiry: nothing reopened it.
	if hs.nodes[0].Expiry == nil || !hs.nodes[0].Expiry.Before(time.Now()) {
		t.Fatalf("node expiry = %v, want still in the past", hs.nodes[0].Expiry)
	}
}

// maintFixture is a reconciler on the real change pipeline and the real maintenance service
// (F3b-016): users 1 and 2 hold the dev role and already sit in group:dev; user 1 owns the node 100.
// The protection thresholds are widened so the role loss of user 1 applies instead of waiting for
// approval. The maintenance starts in state (off, active or reconcile_pending). Call loseRole to
// make the next run find the group change and the expiry.
type maintFixture struct {
	r     *Reconciler
	z     *fakeZitadelReader
	hs    *fakeHeadscale
	s     *store.Store
	maint *maintenance.Service
}

func newMaintFixture(t *testing.T, dbPath string, state maintenance.State) *maintFixture {
	t.Helper()
	ctx := context.Background()
	s, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	z := &fakeZitadelReader{
		grants: []zitadel.Grant{{UserID: "1", Role: "dev"}, {UserID: "2", Role: "dev"}},
		states: map[string]zitadel.UserState{"1": zitadel.UserActive, "2": zitadel.UserActive},
	}
	hs := newFakeHeadscale(`{"acls":[],"groups":{"group:dev":["` + member("1") + `","` + member("2") + `"]}}`)
	hs.users = []headscale.User{{ID: 11, ProviderID: issuer + "/1"}, {ID: 12, ProviderID: issuer + "/2"}}
	hs.nodes = []headscale.Node{{ID: 100, Name: "laptop", UserID: 11}}
	maint := maintenance.New(s.Queries())
	pipe := change.New(hs, s.Queries(), audit.New(s.Queries()), s).WithMaintenance(maint)
	r, err := NewReconciler(ReconcilerConfig{
		Zitadel: z, Headscale: hs, Pipeline: pipe, Queries: s.Queries(), DryRun: s, Issuer: issuer,
		Settings:    Settings{MaxRemovedPercent: 100, MaxRemovedUsers: 10},
		Maintenance: maint,
	})
	if err != nil {
		t.Fatalf("NewReconciler: %v", err)
	}
	setDryRun(t, s, false)
	f := &maintFixture{r: r, z: z, hs: hs, s: s, maint: maint}
	switch state {
	case maintenance.Off:
	case maintenance.Active, maintenance.ReconcilePending:
		if _, err := maint.Start(ctx, "req-1", "devops"); err != nil {
			t.Fatalf("Start maintenance: %v", err)
		}
		if state == maintenance.ReconcilePending {
			if err := maint.SetHostResult(ctx, "req-1", `{"status":"succeeded"}`); err != nil {
				t.Fatalf("SetHostResult: %v", err)
			}
			if _, err := maint.ToReconcilePending(ctx, "req-1"); err != nil {
				t.Fatalf("ToReconcilePending: %v", err)
			}
		}
	}
	return f
}

// loseRole removes user 1's grant: the next plan drops user 1 from group:dev and expires node 100.
func (f *maintFixture) loseRole() {
	f.z.grants = []zitadel.Grant{{UserID: "2", Role: "dev"}}
}

func (f *maintFixture) pending(t *testing.T) bool {
	t.Helper()
	st, err := f.maint.Get(context.Background())
	if err != nil {
		t.Fatalf("maintenance Get: %v", err)
	}
	return st.PendingReconcile
}

// F3b-016 AC1: while the maintenance is active the reconcile still expires the node (it only
// narrows access), writes no policy and marks the held reconcile as a durable pending intent.
func TestReconcile_MaintenanceExpiresButHoldsPolicy(t *testing.T) {
	f := newMaintFixture(t, filepath.Join(t.TempDir(), "tagcess.db"), maintenance.Active)
	f.loseRole()
	before := f.hs.Policy()

	res, err := f.r.Run(context.Background(), "periodic")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Status != change.StatusHeld || !res.Change.PolicyHeld || res.Change.Applied {
		t.Fatalf("result = %+v, want held", res.Change)
	}
	if got := f.hs.Expired(); len(got) != 1 || got[0] != 100 {
		t.Fatalf("expired = %v, want [100]", got)
	}
	if len(f.hs.SetCalls()) != 0 || f.hs.Policy() != before {
		t.Fatalf("policy was written during maintenance: calls %v", f.hs.SetCalls())
	}
	if !f.pending(t) {
		t.Error("pending reconcile intent was not marked")
	}
}

// F3b-016 AC3: in reconcile_pending the reconcile may write the policy again.
func TestReconcile_ReconcilePendingAllowsSync(t *testing.T) {
	f := newMaintFixture(t, filepath.Join(t.TempDir(), "tagcess.db"), maintenance.ReconcilePending)
	f.loseRole()

	res, err := f.r.Run(context.Background(), "manual")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Change.Applied || res.Change.PolicyHeld {
		t.Fatalf("result = %+v, want applied", res.Change)
	}
	groups := groupsOf(t, []byte(f.hs.Policy()))
	if got := groups["group:dev"]; len(got) != 1 || got[0] != member("2") {
		t.Fatalf("group:dev = %v, want [%s]", got, member("2"))
	}
	if got := f.hs.Expired(); len(got) != 1 || got[0] != 100 {
		t.Fatalf("expired = %v, want [100]", got)
	}
}

// F3b-016 AC4: a webhook or periodic trigger that arrives during the maintenance is recorded with its
// own trigger name, runs by the maintenance rules and leaves the pending intent.
func TestReconcile_TriggerRecordedDuringMaintenance(t *testing.T) {
	for _, trigger := range []string{"webhook", "periodic"} {
		t.Run(trigger, func(t *testing.T) {
			f := newMaintFixture(t, filepath.Join(t.TempDir(), "tagcess.db"), maintenance.Active)
			f.loseRole()

			if _, err := f.r.Run(context.Background(), trigger); err != nil {
				t.Fatalf("Run: %v", err)
			}
			if n := count(t, f.s, `SELECT count(*) FROM sync_runs WHERE trigger = ? AND result = 'held'`, trigger); n != 1 {
				t.Errorf("held sync_runs for %s = %d, want 1", trigger, n)
			}
			if len(f.hs.SetCalls()) != 0 {
				t.Errorf("policy written: %v", f.hs.SetCalls())
			}
			if !f.pending(t) {
				t.Error("pending reconcile intent was not marked")
			}
		})
	}
}

// A run during the maintenance that finds nothing to change holds nothing back, so it must not mark
// a pending intent; the maintenance stays untouched.
func TestReconcile_MaintenanceNoChangeLeavesNoPending(t *testing.T) {
	f := newMaintFixture(t, filepath.Join(t.TempDir(), "tagcess.db"), maintenance.Active)

	res, err := f.r.Run(context.Background(), "periodic")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Status != ResultNoChange {
		t.Fatalf("status = %q, want %q", res.Status, ResultNoChange)
	}
	if f.pending(t) {
		t.Error("a no-change run marked a pending reconcile")
	}
}

// F3b-016 AC5: the pending intent is part of the maintenance row, so it survives the container
// restarting while the maintenance is open.
func TestReconcile_PendingIntentPersists(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "tagcess.db")
	f := newMaintFixture(t, path, maintenance.Active)
	f.loseRole()
	if _, err := f.r.Run(ctx, "webhook"); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !f.pending(t) {
		t.Fatal("pending reconcile intent was not marked")
	}
	if err := f.s.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	s2, err := store.Open(ctx, path)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	t.Cleanup(func() { _ = s2.Close() })
	st, err := maintenance.New(s2.Queries()).Get(ctx)
	if err != nil {
		t.Fatalf("Get after restart: %v", err)
	}
	if st.State != maintenance.Active || !st.PendingReconcile || st.RequestID != "req-1" {
		t.Fatalf("status after restart = %+v, want active with the pending reconcile kept", st)
	}
}

// The sync flow names its source explicitly, so the maintenance gate never has to guess it from an
// empty revision source (F3b-015 review).
func TestRequest_CarriesSyncSource(t *testing.T) {
	in := Input{
		Read:   Read{Complete: true, Grants: []zitadel.Grant{}, States: map[string]zitadel.UserState{}},
		Policy: []byte(`{"acls":[],"groups":{}}`),
		Format: render.ProviderIDFormat(issuer),
	}
	req, err := Request(in, Plan{WillApply: true}, SystemActor, "webhook", "x")
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	if req.Revision.Source != "sync" || req.Trigger != "webhook" || req.Actor != SystemActor {
		t.Fatalf("request = source %q trigger %q actor %q", req.Revision.Source, req.Trigger, req.Actor)
	}
}

// A failed expiry during the maintenance still leaves the pending intent: the policy step was held
// either way, and the next reconcile retries the expiry.
func TestReconcile_MaintenanceExpireFailureKeepsPendingIntent(t *testing.T) {
	f := newMaintFixture(t, filepath.Join(t.TempDir(), "tagcess.db"), maintenance.Active)
	f.loseRole()
	f.hs.expireErr[100] = errors.New("boom")

	res, err := f.r.Run(context.Background(), "periodic")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Status != change.StatusFailed || !res.Change.PolicyHeld {
		t.Fatalf("result = %+v, want failed with the policy held", res.Change)
	}
	if len(f.hs.SetCalls()) != 0 {
		t.Errorf("policy written: %v", f.hs.SetCalls())
	}
	if !f.pending(t) {
		t.Error("pending reconcile intent was not marked")
	}
}

// state reads the maintenance row.
func (f *maintFixture) state(t *testing.T) maintenance.Status {
	t.Helper()
	st, err := f.maint.Get(context.Background())
	if err != nil {
		t.Fatalf("maintenance Get: %v", err)
	}
	return st
}

// F3b-019 AC2: a complete, successful reconcile in reconcile_pending ends the maintenance and
// audits it; afterwards widening admin writes pass again.
func TestReconcile_ClearsMaintenanceAfterSuccess(t *testing.T) {
	for _, tc := range []struct {
		name string
		lose bool
	}{
		{"applied", true},
		{"nothing to apply", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newMaintFixture(t, filepath.Join(t.TempDir(), "tagcess.db"), maintenance.ReconcilePending)
			if tc.lose {
				f.loseRole()
			}
			ctx := context.Background()
			if err := f.maint.CheckWidening(ctx, maintenance.SourceAdmin); err == nil {
				t.Fatal("admin widening passed in reconcile_pending")
			}

			if _, err := f.r.Run(ctx, "manual"); err != nil {
				t.Fatalf("Run: %v", err)
			}
			st := f.state(t)
			if st.State != maintenance.Off || st.CloseNote != "" || st.RequestID != "" {
				t.Fatalf("maintenance = %+v, want off with no note", st)
			}
			if err := f.maint.CheckWidening(ctx, maintenance.SourceAdmin); err != nil {
				t.Errorf("admin widening after the close = %v, want nil", err)
			}
			var actor, target, result string
			if err := f.s.DB().QueryRowContext(ctx,
				`SELECT actor, target, result FROM audit_events WHERE event = ?`, EventMaintenanceClosed,
			).Scan(&actor, &target, &result); err != nil {
				t.Fatalf("close audit row: %v", err)
			}
			if actor != SystemActor || target != "request:req-1" || result != "off" {
				t.Errorf("audit = %q/%q/%q, want %s/request:req-1/off", actor, target, result, SystemActor)
			}
		})
	}
}

// The reconcile only closes a maintenance that is waiting for it: during an active maintenance, or
// with none, a run changes no maintenance state and writes no close audit.
func TestReconcile_DoesNotCloseOtherStates(t *testing.T) {
	for _, state := range []maintenance.State{maintenance.Off, maintenance.Active} {
		t.Run(string(state), func(t *testing.T) {
			f := newMaintFixture(t, filepath.Join(t.TempDir(), "tagcess.db"), state)
			if _, err := f.r.Run(context.Background(), "manual"); err != nil {
				t.Fatalf("Run: %v", err)
			}
			if st := f.state(t); st.State != state {
				t.Errorf("state = %s, want %s", st.State, state)
			}
			if n := count(t, f.s, `SELECT count(*) FROM audit_events WHERE event = ?`, EventMaintenanceClosed); n != 0 {
				t.Errorf("close audits = %d, want 0", n)
			}
		})
	}
}

// F3b-019 AC3: a reconcile that could not read Zitadel, failed, or did not finish applying leaves
// reconcile_pending in place, so widening admin writes stay refused and the next run retries.
func TestReconcile_KeepsPendingOnFailure(t *testing.T) {
	tests := []struct {
		name  string
		setup func(f *maintFixture)
	}{
		{"zitadel unreadable", func(f *maintFixture) { f.z.grantsErr = errors.New("zitadel down") }},
		{"user states unreadable", func(f *maintFixture) { f.z.statesErr = errors.New("states down") }},
		{"headscale unreadable", func(f *maintFixture) { f.hs.policyErr = errors.New("headscale down") }},
		{"expire fails", func(f *maintFixture) { f.loseRole(); f.hs.expireErr[100] = errors.New("boom") }},
		{"policy write fails", func(f *maintFixture) { f.loseRole(); f.hs.setErr = errors.New("write failed") }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newMaintFixture(t, filepath.Join(t.TempDir(), "tagcess.db"), maintenance.ReconcilePending)
			tc.setup(f)
			_, _ = f.r.Run(context.Background(), "manual")

			if st := f.state(t); st.State != maintenance.ReconcilePending || st.RequestID != "req-1" {
				t.Fatalf("maintenance = %s/%s, want reconcile_pending/req-1", st.State, st.RequestID)
			}
			if err := f.maint.CheckWidening(context.Background(), maintenance.SourceAdmin); err == nil {
				t.Error("admin widening passes although the reconcile failed")
			}
			if n := count(t, f.s, `SELECT count(*) FROM audit_events WHERE event = ?`, EventMaintenanceClosed); n != 0 {
				t.Errorf("close audits = %d, want 0", n)
			}

			// Once the cause is gone the next run completes and closes.
			f.z.grantsErr, f.z.statesErr, f.hs.policyErr, f.hs.setErr = nil, nil, nil, nil
			delete(f.hs.expireErr, 100)
			if _, err := f.r.Run(context.Background(), "periodic"); err != nil {
				t.Fatalf("retry Run: %v", err)
			}
			if st := f.state(t); st.State != maintenance.Off {
				t.Errorf("state after the retry = %s, want off", st.State)
			}
		})
	}
}

// F3b-019 AC7: with dry run on, the reconcile after a success applies nothing but still counts as
// complete: the maintenance ends and the close note says the diff was skipped.
func TestMaintenance_DryRunClearsAfterReconcile(t *testing.T) {
	f := newMaintFixture(t, filepath.Join(t.TempDir(), "tagcess.db"), maintenance.ReconcilePending)
	setDryRun(t, f.s, true)
	f.loseRole()
	before := f.hs.Policy()

	res, err := f.r.Run(context.Background(), "manual")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Status != change.StatusDryRun {
		t.Fatalf("status = %q, want %q", res.Status, change.StatusDryRun)
	}
	if len(f.hs.SetCalls()) != 0 || f.hs.Policy() != before || len(f.hs.Expired()) != 0 {
		t.Fatalf("dry run wrote: policy calls %v, expired %v", f.hs.SetCalls(), f.hs.Expired())
	}
	st := f.state(t)
	if st.State != maintenance.Off || st.CloseNote != DryRunSkippedNote {
		t.Fatalf("maintenance = %s note %q, want off with %q", st.State, st.CloseNote, DryRunSkippedNote)
	}
	if DryRunSkippedNote != "dry_run_skipped" {
		t.Errorf("DryRunSkippedNote = %q, want dry_run_skipped", DryRunSkippedNote)
	}
}
