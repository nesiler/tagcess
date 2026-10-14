package hsadmin

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/headscale/admin"
	"github.com/nesiler/tagcess/internal/maintenance"
	"github.com/nesiler/tagcess/internal/store/db"
)

// unreadableQueries makes the maintenance state unreadable.
type unreadableQueries struct{ *db.Queries }

func (unreadableQueries) GetHeadscaleMaintenance(context.Context) (db.GetHeadscaleMaintenanceRow, error) {
	return db.GetHeadscaleMaintenanceRow{}, errors.New("database is locked")
}

// maintHarness is the executor harness with a maintenance gate in the given state.
func maintHarness(t *testing.T, state maintenance.State) *harness {
	t.Helper()
	h := newHarness(t)
	svc := maintenance.New(h.store.Queries())
	ctx := context.Background()
	if state != maintenance.Off {
		if _, err := svc.Start(ctx, "req-1", testActor); err != nil {
			t.Fatalf("Start: %v", err)
		}
	}
	if state == maintenance.ReconcilePending {
		if err := svc.SetHostResult(ctx, "req-1", `{"status":"succeeded"}`); err != nil {
			t.Fatalf("SetHostResult: %v", err)
		}
		if _, err := svc.ToReconcilePending(ctx, "req-1"); err != nil {
			t.Fatalf("ToReconcilePending: %v", err)
		}
	}
	h.ex = New(Config{Reader: h.rd, Audit: h.audit, Store: h.store.Queries(), Maintenance: svc})
	return h
}

// addKeys puts one pre-auth key and one API key on the fake.
func (h *harness) addKeys() {
	h.rd.mu.Lock()
	defer h.rd.mu.Unlock()
	h.rd.keys = []admin.PreAuthKey{{ID: 5, UserID: 10}}
	h.rd.apiKeys = []admin.APIKey{{ID: 6, Prefix: "abc"}}
}

// opFor builds an operation of kind k that counts one RPC and always reads back as applied.
func (h *harness) opFor(k Kind) Op {
	op := Op{
		Actor: testActor, Kind: k, Target: "t:" + string(k),
		Apply:  func(context.Context) error { h.rpcs.Add(1); return nil },
		Verify: func(context.Context, Reader) (bool, error) { return true, nil },
	}
	switch k {
	case KindPreAuthCreate:
	case KindPreAuthExpire, KindPreAuthDelete:
		op.ID, op.Expected = 5, PreAuthVersion(h.rd.keys[0])
	case KindAPIKeyExpire, KindAPIKeyDelete:
		op.ID, op.Expected = 6, APIKeyVersion(h.rd.apiKeys[0])
	default:
		op.ID, op.Expected = 1, NodeVersion(h.rd.node(1))
		if k == KindNodeTags {
			op.Tags = []string{"tag:other"}
		}
	}
	return op
}

func wantRefused(t *testing.T, h *harness, res Result, err error) {
	t.Helper()
	if !errors.Is(err, ErrMaintenance) || !errors.Is(err, ErrBlocked) || res.Status != StatusBlocked {
		t.Fatalf("Do = %+v, %v; want blocked with ErrMaintenance", res, err)
	}
	if res.Note != "bakım sürüyor" {
		t.Errorf("note = %q, want the maintenance reason", res.Note)
	}
	if h.rpcs.Load() != 0 {
		t.Errorf("rpcs = %d, want 0 before the RPC", h.rpcs.Load())
	}
	if got := h.results(); !slices.Equal(got, []string{"blocked"}) {
		t.Errorf("audit = %v, want [blocked]", got)
	}
}

func wantApplied(t *testing.T, h *harness, res Result, err error) {
	t.Helper()
	if err != nil || res.Status != StatusApplied {
		t.Fatalf("Do = %+v, %v; want applied", res, err)
	}
	if h.rpcs.Load() != 1 {
		t.Errorf("rpcs = %d, want 1", h.rpcs.Load())
	}
}

// AC3 (F3b-027): an executor wired without an explicit Maintenance gate still gets one on the
// store (the change.NewSite pattern), so a widening write cannot run gate-less.
func TestExecutor_DefaultsMaintenanceGateFromStore(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t) // newHarness deliberately wires no Maintenance.
	if h.ex.gate == nil {
		t.Fatal("New built no maintenance gate from the store")
	}
	svc := maintenance.New(h.store.Queries())
	if _, err := svc.Start(ctx, "req-1", testActor); err != nil {
		t.Fatalf("Start: %v", err)
	}
	h.addKeys()
	res, err := h.ex.Do(ctx, h.opFor(KindNodeReopen))
	wantRefused(t, h, res, err)
}

// AC1: widening kinds are refused while the maintenance is open, before the RPC and audited.
func TestExecutor_MaintenanceBlocksWidening(t *testing.T) {
	kinds := []Kind{KindNodeReopen, KindNodeTags, KindNodeRoutes, KindPreAuthCreate}
	for _, state := range []maintenance.State{maintenance.Active, maintenance.ReconcilePending} {
		for _, k := range kinds {
			t.Run(fmt.Sprintf("%s/%s", state, k), func(t *testing.T) {
				h := maintHarness(t, state)
				h.addKeys()
				res, err := h.ex.Do(context.Background(), h.opFor(k))
				wantRefused(t, h, res, err)
			})
		}
	}
	t.Run("off allows", func(t *testing.T) {
		for _, k := range kinds {
			h := maintHarness(t, maintenance.Off)
			h.addKeys()
			res, err := h.ex.Do(context.Background(), h.opFor(k))
			wantApplied(t, h, res, err)
		}
	})
}

// AC2: an expiry change is refused while open when it extends or removes the expiry (or when the
// op cannot say), and runs when it shortens it.
func TestExecutor_MaintenanceExpiryDirection(t *testing.T) {
	soon := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
	later := soon.Add(48 * time.Hour)
	earlier := soon.Add(-12 * time.Hour)
	cases := []struct {
		name    string
		current *time.Time
		widens  func(admin.AdminNode) bool
		allowed bool
	}{
		{"extends", &soon, func(n admin.AdminNode) bool { return later.After(*n.Expiry) }, false},
		{"disables", &soon, func(admin.AdminNode) bool { return true }, false},
		{"shortens", &soon, func(n admin.AdminNode) bool { return earlier.After(*n.Expiry) }, true},
		{"no direction given fails closed", &soon, nil, false},
		{"sets from none", nil, func(n admin.AdminNode) bool { return n.Expiry == nil }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := maintHarness(t, maintenance.Active)
			h.rd.mutate(1, func(n *admin.AdminNode) { n.Expiry = tc.current })
			op := h.opFor(KindNodeExpiry)
			op.Widens = tc.widens
			res, err := h.ex.Do(context.Background(), op)
			if tc.allowed {
				wantApplied(t, h, res, err)
			} else {
				wantRefused(t, h, res, err)
			}
		})
	}
	t.Run("off ignores direction", func(t *testing.T) {
		h := maintHarness(t, maintenance.Off)
		op := h.opFor(KindNodeExpiry)
		res, err := h.ex.Do(context.Background(), op)
		wantApplied(t, h, res, err)
	})
}

// AC3: narrowing operations run normally while the maintenance is open.
func TestExecutor_MaintenanceAllowsNarrowing(t *testing.T) {
	kinds := []Kind{KindNodeExpire, KindNodeDelete, KindNodeRename, KindPreAuthExpire, KindPreAuthDelete, KindAPIKeyExpire, KindAPIKeyDelete}
	for _, state := range []maintenance.State{maintenance.Active, maintenance.ReconcilePending} {
		for _, k := range kinds {
			t.Run(fmt.Sprintf("%s/%s", state, k), func(t *testing.T) {
				h := maintHarness(t, state)
				h.addKeys()
				res, err := h.ex.Do(context.Background(), h.opFor(k))
				wantApplied(t, h, res, err)
			})
		}
	}
}

// AC4: an unreadable maintenance state refuses widening and still runs narrowing.
func TestExecutor_MaintenanceUnreadableFailsClosed(t *testing.T) {
	setup := func(t *testing.T) *harness {
		h := newHarness(t)
		h.addKeys()
		h.ex = New(Config{
			Reader: h.rd, Audit: h.audit, Store: h.store.Queries(),
			Maintenance: maintenance.New(unreadableQueries{h.store.Queries()}),
		})
		return h
	}
	for _, k := range []Kind{KindNodeReopen, KindNodeTags, KindNodeRoutes, KindPreAuthCreate, KindNodeExpiry} {
		t.Run("widening "+string(k), func(t *testing.T) {
			h := setup(t)
			op := h.opFor(k)
			op.Widens = func(admin.AdminNode) bool { return true }
			res, err := h.ex.Do(context.Background(), op)
			if !errors.Is(err, ErrMaintenance) || res.Status != StatusBlocked || h.rpcs.Load() != 0 {
				t.Fatalf("Do = %+v, %v, rpcs %d; want blocked", res, err, h.rpcs.Load())
			}
		})
	}
	for _, k := range []Kind{KindNodeExpire, KindNodeDelete, KindNodeRename, KindPreAuthExpire, KindAPIKeyDelete} {
		t.Run("narrowing "+string(k), func(t *testing.T) {
			h := setup(t)
			res, err := h.ex.Do(context.Background(), h.opFor(k))
			wantApplied(t, h, res, err)
		})
	}
	t.Run("shortening expiry", func(t *testing.T) {
		h := setup(t)
		op := h.opFor(KindNodeExpiry)
		op.Widens = func(admin.AdminNode) bool { return false }
		res, err := h.ex.Do(context.Background(), op)
		wantApplied(t, h, res, err)
	})
}

// countingReader counts node reads so a test can tell the fresh read happened.
type countingReader struct {
	Reader
	nodeReads atomic.Int32
}

func (c *countingReader) ListNodes(ctx context.Context) ([]admin.AdminNode, error) {
	c.nodeReads.Add(1)
	return c.Reader.ListNodes(ctx)
}

// spyGate records the conditions it was called under, then refuses.
type spyGate struct {
	h          *harness
	rd         *countingReader
	lockHeld   bool
	readsSeen  int32
	auditSeen  int
	calls      int
	sourceSeen string
}

func (g *spyGate) CheckWidening(_ context.Context, source string) error {
	g.calls++
	g.sourceSeen = source
	got := make(chan struct{})
	go func() { _ = change.WithWriterLock(func() error { close(got); return nil }) }()
	select {
	case <-got:
	case <-time.After(100 * time.Millisecond):
		g.lockHeld = true
	}
	g.readsSeen = g.rd.nodeReads.Load()
	g.auditSeen = len(g.h.events())
	return maintenance.ErrMaintenance
}

// AC5: the check runs under the writer lock, after the fresh read and before the intent audit.
func TestExecutor_MaintenanceCheckedUnderLock(t *testing.T) {
	h := newHarness(t)
	rd := &countingReader{Reader: h.rd}
	gate := &spyGate{h: h, rd: rd}
	h.ex = New(Config{Reader: rd, Audit: h.audit, Store: h.store.Queries(), Maintenance: gate})

	res, err := h.ex.Do(context.Background(), h.opFor(KindNodeTags))
	if !errors.Is(err, ErrMaintenance) || res.Status != StatusBlocked {
		t.Fatalf("Do = %+v, %v", res, err)
	}
	if gate.calls != 1 {
		t.Fatalf("gate calls = %d, want 1", gate.calls)
	}
	if !gate.lockHeld {
		t.Error("gate ran outside the writer lock")
	}
	if gate.readsSeen < 1 {
		t.Error("gate ran before the fresh read")
	}
	if gate.auditSeen != 0 {
		t.Errorf("gate saw %d audit rows, want 0 (before the intent audit)", gate.auditSeen)
	}
	if gate.sourceSeen != maintenance.SourceAdmin {
		t.Errorf("source = %q, want admin", gate.sourceSeen)
	}

	// A narrowing op never asks the gate.
	gate.calls = 0
	h.rpcs.Store(0)
	h.ex = New(Config{Reader: rd, Audit: h.audit, Store: h.store.Queries(), Maintenance: gate})
	res, err = h.ex.Do(context.Background(), h.renameOp(1, "x"))
	if err != nil || res.Status != StatusApplied || gate.calls != 0 {
		t.Fatalf("narrowing: Do = %+v, %v, gate calls %d", res, err, gate.calls)
	}
}

// A widening op the fresh read finds protected or stale is refused for that reason first; and a
// DiffFrom still shows the audit "before" on the maintenance refusal.
func TestExecutor_MaintenanceRefusalKeepsDiff(t *testing.T) {
	h := maintHarness(t, maintenance.Active)
	op := h.opFor(KindNodeTags)
	op.DiffFrom = func(n admin.AdminNode) audit.Diff {
		return audit.Diff{{Field: "tags", Before: "old", After: "tag:other"}}
	}
	_, err := h.ex.Do(context.Background(), op)
	if !errors.Is(err, ErrMaintenance) {
		t.Fatalf("err = %v", err)
	}
	evs := h.events()
	if len(evs) != 1 || !hasChange(evs[0].Diff, "tags", "tag:other") {
		t.Errorf("audit = %+v", evs)
	}
}
