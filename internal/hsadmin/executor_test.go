package hsadmin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/headscale/admin"
	"github.com/nesiler/tagcess/internal/store"
	"github.com/nesiler/tagcess/internal/store/db"
)

const testActor = "devops@example.com"

// fakeReader is the live Headscale view the executor reads. Apply closures in tests mutate it the
// way a real RPC would.
type fakeReader struct {
	mu      sync.Mutex
	nodes   []admin.AdminNode
	keys    []admin.PreAuthKey
	apiKeys []admin.APIKey
	// listErr makes every read fail.
	listErr error
	// ctxErrAtRead records a canceled context seen by a read.
	ctxErrAtRead error
}

func (r *fakeReader) ListNodes(ctx context.Context) ([]admin.AdminNode, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		r.ctxErrAtRead = err
		return nil, err
	}
	if r.listErr != nil {
		return nil, r.listErr
	}
	return append([]admin.AdminNode(nil), r.nodes...), nil
}

func (r *fakeReader) ListPreAuthKeys(ctx context.Context) ([]admin.PreAuthKey, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.listErr != nil {
		return nil, r.listErr
	}
	return append([]admin.PreAuthKey(nil), r.keys...), nil
}

func (r *fakeReader) ListApiKeys(ctx context.Context) ([]admin.APIKey, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.listErr != nil {
		return nil, r.listErr
	}
	return append([]admin.APIKey(nil), r.apiKeys...), nil
}

func (r *fakeReader) node(id uint64) admin.AdminNode {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, n := range r.nodes {
		if n.ID == id {
			return n
		}
	}
	return admin.AdminNode{}
}

func (r *fakeReader) mutate(id uint64, fn func(n *admin.AdminNode)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.nodes {
		if r.nodes[i].ID == id {
			fn(&r.nodes[i])
		}
	}
}

func (r *fakeReader) setListErr(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.listErr = err
}

type harness struct {
	t      *testing.T
	store  *store.Store
	audit  *audit.Logger
	rd     *fakeReader
	ex     *Executor
	logBuf *bytes.Buffer
	rpcs   atomic.Int32
}

func newHarness(t *testing.T) *harness { return newHarnessWithRecorder(t, nil) }

// newHarnessWithRecorder lets a test wrap the audit recorder (to make writes fail).
func newHarnessWithRecorder(t *testing.T, wrap func(audit.Recorder) audit.Recorder) *harness {
	t.Helper()
	s, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "tagcess.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	var rec audit.Recorder = s.Queries()
	if wrap != nil {
		rec = wrap(rec)
	}
	h := &harness{t: t, store: s, audit: audit.New(rec), logBuf: &bytes.Buffer{}}
	h.rd = &fakeReader{nodes: []admin.AdminNode{
		{ID: 1, Name: "laptop", GivenName: "laptop", UserID: 10, UserName: "carol"},
		{ID: 2, Name: "gw", GivenName: "gw", UserID: 11, UserName: "ops", Tags: []string{"tag:vpn-server"}},
		{ID: 3, Name: "app", GivenName: "app", UserID: 11, UserName: "ops", Tags: []string{"tag:other"}},
	}}
	h.ex = New(Config{
		Reader: h.rd,
		Audit:  h.audit,
		Store:  s.Queries(),
		Log:    slog.New(slog.NewTextHandler(h.logBuf, nil)),
	})
	return h
}

// nodeOp builds an op on a node. apply counts as one RPC and runs fn against the fake.
func (h *harness) nodeOp(kind Kind, id uint64, apply func(n *admin.AdminNode) error, verify func(n admin.AdminNode) bool) Op {
	n := h.rd.node(id)
	return Op{
		Actor:    testActor,
		Kind:     kind,
		ID:       id,
		Target:   fmt.Sprintf("node:%d", id),
		Expected: NodeVersion(n),
		Apply: func(ctx context.Context) error {
			h.rpcs.Add(1)
			var err error
			h.rd.mutate(id, func(n *admin.AdminNode) {
				if apply != nil {
					err = apply(n)
				}
			})
			return err
		},
		Verify: func(ctx context.Context, r Reader) (bool, error) {
			nodes, err := r.ListNodes(ctx)
			if err != nil {
				return false, err
			}
			for _, n := range nodes {
				if n.ID == id {
					return verify == nil || verify(n), nil
				}
			}
			return verify == nil, nil
		},
	}
}

func (h *harness) renameOp(id uint64, to string) Op {
	op := h.nodeOp(KindNodeRename, id,
		func(n *admin.AdminNode) error { n.GivenName = to; return nil },
		func(n admin.AdminNode) bool { return n.GivenName == to })
	op.Diff = audit.Diff{{Field: "given_name", Before: h.rd.node(id).GivenName, After: to}}
	return op
}

func (h *harness) events() []audit.Event {
	h.t.Helper()
	evs, err := h.audit.List(context.Background(), audit.Filter{Limit: 100})
	if err != nil {
		h.t.Fatal(err)
	}
	// oldest first
	for i, j := 0, len(evs)-1; i < j; i, j = i+1, j-1 {
		evs[i], evs[j] = evs[j], evs[i]
	}
	return evs
}

func (h *harness) results() []string {
	var out []string
	for _, e := range h.events() {
		out = append(out, e.Result)
	}
	return out
}

func (h *harness) setSetting(value string) {
	h.t.Helper()
	err := h.store.Queries().UpsertSetting(context.Background(), db.UpsertSettingParams{
		Key: ProtectedTagsKey, Value: value, UpdatedAt: "2026-10-01T00:00:00.000Z",
	})
	if err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) openAlerts() []db.Alert {
	h.t.Helper()
	alerts, err := h.store.Queries().ListOpenAlerts(context.Background())
	if err != nil {
		h.t.Fatal(err)
	}
	return alerts
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// AC1: two operations and a policy write never run at the same time (one process-wide writer).
func TestExecutor_SerializedWithPolicyPipeline(t *testing.T) {
	h := newHarness(t)
	var inside, overlaps atomic.Int32
	enter := func() {
		if inside.Add(1) > 1 {
			overlaps.Add(1)
		}
		time.Sleep(30 * time.Millisecond)
		inside.Add(-1)
	}
	slow := func(id uint64, to string) Op {
		op := h.renameOp(id, to)
		inner := op.Apply
		op.Apply = func(ctx context.Context) error { enter(); return inner(ctx) }
		return op
	}
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); _, _ = h.ex.Do(context.Background(), slow(1, "a")) }()
	go func() { defer wg.Done(); _, _ = h.ex.Do(context.Background(), slow(3, "b")) }()
	go func() { // the policy pipeline's writer section
		defer wg.Done()
		_ = change.WithWriterLock(func() error { enter(); return nil })
	}()
	wg.Wait()
	if overlaps.Load() != 0 {
		t.Fatalf("%d overlapping writer sections", overlaps.Load())
	}
	if got := h.rpcs.Load(); got != 2 {
		t.Errorf("rpcs = %d, want 2", got)
	}
}

// AC2: the started record is written before the RPC (and a failing write stops the RPC); the
// result follows the read-back.
func TestExecutor_AuditOrder(t *testing.T) {
	h := newHarness(t)
	op := h.renameOp(1, "renamed")
	inner := op.Apply
	var atRPC []string
	op.Apply = func(ctx context.Context) error {
		atRPC = h.results()
		return inner(ctx)
	}
	res, err := h.ex.Do(context.Background(), op)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if res.Status != StatusApplied {
		t.Errorf("status = %q", res.Status)
	}
	if !equalStrings(atRPC, []string{"started"}) {
		t.Errorf("audit at RPC time = %v, want [started]", atRPC)
	}
	if got := h.results(); !equalStrings(got, []string{"started", "applied"}) {
		t.Errorf("audit = %v", got)
	}
	for _, e := range h.events() {
		if e.Actor != testActor || e.Event != "headscale.node.rename" || e.Target != "node:1" {
			t.Errorf("event = %+v", e)
		}
	}

	t.Run("started write fails", func(t *testing.T) {
		h := newHarnessWithRecorder(t, func(r audit.Recorder) audit.Recorder { return failingRecorder{r} })
		_, err := h.ex.Do(context.Background(), h.renameOp(1, "x"))
		if err == nil {
			t.Fatal("Do succeeded without an audit record")
		}
		if h.rpcs.Load() != 0 {
			t.Errorf("rpcs = %d, want 0", h.rpcs.Load())
		}
	})
}

type failingRecorder struct{ audit.Recorder }

func (failingRecorder) InsertAuditEvent(context.Context, db.InsertAuditEventParams) (db.AuditEvent, error) {
	return db.AuditEvent{}, errors.New("disk full")
}

// AC3: protected nodes reject delete, expire, expiry and tag changes without an RPC.
func TestExecutor_ProtectedNodeBlocked(t *testing.T) {
	tests := []struct {
		name    string
		kind    Kind
		id      uint64
		tags    []string
		blocked bool
	}{
		{"delete protected", KindNodeDelete, 2, nil, true},
		{"expire protected", KindNodeExpire, 2, nil, true},
		{"expiry protected", KindNodeExpiry, 2, nil, true},
		{"tags protected", KindNodeTags, 2, []string{"tag:other"}, true},
		{"rename protected", KindNodeRename, 2, nil, false},
		{"routes protected", KindNodeRoutes, 2, nil, false},
		{"delete unprotected tagged", KindNodeDelete, 3, nil, false},
		{"delete personal", KindNodeDelete, 1, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			op := h.nodeOp(tt.kind, tt.id, nil, nil)
			op.Tags = tt.tags
			res, err := h.ex.Do(context.Background(), op)
			if tt.blocked {
				if !errors.Is(err, ErrBlocked) || res.Status != StatusBlocked {
					t.Fatalf("Do = %+v, %v; want blocked", res, err)
				}
				if h.rpcs.Load() != 0 {
					t.Errorf("rpcs = %d, want 0", h.rpcs.Load())
				}
				if got := h.results(); !equalStrings(got, []string{"blocked"}) {
					t.Errorf("audit = %v, want [blocked]", got)
				}
				return
			}
			if err != nil || res.Status != StatusApplied || h.rpcs.Load() != 1 {
				t.Fatalf("Do = %+v, %v, rpcs %d; want applied", res, err, h.rpcs.Load())
			}
		})
	}
}

// AC3b: no node, personal or not, may be given a protected tag.
func TestExecutor_ProtectedTagAssignmentBlocked(t *testing.T) {
	for _, tag := range []string{"tag:k8s", "tag:vpn-server"} {
		h := newHarness(t)
		op := h.nodeOp(KindNodeTags, 1, nil, nil)
		op.Tags = []string{"tag:ok", tag}
		_, err := h.ex.Do(context.Background(), op)
		if !errors.Is(err, ErrBlocked) {
			t.Fatalf("assign %s: err = %v, want ErrBlocked", tag, err)
		}
		if h.rpcs.Load() != 0 {
			t.Errorf("assign %s: rpcs = %d", tag, h.rpcs.Load())
		}
		if got := h.results(); !equalStrings(got, []string{"blocked"}) {
			t.Errorf("audit = %v", got)
		}
	}
	h := newHarness(t)
	op := h.nodeOp(KindNodeTags, 1, func(n *admin.AdminNode) error { n.Tags = []string{"tag:ok"}; return nil }, nil)
	op.Tags = []string{"tag:ok"}
	if _, err := h.ex.Do(context.Background(), op); err != nil {
		t.Fatalf("harmless tag: %v", err)
	}
}

// AC5: a version that no longer matches the live state never reaches the RPC.
func TestExecutor_StaleVersionRejected(t *testing.T) {
	h := newHarness(t)
	op := h.renameOp(1, "x")
	h.rd.mutate(1, func(n *admin.AdminNode) { n.Tags = []string{"tag:other"} }) // changed after the page loaded
	res, err := h.ex.Do(context.Background(), op)
	if !errors.Is(err, ErrStale) || res.Status != StatusStale {
		t.Fatalf("Do = %+v, %v; want ErrStale", res, err)
	}
	if h.rpcs.Load() != 0 {
		t.Errorf("rpcs = %d, want 0", h.rpcs.Load())
	}

	// A vanished target is stale too.
	gone := h.renameOp(3, "y")
	h.rd.mu.Lock()
	h.rd.nodes = h.rd.nodes[:2]
	h.rd.mu.Unlock()
	if _, err := h.ex.Do(context.Background(), gone); !errors.Is(err, ErrStale) {
		t.Errorf("missing node: err = %v, want ErrStale", err)
	}

	// Key operations compare key versions.
	h.rd.keys = []admin.PreAuthKey{{ID: 7, UserID: 10, Reusable: true}}
	keyOp := Op{
		Actor: testActor, Kind: KindPreAuthExpire, ID: 7, Target: "preauth:7",
		Expected: PreAuthVersion(admin.PreAuthKey{ID: 7, UserID: 10}),
		Apply:    func(context.Context) error { h.rpcs.Add(1); return nil },
		Verify:   func(context.Context, Reader) (bool, error) { return true, nil },
	}
	if _, err := h.ex.Do(context.Background(), keyOp); !errors.Is(err, ErrStale) {
		t.Errorf("stale key: err = %v, want ErrStale", err)
	}
	keyOp.Expected = PreAuthVersion(h.rd.keys[0])
	if res, err := h.ex.Do(context.Background(), keyOp); err != nil || res.Status != StatusApplied {
		t.Errorf("fresh key: %+v, %v", res, err)
	}

	// Without an expected version a targeted op is invalid.
	bad := h.renameOp(1, "z")
	bad.Expected = ""
	if _, err := h.ex.Do(context.Background(), bad); !errors.Is(err, ErrInvalidOp) {
		t.Errorf("no version: err = %v, want ErrInvalidOp", err)
	}
}

// AC6: an RPC error is never retried; the read-back decides the outcome.
func TestExecutor_RPCErrorReadBackApplied(t *testing.T) {
	h := newHarness(t)
	op := h.nodeOp(KindNodeRename, 1,
		func(n *admin.AdminNode) error { n.GivenName = "done"; return errors.New("response lost") },
		func(n admin.AdminNode) bool { return n.GivenName == "done" })
	res, err := h.ex.Do(context.Background(), op)
	if err != nil || res.Status != StatusApplied {
		t.Fatalf("Do = %+v, %v; want applied", res, err)
	}
	if !strings.Contains(res.Note, "response lost") {
		t.Errorf("note = %q", res.Note)
	}
	if h.rpcs.Load() != 1 {
		t.Errorf("rpcs = %d, want 1", h.rpcs.Load())
	}
	if got := h.results(); !equalStrings(got, []string{"started", "applied"}) {
		t.Errorf("audit = %v", got)
	}
	if len(h.openAlerts()) != 0 {
		t.Errorf("alerts = %v", h.openAlerts())
	}
}

func TestExecutor_RPCErrorNotApplied(t *testing.T) {
	h := newHarness(t)
	op := h.nodeOp(KindNodeRename, 1,
		func(n *admin.AdminNode) error { return errors.New("boom") },
		func(n admin.AdminNode) bool { return n.GivenName == "never" })
	res, err := h.ex.Do(context.Background(), op)
	if err == nil || res.Status != StatusFailed {
		t.Fatalf("Do = %+v, %v; want failed", res, err)
	}
	if h.rpcs.Load() != 1 {
		t.Errorf("rpcs = %d, want 1", h.rpcs.Load())
	}
	if got := h.results(); !equalStrings(got, []string{"started", "failed"}) {
		t.Errorf("audit = %v", got)
	}
	if len(h.openAlerts()) != 0 {
		t.Errorf("a clean failure must not alert: %v", h.openAlerts())
	}
}

func TestExecutor_UnknownOutcomeAlert(t *testing.T) {
	h := newHarness(t)
	op := h.nodeOp(KindNodeRename, 1, nil, nil)
	inner := op.Apply
	op.Apply = func(ctx context.Context) error {
		_ = inner(ctx)
		h.rd.setListErr(errors.New("headscale unreachable")) // the read-back will fail
		return errors.New("deadline exceeded")
	}
	res, err := h.ex.Do(context.Background(), op)
	if !errors.Is(err, ErrUnknown) || res.Status != StatusUnknown {
		t.Fatalf("Do = %+v, %v; want unknown", res, err)
	}
	if h.rpcs.Load() != 1 {
		t.Errorf("rpcs = %d, want 1", h.rpcs.Load())
	}
	if got := h.results(); !equalStrings(got, []string{"started", "unknown"}) {
		t.Errorf("audit = %v", got)
	}
	alerts := h.openAlerts()
	if len(alerts) != 1 || alerts[0].Kind != AlertUnverified {
		t.Fatalf("alerts = %+v, want one %s", alerts, AlertUnverified)
	}
}

// AC7: a secret field reaches the audit log, the logs, the alerts and the errors only as a mask.
func TestExecutor_AuditHasNoSecret(t *testing.T) {
	const secret = "hskey-auth-SECRET-VALUE-123"
	h := newHarness(t)
	op := Op{
		Actor:  testActor,
		Kind:   KindPreAuthCreate,
		Target: "preauth:user:10",
		Diff: audit.Diff{
			{Field: "user", After: "carol"},
			{Field: "key", After: secret, Secret: true},
		},
		Apply:  func(context.Context) error { h.rpcs.Add(1); return fmt.Errorf("rpc failed for %s", secret) },
		Verify: func(context.Context, Reader) (bool, error) { return false, fmt.Errorf("lookup %s failed", secret) },
	}
	res, err := h.ex.Do(context.Background(), op)
	if err == nil {
		t.Fatal("expected an error")
	}
	var sb strings.Builder
	sb.WriteString(err.Error() + "\n" + res.Note + "\n" + h.logBuf.String() + "\n")
	rows, qerr := h.store.DB().QueryContext(context.Background(), `SELECT actor, event, target, diff, result FROM audit_events`)
	if qerr != nil {
		t.Fatal(qerr)
	}
	defer func() { _ = rows.Close() }()
	n := 0
	for rows.Next() {
		var a, e, tg, d, r string
		if err := rows.Scan(&a, &e, &tg, &d, &r); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&sb, "%s|%s|%s|%s|%s\n", a, e, tg, d, r)
		n++
	}
	if n == 0 {
		t.Fatal("no audit rows")
	}
	arows, qerr := h.store.DB().QueryContext(context.Background(), `SELECT kind, source FROM alerts`)
	if qerr != nil {
		t.Fatal(qerr)
	}
	defer func() { _ = arows.Close() }()
	for arows.Next() {
		var k, s string
		_ = arows.Scan(&k, &s)
		sb.WriteString(k + "|" + s + "\n")
	}
	if strings.Contains(sb.String(), secret) {
		t.Fatalf("secret leaked:\n%s", sb.String())
	}
	if !strings.Contains(sb.String(), audit.Mask) {
		t.Errorf("mask missing:\n%s", sb.String())
	}
}

// AC8: an operation without an actor is refused before anything happens.
func TestExecutor_ActorRequired(t *testing.T) {
	for _, actor := range []string{"", "   "} {
		h := newHarness(t)
		op := h.renameOp(1, "x")
		op.Actor = actor
		_, err := h.ex.Do(context.Background(), op)
		if !errors.Is(err, ErrActorRequired) {
			t.Errorf("actor %q: err = %v", actor, err)
		}
		if h.rpcs.Load() != 0 || len(h.events()) != 0 {
			t.Errorf("actor %q: rpcs %d, events %d", actor, h.rpcs.Load(), len(h.events()))
		}
	}
}

// AC9: a canceled caller context does not stop the read-back or the result record.
func TestExecutor_CanceledContextStillRecords(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	op := h.nodeOp(KindNodeRename, 1,
		func(n *admin.AdminNode) error { n.GivenName = "landed"; return nil },
		func(n admin.AdminNode) bool { return n.GivenName == "landed" })
	inner := op.Apply
	op.Apply = func(c context.Context) error {
		_ = inner(c)
		cancel() // the request is canceled while the RPC is in flight
		return context.Canceled
	}
	res, err := h.ex.Do(ctx, op)
	if err != nil || res.Status != StatusApplied {
		t.Fatalf("Do = %+v, %v; want applied", res, err)
	}
	if h.rd.ctxErrAtRead != nil {
		t.Errorf("read-back ran with a canceled context: %v", h.rd.ctxErrAtRead)
	}
	if got := h.results(); !equalStrings(got, []string{"started", "applied"}) {
		t.Errorf("audit = %v", got)
	}
}

// F3-016: an op may report facts it only learned from the read-back (the expiry a node ended up
// with); they ride on the terminal audit row, not on the intent row.
func TestExecutor_ObservedDiffOnResultRow(t *testing.T) {
	h := newHarness(t)
	op := h.renameOp(1, "renamed")
	var seen string
	inner := op.Verify
	op.Verify = func(ctx context.Context, r Reader) (bool, error) {
		seen = "read-back-fact"
		return inner(ctx, r)
	}
	op.Observed = func() audit.Diff { return audit.Diff{{Field: "observed.fact", After: seen}} }
	if _, err := h.ex.Do(context.Background(), op); err != nil {
		t.Fatalf("Do: %v", err)
	}
	evs := h.events()
	if len(evs) != 2 {
		t.Fatalf("events = %d, want started + applied", len(evs))
	}
	has := func(e audit.Event) bool {
		for _, c := range e.Diff {
			if c.Field == "observed.fact" && c.After == "read-back-fact" {
				return true
			}
		}
		return false
	}
	if has(evs[0]) {
		t.Errorf("started row carries the read-back fact: %+v", evs[0].Diff)
	}
	if !has(evs[1]) {
		t.Errorf("applied row lacks the read-back fact: %+v", evs[1].Diff)
	}
}

// F3-022 AC2/AC8: a Precheck runs under the writer lock before the intent record; a refusal
// stops the operation without an RPC and is audited as blocked.
func TestExecutor_Precheck(t *testing.T) {
	createOp := func(h *harness, pre func(ctx context.Context) error) Op {
		return Op{
			Actor: testActor, Kind: KindPreAuthCreate, Target: "preauth:new",
			Precheck: pre,
			Apply:    func(ctx context.Context) error { h.rpcs.Add(1); return nil },
			Verify:   func(ctx context.Context, r Reader) (bool, error) { return true, nil },
		}
	}

	t.Run("refusal stops before the RPC", func(t *testing.T) {
		h := newHarness(t)
		res, err := h.ex.Do(context.Background(), createOp(h, func(context.Context) error { return errors.New("kullanıcı uygun değil") }))
		if !errors.Is(err, ErrBlocked) || res.Status != StatusBlocked {
			t.Fatalf("Do = %+v, %v; want blocked", res, err)
		}
		if !strings.Contains(res.Note, "kullanıcı uygun değil") {
			t.Errorf("note = %q", res.Note)
		}
		if h.rpcs.Load() != 0 {
			t.Errorf("rpcs = %d, want 0", h.rpcs.Load())
		}
		if got := h.results(); !equalStrings(got, []string{"blocked"}) {
			t.Errorf("audit = %v, want [blocked]", got)
		}
	})

	t.Run("passes under the writer lock", func(t *testing.T) {
		h := newHarness(t)
		held := make(chan bool, 1)
		pre := func(context.Context) error {
			got := make(chan struct{})
			go func() { _ = change.WithWriterLock(func() error { close(got); return nil }) }()
			select {
			case <-got:
				held <- false // the lock was free: the check is not serialized
			case <-time.After(100 * time.Millisecond):
				held <- true
			}
			return nil
		}
		res, err := h.ex.Do(context.Background(), createOp(h, pre))
		if err != nil || res.Status != StatusApplied {
			t.Fatalf("Do = %+v, %v", res, err)
		}
		if !<-held {
			t.Error("precheck ran outside the writer lock")
		}
		if h.rpcs.Load() != 1 {
			t.Errorf("rpcs = %d, want 1", h.rpcs.Load())
		}
	})
}

// F3-021 AC5 mechanism: a Guard runs inside the writer lock, after the fresh read and the
// staleness check and before the intent audit and the RPC. Its evidence reaches the audit entries;
// a guard error refuses the op without any RPC (blocked, ErrGuard).
func TestExecutor_GuardRefusesBeforeRPC(t *testing.T) {
	h := newHarness(t)
	op := h.renameOp(1, "x")
	var sawNode admin.AdminNode
	op.Guard = func(ctx context.Context, target admin.AdminNode) (audit.Diff, error) {
		sawNode = target
		if target.ID != 1 {
			t.Errorf("guard target = node %d, want 1", target.ID)
		}
		return nil, errors.New("kullanıcı uygun değil: rolü yok")
	}
	res, err := h.ex.Do(context.Background(), op)
	if !errors.Is(err, ErrGuard) || res.Status != StatusBlocked {
		t.Fatalf("Do = %+v, %v; want ErrGuard/blocked", res, err)
	}
	if sawNode.ID != 1 {
		t.Fatalf("guard saw node %v", sawNode)
	}
	if h.rpcs.Load() != 0 {
		t.Errorf("rpcs = %d, want 0", h.rpcs.Load())
	}
	if got := h.results(); !equalStrings(got, []string{"blocked"}) {
		t.Fatalf("audit = %v, want [blocked]", got)
	}
	noteOK := false
	for _, c := range h.events()[0].Diff {
		if c.Field == "note" && strings.Contains(c.After, "rolü yok") {
			noteOK = true
		}
	}
	if !noteOK {
		t.Errorf("refusal note lacks the guard reason: %+v", h.events()[0].Diff)
	}
}

// The guard's evidence is part of the started and result entries next to the op's own diff.
func TestExecutor_GuardEvidenceAudited(t *testing.T) {
	h := newHarness(t)
	op := h.renameOp(1, "renamed")
	op.Guard = func(ctx context.Context, target admin.AdminNode) (audit.Diff, error) {
		return audit.Diff{
			{Field: "zitadel_kullanıcı", After: "123456"},
			{Field: "hesap_durumu", After: "active"},
			{Field: "roller", After: "vpn_user, vpn_admin"},
		}, nil
	}
	if _, err := h.ex.Do(context.Background(), op); err != nil {
		t.Fatalf("Do: %v", err)
	}
	for _, e := range h.events() {
		if !hasChange(e.Diff, "zitadel_kullanıcı", "123456") ||
			!hasChange(e.Diff, "hesap_durumu", "active") ||
			!hasChange(e.Diff, "roller", "vpn_user, vpn_admin") ||
			!hasChange2(e.Diff, "given_name", "laptop", "renamed") {
			t.Errorf("entry %s lacks the evidence or the diff: %+v", e.Result, e.Diff)
		}
	}
}

func hasChange(d audit.Diff, field, after string) bool {
	for _, c := range d {
		if c.Field == field && c.After == after {
			return true
		}
	}
	return false
}

func hasChange2(d audit.Diff, field, before, after string) bool {
	for _, c := range d {
		if c.Field == field && c.Before == before && c.After == after {
			return true
		}
	}
	return false
}

// The guard runs after the staleness check: a stale op never reaches the guard, and a passing
// guard cannot save a stale op either.
func TestExecutor_GuardAfterStaleness(t *testing.T) {
	h := newHarness(t)
	op := h.renameOp(1, "x")
	guardRan := false
	op.Guard = func(ctx context.Context, target admin.AdminNode) (audit.Diff, error) {
		guardRan = true
		return nil, nil
	}
	h.rd.mutate(1, func(n *admin.AdminNode) { n.Tags = []string{"tag:other"} })
	if _, err := h.ex.Do(context.Background(), op); !errors.Is(err, ErrStale) {
		t.Fatalf("stale op: err = %v, want ErrStale", err)
	}
	if guardRan {
		t.Error("guard ran although the op was stale")
	}
}

// A guard failure leaves no alert: nothing was written, the refusal itself is the record.
func TestExecutor_GuardRefusalNoAlert(t *testing.T) {
	h := newHarness(t)
	op := h.renameOp(1, "x")
	op.Guard = func(ctx context.Context, target admin.AdminNode) (audit.Diff, error) {
		return nil, errors.New("reddedildi")
	}
	if _, err := h.ex.Do(context.Background(), op); !errors.Is(err, ErrGuard) {
		t.Fatalf("err = %v, want ErrGuard", err)
	}
	if len(h.openAlerts()) != 0 {
		t.Errorf("alerts = %v, want none", h.openAlerts())
	}
}
