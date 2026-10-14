package change

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/headscale"
	"github.com/nesiler/tagcess/internal/store"
)

const (
	beforePolicy = `{"acls":[],"groups":{"group:ops":["https://idp/9@"]}}`
	targetPolicy = `{"acls":[],"groups":{"group:ops":["https://idp/1@","https://idp/9@"]}}`
)

// fakeHeadscale records calls and holds one policy in memory. It is the same concurrency test fixture
// as the real client's method set, narrowed to what the pipeline uses.
type fakeHeadscale struct {
	mu    sync.Mutex
	calls []string
	args  map[string][]string

	policy string
	// getAfter overrides what GetPolicy returns once readCount exceeds 1 (the verification read).
	getAfter string
	// getErrAfter makes the verification read fail, modelling a Headscale that cannot be read back
	// after the write.
	getErrAfter error
	getCount    int

	checkErr error
	setErr   error
	// setErrCommitted makes SetPolicy report an error after it committed the policy, modelling an
	// RPC that fails on the way back.
	setErrCommitted error
	// cancelOnSet is called by SetPolicy after it commits, letting a test cancel the request context
	// in flight (the server committed but the RPC never returned).
	cancelOnSet func()
	expireErr   map[uint64]error

	// checkBlock, when set, holds every CheckPolicy until it is closed; it lets a test observe
	// whether two applies overlap.
	checkBlock chan struct{}

	inFlight    int
	maxInFlight int
}

func newFake() *fakeHeadscale {
	return &fakeHeadscale{policy: beforePolicy, args: map[string][]string{}, expireErr: map[uint64]error{}}
}

func (f *fakeHeadscale) record(name string, args ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, name)
	f.args[name] = append(f.args[name], args...)
}

func (f *fakeHeadscale) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *fakeHeadscale) MaxInFlight() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.maxInFlight
}

func (f *fakeHeadscale) GetPolicy(ctx context.Context) (headscale.Policy, error) {
	f.record("GetPolicy")
	if err := ctx.Err(); err != nil {
		return headscale.Policy{}, err
	}
	f.mu.Lock()
	f.getCount++
	n := f.getCount
	after := f.getAfter
	getErr := f.getErrAfter
	cur := f.policy
	f.mu.Unlock()
	if n > 1 && getErr != nil {
		return headscale.Policy{}, getErr
	}
	if n > 1 && after != "" {
		return headscale.Policy{Text: after}, nil
	}
	return headscale.Policy{Text: cur}, nil
}

func (f *fakeHeadscale) CheckPolicy(_ context.Context, policy string) error {
	f.mu.Lock()
	f.inFlight++
	if f.inFlight > f.maxInFlight {
		f.maxInFlight = f.inFlight
	}
	block := f.checkBlock
	err := f.checkErr
	f.mu.Unlock()
	f.record("CheckPolicy", policy)
	if block != nil {
		<-block
	}
	f.mu.Lock()
	f.inFlight--
	f.mu.Unlock()
	return err
}

func (f *fakeHeadscale) SetPolicy(ctx context.Context, policy string) (headscale.Policy, error) {
	f.record("SetPolicy", policy)
	f.mu.Lock()
	if f.setErrCommitted != nil {
		f.policy = policy
		err := f.setErrCommitted
		f.mu.Unlock()
		return headscale.Policy{Text: policy}, err
	}
	if f.setErr != nil {
		err := f.setErr
		f.mu.Unlock()
		return headscale.Policy{}, err
	}
	f.policy = policy
	cancel := f.cancelOnSet
	f.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if err := ctx.Err(); err != nil {
		return headscale.Policy{Text: policy}, err
	}
	return headscale.Policy{Text: policy}, nil
}

func (f *fakeHeadscale) ExpireNode(_ context.Context, id uint64) (headscale.Node, error) {
	f.record("ExpireNode", fmt.Sprint(id))
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.expireErr[id]; err != nil {
		return headscale.Node{}, err
	}
	return headscale.Node{ID: id}, nil
}

func (f *fakeHeadscale) SetErr(err error) { f.setErr = err }
func (f *fakeHeadscale) SetErrCommitted(err error) {
	f.setErrCommitted = err
}
func (f *fakeHeadscale) SetGetAfter(p string) {
	f.getAfter = p
}
func (f *fakeHeadscale) SetGetErrAfter(err error)          { f.getErrAfter = err }
func (f *fakeHeadscale) SetCancelOnSet(fn func())          { f.cancelOnSet = fn }
func (f *fakeHeadscale) SetExpireErr(id uint64, err error) { f.expireErr[id] = err }
func (f *fakeHeadscale) SetCheckErr(err error)             { f.checkErr = err }
func (f *fakeHeadscale) BlockCheck(ch chan struct{})       { f.checkBlock = ch }

// fakeDryRun is a controllable dry-run source; it defaults to off. Tests reach it through
// p.dryRun.(*fakeDryRun).
type fakeDryRun struct {
	mu  sync.Mutex
	on  bool
	err error
}

func (f *fakeDryRun) DryRun(context.Context) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.on, f.err
}

func (f *fakeDryRun) set(on bool) {
	f.mu.Lock()
	f.on = on
	f.mu.Unlock()
}

func newPipeline(t *testing.T) (*Pipeline, *fakeHeadscale, *store.Store) {
	t.Helper()
	s, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "tagcess.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	hs := newFake()
	return New(hs, s.Queries(), audit.New(s.Queries()), &fakeDryRun{}), hs, s
}

// versionOf is the version of the proposal currently stored for a pending change, as the sync page
// would render it.
func versionOf(t *testing.T, s *store.Store, id int64) string {
	t.Helper()
	var after string
	if err := s.DB().QueryRowContext(context.Background(),
		`SELECT after_summary FROM changes WHERE id = ?`, id).Scan(&after); err != nil {
		t.Fatalf("read after_summary: %v", err)
	}
	return ProposalVersion(after)
}

func baseRequest() Request {
	return Request{
		Kind:    KindPolicy,
		Actor:   "dev@example.com",
		Trigger: "manual",
		Summary: "1 eklendi",
		Target:  []byte(targetPolicy),
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

// AC1: the apply path checks, writes and verifies the policy, expires the nodes, and records audit
// plus sync_runs.
func TestApply_HappyPath(t *testing.T) {
	ctx := context.Background()
	p, hs, s := newPipeline(t)

	req := baseRequest()
	req.Expire = []uint64{7, 8}
	res, err := p.Submit(ctx, req)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if !res.Applied || res.Status != StatusApplied {
		t.Fatalf("result = %+v, want applied", res)
	}

	// Verification Subsequence: CheckPolicy -> SetPolicy -> GetPolicy, then every expire.
	want := []string{"GetPolicy", "CheckPolicy", "SetPolicy", "GetPolicy", "ExpireNode", "ExpireNode"}
	got := hs.Calls()
	if len(got) != len(want) {
		t.Fatalf("calls = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("call %d = %q, want %q (all: %v)", i, got[i], want[i], got)
		}
	}

	if n := count(t, s, `SELECT count(*) FROM changes WHERE status = 'applied'`); n != 1 {
		t.Errorf("applied changes = %d, want 1", n)
	}
	if n := count(t, s, `SELECT count(*) FROM audit_events WHERE event = 'policy.apply' AND result = 'applied'`); n != 1 {
		t.Errorf("applied audit events = %d, want 1", n)
	}
	if n := count(t, s, `SELECT count(*) FROM sync_runs WHERE result = 'applied'`); n != 1 {
		t.Errorf("applied sync_runs = %d, want 1", n)
	}
}

// AC2: a rejected CheckPolicy stops the pipeline before any write.
func TestApply_CheckFailsNothingApplied(t *testing.T) {
	ctx := context.Background()
	p, hs, s := newPipeline(t)
	hs.SetCheckErr(&headscale.PolicyError{Message: "bad group"})

	res, err := p.Submit(ctx, baseRequest())
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if res.Applied || res.Status != StatusFailed {
		t.Fatalf("result = %+v, want failed", res)
	}
	for _, c := range hs.Calls() {
		if c == "SetPolicy" || c == "ExpireNode" {
			t.Fatalf("wrote before the check passed: %v", hs.Calls())
		}
	}
	if n := count(t, s, `SELECT count(*) FROM changes WHERE status = 'failed'`); n != 1 {
		t.Errorf("failed changes = %d, want 1", n)
	}
}

// AC3: a plan that needs approval is stored and nothing is applied.
func TestApply_PendingApprovalStored(t *testing.T) {
	ctx := context.Background()
	p, hs, s := newPipeline(t)

	req := baseRequest()
	req.NeedsApproval = true
	req.Reason = "eşik aşıldı"
	res, err := p.Submit(ctx, req)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if res.Status != StatusPendingApproval || res.Applied {
		t.Fatalf("result = %+v, want pending", res)
	}
	if len(hs.Calls()) != 0 {
		t.Fatalf("pending approval touched Headscale: %v", hs.Calls())
	}
	if n := count(t, s, `SELECT count(*) FROM changes WHERE status = 'pending_approval'`); n != 1 {
		t.Errorf("pending changes = %d, want 1", n)
	}
}

// AC4: approval recomputes; a changed plan is offered again instead of being applied.
func TestApply_ApprovalRecomputes(t *testing.T) {
	ctx := context.Background()
	p, hs, s := newPipeline(t)

	req := baseRequest()
	req.NeedsApproval = true
	pending, err := p.Submit(ctx, req)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}

	changed := baseRequest()
	changed.Target = []byte(`{"acls":[],"groups":{"group:ops":["https://idp/2@"]}}`)

	res, err := p.Approve(ctx, "approver@example.com", pending.ChangeID, versionOf(t, s, pending.ChangeID),
		func(context.Context) (Request, error) { return changed, nil })
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if res.Status != StatusNeedsReapproval || res.Applied {
		t.Fatalf("first approve = %+v, want needs_reapproval", res)
	}
	for _, c := range hs.Calls() {
		if c == "SetPolicy" {
			t.Fatal("a changed plan was applied")
		}
	}
	var status, after string
	if err := s.DB().QueryRowContext(ctx, `SELECT status, after_summary FROM changes WHERE id = ?`, pending.ChangeID).
		Scan(&status, &after); err != nil {
		t.Fatalf("read change: %v", err)
	}
	if status != StatusPendingApproval {
		t.Errorf("status = %q, want pending_approval", status)
	}
	if after == "" {
		t.Error("the new proposal was not stored")
	}

	// Approving the now-stored plan applies it.
	res, err = p.Approve(ctx, "approver@example.com", pending.ChangeID, versionOf(t, s, pending.ChangeID),
		func(context.Context) (Request, error) { return changed, nil })
	if err != nil {
		t.Fatalf("second Approve: %v", err)
	}
	if !res.Applied || res.Status != StatusApplied {
		t.Fatalf("second approve = %+v, want applied", res)
	}
	got := hs.args["SetPolicy"]
	if len(got) != 1 || got[0] != string(changed.Target) {
		t.Fatalf("SetPolicy args = %v, want the new target", got)
	}
}

// A stale approval form (its proposal was replaced by a reapproval) must be refused and apply
// nothing: the operator never saw the plan that would be written (Y-03.4).
func TestApply_StaleProposalRefused(t *testing.T) {
	ctx := context.Background()
	p, hs, s := newPipeline(t)

	req := baseRequest()
	req.NeedsApproval = true
	pending, err := p.Submit(ctx, req)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	displayed := versionOf(t, s, pending.ChangeID)

	// A concurrent reapproval replaces the stored proposal with a different (unseen) one.
	changed := baseRequest()
	changed.Target = []byte(`{"acls":[],"groups":{"group:ops":["https://idp/2@"]}}`)
	if _, err := p.Approve(ctx, "other@example.com", pending.ChangeID, displayed,
		func(context.Context) (Request, error) { return changed, nil }); err != nil {
		t.Fatalf("reapproval: %v", err)
	}

	// The stale form still carries the old version: it is refused and applies nothing.
	res, err := p.Approve(ctx, "approver@example.com", pending.ChangeID, displayed,
		func(context.Context) (Request, error) { return changed, nil })
	if !errors.Is(err, ErrProposalStale) {
		t.Fatalf("stale approve err = %v, want ErrProposalStale", err)
	}
	if res.Applied {
		t.Fatal("a stale approval applied")
	}
	for _, c := range hs.Calls() {
		if c == "SetPolicy" || c == "ExpireNode" {
			t.Fatalf("a stale approval wrote to Headscale: %v", hs.Calls())
		}
	}
}

// Dry-run is read at the protected write boundary: a toggle that landed after the plan was evaluated
// must still stop the write, even when the request itself was not marked dry-run (Y-06).
func TestApply_DryRunReadAtWriteBoundary(t *testing.T) {
	ctx := context.Background()
	p, hs, s := newPipeline(t)
	p.dryRun.(*fakeDryRun).set(true)

	res, err := p.Submit(ctx, baseRequest())
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if res.Status != StatusDryRun || res.Applied {
		t.Fatalf("result = %+v, want dry_run", res)
	}
	if len(hs.Calls()) != 0 {
		t.Fatalf("dry run at the write boundary touched Headscale: %v", hs.Calls())
	}
	if n := count(t, s, `SELECT count(*) FROM changes`); n != 0 {
		t.Errorf("dry run wrote %d change rows, want 0", n)
	}
	if n := count(t, s, `SELECT count(*) FROM sync_runs WHERE result = 'dry_run'`); n != 1 {
		t.Errorf("dry-run sync_runs = %d, want 1", n)
	}
}

// A dry-run toggle that lands after a plan was evaluated but before the queued apply takes the writer
// lock must stop the write (Y-06). The toggle writes the same dry_run setting web.SettingDryRun writes,
// under the same writer lock, so the boundary read sees it. No sleeps: the plan is evaluated first,
// then the toggle runs, then the apply.
func TestApply_DryRunToggleBeforeApplyStopsWrite(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(ctx, filepath.Join(t.TempDir(), "tagcess.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	hs := newFake()
	p := New(hs, s.Queries(), audit.New(s.Queries()), s)

	// The store seeds dry-run on (Y-06.2); turn it off so the toggle below really flips it.
	setStoreDryRun(t, ctx, s, false)

	// The plan is already evaluated against the live policy; the operator then turns dry-run on before
	// the queued apply enters the writer lock.
	req := baseRequest()
	req.SourcePolicy = []byte(beforePolicy)
	setStoreDryRun(t, ctx, s, true)

	res, err := p.Submit(ctx, req)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if res.Status != StatusDryRun || res.Applied {
		t.Fatalf("result = %+v, want dry_run", res)
	}
	if len(hs.Calls()) != 0 {
		t.Fatalf("the queued apply wrote to Headscale after the toggle: %v", hs.Calls())
	}
	if n := count(t, s, `SELECT count(*) FROM changes`); n != 0 {
		t.Errorf("dry run wrote %d change rows, want 0", n)
	}
	if n := count(t, s, `SELECT count(*) FROM sync_runs WHERE result = 'dry_run'`); n != 1 {
		t.Errorf("dry-run sync_runs = %d, want 1", n)
	}
}

// setStoreDryRun flips the dry_run setting under the writer lock, exactly as web.SettingDryRun does,
// so a test can order a toggle against an apply without sleeps.
func setStoreDryRun(t *testing.T, ctx context.Context, s *store.Store, on bool) {
	t.Helper()
	value := "false"
	if on {
		value = "true"
	}
	err := WithWriterLock(func() error {
		_, err := s.DB().ExecContext(ctx, `UPDATE settings SET value = ? WHERE key = 'dry_run'`, value)
		return err
	})
	if err != nil {
		t.Fatalf("set dry_run=%v: %v", on, err)
	}
}

// AC5: two applies are serialized by the single writer lock.
func TestApply_SerializedByLock(t *testing.T) {
	p, hs, _ := newPipeline(t)

	block := make(chan struct{})
	hs.BlockCheck(block)

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, _ = p.Submit(context.Background(), baseRequest())
		}()
	}
	close(start)
	// Give the first apply time to reach CheckPolicy, then let them run.
	time.Sleep(50 * time.Millisecond)
	close(block)
	wg.Wait()

	if n := hs.MaxInFlight(); n != 1 {
		t.Fatalf("max concurrent applies = %d, want 1", n)
	}
}

// AC6: dry run writes only sync_runs and never touches Headscale.
func TestApply_DryRunNoWrites(t *testing.T) {
	ctx := context.Background()
	p, hs, s := newPipeline(t)

	req := baseRequest()
	req.DryRun = true
	res, err := p.Submit(ctx, req)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if res.Applied {
		t.Fatal("dry run applied")
	}
	if len(hs.Calls()) != 0 {
		t.Fatalf("dry run touched Headscale: %v", hs.Calls())
	}
	if n := count(t, s, `SELECT count(*) FROM changes`); n != 0 {
		t.Errorf("dry run wrote %d change rows, want 0", n)
	}
	if n := count(t, s, `SELECT count(*) FROM sync_runs`); n != 1 {
		t.Errorf("dry run sync_runs = %d, want 1", n)
	}
}

// AC7a: a policy that does not read back as written must never be "rolled back" to the previous
// policy when that could widen access. Here the write removed group:ops and the previous policy
// granted it, so restoring the previous policy would re-open access; the live state is kept, the
// change is failed and a critical mismatch alert is raised (rule 7).
func TestApply_VerifyMismatchDoesNotWiden(t *testing.T) {
	ctx := context.Background()
	p, hs, s := newPipeline(t)
	// The previous policy grants group:ops; the target removes it.
	hs.policy = `{"acls":[],"groups":{"group:ops":["https://idp/9@"]}}`
	// The readback is a third state: neither the target nor the previous policy.
	hs.SetGetAfter(`{"acls":[],"groups":{"group:dev":["https://idp/3@"]}}`)

	req := baseRequest()
	req.Target = []byte(`{"acls":[],"groups":{}}`) // removes group:ops
	res, err := p.Submit(ctx, req)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if res.Applied || res.Status != StatusFailed {
		t.Fatalf("result = %+v, want failed", res)
	}
	sets := hs.args["SetPolicy"]
	if len(sets) != 1 || sets[0] != `{"acls":[],"groups":{}}` {
		t.Fatalf("SetPolicy calls = %v, want only the attempted target (no widening rollback)", sets)
	}
	if n := count(t, s, `SELECT count(*) FROM alerts WHERE kind = ?`, AlertPolicyMismatch); n != 1 {
		t.Errorf("mismatch alerts = %d, want 1", n)
	}
}

// AC9: the terminal record writer retries a transient failure so an applied write is never lost to a
// blip.
func TestRetryRecord_RecoversTransientFailure(t *testing.T) {
	ctx := context.Background()
	attempts := 0
	err := retryRecord(ctx, func() error {
		attempts++
		if attempts < 2 {
			return errors.New("database is locked")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("retryRecord: %v", err)
	}
	if attempts != 2 {
		t.Errorf("attempts = %d, want 2", attempts)
	}
}

// AC9: a permanent failure still surfaces after the bounded attempts.
func TestRetryRecord_GivesUpAfterAttempts(t *testing.T) {
	ctx := context.Background()
	attempts := 0
	err := retryRecord(ctx, func() error {
		attempts++
		return errors.New("database is locked")
	})
	if err == nil {
		t.Fatal("retryRecord: want an error")
	}
	if attempts != recordAttempts {
		t.Errorf("attempts = %d, want %d", attempts, recordAttempts)
	}
}

// AC7b: a half-finished expiry must not restore the (wider) previous policy; the verified, narrower
// policy stays and the failure is alerted (rule 7: never widen access).
func TestApply_ExpireFailureKeepsVerifiedPolicy(t *testing.T) {
	ctx := context.Background()
	p, hs, s := newPipeline(t)
	hs.SetExpireErr(8, errors.New("headscale down"))

	req := baseRequest()
	req.Expire = []uint64{7, 8}
	res, err := p.Submit(ctx, req)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if res.Applied || res.Status != StatusFailed {
		t.Fatalf("result = %+v, want failed", res)
	}
	sets := hs.args["SetPolicy"]
	if len(sets) != 1 || sets[0] != targetPolicy {
		t.Fatalf("SetPolicy calls = %v, want only the verified target (no widening rollback)", sets)
	}
	if n := count(t, s, `SELECT count(*) FROM alerts WHERE kind = ?`, AlertPolicyExpireFailed); n != 1 {
		t.Errorf("expire-failed alerts = %d, want 1", n)
	}
}

// When the verification readback fails after a successful SetPolicy, the write is kept (never rolled
// back to a possibly wider policy) and a critical alert is raised instead.
func TestApply_ReadbackFailsKeepsVerifiedPolicy(t *testing.T) {
	ctx := context.Background()
	p, hs, s := newPipeline(t)
	hs.SetGetErrAfter(errors.New("headscale down"))

	res, err := p.Submit(ctx, baseRequest())
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if res.Applied || res.Status != StatusFailed {
		t.Fatalf("result = %+v, want failed", res)
	}
	sets := hs.args["SetPolicy"]
	if len(sets) != 1 || sets[0] != targetPolicy {
		t.Fatalf("SetPolicy calls = %v, want only the verified target (no widening rollback)", sets)
	}
	if n := count(t, s, `SELECT count(*) FROM alerts WHERE kind = ?`, AlertPolicyUnverified); n != 1 {
		t.Errorf("unverified alerts = %d, want 1", n)
	}
}

// A SetPolicy error whose readback shows a third state (neither target nor previous) is ambiguous:
// the pipeline must not guess by restoring the previous policy, which could widen access.
func TestApply_SetPolicyErrorUnexpectedPolicyNotRestored(t *testing.T) {
	ctx := context.Background()
	p, hs, s := newPipeline(t)
	hs.SetErr(errors.New("headscale down"))
	hs.SetGetAfter(`{"acls":[],"groups":{"group:x":["https://idp/3@"]}}`)

	res, err := p.Submit(ctx, baseRequest())
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if res.Applied || res.Status != StatusFailed {
		t.Fatalf("result = %+v, want failed", res)
	}
	sets := hs.args["SetPolicy"]
	if len(sets) != 1 || sets[0] != targetPolicy {
		t.Fatalf("SetPolicy calls = %v, want only the attempted target (no guess rollback)", sets)
	}
	if n := count(t, s, `SELECT count(*) FROM alerts WHERE kind = ?`, AlertPolicyUnverified); n != 1 {
		t.Errorf("unverified alerts = %d, want 1", n)
	}
}

// A caller context canceled while SetPolicy is in flight must not blind the readback: the server may
// have committed, so the readback runs on a fresh bounded context and a committed policy is never
// rolled back to the possibly wider previous one (rule 7).
func TestApply_CanceledContextReadbackDoesNotWiden(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, hs, s := newPipeline(t)
	hs.SetCancelOnSet(cancel)

	res, err := p.Submit(ctx, baseRequest())
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if !res.Applied || res.Status != StatusApplied {
		t.Fatalf("result = %+v, want applied (the write committed)", res)
	}
	sets := hs.args["SetPolicy"]
	if len(sets) != 1 || sets[0] != targetPolicy {
		t.Fatalf("SetPolicy calls = %v, want only the verified target (no widening rollback)", sets)
	}
	if n := count(t, s, `SELECT count(*) FROM alerts`); n != 0 {
		t.Errorf("alerts = %d, want 0", n)
	}
}

// A failure to record the applied write (here: the change row cannot be inserted) must not suppress
// the terminal audit or the critical alert: both are written through an independent path.
func TestApply_BookkeepingErrorStillAlerts(t *testing.T) {
	ctx := context.Background()
	p, _, s := newPipeline(t)
	if _, err := s.DB().ExecContext(ctx, `DROP TABLE changes`); err != nil {
		t.Fatalf("drop changes: %v", err)
	}

	if _, err := p.Submit(ctx, baseRequest()); err == nil {
		t.Fatal("Submit with an unwritable change row: want an error")
	}
	if n := count(t, s, `SELECT count(*) FROM audit_events WHERE event = 'policy.apply' AND result = 'applied'`); n != 1 {
		t.Errorf("terminal audit events = %d, want 1", n)
	}
	if n := count(t, s, `SELECT count(*) FROM alerts WHERE kind = ?`, AlertPolicyBookkeepingFailed); n != 1 {
		t.Errorf("bookkeeping alerts = %d, want 1", n)
	}
}

// The same survives on the failure path: a verification mismatch that cannot be recorded still
// writes the terminal audit and the critical alert.
func TestApply_FailedBookkeepingErrorStillAlerts(t *testing.T) {
	ctx := context.Background()
	p, hs, s := newPipeline(t)
	hs.SetGetAfter(`{"acls":[],"groups":{}}`)
	if _, err := s.DB().ExecContext(ctx, `DROP TABLE changes`); err != nil {
		t.Fatalf("drop changes: %v", err)
	}

	if _, err := p.Submit(ctx, baseRequest()); err == nil {
		t.Fatal("Submit with an unwritable change row: want an error")
	}
	if n := count(t, s, `SELECT count(*) FROM audit_events WHERE event = 'policy.apply_failed'`); n != 1 {
		t.Errorf("terminal audit events = %d, want 1", n)
	}
	if n := count(t, s, `SELECT count(*) FROM alerts WHERE kind = ?`, AlertPolicyMismatch); n != 1 {
		t.Errorf("mismatch alerts = %d, want 1", n)
	}
	if n := count(t, s, `SELECT count(*) FROM alerts WHERE kind = ?`, AlertPolicyBookkeepingFailed); n != 1 {
		t.Errorf("bookkeeping alerts = %d, want 1", n)
	}
}

// AC9 (audit failure after a verified apply): if only the terminal audit record cannot be written
// after the external write has been verified, the applied change must still be recorded and the
// critical bookkeeping alert raised, so the applied write is never silently lost. The pre-write
// "policy.apply_start" audit must keep working, so the table is made to fail only on the terminal
// event.
func TestApply_AuditFailureAfterApplyStillRecords(t *testing.T) {
	ctx := context.Background()
	p, _, s := newPipeline(t)
	_, err := s.DB().ExecContext(ctx, `
CREATE TRIGGER audit_terminal_unavailable BEFORE INSERT ON audit_events
WHEN NEW.event = 'policy.apply'
BEGIN
  SELECT RAISE(ABORT, 'audit log unavailable');
END`)
	if err != nil {
		t.Fatalf("create trigger: %v", err)
	}

	req := baseRequest()
	req.Expire = []uint64{7}
	if _, err := p.Submit(ctx, req); err == nil {
		t.Fatal("Submit with an unwritable terminal audit: want an error")
	}
	// The external write happened and is still recorded, so it is not lost.
	if n := count(t, s, `SELECT count(*) FROM changes WHERE status = 'applied'`); n != 1 {
		t.Errorf("applied changes = %d, want 1", n)
	}
	if n := count(t, s, `SELECT count(*) FROM sync_runs WHERE result = 'applied'`); n != 1 {
		t.Errorf("applied sync_runs = %d, want 1", n)
	}
	if n := count(t, s, `SELECT count(*) FROM alerts WHERE kind = ?`, AlertPolicyBookkeepingFailed); n != 1 {
		t.Errorf("bookkeeping alerts = %d, want 1", n)
	}
}

// A dry run turned on while a change waits for approval must not write on approval (Y-06.1).
func TestApply_ApproveHonorsDryRun(t *testing.T) {
	ctx := context.Background()
	p, hs, s := newPipeline(t)

	req := baseRequest()
	req.NeedsApproval = true
	pending, err := p.Submit(ctx, req)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}

	dry := baseRequest()
	dry.DryRun = true
	res, err := p.Approve(ctx, "approver@example.com", pending.ChangeID, versionOf(t, s, pending.ChangeID),
		func(context.Context) (Request, error) { return dry, nil })
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if res.Status != StatusDryRun || res.Applied {
		t.Fatalf("approve under dry run = %+v, want dry_run", res)
	}
	for _, c := range hs.Calls() {
		if c == "SetPolicy" || c == "ExpireNode" {
			t.Fatalf("dry run approval wrote to Headscale: %v", hs.Calls())
		}
	}
	var status string
	if err := s.DB().QueryRowContext(ctx, `SELECT status FROM changes WHERE id = ?`, pending.ChangeID).Scan(&status); err != nil {
		t.Fatalf("read change: %v", err)
	}
	if status != StatusPendingApproval {
		t.Errorf("status = %q, want it to stay pending_approval", status)
	}
}

// A dry run wins over a blocked flag: it must still only write sync_runs (Y-06).
func TestApply_BlockedDryRunOnlySyncRun(t *testing.T) {
	ctx := context.Background()
	p, hs, s := newPipeline(t)

	req := baseRequest()
	req.Blocked = true
	req.DryRun = true
	req.Reason = "referanslı grup"
	res, err := p.Submit(ctx, req)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if res.Status != StatusDryRun || res.Applied {
		t.Fatalf("result = %+v, want dry_run", res)
	}
	if len(hs.Calls()) != 0 {
		t.Fatalf("dry run touched Headscale: %v", hs.Calls())
	}
	if n := count(t, s, `SELECT count(*) FROM changes`); n != 0 {
		t.Errorf("dry run wrote %d change rows, want 0", n)
	}
	if n := count(t, s, `SELECT count(*) FROM sync_runs`); n != 1 {
		t.Errorf("dry run sync_runs = %d, want 1", n)
	}
}

// A plan computed from a policy that changed since must not overwrite the live policy.
func TestApply_StalePolicyNotApplied(t *testing.T) {
	ctx := context.Background()
	p, hs, s := newPipeline(t)
	hs.policy = `{"acls":[],"groups":{"group:x":["https://idp/1@"]}}` // changed after the plan

	req := baseRequest()
	req.SourcePolicy = []byte(beforePolicy)
	res, err := p.Submit(ctx, req)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if res.Applied || res.Status != StatusFailed {
		t.Fatalf("result = %+v, want failed", res)
	}
	for _, c := range hs.Calls() {
		if c == "CheckPolicy" || c == "SetPolicy" {
			t.Fatalf("a stale plan reached Headscale: %v", hs.Calls())
		}
	}
	if n := count(t, s, `SELECT count(*) FROM alerts WHERE kind = ?`, AlertPolicyStale); n != 1 {
		t.Errorf("stale alerts = %d, want 1", n)
	}
}

// An approval whose replan fails must still record the failure (a zero request has an empty trigger,
// which the sync_runs CHECK rejects if not filled from the approval).
func TestApply_ApproveReplanErrorIsRecorded(t *testing.T) {
	ctx := context.Background()
	p, hs, s := newPipeline(t)

	req := baseRequest()
	req.NeedsApproval = true
	pending, err := p.Submit(ctx, req)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}

	res, err := p.Approve(ctx, "approver@example.com", pending.ChangeID, versionOf(t, s, pending.ChangeID),
		func(context.Context) (Request, error) { return Request{}, errors.New("read failed") })
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if res.Status != StatusFailed || res.Applied {
		t.Fatalf("result = %+v, want failed", res)
	}
	if n := count(t, s, `SELECT count(*) FROM sync_runs WHERE trigger = 'manual' AND result = 'failed'`); n != 1 {
		t.Errorf("manual failed sync_runs = %d, want 1", n)
	}
	for _, c := range hs.Calls() {
		if c == "SetPolicy" {
			t.Fatalf("a failed replan wrote to Headscale: %v", hs.Calls())
		}
	}
}

// A SetPolicy error that still committed the policy is detected by reading it back: the change is
// applied, not silently marked failed.
func TestApply_SetPolicyErrorCommitted(t *testing.T) {
	ctx := context.Background()
	p, hs, s := newPipeline(t)
	hs.SetErrCommitted(errors.New("timeout on the way back"))

	res, err := p.Submit(ctx, baseRequest())
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if !res.Applied || res.Status != StatusApplied {
		t.Fatalf("result = %+v, want applied (the policy did commit)", res)
	}
	if n := count(t, s, `SELECT count(*) FROM alerts`); n != 0 {
		t.Errorf("alerts = %d, want 0", n)
	}
}

// A SetPolicy error that did not commit is a plain failure; nothing is restored or alerted.
func TestApply_SetPolicyErrorNotApplied(t *testing.T) {
	ctx := context.Background()
	p, hs, s := newPipeline(t)
	hs.SetErr(errors.New("headscale down"))

	res, err := p.Submit(ctx, baseRequest())
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if res.Applied || res.Status != StatusFailed {
		t.Fatalf("result = %+v, want failed", res)
	}
	sets := hs.args["SetPolicy"]
	if len(sets) != 1 || sets[0] != targetPolicy {
		t.Fatalf("SetPolicy calls = %v, want only the target", sets)
	}
	if n := count(t, s, `SELECT count(*) FROM alerts`); n != 0 {
		t.Errorf("alerts = %d, want 0", n)
	}
}

// A change needs an actor: A-01.1 requires knowing who did it.
func TestApply_RejectsMissingActor(t *testing.T) {
	p, hs, _ := newPipeline(t)
	req := baseRequest()
	req.Actor = "  "
	if _, err := p.Submit(context.Background(), req); err == nil {
		t.Fatal("Submit without an actor: want error")
	}
	if len(hs.Calls()) != 0 {
		t.Fatalf("missing actor still touched Headscale: %v", hs.Calls())
	}
}
