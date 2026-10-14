package change

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/nesiler/tagcess/internal/maintenance"
	"github.com/nesiler/tagcess/internal/policyrev"
	"github.com/nesiler/tagcess/internal/store"
)

// fakeGate is a controllable maintenance gate: it follows the real CheckWidening table for the state
// it holds and records every call.
type fakeGate struct {
	state   maintenance.State
	readErr error
	calls   []string
	// onCall runs inside CheckWidening, so a test can look at the world at the moment of the check.
	onCall func()
}

func (g *fakeGate) CheckWidening(_ context.Context, source string) error {
	g.calls = append(g.calls, source)
	if g.onCall != nil {
		g.onCall()
	}
	if g.readErr != nil {
		return fmt.Errorf("%w: durum okunamadı: %w", maintenance.ErrMaintenance, g.readErr)
	}
	switch {
	case g.state == maintenance.Off:
		return nil
	case g.state == maintenance.ReconcilePending && source == maintenance.SourceSync:
		return nil
	}
	return maintenance.ErrMaintenance
}

func gatedStore(t *testing.T, state maintenance.State) (*Pipeline, *fakeHeadscale, *fakeGate, *store.Store) {
	t.Helper()
	p, hs, s := newPipeline(t)
	g := &fakeGate{state: state}
	p.WithMaintenance(g)
	return p, hs, g, s
}

func gatedPipeline(t *testing.T, state maintenance.State) (*Pipeline, *fakeHeadscale, *fakeGate, func(query string, args ...any) int) {
	t.Helper()
	p, hs, g, s := gatedStore(t, state)
	return p, hs, g, func(query string, args ...any) int { return count(t, s, query, args...) }
}

func noPolicyWrite(t *testing.T, calls []string) {
	t.Helper()
	for _, c := range calls {
		if c == "SetPolicy" || c == "CheckPolicy" {
			t.Fatalf("policy was written or checked during maintenance: %v", calls)
		}
	}
}

func expireCalls(calls []string) int {
	n := 0
	for _, c := range calls {
		if c == "ExpireNode" {
			n++
		}
	}
	return n
}

// F3b-015 AC2: during an active maintenance a sync request does not write the policy, still expires
// the nodes, and the result says the policy was held.
func TestChange_MaintenanceSkipsPolicyKeepsExpire(t *testing.T) {
	ctx := context.Background()
	p, hs, g, cnt := gatedPipeline(t, maintenance.Active)

	req := baseRequest()
	req.Trigger = "periodic"
	req.Revision = RevisionMeta{Source: maintenance.SourceSync}
	req.Expire = []uint64{7, 8}
	res, err := p.Submit(ctx, req)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if !res.PolicyHeld || res.Applied || res.Status != StatusHeld {
		t.Fatalf("result = %+v, want held and not applied", res)
	}
	noPolicyWrite(t, hs.Calls())
	if n := expireCalls(hs.Calls()); n != 2 {
		t.Errorf("ExpireNode calls = %d, want 2 (calls: %v)", n, hs.Calls())
	}
	if len(g.calls) != 1 || g.calls[0] != maintenance.SourceSync {
		t.Errorf("gate calls = %v, want one sync check", g.calls)
	}
	if n := cnt(`SELECT count(*) FROM audit_events WHERE event = 'policy.held'`); n != 1 {
		t.Errorf("policy.held audit events = %d, want 1", n)
	}
	if n := cnt(`SELECT count(*) FROM audit_events WHERE event IN ('policy.apply_start', 'policy.apply')`); n != 0 {
		t.Errorf("apply audit events = %d, want 0", n)
	}
	if n := cnt(`SELECT count(*) FROM sync_runs WHERE result = 'held'`); n != 1 {
		t.Errorf("held sync_runs = %d, want 1", n)
	}
	if n := cnt(`SELECT count(*) FROM changes WHERE status = 'applied'`); n != 0 {
		t.Errorf("applied changes = %d, want 0", n)
	}
}

// A held sync request with no expiries is held too, and an expire that fails is alerted.
func TestChange_MaintenanceHeldWithoutExpireAndExpireFailure(t *testing.T) {
	ctx := context.Background()

	t.Run("no expire", func(t *testing.T) {
		p, hs, _, _ := gatedPipeline(t, maintenance.Active)
		req := baseRequest()
		req.Revision = RevisionMeta{Source: maintenance.SourceSync}
		res, err := p.Submit(ctx, req)
		if err != nil || !res.PolicyHeld {
			t.Fatalf("Submit = %+v, %v; want held", res, err)
		}
		if got := hs.Calls(); len(got) != 0 {
			t.Errorf("Headscale calls = %v, want none", got)
		}
	})

	t.Run("expire fails", func(t *testing.T) {
		p, hs, _, cnt := gatedPipeline(t, maintenance.Active)
		hs.SetExpireErr(8, errors.New("headscale down"))
		req := baseRequest()
		req.Revision = RevisionMeta{Source: maintenance.SourceSync}
		req.Expire = []uint64{7, 8, 9}
		res, err := p.Submit(ctx, req)
		if err != nil {
			t.Fatalf("Submit: %v", err)
		}
		if !res.PolicyHeld || res.Applied {
			t.Fatalf("result = %+v, want held", res)
		}
		if n := cnt(`SELECT count(*) FROM alerts WHERE kind = ?`, AlertPolicyExpireFailed); n != 1 {
			t.Errorf("expire alerts = %d, want 1", n)
		}
		noPolicyWrite(t, hs.Calls())
	})
}

// AC3: reconcile_pending lets only the sync write the policy; every other source is refused.
func TestChange_ReconcilePendingAllowsSyncOnly(t *testing.T) {
	ctx := context.Background()

	t.Run("sync writes", func(t *testing.T) {
		p, hs, g, _ := gatedPipeline(t, maintenance.ReconcilePending)
		req := baseRequest()
		req.Revision = RevisionMeta{Source: maintenance.SourceSync}
		res, err := p.Submit(ctx, req)
		if err != nil {
			t.Fatalf("Submit: %v", err)
		}
		if !res.Applied || res.PolicyHeld {
			t.Fatalf("result = %+v, want applied", res)
		}
		if hs.policy != targetPolicy {
			t.Errorf("policy was not written")
		}
		if len(g.calls) != 1 || g.calls[0] != maintenance.SourceSync {
			t.Errorf("gate calls = %v, want one sync check", g.calls)
		}
	})

	for _, src := range []policyrev.Source{policyrev.SourceUI, policyrev.SourceRollback, policyrev.SourceRecovery} {
		t.Run(string(src)+" is refused", func(t *testing.T) {
			p, hs, g, cnt := gatedPipeline(t, maintenance.ReconcilePending)
			req := baseRequest()
			req.Revision = RevisionMeta{Source: string(src)}
			res, err := p.Submit(ctx, req)
			if !errors.Is(err, maintenance.ErrMaintenance) {
				t.Fatalf("err = %v, want ErrMaintenance", err)
			}
			if res.Applied || res.PolicyHeld {
				t.Errorf("result = %+v, want a plain refusal", res)
			}
			if len(g.calls) != 1 || g.calls[0] != maintenance.SourceAdmin {
				t.Errorf("gate calls = %v, want one admin check", g.calls)
			}
			if len(hs.Calls()) != 0 {
				t.Errorf("Headscale calls = %v, want none", hs.Calls())
			}
			if n := cnt(`SELECT count(*) FROM audit_events WHERE event = 'policy.apply_refused'`); n != 1 {
				t.Errorf("policy.apply_refused audit events = %d, want 1", n)
			}
		})
	}
}

// An explicit "sync" source counts as the sync; an empty source does not (F3b-027 AC2). An active
// maintenance refuses every non-sync source and holds the sync.
func TestChange_MaintenanceActiveBySource(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		source   string
		wantHeld bool
	}{
		{"", false}, {"sync", true}, {"ui", false}, {"rollback", false}, {"recovery", false},
	} {
		t.Run("source="+tc.source, func(t *testing.T) {
			p, hs, _, _ := gatedPipeline(t, maintenance.Active)
			req := baseRequest()
			req.Revision = RevisionMeta{Source: tc.source}
			res, err := p.Submit(ctx, req)
			noPolicyWrite(t, hs.Calls())
			if tc.wantHeld {
				if err != nil || !res.PolicyHeld {
					t.Fatalf("Submit = %+v, %v; want held", res, err)
				}
				return
			}
			if !errors.Is(err, maintenance.ErrMaintenance) || res.PolicyHeld {
				t.Fatalf("Submit = %+v, %v; want ErrMaintenance", res, err)
			}
		})
	}
}

// AC2 (F3b-027): an empty revision source is not the sync flow. While a reconcile is pending it is
// treated like an admin write: the policy write is refused, audited, and nothing reaches Headscale.
func TestChange_EmptySourceIsNotSync(t *testing.T) {
	ctx := context.Background()
	p, hs, g, cnt := gatedPipeline(t, maintenance.ReconcilePending)
	req := baseRequest()
	req.Revision = RevisionMeta{Source: ""}
	if _, err := p.Submit(ctx, req); !errors.Is(err, maintenance.ErrMaintenance) {
		t.Fatalf("Submit = %v, want ErrMaintenance", err)
	}
	if len(g.calls) != 1 || g.calls[0] != maintenance.SourceAdmin {
		t.Errorf("gate calls = %v, want one admin check", g.calls)
	}
	if len(hs.Calls()) != 0 {
		t.Errorf("Headscale calls = %v, want none", hs.Calls())
	}
	if n := cnt(`SELECT count(*) FROM audit_events WHERE event = 'policy.apply_refused'`); n != 1 {
		t.Errorf("policy.apply_refused audit events = %d, want 1", n)
	}
}

// AC4: a maintenance state that cannot be read refuses the policy write and keeps the expiries going.
func TestChange_MaintenanceUnreadableFailsClosed(t *testing.T) {
	ctx := context.Background()

	t.Run("sync: held, expire runs", func(t *testing.T) {
		p, hs, g, _ := gatedPipeline(t, maintenance.Off)
		g.readErr = errors.New("database is closed")
		req := baseRequest()
		req.Revision = RevisionMeta{Source: maintenance.SourceSync}
		req.Expire = []uint64{7}
		res, err := p.Submit(ctx, req)
		if err != nil {
			t.Fatalf("Submit: %v", err)
		}
		if !res.PolicyHeld || res.Applied {
			t.Fatalf("result = %+v, want held", res)
		}
		noPolicyWrite(t, hs.Calls())
		if n := expireCalls(hs.Calls()); n != 1 {
			t.Errorf("ExpireNode calls = %d, want 1", n)
		}
	})

	t.Run("ui: refused", func(t *testing.T) {
		p, hs, g, _ := gatedPipeline(t, maintenance.Off)
		g.readErr = errors.New("database is closed")
		req := baseRequest()
		req.Revision = RevisionMeta{Source: "ui"}
		_, err := p.Submit(ctx, req)
		if !errors.Is(err, maintenance.ErrMaintenance) {
			t.Fatalf("err = %v, want ErrMaintenance", err)
		}
		if len(hs.Calls()) != 0 {
			t.Errorf("Headscale calls = %v, want none", hs.Calls())
		}
	})
}

// AC5: the gate runs under the writer lock, before anything is written to Headscale and before the
// apply_start audit; Approve and SubmitBuilt reach it too.
func TestChange_MaintenanceCheckedUnderLock(t *testing.T) {
	ctx := context.Background()

	check := func(t *testing.T, run func(p *Pipeline) (Result, error)) {
		t.Helper()
		p, hs, g, cnt := gatedPipeline(t, maintenance.Off)
		var held bool
		var writesAtCheck, auditAtCheck int
		g.onCall = func() {
			held = lockHeld()
			for _, c := range hs.Calls() {
				if c == "SetPolicy" || c == "CheckPolicy" {
					writesAtCheck++
				}
			}
			auditAtCheck = cnt(`SELECT count(*) FROM audit_events WHERE event = 'policy.apply_start'`)
		}
		res, err := run(p)
		if err != nil || !res.Applied {
			t.Fatalf("result = %+v, err = %v, want applied", res, err)
		}
		if !held {
			t.Error("the maintenance gate ran without the writer lock")
		}
		if writesAtCheck != 0 || auditAtCheck != 0 {
			t.Errorf("at the check: policy calls = %d, apply_start events = %d, want 0 and 0", writesAtCheck, auditAtCheck)
		}
		if len(g.calls) != 1 {
			t.Errorf("gate calls = %d, want 1", len(g.calls))
		}
	}

	t.Run("Submit", func(t *testing.T) {
		check(t, func(p *Pipeline) (Result, error) { return p.Submit(ctx, baseRequest()) })
	})
	t.Run("SubmitBuilt", func(t *testing.T) {
		var gateBeforeBuild atomic.Bool
		check(t, func(p *Pipeline) (Result, error) {
			return p.SubmitBuilt(ctx, "dev@example.com", func(context.Context) (Request, error) {
				gateBeforeBuild.Store(len(p.maint.(*fakeGate).calls) > 0)
				return baseRequest(), nil
			})
		})
		if gateBeforeBuild.Load() {
			t.Error("the gate ran before build: it must run after the fresh reads")
		}
	})
	t.Run("Approve", func(t *testing.T) {
		p, hs, g, s := gatedStore(t, maintenance.Active)
		req := baseRequest()
		req.Revision = RevisionMeta{Source: maintenance.SourceSync}
		req.NeedsApproval = true
		pending, err := p.Submit(ctx, req)
		if err != nil || pending.Status != StatusPendingApproval {
			t.Fatalf("Submit = %+v, %v; want pending", pending, err)
		}
		res, err := p.Approve(ctx, "approver@example.com", pending.ChangeID, versionOf(t, s, pending.ChangeID),
			func(context.Context) (Request, error) {
				repl := baseRequest()
				repl.Revision = RevisionMeta{Source: maintenance.SourceSync}
				return repl, nil
			})
		if err != nil {
			t.Fatalf("Approve: %v", err)
		}
		if !res.PolicyHeld || res.Applied {
			t.Fatalf("Approve result = %+v, want held", res)
		}
		noPolicyWrite(t, hs.Calls())
		if len(g.calls) != 1 {
			t.Errorf("gate calls = %d, want 1", len(g.calls))
		}
	})
}

// A dry run never reaches the gate: it writes nothing anyway.
func TestChange_MaintenanceDryRunSkipsGate(t *testing.T) {
	p, _, g, _ := gatedPipeline(t, maintenance.Active)
	req := baseRequest()
	req.DryRun = true
	res, err := p.Submit(context.Background(), req)
	if err != nil || res.Status != StatusDryRun {
		t.Fatalf("Submit = %+v, %v; want dry run", res, err)
	}
	if len(g.calls) != 0 {
		t.Errorf("gate calls = %v, want none", g.calls)
	}
}
