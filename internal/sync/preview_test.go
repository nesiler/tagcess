package sync

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// Preview is the read-only view behind the sync screen: it computes the diff without applying or
// recording anything.
func TestPreview_ReadOnlyDiff(t *testing.T) {
	ctx := context.Background()
	r, _, hs, s := newTestReconciler(t)

	plan, err := r.Preview(ctx)
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if plan.Blocked || plan.NeedsApproval {
		t.Fatalf("plan = %+v, want an open diff", plan)
	}
	if len(plan.GroupDiff.Groups) != 1 || plan.GroupDiff.Groups[0].Group != "group:dev" {
		t.Fatalf("group diff = %+v, want group:dev", plan.GroupDiff.Groups)
	}
	if got := plan.GroupDiff.Groups[0].Added; len(got) != 1 || got[0] != member("1") {
		t.Fatalf("added = %v, want [%s]", got, member("1"))
	}
	if len(hs.SetCalls()) != 0 {
		t.Errorf("Preview wrote to Headscale: %v", hs.SetCalls())
	}
	if n := count(t, s, `SELECT count(*) FROM sync_runs`); n != 0 {
		t.Errorf("Preview recorded %d sync_runs, want 0", n)
	}
	if n := count(t, s, `SELECT count(*) FROM alerts`); n != 0 {
		t.Errorf("Preview raised %d alerts, want 0", n)
	}
}

// A failed read is shown as a plan reason, not as a handler error, so the page can explain it.
func TestPreview_ReadFailureReason(t *testing.T) {
	ctx := context.Background()
	r, _, hs, _ := newTestReconciler(t)
	hs.policyErr = errors.New("boom")

	plan, err := r.Preview(ctx)
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if !strings.Contains(plan.Reason, "okuma hatası") {
		t.Fatalf("reason = %q, want a read-failure reason", plan.Reason)
	}
}

// Replan rebuilds the request for the approval flow, and an untrusted read never becomes a change.
func TestReplan(t *testing.T) {
	t.Run("healthy read is appliable", func(t *testing.T) {
		r, _, _, _ := newTestReconciler(t)
		req, err := r.Replan(context.Background())
		if err != nil {
			t.Fatalf("Replan: %v", err)
		}
		if req.Blocked || len(req.Target) == 0 {
			t.Fatalf("request = %+v, want an appliable target", req)
		}
	})

	t.Run("failed read is blocked", func(t *testing.T) {
		r, z, _, _ := newTestReconciler(t)
		z.grantsErr = errors.New("boom")
		req, err := r.Replan(context.Background())
		if err != nil {
			t.Fatalf("Replan: %v", err)
		}
		if !req.Blocked || len(req.Target) != 0 {
			t.Fatalf("request = %+v, want blocked with no target", req)
		}
	})
}
