package web

import (
	"context"
	"path/filepath"
	"sync"
	"testing"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/headscale"
	"github.com/nesiler/tagcess/internal/store"
	"github.com/nesiler/tagcess/internal/store/db"
	agentsync "github.com/nesiler/tagcess/internal/sync"
)

const (
	// livePolicy is the policy the queued plan was computed from; targetPolicy adds one member.
	livePolicy   = `{"acls":[],"groups":{"group:ops":["https://idp/9@"]}}`
	targetPolicy = `{"acls":[],"groups":{"group:ops":["https://idp/1@","https://idp/9@"]}}`
)

// fakeHeadscale is a change.Headscale double that records every write, so a test can prove a dry-run
// apply never reaches Headscale.
type fakeHeadscale struct {
	mu     sync.Mutex
	policy string
	writes []string
}

func newFakeHeadscale() *fakeHeadscale {
	return &fakeHeadscale{policy: livePolicy}
}

func (f *fakeHeadscale) GetPolicy(context.Context) (headscale.Policy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return headscale.Policy{Text: f.policy}, nil
}

func (f *fakeHeadscale) CheckPolicy(context.Context, string) error { return nil }

func (f *fakeHeadscale) SetPolicy(_ context.Context, policy string) (headscale.Policy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.policy = policy
	f.writes = append(f.writes, "SetPolicy")
	return headscale.Policy{Text: policy}, nil
}

func (f *fakeHeadscale) ExpireNode(_ context.Context, id uint64) (headscale.Node, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes = append(f.writes, "ExpireNode")
	return headscale.Node{ID: id}, nil
}

func (f *fakeHeadscale) wrote() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.writes) > 0
}

// Y-06: a dry-run toggle that lands after a plan was evaluated but before the queued apply enters the
// writer lock must stop the write. This drives the real web.SettingDryRun path against the real change
// pipeline over one store, so it also guards the wiring between the two: the toggle stores the setting
// and the pipeline re-reads it at the write boundary right before calling Headscale. No sleeps.
func TestSettingDryRun_StopsQueuedApply(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(ctx, filepath.Join(t.TempDir(), "tagcess.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	hs := newFakeHeadscale()
	pipe := change.New(hs, s.Queries(), audit.New(s.Queries()), s)
	setter := NewSettingDryRun(s.Queries())

	// The store seeds dry-run on (Y-06.2); turn it off and check the setting actually moved, so a
	// no-op setter cannot make this test pass by leaving dry-run on.
	if err := setter.SetDryRun(ctx, false); err != nil {
		t.Fatalf("SetDryRun(false): %v", err)
	}
	if on, err := s.DryRun(ctx); err != nil || on {
		t.Fatalf("after SetDryRun(false): on=%v err=%v, want off", on, err)
	}

	// The operator turns dry-run on while the evaluated apply waits to enter the writer lock.
	if err := setter.SetDryRun(ctx, true); err != nil {
		t.Fatalf("SetDryRun(true): %v", err)
	}
	if on, err := s.DryRun(ctx); err != nil || !on {
		t.Fatalf("after SetDryRun(true): on=%v err=%v, want on", on, err)
	}

	res, err := pipe.Submit(ctx, change.Request{
		Kind:         change.KindPolicy,
		Actor:        "system:sync",
		Trigger:      "manual",
		Summary:      "1 eklendi",
		Target:       []byte(targetPolicy),
		SourcePolicy: []byte(livePolicy),
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if res.Status != change.StatusDryRun || res.Applied {
		t.Fatalf("result = %+v, want dry_run", res)
	}
	if hs.wrote() {
		t.Fatalf("the toggle did not stop the queued apply: writes = %v", hs.writes)
	}
}

// F4-023 review: a monitor row below the opening threshold (non-empty subject, empty severity) only
// carries hysteresis counters and must not reach the sync overview. Legacy pipeline alerts (empty
// subject, empty severity) and raised monitor alerts stay visible.
func TestOverviewHidesPendingMonitorCounters(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(ctx, filepath.Join(t.TempDir(), "tagcess.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	q := s.Queries()
	const at = "2026-10-04T12:00:00.000Z"
	if _, err := q.InsertAlert(ctx, db.InsertAlertParams{Kind: "policy_mismatch", Source: "headscale", FirstSeenAt: at, LastSeenAt: at}); err != nil {
		t.Fatalf("InsertAlert: %v", err)
	}
	for _, m := range []struct{ kind, subject, severity string }{
		{"monitor_target_health", "pending.example", ""},
		{"monitor_target_health", "raised.example", "critical"},
	} {
		if _, err := q.InsertMonitorAlert(ctx, db.InsertMonitorAlertParams{
			Kind: m.kind, Subject: m.subject, Source: "target", Severity: m.severity, Freshness: "fresh",
			FirstSeenAt: at, LastSeenAt: at,
		}); err != nil {
			t.Fatalf("InsertMonitorAlert %s: %v", m.subject, err)
		}
	}

	reader, err := NewOverviewReader(OverviewConfig{
		Queries: q,
		Preview: func(context.Context) (agentsync.Plan, error) { return agentsync.Plan{}, nil },
	})
	if err != nil {
		t.Fatalf("NewOverviewReader: %v", err)
	}
	ov, err := reader.Overview(ctx)
	if err != nil {
		t.Fatalf("Overview: %v", err)
	}
	if len(ov.Alerts) != 2 {
		t.Fatalf("overview alerts = %+v, want the legacy alert and the raised monitor alert only", ov.Alerts)
	}
	kinds := map[string]int{}
	for _, a := range ov.Alerts {
		kinds[a.Kind]++
	}
	if kinds["policy_mismatch"] != 1 || kinds["monitor_target_health"] != 1 {
		t.Fatalf("overview kinds = %v, want one policy_mismatch and one raised monitor_target_health", kinds)
	}
}
