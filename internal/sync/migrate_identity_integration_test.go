//go:build integration

// Integration test for F1-016 (AC3): the G-03 identity conversion runs through the real change
// pipeline (CheckPolicy -> SetPolicy -> GetPolicy, change/sync_run/audit records) and must not change
// who can reach what or expire any node. The Headscale surface is a fake that enforces the same
// resolution rule Headscale uses (provider identifier first, then e-mail/name); the write path, the
// store and the audit log are the real ones. Run with
// `go test -tags=integration -run TestG03_NoAccessChange ./internal/sync/...` or `make lab-integration`.
package sync

import (
	"context"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/headscale"
	"github.com/nesiler/tagcess/internal/store"
)

// resolveMembers mirrors Headscale's resolveUser: drop a trailing "@", then match the provider
// identifier, the e-mail or the name. It returns the resolved Headscale user ids, sorted.
func resolveMembers(members []string, users []headscale.User) []uint64 {
	var out []uint64
	for _, m := range members {
		key := strings.TrimSuffix(m, "@")
		for _, u := range users {
			if u.ProviderID == key || u.Email == m || u.Name == m {
				out = append(out, u.ID)
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func resolvedGroups(policy []byte, users []headscale.User, t *testing.T) map[string][]uint64 {
	t.Helper()
	out := map[string][]uint64{}
	for name, members := range groupsOf(t, policy) {
		out[name] = resolveMembers(members, users)
	}
	return out
}

func TestG03_NoAccessChange(t *testing.T) {
	ctx := context.Background()
	in := g03Input()
	// Nodes owned by the very users being converted: a bug that drops a membership would try to
	// expire them, which this test must catch.
	hs := newFakeHeadscale(string(in.Policy))
	hs.users = in.Users
	hs.nodes = []headscale.Node{{ID: 100, UserID: 11}, {ID: 101, UserID: 12}}
	in.Nodes = hs.nodes

	p := Compute(in)
	if p.Identity == nil || !p.NeedsApproval || p.Blocked {
		t.Fatalf("conversion plan = %+v", p)
	}
	req, err := Request(in, p, SystemActor, "manual", planSummary(p))
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	if len(req.Expire) != 0 {
		t.Fatalf("a conversion must not queue node expiries: %v", req.Expire)
	}

	s, err := store.Open(ctx, filepath.Join(t.TempDir(), "tagcess.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	pipe := change.New(hs, s.Queries(), audit.New(s.Queries()), s)
	if _, err := s.DB().ExecContext(ctx, `UPDATE settings SET value = 'false' WHERE key = 'dry_run'`); err != nil {
		t.Fatalf("turn off dry run: %v", err)
	}

	submitted, err := pipe.Submit(ctx, req)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if submitted.Status != change.StatusPendingApproval {
		t.Fatalf("submit status = %q, want %q", submitted.Status, change.StatusPendingApproval)
	}

	var stored string
	if err := s.DB().QueryRowContext(ctx,
		`SELECT after_summary FROM changes WHERE id = ?`, submitted.ChangeID).Scan(&stored); err != nil {
		t.Fatalf("read after_summary: %v", err)
	}
	approved, err := pipe.Approve(ctx, "devops", submitted.ChangeID, change.ProposalVersion(stored),
		func(context.Context) (change.Request, error) { return req, nil })
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if !approved.Applied || approved.Status != change.StatusApplied {
		t.Fatalf("approve result = %+v, want applied", approved)
	}

	if got := hs.Expired(); len(got) != 0 {
		t.Fatalf("a conversion expired nodes: %v", got)
	}
	if got := hs.SetCalls(); len(got) != 1 {
		t.Fatalf("SetPolicy calls = %d, want 1", len(got))
	}

	before := resolvedGroups(in.Policy, in.Users, t)
	after := resolvedGroups([]byte(hs.Policy()), in.Users, t)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("the conversion changed who can reach what:\nbefore %v\nafter  %v", before, after)
	}
	// Guard against a vacuous pass: the conversion must actually have moved someone.
	total := 0
	for _, ids := range after {
		total += len(ids)
	}
	if total == 0 {
		t.Fatal("no member resolved; the test proves nothing")
	}
}

// An explicitly dropped unmatched e-mail reaches the audit log through the real pipeline: the drop
// is recorded when the change is queued for approval (AC2).
func TestG03_DroppedEmailIsAudited(t *testing.T) {
	ctx := context.Background()
	in := g03Input()
	in.Policy = policyWith(`"group:dev": ["user1@example.com", "user2@example.com", "ghost@example.com"], "group:ops": []`)
	in.DroppedEmails = []string{"ghost@example.com"}

	p := Compute(in)
	if p.Blocked || !p.NeedsApproval || p.Identity == nil || len(p.Identity.Dropped) != 1 {
		t.Fatalf("dropping the unmatched e-mail should allow approval: %+v", p)
	}
	req, err := Request(in, p, "devops", "manual", planSummary(p))
	if err != nil {
		t.Fatalf("Request: %v", err)
	}

	hs := newFakeHeadscale(string(in.Policy))
	hs.users = in.Users
	s, err := store.Open(ctx, filepath.Join(t.TempDir(), "tagcess.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	pipe := change.New(hs, s.Queries(), audit.New(s.Queries()), s)

	res, err := pipe.Submit(ctx, req)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if res.Status != change.StatusPendingApproval {
		t.Fatalf("submit status = %q, want %q", res.Status, change.StatusPendingApproval)
	}
	var diff string
	if err := s.DB().QueryRowContext(ctx,
		`SELECT diff FROM audit_events WHERE event = 'policy.pending_approval'`).Scan(&diff); err != nil {
		t.Fatalf("read pending audit event: %v", err)
	}
	if !strings.Contains(diff, "ghost@example.com") {
		t.Fatalf("the dropped e-mail is not in the audit log: %s", diff)
	}
}
