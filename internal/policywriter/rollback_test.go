package policywriter

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/internal/policydoc"
	"github.com/nesiler/tagcess/internal/policyrev"
	"github.com/nesiler/tagcess/internal/zitadel"
)

// F3-025 (A-03, ADR 0020): a rollback is a normal save of an earlier applied revision's raw text with
// source=rollback. The writer rebuilds today's groups and locked tests, validates and applies it as a
// new revision; the old revision is never touched.

// rollbackReq is the save of revision target's raw text as a rollback, based on the live policy.
func (e *env) rollbackReq(target policyrev.Revision) SaveRequest {
	e.t.Helper()
	return SaveRequest{
		Actor: devops, Text: target.Raw, BaseHash: policyrev.HashRaw(e.hs.Policy()),
		Source: policyrev.SourceRollback, RollbackOf: target.ID, Reason: "geri alma",
	}
}

// twoSaves applies A then B (each a comment edit of the live policy) and returns both revisions.
func (e *env) twoSaves() (a, b policyrev.Revision) {
	e.t.Helper()
	resA, err := e.save(strings.Replace(e.live, "// everyone reaches the gate", "// version A", 1))
	if err != nil {
		e.t.Fatalf("save A: %v", err)
	}
	resB, err := e.save(strings.Replace(resA.Text, "// version A", "// version B", 1))
	if err != nil {
		e.t.Fatalf("save B: %v", err)
	}
	return resA.Revision, resB.Revision
}

// AC4: the candidate's groups come from today's Zitadel, not from the old revision, and the locked
// tests are rebuilt from today's parameters.
func TestPolicyRollback_UsesCurrentGroups(t *testing.T) {
	e := newEnv(t)
	a, _ := e.twoSaves()
	if !strings.Contains(a.Raw, member("u10")) {
		t.Fatalf("revision A lacks u10 in its groups:\n%s", a.Raw)
	}

	// Today u10 lost the dev role, and the UI port of the locked tests changed.
	var grants []zitadel.Grant
	for _, g := range e.z.grants {
		if g.UserID != "u10" {
			grants = append(grants, g)
		}
	}
	e.z.setGrants(grants)
	cfg := policydoc.DefaultLockedConfig(9000)
	cfg.UIPort = 8443
	w, err := New(Config{Evaluator: e.rec, Pipeline: e.pipe, Revisions: e.revs, Checker: e.hs, Locked: cfg})
	if err != nil {
		t.Fatal(err)
	}

	res, err := w.Preview(context.Background(), e.rollbackReq(a))
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if !res.Report.Valid() {
		t.Fatalf("report = %+v", res.Report)
	}
	if strings.Contains(res.Text, member("u10")) {
		t.Errorf("the candidate has the old revision's group member u10:\n%s", res.Text)
	}
	if !strings.Contains(res.Text, member("u01")) || !strings.Contains(res.Text, "// version A") {
		t.Errorf("the candidate lost today's members or the revision's text:\n%s", res.Text)
	}
	if !res.GroupsRebuilt {
		t.Error("GroupsRebuilt = false, want true: the old groups differ from today's")
	}
	if !strings.Contains(res.Text, `"tag:vpn-server:8443"`) {
		t.Errorf("the locked tests were not rebuilt with today's UI port:\n%s", res.Text)
	}
	if len(e.hs.Sets()) != 2 {
		t.Errorf("SetPolicy calls = %d, want only the two saves: a preview must not write", len(e.hs.Sets()))
	}
}

// AC5: approving applies the candidate as a NEW revision (source rollback, rollback_of set); the old
// revision is unchanged and an audit event is written.
func TestPolicyRollback_AppliesAsNewRevision(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a, b := e.twoSaves()
	before := e.revisions()
	auditBefore := e.count(`SELECT count(*) FROM audit_events WHERE event = 'policy.apply' AND actor = ?`, devops)

	res, err := e.w.Save(ctx, e.rollbackReq(a))
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if !res.Change.Applied {
		t.Fatalf("result = %+v, want applied", res.Change)
	}
	rev := res.Revision
	if rev.ID == a.ID || rev.ID == b.ID || rev.Source != policyrev.SourceRollback || rev.RollbackOf != a.ID ||
		rev.ApplyStatus != policyrev.StatusApplied || rev.Actor != devops {
		t.Errorf("new revision = %+v, want a new applied rollback of %d", rev, a.ID)
	}
	if got := e.hs.Policy(); got != rev.Raw {
		t.Errorf("live policy is not the new revision's text:\n got %q\nwant %q", got, rev.Raw)
	}
	if want := e.expected(a.Raw); rev.Raw != want {
		t.Errorf("rolled-back text = %q, want the composed %q", rev.Raw, want)
	}
	// The old revisions are exactly as they were.
	after := e.revisions()
	if len(after) != len(before)+1 {
		t.Fatalf("revisions = %d, want %d", len(after), len(before)+1)
	}
	for _, old := range before {
		got, err := e.revs.Get(ctx, old.ID)
		if err != nil || got != old {
			t.Errorf("revision %d changed: %+v -> %+v (err %v)", old.ID, old, got, err)
		}
	}
	if n := e.count(`SELECT count(*) FROM audit_events WHERE event = 'policy.apply' AND actor = ?`, devops); n != auditBefore+1 {
		t.Errorf("policy.apply audit events = %d, want %d", n, auditBefore+1)
	}
}

// AC6 (writer side): only an applied revision is a rollback target; the check runs before anything
// is read or written.
func TestPolicyRollback_OnlyAppliedTargets(t *testing.T) {
	ctx := context.Background()
	for _, status := range []policyrev.Status{policyrev.StatusFailed, policyrev.StatusDryRun, policyrev.StatusUnknown, policyrev.StatusPending} {
		t.Run(string(status), func(t *testing.T) {
			e := newEnv(t)
			rev, err := e.revs.Add(ctx, policyrev.NewRevision{Raw: e.live, Source: policyrev.SourceUI, Actor: devops, Reason: "x"})
			if err != nil {
				t.Fatal(err)
			}
			if status != policyrev.StatusPending {
				if err := e.revs.Finish(ctx, rev.ID, status, "d"); err != nil {
					t.Fatal(err)
				}
			}
			rev, _ = e.revs.Get(ctx, rev.ID)
			if _, err := e.w.Preview(ctx, e.rollbackReq(rev)); !errors.Is(err, ErrRollbackTarget) {
				t.Errorf("Preview err = %v, want ErrRollbackTarget", err)
			}
			if _, err := e.w.Save(ctx, e.rollbackReq(rev)); !errors.Is(err, ErrRollbackTarget) {
				t.Errorf("Save err = %v, want ErrRollbackTarget", err)
			}
			if n := len(e.hs.Sets()); n != 0 {
				t.Errorf("SetPolicy calls = %d, want 0", n)
			}
		})
	}
	t.Run("unknown id and no id", func(t *testing.T) {
		e := newEnv(t)
		for _, id := range []int64{0, 9999} {
			req := e.rollbackReq(policyrev.Revision{ID: id, Raw: e.live})
			if _, err := e.w.Save(ctx, req); !errors.Is(err, ErrRollbackTarget) {
				t.Errorf("Save(rollback_of %d) err = %v, want ErrRollbackTarget", id, err)
			}
		}
	})
	t.Run("applied and external are targets", func(t *testing.T) {
		e := newEnv(t)
		base, _, err := e.revs.EnsureBaseline(ctx, e.live, "tagcess")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.w.Save(ctx, e.rollbackReq(base)); err != nil {
			t.Errorf("rollback to the external baseline: %v", err)
		}
	})
}

// AC7 (writer side): a rollback is stopped exactly like an editor save: Zitadel unreadable, a stale
// base, an uncertain earlier write. Nothing is written.
func TestPolicyRollback_BlockedLikeEditor(t *testing.T) {
	ctx := context.Background()

	t.Run("zitadel unreadable", func(t *testing.T) {
		e := newEnv(t)
		a, _ := e.twoSaves()
		sets := len(e.hs.Sets())
		e.z.grantsErr = errors.New("zitadel down")
		if _, err := e.w.Save(ctx, e.rollbackReq(a)); !errors.Is(err, ErrZitadelUnavailable) {
			t.Fatalf("err = %v, want ErrZitadelUnavailable", err)
		}
		if _, err := e.w.Preview(ctx, e.rollbackReq(a)); !errors.Is(err, ErrZitadelUnavailable) {
			t.Fatalf("preview err = %v, want ErrZitadelUnavailable", err)
		}
		if len(e.hs.Sets()) != sets {
			t.Error("a policy was written while Zitadel is unreadable")
		}
	})
	t.Run("stale base", func(t *testing.T) {
		e := newEnv(t)
		a, _ := e.twoSaves()
		req := e.rollbackReq(a)
		req.BaseHash = policyrev.HashRaw("something else")
		if _, err := e.w.Save(ctx, req); !errors.Is(err, ErrStale) {
			t.Fatalf("err = %v, want ErrStale", err)
		}
	})
	t.Run("uncertain earlier write", func(t *testing.T) {
		e := newEnv(t)
		a, _ := e.twoSaves()
		e.hs.setStores = `{"acls": [], "groups": {}}`
		if _, err := e.save(strings.Replace(e.hs.Policy(), "// version B", "// version C", 1)); !errors.Is(err, ErrNotApplied) {
			t.Fatalf("setup save err = %v, want ErrNotApplied", err)
		}
		e.hs.setStores = ""
		sets := len(e.hs.Sets())
		if _, err := e.w.Save(ctx, e.rollbackReq(a)); !errors.Is(err, ErrUncertain) {
			t.Fatalf("err = %v, want ErrUncertain", err)
		}
		if len(e.hs.Sets()) != sets {
			t.Error("a rollback was written while the state is uncertain")
		}
	})
}
