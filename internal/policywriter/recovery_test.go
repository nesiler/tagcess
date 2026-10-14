package policywriter

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/internal/policyrev"
	"github.com/nesiler/tagcess/internal/zitadel"
)

// F3-029 (H-04, A-03, R2 karar 20/163): the controlled UI recovery of an uncertain policy state. The
// candidate is the last applied revision's raw text with today's Zitadel groups and the rebuilt locked
// tests; it is validated, shown against a fresh read of the live policy, and applied only on an
// explicit approval, under the writer lock, through the same pipeline as every other write.

// recoverReq is the recovery request as the page sends it: no text (the writer resolves the target),
// the base hash of the live policy that was shown.
func (e *env) recoverReq() SaveRequest {
	return SaveRequest{Actor: devops, Source: policyrev.SourceRecovery, BaseHash: policyrev.HashRaw(e.hs.Policy())}
}

// uncertainState applies A and B, then a third save whose readback does not match: the revision ends
// unknown and Headscale holds the text it stored instead. It returns B, the last applied revision.
func (e *env) uncertainState() (b policyrev.Revision) {
	e.t.Helper()
	_, b = e.twoSaves()
	// The stored text differs from what was written in meaning (an extra host), so the readback does not match.
	stored := strings.Replace(b.Raw, `"tagOwners": {`, `"hosts": {"stored": "100.64.0.99"}, "tagOwners": {`, 1)
	if stored == b.Raw {
		e.t.Fatal("setup: the stored text equals B")
	}
	e.hs.setStores = stored
	_, err := e.save(strings.Replace(b.Raw, "// version B", "// version C", 1))
	if !errors.Is(err, ErrNotApplied) {
		e.t.Fatalf("setup save err = %v, want ErrNotApplied", err)
	}
	e.hs.setStores = ""
	if top := e.revisions()[0]; top.ApplyStatus != policyrev.StatusUnknown {
		e.t.Fatalf("setup revision = %+v, want unknown", top)
	}
	return b
}

func (e *env) uncertain() string {
	e.t.Helper()
	l, err := e.w.Live(context.Background())
	if err != nil {
		e.t.Fatal(err)
	}
	return l.Uncertain
}

// AC1: with an uncertain state the preview shows the target (the last applied revision) and the
// candidate (old raw text, today's groups, rebuilt locked tests) and writes nothing.
func TestRecovery_CandidateReadOnly(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	b := e.uncertainState()

	// Today u10 lost the dev role: the candidate must not carry B's old group.
	var grants []zitadel.Grant
	for _, g := range e.z.grants {
		if g.UserID != "u10" {
			grants = append(grants, g)
		}
	}
	e.z.setGrants(grants)
	sets, revs := len(e.hs.Sets()), len(e.revisions())
	live := e.hs.Policy()

	res, err := e.w.Preview(ctx, e.recoverReq())
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if res.Target.ID != b.ID {
		t.Errorf("target = #%d, want the last applied revision #%d", res.Target.ID, b.ID)
	}
	if want := e.expected(b.Raw); res.Text != want {
		t.Errorf("candidate = %q, want the target's text with today's groups %q", res.Text, want)
	}
	if strings.Contains(res.Text, member("u10")) || !strings.Contains(res.Text, "// version B") {
		t.Errorf("candidate has the wrong groups or text:\n%s", res.Text)
	}
	if !res.Report.Valid() {
		t.Errorf("report = %+v, want valid", res.Report)
	}
	if res.Current != live || res.RawDiff == "" {
		t.Errorf("current/diff = %q / %q, want the fresh live policy and a difference", res.Current, res.RawDiff)
	}
	if len(e.hs.Sets()) != sets || len(e.revisions()) != revs {
		t.Error("the preview wrote a policy or a revision")
	}
	if e.hs.Policy() != live {
		t.Error("the live policy changed")
	}
}

// AC1 (no target): a store with no applied revision has nothing to recover to.
func TestRecovery_NoTarget(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	rev, err := e.revs.Add(ctx, policyrev.NewRevision{Raw: e.live, Source: policyrev.SourceUI, Actor: devops, Reason: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.revs.Finish(ctx, rev.ID, policyrev.StatusUnknown, "d"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.w.Save(ctx, e.recoverReq()); !errors.Is(err, ErrNoRecoveryTarget) {
		t.Fatalf("err = %v, want ErrNoRecoveryTarget", err)
	}
	if len(e.hs.Sets()) != 0 {
		t.Error("a policy was written without a target")
	}
}

// Recovery is only open while the state is uncertain.
func TestRecovery_OnlyWhileUncertain(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.twoSaves()
	sets := len(e.hs.Sets())
	for name, fn := range map[string]func() error{
		"preview": func() error { _, err := e.w.Preview(ctx, e.recoverReq()); return err },
		"save":    func() error { _, err := e.w.Save(ctx, e.recoverReq()); return err },
	} {
		if err := fn(); !errors.Is(err, ErrNotUncertain) {
			t.Errorf("%s err = %v, want ErrNotUncertain", name, err)
		}
	}
	if len(e.hs.Sets()) != sets {
		t.Error("a recovery wrote while nothing was uncertain")
	}
}

// AC2: the candidate is validated again; one that fails is not applied.
func TestRecovery_RevalidatesCandidate(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.uncertainState()
	e.hs.checkErr = errors.New("policy: group group:ghost is not defined")
	sets := len(e.hs.Sets())

	res, err := e.w.Preview(ctx, e.recoverReq())
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if res.Report.Valid() {
		t.Fatalf("report = %+v, want a failed validation", res.Report)
	}
	if _, err := e.w.Save(ctx, e.recoverReq()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Save err = %v, want ErrInvalid", err)
	}
	if len(e.hs.Sets()) != sets {
		t.Error("an invalid candidate was written")
	}
	if e.uncertain() == "" {
		t.Error("the uncertain state was cleared by a refused recovery")
	}
}

// AC3: the difference is against a fresh read of the live policy, every time.
func TestRecovery_ShowsDiffAgainstFreshLive(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.uncertainState()

	first, err := e.w.Preview(ctx, e.recoverReq())
	if err != nil {
		t.Fatal(err)
	}
	// Someone changes the live policy; the next read shows it.
	changed := strings.Replace(e.hs.Policy(), "100.64.0.99", "100.64.0.98", 1)
	e.hs.setPolicy(changed)
	second, err := w2Preview(e, changed)
	if err != nil {
		t.Fatal(err)
	}
	if first.Current == second.Current || second.Current != changed {
		t.Errorf("current = %q then %q, want the fresh live text", first.Current, second.Current)
	}
	if !strings.Contains(second.RawDiff, "100.64.0.98") || !strings.Contains(first.RawDiff, "100.64.0.99") {
		t.Errorf("diffs are not against the live text at each read:\nfirst %q\nsecond %q", first.RawDiff, second.RawDiff)
	}
	// A stale base (the page showed an older live policy) is refused.
	req := e.recoverReq()
	req.BaseHash = policyrev.HashRaw(first.Current)
	if _, err := e.w.Save(ctx, req); !errors.Is(err, ErrStale) {
		t.Errorf("Save with a stale base err = %v, want ErrStale", err)
	}
}

func w2Preview(e *env, live string) (SaveResult, error) {
	req := e.recoverReq()
	req.BaseHash = policyrev.HashRaw(live)
	return e.w.Preview(context.Background(), req)
}

// AC4: the approval applies the candidate as a recovery revision of the target, reads it back, and
// the uncertain state is gone; the writer accepts saves again.
func TestRecovery_ApplyClearsUnknown(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	b := e.uncertainState()
	if e.uncertain() == "" {
		t.Fatal("setup is not uncertain")
	}
	auditBefore := e.count(`SELECT count(*) FROM audit_events WHERE event = 'policy.apply' AND actor = ?`, devops)

	res, err := e.w.Save(ctx, e.recoverReq())
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if !res.Change.Applied {
		t.Fatalf("result = %+v, want applied", res.Change)
	}
	rev := res.Revision
	if rev.Source != policyrev.SourceRecovery || rev.RollbackOf != b.ID || rev.ApplyStatus != policyrev.StatusApplied || rev.Actor != devops {
		t.Errorf("revision = %+v, want an applied recovery of #%d", rev, b.ID)
	}
	if want := e.expected(b.Raw); e.hs.Policy() != want || rev.Raw != want {
		t.Errorf("live policy = %q, want the candidate %q", e.hs.Policy(), want)
	}
	if got := e.uncertain(); got != "" {
		t.Errorf("uncertain = %q after a successful recovery, want cleared", got)
	}
	if n := e.count(`SELECT count(*) FROM audit_events WHERE event = 'policy.apply' AND actor = ?`, devops); n != auditBefore+1 {
		t.Errorf("policy.apply audit events = %d, want %d", n, auditBefore+1)
	}
	// The unknown revision is kept as history.
	var unknown int
	for _, r := range e.revisions() {
		if r.ApplyStatus == policyrev.StatusUnknown {
			unknown++
		}
	}
	if unknown != 1 {
		t.Errorf("unknown revisions = %d, want the original one kept", unknown)
	}
	if _, err := e.save(strings.Replace(e.hs.Policy(), "// version B", "// version D", 1)); err != nil {
		t.Errorf("save after the recovery: %v", err)
	}
}

// AC6: Zitadel or the live policy unreadable blocks the recovery; nothing is written.
func TestRecovery_BlockedWhileZitadelDown(t *testing.T) {
	ctx := context.Background()
	t.Run("zitadel", func(t *testing.T) {
		e := newEnv(t)
		e.uncertainState()
		sets := len(e.hs.Sets())
		e.z.grantsErr = errors.New("zitadel down")
		if _, err := e.w.Preview(ctx, e.recoverReq()); !errors.Is(err, ErrZitadelUnavailable) {
			t.Errorf("Preview err = %v, want ErrZitadelUnavailable", err)
		}
		if _, err := e.w.Save(ctx, e.recoverReq()); !errors.Is(err, ErrZitadelUnavailable) {
			t.Errorf("Save err = %v, want ErrZitadelUnavailable", err)
		}
		if len(e.hs.Sets()) != sets || e.uncertain() == "" {
			t.Error("a blocked recovery wrote or cleared the state")
		}
	})
	t.Run("live policy", func(t *testing.T) {
		e := newEnv(t)
		e.uncertainState()
		sets := len(e.hs.Sets())
		req := e.recoverReq()
		e.hs.policyErr = errors.New("headscale down")
		if _, err := e.w.Preview(ctx, req); !errors.Is(err, ErrHeadscaleUnavailable) {
			t.Errorf("Preview err = %v, want ErrHeadscaleUnavailable", err)
		}
		if _, err := e.w.Save(ctx, req); !errors.Is(err, ErrHeadscaleUnavailable) {
			t.Errorf("Save err = %v, want ErrHeadscaleUnavailable", err)
		}
		if len(e.hs.Sets()) != sets {
			t.Error("a policy was written while the live policy is unreadable")
		}
	})
}

// AC7: a recovery that fails or cannot be verified keeps the state uncertain, never restores an older
// policy and never reports success; a new attempt is possible and nothing retries by itself.
func TestRecovery_FailureKeepsUnknown(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	b := e.uncertainState()

	t.Run("write refused", func(t *testing.T) {
		live := e.hs.Policy()
		sets := len(e.hs.Sets())
		e.hs.setErr = errors.New("boom")
		res, err := e.w.Save(ctx, e.recoverReq())
		if !errors.Is(err, ErrNotApplied) || res.Change.Applied {
			t.Fatalf("err = %v, applied = %v; want ErrNotApplied and not applied", err, res.Change.Applied)
		}
		if res.Revision.Source != policyrev.SourceRecovery || res.Revision.ApplyStatus != policyrev.StatusFailed {
			t.Errorf("revision = %+v, want a failed recovery", res.Revision)
		}
		if len(e.hs.Sets()) != sets+1 {
			t.Errorf("SetPolicy calls = %d, want exactly the one attempt (no restore, no retry)", len(e.hs.Sets())-sets)
		}
		if e.hs.Policy() != live || e.uncertain() == "" {
			t.Error("the live policy changed or the state was cleared by a failed recovery")
		}
	})
	t.Run("readback does not match", func(t *testing.T) {
		e.hs.setErr = nil
		other := `{"acls": [], "groups": {}}`
		e.hs.setStores = other
		sets := len(e.hs.Sets())
		res, err := e.w.Save(ctx, e.recoverReq())
		if !errors.Is(err, ErrNotApplied) || res.Revision.ApplyStatus != policyrev.StatusUnknown {
			t.Fatalf("err = %v, revision = %+v; want ErrNotApplied and unknown", err, res.Revision)
		}
		if len(e.hs.Sets()) != sets+1 || e.hs.Policy() != other {
			t.Errorf("SetPolicy calls = %d, live = %q; want one attempt and no restore", len(e.hs.Sets())-sets, e.hs.Policy())
		}
		if e.uncertain() == "" {
			t.Error("the state was cleared although the recovery could not be verified")
		}
	})
	t.Run("a new attempt works", func(t *testing.T) {
		e.hs.setStores = ""
		// The page would show the live policy as it is now: the stored `other` text.
		res, err := e.w.Save(ctx, e.recoverReq())
		if err != nil {
			t.Fatalf("retry: %v", err)
		}
		if res.Revision.RollbackOf != b.ID || e.uncertain() != "" {
			t.Errorf("revision = %+v, uncertain = %q; want a recovery of #%d that clears the state", res.Revision, e.uncertain(), b.ID)
		}
	})
}

// AC5: no automatic path reaches the recovery. The source label and the writer's recovery entry are
// referenced only by the writer itself and by the recovery page; the sync, the reconciler, the hook and
// the startup code never name them.
func TestRecovery_NeverAutomatic(t *testing.T) {
	root := filepath.Join("..", "..")
	allowed := map[string]bool{
		filepath.Join("internal", "policywriter", "writer.go"):       true,
		filepath.Join("internal", "policywriter", "recovery.go"):     true,
		filepath.Join("internal", "policyrev", "policyrev.go"):       true,
		filepath.Join("internal", "web", "policy_recovery.go"):       true,
		filepath.Join("internal", "web", "policy_recovery_templ.go"): true,
	}
	needles := []string{"SourceRecovery", "ErrNotUncertain"}
	scanned := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); n == ".git" || n == ".claude" || n == "node_modules" || n == "vendor" {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		body, err := os.ReadFile(path) //nolint:gosec // walks this repository's own sources
		if err != nil {
			return err
		}
		scanned++
		for _, n := range needles {
			if strings.Contains(string(body), n) && !allowed[rel] {
				t.Errorf("%s refers to %s: the recovery must only be reachable from its page", rel, n)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned < 50 {
		t.Fatalf("scanned %d files, the walk is not covering the repository", scanned)
	}
}
