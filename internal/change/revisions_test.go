package change

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/headscale"
)

// lockHeld reports whether another goroutine is kept out of the writer lock right now. The probe
// goroutine acquires and releases the lock as soon as it can, so it never outlives the holder.
func lockHeld() bool {
	got := make(chan struct{})
	go func() {
		_ = WithWriterLock(func() error { close(got); return nil })
	}()
	select {
	case <-got:
		return false
	case <-time.After(100 * time.Millisecond):
		return true
	}
}

// F3-010: SubmitBuilt takes the writer lock first and runs build inside it, so the fresh reads build
// makes are covered by the same lock as the apply. A failing build writes nothing.
func TestSubmitBuilt_BuildRunsUnderLock(t *testing.T) {
	ctx := context.Background()

	t.Run("build runs under the lock and its request is applied", func(t *testing.T) {
		p, hs, s := newPipeline(t)
		var held bool
		res, err := p.SubmitBuilt(ctx, "dev@example.com", func(context.Context) (Request, error) {
			held = lockHeld()
			return baseRequest(), nil
		})
		if err != nil {
			t.Fatalf("SubmitBuilt: %v", err)
		}
		if !held {
			t.Error("build ran without the writer lock")
		}
		if !res.Applied || res.Status != StatusApplied {
			t.Fatalf("result = %+v, want applied", res)
		}
		if n := count(t, s, `SELECT count(*) FROM changes WHERE status = 'applied'`); n != 1 {
			t.Errorf("applied changes = %d, want 1", n)
		}
		if got := hs.Calls(); len(got) == 0 || got[len(got)-1] != "GetPolicy" {
			t.Errorf("calls = %v, want the usual apply sequence", got)
		}
		if lockHeld() {
			t.Error("the writer lock was not released")
		}
	})

	t.Run("a build error is returned and nothing is written", func(t *testing.T) {
		p, hs, s := newPipeline(t)
		boom := errors.New("zitadel down")
		res, err := p.SubmitBuilt(ctx, "dev@example.com", func(context.Context) (Request, error) {
			return Request{}, boom
		})
		if !errors.Is(err, boom) {
			t.Fatalf("err = %v, want the build error", err)
		}
		if res != (Result{}) {
			t.Errorf("result = %+v, want zero", res)
		}
		if len(hs.Calls()) != 0 {
			t.Errorf("a failed build touched Headscale: %v", hs.Calls())
		}
		if n := count(t, s, `SELECT count(*) FROM changes`); n != 0 {
			t.Errorf("a failed build wrote %d change rows, want 0", n)
		}
		if lockHeld() {
			t.Error("the writer lock was not released after a build error")
		}
	})

	t.Run("an empty actor is refused before build runs", func(t *testing.T) {
		p, _, _ := newPipeline(t)
		ran := false
		_, err := p.SubmitBuilt(ctx, " ", func(context.Context) (Request, error) {
			ran = true
			return baseRequest(), nil
		})
		if err == nil || ran {
			t.Errorf("err = %v, build ran = %v; want an error and no build", err, ran)
		}
	})

	t.Run("the actor is stamped on the built request", func(t *testing.T) {
		p, _, s := newPipeline(t)
		req := baseRequest()
		req.Actor = "someone-else@example.com"
		if _, err := p.SubmitBuilt(ctx, "dev@example.com", func(context.Context) (Request, error) { return req, nil }); err != nil {
			t.Fatalf("SubmitBuilt: %v", err)
		}
		if n := count(t, s, `SELECT count(*) FROM changes WHERE actor = 'dev@example.com'`); n != 1 {
			t.Errorf("changes by the submitting actor = %d, want 1", n)
		}
	})
}

// fakeRevisions is an in-memory PolicyRevisions.
type fakeRevisions struct {
	mu       sync.Mutex
	begun    []Request
	changeID []int64
	finished []finishedRev
	beginErr error
	nextID   int64
}

type finishedRev struct {
	ID      int64
	Outcome string
	Detail  string
}

func (f *fakeRevisions) Begin(_ context.Context, req Request, changeID int64) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.beginErr != nil {
		return 0, f.beginErr
	}
	f.begun = append(f.begun, req)
	f.changeID = append(f.changeID, changeID)
	f.nextID++
	return f.nextID, nil
}

func (f *fakeRevisions) Finish(_ context.Context, id int64, outcome, detail string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.finished = append(f.finished, finishedRev{ID: id, Outcome: outcome, Detail: detail})
	return nil
}

// F3-010 AC12: a sync apply records a source=sync revision (pending first, then applied) bound to the
// change; without a recorder the pipeline behaves as before.
func TestPipeline_RecordsSyncRevision(t *testing.T) {
	ctx := context.Background()

	t.Run("applied sync request", func(t *testing.T) {
		p, _, s := newPipeline(t)
		rev := &fakeRevisions{}
		p.WithRevisions(rev)

		res, err := p.Submit(ctx, baseRequest())
		if err != nil || !res.Applied {
			t.Fatalf("Submit = %+v, %v; want applied", res, err)
		}
		if len(rev.begun) != 1 || len(rev.finished) != 1 {
			t.Fatalf("begun = %d, finished = %d; want 1 and 1", len(rev.begun), len(rev.finished))
		}
		if got := rev.finished[0]; got.Outcome != RevisionApplied || got.ID != res.RevisionID || res.RevisionID == 0 {
			t.Errorf("finished = %+v, result revision = %d; want applied for the same revision", got, res.RevisionID)
		}
		// The revision is bound to the change that was reserved before the write.
		if rev.changeID[0] == 0 || rev.changeID[0] != res.ChangeID {
			t.Errorf("revision change id = %d, result change id = %d; want the same non-zero id", rev.changeID[0], res.ChangeID)
		}
		if n := count(t, s, `SELECT count(*) FROM changes WHERE id = ? AND status = 'applied'`, res.ChangeID); n != 1 {
			t.Errorf("the reserved change row did not end applied")
		}
		if n := count(t, s, `SELECT count(*) FROM changes`); n != 1 {
			t.Errorf("changes = %d, want exactly 1 (the reservation is reused)", n)
		}
	})

	t.Run("without a recorder nothing changes", func(t *testing.T) {
		p, _, _ := newPipeline(t)
		res, err := p.Submit(ctx, baseRequest())
		if err != nil || !res.Applied || res.RevisionID != 0 {
			t.Fatalf("Submit = %+v, %v; want applied without a revision", res, err)
		}
	})

	t.Run("a revision that cannot be started stops the write", func(t *testing.T) {
		p, hs, s := newPipeline(t)
		p.WithRevisions(&fakeRevisions{beginErr: errors.New("db locked")})
		if _, err := p.Submit(ctx, baseRequest()); err == nil {
			t.Fatal("Submit succeeded, want the revision error")
		}
		for _, c := range hs.Calls() {
			if c == "SetPolicy" {
				t.Fatalf("SetPolicy ran although the revision was not recorded: %v", hs.Calls())
			}
		}
		if n := count(t, s, `SELECT count(*) FROM changes WHERE status = 'applied'`); n != 0 {
			t.Errorf("applied changes = %d, want 0", n)
		}
	})
}

// F3-010: every outcome of an apply ends the revision in the matching state: only a policy that read
// back verified is applied; an unverifiable or mismatching write is unknown; anything refused before
// the write is failed; a dry run is dry_run.
func TestPipeline_RevisionOutcomes(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name  string
		setup func(hs *fakeHeadscale, p *Pipeline)
		want  string
	}{
		{"check rejected", func(hs *fakeHeadscale, _ *Pipeline) { hs.SetCheckErr(&headscale.PolicyError{Message: "no"}) }, RevisionFailed},
		{"set failed, nothing written", func(hs *fakeHeadscale, _ *Pipeline) { hs.SetErr(errors.New("boom")) }, RevisionFailed},
		{"readback differs", func(hs *fakeHeadscale, _ *Pipeline) { hs.SetGetAfter(`{"acls":[]}`) }, RevisionUnknown},
		{"readback fails", func(hs *fakeHeadscale, _ *Pipeline) { hs.SetGetErrAfter(errors.New("down")) }, RevisionUnknown},
		{"set errored but committed", func(hs *fakeHeadscale, _ *Pipeline) { hs.SetErrCommitted(errors.New("rpc")) }, RevisionApplied},
		{"node expiry fails after verified write", func(hs *fakeHeadscale, _ *Pipeline) { hs.SetExpireErr(7, errors.New("x")) }, RevisionApplied},
		{"dry run", func(_ *fakeHeadscale, p *Pipeline) { p.dryRun.(*fakeDryRun).set(true) }, RevisionDryRun},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, hs, _ := newPipeline(t)
			rev := &fakeRevisions{}
			p.WithRevisions(rev)
			tt.setup(hs, p)
			req := baseRequest()
			req.Expire = []uint64{7}
			res, _ := p.Submit(ctx, req)
			if len(rev.finished) != 1 {
				t.Fatalf("finished = %v, want exactly one", rev.finished)
			}
			if got := rev.finished[0].Outcome; got != tt.want {
				t.Errorf("outcome = %q (detail %q), want %q; result %+v", got, rev.finished[0].Detail, tt.want, res)
			}
			if tt.want == RevisionDryRun && res.ChangeID != 0 {
				t.Errorf("a dry run reserved change %d, want none", res.ChangeID)
			}
		})
	}
}

// The request's revision metadata reaches the recorder; the source defaults to sync.
func TestPipeline_RevisionMetaPassedThrough(t *testing.T) {
	p, _, _ := newPipeline(t)
	rev := &fakeRevisions{}
	p.WithRevisions(rev)
	req := baseRequest()
	req.Revision = RevisionMeta{Source: "ui", Reason: "why", Validation: `{"ok":true}`}
	if _, err := p.Submit(context.Background(), req); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if got := rev.begun[0].Revision; got != req.Revision {
		t.Errorf("recorder saw %+v, want %+v", got, req.Revision)
	}
}
