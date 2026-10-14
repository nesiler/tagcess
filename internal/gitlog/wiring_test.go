package gitlog

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Tests of the F2-019 wiring round: the open notes of the core review (poison intent, double alert
// on a failed drain, an unparsable queue line) and the retry reference the change pipeline uses to
// bind a durable version to a revision that was committed late (A-03.4).

func (f *fakeAlerter) count(kind string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, k := range f.kinds {
		if k == kind {
			n++
		}
	}
	return n
}

func (f *fakeAuditor) count(event string) int {
	n := 0
	for _, e := range f.all() {
		if e.Event == event {
			n++
		}
	}
	return n
}

func seedCommit(t *testing.T, log *Log) {
	t.Helper()
	if _, err := log.Commit(context.Background(), CommitRequest{
		Actor: "system:sync", AppliedAt: baseTime,
		Files: []File{{Name: "Caddyfile", Content: []byte("v0")}},
	}); err != nil {
		t.Fatalf("seed commit: %v", err)
	}
}

// LOW 8: an intent that can never commit (its content looks secret) must not stop the queue for
// good: it is quarantined with an audit event and an alert, and the intents behind it still commit
// in order. The secret value never reaches git.
func TestArtifactGit_QuarantinesPoisonIntent(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	log, aud, al := newLog(t, dir)
	ctx := context.Background()
	seedCommit(t, log)

	if _, err := log.queue.Enqueue(ctx, Retry{
		Actor: "alice@example.com", AppliedAt: baseTime, Reason: "index locked",
		Files: []File{{Name: "Caddyfile", Content: []byte("password = hunter2hunter2")}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := log.queue.Enqueue(ctx, Retry{
		Actor: "bob@example.com", AppliedAt: baseTime, Reason: "index locked",
		Files: []File{{Name: "Caddyfile", Content: []byte("v2")}},
	}); err != nil {
		t.Fatal(err)
	}

	results, err := log.RetryPending(ctx)
	if err != nil {
		t.Fatalf("RetryPending: %v", err)
	}
	if len(results) != 1 || !results[0].Committed {
		t.Fatalf("results = %+v, want only the intent behind the poison one committed", results)
	}
	pending, err := log.Pending(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Errorf("pending = %+v, want the poison intent removed", pending)
	}
	if got := gitOut(t, dir, "show", "HEAD:Caddyfile"); got != "v2" {
		t.Errorf("HEAD content = %q, want v2", got)
	}
	if all := gitOut(t, dir, "log", "-p", "--all"); strings.Contains(all, "hunter2") {
		t.Errorf("the secret value reached the git history")
	}
	if aud.count(EventRetryQuarantined) != 1 {
		t.Errorf("quarantine audit events = %d, want 1: %+v", aud.count(EventRetryQuarantined), aud.all())
	}
	if !al.has(AlertGitFailed) {
		t.Errorf("expected alert %s for the quarantined intent, got %v", AlertGitFailed, al.kinds)
	}
}

// Core review note: a drain that fails while a new commit waits behind it raised two alerts and two
// failure audits for one failed attempt. One failed attempt is one alert and one audit event.
func TestArtifactGit_FailedDrainRaisesOneAlert(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	log, aud, al := newLog(t, dir)
	ctx := context.Background()
	seedCommit(t, log)

	lock := filepath.Join(dir, ".git", "index.lock")
	if err := os.WriteFile(lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Commit(ctx, CommitRequest{
		Actor: "alice@example.com", AppliedAt: baseTime,
		Files: []File{{Name: "Caddyfile", Content: []byte("v1")}},
	}); err == nil {
		t.Fatal("Commit with a locked index returned no error")
	}
	alerts, audits := al.count(AlertGitFailed), aud.count(EventCommitFailed)

	// bob's commit first tries to drain alice's intent, which fails; bob's intent queues behind it.
	if _, err := log.Commit(ctx, CommitRequest{
		Actor: "bob@example.com", AppliedAt: baseTime,
		Files: []File{{Name: "Caddyfile", Content: []byte("v2")}},
	}); err == nil {
		t.Fatal("Commit behind a failing drain returned no error")
	}
	if got := al.count(AlertGitFailed) - alerts; got != 1 {
		t.Errorf("alerts for the failed drain = %d, want 1", got)
	}
	if got := aud.count(EventCommitFailed) - audits; got != 1 {
		t.Errorf("failure audit events for the failed drain = %d, want 1", got)
	}
	pending, err := log.Pending(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 2 || pending[0].Actor != "alice@example.com" || pending[1].Actor != "bob@example.com" {
		t.Fatalf("pending = %+v, want [alice bob]", pending)
	}
}

// A public RetryPending that fails still raises its one alert.
func TestArtifactGit_RetryPendingFailureAlerts(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	log, aud, al := newLog(t, dir)
	ctx := context.Background()
	seedCommit(t, log)

	lock := filepath.Join(dir, ".git", "index.lock")
	if err := os.WriteFile(lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Commit(ctx, CommitRequest{
		Actor: "alice@example.com", AppliedAt: baseTime,
		Files: []File{{Name: "Caddyfile", Content: []byte("v1")}},
	}); err == nil {
		t.Fatal("Commit with a locked index returned no error")
	}
	alerts, audits := al.count(AlertGitFailed), aud.count(EventCommitFailed)
	if _, err := log.RetryPending(ctx); err == nil {
		t.Fatal("RetryPending with a locked index returned no error")
	}
	if got := al.count(AlertGitFailed) - alerts; got != 1 {
		t.Errorf("alerts for the failed retry = %d, want 1", got)
	}
	if got := aud.count(EventCommitFailed) - audits; got != 1 {
		t.Errorf("failure audit events for the failed retry = %d, want 1", got)
	}
}

// Core review note: an unparsable line in the middle of the queue stopped every commit for good.
// The line is set aside (kept in a .corrupt file), the intents around it keep their order, and the
// operator hears about it through an audit event and an alert.
func TestArtifactGit_CorruptQueueLineIsSetAside(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	log, aud, al := newLog(t, dir)
	ctx := context.Background()
	seedCommit(t, log)

	if _, err := log.queue.Enqueue(ctx, Retry{
		Actor: "alice@example.com", AppliedAt: baseTime,
		Files: []File{{Name: "Caddyfile", Content: []byte("v1")}},
	}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, ".git", "tagcess-git-retry.jsonl")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("{not json}\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := log.queue.Enqueue(ctx, Retry{
		Actor: "bob@example.com", AppliedAt: baseTime,
		Files: []File{{Name: "Caddyfile", Content: []byte("v2")}},
	}); err != nil {
		t.Fatal(err)
	}

	results, err := log.RetryPending(ctx)
	if err != nil {
		t.Fatalf("RetryPending with a corrupt middle line: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("results = %+v, want the two good intents committed in order", results)
	}
	if got := gitOut(t, dir, "show", "HEAD:Caddyfile"); got != "v2" {
		t.Errorf("HEAD content = %q, want v2", got)
	}
	kept, err := os.ReadFile(path + ".corrupt")
	if err != nil || !strings.Contains(string(kept), "{not json}") {
		t.Errorf("corrupt line not kept for the operator: %q, %v", kept, err)
	}
	if aud.count(EventQueueCorrupt) != 1 {
		t.Errorf("queue-corrupt audit events = %d, want 1", aud.count(EventQueueCorrupt))
	}
	if !al.has(AlertGitFailed) {
		t.Errorf("expected alert %s for the corrupt line, got %v", AlertGitFailed, al.kinds)
	}
}

type refCall struct{ ref, revision string }

type refRecorder struct {
	mu    sync.Mutex
	calls []refCall
}

func (r *refRecorder) bind(_ context.Context, ref, revision string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, refCall{ref, revision})
	return nil
}

// A-03.4: a commit that had to be queued still ends up bound to its durable version. The caller's
// opaque Ref travels with the intent and is handed back, with the real revision, when the intent is
// finally committed — in queue order, by either drain path.
func TestArtifactGit_RetryReportsRef(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	rec := &refRecorder{}
	log, err := New(Config{Dir: dir, OnRetried: rec.bind})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	seedCommit(t, log)

	lock := filepath.Join(dir, ".git", "index.lock")
	if err := os.WriteFile(lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{"site-change:7", "site-change:8"} {
		if _, err := log.Commit(ctx, CommitRequest{
			Actor: "alice@example.com", AppliedAt: baseTime, Ref: ref,
			Files: []File{{Name: "Caddyfile", Content: []byte("content of " + ref)}},
		}); err == nil {
			t.Fatal("Commit with a locked index returned no error")
		}
	}
	if err := os.Remove(lock); err != nil {
		t.Fatal(err)
	}

	// A third commit drains the two intents first, then commits itself; its own Ref is not reported
	// through the hook (the caller has the Result).
	res, err := log.Commit(ctx, CommitRequest{
		Actor: "bob@example.com", AppliedAt: baseTime, Ref: "site-change:9",
		Files: []File{{Name: "Caddyfile", Content: []byte("content of site-change:9")}},
	})
	if err != nil {
		t.Fatalf("Commit after the lock was released: %v", err)
	}
	if len(rec.calls) != 2 || rec.calls[0].ref != "site-change:7" || rec.calls[1].ref != "site-change:8" {
		t.Fatalf("hook calls = %+v, want the two drained refs in order", rec.calls)
	}
	for _, c := range rec.calls {
		if len(c.revision) != 40 || c.revision == res.Revision {
			t.Errorf("revision for %s = %q, want its own commit (not the newest %s)", c.ref, c.revision, res.Revision)
		}
	}
	// The revision handed to the hook is the commit that holds that intent's content.
	if got := gitOut(t, dir, "show", rec.calls[0].revision+":Caddyfile"); got != "content of site-change:7" {
		t.Errorf("revision %s holds %q, want the first intent's content", rec.calls[0].revision, got)
	}
}
