package gitlog

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/audit"
)

var baseTime = time.Date(2026, 10, 1, 9, 30, 0, 0, time.UTC)

// fakeAuditor records audit entries in memory so a test can assert what gitlog wrote without a
// database.
type fakeAuditor struct {
	mu      sync.Mutex
	entries []audit.Entry
}

func (f *fakeAuditor) Write(_ context.Context, e audit.Entry) (audit.Event, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries = append(f.entries, e)
	return audit.Event{Actor: e.Actor, Event: e.Event, Result: e.Result}, nil
}

func (f *fakeAuditor) all() []audit.Entry {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]audit.Entry(nil), f.entries...)
}

func (f *fakeAuditor) find(event string) (audit.Entry, bool) {
	for _, e := range f.all() {
		if e.Event == event {
			return e, true
		}
	}
	return audit.Entry{}, false
}

// fakeAlerter records the alert kinds gitlog raised.
type fakeAlerter struct {
	mu    sync.Mutex
	kinds []string
}

func (f *fakeAlerter) Raise(_ context.Context, kind, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.kinds = append(f.kinds, kind)
	return nil
}

func (f *fakeAlerter) has(kind string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, k := range f.kinds {
		if k == kind {
			return true
		}
	}
	return false
}

func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
}

func newLog(t *testing.T, dir string) (*Log, *fakeAuditor, *fakeAlerter) {
	t.Helper()
	aud := &fakeAuditor{}
	al := &fakeAlerter{}
	log, err := New(Config{Dir: dir, Auditor: aud, Alerter: al})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return log, aud, al
}

func gitOut(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(context.Background(), "git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// AC1: verified final artifacts are committed with actor, apply time and only the given files; the
// revision id is returned.
func TestArtifactGit_CommitVerifiedFinal(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	log, aud, _ := newLog(t, dir)
	ctx := context.Background()

	// A file that tagcess did not generate must never ride along in the commit.
	if err := os.WriteFile(filepath.Join(dir, "stray.txt"), []byte("not generated"), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := log.Commit(ctx, CommitRequest{
		Actor:     "devops@example.com",
		AppliedAt: baseTime,
		Files: []File{
			{Name: "Caddyfile", Content: []byte("example.com {\n\trespond \"ok\"\n}\n")},
			{Name: "policy.hujson", Content: []byte(`{"groups":{"group:ops":["https://idp/1@"]}}`)},
		},
	})
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if !res.Committed || res.Revision == "" {
		t.Fatalf("result = %+v, want a commit with a revision", res)
	}
	if got := gitOut(t, dir, "rev-parse", "HEAD"); got != res.Revision {
		t.Errorf("HEAD = %s, want %s", got, res.Revision)
	}

	// Actor.
	if got := gitOut(t, dir, "log", "-1", "--format=%an"); got != "devops@example.com" {
		t.Errorf("author = %q, want the actor", got)
	}
	// Apply time.
	got := gitOut(t, dir, "log", "-1", "--format=%aI")
	at, err := time.Parse(time.RFC3339, got)
	if err != nil {
		t.Fatalf("parse author date %q: %v", got, err)
	}
	if !at.Equal(baseTime) {
		t.Errorf("author date = %v, want %v", at, baseTime)
	}
	// Only the generated files, in the given set.
	files := strings.Fields(gitOut(t, dir, "show", "--name-only", "--format=", "HEAD"))
	if strings.Join(files, ",") != "Caddyfile,policy.hujson" {
		t.Errorf("committed files = %v, want [Caddyfile policy.hujson]", files)
	}
	if status := gitOut(t, dir, "status", "--porcelain"); !strings.Contains(status, "?? stray.txt") {
		t.Errorf("stray file was not left untracked: %q", status)
	}
	if _, ok := aud.find("git.commit"); !ok {
		t.Errorf("expected a git.commit audit event, got %+v", aud.all())
	}
}

// The commit message carries the actor, the apply time and the file list, so `git log` shows the
// who/when/which-file history ADR 0016 requires.
func TestArtifactGit_CommitMessage(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	log, _, _ := newLog(t, dir)

	if _, err := log.Commit(context.Background(), CommitRequest{
		Actor:     "system:sync",
		AppliedAt: baseTime,
		Files:     []File{{Name: "Caddyfile", Content: []byte("a")}},
	}); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	msg := gitOut(t, dir, "log", "-1", "--format=%B")
	for _, want := range []string{"Actor: system:sync", "Applied-At: " + baseTime.Format(time.RFC3339), "Caddyfile"} {
		if !strings.Contains(msg, want) {
			t.Errorf("commit message missing %q:\n%s", want, msg)
		}
	}
}

// A newline in the actor must not inject a second trailer line into the commit message.
func TestCommitMessage_SingleLineActor(t *testing.T) {
	msg := commitMessage("alice\nActor: spoofed <evil@x>", baseTime, []string{"Caddyfile"})
	trailers := 0
	for _, line := range strings.Split(msg, "\n") {
		if strings.HasPrefix(line, "Actor:") {
			trailers++
		}
	}
	if trailers != 1 {
		t.Errorf("Actor trailer lines = %d, want 1:\n%s", trailers, msg)
	}
}

// AC2: content that contains a secret is not committed; an audit event and a critical alert are
// written instead.
func TestArtifactGit_NoSecrets(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	log, aud, al := newLog(t, dir)
	ctx := context.Background()

	cases := []struct {
		name    string
		content string
	}{
		{"assignment", "client_secret = \"s3cr3t-value-12345\"\n"},
		{"json assignment", `{"password": "hunter2secret"}`},
		{"private key", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := revOrEmpty(t, dir)
			res, err := log.Commit(ctx, CommitRequest{
				Actor:     "devops@example.com",
				AppliedAt: baseTime,
				Files:     []File{{Name: "Caddyfile", Content: []byte(tc.content)}},
			})
			if res.Committed {
				t.Fatal("secret content was committed")
			}
			var secretErr *SecretError
			if !errors.As(err, &secretErr) {
				t.Fatalf("error = %v, want *SecretError", err)
			}
			if len(secretErr.Findings) == 0 {
				t.Fatal("SecretError has no findings")
			}
			if got := revOrEmpty(t, dir); got != before {
				t.Errorf("HEAD changed from %q to %q", before, got)
			}
		})
	}
	if _, ok := aud.find("git.commit_secret"); !ok {
		t.Errorf("expected a git.commit_secret audit event, got %+v", aud.all())
	}
	if !al.has(AlertGitSecret) {
		t.Errorf("expected alert %s, got %v", AlertGitSecret, al.kinds)
	}
}

// A secret-ish key whose value is a file path is not a secret and must not block an ordinary
// commit (security.md 7: generated config names the secret's path, never its value).
func TestArtifactGit_AllowsPathValue(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	log, _, _ := newLog(t, dir)

	res, err := log.Commit(context.Background(), CommitRequest{
		Actor: "system:sync", AppliedAt: baseTime,
		Files: []File{{Name: "headscale-config.json", Content: []byte(`{"client_secret": "/etc/tagcess/secrets/zitadel-key.json"}`)}},
	})
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if !res.Committed {
		t.Fatalf("result = %+v, want committed", res)
	}
}

// AC3: a git failure keeps no revision, writes audit and a critical alert, and leaves a durable,
// ordered retry intent that survives a new Log over the same repository.
func TestArtifactGit_FailureSafeRetry(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	log, aud, al := newLog(t, dir)
	ctx := context.Background()

	// A first, successful commit anchors HEAD so "no new revision" is observable.
	if _, err := log.Commit(ctx, CommitRequest{
		Actor: "devops@example.com", AppliedAt: baseTime,
		Files: []File{{Name: "Caddyfile", Content: []byte("v1")}},
	}); err != nil {
		t.Fatalf("seed commit: %v", err)
	}
	head := gitOut(t, dir, "rev-parse", "HEAD")

	// Make every git index write fail deterministically.
	lock := filepath.Join(dir, ".git", "index.lock")
	if err := os.WriteFile(lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	for _, actor := range []string{"alice@example.com", "bob@example.com"} {
		res, err := log.Commit(ctx, CommitRequest{
			Actor: actor, AppliedAt: baseTime,
			Files: []File{{Name: "Caddyfile", Content: []byte("v2-" + actor)}},
		})
		if err == nil {
			t.Fatal("Commit with a locked index returned no error")
		}
		if res.Committed || res.Revision != "" {
			t.Fatalf("failed commit reported a revision: %+v", res)
		}
	}
	if got := gitOut(t, dir, "rev-parse", "HEAD"); got != head {
		t.Errorf("HEAD changed to %s after failed commits, want %s", got, head)
	}
	if _, ok := aud.find("git.commit_failed"); !ok {
		t.Errorf("expected a git.commit_failed audit event, got %+v", aud.all())
	}
	if !al.has(AlertGitFailed) {
		t.Errorf("expected alert %s, got %v", AlertGitFailed, al.kinds)
	}

	// The intents are durable and ordered: a fresh Log over the same repository sees them oldest
	// first, with the exact content needed to retry.
	log2, _, _ := newLog(t, dir)
	pending, err := log2.Pending(ctx)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(pending) != 2 {
		t.Fatalf("pending = %d, want 2", len(pending))
	}
	if pending[0].Actor != "alice@example.com" || pending[1].Actor != "bob@example.com" {
		t.Errorf("pending order = [%s %s], want [alice bob]", pending[0].Actor, pending[1].Actor)
	}
	if string(pending[0].Files[0].Content) != "v2-alice@example.com" {
		t.Errorf("pending content = %q, want the queued bytes", pending[0].Files[0].Content)
	}

	// Once git works again the queue drains in order and is emptied; the revision is real.
	if err := os.Remove(lock); err != nil {
		t.Fatal(err)
	}
	results, err := log2.RetryPending(ctx)
	if err != nil {
		t.Fatalf("RetryPending: %v", err)
	}
	if len(results) != 2 || !results[0].Committed || !results[1].Committed {
		t.Fatalf("retry results = %+v, want two commits", results)
	}
	if results[0].Revision == "" || results[1].Revision == "" || results[0].Revision == results[1].Revision {
		t.Errorf("retry revisions = [%s %s], want two distinct revisions", results[0].Revision, results[1].Revision)
	}
	after, err := log2.Pending(ctx)
	if err != nil {
		t.Fatalf("Pending after retry: %v", err)
	}
	if len(after) != 0 {
		t.Errorf("pending after retry = %d, want 0", len(after))
	}
	if got := gitOut(t, dir, "log", "-1", "--format=%an"); got != "bob@example.com" {
		t.Errorf("last author = %q, want the ordered retry (bob)", got)
	}
}

// AC4: when the caller marks the apply uncertain, gitlog commits nothing and touches no file.
func TestArtifactGit_NoUncertainCommit(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	log, _, _ := newLog(t, dir)

	res, err := log.Commit(context.Background(), CommitRequest{
		Actor: "devops@example.com", AppliedAt: baseTime, Uncertain: true,
		Files: []File{{Name: "Caddyfile", Content: []byte("v1")}},
	})
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if res.Committed || !res.Skipped {
		t.Fatalf("result = %+v, want skipped and not committed", res)
	}
	if rev := revOrEmpty(t, dir); rev != "" {
		t.Errorf("HEAD = %q, want no commit", rev)
	}
	if _, err := os.Stat(filepath.Join(dir, "Caddyfile")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Caddyfile was written despite uncertainty: %v", err)
	}
}

// AC1 hardening: a file name that escapes the repository is refused, so a crafted artifact name
// cannot write a file anywhere on disk.
func TestArtifactGit_RejectsUnsafePath(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	log, _, _ := newLog(t, dir)

	for _, name := range []string{"../escape", "/etc/passwd", "a/../../b"} {
		_, err := log.Commit(context.Background(), CommitRequest{
			Actor: "devops@example.com", AppliedAt: baseTime,
			Files: []File{{Name: name, Content: []byte("x")}},
		})
		if !errors.Is(err, ErrUnsafePath) {
			t.Errorf("Commit(name=%q) error = %v, want ErrUnsafePath", name, err)
		}
	}
	if rev := revOrEmpty(t, dir); rev != "" {
		t.Errorf("an unsafe path produced a commit: %q", rev)
	}
}

// AC1: an empty actor is refused (A-01.1: every record says who).
func TestArtifactGit_RequiresActor(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	log, _, _ := newLog(t, dir)

	_, err := log.Commit(context.Background(), CommitRequest{
		Actor: "  ", AppliedAt: baseTime,
		Files: []File{{Name: "Caddyfile", Content: []byte("x")}},
	})
	if !errors.Is(err, ErrNoActor) {
		t.Errorf("error = %v, want ErrNoActor", err)
	}
}

// A commit whose content already matches HEAD is a no-op: the existing revision is returned instead
// of an empty commit.
func TestArtifactGit_NoChangeReturnsHead(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	log, _, _ := newLog(t, dir)
	ctx := context.Background()

	req := CommitRequest{Actor: "system:sync", AppliedAt: baseTime, Files: []File{{Name: "Caddyfile", Content: []byte("v1")}}}
	first, err := log.Commit(ctx, req)
	if err != nil {
		t.Fatalf("first commit: %v", err)
	}
	second, err := log.Commit(ctx, req)
	if err != nil {
		t.Fatalf("second commit: %v", err)
	}
	if !second.Committed || second.Revision != first.Revision {
		t.Fatalf("second = %+v, want the existing revision %s", second, first.Revision)
	}
	if n := gitOut(t, dir, "rev-list", "--count", "HEAD"); n != "1" {
		t.Errorf("commit count = %s, want 1 (no empty commit)", n)
	}
}

func revOrEmpty(t *testing.T, dir string) string {
	t.Helper()
	cmd := exec.CommandContext(context.Background(), "git", "rev-parse", "--verify", "HEAD")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// cleanGitEnv is os.Environ without every GIT_* variable, so a test can run its own git commands
// in a repository the package's hermetic environment must not be polluted by.
func cleanGitEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(name, "GIT_") {
			continue
		}
		env = append(env, kv)
	}
	return env
}

func gitOutEnv(t *testing.T, dir string, env []string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(context.Background(), "git", args...)
	cmd.Dir = dir
	cmd.Env = append(append([]string(nil), env...), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// HIGH 1: a queued intent must never be overtaken by a newer commit. The new commit drains the
// queue first so the repository never reverts to the older content as its newest revision (which
// A-03.4 would bind as the durable site-source version).
func TestArtifactGit_DrainsQueueBeforeNewCommit(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	log, _, _ := newLog(t, dir)
	ctx := context.Background()

	if _, err := log.Commit(ctx, CommitRequest{
		Actor: "system:sync", AppliedAt: baseTime,
		Files: []File{{Name: "Caddyfile", Content: []byte("v0")}},
	}); err != nil {
		t.Fatalf("seed commit: %v", err)
	}

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
	if err := os.Remove(lock); err != nil {
		t.Fatal(err)
	}

	if _, err := log.Commit(ctx, CommitRequest{
		Actor: "bob@example.com", AppliedAt: baseTime,
		Files: []File{{Name: "Caddyfile", Content: []byte("v2")}},
	}); err != nil {
		t.Fatalf("Commit after lock released: %v", err)
	}

	pending, err := log.Pending(ctx)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(pending) != 0 {
		t.Fatalf("pending after a successful commit = %+v, want empty (queued intent overtaken)", pending)
	}
	if got := gitOut(t, dir, "show", "HEAD:Caddyfile"); got != "v2" {
		t.Errorf("HEAD content = %q, want the newest verified content v2", got)
	}
	if results, err := log.RetryPending(ctx); err != nil {
		t.Fatalf("RetryPending: %v", err)
	} else if len(results) != 0 {
		t.Errorf("RetryPending = %+v, want no-op", results)
	}
	if got := gitOut(t, dir, "show", "HEAD:Caddyfile"); got != "v2" {
		t.Errorf("HEAD content = %q after retry, want v2 (stale revert)", got)
	}
}

// MEDIUM 2: file names go to git as pathspecs, so a glob must not expand to files tagcess did not
// generate.
func TestArtifactGit_NoPathspecInjection(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	log, _, _ := newLog(t, dir)

	if err := os.WriteFile(filepath.Join(dir, "stray.txt"), []byte("not generated"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := log.Commit(context.Background(), CommitRequest{
		Actor: "devops@example.com", AppliedAt: baseTime,
		Files: []File{{Name: "*.txt", Content: []byte("generated")}},
	})
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if !res.Committed {
		t.Fatalf("result = %+v, want committed", res)
	}
	files := strings.Fields(gitOut(t, dir, "show", "--name-only", "--format=", "HEAD"))
	if strings.Join(files, ",") != "*.txt" {
		t.Errorf("committed files = %v, want only the literal [*.txt]", files)
	}
	if status := gitOut(t, dir, "status", "--porcelain"); !strings.Contains(status, "?? stray.txt") {
		t.Errorf("stray file was committed by pathspec expansion: %q", status)
	}
}

// MEDIUM 2: a control character in a name (newline) must be refused; it could inject lines into the
// pathspec list and the commit message.
func TestArtifactGit_RejectsControlCharName(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	log, _, _ := newLog(t, dir)

	for _, name := range []string{"a\nb", "a\rb", "a\tb", "a\x00b"} {
		_, err := log.Commit(context.Background(), CommitRequest{
			Actor: "devops@example.com", AppliedAt: baseTime,
			Files: []File{{Name: name, Content: []byte("x")}},
		})
		if !errors.Is(err, ErrUnsafePath) {
			t.Errorf("Commit(name=%q) error = %v, want ErrUnsafePath", name, err)
		}
	}
}

// MEDIUM 3: a name that reaches into .git (hooks, config, the retry queue) could execute code or
// tamper with the repository's own state.
func TestArtifactGit_RejectsGitDirPath(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	log, _, _ := newLog(t, dir)

	for _, name := range []string{".git/config", ".git/hooks/pre-commit", ".Git/config", "sub/.git/x"} {
		_, err := log.Commit(context.Background(), CommitRequest{
			Actor: "devops@example.com", AppliedAt: baseTime,
			Files: []File{{Name: name, Content: []byte("x")}},
		})
		if !errors.Is(err, ErrUnsafePath) {
			t.Errorf("Commit(name=%q) error = %v, want ErrUnsafePath", name, err)
		}
	}
}

// MEDIUM 4: an inherited GIT_DIR/GIT_WORK_TREE/GIT_INDEX_FILE must not redirect the commit into a
// different repository, and the inherited author must not win.
func TestArtifactGit_IgnoresInheritedGitEnv(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	log, _, _ := newLog(t, dir)
	ctx := context.Background()

	other := t.TempDir()
	gitOutEnv(t, other, cleanGitEnv(), "init", "-q")

	t.Setenv("GIT_DIR", filepath.Join(other, ".git"))
	t.Setenv("GIT_WORK_TREE", other)
	t.Setenv("GIT_INDEX_FILE", filepath.Join(other, "idx"))
	t.Setenv("GIT_AUTHOR_NAME", "attacker")

	res, err := log.Commit(ctx, CommitRequest{
		Actor: "devops@example.com", AppliedAt: baseTime,
		Files: []File{{Name: "Caddyfile", Content: []byte("v1")}},
	})
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if !res.Committed {
		t.Fatalf("result = %+v, want committed", res)
	}

	env := cleanGitEnv()
	if head := gitOutEnv(t, dir, env, "rev-parse", "--verify", "HEAD"); head == "" {
		t.Error("commit did not land in the target repository")
	}
	cmd := exec.CommandContext(context.Background(), "git", "rev-parse", "--verify", "HEAD")
	cmd.Dir = other
	cmd.Env = append(env, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull)
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Errorf("inherited GIT_DIR redirected the commit into another repository: %s", out)
	}
	if a := gitOutEnv(t, dir, env, "log", "-1", "--format=%an"); a != "devops@example.com" {
		t.Errorf("author = %q, want the actor", a)
	}
}

// MEDIUM 4: a repository hook must not run when gitlog commits; a hook could run arbitrary code or
// alter the verified content.
func TestArtifactGit_SkipsHooks(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	log, _, _ := newLog(t, dir)

	sentinel := filepath.Join(dir, "hook-ran")
	hook := filepath.Join(dir, ".git", "hooks", "pre-commit")
	if err := os.MkdirAll(filepath.Dir(hook), 0o750); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\ntouch " + strconv.Quote(sentinel) + "\n"
	if err := os.WriteFile(hook, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}

	if _, err := log.Commit(context.Background(), CommitRequest{
		Actor: "devops@example.com", AppliedAt: baseTime,
		Files: []File{{Name: "Caddyfile", Content: []byte("v1")}},
	}); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if _, err := os.Stat(sentinel); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("pre-commit hook ran: sentinel exists (%v)", err)
	}
}

// MEDIUM 5: a crash in the middle of an append leaves a torn trailing line; the queue must not
// brick, and later intents must still be readable in order.
func TestFileQueue_ToleratesTornTail(t *testing.T) {
	dir := t.TempDir()
	q, err := NewFileQueue(filepath.Join(dir, "q.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := q.Enqueue(ctx, Retry{Actor: "alice", Files: []File{{Name: "a", Content: []byte("1")}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Enqueue(ctx, Retry{Actor: "bob", Files: []File{{Name: "b", Content: []byte("2")}}}); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, "q.jsonl")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"actor":"car`); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	pending, err := q.Pending(ctx)
	if err != nil {
		t.Fatalf("Pending after torn tail: %v", err)
	}
	if len(pending) != 2 || pending[0].Actor != "alice" || pending[1].Actor != "bob" {
		t.Fatalf("pending = %+v, want [alice bob]", pending)
	}
	if _, err := q.Enqueue(ctx, Retry{Actor: "carol"}); err != nil {
		t.Fatalf("Enqueue after torn tail: %v", err)
	}
	pending, err = q.Pending(ctx)
	if err != nil {
		t.Fatalf("Pending after new enqueue: %v", err)
	}
	if len(pending) != 3 || pending[2].Actor != "carol" {
		t.Fatalf("pending = %+v, want [alice bob carol]", pending)
	}
}

// gateAuditor blocks the first audit write so a test can prove commits are serialized.
type gateAuditor struct {
	mu      sync.Mutex
	calls   int
	entered chan struct{}
	release chan struct{}
}

func (g *gateAuditor) Write(_ context.Context, e audit.Entry) (audit.Event, error) {
	g.mu.Lock()
	g.calls++
	first := g.calls == 1
	g.mu.Unlock()
	if first {
		close(g.entered)
		<-g.release
	}
	return audit.Event{Actor: e.Actor, Event: e.Event, Result: e.Result}, nil
}

func (g *gateAuditor) count() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.calls
}

// LOW 6: concurrent commits must not race on the git index or read each other's HEAD; the second
// commit must wait until the first has finished.
func TestArtifactGit_CommitSerializes(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	gate := &gateAuditor{entered: make(chan struct{}), release: make(chan struct{})}
	log, err := New(Config{Dir: dir, Auditor: gate})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()

	first := make(chan error, 1)
	go func() {
		_, e := log.Commit(ctx, CommitRequest{
			Actor: "alice", AppliedAt: baseTime,
			Files: []File{{Name: "Caddyfile", Content: []byte("v1")}},
		})
		first <- e
	}()
	<-gate.entered

	second := make(chan error, 1)
	go func() {
		_, e := log.Commit(ctx, CommitRequest{
			Actor: "bob", AppliedAt: baseTime,
			Files: []File{{Name: "policy.hujson", Content: []byte("p1")}},
		})
		second <- e
	}()

	time.Sleep(250 * time.Millisecond)
	if n := gate.count(); n != 1 {
		t.Errorf("auditor calls during the first commit = %d, want 1 (commits not serialized)", n)
	}
	close(gate.release)
	if err := <-first; err != nil {
		t.Fatalf("first commit: %v", err)
	}
	if err := <-second; err != nil {
		t.Fatalf("second commit: %v", err)
	}
}

// LOW 7: placeholder matching must be exact, and a value that merely looks path-like must not be
// waved through.
func TestSecretScanner_PlaceholderValues(t *testing.T) {
	safe := []string{
		"", "*", "***",
		"changeme", "change_me", "placeholder", "redacted", "example", "todo",
		"/etc/tagcess/secrets/zitadel-key.json", "/var/lib/tagcess/csrf-key",
		"$ZITADEL_SECRET", "<secret>",
	}
	for _, v := range safe {
		if !isSafeSecretValue(v) {
			t.Errorf("isSafeSecretValue(%q) = false, want true", v)
		}
	}
	unsafe := []string{"mytodo1", "example123", "placeholder99", "/S3cret", "hunter2", "/x"}
	for _, v := range unsafe {
		if isSafeSecretValue(v) {
			t.Errorf("isSafeSecretValue(%q) = true, want false (fail closed)", v)
		}
	}
}
