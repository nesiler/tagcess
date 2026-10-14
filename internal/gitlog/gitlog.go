// Package gitlog commits the final, verified artifacts tagcess produced (Caddyfile, Headscale
// policy, MagicDNS records and other generated files) to a local git repository (A-02, ADR 0016).
// Only the files handed in are committed; every commit carries the actor, the apply time and the
// file list, and the resulting revision id is returned so the interface can bind a durable version
// to it (A-03.4). Content that looks like a secret is refused (AC2). When git fails, the verified
// live/disk state is untouched, an audit event and a critical alert are written, and the commit is
// kept as a durable, ordered retry intent instead of being shown as a success (AC3). A caller that
// marks the apply uncertain gets no commit at all (AC4).
//
// The package is standalone: it knows nothing about internal/change, the store or the renderer. The
// caller injects the audit writer, the alerter, the secret scanner and the retry queue; the queue
// and scanner have file- and regexp-based defaults here, and a later wiring round may pass the
// store-backed queue. Git runs as a subprocess with explicit arguments, never through a shell.
package gitlog

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/nesiler/tagcess/internal/audit"
)

// Alert kinds raised by the package. They are distinct so the dashboard tells a secret refusal
// apart from a git failure.
const (
	// AlertGitSecret is raised when an artifact was refused because it looks like it contains a
	// secret; nothing was committed (AC2, NFR-04).
	AlertGitSecret = "git_secret"
	// AlertGitFailed is raised when a verified artifact could not be committed; the intent is queued
	// for retry and the verified live/disk state is kept (AC3, rule 7).
	AlertGitFailed = "git_failed"
)

// Audit events written by the package.
const (
	EventCommit        = "git.commit"
	EventCommitSecret  = "git.commit_secret" //nolint:gosec // G101: an audit event name, not a credential
	EventCommitFailed  = "git.commit_failed"
	EventSkipUncertain = "git.skip_uncertain"
	// EventRetryQuarantined: a queued intent can never commit (its content looks secret, its name is
	// unsafe) and was dropped from the queue so the intents behind it can go on.
	EventRetryQuarantined = "git.retry_quarantined"
	// EventQueueCorrupt: an unparsable line was set aside from the retry queue.
	EventQueueCorrupt = "git.queue_corrupt"
)

var (
	// ErrNoActor is returned when a commit has no actor (A-01.1: every record says who).
	ErrNoActor = errors.New("gitlog: actor is required")
	// ErrUnsafePath is returned when an artifact name would escape the repository. It is a
	// fail-closed guard: a crafted name must never write outside the repository.
	ErrUnsafePath = errors.New("gitlog: unsafe artifact path")
)

// File is one generated artifact: a repository-relative name and its exact bytes.
type File struct {
	Name    string `json:"name"`
	Content []byte `json:"content"`
}

// CommitRequest is one commit of verified final artifacts. Uncertain means the caller could not
// confirm the apply (the readback failed): the package then commits nothing (AC4).
type CommitRequest struct {
	Actor     string
	AppliedAt time.Time
	Files     []File
	Uncertain bool
	// Ref is an opaque token of the caller (e.g. "site-change:12"). It is stored with a queued intent
	// and handed to Config.OnRetried with the real revision once that intent is committed, so the
	// caller can bind a durable record to a revision that arrived late (A-03.4).
	Ref string
}

// Result reports what the package did. A no-op (identical content) returns the existing revision,
// so A-03 can always bind a version.
type Result struct {
	Revision  string
	Committed bool
	Skipped   bool
}

// Retry is one queued commit intent: everything needed to retry a failed commit later (AC3).
type Retry struct {
	ID        int64     `json:"id"`
	Actor     string    `json:"actor"`
	AppliedAt time.Time `json:"applied_at"`
	Files     []File    `json:"files"`
	Reason    string    `json:"reason"`
	QueuedAt  time.Time `json:"queued_at"`
	Ref       string    `json:"ref,omitempty"`
}

// Queue is the durable, ordered retry store. Enqueue appends an intent and returns its id; Pending
// returns them oldest first; Complete removes a drained intent. The default is a file-backed queue
// (NewFileQueue); a store table can implement the same interface in the wiring round.
type Queue interface {
	Enqueue(ctx context.Context, r Retry) (int64, error)
	Pending(ctx context.Context) ([]Retry, error)
	Complete(ctx context.Context, id int64) error
}

// Auditor is the append-only audit log. It is satisfied by *audit.Logger.
type Auditor interface {
	Write(ctx context.Context, e audit.Entry) (audit.Event, error)
}

// Alerter raises a critical alert. It is satisfied by a small adapter over the alerts table.
type Alerter interface {
	Raise(ctx context.Context, kind, source string) error
}

// Config configures a Log. Only Dir is required; the rest have safe defaults.
type Config struct {
	// Dir is the git working tree. It is created and initialized if missing.
	Dir string
	// Queue is the durable retry store. Defaults to a file inside the repository's .git directory.
	Queue Queue
	// Auditor and Alerter receive the package's events and alerts. They may be nil (no-op), but the
	// wiring must set them so a refusal or failure is visible (AC2, AC3).
	Auditor Auditor
	Alerter Alerter
	// Scanner detects secrets in content. Defaults to DefaultScanner.
	Scanner Scanner
	// GitBin is the git executable. Defaults to "git".
	GitBin string
	// Clock is used when a request has no apply time and to stamp retry intents.
	Clock func() time.Time
	// OnRetried is called with the Ref and the revision of a queued intent right after it was
	// committed by a drain. A failure keeps the intent queued (the commit is idempotent, so the retry
	// reports the same revision). It is not called for a commit that succeeded the first time: the
	// caller has that Result.
	OnRetried func(ctx context.Context, ref, revision string) error
}

// Log commits generated artifacts to one local repository. It serializes its own commits so two
// callers never race on the git index or read each other's HEAD (LOW 6).
type Log struct {
	mu      sync.Mutex
	dir     string
	home    string
	gitBin  string
	queue   Queue
	auditor Auditor
	alerter Alerter
	scanner Scanner
	clock   func() time.Time
	onRetry func(ctx context.Context, ref, revision string) error
}

// New returns a Log for the repository at cfg.Dir, creating and initializing it if needed. A
// missing repository is initialized here so no manual step is left behind (rule 6).
func New(cfg Config) (*Log, error) {
	if strings.TrimSpace(cfg.Dir) == "" {
		return nil, errors.New("gitlog: Dir is required")
	}
	if err := os.MkdirAll(cfg.Dir, 0o750); err != nil {
		return nil, fmt.Errorf("gitlog: create repository dir: %w", err)
	}
	l := &Log{
		dir:     cfg.Dir,
		home:    filepath.Join(cfg.Dir, ".git", "tagcess-git-home"),
		gitBin:  cfg.GitBin,
		queue:   cfg.Queue,
		auditor: cfg.Auditor,
		alerter: cfg.Alerter,
		scanner: cfg.Scanner,
		clock:   cfg.Clock,
		onRetry: cfg.OnRetried,
	}
	if l.gitBin == "" {
		l.gitBin = "git"
	}
	if l.clock == nil {
		l.clock = time.Now
	}
	if l.scanner == nil {
		l.scanner = DefaultScanner()
	}
	if _, err := os.Stat(filepath.Join(l.dir, ".git")); errors.Is(err, os.ErrNotExist) {
		if _, err := l.git(context.Background(), nil, "", "init", "-q"); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, fmt.Errorf("gitlog: inspect repository: %w", err)
	}
	if err := os.MkdirAll(l.home, 0o750); err != nil {
		return nil, fmt.Errorf("gitlog: create git home: %w", err)
	}
	if l.queue == nil {
		q, err := NewFileQueue(filepath.Join(l.dir, ".git", "tagcess-git-retry.jsonl"))
		if err != nil {
			return nil, err
		}
		l.queue = q
	}
	return l, nil
}

// Commit writes the given verified files and commits them, returning the revision id. It performs
// no commit when the request is uncertain (AC4), when there are no files, or when the content
// matches the current revision (the existing revision is returned).
func (l *Log) Commit(ctx context.Context, req CommitRequest) (Result, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.commit(ctx, req, modeFresh)
}

// commit modes: a fresh request queues itself and reports a failure (audit + alert); a drained
// intent is already queued, and a failure inside a drain is reported by whoever started the drain.
type commitMode int

const (
	modeFresh commitMode = iota
	modeRetry
)

func (l *Log) commit(ctx context.Context, req CommitRequest, mode commitMode) (Result, error) {
	queueOnFailure := mode == modeFresh
	actor := strings.TrimSpace(req.Actor)
	if actor == "" {
		return Result{}, ErrNoActor
	}
	if req.Uncertain {
		_ = l.audit(ctx, audit.Entry{
			Actor: actor, Event: EventSkipUncertain, Target: "git", Result: "skipped",
			Diff: audit.Diff{{Field: "reason", After: "apply uncertain"}},
		})
		return Result{Skipped: true}, nil
	}
	if len(req.Files) == 0 {
		return Result{Skipped: true}, nil
	}
	for _, f := range req.Files {
		if err := validateName(f.Name); err != nil {
			return Result{}, err
		}
	}
	if findings := l.scanner.Find(req.Files); len(findings) > 0 {
		secretErr := &SecretError{Findings: findings}
		return Result{}, errors.Join(secretErr,
			l.audit(ctx, audit.Entry{
				Actor: actor, Event: EventCommitSecret, Target: "git", Result: "blocked",
				Diff: audit.Diff{{Field: "secret", After: findingsText(findings)}},
			}),
			l.raise(ctx, AlertGitSecret, "git"),
		)
	}

	appliedAt := req.AppliedAt
	if appliedAt.IsZero() {
		appliedAt = l.clock()
	}

	// A queued intent must never be overtaken: it holds older verified content that A-03.4 binds a
	// durable version to. Drain the queue first; if it cannot drain, queue this request behind the
	// pending ones and report the failure instead of committing out of order (HIGH 1).
	if queueOnFailure {
		pending, err := l.pending(ctx)
		if err != nil {
			return l.fail(ctx, req, actor, appliedAt, true, err)
		}
		if len(pending) > 0 {
			// A failed drain is reported once, by fail below.
			if _, err := l.retryPending(ctx, false); err != nil {
				return l.fail(ctx, req, actor, appliedAt, true, err)
			}
		}
	}

	names := make([]string, 0, len(req.Files))
	for _, f := range req.Files {
		if err := l.writeFile(f); err != nil {
			return l.fail(ctx, req, actor, appliedAt, queueOnFailure, err)
		}
		names = append(names, f.Name)
	}

	if _, err := l.git(ctx, nil, "", append([]string{"add", "--"}, names...)...); err != nil {
		return l.fail(ctx, req, actor, appliedAt, queueOnFailure, err)
	}
	status, err := l.git(ctx, nil, "", append([]string{"status", "--porcelain", "--"}, names...)...)
	if err != nil {
		return l.fail(ctx, req, actor, appliedAt, queueOnFailure, err)
	}
	if strings.TrimSpace(status) == "" {
		rev, err := l.revision(ctx)
		if err != nil {
			return l.fail(ctx, req, actor, appliedAt, queueOnFailure, err)
		}
		return Result{Revision: rev, Committed: true}, l.audit(ctx, l.commitEntry(actor, rev, names))
	}

	env := []string{
		"GIT_AUTHOR_NAME=" + authorName(actor),
		"GIT_AUTHOR_EMAIL=tagcess@localhost",
		"GIT_COMMITTER_NAME=tagcess",
		"GIT_COMMITTER_EMAIL=tagcess@localhost",
		"GIT_AUTHOR_DATE=" + appliedAt.UTC().Format(time.RFC3339),
		"GIT_COMMITTER_DATE=" + appliedAt.UTC().Format(time.RFC3339),
	}
	commitArgs := append([]string{"commit", "-q", "--cleanup=verbatim", "-F", "-", "--"}, names...)
	if _, err := l.git(ctx, env, commitMessage(actor, appliedAt, names), commitArgs...); err != nil {
		return l.fail(ctx, req, actor, appliedAt, queueOnFailure, err)
	}
	rev, err := l.revision(ctx)
	if err != nil {
		return l.fail(ctx, req, actor, appliedAt, queueOnFailure, err)
	}
	return Result{Revision: rev, Committed: true}, l.audit(ctx, l.commitEntry(actor, rev, names))
}

// Pending returns the durable retry intents, oldest first.
func (l *Log) Pending(ctx context.Context) ([]Retry, error) {
	return l.pending(ctx)
}

// quarantiner is implemented by a queue that sets unparsable lines aside; the Log reports them.
type quarantiner interface {
	TakeQuarantined() []string
}

// pending reads the queue and reports every line the queue had to set aside (an audit event and an
// alert each), so a damaged queue is never silent.
func (l *Log) pending(ctx context.Context) ([]Retry, error) {
	list, err := l.queue.Pending(ctx)
	if q, ok := l.queue.(quarantiner); ok {
		for _, why := range q.TakeQuarantined() {
			_ = l.audit(ctx, audit.Entry{
				Actor: "system:git", Event: EventQueueCorrupt, Target: "git", Result: "quarantined",
				Diff: audit.Diff{{Field: "reason", After: why}},
			})
			_ = l.raise(ctx, AlertGitFailed, "git")
		}
	}
	return list, err
}

// RetryPending drains the queue oldest first: each intent is committed and then removed. It stops at
// the first failure so a later intent can never overtake an earlier one, and that intent stays in
// the queue (AC3). An intent that can never commit (secret content, unsafe name) is quarantined: it
// is removed with an audit event and an alert, and the drain goes on.
func (l *Log) RetryPending(ctx context.Context) ([]Result, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.retryPending(ctx, true)
}

// retryPending drains the queue. notify says who reports a failure: the public entry point does (one
// audit event and one alert for the intent that failed); a drain started by Commit does not, because
// that Commit reports the failure once itself.
func (l *Log) retryPending(ctx context.Context, notify bool) ([]Result, error) {
	pending, err := l.pending(ctx)
	if err != nil {
		return nil, err
	}
	results := make([]Result, 0, len(pending))
	for _, intent := range pending {
		res, err := l.commit(ctx, CommitRequest{
			Actor: intent.Actor, AppliedAt: intent.AppliedAt, Files: intent.Files,
		}, modeRetry)
		if err != nil {
			if isPermanent(err) {
				if qerr := l.quarantine(ctx, intent, err); qerr != nil {
					return results, qerr
				}
				continue
			}
			if notify {
				err = l.report(ctx, intent.Actor, err)
			}
			return results, err
		}
		if intent.Ref != "" && l.onRetry != nil {
			if err := l.onRetry(ctx, intent.Ref, res.Revision); err != nil {
				return results, fmt.Errorf("gitlog: bind revision of %s: %w", intent.Ref, err)
			}
		}
		if err := l.queue.Complete(ctx, intent.ID); err != nil {
			return results, err
		}
		results = append(results, res)
	}
	return results, nil
}

// isPermanent reports whether a retry can never succeed: the content looks secret or the request is
// malformed. Retrying it again would only stop the queue for good (LOW 8).
func isPermanent(err error) bool {
	var secret *SecretError
	return errors.As(err, &secret) || errors.Is(err, ErrUnsafePath) || errors.Is(err, ErrNoActor)
}

// quarantine removes an intent that can never commit. It is audited and alerted before it is
// dropped; only the reason (file and rule names, never a value) is recorded.
func (l *Log) quarantine(ctx context.Context, intent Retry, cause error) error {
	_ = l.audit(ctx, audit.Entry{
		Actor: actorOrSystem(intent.Actor), Event: EventRetryQuarantined, Target: "git", Result: "quarantined",
		Diff: audit.Diff{{Field: "reason", After: permanentReason(cause)}},
	})
	_ = l.raise(ctx, AlertGitFailed, "git")
	return l.queue.Complete(ctx, intent.ID)
}

func actorOrSystem(actor string) string {
	if a := strings.TrimSpace(actor); a != "" {
		return a
	}
	return "system:git"
}

// permanentReason is the part of a permanent failure that is safe to record: a secret refusal names
// files and rules only.
func permanentReason(err error) string {
	var secret *SecretError
	switch {
	case errors.As(err, &secret):
		return secret.Error()
	case errors.Is(err, ErrUnsafePath):
		return ErrUnsafePath.Error()
	default:
		return ErrNoActor.Error()
	}
}

// report records one failed retry as an audit event and an alert, and returns the cause.
func (l *Log) report(ctx context.Context, actor string, cause error) error {
	return errors.Join(cause,
		l.audit(ctx, audit.Entry{
			Actor: actorOrSystem(actor), Event: EventCommitFailed, Target: "git", Result: "failed",
			Diff: audit.Diff{{Field: "reason", After: cause.Error()}},
		}),
		l.raise(ctx, AlertGitFailed, "git"),
	)
}

// fail records a failed commit: the intent is queued durably (when the caller is not already the
// retry path), an audit event and a critical alert are written, and no revision is reported. The
// repository's working tree is left as it is; gitlog commits with an explicit pathspec, so a file
// left behind by a failed attempt can never ride along in a later commit.
func (l *Log) fail(ctx context.Context, req CommitRequest, actor string, appliedAt time.Time, queueOnFailure bool, cause error) (Result, error) {
	if !queueOnFailure {
		// A drained intent is already queued; whoever started the drain reports the failure once.
		return Result{}, cause
	}
	var sideErrs []error
	if queueOnFailure {
		if _, err := l.queue.Enqueue(ctx, Retry{
			Actor: actor, AppliedAt: appliedAt,
			Files:  append([]File(nil), req.Files...),
			Reason: cause.Error(), QueuedAt: l.clock(), Ref: req.Ref,
		}); err != nil {
			sideErrs = append(sideErrs, fmt.Errorf("gitlog: queue retry: %w", err))
		}
	}
	sideErrs = append(sideErrs,
		l.audit(ctx, audit.Entry{
			Actor: actor, Event: EventCommitFailed, Target: "git", Result: "failed",
			Diff: audit.Diff{{Field: "reason", After: cause.Error()}},
		}),
		l.raise(ctx, AlertGitFailed, "git"),
	)
	return Result{}, errors.Join(append([]error{cause}, sideErrs...)...)
}

func (l *Log) commitEntry(actor, revision string, names []string) audit.Entry {
	return audit.Entry{
		Actor: actor, Event: EventCommit, Target: "git", Result: "applied",
		Diff: audit.Diff{
			{Field: "revision", After: revision},
			{Field: "files", After: strings.Join(names, ", ")},
		},
	}
}

func (l *Log) writeFile(f File) error {
	full := filepath.Join(l.dir, filepath.FromSlash(f.Name))
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		return fmt.Errorf("gitlog: create dir for %s: %w", f.Name, err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(full), ".tmp-*")
	if err != nil {
		return fmt.Errorf("gitlog: write %s: %w", f.Name, err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(f.Content); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("gitlog: write %s: %w", f.Name, err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("gitlog: write %s: %w", f.Name, err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("gitlog: write %s: %w", f.Name, err)
	}
	if err := os.Rename(tmpName, full); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("gitlog: write %s: %w", f.Name, err)
	}
	return nil
}

func (l *Log) revision(ctx context.Context) (string, error) {
	out, err := l.git(ctx, nil, "", "rev-parse", "--verify", "HEAD")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

func (l *Log) audit(ctx context.Context, e audit.Entry) error {
	if l.auditor == nil {
		return nil
	}
	_, err := l.auditor.Write(ctx, e)
	return err
}

func (l *Log) raise(ctx context.Context, kind, source string) error {
	if l.alerter == nil {
		return nil
	}
	return l.alerter.Raise(ctx, kind, source)
}

// git runs one git command in the repository. Arguments are passed directly (no shell). File names
// are treated as literal pathspecs (no glob/magic expansion) and the environment is made hermetic:
// every inherited GIT_* variable (GIT_DIR, GIT_WORK_TREE, GIT_INDEX_FILE, ...) is dropped so the
// command can never be redirected to another repository, the home/config directories point at a
// throwaway directory, and hooks/signing are disabled so the repository cannot run code or change
// the result. An optional stdin feeds the commit message (MEDIUM 2, MEDIUM 4).
func (l *Log) git(ctx context.Context, extraEnv []string, stdin string, args ...string) (string, error) {
	argv := append([]string{"-c", "core.hooksPath=" + os.DevNull, "-c", "commit.gpgsign=false"}, args...)
	cmd := exec.CommandContext(ctx, l.gitBin, argv...) //nolint:gosec // G204: fixed git binary, no shell
	cmd.Dir = l.dir
	cmd.Env = append(l.hermeticEnv(), extraEnv...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = strings.TrimSpace(out.String())
		}
		return out.String(), fmt.Errorf("gitlog: git %s: %w: %s", strings.Join(args, " "), err, msg)
	}
	return out.String(), nil
}

// hermeticEnv returns the process environment with every GIT_* variable and the home/config
// variables removed, then points HOME/XDG_CONFIG_HOME at the throwaway git home and fixes the
// literal-pathspec, config and prompt settings. It keeps extraEnv (the commit identity/date) that
// the caller appends after it.
func (l *Log) hermeticEnv() []string {
	env := make([]string, 0, len(os.Environ())+6)
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		switch {
		case strings.HasPrefix(name, "GIT_"), name == "HOME", name == "XDG_CONFIG_HOME":
			continue
		}
		env = append(env, kv)
	}
	return append(env,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_TERMINAL_PROMPT=0",
		"GIT_LITERAL_PATHSPECS=1",
		"HOME="+l.home,
		"XDG_CONFIG_HOME="+l.home,
	)
}

// validateName refuses anything but a clean, relative, slash-separated path inside the repository.
// Control characters are refused (they could inject pathspec/message lines) and no path component
// may be .git (writing there would execute hooks or tamper with the repository's own state).
func validateName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: empty name", ErrUnsafePath)
	}
	if strings.Contains(name, `\`) {
		return fmt.Errorf("%w: %q", ErrUnsafePath, name)
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: %q", ErrUnsafePath, name)
		}
	}
	clean := path.Clean(name)
	if filepath.IsAbs(name) || strings.HasPrefix(name, "/") || clean != name ||
		clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return fmt.Errorf("%w: %q", ErrUnsafePath, name)
	}
	for _, part := range strings.Split(clean, "/") {
		if strings.EqualFold(part, ".git") {
			return fmt.Errorf("%w: %q", ErrUnsafePath, name)
		}
	}
	return nil
}

// oneLine collapses control characters (including newlines) to spaces and trims, so an actor can
// never inject extra lines into the commit message or the git author header.
func oneLine(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsControl(r) {
			b.WriteRune(' ')
			continue
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

// authorName turns an actor into a single-line git author name, dropping the name/email delimiters
// git would otherwise parse. The exact actor is still carried in the commit message.
func authorName(actor string) string {
	name := strings.TrimSpace(strings.NewReplacer("<", " ", ">", " ").Replace(oneLine(actor)))
	if name == "" {
		return "tagcess"
	}
	return name
}

func commitMessage(actor string, at time.Time, names []string) string {
	var b strings.Builder
	b.WriteString("tagcess: verified artifacts\n\n")
	b.WriteString("Actor: " + oneLine(actor) + "\n")
	b.WriteString("Applied-At: " + at.UTC().Format(time.RFC3339) + "\n")
	b.WriteString("Files:\n")
	for _, name := range names {
		b.WriteString("  " + name + "\n")
	}
	return b.String()
}

func findingsText(findings []Finding) string {
	parts := make([]string, 0, len(findings))
	for _, f := range findings {
		parts = append(parts, f.File+" ("+f.Rule+")")
	}
	return strings.Join(parts, ", ")
}
