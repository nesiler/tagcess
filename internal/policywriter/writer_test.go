package policywriter

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	gosync "sync"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/gitlog"
	"github.com/nesiler/tagcess/internal/headscale"
	"github.com/nesiler/tagcess/internal/maintenance"
	"github.com/nesiler/tagcess/internal/policydoc"
	"github.com/nesiler/tagcess/internal/policyrev"
	"github.com/nesiler/tagcess/internal/store"
	"github.com/nesiler/tagcess/internal/sync"
	"github.com/nesiler/tagcess/internal/zitadel"
)

const (
	testIssuer = "https://idp.example.com"
	devops     = "devops@example.com"
)

// skeleton is a policy with every section the writer must keep. The groups section is the part
// Zitadel owns; the fixture renders it from the fake Zitadel so the live policy starts in sync.
const skeleton = `// tagcess test policy
{
  "groups": {},
  "tagOwners": {
    "tag:vpn-server": ["group:devops"], // owner note
    "tag:k8s": ["group:devops"],
  },
  "acls": [
    // everyone reaches the gate
    {"action": "accept", "src": ["autogroup:member"], "dst": ["tag:vpn-server:443"]},
  ],
  "grants": [
    {"src": ["group:devops"], "dst": ["tag:k8s"], "ip": ["*"]},
  ],
  "ssh": [
    {"action": "accept", "src": ["group:devops"], "dst": ["tag:k8s"], "users": ["root"]},
  ],
  "tests": [
    {"src": "group:dev", "accept": ["tag:vpn-server:443"]}, // user test
  ],
}
`

var lockedCfg = policydoc.DefaultLockedConfig(9000)

// fakeHS is Headscale as the writer, the reconciler and the pipeline see it.
type fakeHS struct {
	mu     gosync.Mutex
	policy string
	users  []headscale.User
	nodes  []headscale.Node

	calls   []string
	sets    []string
	expired []uint64
	// onRead is called at the start of every read; a test uses it to probe the writer lock.
	onRead func(name string)

	checkErr error
	setErr   error
	// setStores replaces what SetPolicy stores (a write the readback will not match).
	setStores string
	policyErr error
}

func (f *fakeHS) read(name string) {
	f.mu.Lock()
	f.calls = append(f.calls, name)
	fn := f.onRead
	f.mu.Unlock()
	if fn != nil {
		fn(name)
	}
}

func (f *fakeHS) GetPolicy(context.Context) (headscale.Policy, error) {
	f.read("GetPolicy")
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.policyErr != nil {
		return headscale.Policy{}, f.policyErr
	}
	return headscale.Policy{Text: f.policy}, nil
}

func (f *fakeHS) ListUsers(context.Context) ([]headscale.User, error) {
	f.read("ListUsers")
	return f.users, nil
}

func (f *fakeHS) ListNodes(context.Context) ([]headscale.Node, error) {
	f.read("ListNodes")
	return f.nodes, nil
}

func (f *fakeHS) CheckPolicy(context.Context, string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "CheckPolicy")
	return f.checkErr
}

func (f *fakeHS) SetPolicy(_ context.Context, policy string) (headscale.Policy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "SetPolicy")
	f.sets = append(f.sets, policy)
	if f.setErr != nil {
		return headscale.Policy{}, f.setErr
	}
	if f.setStores != "" {
		f.policy = f.setStores
		return headscale.Policy{Text: f.policy}, nil
	}
	f.policy = policy
	return headscale.Policy{Text: policy}, nil
}

func (f *fakeHS) ExpireNode(_ context.Context, id uint64) (headscale.Node, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "ExpireNode")
	f.expired = append(f.expired, id)
	return headscale.Node{ID: id}, nil
}

func (f *fakeHS) Sets() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.sets...)
}

func (f *fakeHS) Policy() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.policy
}

func (f *fakeHS) setPolicy(p string) {
	f.mu.Lock()
	f.policy = p
	f.mu.Unlock()
}

// fakeZ is Zitadel: the grants of the vpn project and the account states.
type fakeZ struct {
	mu        gosync.Mutex
	grants    []zitadel.Grant
	grantsErr error
	statesErr error
	drop      map[string]bool // user ids whose state is missing from the answer
	onRead    func(name string)
}

func (z *fakeZ) ListGrants(context.Context) ([]zitadel.Grant, error) {
	z.mu.Lock()
	fn := z.onRead
	z.mu.Unlock()
	if fn != nil {
		fn("ListGrants")
	}
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.grantsErr != nil {
		return nil, z.grantsErr
	}
	return append([]zitadel.Grant(nil), z.grants...), nil
}

func (z *fakeZ) UserStates(_ context.Context, ids []string) (map[string]zitadel.UserState, error) {
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.statesErr != nil {
		return nil, z.statesErr
	}
	out := map[string]zitadel.UserState{}
	for _, id := range ids {
		if !z.drop[id] {
			out[id] = zitadel.UserActive
		}
	}
	return out, nil
}

func (z *fakeZ) setGrants(g []zitadel.Grant) {
	z.mu.Lock()
	z.grants = g
	z.mu.Unlock()
}

// fakeGit records the commits the pipeline makes (A-02).
type fakeGit struct {
	mu      gosync.Mutex
	commits []gitlog.CommitRequest
}

func (g *fakeGit) Commit(_ context.Context, req gitlog.CommitRequest) (gitlog.Result, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.commits = append(g.commits, req)
	return gitlog.Result{Revision: "rev1"}, nil
}

func (g *fakeGit) Pending(context.Context) ([]gitlog.Retry, error) { return nil, nil }

type env struct {
	t     *testing.T
	st    *store.Store
	hs    *fakeHS
	z     *fakeZ
	git   *fakeGit
	revs  *policyrev.Repo
	pipe  *change.Pipeline
	maint *maintenance.Service
	rec   *sync.Reconciler
	w     *Writer
	live  string // the policy Headscale starts with, groups in sync with Zitadel
}

// newEnv builds the whole stack over fakes: ten users with the dev role, two of them also devops.
// Dry run is off (the store seeds it on).
func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "tagcess.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if _, err := st.DB().ExecContext(ctx, `UPDATE settings SET value = 'false' WHERE key = 'dry_run'`); err != nil {
		t.Fatalf("dry_run off: %v", err)
	}

	z := &fakeZ{drop: map[string]bool{}}
	hs := &fakeHS{}
	for i := 1; i <= 10; i++ {
		id := userID(i)
		z.grants = append(z.grants, zitadel.Grant{UserID: id, Role: "dev"})
		if i <= 2 {
			z.grants = append(z.grants, zitadel.Grant{UserID: id, Role: "devops"})
		}
		hs.users = append(hs.users, headscale.User{ID: uint64(i), Name: id, ProviderID: testIssuer + "/" + id})
		hs.nodes = append(hs.nodes, headscale.Node{ID: uint64(i), Name: "laptop-" + id, UserID: uint64(i)})
	}

	revs := policyrev.New(st.Queries())
	git := &fakeGit{}
	maint := maintenance.New(st.Queries())
	pipe := change.New(hs, st.Queries(), audit.New(st.Queries()), st).WithGit(git).WithRevisions(NewRecorder(revs)).WithMaintenance(maint)
	rec, err := sync.NewReconciler(sync.ReconcilerConfig{
		Zitadel: z, Headscale: hs, Pipeline: pipe, Queries: st.Queries(), DryRun: st, Issuer: testIssuer,
	})
	if err != nil {
		t.Fatalf("NewReconciler: %v", err)
	}
	w, err := New(Config{Evaluator: rec, Pipeline: pipe, Revisions: revs, Checker: hs, Locked: lockedCfg})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	e := &env{t: t, st: st, hs: hs, z: z, git: git, revs: revs, pipe: pipe, maint: maint, rec: rec, w: w}

	ev, err := rec.Evaluate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	in := ev.Input
	in.Policy = []byte(skeleton)
	live, err := sync.Target(in)
	if err != nil {
		t.Fatalf("render live policy: %v", err)
	}
	e.live = string(live)
	hs.policy = e.live
	return e
}

func userID(i int) string { return "u" + string(rune('0'+i/10)) + string(rune('0'+i%10)) }

func member(id string) string { return testIssuer + "/" + id + "@" }

// save submits text with the hash of the live policy as the editor's base.
func (e *env) save(text string) (SaveResult, error) {
	e.t.Helper()
	return e.w.Save(context.Background(), SaveRequest{
		Actor: devops, Text: text, BaseHash: policyrev.HashRaw(e.hs.Policy()),
	})
}

// expected is what Save must write for text: Zitadel's groups, then the locked tests, nothing else.
func (e *env) expected(text string) string {
	e.t.Helper()
	ev, err := e.rec.Evaluate(context.Background())
	if err != nil {
		e.t.Fatal(err)
	}
	in := ev.Input
	in.Policy = []byte(text)
	composed, err := sync.Target(in)
	if err != nil {
		e.t.Fatalf("compose: %v", err)
	}
	res, err := policydoc.Inject(string(composed), lockedCfg)
	if err != nil {
		e.t.Fatalf("inject: %v", err)
	}
	return res.Text
}

func (e *env) count(query string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.st.DB().QueryRowContext(context.Background(), query, args...).Scan(&n); err != nil {
		e.t.Fatalf("count %q: %v", query, err)
	}
	return n
}

func (e *env) revisions() []policyrev.Revision {
	e.t.Helper()
	revs, err := e.revs.List(context.Background(), 100)
	if err != nil {
		e.t.Fatal(err)
	}
	return revs
}

// lockHeld reports whether the writer lock is held right now (the probe acquires it as soon as it can).
func lockHeld() bool {
	got := make(chan struct{})
	go func() { _ = change.WithWriterLock(func() error { close(got); return nil }) }()
	select {
	case <-got:
		return false
	case <-time.After(100 * time.Millisecond):
		return true
	}
}

// AC1: the live policy, users, nodes and Zitadel roles are read after the writer lock is taken, and
// only those reads build the request: a Zitadel change between the editor load and the save is
// what lands in the groups.
func TestPolicyWriter_ReadsUnderLock(t *testing.T) {
	e := newEnv(t)
	var mu gosync.Mutex
	held := map[string]bool{}
	probe := func(name string) {
		h := lockHeld()
		mu.Lock()
		if _, seen := held[name]; !seen {
			held[name] = h
		}
		mu.Unlock()
	}
	e.hs.onRead = probe
	e.z.onRead = probe

	// The text the editor loaded; then Zitadel gains a devops before the save runs.
	text := e.live
	e.z.setGrants(append(e.z.grants, zitadel.Grant{UserID: userID(3), Role: "devops"}))

	res, err := e.save(text)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	for _, name := range []string{"GetPolicy", "ListUsers", "ListNodes", "ListGrants"} {
		h, seen := held[name]
		if !seen {
			t.Errorf("%s was never read", name)
		} else if !h {
			t.Errorf("%s was read without the writer lock", name)
		}
	}
	if !strings.Contains(e.hs.Policy(), member(userID(3))+`"`) || !res.Change.Applied {
		t.Errorf("the save did not use the Zitadel read taken under the lock:\n%s", e.hs.Policy())
	}
	if want := e.expected(text); e.hs.Policy() != want {
		t.Errorf("written policy differs from the one composed from the fresh reads:\n got %q\nwant %q", e.hs.Policy(), want)
	}
}

// AC2: Zitadel unreadable or incomplete: nothing is written, no revision is left pending, the
// attempt is blocked as "Zitadel okunamıyor".
func TestPolicyWriter_ZitadelDownBlocks(t *testing.T) {
	tests := []struct {
		name  string
		setup func(e *env)
	}{
		{"grants unreadable", func(e *env) { e.z.grantsErr = errors.New("connection refused") }},
		{"states unreadable", func(e *env) { e.z.statesErr = errors.New("timeout") }},
		{"a state is missing", func(e *env) { e.z.drop[userID(4)] = true }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			tt.setup(e)
			res, err := e.save(e.live)
			if !errors.Is(err, ErrZitadelUnavailable) {
				t.Fatalf("err = %v, want ErrZitadelUnavailable", err)
			}
			if !strings.Contains(err.Error(), "Zitadel okunamıyor") {
				t.Errorf("err = %q, want the reason named", err)
			}
			if res.Change.Applied {
				t.Error("an unreadable Zitadel still applied")
			}
			if len(e.hs.Sets()) != 0 {
				t.Errorf("SetPolicy ran: %v", e.hs.Sets())
			}
			if n := len(e.revisions()); n != 0 {
				t.Errorf("revisions = %d, want none (nothing pending, nothing recorded)", n)
			}
			if n := e.count(`SELECT count(*) FROM changes`); n != 0 {
				t.Errorf("changes = %d, want 0", n)
			}
		})
	}

	t.Run("Headscale unreadable", func(t *testing.T) {
		e := newEnv(t)
		e.hs.policyErr = errors.New("socket closed")
		if _, err := e.save(e.live); !errors.Is(err, ErrHeadscaleUnavailable) {
			t.Fatalf("err = %v, want ErrHeadscaleUnavailable", err)
		}
		if len(e.hs.Sets()) != 0 || len(e.revisions()) != 0 {
			t.Error("an unreadable Headscale wrote something")
		}
	})
}

// AC3: an editor whose base hash no longer matches the live policy gets ErrStale and the current text;
// nothing is written.
func TestPolicyWriter_StaleBaseRejected(t *testing.T) {
	e := newEnv(t)
	loaded := policyrev.HashRaw(e.live)
	changed := strings.Replace(e.live, "// everyone reaches the gate", "// changed elsewhere", 1)
	e.hs.setPolicy(changed)

	res, err := e.w.Save(context.Background(), SaveRequest{Actor: devops, Text: e.live, BaseHash: loaded})
	if !errors.Is(err, ErrStale) {
		t.Fatalf("err = %v, want ErrStale", err)
	}
	if res.Current != changed {
		t.Errorf("Current = %q, want the live text", res.Current)
	}
	if len(e.hs.Sets()) != 0 || len(e.revisions()) != 0 {
		t.Error("a stale save wrote something")
	}

	// The same base hash with the current live text is fine.
	if _, err := e.w.Save(context.Background(), SaveRequest{Actor: devops, Text: changed, BaseHash: policyrev.HashRaw(changed)}); err != nil {
		t.Fatalf("Save with the current base: %v", err)
	}
}

// AC4a: the groups the user sends are thrown away; Zitadel's groups are written.
func TestPolicyWriter_GroupsComposedFromZitadel(t *testing.T) {
	e := newEnv(t)
	evil := member("evil")
	// The user hands devops to somebody Zitadel does not know and drops a real member.
	text := strings.Replace(e.live, `"group:devops": [`, `"group:devops": [`+`"`+evil+`", `, 1)
	text = strings.Replace(text, `"`+member(userID(1))+`",`, "", 1)
	if text == e.live {
		t.Fatal("fixture: the groups edit did not change the text")
	}

	res, err := e.save(text)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if !res.Change.Applied {
		t.Fatalf("result = %+v, want applied", res.Change)
	}
	got := e.hs.Policy()
	if strings.Contains(got, evil) {
		t.Errorf("the user's group member reached Headscale:\n%s", got)
	}
	if want := e.expected(text); got != want {
		t.Errorf("written policy is not the Zitadel composition:\n got %q\nwant %q", got, want)
	}
	if !strings.Contains(got, member(userID(1))) {
		t.Errorf("the real member the user dropped is missing:\n%s", got)
	}
	if !res.GroupsRebuilt {
		t.Error("GroupsRebuilt = false, want the notice that tagcess rebuilt the groups")
	}
}

// AC4b: when the sync would hold the resulting plan for approval, the writer blocks and points at
// /sync instead of bypassing the threshold.
func TestPolicyWriter_PendingSyncBlocks(t *testing.T) {
	e := newEnv(t)
	// Five of ten users lose every role: over the Y-03.4 threshold, so the sync waits for approval.
	var kept []zitadel.Grant
	for _, g := range e.z.grants {
		if g.UserID >= userID(6) {
			kept = append(kept, g)
		}
	}
	e.z.setGrants(kept)
	// Their Headscale nodes are theirs; only the grants matter here.

	res, err := e.save(e.live)
	if !errors.Is(err, ErrSyncPending) {
		t.Fatalf("err = %v, want ErrSyncPending", err)
	}
	if !strings.Contains(err.Error(), "/sync") {
		t.Errorf("err = %q, want it to point at /sync", err)
	}
	if res.Change.Applied || len(e.hs.Sets()) != 0 || len(e.revisions()) != 0 {
		t.Error("a held plan was written anyway")
	}
}

// AC5: a document that fails validation is not written, and the layered report comes back.
func TestPolicyWriter_InvalidNotWritten(t *testing.T) {
	tests := []struct {
		name      string
		text      func(e *env) string
		checkErr  error
		wantStage policydoc.Stage
	}{
		{"syntax", func(e *env) string { return strings.Replace(e.live, `"acls": [`, `"acls": [ ,,`, 1) }, nil, policydoc.StageSyntax},
		{"structure", func(e *env) string {
			t := strings.Replace(e.live, `"acls"`, `"#acls"`, 1)
			return strings.Replace(t, `"grants"`, `"#grants"`, 1)
		}, nil, policydoc.StageStructure},
		{"headscale rejects", func(e *env) string { return e.live }, &headscale.PolicyError{Message: "unknown group"}, policydoc.StageCheck},
		{"headscale unreachable", func(e *env) string { return e.live }, errors.New("deadline exceeded"), policydoc.StageCheck},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			e.hs.checkErr = tt.checkErr
			res, err := e.save(tt.text(e))
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("err = %v, want ErrInvalid", err)
			}
			if res.Report.Valid() {
				t.Error("the report of a rejected text is valid")
			}
			if got := res.Report.Stage(tt.wantStage).State; got == policydoc.StatePass || got == policydoc.StateSkipped {
				t.Errorf("stage %s = %s, want fail/unverified", tt.wantStage, got)
			}
			if len(e.hs.Sets()) != 0 {
				t.Errorf("SetPolicy ran for an invalid policy: %v", e.hs.Sets())
			}
			if n := len(e.revisions()); n != 0 {
				t.Errorf("revisions = %d, want none", n)
			}
		})
	}
}

// AC6: a successful save records the revision pending, applies it through the pipeline, and marks it
// applied with the change id; the audit entry and the git revision exist; Headscale holds exactly the
// composed text, with comments, grants, ssh and the user's tests kept.
func TestPolicyWriter_HappyPath(t *testing.T) {
	e := newEnv(t)
	text := strings.Replace(e.live, "// everyone reaches the gate", "// everyone reaches the gate (edited)", 1)

	res, err := e.save(text)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if !res.Change.Applied || res.Change.Status != change.StatusApplied {
		t.Fatalf("result = %+v, want applied", res.Change)
	}
	got := e.hs.Policy()
	if want := e.expected(text); got != want {
		t.Fatalf("Headscale holds a different text than the composed one:\n got %q\nwant %q", got, want)
	}
	for _, keep := range []string{"// tagcess test policy", "// owner note", "(edited)", `"grants"`, `"ssh"`, "// user test", `/* tagcess:locked */`} {
		if !strings.Contains(got, keep) {
			t.Errorf("the applied text lost %q:\n%s", keep, got)
		}
	}

	revs := e.revisions() // newest first: the ui revision, then the external baseline
	if len(revs) != 2 {
		t.Fatalf("revisions = %d, want baseline + ui", len(revs))
	}
	ui, base := revs[0], revs[1]
	if base.Source != policyrev.SourceExternal || base.ApplyStatus != policyrev.StatusApplied || base.Raw != e.live {
		t.Errorf("baseline = %+v, want the live policy as an applied external revision", base)
	}
	if ui.Source != policyrev.SourceUI || ui.ApplyStatus != policyrev.StatusApplied || ui.Actor != devops {
		t.Errorf("revision = %+v, want applied, ui, by the actor", ui)
	}
	if ui.Raw != got || ui.BaseHash != policyrev.HashRaw(e.live) || ui.ParentID != base.ID {
		t.Errorf("revision content/base/parent wrong: %+v", ui)
	}
	if ui.ChangeID == 0 || ui.ChangeID != res.Change.ChangeID || res.Revision.ID != ui.ID {
		t.Errorf("change id = %d (result %d), revision in result %d; want them bound", ui.ChangeID, res.Change.ChangeID, res.Revision.ID)
	}
	if n := e.count(`SELECT count(*) FROM audit_events WHERE event = 'policy.apply' AND actor = ?`, devops); n != 1 {
		t.Errorf("policy.apply audit events = %d, want 1", n)
	}
	if len(e.git.commits) != 1 || string(e.git.commits[0].Files[0].Content) != got {
		t.Errorf("git commits = %+v, want one with the applied text", e.git.commits)
	}
	// No node was touched.
	if len(e.hs.expired) != 0 {
		t.Errorf("expired nodes = %v, want none", e.hs.expired)
	}
}

// AC7: a write whose outcome is uncertain keeps the live policy, stays "unknown" and refuses further
// saves until the live policy matches the last applied revision again.
func TestPolicyWriter_UnknownBlocksFurtherWrites(t *testing.T) {
	e := newEnv(t)
	text := strings.Replace(e.live, "// everyone reaches the gate", "// first", 1)

	// Headscale accepts the write but holds something else when read back.
	other := `{"acls": [], "groups": {}}`
	e.hs.setStores = other
	res, err := e.save(text)
	if !errors.Is(err, ErrNotApplied) {
		t.Fatalf("err = %v, want ErrNotApplied", err)
	}
	if res.Revision.ApplyStatus != policyrev.StatusUnknown {
		t.Fatalf("revision = %+v, want unknown", res.Revision)
	}
	if got := e.hs.Policy(); got != other {
		t.Errorf("the pipeline touched the live policy after the mismatch: %q", got)
	}
	if n := len(e.hs.Sets()); n != 1 {
		t.Errorf("SetPolicy calls = %d, want only the uncertain one (no restore)", n)
	}

	// Further saves are refused, whatever they contain, and write nothing.
	e.hs.setStores = ""
	before := len(e.revisions())
	res2, err := e.w.Save(context.Background(), SaveRequest{Actor: devops, Text: text, BaseHash: policyrev.HashRaw(other)})
	if !errors.Is(err, ErrUncertain) {
		t.Fatalf("second save err = %v, want ErrUncertain", err)
	}
	if res2.Change.Applied || len(e.hs.Sets()) != 1 || len(e.revisions()) != before {
		t.Error("a save went through while the state is uncertain")
	}

	// Once the live policy is the last applied revision again, writes resume.
	e.hs.setPolicy(e.live)
	if _, err := e.save(text); err != nil {
		t.Fatalf("save after the live policy matches the last applied revision again: %v", err)
	}
}

// A refusal before the write (here: SetPolicy fails and the policy is unchanged) is a failed revision
// that does not block later saves.
func TestPolicyWriter_FailedWriteDoesNotBlock(t *testing.T) {
	e := newEnv(t)
	e.hs.setErr = errors.New("boom")
	res, err := e.save(strings.Replace(e.live, "// everyone reaches the gate", "// x", 1))
	if !errors.Is(err, ErrNotApplied) || res.Revision.ApplyStatus != policyrev.StatusFailed {
		t.Fatalf("err = %v, revision = %+v; want ErrNotApplied and failed", err, res.Revision)
	}
	e.hs.setErr = nil
	if _, err := e.save(e.live); err != nil {
		t.Fatalf("save after a failed write: %v", err)
	}
}

// AC11: with dry run on nothing is written, the revision ends dry_run (never pending or unknown) and
// the next save is not blocked.
func TestPolicyWriter_DryRunNoWrite(t *testing.T) {
	e := newEnv(t)
	if _, err := e.st.DB().ExecContext(context.Background(), `UPDATE settings SET value = 'true' WHERE key = 'dry_run'`); err != nil {
		t.Fatal(err)
	}
	res, err := e.save(strings.Replace(e.live, "// everyone reaches the gate", "// dry", 1))
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if res.Change.Status != change.StatusDryRun || res.Change.Applied {
		t.Fatalf("result = %+v, want dry_run", res.Change)
	}
	if len(e.hs.Sets()) != 0 {
		t.Errorf("a dry run wrote to Headscale: %v", e.hs.Sets())
	}
	if res.Revision.ApplyStatus != policyrev.StatusDryRun {
		t.Errorf("revision = %+v, want dry_run", res.Revision)
	}
	for _, r := range e.revisions() {
		if r.ApplyStatus == policyrev.StatusPending || r.ApplyStatus == policyrev.StatusUnknown {
			t.Errorf("revision %d is %s after a dry run", r.ID, r.ApplyStatus)
		}
	}

	if _, err := e.st.DB().ExecContext(context.Background(), `UPDATE settings SET value = 'false' WHERE key = 'dry_run'`); err != nil {
		t.Fatal(err)
	}
	if res, err := e.save(e.live); err != nil || !res.Change.Applied {
		t.Fatalf("save after the dry run = %+v, %v; want applied", res.Change, err)
	}
}

// AC8: the writer never expires a node; the next reconcile still plans the expiry of a user who lost
// every role.
func TestPolicyWriter_LeavesExpiryToReconcile(t *testing.T) {
	e := newEnv(t)
	lost := userID(10)
	var kept []zitadel.Grant
	for _, g := range e.z.grants {
		if g.UserID != lost {
			kept = append(kept, g)
		}
	}
	e.z.setGrants(kept)

	if res, err := e.save(e.live); err != nil || !res.Change.Applied {
		t.Fatalf("Save = %+v, %v; want applied", res.Change, err)
	}
	if len(e.hs.expired) != 0 {
		t.Fatalf("the writer expired nodes: %v", e.hs.expired)
	}
	if strings.Contains(e.hs.Policy(), member(lost)) {
		t.Error("the user who lost every role is still in the groups")
	}

	if _, err := e.rec.Run(context.Background(), sync.TriggerManual); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if len(e.hs.expired) != 1 || e.hs.expired[0] != 10 {
		t.Errorf("expired after the reconcile = %v, want [10]", e.hs.expired)
	}
}

// AC10: Preview writes nothing: no Headscale write, no revision, no baseline, no change, no audit.
// It returns the report, the raw and semantic diff, and what tagcess added.
func TestPolicyWriter_PreviewIsReadOnly(t *testing.T) {
	e := newEnv(t)
	text := strings.Replace(e.live, `"dst": ["tag:vpn-server:443"]}`, `"dst": ["tag:vpn-server:443", "tag:k8s:8080"]}`, 1)
	// A hand edit of the groups: Preview must say tagcess rebuilds them.
	text = strings.Replace(text, `"group:devops": [`, `"group:devops": ["`+member("evil")+`", `, 1)

	callsBefore := len(e.hs.calls)
	res, err := e.w.Preview(context.Background(), SaveRequest{Actor: devops, Text: text, BaseHash: policyrev.HashRaw(e.live)})
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if !res.Report.Valid() || !res.Report.Matches(res.Text) {
		t.Errorf("report = %+v, want a valid report bound to the final text", res.Report)
	}
	if res.Text != e.expected(text) {
		t.Errorf("Text is not the composed document")
	}
	if !strings.Contains(res.RawDiff, `tag:k8s:8080`) || !strings.Contains(res.RawDiff, `/* tagcess:locked */`) {
		t.Errorf("RawDiff misses the edit or the locked tests:\n%s", res.RawDiff)
	}
	sections := map[string]bool{}
	for _, c := range res.Semantic {
		sections[c.Section] = true
	}
	if !sections["acls"] || !sections["tests"] {
		t.Errorf("Semantic = %+v, want acls and tests changes", res.Semantic)
	}
	if !res.GroupsRebuilt {
		t.Error("GroupsRebuilt = false, want true")
	}
	if len(res.Locked) != len(lockedRulesInDefault()) {
		t.Errorf("Locked = %+v, want one added entry per locked rule", res.Locked)
	}

	for _, c := range e.hs.calls[callsBefore:] {
		if c == "SetPolicy" || c == "ExpireNode" {
			t.Errorf("Preview called %s", c)
		}
	}
	if n := len(e.revisions()); n != 0 {
		t.Errorf("revisions = %d, want none (not even a baseline)", n)
	}
	for _, table := range []string{"changes", "audit_events", "sync_runs"} {
		if n := e.count(`SELECT count(*) FROM ` + table); n != 0 {
			t.Errorf("%s rows = %d, want 0", table, n)
		}
	}

	// A text that fails validation still previews: the report says why.
	bad, err := e.w.Preview(context.Background(), SaveRequest{Actor: devops, Text: "{", BaseHash: policyrev.HashRaw(e.live)})
	if err != nil {
		t.Fatalf("Preview(invalid): %v", err)
	}
	if bad.Report.Valid() || bad.Report.Stage(policydoc.StageSyntax).State != policydoc.StateFail {
		t.Errorf("report = %+v, want a syntax failure", bad.Report)
	}
}

func lockedRulesInDefault() []string {
	return []string{policydoc.RuleUI, policydoc.RuleWebhook, policydoc.RuleSSH}
}

// AC12 (recorder side): a sync apply is recorded as a source=sync revision bound to its change, so
// the live policy is not "external" afterwards.
func TestRecorder_SyncRevisionKeepsLivePolicyKnown(t *testing.T) {
	e := newEnv(t)
	e.z.setGrants(append(e.z.grants, zitadel.Grant{UserID: userID(3), Role: "devops"}))
	res, err := e.rec.Run(context.Background(), sync.TriggerManual)
	if err != nil || !res.Change.Applied {
		t.Fatalf("reconcile = %+v, %v; want applied", res.Change, err)
	}
	revs := e.revisions()
	if len(revs) != 1 || revs[0].Source != policyrev.SourceSync || revs[0].ApplyStatus != policyrev.StatusApplied || revs[0].ChangeID != res.Change.ChangeID {
		t.Fatalf("revisions = %+v, want one applied sync revision bound to the change", revs)
	}
	rev, added, err := e.revs.EnsureBaseline(context.Background(), e.hs.Policy(), "tagcess")
	if err != nil || added {
		t.Errorf("EnsureBaseline = %+v, added %v, err %v; want the sync revision to be the known live policy", rev, added, err)
	}
}

// The source decides how a revision is labelled; a rollback names the revision it restores.
func TestPolicyWriter_SourceAndRollbackRecorded(t *testing.T) {
	e := newEnv(t)
	// A rollback names an applied revision (F3-025): the external baseline is one.
	target, _, err := e.revs.EnsureBaseline(context.Background(), e.live, "tagcess")
	if err != nil {
		t.Fatalf("EnsureBaseline: %v", err)
	}
	_, err = e.w.Save(context.Background(), SaveRequest{
		Actor: devops, Text: e.live, BaseHash: policyrev.HashRaw(e.live),
		Source: policyrev.SourceRollback, RollbackOf: target.ID, Reason: "undo",
	})
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	top := e.revisions()[0]
	if top.Source != policyrev.SourceRollback || top.RollbackOf != target.ID || top.Reason != "undo" {
		t.Errorf("revision = %+v, want rollback of %d with the reason", top, target.ID)
	}
}

func TestPolicyWriter_ActorRequired(t *testing.T) {
	e := newEnv(t)
	if _, err := e.w.Save(context.Background(), SaveRequest{Text: e.live, BaseHash: policyrev.HashRaw(e.live)}); err == nil {
		t.Fatal("Save without an actor succeeded")
	}
}

// Live (F3-019): the editor's starting point. The live text and its base hash are shown even while
// Zitadel is down (the page opens read-only); an unresolved earlier write is reported with its
// detail; nothing is written.
func TestPolicyWriter_Live(t *testing.T) {
	ctx := context.Background()

	t.Run("ready", func(t *testing.T) {
		e := newEnv(t)
		live, err := e.w.Live(ctx)
		if err != nil {
			t.Fatalf("Live: %v", err)
		}
		if live.Text != e.live || live.BaseHash != policyrev.HashRaw(e.live) {
			t.Errorf("Live = %+v, want the live text and its hash", live)
		}
		if live.ZitadelErr != nil || live.HeadscaleErr != nil || live.Uncertain != "" {
			t.Errorf("Live = %+v, want no blocker", live)
		}
		if len(e.revisions()) != 0 || e.count(`SELECT count(*) FROM changes`) != 0 {
			t.Error("Live wrote a revision or a change")
		}
	})

	t.Run("Zitadel down keeps the text", func(t *testing.T) {
		e := newEnv(t)
		e.z.grantsErr = errors.New("connection refused")
		live, err := e.w.Live(ctx)
		if err != nil {
			t.Fatalf("Live: %v", err)
		}
		if !errors.Is(live.ZitadelErr, ErrZitadelUnavailable) || live.Text != e.live {
			t.Errorf("Live = %+v, want ErrZitadelUnavailable and the live text", live)
		}
	})

	t.Run("a missing account state closes editing too", func(t *testing.T) {
		e := newEnv(t)
		e.z.drop[userID(4)] = true
		live, err := e.w.Live(ctx)
		if err != nil {
			t.Fatalf("Live: %v", err)
		}
		if !errors.Is(live.ZitadelErr, ErrZitadelUnavailable) {
			t.Errorf("ZitadelErr = %v, want ErrZitadelUnavailable", live.ZitadelErr)
		}
	})

	t.Run("Headscale down", func(t *testing.T) {
		e := newEnv(t)
		e.hs.policyErr = errors.New("socket closed")
		live, err := e.w.Live(ctx)
		if err != nil {
			t.Fatalf("Live: %v", err)
		}
		if !errors.Is(live.HeadscaleErr, ErrHeadscaleUnavailable) || live.Text != "" || live.BaseHash != "" {
			t.Errorf("Live = %+v, want ErrHeadscaleUnavailable and no text", live)
		}
	})

	t.Run("uncertain write", func(t *testing.T) {
		e := newEnv(t)
		text := strings.Replace(e.live, "// everyone reaches the gate", "// first", 1)
		e.hs.setStores = `{"acls": [], "groups": {}}`
		if _, err := e.save(text); !errors.Is(err, ErrNotApplied) {
			t.Fatalf("save err = %v, want ErrNotApplied", err)
		}
		live, err := e.w.Live(ctx)
		if err != nil {
			t.Fatalf("Live: %v", err)
		}
		if live.Uncertain == "" || !strings.Contains(live.Uncertain, "unknown") {
			t.Errorf("Uncertain = %q, want the unresolved revision named", live.Uncertain)
		}
		// The live policy equal to the last applied revision clears it.
		e.hs.setStores = ""
		e.hs.setPolicy(e.live)
		if live, err = e.w.Live(ctx); err != nil || live.Uncertain != "" {
			t.Errorf("after the live policy matches again: Uncertain = %q, err = %v", live.Uncertain, err)
		}
	})
}
