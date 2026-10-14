package hshelper

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/nesiler/tagcess/internal/hostpatch"
)

const (
	idA     = "0b7f4c1e-52d3-4a8e-9c61-3f2d8a7e5b10"
	idB     = "7c1d2e3f-4a5b-4c6d-8e7f-0a1b2c3d4e5f"
	idC     = "11111111-2222-4333-8444-555555555555"
	nilID   = "00000000-0000-0000-0000-000000000000"
	baseRev = "740a57b59f3878100ec9dd17b117f5239adbb93bd7686cb4cce8a1645bc49ad5"
)

type env struct {
	t    *testing.T
	root string
	cfg  Config
	now  time.Time
	proj *fakeProjector
	logs []string
}

// fakeProjector stands in for the real config projection (F3b-005, wired in F3b-008).
type fakeProjector struct {
	groups []string
	err    error
	calls  int
}

func (p *fakeProjector) Project() ([]string, string, error) {
	p.calls++
	if p.err != nil {
		return nil, "", p.err
	}
	rev, err := hostpatch.BaseRev(p.groups)
	return p.groups, rev, err
}

func newEnv(t *testing.T) *env {
	t.Helper()
	root := t.TempDir()
	for _, d := range []string{"requests", "results", "private"} {
		if err := os.Mkdir(filepath.Join(root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	e := &env{t: t, root: root, now: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)}
	e.proj = &fakeProjector{groups: []string{"devops"}}
	e.cfg = Config{
		Root: root, RequestUID: uint32(os.Getuid()), Now: func() time.Time { return e.now }, Projector: e.proj,
		Logf: func(format string, args ...any) { e.logs = append(e.logs, fmt.Sprintf(format, args...)) },
	}
	return e
}

func (e *env) path(parts ...string) string {
	return filepath.Join(append([]string{e.root}, parts...)...)
}

func (e *env) write(rel, content string) {
	e.t.Helper()
	if err := os.WriteFile(e.path(rel), []byte(content), 0o600); err != nil {
		e.t.Fatal(err)
	}
}

// publish writes a valid request for id and the marker pointing at it.
func (e *env) publish(id string, groups ...string) []byte {
	e.t.Helper()
	if len(groups) == 0 {
		groups = []string{"devops"}
	}
	b, err := hostpatch.BuildRequest(id, baseRev, groups)
	if err != nil {
		e.t.Fatal(err)
	}
	e.write("requests/"+id+".json", string(b))
	e.write("requests/request.ready", id)
	return b
}

func (e *env) exists(rel string) bool {
	_, err := os.Lstat(e.path(rel))
	return err == nil
}

func (e *env) run() Outcome {
	e.t.Helper()
	out, err := Run(e.cfg)
	if err != nil {
		e.t.Fatalf("Run: %v", err)
	}
	return out
}

func (e *env) result() hostpatch.Result {
	e.t.Helper()
	b, err := os.ReadFile(e.path("results/result.json"))
	if err != nil {
		e.t.Fatalf("result.json: %v", err)
	}
	r, err := hostpatch.DecodeResult(b)
	if err != nil {
		e.t.Fatalf("DecodeResult: %v", err)
	}
	return r
}

func (e *env) journal() Journal {
	e.t.Helper()
	j, found, err := ReadJournal(e.path("private"))
	if err != nil || !found {
		e.t.Fatalf("ReadJournal found=%v err=%v", found, err)
	}
	return j
}

func (e *env) setJournal(id string, state hostpatch.State) {
	e.t.Helper()
	if err := WriteJournal(e.path("private"), Journal{Version: hostpatch.Version, RequestID: id, State: state}); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) wantRejected(id string, code hostpatch.ErrorCode) {
	e.t.Helper()
	r := e.result()
	if r.RequestID != id || r.State != hostpatch.StateFailed || r.ErrorCode != code {
		e.t.Errorf("result = %+v, want failed/%s for %s", r, code, id)
	}
	if r.ConfigChanged == nil || *r.ConfigChanged || r.HealthVerified {
		e.t.Errorf("a rejection must say the config is unchanged: %+v", r)
	}
	if e.exists("requests/request.ready") {
		e.t.Error("marker was not consumed")
	}
}

// AC1: a valid request is copied to private/, journalled as accepted, then marker and request go.
func TestIntake_AcceptsValid(t *testing.T) {
	e := newEnv(t)
	raw := e.publish(idA, "devops", "developer")

	if out := e.run(); out != OutcomeAccepted {
		t.Fatalf("outcome = %v", out)
	}
	got, err := os.ReadFile(e.path("private/request.json"))
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("private copy = %q, %v; want %q", got, err, raw)
	}
	j := e.journal()
	if j.RequestID != idA || j.State != hostpatch.StateAccepted || j.ErrorCode != "" {
		t.Errorf("journal = %+v", j)
	}
	if st, err := os.Stat(e.path("private/journal.json")); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("journal mode = %v, %v", st, err)
	}
	if st, err := os.Stat(e.path("private/request.json")); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("copy mode = %v, %v", st, err)
	}
	for _, rel := range []string{"requests/request.ready", "requests/" + idA + ".json", "results/result.json"} {
		if e.exists(rel) {
			t.Errorf("%s should not exist", rel)
		}
	}
	if e.proj.calls != 1 {
		t.Errorf("status published %d times, want 1", e.proj.calls)
	}
	if out := e.run(); out != OutcomeIdle {
		t.Errorf("second run with no marker: outcome = %v", out)
	}
}

// A terminal journal lets the next ID in; the journal then follows the new ID.
func TestIntake_AcceptsAfterTerminal(t *testing.T) {
	for _, st := range []hostpatch.State{hostpatch.StateSucceeded, hostpatch.StateFailed, hostpatch.StateInterrupted} {
		t.Run(string(st), func(t *testing.T) {
			e := newEnv(t)
			e.setJournal(idA, st)
			e.publish(idB)
			if out := e.run(); out != OutcomeAccepted {
				t.Fatalf("outcome = %v", out)
			}
			if j := e.journal(); j.RequestID != idB || j.State != hostpatch.StateAccepted {
				t.Errorf("journal = %+v", j)
			}
		})
	}
}

// AC2: unsafe marker or request files are rejected without being read or followed.
func TestIntake_RejectsUnsafeFiles(t *testing.T) {
	outside := func(e *env, content string) string {
		p := filepath.Join(t.TempDir(), "target")
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	valid := func(e *env, id string) string {
		b, _ := hostpatch.BuildRequest(id, baseRev, []string{"devops"})
		return string(b)
	}
	tests := []struct {
		name   string
		wantID string
		setup  func(e *env)
	}{
		{"marker is a symlink", nilID, func(e *env) {
			mustNil(t, os.Symlink(outside(e, idA), e.path("requests/request.ready")))
			e.write("requests/"+idA+".json", valid(e, idA))
		}},
		{"marker is a FIFO", nilID, func(e *env) {
			if err := unix.Mkfifo(e.path("requests/request.ready"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"marker is a directory", nilID, func(e *env) {
			mustNil(t, os.Mkdir(e.path("requests/request.ready"), 0o700))
		}},
		{"marker over 64 bytes", nilID, func(e *env) {
			e.write("requests/request.ready", idA+strings.Repeat("\n", 40))
		}},
		{"marker is not a UUID", nilID, func(e *env) { e.write("requests/request.ready", "../../private/journal.json") }},
		{"marker uppercase UUID", nilID, func(e *env) { e.write("requests/request.ready", strings.ToUpper(idA)) }},
		{"marker empty", nilID, func(e *env) { e.write("requests/request.ready", "") }},
		{"marker wrong owner", nilID, func(e *env) {
			e.publish(idA)
			e.cfg.RequestUID = uint32(os.Getuid()) + 1
		}},
		{"request is a symlink", idA, func(e *env) {
			mustNil(t, os.Symlink(outside(e, valid(e, idA)), e.path("requests/"+idA+".json")))
			e.write("requests/request.ready", idA)
		}},
		{"request is a FIFO", idA, func(e *env) {
			if err := unix.Mkfifo(e.path("requests/"+idA+".json"), 0o600); err != nil {
				t.Fatal(err)
			}
			e.write("requests/request.ready", idA)
		}},
		{"request is a directory", idA, func(e *env) {
			mustNil(t, os.Mkdir(e.path("requests/"+idA+".json"), 0o700))
			e.write("requests/request.ready", idA)
		}},
		{"request over 4 KiB", idA, func(e *env) {
			e.write("requests/"+idA+".json", valid(e, idA)+strings.Repeat(" ", hostpatch.MaxRequestBytes))
			e.write("requests/request.ready", idA)
		}},
		{"request missing", idA, func(e *env) { e.write("requests/request.ready", idA) }},
		{"request names another id", idA, func(e *env) {
			e.write("requests/"+idA+".json", valid(e, idB))
			e.write("requests/request.ready", idA)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			tt.setup(e)

			done := make(chan Outcome, 1)
			go func() {
				out, err := Run(e.cfg)
				if err != nil {
					t.Errorf("Run: %v", err)
				}
				done <- out
			}()
			select {
			case out := <-done:
				if out != OutcomeRejected {
					t.Errorf("outcome = %v", out)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Run blocked on a non-regular file")
			}
			e.wantRejected(tt.wantID, hostpatch.CodeInvalidRequest)
			if e.exists("private/request.json") {
				t.Error("an unsafe request was copied to private/")
			}
			if e.exists("private/journal.json") {
				t.Error("a rejection must not write the journal")
			}
			if tt.wantID != nilID && e.exists("requests/"+tt.wantID+".json") {
				t.Error("rejected request file was left behind")
			}
		})
	}
}

// The owner check runs on the opened fd; a wrong uid is rejected for any file.
func TestOpenSafe_WrongOwner(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	dirfd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(dirfd) }()
	if _, err := readSafe(dirfd, "f", uint32(os.Getuid()), 16); err != nil {
		t.Fatalf("own file: %v", err)
	}
	if _, err := readSafe(dirfd, "f", uint32(os.Getuid())+1, 16); !errors.Is(err, errUnsafe) {
		t.Errorf("wrong owner err = %v, want errUnsafe", err)
	}
	if _, err := readSafe(dirfd, "missing", uint32(os.Getuid()), 16); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing err = %v, want ErrNotExist", err)
	}
}

// AC3: a request that fails the F3b-004 validation is rejected and leaves no copy.
func TestIntake_RejectsInvalidPatch(t *testing.T) {
	good := fmt.Sprintf(`"version":1,"request_id":%q,"base_rev":%q`, idA, baseRev)
	tests := []struct{ name, doc string }{
		{"empty list", `{` + good + `,"patch":{"oidc":{"allowed_groups":[]}}}`},
		{"devops missing", `{` + good + `,"patch":{"oidc":{"allowed_groups":["developer"]}}}`},
		{"unknown group", `{` + good + `,"patch":{"oidc":{"allowed_groups":["devops","admin"]}}}`},
		{"extra field", `{` + good + `,"patch":{"oidc":{"allowed_groups":["devops"],"allowed_domains":["x"]}}}`},
		{"unknown top-level key", `{` + good + `,"patch":{"oidc":{"allowed_groups":["devops"]}},"cmd":"x"}`},
		{"not json", `devops`},
		{"empty file", ``},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			e.write("requests/"+idA+".json", tt.doc)
			e.write("requests/request.ready", idA)
			if out := e.run(); out != OutcomeRejected {
				t.Fatalf("outcome = %v", out)
			}
			e.wantRejected(idA, hostpatch.CodeInvalidRequest)
			if r := e.result(); r.Phase != hostpatch.PhaseValidate {
				t.Errorf("phase = %q", r.Phase)
			}
			for _, rel := range []string{"private/request.json", "private/journal.json", "requests/" + idA + ".json"} {
				if e.exists(rel) {
					t.Errorf("%s should not exist", rel)
				}
			}
		})
	}
}

// AC4: the same ID as the last journal or result is not run again and the result is not replaced.
func TestIntake_DuplicateID(t *testing.T) {
	published := func(e *env) {
		b, err := hostpatch.EncodeResult(hostpatch.Result{
			Version: 1, RequestID: idA, State: hostpatch.StateSucceeded, Phase: hostpatch.PhaseCheck,
			FinishedAt: e.now.Add(-time.Hour), HealthVerified: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		e.write("results/result.json", string(b))
	}
	tests := []struct {
		name  string
		setup func(e *env)
	}{
		{"last journal ID, terminal", func(e *env) { e.setJournal(idA, hostpatch.StateSucceeded); published(e) }},
		{"last journal ID, still accepted", func(e *env) { e.setJournal(idA, hostpatch.StateAccepted) }},
		{"last result ID without a journal entry", func(e *env) { published(e) }},
		{"last result ID, journal moved on", func(e *env) { published(e); e.setJournal(idB, hostpatch.StateFailed) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			tt.setup(e)
			e.publish(idA)
			e.write("private/request.json", "previous copy")
			beforeResult, _ := os.ReadFile(e.path("results/result.json"))
			beforeJournal, _ := os.ReadFile(e.path("private/journal.json"))

			if out := e.run(); out != OutcomeDuplicate {
				t.Fatalf("outcome = %v", out)
			}
			afterResult, _ := os.ReadFile(e.path("results/result.json"))
			afterJournal, _ := os.ReadFile(e.path("private/journal.json"))
			if !bytes.Equal(beforeResult, afterResult) || !bytes.Equal(beforeJournal, afterJournal) {
				t.Error("a duplicate changed the result or the journal")
			}
			if got, _ := os.ReadFile(e.path("private/request.json")); string(got) != "previous copy" {
				t.Errorf("a duplicate replaced the private copy: %q", got)
			}
			for _, rel := range []string{"requests/request.ready", "requests/" + idA + ".json"} {
				if e.exists(rel) {
					t.Errorf("%s was not consumed", rel)
				}
			}
		})
	}
}

// AC5: while the journal is not terminal, a new ID is refused with busy and nothing else changes.
func TestIntake_BusyWhileNonTerminal(t *testing.T) {
	for _, st := range []hostpatch.State{hostpatch.StateAccepted, hostpatch.StateApplying} {
		t.Run(string(st), func(t *testing.T) {
			e := newEnv(t)
			e.setJournal(idA, st)
			e.write("private/request.json", "request A")
			beforeJournal, _ := os.ReadFile(e.path("private/journal.json"))
			e.publish(idB)

			if out := e.run(); out != OutcomeRejected {
				t.Fatalf("outcome = %v", out)
			}
			e.wantRejected(idB, hostpatch.CodeBusy)
			afterJournal, _ := os.ReadFile(e.path("private/journal.json"))
			if !bytes.Equal(beforeJournal, afterJournal) {
				t.Error("busy changed the journal")
			}
			if got, _ := os.ReadFile(e.path("private/request.json")); string(got) != "request A" {
				t.Errorf("busy replaced the private copy: %q", got)
			}
			if e.exists("requests/" + idB + ".json") {
				t.Error("the refused request file was left behind")
			}
		})
	}
}

// An unreadable journal is F3b-007's job; until then nothing is accepted or consumed.
func TestIntake_UnreadableJournalFailsSafe(t *testing.T) {
	e := newEnv(t)
	e.write("private/journal.json", "{not json")
	e.publish(idA)
	if _, err := Run(e.cfg); !errors.Is(err, ErrJournalCorrupt) {
		t.Fatalf("err = %v, want ErrJournalCorrupt", err)
	}
	if !e.exists("requests/request.ready") || e.exists("private/request.json") || e.exists("results/result.json") {
		t.Error("a corrupt journal must leave marker in place and accept nothing")
	}
}

// AC6 (part 1): a held lock blocks the run before it touches the marker.
func TestIntake_FlockSerializes(t *testing.T) {
	e := newEnv(t)
	e.publish(idA)
	lock, err := lockFile(e.path("private"))
	if err != nil {
		t.Fatal(err)
	}

	var finished atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := Run(e.cfg); err != nil {
			t.Errorf("Run: %v", err)
		}
		finished.Store(true)
	}()
	time.Sleep(300 * time.Millisecond)
	if finished.Load() || !e.exists("requests/request.ready") {
		t.Fatal("Run did not wait for the lock")
	}
	_ = lock.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not resume after the lock was released")
	}
	if j := e.journal(); j.RequestID != idA || j.State != hostpatch.StateAccepted {
		t.Errorf("journal = %+v", j)
	}
}

// AC6 (part 2): two real processes race for one marker; exactly one handles it.
func TestIntake_FlockSerializesProcesses(t *testing.T) {
	if root := os.Getenv("HSHELPER_TEST_ROOT"); root != "" {
		out, err := Run(Config{Root: root, RequestUID: uint32(os.Getuid())})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("OUTCOME=" + string(out))
		return
	}
	e := newEnv(t)
	e.publish(idA)

	const procs = 4
	cmds := make([]*exec.Cmd, procs)
	outs := make([]*bytes.Buffer, procs)
	for i := range cmds {
		outs[i] = &bytes.Buffer{}
		cmds[i] = exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestIntake_FlockSerializesProcesses$")
		cmds[i].Env = append(os.Environ(), "HSHELPER_TEST_ROOT="+e.root)
		cmds[i].Stdout, cmds[i].Stderr = outs[i], outs[i]
	}
	for _, c := range cmds {
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
	}
	accepted, idle := 0, 0
	for i, c := range cmds {
		if err := c.Wait(); err != nil {
			t.Fatalf("child %d: %v\n%s", i, err, outs[i])
		}
		switch {
		case strings.Contains(outs[i].String(), "OUTCOME="+string(OutcomeAccepted)):
			accepted++
		case strings.Contains(outs[i].String(), "OUTCOME="+string(OutcomeIdle)):
			idle++
		default:
			t.Fatalf("child %d output: %s", i, outs[i])
		}
	}
	if accepted != 1 || idle != procs-1 {
		t.Errorf("accepted=%d idle=%d, want 1 and %d", accepted, idle, procs-1)
	}
	if j := e.journal(); j.RequestID != idA || j.State != hostpatch.StateAccepted {
		t.Errorf("journal = %+v", j)
	}
}

// result.json is written atomically, readable by the container, and within 4 KiB.
func TestWriteResult(t *testing.T) {
	e := newEnv(t)
	no := false
	r := hostpatch.Result{Version: 1, RequestID: idA, State: hostpatch.StateFailed, Phase: hostpatch.PhaseValidate,
		FinishedAt: e.now, ErrorCode: hostpatch.CodeInvalidRequest, ConfigChanged: &no}
	if err := WriteResult(e.path("results"), r); err != nil {
		t.Fatal(err)
	}
	if got := e.result(); got.RequestID != idA || got.ErrorCode != hostpatch.CodeInvalidRequest {
		t.Errorf("result = %+v", got)
	}
	if st, err := os.Stat(e.path("results/result.json")); err != nil || st.Mode().Perm() != 0o644 {
		t.Errorf("mode = %v, %v", st, err)
	}
	ents, _ := os.ReadDir(e.path("results"))
	if len(ents) != 1 {
		t.Errorf("results/ holds %d entries, want only result.json", len(ents))
	}
	if err := WriteResult(e.path("results"), hostpatch.Result{}); !errors.Is(err, hostpatch.ErrInvalidResult) {
		t.Errorf("invalid result err = %v", err)
	}
	if got := e.result(); got.RequestID != idA {
		t.Error("a rejected write replaced the previous result")
	}
}

// Journal round trip and strict reading; no raw config or unknown field slips in.
func TestJournal_RoundTripAndStrict(t *testing.T) {
	dir := t.TempDir()
	if _, found, err := ReadJournal(dir); found || err != nil {
		t.Fatalf("empty dir: found=%v err=%v", found, err)
	}
	j := Journal{Version: 1, RequestID: idA, State: hostpatch.StateApplying, Phase: hostpatch.PhaseBackup,
		BaseHash: strings.Repeat("a", 64), CandidateHash: strings.Repeat("b", 64), BackupRef: "backup-1"}
	if err := WriteJournal(dir, j); err != nil {
		t.Fatal(err)
	}
	got, found, err := ReadJournal(dir)
	if err != nil || !found || got != j {
		t.Fatalf("got %+v found=%v err=%v", got, found, err)
	}
	for name, doc := range map[string]string{
		"unknown field": `{"version":1,"request_id":"` + idA + `","state":"accepted","config":"secret"}`,
		"bad state":     `{"version":1,"request_id":"` + idA + `","state":"running"}`,
		"bad id":        `{"version":1,"request_id":"x","state":"accepted"}`,
		"bad version":   `{"version":2,"request_id":"` + idA + `","state":"accepted"}`,
		"trailing":      `{"version":1,"request_id":"` + idA + `","state":"accepted"} {}`,
	} {
		if err := os.WriteFile(filepath.Join(dir, "journal.json"), []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := ReadJournal(dir); !errors.Is(err, ErrJournalCorrupt) {
			t.Errorf("%s: err = %v, want ErrJournalCorrupt", name, err)
		}
	}
	if err := WriteJournal(dir, Journal{Version: 1, RequestID: "bad", State: hostpatch.StateAccepted}); err == nil {
		t.Error("WriteJournal accepted an invalid journal")
	}
}

func mustNil(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
