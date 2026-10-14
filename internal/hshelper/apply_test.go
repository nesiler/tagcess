package hshelper

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/hostpatch"
)

const liveConfig = `server_url: https://hs.example.test
oidc:
  issuer: https://idp.example.test
  client_secret_path: /etc/headscale/oidc_secret
  allowed_groups:
    - devops
`

// outputMarker stands for command output that must never reach result.json, the journal,
// status.json or the logs.
const outputMarker = "SECRET-COMMAND-OUTPUT-8f3a"

// snapshot is what the fake runner saw when it was called.
type snapshot struct {
	call      string
	journal   Journal
	hasJrnl   bool
	config    []byte
	hasBackup bool
}

// fakeRunner stands in for systemctl, the headscale binary and the health probes. Each hook may
// fail the step; the default is success.
type fakeRunner struct {
	e         *applyEnv
	calls     []string
	snaps     []snapshot
	ctUser    string
	ctPath    string
	ctContent []byte
	ctMode    os.FileMode
	ctUID     uint32

	configtest func(ctx context.Context) error
	restart    func(ctx context.Context) error
	check      func(ctx context.Context, n int) error
	checks     int
}

func (f *fakeRunner) snap(call string) {
	s := snapshot{call: call}
	if j, found, err := ReadJournal(f.e.path("private")); err == nil && found {
		s.journal, s.hasJrnl = j, true
	}
	s.config, _ = os.ReadFile(f.e.confPath)
	if j, ok := f.e.lastID(); ok {
		_, err := os.Stat(f.e.path("private", "backup-"+j+".yaml"))
		s.hasBackup = err == nil
	}
	f.snaps = append(f.snaps, s)
	f.calls = append(f.calls, call)
}

func (f *fakeRunner) Configtest(ctx context.Context, serviceUser, configPath string) error {
	f.snap("configtest")
	f.ctUser, f.ctPath = serviceUser, configPath
	f.ctContent, _ = os.ReadFile(configPath)
	if st, err := os.Stat(configPath); err == nil {
		f.ctMode = st.Mode().Perm()
		f.ctUID = st.Sys().(*syscallStat).Uid
	}
	if f.configtest != nil {
		return f.configtest(ctx)
	}
	return nil
}

func (f *fakeRunner) Restart(ctx context.Context, unit string) error {
	f.snap("restart")
	if unit != "headscale.service" {
		return errors.New("wrong unit")
	}
	if f.restart != nil {
		return f.restart(ctx)
	}
	return nil
}

func (f *fakeRunner) Check(ctx context.Context, unit string) error {
	f.snap("check")
	f.checks++
	if f.check != nil {
		return f.check(ctx, f.checks)
	}
	return nil
}

func (f *fakeRunner) count(call string) int {
	n := 0
	for _, c := range f.calls {
		if c == call {
			n++
		}
	}
	return n
}

type syscallStat = syscall.Stat_t

// applyEnv is env plus a live config in its own directory (like /etc/headscale) and a fake runner.
type applyEnv struct {
	*env
	confDir  string
	confPath string
	runner   *fakeRunner
	id       string
}

func newApplyEnv(t *testing.T) *applyEnv {
	t.Helper()
	e := &applyEnv{env: newEnv(t), confDir: t.TempDir()}
	e.confPath = filepath.Join(e.confDir, "config.yaml")
	if err := os.WriteFile(e.confPath, []byte(liveConfig), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(e.confPath, 0o640); err != nil {
		t.Fatal(err)
	}
	e.runner = &fakeRunner{e: e}
	e.cfg.ConfigPath = e.confPath
	e.cfg.ServiceUser = "headscale"
	e.cfg.Unit = "headscale.service"
	e.cfg.Runner = e.runner
	e.cfg.Projector = NewFileProjector(e.confPath)
	e.cfg.ConfigtestTimeout = 2 * time.Second
	e.cfg.RestartTimeout = 2 * time.Second
	e.cfg.HealthTimeout = 2 * time.Second
	e.cfg.PollInterval = time.Millisecond
	return e
}

func (e *applyEnv) lastID() (string, bool) { return e.id, e.id != "" }

// request publishes a valid request against the live config and returns its ID.
func (e *applyEnv) request(id string, groups ...string) {
	e.t.Helper()
	e.id = id
	e.publish(id, groups...)
}

func (e *applyEnv) applied(id string, groups ...string) Outcome {
	e.t.Helper()
	e.request(id, groups...)
	return e.run()
}

func (e *applyEnv) liveBytes() []byte {
	e.t.Helper()
	b, err := os.ReadFile(e.confPath)
	if err != nil {
		e.t.Fatal(err)
	}
	return b
}

func (e *applyEnv) wantResult(id string, state hostpatch.State, code hostpatch.ErrorCode, phase hostpatch.Phase, changed *bool, healthy bool) {
	e.t.Helper()
	r := e.result()
	if r.RequestID != id || r.State != state || r.ErrorCode != code || r.Phase != phase || r.HealthVerified != healthy {
		e.t.Errorf("result = %+v, want %s/%s/%s health=%v for %s", r, state, code, phase, healthy, id)
	}
	switch {
	case changed == nil && r.ConfigChanged != nil:
		e.t.Errorf("config_changed = %v, want null", *r.ConfigChanged)
	case changed != nil && (r.ConfigChanged == nil || *r.ConfigChanged != *changed):
		e.t.Errorf("config_changed = %v, want %v", r.ConfigChanged, *changed)
	}
	if j := e.journal(); j.RequestID != id || j.State != state || j.ErrorCode != code {
		e.t.Errorf("journal = %+v, want %s/%s for %s", j, state, code, id)
	}
}

func (e *applyEnv) noTempLeft() {
	e.t.Helper()
	ents, err := os.ReadDir(e.confDir)
	if err != nil {
		e.t.Fatal(err)
	}
	for _, ent := range ents {
		if ent.Name() != "config.yaml" {
			e.t.Errorf("leftover file next to the config: %s", ent.Name())
		}
	}
}

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// AC1: every stage is journalled in order, the config is replaced by the candidate with owner and
// mode kept, the unit is restarted, health and the candidate hash are verified, and the result is
// succeeded.
func TestApply_Succeeds(t *testing.T) {
	e := newApplyEnv(t)
	if out := e.applied(idA, "devops", "developer"); out != OutcomeSucceeded {
		t.Fatalf("outcome = %v", out)
	}
	e.wantResult(idA, hostpatch.StateSucceeded, "", hostpatch.PhaseCheck, boolp(true), true)

	want, err := Candidate([]byte(liveConfig), []string{"devops", "developer"})
	if err != nil {
		t.Fatal(err)
	}
	if got := e.liveBytes(); !bytes.Equal(got, want) {
		t.Errorf("live config = %q, want the candidate %q", got, want)
	}
	if st, err := os.Stat(e.confPath); err != nil || st.Mode().Perm() != 0o640 {
		t.Errorf("mode after replace = %v, %v; want 0640", st, err)
	}
	e.noTempLeft()

	if got := strings.Join(e.runner.calls, ","); got != "configtest,restart,check" {
		t.Fatalf("calls = %s", got)
	}
	cfgTest, restart, check := e.runner.snaps[0], e.runner.snaps[1], e.runner.snaps[2]
	if !cfgTest.hasJrnl || cfgTest.journal.State != hostpatch.StateApplying || cfgTest.journal.Phase != hostpatch.PhaseValidate {
		t.Errorf("journal at configtest = %+v", cfgTest.journal)
	}
	if !bytes.Equal(cfgTest.config, []byte(liveConfig)) || cfgTest.hasBackup {
		t.Error("configtest must run before the backup and before the live config changes")
	}
	if restart.journal.State != hostpatch.StateApplying || restart.journal.Phase != hostpatch.PhaseRestart {
		t.Errorf("journal at restart = %+v", restart.journal)
	}
	if !bytes.Equal(restart.config, want) || !restart.hasBackup {
		t.Error("restart must come after the backup and the replacement")
	}
	if check.journal.Phase != hostpatch.PhaseCheck {
		t.Errorf("journal at check = %+v", check.journal)
	}

	bk, err := os.ReadFile(e.path("private", "backup-"+idA+".yaml"))
	if err != nil || string(bk) != liveConfig {
		t.Errorf("backup = %q, %v; want the old config", bk, err)
	}
	if st, err := os.Stat(e.path("private", "backup-"+idA+".yaml")); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("backup mode = %v, %v", st, err)
	}
	j := e.journal()
	if j.BaseHash != sum([]byte(liveConfig)) || j.CandidateHash != sum(want) || j.BackupRef != "backup-"+idA+".yaml" {
		t.Errorf("journal hashes/backup = %+v", j)
	}

	var s hostpatch.Status
	if s, err = hostpatch.DecodeStatus(e.read("results/status.json")); err != nil {
		t.Fatal(err)
	}
	if strings.Join(s.AllowedGroups, ",") != "devops,developer" || s.State != hostpatch.StateSucceeded || s.RequestID != idA {
		t.Errorf("status = %+v", s)
	}
	if e.exists("requests/request.ready") {
		t.Error("marker still there")
	}
}

// The health check polls until the service is up, within the health timeout.
func TestApply_HealthPollsUntilUp(t *testing.T) {
	e := newApplyEnv(t)
	e.runner.check = func(_ context.Context, n int) error {
		if n < 3 {
			return errors.New("starting")
		}
		return nil
	}
	if out := e.applied(idA, "devops", "developer"); out != OutcomeSucceeded {
		t.Fatalf("outcome = %v", out)
	}
	if e.runner.checks != 3 || e.runner.count("restart") != 1 {
		t.Errorf("checks = %d, restarts = %d", e.runner.checks, e.runner.count("restart"))
	}
}

// AC2: a base_rev that does not match the live projection is refused and nothing is touched.
func TestApply_StaleBase(t *testing.T) {
	e := newApplyEnv(t)
	live := strings.Replace(liveConfig, "    - devops\n", "    - devops\n    - developer\n", 1)
	if err := os.WriteFile(e.confPath, []byte(live), 0o640); err != nil {
		t.Fatal(err)
	}
	e.request(idA, "devops") // base_rev is the one for ["devops"], the live config now has two groups
	if out := e.run(); out != OutcomeFailed {
		t.Fatalf("outcome = %v", out)
	}
	e.wantResult(idA, hostpatch.StateFailed, hostpatch.CodeStaleBase, hostpatch.PhaseValidate, boolp(false), false)
	if !bytes.Equal(e.liveBytes(), []byte(live)) {
		t.Error("live config changed")
	}
	if len(e.runner.calls) != 0 {
		t.Errorf("runner called: %v", e.runner.calls)
	}
	e.noTempLeft()
	if e.exists("private/backup-" + idA + ".yaml") {
		t.Error("a stale request must not leave a backup")
	}
	s, err := hostpatch.DecodeStatus(e.read("results/status.json"))
	if err != nil || strings.Join(s.AllowedGroups, ",") != "devops,developer" {
		t.Errorf("status must be refreshed to the live groups: %+v, %v", s, err)
	}
}

// AC1 (F3b-027): the live config is checked again right before the rename. A hand edit between the
// read and the replace is not overwritten: the candidate is dropped, the live config is kept and the
// result is failed/stale_base with config_changed false.
func TestApply_LiveConfigChangedBeforeReplace(t *testing.T) {
	e := newApplyEnv(t)
	edited := strings.Replace(liveConfig, "    - devops\n", "    - devops\n    - developer\n", 1)
	// The hand edit lands after the helper read the config, while configtest runs on the candidate.
	e.runner.configtest = func(context.Context) error {
		return os.WriteFile(e.confPath, []byte(edited), 0o640)
	}
	if out := e.applied(idA, "devops", "developer"); out != OutcomeFailed {
		t.Fatalf("outcome = %v", out)
	}
	e.wantResult(idA, hostpatch.StateFailed, hostpatch.CodeStaleBase, hostpatch.PhaseReplace, boolp(false), false)
	if got := e.liveBytes(); string(got) != edited {
		t.Errorf("live config = %q, want the hand edit kept", got)
	}
	if e.runner.count("restart") != 0 || e.runner.count("check") != 0 {
		t.Errorf("runner ran after the base changed: %v", e.runner.calls)
	}
	e.noTempLeft()
}

// A config the projection cannot read is refused (fail safe), and nothing is touched.
func TestApply_ConfigUnreadable(t *testing.T) {
	tests := []struct {
		name  string
		setup func(e *applyEnv)
	}{
		{"not yaml", func(e *applyEnv) { _ = os.WriteFile(e.confPath, []byte("a: [b\n"), 0o640) }},
		{"missing", func(e *applyEnv) { _ = os.Remove(e.confPath) }},
		{"symlink", func(e *applyEnv) {
			real := filepath.Join(e.confDir, "real.yaml")
			_ = os.Rename(e.confPath, real)
			_ = os.Symlink(real, e.confPath)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newApplyEnv(t)
			e.request(idA, "devops", "developer")
			tt.setup(e)
			if out := e.run(); out != OutcomeFailed {
				t.Fatalf("outcome = %v", out)
			}
			e.wantResult(idA, hostpatch.StateFailed, hostpatch.CodeConfigUnreadable, hostpatch.PhaseValidate, boolp(false), false)
			if len(e.runner.calls) != 0 {
				t.Errorf("runner called: %v", e.runner.calls)
			}
		})
	}
}

// The private copy is trusted only when it carries the journal's ID (F3b-006 review note).
func TestApply_RequestCopyMismatch(t *testing.T) {
	e := newApplyEnv(t)
	e.request(idA, "devops", "developer")
	// Intake by hand, then swap the private copy for another request's.
	e.cfg.Runner = nil
	if out := e.run(); out != OutcomeAccepted {
		t.Fatalf("intake outcome = %v", out)
	}
	other, err := hostpatch.BuildRequest(idB, baseRev, []string{"devops", "developer"})
	if err != nil {
		t.Fatal(err)
	}
	e.write("private/request.json", string(other))
	e.cfg.Runner = e.runner
	if out, err := apply(e.cfg); err != nil || out != OutcomeFailed {
		t.Fatalf("apply = %v, %v", out, err)
	}
	e.wantResult(idA, hostpatch.StateFailed, hostpatch.CodeInvalidRequest, hostpatch.PhaseValidate, boolp(false), false)
	if len(e.runner.calls) != 0 || !bytes.Equal(e.liveBytes(), []byte(liveConfig)) {
		t.Error("nothing may run or change")
	}
}

// AC3: configtest failure or timeout leaves the live config alone, does not restart, removes the
// temporary candidate.
func TestApply_ConfigtestFailure(t *testing.T) {
	tests := []struct {
		name string
		fn   func(ctx context.Context) error
	}{
		{"fails", func(context.Context) error { return errors.New("bad config") }},
		{"times out", func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newApplyEnv(t)
			e.cfg.ConfigtestTimeout = 30 * time.Millisecond
			e.runner.configtest = tt.fn
			if out := e.applied(idA, "devops", "developer"); out != OutcomeFailed {
				t.Fatalf("outcome = %v", out)
			}
			e.wantResult(idA, hostpatch.StateFailed, hostpatch.CodeConfigtestFailed, hostpatch.PhaseValidate, boolp(false), false)
			if !bytes.Equal(e.liveBytes(), []byte(liveConfig)) {
				t.Error("live config changed")
			}
			if e.runner.count("restart") != 0 || e.runner.count("check") != 0 {
				t.Errorf("calls = %v", e.runner.calls)
			}
			e.noTempLeft()
			if e.exists("private/backup-" + idA + ".yaml") {
				t.Error("backup taken before configtest passed")
			}
		})
	}
}

// AC10: configtest runs as the service user, on a candidate in the config's own directory that the
// service user can read (same owner and mode as the live file), never on the live file or in the
// root-only private dir; when the identity cannot be had the step fails and nothing else runs.
func TestApply_ConfigtestAsServiceUser(t *testing.T) {
	e := newApplyEnv(t)
	if out := e.applied(idA, "devops", "developer"); out != OutcomeSucceeded {
		t.Fatalf("outcome = %v", out)
	}
	r := e.runner
	if r.ctUser != "headscale" {
		t.Errorf("configtest user = %q, want the --service-user value", r.ctUser)
	}
	if filepath.Dir(r.ctPath) != e.confDir || r.ctPath == e.confPath {
		t.Errorf("configtest path = %q, want a temporary file next to %q", r.ctPath, e.confPath)
	}
	if strings.HasPrefix(r.ctPath, e.path("private")) {
		t.Error("the candidate must not be in the 0700 private dir")
	}
	// viper (Headscale) infers the config type from the extension; a suffix it does not map makes
	// configtest fail before it ever reads the file (F3b-010 finding).
	if filepath.Base(r.ctPath) != ".config.tagcess-new.yaml" {
		t.Errorf("candidate path %q, want .config.tagcess-new.yaml (a .yaml extension)", r.ctPath)
	}
	want, _ := Candidate([]byte(liveConfig), []string{"devops", "developer"})
	if !bytes.Equal(r.ctContent, want) {
		t.Errorf("configtest saw %q, want the candidate", r.ctContent)
	}
	if r.ctMode != 0o640 || r.ctUID != uint32(os.Getuid()) {
		t.Errorf("candidate owner/mode = %d/%v, want the live file's", r.ctUID, r.ctMode)
	}
	if strings.Contains(strings.Join(e.logs, "\n"), "root") {
		t.Errorf("logs: %v", e.logs)
	}

	t.Run("identity cannot be dropped to", func(t *testing.T) {
		e := newApplyEnv(t)
		e.runner.configtest = func(context.Context) error { return errNoServiceUser }
		if out := e.applied(idA, "devops", "developer"); out != OutcomeFailed {
			t.Fatalf("outcome = %v", out)
		}
		e.wantResult(idA, hostpatch.StateFailed, hostpatch.CodeConfigtestFailed, hostpatch.PhaseValidate, boolp(false), false)
		if e.runner.count("restart") != 0 || !bytes.Equal(e.liveBytes(), []byte(liveConfig)) {
			t.Error("nothing may run or change")
		}
		e.noTempLeft()
	})
}

// AC3 (backup): a backup that cannot be written stops before the replacement.
func TestApply_BackupFailure(t *testing.T) {
	e := newApplyEnv(t)
	e.request(idA, "devops", "developer")
	if err := os.MkdirAll(e.path("private", "backup-"+idA+".yaml", "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if out := e.run(); out != OutcomeFailed {
		t.Fatalf("outcome = %v", out)
	}
	e.wantResult(idA, hostpatch.StateFailed, hostpatch.CodeBackupFailed, hostpatch.PhaseBackup, boolp(false), false)
	if !bytes.Equal(e.liveBytes(), []byte(liveConfig)) || e.runner.count("restart") != 0 {
		t.Error("nothing may change or restart")
	}
	e.noTempLeft()
}

// AC4: after the replacement a restart or health failure leaves the new config in place: no
// restore, no second restart.
func TestApply_HealthFailureNoRollback(t *testing.T) {
	tests := []struct {
		name  string
		setup func(e *applyEnv)
		code  hostpatch.ErrorCode
		phase hostpatch.Phase
	}{
		{"restart fails", func(e *applyEnv) {
			e.runner.restart = func(context.Context) error { return errors.New("failed") }
		}, hostpatch.CodeRestartFailed, hostpatch.PhaseRestart},
		{"restart times out", func(e *applyEnv) {
			e.cfg.RestartTimeout = 30 * time.Millisecond
			e.runner.restart = func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }
		}, hostpatch.CodeRestartFailed, hostpatch.PhaseRestart},
		{"health check fails", func(e *applyEnv) {
			e.cfg.HealthTimeout = 30 * time.Millisecond
			e.runner.check = func(context.Context, int) error { return errors.New("unhealthy") }
		}, hostpatch.CodeHealthFailed, hostpatch.PhaseCheck},
		{"health check times out", func(e *applyEnv) {
			e.cfg.HealthTimeout = 30 * time.Millisecond
			e.runner.check = func(ctx context.Context, _ int) error { <-ctx.Done(); return ctx.Err() }
		}, hostpatch.CodeHealthFailed, hostpatch.PhaseCheck},
		{"config is not the candidate after the checks", func(e *applyEnv) {
			e.runner.check = func(context.Context, int) error {
				return os.WriteFile(e.confPath, []byte("other: 1\n"), 0o640)
			}
		}, hostpatch.CodeHealthFailed, hostpatch.PhaseCheck},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newApplyEnv(t)
			tt.setup(e)
			if out := e.applied(idA, "devops", "developer"); out != OutcomeFailed {
				t.Fatalf("outcome = %v", out)
			}
			e.wantResult(idA, hostpatch.StateFailed, tt.code, tt.phase, boolp(true), false)
			if e.runner.count("restart") != 1 {
				t.Errorf("restarts = %d, want exactly 1", e.runner.count("restart"))
			}
			live := e.liveBytes()
			if bytes.Equal(live, []byte(liveConfig)) {
				t.Error("the backup was put back")
			}
			if tt.name != "config is not the candidate after the checks" && sum(live) != e.journal().CandidateHash {
				t.Error("live config is not the candidate")
			}
			e.noTempLeft()
		})
	}
}

// AC5: a replacement whose outcome is unknown is failed with config_changed null, never success,
// and nothing restarts.
func TestApply_ReplaceUnknown(t *testing.T) {
	e := newApplyEnv(t)
	e.cfg.rename = func(oldpath, newpath string) error { return errors.New("rename: i/o error") }
	if out := e.applied(idA, "devops", "developer"); out != OutcomeFailed {
		t.Fatalf("outcome = %v", out)
	}
	e.wantResult(idA, hostpatch.StateFailed, hostpatch.CodeReplaceFailed, hostpatch.PhaseReplace, nil, false)
	if e.runner.count("restart") != 0 {
		t.Error("restarted after an unknown replacement")
	}
	e.noTempLeft()
}

// AC6: command output and config content never reach result.json, the journal, status.json or the
// logs; only codes and stages.
func TestApply_ResultCarriesNoOutput(t *testing.T) {
	steps := []struct {
		name  string
		setup func(e *applyEnv)
	}{
		{"configtest", func(e *applyEnv) {
			e.runner.configtest = func(context.Context) error { return errors.New(outputMarker + " " + liveConfig) }
		}},
		{"restart", func(e *applyEnv) {
			e.runner.restart = func(context.Context) error { return errors.New(outputMarker) }
		}},
		{"check", func(e *applyEnv) {
			e.cfg.HealthTimeout = 20 * time.Millisecond
			e.runner.check = func(context.Context, int) error { return errors.New(outputMarker) }
		}},
		{"replace", func(e *applyEnv) {
			e.cfg.rename = func(string, string) error { return errors.New(outputMarker) }
		}},
	}
	for _, st := range steps {
		t.Run(st.name, func(t *testing.T) {
			e := newApplyEnv(t)
			st.setup(e)
			e.applied(idA, "devops", "developer")
			files := []string{"results/result.json", "results/status.json", "private/journal.json"}
			for _, f := range files {
				b := e.read(f)
				for _, bad := range []string{outputMarker, "idp.example.test", "client_secret_path", "oidc_secret"} {
					if bytes.Contains(b, []byte(bad)) {
						t.Errorf("%s contains %q", f, bad)
					}
				}
			}
			for _, l := range e.logs {
				for _, bad := range []string{outputMarker, "idp.example.test", "client_secret_path", "oidc_secret"} {
					if strings.Contains(l, bad) {
						t.Errorf("log %q contains %q", l, bad)
					}
				}
			}
		})
	}
}

// AC7: when result.json cannot be written the journal keeps its non-terminal state, the call
// returns an error, and the next finalize publishes interrupted for the same ID.
func TestApply_ResultWriteFailureKeepsJournal(t *testing.T) {
	e := newApplyEnv(t)
	e.request(idA, "devops", "developer")
	// results/ becomes a plain file, so result.json cannot be written (status.json neither).
	if err := os.RemoveAll(e.path("results")); err != nil {
		t.Fatal(err)
	}
	e.write("results", "not a directory")

	out, err := Run(e.cfg)
	if err == nil {
		t.Fatalf("Run returned no error, outcome %v", out)
	}
	if out == OutcomeSucceeded {
		t.Error("a result that was not published is not a success")
	}
	j := e.journal()
	if j.RequestID != idA || j.State.Terminal() {
		t.Errorf("journal = %+v, want it kept in its non-terminal state", j)
	}

	if err := os.Remove(e.path("results")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(e.path("results"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := e.finalize(); got != OutcomeInterrupted {
		t.Fatalf("finalize outcome = %v", got)
	}
	e.wantInterrupted(idA, hostpatch.CodeInterrupted, j.Phase, nil)
}

// AC8: the source has no path that copies the backup back over the live config. Backup names are
// built and used by writeBackup only (and the journal field set in run), so no other function can read a backup; and nothing in the
// code is called or says restore/rollback/revert.
func TestApply_NoRestorePath(t *testing.T) {
	fset := token.NewFileSet()
	names, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]*ast.File{}
	for _, n := range names {
		if strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, n, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		files[n] = f
	}
	// ident -> the functions that may mention it (nil: anywhere, they are plain constants).
	allowed := map[string][]string{
		"PhaseBackup": nil, "CodeBackupFailed": nil,
		"BackupRef": {"run"}, "writeBackup": {"run", "writeBackup"}, "backupName": {"writeBackup", "backupName"},
	}
	banned := regexp.MustCompile(`(?i)restore|rollback|roll back|revert`)
	for name, file := range files {
		for _, d := range file.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(fn, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.Ident:
					if banned.MatchString(x.Name) {
						t.Errorf("%s: identifier %q", name, x.Name)
					}
					if funcs, ok := allowed[x.Name]; strings.Contains(strings.ToLower(x.Name), "backup") && (!ok || (funcs != nil && !slices.Contains(funcs, fn.Name.Name))) {
						t.Errorf("%s: %s mentions %q", name, fn.Name.Name, x.Name)
					}
				case *ast.BasicLit:
					if x.Kind == token.STRING && (banned.MatchString(x.Value) || (strings.Contains(x.Value, "backup-") && fn.Name.Name != "backupName")) {
						t.Errorf("%s: %s has string %s", name, fn.Name.Name, x.Value)
					}
				}
				return true
			})
		}
	}
}

// A request for an ID that already ran is not applied again (the duplicate rule of intake holds).
func TestApply_DuplicateNotRerun(t *testing.T) {
	e := newApplyEnv(t)
	if out := e.applied(idA, "devops", "developer"); out != OutcomeSucceeded {
		t.Fatalf("outcome = %v", out)
	}
	calls := len(e.runner.calls)
	e.write("requests/request.ready", idA)
	if out := e.run(); out != OutcomeDuplicate {
		t.Fatalf("outcome = %v", out)
	}
	if len(e.runner.calls) != calls {
		t.Error("the duplicate ran again")
	}
}
