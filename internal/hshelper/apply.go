package hshelper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/nesiler/tagcess/internal/hostpatch"
)

const (
	defaultConfigtestTimeout = 15 * time.Second
	defaultRestartTimeout    = 45 * time.Second
	defaultHealthTimeout     = 30 * time.Second
	defaultPollInterval      = time.Second
	// maxConfigBytes bounds the live config the helper reads.
	maxConfigBytes = 1 << 20
)

// fileMeta is the owner and mode of the live config; the candidate gets the same.
type fileMeta struct {
	uid, gid uint32
	mode     os.FileMode
}

// readConfigFile reads the live config without following a link, from the opened fd, and returns
// its owner and mode. Anything but a regular file of reasonable size is config_unreadable.
func readConfigFile(path string) ([]byte, fileMeta, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fileMeta{}, unreadable("cannot open the config")
	}
	f := os.NewFile(uintptr(fd), "config")
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size > maxConfigBytes {
		return nil, fileMeta{}, unreadable("the config is not a regular file of supported size")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil || len(b) > maxConfigBytes {
		return nil, fileMeta{}, unreadable("cannot read the config")
	}
	return b, fileMeta{uid: st.Uid, gid: st.Gid, mode: os.FileMode(st.Mode & 0o777)}, nil
}

func sha(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// applier carries one request through the flow. The caller holds the flock.
type applier struct {
	cfg  Config
	priv string
	j    Journal
	tmp  string // the candidate file next to the live config, until it is renamed or removed
}

// apply runs the accepted request in the journal: base_rev check, candidate, configtest, backup,
// atomic replace, restart, health check (ADR 0008, ADR 0021). Every stage is journalled before it
// starts. A failure before the replace leaves the live config alone; a failure after it leaves
// the new config in place. There is no restore and no second restart. The result is published
// before the journal turns terminal, so a crash in between is interrupted at the next start.
func apply(cfg Config) (Outcome, error) {
	priv := filepath.Join(cfg.Root, privateDir)
	j, found, err := ReadJournal(priv)
	if err != nil {
		return OutcomeIdle, err
	}
	if !found || j.State != hostpatch.StateAccepted {
		return OutcomeIdle, nil
	}
	a := &applier{cfg: cfg, priv: priv, j: j}
	return a.run()
}

func (a *applier) run() (Outcome, error) {
	req, err := a.loadRequest()
	if err != nil {
		return a.fail(hostpatch.PhaseValidate, hostpatch.CodeInvalidRequest, new(bool))
	}
	if err := a.enter(hostpatch.PhaseValidate); err != nil {
		return OutcomeIdle, err
	}

	src, meta, err := readConfigFile(a.cfg.ConfigPath)
	if err != nil {
		return a.fail(hostpatch.PhaseValidate, hostpatch.CodeConfigUnreadable, new(bool))
	}
	_, rev, err := Project(src)
	if err != nil {
		return a.fail(hostpatch.PhaseValidate, hostpatch.CodeConfigUnreadable, new(bool))
	}
	if rev != req.BaseRev {
		return a.fail(hostpatch.PhaseValidate, hostpatch.CodeStaleBase, new(bool))
	}
	cand, err := Candidate(src, req.Patch.OIDC.AllowedGroups)
	if err != nil {
		code := hostpatch.CodeInvalidRequest
		if errors.Is(err, ErrConfigUnreadable) {
			code = hostpatch.CodeConfigUnreadable
		}
		return a.fail(hostpatch.PhaseValidate, code, new(bool))
	}
	a.j.BaseHash, a.j.CandidateHash = sha(src), sha(cand)
	if a.tmp, err = writeCandidate(a.cfg.ConfigPath, cand, meta); err != nil {
		return a.fail(hostpatch.PhaseValidate, hostpatch.CodeConfigtestFailed, new(bool))
	}
	if err := a.save(); err != nil {
		return a.abort(err)
	}

	// configtest: as the service user, on the candidate file the replace will use.
	if err := a.step(a.cfg.configtestTimeout(), func(ctx context.Context) error {
		return a.cfg.Runner.Configtest(ctx, a.cfg.ServiceUser, a.tmp)
	}); err != nil {
		return a.fail(hostpatch.PhaseValidate, hostpatch.CodeConfigtestFailed, new(bool))
	}

	if err := a.enter(hostpatch.PhaseBackup); err != nil {
		return a.abort(err)
	}
	ref, err := writeBackup(a.priv, a.j.RequestID, src)
	if err != nil {
		return a.fail(hostpatch.PhaseBackup, hostpatch.CodeBackupFailed, new(bool))
	}
	a.j.BackupRef = ref

	if err := a.enter(hostpatch.PhaseReplace); err != nil {
		return a.abort(err)
	}
	// The candidate was built from the bytes read before configtest. If the live config changed
	// since (a hand edit), renaming would silently overwrite it: re-read the base hash one last time
	// before the rename and refuse, leaving the live file alone (F3b-008 LOW 1, F3b-027 AC1).
	live, _, err := readConfigFile(a.cfg.ConfigPath)
	if err != nil {
		return a.fail(hostpatch.PhaseReplace, hostpatch.CodeConfigUnreadable, new(bool))
	}
	if sha(live) != a.j.BaseHash {
		return a.fail(hostpatch.PhaseReplace, hostpatch.CodeStaleBase, new(bool))
	}
	if err := a.replace(); err != nil {
		// Whether the new file is in place is not known to the helper: not success, not "unchanged".
		return a.fail(hostpatch.PhaseReplace, hostpatch.CodeReplaceFailed, nil)
	}

	yes := true
	if err := a.enter(hostpatch.PhaseRestart); err != nil {
		return a.abort(err)
	}
	if err := a.step(a.cfg.restartTimeout(), func(ctx context.Context) error {
		return a.cfg.Runner.Restart(ctx, a.cfg.Unit)
	}); err != nil {
		return a.fail(hostpatch.PhaseRestart, hostpatch.CodeRestartFailed, &yes)
	}

	if err := a.enter(hostpatch.PhaseCheck); err != nil {
		return a.abort(err)
	}
	if err := a.step(a.cfg.healthTimeout(), a.pollHealth); err != nil {
		return a.fail(hostpatch.PhaseCheck, hostpatch.CodeHealthFailed, &yes)
	}
	if live, _, err := readConfigFile(a.cfg.ConfigPath); err != nil || sha(live) != a.j.CandidateHash {
		return a.fail(hostpatch.PhaseCheck, hostpatch.CodeHealthFailed, &yes)
	}
	return a.finish(hostpatch.Result{
		Version: hostpatch.Version, RequestID: a.j.RequestID, State: hostpatch.StateSucceeded, Phase: hostpatch.PhaseCheck,
		FinishedAt: a.cfg.now(), ConfigChanged: &yes, HealthVerified: true,
	})
}

// loadRequest reads the private copy of the request. It is trusted only when it carries the ID
// the journal is about.
func (a *applier) loadRequest() (hostpatch.Request, error) {
	f, err := os.Open(filepath.Join(a.priv, copyName)) //nolint:gosec // root-owned private dir
	if err != nil {
		return hostpatch.Request{}, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, hostpatch.MaxRequestBytes+1))
	if err != nil {
		return hostpatch.Request{}, err
	}
	req, err := hostpatch.ParseRequest(b)
	if err != nil {
		return hostpatch.Request{}, err
	}
	if req.RequestID != a.j.RequestID {
		return hostpatch.Request{}, errors.New("request copy belongs to another ID")
	}
	return req, nil
}

// save writes the journal as it is now.
func (a *applier) save() error { return WriteJournal(a.priv, a.j) }

// enter journals the start of a stage.
func (a *applier) enter(p hostpatch.Phase) error {
	a.j.State, a.j.Phase = hostpatch.StateApplying, p
	return a.save()
}

// step runs fn under its own timeout.
func (a *applier) step(timeout time.Duration, fn func(ctx context.Context) error) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return fn(ctx)
}

// pollHealth retries the runner's check until it passes or ctx ends.
func (a *applier) pollHealth(ctx context.Context) error {
	for {
		err := a.cfg.Runner.Check(ctx, a.cfg.Unit)
		if err == nil {
			return nil
		}
		t := time.NewTimer(a.cfg.pollInterval())
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}

// replace renames the candidate over the live config and syncs the directory.
func (a *applier) replace() error {
	rename := a.cfg.rename
	if rename == nil {
		rename = os.Rename
	}
	if err := rename(a.tmp, a.cfg.ConfigPath); err != nil {
		return err
	}
	a.tmp = ""
	return syncDir(filepath.Dir(a.cfg.ConfigPath))
}

// fail publishes a failed result carrying only the stage and the code.
func (a *applier) fail(p hostpatch.Phase, code hostpatch.ErrorCode, changed *bool) (Outcome, error) {
	a.dropCandidate()
	a.cfg.logf("request %s failed at %s: %s", a.j.RequestID, p, code)
	return a.finish(hostpatch.Result{
		Version: hostpatch.Version, RequestID: a.j.RequestID, State: hostpatch.StateFailed, Phase: p,
		FinishedAt: a.cfg.now(), ErrorCode: code, ConfigChanged: changed,
	})
}

// abort is for a journal that could not be written mid-flow: nothing more runs, the journal keeps
// its last state, and the next start turns it into interrupted.
func (a *applier) abort(err error) (Outcome, error) {
	a.dropCandidate()
	return OutcomeFailed, fmt.Errorf("write journal: %w", err)
}

// finish publishes r, then makes the journal terminal. If the result cannot be written the journal
// stays as it is (ADR 0021 b) and the error is returned.
func (a *applier) finish(r hostpatch.Result) (Outcome, error) {
	// Never succeeded unless the result is out and the journal agrees.
	if err := WriteResult(filepath.Join(a.cfg.Root, resultsDir), r); err != nil {
		return OutcomeFailed, fmt.Errorf("publish result: %w", err)
	}
	a.j.State, a.j.Phase, a.j.ErrorCode = r.State, r.Phase, r.ErrorCode
	if err := a.save(); err != nil {
		return OutcomeFailed, fmt.Errorf("write journal: %w", err)
	}
	out := OutcomeFailed
	if r.State == hostpatch.StateSucceeded {
		out = OutcomeSucceeded
	}
	if r.State == hostpatch.StateSucceeded {
		a.cfg.logf("request %s succeeded", r.RequestID)
	}
	return out, nil
}

// dropCandidate removes the temporary candidate if it is still there.
func (a *applier) dropCandidate() {
	if a.tmp != "" {
		_ = os.Remove(a.tmp)
		a.tmp = ""
	}
}

// writeCandidate creates the candidate next to the live config with the live file's owner and
// mode (the service user must be able to read it for configtest), fsynced.
func writeCandidate(configPath string, data []byte, meta fileMeta) (string, error) {
	dir, base := filepath.Split(configPath)
	// The temp file keeps a .yaml extension: Headscale uses viper, which infers the config type
	// from the extension, so `configtest -c` rejects a name it cannot map (F3b-010).
	path := filepath.Join(dir, "."+strings.TrimSuffix(base, filepath.Ext(base))+".tagcess-new.yaml")
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return "", err
	}
	f := os.NewFile(uintptr(fd), path)
	if err = f.Chown(int(meta.uid), int(meta.gid)); err == nil {
		err = f.Chmod(meta.mode)
	}
	if err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return path, nil
}

func backupName(id string) string { return "backup-" + id + ".yaml" }

// writeBackup keeps the pre-change config under private/ (root, 0600) and returns its name for
// the journal. Backups are kept for the operator; the helper never reads one back.
func writeBackup(privDir, id string, src []byte) (string, error) {
	name := backupName(id)
	if err := atomicWrite(privDir, name, src, 0o600); err != nil {
		return "", err
	}
	return name, nil
}
