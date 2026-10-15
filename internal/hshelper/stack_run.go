package hshelper

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"golang.org/x/sys/unix"

	"github.com/nesiler/tagcess/internal/hostpatch"
	"github.com/nesiler/tagcess/internal/stack"
)

const (
	handoffDir = "handoff"
	handoffIn  = "in"
	// defaultHandoffMaxAge is how long a drop file may wait (setup-flow.md §5.4).
	defaultHandoffMaxAge = 15 * time.Minute
)

// handoffNameRE matches `<request_id>.<kind>`; anything else in the drop directory is junk.
var handoffNameRE = regexp.MustCompile(`^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.([a-z0-9_]+)$`)

// StackConfig is the stack channel's fixed setup. Nothing in a request can change it.
type StackConfig struct {
	// Root is the channel root (/var/lib/tagcess-host): requests/, results/, private/, handoff/in/.
	Root string
	// StackDir is /etc/tagcess/stack; TagcessSecretsDir is /etc/tagcess/secrets.
	StackDir          string
	TagcessSecretsDir string
	// HeadscaleRoot is the ADR 0021 channel root. Both channels take the flock of its private/ directory, and
	// neither runs while the other's journal is not terminal. Empty when there is no Headscale channel.
	HeadscaleRoot string
	// RequestUID is the uid the container's request and drop files must belong to.
	RequestUID uint32
	// HandoffUID is the uid drop files must belong to; zero means RequestUID.
	HandoffUID uint32
	// Manifest is the release manifest embedded in the helper binary.
	Manifest stack.Manifest
	Docker   Docker
	// Discover produces results/discovery.json for the discover operation (I-3); nil means unsupported.
	Discover func() ([]byte, error)
	// SecretOwner returns the uid and gid a component's secret files belong to; nil leaves the owner alone.
	SecretOwner func(c stack.Component) (uid, gid int, ok bool)

	Now func() time.Time
	// Logf only ever gets IDs and reasons, never file content.
	Logf func(format string, args ...any)
	// ValidateTimeout and StepTimeout bound `config --quiet` and the pull/start steps; HandoffMaxAge the drop files.
	ValidateTimeout time.Duration
	StepTimeout     time.Duration
	HandoffMaxAge   time.Duration

	// randRead fills secrets; tests inject it.
	randRead func([]byte) (int, error)
}

func (c StackConfig) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c StackConfig) logf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
		return
	}
	log.Printf(format, args...)
}

func (c StackConfig) validateTimeout() time.Duration {
	return orDefault(c.ValidateTimeout, defaultValidate)
}
func (c StackConfig) stepTimeout() time.Duration { return orDefault(c.StepTimeout, defaultDockerStep) }
func (c StackConfig) handoffMaxAge() time.Duration {
	return orDefault(c.HandoffMaxAge, defaultHandoffMaxAge)
}

func (c StackConfig) handoffUID() uint32 {
	if c.HandoffUID != 0 {
		return c.HandoffUID
	}
	return c.RequestUID
}

func (c StackConfig) priv() string { return filepath.Join(c.Root, privateDir) }

// lockDir is where the shared helper.lock lives: the Headscale channel's private/ when there is one.
func (c StackConfig) lockDir() string {
	if c.HeadscaleRoot != "" {
		return filepath.Join(c.HeadscaleRoot, privateDir)
	}
	return c.priv()
}

func (c StackConfig) tagcessSecretsDir() string {
	if c.TagcessSecretsDir != "" {
		return c.TagcessSecretsDir
	}
	return "/etc/tagcess/secrets"
}

// stackLocked runs fn under the shared exclusive flock and then publishes status.json.
func stackLocked(cfg StackConfig, fn func() (Outcome, error)) (Outcome, error) {
	lock, err := lockFile(cfg.lockDir())
	if err != nil {
		return OutcomeIdle, err
	}
	defer func() { _ = lock.Close() }()
	out, err := fn()
	if perr := PublishStackStatus(cfg); perr != nil {
		cfg.logf("stack status.json not published: %v", perr)
	}
	return out, err
}

// otherChannelBusy reports whether the ADR 0021 journal is not terminal. An unreadable one counts as busy: when
// the state of the other channel is unknown, nothing changes.
func otherChannelBusy(cfg StackConfig) bool {
	if cfg.HeadscaleRoot == "" {
		return false
	}
	j, found, err := ReadJournal(filepath.Join(cfg.HeadscaleRoot, privateDir))
	return err != nil || (found && !j.State.Terminal())
}

// stackChannelBusy is the reverse check, used by the ADR 0021 intake: the stack journal is not terminal.
func stackChannelBusy(stackRoot string) bool {
	if stackRoot == "" {
		return false
	}
	j, found, err := readStackJournal(filepath.Join(stackRoot, privateDir))
	return err != nil || (found && !j.State.Terminal())
}

// StackRun is the `stack-run` mode (the .path trigger): under the shared flock it takes at most one pending
// request, accepts or rejects it, and runs an accepted one to a terminal result.
func StackRun(cfg StackConfig) (Outcome, error) {
	return stackLocked(cfg, func() (Outcome, error) {
		out, req, err := stackIntake(cfg)
		if err != nil || out != OutcomeAccepted {
			return out, err
		}
		return runStackOp(cfg, req)
	})
}

func stackIntake(cfg StackConfig) (Outcome, StackRequest, error) {
	priv := cfg.priv()
	results := filepath.Join(cfg.Root, resultsDir)
	dirfd, err := unix.Open(filepath.Join(cfg.Root, requestsDir), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return OutcomeIdle, StackRequest{}, fmt.Errorf("open requests dir: %w", err)
	}
	defer func() { _ = unix.Close(dirfd) }()

	// reject publishes the failure, deletes the request's drop files and consumes the marker.
	reject := func(id string, op StackOp, code StackCode, why string) (Outcome, StackRequest, error) {
		cfg.logf("stack request %s rejected: %s (%s)", id, code, why)
		unchanged := false
		if err := writeStackResult(results, StackResult{
			Version: StackVersion, RequestID: id, Op: op, State: hostpatch.StateFailed, Phase: StackPhaseValidate,
			FinishedAt: cfg.now(), ErrorCode: code, Changed: &unchanged,
		}); err != nil {
			return OutcomeIdle, StackRequest{}, fmt.Errorf("publish result: %w", err)
		}
		if id == unknownID {
			deleteAllHandoff(cfg)
		} else {
			deleteHandoff(cfg, id)
		}
		return OutcomeRejected, StackRequest{}, consume(Config{Logf: cfg.Logf}, dirfd, id)
	}

	mb, err := readSafe(dirfd, markerName, cfg.RequestUID, hostpatch.MaxMarkerBytes)
	if errors.Is(err, os.ErrNotExist) {
		return OutcomeIdle, StackRequest{}, nil
	}
	if err != nil {
		return reject(unknownID, "", StackInvalidRequest, "unsafe marker")
	}
	id, err := hostpatch.ParseMarker(mb)
	if err != nil {
		return reject(unknownID, "", StackInvalidRequest, "bad marker")
	}

	j, found, err := readStackJournal(priv)
	if err != nil {
		return OutcomeIdle, StackRequest{}, err
	}
	if (found && j.RequestID == id) || readStackResultID(results) == id {
		cfg.logf("stack request %s ignored: same ID as the last journal/result", id)
		return OutcomeDuplicate, StackRequest{}, consume(Config{Logf: cfg.Logf}, dirfd, id)
	}
	if found && !j.State.Terminal() {
		return reject(id, "", StackBusy, "stack journal not terminal")
	}
	if otherChannelBusy(cfg) {
		return reject(id, "", StackBusy, "the Headscale channel has an unfinished operation")
	}

	rb, err := readSafe(dirfd, id+".json", cfg.RequestUID, MaxStackRequestBytes)
	if err != nil {
		return reject(id, "", StackInvalidRequest, "unreadable or unsafe request file")
	}
	req, err := ParseStackRequest(rb)
	if err != nil {
		return reject(id, "", StackInvalidRequest, err.Error())
	}
	if req.RequestID != id {
		return reject(id, req.Op, StackInvalidRequest, "request_id differs from the marker")
	}
	if req.Op.writes() {
		st, err := readStackState(priv)
		if err != nil {
			return reject(id, req.Op, StackInvalidRequest, "stack state unreadable")
		}
		if st.rev() != req.BaseRev {
			return reject(id, req.Op, StackStaleBase, "base_rev is stale")
		}
	}

	if err := atomicWrite(priv, stackRequestName, rb, 0o600); err != nil {
		return OutcomeIdle, StackRequest{}, fmt.Errorf("copy request: %w", err)
	}
	if err := writeStackJournal(priv, stackJournal{Version: StackVersion, RequestID: id, Op: req.Op, State: hostpatch.StateAccepted}); err != nil {
		return OutcomeIdle, StackRequest{}, fmt.Errorf("write journal: %w", err)
	}
	deleteHandoffExcept(cfg, id)
	cfg.logf("stack request %s accepted (%s)", id, req.Op)
	return OutcomeAccepted, req, consume(Config{Logf: cfg.Logf}, dirfd, id)
}

// handoffPath is the drop directory.
func (c StackConfig) handoffPath() string { return filepath.Join(c.Root, handoffDir, handoffIn) }

// removeHandoff deletes, without reading, every drop file for which del returns true. m is the parsed
// `<request_id>.<kind>` name, nil for a junk name.
func removeHandoff(cfg StackConfig, del func(m []string) bool) {
	entries, err := os.ReadDir(cfg.handoffPath())
	if err != nil {
		return
	}
	dirfd, err := unix.Open(cfg.handoffPath(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return
	}
	defer func() { _ = unix.Close(dirfd) }()
	for _, e := range entries {
		if !del(handoffNameRE.FindStringSubmatch(e.Name())) {
			continue
		}
		if err := unlinkAt(dirfd, e.Name()); err != nil {
			cfg.logf("handoff: cannot remove a drop file: %v", err)
		}
	}
}

// deleteHandoff removes the drop files of request id.
func deleteHandoff(cfg StackConfig, id string) {
	removeHandoff(cfg, func(m []string) bool { return m != nil && m[1] == id })
}

// deleteHandoffExcept removes every drop file that does not belong to request id: another or a finished
// request's (replay) and junk.
func deleteHandoffExcept(cfg StackConfig, id string) {
	removeHandoff(cfg, func(m []string) bool { return m == nil || m[1] != id })
}

// deleteAllHandoff removes every drop file.
func deleteAllHandoff(cfg StackConfig) { removeHandoff(cfg, func([]string) bool { return true }) }

// sweepStaleHandoff deletes every drop file older than the maximum age and every junk name, unread.
func sweepStaleHandoff(cfg StackConfig) {
	entries, err := os.ReadDir(cfg.handoffPath())
	if err != nil {
		return
	}
	dirfd, err := unix.Open(cfg.handoffPath(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return
	}
	defer func() { _ = unix.Close(dirfd) }()
	for _, e := range entries {
		var st unix.Stat_t
		if err := unix.Fstatat(dirfd, e.Name(), &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			continue
		}
		age := cfg.now().Sub(time.Unix(st.Mtim.Sec, st.Mtim.Nsec))
		if handoffNameRE.MatchString(e.Name()) && age <= cfg.handoffMaxAge() {
			continue
		}
		if err := unlinkAt(dirfd, e.Name()); err != nil {
			cfg.logf("handoff: cannot remove a stale drop file: %v", err)
		}
	}
}

// readHandoff reads the listed kinds of request id from the drop directory with the ADR 0021 b file rules
// (O_NOFOLLOW, regular file, owner, size on the opened fd). Every other file in the directory is deleted unread
// first: another or a finished request's (replay), an unlisted kind, junk. A listed file that is missing or unsafe
// is deleted and the whole read fails, so the step fails and tagcess re-runs it.
func readHandoff(cfg StackConfig, id string, kinds []HandoffKind) (map[HandoffKind][]byte, error) {
	keep := map[HandoffKind]bool{}
	for _, k := range kinds {
		keep[k] = true
	}
	removeHandoff(cfg, func(m []string) bool { return m == nil || m[1] != id || !keep[HandoffKind(m[2])] })
	dirfd, err := unix.Open(cfg.handoffPath(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if len(kinds) == 0 {
			return nil, nil
		}
		return nil, errors.New("handoff directory unsafe")
	}
	defer func() { _ = unix.Close(dirfd) }()
	out := map[HandoffKind][]byte{}
	var failed bool
	for _, k := range kinds {
		name := id + "." + string(k)
		b, err := readSafe(dirfd, name, cfg.handoffUID(), MaxHandoffBytes)
		if err != nil {
			cfg.logf("handoff: kind %s is missing or unsafe", k)
			_ = unlinkAt(dirfd, name)
			failed = true
			continue
		}
		out[k] = b
	}
	if failed {
		return nil, errors.New("handoff failed")
	}
	return out, nil
}

// StackBoot is the `stack-boot` mode (service start): unfinished work is never resumed, it becomes interrupted;
// a request that was published but never accepted is consumed without running; every drop file is deleted
// (setup-flow.md §5.4).
func StackBoot(cfg StackConfig) (Outcome, error) {
	return stackLocked(cfg, func() (Outcome, error) {
		out, err := recoverStack(cfg)
		if err != nil {
			return out, err
		}
		stale, err := consumeStaleStackMarker(cfg)
		if err != nil {
			return out, err
		}
		if stale {
			out = OutcomeInterrupted
		}
		deleteAllHandoff(cfg)
		return out, nil
	})
}

// StackFinalize is the `stack-finalize` mode (ExecStopPost): a journal that is not terminal after the service
// ended becomes interrupted, and the request's drop files are deleted.
func StackFinalize(cfg StackConfig) (Outcome, error) {
	return stackLocked(cfg, func() (Outcome, error) {
		out, err := recoverStack(cfg)
		sweepStaleHandoff(cfg)
		return out, err
	})
}

// StackSweep is the `stack-sweep` mode (a timer): drop files older than the maximum age are deleted unread.
func StackSweep(cfg StackConfig) (Outcome, error) {
	return stackLocked(cfg, func() (Outcome, error) {
		sweepStaleHandoff(cfg)
		return OutcomeIdle, nil
	})
}

func recoverStack(cfg StackConfig) (Outcome, error) {
	priv := cfg.priv()
	j, found, err := readStackJournal(priv)
	switch {
	case errors.Is(err, ErrJournalCorrupt):
		cfg.logf("stack journal corrupt (%v): preserving it", err)
		if err := preserveCorruptFile(priv, stackJournalName, cfg.now()); err != nil {
			return OutcomeIdle, fmt.Errorf("preserve stack journal: %w", err)
		}
	case err != nil:
		return OutcomeIdle, err
	case found && j.State.Terminal():
		return OutcomeIdle, nil
	case found:
		cfg.logf("stack request %s was %s: interrupted", j.RequestID, j.State)
		var changed *bool
		if j.State == hostpatch.StateAccepted {
			changed = new(bool)
		}
		defer deleteHandoff(cfg, j.RequestID)
		return OutcomeInterrupted, interruptStack(cfg, j, StackInterrupted, changed)
	default:
		if _, err := os.Lstat(filepath.Join(priv, stackRequestName)); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return OutcomeIdle, nil
			}
			return OutcomeIdle, err
		}
		cfg.logf("stack journal lost, a request copy exists")
	}
	return OutcomeInterrupted, interruptStack(cfg, stackJournal{Version: StackVersion, RequestID: unknownID}, StackJournalCorrupt, nil)
}

func consumeStaleStackMarker(cfg StackConfig) (bool, error) {
	dirfd, err := unix.Open(filepath.Join(cfg.Root, requestsDir), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return false, fmt.Errorf("open requests dir: %w", err)
	}
	defer func() { _ = unix.Close(dirfd) }()
	mb, err := readSafe(dirfd, markerName, cfg.RequestUID, hostpatch.MaxMarkerBytes)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	var id string
	if err == nil {
		id, err = hostpatch.ParseMarker(mb)
	}
	if err != nil {
		cfg.logf("junk marker removed")
		return false, consume(Config{Logf: cfg.Logf}, dirfd, unknownID)
	}
	j, found, err := readStackJournal(cfg.priv())
	if err != nil {
		return false, err
	}
	if (found && j.RequestID == id) || readStackResultID(filepath.Join(cfg.Root, resultsDir)) == id {
		return false, consume(Config{Logf: cfg.Logf}, dirfd, id)
	}
	cfg.logf("stack request %s was published but never accepted: interrupted without running", id)
	if err := interruptStack(cfg, stackJournal{Version: StackVersion, RequestID: id}, StackInterrupted, new(bool)); err != nil {
		return false, err
	}
	return true, consume(Config{Logf: cfg.Logf}, dirfd, id)
}

// interruptStack publishes the interrupted result first, then makes the journal say the same.
func interruptStack(cfg StackConfig, j stackJournal, code StackCode, changed *bool) error {
	if err := writeStackResult(filepath.Join(cfg.Root, resultsDir), StackResult{
		Version: StackVersion, RequestID: j.RequestID, Op: j.Op, State: hostpatch.StateInterrupted, Phase: j.Phase,
		FinishedAt: cfg.now(), ErrorCode: code, Changed: changed,
	}); err != nil {
		return fmt.Errorf("publish result: %w", err)
	}
	j.State, j.ErrorCode = hostpatch.StateInterrupted, code
	if err := writeStackJournal(cfg.priv(), j); err != nil {
		return fmt.Errorf("write journal: %w", err)
	}
	return nil
}

// preserveCorruptFile renames a file that cannot be trusted to <name>.corrupt-<UTC time>.
func preserveCorruptFile(dir, name string, now time.Time) error {
	base := name + ".corrupt-" + now.UTC().Format("20060102T150405Z")
	target := base
	for i := 1; ; i++ {
		if _, err := os.Lstat(filepath.Join(dir, target)); errors.Is(err, os.ErrNotExist) {
			break
		}
		if i > 99 {
			return errors.New("too many preserved files")
		}
		target = fmt.Sprintf("%s-%d", base, i)
	}
	if err := os.Rename(filepath.Join(dir, name), filepath.Join(dir, target)); err != nil {
		return err
	}
	return syncDir(dir)
}
