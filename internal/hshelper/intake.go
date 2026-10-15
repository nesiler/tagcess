package hshelper

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"

	"github.com/nesiler/tagcess/internal/hostpatch"
)

const (
	markerName  = "request.ready"
	copyName    = "request.json"
	unknownID   = "00000000-0000-0000-0000-000000000000"
	requestsDir = "requests"
	resultsDir  = "results"
	privateDir  = "private"
)

// Outcome is what one `run` did with the pending marker.
type Outcome string

const (
	OutcomeIdle      Outcome = "idle"      // no marker
	OutcomeAccepted  Outcome = "accepted"  // request copied, journal written, marker consumed
	OutcomeRejected  Outcome = "rejected"  // result.json published, marker consumed
	OutcomeDuplicate Outcome = "duplicate" // same ID as the last journal/result; marker consumed, nothing else touched
	OutcomeSucceeded Outcome = "succeeded" // accepted and applied: succeeded result published
	OutcomeFailed    Outcome = "failed"    // accepted but stopped: failed result published (no restore)

	OutcomeInterrupted Outcome = "interrupted" // boot/finalize turned unfinished or lost work into an interrupted result
)

// Config is the helper's fixed setup. Nothing in a request can change it.
type Config struct {
	// Root is the host root (/var/lib/tagcess-headscale): requests/, results/, private/.
	Root string
	// RequestUID is the uid the container's request files must belong to.
	RequestUID uint32
	// Now defaults to time.Now.
	Now func() time.Time
	// StackRoot is the stack channel's root (/var/lib/tagcess-host), or empty when there is none. A request is
	// refused while the stack journal is not terminal (setup-flow.md §5.3); both channels share this root's flock.
	StackRoot string
	// Projector reads the live config for status.json (NewFileProjector in production).
	Projector Projector

	// The apply flow (ADR 0021): the live Headscale config, its unit and the service user configtest
	// runs as. They come from flags, never from a request. A nil Runner makes Run stop after intake.
	ConfigPath  string
	Unit        string
	ServiceUser string
	Runner      Runner
	// Step timeouts and the health poll interval; zero means ADR 0008's 15 s / 45 s / 30 s and 1 s.
	ConfigtestTimeout time.Duration
	RestartTimeout    time.Duration
	HealthTimeout     time.Duration
	PollInterval      time.Duration

	// rename replaces the live config with the candidate (os.Rename); tests inject failures.
	rename func(oldpath, newpath string) error
	// Logf defaults to log.Printf. It only ever gets IDs and reasons, never file content.
	Logf func(format string, args ...any)
}

func (c Config) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func orDefault(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}

func (c Config) configtestTimeout() time.Duration {
	return orDefault(c.ConfigtestTimeout, defaultConfigtestTimeout)
}
func (c Config) restartTimeout() time.Duration {
	return orDefault(c.RestartTimeout, defaultRestartTimeout)
}
func (c Config) healthTimeout() time.Duration {
	return orDefault(c.HealthTimeout, defaultHealthTimeout)
}
func (c Config) pollInterval() time.Duration { return orDefault(c.PollInterval, defaultPollInterval) }

func (c Config) logf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
		return
	}
	log.Printf(format, args...)
}

// errUnsafe marks a file that failed the fd-level checks: not openable without following a link,
// not a regular file, wrong owner, or too large.
var errUnsafe = errors.New("unsafe file")

// readSafe opens dirfd/name without following links or blocking, checks the opened fd (regular
// file, owner uid, at most max bytes) and returns its content. A missing file is os.ErrNotExist;
// every other failure is errUnsafe. Nothing is read from a FIFO, directory or other special file.
func readSafe(dirfd int, name string, uid uint32, max int) ([]byte, error) {
	fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, os.ErrNotExist
	}
	if err != nil {
		return nil, errUnsafe
	}
	f := os.NewFile(uintptr(fd), name)
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, errUnsafe
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != uid || st.Size > int64(max) {
		return nil, errUnsafe
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil || len(b) > max {
		return nil, errUnsafe
	}
	return b, nil
}

// unlinkAt removes dirfd/name (a link is removed, never followed). An empty directory is removed
// too, so a junk marker cannot keep the .path unit firing.
func unlinkAt(dirfd int, name string) error {
	err := unix.Unlinkat(dirfd, name, 0)
	if errors.Is(err, unix.EISDIR) || errors.Is(err, unix.EPERM) {
		err = unix.Unlinkat(dirfd, name, unix.AT_REMOVEDIR)
	}
	if err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	return nil
}

// locked runs fn under the exclusive flock and then publishes status.json, so every mode ends the
// same way. A status failure is logged, not returned: the mode's own result stands.
func locked(cfg Config, fn func() (Outcome, error)) (Outcome, error) {
	lock, err := lockFile(filepath.Join(cfg.Root, privateDir))
	if err != nil {
		return OutcomeIdle, err
	}
	defer func() { _ = lock.Close() }()

	out, err := fn()
	if perr := PublishStatus(cfg); perr != nil {
		cfg.logf("status.json not published: %v", perr)
	}
	return out, err
}

// Run is the `run` mode (the .path trigger): under the flock it takes at most one pending request.
// A request is either accepted (copied to private/, journalled `accepted`, marker and request
// consumed), rejected with a result.json, or ignored as a duplicate. An accepted request is applied
// at once when cfg.Runner is set (apply.go); a failed apply is a published result, not an error.
// A journal that cannot be read stops the run with ErrJournalCorrupt and changes nothing.
func Run(cfg Config) (Outcome, error) {
	return locked(cfg, func() (Outcome, error) {
		out, err := intake(cfg)
		if err != nil || out != OutcomeAccepted || cfg.Runner == nil {
			return out, err
		}
		return apply(cfg)
	})
}

func intake(cfg Config) (Outcome, error) {
	priv := filepath.Join(cfg.Root, privateDir)
	results := filepath.Join(cfg.Root, resultsDir)
	dirfd, err := unix.Open(filepath.Join(cfg.Root, requestsDir), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return OutcomeIdle, fmt.Errorf("open requests dir: %w", err)
	}
	defer func() { _ = unix.Close(dirfd) }()

	// reject publishes the failure, then consumes the marker and the request file named by id.
	reject := func(id string, code hostpatch.ErrorCode, phase hostpatch.Phase, why string) (Outcome, error) {
		cfg.logf("request %s rejected: %s (%s)", id, code, why)
		unchanged := false
		if err := WriteResult(results, hostpatch.Result{
			Version: hostpatch.Version, RequestID: id, State: hostpatch.StateFailed, Phase: phase,
			FinishedAt: cfg.now(), ErrorCode: code, ConfigChanged: &unchanged,
		}); err != nil {
			return OutcomeIdle, fmt.Errorf("publish result: %w", err)
		}
		return OutcomeRejected, consume(cfg, dirfd, id)
	}

	mb, err := readSafe(dirfd, markerName, cfg.RequestUID, hostpatch.MaxMarkerBytes)
	if errors.Is(err, os.ErrNotExist) {
		return OutcomeIdle, nil
	}
	if err != nil {
		// No UUID can be trusted; the result carries the nil UUID so it matches no real request.
		return reject(unknownID, hostpatch.CodeInvalidRequest, hostpatch.PhaseValidate, "unsafe marker")
	}
	id, err := hostpatch.ParseMarker(mb)
	if err != nil {
		return reject(unknownID, hostpatch.CodeInvalidRequest, hostpatch.PhaseValidate, "bad marker")
	}

	j, found, err := ReadJournal(priv)
	if err != nil {
		return OutcomeIdle, err
	}
	if (found && j.RequestID == id) || readResultID(results) == id {
		cfg.logf("request %s ignored: same ID as the last journal/result", id)
		return OutcomeDuplicate, consume(cfg, dirfd, id)
	}
	if found && !j.State.Terminal() {
		return reject(id, hostpatch.CodeBusy, "", "journal not terminal")
	}

	if stackChannelBusy(cfg.StackRoot) {
		return reject(id, hostpatch.CodeBusy, "", "the stack channel has an unfinished operation")
	}

	rb, err := readSafe(dirfd, id+".json", cfg.RequestUID, hostpatch.MaxRequestBytes)
	if err != nil {
		return reject(id, hostpatch.CodeInvalidRequest, hostpatch.PhaseValidate, "unreadable or unsafe request file")
	}
	req, err := hostpatch.ParseRequest(rb)
	if err != nil {
		return reject(id, hostpatch.CodeInvalidRequest, hostpatch.PhaseValidate, err.Error())
	}
	if req.RequestID != id {
		return reject(id, hostpatch.CodeInvalidRequest, hostpatch.PhaseValidate, "request_id differs from the marker")
	}

	if err := atomicWrite(priv, copyName, rb, 0o600); err != nil {
		return OutcomeIdle, fmt.Errorf("copy request: %w", err)
	}
	if err := WriteJournal(priv, Journal{Version: hostpatch.Version, RequestID: id, State: hostpatch.StateAccepted}); err != nil {
		return OutcomeIdle, fmt.Errorf("write journal: %w", err)
	}
	cfg.logf("request %s accepted", id)
	return OutcomeAccepted, consume(cfg, dirfd, id)
}

// consume removes the marker, then the request file for id (not for the nil UUID). It runs only
// after the journal or result is durable; a failure leaves the marker and is returned.
func consume(cfg Config, dirfd int, id string) error {
	if err := unlinkAt(dirfd, markerName); err != nil {
		return fmt.Errorf("consume marker: %w", err)
	}
	if id == unknownID {
		return nil
	}
	if err := unlinkAt(dirfd, id+".json"); err != nil {
		cfg.logf("request %s: leaving request file: %v", id, err)
	}
	return nil
}
