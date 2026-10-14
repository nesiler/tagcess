package hshelper

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/nesiler/tagcess/internal/hostpatch"
)

// Boot is the `boot` mode (service start): work that was accepted or applying when the host or
// service went down is never resumed. It becomes interrupted, a request that was published but
// never journalled is consumed without running and gets an interrupted result (ADR 0021 c), and a
// journal that cannot be trusted is kept aside and replaced.
func Boot(cfg Config) (Outcome, error) {
	return locked(cfg, func() (Outcome, error) {
		out, err := recoverJournal(cfg)
		if err != nil {
			return out, err
		}
		stale, err := consumeStaleMarker(cfg)
		if err != nil {
			return out, err
		}
		if stale {
			out = OutcomeInterrupted
		}
		return out, nil
	})
}

// Finalize is the `finalize` mode (service ExecStopPost): if the service was killed mid-request the
// journal is not terminal, so it is turned into interrupted and published, and the container does
// not wait for a result that will never come. A terminal journal is left as it is.
func Finalize(cfg Config) (Outcome, error) {
	return locked(cfg, func() (Outcome, error) { return recoverJournal(cfg) })
}

// recoverJournal makes the journal sound: a non-terminal one becomes interrupted; a corrupt one is
// preserved and replaced, and so is a missing one when private/request.json shows a request was
// accepted. The ID of a lost journal is unknown, so its result carries the nil UUID.
func recoverJournal(cfg Config) (Outcome, error) {
	priv := filepath.Join(cfg.Root, privateDir)
	j, found, err := ReadJournal(priv)
	switch {
	case errors.Is(err, ErrJournalCorrupt):
		cfg.logf("journal corrupt (%v): preserving it", err)
		if err := preserveCorrupt(priv, cfg.now()); err != nil {
			return OutcomeIdle, fmt.Errorf("preserve journal: %w", err)
		}
	case err != nil:
		return OutcomeIdle, err
	case found && j.State.Terminal():
		return OutcomeIdle, nil
	case found:
		// Accepted: nothing was touched yet. Applying: the config may or may not have changed.
		var changed *bool
		if j.State == hostpatch.StateAccepted {
			changed = new(bool) // false: known unchanged
		}
		cfg.logf("request %s was %s: interrupted", j.RequestID, j.State)
		return OutcomeInterrupted, interrupt(cfg, j, hostpatch.CodeInterrupted, changed)
	default:
		if _, err := os.Lstat(filepath.Join(priv, copyName)); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return OutcomeIdle, nil // a fresh helper
			}
			return OutcomeIdle, err
		}
		cfg.logf("journal lost, a request copy exists")
	}
	j = Journal{Version: hostpatch.Version, RequestID: unknownID}
	return OutcomeInterrupted, interrupt(cfg, j, hostpatch.CodeJournalCorrupt, nil)
}

// consumeStaleMarker removes a pending marker (and its request file) without running it. A valid
// ID that has no answer yet gets an interrupted result and a journal that follows it; an ID the
// journal or result already knows keeps its result; a junk marker is only removed. It reports
// whether an interrupted result was written.
func consumeStaleMarker(cfg Config) (bool, error) {
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
		return false, consume(cfg, dirfd, unknownID)
	}

	j, found, err := ReadJournal(filepath.Join(cfg.Root, privateDir))
	if err != nil {
		return false, err
	}
	if (found && j.RequestID == id) || readResultID(filepath.Join(cfg.Root, resultsDir)) == id {
		cfg.logf("request %s ignored: same ID as the last journal/result", id)
		return false, consume(cfg, dirfd, id)
	}
	cfg.logf("request %s was published but never accepted: interrupted without running", id)
	if err := interrupt(cfg, Journal{Version: hostpatch.Version, RequestID: id}, hostpatch.CodeInterrupted, new(bool)); err != nil {
		return false, err
	}
	return true, consume(cfg, dirfd, id)
}

// interrupt publishes the interrupted result for j first, then makes the journal say the same, so a
// crash in between leaves a journal that is still non-terminal and is interrupted again.
// changed is nil when the helper cannot tell whether the live config changed.
func interrupt(cfg Config, j Journal, code hostpatch.ErrorCode, changed *bool) error {
	if err := WriteResult(filepath.Join(cfg.Root, resultsDir), hostpatch.Result{
		Version: hostpatch.Version, RequestID: j.RequestID, State: hostpatch.StateInterrupted, Phase: j.Phase,
		FinishedAt: cfg.now(), ErrorCode: code, ConfigChanged: changed,
	}); err != nil {
		return fmt.Errorf("publish result: %w", err)
	}
	j.State, j.ErrorCode = hostpatch.StateInterrupted, code
	if err := WriteJournal(filepath.Join(cfg.Root, privateDir), j); err != nil {
		return fmt.Errorf("write journal: %w", err)
	}
	return nil
}
