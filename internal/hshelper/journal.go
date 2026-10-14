// Package hshelper is the Headscale host helper (ADR 0021 b/c). This part takes a request the
// container published, checks its files on the opened fd, keeps the single journal, and writes
// result.json. It runs as root on the host; everything the container writes is untrusted input.
package hshelper

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"

	"github.com/nesiler/tagcess/internal/hostpatch"
)

const (
	journalName = "journal.json"
	lockName    = "helper.lock"
	maxJournal  = 16 << 10
)

// ErrJournalCorrupt means private/journal.json exists but cannot be trusted. `run` stops and
// changes nothing; `boot` and `finalize` keep the file aside and start a new journal.
var ErrJournalCorrupt = errors.New("journal corrupt")

// Journal is the one record of the current or last request (ADR 0021 c). It holds IDs, states and
// hashes only: no raw config, no secrets. BackupRef is a host-side reference, not a path to read
// from outside.
type Journal struct {
	Version       int                 `json:"version"`
	RequestID     string              `json:"request_id"`
	State         hostpatch.State     `json:"state"`
	Phase         hostpatch.Phase     `json:"phase"`
	BaseHash      string              `json:"base_hash"`
	CandidateHash string              `json:"candidate_hash"`
	BackupRef     string              `json:"backup_ref"`
	ErrorCode     hostpatch.ErrorCode `json:"error_code"`
}

func (j Journal) validate() error {
	switch {
	case j.Version != hostpatch.Version:
		return errors.New("unsupported version")
	case !hostpatch.ValidRequestID(j.RequestID):
		return errors.New("bad request_id")
	case !j.State.Valid():
		return errors.New("unknown state")
	case j.Phase != "" && !j.Phase.Valid():
		return errors.New("unknown phase")
	case j.ErrorCode != "" && !j.ErrorCode.Valid():
		return errors.New("unknown error_code")
	}
	return nil
}

// ReadJournal reads privateDir/journal.json. A missing file is (zero, false, nil); anything that
// is not a valid journal is ErrJournalCorrupt.
func ReadJournal(privateDir string) (Journal, bool, error) {
	f, err := os.Open(filepath.Join(privateDir, journalName)) //nolint:gosec // root-owned private dir
	if errors.Is(err, os.ErrNotExist) {
		return Journal{}, false, nil
	}
	if err != nil {
		return Journal{}, false, fmt.Errorf("open journal: %w", err)
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxJournal+1))
	if err != nil {
		return Journal{}, false, fmt.Errorf("read journal: %w", err)
	}
	if len(b) > maxJournal {
		return Journal{}, false, fmt.Errorf("%w: too large", ErrJournalCorrupt)
	}
	var j Journal
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&j); err != nil {
		return Journal{}, false, fmt.Errorf("%w: not a journal document", ErrJournalCorrupt)
	}
	if _, err := dec.Token(); err != io.EOF {
		return Journal{}, false, fmt.Errorf("%w: data after the document", ErrJournalCorrupt)
	}
	if err := j.validate(); err != nil {
		return Journal{}, false, fmt.Errorf("%w: %w", ErrJournalCorrupt, err)
	}
	return j, true, nil
}

// WriteJournal validates j and replaces privateDir/journal.json atomically (0600, file and
// directory fsynced).
func WriteJournal(privateDir string, j Journal) error {
	if err := j.validate(); err != nil {
		return fmt.Errorf("journal: %w", err)
	}
	b, err := json.Marshal(j)
	if err != nil {
		return err
	}
	return atomicWrite(privateDir, journalName, b, 0o600)
}

// preserveCorrupt renames a journal that cannot be trusted to journal.json.corrupt-<UTC time> (a
// numeric suffix keeps an earlier copy from being replaced), so the evidence stays and a new
// journal can start.
func preserveCorrupt(privateDir string, now time.Time) error {
	base := journalName + ".corrupt-" + now.UTC().Format("20060102T150405Z")
	name := base
	for i := 1; ; i++ {
		if _, err := os.Lstat(filepath.Join(privateDir, name)); errors.Is(err, os.ErrNotExist) {
			break
		}
		if i > 99 {
			return errors.New("too many preserved journals")
		}
		name = fmt.Sprintf("%s-%d", base, i)
	}
	if err := os.Rename(filepath.Join(privateDir, journalName), filepath.Join(privateDir, name)); err != nil {
		return err
	}
	return syncDir(privateDir)
}

// atomicWrite replaces dir/name with data: temporary file, fsync, rename, directory fsync. A crash
// leaves either the old file or the new one, never a partial file under the final name.
func atomicWrite(dir, name string, data []byte, perm os.FileMode) error {
	tmp := filepath.Join(dir, "."+name+".tmp")
	if err := os.Remove(tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm) //nolint:gosec // fixed names in a root-owned dir
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Chmod(perm) // not subject to the umask
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, filepath.Join(dir, name))
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncDir(dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // root-owned dir
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

// fileLock is the exclusive flock on privateDir/helper.lock. The lock file is kept; only the
// descriptor is released.
type fileLock struct{ f *os.File }

// lockFile blocks until it holds the exclusive lock. The kernel drops it if the process dies.
func lockFile(privateDir string) (*fileLock, error) {
	fd, err := unix.Open(filepath.Join(privateDir, lockName), unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock: %w", err)
	}
	for {
		if err = unix.Flock(fd, unix.LOCK_EX); err != unix.EINTR {
			break
		}
	}
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("flock: %w", err)
	}
	return &fileLock{f: os.NewFile(uintptr(fd), lockName)}, nil
}

// Close releases the lock.
func (l *fileLock) Close() error { return l.f.Close() }
