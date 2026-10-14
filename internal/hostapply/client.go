// Package hostapply is the container side of the Headscale host helper channel (ADR 0021 b, H-07).
// It publishes a patch request into the shared requests directory and reads the helper's
// result.json and status.json from the read-only results directory. It knows no other host path.
//
// Reads never invent state: a missing, oversize, malformed or symlinked file is an error, and a
// result for another request ID is "no result", never success.
package hostapply

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/nesiler/tagcess/internal/hostpatch"
)

const (
	markerName = "request.ready"
	resultName = "result.json"
	statusName = "status.json"
)

var (
	// ErrBusy means request.ready exists: a request is already pending, so none is written.
	ErrBusy = errors.New("hostapply: a request is already pending")
	// ErrNoResult means result.json is absent or belongs to another request ID.
	ErrNoResult = errors.New("hostapply: no result for this request")
)

// Client reads and writes the two shared directories.
type Client struct {
	requestsDir, resultsDir string

	// Test hooks: after a temp file is synced, after it is renamed into place, and the directory sync.
	afterTemp   func(name string)
	afterRename func(name string)
	syncDir     func(dir string) error // replaces the directory fsync
}

// New returns a Client for the given absolute directories.
func New(requestsDir, resultsDir string) (*Client, error) {
	for _, d := range []string{requestsDir, resultsDir} {
		if !filepath.IsAbs(d) || filepath.Clean(d) != d {
			return nil, fmt.Errorf("hostapply: %q is not a clean absolute path", d)
		}
	}
	return &Client{requestsDir: requestsDir, resultsDir: resultsDir}, nil
}

// Publish validates doc (the bytes hostpatch.BuildRequest produced) and publishes it: first
// requests/<UUID>.json, then requests/request.ready holding the UUID, each by temp file, fsync and
// rename. If a marker already exists it returns ErrBusy and writes nothing. tagcess is the only
// writer and the maintenance flag serialises requests, so the check and the rename need no lock.
func (c *Client) Publish(doc []byte) error {
	req, err := hostpatch.ParseRequest(doc)
	if err != nil {
		return err
	}
	marker := filepath.Join(c.requestsDir, markerName)
	if _, err := os.Lstat(marker); err == nil {
		return ErrBusy
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("hostapply: check marker: %w", err)
	}
	mark, err := hostpatch.FormatMarker(req.RequestID)
	if err != nil {
		return err
	}
	reqPath := filepath.Join(c.requestsDir, req.RequestID+".json")
	if _, err := c.writeAtomic(req.RequestID+".json", doc); err != nil {
		// Whether or not the rename happened, no marker points to this file yet.
		_ = os.Remove(reqPath)
		return err
	}
	renamed, err := c.writeAtomic(markerName, mark)
	if err != nil && !renamed {
		// Best effort: do not leave an orphan request that no marker points to.
		_ = os.Remove(reqPath)
		return err
	}
	// Once the marker is renamed the request is published and the helper may already be reading
	// <UUID>.json, so it is never removed. A directory sync failure after that rename only means the
	// publish may not survive a crash; it is treated as published and the caller learns the outcome
	// from Result and Status.
	return nil
}

// writeAtomic writes data to requestsDir/name via a dot-prefixed temp file in the same directory.
// renamed reports whether the final rename succeeded: an error with renamed false means nothing was
// published; an error with renamed true is a failed directory sync after the file was published.
func (c *Client) writeAtomic(name string, data []byte) (renamed bool, err error) {
	f, err := os.CreateTemp(c.requestsDir, "."+name+".tmp-*")
	if err != nil {
		return false, fmt.Errorf("hostapply: %w", err)
	}
	tmp := f.Name()
	defer func() {
		if err != nil && !renamed {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if _, err = f.Write(data); err != nil {
		return false, fmt.Errorf("hostapply: write %s: %w", name, err)
	}
	if err = f.Sync(); err != nil {
		return false, fmt.Errorf("hostapply: sync %s: %w", name, err)
	}
	if err = f.Close(); err != nil {
		return false, fmt.Errorf("hostapply: close %s: %w", name, err)
	}
	if c.afterTemp != nil {
		c.afterTemp(filepath.Base(tmp))
	}
	if err = os.Rename(tmp, filepath.Join(c.requestsDir, name)); err != nil {
		return false, fmt.Errorf("hostapply: publish %s: %w", name, err)
	}
	if c.afterRename != nil {
		c.afterRename(name)
	}
	// Make the rename itself durable; the file is already published, so a failure here is reported but not undone.
	if serr := c.syncRequestsDir(); serr != nil {
		return true, fmt.Errorf("hostapply: sync directory: %w", serr)
	}
	return true, nil
}

func (c *Client) syncRequestsDir() error {
	if c.syncDir != nil {
		return c.syncDir(c.requestsDir)
	}
	d, err := os.Open(c.requestsDir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

// Result returns the helper's result for requestID. A missing result.json or one for another ID is
// ErrNoResult; an unreadable, oversize, symlinked or invalid file is a different error. None of
// them is ever a success.
func (c *Client) Result(requestID string) (hostpatch.Result, error) {
	if !hostpatch.ValidRequestID(requestID) {
		return hostpatch.Result{}, fmt.Errorf("%w: bad request_id", hostpatch.ErrInvalidRequest)
	}
	b, err := readSmallFile(filepath.Join(c.resultsDir, resultName))
	if errors.Is(err, os.ErrNotExist) {
		return hostpatch.Result{}, ErrNoResult
	}
	if err != nil {
		return hostpatch.Result{}, err
	}
	r, err := hostpatch.DecodeResult(b)
	if err != nil {
		return hostpatch.Result{}, err
	}
	if r.RequestID != requestID {
		return hostpatch.Result{}, ErrNoResult
	}
	return r, nil
}

// Status returns the helper's secret-free status snapshot. Any failure to read or validate it is an
// error: the caller must not start a new patch without it (ADR 0021 b). A status with ConfigError
// set is valid but carries no groups or base_rev: the helper could not read the live config.
func (c *Client) Status() (hostpatch.Status, error) {
	b, err := readSmallFile(filepath.Join(c.resultsDir, statusName))
	if err != nil {
		return hostpatch.Status{}, err
	}
	return hostpatch.DecodeStatus(b)
}

// readSmallFile reads a regular file of at most MaxResultBytes without following a symlink. The
// type and size checks run on the opened descriptor, not on the path.
func readSmallFile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) // #nosec G304 -- fixed file name inside the configured results directory
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("hostapply: %s is a symlink", filepath.Base(path))
		}
		return nil, fmt.Errorf("hostapply: %w", err)
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("hostapply: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("hostapply: %s is not a regular file", filepath.Base(path))
	}
	b, err := io.ReadAll(io.LimitReader(f, hostpatch.MaxResultBytes+1))
	if err != nil {
		return nil, fmt.Errorf("hostapply: %w", err)
	}
	if len(b) > hostpatch.MaxResultBytes {
		return nil, fmt.Errorf("hostapply: %s is larger than %d bytes", filepath.Base(path), hostpatch.MaxResultBytes)
	}
	return b, nil
}
