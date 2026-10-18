package discover

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"time"

	"golang.org/x/sys/unix"
)

const (
	cmdTimeout   = 20 * time.Second
	maxCmdOutput = 1 << 20
	maxFileBytes = 1 << 20
	maxGetBytes  = 4 << 20
)

// OSHost is the real host. Commands run with a fixed C locale and a time limit, output is capped.
type OSHost struct{}

// ReadFile opens without following a link or blocking (a FIFO would hang the root helper), then checks
// the opened fd: only a regular file of bounded size is read.
func (OSHost) ReadFile(p string) ([]byte, error) {
	fd, err := unix.Open(p, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "discover")
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, errors.New("not a regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err == nil && len(b) > maxFileBytes {
		return nil, errors.New("file too large")
	}
	return b, err
}

func (OSHost) ReadDir(p string) ([]string, error) {
	es, err := os.ReadDir(p)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(es))
	for _, e := range es {
		names = append(names, e.Name())
	}
	return names, nil
}

func (OSHost) Exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

type capWriter struct {
	buf bytes.Buffer
}

func (w *capWriter) Write(p []byte) (int, error) {
	if room := maxCmdOutput - w.buf.Len(); room > 0 {
		w.buf.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

func (OSHost) Run(name string, args ...string) (string, error) { return runCmd(name, args...) }

func (OSHost) RunAs(user, name string, args ...string) (string, error) {
	if _, err := exec.LookPath("runuser"); err != nil {
		return "", errors.New("runuser not installed")
	}
	return runCmd("runuser", append([]string{"-u", user, "--", name}, args...)...)
}

func runCmd(name string, args ...string) (string, error) {
	if _, err := exec.LookPath(name); err != nil {
		return "", fmt.Errorf("%s: not installed", name)
	}
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // fixed names and arguments from this package
	cmd.Env = []string{"LC_ALL=C", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	var w capWriter
	cmd.Stdout = &w // stderr is dropped: tools log warnings there that must not mix into parsed output
	err := cmd.Run()
	return w.buf.String(), err
}

// Get only talks to a loopback address, without redirects.
func (OSHost) Get(raw string) (int, []byte, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" {
		return 0, nil, errors.New("only plain http to loopback")
	}
	if ip := net.ParseIP(u.Hostname()); ip == nil || !ip.IsLoopback() {
		return 0, nil, errors.New("only plain http to loopback")
	}
	c := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Get(raw) //nolint:noctx // bounded by the client timeout
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxGetBytes))
	return resp.StatusCode, b, err
}

// Run scans the real host and returns the discovery.json document (the helper's `discover` operation).
func Run() ([]byte, error) { return Scan(OSHost{}) }
