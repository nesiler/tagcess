package hshelper

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
	"time"

	"github.com/nesiler/tagcess/internal/headscale"
)

const (
	defaultHeadscaleBin = "/usr/bin/headscale"
	defaultSystemctlBin = "/usr/bin/systemctl"
	// cleanPath is the whole environment configtest gets.
	cleanPath = "PATH=/usr/sbin:/usr/bin:/sbin:/bin"
	// readCallTimeout bounds the one gRPC read of the health check; the check's own deadline wins if shorter.
	readCallTimeout = 5 * time.Second
)

// errNoServiceUser means the identity configtest must run under could not be had. The step then
// fails; it never falls back to root (ADR 0021 b).
var errNoServiceUser = errors.New("service user identity unavailable")

// Runner is everything the apply flow does outside the helper's own files. The real one is
// SystemRunner; the unit tests use a fake. Errors carry no command output: the apply flow only
// ever turns them into an error code.
type Runner interface {
	// Configtest runs `headscale configtest -c configPath` as serviceUser, never as root.
	Configtest(ctx context.Context, serviceUser, configPath string) error
	// Restart restarts the unit and returns when systemd reports it done.
	Restart(ctx context.Context, unit string) error
	// Check passes only when the unit is active, the health endpoint answers 200 and a read-only
	// gRPC call works. It is not OIDC login proof (ADR 0021 c).
	Check(ctx context.Context, unit string) error
}

// SystemRunner runs the fixed host commands. Paths and the health address come from the helper's
// flags; nothing here is taken from a request.
type SystemRunner struct {
	// HealthURL is the fixed loopback /health address; Socket is Headscale's unix socket.
	HealthURL string
	Socket    string
	// HeadscaleBin and SystemctlBin default to the package paths.
	HeadscaleBin string
	SystemctlBin string

	lookup func(name string) (*user.User, error)
	exec   func(c *exec.Cmd) error
}

// NewSystemRunner returns the runner for the real host.
func NewSystemRunner(healthURL, socket string) *SystemRunner {
	return &SystemRunner{
		HealthURL: healthURL, Socket: socket,
		HeadscaleBin: defaultHeadscaleBin, SystemctlBin: defaultSystemctlBin,
		lookup: user.Lookup,
		exec:   func(c *exec.Cmd) error { return c.Run() },
	}
}

// serviceCredential resolves name to an identity with that user's uid and primary gid and no
// supplementary groups. An unknown user, a non-numeric id, or uid/gid 0 is errNoServiceUser.
func serviceCredential(name string, lookup func(string) (*user.User, error)) (*syscall.Credential, error) {
	if name == "" {
		return nil, errNoServiceUser
	}
	u, err := lookup(name)
	if err != nil || u == nil {
		return nil, errNoServiceUser
	}
	uid, uerr := strconv.ParseUint(u.Uid, 10, 32)
	gid, gerr := strconv.ParseUint(u.Gid, 10, 32)
	if uerr != nil || gerr != nil || uid == 0 || gid == 0 {
		return nil, errNoServiceUser
	}
	return &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}, nil
}

// Configtest implements Runner. Output is discarded: it can echo config content.
func (r *SystemRunner) Configtest(ctx context.Context, serviceUser, configPath string) error {
	cred, err := serviceCredential(serviceUser, r.lookup)
	if err != nil {
		return err
	}
	c := exec.CommandContext(ctx, r.HeadscaleBin, "configtest", "-c", configPath) //nolint:gosec // fixed binary; configPath is the helper's own temp file
	c.Env = []string{cleanPath}
	c.Dir = "/"
	c.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	c.WaitDelay = 2 * time.Second
	return r.exec(c)
}

func (r *SystemRunner) systemctl(ctx context.Context, args ...string) error {
	c := exec.CommandContext(ctx, r.SystemctlBin, args...) //nolint:gosec // fixed binary, unit from the helper's flag
	c.Env = []string{cleanPath}
	c.Dir = "/"
	c.WaitDelay = 2 * time.Second
	return r.exec(c)
}

// Restart implements Runner.
func (r *SystemRunner) Restart(ctx context.Context, unit string) error {
	return r.systemctl(ctx, "restart", unit)
}

// Check implements Runner.
func (r *SystemRunner) Check(ctx context.Context, unit string) error {
	if err := r.systemctl(ctx, "is-active", "--quiet", unit); err != nil {
		return errors.New("unit not active")
	}
	if err := httpHealth(ctx, r.HealthURL); err != nil {
		return err
	}
	c, err := headscale.New(headscale.Config{Target: r.Socket, Timeout: readCallTimeout})
	if err != nil {
		return errors.New("grpc target")
	}
	defer func() { _ = c.Close() }()
	if _, err := c.ListUsers(ctx); err != nil {
		return errors.New("grpc read failed")
	}
	return nil
}

func httpHealth(ctx context.Context, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return errors.New("health request")
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req) //nolint:gosec // fixed loopback URL from the helper's flag
	if err != nil {
		return errors.New("health unreachable")
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<10))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health status %d", resp.StatusCode)
	}
	return nil
}

// FileProjector is the real Projector: it reads the live config file and projects it.
type FileProjector struct{ path string }

// NewFileProjector returns the projector for the config at path.
func NewFileProjector(path string) *FileProjector { return &FileProjector{path: path} }

// Project implements Projector.
func (p *FileProjector) Project() ([]string, string, error) {
	src, _, err := readConfigFile(p.path)
	if err != nil {
		return nil, "", err
	}
	return Project(src)
}
