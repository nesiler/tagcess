package hshelper

import (
	"context"
	"os/exec"
	"time"

	"github.com/nesiler/tagcess/internal/stack"
)

const (
	defaultDockerBin  = "/usr/bin/docker"
	composeProject    = "tagcess"
	defaultValidate   = 30 * time.Second
	defaultDockerStep = 10 * time.Minute
)

// Docker is everything the stack channel does through `docker compose`. The real one is SystemDocker; the tests
// use a fake. Errors carry no command output: output can echo configuration.
type Docker interface {
	// ConfigQuiet runs `docker compose config --quiet` on a candidate compose file.
	ConfigQuiet(ctx context.Context, composeFile string) error
	// Pull pulls the image of one service.
	Pull(ctx context.Context, composeFile string, c stack.Component) error
	// Up starts (or recreates) one service and waits until it is running or healthy.
	Up(ctx context.Context, composeFile string, c stack.Component) error
	// Remove stops and removes one service container; its data stays.
	Remove(ctx context.Context, composeFile string, c stack.Component) error
	// Restart restarts one service.
	Restart(ctx context.Context, composeFile string, c stack.Component) error
}

// SystemDocker runs the fixed docker binary. Service names come from the closed component list, the compose file
// path from the helper's own layout; nothing is taken from a request.
type SystemDocker struct {
	Bin string
}

// NewSystemDocker returns the runner for the real host.
func NewSystemDocker() *SystemDocker { return &SystemDocker{Bin: defaultDockerBin} }

func (d *SystemDocker) compose(ctx context.Context, file string, args ...string) error {
	full := append([]string{"compose", "-p", composeProject, "-f", file}, args...)
	c := exec.CommandContext(ctx, d.Bin, full...) //nolint:gosec // fixed binary; file and service come from the helper
	c.Env = []string{cleanPath}
	c.Dir = "/"
	c.WaitDelay = 2 * time.Second
	return c.Run()
}

// ConfigQuiet implements Docker.
func (d *SystemDocker) ConfigQuiet(ctx context.Context, file string) error {
	return d.compose(ctx, file, "config", "--quiet")
}

// Pull implements Docker.
func (d *SystemDocker) Pull(ctx context.Context, file string, c stack.Component) error {
	return d.compose(ctx, file, "pull", string(c))
}

// Up implements Docker.
func (d *SystemDocker) Up(ctx context.Context, file string, c stack.Component) error {
	return d.compose(ctx, file, "up", "-d", "--wait", "--no-deps", string(c))
}

// Remove implements Docker.
func (d *SystemDocker) Remove(ctx context.Context, file string, c stack.Component) error {
	return d.compose(ctx, file, "rm", "--stop", "--force", string(c))
}

// Restart implements Docker.
func (d *SystemDocker) Restart(ctx context.Context, file string, c stack.Component) error {
	return d.compose(ctx, file, "restart", string(c))
}
