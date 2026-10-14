// Package hostlab is the Go fixture of the F3b-002 host lab (a privileged systemd container on OrbStack with
// Headscale v0.29.4 and the ADR 0021 b directories). Start returns a ready lab, setting it up with hostlab.sh
// when needed; the lab is persistent, so tests clean up only their own files and `make hostlab-down` (or Down)
// removes it. Lab only (ADR 0014): it never touches production and never talks to the lab Zitadel's cluster.
//
// The script reads HOSTLAB_HTTP_PORT, HOSTLAB_METRICS_PORT and HOSTLAB_GRPC_PORT from the environment; set them
// to free ports when the compose Headscale is running. Two test binaries must not start the lab at the same
// time (one container name), so run the packages that use it one after the other.
package hostlab

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/nesiler/tagcess/internal/headscale"
)

// RootInContainer is the host root of ADR 0021 b inside the lab container.
const RootInContainer = "/var/lib/tagcess-headscale"

// containerName is the fixed container name hostlab.sh uses.
const containerName = "tagcess-hostlab"

// Lab is a running host lab.
type Lab struct {
	Name     string // container name
	State    string // Mac directory holding requests/ and results/ (bind-mounted)
	HTTPAddr string // Headscale's HTTP listener, 127.0.0.1:<port>
	GRPCAddr string // Headscale's gRPC over the socat relay, 127.0.0.1:<port>

	client *headscale.Client
	api    v1.HeadscaleServiceClient
}

// Start returns the running lab, running `hostlab.sh up` first when there is none or it is not healthy.
// The returned lab stays up when the test ends. Failures are fatal (they mean OrbStack, the OIDC seed or the
// script is broken, not the code under test).
func Start(t testing.TB) *Lab {
	t.Helper()
	if lab, err := load(); err == nil {
		return lab.connect(t)
	}
	return Up(t)
}

// Up runs `hostlab.sh up` (always from scratch) and returns the new lab.
func Up(t testing.TB) *Lab {
	t.Helper()
	script(t, "up")
	lab, err := load()
	if err != nil {
		t.Fatalf("hostlab: lab is not usable after up: %v", err)
	}
	return lab.connect(t)
}

// Down runs `hostlab.sh down`: it removes the container and its temporary directory.
func Down(t testing.TB) {
	t.Helper()
	script(t, "down")
}

// RequestsDir is the Mac path of the bind-mounted requests/ directory.
func (l *Lab) RequestsDir() string { return filepath.Join(l.State, "requests") }

// ResultsDir is the Mac path of the bind-mounted results/ directory.
func (l *Lab) ResultsDir() string { return filepath.Join(l.State, "results") }

// Client is the narrow F1 Headscale client over the loopback relay.
func (l *Lab) Client() *headscale.Client { return l.client }

// Exec runs a command in the container as root and returns its combined output; a failure is fatal.
func (l *Lab) Exec(t testing.TB, args ...string) string {
	t.Helper()
	out, err := l.ExecErr(args...)
	if err != nil {
		t.Fatalf("hostlab: docker exec %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

// ExecErr is Exec for commands whose failure is an answer (test -e, mountpoint -q): it returns the error.
func (l *Lab) ExecErr(args ...string) (string, error) {
	var out bytes.Buffer
	cmd := exec.CommandContext(context.Background(), "docker", append([]string{"exec", l.Name}, args...)...) //nolint:gosec // lab-only test helper; args come from tests
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

func (l *Lab) connect(t testing.TB) *Lab {
	t.Helper()
	c, err := headscale.New(headscale.Config{Target: l.GRPCAddr, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("hostlab: headscale client for %s: %v", l.GRPCAddr, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	l.client = c
	// The v1 admin client over the same relay: the relay connects to Headscale's unix socket, the
	// unauthenticated admin surface the host tooling uses (the tests create users and nodes with it).
	conn, err := grpc.NewClient(l.GRPCAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("hostlab: raw grpc client for %s: %v", l.GRPCAddr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	l.api = v1.NewHeadscaleServiceClient(conn)
	return l
}

// load finds a running, healthy lab: the container's state label points at the Mac directory whose lab.env
// (written by hostlab.sh up) holds the addresses.
func load() (*Lab, error) {
	out, err := exec.CommandContext(context.Background(), "docker", "inspect", "-f", `{{.State.Running}} {{index .Config.Labels "tagcess.hostlab.state"}}`, containerName).Output()
	if err != nil {
		return nil, fmt.Errorf("no lab container: %w", err)
	}
	running, state, _ := strings.Cut(strings.TrimSpace(string(out)), " ")
	if running != "true" || state == "" {
		return nil, fmt.Errorf("lab container is not running")
	}
	env, err := os.ReadFile(filepath.Join(state, "lab.env")) //nolint:gosec // state is the lab container's own label
	if err != nil {
		return nil, fmt.Errorf("read lab.env: %w", err)
	}
	vals := map[string]string{}
	for _, line := range strings.Split(string(env), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			vals[k] = v
		}
	}
	lab := &Lab{Name: containerName, State: state, HTTPAddr: vals["HOSTLAB_HTTP_ADDR"], GRPCAddr: vals["HOSTLAB_GRPC_ADDR"]}
	if lab.HTTPAddr == "" || lab.GRPCAddr == "" {
		return nil, fmt.Errorf("lab.env has no addresses")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+lab.HTTPAddr+"/health", nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("lab /health: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("lab /health = %d", resp.StatusCode)
	}
	return lab, nil
}

func script(t testing.TB, verb string) {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	cmd := exec.CommandContext(context.Background(), filepath.Join(filepath.Dir(file), "hostlab.sh"), verb) //nolint:gosec // fixed script, verb from this package
	out, err := cmd.CombinedOutput()
	t.Logf("hostlab.sh %s:\n%s", verb, out)
	if err != nil {
		t.Fatalf("hostlab.sh %s failed: %v", verb, err)
	}
}
