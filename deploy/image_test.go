//go:build image

// AC1 image build check. `make image-test` builds deploy/Dockerfile from the repo root and proves the
// image runs as a non-root user and ships git. Needs Docker, so it is kept out of `make check`.
package deploy_test

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testImage = "tagcess:image-test"

func TestImage_NonRoot(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not available")
	}
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	// The GIDs are required build args (no silent defaults); use free Alpine GIDs for the test build.
	build := exec.CommandContext(ctx, "docker", "build", "-f", filepath.Join("deploy", "Dockerfile"),
		"--build-arg", "CADDY_GID=998", "--build-arg", "HEADSCALE_GID=992", "-t", testImage, root)
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("docker build: %v\n%s", err, out)
	}

	// Run the runtime shell instead of the tagcess entrypoint to inspect the configured user, its
	// groups and git.
	out, err := exec.CommandContext(ctx, "docker", "run", "--rm", "--entrypoint", "/bin/sh", testImage,
		"-c", "id -u; id -Gn; git --version").CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 3 {
		t.Fatalf("unexpected image output: %q", out)
	}
	if lines[0] == "0" {
		t.Errorf("image runs as root (uid 0); want a non-root user")
	}
	for _, group := range []string{"caddy", "headscale"} {
		if !strings.Contains(lines[1], group) {
			t.Errorf("user is not in the %s group (needed for ui.sock / headscale.sock): %q", group, lines[1])
		}
	}
	if !strings.Contains(lines[2], "git version") {
		t.Errorf("image has no git: %q", lines[2])
	}
}
