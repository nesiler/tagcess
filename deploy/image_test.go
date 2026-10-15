//go:build image

// Image build checks (AC1, AC3). `make image-test` builds deploy/Dockerfile from the repo root
// and proves the image runs as a non-root user with git, and ships THIRD_PARTY_NOTICES. Needs
// Docker, so it is kept out of `make check`.
package deploy_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testImage = "tagcess:image-test"

// buildImage builds deploy/Dockerfile once (Docker layer caching makes a second call a hit) and
// returns the repo root and a context for the build and the runs. It skips without Docker.
func buildImage(t *testing.T) (string, context.Context) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not available")
	}
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	t.Cleanup(cancel)

	// The GIDs are required build args (no silent defaults); use free Alpine GIDs for the test build.
	build := exec.CommandContext(ctx, "docker", "build", "-f", filepath.Join("deploy", "Dockerfile"),
		"--build-arg", "CADDY_GID=998", "--build-arg", "HEADSCALE_GID=992", "-t", testImage, root)
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("docker build: %v\n%s", err, out)
	}
	return root, ctx
}

// runImage runs a shell command in the runtime image and returns its output.
func runImage(t *testing.T, ctx context.Context, script string) string {
	t.Helper()
	out, err := exec.CommandContext(ctx, "docker", "run", "--rm", "--entrypoint", "/bin/sh", testImage, "-c", script).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	return string(out)
}

func TestImage_NonRoot(t *testing.T) {
	_, ctx := buildImage(t)

	// Run the runtime shell instead of the tagcess entrypoint to inspect the configured user, its
	// groups and git.
	out := runImage(t, ctx, "id -u; id -Gn; git --version")
	lines := strings.Split(strings.TrimSpace(out), "\n")
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

// TestImage_ThirdPartyNotices is AC3: the image ships the notices, byte for byte.
func TestImage_ThirdPartyNotices(t *testing.T) {
	root, ctx := buildImage(t)

	want, err := os.ReadFile(filepath.Join(root, "THIRD_PARTY_NOTICES"))
	if err != nil {
		t.Fatal(err)
	}
	got := runImage(t, ctx, "cat /usr/share/doc/tagcess/THIRD_PARTY_NOTICES")
	if got != string(want) {
		t.Errorf("image THIRD_PARTY_NOTICES differs from the repo copy:\n%s", got)
	}
}
