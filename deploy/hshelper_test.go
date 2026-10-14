// AC1/AC2 of F3b-009: the systemd units and the install script for the Headscale host helper
// (ADR 0008, ADR 0021 b). These are static checks: they parse the committed artifacts and never
// start systemd. The live double-install and the .path trigger are F3b-010 (lab).
package deploy_test

import (
	"context"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

const (
	helperBinary = "/usr/local/bin/tagcess-hshelper"
	helperRoot   = "/var/lib/tagcess-headscale"
)

var helperUnits = []string{
	"tagcess-hshelper.path",
	"tagcess-hshelper.service",
	"tagcess-hshelper-boot.service",
}

// TestHelperUnits_Static is AC1: the units pin the ADR 0021 b trigger and the fixed flags, and they
// contain no Docker socket, no D-Bus and no path outside the fixed list.
func TestHelperUnits_Static(t *testing.T) {
	path := readHelper(t, "tagcess-hshelper.path")
	service := readHelper(t, "tagcess-hshelper.service")
	boot := readHelper(t, "tagcess-hshelper-boot.service")

	// The .path unit watches the marker only.
	for _, want := range []string{
		"PathExists=" + helperRoot + "/requests/request.ready",
		"Unit=tagcess-hshelper.service",
		"WantedBy=multi-user.target",
	} {
		if !strings.Contains(path, want) {
			t.Errorf("tagcess-hshelper.path: missing %q", want)
		}
	}

	// Both oneshot services are bounded the same way (ADR 0021 b, R2:25).
	for name, unit := range map[string]string{
		"tagcess-hshelper.service":      service,
		"tagcess-hshelper-boot.service": boot,
	} {
		for _, want := range []string{"Type=oneshot", "TimeoutStartSec=120", "KillMode=control-group"} {
			if !strings.Contains(unit, want) {
				t.Errorf("%s: missing %q", name, want)
			}
		}
	}

	if !strings.Contains(service, "ExecStart="+helperBinary+" run ") {
		t.Errorf("tagcess-hshelper.service: ExecStart is not `%s run …`", helperBinary)
	}
	if !strings.Contains(service, "ExecStopPost="+helperBinary+" finalize ") {
		t.Errorf("tagcess-hshelper.service: ExecStopPost is not `%s finalize …`", helperBinary)
	}
	if !strings.Contains(boot, "ExecStart="+helperBinary+" boot ") {
		t.Errorf("tagcess-hshelper-boot.service: ExecStart is not `%s boot …`", helperBinary)
	}
	for _, want := range []string{"WantedBy=multi-user.target", "Before=tagcess-hshelper.path"} {
		if !strings.Contains(boot, want) {
			t.Errorf("tagcess-hshelper-boot.service: missing %q", want)
		}
	}

	// Every command line carries the full fixed flag set; a request cannot add a flag or a path.
	fixedFlags := []string{
		"--config /etc/headscale/config.yaml",
		"--root " + helperRoot,
		"--unit headscale.service",
		"--service-user headscale",
		"--health http://127.0.0.1:8080/health",
		"--socket /var/run/headscale/headscale.sock",
		"--request-uid 10001",
	}
	execLines := helperExecLines(t, "tagcess-hshelper.service", "tagcess-hshelper-boot.service")
	if len(execLines) != 3 {
		t.Fatalf("want 3 Exec lines (service run + finalize, boot run), got %d: %v", len(execLines), execLines)
	}
	for _, line := range execLines {
		for _, flag := range fixedFlags {
			if !strings.Contains(line, flag) {
				t.Errorf("Exec line %q: missing fixed flag %q", line, flag)
			}
		}
	}

	// No Docker socket, no D-Bus, and no path outside the fixed list.
	allowedPath := regexp.MustCompile(`^(/usr/local/bin/tagcess-hshelper|/etc/headscale|/var/lib/tagcess-headscale|/var/run/headscale)(/|$)`)
	pathToken := regexp.MustCompile(`(?:^|[\s=])(/[A-Za-z0-9._/-]+)`)
	for _, unit := range helperUnits {
		content := readHelper(t, unit)
		for _, banned := range []string{"docker.sock", "docker", "dbus", "/var/run/docker"} {
			if strings.Contains(content, banned) {
				t.Errorf("%s: contains forbidden %q", unit, banned)
			}
		}
		for _, line := range strings.Split(content, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue
			}
			for _, m := range pathToken.FindAllStringSubmatch(line, -1) {
				if !allowedPath.MatchString(m[1]) {
					t.Errorf("%s: path %q is not in the fixed list", unit, m[1])
				}
			}
		}
	}
}

// TestInstallScript_Static is AC2: install.sh verifies the binary SHA-256, creates the ADR 0021 b
// directories, runs systemd-analyze verify and installs idempotently, without ever writing the
// Headscale config or touching the Headscale service.
func TestInstallScript_Static(t *testing.T) {
	const script = "hshelper/install.sh"
	if out, err := exec.CommandContext(context.Background(), "bash", "-n", script).CombinedOutput(); err != nil {
		t.Fatalf("bash -n %s: %v\n%s", script, err, out)
	}
	content := readHelper(t, "install.sh")

	for _, want := range []string{
		"sha256sum -c", // AC2: verify the given SHA-256 before installing
		"install -d",   // idempotent directory creation
		"systemd-analyze verify",
		"systemctl daemon-reload",
		"systemctl enable", // enable boot + .path
		"$REQUEST_UID",     // requests/ owner follows the request uid
	} {
		if !strings.Contains(content, want) {
			t.Errorf("install.sh: missing %q", want)
		}
	}

	// The three ADR 0021 b directories get their owner/mode on the same line.
	for _, d := range []struct {
		dir, mode string
	}{
		{"requests", "0700"},
		{"results", "0755"},
		{"private", "0700"},
	} {
		found := false
		for _, line := range strings.Split(content, "\n") {
			if strings.Contains(line, d.dir) && strings.Contains(line, d.mode) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("install.sh: no line creates %s with mode %s", d.dir, d.mode)
		}
	}

	// Idempotent: no bare `mkdir` (use `install -d`, which succeeds on a second run).
	if regexp.MustCompile(`(?m)^\s*mkdir\s`).MatchString(content) {
		t.Error("install.sh: uses mkdir; use `install -d` so a second run does not fail")
	}

	// Review fix: the --health guard is an anchored regex, not a wide `127.0.0.1:*` glob.
	if !strings.Contains(content, `^http://(127\.0\.0\.1|localhost):[0-9]+/health$`) {
		t.Error("install.sh: --health guard is not the anchored loopback /health regex")
	}

	// Review fix: the binary is copied to a private temp file and the SHA-256 is verified on that
	// copy, so the caller's path cannot change between the check and the install.
	if !strings.Contains(content, "mktemp") {
		t.Error("install.sh: binary SHA-256 is not verified on a private temp copy")
	}
	for _, line := range strings.Split(content, "\n") {
		if strings.Contains(line, "sha256sum -c") && strings.Contains(line, "$BINARY") {
			t.Errorf("install.sh: sha256 check reads the caller's path: %q", line)
		}
	}

	// Review fix: units are rendered to a temp dir, verified there, and installed only after
	// systemd-analyze verify has passed.
	verify := strings.Index(content, "systemd-analyze verify")
	installUnits := strings.Index(content, `install -m 0644 -o root -g root "$UNIT_TMP/`)
	if verify < 0 || installUnits < 0 || verify > installUnits {
		t.Error("install.sh: units are not verified before they are installed")
	}

	// It must not read or write the Headscale config, nor stop/start/restart the Headscale service.
	if strings.Contains(content, "/etc/headscale/config.yaml") {
		t.Error("install.sh must not touch /etc/headscale/config.yaml")
	}
	if regexp.MustCompile(`systemctl\s+(stop|start|restart|disable|enable)\s+headscale(\.service)?\b`).MatchString(content) {
		t.Error("install.sh must not stop/start/restart/disable the Headscale service")
	}
	if strings.Contains(content, "headscale configtest") {
		t.Error("install.sh must not run headscale configtest")
	}
}

// helperExecLines returns the Exec* lines of the given units, each trimmed.
func helperExecLines(t *testing.T, units ...string) []string {
	t.Helper()
	var out []string
	for _, unit := range units {
		for _, line := range strings.Split(readHelper(t, unit), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "Exec") {
				out = append(out, line)
			}
		}
	}
	return out
}

func readHelper(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("hshelper/" + name)
	if err != nil {
		t.Fatalf("read hshelper/%s: %v", name, err)
	}
	return string(b)
}
