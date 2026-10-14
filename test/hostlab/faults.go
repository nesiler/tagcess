// F3b-022: shared fixtures for driving the host lab from Go. The install/build helpers are the
// production install path (deploy/hshelper/install.sh) and the fault helpers inject the three ADR
// 0021 e.5 failures into the lab container only: a configtest error (the OIDC secret file is moved
// aside), a post-replace health error (an ExecStartPre=/bin/false drop-in on headscale.service) and
// a TimeoutStartSec overrun (a short helper timeout plus a delayed Headscale start). None of this
// touches production; every injection returns an idempotent restore.
package hostlab

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/hostpatch"
	"github.com/nesiler/tagcess/internal/hshelper"
)

// Paths inside the lab container. ConfigInLab is where hostlab.sh installs the Headscale config;
// CandidateInLab is the helper's candidate temp file, which must keep a .yaml suffix (F3b-010).
const (
	ConfigInLab    = "/etc/headscale/config.yaml"
	CandidateInLab = "/etc/headscale/.config.tagcess-new.yaml"
	HelperBinInLab = "/usr/local/bin/tagcess-hshelper"
	// OIDCSecretInLab is where hostlab.sh installs the lab OIDC client secret file. The name trips
	// gosec's hardcoded-credential check but is only a container path, never a secret value.
	OIDCSecretInLab = "/etc/headscale/oidc_client_secret" //nolint:gosec // G101: a path, not a credential
	// oidcSecretAside is where HideOIDCSecret parks the secret inside the container (root-only, not
	// on the bind mount and not a repo file); the secret never leaves the container.
	oidcSecretAside = "/root/.tagcess-oidc-secret.bak" //nolint:gosec // G101: a path, not a credential
)

// RepoRoot is the module root, two levels above test/hostlab.
func RepoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..")
}

// DockerCopy copies a file or directory into the lab container.
func DockerCopy(t testing.TB, src, dst string) {
	t.Helper()
	cmd := exec.CommandContext(context.Background(), "docker", "cp", src, dst) //nolint:gosec // G204: fixed subprocess; paths come from the lab fixture
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("docker cp %s %s: %v\n%s", src, dst, err, b)
	}
}

// BuildHelper cross-compiles cmd/tagcess-hshelper for the lab and returns its local path and SHA-256.
func BuildHelper(t testing.TB, lab *Lab) (string, string) {
	t.Helper()
	arch := ""
	switch got := strings.TrimSpace(lab.Exec(t, "uname", "-m")); got {
	case "aarch64", "arm64":
		arch = "arm64"
	case "x86_64", "amd64":
		arch = "amd64"
	default:
		t.Fatalf("unsupported lab architecture %q", got)
	}
	out := filepath.Join(t.TempDir(), "tagcess-hshelper")
	cmd := exec.CommandContext(context.Background(), "go", "build", "-o", out, "./cmd/tagcess-hshelper") //nolint:gosec // G204: fixed subprocess, fixed package
	cmd.Dir = RepoRoot()
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build helper: %v\n%s", err, b)
	}
	data, err := os.ReadFile(out) //nolint:gosec // G304: out is a path this function built under t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return out, hex.EncodeToString(sum[:])
}

// RunInstall copies the helper binary and deploy/hshelper into the lab and runs install.sh with the
// lab's two per-host values (request uid 0, the lab health address).
func RunInstall(t testing.TB, lab *Lab, bin, sum string) string {
	t.Helper()
	DockerCopy(t, bin, lab.Name+":/root/tagcess-hshelper")
	// A reused lab still holds the previous deploy/hshelper: `docker cp <dir> /opt/hshelper` into an
	// existing directory nests it (/opt/hshelper/hshelper), so remove the target first.
	_, _ = lab.ExecErr("rm", "-rf", "/opt/hshelper")
	DockerCopy(t, filepath.Join(RepoRoot(), "deploy", "hshelper"), lab.Name+":/opt/hshelper")
	out, err := lab.ExecErr("/bin/bash", "/opt/hshelper/install.sh",
		"--binary", "/root/tagcess-hshelper", "--sha256", sum,
		"--request-uid", "0", "--health", "http://"+lab.HTTPAddr+"/health")
	if err != nil {
		t.Fatalf("install.sh: %v\n%s", err, out)
	}
	return out
}

// Install builds and installs the helper (install.sh is idempotent) and republishes status.json.
func Install(t testing.TB, lab *Lab) {
	t.Helper()
	bin, sum := BuildHelper(t, lab)
	if out := RunInstall(t, lab, bin, sum); !strings.Contains(out, "installed the tagcess Headscale host helper") {
		t.Fatalf("install.sh output: %s", out)
	}
}

// ConfigBytes is the live Headscale config in the lab.
func ConfigBytes(t testing.TB, lab *Lab) []byte {
	t.Helper()
	return []byte(lab.Exec(t, "cat", ConfigInLab))
}

// WriteConfig replaces the live Headscale config with content, restarts Headscale and waits for it,
// then has the helper republish status.json. It is test setup (the tested path is the helper's own
// apply).
func WriteConfig(t testing.TB, lab *Lab, content []byte) {
	t.Helper()
	f, err := os.CreateTemp("", "tagcess-config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if _, err := f.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	DockerCopy(t, f.Name(), lab.Name+":"+ConfigInLab)
	lab.Exec(t, "chown", "root:root", ConfigInLab)
	lab.Exec(t, "chmod", "0644", ConfigInLab)
	_, _ = lab.ExecErr("systemctl", "reset-failed", "headscale.service")
	lab.Exec(t, "systemctl", "restart", "headscale.service")
	WaitHealth(t, lab)
	PublishStatus(t, lab)
}

// PublishStatus reruns the helper's boot unit so results/status.json projects the current config.
func PublishStatus(t testing.TB, lab *Lab) {
	t.Helper()
	lab.Exec(t, "systemctl", "restart", "tagcess-hshelper-boot.service")
}

// SetGroups writes allowed_groups into the live config through the same candidate helper used in
// production, then restarts Headscale and republishes status. It is test setup; it lets a scenario
// start from a known group list.
func SetGroups(t testing.TB, lab *Lab, groups []string) {
	t.Helper()
	cand, err := hshelper.Candidate(ConfigBytes(t, lab), groups)
	if err != nil {
		t.Fatalf("build a baseline candidate: %v", err)
	}
	WriteConfig(t, lab, cand)
}

// HealthCode is Headscale's /health status, or 0 when it cannot be reached.
func HealthCode(lab *Lab) int {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+lab.HTTPAddr+"/health", nil)
	if err != nil {
		return 0
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// WaitHealth waits until Headscale answers /health 200.
func WaitHealth(t testing.TB, lab *Lab) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if HealthCode(lab) == http.StatusOK {
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("headscale /health did not return 200 within 90s")
}

// Fault injection ------------------------------------------------------------------------------

// HideOIDCSecret moves the OIDC client secret aside so `headscale configtest` fails at validation
// while the running Headscale keeps its already-loaded config. It returns a restore that puts the
// secret back (idempotent).
func HideOIDCSecret(t testing.TB, lab *Lab) func() {
	t.Helper()
	lab.Exec(t, "mv", OIDCSecretInLab, oidcSecretAside)
	return func() {
		_, _ = lab.ExecErr("sh", "-c", "[ -e "+oidcSecretAside+" ] && mv "+oidcSecretAside+" "+OIDCSecretInLab)
	}
}

// AddDropIn writes a systemd drop-in for unit and reloads systemd.
func AddDropIn(t testing.TB, lab *Lab, unit, content string) {
	t.Helper()
	dir := "/etc/systemd/system/" + unit + ".d"
	lab.Exec(t, "mkdir", "-p", dir)
	f, err := os.CreateTemp("", "tagcess-dropin-*.conf")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	DockerCopy(t, f.Name(), lab.Name+":"+dir+"/zz-tagcess-fault.conf")
	lab.Exec(t, "chown", "root:root", dir+"/zz-tagcess-fault.conf")
	lab.Exec(t, "chmod", "0644", dir+"/zz-tagcess-fault.conf")
	lab.Exec(t, "systemctl", "daemon-reload")
}

// ClearDropIn removes this package's drop-in for unit and reloads systemd.
func ClearDropIn(t testing.TB, lab *Lab, unit string) {
	t.Helper()
	_, _ = lab.ExecErr("rm", "-f", "/etc/systemd/system/"+unit+".d/zz-tagcess-fault.conf")
	lab.Exec(t, "systemctl", "daemon-reload")
}

// FaultHealth makes a post-replace restart fail: configtest still passes (it runs the Headscale
// binary directly), but ExecStartPre=/bin/false stops the service from coming back.
func FaultHealth(t testing.TB, lab *Lab) func() {
	t.Helper()
	AddDropIn(t, lab, "headscale.service", "[Service]\nExecStartPre=/bin/false\n")
	return func() {
		ClearDropIn(t, lab, "headscale.service")
		_, _ = lab.ExecErr("systemctl", "reset-failed", "headscale.service")
	}
}

// FaultTimeout lowers the helper's TimeoutStartSec to 20s and delays Headscale's start by 30s, so
// systemd kills the helper mid-restart; ExecStopPost finalize publishes interrupted. configtest
// still passes.
func FaultTimeout(t testing.TB, lab *Lab) func() {
	t.Helper()
	AddDropIn(t, lab, "tagcess-hshelper.service", "[Service]\nTimeoutStartSec=20\n")
	AddDropIn(t, lab, "headscale.service", "[Service]\nExecStartPre=/bin/sleep 30\n")
	return func() {
		ClearDropIn(t, lab, "tagcess-hshelper.service")
		ClearDropIn(t, lab, "headscale.service")
		_, _ = lab.ExecErr("systemctl", "reset-failed", "headscale.service")
	}
}

// FaultRestartDelay slows Headscale's start by d (ExecStartPre=/bin/sleep), so an apply's restart
// step keeps the maintenance open for the duration of the test's widening and narrowing writes. d
// must stay below the helper's 45s restart timeout (ADR 0008). It returns an idempotent restore.
func FaultRestartDelay(t testing.TB, lab *Lab, d time.Duration) func() {
	t.Helper()
	AddDropIn(t, lab, "headscale.service", fmt.Sprintf("[Service]\nExecStartPre=/bin/sleep %d\n", int(d.Seconds())))
	return func() {
		ClearDropIn(t, lab, "headscale.service")
		_, _ = lab.ExecErr("systemctl", "reset-failed", "headscale.service")
	}
}

// FaultHelperDelay slows the helper oneshot by d (ExecStartPre=/bin/sleep on its unit), so an apply
// stays in the maintenance for the whole test while Headscale keeps answering reads: the widening
// and narrowing scenarios need a readable Headscale to reach the gate (a Headscale restart delay
// would stop it and the writers would fail at the read instead). d stays below TimeoutStartSec=120.
func FaultHelperDelay(t testing.TB, lab *Lab, d time.Duration) func() {
	t.Helper()
	AddDropIn(t, lab, "tagcess-hshelper.service", fmt.Sprintf("[Service]\nExecStartPre=/bin/sleep %d\n", int(d.Seconds())))
	return func() {
		ClearDropIn(t, lab, "tagcess-hshelper.service")
		_, _ = lab.ExecErr("systemctl", "reset-failed", "tagcess-hshelper.service")
	}
}

// ReadStatus reads results/status.json, ok=false while it is absent or invalid.
func ReadStatus(lab *Lab) (hostpatch.Status, bool) {
	b, err := os.ReadFile(filepath.Join(lab.ResultsDir(), "status.json"))
	if err != nil {
		return hostpatch.Status{}, false
	}
	s, err := hostpatch.DecodeStatus(b)
	if err != nil {
		return hostpatch.Status{}, false
	}
	return s, true
}

// WaitStatus waits until status.json projects the wanted base_rev with no config error.
func WaitStatus(t testing.TB, lab *Lab, rev string) hostpatch.Status {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if s, ok := ReadStatus(lab); ok && s.BaseRev == rev && s.ConfigError == "" {
			return s
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("status.json did not show base_rev %s within 30s", rev)
	return hostpatch.Status{}
}

// ClearDir removes everything inside dir (the lab keeps the directory itself).
func ClearDir(t testing.TB, dir string) {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			t.Fatal(err)
		}
	}
}
