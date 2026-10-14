//go:build integration

// Integration tests of the F3b-002 host lab and the F3b-003 fixture (OrbStack + lab Zitadel as the OIDC issuer).
// Run them with `go test -tags=integration -count=1 -v ./test/hostlab/...`. If the compose Headscale is up, set
// HOSTLAB_HTTP_PORT, HOSTLAB_METRICS_PORT and HOSTLAB_GRPC_PORT to free ports first (same ports otherwise).
// The lab is persistent: the tests clean up only their own files; `make hostlab-down` removes the lab.
package hostlab_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nesiler/tagcess/test/hostlab"
	"github.com/nesiler/tagcess/test/labenv"
)

// TestHostLab_Up is AC1: `hostlab.sh up` (make hostlab-up) leaves headscale.service active, v0.29.4 and /health 200.
func TestHostLab_Up(t *testing.T) {
	lab := hostlab.Up(t)

	if got := strings.TrimSpace(lab.Exec(t, "systemctl", "is-active", "headscale.service")); got != "active" {
		t.Errorf("headscale.service is %q, want active", got)
	}
	if got := lab.Exec(t, "headscale", "version"); !strings.HasPrefix(got, "headscale version v0.29.4\n") {
		t.Errorf("headscale version output = %q, want it to start with %q", got, "headscale version v0.29.4")
	}
	status := httpGet(t, "http://"+lab.HTTPAddr+"/health")
	if status != http.StatusOK {
		t.Errorf("/health = %d, want 200", status)
	}
}

// TestHostLab_Layout is AC2: the ADR 0021 b directories exist, private is root 0700 and container-only,
// requests/ and results/ are shared with the Mac in both directions.
func TestHostLab_Layout(t *testing.T) {
	lab := hostlab.Start(t)
	root := hostlab.RootInContainer

	if got := strings.TrimSpace(lab.Exec(t, "stat", "-c", "%a %U", root+"/private")); got != "700 root" {
		t.Errorf("%s/private is %q, want %q", root, got, "700 root")
	}
	for _, d := range []string{"requests", "results"} {
		if _, err := lab.ExecErr("mountpoint", "-q", root+"/"+d); err != nil {
			t.Errorf("%s/%s is not a bind mount: %v", root, d, err)
		}
		if st, err := os.Stat(filepath.Join(lab.State, d)); err != nil || !st.IsDir() {
			t.Errorf("%s is not a directory on the Mac: %v", d, err)
		}
	}
	if _, err := lab.ExecErr("mountpoint", "-q", root+"/private"); err == nil {
		t.Errorf("%s/private must not be a mount", root)
	}
	if _, err := os.Stat(filepath.Join(lab.State, "private")); err == nil {
		t.Error("private/ is visible on the Mac")
	}

	// Mac -> container (requests/) and container -> Mac (results/).
	name := fmt.Sprintf(".layout-%d", time.Now().UnixNano())
	macFile := filepath.Join(lab.RequestsDir(), name)
	if err := os.WriteFile(macFile, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(macFile) })
	waitFor(t, 10*time.Second, "requests/"+name+" visible in the container", func() bool {
		_, err := lab.ExecErr("test", "-e", root+"/requests/"+name)
		return err == nil
	})
	labFile := root + "/results/" + name
	lab.Exec(t, "touch", labFile)
	t.Cleanup(func() { _, _ = lab.ExecErr("rm", "-f", labFile) })
	waitFor(t, 10*time.Second, "results/"+name+" visible on the Mac", func() bool {
		_, err := os.Stat(filepath.Join(lab.ResultsDir(), name))
		return err == nil
	})
}

// TestHostLab_FixtureGRPC is AC3: Start returns the loopback gRPC address, the Mac paths of requests/ and
// results/ and a command helper; ListUsers works over the relay.
func TestHostLab_FixtureGRPC(t *testing.T) {
	lab := hostlab.Start(t)

	if !strings.HasPrefix(lab.GRPCAddr, "127.0.0.1:") {
		t.Errorf("GRPCAddr = %q, want a loopback address", lab.GRPCAddr)
	}
	for _, d := range []string{lab.RequestsDir(), lab.ResultsDir()} {
		if st, err := os.Stat(d); err != nil || !st.IsDir() {
			t.Errorf("%s is not a directory: %v", d, err)
		}
	}
	if got := strings.TrimSpace(lab.Exec(t, "echo", "hello")); got != "hello" {
		t.Errorf("Exec echo = %q, want hello", got)
	}
	if _, err := lab.ExecErr("false"); err == nil {
		t.Error("ExecErr of a failing command returned no error")
	}
	if _, err := lab.Client().ListUsers(context.Background()); err != nil {
		t.Errorf("ListUsers over the relay: %v", err)
	}
}

// TestHostLab_Down is AC4: `hostlab.sh down` removes the container and the temporary directory, and does
// not touch the lab Zitadel (it stays reachable as the OIDC issuer). A later Start brings the lab back.
func TestHostLab_Down(t *testing.T) {
	lab := hostlab.Start(t)
	name, state := lab.Name, lab.State

	hostlab.Down(t)

	out, err := exec.CommandContext(context.Background(), "docker", "ps", "-a", "--format", "{{.Names}}", "--filter", "name=^"+name+"$").Output()
	if err != nil {
		t.Fatalf("docker ps: %v", err)
	}
	if strings.TrimSpace(string(out)) != "" {
		t.Errorf("container %s still exists after down: %s", name, out)
	}
	if _, err := os.Stat(state); err == nil {
		t.Errorf("temporary directory %s still exists after down", state)
	}
	// The lab Zitadel is only an issuer here; down must leave it as it was.
	status := httpGet(t, labenv.ZitadelIssuer()+"/.well-known/openid-configuration")
	if status != http.StatusOK {
		t.Errorf("lab Zitadel discovery = %d after down, want 200", status)
	}
}

// TestHostLab_PathTriggerOnBindMount is AC5/AC6: a file written on the Mac into the bind-mounted requests/
// must trigger a trial .path unit (PathExists) inside the container, both written in place and published by
// atomic rename (the ADR 0021 b protocol). If it does not, this test fails on purpose: no lab-only fallback
// exists; the finding goes to stack-notes and to the developer (R2:29 d). The uid/gid/mode the container
// sees for a Mac-written file is logged for stack-notes (AC6).
func TestHostLab_PathTriggerOnBindMount(t *testing.T) {
	lab := hostlab.Start(t)
	for _, tc := range []struct {
		name  string
		write func(path string) error
	}{
		{"write", func(path string) error { return os.WriteFile(path, []byte("x"), 0o640) }},
		{"rename", func(path string) error {
			tmp := path + ".tmp"
			if err := os.WriteFile(tmp, []byte("x"), 0o640); err != nil {
				return err
			}
			return os.Rename(tmp, path)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) { probePathTrigger(t, lab, tc.write) })
	}
}

func probePathTrigger(t *testing.T, lab *hostlab.Lab, write func(path string) error) {
	root := hostlab.RootInContainer
	id := fmt.Sprintf("%d", time.Now().UnixNano())
	marker := "probe-" + id
	unit := "tagcess-pathprobe-" + id
	fired := "/tmp/" + unit + ".fired"
	macFile := filepath.Join(lab.RequestsDir(), marker)
	// Register the cleanup before creating the unit: if the create command fails, the trial unit and
	// its file must not be left behind (F3b-027 AC7).
	t.Cleanup(func() {
		_ = os.Remove(macFile)
		_, _ = lab.ExecErr("sh", "-c", fmt.Sprintf("systemctl stop %[1]s.path %[1]s.service; rm -f /etc/systemd/system/%[1]s.* %[2]s; systemctl daemon-reload", unit, fired))
	})

	lab.Exec(t, "sh", "-c", fmt.Sprintf(`cat >/etc/systemd/system/%[1]s.path <<'UNIT'
[Path]
PathExists=%[2]s/requests/%[3]s
UNIT
cat >/etc/systemd/system/%[1]s.service <<'UNIT'
[Service]
Type=oneshot
ExecStart=/bin/touch %[4]s
UNIT
systemctl daemon-reload && systemctl start %[1]s.path`, unit, root, marker, fired))
	// A .path unit is "active" while it waits; its sub-state says whether it already triggered.
	if got := strings.TrimSpace(lab.Exec(t, "systemctl", "show", "-p", "SubState", "--value", unit+".path")); got != "waiting" {
		t.Fatalf("trial .path unit SubState is %q before the write, want waiting", got)
	}

	if err := write(macFile); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	triggered := false
	for time.Since(start) < 15*time.Second {
		if _, err := lab.ExecErr("test", "-e", fired); err == nil {
			triggered = true
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	elapsed := time.Since(start)

	// AC6: what the container sees for a file the Mac wrote (uid:gid mode).
	seen := strings.TrimSpace(lab.Exec(t, "stat", "-c", "%u:%g %a", root+"/requests/"+marker))
	if st, err := os.Stat(macFile); err == nil {
		sys := st.Sys().(*syscall.Stat_t)
		t.Logf("MEASURED bind mount: Mac wrote %s as uid:gid %d:%d mode %o; the container sees uid:gid mode %q",
			marker, sys.Uid, sys.Gid, st.Mode().Perm(), seen)
	}
	if !triggered {
		t.Fatal("PathExists did NOT fire within 15s for a file written on the Mac into the bind-mounted requests/ (OrbStack inotify gap); " +
			"no lab fallback exists: record this in stack-notes and ask the developer (task F3b-003, R2:29 d)")
	}
	t.Logf("MEASURED: PathExists fired %s after the Mac write", elapsed.Round(10*time.Millisecond))
}

// httpGet returns the status code of a GET (the body is drained and closed).
func httpGet(t *testing.T, url string) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

func waitFor(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Errorf("timed out after %s waiting for %s", d, what)
}
