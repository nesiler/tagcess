//go:build integration

// Integration smoke tests of the F3b host helper (cmd/tagcess-hshelper, deploy/hshelper) against the
// real systemd + Headscale v0.29.4 host lab (F3b-002/003). They cross-compile the helper for the lab
// container, install it with deploy/hshelper/install.sh (the production install path), and drive the
// .path trigger over the bind-mounted requests/results directories. This completes the F3b-006/007/008
// unit tests; findings belong to those tasks. The lab is persistent: the tests clean up their own
// files and AC2 restores the lab's starting config. Run with:
//
//	go test -tags=integration -count=1 -v ./test/hostlab/
//
// If the compose Headscale is running, set HOSTLAB_HTTP_PORT, HOSTLAB_METRICS_PORT and HOSTLAB_GRPC_PORT
// to free ports first (hostlab.sh up reads them).
package hostlab_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/hostpatch"
	"github.com/nesiler/tagcess/internal/hshelper"
	"github.com/nesiler/tagcess/test/hostlab"
)

// nilID is the all-zero UUID the helper publishes when the marker itself is untrusted (F3b-006).
const nilID = "00000000-0000-0000-0000-000000000000"

// TestHostLab_InstallIdempotent is AC1: install.sh runs twice with the same result, sets the ADR 0021 b
// directory owners/modes, passes `systemd-analyze verify`, and leaves Headscale's config and start
// time untouched.
func TestHostLab_InstallIdempotent(t *testing.T) {
	lab := hostlab.Start(t)
	hostlab.ClearDir(t, lab.RequestsDir())
	hostlab.ClearDir(t, lab.ResultsDir())

	before := hostlab.ConfigBytes(t, lab)
	beforeStart := strings.TrimSpace(lab.Exec(t, "systemctl", "show", "-p", "ActiveEnterTimestamp", "--value", "headscale.service"))

	bin, sum := hostlab.BuildHelper(t, lab)
	out1 := hostlab.RunInstall(t, lab, bin, sum)
	out2 := hostlab.RunInstall(t, lab, bin, sum)

	lab.Exec(t, "systemd-analyze", "verify",
		"/etc/systemd/system/tagcess-hshelper.path",
		"/etc/systemd/system/tagcess-hshelper.service",
		"/etc/systemd/system/tagcess-hshelper-boot.service")

	for _, tc := range []struct{ path, want string }{
		{hostlab.RootInContainer, "755 root:root"},
		{hostlab.RootInContainer + "/requests", "700 root:root"},
		{hostlab.RootInContainer + "/results", "755 root:root"},
		{hostlab.RootInContainer + "/private", "700 root:root"},
	} {
		if got := strings.TrimSpace(lab.Exec(t, "stat", "-c", "%a %U:%G", tc.path)); got != tc.want {
			t.Errorf("%s owner/mode = %q, want %q", tc.path, got, tc.want)
		}
	}
	if got := strings.TrimSpace(lab.Exec(t, "sha256sum", hostlab.HelperBinInLab)); !strings.HasPrefix(got, sum+" ") {
		t.Errorf("installed binary sha256 = %q, want it to start with %q", got, sum)
	}
	if !bytes.Equal(before, hostlab.ConfigBytes(t, lab)) {
		t.Error("install.sh changed the Headscale config")
	}
	afterStart := strings.TrimSpace(lab.Exec(t, "systemctl", "show", "-p", "ActiveEnterTimestamp", "--value", "headscale.service"))
	if afterStart != beforeStart {
		t.Errorf("headscale.service start time changed by install.sh: %q -> %q", beforeStart, afterStart)
	}
	if lastLine(out1) != lastLine(out2) {
		t.Errorf("install.sh did not give the same result:\nfirst:  %s\nsecond: %s", lastLine(out1), lastLine(out2))
	}
	if got := strings.TrimSpace(lab.Exec(t, "systemctl", "is-active", "headscale.service")); got != "active" {
		t.Errorf("headscale.service is %q after install, want active", got)
	}
}

// TestHostLab_HelperApplySmoke is AC2: a valid request written with the expected uid triggers the
// .path/oneshot unit; the result is succeeded with the same ID; Headscale stays healthy; only
// oidc.allowed_groups changed; status.json shows the new list and base_rev.
func TestHostLab_HelperApplySmoke(t *testing.T) {
	lab := hostlab.Start(t)
	hostlab.Install(t, lab)
	hostlab.ClearDir(t, lab.RequestsDir())
	hostlab.ClearDir(t, lab.ResultsDir())

	// The lab starts with no allowed_groups; restore that at the end so later tests see a clean lab.
	before := hostlab.ConfigBytes(t, lab)
	t.Cleanup(func() { restoreConfig(t, lab, before) })

	current, _, err := hshelper.Project(before)
	if err != nil {
		t.Fatalf("project live config: %v", err)
	}
	groups := []string{"devops"}
	if len(current) == 1 && current[0] == "devops" {
		groups = []string{"devops", "developer"}
	}
	wantRev, err := hostpatch.BaseRev(groups)
	if err != nil {
		t.Fatal(err)
	}

	id := newID(t)
	writeRequest(t, lab, id, groups)
	r := waitForResult(t, lab, id)

	if r.State != hostpatch.StateSucceeded {
		t.Fatalf("result = %+v, want succeeded", r)
	}
	if r.ErrorCode != "" || r.Phase != hostpatch.PhaseCheck {
		t.Errorf("result phase/error = %s/%q, want check and empty", r.Phase, r.ErrorCode)
	}
	if r.ConfigChanged == nil || !*r.ConfigChanged || !r.HealthVerified {
		t.Errorf("result config_changed/health = %v/%v, want true/true", r.ConfigChanged, r.HealthVerified)
	}

	// The helper's candidate (same function, deterministic) is the whole new file.
	after := hostlab.ConfigBytes(t, lab)
	wantCand, err := hshelper.Candidate(before, groups)
	if err != nil {
		t.Fatalf("build expected candidate: %v", err)
	}
	if !bytes.Equal(after, wantCand) {
		t.Errorf("live config is not the candidate; only allowed_groups may change\n--- got ---\n%s\n--- want ---\n%s", after, wantCand)
	}
	// Independent of hshelper.Candidate: a line diff of before/after must touch only
	// oidc.allowed_groups. Blank lines are ignored because the helper re-encodes the YAML, which
	// drops them; any other changed line means something outside allowed_groups was rewritten.
	removed, added := diffLines(before, after)
	for _, line := range append(append([]string{}, removed...), added...) {
		if !allowedGroupsLine(line) {
			t.Errorf("line changed outside oidc.allowed_groups: %q (removed %q, added %q)", line, removed, added)
		}
	}

	if got := hostlab.HealthCode(lab); got != http.StatusOK {
		t.Errorf("headscale /health = %d, want 200", got)
	}
	if got := strings.TrimSpace(lab.Exec(t, "systemctl", "is-active", "headscale.service")); got != "active" {
		t.Errorf("headscale.service is %q, want active", got)
	}
	if _, err := lab.Client().ListUsers(context.Background()); err != nil {
		t.Errorf("gRPC ListUsers after apply: %v", err)
	}

	s := waitForStatus(t, lab, wantRev)
	if s.RequestID != id {
		t.Errorf("status request_id = %q, want %q", s.RequestID, id)
	}
	if s.State != hostpatch.StateSucceeded {
		t.Errorf("status state = %q, want succeeded", s.State)
	}
	if !equalGroups(s.AllowedGroups, groups) {
		t.Errorf("status allowed_groups = %v, want %v", s.AllowedGroups, groups)
	}
}

// TestHostLab_BootPublishesStatus is AC3: restarting the boot unit republishes status.json with the
// current projection and does not touch the config.
func TestHostLab_BootPublishesStatus(t *testing.T) {
	lab := hostlab.Start(t)
	hostlab.Install(t, lab)

	src := hostlab.ConfigBytes(t, lab)
	groups, rev, err := hshelper.Project(src)
	if err != nil {
		t.Fatalf("project live config: %v", err)
	}

	// Remove the published status so the restart is the only thing that can recreate it.
	if err := os.Remove(filepath.Join(lab.ResultsDir(), "status.json")); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	lab.Exec(t, "systemctl", "restart", "tagcess-hshelper-boot.service")

	s := waitForStatus(t, lab, rev)
	if !equalGroups(s.AllowedGroups, groups) {
		t.Errorf("status allowed_groups = %v, want the config projection %v", s.AllowedGroups, groups)
	}
	if s.ConfigError != "" {
		t.Errorf("status config_error = %q, want empty", s.ConfigError)
	}
	if !bytes.Equal(src, hostlab.ConfigBytes(t, lab)) {
		t.Error("the boot unit changed the Headscale config")
	}
}

// TestHostLab_RejectsForeignRequest is AC4: a marker or request file written as a symlink is rejected
// in the lab and the config does not change. OrbStack's virtiofs normalizes every file in the bind
// mount to uid 0, so the lab cannot produce a wrong-owner request; that case is covered by the
// F3b-006 unit tests. This is the symlink half of "wrong uid or symlink".
func TestHostLab_RejectsForeignRequest(t *testing.T) {
	lab := hostlab.Start(t)
	hostlab.Install(t, lab)
	hostlab.ClearDir(t, lab.RequestsDir())

	before := hostlab.ConfigBytes(t, lab)
	beforeSum := shaHex(before)

	// A valid, different group set: following either link below would accept the request and
	// rewrite the config, so a followed link is visibly wrong, not merely differently rejected.
	current, _, err := hshelper.Project(before)
	if err != nil {
		t.Fatalf("project live config: %v", err)
	}
	groups := []string{"devops", "developer"}
	if equalGroups(current, groups) {
		groups = []string{"devops"}
	}

	t.Run("marker symlink", func(t *testing.T) {
		removeResult(t, lab)
		id := newID(t)
		// A valid request file for id sits in requests/, and the marker symlink's target holds id:
		// a followed marker link would find and accept that request (and change the config).
		writeRequestBody(t, lab, id, groups)
		t.Cleanup(func() { _ = os.Remove(filepath.Join(lab.RequestsDir(), id+".json")) })

		// The target is a real file in the container, so systemd's PathExists (which follows
		// symlinks) fires and the helper gets to reject the link. A dangling symlink would never
		// trigger the .path unit.
		targetInContainer := hostlab.RootInContainer + "/requests/marker-target.txt"
		target := filepath.Join(lab.RequestsDir(), "marker-target.txt")
		if err := os.WriteFile(target, []byte(id), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(target) })
		link := filepath.Join(lab.RequestsDir(), "request.ready")
		_ = os.Remove(link)
		if err := os.Symlink(targetInContainer, link); err != nil {
			t.Fatal(err)
		}
		r := waitForResult(t, lab, nilID)
		if r.State != hostpatch.StateFailed || r.ErrorCode != hostpatch.CodeInvalidRequest {
			t.Errorf("result = %s/%q, want failed/invalid_request", r.State, r.ErrorCode)
		}
		if r.ConfigChanged == nil || *r.ConfigChanged {
			t.Errorf("config_changed = %v, want false", r.ConfigChanged)
		}
		if _, err := os.Lstat(link); !os.IsNotExist(err) {
			t.Errorf("the marker was not consumed: %v", err)
		}
	})

	t.Run("request symlink", func(t *testing.T) {
		removeResult(t, lab)
		id := newID(t)
		// The request file is a symlink to a valid request that exists in the container; the marker
		// is a regular file naming id. A followed request link would accept and apply the new groups.
		targetInContainer := hostlab.RootInContainer + "/requests/request-target-" + id + ".json"
		target := filepath.Join(lab.RequestsDir(), "request-target-"+id+".json")
		if err := os.WriteFile(target, requestDoc(t, lab, id, groups), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(target) })
		if err := os.Symlink(targetInContainer, filepath.Join(lab.RequestsDir(), id+".json")); err != nil {
			t.Fatal(err)
		}
		writeMarker(t, lab, id)
		r := waitForResult(t, lab, id)
		if r.State != hostpatch.StateFailed || r.ErrorCode != hostpatch.CodeInvalidRequest {
			t.Errorf("result = %s/%q, want failed/invalid_request", r.State, r.ErrorCode)
		}
		if r.ConfigChanged == nil || *r.ConfigChanged {
			t.Errorf("config_changed = %v, want false", r.ConfigChanged)
		}
		after := hostlab.ConfigBytes(t, lab)
		if !bytes.Equal(after, before) {
			t.Errorf("the live config changed although the request link had to be rejected")
		}
		wantCand, err := hshelper.Candidate(before, groups)
		if err != nil {
			t.Fatalf("build candidate: %v", err)
		}
		if bytes.Equal(after, wantCand) {
			t.Errorf("the live config is the candidate a followed request link would apply")
		}
	})

	if got := shaHex(hostlab.ConfigBytes(t, lab)); got != beforeSum {
		t.Errorf("the config changed after rejected requests: %s -> %s", beforeSum, got)
	}
}

// TestHostLab_ConfigtestLeavesStateDir is AC5: the real `headscale configtest`, run as the headscale
// service user on a .yaml candidate, leaves /var/lib/headscale's owner/mode and file list unchanged
// and Headscale can still open afterwards.
func TestHostLab_ConfigtestLeavesStateDir(t *testing.T) {
	lab := hostlab.Start(t)
	hostlab.Install(t, lab)

	before := stateDirSnapshot(t, lab)

	src := hostlab.ConfigBytes(t, lab)
	cand, err := hshelper.Candidate(src, []string{"devops"})
	if err != nil {
		t.Fatalf("build candidate: %v", err)
	}
	local := filepath.Join(t.TempDir(), "candidate.yaml")
	if err := os.WriteFile(local, cand, 0o644); err != nil {
		t.Fatal(err)
	}
	hostlab.DockerCopy(t, local, lab.Name+":"+hostlab.CandidateInLab)
	lab.Exec(t, "chown", "root:root", hostlab.CandidateInLab)
	lab.Exec(t, "chmod", "0644", hostlab.CandidateInLab)
	t.Cleanup(func() { _, _ = lab.ExecErr("rm", "-f", hostlab.CandidateInLab) })

	// The exact identity the helper uses for configtest: the headscale service user, clean environment.
	out, err := exec.CommandContext(context.Background(), "docker", "exec", "-u", "headscale", lab.Name,
		"env", "-i", "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"/usr/bin/headscale", "configtest", "-c", hostlab.CandidateInLab).CombinedOutput()
	if err != nil {
		t.Fatalf("configtest as the service user: %v\n%s", err, out)
	}

	if after := stateDirSnapshot(t, lab); after != before {
		t.Errorf("/var/lib/headscale changed by configtest:\n--- before ---\n%s\n--- after ---\n%s", before, after)
	}

	lab.Exec(t, "systemctl", "restart", "headscale.service")
	hostlab.WaitHealth(t, lab)
	if got := strings.TrimSpace(lab.Exec(t, "systemctl", "is-active", "headscale.service")); got != "active" {
		t.Errorf("headscale.service is %q after configtest, want active", got)
	}
}

// requestDoc builds the request document for id and groups, with base_rev from the live config.
func requestDoc(t *testing.T, lab *hostlab.Lab, id string, groups []string) []byte {
	t.Helper()
	_, rev, err := hshelper.Project(hostlab.ConfigBytes(t, lab))
	if err != nil {
		t.Fatalf("project live config: %v", err)
	}
	doc, err := hostpatch.BuildRequest(id, rev, groups)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	return doc
}

// writeRequestBody writes requests/<id>.json (no marker), ADR 0021 a style.
func writeRequestBody(t *testing.T, lab *hostlab.Lab, id string, groups []string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(lab.RequestsDir(), id+".json"), requestDoc(t, lab, id, groups), 0o644); err != nil {
		t.Fatal(err)
	}
}

// writeMarker publishes requests/request.ready holding id by atomic rename, ADR 0021 b style.
func writeMarker(t *testing.T, lab *hostlab.Lab, id string) {
	t.Helper()
	marker := filepath.Join(lab.RequestsDir(), "request.ready")
	tmp := marker + ".tmp"
	if err := os.WriteFile(tmp, []byte(id), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, marker); err != nil {
		t.Fatal(err)
	}
}

// writeRequest publishes a valid request for id over the bind mount, ADR 0021 b style: the request file
// first, then the marker by atomic rename. base_rev comes from the live config.
func writeRequest(t *testing.T, lab *hostlab.Lab, id string, groups []string) {
	t.Helper()
	writeRequestBody(t, lab, id, groups)
	writeMarker(t, lab, id)
}

// waitForResult waits for results/result.json to carry id and returns it.
func waitForResult(t *testing.T, lab *hostlab.Lab, id string) hostpatch.Result {
	t.Helper()
	deadline := time.Now().Add(150 * time.Second)
	for time.Now().Before(deadline) {
		if r, ok := readResult(lab, id); ok {
			return r
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("no result.json for %s within 150s", id)
	return hostpatch.Result{}
}

// waitForStatus waits for results/status.json to project the wanted base_rev with no config_error.
func waitForStatus(t *testing.T, lab *hostlab.Lab, rev string) hostpatch.Status {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if s, ok := readStatus(lab, rev); ok {
			return s
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("status.json did not show base_rev %s within 30s", rev)
	return hostpatch.Status{}
}

func readResult(lab *hostlab.Lab, id string) (hostpatch.Result, bool) {
	b, err := os.ReadFile(filepath.Join(lab.ResultsDir(), "result.json"))
	if err != nil {
		return hostpatch.Result{}, false
	}
	r, err := hostpatch.DecodeResult(b)
	if err != nil || r.RequestID != id {
		return hostpatch.Result{}, false
	}
	return r, true
}

func readStatus(lab *hostlab.Lab, rev string) (hostpatch.Status, bool) {
	b, err := os.ReadFile(filepath.Join(lab.ResultsDir(), "status.json"))
	if err != nil {
		return hostpatch.Status{}, false
	}
	s, err := hostpatch.DecodeStatus(b)
	if err != nil || s.BaseRev != rev || s.ConfigError != "" {
		return hostpatch.Status{}, false
	}
	return s, true
}

// restoreConfig puts the lab's starting config back and restarts Headscale so later tests see a clean
// lab (the task's clean-state rule; not a helper restore path).
func restoreConfig(t *testing.T, lab *hostlab.Lab, content []byte) {
	t.Helper()
	f, err := os.CreateTemp("", "tagcess-restore-*.yaml")
	if err != nil {
		t.Fatalf("restore config: %v", err)
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if _, err := f.Write(content); err != nil {
		t.Fatalf("restore config: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("restore config: %v", err)
	}
	hostlab.DockerCopy(t, f.Name(), lab.Name+":"+hostlab.ConfigInLab)
	lab.Exec(t, "chown", "root:root", hostlab.ConfigInLab)
	lab.Exec(t, "chmod", "0644", hostlab.ConfigInLab)
	lab.Exec(t, "systemctl", "restart", "headscale.service")
	hostlab.WaitHealth(t, lab)
}

// stateDirSnapshot is the owner/mode of /var/lib/headscale and, for each entry, its name and
// owner/mode, sorted: exactly what configtest must leave alone.
func stateDirSnapshot(t *testing.T, lab *hostlab.Lab) string {
	t.Helper()
	return lab.Exec(t, "sh", "-c",
		"stat -c 'dir %a %U:%G' /var/lib/headscale; find /var/lib/headscale -mindepth 1 -maxdepth 1 -printf '%f %u:%g %m\\n' | sort")
}

func shaHex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func removeResult(t *testing.T, lab *hostlab.Lab) {
	t.Helper()
	if err := os.Remove(filepath.Join(lab.ResultsDir(), "result.json")); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	return lines[len(lines)-1]
}

func equalGroups(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for _, g := range want {
		if !contains(got, g) {
			return false
		}
	}
	return true
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// nonBlankLines splits b into lines and drops the blank ones (the YAML encoder removes them).
func nonBlankLines(b []byte) []string {
	var out []string
	for _, line := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		if strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}
	return out
}

// diffLines returns the non-blank lines that differ between before and after (order-preserving
// longest-common-subsequence diff), so a test can assert that only allowed_groups changed.
func diffLines(before, after []byte) (removed, added []string) {
	b, a := nonBlankLines(before), nonBlankLines(after)
	n, m := len(b), len(a)
	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			switch {
			case b[i] == a[j]:
				lcs[i][j] = lcs[i+1][j+1] + 1
			case lcs[i+1][j] >= lcs[i][j+1]:
				lcs[i][j] = lcs[i+1][j]
			default:
				lcs[i][j] = lcs[i][j+1]
			}
		}
	}
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case b[i] == a[j]:
			i, j = i+1, j+1
		case lcs[i+1][j] >= lcs[i][j+1]:
			removed = append(removed, b[i])
			i++
		default:
			added = append(added, a[j])
			j++
		}
	}
	removed = append(removed, b[i:]...)
	added = append(added, a[j:]...)
	return removed, added
}

// allowedGroupsLine reports whether a changed line belongs to oidc.allowed_groups: its key line or
// one of the group list items. Anything else changed is a bug in the candidate.
func allowedGroupsLine(line string) bool {
	s := strings.TrimSpace(line)
	if strings.HasPrefix(s, "allowed_groups:") {
		return true
	}
	if item, ok := strings.CutPrefix(s, "- "); ok {
		switch item {
		case "devops", "developer", "standart":
			return true
		}
	}
	return false
}

func newID(t *testing.T) string {
	t.Helper()
	out, err := exec.CommandContext(context.Background(), "uuidgen").Output()
	if err != nil {
		t.Fatalf("uuidgen: %v", err)
	}
	id := strings.ToLower(strings.TrimSpace(string(out)))
	if !hostpatch.ValidRequestID(id) {
		t.Fatalf("uuidgen returned %q, not a lowercase UUID", id)
	}
	return id
}
