//go:build integration

// F3b-022: the real tagcess binary driven through its web interface against the host lab (F3b-002/003:
// OrbStack systemd container, Headscale v0.29.4, the ADR 0021 b shared directories) instead of a
// disposable Headscale. This is the connection `make hostlab-ui` (test/ui/hostlab-up.sh) sets up for
// the developer, and the frame the fault scenarios of f3b_failure_test.go run in: the binary writes a
// patch into the bind-mounted requests/ directory, the installed helper applies it under systemd, and
// the interface reads status.json/result.json back.
//
// The lab is persistent and shared: newF3bStack resets the requests/results directories and the live
// config to a known baseline, and restores them at the end. Run with (`make lab-up` first; stop the
// compose Headscale or pin free HOSTLAB_* ports):
//
//	go test -tags=integration -count=1 -v -run TestHostLab ./test/e2e/
package e2e_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/hostpatch"
	"github.com/nesiler/tagcess/internal/maintenance"
	"github.com/nesiler/tagcess/test/hostlab"
)

// f3bBaselineGroups is the allowed_groups list every scenario starts from.
var f3bBaselineGroups = []string{hostpatch.GroupDevops}

// f3bStack is a running F3b scenario: the lab Zitadel, the host lab with its helper, and the real
// tagcess binary wired to the lab's shared directories.
type f3bStack struct {
	t    *testing.T
	l    *labEnv
	hl   *hostlab.Lab
	proc *tagcessProc
	ui   *uiClient
	cfg  tagcessConfig
	// baseline is the lab config as it was before the scenario, restored at the end.
	baseline []byte
	// restores are the fault injections still active, undone (reverse order) at the end.
	restores []func()
}

// newF3bStack brings up the host lab, installs the helper, sets a known baseline config and starts
// the binary. It is the Go equivalent of `make hostlab-ui`.
func newF3bStack(t *testing.T) *f3bStack {
	t.Helper()
	l := setupLab(t)
	hl := hostlab.Start(t)
	hostlab.Install(t, hl)
	hostlab.ClearDir(t, hl.RequestsDir())
	hostlab.ClearDir(t, hl.ResultsDir())
	// The lab Headscale starts with no policy row; the interface's uncertain-outcome check reads it,
	// so seed the same fixture policy the F3 scenarios use before starting the binary.
	if _, err := hl.Client().SetPolicy(context.Background(), f3Policy); err != nil {
		t.Fatalf("seed the host lab policy: %v", err)
	}
	baseline := hostlab.ConfigBytes(t, hl)
	hostlab.SetGroups(t, hl, f3bBaselineGroups)

	s := &f3bStack{t: t, l: l, hl: hl, baseline: baseline}
	// Registered before startTagcess, so its clean-up runs first (LIFO): the binary stops, then the
	// faults are undone and the lab config is restored.
	t.Cleanup(func() {
		s.clearFaults()
		hostlab.WriteConfig(t, hl, baseline)
	})

	s.cfg = tagcessConfig{
		headscaleAddr:   hl.GRPCAddr,
		issuer:          l.issuer,
		keyFile:         filepath.Join(l.secrets(), "zitadel-key.json"),
		interval:        5 * time.Minute,
		hostRequestsDir: hl.RequestsDir(),
		hostResultsDir:  hl.ResultsDir(),
	}
	s.proc = startTagcess(t, l, s.cfg)
	s.ui = newUIClient(t, s.proc.uiSock)
	return s
}

// restart stops the binary and starts it again on the same data directory, so the store (the
// maintenance row and the request ID) survives: the F3b-024 restart-resume scenario.
func (s *f3bStack) restart() {
	s.t.Helper()
	s.proc.stop(s.t)
	s.cfg.dataDir = s.proc.dataDir
	s.proc = startTagcess(s.t, s.l, s.cfg)
	s.ui = newUIClient(s.t, s.proc.uiSock)
}

// clearFaults undoes every injection a scenario made (idempotent).
func (s *f3bStack) clearFaults() {
	for i := len(s.restores) - 1; i >= 0; i-- {
		s.restores[i]()
	}
	s.restores = nil
}

// injectFault registers a restore to run at clean-up and returns it for an explicit undo.
func (s *f3bStack) injectFault(restore func()) func() {
	s.restores = append(s.restores, restore)
	return restore
}

// status is the helper's current status.json.
func (s *f3bStack) status() hostpatch.Status {
	s.t.Helper()
	st, ok := hostlab.ReadStatus(s.hl)
	if !ok {
		s.t.Fatalf("the lab has no valid status.json")
	}
	return st
}

// waitStatus waits for status.json to project rev and returns it.
func (s *f3bStack) waitStatus(rev string) hostpatch.Status {
	s.t.Helper()
	return hostlab.WaitStatus(s.t, s.hl, rev)
}

// maint reads the durable maintenance row.
func (s *f3bStack) maint() (maintenance.State, string, string) {
	s.t.Helper()
	var state, reqID, last string
	err := s.proc.storeDB(s.t).QueryRow(
		`SELECT state, request_id, last_host_result FROM headscale_maintenance WHERE id = 1`,
	).Scan(&state, &reqID, &last)
	if err != nil {
		s.t.Fatalf("read maintenance row: %v", err)
	}
	return maintenance.State(state), reqID, last
}

// waitMaintState waits until the maintenance is in want.
func (s *f3bStack) waitMaintState(want maintenance.State) {
	s.t.Helper()
	if err := poll(s.t, 90*time.Second, func() (bool, error) {
		st, _, _ := s.maint()
		return st == want, nil
	}); err != nil {
		st, id, last := s.maint()
		s.t.Fatalf("maintenance never became %q (is %q, req %q, last %q): %v", want, st, id, last, err)
	}
}

// waitHostResult waits until the maintenance row carries a terminal host result for the open request
// and returns its state and error code.
func (s *f3bStack) waitHostResult() (hostpatch.State, hostpatch.ErrorCode) {
	s.t.Helper()
	var state hostpatch.State
	var code hostpatch.ErrorCode
	err := poll(s.t, 150*time.Second, func() (bool, error) {
		_, reqID, last := s.maint()
		if last == "" {
			return false, nil
		}
		var v hostResultView
		if e := json.Unmarshal([]byte(last), &v); e != nil {
			return false, e
		}
		// The result must belong to the request the row currently holds: a terminal result of an
		// earlier request is not this request's outcome (F3b-022 LOW, F3b-027 AC5).
		if v.Status == "" || v.RequestID != reqID {
			return false, nil
		}
		state, code = hostpatch.State(v.Status), hostpatch.ErrorCode(v.ErrorCode)
		return state.Terminal(), nil
	})
	if err != nil {
		_, id, last := s.maint()
		s.t.Fatalf("no terminal host result for the open request %q (last %q): %v", id, last, err)
	}
	return state, code
}

// lastResult parses the maintenance row's stored host result.
func (s *f3bStack) lastResult() hostResultView {
	s.t.Helper()
	_, _, last := s.maint()
	var v hostResultView
	if last == "" {
		s.t.Fatalf("the maintenance row has no host result")
	}
	if err := json.Unmarshal([]byte(last), &v); err != nil {
		s.t.Fatalf("parse the stored host result: %v", err)
	}
	return v
}

// hostResultView mirrors the secret-free fields main.go stores in the maintenance row.
type hostResultView struct {
	Status         string `json:"status"`
	RequestID      string `json:"request_id"`
	Phase          string `json:"phase"`
	ErrorCode      string `json:"error_code"`
	ConfigChanged  *bool  `json:"config_changed"`
	HealthVerified bool   `json:"health_verified"`
}

// enableWriteSwitch turns on Headscale config write through the settings screen (two-step confirm).
func (s *f3bStack) enableWriteSwitch() {
	s.t.Helper()
	code, body := s.ui.post("/headscale/settings/config-write", url.Values{"enabled": {"true"}})
	if code != http.StatusOK {
		s.t.Fatalf("open the write switch: status %d: %s", code, excerpt(body))
	}
	code, body = s.ui.post("/headscale/settings/config-write", confirmForm(s.t, body, "/headscale/settings/config-write"))
	if code != http.StatusOK {
		s.t.Fatalf("confirm the write switch: status %d: %s", code, excerpt(body))
	}
	mustContain(s.t, "write switch result", body, "Config yazma switch'i açıldı")
}

// triggerSync asks for a manual reconcile (the Y-04 expiry path) without waiting for it; the writer
// lock serialises the later apply behind it.
func (s *f3bStack) triggerSync() {
	s.t.Helper()
	if code, body := s.ui.post("/sync/trigger", nil); code != http.StatusSeeOther {
		s.t.Fatalf("POST /sync/trigger: status %d: %s", code, excerpt(body))
	}
}

// awaitSyncRun waits until a sync run beyond after has been recorded; /sync/trigger only asks for a
// run, so a test that depends on the run's effect must wait for it to finish.
func (s *f3bStack) awaitSyncRun(after int) {
	s.t.Helper()
	if err := poll(s.t, 30*time.Second, func() (bool, error) {
		return s.proc.queryInt(s.t, `SELECT count(*) FROM sync_runs`) > after, nil
	}); err != nil {
		s.t.Fatalf("the triggered reconcile did not finish: %v", err)
	}
}

// applyOK previews then applies groups at the current base_rev and requires the redirect.
func (s *f3bStack) applyOK(groups []string) {
	s.t.Helper()
	base := s.status().BaseRev
	pv := url.Values{}
	for _, g := range groups {
		pv.Add("group", g)
	}
	if code, body := s.ui.post("/headscale/config/preview", pv); code != http.StatusOK {
		s.t.Fatalf("preview %v: status %d: %s", groups, code, excerpt(body))
	}
	form := url.Values{"confirm": {"1"}, "base_rev": {base}}
	for _, g := range groups {
		form.Add("group", g)
	}
	code, body := s.ui.post("/headscale/config/apply", form)
	if code != http.StatusSeeOther {
		s.t.Fatalf("apply %v: status %d, want 303: %s", groups, code, excerpt(body))
	}
}

// TestHostLab_UIConnects is AC1: the stack `make hostlab-ui` (test/ui/hostlab-up.sh) builds starts
// tagcess wired to the host lab, and the /headscale/config page shows the lab's status.json (the
// current allowed_groups and base_rev).
func TestHostLab_UIConnects(t *testing.T) {
	// The script the Makefile target runs must exist and be wired.
	if b, err := os.ReadFile(filepath.Join(repoRoot(), "Makefile")); err != nil || !strings.Contains(string(b), "hostlab-ui:") {
		t.Fatalf("the Makefile has no hostlab-ui target: %v", err)
	}
	if _, err := os.Stat(filepath.Join(repoRoot(), "test", "ui", "hostlab-up.sh")); err != nil {
		t.Fatalf("test/ui/hostlab-up.sh: %v", err)
	}

	s := newF3bStack(t)
	st := s.status()
	if !equalGroupList(st.AllowedGroups, f3bBaselineGroups) {
		t.Fatalf("lab status groups = %v, want the baseline %v", st.AllowedGroups, f3bBaselineGroups)
	}
	page := s.ui.getOK("/headscale/config")
	mustContain(t, "config page", page, st.BaseRev, "base_rev")
	for _, g := range st.AllowedGroups {
		mustContain(t, "config page", page, g)
	}
}

// equalGroupList reports whether a and b hold the same groups (order-insensitive).
func equalGroupList(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for _, x := range b {
		if !containsString(a, x) {
			return false
		}
	}
	return true
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
