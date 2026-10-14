//go:build integration

// F3b-022: the ADR 0021 e.5 failure trials on the host lab, driven through the real interface. Each
// test injects one fault (configtest error, post-replace health error, TimeoutStartSec overrun),
// starts a patch, and checks that the system reports the failure without ever claiming success or
// restoring the config: the maintenance stays active and the way out is a new patch or "close the
// maintenance". The injections are undone at the end (newF3bStack's clean-up is the safety net).
package e2e_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/hostpatch"
	"github.com/nesiler/tagcess/internal/hshelper"
	"github.com/nesiler/tagcess/internal/maintenance"
	"github.com/nesiler/tagcess/test/hostlab"
)

// f3bWanted is the group list the failure scenarios try to apply.
var f3bWanted = []string{hostpatch.GroupDevops, hostpatch.GroupDeveloper}

// TestHostLab_Failure_Configtest is AC2: a configtest error must not change the live config or
// restart Headscale; the result is failed/configtest_failed with config_changed=false.
func TestHostLab_Failure_Configtest(t *testing.T) {
	s := newF3bStack(t)
	s.enableWriteSwitch()

	before := hostlab.ConfigBytes(t, s.hl)
	beforeStart := startTimestamp(s)

	restore := s.injectFault(hostlab.HideOIDCSecret(t, s.hl))
	s.applyOK(f3bWanted)

	state, code := s.waitHostResult()
	if state != hostpatch.StateFailed || code != hostpatch.CodeConfigtestFailed {
		t.Fatalf("result = %s/%s, want failed/configtest_failed", state, code)
	}
	res := s.lastResult()
	if res.Phase != string(hostpatch.PhaseValidate) {
		t.Errorf("phase = %q, want validate", res.Phase)
	}
	if res.ConfigChanged == nil || *res.ConfigChanged {
		t.Errorf("config_changed = %v, want false", res.ConfigChanged)
	}
	if got := hostlab.ConfigBytes(t, s.hl); string(got) != string(before) {
		t.Errorf("the live config changed although configtest failed")
	}
	if after := startTimestamp(s); after != beforeStart {
		t.Errorf("Headscale restarted on a configtest failure: %q -> %q", beforeStart, after)
	}
	maintState(t, s, maintenance.Active)

	restore()
}

// TestHostLab_Failure_Health is AC3: after the replace, a restart that cannot bring Headscale back
// leaves the new config in place (config_changed=true, health_verified=false) with no rollback and
// no second restart; the maintenance stays active.
func TestHostLab_Failure_Health(t *testing.T) {
	s := newF3bStack(t)
	s.enableWriteSwitch()

	before := hostlab.ConfigBytes(t, s.hl)
	restore := s.injectFault(hostlab.FaultHealth(t, s.hl))
	s.applyOK(f3bWanted)

	state, code := s.waitHostResult()
	if state != hostpatch.StateFailed {
		t.Fatalf("result state = %s, want failed", state)
	}
	// The drop-in makes `systemctl restart headscale` exit non-zero, so the helper fails in the
	// restart step with restart_failed and never reaches the health check. The health_failed code
	// (a restart that returns 0 but the service never becomes healthy) has no lab trial: this fault
	// only exercises the restart step (stack-notes 2026-10-04).
	if code != hostpatch.CodeRestartFailed {
		t.Errorf("error_code = %s, want restart_failed", code)
	}
	res := s.lastResult()
	if res.ConfigChanged == nil || !*res.ConfigChanged {
		t.Errorf("config_changed = %v, want true", res.ConfigChanged)
	}
	if res.HealthVerified {
		t.Errorf("health_verified = true, want false")
	}

	// No rollback: the live config is the candidate the helper wrote, not the baseline.
	wantCand, err := hshelper.Candidate(before, f3bWanted)
	if err != nil {
		t.Fatalf("build the candidate: %v", err)
	}
	if got := hostlab.ConfigBytes(t, s.hl); string(got) != string(wantCand) {
		t.Errorf("the live config is not the candidate (a rollback happened):\n--- got ---\n%s", got)
	}
	if got := hostlab.HealthCode(s.hl); got == http.StatusOK {
		t.Errorf("Headscale /health = %d, want a failure (the health fault is active)", got)
	}
	maintState(t, s, maintenance.Active)

	restore()
}

// TestHostLab_Failure_Timeout is AC4: a systemd TimeoutStartSec overrun during the restart kills the
// helper; ExecStopPost finalize publishes interrupted, with no automatic continue or rollback, and
// the maintenance stays active.
func TestHostLab_Failure_Timeout(t *testing.T) {
	s := newF3bStack(t)
	s.enableWriteSwitch()

	before := hostlab.ConfigBytes(t, s.hl)
	restore := s.injectFault(hostlab.FaultTimeout(t, s.hl))
	s.applyOK(f3bWanted)

	state, _ := s.waitHostResult()
	if state != hostpatch.StateInterrupted {
		t.Fatalf("result state = %s, want interrupted", state)
	}
	res := s.lastResult()
	if res.ConfigChanged != nil {
		t.Errorf("config_changed = %v, want unknown (nil) for a killed apply", res.ConfigChanged)
	}
	// "No automatic rollback": the systemd kill happens after the replace, so the live config is
	// the candidate the helper wrote, exactly as in AC3, and the maintenance stays open.
	wantCand, err := hshelper.Candidate(before, f3bWanted)
	if err != nil {
		t.Fatalf("build the candidate: %v", err)
	}
	if got := hostlab.ConfigBytes(t, s.hl); string(got) != string(wantCand) {
		t.Errorf("the live config is not the candidate (a rollback happened):\n--- got ---\n%s", got)
	}
	maintState(t, s, maintenance.Active)

	// "No automatic continue": Headscale's own delayed start finishes here, and we then wait well
	// past it. If the killed helper or systemd were to resume or roll the request back on its own,
	// it would change the stored result or the config within this window.
	hostlab.WaitHealth(t, s.hl)
	time.Sleep(35 * time.Second)

	st, _, last := s.maint()
	if st != maintenance.Active {
		t.Errorf("maintenance = %q after the restart window, want active", st)
	}
	var again hostResultView
	if err := json.Unmarshal([]byte(last), &again); err != nil {
		t.Fatalf("parse the stored host result after the restart window: %v", err)
	}
	if again.Status != string(hostpatch.StateInterrupted) || again.RequestID != res.RequestID {
		t.Errorf("result changed after the restart window: %s/%s, want interrupted/%s",
			again.Status, again.RequestID, res.RequestID)
	}
	if got := hostlab.ConfigBytes(t, s.hl); string(got) != string(wantCand) {
		t.Errorf("the live config changed after the restart window (a rollback happened)")
	}

	restore()
}

// TestHostLab_Failure_RecoverWithNewPatch is AC5: for every failure injection, once it is gone an
// ordinary new patch succeeds, the config projects the new list and the reconcile closes the
// maintenance.
func TestHostLab_Failure_RecoverWithNewPatch(t *testing.T) {
	cases := []struct {
		name      string
		inject    func(t *testing.T, s *f3bStack) func()
		failState hostpatch.State
		// recover is the new patch. It must differ from the live config the failed attempt left
		// behind: configtest changes nothing (re-apply f3bWanted), while the replace-based faults
		// leave the candidate in place (return to the baseline).
		recover []string
	}{
		{
			name: "configtest",
			inject: func(t *testing.T, s *f3bStack) func() {
				return s.injectFault(hostlab.HideOIDCSecret(t, s.hl))
			},
			failState: hostpatch.StateFailed,
			recover:   f3bWanted,
		},
		{
			name: "health",
			inject: func(t *testing.T, s *f3bStack) func() {
				return s.injectFault(hostlab.FaultHealth(t, s.hl))
			},
			failState: hostpatch.StateFailed,
			recover:   f3bBaselineGroups,
		},
		{
			name: "timeout",
			inject: func(t *testing.T, s *f3bStack) func() {
				return s.injectFault(hostlab.FaultTimeout(t, s.hl))
			},
			failState: hostpatch.StateInterrupted,
			recover:   f3bBaselineGroups,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newF3bStack(t)
			s.enableWriteSwitch()

			restore := tc.inject(t, s)
			s.applyOK(f3bWanted)
			if state, _ := s.waitHostResult(); state != tc.failState {
				t.Fatalf("the injected failure did not fail: %s, want %s", state, tc.failState)
			}
			restore()
			// The replace-based faults leave Headscale down; the recovery needs it answering again.
			hostlab.WaitHealth(t, s.hl)

			s.applyOK(tc.recover)
			state, code := s.waitHostResult()
			if state != hostpatch.StateSucceeded || code != "" {
				t.Fatalf("recovery result = %s/%s, want succeeded", state, code)
			}
			wantRev, err := hostpatch.BaseRev(tc.recover)
			if err != nil {
				t.Fatal(err)
			}
			st := s.waitStatus(wantRev)
			if !equalGroupList(st.AllowedGroups, tc.recover) {
				t.Fatalf("status groups = %v, want %v", st.AllowedGroups, tc.recover)
			}
			s.waitMaintState(maintenance.Off)
		})
	}
}

// TestHostLab_Failure_CloseMaintenance is AC6: after a failure that left the new config in place,
// "close the maintenance" ends it after the hand-over reconcile without restoring the config.
func TestHostLab_Failure_CloseMaintenance(t *testing.T) {
	s := newF3bStack(t)
	s.enableWriteSwitch()

	// The health fault replaces the config and then fails to restart, so the candidate is live when
	// the operator closes. "Close does not restore" is meaningful only here: a configtest failure
	// never changed the config to begin with.
	before := hostlab.ConfigBytes(t, s.hl)
	wantCand, err := hshelper.Candidate(before, f3bWanted)
	if err != nil {
		t.Fatalf("build the candidate: %v", err)
	}
	restore := s.injectFault(hostlab.FaultHealth(t, s.hl))
	s.applyOK(f3bWanted)
	if state, _ := s.waitHostResult(); state != hostpatch.StateFailed {
		t.Fatalf("the injected failure did not fail: %s", state)
	}
	// The close's reconcile must read Headscale, so bring it back before closing; the drop-in's only
	// effect is the failed restart, and the candidate config is what it loads.
	restore()
	hostlab.WaitHealth(t, s.hl)

	_, reqID, _ := s.maint()
	code, body := s.ui.post("/headscale/config/close", url.Values{
		"request_id": {reqID}, "confirm": {"1"},
	})
	if code != http.StatusOK {
		t.Fatalf("close the maintenance: status %d: %s", code, excerpt(body))
	}
	mustContain(t, "close page", body, "bakım kapatma istendi")
	s.waitMaintState(maintenance.Off)

	if got := hostlab.ConfigBytes(t, s.hl); string(got) != string(wantCand) {
		t.Errorf("closing the maintenance changed the config; the candidate must stay in place")
	}
}

// TestHostLab_Failure_NewPatchWhileHeadscaleDown is AC7: with Headscale down after a health failure
// and an unresolved outcome present (an expire/write whose result could not be read back), a new
// recovery patch must not be blocked; once the injection is gone it succeeds.
func TestHostLab_Failure_NewPatchWhileHeadscaleDown(t *testing.T) {
	s := newF3bStack(t)
	s.enableWriteSwitch()

	restore := s.injectFault(hostlab.FaultHealth(t, s.hl))
	s.applyOK(f3bWanted)
	if state, _ := s.waitHostResult(); state != hostpatch.StateFailed {
		t.Fatalf("the health fault did not fail: %s", state)
	}
	maintState(t, s, maintenance.Active)

	// Headscale is down: a Y-04 expire/manual write cannot be verified. It leaves an unresolved
	// outcome (the F3b-018 AC3b condition) that must not block the recovery patch. The fixture
	// records the unresolved outcome the same way an expire attempt would.
	_, _ = s.proc.storeDB(t).Exec(
		`INSERT INTO alerts (kind, source, first_seen_at, last_seen_at) VALUES (?, ?, ?, ?)`,
		"headscale_admin_unverified", "expire", nowStamp(), nowStamp(),
	)
	// The reconcile's Y-04 expiry attempt runs against a Headscale that is down. Let the triggered
	// run finish, then prove the fixture is still open right before the recovery patch: a test that
	// relied on an unknown outcome that the run had already resolved would prove nothing.
	beforeRuns := s.proc.queryInt(t, `SELECT count(*) FROM sync_runs`)
	s.triggerSync()
	s.awaitSyncRun(beforeRuns)
	if n := s.proc.queryInt(t, `SELECT count(*) FROM alerts WHERE kind = 'headscale_admin_unverified' AND resolved_at IS NULL`); n != 1 {
		t.Fatalf("open headscale_admin_unverified alerts = %d, want 1 (the fixture must be live before the recovery patch)", n)
	}

	// A recovery patch while the maintenance is active is not blocked by the unresolved outcome.
	restore()
	hostlab.WaitHealth(t, s.hl)
	s.applyOK([]string{hostpatch.GroupDevops})
	state, code := s.waitHostResult()
	if state != hostpatch.StateSucceeded || code != "" {
		t.Fatalf("recovery while Headscale was down: result = %s/%s, want succeeded", state, code)
	}
	// The success hands the maintenance to a reconcile. A reconcile that starts in the instant the
	// relay is still reconnecting records a read failure and leaves the flag pending, so keep
	// asking until it completes (the same retry the periodic reconcile provides).
	s.waitMaintOffRetrying()
}

// waitMaintOffRetrying waits for the maintenance to close, re-asking for a reconcile when a run
// raced a Headscale restart.
func (s *f3bStack) waitMaintOffRetrying() {
	s.t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for {
		st, id, last := s.maint()
		if st == maintenance.Off {
			return
		}
		if time.Now().After(deadline) {
			s.t.Fatalf("maintenance never closed (is %q, req %q, last %q)", st, id, last)
		}
		if code, body := s.ui.post("/sync/trigger", nil); code != http.StatusSeeOther {
			s.t.Fatalf("POST /sync/trigger: status %d: %s", code, excerpt(body))
		}
		time.Sleep(3 * time.Second)
	}
}

// maintState fails the test unless the maintenance is in want.
func maintState(t *testing.T, s *f3bStack, want maintenance.State) {
	t.Helper()
	st, id, last := s.maint()
	if st != want {
		t.Fatalf("maintenance = %q (req %q, last %q), want %q", st, id, last, want)
	}
}

// startTimestamp is Headscale's ActiveEnterTimestamp (when the current process started).
func startTimestamp(s *f3bStack) string {
	return strings.TrimSpace(s.hl.Exec(s.t, "systemctl", "show", "-p", "ActiveEnterTimestamp", "--value", "headscale.service"))
}

// nowStamp is the fixed-width UTC stamp the store uses for alert times.
func nowStamp() string { return time.Now().UTC().Format("2006-01-02T15:04:05.000Z") }
