//go:build integration

// F3b-024: the F3b end-to-end acceptance test on the host lab (F3b-002/003, ADR 0021 b) with the
// real helper and the lab Zitadel. It exercises the automated part of the F3b exit criteria in one
// package: the successful apply, the maintenance gate (widening refused, narrowing allowed), the
// reconcile before the writers reopen, the container restart resume, the stale base_rev refusal, the
// uncertain-policy start refusal and the secret scan. Run it with:
//
//	make hostlab-up && go test -tags=integration -count=1 -v -run TestF3b_E2E ./test/e2e/
//
// Every scenario clears its own lab users, nodes and maintenance state; `newF3bStack` restores the
// lab config at the end. `hostlab.Start` reuses a running lab, so an image built before the
// `sqlite3` addition (test/hostlab/Dockerfile) gives a confusing fixture failure; run
// `make hostlab-down && make hostlab-up` to rebuild first.
package e2e_test

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/headscale"
	"github.com/nesiler/tagcess/internal/hostpatch"
	"github.com/nesiler/tagcess/internal/hshelper"
	"github.com/nesiler/tagcess/internal/maintenance"
	"github.com/nesiler/tagcess/internal/policyrev"
	"github.com/nesiler/tagcess/test/compose/hsstack"
	"github.com/nesiler/tagcess/test/compose/seed"
	"github.com/nesiler/tagcess/test/hostlab"
)

// f3bAllGroups is the widest list the interface offers; applying it is the widening every scenario
// starts from.
var f3bAllGroups = []string{hostpatch.GroupDevops, hostpatch.GroupDeveloper, hostpatch.GroupStandart}

// The delays keep an apply inside the maintenance long enough for the scenario's own writes. The
// widening/narrowing scenarios delay the helper oneshot (before configtest), so Headscale keeps
// answering the fresh reads the gate needs while the maintenance is open; the restart-resume
// scenario delays Headscale's own start, which is enough there because it never reads the gate.
const (
	f3bApplyDelay   = 40 * time.Second
	f3bRestartDelay = 30 * time.Second
)

// f3bUser is a lab Zitadel user linked to a Headscale user in the host lab, the way an OIDC sign-in
// would link it.
type f3bUser struct {
	zitadelID string
	hsName    string
}

// user creates the Zitadel user (deleted at the end) and the linked Headscale user (deleted at the
// end). SetProviderID restarts Headscale, so users are created before any maintenance opens.
func (s *f3bStack) user(name, role string) f3bUser {
	s.t.Helper()
	zid := s.l.createUserWithRole(s.t, role)
	hsName := fmt.Sprintf("f3b024-%s-%d", name, time.Now().UnixNano()%1_000_000)
	s.hl.CreateUser(s.t, hsName)
	s.hl.SetProviderID(s.t, hsName, s.l.zitadelProviderID(zid))
	return f3bUser{zitadelID: zid, hsName: hsName}
}

// node registers a lab node under the user (deleted at the end).
func (s *f3bStack) node(name string, u f3bUser, tag string) uint64 {
	s.t.Helper()
	return s.hl.NewNode(s.t, u.hsName, name, tag)
}

// nodeInfo reads one lab node through the narrow client.
func (s *f3bStack) nodeInfo(id uint64) headscale.Node {
	s.t.Helper()
	nodes, err := s.hl.Client().ListNodes(context.Background())
	if err != nil {
		s.t.Fatalf("list the lab nodes: %v", err)
	}
	for _, n := range nodes {
		if n.ID == id {
			return n
		}
	}
	s.t.Fatalf("lab node %d is gone", id)
	return headscale.Node{}
}

// nodeGone reports whether the node no longer exists.
func (s *f3bStack) nodeGone(id uint64) bool {
	nodes, err := s.hl.Client().ListNodes(context.Background())
	if err != nil {
		s.t.Fatalf("list the lab nodes: %v", err)
	}
	for _, n := range nodes {
		if n.ID == id {
			return false
		}
	}
	return true
}

// nodeExpired reports whether the node's expiry is in the past.
func nodeExpired(n headscale.Node) bool { return n.Expiry != nil && n.Expiry.Before(time.Now()) }

// deviceFields reads the hidden fields a device's detail page posts back.
func (s *f3bStack) deviceFields(id uint64, extra url.Values) url.Values {
	s.t.Helper()
	form := formOf{s.ui.getOK(devicePath(id, ""))}
	v := url.Values{
		"expected":       {form.value("expected")},
		"current_name":   {form.value("current_name")},
		"current_expiry": {form.value("current_expiry")},
	}
	if v.Get("expected") == "" {
		s.t.Fatalf("the detail page of device %d offers no form version", id)
	}
	for k, vals := range extra {
		v[k] = vals
	}
	return v
}

// deviceAction posts one device action with the page's own version stamp.
func (s *f3bStack) deviceAction(id uint64, suffix string, extra url.Values) (int, string) {
	s.t.Helper()
	return s.ui.post(devicePath(id, suffix), s.deviceFields(id, extra))
}

// policyGroups reads the groups section of the lab policy.
func (s *f3bStack) policyGroups() map[string][]string {
	s.t.Helper()
	p, err := s.hl.Client().GetPolicy(context.Background())
	if err != nil {
		s.t.Fatalf("read the lab policy: %v", err)
	}
	return hsstack.ParsePolicyGroups(s.t, p.Text)
}

// waitGroupMember triggers reconciles until the Zitadel user is (not) in the role's group.
func (s *f3bStack) waitGroupMember(role, zitadelID string, want bool) {
	s.t.Helper()
	member := s.l.providerID(zitadelID)
	if err := poll(s.t, 90*time.Second, func() (bool, error) {
		s.triggerSync()
		return containsString(s.policyGroups()["group:"+role], member) == want, nil
	}); err != nil {
		s.t.Fatalf("group:%s membership of %s never became %v: %v", role, zitadelID, want, err)
	}
}

// auditID returns the newest audit event id, or 0.
func (s *f3bStack) auditID() int {
	return s.proc.queryInt(s.t, `SELECT COALESCE(MAX(id), 0) FROM audit_events`)
}

// auditHasAfter reports whether an event with a matching diff exists after id.
func (s *f3bStack) auditHasAfter(event string, afterID int, like string) bool {
	n := s.proc.queryInt(s.t,
		`SELECT count(*) FROM audit_events WHERE event = ? AND id > ? AND diff LIKE ?`,
		event, afterID, "%"+like+"%")
	return n > 0
}

// applyWidening opens the maintenance with the widest group list.
func (s *f3bStack) applyWidening() {
	s.t.Helper()
	s.enableWriteSwitch()
	s.applyOK(f3bAllGroups)
}

// waitMaintenanceActive waits until the durable flag is active.
func (s *f3bStack) waitMaintenanceActive() {
	s.t.Helper()
	s.waitMaintState(maintenance.Active)
}

// waitNoUncertainty drives reconciles until no unresolved write outcome (an unverified admin write
// or a key revocation) is open. Creating lab users restarts Headscale; a webhook-triggered reconcile
// that lands in the restart records a transient read failure, and an open one would refuse the
// maintenance start (the intended AC7 behaviour). Scenarios that want a clean flag wait it out first.
func (s *f3bStack) waitNoUncertainty() {
	s.t.Helper()
	if err := poll(s.t, 150*time.Second, func() (bool, error) {
		s.triggerSync()
		n := s.proc.queryInt(s.t,
			`SELECT count(*) FROM alerts WHERE resolved_at IS NULL AND kind IN ('key_revoke_failed', 'headscale_admin_unverified')`)
		return n == 0, nil
	}); err != nil {
		s.t.Fatalf("an unresolved write outcome stayed open: %v", err)
	}
}

// TestF3b_E2E_ApplyAllowedGroups is AC1: an approved preview of ["devops","developer","standart"]
// succeeds, only oidc.allowed_groups changes, Headscale stays healthy and the started/finished audit
// records exist.
func TestF3b_E2E_ApplyAllowedGroups(t *testing.T) {
	s := newF3bStack(t)
	s.enableWriteSwitch()

	before := hostlab.ConfigBytes(t, s.hl)
	s.applyOK(f3bAllGroups)

	state, code := s.waitHostResult()
	if state != hostpatch.StateSucceeded || code != "" {
		t.Fatalf("result = %s/%s, want succeeded", state, code)
	}
	res := s.lastResult()
	if res.ConfigChanged == nil || !*res.ConfigChanged || !res.HealthVerified {
		t.Fatalf("config_changed/health = %v/%v, want true/true", res.ConfigChanged, res.HealthVerified)
	}

	rev, err := hostpatch.BaseRev(f3bAllGroups)
	if err != nil {
		t.Fatal(err)
	}
	st := s.waitStatus(rev)
	if !equalGroupList(st.AllowedGroups, f3bAllGroups) {
		t.Fatalf("status groups = %v, want %v", st.AllowedGroups, f3bAllGroups)
	}

	// Only oidc.allowed_groups changed: the helper's own candidate is the whole new file.
	wantCand, err := hshelper.Candidate(before, f3bAllGroups)
	if err != nil {
		t.Fatalf("build the candidate: %v", err)
	}
	if got := hostlab.ConfigBytes(t, s.hl); !bytes.Equal(got, wantCand) {
		t.Fatalf("the live config is not the candidate:\n--- got ---\n%s", got)
	}
	if got := hostlab.HealthCode(s.hl); got != http.StatusOK {
		t.Fatalf("headscale /health = %d, want 200", got)
	}

	target := "request:" + res.RequestID
	if n := s.proc.queryInt(t, `SELECT count(*) FROM audit_events WHERE event = 'headscale.config.started' AND target = ?`, target); n != 1 {
		t.Errorf("started audit records for %s = %d, want 1", target, n)
	}
	if n := s.proc.queryInt(t, `SELECT count(*) FROM audit_events WHERE event = 'headscale.config.finished' AND target = ? AND result = 'succeeded'`, target); n != 1 {
		t.Errorf("finished audit records for %s = %d, want 1 succeeded", target, n)
	}
	s.waitMaintOffRetrying()

	// AC1's "the UI shows succeeded": fetch the config page and check the rendered last result, not
	// just the stored row (hs_config.templ renders "Son işlem ... durum succeeded").
	page := s.ui.getOK("/headscale/config")
	mustContain(t, "config page", page, "Son işlem", "succeeded")
}

// TestF3b_E2E_MaintenanceBlocksWidening is AC2: while the maintenance is open, every widening write
// is refused with "bakım sürüyor" and Headscale / the DNS file are unchanged.
func TestF3b_E2E_MaintenanceBlocksWidening(t *testing.T) {
	s := newF3bStack(t)
	ops := s.user("ops", "devops")
	laptop := s.node("laptop", ops, "")
	gw := s.node("gw", ops, f3SharedTag)
	// The locked policy tests resolve the server and k8s tags to real node addresses; without them a
	// policy save is refused at validation before it can reach the maintenance gate.
	s.node("srv", ops, f3ServerTag)
	s.node("k8s", ops, f3K8sTag)
	s.hl.SetNodeRoutableIPs(t, "gw", []string{"10.88.0.0/24"})

	// An expiry to extend, set before the maintenance (a widening write while the flag is off).
	future := time.Now().UTC().Add(48 * time.Hour).Format("2006-01-02T15:04")
	if code, body := s.deviceAction(laptop, "/expiry", url.Values{"expiry": {future}}); code != http.StatusOK {
		t.Fatalf("set the box's expiry: status %d: %s", code, excerpt(body))
	}

	// Capture the version stamps the maintenance will make stale for a fresh read.
	laptopExpected := s.deviceFields(laptop, nil).Get("expected")
	reopen := formOf{s.ui.getOK(devicePath(laptop, "/reopen"))}
	tags := formOf{s.ui.getOK(devicePath(gw, "/tags"))}
	routes := formOf{s.ui.getOK(devicePath(gw, "/routes"))}

	beforeLaptop := s.nodeInfo(laptop)
	beforeGW := s.nodeInfo(gw)

	// Keep the maintenance open while Headscale keeps answering, so the gate (not a read failure)
	// is what the writers hit.
	s.waitNoUncertainty()
	s.injectFault(hostlab.FaultHelperDelay(t, s.hl, f3bApplyDelay))
	s.applyWidening()
	s.waitMaintenanceActive()

	// Each widening op must be refused and leave the world alone. The maintenance band carries "bakım
	// sürüyor" on every Headscale page, so the response body is not evidence; the executor's audit
	// row is. Each op's refusal is asserted with the same audit helper as tags/routes below.

	// Reopen.
	beforeID := s.auditID()
	if code, body := s.ui.post(devicePath(laptop, "/reopen/apply"), url.Values{
		"expected": {reopen.value("expected")}, "current_name": {reopen.value("current_name")},
		"current_expiry": {reopen.value("current_expiry")}, "confirm": {reopen.value("confirm")},
		"expiry": {time.Now().UTC().Add(72 * time.Hour).Format("2006-01-02T15:04")},
	}); code != http.StatusConflict {
		t.Fatalf("reopen under maintenance: status %d, body %s", code, excerpt(body))
	}
	if !s.auditHasAfter("headscale.node.reopen", beforeID, "bakım sürüyor") {
		t.Errorf("no headscale.node.reopen refusal with 'bakım sürüyor' was recorded")
	}
	if n := s.nodeInfo(laptop); !equalTimes(n.Expiry, beforeLaptop.Expiry) {
		t.Errorf("the reopen changed the node expiry under maintenance")
	}

	// Tag change.
	beforeID = s.auditID()
	if code, body := s.ui.post(devicePath(gw, "/tags"), url.Values{"version": {tags.value("version")}, "tag": {f3SharedTag}}); code != http.StatusForbidden {
		t.Fatalf("tag change under maintenance: status %d: %s", code, excerpt(body))
	}
	if !s.auditHasAfter("headscale.node.tags", beforeID, "bakım sürüyor") {
		t.Errorf("no headscale.node.tags refusal with 'bakım sürüyor' was recorded")
	}
	if n := s.nodeInfo(gw); !equalStrings(n.Tags, beforeGW.Tags) {
		t.Errorf("the tag change went through under maintenance: %v -> %v", beforeGW.Tags, n.Tags)
	}

	// Route approval.
	beforeID = s.auditID()
	if code, _ := s.ui.post(devicePath(gw, "/routes"), url.Values{"version": {routes.value("version")}, "route": {"10.88.0.0/24"}}); code != http.StatusConflict {
		t.Fatalf("route approval under maintenance: status %d", code)
	}
	if !s.auditHasAfter("headscale.node.routes", beforeID, "bakım sürüyor") {
		t.Errorf("no headscale.node.routes refusal with 'bakım sürüyor' was recorded")
	}
	if got := s.hl.ApprovedRoutes(t, gw); len(got) != 0 {
		t.Errorf("the route was approved under maintenance: %v", got)
	}

	// Pre-auth key creation.
	beforeKeys := s.hl.PreAuthKeyCount(t)
	beforeID = s.auditID()
	if code, body := s.ui.post("/headscale/keys/preauth/create", url.Values{"tags": {f3SharedTag}, "expires_in": {"2h"}}); code != http.StatusBadRequest {
		t.Fatalf("pre-auth create under maintenance: status %d: %s", code, excerpt(body))
	}
	if !s.auditHasAfter("headscale.preauth.create", beforeID, "bakım sürüyor") {
		t.Errorf("no headscale.preauth.create refusal with 'bakım sürüyor' was recorded")
	}
	if got := s.hl.PreAuthKeyCount(t); got != beforeKeys {
		t.Errorf("a pre-auth key was created under maintenance: %d -> %d", beforeKeys, got)
	}

	// Expiry extension.
	beforeID = s.auditID()
	later := time.Now().UTC().Add(96 * time.Hour).Format("2006-01-02T15:04")
	if code, body := s.ui.post(devicePath(laptop, "/expiry"), url.Values{"expected": {laptopExpected}, "expiry": {later}}); code != http.StatusConflict {
		t.Fatalf("expiry extension under maintenance: status %d: %s", code, excerpt(body))
	}
	if !s.auditHasAfter("headscale.node.expiry", beforeID, "bakım sürüyor") {
		t.Errorf("no headscale.node.expiry refusal with 'bakım sürüyor' was recorded")
	}
	if n := s.nodeInfo(laptop); !equalTimes(n.Expiry, beforeLaptop.Expiry) {
		t.Errorf("the expiry was extended under maintenance")
	}

	// Policy save: the audit names the refusal and the live policy text is unchanged (nothing was
	// written); the band text alone cannot prove the second half.
	policyBefore, err := s.hl.Client().GetPolicy(context.Background())
	if err != nil {
		t.Fatalf("read the live policy before the save: %v", err)
	}
	beforeID = s.auditID()
	code, body := s.savePolicyEdit()
	if !s.auditHasAfter("policy.apply_refused", beforeID, "bakım sürüyor") {
		t.Errorf("no policy.apply_refused with 'bakım sürüyor' was recorded (save status %d: %s)", code, excerpt(body))
	}
	policyAfter, err := s.hl.Client().GetPolicy(context.Background())
	if err != nil {
		t.Errorf("read the live policy after the save: %v", err)
	} else if policyAfter.Text != policyBefore.Text {
		t.Errorf("the refused policy save changed the live policy")
	}

	// The manual DNS write (H-06) needs the F2 site layer; it is exercised by
	// TestF3b_MaintenanceBlocksDNSWrite, which runs the same gate on a stack that carries it and
	// runs under `make e2e` (it does not need the host lab).

	// Let the helper finish and the success reconcile close the maintenance before clean-up restores
	// the config (otherwise the still-running helper would write it back afterwards).
	if state, _ := s.waitHostResult(); state != hostpatch.StateSucceeded {
		t.Fatalf("the apply did not succeed: %s", state)
	}
	s.waitMaintOffRetrying()

	// Positive control: with the maintenance closed the same widening writes succeed, so the refusals
	// above were the gate and not an unrelated guard (a stale stamp or a validation error would also
	// produce the refusal status codes).
	beforeKeys = s.hl.PreAuthKeyCount(t)
	if code, body := s.ui.post("/headscale/keys/preauth/create", url.Values{"tags": {f3SharedTag}, "expires_in": {"2h"}}); code != http.StatusOK {
		t.Fatalf("pre-auth create after the maintenance closed: status %d: %s", code, excerpt(body))
	}
	if got := s.hl.PreAuthKeyCount(t); got != beforeKeys+1 {
		t.Errorf("the pre-auth key was not created after the maintenance closed: %d -> %d", beforeKeys, got)
	}
	later = time.Now().UTC().Add(120 * time.Hour).Format("2006-01-02T15:04")
	if code, body := s.ui.post(devicePath(laptop, "/expiry"), url.Values{"expected": {s.deviceFields(laptop, nil).Get("expected")}, "expiry": {later}}); code != http.StatusOK {
		t.Fatalf("expiry extension after the maintenance closed: status %d: %s", code, excerpt(body))
	}
	if n := s.nodeInfo(laptop); n.Expiry == nil || !n.Expiry.After(*beforeLaptop.Expiry) {
		t.Errorf("the expiry was not extended after the maintenance closed: %v", n.Expiry)
	}

	// Reopen positive control (F3b-027 AC6): refused under maintenance above, the same operation
	// succeeds once the flag is off. A fresh form carries the current node version, and the effect is
	// verified on the node, not only by the response status.
	reopenExpiry := time.Now().UTC().Add(144 * time.Hour).Format("2006-01-02T15:04")
	wantedReopen, err := time.Parse("2006-01-02T15:04", reopenExpiry)
	if err != nil {
		t.Fatalf("parse the reopen expiry: %v", err)
	}
	reopenAfter := formOf{s.ui.getOK(devicePath(laptop, "/reopen"))}
	if code, body := s.ui.post(devicePath(laptop, "/reopen/apply"), url.Values{
		"expected":       {reopenAfter.value("expected")},
		"current_name":   {reopenAfter.value("current_name")},
		"current_expiry": {reopenAfter.value("current_expiry")},
		"confirm":        {reopenAfter.value("confirm")},
		"expiry":         {reopenExpiry},
	}); code != http.StatusOK {
		t.Fatalf("reopen after the maintenance closed: status %d: %s", code, excerpt(body))
	}
	if n := s.nodeInfo(laptop); n.Expiry == nil || n.Expiry.Sub(wantedReopen).Abs() > time.Minute {
		t.Errorf("the reopen did not set the requested expiry: got %v, want %v", n.Expiry, wantedReopen)
	}
}

// TestF3b_E2E_MaintenanceAllowsNarrowing is AC3: in the same maintenance window, manual expire,
// rename and a role-loss reconcile apply their narrowing writes, while the policy is not written.
func TestF3b_E2E_MaintenanceAllowsNarrowing(t *testing.T) {
	s := newF3bStack(t)
	ops := s.user("ops", "devops")
	target := s.user("target", "standart")
	for i := range 3 {
		s.user(fmt.Sprintf("pad%d", i), "standart")
	}
	phone := s.node("phone", ops, "")
	tablet := s.node("tablet", ops, "")
	roleNode := s.node("role-node", target, "")

	// The start-up reconciles put the standart holders into group:standart, so a role loss is a
	// fraction of the group and does not need approval.
	s.waitGroupMember("standart", target.zitadelID, true)

	s.waitNoUncertainty()
	s.injectFault(hostlab.FaultHelperDelay(t, s.hl, f3bApplyDelay))
	s.applyWidening()
	s.waitMaintenanceActive()

	// Manual expire (narrowing) runs under maintenance.
	if code, body := s.deviceAction(phone, "/expire", nil); code != http.StatusOK || !strings.Contains(body, "Apply edildi") {
		t.Fatalf("expire under maintenance: status %d: %s", code, excerpt(body))
	}
	if n := s.nodeInfo(phone); !nodeExpired(n) {
		t.Errorf("the expire did not apply under maintenance")
	}

	// Manual rename (narrowing) runs under maintenance.
	if code, body := s.deviceAction(tablet, "/rename", url.Values{"name": {"tablet-renamed"}}); code != http.StatusOK || !strings.Contains(body, "Apply edildi") {
		t.Fatalf("rename under maintenance: status %d: %s", code, excerpt(body))
	}
	if n := s.nodeInfo(tablet); n.GivenName != "tablet-renamed" {
		t.Errorf("given name after rename = %q, want tablet-renamed", n.GivenName)
	}

	// Role loss: the reconcile expires the node (narrowing) but must not write the policy (widening).
	heldBefore := s.auditID()
	s.l.removeGrant(s.t, target.zitadelID)
	if err := poll(s.t, 120*time.Second, func() (bool, error) {
		s.triggerSync()
		return nodeExpired(s.nodeInfo(roleNode)), nil
	}); err != nil {
		t.Fatalf("the role-loss node was not expired during maintenance: %v", err)
	}
	if !s.auditHasAfter("policy.held", heldBefore, "bakım sürüyor") {
		t.Errorf("no policy.held record naming the maintenance: the reconcile wrote the policy during maintenance")
	}
	// The held reconcile must not have written the policy: the audit row alone cannot prove the live
	// policy was left alone, so check the group itself (the target is still in it).
	if !containsString(s.policyGroups()["group:standart"], s.l.providerID(target.zitadelID)) {
		t.Errorf("the held reconcile wrote the policy: the target left group:standart during maintenance")
	}
	if s.nodeGone(roleNode) {
		t.Errorf("the role-loss node was deleted, want expired")
	}

	if state, _ := s.waitHostResult(); state != hostpatch.StateSucceeded {
		t.Fatalf("the apply did not succeed: %s", state)
	}
	s.waitMaintOffRetrying()
}

// TestF3b_E2E_ReconcileBeforeWriters is AC4: on success the reconcile runs (and writes the pending
// group change) before the maintenance closes, and a widening write sent earlier is refused.
func TestF3b_E2E_ReconcileBeforeWriters(t *testing.T) {
	s := newF3bStack(t)
	target := s.user("target", "standart")
	for i := range 3 {
		s.user(fmt.Sprintf("pad%d", i), "standart")
	}
	s.waitGroupMember("standart", target.zitadelID, true)

	s.waitNoUncertainty()
	s.injectFault(hostlab.FaultHelperDelay(t, s.hl, f3bApplyDelay))
	s.applyWidening()
	s.waitMaintenanceActive()

	// A widening write while the maintenance is open is refused; this is the "before the reconcile"
	// writer that must stay out.
	beforeID := s.auditID()
	if code, body := s.ui.post("/headscale/keys/preauth/create", url.Values{"tags": {f3SharedTag}}); code != http.StatusBadRequest || !strings.Contains(body, "bakım sürüyor") {
		t.Fatalf("the widening write was not refused: status %d: %s", code, excerpt(body))
	}
	if !s.auditHasAfter("headscale.preauth.create", beforeID, "bakım sürüyor") {
		t.Errorf("no widening refusal audit under maintenance")
	}

	// A pending group change: the target loses the role while the maintenance is open.
	s.l.removeGrant(s.t, target.zitadelID)
	heldBefore := s.auditID()
	if err := poll(s.t, 120*time.Second, func() (bool, error) {
		s.triggerSync()
		return s.auditHasAfter("policy.held", heldBefore, "tutuldu"), nil
	}); err != nil {
		t.Fatalf("the role-loss reconcile was never held during maintenance: %v", err)
	}
	if !containsString(s.policyGroups()["group:standart"], s.l.providerID(target.zitadelID)) {
		t.Fatalf("the held reconcile wrote the policy: the target left group:standart during maintenance")
	}

	// The apply succeeds; the closing reconcile writes the pending change and then ends the flag.
	if state, _ := s.waitHostResult(); state != hostpatch.StateSucceeded {
		t.Fatalf("the apply did not succeed: %s", state)
	}
	s.waitMaintOffRetrying()
	if containsString(s.policyGroups()["group:standart"], s.l.providerID(target.zitadelID)) {
		t.Fatalf("the pending group change was not written after success")
	}

	// Audit order: finished -> applied -> closed.
	finished := s.proc.queryInt(t, `SELECT COALESCE(MAX(id), 0) FROM audit_events WHERE event = 'headscale.config.finished'`)
	closed := s.proc.queryInt(t, `SELECT COALESCE(MAX(id), 0) FROM audit_events WHERE event = 'headscale.maintenance.closed'`)
	if finished == 0 || closed == 0 || closed <= finished {
		t.Fatalf("audit order finished=%d closed=%d, want finished < closed", finished, closed)
	}
	if n := s.proc.queryInt(t,
		`SELECT count(*) FROM audit_events WHERE event = 'policy.apply' AND result = 'applied' AND id > ? AND id < ?`,
		finished, closed); n == 0 {
		t.Errorf("no policy.apply between the result and the maintenance close: the reconcile did not run before the writers reopened")
	}
}

// TestF3b_E2E_ContainerRestartResumes is AC5: a restart during the apply keeps the same request ID
// and the flow completes after the binary comes back.
func TestF3b_E2E_ContainerRestartResumes(t *testing.T) {
	s := newF3bStack(t)
	s.injectFault(hostlab.FaultRestartDelay(t, s.hl, f3bRestartDelay))
	s.applyWidening()
	s.waitMaintenanceActive()

	_, reqID, _ := s.maint()
	if reqID == "" {
		t.Fatal("the maintenance opened without a request ID")
	}

	// Restart the binary while the helper is still applying; the store (the flag and the ID) stays.
	s.restart()

	if state, _ := s.waitHostResult(); state != hostpatch.StateSucceeded {
		t.Fatalf("the apply did not succeed after the restart: %s", state)
	}
	res := s.lastResult()
	if res.RequestID != reqID {
		t.Fatalf("result request_id = %q, want the resumed %q", res.RequestID, reqID)
	}
	s.waitMaintOffRetrying()

	rev, err := hostpatch.BaseRev(f3bAllGroups)
	if err != nil {
		t.Fatal(err)
	}
	st := s.waitStatus(rev)
	if !equalGroupList(st.AllowedGroups, f3bAllGroups) {
		t.Fatalf("status groups after the restart = %v, want %v", st.AllowedGroups, f3bAllGroups)
	}
}

// TestF3b_E2E_StaleBaseRejected is AC6: a preview approved after another request changed the host
// config is refused for a stale base_rev and the config does not change.
func TestF3b_E2E_StaleBaseRejected(t *testing.T) {
	s := newF3bStack(t)
	s.enableWriteSwitch()

	base := s.status().BaseRev
	pv := url.Values{}
	for _, g := range f3bAllGroups {
		pv.Add("group", g)
	}
	if code, body := s.ui.post("/headscale/config/preview", pv); code != http.StatusOK {
		t.Fatalf("preview: status %d: %s", code, excerpt(body))
	}

	// Another request changes the host config (here: the same helper path, out of band).
	other := []string{hostpatch.GroupDevops, hostpatch.GroupDeveloper}
	hostlab.SetGroups(t, s.hl, other)
	wantOther, err := hshelper.Candidate(hostlab.ConfigBytes(t, s.hl), other)
	if err != nil {
		t.Fatalf("build the other candidate: %v", err)
	}
	if s.status().BaseRev == base {
		t.Fatal("the other request did not change base_rev")
	}

	form := url.Values{"confirm": {"1"}, "base_rev": {base}}
	for _, g := range f3bAllGroups {
		form.Add("group", g)
	}
	code, body := s.ui.post("/headscale/config/apply", form)
	if code != http.StatusConflict || !strings.Contains(body, "farklı") {
		t.Fatalf("stale apply: status %d, want a stale-base refusal: %s", code, excerpt(body))
	}
	if got := hostlab.ConfigBytes(t, s.hl); !bytes.Equal(got, wantOther) {
		t.Fatalf("the stale apply changed the config")
	}
	maintState(t, s, maintenance.Off)
}

// TestF3b_E2E_UnknownPolicyBlocksStart is AC7: with an unresolved policy write (F3-029) a new H-07
// request is not started and the maintenance stays off.
func TestF3b_E2E_UnknownPolicyBlocksStart(t *testing.T) {
	s := newF3bStack(t)
	s.enableWriteSwitch()

	// Fabricate the F3-029 state: a newer unknown revision whose result was never verified.
	live, err := s.hl.Client().GetPolicy(context.Background())
	if err != nil {
		t.Fatalf("read the live policy: %v", err)
	}
	if _, err := s.proc.storeDB(t).Exec(
		`INSERT INTO policy_revisions (raw, raw_hash, canonical_hash, source, actor, created_at, apply_status, apply_detail)
		 VALUES (?, ?, ?, 'sync', 'system:sync', ?, 'unknown', 'f3b024 fixture')`,
		live.Text, "f3b024-unknown", "f3b024-unknown", nowStamp(),
	); err != nil {
		t.Fatalf("fixture the unknown revision: %v", err)
	}

	base := s.status().BaseRev
	pv := url.Values{}
	for _, g := range f3bAllGroups {
		pv.Add("group", g)
	}
	code, body := s.ui.post("/headscale/config/preview", pv)
	if code != http.StatusOK {
		t.Fatalf("preview: status %d: %s", code, excerpt(body))
	}
	form := url.Values{"confirm": {"1"}, "base_rev": {base}}
	for _, g := range f3bAllGroups {
		form.Add("group", g)
	}
	code, body = s.ui.post("/headscale/config/apply", form)
	if code != http.StatusConflict || !strings.Contains(body, "belirsiz") {
		t.Fatalf("apply with an uncertain policy: status %d, want a refusal naming the uncertainty: %s", code, excerpt(body))
	}
	maintState(t, s, maintenance.Off)
	if reqs, _ := os.ReadDir(s.hl.RequestsDir()); len(reqs) != 0 {
		t.Fatalf("the refused start published %d request files", len(reqs))
	}
}

// TestF3b_E2E_NoSecretsAnywhere is AC8: after an apply, the request/result files, the audit table,
// the artifact git repository and the application log hold no OIDC client secret, config content or
// pre-auth key/token.
func TestF3b_E2E_NoSecretsAnywhere(t *testing.T) {
	s := newF3bStack(t)
	s.enableWriteSwitch()
	s.applyOK(f3bAllGroups)
	if state, _ := s.waitHostResult(); state != hostpatch.StateSucceeded {
		t.Fatalf("the apply did not succeed: %s", state)
	}
	s.waitMaintOffRetrying()
	s.proc.stop(t)

	oidcSecret := s.l.envFileValue(t, "HEADSCALE_OIDC_CLIENT_SECRET")
	webhookKey := s.l.readSecret(t, seed.WebhookSigningKeyFile)
	config := string(hostlab.ConfigBytes(t, s.hl))
	secrets := map[string]string{
		"the OIDC client secret":   oidcSecret,
		"the webhook signing key":  webhookKey,
		"the bootstrap PAT":        s.l.pat,
		"the raw Headscale config": config,
		// The whole config may never sit in one file, so the raw-content check alone could be
		// vacuous. These distinctive Headscale-only lines catch the config leaking in pieces (they
		// do not appear in tagcess's own config, unlike the shared issuer or client id).
		"the config's client_secret_path line": "client_secret_path: /etc/headscale/oidc_client_secret",
		"the config's base_domain line":        "base_domain: ts.tagcess.test",
	}

	// detect reports the secrets found in data (empty means clean). It does not fail the test, so the
	// mutation proof below can ask the same detector whether it catches a planted leak.
	detect := func(data []byte) []string {
		var hits []string
		for name, sec := range secrets {
			if sec != "" && strings.Contains(string(data), sec) {
				hits = append(hits, name)
			}
		}
		if preAuthSecretRE.Match(data) {
			hits = append(hits, "a full pre-auth key")
		}
		return hits
	}
	scan := func(where string, data []byte) {
		for _, name := range detect(data) {
			t.Errorf("%s holds %s", where, name)
		}
	}
	for _, dir := range []string{s.hl.RequestsDir(), s.hl.ResultsDir()} {
		ents, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range ents {
			b, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				t.Fatalf("read %s/%s: %v", dir, e.Name(), err)
			}
			scan(dir+"/"+e.Name(), b)
		}
	}
	// The audit table and the stored host result explicitly (the DB file scan below covers them too).
	for name, sec := range secrets {
		if sec == "" {
			continue
		}
		if n := s.proc.queryInt(t, `SELECT count(*) FROM audit_events WHERE instr(diff, ?) > 0`, sec); n > 0 {
			t.Errorf("the audit table holds %s", name)
		}
		if n := s.proc.queryInt(t, `SELECT count(*) FROM headscale_maintenance WHERE instr(last_host_result, ?) > 0`, sec); n > 0 {
			t.Errorf("the stored host result holds %s", name)
		}
	}
	// MUTATION PROOF: a secret planted inside the scanned tree must be found, so the scan is not
	// vacuous. The positive control removes the file again before the real scan.
	leakPath := filepath.Join(s.proc.dataDir, "leak.txt")
	if err := os.WriteFile(leakPath, []byte(oidcSecret), 0o600); err != nil {
		t.Fatal(err)
	}
	caught := false
	if err := filepath.Walk(s.proc.dataDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || info.Mode()&os.ModeSocket != 0 {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr == nil && len(detect(b)) > 0 {
			caught = true
		}
		return nil
	}); err != nil {
		t.Fatalf("walk the data directory for the mutation: %v", err)
	}
	if !caught {
		t.Fatalf("mutation not caught: the scan missed the planted OIDC secret")
	}
	if err := os.Remove(leakPath); err != nil {
		t.Fatal(err)
	}
	// The whole data directory (store, logs buffer below, artifacts). A file that cannot be read is
	// a failure, not a silent skip: an unreadable file could be hiding a secret (F3b-027 AC6).
	if err := filepath.Walk(s.proc.dataDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("walk %s: %w", path, err)
		}
		if info.IsDir() || info.Mode()&os.ModeSocket != 0 {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return fmt.Errorf("read %s: %w", path, rerr)
		}
		scan(path, b)
		return nil
	}); err != nil {
		t.Fatalf("walk the data directory: %v", err)
	}
	scan("the application log", s.proc.stderr.Bytes())

	gitDir := filepath.Join(s.proc.dataDir, "artifact-git")
	if _, err := os.Stat(gitDir); err != nil {
		t.Fatalf("the artifact git repository is missing from %s (main.go always creates it): %v", s.proc.dataDir, err)
	}
	out, err := execGit(gitDir, "log", "-p", "--all")
	if err != nil {
		t.Fatalf("read the artifact git history: %v", err)
	}
	scan("the artifact git history", []byte(out))
}

// savePolicyEdit posts a hand-made policy save (a new host) with the hash the handler checks, so the
// pipeline's maintenance gate — not the UI's preview form — is what has to refuse it.
func (s *f3bStack) savePolicyEdit() (int, string) {
	s.t.Helper()
	live, err := s.hl.Client().GetPolicy(context.Background())
	if err != nil {
		s.t.Fatalf("read the live policy: %v", err)
	}
	edited := strings.Replace(live.Text, `"tagOwners"`, `"hosts": {"f3b024-h": "100.64.0.240"}, "tagOwners"`, 1)
	if edited == live.Text {
		s.t.Fatalf("the policy fixture has no tagOwners to edit")
	}
	return s.ui.post("/headscale/policy/save", url.Values{
		"text":        {edited},
		"base_hash":   {policyrev.HashRaw(live.Text)},
		"report_hash": {policyrev.HashRaw(edited)},
	})
}

// equalTimes compares two nullable expiries.
func equalTimes(a, b *time.Time) bool {
	switch {
	case a == nil && b == nil:
		return true
	case a == nil || b == nil:
		return false
	default:
		return a.Equal(*b)
	}
}

// equalStrings compares two string slices.
func equalStrings(a, b []string) bool { return equalGroupList(a, b) }

// TestF3b_MaintenanceBlocksDNSWrite is AC2's manual-DNS half: the H-06 manual DNS write is a
// widening write and must be refused while the durable maintenance flag is active, leaving the DNS
// file alone. It needs the F2 site layer (locked system sites), so it runs on the F2 stack; the flag
// is set the way an open H-07 request sets it, which is what the site pipeline's gate reads.
// It is deliberately not named TestF3b_E2E_*: it does not need the host lab, so `make e2e` runs it
// (F3b-027 AC6).
func TestF3b_MaintenanceBlocksDNSWrite(t *testing.T) {
	// The F2 fixture watches the compose DNS file; the local compose stack is not needed for this
	// scenario, only the file's directory, so create an empty one when `make lab-up` has not.
	dnsPath := filepath.Join(repoRoot(), "test", "compose", "dns", "extra-records.json")
	if _, err := os.Stat(dnsPath); os.IsNotExist(err) {
		if err := os.MkdirAll(filepath.Dir(dnsPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dnsPath, []byte("[]"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	s := newF2Stack(t, f2Options{})

	now := nowStamp()
	if _, err := s.proc.storeDB(t).Exec(
		`UPDATE headscale_maintenance SET state = 'active', request_id = ?, actor = ?, started_at = ?, updated_at = ?, close_note = '' WHERE id = 1`,
		"f3b02400-0000-4000-8000-000000000000", e2eOperator, now, now,
	); err != nil {
		t.Fatalf("open the maintenance flag: %v", err)
	}
	before, err := os.ReadFile(s.dnsFile)
	if err != nil {
		t.Fatalf("read the DNS file: %v", err)
	}

	form := url.Values{"action": {"add"}, "name": {"f3b024-dns.example.com"}, "value": {"100.64.0.55"}}
	code, body := s.ui.post("/headscale/dns/preview", form)
	if code != http.StatusOK {
		t.Fatalf("DNS preview under maintenance: status %d: %s", code, excerpt(body))
	}
	request, version := inputValue(body, "request"), inputValue(body, "plan_version")
	if request == "" || version == "" {
		t.Fatalf("the preview offered no plan: %s", excerpt(body))
	}
	code, body = s.ui.post("/headscale/dns/approve", url.Values{"request": {request}, "plan_version": {version}})
	res := parseResult(code, body)
	// The maintenance band renders "bakım sürüyor" on every page, so the raw body is not evidence;
	// the recorded change result is. The site pipeline records a blocked maintenance refusal as a
	// failed change whose reason names the maintenance (site.go conclude), which parseResult reads
	// from the change row, not from the band.
	if res.applied || !strings.Contains(res.reason, "bakım sürüyor") {
		t.Fatalf("DNS approve under maintenance: status %d, change %q, reason %q: %s", code, res.changeStatus, res.reason, excerpt(body))
	}
	after, err := os.ReadFile(s.dnsFile)
	if err != nil {
		t.Fatalf("read the DNS file after the refusal: %v", err)
	}
	if !bytes.Equal(after, before) {
		t.Errorf("the DNS file changed under maintenance")
	}
}
