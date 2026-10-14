//go:build integration

// Integration test for F3-010 AC6 against a disposable database-mode Headscale (test/compose/hsstack,
// needs only local Docker): `go test -tags=integration ./internal/policywriter/...`. Zitadel is a fake;
// the writer, the pipeline and the revision store are the real ones.
package policywriter

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/headscale"
	"github.com/nesiler/tagcess/internal/policydoc"
	"github.com/nesiler/tagcess/internal/policyrev"
	"github.com/nesiler/tagcess/internal/store"
	"github.com/nesiler/tagcess/internal/sync"
	"github.com/nesiler/tagcess/internal/zitadel"
	"github.com/nesiler/tagcess/test/compose/hsstack"
)

// Host aliases stand in for groups and tags so the locked tests resolve without registered nodes (the
// same device F3-006's integration tests use); real groups and nodes are proved in F3-026/F3-028.
var integrationLocked = policydoc.LockedConfig{
	DevopsGroup: "devops-host", ServerTag: "vpn-host", UIPort: 443, K8sTag: "k8s-host", WebhookPort: 9000,
	SSHSrc: "devops-host", SSHDst: []string{"vpn-host", "k8s-host"}, SSHPort: 22,
}

// richPolicy has every section the editor does not own, comments in odd places and trailing commas.
const richPolicy = `// tagcess integration policy
{
  "groups": {},
  "hosts": {
    "devops-host": "100.64.9.1", // devops laptop
    "vpn-host": "100.64.9.2",
    "k8s-host": "100.64.9.3",
  },
  "acls": [
    // devops reach the servers
    { "action": "accept", "src": ["devops-host"], "dst": ["vpn-host:443,22", "k8s-host:22"] },
    { "action": "accept", "src": ["k8s-host"], "dst": ["vpn-host:9000"] },
  ],
  "grants": [
    { "src": ["devops-host"], "dst": ["k8s-host"], "ip": ["*"] }, // everything for devops
  ],
  "ssh": [
    { "action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self"], "users": ["autogroup:nonroot"] },
  ],
  "nodeAttrs": [
    { "target": ["autogroup:member"], "attr": ["nodeAttr:integration"] },
  ],
  "tests": [
    { "src": "devops-host", "accept": ["k8s-host:22"] }, // user test
  ],
}
`

// seedHeadscaleUsers gives the Zitadel users a Headscale user with the matching provider ID: only role
// holders Headscale knows are written into a group (F3-031). Each call restarts Headscale.
func seedHeadscaleUsers(t *testing.T, stack *hsstack.Stack, ids ...string) {
	t.Helper()
	for _, id := range ids {
		stack.CreateUser(t, id)
		stack.SetProviderID(t, id, testIssuer+"/"+id)
	}
}

// AC6: the text in Headscale after a save is byte for byte the composed text: Zitadel's groups,
// the locked tests added, and grants, ssh, nodeAttrs, tests and every comment kept.
func TestPolicyWriter_Integration_RoundTripLossless(t *testing.T) {
	ctx := context.Background()
	stack := hsstack.Start(t)
	seedHeadscaleUsers(t, stack, "u01", "u02")
	hs := stack.Client()
	if _, err := hs.SetPolicy(ctx, richPolicy); err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "tagcess.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if _, err := st.DB().ExecContext(ctx, `UPDATE settings SET value = 'false' WHERE key = 'dry_run'`); err != nil {
		t.Fatal(err)
	}
	revs := policyrev.New(st.Queries())
	pipe := change.New(hs, st.Queries(), audit.New(st.Queries()), st).WithRevisions(NewRecorder(revs))
	z := &fakeZ{drop: map[string]bool{}, grants: []zitadel.Grant{
		{UserID: "u01", Role: "devops"}, {UserID: "u01", Role: "dev"}, {UserID: "u02", Role: "dev"},
	}}
	rec, err := sync.NewReconciler(sync.ReconcilerConfig{
		Zitadel: z, Headscale: hs, Pipeline: pipe, Queries: st.Queries(), DryRun: st, Issuer: testIssuer,
	})
	if err != nil {
		t.Fatal(err)
	}
	w, err := New(Config{Evaluator: rec, Pipeline: pipe, Revisions: revs, Checker: hs, Locked: integrationLocked})
	if err != nil {
		t.Fatal(err)
	}

	live, err := hs.GetPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if live.Text != richPolicy {
		t.Fatalf("Headscale does not return the stored text byte for byte:\n got %q\nwant %q", live.Text, richPolicy)
	}
	text := strings.Replace(live.Text, "// devops reach the servers", "// devops reach the servers (edited)", 1)

	res, err := w.Save(ctx, SaveRequest{Actor: devops, Text: text, BaseHash: policyrev.HashRaw(live.Text)})
	if err != nil {
		t.Fatalf("Save: %v (report %+v)", err, res.Report.Stages)
	}
	if !res.Change.Applied {
		t.Fatalf("result = %+v, want applied", res.Change)
	}

	got, err := hs.GetPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := rec.Evaluate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	in := ev.Input
	in.Policy = []byte(text)
	composed, err := sync.Target(in)
	if err != nil {
		t.Fatal(err)
	}
	want, err := policydoc.Inject(string(composed), integrationLocked)
	if err != nil {
		t.Fatal(err)
	}
	if got.Text != want.Text {
		t.Fatalf("Headscale text is not the composed text:\n got %q\nwant %q", got.Text, want.Text)
	}
	for _, keep := range []string{
		"// tagcess integration policy", "// devops laptop", "(edited)", "// everything for devops", "// user test",
		`"grants"`, `"ssh"`, `"nodeAttrs"`, `"tests"`, `/* tagcess:locked */`, member("u01"), member("u02"),
	} {
		if !strings.Contains(got.Text, keep) {
			t.Errorf("the stored policy lost %q:\n%s", keep, got.Text)
		}
	}
	top, err := revs.Get(ctx, res.Revision.ID)
	if err != nil || top.ApplyStatus != policyrev.StatusApplied || top.Raw != got.Text || top.ChangeID != res.Change.ChangeID {
		t.Errorf("revision = %+v (err %v), want applied with the stored text and the change id", top, err)
	}
}

// stopAfterSet is the real Headscale client that, once armed, stops the container right after the
// next SetPolicy has been accepted: the write is committed but its readback cannot be done.
type stopAfterSet struct {
	*headscale.Client
	stack *hsstack.Stack
	t     *testing.T
	armed bool
}

func (s *stopAfterSet) SetPolicy(ctx context.Context, policy string) (headscale.Policy, error) {
	pol, err := s.Client.SetPolicy(ctx, policy)
	if s.armed {
		s.armed = false
		s.stack.Stop(s.t)
	}
	return pol, err
}

// integrationEnv is the real writer, pipeline and revision store over a disposable Headscale seeded
// with richPolicy; Zitadel is the fake.
type integrationEnv struct {
	hs    *stopAfterSet
	stack *hsstack.Stack
	z     *fakeZ
	revs  *policyrev.Repo
	rec   *sync.Reconciler
	w     *Writer
}

func newIntegrationEnv(t *testing.T) *integrationEnv {
	t.Helper()
	ctx := context.Background()
	stack := hsstack.Start(t)
	seedHeadscaleUsers(t, stack, "u01", "u02")
	hs := &stopAfterSet{Client: stack.Client(), stack: stack, t: t}
	if _, err := hs.SetPolicy(ctx, richPolicy); err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "tagcess.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if _, err := st.DB().ExecContext(ctx, `UPDATE settings SET value = 'false' WHERE key = 'dry_run'`); err != nil {
		t.Fatal(err)
	}
	revs := policyrev.New(st.Queries())
	pipe := change.New(hs, st.Queries(), audit.New(st.Queries()), st).WithRevisions(NewRecorder(revs))
	z := &fakeZ{drop: map[string]bool{}, grants: []zitadel.Grant{
		{UserID: "u01", Role: "devops"}, {UserID: "u01", Role: "dev"}, {UserID: "u02", Role: "dev"},
	}}
	rec, err := sync.NewReconciler(sync.ReconcilerConfig{
		Zitadel: z, Headscale: hs, Pipeline: pipe, Queries: st.Queries(), DryRun: st, Issuer: testIssuer,
	})
	if err != nil {
		t.Fatal(err)
	}
	w, err := New(Config{Evaluator: rec, Pipeline: pipe, Revisions: revs, Checker: hs, Locked: integrationLocked})
	if err != nil {
		t.Fatal(err)
	}
	return &integrationEnv{hs: hs, stack: stack, z: z, revs: revs, rec: rec, w: w}
}

// save submits text against the live policy as the editor would.
func (e *integrationEnv) save(t *testing.T, req SaveRequest) SaveResult {
	t.Helper()
	live, err := e.hs.GetPolicy(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	req.Actor, req.BaseHash = devops, policyrev.HashRaw(live.Text)
	res, err := e.w.Save(context.Background(), req)
	if err != nil {
		t.Fatalf("Save: %v (report %+v)", err, res.Report.Stages)
	}
	if !res.Change.Applied {
		t.Fatalf("result = %+v, want applied", res.Change)
	}
	return res
}

// F3-031 AC4: a devops holder who has no Headscale user yet is not written into group:devops, so
// Headscale's tests that resolve the group still pass and the editor can save. Before the fix the
// group carried the member and Headscale refused every write with "user not found".
func TestPolicyWriter_Integration_DevopsWithoutHeadscaleUser(t *testing.T) {
	ctx := context.Background()
	stack := hsstack.Start(t)
	seedHeadscaleUsers(t, stack, "u01")
	// u01 has a laptop, so group:devops resolves to a real address for the test below.
	stack.NewNode(t, "u01", "u01-laptop", "")
	hs := stack.Client()
	// A test and a rule that resolve group:devops; Headscale looks every member up when it runs them.
	text := strings.Replace(richPolicy, `"groups": {}`, `"groups": {"group:devops": ["`+member("u01")+`"]}`, 1)
	text = strings.Replace(text, `  "acls": [`, `  "acls": [
    { "action": "accept", "src": ["group:devops"], "dst": ["k8s-host:22"] },`, 1)
	text = strings.Replace(text, `  "tests": [`, `  "tests": [
    { "src": "group:devops", "accept": ["k8s-host:22"] },`, 1)
	if _, err := hs.SetPolicy(ctx, text); err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "tagcess.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if _, err := st.DB().ExecContext(ctx, `UPDATE settings SET value = 'false' WHERE key = 'dry_run'`); err != nil {
		t.Fatal(err)
	}
	revs := policyrev.New(st.Queries())
	pipe := change.New(hs, st.Queries(), audit.New(st.Queries()), st).WithRevisions(NewRecorder(revs))
	// u03 holds devops in Zitadel but has never logged in to the VPN.
	z := &fakeZ{drop: map[string]bool{}, grants: []zitadel.Grant{
		{UserID: "u01", Role: "devops"}, {UserID: "u03", Role: "devops"},
	}}
	rec, err := sync.NewReconciler(sync.ReconcilerConfig{
		Zitadel: z, Headscale: hs, Pipeline: pipe, Queries: st.Queries(), DryRun: st, Issuer: testIssuer,
	})
	if err != nil {
		t.Fatal(err)
	}
	w, err := New(Config{Evaluator: rec, Pipeline: pipe, Revisions: revs, Checker: hs, Locked: integrationLocked})
	if err != nil {
		t.Fatal(err)
	}

	live, err := hs.GetPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(live.Text, "// devops reach the servers", "// devops reach the servers (edited)", 1)
	res, err := w.Save(ctx, SaveRequest{Actor: devops, Text: edited, BaseHash: policyrev.HashRaw(live.Text)})
	if err != nil {
		t.Fatalf("Save: %v (report %+v)", err, res.Report.Stages)
	}
	if !res.Change.Applied {
		t.Fatalf("result = %+v, want applied", res.Change)
	}
	got, err := hs.GetPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got.Text, member("u01")) {
		t.Errorf("u01 (has a Headscale user) is missing from group:devops:\n%s", got.Text)
	}
	if strings.Contains(got.Text, member("u03")) {
		t.Errorf("u03 has no Headscale user and must not be in a group:\n%s", got.Text)
	}
}

// F3-025 AC9: save A, save B, roll back to A: the live policy is byte for byte A's (the groups and the
// locked tests are rebuilt from today's state, and unchanged here), a Zitadel change in between shows
// up only in the rebuilt groups, and the rollback is a new revision that names A.
func TestPolicyRollback_Integration_RoundTrip(t *testing.T) {
	ctx := context.Background()
	e := newIntegrationEnv(t)

	a := e.save(t, SaveRequest{Text: strings.Replace(richPolicy, "// devops reach the servers", "// version A", 1)})
	b := e.save(t, SaveRequest{Text: strings.Replace(a.Text, "// version A", "// version B", 1)})
	if a.Text == b.Text {
		t.Fatal("A and B are the same text")
	}

	rb := e.save(t, SaveRequest{Text: a.Revision.Raw, Source: policyrev.SourceRollback, RollbackOf: a.Revision.ID, Reason: "geri alma"})
	got, err := e.hs.GetPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.Text != a.Revision.Raw {
		t.Fatalf("live policy after the rollback is not A's text byte for byte:\n got %q\nwant %q", got.Text, a.Revision.Raw)
	}
	if rb.Revision.ID == a.Revision.ID || rb.Revision.Source != policyrev.SourceRollback || rb.Revision.RollbackOf != a.Revision.ID {
		t.Errorf("rollback revision = %+v, want a new rollback of %d", rb.Revision, a.Revision.ID)
	}
	if old, err := e.revs.Get(ctx, a.Revision.ID); err != nil || old != a.Revision {
		t.Errorf("revision A changed: %+v -> %+v (err %v)", a.Revision, old, err)
	}

	// Today's groups win: u02 gets the devops role, then B-state is rolled back to A once more.
	e.z.setGrants(append(e.z.grants, zitadel.Grant{UserID: "u02", Role: "devops"}))
	e.save(t, SaveRequest{Text: strings.Replace(got.Text, "// version A", "// version B", 1)})
	rb2 := e.save(t, SaveRequest{Text: a.Revision.Raw, Source: policyrev.SourceRollback, RollbackOf: a.Revision.ID})
	ev, err := e.rec.Evaluate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	in := ev.Input
	in.Policy = []byte(a.Revision.Raw)
	composed, err := sync.Target(in)
	if err != nil {
		t.Fatal(err)
	}
	want, err := policydoc.Inject(string(composed), integrationLocked)
	if err != nil {
		t.Fatal(err)
	}
	final, err := e.hs.GetPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if final.Text != want.Text || final.Text != rb2.Revision.Raw {
		t.Fatalf("live policy is not A composed with today's groups:\n got %q\nwant %q", final.Text, want.Text)
	}
	if final.Text == a.Revision.Raw {
		t.Error("the groups were not rebuilt: the rollback restored A's old groups")
	}
}

// F3-029 AC8: Headscale is stopped right after it accepted a policy write, before the readback. The
// writer marks the revision unknown and stops writing; when Headscale is back the recovery shows the
// candidate (the last applied revision with today's groups) and applies it on approval, and the live
// policy is the candidate.
func TestRecovery_Integration_StopHeadscaleDuringApply(t *testing.T) {
	ctx := context.Background()
	e := newIntegrationEnv(t)

	a := e.save(t, SaveRequest{Text: strings.Replace(richPolicy, "// devops reach the servers", "// version A", 1)})

	// B is committed by Headscale, which then goes away before the pipeline can read it back.
	liveA, err := e.hs.GetPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	e.hs.armed = true
	res, err := e.w.Save(ctx, SaveRequest{
		Actor: devops, BaseHash: policyrev.HashRaw(liveA.Text),
		Text: strings.Replace(a.Revision.Raw, "// version A", "// version B", 1),
	})
	if !errors.Is(err, ErrNotApplied) || res.Change.Applied || res.Revision.ApplyStatus != policyrev.StatusUnknown {
		t.Fatalf("err = %v, applied = %v, revision = %+v; want ErrNotApplied and an unknown revision", err, res.Change.Applied, res.Revision)
	}

	// Headscale is down: nothing is written, and the recovery is blocked too.
	l, err := e.w.Live(ctx)
	if err != nil || !errors.Is(l.HeadscaleErr, ErrHeadscaleUnavailable) {
		t.Fatalf("Live while down = %+v, %v; want ErrHeadscaleUnavailable", l, err)
	}
	down := SaveRequest{Actor: devops, BaseHash: policyrev.HashRaw(liveA.Text)}
	if _, err := e.w.Save(ctx, down); !errors.Is(err, ErrHeadscaleUnavailable) {
		t.Errorf("Save while down err = %v, want ErrHeadscaleUnavailable", err)
	}
	down.Source = policyrev.SourceRecovery
	if _, err := e.w.Preview(ctx, down); !errors.Is(err, ErrHeadscaleUnavailable) {
		t.Errorf("recovery preview while down err = %v, want ErrHeadscaleUnavailable", err)
	}

	// Headscale is back with B's policy, which no applied revision matches: the state is uncertain, a
	// normal save is refused, the recovery is open.
	e.stack.Restart(t)
	live, err := e.hs.GetPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if live.Text == a.Revision.Raw {
		t.Fatal("setup: Headscale holds A again, the write of B did not commit")
	}
	l, err = e.w.Live(ctx)
	if err != nil || l.Uncertain == "" {
		t.Fatalf("Live after the restart = %+v, %v; want an uncertain state", l, err)
	}
	if _, err := e.w.Save(ctx, SaveRequest{Actor: devops, Text: live.Text, BaseHash: policyrev.HashRaw(live.Text)}); !errors.Is(err, ErrUncertain) {
		t.Errorf("normal save err = %v, want ErrUncertain", err)
	}

	req := SaveRequest{Actor: devops, BaseHash: policyrev.HashRaw(live.Text), Source: policyrev.SourceRecovery}
	cand, err := e.w.Preview(ctx, req)
	if err != nil {
		t.Fatalf("recovery preview: %v", err)
	}
	if cand.Target.ID != a.Revision.ID || !cand.Report.Valid() || cand.Current != live.Text {
		t.Fatalf("candidate target #%d valid %v current-is-live %v; want #%d, valid, the live text", cand.Target.ID, cand.Report.Valid(), cand.Current == live.Text, a.Revision.ID)
	}
	if got, _ := e.hs.GetPolicy(ctx); got.Text != live.Text {
		t.Fatal("the preview changed the live policy")
	}

	rec, err := e.w.Save(ctx, req)
	if err != nil {
		t.Fatalf("recovery: %v (report %+v)", err, rec.Report.Stages)
	}
	if !rec.Change.Applied || rec.Revision.Source != policyrev.SourceRecovery || rec.Revision.RollbackOf != a.Revision.ID {
		t.Fatalf("recovery result = %+v / %+v, want an applied recovery of #%d", rec.Change, rec.Revision, a.Revision.ID)
	}
	got, err := e.hs.GetPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.Text != cand.Text {
		t.Fatalf("live policy is not the candidate:\n got %q\nwant %q", got.Text, cand.Text)
	}
	if l, err = e.w.Live(ctx); err != nil || l.Uncertain != "" {
		t.Errorf("Live after the recovery = %+v, %v; want the uncertain state cleared", l, err)
	}
}
