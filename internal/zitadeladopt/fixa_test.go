package zitadeladopt

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// fixaRacyFake adds targets to executions right after the runner's first read of them: another writer (the
// console, another tool run) changes an execution between the read and the write.
type fixaRacyFake struct {
	*fakeZitadel
	reads int
	late  map[string][]string // condition -> targets that appear after the first read
}

func (f *fixaRacyFake) Executions(ctx context.Context) ([]Execution, error) {
	out, err := f.fakeZitadel.Executions(ctx)
	f.reads++
	if f.reads == 1 {
		for c, t := range f.late {
			f.executions[c] = append(f.executions[c], t...)
		}
	}
	return out, err
}

func fixaOptions(dir string) Options {
	o := existingOptions(dir)
	o.CreateActions, o.GroupsExecution = true, true
	return o
}

// H5: an execution that already carries other targets keeps them (in order); tagcess's target is appended. The fake
// replaces the list the way Zitadel's SetExecution does, so a dropped target shows up in the final lists.
func TestZitadelAdopt_ExecutionKeepsExistingTargets(t *testing.T) {
	f := existingFake()
	f.executions["event:user.grant.added"] = []string{"t-other-1", "t-other-2"}
	f.executions["event:user.locked"] = []string{"t-other-3"}
	f.executions["function:preuserinfo"] = []string{"t-fn-1"}
	f.executions["event:project.added"] = []string{"t-unrelated"} // not one of tagcess's conditions
	run(t, f, fixaOptions(t.TempDir()))
	wh, groups := f.targets[WebhookTargetName].ID, f.targets[GroupsTargetName].ID
	for cond, want := range map[string][]string{
		"event:user.grant.added": {"t-other-1", "t-other-2", wh},
		"event:user.locked":      {"t-other-3", wh},
		"function:preuserinfo":   {"t-fn-1", groups},
		"event:user.removed":     {wh},
		"event:project.added":    {"t-unrelated"},
	} {
		if got := f.executions[cond]; !slices.Equal(got, want) {
			t.Errorf("%s: targets %v, want %v", cond, got, want)
		}
	}
}

// H5: a target another writer adds between the runner's read and its write is kept (the list is read again).
func TestZitadelAdopt_ExecutionRaceKeepsLateTarget(t *testing.T) {
	f := &fixaRacyFake{fakeZitadel: existingFake(), late: map[string][]string{
		"event:user.grant.added": {"t-late-1"},
		"function:preuserinfo":   {"t-late-fn"},
	}}
	if _, err := Run(context.Background(), f, fixaOptions(t.TempDir())); err != nil {
		t.Fatal(err)
	}
	wh, groups := f.targets[WebhookTargetName].ID, f.targets[GroupsTargetName].ID
	if got := f.executions["event:user.grant.added"]; !slices.Equal(got, []string{"t-late-1", wh}) {
		t.Errorf("event:user.grant.added: %v", got)
	}
	if got := f.executions["function:preuserinfo"]; !slices.Equal(got, []string{"t-late-fn", groups}) {
		t.Errorf("function:preuserinfo: %v", got)
	}
}

// H5: when our target is already in the list nothing is written and the order is not touched.
func TestZitadelAdopt_ExecutionAlreadyListedNoWrite(t *testing.T) {
	f := existingFake()
	o := fixaOptions(t.TempDir())
	run(t, f, o)
	f.executions["event:user.locked"] = []string{"t-first", f.targets[WebhookTargetName].ID}
	writes := f.writes
	res := run(t, f, o)
	if f.writes != writes || res.Changed {
		t.Fatalf("second run wrote: writes %d -> %d", writes, f.writes)
	}
	if got := f.executions["event:user.locked"]; got[0] != "t-first" {
		t.Fatalf("order changed: %v", got)
	}
}

func fixaSecretFiles(t *testing.T, dir string) map[string]string {
	t.Helper()
	got := map[string]string{}
	for k, f := range map[string]string{"headscale_oidc_client_secret": "headscale_oidc_client_secret", "oauth2_proxy_client_secret": "oauth2_proxy_client_secret",
		"webhook_signing_key": "webhook-signing-key", "groups_signing_key": "groups-signing-key"} {
		if b, err := os.ReadFile(filepath.Join(dir, f)); err == nil { // #nosec G304 -- test temp dir
			got[k] = string(b)
		}
	}
	return got
}

// H7: a second run reports the secret files the first run wrote (verified: they exist and are not empty); the files
// are not rewritten.
func TestZitadelAdopt_RerunReportsExistingSecretPaths(t *testing.T) {
	dir := t.TempDir()
	f := newFake()
	o := fixaOptions(dir)
	first := run(t, f, o)
	before := fixaSecretFiles(t, dir)
	second := run(t, f, o)
	if len(first.Secrets) != 4 {
		t.Fatalf("first run secrets: %v", first.Secrets)
	}
	for k, p := range first.Secrets {
		if second.Secrets[k] != p {
			t.Errorf("%s: second run reports %q, first %q", k, second.Secrets[k], p)
		}
	}
	if after := fixaSecretFiles(t, dir); !slices.Equal(sortedPairs(before), sortedPairs(after)) {
		t.Fatal("a secret file was rewritten by the second run")
	}
	if len(second.MissingSecrets) != 0 {
		t.Fatalf("missing secrets reported: %+v", second.MissingSecrets)
	}
}

func sortedPairs(m map[string]string) []string {
	var out []string
	for k, v := range m {
		out = append(out, k+"="+v)
	}
	slices.Sort(out)
	return out
}

// H7: an interrupted run's earlier creations are carried by the rerun's report: the first run stops after the webhook
// target (its secrets are on disk), the rerun reports all paths including those.
func TestZitadelAdopt_InterruptedRunPathsCarriedOver(t *testing.T) {
	dir := t.TempDir()
	f := newFake()
	o := fixaOptions(dir)
	// writes: project 1, roles 2-4, headscale app 5, oauth2-proxy app 6, webhook target 7, first execution 8 fails.
	f.failWrite = 8
	first, err := Run(context.Background(), f, o)
	if err == nil {
		t.Fatal("the injected failure was not reported")
	}
	if first.Secrets["webhook_signing_key"] == "" {
		t.Fatalf("the interrupted run lost the webhook key path: %v", first.Secrets)
	}
	f.failWrite = 0
	second := run(t, f, o)
	for _, k := range []string{"headscale_oidc_client_secret", "oauth2_proxy_client_secret", "webhook_signing_key", "groups_signing_key"} {
		if p := second.Secrets[k]; p == "" || filepath.Dir(p) != dir {
			t.Errorf("rerun does not report %s: %q", k, p)
		}
	}
	if len(second.MissingSecrets) != 0 {
		t.Fatalf("missing: %+v", second.MissingSecrets)
	}
}

// H7: an object the tool created whose secret file is gone is reported explicitly (result field and a blocking guide
// item) and the file is not invented; an existing object the tool never created is not reported.
func TestZitadelAdopt_MissingSecretFileReported(t *testing.T) {
	dir := t.TempDir()
	f := newFake()
	o := fixaOptions(dir)
	run(t, f, o)
	for _, n := range []string{"webhook-signing-key", "oauth2_proxy_client_secret"} {
		if err := os.Remove(filepath.Join(dir, n)); err != nil {
			t.Fatal(err)
		}
	}
	writes := f.writes
	res := run(t, f, o)
	if f.writes != writes {
		t.Fatalf("the rerun wrote to Zitadel (%d -> %d)", writes, f.writes)
	}
	var keys []string
	for _, m := range res.MissingSecrets {
		keys = append(keys, m.Key)
		if m.Object == "" || m.Path == "" {
			t.Errorf("incomplete entry %+v", m)
		}
	}
	slices.Sort(keys)
	if !slices.Equal(keys, []string{"oauth2_proxy_client_secret", "webhook_signing_key"}) {
		t.Fatalf("missing secrets %v", keys)
	}
	if res.Secrets["webhook_signing_key"] != "" || res.Secrets["groups_signing_key"] == "" {
		t.Fatalf("secrets %v", res.Secrets)
	}
	if _, err := os.Stat(filepath.Join(dir, "webhook-signing-key")); err == nil {
		t.Fatal("a secret file was made up")
	}
	var blocking bool
	for _, g := range res.Guide {
		blocking = blocking || (g.ID == "zitadel-secret-missing" && g.Blocking)
	}
	if !blocking {
		t.Fatalf("no blocking guide item: %+v", res.Guide)
	}

	// The existing installation's own apps (never created by the tool) are not "missing".
	c := existingFake()
	co := existingOptions(t.TempDir())
	if res := run(t, c, co); len(res.MissingSecrets) != 0 {
		t.Fatalf("existing objects reported as missing: %+v", res.MissingSecrets)
	}
}
