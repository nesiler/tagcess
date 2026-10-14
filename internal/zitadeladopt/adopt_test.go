package zitadeladopt

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func run(t *testing.T, f *fakeZitadel, o Options) *Result {
	t.Helper()
	res, err := Run(context.Background(), f, o)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return res
}

// AC8 (F6-004): with the project, roles and apps already there, their ids come back and nothing is created.
func TestZitadelAdopt_ReusesExisting(t *testing.T) {
	f := existingFake()
	o := existingOptions(t.TempDir())
	o.Apps[1].RedirectURIs = f.apps["oauth2-proxy"].RedirectURIs[:1] // already registered
	o.Apps[1].PostLogoutURIs = nil
	res := run(t, f, o)
	if res.ProjectID != "p-vpn" || res.Apps["headscale"].ClientID != "c-hs" || res.Apps["oauth2-proxy"].AppID != "a-op" {
		t.Fatalf("ids %+v %+v", res.ProjectID, res.Apps)
	}
	if f.writes != 0 || res.Changed || len(f.apps) != 2 || len(f.roles) != 3 {
		t.Fatalf("writes %d changed %v apps %d roles %v", f.writes, res.Changed, len(f.apps), f.roles)
	}
}

// AC9 (F6-004): no flag combination changes users, grants, project or org memberships or keys.
func TestZitadelAdopt_NeverCreatesUsersOrGrants(t *testing.T) {
	for _, mk := range []func() *fakeZitadel{newFake, existingFake} {
		for _, flags := range []func(*Options){
			func(*Options) {},
			func(o *Options) { o.CreateActions = true; o.GroupsExecution = true; o.ReportUnroled = true },
			func(o *Options) { o.DryRun = true; o.ReportUnroled = true },
		} {
			f := mk()
			before := f.peopleSnapshot()
			o := existingOptions(t.TempDir())
			flags(&o)
			run(t, f, o)
			if after := f.peopleSnapshot(); after != before {
				t.Fatalf("people changed:\n%s\n%s", before, after)
			}
		}
	}
	// Structurally: the real adapter calls none of Zitadel's user, grant, membership or delete RPCs.
	src, err := os.ReadFile("grpc.go")
	if err != nil {
		t.Fatal(err)
	}
	forbidden := regexp.MustCompile(`\.(CreateUser|AddHumanUser|AddMachineUser|UpdateUser|DeleteUser|RemoveUser|CreateAuthorization|UpdateAuthorization|DeleteAuthorization|AddUserGrant|UpdateUserGrant|CreateAdministrator|UpdateAdministrator|DeleteAdministrator|AddProjectMember|AddOrgMember|AddKey|RemoveKey|Delete\w+|Remove\w+|Deactivate\w+|UpdateProject|SetAction|UpdateAction|AddFlow\w*|SetTriggerActions)\(`)
	if m := forbidden.FindString(string(src)); m != "" {
		t.Fatalf("grpc.go calls a forbidden RPC: %s", m)
	}
}

// AC10 (F6-004): --dry-run writes the plan and changes nothing.
func TestZitadelAdopt_DryRunNoWrites(t *testing.T) {
	for _, f := range []*fakeZitadel{newFake(), existingFake()} {
		before := f.snapshot()
		o := existingOptions(t.TempDir())
		o.DryRun, o.CreateActions, o.GroupsExecution = true, true, true
		res, err := Run(context.Background(), f, o)
		if err != nil && !strings.Contains(err.Error(), "groups target") {
			t.Fatal(err)
		}
		if f.writes != 0 || f.snapshot() != before {
			t.Fatalf("dry run wrote %d times", f.writes)
		}
		if res == nil || len(res.Plan) == 0 || !res.DryRun || res.Changed {
			t.Fatalf("dry run result %+v", res)
		}
	}
	res := run(t, newFake(), Options{ProjectName: "vpn", Roles: []string{"devops"}, DryRun: true,
		Apps: []AppSpec{{Name: "headscale", RedirectURIs: []string{"https://hs/cb"}}}})
	var creates []string
	for _, s := range res.Plan {
		if s.Action == ActCreate || s.Action == ActAdd {
			creates = append(creates, s.Object)
		}
	}
	if !slices.Equal(creates, []string{"project vpn", "role devops", "app headscale"}) {
		t.Fatalf("plan creates %v", creates)
	}
}

// AC11 (F6-004): a missing redirect URI is added, an extra one is kept, project settings stay as they are.
func TestZitadelAdopt_AddOnlyNeverDeletes(t *testing.T) {
	f := existingFake()
	f.project.RoleAssertion, f.project.AuthorizationRequired = false, true
	o := existingOptions(t.TempDir())
	res := run(t, f, o)
	got := f.apps["oauth2-proxy"].RedirectURIs
	want := []string{"https://monitor.example.test/oauth2/callback", "https://docs.example.test/oauth2/callback", "https://tagcess.example.test/oauth2/callback"}
	if !slices.Equal(got, want) || !slices.Equal(f.apps["oauth2-proxy"].PostLogoutURIs, []string{"https://tagcess.example.test/"}) {
		t.Fatalf("redirect URIs %v post-logout %v", got, f.apps["oauth2-proxy"].PostLogoutURIs)
	}
	if f.project.RoleAssertion || !f.project.AuthorizationRequired || res.Report.ProjectSettings.RoleAssertion {
		t.Fatalf("project settings changed or misreported: %+v %+v", f.project, res.Report.ProjectSettings)
	}
	var untouched bool
	for _, s := range res.Plan {
		untouched = untouched || (s.Object == "app oauth2-proxy" && s.Action == ActUntouched)
	}
	if !untouched {
		t.Fatalf("the kept URIs are not in the plan: %+v", res.Plan)
	}
}

// AC12 (F6-004): the second run says "no change".
func TestZitadelAdopt_Idempotent(t *testing.T) {
	for _, f := range []*fakeZitadel{newFake(), existingFake()} {
		o := existingOptions(t.TempDir())
		o.CreateActions, o.GroupsExecution = true, true
		first := run(t, f, o)
		writes := f.writes
		second := run(t, f, o)
		if !first.Changed || second.Changed || f.writes != writes {
			t.Fatalf("first changed %v, second changed %v, writes %d -> %d", first.Changed, second.Changed, writes, f.writes)
		}
		if first.ProjectID != second.ProjectID || first.Apps["headscale"] != second.Apps["headscale"] {
			t.Fatalf("ids differ between runs")
		}
	}
}

// AC13 (F6-004): unreachable Zitadel or a refused credential stops before any write; an interrupted run is
// completed by the next one without duplicates.
func TestZitadelAdopt_UnreachableAndResume(t *testing.T) {
	f := newFake()
	f.orgErr = errors.New("rpc error: code = Unauthenticated")
	if _, err := Run(context.Background(), f, existingOptions(t.TempDir())); !errors.Is(err, ErrUnreachable) || f.writes != 0 {
		t.Fatalf("err %v writes %d", err, f.writes)
	}
	broken := newFake()
	broken.failWrite = 3 // project, devops, then the developer role fails
	o := existingOptions(t.TempDir())
	o.CreateActions = true
	if _, err := Run(context.Background(), broken, o); err == nil {
		t.Fatal("the injected failure was not reported")
	}
	broken.failWrite = 0
	res := run(t, broken, o)
	clean := newFake()
	run(t, clean, o)
	if len(broken.roles) != 3 || len(broken.apps) != 2 || len(broken.targets) != 2 || res.ProjectID == "" {
		t.Fatalf("resume did not complete: roles %v apps %d targets %d", broken.roles, len(broken.apps), len(broken.targets))
	}
	if len(broken.executions) != len(clean.executions) {
		t.Fatalf("executions %d vs %d", len(broken.executions), len(clean.executions))
	}
}

// AC14 (F6-004): created secrets go only to 0600 files: never into the JSON result.
func TestZitadelAdopt_NoSecretInOutput(t *testing.T) {
	dir := t.TempDir()
	f := newFake()
	o := existingOptions(dir)
	o.CreateActions = true
	res := run(t, f, o)
	out, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.secrets) != 4 {
		t.Fatalf("expected 2 client secrets and 2 signing keys, got %d", len(f.secrets))
	}
	for _, s := range f.secrets {
		if strings.Contains(string(out), s) {
			t.Fatal("a secret value is in the result")
		}
	}
	for key, path := range res.Secrets {
		st, err := os.Stat(path)
		if err != nil || st.Mode().Perm() != 0o600 || filepath.Dir(path) != dir {
			t.Fatalf("%s: %v %v", key, err, st)
		}
		data, _ := os.ReadFile(path) // #nosec G304 -- test temp dir
		if !slices.Contains(f.secrets, string(data)) {
			t.Fatalf("%s does not hold the secret byte for byte", key)
		}
	}
	for _, k := range []string{"headscale_oidc_client_secret", "oauth2_proxy_client_secret", "webhook_signing_key", "groups_signing_key"} {
		if res.Secrets[k] == "" {
			t.Errorf("secret path %s missing", k)
		}
	}
}

// AC15 (F6-004): a missing service user or membership is reported with console steps, never created.
func TestZitadelAdopt_ServiceUserReportOnly(t *testing.T) {
	f := existingFake()
	res := run(t, f, existingOptions(t.TempDir()))
	su := res.Report.ServiceUser
	if su.Exists || su.ProjectOwner || su.OrgOwnerViewer || su.Keys != 0 {
		t.Fatalf("report %+v", su)
	}
	if _, ok := f.users["tagcess"]; ok {
		t.Fatal("the service user was created")
	}
	var g *GuideItem
	for i := range res.Guide {
		if res.Guide[i].ID == "zitadel-service-user" {
			g = &res.Guide[i]
		}
	}
	if g == nil || len(g.Steps) != 4 || !strings.Contains(strings.Join(g.Steps, " "), "PROJECT_OWNER") {
		t.Fatalf("guide %+v", res.Guide)
	}
	// Present user with a membership but no key: only the missing parts are steps.
	f.users["tagcess"] = User{ID: "su", Username: "tagcess", Machine: true}
	f.members["su|project|p-vpn"] = []string{"PROJECT_OWNER"}
	f.members["su|org|org-1"] = []string{"ORG_OWNER_VIEWER"}
	res = run(t, f, existingOptions(t.TempDir()))
	if !res.Report.ServiceUser.ProjectOwner || !res.Report.ServiceUser.OrgOwnerViewer {
		t.Fatalf("report %+v", res.Report.ServiceUser)
	}
	for _, it := range res.Guide {
		if it.ID == "zitadel-service-user" && (len(it.Steps) != 1 || !strings.Contains(it.Steps[0], "Keys")) {
			t.Fatalf("steps %v", it.Steps)
		}
	}
}

// AC16 (F6-004): Actions v2 objects only with --create-actions; without it they are only reported.
func TestZitadelAdopt_CreateActionsOnlyWithFlag(t *testing.T) {
	f := existingFake()
	res := run(t, f, existingOptions(t.TempDir()))
	if len(f.targets) != 0 || len(f.executions) != 0 || res.Report.ActionsV2.WebhookTarget {
		t.Fatalf("v2 objects without the flag: %v %v", f.targets, f.executions)
	}
	if !slices.ContainsFunc(res.Guide, func(g GuideItem) bool { return g.ID == "zitadel-webhook-target" }) {
		t.Fatal("no guide item for the missing webhook target")
	}
	o := existingOptions(t.TempDir())
	o.CreateActions = true
	res = run(t, f, o)
	if len(f.targets) != 2 || len(f.executions) != len(WebhookEvents) || res.Report.ActionsV2.WebhookExecutions != len(WebhookEvents) {
		t.Fatalf("targets %v executions %d report %+v", f.targets, len(f.executions), res.Report.ActionsV2)
	}
	if res.Secrets["webhook_signing_key"] == "" {
		t.Fatal("the signing key file was not written")
	}
}

// AC17 (F6-004): without --groups-execution Actions v1 stays as it is, no v2 groups execution is made, both are
// reported and the v1 -> v2 switch is a guide item.
func TestZitadelAdopt_GroupsClaimLeftToDeveloper(t *testing.T) {
	f := existingFake()
	o := existingOptions(t.TempDir())
	o.CreateActions = true // an existing installation may confirm the targets; never the execution
	before := f.peopleSnapshot()
	res := run(t, f, o)
	if _, ok := f.executions["function:"+FunctionPreuserinfo]; ok {
		t.Fatal("the groups execution was created without --groups-execution")
	}
	if f.peopleSnapshot() != before || !slices.Equal(f.v1, []string{V1GroupsActionName}) || !f.v1Bound[V1GroupsActionName] {
		t.Fatal("Actions v1 changed")
	}
	if !res.Report.ActionsV1.GroupsAction || !res.Report.ActionsV1.FlowBound || res.Report.ActionsV2.GroupsExecution {
		t.Fatalf("report %+v %+v", res.Report.ActionsV1, res.Report.ActionsV2)
	}
	if !slices.ContainsFunc(res.Guide, func(g GuideItem) bool { return g.ID == "zitadel-groups-v1-to-v2" }) {
		t.Fatal("no v1 -> v2 guide item")
	}
	o.GroupsExecution = true // lab
	run(t, f, o)
	if _, ok := f.executions["function:"+FunctionPreuserinfo]; !ok {
		t.Fatal("--groups-execution did not bind the groups target")
	}
}

// AC18 (F6-004): --report-unroled gives only the count: no name, e-mail or id, and no write.
func TestZitadelAdopt_ReportUnroledCountOnly(t *testing.T) {
	f := existingFake()
	f.users["svc"] = User{ID: "m1", Username: "svc", Machine: true}
	o := existingOptions(t.TempDir())
	o.ReportUnroled = true
	o.Apps = nil
	writes := f.writes
	res := run(t, f, o)
	if res.Report.UnroledUsers == nil || *res.Report.UnroledUsers != 2 || f.writes != writes {
		t.Fatalf("unroled %v writes %d", res.Report.UnroledUsers, f.writes-writes)
	}
	out, _ := json.Marshal(res)
	for _, s := range []string{"carol", "dave", "u2", "u3", "example.test\"", "@example"} {
		if strings.Contains(string(out), s) {
			t.Fatalf("the report names a user (%s): %s", s, out)
		}
	}
}

// AC19 (F6-004): report and guide carry no secret-shaped value.
func TestZitadelAdopt_ReportNoSecret(t *testing.T) {
	f := newFake()
	o := existingOptions(t.TempDir())
	o.CreateActions, o.GroupsExecution, o.ReportUnroled = true, true, true
	res := run(t, f, o)
	out, _ := json.Marshal(struct {
		R Report
		G []GuideItem
		P []Step
	}{res.Report, res.Guide, res.Plan})
	token := regexp.MustCompile(`[A-Za-z0-9+/_-]{32,}`)
	for _, m := range token.FindAllString(string(out), -1) {
		if strings.ContainsAny(m, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") && strings.ContainsAny(m, "0123456789") {
			t.Fatalf("secret-shaped value in the report: %s", m)
		}
	}
	for _, s := range f.secrets {
		if strings.Contains(string(out), s) {
			t.Fatal("a secret is in the report")
		}
	}
}
