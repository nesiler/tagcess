// Package zitadeladopt is the installer's Zitadel step (F6-004, F6 öneri 12 [Ö]): it finds the `vpn` project,
// its roles and the OIDC applications tagcess needs in an existing Zitadel and creates only what is missing.
// It never creates or changes a person, a role grant or a membership (rule 3), never deletes anything and never
// changes an existing object beyond adding a missing redirect URI. The tagcess service user (ADR 0009), Actions v1
// and the groups claim are reported, with console steps as guide items (decisions 2 and 6 [K]); Actions v2
// targets/executions are created only on request. The API interface below has no method that could do more.
package zitadeladopt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Names of the objects the installer owns or looks for.
const (
	WebhookTargetName   = "tagcess-webhook"
	GroupsTargetName    = "tagcess-groups-claim"
	FunctionPreuserinfo = "preuserinfo"
	V1GroupsActionName  = "vpnGroups"
	TargetRestAsync     = "rest_async"
	TargetRestCall      = "rest_call"
)

// WebhookEvents are the Actions v2 event conditions that trigger tagcess's reconcile (same list as the lab seed).
var WebhookEvents = []string{
	"user.grant.added", "user.grant.changed", "user.grant.removed", "user.grant.deactivated", "user.grant.reactivated",
	"user.grant.cascade.changed", "user.grant.cascade.removed", "user.deactivated", "user.locked", "user.removed",
	"user.reactivated",
}

// Project is a Zitadel project with the settings the installer reports (never changes).
type Project struct {
	ID, Name                             string
	RoleAssertion, AuthorizationRequired bool
}

// App is an OIDC application.
type App struct {
	ID, Name, ClientID           string
	RedirectURIs, PostLogoutURIs []string
}

// User is the part of a user the report needs.
type User struct {
	ID, Username string
	Machine      bool
}

// Target is an Actions v2 target.
type Target struct {
	ID, Name, Endpoint, Kind string
}

// Execution is an Actions v2 execution: "event:<name>" or "function:<name>" and its target ids.
type Execution struct {
	Condition string
	Targets   []string
}

// API is everything the step may do in Zitadel. Reads, plus exactly five kinds of writes: create a project, add a
// role, create an OIDC app, set an app's URI lists (the caller only ever passes a superset of today's lists),
// create an Actions v2 target and set an execution. There is deliberately no user, grant, membership or delete
// method.
type API interface {
	OrgID(ctx context.Context) (string, error)
	FindProject(ctx context.Context, orgID, name string) (*Project, error)
	CreateProject(ctx context.Context, orgID, name string) (string, error)
	ProjectRoles(ctx context.Context, projectID string) ([]string, error)
	AddProjectRole(ctx context.Context, projectID, key string) error
	FindApp(ctx context.Context, projectID, name string) (*App, error)
	CreateApp(ctx context.Context, projectID, name string, redirects, postLogout []string) (App, string, error)
	SetAppURIs(ctx context.Context, projectID string, app App, redirects, postLogout []string) error
	FindUser(ctx context.Context, username string) (*User, error)
	MemberRoles(ctx context.Context, userID, resource, resourceID string) ([]string, error)
	KeyCount(ctx context.Context, userID string) (int, error)
	FindTarget(ctx context.Context, name string) (*Target, error)
	CreateTarget(ctx context.Context, name, endpoint, kind string) (id, signingKey string, err error)
	Executions(ctx context.Context) ([]Execution, error)
	SetExecution(ctx context.Context, condition string, targetIDs []string) error
	V1Actions(ctx context.Context) (names []string, flowBound map[string]bool, err error)
	UnroledActiveUsers(ctx context.Context, orgID, projectID string) (int, error)
}

// AppSpec is one OIDC application the installer needs and the URIs it must at least carry.
type AppSpec struct {
	Name           string
	SecretKey      string // the secret_files key of a newly created app's client secret
	RedirectURIs   []string
	PostLogoutURIs []string
}

// Options configure one run.
type Options struct {
	ProjectName     string
	Roles           []string
	Apps            []AppSpec
	ServiceUser     string
	WebhookURL      string
	GroupsURL       string
	CreateActions   bool // create the webhook target + executions and the groups target (lab; existing installation only on confirmation)
	GroupsExecution bool // bind the groups target to preuserinfo (lab only)
	ReportUnroled   bool
	DryRun          bool
	SecretOutDir    string
}

// Step is one line of the plan.
type Step struct {
	Object string `json:"object"`
	Action string `json:"action"` // exists | create | add | untouched | report
	Detail string `json:"detail,omitempty"`
}

// Plan actions.
const (
	ActExists    = "exists"
	ActCreate    = "create"
	ActAdd       = "add"
	ActUntouched = "untouched"
)

// GuideItem is a console step for the developer (the installer's guide format, F6-001).
type GuideItem struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Steps    []string `json:"steps"`
	Blocking bool     `json:"blocking"`
}

// AppResult is an application's ids (public values).
type AppResult struct {
	AppID    string `json:"app_id"`
	ClientID string `json:"client_id"`
}

// Report is the read-only state the installer reports (decisions 1, 2, 6 [K]).
type Report struct {
	ProjectSettings struct {
		RoleAssertion         bool `json:"role_assertion"`
		AuthorizationRequired bool `json:"authorization_required"`
	} `json:"project_settings"`
	ServiceUser struct {
		Exists         bool   `json:"exists"`
		Username       string `json:"username"`
		ProjectOwner   bool   `json:"project_owner"`
		OrgOwnerViewer bool   `json:"org_owner_viewer"`
		Keys           int    `json:"keys"`
	} `json:"service_user"`
	ActionsV1 struct {
		GroupsAction bool `json:"groups_action"`
		FlowBound    bool `json:"flow_bound"`
	} `json:"actions_v1"`
	ActionsV2 struct {
		WebhookTarget     bool `json:"webhook_target"`
		WebhookExecutions int  `json:"webhook_executions"`
		WebhookEvents     int  `json:"webhook_events"`
		GroupsTarget      bool `json:"groups_target"`
		GroupsExecution   bool `json:"groups_execution"`
	} `json:"actions_v2"`
	UnroledUsers *int `json:"unroled_users"`
}

// Result is the tool's JSON output. It carries ids and secret file PATHS only.
type Result struct {
	DryRun    bool                 `json:"dry_run"`
	Changed   bool                 `json:"changed"`
	OrgID     string               `json:"org_id"`
	ProjectID string               `json:"project_id"`
	Apps      map[string]AppResult `json:"apps"`
	Plan      []Step               `json:"plan"`
	Report    Report               `json:"report"`
	Guide     []GuideItem          `json:"guide"`
	Secrets   map[string]string    `json:"secrets"`
	// MissingSecrets lists objects this tool created whose secret file is gone (Zitadel shows a secret once).
	MissingSecrets []MissingSecret `json:"missing_secrets"`
}

// MissingSecret is an object created by an earlier run of this tool whose secret file no longer exists.
type MissingSecret struct {
	Key    string `json:"key"`
	Object string `json:"object"`
	Path   string `json:"path"`
}

// ErrUnreachable wraps every failure before the first write: nothing was changed.
var ErrUnreachable = errors.New("zitadel unreachable or the admin credential was refused; nothing was written")

type runner struct {
	api API
	o   Options
	res *Result
}

func (r *runner) plan(object, action, detail string) {
	r.res.Plan = append(r.res.Plan, Step{Object: object, Action: action, Detail: detail})
}

func (r *runner) write(object, action, detail string, do func() error) error {
	r.plan(object, action, detail)
	if r.o.DryRun {
		return nil
	}
	if err := do(); err != nil {
		return fmt.Errorf("%s %s: %w", action, object, err)
	}
	r.res.Changed = true
	return nil
}

// writeSecret stores a value Zitadel shows only once in a 0600 file and returns its path. The value never goes
// anywhere else.
func (r *runner) writeSecret(name, value string) (string, error) {
	if r.o.SecretOutDir == "" {
		return "", fmt.Errorf("a secret for %s was created but --secret-out-dir is not set", name)
	}
	if err := os.MkdirAll(r.o.SecretOutDir, 0o700); err != nil {
		return "", err
	}
	p := filepath.Join(r.o.SecretOutDir, name)
	if err := os.WriteFile(p, []byte(value), 0o600); err != nil {
		return "", err
	}
	if err := os.Chmod(p, 0o600); err != nil {
		return "", err
	}
	return p, nil
}

// ledgerName is the file in the secret directory that lists the secret keys this tool created (no secret value in it).
// A rerun needs it to tell "created by us, the file is gone" from "the existing installation's own object, never ours".
const ledgerName = ".created.json"

func (r *runner) readLedger() []string {
	data, err := os.ReadFile(filepath.Join(r.o.SecretOutDir, ledgerName)) // #nosec G304 -- the tool's own secret directory
	if err != nil {
		return nil
	}
	var l struct {
		Created []string `json:"created"`
	}
	if json.Unmarshal(data, &l) != nil {
		return nil
	}
	return l.Created
}

// recordCreated notes that the tool created the object behind secret key, before its secret is written.
func (r *runner) recordCreated(key string) error {
	if r.o.SecretOutDir == "" {
		return fmt.Errorf("a secret for %s was created but --secret-out-dir is not set", key)
	}
	if err := os.MkdirAll(r.o.SecretOutDir, 0o700); err != nil {
		return err
	}
	created := r.readLedger()
	if slices.Contains(created, key) {
		return nil
	}
	data, err := json.Marshal(map[string][]string{"created": append(created, key)})
	if err != nil {
		return err
	}
	p := filepath.Join(r.o.SecretOutDir, ledgerName)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		return err
	}
	return os.Chmod(p, 0o600)
}

// adoptSecret reports the secret file of an object that already exists: the path when the file is there and not
// empty (an earlier run wrote it; it is never rewritten); an explicit "missing" entry when the tool created the
// object but the file is gone (Zitadel shows the value only once). Objects the tool never created are not tracked.
func (r *runner) adoptSecret(key, file, object string) {
	if r.o.SecretOutDir == "" {
		return
	}
	p := filepath.Join(r.o.SecretOutDir, file)
	if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() && st.Size() > 0 {
		r.res.Secrets[key] = p
		return
	}
	if slices.Contains(r.readLedger(), key) {
		r.res.MissingSecrets = append(r.res.MissingSecrets, MissingSecret{Key: key, Object: object, Path: p})
		r.plan(object, "report", "secret file missing: "+p)
	}
}

// addToExecution adds targetID to the execution's target list. Zitadel's SetExecution replaces the whole list, so the
// current list is read again right before the write and extended (never replaced): targets other tools or people put
// on the same condition stay, in their order.
func (r *runner) addToExecution(ctx context.Context, cond, targetID string) error {
	execs, err := r.api.Executions(ctx)
	if err != nil {
		return fmt.Errorf("read Actions v2 executions: %w", err)
	}
	var cur []string
	for _, e := range execs {
		if e.Condition == cond {
			cur = slices.Clone(e.Targets)
		}
	}
	if slices.Contains(cur, targetID) {
		return nil
	}
	return r.api.SetExecution(ctx, cond, append(cur, targetID))
}

// Run finds or creates what tagcess needs and reports the rest. An error before the first write is ErrUnreachable;
// a later error leaves what was done in place, and a rerun completes the rest (every step is find-or-create).
func Run(ctx context.Context, api API, o Options) (*Result, error) {
	if o.ProjectName == "" {
		return nil, errors.New("project name is required")
	}
	res := &Result{DryRun: o.DryRun, Apps: map[string]AppResult{}, Plan: []Step{}, Guide: []GuideItem{}, Secrets: map[string]string{}, MissingSecrets: []MissingSecret{}}
	r := &runner{api: api, o: o, res: res}
	orgID, err := api.OrgID(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnreachable, err)
	}
	res.OrgID = orgID

	proj, err := api.FindProject(ctx, orgID, o.ProjectName)
	if err != nil {
		return nil, fmt.Errorf("%w: find project: %w", ErrUnreachable, err)
	}
	if proj == nil {
		if err := r.write("project "+o.ProjectName, ActCreate, "", func() error {
			id, err := api.CreateProject(ctx, orgID, o.ProjectName)
			res.ProjectID = id
			return err
		}); err != nil {
			return res, err
		}
	} else {
		r.plan("project "+o.ProjectName, ActExists, proj.ID)
		res.ProjectID = proj.ID
		res.Report.ProjectSettings.RoleAssertion = proj.RoleAssertion
		res.Report.ProjectSettings.AuthorizationRequired = proj.AuthorizationRequired
	}

	if err := r.roles(ctx); err != nil {
		return res, err
	}
	for _, spec := range o.Apps {
		if err := r.app(ctx, spec); err != nil {
			return res, err
		}
	}
	if err := r.serviceUser(ctx, orgID); err != nil {
		return res, err
	}
	if err := r.actions(ctx); err != nil {
		return res, err
	}
	r.missingSecretsGuide()
	if o.ReportUnroled && res.ProjectID != "" {
		n, err := api.UnroledActiveUsers(ctx, orgID, res.ProjectID)
		if err != nil {
			return res, fmt.Errorf("count users without a role: %w", err)
		}
		res.Report.UnroledUsers = &n
	}
	return res, nil
}

// missingSecretsGuide turns the missing secret files into one blocking guide item: the objects exist in Zitadel but the
// value cannot be shown again.
func (r *runner) missingSecretsGuide() {
	if len(r.res.MissingSecrets) == 0 {
		return
	}
	steps := []string{"Zitadel bu değerleri yalnız yaratıldığında bir kez gösterir; araç dosyayı uydurmaz ve yeniden yazmaz. Eksik dosyalar:"}
	for _, m := range r.res.MissingSecrets {
		steps = append(steps, fmt.Sprintf("%s: %s (anahtar %s)", m.Object, m.Path, m.Key))
	}
	steps = append(steps,
		"Dosyayı yedeğinden geri koy ya da değeri secret_files.<anahtar> olarak ver.",
		"Değer yoksa: konsolda uygulamanın client secret'ını yenile / target'ın imza anahtarını yeniden oluştur (eski target'ı konsoldan sil, araç yenisini açıp yeni anahtarı yazar).")
	r.res.Guide = append(r.res.Guide, GuideItem{ID: "zitadel-secret-missing", Title: "Zitadel'de açılmış ama secret dosyası eksik", Steps: steps, Blocking: true})
}

func (r *runner) roles(ctx context.Context) error {
	var have []string
	if r.res.ProjectID != "" {
		var err error
		if have, err = r.api.ProjectRoles(ctx, r.res.ProjectID); err != nil {
			return fmt.Errorf("list project roles: %w", err)
		}
	}
	for _, role := range r.o.Roles {
		if slices.Contains(have, role) {
			r.plan("role "+role, ActExists, "")
			continue
		}
		if err := r.write("role "+role, ActAdd, "", func() error { return r.api.AddProjectRole(ctx, r.res.ProjectID, role) }); err != nil {
			return err
		}
	}
	for _, role := range have {
		if !slices.Contains(r.o.Roles, role) {
			r.plan("role "+role, ActUntouched, "not one of tagcess's roles; left as it is")
		}
	}
	return nil
}

// union returns have plus the missing entries of want, in order (nothing is ever removed).
func union(have, want []string) ([]string, []string) {
	out := slices.Clone(have)
	var added []string
	for _, w := range want {
		if !slices.Contains(out, w) {
			out = append(out, w)
			added = append(added, w)
		}
	}
	return out, added
}

func (r *runner) app(ctx context.Context, spec AppSpec) error {
	obj := "app " + spec.Name
	var app *App
	if r.res.ProjectID != "" {
		var err error
		if app, err = r.api.FindApp(ctx, r.res.ProjectID, spec.Name); err != nil {
			return fmt.Errorf("find %s: %w", obj, err)
		}
	}
	if app == nil {
		return r.write(obj, ActCreate, strings.Join(spec.RedirectURIs, " "), func() error {
			created, secret, err := r.api.CreateApp(ctx, r.res.ProjectID, spec.Name, spec.RedirectURIs, spec.PostLogoutURIs)
			if err != nil {
				return err
			}
			r.res.Apps[spec.Name] = AppResult{AppID: created.ID, ClientID: created.ClientID}
			if secret != "" && spec.SecretKey != "" {
				if err := r.recordCreated(spec.SecretKey); err != nil {
					return err
				}
				p, err := r.writeSecret(spec.SecretKey, secret)
				if err != nil {
					return err
				}
				r.res.Secrets[spec.SecretKey] = p
			}
			return nil
		})
	}
	r.res.Apps[spec.Name] = AppResult{AppID: app.ID, ClientID: app.ClientID}
	if spec.SecretKey != "" {
		r.adoptSecret(spec.SecretKey, spec.SecretKey, obj)
	}
	redirects, addR := union(app.RedirectURIs, spec.RedirectURIs)
	postLogout, addP := union(app.PostLogoutURIs, spec.PostLogoutURIs)
	if len(addR)+len(addP) == 0 {
		r.plan(obj, ActExists, app.ClientID)
	} else if err := r.write(obj, ActAdd, "redirect URIs: "+strings.Join(append(addR, addP...), " "), func() error {
		return r.api.SetAppURIs(ctx, r.res.ProjectID, *app, redirects, postLogout)
	}); err != nil {
		return err
	}
	var extra []string
	for _, u := range app.RedirectURIs {
		if !slices.Contains(spec.RedirectURIs, u) {
			extra = append(extra, u)
		}
	}
	if len(extra) > 0 {
		r.plan(obj, ActUntouched, fmt.Sprintf("%d other redirect URIs kept (tagcess's site sync owns them)", len(extra)))
	}
	return nil
}

func (r *runner) serviceUser(ctx context.Context, orgID string) error {
	su := &r.res.Report.ServiceUser
	su.Username = r.o.ServiceUser
	if r.o.ServiceUser == "" {
		return nil
	}
	u, err := r.api.FindUser(ctx, r.o.ServiceUser)
	if err != nil {
		return fmt.Errorf("find service user: %w", err)
	}
	if u != nil {
		su.Exists = true
		if r.res.ProjectID != "" {
			roles, err := r.api.MemberRoles(ctx, u.ID, "project", r.res.ProjectID)
			if err != nil {
				return fmt.Errorf("service user project membership: %w", err)
			}
			su.ProjectOwner = slices.Contains(roles, "PROJECT_OWNER")
		}
		roles, err := r.api.MemberRoles(ctx, u.ID, "org", orgID)
		if err != nil {
			return fmt.Errorf("service user org membership: %w", err)
		}
		su.OrgOwnerViewer = slices.Contains(roles, "ORG_OWNER_VIEWER")
		if su.Keys, err = r.api.KeyCount(ctx, u.ID); err != nil {
			return fmt.Errorf("service user keys: %w", err)
		}
	}
	r.plan("service user "+r.o.ServiceUser, "report", fmt.Sprintf("exists=%v project_owner=%v org_owner_viewer=%v keys=%d",
		su.Exists, su.ProjectOwner, su.OrgOwnerViewer, su.Keys))
	var steps []string
	if !su.Exists {
		steps = append(steps, fmt.Sprintf("Zitadel konsolu → Users → Service Users → New: kullanıcı adı %q, erişim token tipi JWT (ADR 0009).", r.o.ServiceUser))
	}
	if !su.ProjectOwner {
		steps = append(steps, fmt.Sprintf("Projects → %s → Members (Roles): %s kullanıcısına PROJECT_OWNER ver.", r.o.ProjectName, r.o.ServiceUser))
	}
	if !su.OrgOwnerViewer {
		steps = append(steps, fmt.Sprintf("Organization → Members (Roles): %s kullanıcısına ORG_OWNER_VIEWER ver (kullanıcı durumlarını okumak için).", r.o.ServiceUser))
	}
	if su.Keys == 0 {
		steps = append(steps, fmt.Sprintf("Users → %s → Keys → New (JSON): indirilen dosyayı repo dışında sakla, yolunu secret_files.zitadel_key olarak ver; host fazı onu 0400 ile kopyalar.", r.o.ServiceUser))
	}
	if len(steps) > 0 {
		r.res.Guide = append(r.res.Guide, GuideItem{ID: "zitadel-service-user", Title: "tagcess servis kullanıcısını konsoldan tamamla (ADR 0009)",
			Steps: steps, Blocking: true})
	}
	return nil
}

func targetsHave(execs []Execution, condition, targetID string) bool {
	for _, e := range execs {
		if e.Condition == condition && (targetID == "" || slices.Contains(e.Targets, targetID)) {
			return true
		}
	}
	return false
}

func (r *runner) actions(ctx context.Context) error {
	v2 := &r.res.Report.ActionsV2
	names, bound, err := r.api.V1Actions(ctx)
	if err != nil {
		return fmt.Errorf("read Actions v1: %w", err)
	}
	r.res.Report.ActionsV1.GroupsAction = slices.Contains(names, V1GroupsActionName)
	r.res.Report.ActionsV1.FlowBound = bound[V1GroupsActionName]
	r.plan("actions v1 "+V1GroupsActionName, "report", fmt.Sprintf("present=%v flow_bound=%v (never changed)", r.res.Report.ActionsV1.GroupsAction, r.res.Report.ActionsV1.FlowBound))

	execs, err := r.api.Executions(ctx)
	if err != nil {
		return fmt.Errorf("read Actions v2 executions: %w", err)
	}
	webhook, err := r.api.FindTarget(ctx, WebhookTargetName)
	if err != nil {
		return fmt.Errorf("find webhook target: %w", err)
	}
	groups, err := r.api.FindTarget(ctx, GroupsTargetName)
	if err != nil {
		return fmt.Errorf("find groups target: %w", err)
	}
	if webhook != nil {
		r.adoptSecret("webhook_signing_key", "webhook-signing-key", "target "+WebhookTargetName)
	}
	if groups != nil {
		r.adoptSecret("groups_signing_key", "groups-signing-key", "target "+GroupsTargetName)
	}

	if r.o.CreateActions {
		if webhook == nil {
			if r.o.WebhookURL == "" {
				return errors.New("--create-actions needs --webhook-url")
			}
			if err := r.write("target "+WebhookTargetName, ActCreate, r.o.WebhookURL, func() error {
				id, key, err := r.api.CreateTarget(ctx, WebhookTargetName, r.o.WebhookURL, TargetRestAsync)
				if err != nil {
					return err
				}
				webhook = &Target{ID: id, Name: WebhookTargetName, Endpoint: r.o.WebhookURL, Kind: TargetRestAsync}
				if err := r.recordCreated("webhook_signing_key"); err != nil {
					return err
				}
				p, err := r.writeSecret("webhook-signing-key", key)
				if err != nil {
					return err
				}
				r.res.Secrets["webhook_signing_key"] = p
				return nil
			}); err != nil {
				return err
			}
		} else {
			r.plan("target "+WebhookTargetName, ActExists, webhook.Endpoint)
		}
		for _, ev := range WebhookEvents {
			cond := "event:" + ev
			if webhook != nil && targetsHave(execs, cond, webhook.ID) {
				continue
			}
			if err := r.write("execution "+cond, ActCreate, WebhookTargetName, func() error {
				return r.addToExecution(ctx, cond, webhook.ID)
			}); err != nil {
				return err
			}
		}
		if groups == nil && r.o.GroupsURL != "" {
			if err := r.write("target "+GroupsTargetName, ActCreate, r.o.GroupsURL, func() error {
				id, key, err := r.api.CreateTarget(ctx, GroupsTargetName, r.o.GroupsURL, TargetRestCall)
				if err != nil {
					return err
				}
				groups = &Target{ID: id, Name: GroupsTargetName, Endpoint: r.o.GroupsURL, Kind: TargetRestCall}
				if err := r.recordCreated("groups_signing_key"); err != nil {
					return err
				}
				p, err := r.writeSecret("groups-signing-key", key)
				if err != nil {
					return err
				}
				r.res.Secrets["groups_signing_key"] = p
				return nil
			}); err != nil {
				return err
			}
		} else if groups != nil {
			r.plan("target "+GroupsTargetName, ActExists, groups.Endpoint)
		}
	}
	if r.o.GroupsExecution {
		cond := "function:" + FunctionPreuserinfo
		switch {
		case groups == nil:
			return errors.New("--groups-execution needs the groups target (--create-actions --groups-url)")
		case targetsHave(execs, cond, groups.ID):
			r.plan("execution "+cond, ActExists, GroupsTargetName)
		default:
			if err := r.write("execution "+cond, ActCreate, GroupsTargetName, func() error {
				return r.addToExecution(ctx, cond, groups.ID)
			}); err != nil {
				return err
			}
		}
	}

	// Report the v2 state as it is after this run (a dry run reports today's state).
	if !r.o.DryRun {
		if execs, err = r.api.Executions(ctx); err != nil {
			return fmt.Errorf("read Actions v2 executions: %w", err)
		}
	}
	v2.WebhookTarget = webhook != nil && webhook.ID != ""
	v2.GroupsTarget = groups != nil && groups.ID != ""
	v2.WebhookEvents = len(WebhookEvents)
	for _, ev := range WebhookEvents {
		if v2.WebhookTarget && targetsHave(execs, "event:"+ev, webhook.ID) {
			v2.WebhookExecutions++
		}
	}
	v2.GroupsExecution = targetsHave(execs, "function:"+FunctionPreuserinfo, "")
	if r.o.DryRun {
		v2.WebhookTarget, v2.GroupsTarget = webhook != nil, groups != nil
	}

	if !v2.WebhookTarget || v2.WebhookExecutions < v2.WebhookEvents {
		r.res.Guide = append(r.res.Guide, GuideItem{ID: "zitadel-webhook-target", Title: "Zitadel Actions v2 webhook target'ı onayla",
			Steps: []string{
				fmt.Sprintf("Actions v2 webhook target'ı (%s) ve %d olay execution'ı yok ya da eksik; tagcess rol değişikliklerini bu yolla anında duyar (yoksa periyodik senkron).", WebhookTargetName, len(WebhookEvents)),
				"Şirkette yalnız açık onayla oluşturulur: install.sh zitadel_seed fazında ayrıca sorar (zitadel_seed_create_actions=true).",
				"Oluşan imza anahtarı yalnız secret dosyasına yazılır ve host fazı onu /etc/tagcess/secrets'e kopyalar.",
			}})
	}
	if r.res.Report.ActionsV1.GroupsAction && !v2.GroupsExecution {
		r.res.Guide = append(r.res.Guide, GuideItem{ID: "zitadel-groups-v1-to-v2", Title: "groups claim'ini Actions v1'den v2'ye elle geçir (karar 2)",
			Steps: []string{
				fmt.Sprintf("Bugün groups claim'ini Actions v1 %q yazıyor; kurulum aracı v1'e dokunmaz ve v2 groups execution'ını oluşturmaz.", V1GroupsActionName),
				fmt.Sprintf("Uygun zamanda: Actions v2'de %s function'ını %s target'ına bağla, bir test girişiyle groups claim'ini doğrula, sonra v1 akışından %s'ı çıkar.", FunctionPreuserinfo, GroupsTargetName, V1GroupsActionName),
				"Geçiş sırasında iki kaynak aynı claim'i yazmasın: önce v2'yi bağla, doğrula, sonra v1'i kaldır.",
			}})
	}
	return nil
}
