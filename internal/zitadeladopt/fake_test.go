package zitadeladopt

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
)

// fakeZitadel is an in-memory Zitadel for the decision tables. Users, grants and memberships exist only as
// data the API can read: it has no way to change them, which the tests also check.
type fakeZitadel struct {
	orgErr     error
	failWrite  int // the n-th write (1-based) fails; 0 never
	writes     int
	nextID     int
	project    *Project
	roles      []string
	apps       map[string]*App
	users      map[string]User     // username -> user
	members    map[string][]string // userID|resource|resourceID -> roles
	keys       map[string]int
	grants     map[string][]string // userID -> roles in the project
	active     map[string]bool     // userID -> active human
	targets    map[string]*Target
	executions map[string][]string
	v1         []string
	v1Bound    map[string]bool
	secrets    []string // every secret value handed out
}

func newFake() *fakeZitadel {
	return &fakeZitadel{apps: map[string]*App{}, users: map[string]User{}, members: map[string][]string{}, keys: map[string]int{},
		grants: map[string][]string{}, active: map[string]bool{}, targets: map[string]*Target{}, executions: map[string][]string{},
		v1Bound: map[string]bool{}}
}

func (f *fakeZitadel) id(prefix string) string {
	f.nextID++
	return fmt.Sprintf("%s-%d", prefix, f.nextID)
}

func (f *fakeZitadel) write() error {
	f.writes++
	if f.failWrite > 0 && f.writes == f.failWrite {
		return errors.New("injected write failure")
	}
	return nil
}

// snapshot is everything the fake holds, for before/after comparisons.
func (f *fakeZitadel) snapshot() string {
	var b strings.Builder
	fmt.Fprintf(&b, "project=%+v roles=%v\n", f.project, f.roles)
	keys := func(m any) []string {
		var out []string
		switch mm := m.(type) {
		case map[string]*App:
			for k, v := range mm {
				out = append(out, fmt.Sprintf("%s=%+v", k, *v))
			}
		case map[string]*Target:
			for k, v := range mm {
				out = append(out, fmt.Sprintf("%s=%+v", k, *v))
			}
		case map[string][]string:
			for k, v := range mm {
				out = append(out, fmt.Sprintf("%s=%v", k, v))
			}
		}
		sort.Strings(out)
		return out
	}
	fmt.Fprintf(&b, "apps=%v targets=%v executions=%v\n", keys(f.apps), keys(f.targets), keys(f.executions))
	fmt.Fprintf(&b, "%s", f.peopleSnapshot())
	return b.String()
}

// peopleSnapshot is users, grants, memberships and keys: what the step must never change.
func (f *fakeZitadel) peopleSnapshot() string {
	var u []string
	for k, v := range f.users {
		u = append(u, fmt.Sprintf("%s=%+v", k, v))
	}
	sort.Strings(u)
	var g, m []string
	for k, v := range f.grants {
		g = append(g, fmt.Sprintf("%s=%v", k, v))
	}
	for k, v := range f.members {
		m = append(m, fmt.Sprintf("%s=%v", k, v))
	}
	sort.Strings(g)
	sort.Strings(m)
	return fmt.Sprintf("users=%v grants=%v members=%v keys=%v v1=%v %v\n", u, g, m, f.keys, f.v1, f.v1Bound)
}

func (f *fakeZitadel) OrgID(context.Context) (string, error) {
	if f.orgErr != nil {
		return "", f.orgErr
	}
	return "org-1", nil
}

func (f *fakeZitadel) FindProject(_ context.Context, _, name string) (*Project, error) {
	if f.project != nil && f.project.Name == name {
		p := *f.project
		return &p, nil
	}
	return nil, nil
}

func (f *fakeZitadel) CreateProject(_ context.Context, _, name string) (string, error) {
	if err := f.write(); err != nil {
		return "", err
	}
	f.project = &Project{ID: f.id("project"), Name: name, RoleAssertion: true, AuthorizationRequired: true}
	return f.project.ID, nil
}

func (f *fakeZitadel) ProjectRoles(context.Context, string) ([]string, error) {
	return slices.Clone(f.roles), nil
}

func (f *fakeZitadel) AddProjectRole(_ context.Context, _, key string) error {
	if err := f.write(); err != nil {
		return err
	}
	if !slices.Contains(f.roles, key) {
		f.roles = append(f.roles, key)
	}
	return nil
}

func (f *fakeZitadel) FindApp(_ context.Context, _, name string) (*App, error) {
	if a, ok := f.apps[name]; ok {
		c := *a
		c.RedirectURIs, c.PostLogoutURIs = slices.Clone(a.RedirectURIs), slices.Clone(a.PostLogoutURIs)
		return &c, nil
	}
	return nil, nil
}

func (f *fakeZitadel) CreateApp(_ context.Context, _, name string, redirects, postLogout []string) (App, string, error) {
	if err := f.write(); err != nil {
		return App{}, "", err
	}
	a := &App{ID: f.id("app"), Name: name, ClientID: f.id("client"), RedirectURIs: slices.Clone(redirects), PostLogoutURIs: slices.Clone(postLogout)}
	f.apps[name] = a
	secret := "zSECRETclient" + strings.Repeat("Ab9", 12) + name
	f.secrets = append(f.secrets, secret)
	return *a, secret, nil
}

func (f *fakeZitadel) SetAppURIs(_ context.Context, _ string, app App, redirects, postLogout []string) error {
	if err := f.write(); err != nil {
		return err
	}
	a := f.apps[app.Name]
	a.RedirectURIs, a.PostLogoutURIs = slices.Clone(redirects), slices.Clone(postLogout)
	return nil
}

func (f *fakeZitadel) FindUser(_ context.Context, username string) (*User, error) {
	if u, ok := f.users[username]; ok {
		return &u, nil
	}
	return nil, nil
}

func (f *fakeZitadel) MemberRoles(_ context.Context, userID, resource, resourceID string) ([]string, error) {
	return slices.Clone(f.members[userID+"|"+resource+"|"+resourceID]), nil
}

func (f *fakeZitadel) KeyCount(_ context.Context, userID string) (int, error) {
	return f.keys[userID], nil
}

func (f *fakeZitadel) FindTarget(_ context.Context, name string) (*Target, error) {
	if t, ok := f.targets[name]; ok {
		c := *t
		return &c, nil
	}
	return nil, nil
}

func (f *fakeZitadel) CreateTarget(_ context.Context, name, endpoint, kind string) (string, string, error) {
	if err := f.write(); err != nil {
		return "", "", err
	}
	t := &Target{ID: f.id("target"), Name: name, Endpoint: endpoint, Kind: kind}
	f.targets[name] = t
	key := "SIGNkey" + strings.Repeat("Qz7", 12) + name
	f.secrets = append(f.secrets, key)
	return t.ID, key, nil
}

func (f *fakeZitadel) Executions(context.Context) ([]Execution, error) {
	var out []Execution
	for c, t := range f.executions {
		out = append(out, Execution{Condition: c, Targets: slices.Clone(t)})
	}
	return out, nil
}

func (f *fakeZitadel) SetExecution(_ context.Context, condition string, ids []string) error {
	if err := f.write(); err != nil {
		return err
	}
	f.executions[condition] = slices.Clone(ids)
	return nil
}

func (f *fakeZitadel) V1Actions(context.Context) ([]string, map[string]bool, error) {
	b := map[string]bool{}
	for k, v := range f.v1Bound {
		b[k] = v
	}
	return slices.Clone(f.v1), b, nil
}

func (f *fakeZitadel) UnroledActiveUsers(context.Context, string, string) (int, error) {
	n := 0
	for _, u := range f.users {
		if !u.Machine && f.active[u.ID] && len(f.grants[u.ID]) == 0 {
			n++
		}
	}
	return n, nil
}

// existingFake is the adopt shape: the vpn project with roles, both apps (oauth2-proxy with site callbacks),
// people with and without roles, Actions v1 vpnGroups bound, no v2 objects, no tagcess service user.
func existingFake() *fakeZitadel {
	f := newFake()
	f.project = &Project{ID: "p-vpn", Name: "vpn", RoleAssertion: true, AuthorizationRequired: true}
	f.roles = []string{"devops", "developer", "standart"}
	f.apps["headscale"] = &App{ID: "a-hs", Name: "headscale", ClientID: "c-hs", RedirectURIs: []string{"https://hs.example.test/oidc/callback"}}
	f.apps["oauth2-proxy"] = &App{ID: "a-op", Name: "oauth2-proxy", ClientID: "c-op",
		RedirectURIs: []string{"https://monitor.example.test/oauth2/callback", "https://docs.example.test/oauth2/callback"}}
	for i, name := range []string{"alice@example.test", "bob@example.test", "carol@example.test", "dave@example.test"} {
		id := fmt.Sprintf("u%d", i)
		f.users[name] = User{ID: id, Username: name}
		f.active[id] = true
	}
	f.grants["u0"] = []string{"devops"}
	f.grants["u1"] = []string{"developer"}
	f.members["u0|org|org-1"] = []string{"ORG_OWNER"}
	f.v1 = []string{V1GroupsActionName}
	f.v1Bound[V1GroupsActionName] = true
	return f
}

func existingOptions(dir string) Options {
	return Options{
		ProjectName: "vpn", Roles: []string{"devops", "developer", "standart"}, ServiceUser: "tagcess", SecretOutDir: dir,
		Apps: []AppSpec{
			{Name: "headscale", SecretKey: "headscale_oidc_client_secret", RedirectURIs: []string{"https://hs.example.test/oidc/callback"}},
			{Name: "oauth2-proxy", SecretKey: "oauth2_proxy_client_secret", RedirectURIs: []string{"https://tagcess.example.test/oauth2/callback"},
				PostLogoutURIs: []string{"https://tagcess.example.test/"}},
		},
		WebhookURL: "http://100.64.0.4:9443/hook", GroupsURL: "http://100.64.0.4:9443/groups",
	}
}
