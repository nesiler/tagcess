package zitadeladopt

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/zitadel-go/v3/pkg/client"
	actionv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/action/v2"
	applicationv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/application/v2"
	authorizationv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/authorization/v2"
	filterv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/filter/v2"
	internalpermissionv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/internal_permission/v2"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/management"
	objectv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/object/v2"
	projectv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/project/v2"
	userv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
	"google.golang.org/protobuf/types/known/durationpb"
)

// Conn locates Zitadel and the administrator credential. Exactly one of KeyFile (JWT profile key JSON) and PATFile
// (personal access token, fresh lab) is set. The credential is read from its file and never copied anywhere.
type Conn struct {
	Host     string
	Port     uint16
	Insecure bool // plaintext h2c, loopback hosts only (a local test stack)
	KeyFile  string
	PATFile  string
}

// pageSize is the list page size; the lists the installer reads are small.
const pageSize = 500

// targetTimeout is the per-delivery timeout of the targets the installer creates (as the lab seed).
const targetTimeout = 10 * time.Second

// GRPC is the API over Zitadel's gRPC services.
type GRPC struct {
	mgmt    management.ManagementServiceClient
	project projectv2.ProjectServiceClient
	apps    applicationv2.ApplicationServiceClient
	users   userv2.UserServiceClient
	perms   internalpermissionv2.InternalPermissionServiceClient
	authz   authorizationv2.AuthorizationServiceClient
	actions actionv2.ActionServiceClient
	close   func() error
}

// Dial connects with the administrator credential. Errors name files, never their content.
func Dial(ctx context.Context, c Conn) (*GRPC, error) {
	if c.Host == "" {
		return nil, errors.New("zitadel host is required")
	}
	if (c.KeyFile == "") == (c.PATFile == "") {
		return nil, errors.New("give exactly one of --admin-key-file and --admin-pat-file")
	}
	var auth client.TokenSourceInitializer
	if c.KeyFile != "" {
		if _, err := os.Stat(c.KeyFile); err != nil {
			return nil, fmt.Errorf("admin key file %s: %w", c.KeyFile, err)
		}
		auth = client.DefaultServiceUserAuthentication(c.KeyFile, oidc.ScopeOpenID, client.ScopeZitadelAPI())
	} else {
		raw, err := os.ReadFile(c.PATFile) // #nosec G304 -- operator-provided path
		if err != nil {
			return nil, fmt.Errorf("admin PAT file %s: %w", c.PATFile, err)
		}
		pat := strings.TrimSpace(string(raw))
		if pat == "" {
			return nil, fmt.Errorf("admin PAT file %s is empty", c.PATFile)
		}
		auth = client.PAT(pat)
	}
	var opts []zitadel.Option
	switch {
	case c.Insecure:
		if ip := net.ParseIP(c.Host); c.Host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return nil, fmt.Errorf("plaintext connection to %s refused: --insecure is for loopback hosts only", c.Host)
		}
		opts = append(opts, zitadel.WithInsecure(strconv.Itoa(int(c.Port))))
	case c.Port != 0:
		opts = append(opts, zitadel.WithPort(c.Port))
	}
	api, err := client.New(ctx, zitadel.New(c.Host, opts...), client.WithAuth(auth))
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", c.Host, err)
	}
	return &GRPC{
		mgmt: api.ManagementService(), project: api.ProjectServiceV2(), apps: api.ApplicationServiceV2(), users: api.UserServiceV2(),
		perms: api.InternalPermissionServiceV2(), authz: api.AuthorizationServiceV2(), actions: api.ActionServiceV2(), close: api.Close,
	}, nil
}

// Close closes the connection.
func (g *GRPC) Close() error { return g.close() }

func page() *filterv2.PaginationRequest { return &filterv2.PaginationRequest{Limit: pageSize} }

// OrgID is the administrator's organization.
func (g *GRPC) OrgID(ctx context.Context) (string, error) {
	resp, err := g.mgmt.GetMyOrg(ctx, &management.GetMyOrgRequest{})
	if err != nil {
		return "", err
	}
	return resp.GetOrg().GetId(), nil
}

// FindProject finds a project by exact name in the organization.
func (g *GRPC) FindProject(ctx context.Context, orgID, name string) (*Project, error) {
	resp, err := g.project.ListProjects(ctx, &projectv2.ListProjectsRequest{
		Pagination: page(),
		Filters: []*projectv2.ProjectSearchFilter{
			{Filter: &projectv2.ProjectSearchFilter_ProjectNameFilter{ProjectNameFilter: &projectv2.ProjectNameFilter{
				ProjectName: name, Method: filterv2.TextFilterMethod_TEXT_FILTER_METHOD_EQUALS}}},
			{Filter: &projectv2.ProjectSearchFilter_OrganizationIdFilter{OrganizationIdFilter: &projectv2.ProjectOrganizationIDFilter{OrganizationId: orgID}}},
		},
	})
	if err != nil {
		return nil, err
	}
	for _, p := range resp.GetProjects() {
		if p.GetName() == name {
			return &Project{ID: p.GetProjectId(), Name: p.GetName(), RoleAssertion: p.GetProjectRoleAssertion(),
				AuthorizationRequired: p.GetAuthorizationRequired()}, nil
		}
	}
	return nil, nil
}

// CreateProject creates the project with the settings tagcess expects (ADR 0009; role assertion and
// authorization required, as the lab seed and the existing installation's project).
func (g *GRPC) CreateProject(ctx context.Context, orgID, name string) (string, error) {
	resp, err := g.project.CreateProject(ctx, &projectv2.CreateProjectRequest{
		OrganizationId: orgID, Name: name, ProjectRoleAssertion: true, AuthorizationRequired: true,
	})
	if err != nil {
		return "", err
	}
	return resp.GetProjectId(), nil
}

// ProjectRoles lists the role keys of the project.
func (g *GRPC) ProjectRoles(ctx context.Context, projectID string) ([]string, error) {
	resp, err := g.project.ListProjectRoles(ctx, &projectv2.ListProjectRolesRequest{ProjectId: projectID, Pagination: page()})
	if err != nil {
		return nil, err
	}
	var keys []string
	for _, r := range resp.GetProjectRoles() {
		keys = append(keys, r.GetKey())
	}
	return keys, nil
}

// AddProjectRole adds one role.
func (g *GRPC) AddProjectRole(ctx context.Context, projectID, key string) error {
	_, err := g.project.AddProjectRole(ctx, &projectv2.AddProjectRoleRequest{ProjectId: projectID, RoleKey: key, DisplayName: key})
	return err
}

// FindApp finds an OIDC application by exact name in the project.
func (g *GRPC) FindApp(ctx context.Context, projectID, name string) (*App, error) {
	resp, err := g.apps.ListApplications(ctx, &applicationv2.ListApplicationsRequest{
		Pagination: page(),
		Filters: []*applicationv2.ApplicationSearchFilter{
			{Filter: &applicationv2.ApplicationSearchFilter_ProjectIdFilter{ProjectIdFilter: &applicationv2.ProjectIDFilter{ProjectId: projectID}}},
			{Filter: &applicationv2.ApplicationSearchFilter_NameFilter{NameFilter: &applicationv2.ApplicationNameFilter{Name: name}}},
		},
	})
	if err != nil {
		return nil, err
	}
	for _, a := range resp.GetApplications() {
		if a.GetName() != name {
			continue
		}
		oidcCfg := a.GetOidcConfiguration()
		if oidcCfg == nil {
			return nil, fmt.Errorf("application %s is not an OIDC application", name)
		}
		return &App{ID: a.GetApplicationId(), Name: name, ClientID: oidcCfg.GetClientId(),
			RedirectURIs: slices.Clone(oidcCfg.GetRedirectUris()), PostLogoutURIs: slices.Clone(oidcCfg.GetPostLogoutRedirectUris())}, nil
	}
	return nil, nil
}

// CreateApp creates a web OIDC application (code flow, basic auth, the Zitadel defaults the lab seed uses).
func (g *GRPC) CreateApp(ctx context.Context, projectID, name string, redirects, postLogout []string) (App, string, error) {
	resp, err := g.apps.CreateApplication(ctx, &applicationv2.CreateApplicationRequest{
		ProjectId: projectID, Name: name,
		ApplicationType: &applicationv2.CreateApplicationRequest_OidcConfiguration{OidcConfiguration: &applicationv2.CreateOIDCApplicationRequest{
			RedirectUris: redirects, PostLogoutRedirectUris: postLogout,
		}},
	})
	if err != nil {
		return App{}, "", err
	}
	o := resp.GetOidcConfiguration()
	return App{ID: resp.GetApplicationId(), Name: name, ClientID: o.GetClientId(), RedirectURIs: redirects, PostLogoutURIs: postLogout},
		o.GetClientSecret(), nil
}

// SetAppURIs writes both URI lists; every other OIDC field is sent back as read (UpdateApplication resets missing
// fields). The caller passes supersets of today's lists only.
func (g *GRPC) SetAppURIs(ctx context.Context, projectID string, app App, redirects, postLogout []string) error {
	cur, err := g.apps.GetApplication(ctx, &applicationv2.GetApplicationRequest{ApplicationId: app.ID})
	if err != nil {
		return err
	}
	o := cur.GetApplication().GetOidcConfiguration()
	if o == nil {
		return fmt.Errorf("application %s is not an OIDC application", app.Name)
	}
	for _, u := range o.GetRedirectUris() {
		if !slices.Contains(redirects, u) {
			return fmt.Errorf("application %s: refusing a write that would drop the redirect URI %s", app.Name, u)
		}
	}
	for _, u := range o.GetPostLogoutRedirectUris() {
		if !slices.Contains(postLogout, u) {
			return fmt.Errorf("application %s: refusing a write that would drop the post-logout URI %s", app.Name, u)
		}
	}
	_, err = g.apps.UpdateApplication(ctx, &applicationv2.UpdateApplicationRequest{
		ApplicationId: app.ID, ProjectId: projectID,
		ApplicationType: &applicationv2.UpdateApplicationRequest_OidcConfiguration{OidcConfiguration: &applicationv2.UpdateOIDCApplicationConfigurationRequest{
			RedirectUris: redirects, PostLogoutRedirectUris: postLogout, ResponseTypes: o.GetResponseTypes(),
			GrantTypes: o.GetGrantTypes(), ClockSkew: o.GetClockSkew(), LoginVersion: o.GetLoginVersion(),
		}},
	})
	return err
}

// FindUser finds a user by exact user name.
func (g *GRPC) FindUser(ctx context.Context, username string) (*User, error) {
	resp, err := g.users.ListUsers(ctx, &userv2.ListUsersRequest{Queries: []*userv2.SearchQuery{
		{Query: &userv2.SearchQuery_UserNameQuery{UserNameQuery: &userv2.UserNameQuery{UserName: username, Method: objectv2.TextQueryMethod_TEXT_QUERY_METHOD_EQUALS}}},
	}})
	if err != nil {
		return nil, err
	}
	for _, u := range resp.GetResult() {
		if u.GetUsername() == username {
			return &User{ID: u.GetUserId(), Username: username, Machine: u.GetMachine() != nil}, nil
		}
	}
	return nil, nil
}

// MemberRoles lists the administrator roles of a user on a project or an organization.
func (g *GRPC) MemberRoles(ctx context.Context, userID, resource, resourceID string) ([]string, error) {
	rf := &internalpermissionv2.ResourceFilter{}
	switch resource {
	case "project":
		rf.Resource = &internalpermissionv2.ResourceFilter_ProjectId{ProjectId: resourceID}
	case "org":
		rf.Resource = &internalpermissionv2.ResourceFilter_OrganizationId{OrganizationId: resourceID}
	default:
		return nil, fmt.Errorf("unknown resource %q", resource)
	}
	resp, err := g.perms.ListAdministrators(ctx, &internalpermissionv2.ListAdministratorsRequest{
		Pagination: page(),
		Filters: []*internalpermissionv2.AdministratorSearchFilter{
			{Filter: &internalpermissionv2.AdministratorSearchFilter_InUserIdsFilter{InUserIdsFilter: &filterv2.InIDsFilter{Ids: []string{userID}}}},
			{Filter: &internalpermissionv2.AdministratorSearchFilter_Resource{Resource: rf}},
		},
	})
	if err != nil {
		return nil, err
	}
	var roles []string
	for _, a := range resp.GetAdministrators() {
		roles = append(roles, a.GetRoles()...)
	}
	return roles, nil
}

// KeyCount counts the machine keys of a user (key material is never readable).
func (g *GRPC) KeyCount(ctx context.Context, userID string) (int, error) {
	resp, err := g.users.ListKeys(ctx, &userv2.ListKeysRequest{
		Pagination: page(),
		Filters:    []*userv2.KeysSearchFilter{{Filter: &userv2.KeysSearchFilter_UserIdFilter{UserIdFilter: &filterv2.IDFilter{Id: userID}}}},
	})
	if err != nil {
		return 0, err
	}
	return len(resp.GetResult()), nil
}

// FindTarget finds an Actions v2 target by exact name.
func (g *GRPC) FindTarget(ctx context.Context, name string) (*Target, error) {
	resp, err := g.actions.ListTargets(ctx, &actionv2.ListTargetsRequest{
		Pagination: page(),
		Filters: []*actionv2.TargetSearchFilter{{Filter: &actionv2.TargetSearchFilter_TargetNameFilter{
			TargetNameFilter: &actionv2.TargetNameFilter{TargetName: name, Method: filterv2.TextFilterMethod_TEXT_FILTER_METHOD_EQUALS}}}},
	})
	if err != nil {
		return nil, err
	}
	for _, t := range resp.GetTargets() {
		if t.GetName() == name {
			kind := TargetRestAsync
			if t.GetRestCall() != nil {
				kind = TargetRestCall
			}
			return &Target{ID: t.GetId(), Name: name, Endpoint: t.GetEndpoint(), Kind: kind}, nil
		}
	}
	return nil, nil
}

// CreateTarget creates a rest_async (webhook) or rest_call (groups claim) target and returns its id and the
// signing key Zitadel shows only now.
func (g *GRPC) CreateTarget(ctx context.Context, name, endpoint, kind string) (string, string, error) {
	req := &actionv2.CreateTargetRequest{Name: name, Endpoint: endpoint, Timeout: durationpb.New(targetTimeout), PayloadType: actionv2.PayloadType_PAYLOAD_TYPE_JSON}
	if kind == TargetRestCall {
		req.TargetType = &actionv2.CreateTargetRequest_RestCall{RestCall: &actionv2.RESTCall{}}
	} else {
		req.TargetType = &actionv2.CreateTargetRequest_RestAsync{RestAsync: &actionv2.RESTAsync{}}
	}
	resp, err := g.actions.CreateTarget(ctx, req)
	if err != nil {
		return "", "", err
	}
	return resp.GetId(), resp.GetSigningKey(), nil
}

// Executions lists the Actions v2 executions as "event:<name>" / "function:<name>" conditions.
func (g *GRPC) Executions(ctx context.Context) ([]Execution, error) {
	resp, err := g.actions.ListExecutions(ctx, &actionv2.ListExecutionsRequest{Pagination: page()})
	if err != nil {
		return nil, err
	}
	var out []Execution
	for _, e := range resp.GetExecutions() {
		c := e.GetCondition()
		var cond string
		switch {
		case c.GetEvent() != nil:
			cond = "event:" + c.GetEvent().GetEvent()
		case c.GetFunction() != nil:
			cond = "function:" + c.GetFunction().GetName()
		default:
			continue
		}
		out = append(out, Execution{Condition: cond, Targets: slices.Clone(e.GetTargets())})
	}
	return out, nil
}

// SetExecution sets the targets of one event or function execution.
func (g *GRPC) SetExecution(ctx context.Context, condition string, targetIDs []string) error {
	kind, name, ok := strings.Cut(condition, ":")
	if !ok {
		return fmt.Errorf("bad condition %q", condition)
	}
	c := &actionv2.Condition{}
	switch kind {
	case "event":
		c.ConditionType = &actionv2.Condition_Event{Event: &actionv2.EventExecution{Condition: &actionv2.EventExecution_Event{Event: name}}}
	case "function":
		c.ConditionType = &actionv2.Condition_Function{Function: &actionv2.FunctionExecution{Name: name}}
	default:
		return fmt.Errorf("bad condition %q", condition)
	}
	_, err := g.actions.SetExecution(ctx, &actionv2.SetExecutionRequest{Condition: c, Targets: targetIDs})
	return err
}

// V1Actions lists the Actions v1 names and which of them a flow trigger runs (read only; never changed).
func (g *GRPC) V1Actions(ctx context.Context) ([]string, map[string]bool, error) {
	resp, err := g.mgmt.ListActions(ctx, &management.ListActionsRequest{})
	if err != nil {
		return nil, nil, err
	}
	var names []string
	for _, a := range resp.GetResult() {
		names = append(names, a.GetName())
	}
	bound := map[string]bool{}
	types, err := g.mgmt.ListFlowTypes(ctx, &management.ListFlowTypesRequest{})
	if err != nil {
		return nil, nil, err
	}
	for _, ft := range types.GetResult() {
		flow, err := g.mgmt.GetFlow(ctx, &management.GetFlowRequest{Type: ft.GetId()})
		if err != nil {
			return nil, nil, err
		}
		for _, ta := range flow.GetFlow().GetTriggerActions() {
			for _, a := range ta.GetActions() {
				bound[a.GetName()] = true
			}
		}
	}
	return names, bound, nil
}

// UnroledActiveUsers counts active human users of the organization without any active authorization in the
// project. Only the number leaves this function.
func (g *GRPC) UnroledActiveUsers(ctx context.Context, orgID, projectID string) (int, error) {
	users, err := g.users.ListUsers(ctx, &userv2.ListUsersRequest{
		Query: &objectv2.ListQuery{Limit: pageSize},
		Queries: []*userv2.SearchQuery{
			{Query: &userv2.SearchQuery_TypeQuery{TypeQuery: &userv2.TypeQuery{Type: userv2.Type_TYPE_HUMAN}}},
			{Query: &userv2.SearchQuery_StateQuery{StateQuery: &userv2.StateQuery{State: userv2.UserState_USER_STATE_ACTIVE}}},
			{Query: &userv2.SearchQuery_OrganizationIdQuery{OrganizationIdQuery: &userv2.OrganizationIdQuery{OrganizationId: orgID}}},
		},
	})
	if err != nil {
		return 0, err
	}
	if t := users.GetDetails().GetTotalResult(); t > uint64(len(users.GetResult())) {
		return 0, fmt.Errorf("more than %d users: the count would be incomplete", pageSize)
	}
	auths, err := g.authz.ListAuthorizations(ctx, &authorizationv2.ListAuthorizationsRequest{
		Pagination: page(),
		Filters: []*authorizationv2.AuthorizationsSearchFilter{{Filter: &authorizationv2.AuthorizationsSearchFilter_ProjectId{
			ProjectId: &filterv2.IDFilter{Id: projectID}}}},
	})
	if err != nil {
		return 0, err
	}
	if t := auths.GetPagination().GetTotalResult(); t > uint64(len(auths.GetAuthorizations())) {
		return 0, fmt.Errorf("more than %d authorizations: the count would be incomplete", pageSize)
	}
	roled := map[string]bool{}
	for _, a := range auths.GetAuthorizations() {
		if a.GetState() == authorizationv2.State_STATE_ACTIVE && len(a.GetRoles()) > 0 {
			roled[a.GetUser().GetId()] = true
		}
	}
	n := 0
	for _, u := range users.GetResult() {
		if !roled[u.GetUserId()] {
			n++
		}
	}
	return n, nil
}
