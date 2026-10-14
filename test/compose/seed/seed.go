// Package seed bootstraps the lab Zitadel and the compose Headscale for tagcess's F1 integration tests
// (F1-004): the "vpn" project, its roles, a few example users, the tagcess service user and its
// JWT profile key, the "headscale" OIDC app, and a Headscale user with a pre-auth key for
// registering test nodes without a browser.
//
// Every step is create-if-missing, not full reconciliation: Zitadel's v2 APIs return
// codes.AlreadyExists on a duplicate create, which this package treats as success, so running the
// seed twice against the same stack is safe (AC2) but does not update anything that already
// exists — a role reassigned to a TestUser between two runs, for instance, keeps its old grant
// too. That's fine for a disposable test fixture; it would not be for a real reconcile loop. The
// one true exception is the service user's key: Zitadel never lets you fetch a key's private
// material again, so the key is only (re)created when it's missing or belongs to a different user.
package seed

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	zclient "github.com/zitadel/zitadel-go/v3/pkg/client"

	actionv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/action/v2"
	applicationv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/application/v2"
	authorizationv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/authorization/v2"
	filterv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/filter/v2"
	internalpermissionv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/internal_permission/v2"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/management"
	objectv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/object/v2"
	projectv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/project/v2"
	userv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
)

const (
	// ProjectName is the Zitadel project tagcess reads roles from (ADR 0009, overview.md §6.3).
	ProjectName = "vpn"
	// ServiceUserName is the tagcess service (machine) user, scoped to ProjectName as PROJECT_OWNER.
	ServiceUserName = "tagcess"
	// HeadscaleAppName is the Zitadel OIDC application Headscale logs test users in through.
	HeadscaleAppName = "headscale"
)

// Roles are the project roles tagcess's local test stack seeds (overview.md §6.3 [K]).
var Roles = []string{"devops", "developer", "standart"}

// TestUser is one example human user, granted exactly one role.
type TestUser struct {
	Username string
	Role     string
}

// TestUsers are the example users the seed creates, one per role.
var TestUsers = []TestUser{
	{Username: "devops@tagcess.test", Role: "devops"},
	{Username: "developer@tagcess.test", Role: "developer"},
	{Username: "standart@tagcess.test", Role: "standart"},
}

// TestUserPassword is the fixed password for TestUsers. This is a disposable lab
// (ADR 0014; test/compose/.secrets is gitignored); there is nothing to protect a real secret from.
const TestUserPassword = "Tagcess-Test-1!" // #nosec G101 -- not a secret, see comment above

// Config points the seed at the lab Zitadel and where to write its output.
type Config struct {
	// ZitadelAddr is host:port of Zitadel, e.g. "tagcess-zitadel.lab.example.com:443" (lab).
	ZitadelAddr string
	// ZitadelTLS is true when ZitadelAddr speaks TLS; false means plaintext gRPC (h2c).
	ZitadelTLS bool
	// BootstrapPAT authenticates as the FirstInstance machine user (IAM_OWNER); lab-up copies its PAT
	// from the cluster Secret to test/compose/.secrets/lab/bootstrap-pat (test/lab/up.sh).
	BootstrapPAT string
	// SecretsDir is test/compose/.secrets/lab: the service user's key.json is cached here.
	SecretsDir string
	// EnvFile is test/compose/.env: HEADSCALE_OIDC_CLIENT_ID/SECRET are written here for
	// compose.yaml to pick up before Headscale starts.
	EnvFile string
	// HeadscaleRedirectURI is Headscale's OIDC callback (server_url + "/oidc/callback").
	HeadscaleRedirectURI string
	// OAuth2ProxyRedirectURI is the local oauth2-proxy callback
	// (http://localhost:8080/oauth2/callback). Empty skips the oauth2-proxy app.
	OAuth2ProxyRedirectURI string
	// OAuth2ProxyPostLogoutURI is registered as the oauth2-proxy app's post-logout redirect URI when the
	// app is created (J1); tagcess adds it to an existing app itself. Empty registers none.
	OAuth2ProxyPostLogoutURI string
	// WebhookURL is the Actions v2 target endpoint (the tagcess webhook, e.g.
	// http://100.65.26.120:9443/hook). Empty skips the target and executions.
	WebhookURL string
	// GroupsURL is the Actions v2 `rest_call` target endpoint that answers the `groups` claim
	// during `preuserinfo` (F1-026, e.g. http://100.65.26.120:9443/groups). Empty skips it.
	GroupsURL string
}

// Result is what SeedZitadel produced or found already present.
type Result struct {
	OrgID           string
	ProjectID       string
	RoleKeys        []string
	Users           map[string]string // username -> user id
	ServiceUserID   string
	KeyFilePath     string
	HeadscaleApp    *OIDCAppResult
	OAuth2ProxyApp  *OIDCAppResult
	WebhookTargetID string
	GroupsTargetID  string
}

// OIDCAppResult is a Zitadel OIDC app the test stack authenticates through.
type OIDCAppResult struct {
	AppID    string
	ClientID string
	// ClientSecret is empty when the app already existed: Zitadel only reveals a client secret
	// once, at creation. On a second run the seed keeps whatever is already in cfg.EnvFile.
	ClientSecret string
}

// SeedZitadel is the Zitadel half of the seed tool: project, roles, example users, the tagcess
// service user and key, and the Headscale OIDC app. Safe to call repeatedly (AC2).
func SeedZitadel(ctx context.Context, cfg Config) (*Result, error) {
	conn, err := grpc.NewClient(cfg.ZitadelAddr, Endpoint{TLS: cfg.ZitadelTLS}.DialOption())
	if err != nil {
		return nil, fmt.Errorf("seed: dial zitadel: %w", err)
	}
	defer func() { _ = conn.Close() }()

	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+cfg.BootstrapPAT)
	mgmt := management.NewManagementServiceClient(conn)
	projects := projectv2.NewProjectServiceClient(conn)
	users := userv2.NewUserServiceClient(conn)
	permissions := internalpermissionv2.NewInternalPermissionServiceClient(conn)
	applications := applicationv2.NewApplicationServiceClient(conn)

	org, err := mgmt.GetMyOrg(ctx, &management.GetMyOrgRequest{})
	if err != nil {
		return nil, fmt.Errorf("seed: get bootstrap org: %w", err)
	}
	orgID := org.GetOrg().GetId()

	res := &Result{OrgID: orgID, Users: map[string]string{}}

	projectID, err := getOrCreateProject(ctx, projects, orgID)
	if err != nil {
		return nil, err
	}
	res.ProjectID = projectID
	// The project id is stable and not a secret; caching it in the env file lets local tools
	// (make ui) build a tagcess config without querying Zitadel. .env is already the shared output
	// for the compose stack's client ids/secrets (seed package doc).
	if cfg.EnvFile != "" {
		if err := upsertEnv(cfg.EnvFile, map[string]string{"ZITADEL_PROJECT_ID": projectID}); err != nil {
			return nil, err
		}
	}

	for _, role := range Roles {
		if err := addProjectRole(ctx, projects, projectID, role); err != nil {
			return nil, err
		}
		res.RoleKeys = append(res.RoleKeys, role)
	}

	for _, tu := range TestUsers {
		userID, err := getOrCreateHumanUser(ctx, users, orgID, tu.Username)
		if err != nil {
			return nil, err
		}
		res.Users[tu.Username] = userID
		if err := grantRole(ctx, conn, userID, projectID, orgID, tu.Role); err != nil {
			return nil, err
		}
	}

	serviceUserID, err := getOrCreateMachineUser(ctx, users, orgID, ServiceUserName)
	if err != nil {
		return nil, err
	}
	res.ServiceUserID = serviceUserID

	if err := addProjectMember(ctx, permissions, projectID, serviceUserID, "PROJECT_OWNER"); err != nil {
		return nil, err
	}
	// ADR 0009 (F1-007 amendment): reading user states needs a read-only org role; project scope alone
	// makes ListUsers hide every other user without touching totalResult.
	if err := addOrgMember(ctx, permissions, orgID, serviceUserID, "ORG_OWNER_VIEWER"); err != nil {
		return nil, err
	}

	keyPath := filepath.Join(cfg.SecretsDir, "zitadel-key.json")
	if err := ensureServiceUserKey(ctx, users, serviceUserID, keyPath); err != nil {
		return nil, err
	}
	res.KeyFilePath = keyPath

	if cfg.HeadscaleRedirectURI != "" {
		app, err := EnsureOIDCApp(ctx, applications, projectID, HeadscaleAppName, cfg.HeadscaleRedirectURI, cfg.EnvFile, "HEADSCALE_OIDC_CLIENT_ID", "HEADSCALE_OIDC_CLIENT_SECRET")
		if err != nil {
			return nil, err
		}
		res.HeadscaleApp = app
	}

	if cfg.OAuth2ProxyRedirectURI != "" {
		if err := EnsureCookieSecret(cfg.EnvFile); err != nil {
			return nil, err
		}
		var postLogout []string
		if cfg.OAuth2ProxyPostLogoutURI != "" {
			postLogout = []string{cfg.OAuth2ProxyPostLogoutURI}
		}
		app, err := EnsureOIDCApp(ctx, applications, projectID, OAuth2ProxyAppName, cfg.OAuth2ProxyRedirectURI, cfg.EnvFile, "OAUTH2_PROXY_CLIENT_ID", "OAUTH2_PROXY_CLIENT_SECRET", postLogout...)
		if err != nil {
			return nil, err
		}
		res.OAuth2ProxyApp = app
	}

	if cfg.WebhookURL != "" || cfg.GroupsURL != "" {
		actions := actionv2.NewActionServiceClient(conn)
		if cfg.WebhookURL != "" {
			targetID, err := EnsureWebhookTarget(ctx, actions, cfg.WebhookURL, cfg.SecretsDir)
			if err != nil {
				return nil, err
			}
			if err := EnsureWebhookExecutions(ctx, actions, targetID); err != nil {
				return nil, err
			}
			res.WebhookTargetID = targetID
		}
		if cfg.GroupsURL != "" {
			targetID, err := EnsureGroupsTarget(ctx, actions, cfg.GroupsURL, cfg.SecretsDir)
			if err != nil {
				return nil, err
			}
			if err := EnsureGroupsExecution(ctx, actions, targetID); err != nil {
				return nil, err
			}
			res.GroupsTargetID = targetID
		}
	}

	return res, nil
}

// ignoreAlreadyExists treats a codes.AlreadyExists gRPC error as success: Zitadel returns it for
// any duplicate create, which is exactly the outcome the seed wants on a second run.
func ignoreAlreadyExists(err error) error {
	if err == nil || status.Code(err) == codes.AlreadyExists {
		return nil
	}
	return err
}

func isAlreadyExists(err error) bool {
	return status.Code(err) == codes.AlreadyExists
}

func getOrCreateProject(ctx context.Context, c projectv2.ProjectServiceClient, orgID string) (string, error) {
	if id, err := findProjectID(ctx, c, orgID); err != nil {
		return "", err
	} else if id != "" {
		return id, nil
	}
	resp, err := c.CreateProject(ctx, &projectv2.CreateProjectRequest{
		OrganizationId:        orgID,
		Name:                  ProjectName,
		ProjectRoleAssertion:  true,
		AuthorizationRequired: true,
		ProjectAccessRequired: false,
	})
	if err != nil {
		if isAlreadyExists(err) {
			id, ferr := findProjectID(ctx, c, orgID)
			if ferr != nil {
				return "", ferr
			}
			if id != "" {
				return id, nil
			}
		}
		return "", fmt.Errorf("seed: create project %q: %w", ProjectName, err)
	}
	return resp.GetProjectId(), nil
}

func findProjectID(ctx context.Context, c projectv2.ProjectServiceClient, orgID string) (string, error) {
	resp, err := c.ListProjects(ctx, &projectv2.ListProjectsRequest{
		Filters: []*projectv2.ProjectSearchFilter{
			{Filter: &projectv2.ProjectSearchFilter_ProjectNameFilter{
				ProjectNameFilter: &projectv2.ProjectNameFilter{
					ProjectName: ProjectName,
					Method:      filterv2.TextFilterMethod_TEXT_FILTER_METHOD_EQUALS,
				},
			}},
			{Filter: &projectv2.ProjectSearchFilter_OrganizationIdFilter{
				OrganizationIdFilter: &projectv2.ProjectOrganizationIDFilter{OrganizationId: orgID},
			}},
		},
	})
	if err != nil {
		return "", fmt.Errorf("seed: list projects: %w", err)
	}
	for _, p := range resp.GetProjects() {
		if p.GetName() == ProjectName {
			return p.GetProjectId(), nil
		}
	}
	return "", nil
}

func addProjectRole(ctx context.Context, c projectv2.ProjectServiceClient, projectID, role string) error {
	_, err := c.AddProjectRole(ctx, &projectv2.AddProjectRoleRequest{
		ProjectId:   projectID,
		RoleKey:     role,
		DisplayName: role,
	})
	return ignoreAlreadyExists(err)
}

func getOrCreateHumanUser(ctx context.Context, c userv2.UserServiceClient, orgID, username string) (string, error) {
	if id, err := findUserID(ctx, c, username); err != nil {
		return "", err
	} else if id != "" {
		return id, nil
	}
	resp, err := c.CreateUser(ctx, &userv2.CreateUserRequest{
		OrganizationId: orgID,
		Username:       &username,
		UserType: &userv2.CreateUserRequest_Human_{
			Human: &userv2.CreateUserRequest_Human{
				Profile: &userv2.SetHumanProfile{
					GivenName:  "tagcess",
					FamilyName: "test",
				},
				Email: &userv2.SetHumanEmail{
					Email:        username,
					Verification: &userv2.SetHumanEmail_IsVerified{IsVerified: true},
				},
				PasswordType: &userv2.CreateUserRequest_Human_Password{
					Password: &userv2.Password{Password: TestUserPassword, ChangeRequired: false},
				},
			},
		},
	})
	if err != nil {
		if isAlreadyExists(err) {
			id, ferr := findUserID(ctx, c, username)
			if ferr != nil {
				return "", ferr
			}
			if id != "" {
				return id, nil
			}
		}
		return "", fmt.Errorf("seed: create user %q: %w", username, err)
	}
	return resp.GetId(), nil
}

func getOrCreateMachineUser(ctx context.Context, c userv2.UserServiceClient, orgID, username string) (string, error) {
	if id, err := findUserID(ctx, c, username); err != nil {
		return "", err
	} else if id != "" {
		return id, nil
	}
	resp, err := c.CreateUser(ctx, &userv2.CreateUserRequest{
		OrganizationId: orgID,
		Username:       &username,
		UserType: &userv2.CreateUserRequest_Machine_{
			Machine: &userv2.CreateUserRequest_Machine{
				Name:        "tagcess",
				Description: strPtr("tagcess service user (ADR 0009); reads vpn roles and writes oauth2-proxy redirect URIs"),
			},
		},
	})
	if err != nil {
		if isAlreadyExists(err) {
			id, ferr := findUserID(ctx, c, username)
			if ferr != nil {
				return "", ferr
			}
			if id != "" {
				return id, nil
			}
		}
		return "", fmt.Errorf("seed: create machine user %q: %w", username, err)
	}
	return resp.GetId(), nil
}

func findUserID(ctx context.Context, c userv2.UserServiceClient, username string) (string, error) {
	resp, err := c.ListUsers(ctx, &userv2.ListUsersRequest{
		Queries: []*userv2.SearchQuery{
			{Query: &userv2.SearchQuery_UserNameQuery{
				UserNameQuery: &userv2.UserNameQuery{
					UserName: username,
					Method:   objectv2.TextQueryMethod_TEXT_QUERY_METHOD_EQUALS,
				},
			}},
		},
	})
	if err != nil {
		return "", fmt.Errorf("seed: list users %q: %w", username, err)
	}
	for _, u := range resp.GetResult() {
		if u.GetUsername() == username {
			return u.GetUserId(), nil
		}
	}
	return "", nil
}

func grantRole(ctx context.Context, conn *grpc.ClientConn, userID, projectID, orgID, role string) error {
	c := authorizationv2.NewAuthorizationServiceClient(conn)
	_, err := c.CreateAuthorization(ctx, &authorizationv2.CreateAuthorizationRequest{
		UserId:         userID,
		ProjectId:      projectID,
		OrganizationId: orgID,
		RoleKeys:       []string{role},
	})
	return ignoreAlreadyExists(err)
}

func addProjectMember(ctx context.Context, c internalpermissionv2.InternalPermissionServiceClient, projectID, userID, role string) error {
	_, err := c.CreateAdministrator(ctx, &internalpermissionv2.CreateAdministratorRequest{
		UserId:   userID,
		Resource: &internalpermissionv2.ResourceType{Resource: &internalpermissionv2.ResourceType_ProjectId{ProjectId: projectID}},
		Roles:    []string{role},
	})
	return ignoreAlreadyExists(err)
}

func addOrgMember(ctx context.Context, c internalpermissionv2.InternalPermissionServiceClient, orgID, userID, role string) error {
	_, err := c.CreateAdministrator(ctx, &internalpermissionv2.CreateAdministratorRequest{
		UserId:   userID,
		Resource: &internalpermissionv2.ResourceType{Resource: &internalpermissionv2.ResourceType_OrganizationId{OrganizationId: orgID}},
		Roles:    []string{role},
	})
	return ignoreAlreadyExists(err)
}

// ensureServiceUserKey writes keyPath only if it doesn't already hold a key for this exact user
// ID: Zitadel generates a fresh private key on every AddKey call and never lets you read one back,
// so caching the file locally is the only idempotent option (also true for MachineKeyPath in
// compose.yaml). The user ID check matters because recreating the lab (`make lab-down`
// clears SecretsDir, but a manual namespace delete does not) gives the "tagcess" user a new ID;
// without it, a stale key.json would silently keep pointing at a user that no longer exists.
func ensureServiceUserKey(ctx context.Context, c userv2.UserServiceClient, userID, keyPath string) error {
	if existing, err := zclient.ConfigFromKeyFile(keyPath); err == nil && existing.UserID == userID {
		return nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("seed: read existing %s: %w", keyPath, err)
	}
	resp, err := c.AddKey(ctx, &userv2.AddKeyRequest{
		UserId:         userID,
		ExpirationDate: timestamppb.New(time.Now().AddDate(1, 0, 0)),
	})
	if err != nil {
		return fmt.Errorf("seed: add machine key: %w", err)
	}
	// KeyContent is already a complete key.json (the same bytes the Zitadel console lets you
	// download once): {"type":"serviceaccount","keyId":...,"key":"-----BEGIN...","userId":...}.
	data := resp.GetKeyContent()
	if _, err := zclient.ConfigFromKeyFileData(data); err != nil {
		return fmt.Errorf("seed: AddKey returned a key.json zitadel-go can't parse: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return fmt.Errorf("seed: mkdir %s: %w", filepath.Dir(keyPath), err)
	}
	if err := os.WriteFile(keyPath, data, 0o600); err != nil {
		return fmt.Errorf("seed: write %s: %w", keyPath, err)
	}
	return nil
}

func strPtr(s string) *string { return &s }
