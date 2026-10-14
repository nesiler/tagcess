// Package zitadel is tagcess's view of Zitadel (ADR 0009, Y-03, Y-04, S-03). It wraps zitadel-go
// and exposes reads (the role grants of the vpn project, the state of users, OIDC app configs) and
// exactly one write: the redirect URI list of an OIDC app (ADR 0012). It has no function that
// creates, changes or removes a grant (rule 3, security.md §10); a test enforces that.
//
// Every list is read completely or not at all: a failed page, a page set that disagrees with
// itself, or fewer records than Zitadel's totalResult is an error. Zitadel's v2 list endpoints
// silently drop records the caller may not see while totalResult still counts them (R1 B-04), so
// a 2xx alone does not prove the read was complete.
package zitadel

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	zclient "github.com/zitadel/zitadel-go/v3/pkg/client"
	applicationv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/application/v2"
	authorizationv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/authorization/v2"
	filterv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/filter/v2"
	objectv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/object/v2"
	projectv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/project/v2"
	userv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
)

// ErrIncomplete means a list could not be proven complete: fewer records came back than Zitadel
// reports, or the reported total changed while paging. The caller must keep its last known good
// state (rule 7).
var ErrIncomplete = errors.New("zitadel: incomplete read")

// ErrPermissionDenied means Zitadel refused an operation because the service user lacks the
// permission for it (e.g. no project.app.write on an app update). The operation did not happen;
// the caller must keep its last known good state and must never treat the denial as a partial
// success (rule 7, ADR 0012).
var ErrPermissionDenied = errors.New("zitadel: permission denied")

const defaultPageSize = 100

// Application projections are eventually consistent, so the read-back that proves a URI write
// (ADR 0012 rule 4) polls briefly before declaring a drift. Package variables so tests can shrink
// the window.
var (
	appReadBackTries = 20
	appReadBackWait  = 250 * time.Millisecond
)

// Config locates Zitadel and the credentials of the tagcess service user.
type Config struct {
	Host string // e.g. auth.example.com
	Port uint16 // 0: the scheme's default (443)
	// Insecure talks plaintext h2c; only for a local test stack.
	Insecure  bool
	KeyFile   string // JWT profile key.json of the service user (ADR 0009)
	ProjectID string // the vpn project; grants of other projects are ignored
}

// Client reads roles and user states and writes OIDC app redirect URIs. Use New.
type Client struct {
	authz     authorizationv2.AuthorizationServiceClient
	users     userv2.UserServiceClient
	apps      applicationv2.ApplicationServiceClient
	projects  projectv2.ProjectServiceClient
	projectID string
	pageSize  uint32
	closer    func() error
}

// New checks the key file and connects. A missing, unreadable or malformed key file is an error
// here, at startup. Errors name the file, never its content.
func New(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.Host == "" {
		return nil, errors.New("zitadel: host is required")
	}
	if cfg.ProjectID == "" {
		return nil, errors.New("zitadel: project id is required")
	}
	if err := checkKeyFile(cfg.KeyFile); err != nil {
		return nil, err
	}
	var zopts []zitadel.Option
	switch {
	case cfg.Insecure:
		if !isLoopback(cfg.Host) {
			return nil, fmt.Errorf("zitadel: plaintext connection to %s refused: insecure mode is for loopback hosts only", cfg.Host)
		}
		zopts = append(zopts, zitadel.WithInsecure(strconv.Itoa(int(cfg.Port))))
	case cfg.Port != 0:
		zopts = append(zopts, zitadel.WithPort(cfg.Port))
	}
	auth := zclient.DefaultServiceUserAuthentication(cfg.KeyFile, oidc.ScopeOpenID, zclient.ScopeZitadelAPI())
	api, err := zclient.New(ctx, zitadel.New(cfg.Host, zopts...), zclient.WithAuth(auth))
	if err != nil {
		return nil, fmt.Errorf("zitadel: connect to %s: %w", cfg.Host, err)
	}
	return &Client{
		authz:     api.AuthorizationServiceV2(),
		users:     api.UserServiceV2(),
		apps:      api.ApplicationServiceV2(),
		projects:  api.ProjectServiceV2(),
		projectID: cfg.ProjectID,
		pageSize:  defaultPageSize,
		closer:    api.Close,
	}, nil
}

func newClient(conn *grpc.ClientConn, projectID string) *Client {
	return &Client{
		authz:     authorizationv2.NewAuthorizationServiceClient(conn),
		users:     userv2.NewUserServiceClient(conn),
		apps:      applicationv2.NewApplicationServiceClient(conn),
		projects:  projectv2.NewProjectServiceClient(conn),
		projectID: projectID,
		pageSize:  defaultPageSize,
		closer:    conn.Close,
	}
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Close releases the connection.
func (c *Client) Close() error { return c.closer() }

// checkKeyFile validates the shape of a service account key without ever echoing its content: the
// JSON decoder's own errors can quote input, so they are not wrapped.
func checkKeyFile(path string) error {
	if path == "" {
		return errors.New("zitadel: key file path is empty")
	}
	data, err := os.ReadFile(path) // #nosec G304 -- operator-configured key file path
	if err != nil {
		var pe *os.PathError
		if errors.As(err, &pe) {
			err = pe.Err
		}
		return fmt.Errorf("zitadel: read key file %s: %w", path, err)
	}
	var k struct {
		Type   string `json:"type"`
		KeyID  string `json:"keyId"`
		Key    string `json:"key"`
		UserID string `json:"userId"`
	}
	if json.Unmarshal(data, &k) != nil {
		return fmt.Errorf("zitadel: key file %s is not valid JSON", path)
	}
	if k.Type != "serviceaccount" || k.KeyID == "" || k.UserID == "" || k.Key == "" {
		return fmt.Errorf("zitadel: key file %s is not a service account key (need type, keyId, userId, key)", path)
	}
	if block, _ := pem.Decode([]byte(k.Key)); block == nil {
		return fmt.Errorf("zitadel: key file %s holds no PEM private key", path)
	}
	return nil
}

// Grant is one role held by one user in the vpn project.
type Grant struct {
	UserID string
	Role   string
}

// ListGrants returns every active (user, role) pair of the vpn project, sorted by user then role.
// The project filter is part of the request; the result is checked against it again. Grants that
// Zitadel marks inactive are left out (their roles do not reach tokens) but still count toward
// completeness.
func (c *Client) ListGrants(ctx context.Context) ([]Grant, error) {
	auths, err := collect(c.pageSize, (*authorizationv2.Authorization).GetId, func(offset uint64, limit uint32) ([]*authorizationv2.Authorization, uint64, error) {
		resp, err := c.authz.ListAuthorizations(ctx, &authorizationv2.ListAuthorizationsRequest{
			Pagination: &filterv2.PaginationRequest{Offset: offset, Limit: limit},
			Filters: []*authorizationv2.AuthorizationsSearchFilter{
				{Filter: &authorizationv2.AuthorizationsSearchFilter_ProjectId{
					ProjectId: &filterv2.IDFilter{Id: c.projectID},
				}},
			},
		})
		if err != nil {
			return nil, 0, err
		}
		return resp.GetAuthorizations(), resp.GetPagination().GetTotalResult(), nil
	})
	if err != nil {
		return nil, fmt.Errorf("zitadel: list grants: %w", err)
	}
	var grants []Grant
	for _, a := range auths {
		if a.GetProject().GetId() != c.projectID || a.GetState() != authorizationv2.State_STATE_ACTIVE {
			continue
		}
		for _, r := range a.GetRoles() {
			grants = append(grants, Grant{UserID: a.GetUser().GetId(), Role: r.GetKey()})
		}
	}
	sort.Slice(grants, func(i, j int) bool {
		if grants[i].UserID != grants[j].UserID {
			return grants[i].UserID < grants[j].UserID
		}
		return grants[i].Role < grants[j].Role
	})
	return grants, nil
}

// ListRoles returns every role key defined in the vpn project, sorted. It is the RoleSource the
// site validator reads (F2-003 AC3): the read must be provably complete, so a failed or partial
// page is an error and the caller keeps its last known-good state.
func (c *Client) ListRoles(ctx context.Context) ([]string, error) {
	roles, err := collect(c.pageSize, (*projectv2.ProjectRole).GetKey, func(offset uint64, limit uint32) ([]*projectv2.ProjectRole, uint64, error) {
		resp, err := c.projects.ListProjectRoles(ctx, &projectv2.ListProjectRolesRequest{
			ProjectId:  c.projectID,
			Pagination: &filterv2.PaginationRequest{Offset: offset, Limit: limit},
		})
		if err != nil {
			return nil, 0, err
		}
		return resp.GetProjectRoles(), resp.GetPagination().GetTotalResult(), nil
	})
	if err != nil {
		return nil, fmt.Errorf("zitadel: list roles: %w", err)
	}
	out := make([]string, 0, len(roles))
	for _, r := range roles {
		out = append(out, r.GetKey())
	}
	sort.Strings(out)
	return out, nil
}

// UserState is the account state that matters for access.
type UserState int

const (
	UserActive UserState = iota + 1
	UserInactive
	UserLocked
	UserDeleted
	// UserInitial is a user who has not finished setting up yet; not a usable login.
	UserInitial
)

func (s UserState) String() string {
	switch s {
	case UserActive:
		return "active"
	case UserInactive:
		return "inactive"
	case UserLocked:
		return "locked"
	case UserDeleted:
		return "deleted"
	case UserInitial:
		return "initial"
	}
	return "unknown(" + strconv.Itoa(int(s)) + ")"
}

func convertState(s userv2.UserState) (UserState, error) {
	switch s {
	case userv2.UserState_USER_STATE_ACTIVE:
		return UserActive, nil
	case userv2.UserState_USER_STATE_INACTIVE:
		return UserInactive, nil
	case userv2.UserState_USER_STATE_LOCKED:
		return UserLocked, nil
	case userv2.UserState_USER_STATE_DELETED:
		return UserDeleted, nil
	case userv2.UserState_USER_STATE_INITIAL:
		return UserInitial, nil
	}
	return 0, fmt.Errorf("unrecognised user state %v", s)
}

// UserStates returns the state of each requested user ID. Zitadel does not list removed users, so
// an ID missing from the list is looked up directly: NotFound means UserDeleted. Anything that
// cannot be proven (hidden user, failed lookup) is an error, never a guess.
func (c *Client) UserStates(ctx context.Context, ids []string) (map[string]UserState, error) {
	out := make(map[string]UserState, len(ids))
	for start := 0; start < len(ids); start += int(c.pageSize) {
		chunk := ids[start:min(start+int(c.pageSize), len(ids))]
		users, err := collect(c.pageSize, (*userv2.User).GetUserId, func(offset uint64, limit uint32) ([]*userv2.User, uint64, error) {
			resp, err := c.users.ListUsers(ctx, &userv2.ListUsersRequest{
				Query: &objectv2.ListQuery{Offset: offset, Limit: limit},
				Queries: []*userv2.SearchQuery{
					{Query: &userv2.SearchQuery_InUserIdsQuery{InUserIdsQuery: &userv2.InUserIDQuery{UserIds: chunk}}},
				},
			})
			if err != nil {
				return nil, 0, err
			}
			return resp.GetResult(), resp.GetDetails().GetTotalResult(), nil
		})
		if err != nil {
			return nil, fmt.Errorf("zitadel: list users: %w", err)
		}
		for _, u := range users {
			st, err := convertState(u.GetState())
			if err != nil {
				return nil, fmt.Errorf("zitadel: user %s: %w", u.GetUserId(), err)
			}
			out[u.GetUserId()] = st
		}
		for _, id := range chunk {
			if _, ok := out[id]; ok {
				continue
			}
			// Absent from the list: deleted, or hidden from this caller. ListUsers cannot tell them apart
			// (hidden users are not even counted), so ask for the user directly. Only NotFound proves a
			// removal; PermissionDenied means the service user lacks the org read role (ADR 0009).
			st, err := c.absentUserState(ctx, id)
			if err != nil {
				return nil, err
			}
			out[id] = st
		}
	}
	return out, nil
}

func (c *Client) absentUserState(ctx context.Context, id string) (UserState, error) {
	resp, err := c.users.GetUserByID(ctx, &userv2.GetUserByIDRequest{UserId: id})
	switch {
	case status.Code(err) == codes.NotFound:
		return UserDeleted, nil
	case err != nil:
		return 0, fmt.Errorf("%w: user %s missing from the list and not readable: %w", ErrIncomplete, id, describe(err))
	}
	st, cerr := convertState(resp.GetUser().GetState())
	if cerr != nil {
		return 0, fmt.Errorf("zitadel: user %s: %w", id, cerr)
	}
	return st, nil
}

// collect pages through a list until the total Zitadel reports is in hand. It fails with
// ErrIncomplete if a page comes back empty early, if the total changes between pages, or if the
// number of records collected differs from the total.
func collect[T any](pageSize uint32, id func(T) string, fetch func(offset uint64, limit uint32) ([]T, uint64, error)) ([]T, error) {
	var (
		all      []T
		expected uint64
		seen     = map[string]bool{}
	)
	for first := true; ; first = false {
		items, total, err := fetch(uint64(len(all)), pageSize)
		if err != nil {
			return nil, describe(err)
		}
		if first {
			expected = total
		} else if total != expected {
			return nil, fmt.Errorf("%w: total changed from %d to %d while paging", ErrIncomplete, expected, total)
		}
		for _, it := range items {
			// Offset paging can skip one record and repeat another when the data shifts mid-read, which
			// keeps the count right while losing a record; a repeat exposes that.
			if k := id(it); seen[k] {
				return nil, fmt.Errorf("%w: record %s returned twice (data changed while paging)", ErrIncomplete, k)
			} else {
				seen[k] = true
			}
		}
		all = append(all, items...)
		if uint64(len(all)) >= expected {
			break
		}
		if len(items) == 0 {
			break
		}
	}
	if uint64(len(all)) != expected {
		return nil, fmt.Errorf("%w: got %d of %d records (the caller may lack permission to see the rest)", ErrIncomplete, len(all), expected)
	}
	return all, nil
}

func describe(err error) error {
	if s, ok := status.FromError(err); ok && s.Code() != codes.OK {
		return fmt.Errorf("%s: %w", s.Code(), err)
	}
	return err
}

// isDenied reports whether Zitadel refused the operation because the identity holds no permission
// for it. Zitadel v4.16.0 answers such a call either with PermissionDenied or — when no membership
// of the caller entitles it at all — with NotFound and its authz error code in the message, e.g.
// `membership not found (AUTHZ-cdgFk)`; an ordinary missing object carries a different subsystem's
// code (e.g. APP-… for an unknown application). Verified live 2026-10-01 (F2-009 lab run).
func isDenied(err error) bool {
	s, ok := status.FromError(err)
	if !ok {
		return false
	}
	if s.Code() == codes.PermissionDenied {
		return true
	}
	return s.Code() == codes.NotFound && strings.Contains(s.Message(), "(AUTHZ-")
}

// wrapDenied turns a permission refusal into the typed ErrPermissionDenied (AC2, F2-009): the
// caller must be able to tell "not allowed" from any other failure and never assume the write
// happened. Everything else keeps the usual describe() form.
func wrapDenied(what string, err error) error {
	if isDenied(err) {
		return fmt.Errorf("zitadel: %s: %w: %w", what, ErrPermissionDenied, describe(err))
	}
	return fmt.Errorf("zitadel: %s: %w", what, describe(err))
}

// FindAppID returns the ID of the application with exactly that name in the vpn project. Zero or
// several matches are an error: tagcess must never edit an app it cannot identify beyond doubt.
func (c *Client) FindAppID(ctx context.Context, appName string) (string, error) {
	apps, err := collect(c.pageSize, (*applicationv2.Application).GetApplicationId, func(offset uint64, limit uint32) ([]*applicationv2.Application, uint64, error) {
		resp, err := c.apps.ListApplications(ctx, &applicationv2.ListApplicationsRequest{
			Pagination: &filterv2.PaginationRequest{Offset: offset, Limit: limit},
			Filters: []*applicationv2.ApplicationSearchFilter{
				{Filter: &applicationv2.ApplicationSearchFilter_ProjectIdFilter{
					ProjectIdFilter: &applicationv2.ProjectIDFilter{ProjectId: c.projectID},
				}},
				{Filter: &applicationv2.ApplicationSearchFilter_NameFilter{
					NameFilter: &applicationv2.ApplicationNameFilter{Name: appName, Method: filterv2.TextFilterMethod_TEXT_FILTER_METHOD_EQUALS},
				}},
			},
		})
		if err != nil {
			return nil, 0, err
		}
		return resp.GetApplications(), resp.GetPagination().GetTotalResult(), nil
	})
	if err != nil {
		return "", wrapDenied(fmt.Sprintf("list apps named %q", appName), err)
	}
	var ids []string
	for _, a := range apps {
		if a.GetName() == appName {
			ids = append(ids, a.GetApplicationId())
		}
	}
	switch len(ids) {
	case 1:
		return ids[0], nil
	case 0:
		return "", fmt.Errorf("zitadel: project %s has no application named %q", c.projectID, appName)
	default:
		return "", fmt.Errorf("zitadel: project %s has %d applications named %q; refusing to pick one", c.projectID, len(ids), appName)
	}
}

// AppOIDC is the OIDC application configuration tagcess reads and (the redirect URIs of) writes.
// ResponseTypes, GrantTypes, ClockSkew and LoginVersion are carried along because Zitadel v4.16.0
// resets them to their defaults when an update request leaves them out (stack-notes, ADR 0012).
type AppOIDC struct {
	RedirectUris []string
	// PostLogoutRedirectUris are carried along like the fields below: UpdateApplication must not
	// drop them when only the redirect URIs change.
	PostLogoutRedirectUris []string
	ResponseTypes          []applicationv2.OIDCResponseType
	GrantTypes             []applicationv2.OIDCGrantType
	ClockSkew              *durationpb.Duration
	LoginVersion           *applicationv2.LoginVersion
}

// AppOIDC reads an application's OIDC configuration. An application without one is an error:
// tagcess only edits OIDC apps.
func (c *Client) AppOIDC(ctx context.Context, appID string) (*AppOIDC, error) {
	resp, err := c.apps.GetApplication(ctx, &applicationv2.GetApplicationRequest{ApplicationId: appID})
	if err != nil {
		return nil, wrapDenied(fmt.Sprintf("get app %s", appID), err)
	}
	app := resp.GetApplication()
	oidc := app.GetOidcConfiguration()
	if oidc == nil {
		return nil, fmt.Errorf("zitadel: app %s (%s) is not an OIDC application", appID, app.GetName())
	}
	return &AppOIDC{
		RedirectUris:           slices.Clone(oidc.GetRedirectUris()),
		PostLogoutRedirectUris: slices.Clone(oidc.GetPostLogoutRedirectUris()),
		ResponseTypes:          slices.Clone(oidc.GetResponseTypes()),
		GrantTypes:             slices.Clone(oidc.GetGrantTypes()),
		ClockSkew:              oidc.GetClockSkew(),
		LoginVersion:           oidc.GetLoginVersion(),
	}, nil
}

// UpdateAppRedirectURIs replaces an application's redirect URI list — Zitadel has no single-URI
// write, only full-list replacement (ADR 0012) — and proves the result with a fresh read, so a
// silent no-op or a concurrent console edit is an error, never a success report. UpdateApplication
// resets fields missing from the request, so the read values of response_types, grant_types,
// clock_skew and login_version are sent back verbatim. An empty list is refused: a redirect-less
// app cannot log anyone in, and nothing in tagcess ever asks for that (rule 7).
func (c *Client) UpdateAppRedirectURIs(ctx context.Context, appID string, uris []string) error {
	if len(uris) == 0 {
		return fmt.Errorf("zitadel: app %s: refusing to write an empty redirect URI list", appID)
	}
	cur, err := c.AppOIDC(ctx, appID)
	if err != nil {
		return err
	}
	_, err = c.apps.UpdateApplication(ctx, &applicationv2.UpdateApplicationRequest{
		ApplicationId: appID,
		ProjectId:     c.projectID,
		ApplicationType: &applicationv2.UpdateApplicationRequest_OidcConfiguration{
			OidcConfiguration: &applicationv2.UpdateOIDCApplicationConfigurationRequest{
				RedirectUris:           uris,
				PostLogoutRedirectUris: cur.PostLogoutRedirectUris,
				ResponseTypes:          cur.ResponseTypes,
				GrantTypes:             cur.GrantTypes,
				ClockSkew:              cur.ClockSkew,
				LoginVersion:           cur.LoginVersion,
			},
		},
	})
	if err != nil {
		return wrapDenied(fmt.Sprintf("update app %s redirect uris", appID), err)
	}
	for i := 0; ; i++ {
		after, err := c.AppOIDC(ctx, appID)
		if err != nil {
			return err
		}
		if slices.Equal(after.RedirectUris, uris) {
			return nil
		}
		if i+1 >= appReadBackTries {
			return fmt.Errorf("zitadel: app %s redirect uris read back %v, want %v", appID, after.RedirectUris, uris)
		}
		time.Sleep(appReadBackWait)
	}
}

// EnsureAppPostLogoutURI makes sure uri is in the application's post-logout redirect URI list (J1:
// Zitadel's end_session only returns to a registered URI). It is additive: nothing already in the list is
// ever removed or changed, and nothing is written when uri is present. The write carries every other
// field verbatim and is proven by a fresh read, like UpdateAppRedirectURIs.
func (c *Client) EnsureAppPostLogoutURI(ctx context.Context, appID, uri string) error {
	cur, err := c.AppOIDC(ctx, appID)
	if err != nil {
		return err
	}
	if slices.Contains(cur.PostLogoutRedirectUris, uri) {
		return nil
	}
	want := append(slices.Clone(cur.PostLogoutRedirectUris), uri)
	_, err = c.apps.UpdateApplication(ctx, &applicationv2.UpdateApplicationRequest{
		ApplicationId: appID,
		ProjectId:     c.projectID,
		ApplicationType: &applicationv2.UpdateApplicationRequest_OidcConfiguration{
			OidcConfiguration: &applicationv2.UpdateOIDCApplicationConfigurationRequest{
				RedirectUris:           cur.RedirectUris,
				PostLogoutRedirectUris: want,
				ResponseTypes:          cur.ResponseTypes,
				GrantTypes:             cur.GrantTypes,
				ClockSkew:              cur.ClockSkew,
				LoginVersion:           cur.LoginVersion,
			},
		},
	})
	if err != nil {
		return wrapDenied(fmt.Sprintf("update app %s post-logout uris", appID), err)
	}
	for i := 0; ; i++ {
		after, err := c.AppOIDC(ctx, appID)
		if err != nil {
			return err
		}
		if slices.Equal(after.PostLogoutRedirectUris, want) && slices.Equal(after.RedirectUris, cur.RedirectUris) {
			return nil
		}
		if i+1 >= appReadBackTries {
			return fmt.Errorf("zitadel: app %s post-logout uris read back %v, want %v", appID, after.PostLogoutRedirectUris, want)
		}
		time.Sleep(appReadBackWait)
	}
}
