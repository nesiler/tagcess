package zitadel

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	authorizationv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/authorization/v2"
	filterv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/filter/v2"
	objectv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/object/v2"
	projectv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/project/v2"
	userv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
)

const testProject = "proj-vpn"

// fakeAuthz serves ListAuthorizations from an in-memory slice, honouring the project filter,
// offset and limit like Zitadel does. hidden records are counted in totalResult but never
// listed (Zitadel's silent permission filter, R1 B-04). failAtOffset makes one page fail.
type fakeAuthz struct {
	authorizationv2.UnimplementedAuthorizationServiceServer
	all          []*authorizationv2.Authorization
	hidden       uint64
	failAtOffset int64 // -1: never
	wrongTotal   func(offset uint64) uint64
	gotFilters   [][]*authorizationv2.AuthorizationsSearchFilter
}

func (f *fakeAuthz) ListAuthorizations(_ context.Context, req *authorizationv2.ListAuthorizationsRequest) (*authorizationv2.ListAuthorizationsResponse, error) {
	f.gotFilters = append(f.gotFilters, req.GetFilters())
	var pid string
	for _, fl := range req.GetFilters() {
		if p := fl.GetProjectId(); p != nil {
			pid = p.GetId()
		}
	}
	var match []*authorizationv2.Authorization
	for _, a := range f.all {
		if pid == "" || a.GetProject().GetId() == pid {
			match = append(match, a)
		}
	}
	offset := req.GetPagination().GetOffset()
	limit := uint64(req.GetPagination().GetLimit())
	if limit == 0 {
		limit = 100
	}
	if f.failAtOffset >= 0 && offset == uint64(f.failAtOffset) {
		return nil, status.Error(codes.Unavailable, "boom")
	}
	total := uint64(len(match)) + f.hidden
	if f.wrongTotal != nil {
		total = f.wrongTotal(offset)
	}
	end := min(offset+limit, uint64(len(match)))
	var page []*authorizationv2.Authorization
	if offset < end {
		page = match[offset:end]
	}
	return &authorizationv2.ListAuthorizationsResponse{
		Pagination:     &filterv2.PaginationResponse{TotalResult: total, AppliedLimit: limit},
		Authorizations: page,
	}, nil
}

type fakeUsers struct {
	userv2.UnimplementedUserServiceServer
	users  map[string]userv2.UserState
	hidden uint64
	// invisible users exist but are silently left out of ListUsers, uncounted (Zitadel v4.16 without the
	// org read role); GetUserByID answers PermissionDenied for them.
	invisible map[string]bool
	fail      bool
}

func (f *fakeUsers) GetUserByID(_ context.Context, req *userv2.GetUserByIDRequest) (*userv2.GetUserByIDResponse, error) {
	id := req.GetUserId()
	if f.invisible[id] {
		return nil, status.Error(codes.PermissionDenied, "No matching permissions found")
	}
	if st, ok := f.users[id]; ok {
		return &userv2.GetUserByIDResponse{User: &userv2.User{UserId: id, State: st}}, nil
	}
	return nil, status.Error(codes.NotFound, "User not found")
}

func (f *fakeUsers) ListUsers(_ context.Context, req *userv2.ListUsersRequest) (*userv2.ListUsersResponse, error) {
	if f.fail {
		return nil, status.Error(codes.Unavailable, "boom")
	}
	var ids []string
	for _, q := range req.GetQueries() {
		if in := q.GetInUserIdsQuery(); in != nil {
			ids = append(ids, in.GetUserIds()...)
		}
	}
	var res []*userv2.User
	for _, id := range ids {
		if st, ok := f.users[id]; ok && !f.invisible[id] {
			res = append(res, &userv2.User{UserId: id, State: st})
		}
	}
	total := uint64(len(res)) + f.hidden
	offset := min(req.GetQuery().GetOffset(), uint64(len(res)))
	res = res[offset:]
	return &userv2.ListUsersResponse{
		Details: &objectv2.ListDetails{TotalResult: total},
		Result:  res,
	}, nil
}

func authz(id, project, user string, state authorizationv2.State, roles ...string) *authorizationv2.Authorization {
	a := &authorizationv2.Authorization{
		Id:      id,
		Project: &authorizationv2.Project{Id: project},
		User:    &authorizationv2.User{Id: user},
		State:   state,
	}
	for _, r := range roles {
		a.Roles = append(a.Roles, &authorizationv2.Role{Key: r})
	}
	return a
}

func startFake(t *testing.T, az *fakeAuthz, us *fakeUsers) *Client {
	t.Helper()
	lis, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	if az != nil {
		authorizationv2.RegisterAuthorizationServiceServer(srv, az)
	}
	if us != nil {
		userv2.RegisterUserServiceServer(srv, us)
	}
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	c := newClient(conn, testProject)
	c.pageSize = 2 // force several pages with small fixtures
	return c
}

func grantList(n int) []*authorizationv2.Authorization {
	var all []*authorizationv2.Authorization
	for i := range n {
		all = append(all, authz("a"+string(rune('0'+i)), testProject, "u"+string(rune('0'+i)), authorizationv2.State_STATE_ACTIVE, "developer"))
	}
	return all
}

func TestZitadel_ListGrantsPaging(t *testing.T) {
	all := append(grantList(5),
		authz("x1", "other-project", "u9", authorizationv2.State_STATE_ACTIVE, "admin"),
		authz("x2", testProject, "u7", authorizationv2.State_STATE_ACTIVE, "devops", "developer"),
		authz("x3", testProject, "u8", authorizationv2.State_STATE_INACTIVE, "devops"),
	)
	az := &fakeAuthz{all: all, failAtOffset: -1}
	c := startFake(t, az, nil)

	got, err := c.ListGrants(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var pairs []string
	for _, g := range got {
		pairs = append(pairs, g.UserID+":"+g.Role)
	}
	sort.Strings(pairs)
	want := []string{"u0:developer", "u1:developer", "u2:developer", "u3:developer", "u4:developer", "u7:developer", "u7:devops"}
	if !reflect.DeepEqual(pairs, want) {
		t.Fatalf("pairs = %v, want %v (other project and deactivated grants excluded)", pairs, want)
	}
	if len(az.gotFilters) < 3 {
		t.Fatalf("expected several pages, got %d requests", len(az.gotFilters))
	}
	for _, fl := range az.gotFilters {
		if len(fl) == 0 || fl[0].GetProjectId().GetId() != testProject {
			t.Fatalf("request without server-side project filter: %v", fl)
		}
	}
}

func TestZitadel_PartialReadIsError(t *testing.T) {
	az := &fakeAuthz{all: grantList(5), failAtOffset: 2}
	c := startFake(t, az, nil)
	got, err := c.ListGrants(context.Background())
	if err == nil {
		t.Fatalf("expected error, got %v", got)
	}
	if got != nil {
		t.Fatalf("partial result returned with error: %v", got)
	}
}

func TestZitadel_FilteredListIsError(t *testing.T) {
	tests := []struct {
		name string
		az   *fakeAuthz
	}{
		{"hidden records", &fakeAuthz{all: grantList(3), hidden: 2, failAtOffset: -1}},
		{"total changes between pages", &fakeAuthz{all: grantList(4), failAtOffset: -1, wrongTotal: func(o uint64) uint64 { return 4 + o }}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := startFake(t, tt.az, nil)
			got, err := c.ListGrants(context.Background())
			if err == nil || got != nil {
				t.Fatalf("got %v, %v; want nil and error", got, err)
			}
			if !errors.Is(err, ErrIncomplete) {
				t.Fatalf("error %v is not ErrIncomplete", err)
			}
		})
	}
}

func TestZitadel_RepeatedRecordIsError(t *testing.T) {
	a := authz("a0", testProject, "u0", authorizationv2.State_STATE_ACTIVE, "developer")
	// Two pages of size 2 where the second repeats a record from the first: count 4 == total 4.
	az := &fakeAuthz{all: []*authorizationv2.Authorization{a, authz("a1", testProject, "u1", authorizationv2.State_STATE_ACTIVE, "x"), a, authz("a3", testProject, "u3", authorizationv2.State_STATE_ACTIVE, "x")}, failAtOffset: -1}
	c := startFake(t, az, nil)
	if got, err := c.ListGrants(context.Background()); !errors.Is(err, ErrIncomplete) || got != nil {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestZitadel_EmptyProjectIsNotAnError(t *testing.T) {
	c := startFake(t, &fakeAuthz{failAtOffset: -1}, nil)
	got, err := c.ListGrants(context.Background())
	if err != nil || len(got) != 0 {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestZitadel_UserStates(t *testing.T) {
	us := &fakeUsers{users: map[string]userv2.UserState{
		"active":   userv2.UserState_USER_STATE_ACTIVE,
		"inactive": userv2.UserState_USER_STATE_INACTIVE,
		"locked":   userv2.UserState_USER_STATE_LOCKED,
		"deleted":  userv2.UserState_USER_STATE_DELETED,
		"initial":  userv2.UserState_USER_STATE_INITIAL,
	}}
	c := startFake(t, nil, us)
	// "gone" is not returned by ListUsers at all: removed users vanish, which means deleted.
	got, err := c.UserStates(context.Background(), []string{"active", "inactive", "locked", "deleted", "initial", "gone"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]UserState{
		"active": UserActive, "inactive": UserInactive, "locked": UserLocked,
		"deleted": UserDeleted, "initial": UserInitial, "gone": UserDeleted,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("states = %v, want %v", got, want)
	}
}

func TestZitadel_UserStatesErrors(t *testing.T) {
	t.Run("rpc failure", func(t *testing.T) {
		c := startFake(t, nil, &fakeUsers{fail: true})
		if got, err := c.UserStates(context.Background(), []string{"a"}); err == nil || got != nil {
			t.Fatalf("got %v, %v", got, err)
		}
	})
	t.Run("filtered", func(t *testing.T) {
		c := startFake(t, nil, &fakeUsers{users: map[string]userv2.UserState{"a": userv2.UserState_USER_STATE_ACTIVE}, hidden: 1})
		got, err := c.UserStates(context.Background(), []string{"a", "b"})
		if !errors.Is(err, ErrIncomplete) || got != nil {
			t.Fatalf("got %v, %v", got, err)
		}
	})
	t.Run("hidden user is not a deleted user", func(t *testing.T) {
		c := startFake(t, nil, &fakeUsers{
			users:     map[string]userv2.UserState{"a": userv2.UserState_USER_STATE_ACTIVE, "h": userv2.UserState_USER_STATE_ACTIVE},
			invisible: map[string]bool{"h": true},
		})
		got, err := c.UserStates(context.Background(), []string{"a", "h"})
		if !errors.Is(err, ErrIncomplete) || got != nil {
			t.Fatalf("got %v, %v; a user the caller cannot see must not read as deleted", got, err)
		}
	})
	t.Run("unknown state", func(t *testing.T) {
		c := startFake(t, nil, &fakeUsers{users: map[string]userv2.UserState{"a": userv2.UserState_USER_STATE_UNSPECIFIED}})
		if got, err := c.UserStates(context.Background(), []string{"a"}); err == nil || got != nil {
			t.Fatalf("unspecified state must not read as a usable state: %v, %v", got, err)
		}
	})
	t.Run("no ids", func(t *testing.T) {
		c := startFake(t, nil, &fakeUsers{})
		got, err := c.UserStates(context.Background(), nil)
		if err != nil || len(got) != 0 {
			t.Fatalf("got %v, %v", got, err)
		}
	})
}

// TestZitadel_NoGrantWrites is AC4: nothing exported in the package can write or delete a grant,
// and the source never names a grant-writing RPC.
//
// F2-009 note: the package's one intended write is the OIDC app redirect URI update (ADR 0009,
// ADR 0012). appWrites lists exactly that exception to the write-verb check; anything else with a
// write-verb name is still rejected, and the grant-RPC text scan below is untouched.
func TestZitadel_NoGrantWrites(t *testing.T) {
	appWrites := map[string]string{
		// Writes redirect URIs of an OIDC app; grants and members are not involved (ADR 0012).
		"UpdateAppRedirectURIs": "ADR 0009/0012 app redirect URI update",
	}
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]*ast.File{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		files[name] = f
	}
	pkgs := map[string]struct{ Files map[string]*ast.File }{"zitadel": {Files: files}}
	writeVerbs := []string{"Add", "Create", "Set", "Remove", "Delete", "Update", "Assign", "Revoke", "Write", "Put", "Deactivate", "Reactivate", "Activate", "Grant", "Change"}
	forbiddenRPC := []string{"AddUserGrant", "CreateAuthorization", "DeleteAuthorization", "UpdateAuthorization", "DeactivateAuthorization", "ActivateAuthorization", "UpdateUserGrant", "RemoveUserGrant", "DeactivateUserGrant", "ReactivateUserGrant", "BulkAddUserGrant", "BulkRemoveUserGrant", "AddProjectRole", "RemoveProjectRole", "AddUserMember"}
	var exported []string
	for _, pkg := range pkgs {
		for name, f := range pkg.Files {
			src, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			for _, rpc := range forbiddenRPC {
				if strings.Contains(string(src), rpc) {
					t.Errorf("%s references grant-writing RPC %s", name, rpc)
				}
			}
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || !fd.Name.IsExported() {
					continue
				}
				exported = append(exported, fd.Name.Name)
				for _, v := range writeVerbs {
					if strings.HasPrefix(fd.Name.Name, v) && appWrites[fd.Name.Name] == "" {
						t.Errorf("exported %s starts with write verb %q", fd.Name.Name, v)
					}
				}
				delete(appWrites, fd.Name.Name)
			}
		}
	}
	if len(exported) == 0 {
		t.Fatal("found no exported functions; the check is not looking at the package")
	}
	for name := range appWrites {
		t.Errorf("appWrites lists %s but no such exported function exists", name)
	}
}

// TestZitadel_KeyFileErrors is AC5: an unusable key file stops New with a clear error that never
// contains the file's content.
func TestZitadel_KeyFileErrors(t *testing.T) {
	const secret = "TOP-SECRET-KEY-MATERIAL"
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	unreadable := write("unreadable.json", "{}")
	if err := os.Chmod(unreadable, 0); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		path string
	}{
		{"missing", filepath.Join(dir, "nope.json")},
		{"empty path", ""},
		{"directory", dir},
		{"empty file", write("empty.json", "")},
		{"not json", write("bad.json", secret)},
		{"json without key", write("nokey.json", `{"type":"serviceaccount","keyId":"k","userId":"u","note":"`+secret+`"}`)},
		{"wrong type", write("wrongtype.json", `{"type":"application","keyId":"k","userId":"u","key":"`+secret+`"}`)},
		{"key not pem", write("notpem.json", `{"type":"serviceaccount","keyId":"k","userId":"u","key":"`+secret+`"}`)},
		{"unreadable", unreadable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "unreadable" && os.Geteuid() == 0 {
				t.Skip("root can read anything")
			}
			c, err := New(context.Background(), Config{Host: "127.0.0.1", Port: 1, Insecure: true, KeyFile: tt.path, ProjectID: testProject})
			if err == nil {
				_ = c.Close()
				t.Fatal("expected error")
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("error leaks key content: %v", err)
			}
		})
	}
}

func TestZitadel_ConfigValidation(t *testing.T) {
	key := filepath.Join(t.TempDir(), "k.json")
	_ = os.WriteFile(key, []byte(`{}`), 0o600)
	for name, cfg := range map[string]Config{
		"no host":         {Port: 443, KeyFile: key, ProjectID: testProject},
		"insecure remote": {Host: "z.example", Port: 443, Insecure: true, KeyFile: key, ProjectID: testProject},
		"no project":      {Host: "z.example", Port: 443, KeyFile: key},
	} {
		if _, err := New(context.Background(), cfg); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

// fakeProjects serves ListProjectRoles from an in-memory slice, like fakeAuthz does for grants.
type fakeProjects struct {
	projectv2.UnimplementedProjectServiceServer
	roles        []*projectv2.ProjectRole
	hidden       uint64
	failAtOffset int64 // -1: never
}

func (f *fakeProjects) ListProjectRoles(_ context.Context, req *projectv2.ListProjectRolesRequest) (*projectv2.ListProjectRolesResponse, error) {
	if req.GetProjectId() != testProject {
		return &projectv2.ListProjectRolesResponse{}, nil
	}
	offset := req.GetPagination().GetOffset()
	limit := uint64(req.GetPagination().GetLimit())
	if limit == 0 {
		limit = 100
	}
	if f.failAtOffset >= 0 && offset == uint64(f.failAtOffset) {
		return nil, status.Error(codes.Unavailable, "boom")
	}
	end := min(offset+limit, uint64(len(f.roles)))
	var page []*projectv2.ProjectRole
	if offset < end {
		page = f.roles[offset:end]
	}
	return &projectv2.ListProjectRolesResponse{
		Pagination:   &filterv2.PaginationResponse{TotalResult: uint64(len(f.roles)) + f.hidden, AppliedLimit: limit},
		ProjectRoles: page,
	}, nil
}

func startFakeProjects(t *testing.T, pr *fakeProjects) *Client {
	t.Helper()
	lis, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	projectv2.RegisterProjectServiceServer(srv, pr)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	c := newClient(conn, testProject)
	c.pageSize = 2
	return c
}

func roleList(keys ...string) []*projectv2.ProjectRole {
	out := make([]*projectv2.ProjectRole, 0, len(keys))
	for _, k := range keys {
		out = append(out, &projectv2.ProjectRole{Key: k})
	}
	return out
}

// ListRoles pages through the vpn project roles and returns them sorted; a partial read is an
// error, never a short list (F2-003 AC3).
func TestZitadel_ListRolesPaging(t *testing.T) {
	c := startFakeProjects(t, &fakeProjects{roles: roleList("standart", "devops", "developer", "ops", "viewer"), failAtOffset: -1})
	got, err := c.ListRoles(context.Background())
	if err != nil {
		t.Fatalf("ListRoles: %v", err)
	}
	want := []string{"developer", "devops", "ops", "standart", "viewer"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ListRoles = %v, want %v", got, want)
	}
}

func TestZitadel_ListRolesIncomplete(t *testing.T) {
	// Zitadel counts two roles the caller may not see.
	c := startFakeProjects(t, &fakeProjects{roles: roleList("devops", "developer"), hidden: 2, failAtOffset: -1})
	if got, err := c.ListRoles(context.Background()); !errors.Is(err, ErrIncomplete) || got != nil {
		t.Errorf("ListRoles = %v, %v, want ErrIncomplete", got, err)
	}
}

func TestZitadel_ListRolesEmptyAndFailure(t *testing.T) {
	c := startFakeProjects(t, &fakeProjects{failAtOffset: -1})
	got, err := c.ListRoles(context.Background())
	if err != nil || len(got) != 0 {
		t.Errorf("empty project = %v, %v, want empty and no error", got, err)
	}
	c = startFakeProjects(t, &fakeProjects{roles: roleList("a", "b", "c"), failAtOffset: 2})
	if _, err := c.ListRoles(context.Background()); err == nil {
		t.Error("a failed page was not surfaced")
	}
}
