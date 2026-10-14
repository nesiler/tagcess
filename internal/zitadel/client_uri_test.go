package zitadel

import (
	"context"
	"errors"
	"net"
	"slices"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	applicationv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/application/v2"
	filterv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/filter/v2"
)

// fakeApps serves the application v2 service from an in-memory app list. deniedList/deniedGet/
// deniedUpdate map a gRPC PermissionDenied onto the matching call, and lagGet simulates Zitadel's
// eventually consistent projections: after an update, the next lagGet reads return the old state.
type fakeApps struct {
	applicationv2.UnimplementedApplicationServiceServer
	apps         []*applicationv2.Application
	deniedList   bool
	deniedGet    bool
	deniedUpdate bool
	// authzNotFoundGet answers GetApplication with Zitadel's missing-entitlement shape:
	// NotFound plus the authz error code (F2-009 live finding).
	authzNotFoundGet bool
	lagGet           int
	updates          []*applicationv2.UpdateApplicationRequest
	old              []*applicationv2.Application
}

func (f *fakeApps) find(id string) *applicationv2.Application {
	for _, a := range f.apps {
		if a.GetApplicationId() == id {
			return a
		}
	}
	return nil
}

func (f *fakeApps) ListApplications(_ context.Context, req *applicationv2.ListApplicationsRequest) (*applicationv2.ListApplicationsResponse, error) {
	if f.deniedList {
		return nil, status.Error(codes.PermissionDenied, "No matching permissions found")
	}
	var pid string
	for _, fl := range req.GetFilters() {
		if p := fl.GetProjectIdFilter(); p != nil {
			pid = p.GetProjectId()
		}
	}
	if pid == "" {
		return nil, status.Error(codes.InvalidArgument, "no project filter")
	}
	var name string
	var res []*applicationv2.Application
	for _, fl := range req.GetFilters() {
		if n := fl.GetNameFilter(); n != nil {
			name = n.GetName()
		}
	}
	for _, a := range f.apps {
		if a.GetProjectId() == pid && (name == "" || a.GetName() == name) {
			res = append(res, a)
		}
	}
	return &applicationv2.ListApplicationsResponse{
		Pagination:   &filterv2.PaginationResponse{TotalResult: uint64(len(res))},
		Applications: res,
	}, nil
}

func (f *fakeApps) GetApplication(_ context.Context, req *applicationv2.GetApplicationRequest) (*applicationv2.GetApplicationResponse, error) {
	if f.authzNotFoundGet {
		return nil, status.Error(codes.NotFound, "membership not found (AUTHZ-cdgFk)")
	}
	if f.deniedGet {
		return nil, status.Error(codes.PermissionDenied, "No matching permissions found")
	}
	a := f.find(req.GetApplicationId())
	if a == nil {
		return nil, status.Error(codes.NotFound, "not found")
	}
	if f.lagGet > 0 {
		f.lagGet--
		for _, old := range f.old {
			if old.GetApplicationId() == a.GetApplicationId() {
				return &applicationv2.GetApplicationResponse{Application: old}, nil
			}
		}
	}
	return &applicationv2.GetApplicationResponse{Application: a}, nil
}

func (f *fakeApps) UpdateApplication(_ context.Context, req *applicationv2.UpdateApplicationRequest) (*applicationv2.UpdateApplicationResponse, error) {
	if f.deniedUpdate {
		return nil, status.Error(codes.PermissionDenied, "No matching permissions found")
	}
	f.updates = append(f.updates, req)
	a := f.find(req.GetApplicationId())
	if a == nil {
		return nil, status.Error(codes.NotFound, "not found")
	}
	f.old = append(f.old, proto.Clone(a).(*applicationv2.Application))
	oidc := req.GetOidcConfiguration()
	if oidc != nil {
		a.Configuration = &applicationv2.Application_OidcConfiguration{
			OidcConfiguration: &applicationv2.OIDCConfiguration{
				RedirectUris:           oidc.GetRedirectUris(),
				PostLogoutRedirectUris: oidc.GetPostLogoutRedirectUris(),
				ResponseTypes:          oidc.GetResponseTypes(),
				GrantTypes:             oidc.GetGrantTypes(),
				ClockSkew:              oidc.GetClockSkew(),
				LoginVersion:           oidc.GetLoginVersion(),
			},
		}
	}
	return &applicationv2.UpdateApplicationResponse{ChangeDate: nil}, nil
}

func startAppFake(t *testing.T, apps *fakeApps) *Client {
	t.Helper()
	lis, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	applicationv2.RegisterApplicationServiceServer(srv, apps)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return newClient(conn, testProject)
}

func oidcApp(id, project, name string, uris ...string) *applicationv2.Application {
	return &applicationv2.Application{
		ApplicationId: id,
		ProjectId:     project,
		Name:          name,
		Configuration: &applicationv2.Application_OidcConfiguration{
			OidcConfiguration: &applicationv2.OIDCConfiguration{
				RedirectUris:  uris,
				ResponseTypes: []applicationv2.OIDCResponseType{applicationv2.OIDCResponseType_OIDC_RESPONSE_TYPE_CODE},
				GrantTypes:    []applicationv2.OIDCGrantType{applicationv2.OIDCGrantType_OIDC_GRANT_TYPE_AUTHORIZATION_CODE},
				ClockSkew:     durationpb.New(2 * time.Second),
				LoginVersion:  &applicationv2.LoginVersion{Version: &applicationv2.LoginVersion_LoginV1{LoginV1: &applicationv2.LoginV1{}}},
			},
		},
	}
}

func TestZitadel_FindAppID(t *testing.T) {
	apps := &fakeApps{apps: []*applicationv2.Application{
		oidcApp("app-1", testProject, "oauth2-proxy", "https://a/oauth2/callback"),
		oidcApp("app-2", "other-project", "oauth2-proxy", "https://b/oauth2/callback"),
		oidcApp("app-3", testProject, "headscale", "https://c/oidc/callback"),
	}}
	c := startAppFake(t, apps)

	id, err := c.FindAppID(context.Background(), "oauth2-proxy")
	if err != nil {
		t.Fatal(err)
	}
	if id != "app-1" {
		t.Fatalf("id = %q, want app-1 (same name in another project must be ignored)", id)
	}
	if _, err := c.FindAppID(context.Background(), "missing"); err == nil {
		t.Fatal("expected an error for a missing app")
	}
	apps.apps = append(apps.apps, oidcApp("app-4", testProject, "oauth2-proxy", "https://d/oauth2/callback"))
	if _, err := c.FindAppID(context.Background(), "oauth2-proxy"); err == nil {
		t.Fatal("expected an error for two same-named apps")
	}
}

func TestZitadel_FindAppIDPermissionDenied(t *testing.T) {
	c := startAppFake(t, &fakeApps{deniedList: true})
	if _, err := c.FindAppID(context.Background(), "oauth2-proxy"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("error %v is not ErrPermissionDenied", err)
	}
}

// TestZitadel_DenialShapes pins how Zitadel v4.16.0 reports a missing entitlement (verified live,
// F2-009): PermissionDenied, and NotFound carrying its authz error code ("membership not found
// (AUTHZ-…)"). A plain NotFound — an object that does not exist — is not a denial.
func TestZitadel_DenialShapes(t *testing.T) {
	t.Run("authz NotFound is a denial", func(t *testing.T) {
		c := startAppFake(t, &fakeApps{authzNotFoundGet: true})
		_, err := c.AppOIDC(context.Background(), "app-1")
		if !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("error %v is not ErrPermissionDenied", err)
		}
	})
	t.Run("plain NotFound is not a denial", func(t *testing.T) {
		c := startAppFake(t, &fakeApps{})
		_, err := c.AppOIDC(context.Background(), "missing-app")
		if err == nil || errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("error %v must not read as ErrPermissionDenied", err)
		}
	})
}

func TestZitadel_AppOIDCRead(t *testing.T) {
	c := startAppFake(t, &fakeApps{apps: []*applicationv2.Application{
		oidcApp("app-1", testProject, "oauth2-proxy", "https://a/oauth2/callback", "https://b/oauth2/callback"),
	}})
	got, err := c.AppOIDC(context.Background(), "app-1")
	if err != nil {
		t.Fatal(err)
	}
	want := oidcApp("app-1", testProject, "oauth2-proxy", "https://a/oauth2/callback", "https://b/oauth2/callback")
	wantOIDC := want.GetOidcConfiguration()
	if !slices.Equal(got.RedirectUris, wantOIDC.GetRedirectUris()) {
		t.Fatalf("uris = %v, want %v", got.RedirectUris, wantOIDC.GetRedirectUris())
	}
	if !slices.Equal(got.ResponseTypes, wantOIDC.GetResponseTypes()) || !slices.Equal(got.GrantTypes, wantOIDC.GetGrantTypes()) {
		t.Fatalf("response/grant types = %v/%v, want %v/%v", got.ResponseTypes, got.GrantTypes, wantOIDC.GetResponseTypes(), wantOIDC.GetGrantTypes())
	}
	if !proto.Equal(got.ClockSkew, wantOIDC.GetClockSkew()) || !proto.Equal(got.LoginVersion, wantOIDC.GetLoginVersion()) {
		t.Fatalf("clockSkew/loginVersion = %v/%v, want %v/%v", got.ClockSkew, got.LoginVersion, wantOIDC.GetClockSkew(), wantOIDC.GetLoginVersion())
	}
}

func TestZitadel_AppOIDCErrors(t *testing.T) {
	t.Run("permission denied", func(t *testing.T) {
		c := startAppFake(t, &fakeApps{deniedGet: true})
		if _, err := c.AppOIDC(context.Background(), "app-1"); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("error %v is not ErrPermissionDenied", err)
		}
	})
	t.Run("not an oidc app", func(t *testing.T) {
		c := startAppFake(t, &fakeApps{apps: []*applicationv2.Application{{
			ApplicationId: "app-api", ProjectId: testProject, Name: "api",
			Configuration: &applicationv2.Application_ApiConfiguration{ApiConfiguration: &applicationv2.APIConfiguration{}},
		}}})
		if _, err := c.AppOIDC(context.Background(), "app-api"); err == nil || errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("got %v, want a non-OIDC error", err)
		}
	})
}

// TestZitadel_UpdateAppRedirectURIsCarriesReadFields pins the ADR 0012 rule that the write sends
// the read values of response_types, grant_types, clock_skew and login_version: UpdateApplication
// resets those to their defaults when the request leaves them out (Zitadel v4.16.0).
func TestZitadel_UpdateAppRedirectURIsCarriesReadFields(t *testing.T) {
	apps := &fakeApps{apps: []*applicationv2.Application{
		oidcApp("app-1", testProject, "oauth2-proxy", "https://a/oauth2/callback"),
	}}
	c := startAppFake(t, apps)

	if err := c.UpdateAppRedirectURIs(context.Background(), "app-1", []string{"https://a/oauth2/callback", "https://new/oauth2/callback"}); err != nil {
		t.Fatal(err)
	}
	if len(apps.updates) != 1 {
		t.Fatalf("got %d updates, want 1", len(apps.updates))
	}
	oidc := apps.updates[0].GetOidcConfiguration()
	want := apps.apps[0].GetOidcConfiguration()
	if !slices.Equal(oidc.GetRedirectUris(), []string{"https://a/oauth2/callback", "https://new/oauth2/callback"}) {
		t.Fatalf("redirect uris = %v", oidc.GetRedirectUris())
	}
	if !slices.Equal(oidc.GetResponseTypes(), want.GetResponseTypes()) || !slices.Equal(oidc.GetGrantTypes(), want.GetGrantTypes()) {
		t.Fatalf("response/grant types = %v/%v, want %v/%v", oidc.GetResponseTypes(), oidc.GetGrantTypes(), want.GetResponseTypes(), want.GetGrantTypes())
	}
	if !proto.Equal(oidc.GetClockSkew(), want.GetClockSkew()) {
		t.Fatalf("clockSkew = %v, want %v", oidc.GetClockSkew(), want.GetClockSkew())
	}
	if !proto.Equal(oidc.GetLoginVersion(), want.GetLoginVersion()) {
		t.Fatalf("loginVersion = %v, want %v (it would silently flip to UNSPECIFIED)", oidc.GetLoginVersion(), want.GetLoginVersion())
	}
}

func TestZitadel_UpdateAppRedirectURIsVerifiesReadBack(t *testing.T) {
	t.Run("projection lag then match", func(t *testing.T) {
		apps := &fakeApps{lagGet: 1, apps: []*applicationv2.Application{
			oidcApp("app-1", testProject, "oauth2-proxy", "https://a/oauth2/callback"),
		}}
		c := startAppFake(t, apps)
		if err := c.UpdateAppRedirectURIs(context.Background(), "app-1", []string{"https://a/oauth2/callback", "https://new/oauth2/callback"}); err != nil {
			t.Fatalf("a lagging but converging read-back must succeed: %v", err)
		}
	})
	t.Run("stale read-back stays an error", func(t *testing.T) {
		oldTries, oldWait := appReadBackTries, appReadBackWait
		appReadBackTries, appReadBackWait = 2, time.Millisecond
		defer func() { appReadBackTries, appReadBackWait = oldTries, oldWait }()
		apps := &fakeApps{lagGet: 100, apps: []*applicationv2.Application{
			oidcApp("app-1", testProject, "oauth2-proxy", "https://a/oauth2/callback"),
		}}
		c := startAppFake(t, apps)
		if err := c.UpdateAppRedirectURIs(context.Background(), "app-1", []string{"https://a/oauth2/callback", "https://new/oauth2/callback"}); err == nil {
			t.Fatal("a read-back that never matches the write must fail, not report success")
		}
	})
	t.Run("unreadable result is an error", func(t *testing.T) {
		apps := &fakeApps{deniedGet: true, apps: []*applicationv2.Application{
			oidcApp("app-1", testProject, "oauth2-proxy", "https://a/oauth2/callback"),
		}}
		c := startAppFake(t, apps)
		if err := c.UpdateAppRedirectURIs(context.Background(), "app-1", []string{"https://a/oauth2/callback"}); err == nil {
			t.Fatal("an unreadable (never provable) write must fail")
		}
	})
}

func TestZitadel_UpdateAppRedirectURIPermissionDenied(t *testing.T) {
	t.Run("read step denied", func(t *testing.T) {
		c := startAppFake(t, &fakeApps{deniedGet: true})
		err := c.UpdateAppRedirectURIs(context.Background(), "app-1", []string{"https://a/oauth2/callback"})
		if !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("error %v is not ErrPermissionDenied", err)
		}
	})
	t.Run("write step denied", func(t *testing.T) {
		apps := &fakeApps{deniedUpdate: true, apps: []*applicationv2.Application{
			oidcApp("app-1", testProject, "oauth2-proxy", "https://a/oauth2/callback"),
		}}
		c := startAppFake(t, apps)
		err := c.UpdateAppRedirectURIs(context.Background(), "app-1", []string{"https://a/oauth2/callback", "https://new/oauth2/callback"})
		if !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("error %v is not ErrPermissionDenied", err)
		}
		if len(apps.updates) != 0 {
			t.Fatalf("denied update recorded %d requests", len(apps.updates))
		}
	})
}

func TestZitadel_UpdateAppRedirectURIRejectsEmpty(t *testing.T) {
	apps := &fakeApps{apps: []*applicationv2.Application{
		oidcApp("app-1", testProject, "oauth2-proxy", "https://a/oauth2/callback"),
	}}
	c := startAppFake(t, apps)
	if err := c.UpdateAppRedirectURIs(context.Background(), "app-1", nil); err == nil {
		t.Fatal("an empty redirect URI list must be refused")
	}
	if len(apps.updates) != 0 {
		t.Fatalf("refused write reached Zitadel: %d requests", len(apps.updates))
	}
}

// J1: the post-logout URI is added without touching anything else, written once, and a redirect URI
// update keeps the post-logout list.
func TestZitadel_EnsureAppPostLogoutURI(t *testing.T) {
	apps := &fakeApps{apps: []*applicationv2.Application{oidcApp("app-1", testProject, "oauth2-proxy", "https://a/oauth2/callback")}}
	apps.apps[0].GetOidcConfiguration().PostLogoutRedirectUris = []string{"https://other.example/"}
	c := startAppFake(t, apps)
	ctx := context.Background()

	if err := c.EnsureAppPostLogoutURI(ctx, "app-1", "https://t.example/"); err != nil {
		t.Fatal(err)
	}
	cur, err := c.AppOIDC(ctx, "app-1")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"https://other.example/", "https://t.example/"}; !slices.Equal(cur.PostLogoutRedirectUris, want) {
		t.Errorf("post-logout uris = %v, want %v (existing one kept)", cur.PostLogoutRedirectUris, want)
	}
	if !slices.Equal(cur.RedirectUris, []string{"https://a/oauth2/callback"}) || len(apps.updates) != 1 {
		t.Errorf("redirect uris %v, updates %d", cur.RedirectUris, len(apps.updates))
	}
	// Already present: no second write (positive control: the first call did write).
	if err := c.EnsureAppPostLogoutURI(ctx, "app-1", "https://t.example/"); err != nil || len(apps.updates) != 1 {
		t.Errorf("repeat wrote again: err %v, updates %d", err, len(apps.updates))
	}
	// A redirect URI update must carry the post-logout list.
	if err := c.UpdateAppRedirectURIs(ctx, "app-1", []string{"https://a/oauth2/callback", "https://b/oauth2/callback"}); err != nil {
		t.Fatal(err)
	}
	cur, _ = c.AppOIDC(ctx, "app-1")
	if len(cur.PostLogoutRedirectUris) != 2 {
		t.Errorf("redirect update dropped the post-logout uris: %v", cur.PostLogoutRedirectUris)
	}
}

func TestZitadel_EnsureAppPostLogoutURIDenied(t *testing.T) {
	c := startAppFake(t, &fakeApps{apps: []*applicationv2.Application{oidcApp("app-1", testProject, "oauth2-proxy", "https://a/")}, deniedUpdate: true})
	if err := c.EnsureAppPostLogoutURI(context.Background(), "app-1", "https://t.example/"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("error %v is not ErrPermissionDenied", err)
	}
}
