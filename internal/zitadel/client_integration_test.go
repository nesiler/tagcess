//go:build integration

// Integration tests for F1-007 against the lab Zitadel (`make lab-up`, then `make lab-integration`).
// They need the seeded stack of F1-004.
package zitadel_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	authorizationv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/authorization/v2"
	userv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"

	"github.com/nesiler/tagcess/internal/zitadel"
	"github.com/nesiler/tagcess/test/compose/seed"
)

type env struct {
	ep      seed.Endpoint
	pat     string
	seeded  *seed.Result
	client  *zitadel.Client
	adminCx context.Context // carries the bootstrap PAT
	conn    *grpc.ClientConn
}

func setup(t *testing.T) *env {
	t.Helper()
	composeDir, err := filepath.Abs("../../test/compose")
	if err != nil {
		t.Fatal(err)
	}
	ep, err := seed.EndpointFromEnv(composeDir)
	if err != nil {
		t.Fatalf("resolve zitadel endpoint: %v", err)
	}
	patBytes, err := os.ReadFile(ep.PATFile)
	if err != nil {
		t.Fatalf("read bootstrap PAT (is `make lab-up` done?): %v", err)
	}
	pat := strings.TrimSpace(string(patBytes))
	ctx := context.Background()
	// Idempotent: returns the project and user IDs the stack already holds.
	seeded, err := seed.SeedZitadel(ctx, seed.Config{
		ZitadelAddr: ep.Addr, ZitadelTLS: ep.TLS, BootstrapPAT: pat, SecretsDir: ep.SecretsDir,
		EnvFile: filepath.Join(composeDir, ".env"), HeadscaleRedirectURI: "http://localhost:8090/oidc/callback",
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	port, err := strconv.ParseUint(ep.Port, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	c, err := zitadel.New(ctx, zitadel.Config{
		Host: ep.Host, Port: uint16(port), Insecure: !ep.TLS,
		KeyFile: seeded.KeyFilePath, ProjectID: seeded.ProjectID,
	})
	if err != nil {
		t.Fatalf("zitadel.New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	conn, err := grpc.NewClient(ep.Addr, ep.DialOption())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &env{
		ep: ep, pat: pat, seeded: seeded, client: c, conn: conn,
		adminCx: metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+pat),
	}
}

// TestZitadel_ListGrantsAllPages is AC1 against a real Zitadel: every seeded (user, role) pair of
// the vpn project comes back, and nothing from outside the project.
func TestZitadel_ListGrantsAllPages(t *testing.T) {
	e := setup(t)
	grants, err := e.client.ListGrants(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, g := range grants {
		have[g.UserID+":"+g.Role] = true
	}
	for _, tu := range seed.TestUsers {
		id := e.seeded.Users[tu.Username]
		if !have[id+":"+tu.Role] {
			t.Errorf("grant %s (%s) for %s missing from %v", tu.Role, id, tu.Username, grants)
		}
	}
	valid := map[string]bool{}
	for _, r := range seed.Roles {
		valid[r] = true
	}
	for _, g := range grants {
		if !valid[g.Role] {
			t.Errorf("grant with a role outside the vpn project: %+v", g)
		}
	}
}

// TestZitadel_UserStates is AC3: active, inactive, locked and deleted users are told apart, and
// each result is keyed by the Zitadel user ID. The service user sees the throwaway users through
// its org-level ORG_OWNER_VIEWER role (ADR 0009); the deleted one is confirmed by GetUserByID NotFound.
func TestZitadel_UserStates(t *testing.T) {
	e := setup(t)
	ctx := e.adminCx
	users := userv2.NewUserServiceClient(e.conn)
	authz := authorizationv2.NewAuthorizationServiceClient(e.conn)
	suffix := strconv.FormatInt(time.Now().UnixNano(), 36)

	mk := func(kind string) string {
		name := fmt.Sprintf("f1007-%s-%s@tagcess.test", kind, suffix)
		resp, err := users.CreateUser(ctx, &userv2.CreateUserRequest{
			OrganizationId: e.seeded.OrgID,
			Username:       &name,
			UserType: &userv2.CreateUserRequest_Human_{Human: &userv2.CreateUserRequest_Human{
				Profile: &userv2.SetHumanProfile{GivenName: "f1007", FamilyName: kind},
				Email: &userv2.SetHumanEmail{Email: name,
					Verification: &userv2.SetHumanEmail_IsVerified{IsVerified: true}},
			}},
		})
		if err != nil {
			t.Fatalf("create %s user: %v", kind, err)
		}
		id := resp.GetId()
		t.Cleanup(func() { _, _ = users.DeleteUser(e.adminCx, &userv2.DeleteUserRequest{UserId: id}) })
		if _, err := authz.CreateAuthorization(ctx, &authorizationv2.CreateAuthorizationRequest{
			UserId: id, ProjectId: e.seeded.ProjectID, OrganizationId: e.seeded.OrgID, RoleKeys: []string{"standart"},
		}); err != nil {
			t.Fatalf("grant %s user: %v", kind, err)
		}
		return id
	}
	active, inactive, locked, deleted := mk("active"), mk("inactive"), mk("locked"), mk("deleted")
	if _, err := users.DeactivateUser(ctx, &userv2.DeactivateUserRequest{UserId: inactive}); err != nil {
		t.Fatal(err)
	}
	if _, err := users.LockUser(ctx, &userv2.LockUserRequest{UserId: locked}); err != nil {
		t.Fatal(err)
	}
	if _, err := users.DeleteUser(ctx, &userv2.DeleteUserRequest{UserId: deleted}); err != nil {
		t.Fatal(err)
	}

	// Projections are eventually consistent; wait until the states settle.
	want := map[string]zitadel.UserState{
		active: zitadel.UserActive, inactive: zitadel.UserInactive, locked: zitadel.UserLocked, deleted: zitadel.UserDeleted,
	}
	ids := []string{active, inactive, locked, deleted}
	var got map[string]zitadel.UserState
	var err error
	for range 20 {
		got, err = e.client.UserStates(context.Background(), ids)
		if err == nil && fmt.Sprint(got) == fmt.Sprint(want) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	for id, w := range want {
		if got[id] != w {
			t.Errorf("state of %s = %v, want %v", id, got[id], w)
		}
	}
	// The seeded users are active and come back under their Zitadel IDs.
	var seededIDs []string
	for _, id := range e.seeded.Users {
		seededIDs = append(seededIDs, id)
	}
	seededStates, err := e.client.UserStates(context.Background(), seededIDs)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range seededIDs {
		if seededStates[id] != zitadel.UserActive {
			t.Errorf("seeded user %s state = %v, want active", id, seededStates[id])
		}
	}
}
