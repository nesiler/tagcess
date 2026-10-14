//go:build integration

// Integration tests for F1-004: they assume `make lab-up` has already brought the lab Zitadel and the local
// Headscale up and seeded them (ADR 0014). They do not start or stop anything themselves, so run them with
// `make lab-integration` or `go test -tags=integration ./test/compose/...` after `make lab-up`.
package compose_test

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	zclient "github.com/zitadel/zitadel-go/v3/pkg/client"
	authorizationv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/authorization/v2"
	filterv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/filter/v2"
	projectv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/project/v2"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"

	"github.com/nesiler/tagcess/test/compose/seed"
)

// endpoint resolves the Zitadel under test: the lab one (ADR 0014), overridable through
// TAGCESS_ZITADEL_ADDR / TAGCESS_ZITADEL_TLS / TAGCESS_SECRETS_DIR.
func endpoint(t *testing.T) seed.Endpoint {
	t.Helper()
	ep, err := seed.EndpointFromEnv(composeDir(t))
	if err != nil {
		t.Fatalf("resolve zitadel endpoint: %v", err)
	}
	return ep
}

func composeDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("resolve compose dir: %v", err)
	}
	return dir
}

// TestCompose_Healthy is AC1: `make lab-up` brings the lab Zitadel and the local Headscale up healthy.
// lab-up already gated it; this re-checks both health endpoints directly, so the test
// fails clearly if run against a stack that never came up.
func TestCompose_Healthy(t *testing.T) {
	client := &http.Client{Timeout: 5 * time.Second}
	ep := endpoint(t)
	scheme := "http"
	if ep.TLS {
		scheme = "https"
	}
	checkHealth(t, client, "zitadel", scheme+"://"+ep.Addr+"/debug/healthz")
	checkHealth(t, client, "headscale", "http://localhost:8090/health")
}

func checkHealth(t *testing.T, client *http.Client, name, url string) {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("%s %s: %v", name, url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s %s: status %d", name, url, resp.StatusCode)
	}
}

// TestCompose_SeedIdempotent is AC2: the seed tool prepares the vpn project, its roles, example
// users and the service user's key, and a second run against the same stack errors on nothing.
func TestCompose_SeedIdempotent(t *testing.T) {
	dir := composeDir(t)
	ctx := context.Background()

	ep := endpoint(t)
	patBytes, err := os.ReadFile(ep.PATFile)
	if err != nil {
		t.Fatalf("read bootstrap PAT (is `make lab-up` done?): %v", err)
	}
	cfg := seed.Config{
		ZitadelAddr:          ep.Addr,
		ZitadelTLS:           ep.TLS,
		BootstrapPAT:         strings.TrimSpace(string(patBytes)),
		SecretsDir:           ep.SecretsDir,
		EnvFile:              filepath.Join(dir, ".env"),
		HeadscaleRedirectURI: "http://localhost:8090/oidc/callback",
	}

	first, err := seed.SeedZitadel(ctx, cfg)
	if err != nil {
		t.Fatalf("first seed run: %v", err)
	}
	if first.ProjectID == "" || len(first.RoleKeys) != len(seed.Roles) || len(first.Users) != len(seed.TestUsers) {
		t.Fatalf("first seed run produced an incomplete result: %+v", first)
	}
	firstKeyBytes, err := os.ReadFile(first.KeyFilePath)
	if err != nil {
		t.Fatalf("read key file after first run: %v", err)
	}

	second, err := seed.SeedZitadel(ctx, cfg)
	if err != nil {
		t.Fatalf("second seed run (must be idempotent): %v", err)
	}
	if second.ProjectID != first.ProjectID {
		t.Fatalf("second run created a different project: %s vs %s", second.ProjectID, first.ProjectID)
	}
	if second.ServiceUserID != first.ServiceUserID {
		t.Fatalf("second run created a different service user: %s vs %s", second.ServiceUserID, first.ServiceUserID)
	}
	secondKeyBytes, err := os.ReadFile(second.KeyFilePath)
	if err != nil {
		t.Fatalf("read key file after second run: %v", err)
	}
	if !bytes.Equal(firstKeyBytes, secondKeyBytes) {
		t.Fatalf("second run rewrote the service user key file instead of reusing it")
	}

	// Verify the roles and grants actually landed in Zitadel, not just that SeedZitadel returned
	// without error (first.RoleKeys/first.Users are the seed's own request list, not proof of
	// server state).
	verifyRolesExist(ctx, t, cfg.BootstrapPAT, first.ProjectID)
	for username, userID := range first.Users {
		var role string
		for _, tu := range seed.TestUsers {
			if tu.Username == username {
				role = tu.Role
			}
		}
		verifyUserHasRole(ctx, t, cfg.BootstrapPAT, userID, first.ProjectID, role)
	}

	headscaleResult, err := seed.SeedHeadscale(ctx, filepath.Join(dir, "compose.yaml"))
	if err != nil {
		t.Fatalf("first headscale seed: %v", err)
	}
	// Sanity check the node registration path this seed exists for (F1-004 [Ö]): a real tailscale
	// node can register non-interactively with the pre-auth key it produced.
	if !strings.HasPrefix(headscaleResult.PreAuthKey, "hskey-auth-") || len(headscaleResult.PreAuthKey) < 40 {
		t.Fatalf("pre-auth key does not look like a full, usable headscale key: %q", headscaleResult.PreAuthKey)
	}
	secondHeadscale, err := seed.SeedHeadscale(ctx, filepath.Join(dir, "compose.yaml"))
	if err != nil {
		t.Fatalf("second headscale seed (must be idempotent): %v", err)
	}
	if secondHeadscale.UserID != headscaleResult.UserID {
		t.Fatalf("second headscale seed created a different user: %s vs %s", secondHeadscale.UserID, headscaleResult.UserID)
	}
	// `headscale preauthkeys list` masks the key value; this is the only way to prove the second
	// run actually reused the first run's key instead of quietly handing back an unusable one.
	if secondHeadscale.PreAuthKey != headscaleResult.PreAuthKey {
		t.Fatalf("second headscale seed returned a different pre-auth key than the first run")
	}
}

func verifyRolesExist(ctx context.Context, t *testing.T, pat, projectID string) {
	t.Helper()
	conn := dialZitadel(t)
	defer func() { _ = conn.Close() }()
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+pat)
	c := projectv2.NewProjectServiceClient(conn)
	resp, err := c.ListProjectRoles(ctx, &projectv2.ListProjectRolesRequest{ProjectId: projectID})
	if err != nil {
		t.Fatalf("ListProjectRoles: %v", err)
	}
	got := map[string]bool{}
	for _, r := range resp.GetProjectRoles() {
		got[r.GetKey()] = true
	}
	for _, want := range seed.Roles {
		if !got[want] {
			t.Fatalf("role %q not found in Zitadel's project roles: %v", want, got)
		}
	}
}

func verifyUserHasRole(ctx context.Context, t *testing.T, pat, userID, projectID, role string) {
	t.Helper()
	conn := dialZitadel(t)
	defer func() { _ = conn.Close() }()
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+pat)
	c := authorizationv2.NewAuthorizationServiceClient(conn)
	resp, err := c.ListAuthorizations(ctx, &authorizationv2.ListAuthorizationsRequest{
		Filters: []*authorizationv2.AuthorizationsSearchFilter{
			{Filter: &authorizationv2.AuthorizationsSearchFilter_InUserIds{
				InUserIds: &filterv2.InIDsFilter{Ids: []string{userID}},
			}},
			{Filter: &authorizationv2.AuthorizationsSearchFilter_ProjectId{
				ProjectId: &filterv2.IDFilter{Id: projectID},
			}},
		},
	})
	if err != nil {
		t.Fatalf("ListAuthorizations for user %s: %v", userID, err)
	}
	for _, a := range resp.GetAuthorizations() {
		for _, r := range a.GetRoles() {
			if r.GetKey() == role {
				return
			}
		}
	}
	t.Fatalf("user %s has no grant for role %q in project %s", userID, role, projectID)
}

func dialZitadel(t *testing.T) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient(endpoint(t).Addr, endpoint(t).DialOption())
	if err != nil {
		t.Fatalf("dial zitadel: %v", err)
	}
	return conn
}

// TestCompose_ServiceUserCanRead is AC3: the tagcess service user's JWT profile key (ADR 0009)
// gets a real access token from the lab Zitadel, and that token can call ListAuthorizations.
func TestCompose_ServiceUserCanRead(t *testing.T) {
	ep := endpoint(t)
	keyPath := filepath.Join(ep.SecretsDir, "zitadel-key.json")
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("service user key not found at %s (is `make lab-up` done?): %v", keyPath, err)
	}

	ctx := context.Background()
	authOption := zclient.DefaultServiceUserAuthentication(keyPath, oidc.ScopeOpenID, zclient.ScopeZitadelAPI())
	zopts := []zitadel.Option{zitadel.WithInsecure(ep.Port)}
	if ep.TLS {
		port, perr := strconv.ParseUint(ep.Port, 10, 16)
		if perr != nil {
			t.Fatalf("zitadel port %q: %v", ep.Port, perr)
		}
		zopts = []zitadel.Option{zitadel.WithPort(uint16(port))}
	}
	api, err := zclient.New(ctx, zitadel.New(ep.Host, zopts...), zclient.WithAuth(authOption))
	if err != nil {
		t.Fatalf("build zitadel client: %v", err)
	}

	resp, err := api.AuthorizationServiceV2().ListAuthorizations(ctx, &authorizationv2.ListAuthorizationsRequest{})
	if err != nil {
		t.Fatalf("ListAuthorizations: %v", err)
	}
	// Every seeded user must appear with exactly its granted role in the seeded project.
	got := map[string][]string{}
	for _, a := range resp.GetAuthorizations() {
		if a.GetProject().GetName() != seed.ProjectName {
			continue
		}
		var keys []string
		for _, r := range a.GetRoles() {
			keys = append(keys, r.GetKey())
		}
		got[a.GetUser().GetPreferredLoginName()] = keys
	}
	for _, tu := range seed.TestUsers {
		keys, ok := got[tu.Username]
		if !ok {
			t.Errorf("no authorization for %s in project %q; got %v", tu.Username, seed.ProjectName, got)
			continue
		}
		if len(keys) != 1 || keys[0] != tu.Role {
			t.Errorf("%s roles = %v, want [%s]", tu.Username, keys, tu.Role)
		}
	}
}
