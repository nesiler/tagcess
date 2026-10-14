//go:build integration

// Integration test for F1-011 (AC4): reconcile against the real lab Zitadel (the developer's k3s, ADR 0014)
// and the local compose Headscale. Run `make lab-up`, then
// `make lab-integration` (which does not yet include this package) or
// `go test -tags=integration -count=1 -run TestReconcile_Compose ./internal/sync/...`.
//
// The shared compose Headscale runs in policy file mode, where SetPolicy is refused; the live
// policy assertion therefore skips there. To exercise it end to end, point TAGCESS_HEADSCALE_TARGET
// at a database-mode Headscale (see the F1-010 Kanıt for the throwaway-container recipe).
package sync_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tailscale/hujson"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	authorizationv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/authorization/v2"
	userv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/headscale"
	"github.com/nesiler/tagcess/internal/store"
	"github.com/nesiler/tagcess/internal/sync"
	"github.com/nesiler/tagcess/internal/zitadel"
	"github.com/nesiler/tagcess/test/compose/seed"
)

type labEnv struct {
	ep       seed.Endpoint
	seeded   *seed.Result
	client   *zitadel.Client
	conn     *grpc.ClientConn
	adminCtx context.Context
}

func setupLab(t *testing.T) *labEnv {
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
	ctx := context.Background()
	seeded, err := seed.SeedZitadel(ctx, seed.Config{
		ZitadelAddr: ep.Addr, ZitadelTLS: ep.TLS, BootstrapPAT: strings.TrimSpace(string(patBytes)),
		SecretsDir: ep.SecretsDir, EnvFile: filepath.Join(composeDir, ".env"),
		HeadscaleRedirectURI: "http://localhost:8090/oidc/callback",
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	port, err := strconv.ParseUint(ep.Port, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	c, err := zitadel.New(ctx, zitadel.Config{
		Host: ep.Host, Port: uint16(port), Insecure: !ep.TLS, KeyFile: seeded.KeyFilePath, ProjectID: seeded.ProjectID,
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
	return &labEnv{
		ep: ep, seeded: seeded, client: c, conn: conn,
		adminCtx: metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+strings.TrimSpace(string(patBytes))),
	}
}

func (e *labEnv) issuer() string {
	if e.ep.TLS {
		return "https://" + e.ep.Host
	}
	return "http://" + e.ep.Addr
}

// addUserWithRole creates a throwaway human user and grants it role, returning the Zitadel user ID.
func (e *labEnv) addUserWithRole(t *testing.T, role string) string {
	t.Helper()
	users := userv2.NewUserServiceClient(e.conn)
	authz := authorizationv2.NewAuthorizationServiceClient(e.conn)
	name := fmt.Sprintf("f1011-%d@tagcess.test", time.Now().UnixNano())
	resp, err := users.CreateUser(e.adminCtx, &userv2.CreateUserRequest{
		OrganizationId: e.seeded.OrgID,
		Username:       &name,
		UserType: &userv2.CreateUserRequest_Human_{Human: &userv2.CreateUserRequest_Human{
			Profile: &userv2.SetHumanProfile{GivenName: "f1011", FamilyName: role},
			Email: &userv2.SetHumanEmail{Email: name,
				Verification: &userv2.SetHumanEmail_IsVerified{IsVerified: true}},
		}},
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	id := resp.GetId()
	t.Cleanup(func() { _, _ = users.DeleteUser(e.adminCtx, &userv2.DeleteUserRequest{UserId: id}) })
	if _, err := authz.CreateAuthorization(e.adminCtx, &authorizationv2.CreateAuthorizationRequest{
		UserId: id, ProjectId: e.seeded.ProjectID, OrganizationId: e.seeded.OrgID, RoleKeys: []string{role},
	}); err != nil {
		t.Fatalf("grant %s: %v", role, err)
	}
	return id
}

// recordPipeline captures the change request the orchestrator builds without touching Headscale.
type recordPipeline struct {
	reqs []change.Request
}

func (p *recordPipeline) Submit(_ context.Context, req change.Request) (change.Result, error) {
	p.reqs = append(p.reqs, req)
	return change.Result{Status: "recorded"}, nil
}

func (p *recordPipeline) last() (change.Request, bool) {
	if len(p.reqs) == 0 {
		return change.Request{}, false
	}
	return p.reqs[len(p.reqs)-1], true
}

func headscaleTarget() string {
	if t := os.Getenv("TAGCESS_HEADSCALE_TARGET"); t != "" {
		return t
	}
	return "127.0.0.1:50444"
}

func newStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "tagcess.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func newReconciler(t *testing.T, env *labEnv, s *store.Store, hs sync.HeadscaleReader, pipe sync.Pipeline) *sync.Reconciler {
	t.Helper()
	r, err := sync.NewReconciler(sync.ReconcilerConfig{
		Zitadel: env.client, Headscale: hs, Pipeline: pipe, Queries: s.Queries(), DryRun: s, Issuer: env.issuer(),
	})
	if err != nil {
		t.Fatalf("NewReconciler: %v", err)
	}
	return r
}

func groupsOfPolicy(t *testing.T, policy string) map[string][]string {
	t.Helper()
	root, err := hujson.Parse([]byte(policy))
	if err != nil {
		t.Fatalf("parse policy: %v", err)
	}
	root.Standardize()
	var doc struct {
		Groups map[string][]string `json:"groups"`
	}
	if err := json.Unmarshal(root.Pack(), &doc); err != nil {
		t.Fatalf("unmarshal policy: %v", err)
	}
	return doc.Groups
}

// withHSUser is a Headscale reader that also lists a user with the given provider ID. Only role
// holders Headscale knows enter a group (F3-031), and the shared compose Headscale cannot be given a
// provider ID, so the lab user the test creates is lent a Headscale user here.
type withHSUser struct {
	sync.HeadscaleReader
	providerID string
}

func (w withHSUser) ListUsers(ctx context.Context) ([]headscale.User, error) {
	users, err := w.HeadscaleReader.ListUsers(ctx)
	return append(users, headscale.User{ID: 1 << 40, Name: "f3031-lab", ProviderID: w.providerID}), err
}

// TestReconcile_Compose is AC4: a grant added in the lab Zitadel becomes a policy group membership.
func TestReconcile_Compose(t *testing.T) {
	env := setupLab(t)
	userID := env.addUserWithRole(t, "standart")
	want := env.issuer() + "/" + userID + "@"
	lend := func(hs sync.HeadscaleReader) sync.HeadscaleReader {
		return withHSUser{HeadscaleReader: hs, providerID: env.issuer() + "/" + userID}
	}

	// Always exercises the real lab read: the orchestrator must turn the new grant into the
	// rendered target for group:standart.
	t.Run("plan from lab grants", func(t *testing.T) {
		hs, err := headscale.New(headscale.Config{Target: headscaleTarget(), Timeout: 10 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = hs.Close() })
		rec := &recordPipeline{}
		r := newReconciler(t, env, newStore(t), lend(hs), rec)
		if _, err := r.Run(context.Background(), "manual"); err != nil {
			t.Fatalf("Run: %v", err)
		}
		req, ok := rec.last()
		if !ok {
			t.Fatal("the change pipeline was never handed a request")
		}
		if !strings.Contains(string(req.Target), want) {
			t.Fatalf("the rendered policy does not grant the new user:\nwant %s\ngot %s", want, req.Target)
		}
	})

	t.Run("live policy", func(t *testing.T) {
		hs, err := headscale.New(headscale.Config{Target: headscaleTarget(), Timeout: 10 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = hs.Close() })
		ctx := context.Background()

		before, err := hs.GetPolicy(ctx)
		if err != nil {
			t.Fatalf("GetPolicy: %v", err)
		}
		// Apply needs policy.mode=database; the shared compose stack is file mode until the G-02
		// runbook is applied (F1-023). Probe with a harmless deny-all policy (a database-mode
		// Headscale may have no policy yet, and an empty ACL cannot widen access) and skip instead
		// of failing the suite.
		probe := `{"acls":[]}`
		if _, err := hs.SetPolicy(ctx, probe); err != nil {
			if strings.Contains(err.Error(), "update is disabled for modes other than") {
				t.Skipf("compose Headscale runs in policy file mode: %v", err)
			}
			t.Fatalf("SetPolicy probe: %v", err)
		}
		t.Cleanup(func() {
			if before.Text == "" {
				return
			}
			if _, err := hs.SetPolicy(context.Background(), before.Text); err != nil {
				t.Errorf("restore policy: %v", err)
			}
		})

		s := newStore(t)
		if _, err := s.DB().ExecContext(ctx, `UPDATE settings SET value = 'false' WHERE key = 'dry_run'`); err != nil {
			t.Fatalf("turn off dry run: %v", err)
		}
		r := newReconciler(t, env, s, lend(hs), change.New(hs, s.Queries(), audit.New(s.Queries()), s))
		res, err := r.Run(ctx, "manual")
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if !res.Change.Applied {
			t.Fatalf("reconcile did not apply: %+v (reason %q)", res.Change, res.Plan.Reason)
		}
		got, err := hs.GetPolicy(ctx)
		if err != nil {
			t.Fatalf("GetPolicy after reconcile: %v", err)
		}
		members := groupsOfPolicy(t, got.Text)["group:standart"]
		found := false
		for _, m := range members {
			if m == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("group:standart = %v, want it to contain %s", members, want)
		}
	})
}
