//go:build integration

// Integration tests for F1-020: the local Caddy/oauth2-proxy auth path and the lab Zitadel Actions
// v2 target that delivers the webhook to the tagcess receiver over Tailscale. They assume
// `make lab-up` has already run (ADR 0014); run them with `make lab-integration`.
package compose_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	actionv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/action/v2"
	authorizationv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/authorization/v2"
	userv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"

	"github.com/nesiler/tagcess/internal/hook"
	"github.com/nesiler/tagcess/internal/store"
	"github.com/nesiler/tagcess/test/compose/seed"
	"github.com/nesiler/tagcess/test/labenv"
)

// labIssuerHost is the lab Zitadel host (test/lab/lib.sh LAB_HOST).
var labIssuerHost = labenv.ZitadelHost()

// TestCompose_LoginFlow is AC1: Caddy and oauth2-proxy are healthy, and an unauthenticated request
// is driven into the lab Zitadel login flow for the seeded oauth2-proxy client. The interactive
// browser login itself is verified manually; this test proves the wiring that
// makes it possible (client id, redirect URI, issuer).
func TestCompose_LoginFlow(t *testing.T) {
	client := &http.Client{Timeout: 5 * time.Second}
	checkHealth(t, client, "oauth2-proxy", "http://127.0.0.1:4180/ping")

	noRedirect := &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := noRedirect.Get("http://localhost:8080/")
	if err != nil {
		t.Fatalf("GET http://localhost:8080/: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		t.Fatalf("unauthenticated GET /: status %d, want a redirect to oauth2-proxy", resp.StatusCode)
	}
	start := resp.Header.Get("Location")
	if start == "" {
		t.Fatalf("unauthenticated GET /: no Location header")
	}

	resp2, err := noRedirect.Get(resolve(t, "http://localhost:8080", start))
	if err != nil {
		t.Fatalf("GET %s: %v", start, err)
	}
	_ = resp2.Body.Close()
	authorize := resp2.Header.Get("Location")
	u, err := url.Parse(authorize)
	if err != nil {
		t.Fatalf("parse authorize URL %q: %v", authorize, err)
	}
	if u.Host != labIssuerHost {
		t.Fatalf("authorize host = %q, want %q (redirect chain broke)", u.Host, labIssuerHost)
	}
	if !strings.Contains(u.Path, "/oauth/v2/authorize") {
		t.Fatalf("authorize path = %q, want the OIDC authorize endpoint", u.Path)
	}
	if got := u.Query().Get("client_id"); got != envFileValue(t, "OAUTH2_PROXY_CLIENT_ID") {
		t.Fatalf("authorize client_id = %q, want the seeded oauth2-proxy client id", got)
	}
	if got := u.Query().Get("redirect_uri"); got != "http://localhost:8080/oauth2/callback" {
		t.Fatalf("authorize redirect_uri = %q, want the local callback", got)
	}
}

// TestCompose_ActionsSeeded is AC2: the seed installs exactly one target and an execution per
// webhook event, and running it again changes nothing (same target id, still one target).
func TestCompose_ActionsSeeded(t *testing.T) {
	pat := readBootstrapPAT(t)
	ctx := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+pat)
	conn := dialZitadel(t)
	defer func() { _ = conn.Close() }()
	actions := actionv2.NewActionServiceClient(conn)

	targets := listTargets(t, ctx, actions)
	webhook := findWebhookTarget(t, targets)
	if !strings.HasPrefix(webhook.GetEndpoint(), "http://") || !strings.HasSuffix(webhook.GetEndpoint(), "/hook") {
		t.Fatalf("webhook endpoint = %q, want an http .../hook URL", webhook.GetEndpoint())
	}
	assertExecutions(t, ctx, actions, webhook.GetId())

	// Idempotency: re-seed with the endpoint already in place; the target id must not change, no
	// second target may appear and every event must still have exactly one execution.
	cfg := seedConfig(t, pat, webhook.GetEndpoint())
	first, err := seed.SeedZitadel(ctx, cfg)
	if err != nil {
		t.Fatalf("first seed run: %v", err)
	}
	second, err := seed.SeedZitadel(ctx, cfg)
	if err != nil {
		t.Fatalf("second seed run: %v", err)
	}
	if first.WebhookTargetID == "" || first.WebhookTargetID != second.WebhookTargetID {
		t.Fatalf("webhook target id changed across seed runs: %q then %q", first.WebhookTargetID, second.WebhookTargetID)
	}
	if got := filterTargets(listTargets(t, ctx, actions), seed.WebhookTargetName); len(got) != 1 {
		t.Fatalf("re-seeding left %d webhook targets, want 1", len(got))
	}
	assertExecutions(t, ctx, actions, webhook.GetId())
}

// assertExecutions checks that every webhook event has exactly one execution, pointing at targetID.
func assertExecutions(t *testing.T, ctx context.Context, c actionv2.ActionServiceClient, targetID string) {
	t.Helper()
	executions := listExecutions(t, ctx, c)
	for _, event := range seed.WebhookEvents {
		var matched [][]string
		for _, e := range executions {
			if ev := e.GetCondition().GetEvent(); ev != nil && ev.GetEvent() == event {
				matched = append(matched, e.GetTargets())
			}
		}
		if len(matched) != 1 || len(matched[0]) != 1 || matched[0][0] != targetID {
			t.Fatalf("execution %s -> %v, want exactly one pointing at %s", event, matched, targetID)
		}
	}
}

// TestCompose_WebhookDelivered is AC3: adding a grant in the lab Zitadel makes Zitadel deliver a
// signed request to the tagcess webhook receiver (the real hook.Handler), over Tailscale.
func TestCompose_WebhookDelivered(t *testing.T) {
	pat := readBootstrapPAT(t)
	ctx := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+pat)
	conn := dialZitadel(t)
	defer func() { _ = conn.Close() }()
	actions := actionv2.NewActionServiceClient(conn)

	webhook := findWebhookTarget(t, listTargets(t, ctx, actions))
	u, err := url.Parse(webhook.GetEndpoint())
	if err != nil || u.Port() == "" {
		t.Fatalf("webhook endpoint %q has no usable port: %v", webhook.GetEndpoint(), err)
	}

	key := strings.TrimSpace(readFile(t, filepath.Join(endpoint(t).SecretsDir, seed.WebhookSigningKeyFile)))
	if key == "" {
		t.Fatal("webhook signing key is empty; was `make lab-up` run?")
	}

	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "hook.db"))
	if err != nil {
		t.Fatalf("open temp store: %v", err)
	}
	defer func() { _ = st.Close() }()
	signals := make(chan struct{}, 8)
	handler, err := hook.NewHandler(hook.Config{
		SigningKey: []byte(key),
		Queries:    st.Queries(),
		Trigger:    signalerFunc(func() { signals <- struct{}{} }),
	})
	if err != nil {
		t.Fatalf("build hook handler: %v", err)
	}

	// Bind the exact address the target calls (the developer's Tailscale address): the receiver is
	// never exposed on other interfaces.
	ln, err := net.Listen("tcp", u.Host)
	if err != nil {
		t.Fatalf("listen on %s: %v", u.Host, err)
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	// An unsigned delivery is rejected: the receiver must not signal on it (Y-01.2).
	resp, err := http.Post("http://"+u.Host+"/hook", "application/json", strings.NewReader(`{"aggregateID":"x","sequence":1}`))
	if err != nil {
		t.Fatalf("unsigned POST: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unsigned POST: status %d, want 401", resp.StatusCode)
	}

	// A fresh grant triggers user.grant.added, which the seeded execution points at this receiver.
	res := seedConfigResult(t, ctx, pat)
	userID := createGrantUser(t, ctx, conn, res.OrgID, res.ProjectID)
	defer deleteUser(t, ctx, conn, userID)

	select {
	case <-signals:
	case <-time.After(45 * time.Second):
		t.Fatalf("no signed webhook delivery within 45s (target %s)", webhook.GetEndpoint())
	}
}

// signalerFunc adapts a function to hook.Signaler.
type signalerFunc func()

func (f signalerFunc) Signal() { f() }

func resolve(t *testing.T, base, ref string) string {
	t.Helper()
	u, err := url.Parse(ref)
	if err != nil {
		t.Fatalf("parse %q: %v", ref, err)
	}
	if u.IsAbs() {
		return u.String()
	}
	b, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parse base %q: %v", base, err)
	}
	return b.ResolveReference(u).String()
}

// seedConfig is the seed configuration the integration tests use: the local stack's OIDC and
// headscale redirect URIs plus the webhook endpoint already installed in the lab.
func seedConfig(t *testing.T, pat, webhookURL string) seed.Config {
	t.Helper()
	return seed.Config{
		ZitadelAddr:            endpoint(t).Addr,
		ZitadelTLS:             endpoint(t).TLS,
		BootstrapPAT:           pat,
		SecretsDir:             endpoint(t).SecretsDir,
		EnvFile:                filepath.Join(composeDir(t), ".env"),
		HeadscaleRedirectURI:   "http://localhost:8090/oidc/callback",
		OAuth2ProxyRedirectURI: "http://localhost:8080/oauth2/callback",
		WebhookURL:             webhookURL,
	}
}

// seedConfigResult gets the org/project ids without touching the actions or the OIDC apps.
func seedConfigResult(t *testing.T, ctx context.Context, pat string) *seed.Result {
	t.Helper()
	res, err := seed.SeedZitadel(ctx, seed.Config{
		ZitadelAddr:          endpoint(t).Addr,
		ZitadelTLS:           endpoint(t).TLS,
		BootstrapPAT:         pat,
		SecretsDir:           endpoint(t).SecretsDir,
		EnvFile:              filepath.Join(composeDir(t), ".env"),
		HeadscaleRedirectURI: "http://localhost:8090/oidc/callback",
	})
	if err != nil {
		t.Fatalf("seed for ids: %v", err)
	}
	return res
}

// createGrantUser makes a throwaway human user and grants it the standart role, which fires
// user.grant.added.
func createGrantUser(t *testing.T, ctx context.Context, conn *grpc.ClientConn, orgID, projectID string) string {
	t.Helper()
	users := userv2.NewUserServiceClient(conn)
	username := fmt.Sprintf("f120-webhook-%d@tagcess.test", time.Now().UnixNano())
	resp, err := users.CreateUser(ctx, &userv2.CreateUserRequest{
		OrganizationId: orgID,
		Username:       &username,
		UserType: &userv2.CreateUserRequest_Human_{
			Human: &userv2.CreateUserRequest_Human{
				Profile:      &userv2.SetHumanProfile{GivenName: "f120", FamilyName: "webhook"},
				Email:        &userv2.SetHumanEmail{Email: username, Verification: &userv2.SetHumanEmail_IsVerified{IsVerified: true}},
				PasswordType: &userv2.CreateUserRequest_Human_Password{Password: &userv2.Password{Password: seed.TestUserPassword, ChangeRequired: false}},
			},
		},
	})
	if err != nil {
		t.Fatalf("create grant user: %v", err)
	}
	userID := resp.GetId()
	if _, err := authorizationv2.NewAuthorizationServiceClient(conn).CreateAuthorization(ctx, &authorizationv2.CreateAuthorizationRequest{
		UserId:         userID,
		ProjectId:      projectID,
		OrganizationId: orgID,
		RoleKeys:       []string{"standart"},
	}); err != nil {
		t.Fatalf("grant standart: %v", err)
	}
	return userID
}

func deleteUser(t *testing.T, ctx context.Context, conn *grpc.ClientConn, userID string) {
	t.Helper()
	if _, err := userv2.NewUserServiceClient(conn).DeleteUser(ctx, &userv2.DeleteUserRequest{UserId: userID}); err != nil {
		t.Logf("cleanup: delete user %s: %v", userID, err)
	}
}

func listTargets(t *testing.T, ctx context.Context, c actionv2.ActionServiceClient) []*actionv2.Target {
	t.Helper()
	resp, err := c.ListTargets(ctx, &actionv2.ListTargetsRequest{})
	if err != nil {
		t.Fatalf("ListTargets: %v", err)
	}
	return resp.GetTargets()
}

func filterTargets(targets []*actionv2.Target, name string) []*actionv2.Target {
	var out []*actionv2.Target
	for _, tg := range targets {
		if tg.GetName() == name {
			out = append(out, tg)
		}
	}
	return out
}

func findWebhookTarget(t *testing.T, targets []*actionv2.Target) *actionv2.Target {
	t.Helper()
	got := filterTargets(targets, seed.WebhookTargetName)
	if len(got) != 1 {
		t.Fatalf("targets named %q = %d, want exactly 1", seed.WebhookTargetName, len(got))
	}
	return got[0]
}

func listExecutions(t *testing.T, ctx context.Context, c actionv2.ActionServiceClient) []*actionv2.Execution {
	t.Helper()
	resp, err := c.ListExecutions(ctx, &actionv2.ListExecutionsRequest{})
	if err != nil {
		t.Fatalf("ListExecutions: %v", err)
	}
	return resp.GetExecutions()
}

func readBootstrapPAT(t *testing.T) string {
	t.Helper()
	return strings.TrimSpace(readFile(t, endpoint(t).PATFile))
}

func envFileValue(t *testing.T, key string) string {
	t.Helper()
	for _, line := range strings.Split(readFile(t, filepath.Join(composeDir(t), ".env")), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok && k == key {
			return v
		}
	}
	t.Fatalf("%s not found in .env; was `make lab-up` run?", key)
	return ""
}
