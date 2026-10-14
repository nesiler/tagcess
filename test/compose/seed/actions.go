package seed

// F1-020: the seed also prepares the lab-side pieces the local stack needs — the Actions v2 target
// and executions that point at the tagcess webhook, and the OIDC application oauth2-proxy logs in
// through. Both are create-if-missing (like the rest of the seed), so `make lab-up` is repeatable.
//
// The webhook target is `rest_async` (fire-and-forget; Zitadel ignores the response and never
// retries — the periodic reconcile covers a missed delivery, architecture.md §2). The signing key
// Zitadel returns on creation is written to the gitignored SecretsDir because Zitadel never shows it
// again; the receiver (tagcess, or the integration test) reads it from there.
//
// Zitadel's HTTP client refuses to call 100.64.0.0/10 and every private range by default (the
// `HTTPClient.DenyList` system default, cmd/defaults.yaml in Zitadel v4.16.0). The local receiver
// lives on the developer's Tailscale address, so the lab Zitadel overrides that list
// (test/lab/zitadel-values.yaml). The same override is needed in production, where ADR 0003 plans a
// `tag:k8s → tag:vpn-server` call to 100.64.0.4.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	actionv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/action/v2"
	applicationv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/application/v2"
	filterv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/filter/v2"
)

const (
	// WebhookTargetName is the Actions v2 event target the seed owns.
	WebhookTargetName = "tagcess-webhook"
	// WebhookSigningKeyFile is where the target's signing key is cached under SecretsDir. Zitadel
	// shows the key only once, at target creation.
	WebhookSigningKeyFile = "webhook-signing-key"
	// GroupsTargetName is the Actions v2 function target that answers the `groups` claim (F1-026).
	GroupsTargetName = "tagcess-groups-claim"
	// GroupsSigningKeyFile is where the groups target's signing key is cached under SecretsDir.
	GroupsSigningKeyFile = "groups-signing-key"
	// FunctionPreuserinfo is the v2 function whose execution fills the `groups` claim: it runs
	// while the userinfo/ID token is assembled.
	FunctionPreuserinfo = "preuserinfo"
	// OAuth2ProxyAppName is the OIDC application oauth2-proxy logs test users in through.
	OAuth2ProxyAppName = "oauth2-proxy"

	// targetTimeout is the per-delivery HTTP timeout Zitadel waits before it gives up.
	targetTimeout = 10 * time.Second
)

// targetKind is how Zitadel treats a target's response.
type targetKind int

const (
	// restAsync is fire-and-forget; the response is ignored (F1-020 webhook).
	restAsync targetKind = iota
	// restCall is synchronous; the response is applied (F1-026 groups claim).
	restCall
)

// targetSpec describes one Actions v2 target the seed owns.
type targetSpec struct {
	name       string
	endpoint   string
	secretsDir string
	keyFile    string
	kind       targetKind
}

// WebhookEvents are the Actions v2 execution conditions that trigger the tagcess reconcile
// (stack-notes: the grant and user lifecycle events tagcess cares about). An execution for each is
// idempotently installed; SetExecution replaces the target list for a condition.
var WebhookEvents = []string{
	"user.grant.added",
	"user.grant.changed",
	"user.grant.removed",
	"user.grant.deactivated",
	"user.grant.reactivated",
	"user.grant.cascade.changed",
	"user.grant.cascade.removed",
	"user.deactivated",
	"user.locked",
	"user.removed",
	"user.reactivated",
}

// EnsureWebhookTarget creates the Actions v2 event target (or reuses the existing one) and returns
// its ID. The signing key is cached at <secretsDir>/webhook-signing-key; if the target exists but
// that file is gone the target is recreated, because the key can never be read back once shown.
func EnsureWebhookTarget(ctx context.Context, c actionv2.ActionServiceClient, endpoint, secretsDir string) (string, error) {
	return ensureTarget(ctx, c, targetSpec{
		name:       WebhookTargetName,
		endpoint:   endpoint,
		secretsDir: secretsDir,
		keyFile:    WebhookSigningKeyFile,
		kind:       restAsync,
	})
}

// EnsureGroupsTarget creates the Actions v2 `rest_call` target (or reuses the existing one) that
// answers the `groups` claim during `preuserinfo` (F1-026). Like the webhook target, its signing
// key is cached once and the target is recreated if the key file is missing.
func EnsureGroupsTarget(ctx context.Context, c actionv2.ActionServiceClient, endpoint, secretsDir string) (string, error) {
	return ensureTarget(ctx, c, targetSpec{
		name:       GroupsTargetName,
		endpoint:   endpoint,
		secretsDir: secretsDir,
		keyFile:    GroupsSigningKeyFile,
		kind:       restCall,
	})
}

// ensureTarget creates the target (or reuses the existing one) and returns its ID. The signing key
// is cached at <secretsDir>/<keyFile>; if the target exists but that file is gone the target is
// recreated, because the key can never be read back once shown.
func ensureTarget(ctx context.Context, c actionv2.ActionServiceClient, spec targetSpec) (string, error) {
	keyPath := filepath.Join(spec.secretsDir, spec.keyFile)
	existing, err := findTarget(ctx, c, spec.name)
	if err != nil {
		return "", err
	}
	if existing != nil {
		if key, kerr := os.ReadFile(keyPath); kerr == nil && len(strings.TrimSpace(string(key))) > 0 { //nolint:gosec // dev-tool path from SecretsDir
			if existing.GetEndpoint() != spec.endpoint {
				ep := spec.endpoint
				update := &actionv2.UpdateTargetRequest{
					Id:       existing.GetId(),
					Endpoint: &ep,
					Timeout:  durationpb.New(targetTimeout),
				}
				if spec.kind == restCall {
					update.TargetType = &actionv2.UpdateTargetRequest_RestCall{RestCall: &actionv2.RESTCall{}}
				} else {
					update.TargetType = &actionv2.UpdateTargetRequest_RestAsync{RestAsync: &actionv2.RESTAsync{}}
				}
				if _, err := c.UpdateTarget(ctx, update); err != nil {
					return "", fmt.Errorf("seed: update %s target endpoint: %w", spec.name, err)
				}
			}
			return existing.GetId(), nil
		}
		// Key file missing: the target's key is unrecoverable, so recreate it below.
		if _, err := c.DeleteTarget(ctx, &actionv2.DeleteTargetRequest{Id: existing.GetId()}); err != nil {
			return "", fmt.Errorf("seed: delete stale %s target: %w", spec.name, err)
		}
	}
	create := &actionv2.CreateTargetRequest{
		Name:        spec.name,
		Endpoint:    spec.endpoint,
		Timeout:     durationpb.New(targetTimeout),
		PayloadType: actionv2.PayloadType_PAYLOAD_TYPE_JSON,
	}
	if spec.kind == restCall {
		create.TargetType = &actionv2.CreateTargetRequest_RestCall{RestCall: &actionv2.RESTCall{}}
	} else {
		create.TargetType = &actionv2.CreateTargetRequest_RestAsync{RestAsync: &actionv2.RESTAsync{}}
	}
	resp, err := c.CreateTarget(ctx, create)
	if err != nil {
		return "", fmt.Errorf("seed: create %s target: %w", spec.name, err)
	}
	if err := os.MkdirAll(spec.secretsDir, 0o700); err != nil {
		return "", fmt.Errorf("seed: mkdir %s: %w", spec.secretsDir, err)
	}
	if err := os.WriteFile(keyPath, []byte(resp.GetSigningKey()), 0o600); err != nil {
		return "", fmt.Errorf("seed: write %s: %w", keyPath, err)
	}
	return resp.GetId(), nil
}

// EnsureGroupsExecution points the `preuserinfo` function at the groups target. SetExecution is an
// upsert keyed by condition, so re-seeding does not duplicate the execution (F1-020 pattern).
func EnsureGroupsExecution(ctx context.Context, c actionv2.ActionServiceClient, targetID string) error {
	_, err := c.SetExecution(ctx, &actionv2.SetExecutionRequest{
		Condition: &actionv2.Condition{
			ConditionType: &actionv2.Condition_Function{
				Function: &actionv2.FunctionExecution{Name: FunctionPreuserinfo},
			},
		},
		Targets: []string{targetID},
	})
	if err != nil {
		return fmt.Errorf("seed: set execution for %s: %w", FunctionPreuserinfo, err)
	}
	return nil
}

// EnsureWebhookExecutions points every WebhookEvents condition at the target. SetExecution is
// idempotent: calling it again with the same condition replaces the target list, so re-seeding does
// not create duplicates.
func EnsureWebhookExecutions(ctx context.Context, c actionv2.ActionServiceClient, targetID string) error {
	for _, event := range WebhookEvents {
		_, err := c.SetExecution(ctx, &actionv2.SetExecutionRequest{
			Condition: &actionv2.Condition{
				ConditionType: &actionv2.Condition_Event{
					Event: &actionv2.EventExecution{
						Condition: &actionv2.EventExecution_Event{Event: event},
					},
				},
			},
			Targets: []string{targetID},
		})
		if err != nil {
			return fmt.Errorf("seed: set execution for %s: %w", event, err)
		}
	}
	return nil
}

func findTarget(ctx context.Context, c actionv2.ActionServiceClient, name string) (*actionv2.Target, error) {
	list, err := c.ListTargets(ctx, &actionv2.ListTargetsRequest{
		Filters: []*actionv2.TargetSearchFilter{
			{Filter: &actionv2.TargetSearchFilter_TargetNameFilter{
				TargetNameFilter: &actionv2.TargetNameFilter{TargetName: name, Method: filterv2.TextFilterMethod_TEXT_FILTER_METHOD_EQUALS},
			}},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("seed: list targets: %w", err)
	}
	for _, t := range list.GetTargets() {
		if t.GetName() == name {
			return t, nil
		}
	}
	return nil, nil
}

// EnsureOIDCApp creates (or reuses) an OIDC application and keeps its client id/secret in the .env
// file. Zitadel reveals a client secret only at creation, so a stale or missing value is replaced by
// generating a new secret, exactly like the Headscale app (seed.go).
func EnsureOIDCApp(ctx context.Context, c applicationv2.ApplicationServiceClient, projectID, name, redirectURI, envFile, clientIDKey, clientSecretKey string, postLogoutURIs ...string) (*OIDCAppResult, error) {
	app, err := getOrCreateOIDCApp(ctx, c, projectID, name, redirectURI, postLogoutURIs)
	if err != nil {
		return nil, err
	}
	if app.ClientSecret == "" && !envHasValue(envFile, clientIDKey, app.ClientID) {
		gen, err := c.GenerateClientSecret(ctx, &applicationv2.GenerateClientSecretRequest{
			ApplicationId: app.AppID,
			ProjectId:     projectID,
		})
		if err != nil {
			return nil, fmt.Errorf("seed: regenerate %s client secret: %w", name, err)
		}
		app.ClientSecret = gen.GetClientSecret()
	}
	updates := map[string]string{clientIDKey: app.ClientID}
	if app.ClientSecret != "" {
		updates[clientSecretKey] = app.ClientSecret
	} else if !envHasKey(envFile, clientSecretKey) {
		return nil, fmt.Errorf("seed: %s app %s has no cached client secret at %s (was .secrets wiped without the app being recreated?)", name, app.AppID, envFile)
	}
	if err := upsertEnv(envFile, updates); err != nil {
		return nil, err
	}
	return app, nil
}

func getOrCreateOIDCApp(ctx context.Context, c applicationv2.ApplicationServiceClient, projectID, name, redirectURI string, postLogoutURIs []string) (*OIDCAppResult, error) {
	list, err := c.ListApplications(ctx, &applicationv2.ListApplicationsRequest{
		Filters: []*applicationv2.ApplicationSearchFilter{
			{Filter: &applicationv2.ApplicationSearchFilter_ProjectIdFilter{
				ProjectIdFilter: &applicationv2.ProjectIDFilter{ProjectId: projectID},
			}},
			{Filter: &applicationv2.ApplicationSearchFilter_NameFilter{
				NameFilter: &applicationv2.ApplicationNameFilter{Name: name},
			}},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("seed: list applications: %w", err)
	}
	for _, a := range list.GetApplications() {
		if a.GetName() != name {
			continue
		}
		if oidc := a.GetOidcConfiguration(); oidc != nil {
			return &OIDCAppResult{AppID: a.GetApplicationId(), ClientID: oidc.GetClientId()}, nil
		}
		return &OIDCAppResult{AppID: a.GetApplicationId()}, nil
	}
	resp, err := c.CreateApplication(ctx, &applicationv2.CreateApplicationRequest{
		ProjectId: projectID,
		Name:      name,
		ApplicationType: &applicationv2.CreateApplicationRequest_OidcConfiguration{
			OidcConfiguration: &applicationv2.CreateOIDCApplicationRequest{
				RedirectUris:           []string{redirectURI},
				PostLogoutRedirectUris: postLogoutURIs,
			},
		},
	})
	if err != nil {
		if status.Code(err) == codes.AlreadyExists {
			return getOrCreateOIDCApp(ctx, c, projectID, name, redirectURI, postLogoutURIs)
		}
		return nil, fmt.Errorf("seed: create oidc app %q: %w", name, err)
	}
	oidc := resp.GetOidcConfiguration()
	return &OIDCAppResult{
		AppID:        resp.GetApplicationId(),
		ClientID:     oidc.GetClientId(),
		ClientSecret: oidc.GetClientSecret(),
	}, nil
}

// EnsureCookieSecret makes sure the oauth2-proxy cookie secret exists in the .env file, generating
// one (24 random bytes, base64 = the 32 bytes oauth2-proxy requires) on first use.
func EnsureCookieSecret(envFile string) error {
	if envHasKey(envFile, "OAUTH2_PROXY_COOKIE_SECRET") {
		return nil
	}
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return fmt.Errorf("seed: generate cookie secret: %w", err)
	}
	return upsertEnv(envFile, map[string]string{
		"OAUTH2_PROXY_COOKIE_SECRET": base64.StdEncoding.EncodeToString(raw),
	})
}

// envHasValue reports whether the env file's key is exactly value.
func envHasValue(path, key, value string) bool {
	data, err := os.ReadFile(path) //nolint:gosec // dev-tool path from seed config
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if line == key+"="+value {
			return true
		}
	}
	return false
}

// envHasKey reports whether the env file sets key to a non-empty value.
func envHasKey(path, key string) bool {
	data, err := os.ReadFile(path) //nolint:gosec // dev-tool path from seed config
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok && k == key && v != "" {
			return true
		}
	}
	return false
}

// upsertEnv merges updates into the env file (creating it 0600 if needed), preserving every other
// key. The file is a dotenv-style KEY=VALUE list.
func upsertEnv(path string, updates map[string]string) error {
	for k, v := range updates {
		if strings.ContainsAny(k, "\n=") || strings.Contains(v, "\n") {
			return fmt.Errorf("seed: refusing to write env key %q: newline or '=' in key/value", k)
		}
	}
	values := map[string]string{}
	if data, err := os.ReadFile(path); err == nil { //nolint:gosec // dev-tool path from seed config
		for _, line := range strings.Split(string(data), "\n") {
			k, v, ok := strings.Cut(line, "=")
			if !ok || k == "" {
				continue
			}
			values[k] = v
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("seed: read %s: %w", path, err)
	}
	for k, v := range updates {
		values[k] = v
	}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%s\n", k, values[k])
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		return fmt.Errorf("seed: write %s: %w", path, err)
	}
	return nil
}
