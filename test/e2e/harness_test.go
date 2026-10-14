//go:build integration

// Package e2e_test is the end-to-end suite for F1-021: the real tagcess binary (webhook receiver,
// debounced trigger, reconcile orchestrator and change pipeline) against the lab Zitadel (ADR 0014)
// and a disposable, database-mode Headscale. It assumes `make lab-up` has run (lab Zitadel + local
// compose Caddy/oauth2-proxy) and Docker is available; run it with `make e2e`.
//
// The shared compose Headscale runs in policy file mode (SetPolicy is refused), so every scenario
// that writes a policy gets its own throwaway database-mode Headscale on loopback from the shared
// test/compose/hsstack fixture. Its SQLite file is on a host bind mount so a test can patch a
// user's provider identifier directly (Headscale's CLI cannot set one; F1-005 did the same by hand).
package e2e_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pierrec/lz4/v4"
	"github.com/vmihailenco/msgpack/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	actionv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/action/v2"
	authorizationv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/authorization/v2"
	filterv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/filter/v2"
	oidcv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/oidc/v2"
	sessionv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/session/v2"
	userv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"

	"github.com/nesiler/tagcess/internal/groupsclaim"
	"github.com/nesiler/tagcess/internal/store"
	"github.com/nesiler/tagcess/test/compose/hsstack"
	"github.com/nesiler/tagcess/test/compose/seed"
)

// labEnv is the shared lab and local-compose context every test starts from.
type labEnv struct {
	composeDir string
	ep         seed.Endpoint
	pat        string
	issuer     string
	tailnetIP  string
	// webhookURL/groupsURL are what the seeded lab Actions targets point at.
	webhookURL string
	groupsURL  string
	seeded     *seed.Result
	conn       *grpc.ClientConn
	adminCtx   context.Context
	groupsOnce sync.Once
}

// setupLab resolves the lab endpoint, runs the idempotent seed with the webhook/groups targets, and
// returns the shared context. It never changes the lab other than the idempotent seed.
func setupLab(t *testing.T) *labEnv {
	t.Helper()
	composeDir, err := filepath.Abs("../compose")
	if err != nil {
		t.Fatal(err)
	}
	ep, err := seed.EndpointFromEnv(composeDir)
	if err != nil {
		t.Fatalf("resolve zitadel endpoint: %v", err)
	}
	pat, err := os.ReadFile(ep.PATFile)
	if err != nil {
		t.Fatalf("read bootstrap PAT (is `make lab-up` done?): %v", err)
	}
	ip := tailnetIPv4(t)

	ctx := context.Background()
	// The lab network is intermittently slow (a dial timeout is not a failed scenario); the seed is
	// idempotent, so it is simply tried again.
	var seeded *seed.Result
	for attempt := 1; ; attempt++ {
		seeded, err = seed.SeedZitadel(ctx, seed.Config{
			ZitadelAddr:            ep.Addr,
			ZitadelTLS:             ep.TLS,
			BootstrapPAT:           strings.TrimSpace(string(pat)),
			SecretsDir:             ep.SecretsDir,
			EnvFile:                filepath.Join(composeDir, ".env"),
			HeadscaleRedirectURI:   "http://localhost:8090/oidc/callback",
			OAuth2ProxyRedirectURI: "http://localhost:8080/oauth2/callback",
			WebhookURL:             "http://" + ip + ":9443/hook",
			GroupsURL:              "http://" + ip + ":9443/groups",
		})
		if err == nil {
			break
		}
		if attempt == 3 {
			t.Fatalf("seed: %v", err)
		}
		time.Sleep(3 * time.Second)
	}
	conn, err := grpc.NewClient(ep.Addr, ep.DialOption())
	if err != nil {
		t.Fatalf("dial zitadel: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &labEnv{
		composeDir: composeDir,
		ep:         ep,
		pat:        strings.TrimSpace(string(pat)),
		issuer:     "https://" + ep.Host,
		tailnetIP:  ip,
		webhookURL: "http://" + ip + ":9443/hook",
		groupsURL:  "http://" + ip + ":9443/groups",
		seeded:     seeded,
		conn:       conn,
		adminCtx:   metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+strings.TrimSpace(string(pat))),
	}
}

func (l *labEnv) secrets() string { return l.ep.SecretsDir }

func (l *labEnv) envFileValue(t *testing.T, key string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(l.composeDir, ".env"))
	if err != nil {
		t.Fatalf("read .env: %v", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok && k == key {
			return v
		}
	}
	t.Fatalf("%s not found in .env; was `make lab-up` run?", key)
	return ""
}

func (l *labEnv) readSecret(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(l.secrets(), name))
	if err != nil {
		t.Fatalf("read secret %s: %v", name, err)
	}
	return strings.TrimSpace(string(data))
}

// tailnetIPv4 is the address the lab Actions targets call; the webhook and groups handlers must bind
// exactly it.
func tailnetIPv4(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("tailscale", "ip", "-4").Output()
	if err != nil {
		t.Fatalf("tailscale ip -4 (the lab targets call the developer's tailnet address): %v", err)
	}
	line, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	if line == "" {
		t.Fatal("tailscale ip -4 returned no address")
	}
	return line
}

// Zitadel fixtures -----------------------------------------------------------

func (l *labEnv) createUserWithRole(t *testing.T, role string) string {
	t.Helper()
	users := userv2.NewUserServiceClient(l.conn)
	name := fmt.Sprintf("f1021-%d@tagcess.test", time.Now().UnixNano())
	// Zitadel needs a family name; a user without a role (F3-026) is named "norole".
	family := role
	if family == "" {
		family = "norole"
	}
	resp, err := users.CreateUser(l.adminCtx, &userv2.CreateUserRequest{
		OrganizationId: l.seeded.OrgID,
		Username:       &name,
		UserType: &userv2.CreateUserRequest_Human_{Human: &userv2.CreateUserRequest_Human{
			Profile: &userv2.SetHumanProfile{GivenName: "f1021", FamilyName: family},
			Email:   &userv2.SetHumanEmail{Email: name, Verification: &userv2.SetHumanEmail_IsVerified{IsVerified: true}},
		}},
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	id := resp.GetId()
	if role != "" {
		if _, err := authorizationv2.NewAuthorizationServiceClient(l.conn).CreateAuthorization(l.adminCtx, &authorizationv2.CreateAuthorizationRequest{
			UserId: id, ProjectId: l.seeded.ProjectID, OrganizationId: l.seeded.OrgID, RoleKeys: []string{role},
		}); err != nil {
			t.Fatalf("grant %s: %v", role, err)
		}
	}
	t.Cleanup(func() {
		// adminCtx carries the PAT: without it the delete is refused and the lab user (and its grant)
		// stays behind, which TestF3E2E_Cleanup caught (F3-026).
		ctx, cancel := context.WithTimeout(l.adminCtx, 30*time.Second)
		defer cancel()
		var err error
		for i := 0; i < 3; i++ {
			if _, err = userv2.NewUserServiceClient(l.conn).DeleteUser(ctx, &userv2.DeleteUserRequest{UserId: id}); err == nil || status.Code(err) == codes.NotFound {
				return
			}
			time.Sleep(time.Second)
		}
		t.Errorf("delete the lab user %s by hand: %v", id, err)
	})
	return id
}

// createHeadscaleUser makes a lab user without a role and the Headscale user an OIDC sign-in would
// have made for it: only role holders with a Headscale user are written into a group (F3-031). The
// patch restarts the throwaway Headscale, so a test makes its users before it starts tagcess.
func (l *labEnv) createHeadscaleUser(t *testing.T, hs *hsstack.Stack) string {
	t.Helper()
	id := l.createUserWithRole(t, "")
	name := "f1-" + id
	hs.CreateUser(t, name)
	hs.SetProviderID(t, name, l.zitadelProviderID(id))
	return id
}

// createUserWithHeadscaleUser is createHeadscaleUser plus the role, granted last.
func (l *labEnv) createUserWithHeadscaleUser(t *testing.T, hs *hsstack.Stack, role string) string {
	t.Helper()
	id := l.createHeadscaleUser(t, hs)
	l.grant(t, id, role)
	return id
}

// removeGrant deletes the user's authorization in the vpn project (their last role).
func (l *labEnv) removeGrant(t *testing.T, userID string) {
	t.Helper()
	authz := authorizationv2.NewAuthorizationServiceClient(l.conn)
	list, err := authz.ListAuthorizations(l.adminCtx, &authorizationv2.ListAuthorizationsRequest{
		Filters: []*authorizationv2.AuthorizationsSearchFilter{
			{Filter: &authorizationv2.AuthorizationsSearchFilter_InUserIds{InUserIds: &filterv2.InIDsFilter{Ids: []string{userID}}}},
			{Filter: &authorizationv2.AuthorizationsSearchFilter_ProjectId{ProjectId: &filterv2.IDFilter{Id: l.seeded.ProjectID}}},
		},
	})
	if err != nil {
		t.Fatalf("list authorizations for %s: %v", userID, err)
	}
	for _, a := range list.GetAuthorizations() {
		if _, err := authz.DeleteAuthorization(l.adminCtx, &authorizationv2.DeleteAuthorizationRequest{Id: a.GetId()}); err != nil {
			t.Fatalf("delete authorization %s: %v", a.GetId(), err)
		}
	}
}

func (l *labEnv) providerID(userID string) string { return l.issuer + "/" + userID + "@" }

// hasGrant reports whether the user still has an authorization in the vpn project for the role.
func (l *labEnv) hasGrant(t *testing.T, userID, role string) bool {
	t.Helper()
	list, err := authorizationv2.NewAuthorizationServiceClient(l.conn).ListAuthorizations(l.adminCtx, &authorizationv2.ListAuthorizationsRequest{
		Filters: []*authorizationv2.AuthorizationsSearchFilter{
			{Filter: &authorizationv2.AuthorizationsSearchFilter_InUserIds{InUserIds: &filterv2.InIDsFilter{Ids: []string{userID}}}},
			{Filter: &authorizationv2.AuthorizationsSearchFilter_ProjectId{ProjectId: &filterv2.IDFilter{Id: l.seeded.ProjectID}}},
		},
	})
	if err != nil {
		t.Fatalf("list authorizations for %s: %v", userID, err)
	}
	for _, a := range list.GetAuthorizations() {
		for _, r := range a.GetRoles() {
			if r.GetKey() == role {
				return true
			}
		}
	}
	return false
}

// zitadelProviderID is the raw OIDC provider identifier Headscale stores (no trailing "@", ADR 0002).
func (l *labEnv) zitadelProviderID(userID string) string { return l.issuer + "/" + userID }

func (l *labEnv) actions() actionv2.ActionServiceClient {
	return actionv2.NewActionServiceClient(l.conn)
}

// setWebhookEndpoint re-points the seeded webhook target, so a test can make the webhook delivery
// fail while the periodic reconcile stays healthy (AC3). It returns an idempotent restore function
// that re-points the target back and reports a persistent failure instead of silently leaving the
// shared lab pointing at a dead address.
func (l *labEnv) setWebhookEndpoint(t *testing.T, endpoint string) func() {
	t.Helper()
	actions := l.actions()
	list, err := actions.ListTargets(l.adminCtx, &actionv2.ListTargetsRequest{})
	if err != nil {
		t.Fatalf("list targets: %v", err)
	}
	for _, tg := range list.GetTargets() {
		if tg.GetName() != seed.WebhookTargetName {
			continue
		}
		original := tg.GetEndpoint()
		id := tg.GetId()
		if _, err := actions.UpdateTarget(l.adminCtx, &actionv2.UpdateTargetRequest{
			Id:         id,
			Endpoint:   &endpoint,
			TargetType: &actionv2.UpdateTargetRequest_RestAsync{RestAsync: &actionv2.RESTAsync{}},
		}); err != nil {
			t.Fatalf("re-point webhook target: %v", err)
		}
		restored := false
		return func() {
			if restored {
				return
			}
			restored = true
			// Derive from adminCtx so the PAT metadata is preserved.
			ctx, cancel := context.WithTimeout(l.adminCtx, 15*time.Second)
			defer cancel()
			var lastErr error
			for i := 0; i < 5; i++ {
				orig := original
				if _, lastErr = actions.UpdateTarget(ctx, &actionv2.UpdateTargetRequest{
					Id: id, Endpoint: &orig,
					TargetType: &actionv2.UpdateTargetRequest_RestAsync{RestAsync: &actionv2.RESTAsync{}},
				}); lastErr == nil {
					return
				}
				time.Sleep(time.Second)
			}
			t.Errorf("failed to restore the webhook target endpoint to %s: %v", original, lastErr)
		}
	}
	t.Fatal("seeded webhook target not found")
	return nil
}

// The real tagcess binary ----------------------------------------------------

var (
	buildOnce sync.Once
	binPath   string
	buildErr  error
)

func tagcessBinary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "tagcess-e2e-bin")
		if err != nil {
			buildErr = err
			return
		}
		binPath = filepath.Join(dir, "tagcess")
		cmd := exec.Command("go", "build", "-o", binPath, "./cmd/tagcess")
		cmd.Dir = repoRoot()
		if out, err := cmd.CombinedOutput(); err != nil {
			buildErr = fmt.Errorf("go build tagcess: %v: %s", err, out)
		}
	})
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	return binPath
}

func repoRoot() string {
	dir, _ := filepath.Abs("../..")
	return dir
}

// tagcessConfig is what a test varies between runs.
type tagcessConfig struct {
	headscaleAddr string
	issuer        string
	keyFile       string // service user key (tampered for AC4)
	interval      time.Duration
	// site wires the F2 site layer to real artifacts; nil keeps the F1 scenarios on harmless
	// defaults (a dead Caddy admin address, throwaway files in the data directory, no seed).
	site *siteWiring
	// dataDir reuses an earlier run's data directory (F3-030: a restart with another Zitadel key
	// keeps the store, so the revisions and the unresolved state survive); empty makes a new one.
	dataDir string
	// hostRequestsDir/hostResultsDir enable the H-07 host helper channel (F3b-022) by pointing
	// hostapply at the host lab's bind-mounted directories; empty leaves it off (F1/F3 default).
	hostRequestsDir string
	hostResultsDir  string
	// hookListen overrides the webhook listen address (default <tailnet>:9443). F3b-023 keeps the
	// F1-026 groups receiver on :9443 for its logins, so the binary's webhook listens elsewhere.
	hookListen string
	// settings are extra settings rows written next to dry_run before the binary opens the store
	// (the F4 scenarios shorten the inventory interval this way: the first read round runs before the
	// profile is saved, so it would otherwise wait the 5-minute default).
	settings map[string]string
}

// siteWiring is what an F2 scenario points the site pipeline at (config sections caddy, dns and
// sites). Every field is optional; a zero value selects the F1 default.
type siteWiring struct {
	caddyAdmin  string // Caddy admin API base URL
	caddyfile   string // the Caddyfile a restart would read
	dnsRecords  string // the MagicDNS extra-records file Headscale watches
	dnsResolver string // "host:port" asked about changed names
	seedFile    string // first-import seed (G-01)
	vpnAddress  string // sites.vpn_address; the Caddy gate probe dials it (F4-040); default e2eVPNAddress
}

// The site settings every scenario runs with. The hosts of the first-import fixture live under
// the two example domains, so the allowlists carry them; nothing here reaches production.
const (
	e2eTagcessHost = "tagcess.example.com"
	e2eVPNAddress  = "100.64.0.4"
	e2eACMEEmail   = "admin@example.invalid" // the placeholder of the fixture's global block
)

var (
	e2eCertificates = []string{"example.com", "internal.example.org"}
	// e2eZitadelSources is the internal source list the fixture's zitadel block lists after the
	// tailnet range (placeholders, F2-007).
	e2eZitadelSources = []string{
		"198.51.100.0/24", "127.0.0.1/32", "::1/128",
		"192.0.2.10/32", "2001:db8:10::/64", "192.0.2.20/32", "2001:db8:20::/64",
	}
)

// tagcessProc is a running tagcess binary with its own data directory.
type tagcessProc struct {
	dataDir string
	uiSock  string
	cmd     *exec.Cmd
	stderr  *bytes.Buffer
	done    chan struct{}
	db      *sql.DB
}

// startTagcess pre-creates the store (dry run off, so applies happen), writes the config and starts
// the real binary. hook.listen is the tailnet address the seeded webhook target calls.
func startTagcess(t *testing.T, l *labEnv, cfg tagcessConfig) *tagcessProc {
	t.Helper()
	if cfg.interval <= 0 {
		cfg.interval = 5 * time.Minute
	}
	// A short path: a unix socket path is limited to ~104 bytes on macOS and t.TempDir embeds the
	// (long) test name.
	dataDir := cfg.dataDir
	if dataDir == "" {
		var err error
		if dataDir, err = os.MkdirTemp("/tmp", "tagcess-e2e-"); err != nil {
			t.Fatalf("temp dir: %v", err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dataDir) })
	} else {
		// A stopped binary may leave its socket behind; the new one binds a fresh one.
		_ = os.Remove(filepath.Join(dataDir, "ui.sock"))
	}
	// Create the schema and turn dry run off before the binary opens it (Y-06.2 seeds it on).
	st, err := store.Open(context.Background(), filepath.Join(dataDir, "tagcess.db"))
	if err != nil {
		t.Fatalf("open tagcess store: %v", err)
	}
	if _, err := st.DB().Exec(`UPDATE settings SET value = 'false' WHERE key = 'dry_run'`); err != nil {
		t.Fatalf("turn off dry run: %v", err)
	}
	for k, v := range cfg.settings {
		if _, err := st.DB().Exec(`INSERT INTO settings(key, value, updated_at) VALUES(?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, k, v); err != nil {
			t.Fatalf("seed setting %s: %v", k, err)
		}
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close tagcess store: %v", err)
	}

	wiring := siteWiring{}
	if cfg.site != nil {
		wiring = *cfg.site
	}
	if wiring.caddyAdmin == "" {
		wiring.caddyAdmin = "http://127.0.0.1:1" // nothing listens: F1 scenarios never change a site
	}
	if wiring.caddyfile == "" {
		wiring.caddyfile = filepath.Join(dataDir, "Caddyfile")
	}
	if wiring.dnsRecords == "" {
		wiring.dnsRecords = filepath.Join(dataDir, "extra-records.json")
	}
	vpnAddress := wiring.vpnAddress
	if vpnAddress == "" {
		vpnAddress = e2eVPNAddress
	}
	sitesExtra := ""
	if wiring.seedFile != "" {
		sitesExtra = fmt.Sprintf("  seed_file: %s\n", wiring.seedFile)
	}
	resolverLine := ""
	if wiring.dnsResolver != "" {
		resolverLine = fmt.Sprintf("  resolver: %s\n", wiring.dnsResolver)
	}
	hostapplyExtra := ""
	if cfg.hostRequestsDir != "" && cfg.hostResultsDir != "" {
		hostapplyExtra = fmt.Sprintf("hostapply:\n  requests_dir: %s\n  results_dir: %s\n", cfg.hostRequestsDir, cfg.hostResultsDir)
	}
	hookListen := cfg.hookListen
	if hookListen == "" {
		hookListen = l.tailnetIP + ":9443"
	}

	configPath := filepath.Join(dataDir, "config.yaml")
	conf := fmt.Sprintf(`data_dir: %s
ui:
  socket: %s
  socket_group: %s
hook:
  listen: %s
  signing_key_file: %s
headscale:
  socket: %s
zitadel:
  issuer: %s
  project_id: %s
  key_file: %s
  oauth2_proxy_app: %s
caddy:
  admin_url: %s
  caddyfile_path: %s
dns:
  records_path: %s
%s%ssync:
  interval: %s
sites:
  allowed_domains: [example.com, internal.example.org, example.net, k8s-lab.test]
  allowed_targets: [100.64.0.5]
  zitadel_internal_sources: [%s]
  acme_email: %s
  certificates: [%s]
  vpn_address: %s
  tagcess_host: %s
%s`, dataDir, filepath.Join(dataDir, "ui.sock"), currentGroup(t), hookListen,
		filepath.Join(l.secrets(), seed.WebhookSigningKeyFile), cfg.headscaleAddr,
		cfg.issuer, l.seeded.ProjectID, cfg.keyFile, seed.OAuth2ProxyAppName,
		wiring.caddyAdmin, wiring.caddyfile, wiring.dnsRecords, resolverLine, hostapplyExtra, cfg.interval,
		strings.Join(quoteAll(e2eZitadelSources), ", "), e2eACMEEmail,
		strings.Join(e2eCertificates, ", "), vpnAddress, e2eTagcessHost, sitesExtra)
	if err := os.WriteFile(configPath, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}

	proc := &tagcessProc{dataDir: dataDir, uiSock: filepath.Join(dataDir, "ui.sock"), stderr: &bytes.Buffer{}, done: make(chan struct{})}
	cmd := exec.Command(tagcessBinary(t), "-config", configPath)
	cmd.Stderr = proc.stderr
	proc.cmd = cmd
	if err := cmd.Start(); err != nil {
		t.Fatalf("start tagcess: %v", err)
	}
	go func() { _ = cmd.Wait(); close(proc.done) }()
	t.Cleanup(func() {
		proc.stop(t)
		if t.Failed() {
			proc.dumpStore(t)
			t.Logf("tagcess stderr:\n%s", proc.stderr.String())
		}
		if proc.db != nil {
			_ = proc.db.Close()
		}
	})

	waitForListener(t, hookListen, proc)
	waitForUISocket(t, proc)
	return proc
}

// waitForUISocket waits until the UI unix socket accepts connections: the binary starts the hook
// and UI listeners in separate goroutines, so the hook port can be open before the socket exists.
func waitForUISocket(t *testing.T, proc *tagcessProc) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("unix", proc.uiSock, 500*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		select {
		case <-proc.done:
			t.Fatalf("tagcess exited before the UI socket %s was ready: %s", proc.uiSock, proc.stderr.String())
		default:
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("tagcess UI socket %s was not ready: %s", proc.uiSock, proc.stderr.String())
}

func (p *tagcessProc) stop(t *testing.T) {
	t.Helper()
	if p.cmd.Process == nil {
		return
	}
	_ = p.cmd.Process.Signal(os.Interrupt)
	select {
	case <-p.done:
	case <-time.After(15 * time.Second):
		_ = p.cmd.Process.Kill()
		<-p.done
	}
}

// storeDB returns the binary's SQLite store connection for assertions; startTagcess closes it.
func (p *tagcessProc) storeDB(t *testing.T) *sql.DB {
	t.Helper()
	if p.db != nil {
		return p.db
	}
	db, err := sql.Open("sqlite", filepath.Join(p.dataDir, "tagcess.db"))
	if err != nil {
		t.Fatalf("open tagcess store: %v", err)
	}
	p.db = db
	return db
}

// queryInt runs a single-int query against the store.
func (p *tagcessProc) queryInt(t *testing.T, query string, args ...any) int {
	t.Helper()
	var n int
	if err := p.storeDB(t).QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	return n
}

// pendingGroupsAfter polls for the first change whose status is pending_approval and whose id is
// greater than afterID, and returns the groups of the policy it proposes. Tying the pending state to
// a change newer than a recorded id keeps an earlier pending or applied change from satisfying a
// "held for approval" assertion (review F1-021, AC6).
func (p *tagcessProc) pendingGroupsAfter(t *testing.T, afterID int64) map[string][]string {
	t.Helper()
	var (
		id    int64
		after string
	)
	if err := poll(t, 25*time.Second, func() (bool, error) {
		err := p.storeDB(t).QueryRow(
			`SELECT id, after_summary FROM changes WHERE status = 'pending_approval' AND id > ? ORDER BY id LIMIT 1`,
			afterID,
		).Scan(&id, &after)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return false, nil
		case err != nil:
			return false, err
		default:
			return true, nil
		}
	}); err != nil {
		t.Fatalf("no pending_approval change newer than %d: %v", afterID, err)
	}
	var proposal struct {
		Target string `json:"target"`
	}
	if err := json.Unmarshal([]byte(after), &proposal); err != nil {
		t.Fatalf("parse pending change %d after_summary: %v", id, err)
	}
	if proposal.Target == "" {
		t.Fatalf("pending change %d proposes no target policy", id)
	}
	return hsstack.ParsePolicyGroups(t, proposal.Target)
}

// dumpStore logs the reconcile bookkeeping of a failed run so a flaky scenario can be diagnosed.
func (p *tagcessProc) dumpStore(t *testing.T) {
	t.Helper()
	db := p.storeDB(t)
	for _, q := range []string{
		`SELECT started_at || ' | ' || trigger || ' | ' || result || ' | ' || diff_summary FROM sync_runs ORDER BY started_at`,
		`SELECT kind || ' | ' || source || ' | ' || COALESCE(resolved_at, 'open') FROM alerts`,
		`SELECT status || ' | ' || actor || ' | ' || error FROM changes`,
	} {
		rows, err := db.Query(q)
		if err != nil {
			t.Logf("dump %q: %v", q, err)
			continue
		}
		for rows.Next() {
			var line string
			if err := rows.Scan(&line); err != nil {
				t.Logf("scan: %v", err)
				break
			}
			t.Logf("store: %s", line)
		}
		_ = rows.Close()
	}
}

func waitForListener(t *testing.T, addr string, proc *tagcessProc) {
	t.Helper()
	// The binary reads Zitadel before it listens; on a slow lab network that takes a while.
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		select {
		case <-proc.done:
			t.Fatalf("tagcess exited before listening on %s: %s", addr, proc.stderr.String())
		default:
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("tagcess did not listen on %s: %s", addr, proc.stderr.String())
}

func quoteAll(in []string) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = strconv.Quote(v)
	}
	return out
}

// currentGroup is the unix group the UI socket is assigned to; it must exist on the host.
func currentGroup(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("id", "-gn").Output()
	if err != nil {
		t.Fatalf("id -gn: %v", err)
	}
	return strings.TrimSpace(string(out))
}

// tamperedKeyFile writes a service-account key with a freshly generated key whose keyId/userId are
// not registered in Zitadel, so OIDC discovery still succeeds (tagcess starts) but every API call
// fails at token exchange (AC4). A new key is generated so the real service key is never copied.
func (l *labEnv) tamperedKeyFile(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	content := map[string]any{
		"type":   "serviceaccount",
		"keyId":  "00000000000000000000000000000000",
		"key":    string(pemKey),
		"userId": "00000000000000000000000000000000",
	}
	out, err := json.Marshal(content)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "zitadel-key.json")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// poll waits until cond returns true or the timeout elapses; it returns the last error.
func poll(t *testing.T, timeout time.Duration, cond func() (bool, error)) error {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last error
	for {
		ok, err := cond()
		if ok {
			return nil
		}
		last = err
		if time.Now().After(deadline) {
			if last == nil {
				last = errors.New("condition not met before timeout")
			}
			return last
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// Login through the lab Zitadel ----------------------------------------------

// ensureGroupsHandler serves the real groupsclaim handler at the seeded groups target's address
// once per lab, so a real login fills the oauth2-proxy session's `groups` claim (F1-026). It is
// bound exactly to the address the target calls and closed when the test ends.
func (l *labEnv) ensureGroupsHandler(t *testing.T) {
	t.Helper()
	l.groupsOnce.Do(func() { startGroupsHandler(t, l) })
}

func startGroupsHandler(t *testing.T, l *labEnv) {
	t.Helper()
	key := l.readSecret(t, seed.GroupsSigningKeyFile)
	handler, err := groupsclaim.New(groupsclaim.Config{SigningKey: []byte(key), ProjectID: l.seeded.ProjectID})
	if err != nil {
		t.Fatalf("build groupsclaim handler: %v", err)
	}
	u, err := url.Parse(l.groupsURL)
	if err != nil || u.Host == "" {
		t.Fatalf("groups URL %q: %v", l.groupsURL, err)
	}
	ln := listenWithRetry(t, u.Host)
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
}

func listenWithRetry(t *testing.T, addr string) net.Listener {
	t.Helper()
	var lastErr error
	for i := 0; i < 40; i++ {
		ln, err := net.Listen("tcp", addr)
		if err == nil {
			return ln
		}
		lastErr = err
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("listen on %s: %v", addr, lastErr)
	return nil
}

// signLoginClientJWT signs the JWT the Zitadel login v2 client (system user "login-client",
// IAM_LOGIN_CLIENT) uses to call the session and OIDC APIs. The private key is the lab chart's
// `zitadel-login-service-key` tls.key, copied to the gitignored secrets dir by `make lab-up`.
func signLoginClientJWT(t *testing.T, keyPath, issuer string) string {
	t.Helper()
	data, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read login-client key (re-run `make lab-up`): %v", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("login-client key is not PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse login-client key: %v", err)
	}
	b64 := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	header := b64(map[string]any{"alg": "RS256", "typ": "JWT", "kid": "login-client"})
	now := time.Now()
	claims := b64(map[string]any{"iss": "login-client", "sub": "login-client", "aud": issuer, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()})
	signing := header + "." + claims
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// loginThroughOAuth2Proxy completes a real authorization-code login for a lab user through the
// local compose Caddy/oauth2-proxy, using Zitadel's session + OIDC v2 APIs (the same calls the
// login v2 UI makes). It returns an HTTP client whose cookie jar holds the oauth2-proxy session.
func loginThroughOAuth2Proxy(t *testing.T, l *labEnv, loginName string) *http.Client {
	t.Helper()
	l.ensureGroupsHandler(t)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	get := func(u string) *http.Response {
		t.Helper()
		resp, err := client.Get(u)
		if err != nil {
			// Never include the URL: the callback URL carries the authorization code.
			t.Fatalf("oauth2-proxy request failed: %v", err)
		}
		_ = resp.Body.Close()
		return resp
	}
	// Caddy -> oauth2-proxy /oauth2/start -> Zitadel authorize -> login v2 auth request.
	start := get("http://localhost:8080/").Header.Get("Location")
	authorize := get("http://localhost:8080" + start).Header.Get("Location")
	loginURL := get(authorize).Header.Get("Location")
	lu, err := url.Parse(loginURL)
	if err != nil {
		t.Fatalf("parse login URL %q: %v", loginURL, err)
	}
	authRequest := lu.Query().Get("authRequest")
	if authRequest == "" {
		t.Fatalf("no authRequest in %q", loginURL)
	}

	jwt := signLoginClientJWT(t, filepath.Join(l.secrets(), loginClientKeyFile), l.issuer)
	ctx := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+jwt)

	session, err := sessionv2.NewSessionServiceClient(l.conn).CreateSession(ctx, &sessionv2.CreateSessionRequest{
		Checks: &sessionv2.Checks{
			User:     &sessionv2.CheckUser{Search: &sessionv2.CheckUser_LoginName{LoginName: loginName}},
			Password: &sessionv2.CheckPassword{Password: seed.TestUserPassword},
		},
	})
	if err != nil {
		t.Fatalf("CreateSession(%s): %v", loginName, err)
	}
	callback, err := oidcv2.NewOIDCServiceClient(l.conn).CreateCallback(ctx, &oidcv2.CreateCallbackRequest{
		AuthRequestId: authRequest,
		CallbackKind:  &oidcv2.CreateCallbackRequest_Session{Session: &oidcv2.Session{SessionId: session.GetSessionId(), SessionToken: session.GetSessionToken()}},
	})
	if err != nil {
		t.Fatalf("CreateCallback: %v", err)
	}
	if !strings.Contains(callback.GetCallbackUrl(), "code=") {
		t.Fatalf("oauth2-proxy callback URL carries no authorization code")
	}
	// Drive oauth2-proxy's callback: it exchanges the code and stores its session cookie.
	if resp := get(callback.GetCallbackUrl()); resp.StatusCode != http.StatusFound {
		t.Fatalf("oauth2-proxy callback status = %d, want 302", resp.StatusCode)
	}
	return client
}

// loginClientKeyFile is the gitignored copy of the lab login client's key (make lab-up).
const loginClientKeyFile = "login-client-key.pem"

// Forged oauth2-proxy session (AC5): reproduces oauth2-proxy v7's cookie-store session cookie so a
// test can act as a user with a chosen groups claim without the interactive browser login. This is
// the same forge the F1-026 integration test uses.
const oauth2ProxyCookieName = "tagcess_test"

type oauth2Session struct {
	Email             string   `msgpack:"e,omitempty"`
	User              string   `msgpack:"u,omitempty"`
	Groups            []string `msgpack:"g,omitempty"`
	PreferredUsername string   `msgpack:"pu,omitempty"`
}

func forgeSessionCookie(t *testing.T, secret string, groups []string) string {
	t.Helper()
	now := time.Now()
	packed, err := msgpack.Marshal(oauth2Session{
		Email: "f1021@tagcess.test", User: "f1021", Groups: groups, PreferredUsername: "f1021",
	})
	if err != nil {
		t.Fatalf("msgpack session: %v", err)
	}
	block, err := aes.NewCipher(secretBytes(secret))
	if err != nil {
		t.Fatalf("cookie secret is not a usable AES key: %v", err)
	}
	compressed := lz4Compress(t, packed)
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		t.Fatal(err)
	}
	ciphertext := make([]byte, aes.BlockSize+len(compressed))
	copy(ciphertext, iv)
	cipher.NewCFBEncrypter(block, iv).XORKeyStream(ciphertext[aes.BlockSize:], compressed)
	encoded := base64.URLEncoding.EncodeToString(ciphertext)
	ts := strconv.FormatInt(now.Unix(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(oauth2ProxyCookieName))
	mac.Write([]byte(encoded))
	mac.Write([]byte(ts))
	sig := base64.URLEncoding.EncodeToString(mac.Sum(nil))
	return encoded + "|" + ts + "|" + sig
}

func secretBytes(secret string) []byte {
	if b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(secret, "=")); err == nil {
		for _, n := range []int{16, 24, 32} {
			if len(b) == n {
				return b
			}
		}
	}
	return []byte(secret)
}

func lz4Compress(t *testing.T, payload []byte) []byte {
	t.Helper()
	buf := new(bytes.Buffer)
	zw := lz4.NewWriter(nil)
	zw.Apply(lz4.BlockSizeOption(lz4.BlockSize(65536)), lz4.CompressionLevelOption(lz4.Fast))
	zw.Reset(buf)
	if _, err := zw.Write(payload); err != nil {
		t.Fatalf("lz4 write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("lz4 close: %v", err)
	}
	return buf.Bytes()
}
