//go:build integration

// The F3 end-to-end stack (F3-026, reused by F3-030): the real tagcess binary driven through its
// web interface on the unix socket, against a disposable database-mode Headscale (hsstack) and the
// lab Zitadel. Lab users are real (created and deleted through the lab's API) and each of them is
// linked to a Headscale user the way an OIDC sign-in would (provider identifier patched into the
// disposable database), so the reconcile sees the same users the interface shows.
//
// Everything a scenario creates is removed when it ends: the Headscale containers and the
// binary's data directory by the fixtures, the lab users and their grants by labEnv. Scenarios
// that need the F2 site layer (the manual DNS records) use newF2Stack instead; its Caddy box and
// first import are what the DNS pipeline's drift gate needs.
package e2e_test

import (
	"context"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	authorizationv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/authorization/v2"
	userv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"

	"github.com/nesiler/tagcess/internal/headscale"
	"github.com/nesiler/tagcess/internal/headscale/admin"
	"github.com/nesiler/tagcess/test/compose/hsstack"
)

// The tags of the F3 fixture policy. tag:vpn-server and tag:k8s are the default protected server
// tags (R2 karar 13); tag:shared is the shared-device tag a device or a pre-auth key may carry.
const (
	f3ServerTag = "tag:vpn-server"
	f3SharedTag = "tag:shared"
)

// f3Policy is the policy every F3 scenario starts from: the three tags are owned by devops, so
// the interface accepts them; the groups are filled by the reconcile.
const f3Policy = `{
  "tagOwners": {
    "tag:vpn-server": ["group:devops"],
    "tag:k8s": ["group:devops"],
    "tag:shared": ["group:devops"]
  },
  "groups": {"group:devops": []},
  "acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
}`

// f3Stack is one running F3 scenario.
type f3Stack struct {
	t     *testing.T
	root  *testing.T // the scenario's own test: what outlives a section owns the fixtures
	l     *labEnv
	hs    *hsstack.Stack
	adm   *admin.AdminClient
	proc  *tagcessProc
	ui    *uiClient
	proxy *hsProxy // set when the scenario asked for one (f3Options.proxy)
	cfg   tagcessConfig
}

// f3Options varies a scenario.
type f3Options struct {
	interval time.Duration // sync interval of the binary; default long (the tests trigger by hand)
	// prepare runs after the policy is seeded and before tagcess starts: users, nodes and route
	// advertisements are cheaper to set up while no reconcile is running.
	prepare func(s *f3Stack)
	// policy replaces the fixture policy the Headscale starts from (F3-030's rich document).
	policy string
	// proxy puts a pass-through gRPC proxy between the binary and Headscale, so a scenario can make
	// a policy write end uncertain (hsProxy.dieAfterNextSetPolicy).
	proxy bool
}

// newF3Stack builds the stack. The binary starts last, so its first reconcile already sees the
// users and nodes the scenario prepared.
func newF3Stack(t *testing.T, opts f3Options) *f3Stack {
	t.Helper()
	if opts.interval <= 0 {
		opts.interval = 5 * time.Minute
	}
	l := setupLab(t)
	hs := hsstack.Start(t)
	seed := f3Policy
	if opts.policy != "" {
		seed = opts.policy
	}
	if _, err := hs.Client().SetPolicy(context.Background(), seed); err != nil {
		t.Fatalf("seed the F3 fixture policy: %v", err)
	}
	adm, err := admin.NewAdmin(headscale.Config{Target: hs.GRPCAddr(), Timeout: 15 * time.Second})
	if err != nil {
		t.Fatalf("admin client: %v", err)
	}
	t.Cleanup(func() { _ = adm.Close() })
	s := &f3Stack{t: t, root: t, l: l, hs: hs, adm: adm}
	if opts.prepare != nil {
		opts.prepare(s)
	}
	s.cfg = tagcessConfig{
		headscaleAddr: hs.GRPCAddr(),
		issuer:        l.issuer,
		keyFile:       filepath.Join(l.secrets(), "zitadel-key.json"),
		interval:      opts.interval,
	}
	if opts.proxy {
		s.proxy = startHSProxy(t, hs.GRPCAddr())
		s.cfg.headscaleAddr = s.proxy.addr
	}
	s.proc = startTagcess(t, l, s.cfg)
	s.ui = newUIClient(t, s.proc.uiSock)
	return s
}

// restart stops the binary and starts it again on the same data directory with the given Zitadel
// key file: the broken one is how a scenario takes Zitadel away (F1-021's method), the real one is
// how it comes back. The store, so the revisions and the unresolved state, stays.
func (s *f3Stack) restart(keyFile string) {
	s.t.Helper()
	s.proc.stop(s.t)
	s.cfg.keyFile, s.cfg.dataDir = keyFile, s.proc.dataDir
	// The binary belongs to the scenario, not to the section that restarted it: a section's own
	// clean-up would stop it when the section ends.
	s.proc = startTagcess(s.root, s.l, s.cfg)
	s.ui = newUIClient(s.t, s.proc.uiSock)
}

// f3User is a lab user together with the Headscale user it is linked to.
type f3User struct {
	zitadelID string
	hsName    string
	hsID      uint64
}

// user creates a lab user (with role, or none when role is empty) and the Headscale user an OIDC
// sign-in would have made for it. The patch restarts the disposable Headscale, so prepare hooks
// create their users first and their nodes after.
func (s *f3Stack) user(name, role string) f3User {
	s.t.Helper()
	zid := s.l.createUserWithRole(s.t, role)
	hsName := "f3026-" + name
	id := s.hs.CreateUser(s.t, hsName)
	s.hs.SetProviderID(s.t, hsName, s.l.zitadelProviderID(zid))
	return f3User{zitadelID: zid, hsName: hsName, hsID: id}
}

// padHolders makes n more holders of the role, each with a Headscale user. Only holders with a
// Headscale user are in a group (F3-031), so a test that takes one user's role away needs a base
// for that to be a fraction of the group (not 100%, which the protection threshold holds for approval).
func (s *f3Stack) padHolders(role string, n int) {
	s.t.Helper()
	for i := range n {
		s.user(fmt.Sprintf("pad%d", i), role)
	}
}

// grant gives a lab user a role again (a role loss is l.removeGrant).
func (l *labEnv) grant(t *testing.T, userID, role string) {
	t.Helper()
	if _, err := authorizationv2.NewAuthorizationServiceClient(l.conn).CreateAuthorization(l.adminCtx, &authorizationv2.CreateAuthorizationRequest{
		UserId: userID, ProjectId: l.seeded.ProjectID, OrganizationId: l.seeded.OrgID, RoleKeys: []string{role},
	}); err != nil {
		t.Fatalf("grant %s to %s: %v", role, userID, err)
	}
}

// deactivate makes a lab user passive (a disabled account, Y-04's other trigger).
func (l *labEnv) deactivate(t *testing.T, userID string) {
	t.Helper()
	if _, err := userv2.NewUserServiceClient(l.conn).DeactivateUser(l.adminCtx, &userv2.DeactivateUserRequest{UserId: userID}); err != nil {
		t.Fatalf("deactivate %s: %v", userID, err)
	}
}

// node reads one node from Headscale; ok is false when it is gone.
func (s *f3Stack) node(id uint64) (admin.AdminNode, bool) {
	s.t.Helper()
	nodes, err := s.adm.ListNodes(context.Background())
	if err != nil {
		s.t.Fatalf("list nodes: %v", err)
	}
	for _, n := range nodes {
		if n.ID == id {
			return n, true
		}
	}
	return admin.AdminNode{}, false
}

func (s *f3Stack) mustNode(id uint64) admin.AdminNode {
	s.t.Helper()
	n, ok := s.node(id)
	if !ok {
		s.t.Fatalf("node %d is gone", id)
	}
	return n
}

// expired reports whether the node's expiry lies in the past.
func expired(n admin.AdminNode) bool { return n.Expiry != nil && n.Expiry.Before(time.Now()) }

// preAuthKeys lists the pre-auth keys of the disposable Headscale.
func (s *f3Stack) preAuthKeys() []admin.PreAuthKey {
	s.t.Helper()
	keys, err := s.adm.ListPreAuthKeys(context.Background())
	if err != nil {
		s.t.Fatalf("list pre-auth keys: %v", err)
	}
	return keys
}

// keyExpired reports whether the key is gone or no longer valid.
func (s *f3Stack) keyExpired(id uint64) bool {
	for _, k := range s.preAuthKeys() {
		if k.ID == id {
			return k.Expiration != nil && !k.Expiration.After(time.Now())
		}
	}
	return true
}

// triggerSync asks for a manual reconcile through the interface and waits until a run that started
// after the request has been recorded.
func (s *f3Stack) triggerSync() {
	s.t.Helper()
	before := s.proc.queryInt(s.t, `SELECT COALESCE(MAX(id), 0) FROM sync_runs`)
	if code, body := s.ui.post("/sync/trigger", nil); code != http.StatusSeeOther {
		s.t.Fatalf("POST /sync/trigger: status %d: %s", code, excerpt(body))
	}
	if err := poll(s.t, 30*time.Second, func() (bool, error) {
		return s.proc.queryInt(s.t, `SELECT COALESCE(MAX(id), 0) FROM sync_runs`) > before, nil
	}); err != nil {
		s.t.Fatalf("the manual reconcile never recorded a run: %v", err)
	}
}

// waitMember waits until the reconcile has put the lab user into the role's policy group, which
// is the proof that a reconcile saw the user's current grants.
func (s *f3Stack) waitMember(role, zitadelID string, want bool) {
	s.t.Helper()
	member := s.l.providerID(zitadelID)
	if err := poll(s.t, 40*time.Second, func() (bool, error) {
		s.triggerSyncQuiet()
		return containsMember(s.hs.PolicyGroups(s.t)["group:"+role], member) == want, nil
	}); err != nil {
		s.t.Fatalf("group:%s membership of %s never became %v: %v", role, zitadelID, want, err)
	}
}

// triggerSyncQuiet requests a reconcile without waiting for it (the caller polls the effect).
func (s *f3Stack) triggerSyncQuiet() {
	s.t.Helper()
	if code, body := s.ui.post("/sync/trigger", nil); code != http.StatusSeeOther {
		s.t.Fatalf("POST /sync/trigger: status %d: %s", code, excerpt(body))
	}
	time.Sleep(1500 * time.Millisecond)
}

// The interface -------------------------------------------------------------------------------

// formOf is a rendered page's hidden inputs, the way the browser would post them back.
type formOf struct{ body string }

func (f formOf) value(name string) string { return inputValue(f.body, name) }

// getOK reads a page that must render.
func (c *uiClient) getOK(path string) string {
	c.t.Helper()
	code, body := c.get(path)
	if code != http.StatusOK {
		c.t.Fatalf("GET %s: status %d: %s", path, code, excerpt(body))
	}
	return body
}

// uiRaw sends one request over the UI socket with exactly the given identity headers and no CSRF
// help, so a test can present any identity (or none) and see how the interface answers.
func uiRaw(t *testing.T, sock, method, path string, header map[string]string, form url.Values) (int, string) {
	t.Helper()
	hc := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sock)
			},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, "http://tagcess"+path, body)
	if err != nil {
		t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("%s %s: read body: %v", method, path, err)
	}
	return resp.StatusCode, string(out)
}

// Secrets --------------------------------------------------------------------------------------

var preAuthSecretRE = regexp.MustCompile(`hskey-auth-[A-Za-z0-9_-]+`)

// secretOf returns the one key secret a result page shows.
func secretOf(t *testing.T, body string) string {
	t.Helper()
	found := slices.Compact(preAuthSecretRE.FindAllString(body, -1))
	if len(found) != 1 {
		t.Fatalf("the result page shows %d key secrets, want exactly 1: %s", len(found), excerpt(body))
	}
	return found[0]
}

// assertNoSecrets fails when any of the secrets (or any full pre-auth key) is in the binary's
// persisted state or its logs. It stops the binary first: the SQLite file is then complete and
// the stderr buffer is no longer being written.
func (s *f3Stack) assertNoSecrets(secrets ...string) {
	s.t.Helper()
	s.proc.stop(s.t)
	var where []string
	err := filepath.Walk(s.proc.dataDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || info.Mode()&os.ModeSocket != 0 {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		for _, sec := range secrets {
			if strings.Contains(string(data), sec) {
				where = append(where, path)
			}
		}
		if preAuthSecretRE.Match(data) && len(preAuthSecretRE.FindAll(data, -1)) > 0 {
			where = append(where, path+" (a full pre-auth key)")
		}
		return nil
	})
	if err != nil {
		s.t.Fatalf("walk the data directory: %v", err)
	}
	logs := s.proc.stderr.String()
	for _, sec := range secrets {
		if strings.Contains(logs, sec) {
			where = append(where, "application log")
		}
	}
	if preAuthSecretRE.MatchString(logs) {
		where = append(where, "application log (a full pre-auth key)")
	}
	// The artifact history (git) is checked through git so packed objects are read too.
	gitDir := filepath.Join(s.proc.dataDir, "artifact-git")
	if _, err := os.Stat(gitDir); err == nil {
		out, _ := execGit(gitDir, "log", "-p", "--all")
		for _, sec := range secrets {
			if strings.Contains(out, sec) {
				where = append(where, "artifact git history")
			}
		}
	}
	if len(where) > 0 {
		s.t.Errorf("a known secret was found in: %s", strings.Join(where, ", "))
	}
}

func execGit(dir string, args ...string) (string, error) {
	out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput()
	return string(out), err
}

// helpers ---------------------------------------------------------------------------------------

func mustContain(t *testing.T, what, body string, wants ...string) {
	t.Helper()
	// The apostrophe of "switch'i" renders as &#39;; compare the text the reader sees as well.
	text := html.UnescapeString(body)
	for _, w := range wants {
		if !strings.Contains(body, w) && !strings.Contains(text, w) {
			t.Errorf("%s does not contain %q: %s", what, w, excerpt(body))
		}
	}
}

func mustNotContain(t *testing.T, what, body string, nots ...string) {
	t.Helper()
	for _, n := range nots {
		if strings.Contains(body, n) {
			t.Errorf("%s contains %q: %s", what, n, excerpt(body))
		}
	}
}

func devicePath(id uint64, suffix string) string {
	return fmt.Sprintf("/headscale/devices/%d%s", id, suffix)
}

// section runs a scenario step as a subtest and points the stack's helpers at it while it runs, so
// their failures are reported against the step and Fatal never fires on the parent.
func (s *f3Stack) section(t *testing.T, name string, fn func(t *testing.T)) {
	t.Helper()
	t.Run(name, func(sub *testing.T) {
		prev := s.t
		s.t, s.ui.t = sub, sub
		defer func() { s.t, s.ui.t = prev, prev }()
		fn(sub)
	})
}
