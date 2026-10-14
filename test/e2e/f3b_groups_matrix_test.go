//go:build integration

// F3b-023: the real groups-claim accept/reject matrix on the host lab. A fresh, auth-key-less
// Tailscale client (userspace tailscaled in a throwaway state directory) drives a real
// `tailscale up --login-server=<host lab>`; the test completes Headscale's OIDC login without a
// browser by finishing the lab Zitadel session/OIDC APIs and posting Headscale's confirm form, then
// proves the node was (or was not) created in Headscale. The F1-026 groups receiver serves the lab
// Actions target at <tailnet>:9443 for every login. Run it with:
//
//	make hostlab-up && go test -tags=integration -count=1 -v -run TestF3b_E2E_GroupsMatrix ./test/e2e/
//
// It is host-lab gated by its name (like TestF3b_E2E_*), so `make e2e` skips it and
// `make hostlab-e2e` runs it. Never log register/callback URLs, tokens, cookies or claim bodies.
package e2e_test

import (
	"bytes"
	"context"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	oidcv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/oidc/v2"
	sessionv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/session/v2"

	"github.com/nesiler/tagcess/internal/groupsclaim"
	"github.com/nesiler/tagcess/internal/headscale"
	"github.com/nesiler/tagcess/internal/hostpatch"
	"github.com/nesiler/tagcess/test/compose/seed"
	"github.com/nesiler/tagcess/test/hostlab"
)

// The two rejection reasons the matrix distinguishes. A login is a rejection only when the callback
// says so; any other status is a fixture failure, not a matrix row.
const (
	reasonGroupsDenied  = "headscale_groups_denied" // Headscale /oidc/callback returned 401
	reasonGrantRequired = "zitadel_grant_required"  // Zitadel refused the callback (vpn role missing)
)

// TestF3b_E2E_GroupsMatrix is the F3b-023 acceptance test: with ["devops"] applied through the
// helper request path, devops is accepted and developer/norole are rejected with no node; then the
// UI applies ["devops","developer"], developer is accepted and standart is rejected. Every login is
// a fresh client with no auth key; no client state is reused.
func TestF3b_E2E_GroupsMatrix(t *testing.T) {
	l := setupLab(t)
	hl := hostlab.Start(t)
	hostlab.Install(t, hl)
	hostlab.ClearDir(t, hl.RequestsDir())
	hostlab.ClearDir(t, hl.ResultsDir())
	baseline := hostlab.ConfigBytes(t, hl)
	// The interface's reconcile reads the host lab policy; seed the same fixture the F3b tests use.
	if _, err := hl.Client().SetPolicy(context.Background(), f3Policy); err != nil {
		t.Fatalf("seed the host lab policy: %v", err)
	}

	s := &f3bStack{t: t, l: l, hl: hl, baseline: baseline}
	t.Cleanup(func() {
		s.clearFaults()
		hostlab.WriteConfig(t, hl, baseline)
		hostlab.ClearDir(t, hl.RequestsDir())
		hostlab.ClearDir(t, hl.ResultsDir())
	})

	// The groups receiver must serve the seeded target address for every login (F1-026), and the
	// binary's webhook listens on another loopback port so both can run at once.
	stopGroups := startMatrixGroupsHandler(t, l)
	t.Cleanup(stopGroups)

	prefix := fmt.Sprintf("f3b023-%d", time.Now().UnixNano()%1_000_000_000)
	t.Cleanup(func() { hl.DeleteNodesWithPrefix(t, prefix) })

	// Step 1 (ADR 0021 e.3): apply ["devops"] through the helper request path (F3b-003 fixture), not
	// the interface. This is the config the first round of logins runs against.
	roundA := []string{hostpatch.GroupDevops}
	reqA := hostlab.NewRequestID(t)
	hostlab.PublishRequest(t, hl, reqA, roundA)
	resA := hostlab.WaitResult(t, hl, reqA)
	if resA.State != hostpatch.StateSucceeded {
		t.Fatalf("the helper request %s = %s/%s, want succeeded", reqA, resA.State, resA.ErrorCode)
	}
	t.Logf("step 1 helper request ID: %s", reqA)
	revA, err := hostpatch.BaseRev(roundA)
	if err != nil {
		t.Fatal(err)
	}
	if st := hostlab.WaitStatusFor(t, hl, revA); !equalGroupList(st.AllowedGroups, roundA) {
		t.Fatalf("status groups = %v, want %v", st.AllowedGroups, roundA)
	}

	t.Run("devops_only", func(t *testing.T) {
		// AC2: devops is accepted (a node is created for it).
		runMatrixLogin(t, l, hl, prefix, "ops", "lab-devops@tagcess.test", true, "")
		// AC3: developer-only, standart-only, and the account with no vpn role are rejected with no
		// node; standart is rejected because the applied list is still ["devops"].
		runMatrixLogin(t, l, hl, prefix, "dev", "lab-developer@tagcess.test", false, reasonGroupsDenied)
		runMatrixLogin(t, l, hl, prefix, "std1", "lab-standart@tagcess.test", false, reasonGroupsDenied)
		runMatrixLogin(t, l, hl, prefix, "norole", "lab-norole@tagcess.test", false, reasonGrantRequired)
		// lab-emptygroups cannot be produced: the F1-026 receiver appends no groups entry for an
		// empty role list, and a role-less account never reaches Headscale (F3b-001 Kanıt). lab-norole
		// above is the "claim absent" row.
	})

	// Step 3 (ADR 0021 e.4): the interface applies ["devops","developer"]; the request ID is recorded.
	s.cfg = tagcessConfig{
		headscaleAddr:   hl.GRPCAddr,
		issuer:          l.issuer,
		keyFile:         filepath.Join(l.secrets(), "zitadel-key.json"),
		interval:        5 * time.Minute,
		hostRequestsDir: hl.RequestsDir(),
		hostResultsDir:  hl.ResultsDir(),
		hookListen:      freeLoopbackAddr(t),
	}
	s.proc = startTagcess(t, l, s.cfg)
	s.ui = newUIClient(t, s.proc.uiSock)
	s.enableWriteSwitch()
	roundB := []string{hostpatch.GroupDevops, hostpatch.GroupDeveloper}
	s.applyOK(roundB)
	if state, code := s.waitHostResult(); state != hostpatch.StateSucceeded || code != "" {
		t.Fatalf("the UI apply = %s/%s, want succeeded", state, code)
	}
	_, uiReqID, _ := s.maint()
	if uiReqID == "" {
		t.Fatal("the UI apply recorded no request ID")
	}
	t.Logf("UI request ID: %s", uiReqID)
	s.waitMaintOffRetrying()
	if st := hostlab.WaitStatusFor(t, hl, mustBaseRev(t, roundB)); !equalGroupList(st.AllowedGroups, roundB) {
		t.Fatalf("status groups after the UI apply = %v, want %v", st.AllowedGroups, roundB)
	}

	t.Run("devops_developer", func(t *testing.T) {
		// AC4: developer is accepted; the standart-only account is rejected.
		runMatrixLogin(t, l, hl, prefix, "dev2", "lab-developer@tagcess.test", true, "")
		runMatrixLogin(t, l, hl, prefix, "std", "lab-standart@tagcess.test", false, reasonGroupsDenied)
	})
}

// startMatrixGroupsHandler serves the real F1-026 groupsclaim handler at the seeded target address
// (<tailnet>:9443) and returns an idempotent stop. It is started once for the whole test.
func startMatrixGroupsHandler(t *testing.T, l *labEnv) func() {
	t.Helper()
	key := l.readSecret(t, seed.GroupsSigningKeyFile)
	h, err := groupsclaim.New(groupsclaim.Config{SigningKey: []byte(key), ProjectID: l.seeded.ProjectID})
	if err != nil {
		t.Fatalf("build the groupsclaim handler: %v", err)
	}
	addr := net.JoinHostPort(l.tailnetIP, "9443")
	ln := listenWithRetry(t, addr)
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	return func() { _ = srv.Close() }
}

// freeLoopbackAddr returns a loopback address tagcess can bind for its webhook while the groups
// receiver holds :9443.
func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a loopback port: %v", err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().String()
}

func mustBaseRev(t *testing.T, groups []string) string {
	t.Helper()
	rev, err := hostpatch.BaseRev(groups)
	if err != nil {
		t.Fatal(err)
	}
	return rev
}

// runMatrixLogin runs one fresh login for loginName and asserts the expected matrix row.
func runMatrixLogin(t *testing.T, l *labEnv, hl *hostlab.Lab, prefix, short, loginName string, wantAccept bool, wantReason string) {
	t.Helper()
	hostname := prefix + "-" + short
	out := runTailscaleLogin(t, l, "http://"+hl.HTTPAddr, hostname, loginName)

	if wantAccept {
		if !out.accepted {
			t.Fatalf("%s: login was not accepted (reason %q)", short, out.reason)
		}
		var node headscale.Node
		if err := poll(t, 30*time.Second, func() (bool, error) {
			n, ok := nodeByName(t, hl, hostname)
			node = n
			return ok, nil
		}); err != nil {
			t.Fatalf("%s: the accepted login created no node for %s: %v", short, hostname, err)
		}
		if node.UserName != loginName {
			t.Fatalf("%s: node %s belongs to %q, want %q", short, hostname, node.UserName, loginName)
		}
		return
	}

	if out.accepted {
		t.Fatalf("%s: login was accepted, want a rejection", short)
	}
	if out.reason != wantReason {
		t.Fatalf("%s: rejection reason = %q, want %q", short, out.reason, wantReason)
	}
	// The rejection must be provable: the node must not exist, even after a settle.
	time.Sleep(3 * time.Second)
	if n, ok := nodeByName(t, hl, hostname); ok {
		t.Fatalf("%s: a node was created although the login was rejected: %+v", short, n)
	}
}

// nodeByName finds a lab node by its registered name or given name.
func nodeByName(t *testing.T, hl *hostlab.Lab, name string) (headscale.Node, bool) {
	t.Helper()
	nodes, err := hl.Client().ListNodes(context.Background())
	if err != nil {
		t.Fatalf("list the lab nodes: %v", err)
	}
	for _, n := range nodes {
		if n.Name == name || n.GivenName == name {
			return n, true
		}
	}
	return headscale.Node{}, false
}

// loginOutcome is the result of one browser-less Headscale OIDC login attempt.
type loginOutcome struct {
	accepted bool
	reason   string // one of the reason* constants when accepted is false
}

// runTailscaleLogin starts a fresh userspace tailscaled in a throwaway state directory, runs
// `tailscale up --login-server=...` without an auth key, parses its login URL and completes the
// Headscale OIDC flow (Zitadel session/OIDC and Headscale's confirm form). No client state is
// reused between scenarios.
func runTailscaleLogin(t *testing.T, l *labEnv, loginServer, hostname, loginName string) loginOutcome {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "f3b023-ts-")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "sock")
	daemonLog, err := os.Create(filepath.Join(dir, "tailscaled.log"))
	if err != nil {
		t.Fatal(err)
	}
	daemon := exec.Command("tailscaled",
		"--tun=userspace-networking",
		"--state="+filepath.Join(dir, "state"),
		"--socket="+sock,
		"--port=0",
		"--no-logs-no-support")
	daemon.Stdout, daemon.Stderr = daemonLog, daemonLog
	if err := daemon.Start(); err != nil {
		t.Fatalf("start tailscaled: %v", err)
	}
	t.Cleanup(func() {
		_ = daemonLog.Close()
		_ = daemon.Process.Kill()
		_, _ = daemon.Process.Wait()
	})
	waitTailscaleDaemon(t, sock)

	upLogPath := filepath.Join(dir, "up.log")
	upLog, err := os.Create(upLogPath)
	if err != nil {
		t.Fatal(err)
	}
	upCtx, cancel := context.WithCancel(context.Background())
	up := exec.CommandContext(upCtx, "tailscale", "--socket="+sock, "up",
		"--login-server="+loginServer, "--hostname="+hostname)
	up.Stdout, up.Stderr = upLog, upLog
	if err := up.Start(); err != nil {
		cancel()
		t.Fatalf("start tailscale up: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		_ = upLog.Close()
		_ = up.Process.Kill()
		_, _ = up.Process.Wait()
	})

	loginURL := waitForRegisterURL(t, upLogPath)
	return completeHeadscaleOIDC(t, l, loginURL, loginName)
}

// waitTailscaleDaemon waits until the standalone daemon answers `tailscale status`. A logged-out
// daemon still prints "Logged out" but may exit non-zero, so the output is checked too.
func waitTailscaleDaemon(t *testing.T, sock string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		out, err := exec.Command("tailscale", "--socket="+sock, "status").CombinedOutput()
		if err == nil || bytes.Contains(out, []byte("Logged out")) {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("tailscaled did not answer on %s", sock)
}

// registerURLRE extracts the Headscale register URL `tailscale up` prints (no auth key).
var registerURLRE = regexp.MustCompile(`http://[^\s]+/register/[A-Za-z0-9_-]+`)

// waitForRegisterURL reads the login URL out of `tailscale up`'s output.
func waitForRegisterURL(t *testing.T, logPath string) string {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(logPath); err == nil { //nolint:gosec // the path this test created
			if m := registerURLRE.FindString(string(b)); m != "" {
				return m
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("tailscale up printed no Headscale register URL")
	return ""
}

// completeHeadscaleOIDC follows Headscale's register -> Zitadel authorize -> login chain, finishes
// the Zitadel session and OIDC callback with the login v2 client, then posts Headscale's confirm
// form. It returns accepted=true only when Headscale confirmed the registration; a Headscale 401 or
// a Zitadel GrantRequired refusal is a matrix rejection. It never logs a URL, token or claim body.
func completeHeadscaleOIDC(t *testing.T, l *labEnv, loginURL, loginName string) loginOutcome {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar:     jar,
		Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// register -> Zitadel authorize -> login: the URL carrying authRequest is the login page.
	cur, authRequest := loginURL, ""
	for i := 0; i < 6 && authRequest == ""; i++ {
		u, err := url.Parse(cur)
		if err != nil {
			t.Fatalf("parse the login redirect chain: %v", safeError(err))
		}
		if authRequest = u.Query().Get("authRequest"); authRequest != "" {
			break
		}
		loc, code := matrixGET(t, client, cur)
		if loc == "" || code < 300 || code >= 400 {
			t.Fatalf("the login redirect chain stopped with status %d", code)
		}
		cur = loc
	}
	if authRequest == "" {
		t.Fatal("the login redirect chain carried no authRequest")
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
		// Only a Zitadel GrantRequired refusal is the "claim absent / no VPN role" rejection; any
		// other PermissionDenied is a fixture failure, not a matrix row.
		if st, ok := status.FromError(err); ok && st.Code() == codes.PermissionDenied && strings.Contains(st.Message(), "GrantRequired") {
			return loginOutcome{reason: reasonGrantRequired}
		}
		t.Fatalf("CreateCallback: %v", err)
	}

	// The callback URL carries the authorization code; only its status and redirect are used.
	loc, code := matrixGET(t, client, callback.GetCallbackUrl())
	switch {
	case code == http.StatusUnauthorized:
		return loginOutcome{reason: reasonGroupsDenied}
	case code >= 300 && code < 400:
		page, pageCode := matrixGETBody(t, client, loc)
		if pageCode != http.StatusOK {
			t.Fatalf("Headscale confirm page status %d", pageCode)
		}
		form := confirmFields(t, page, loc)
		resp, err := client.PostForm(loc, form)
		if err != nil {
			t.Fatalf("post the Headscale confirm form: %v", safeError(err))
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Headscale confirm status %d", resp.StatusCode)
		}
		return loginOutcome{accepted: true}
	default:
		t.Fatalf("Headscale callback returned status %d", code)
	}
	return loginOutcome{}
}

// confirmFields returns the fields of the page's form with that action, order-independent (Headscale
// emits the hidden input as name then type then value, which the settings helper's stricter regex does
// not match). The values are HTML-unescaped, the way a browser would post them back.
func confirmFields(t *testing.T, page, action string) url.Values {
	t.Helper()
	for _, m := range formRE.FindAllStringSubmatch(page, -1) {
		if html.UnescapeString(m[1]) != action {
			continue
		}
		v := url.Values{}
		for _, in := range matrixInputRE.FindAllStringSubmatch(m[2], -1) {
			name := htmlAttr(in[1], "name")
			if name == "" {
				continue
			}
			v.Set(name, htmlAttr(in[1], "value"))
		}
		if len(v) == 0 {
			t.Fatal("the Headscale confirm form carries no fields")
		}
		return v
	}
	t.Fatalf("the page has no form to %s", action)
	return nil
}

var (
	matrixInputRE = regexp.MustCompile(`(?is)<input([^>]*)>`)
	matrixNameRE  = regexp.MustCompile(`(?i)\bname="([^"]*)"`)
	matrixValueRE = regexp.MustCompile(`(?i)\bvalue="([^"]*)"`)
)

// htmlAttr returns one attribute of an HTML tag, unescaped.
func htmlAttr(tag, key string) string {
	var re *regexp.Regexp
	switch key {
	case "name":
		re = matrixNameRE
	case "value":
		re = matrixValueRE
	default:
		return ""
	}
	if m := re.FindStringSubmatch(tag); m != nil {
		return html.UnescapeString(m[1])
	}
	return ""
}

// matrixGET performs one request without following redirects and returns the Location and status.
func matrixGET(t *testing.T, client *http.Client, u string) (string, int) {
	t.Helper()
	resp, err := client.Get(u)
	if err != nil {
		// Never include the URL: it may carry a code.
		t.Fatalf("request failed: %v", safeError(err))
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.Header.Get("Location"), resp.StatusCode
}

// matrixGETBody reads a bounded response body (the confirm page).
func matrixGETBody(t *testing.T, client *http.Client, u string) (string, int) {
	t.Helper()
	resp, err := client.Get(u)
	if err != nil {
		t.Fatalf("request failed: %v", safeError(err))
	}
	defer func() { _ = resp.Body.Close() }()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, io.LimitReader(resp.Body, 1<<20)); err != nil {
		t.Fatalf("read response: %v", err)
	}
	return buf.String(), resp.StatusCode
}
