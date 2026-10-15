package hshelper

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/hostpatch"
	"github.com/nesiler/tagcess/internal/stack"
)

const (
	canary     = "CANARY-s3cr3t-9f2a7c41"
	stackDig   = "sha256:00000000000000000000000000000000000000000000000000000000000000a1"
	stackDigUp = "sha256:00000000000000000000000000000000000000000000000000000000000000b2"
)

// fakeDocker records every call and fails the ones named in fail.
type fakeDocker struct {
	mu    sync.Mutex
	calls []string
	fail  map[string]error
	// failOnce fails the next call of a name once; fail keeps failing.
	failOnce map[string]bool
	// onConfig runs inside ConfigQuiet, to look at the host while the candidate is validated.
	onConfig func(file string)
}

func (d *fakeDocker) record(name string, c stack.Component) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	key := name
	if c != "" {
		key += ":" + string(c)
	}
	d.calls = append(d.calls, key)
	if d.failOnce[name] {
		delete(d.failOnce, name)
		return errors.New("failed once")
	}
	return d.fail[name]
}

func (d *fakeDocker) ConfigQuiet(_ context.Context, file string) error {
	if d.onConfig != nil {
		d.onConfig(file)
	}
	if _, err := os.Stat(file); err != nil {
		return err
	}
	return d.record("config", "")
}
func (d *fakeDocker) Pull(_ context.Context, _ string, c stack.Component) error {
	return d.record("pull", c)
}
func (d *fakeDocker) Up(_ context.Context, _ string, c stack.Component) error {
	return d.record("up", c)
}
func (d *fakeDocker) Remove(_ context.Context, _ string, c stack.Component) error {
	return d.record("rm", c)
}
func (d *fakeDocker) Restart(_ context.Context, _ string, c stack.Component) error {
	return d.record("restart", c)
}

func (d *fakeDocker) joined() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return strings.Join(d.calls, " ")
}

type stackEnv struct {
	t       *testing.T
	root    string
	stack   string
	hs      string
	secrets string
	cfg     StackConfig
	docker  *fakeDocker
	now     time.Time
	logs    []string
}

func testStackManifest(digest string) stack.Manifest {
	m := stack.Manifest{Release: "v0.0.0-test", Images: map[stack.Component]stack.Image{}}
	for _, c := range stack.AllComponents() {
		m.Images[c] = stack.Image{Name: "registry.example.com/" + string(c), Tag: "1.2.3", Digest: digest}
	}
	return m
}

func testSettings() *stack.Params {
	return &stack.Params{
		HeadscaleHost: "hs.example.com", MagicDNSDomain: "vpn.example.net",
		PrefixV4: "100.64.0.0/10", PrefixV6: "fd7a:115c:a1e0::/48",
		HeadscalePort: 8080, HeadscaleMetrics: 9090, OAuth2ProxyPort: 4180, SetupPort: 9180,
		IssuerURL: "https://idp.example.com", HeadscaleClientID: "headscale-client", ProxyClientID: "proxy-client",
		ProxyHost: "auth.example.com", CookieDomain: "example.com", CookieLifetime: "1h", AdminGroup: "admins",
		CaddyGID: 990, HeadscaleGID: 991, SocketGID: 992,
	}
}

func newStackEnv(t *testing.T) *stackEnv {
	t.Helper()
	e := &stackEnv{t: t, root: t.TempDir(), stack: filepath.Join(t.TempDir(), "stack"), hs: t.TempDir(), secrets: filepath.Join(t.TempDir(), "secrets"),
		docker: &fakeDocker{fail: map[string]error{}}, now: time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)}
	for _, d := range []string{"requests", "results", "private", "handoff/in"} {
		if err := os.MkdirAll(filepath.Join(e.root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(e.hs, "private"), 0o700); err != nil {
		t.Fatal(err)
	}
	e.cfg = StackConfig{
		Root: e.root, StackDir: e.stack, TagcessSecretsDir: e.secrets, HeadscaleRoot: e.hs, RequestUID: uint32(os.Getuid()),
		Manifest: testStackManifest(stackDig), Docker: e.docker,
		Now:  func() time.Time { return e.now },
		Logf: func(format string, args ...any) { e.logs = append(e.logs, fmt.Sprintf(format, args...)) },
	}
	return e
}

func (e *stackEnv) path(parts ...string) string {
	return filepath.Join(append([]string{e.root}, parts...)...)
}

func (e *stackEnv) rev() string {
	e.t.Helper()
	st, err := readStackState(e.path("private"))
	if err != nil {
		e.t.Fatal(err)
	}
	return st.rev()
}

func (e *stackEnv) writeRaw(rel string, b []byte) {
	e.t.Helper()
	if err := os.WriteFile(e.path(rel), b, 0o600); err != nil {
		e.t.Fatal(err)
	}
}

// publish writes the request document and the marker.
func (e *stackEnv) publish(r StackRequest) {
	e.t.Helper()
	b, err := EncodeStackRequest(r)
	if err != nil {
		e.t.Fatal(err)
	}
	e.publishRaw(r.RequestID, b)
}

func (e *stackEnv) publishRaw(id string, b []byte) {
	e.t.Helper()
	e.writeRaw("requests/"+id+".json", b)
	e.writeRaw("requests/request.ready", []byte(id))
}

func (e *stackEnv) run() Outcome {
	e.t.Helper()
	out, err := StackRun(e.cfg)
	if err != nil {
		e.t.Fatalf("StackRun: %v", err)
	}
	return out
}

func (e *stackEnv) result() StackResult {
	e.t.Helper()
	b, err := os.ReadFile(e.path("results", "result.json"))
	if err != nil {
		e.t.Fatal(err)
	}
	var r StackResult
	if err := jsonUnmarshalStrict(b, &r); err != nil {
		e.t.Fatalf("result.json: %v", err)
	}
	return r
}

func (e *stackEnv) exists(rel string) bool {
	_, err := os.Lstat(e.path(rel))
	return err == nil
}

func (e *stackEnv) applyReq(id string, c stack.Component, kinds ...HandoffKind) StackRequest {
	return StackRequest{Version: StackVersion, RequestID: id, Op: OpStackApply, BaseRev: e.rev(), Component: c, Settings: testSettings(), Handoff: kinds}
}

func (e *stackEnv) apply(id string, c stack.Component, kinds ...HandoffKind) StackResult {
	e.t.Helper()
	e.publish(e.applyReq(id, c, kinds...))
	e.run()
	return e.result()
}

func (e *stackEnv) drop(id string, kind HandoffKind, value string) {
	e.t.Helper()
	e.writeRaw("handoff/in/"+id+"."+string(kind), []byte(value))
}

func (e *stackEnv) readStack(rel string) []byte {
	e.t.Helper()
	b, err := os.ReadFile(filepath.Join(e.stack, rel))
	if err != nil {
		e.t.Fatal(err)
	}
	return b
}

func succeeded(t *testing.T, r StackResult) {
	t.Helper()
	if r.State != hostpatch.StateSucceeded {
		t.Fatalf("result = %s/%s/%s, want succeeded", r.State, r.Phase, r.ErrorCode)
	}
}

// AC1: only the operations of §5.3, with the ADR 0021 b file rules.
func TestStackIntake_Table(t *testing.T) {
	valid := func(e *stackEnv) []byte {
		b, err := EncodeStackRequest(e.applyReq(idA, stack.Headscale))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	cases := []struct {
		name  string
		setup func(e *stackEnv)
	}{
		{"unknown op", func(e *stackEnv) {
			e.publishRaw(idA, bytes.Replace(valid(e), []byte("stack.apply"), []byte("stack.exec"), 1))
		}},
		{"unknown field", func(e *stackEnv) {
			e.publishRaw(idA, bytes.Replace(valid(e), []byte(`"op"`), []byte(`"image":"evil","op"`), 1))
		}},
		{"unknown settings field", func(e *stackEnv) {
			e.publishRaw(idA, bytes.Replace(valid(e), []byte(`"settings":{`), []byte(`"settings":{"path":"/etc",`), 1))
		}},
		{"duplicate key", func(e *stackEnv) {
			e.publishRaw(idA, bytes.Replace(valid(e), []byte(`"op"`), []byte(`"op":"discover","op"`), 1))
		}},
		{"case variant key", func(e *stackEnv) {
			e.publishRaw(idA, bytes.Replace(valid(e), []byte(`"op"`), []byte(`"Op"`), 1))
		}},
		{"component list in settings", func(e *stackEnv) {
			e.publishRaw(idA, bytes.Replace(valid(e), []byte(`"settings":{`), []byte(`"settings":{"components":["caddy"],`), 1))
		}},
		{"unknown handoff kind", func(e *stackEnv) {
			e.publishRaw(idA, bytes.Replace(valid(e), []byte(`"component"`), []byte(`"handoff":["root_password"],"component"`), 1))
		}},
		{"kind of another component", func(e *stackEnv) {
			e.publishRaw(idA, bytes.Replace(valid(e), []byte(`"component"`), []byte(`"handoff":["oidc_secret_oauth2_proxy"],"component"`), 1))
		}},
		{"trailing data", func(e *stackEnv) { e.publishRaw(idA, append(valid(e), []byte(`{}`)...)) }},
		{"oversize", func(e *stackEnv) {
			e.publishRaw(idA, append(valid(e), bytes.Repeat([]byte(" "), MaxStackRequestBytes)...))
		}},
		{"id differs from marker", func(e *stackEnv) {
			e.writeRaw("requests/"+idA+".json", valid(e))
			e.writeRaw("requests/request.ready", []byte(idA))
			b := bytes.Replace(valid(e), []byte(idA), []byte(idB), 1)
			e.writeRaw("requests/"+idA+".json", b)
		}},
		{"symlink request file", func(e *stackEnv) {
			e.writeRaw("target.json", valid(e))
			if err := os.Symlink(e.path("target.json"), e.path("requests", idA+".json")); err != nil {
				t.Fatal(err)
			}
			e.writeRaw("requests/request.ready", []byte(idA))
		}},
		{"wrong owner", func(e *stackEnv) {
			e.publishRaw(idA, valid(e))
			e.cfg.RequestUID = uint32(os.Getuid()) + 1
		}},
		{"symlink marker", func(e *stackEnv) {
			e.writeRaw("m", []byte(idA))
			if err := os.Symlink(e.path("m"), e.path("requests", "request.ready")); err != nil {
				t.Fatal(err)
			}
		}},
		{"bad marker", func(e *stackEnv) { e.writeRaw("requests/request.ready", []byte("../../etc/passwd")) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newStackEnv(t)
			tc.setup(e)
			if out := e.run(); out != OutcomeRejected {
				t.Fatalf("outcome = %s, want rejected", out)
			}
			r := e.result()
			if r.State != hostpatch.StateFailed || r.ErrorCode != StackInvalidRequest || r.Changed == nil || *r.Changed {
				t.Fatalf("result = %+v", r)
			}
			if e.exists("requests/request.ready") {
				t.Error("marker not consumed")
			}
			if e.exists("private/stack-journal.json") || e.exists("private/stack-state.json") {
				t.Error("a rejected request left a journal or state")
			}
			if got := e.docker.joined(); got != "" {
				t.Errorf("docker was called: %s", got)
			}
			if _, err := os.Stat(e.stack); err == nil {
				t.Error("the stack directory was created")
			}
		})
	}

	t.Run("all six operations parse", func(t *testing.T) {
		e := newStackEnv(t)
		for _, r := range []StackRequest{
			{Version: 1, RequestID: idA, Op: OpDiscover},
			e.applyReq(idA, stack.Caddy),
			{Version: 1, RequestID: idA, Op: OpStackRemove, BaseRev: e.rev(), Component: stack.Caddy},
			{Version: 1, RequestID: idA, Op: OpServiceRestart, BaseRev: e.rev(), Component: stack.Caddy},
			{Version: 1, RequestID: idA, Op: OpStackUpgrade, BaseRev: e.rev(), Component: stack.Caddy},
			{Version: 1, RequestID: idA, Op: OpHandoffCleanup, TargetID: idB},
		} {
			b, err := EncodeStackRequest(r)
			if err != nil {
				t.Fatalf("%s: %v", r.Op, err)
			}
			if _, err := ParseStackRequest(b); err != nil {
				t.Fatalf("%s: %v", r.Op, err)
			}
		}
	})
}

// AC2: validate with `docker compose config --quiet` before any change; an error leaves the stack alone.
func TestStackApply_ValidatesBeforeAnyChange(t *testing.T) {
	e := newStackEnv(t)
	e.docker.onConfig = func(string) {
		if _, err := os.Stat(e.stack); err == nil {
			t.Error("the stack directory exists while the candidate is validated")
		}
	}
	e.docker.fail["config"] = errors.New("invalid compose")
	r := e.apply(idA, stack.Headscale)
	if r.State != hostpatch.StateFailed || r.ErrorCode != StackConfigInvalid || r.Phase != StackPhaseValidate {
		t.Fatalf("result = %+v", r)
	}
	if r.Changed == nil || *r.Changed {
		t.Errorf("changed = %v, want false", r.Changed)
	}
	if got := e.docker.joined(); got != "config" {
		t.Errorf("docker calls = %q, want only config", got)
	}
	if _, err := os.Stat(e.stack); err == nil {
		t.Error("the stack directory was created")
	}
	if e.exists("private/stack-state.json") {
		t.Error("state was written")
	}
	if e.exists("private/candidate-" + idA) {
		t.Error("the candidate was left behind")
	}

	// A running stack stays byte-identical when a later apply fails validation.
	e.docker.fail = map[string]error{}
	e.docker.onConfig = nil
	succeeded(t, e.apply(idB, stack.Headscale))
	before := e.readStack("compose.yaml")
	e.docker.fail["config"] = errors.New("invalid compose")
	calls := e.docker.joined()
	r = e.apply(idC, stack.OAuth2Proxy)
	if r.ErrorCode != StackConfigInvalid {
		t.Fatalf("result = %+v", r)
	}
	if !bytes.Equal(before, e.readStack("compose.yaml")) {
		t.Error("compose.yaml changed after a failed validation")
	}
	if strings.TrimPrefix(e.docker.joined(), calls) != " config" {
		t.Errorf("docker calls after failure: %q", e.docker.joined())
	}
	if e.exists("../" + filepath.Base(e.stack) + "/oauth2-proxy") {
		t.Error("oauth2-proxy files were written")
	}
}

func TestStackApply_Order(t *testing.T) {
	e := newStackEnv(t)
	succeeded(t, e.apply(idA, stack.Headscale))
	if got := e.docker.joined(); got != "config pull:headscale up:headscale" {
		t.Errorf("docker calls = %q", got)
	}
	for _, rel := range []string{"compose.yaml", "headscale/config.yaml"} {
		if len(e.readStack(rel)) == 0 {
			t.Errorf("%s is empty", rel)
		}
	}
	st, err := readStackState(e.path("private"))
	if err != nil || !st.enabled(stack.Headscale) || st.Images[stack.Headscale].Digest != stackDig {
		t.Errorf("state = %+v, %v", st, err)
	}
	r := e.result()
	if r.Changed == nil || !*r.Changed || r.Phase != StackPhaseStart {
		t.Errorf("result = %+v", r)
	}
	// A failed pull changes nothing: files, state and base_rev stay the last known good.
	compose, rev := e.readStack("compose.yaml"), e.rev()
	e.docker.fail["pull"] = errors.New("registry down")
	r = e.apply(idB, stack.OAuth2Proxy)
	if r.ErrorCode != StackPullFailed || r.Phase != StackPhasePull {
		t.Fatalf("result = %+v", r)
	}
	st, _ = readStackState(e.path("private"))
	if st.enabled(stack.OAuth2Proxy) || e.rev() != rev || !bytes.Equal(compose, e.readStack("compose.yaml")) {
		t.Error("a failed pull changed the files or the state")
	}
	if _, err := os.Lstat(filepath.Join(e.stack, "oauth2-proxy", "oauth2-proxy.cfg")); err == nil {
		t.Error("a failed pull left a component file")
	}
}

// A failed start of a running component restores its files and state; a failed new service stays marked failed.
func TestStackApply_StartFailureRestoresLastKnownGood(t *testing.T) {
	e := newStackEnv(t)
	succeeded(t, e.apply(idA, stack.Headscale))
	compose, rev := e.readStack("compose.yaml"), e.rev()

	e.cfg.Manifest = testStackManifest(stackDigUp)
	e.docker.failOnce = map[string]bool{"up": true}
	e.publish(StackRequest{Version: 1, RequestID: idB, Op: OpStackUpgrade, BaseRev: rev, Component: stack.Headscale})
	e.run()
	r := e.result()
	if r.ErrorCode != StackStartFailed || r.Changed == nil || *r.Changed {
		t.Fatalf("result = %+v", r)
	}
	if !bytes.Equal(compose, e.readStack("compose.yaml")) || e.rev() != rev {
		t.Error("compose.yaml or the state is not the last known good")
	}

	// A new service whose start fails stays written and marked failed.
	e.docker.fail["up"] = errors.New("unhealthy")
	r = e.apply(idC, stack.OAuth2Proxy)
	if r.ErrorCode != StackStartFailed {
		t.Fatalf("result = %+v", r)
	}
	st, _ := readStackState(e.path("private"))
	if !st.enabled(stack.OAuth2Proxy) || !st.failed(stack.OAuth2Proxy) {
		t.Errorf("state = %+v", st)
	}
}

// AC5: a changed Headscale setting is refused while config.yaml exists; nothing is recorded.
func TestStackApply_HeadscaleSettingChangeRefused(t *testing.T) {
	e := newStackEnv(t)
	succeeded(t, e.apply(idA, stack.Headscale))
	cfg, compose, rev := e.readStack("headscale/config.yaml"), e.readStack("compose.yaml"), e.rev()

	for i, target := range []stack.Component{stack.Headscale, stack.OAuth2Proxy} {
		req := e.applyReq(fmt.Sprintf("9999999%d-9999-4999-8999-999999999999", i), target)
		req.Settings.HeadscaleHost = "other.example.com"
		req.Settings.PrefixV4 = "100.100.0.0/16"
		e.publish(req)
		e.run()
		if r := e.result(); r.ErrorCode != StackSettings || r.Changed == nil || *r.Changed {
			t.Fatalf("%s: result = %+v", target, r)
		}
		if e.rev() != rev || !bytes.Equal(cfg, e.readStack("headscale/config.yaml")) || !bytes.Equal(compose, e.readStack("compose.yaml")) {
			t.Fatalf("%s: a refused request changed the host", target)
		}
	}
}

// §5.3: stack.remove takes only a service a failed install added, never tagcess.
func TestStackRemove_OnlyFailedNewServices(t *testing.T) {
	e := newStackEnv(t)
	succeeded(t, e.apply(idA, stack.Headscale))
	succeeded(t, e.apply(idB, stack.OAuth2Proxy))
	remove := func(id string, c stack.Component) StackResult {
		e.publish(StackRequest{Version: 1, RequestID: id, Op: OpStackRemove, BaseRev: e.rev(), Component: c})
		e.run()
		return e.result()
	}
	if r := remove(idC, stack.OAuth2Proxy); r.ErrorCode != StackInvalidRequest {
		t.Errorf("a healthy service was removable: %+v", r)
	}
	e.docker.fail["up"] = errors.New("unhealthy")
	if r := e.apply("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", stack.Tagcess); r.ErrorCode != StackStartFailed {
		t.Fatalf("result = %+v", r)
	}
	if r := remove("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", stack.Tagcess); r.ErrorCode != StackInvalidRequest {
		t.Errorf("tagcess was removable: %+v", r)
	}
}

// §5.4: secrets belong to the service's uid, in a directory it can enter.
func TestStackApply_SecretOwnerPerComponent(t *testing.T) {
	e := newStackEnv(t)
	var asked []stack.Component
	e.cfg.SecretOwner = func(c stack.Component) (int, int, bool) {
		asked = append(asked, c)
		return os.Getuid(), os.Getgid(), true
	}
	e.drop(idA, KindOIDCSecretOAuth2Proxy, canary)
	succeeded(t, e.apply(idA, stack.OAuth2Proxy, KindOIDCSecretOAuth2Proxy))
	if len(asked) != 2 || asked[0] != stack.OAuth2Proxy || asked[1] != stack.OAuth2Proxy {
		t.Errorf("owner asked for %v, want oauth2-proxy twice (client and cookie secret)", asked)
	}
	for c, want := range map[stack.Component][2]int{stack.Tagcess: {10001, 10001}, stack.OAuth2Proxy: {65532, 65532}, stack.Headscale: {0, 0}} {
		uid, gid, ok := DefaultSecretOwner(10001)(c)
		if !ok || uid != want[0] || gid != want[1] {
			t.Errorf("DefaultSecretOwner(%s) = %d:%d %v", c, uid, gid, ok)
		}
	}
}

// AC3: generated secrets are files with mode 0400, never in the compose file or results.
func TestStackApply_SecretFilesAndModes(t *testing.T) {
	e := newStackEnv(t)
	e.drop(idA, KindOIDCSecretOAuth2Proxy, canary)
	r := e.apply(idA, stack.OAuth2Proxy, KindOIDCSecretOAuth2Proxy)
	succeeded(t, r)

	cookie := filepath.Join(e.stack, "secrets", "oauth2-proxy", "cookie_secret")
	client := filepath.Join(e.stack, "secrets", "oauth2-proxy", "client_secret")
	for _, p := range []string{cookie, client} {
		fi, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		if m := fi.Mode().Perm(); m != 0o400 && m != 0o600 {
			t.Errorf("%s mode = %o, want 0400 or 0600", p, m)
		}
	}
	cb, _ := os.ReadFile(cookie)
	if len(cb) != 32 {
		t.Errorf("cookie secret length = %d, want 32", len(cb))
	}
	if b, _ := os.ReadFile(client); string(b) != canary {
		t.Errorf("client secret was not installed")
	}
	if len(r.Installed) != 1 || r.Installed[0] != KindOIDCSecretOAuth2Proxy {
		t.Errorf("installed = %v", r.Installed)
	}
	for _, rel := range []string{"compose.yaml", "oauth2-proxy/oauth2-proxy.cfg"} {
		b := e.readStack(rel)
		if bytes.Contains(b, []byte(canary)) || bytes.Contains(b, cb) {
			t.Errorf("%s contains a secret value", rel)
		}
	}

	// An existing secret is not regenerated.
	e.cfg.randRead = func(b []byte) (int, error) { return 0, errors.New("must not be called") }
	e.writeRaw("../x", nil)
	succeeded(t, e.apply(idB, stack.OAuth2Proxy))
	if b, _ := os.ReadFile(cookie); !bytes.Equal(b, cb) {
		t.Error("the cookie secret was regenerated")
	}
}

// AC4: a stale base_rev is rejected and nothing changes.
func TestStackIntake_StaleBase(t *testing.T) {
	e := newStackEnv(t)
	succeeded(t, e.apply(idA, stack.Headscale))
	compose := e.readStack("compose.yaml")
	calls := e.docker.joined()
	stale := e.applyReq(idB, stack.OAuth2Proxy)
	stale.BaseRev = strings.Repeat("0", 64)
	e.publish(stale)
	if out := e.run(); out != OutcomeRejected {
		t.Fatalf("outcome = %s", out)
	}
	r := e.result()
	if r.ErrorCode != StackStaleBase || r.Changed == nil || *r.Changed {
		t.Fatalf("result = %+v", r)
	}
	if e.docker.joined() != calls || !bytes.Equal(compose, e.readStack("compose.yaml")) {
		t.Error("a stale request changed something")
	}
	if e.exists("private/stack-request.json") && func() bool { j, _, _ := readStackJournal(e.path("private")); return j.RequestID == idB }() {
		t.Error("a stale request was journalled")
	}

	// The same applies to every write operation; handoff.cleanup and discover carry no base_rev.
	for i, op := range []StackOp{OpStackRemove, OpServiceRestart, OpStackUpgrade} {
		id := fmt.Sprintf("00000000-0000-4000-8000-00000000000%d", i+1)
		e.publish(StackRequest{Version: 1, RequestID: id, Op: op, BaseRev: strings.Repeat("1", 64), Component: stack.Headscale})
		e.run()
		if r := e.result(); r.ErrorCode != StackStaleBase {
			t.Errorf("%s: result = %+v", op, r)
		}
	}
}

// AC5: one component's apply leaves every other component's files byte-identical; an existing Headscale config
// is never re-rendered.
func TestStackApply_OtherComponentsStayByteIdentical(t *testing.T) {
	e := newStackEnv(t)
	succeeded(t, e.apply(idA, stack.Headscale))

	// An ADR 0021 patch changed allowed_groups on the host after the first apply.
	hsPath := filepath.Join(e.stack, "headscale", "config.yaml")
	patched := bytes.Replace(e.readStack("headscale/config.yaml"), []byte(`- "admins"`), []byte(`- "admins"`+"\n"+`    - "developer"`), 1)
	if bytes.Equal(patched, e.readStack("headscale/config.yaml")) {
		t.Fatal("test setup: the patch did not change the config")
	}
	if err := os.WriteFile(hsPath, patched, 0o644); err != nil { //nolint:gosec // test file
		t.Fatal(err)
	}
	old := e.readStack("compose.yaml")

	succeeded(t, e.apply(idB, stack.OAuth2Proxy))
	if !bytes.Equal(patched, e.readStack("headscale/config.yaml")) {
		t.Error("the patched Headscale config.yaml was re-rendered")
	}
	// compose.yaml gained one service block and kept the Headscale block byte for byte.
	oldBlocks, newBlocks := splitServices(string(old)), splitServices(string(e.readStack("compose.yaml")))
	if oldBlocks[stack.Headscale] == "" || oldBlocks[stack.Headscale] != newBlocks[stack.Headscale] {
		t.Error("the headscale block of compose.yaml changed")
	}
	if newBlocks[stack.OAuth2Proxy] == "" {
		t.Error("the oauth2-proxy block is missing")
	}

	// Re-applying Headscale itself does not touch an existing config either.
	succeeded(t, e.apply(idC, stack.Headscale))
	if !bytes.Equal(patched, e.readStack("headscale/config.yaml")) {
		t.Error("an apply of headscale re-rendered its existing config.yaml")
	}

	// A setting that would change another component's service block is refused; nothing is written.
	before := e.readStack("compose.yaml")
	cfgBefore := e.readStack("oauth2-proxy/oauth2-proxy.cfg")
	req := e.applyReq("22222222-2222-4222-8222-222222222222", stack.OAuth2Proxy)
	req.Settings.SocketGID = 4242 // changes the headscale service
	e.publish(req)
	e.run()
	if r := e.result(); r.ErrorCode != StackSettings || r.Changed == nil || *r.Changed {
		t.Fatalf("result = %+v", r)
	}
	req = e.applyReq("33333333-3333-4333-8333-333333333333", stack.Headscale)
	req.Settings.CookieLifetime = "2h" // changes the oauth2-proxy config file
	e.publish(req)
	e.run()
	if r := e.result(); r.ErrorCode != StackSettings {
		t.Fatalf("result = %+v", r)
	}
	if !bytes.Equal(before, e.readStack("compose.yaml")) || !bytes.Equal(cfgBefore, e.readStack("oauth2-proxy/oauth2-proxy.cfg")) {
		t.Error("a refused request wrote files")
	}
}

// AC6: the two channels refuse each other while the other has an unfinished operation, and share the lock.
func TestStackChannels_ExclusiveAndShareTheLock(t *testing.T) {
	t.Run("stack refuses while ADR 0021 is not terminal", func(t *testing.T) {
		e := newStackEnv(t)
		if err := WriteJournal(filepath.Join(e.hs, "private"), Journal{Version: 1, RequestID: idC, State: hostpatch.StateApplying, Phase: hostpatch.PhaseRestart}); err != nil {
			t.Fatal(err)
		}
		e.publish(e.applyReq(idA, stack.Headscale))
		e.run()
		if r := e.result(); r.ErrorCode != StackBusy {
			t.Fatalf("result = %+v", r)
		}
		if e.docker.joined() != "" || e.exists("private/stack-state.json") {
			t.Error("a busy request changed something")
		}
	})
	t.Run("ADR 0021 refuses while the stack is not terminal", func(t *testing.T) {
		e := newStackEnv(t)
		if err := writeStackJournal(e.path("private"), stackJournal{Version: 1, RequestID: idC, Op: OpStackApply, State: hostpatch.StateApplying, Phase: StackPhasePull}); err != nil {
			t.Fatal(err)
		}
		h := newEnv(t)
		h.cfg.Root = e.hs
		for _, d := range []string{"requests", "results"} {
			_ = os.MkdirAll(filepath.Join(e.hs, d), 0o700)
		}
		h.cfg.StackRoot = e.root
		h.root = e.hs
		h.publish(idA)
		out, err := Run(h.cfg)
		if err != nil || out != OutcomeRejected {
			t.Fatalf("Run = %s, %v", out, err)
		}
		if r := h.result(); r.ErrorCode != hostpatch.CodeBusy {
			t.Fatalf("result = %+v", r)
		}
	})
	t.Run("one lock", func(t *testing.T) {
		e := newStackEnv(t)
		lock, err := lockFile(filepath.Join(e.hs, "private")) // what the ADR 0021 channel holds while it works
		if err != nil {
			t.Fatal(err)
		}
		e.publish(e.applyReq(idA, stack.Headscale))
		done := make(chan struct{})
		go func() {
			_, _ = StackRun(e.cfg)
			close(done)
		}()
		select {
		case <-done:
			t.Fatal("the stack channel ran while the other channel held the lock")
		case <-time.After(200 * time.Millisecond):
		}
		_ = lock.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("the stack channel did not run after the lock was released")
		}
		succeeded(t, e.result())
	})
}

// AC7: the handoff installs only listed kinds for the running request and deletes everything else unread.
func TestStackHandoff_Table(t *testing.T) {
	const other = "99999999-9999-4999-8999-999999999999"
	cases := []struct {
		name     string
		setup    func(e *stackEnv)
		wantOK   bool
		wantKind bool // the oauth2-proxy client secret is installed
	}{
		{"listed kind of the running request", func(e *stackEnv) { e.drop(idA, KindOIDCSecretOAuth2Proxy, canary) }, true, true},
		{"missing drop file", func(e *stackEnv) {}, false, false},
		{"symlink", func(e *stackEnv) {
			e.writeRaw("real", []byte(canary))
			_ = os.Symlink(e.path("real"), e.path("handoff/in", idA+"."+string(KindOIDCSecretOAuth2Proxy)))
		}, false, false},
		{"wrong owner", func(e *stackEnv) {
			e.drop(idA, KindOIDCSecretOAuth2Proxy, canary)
			e.cfg.HandoffUID = uint32(os.Getuid()) + 1
		}, false, false},
		{"oversize", func(e *stackEnv) {
			e.drop(idA, KindOIDCSecretOAuth2Proxy, strings.Repeat("x", MaxHandoffBytes+1))
		}, false, false},
		{"directory instead of a file", func(e *stackEnv) {
			_ = os.Mkdir(e.path("handoff/in", idA+"."+string(KindOIDCSecretOAuth2Proxy)), 0o700)
		}, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newStackEnv(t)
			tc.setup(e)
			r := e.apply(idA, stack.OAuth2Proxy, KindOIDCSecretOAuth2Proxy)
			if tc.wantOK {
				succeeded(t, r)
			} else if r.ErrorCode != StackHandoffFailed {
				t.Fatalf("result = %+v, want handoff_failed", r)
			}
			_, err := os.Stat(filepath.Join(e.stack, "secrets", "oauth2-proxy", "client_secret"))
			if (err == nil) != tc.wantKind {
				t.Errorf("client secret installed = %v, want %v", err == nil, tc.wantKind)
			}
			entries, _ := os.ReadDir(e.path("handoff/in"))
			if len(entries) != 0 {
				t.Errorf("drop files left behind: %v", entries)
			}
			if !tc.wantOK && (e.exists("private/stack-state.json") || e.docker.joined() != "") {
				t.Error("a failed handoff changed the stack")
			}
		})
	}

	t.Run("replay, unlisted kinds and junk are deleted unread", func(t *testing.T) {
		e := newStackEnv(t)
		e.drop(other, KindOIDCSecretOAuth2Proxy, "replayed")        // another request
		e.drop(idA, KindHookSigningKey, "unlisted")                 // not listed by this request
		e.drop(idA, KindOIDCSecretOAuth2Proxy, canary)              // the one real file
		e.writeRaw("handoff/in/not-a-request-file", []byte("junk")) // junk
		succeeded(t, e.apply(idA, stack.OAuth2Proxy, KindOIDCSecretOAuth2Proxy))
		if b, _ := os.ReadFile(filepath.Join(e.stack, "secrets", "oauth2-proxy", "client_secret")); string(b) != canary {
			t.Error("the listed kind was not installed")
		}
		if e.exists("../" + filepath.Base(e.secrets)) {
			t.Error("an unlisted kind was installed")
		}
		if _, err := os.Stat(filepath.Join(e.secrets, string(KindHookSigningKey))); err == nil {
			t.Error("the unlisted hook key was installed")
		}
		if entries, _ := os.ReadDir(e.path("handoff/in")); len(entries) != 0 {
			t.Errorf("drop files left: %v", entries)
		}
	})

	t.Run("a finished request's ID is a replay", func(t *testing.T) {
		e := newStackEnv(t)
		e.drop(idA, KindOIDCSecretOAuth2Proxy, canary)
		succeeded(t, e.apply(idA, stack.OAuth2Proxy, KindOIDCSecretOAuth2Proxy))
		e.drop(idA, KindOIDCSecretOAuth2Proxy, "replayed-value") // the same ID again, after the end
		e.publish(e.applyReq(idB, stack.OAuth2Proxy, KindOIDCSecretOAuth2Proxy))
		e.run()
		if r := e.result(); r.ErrorCode != StackHandoffFailed {
			t.Fatalf("result = %+v", r)
		}
		if b, _ := os.ReadFile(filepath.Join(e.stack, "secrets", "oauth2-proxy", "client_secret")); string(b) != canary {
			t.Error("a replayed file replaced the secret")
		}
		if entries, _ := os.ReadDir(e.path("handoff/in")); len(entries) != 0 {
			t.Errorf("drop files left: %v", entries)
		}
	})

	t.Run("handoff.cleanup", func(t *testing.T) {
		e := newStackEnv(t)
		e.drop(other, KindHookSigningKey, "abandoned")
		e.publish(StackRequest{Version: 1, RequestID: idA, Op: OpHandoffCleanup, TargetID: other})
		e.run()
		succeeded(t, e.result())
		if entries, _ := os.ReadDir(e.path("handoff/in")); len(entries) != 0 {
			t.Errorf("drop files left: %v", entries)
		}
	})
}

// AC8: drop files are deleted when a request ends, at boot, and after 15 minutes.
func TestStackHandoff_Cleanup(t *testing.T) {
	list := func(e *stackEnv) int {
		entries, _ := os.ReadDir(e.path("handoff/in"))
		return len(entries)
	}
	t.Run("request ends, including a failure", func(t *testing.T) {
		e := newStackEnv(t)
		e.drop(idA, KindOIDCSecretOAuth2Proxy, canary)
		e.docker.fail["pull"] = errors.New("down")
		if r := e.apply(idA, stack.OAuth2Proxy, KindOIDCSecretOAuth2Proxy); r.State != hostpatch.StateFailed {
			t.Fatalf("result = %+v", r)
		}
		if list(e) != 0 {
			t.Error("drop files left after a failed request")
		}
	})
	t.Run("killed between drop and install: boot", func(t *testing.T) {
		e := newStackEnv(t)
		e.drop(idA, KindOIDCSecretOAuth2Proxy, canary)
		if err := writeStackJournal(e.path("private"), stackJournal{Version: 1, RequestID: idA, Op: OpStackApply, State: hostpatch.StateAccepted}); err != nil {
			t.Fatal(err)
		}
		out, err := StackBoot(e.cfg)
		if err != nil || out != OutcomeInterrupted {
			t.Fatalf("StackBoot = %s, %v", out, err)
		}
		if list(e) != 0 {
			t.Error("drop file survived the boot")
		}
		r := e.result()
		if r.State != hostpatch.StateInterrupted || r.RequestID != idA || r.Changed == nil || *r.Changed {
			t.Errorf("result = %+v", r)
		}
		if _, err := os.Stat(filepath.Join(e.stack, "secrets")); err == nil {
			t.Error("a secret was installed")
		}
	})
	t.Run("killed mid-request: finalize", func(t *testing.T) {
		e := newStackEnv(t)
		e.drop(idA, KindOIDCSecretOAuth2Proxy, canary)
		if err := writeStackJournal(e.path("private"), stackJournal{Version: 1, RequestID: idA, Op: OpStackApply, State: hostpatch.StateApplying, Phase: StackPhaseWrite}); err != nil {
			t.Fatal(err)
		}
		if out, err := StackFinalize(e.cfg); err != nil || out != OutcomeInterrupted {
			t.Fatalf("StackFinalize = %s, %v", out, err)
		}
		if list(e) != 0 {
			t.Error("drop file survived finalize")
		}
		if r := e.result(); r.State != hostpatch.StateInterrupted || r.Changed != nil {
			t.Errorf("result = %+v", r)
		}
	})
	t.Run("published but never accepted: boot", func(t *testing.T) {
		e := newStackEnv(t)
		e.drop(idA, KindOIDCSecretOAuth2Proxy, canary)
		e.publish(e.applyReq(idA, stack.OAuth2Proxy, KindOIDCSecretOAuth2Proxy))
		if out, err := StackBoot(e.cfg); err != nil || out != OutcomeInterrupted {
			t.Fatalf("StackBoot = %s, %v", out, err)
		}
		if list(e) != 0 || e.exists("requests/request.ready") || e.docker.joined() != "" {
			t.Error("a request published before the boot was not discarded")
		}
	})
	t.Run("after 15 minutes", func(t *testing.T) {
		e := newStackEnv(t)
		e.drop(idA, KindOIDCSecretOAuth2Proxy, canary)
		e.drop(idB, KindHookSigningKey, "fresh")
		old := e.now.Add(-16 * time.Minute)
		if err := os.Chtimes(e.path("handoff/in", idA+"."+string(KindOIDCSecretOAuth2Proxy)), old, old); err != nil {
			t.Fatal(err)
		}
		e.cfg.Now = func() time.Time { return e.now.Add(0) }
		// the fresh file is "now"
		fresh := e.now
		if err := os.Chtimes(e.path("handoff/in", idB+"."+string(KindHookSigningKey)), fresh, fresh); err != nil {
			t.Fatal(err)
		}
		if _, err := StackSweep(e.cfg); err != nil {
			t.Fatal(err)
		}
		entries, _ := os.ReadDir(e.path("handoff/in"))
		if len(entries) != 1 || !strings.HasPrefix(entries[0].Name(), idB) {
			t.Errorf("after the sweep: %v", entries)
		}
		e.now = e.now.Add(16 * time.Minute)
		if _, err := StackSweep(e.cfg); err != nil {
			t.Fatal(err)
		}
		if list(e) != 0 {
			t.Error("a drop file older than 15 minutes survived")
		}
	})
}

// AC9: no secret value in results, journals, logs, state, status, backups or generated files.
func TestStack_CanarySecretNeverLeaks(t *testing.T) {
	e := newStackEnv(t)
	e.drop(idA, KindOIDCSecretHeadscale, canary)
	succeeded(t, e.apply(idA, stack.Headscale, KindOIDCSecretHeadscale))
	e.drop(idB, KindOIDCSecretOAuth2Proxy, canary+"-proxy")
	succeeded(t, e.apply(idB, stack.OAuth2Proxy, KindOIDCSecretOAuth2Proxy))
	e.drop(idC, KindHookSigningKey, canary+"-hook")
	succeeded(t, e.apply(idC, stack.Tagcess, KindHookSigningKey))
	// a failing request with a drop file, too
	e.docker.fail["config"] = errors.New("boom " + canary)
	e.drop("44444444-4444-4444-8444-444444444444", KindHookSigningKey, canary+"-late")
	e.apply("44444444-4444-4444-8444-444444444444", stack.Tagcess, KindHookSigningKey)

	if _, err := StackBoot(e.cfg); err != nil {
		t.Fatal(err)
	}
	secretFiles := map[string]bool{
		filepath.Join(e.stack, "secrets", "headscale", "oidc_client_secret"): true,
		filepath.Join(e.stack, "secrets", "oauth2-proxy", "client_secret"):   true,
		filepath.Join(e.stack, "secrets", "oauth2-proxy", "cookie_secret"):   true,
		filepath.Join(e.secrets, string(KindHookSigningKey)):                 true,
	}
	cookie, _ := os.ReadFile(filepath.Join(e.stack, "secrets", "oauth2-proxy", "cookie_secret"))
	needles := [][]byte{[]byte(canary), cookie}
	scan := func(root string) {
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || secretFiles[p] {
				return nil
			}
			b, _ := os.ReadFile(p) //nolint:gosec // test scan
			for _, n := range needles {
				if bytes.Contains(b, n) {
					t.Errorf("a secret value is in %s", p)
				}
			}
			return nil
		})
	}
	scan(e.root)
	scan(e.stack)
	scan(e.secrets)
	if got := strings.Join(e.logs, "\n"); strings.Contains(got, canary) || bytes.Contains([]byte(got), cookie) {
		t.Error("a secret value is in the logs")
	}
	for _, p := range []string{"private/stack-journal.json", "results/result.json", "results/status.json"} {
		if !e.exists(p) {
			t.Errorf("%s was not written", p)
		}
	}
}

func TestStackOps_RemoveRestartUpgradeDiscoverCleanup(t *testing.T) {
	e := newStackEnv(t)
	succeeded(t, e.apply(idA, stack.Headscale))
	succeeded(t, e.apply(idB, stack.OAuth2Proxy))

	t.Run("restart", func(t *testing.T) {
		e.publish(StackRequest{Version: 1, RequestID: idC, Op: OpServiceRestart, BaseRev: e.rev(), Component: stack.Headscale})
		e.run()
		succeeded(t, e.result())
		if !strings.HasSuffix(e.docker.joined(), "restart:headscale") {
			t.Errorf("calls: %s", e.docker.joined())
		}
	})
	t.Run("restart of a component that is not enabled", func(t *testing.T) {
		e.publish(StackRequest{Version: 1, RequestID: "55555555-5555-4555-8555-555555555555", Op: OpServiceRestart, BaseRev: e.rev(), Component: stack.Caddy})
		e.run()
		if r := e.result(); r.ErrorCode != StackInvalidRequest {
			t.Errorf("result = %+v", r)
		}
	})
	t.Run("remove keeps data and other services", func(t *testing.T) {
		st, _ := readStackState(e.path("private"))
		st.Failed = []stack.Component{stack.OAuth2Proxy}
		if err := writeStackState(e.path("private"), st); err != nil {
			t.Fatal(err)
		}
		hs := e.readStack("headscale/config.yaml")
		e.publish(StackRequest{Version: 1, RequestID: "66666666-6666-4666-8666-666666666666", Op: OpStackRemove, BaseRev: e.rev(), Component: stack.OAuth2Proxy})
		e.run()
		succeeded(t, e.result())
		if !strings.HasSuffix(e.docker.joined(), "rm:oauth2-proxy") {
			t.Errorf("calls: %s", e.docker.joined())
		}
		st, _ = readStackState(e.path("private"))
		if st.enabled(stack.OAuth2Proxy) || !st.enabled(stack.Headscale) {
			t.Errorf("state = %+v", st.Params.Components)
		}
		if strings.Contains(string(e.readStack("compose.yaml")), "oauth2-proxy:") {
			t.Error("compose.yaml still has the service")
		}
		if !bytes.Equal(hs, e.readStack("headscale/config.yaml")) {
			t.Error("headscale config changed")
		}
		if _, err := os.Stat(filepath.Join(e.stack, "secrets", "oauth2-proxy", "cookie_secret")); err != nil {
			t.Error("the removed service's data was deleted")
		}
	})
	t.Run("upgrade moves one image to the manifest of this helper", func(t *testing.T) {
		e.cfg.Manifest = testStackManifest(stackDigUp)
		before := e.readStack("compose.yaml")
		e.publish(StackRequest{Version: 1, RequestID: "77777777-7777-4777-8777-777777777777", Op: OpStackUpgrade, BaseRev: e.rev(), Component: stack.Headscale})
		e.run()
		succeeded(t, e.result())
		after := e.readStack("compose.yaml")
		if bytes.Equal(before, after) || !strings.Contains(string(after), stackDigUp) {
			t.Error("compose.yaml does not carry the new digest")
		}
		st, _ := readStackState(e.path("private"))
		if st.Images[stack.Headscale].Digest != stackDigUp {
			t.Errorf("state digest = %s", st.Images[stack.Headscale].Digest)
		}
		if !strings.HasSuffix(e.docker.joined(), "pull:headscale up:headscale") {
			t.Errorf("calls: %s", e.docker.joined())
		}
	})
	t.Run("discover without a scanner is unsupported", func(t *testing.T) {
		e.publish(StackRequest{Version: 1, RequestID: "88888888-8888-4888-8888-888888888888", Op: OpDiscover})
		e.run()
		if r := e.result(); r.ErrorCode != StackUnsupported {
			t.Errorf("result = %+v", r)
		}
	})
	t.Run("discover with a scanner writes discovery.json", func(t *testing.T) {
		e.cfg.Discover = func() ([]byte, error) { return []byte(`{"findings":[]}`), nil }
		e.publish(StackRequest{Version: 1, RequestID: "12345678-1234-4234-8234-123456789012", Op: OpDiscover})
		e.run()
		succeeded(t, e.result())
		if b, err := os.ReadFile(e.path("results/discovery.json")); err != nil || string(b) != `{"findings":[]}` {
			t.Errorf("discovery.json = %q, %v", b, err)
		}
	})
}

func TestStack_StatusAndDuplicate(t *testing.T) {
	e := newStackEnv(t)
	succeeded(t, e.apply(idA, stack.Headscale))
	b, err := os.ReadFile(e.path("results/status.json"))
	if err != nil {
		t.Fatal(err)
	}
	var s StackStatus
	if err := jsonUnmarshalStrict(b, &s); err != nil {
		t.Fatal(err)
	}
	if s.BaseRev != e.rev() || s.RequestID != idA || s.State != hostpatch.StateSucceeded || s.Release != "v0.0.0-test" {
		t.Errorf("status = %+v", s)
	}
	// The same request ID again is ignored.
	calls := e.docker.joined()
	e.publish(e.applyReq(idA, stack.Headscale))
	if out := e.run(); out != OutcomeDuplicate {
		t.Fatalf("outcome = %s", out)
	}
	if e.docker.joined() != calls {
		t.Error("a duplicate ran")
	}
}

func jsonUnmarshalStrict(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// A failed first Headscale install stays repairable: retry, or remove and add again.
func TestStackApply_FailedHeadscaleInstallRepairable(t *testing.T) {
	e := newStackEnv(t)
	e.docker.fail["up"] = errors.New("no oidc")
	if r := e.apply(idA, stack.Headscale); r.ErrorCode != StackStartFailed {
		t.Fatalf("first install: %+v", r)
	}
	// Retry with changed settings: the unverified config is rendered again.
	req := e.applyReq(idB, stack.Headscale)
	req.Settings.PrefixV4 = "100.100.0.0/16"
	e.docker.fail = map[string]error{}
	e.publish(req)
	e.run()
	succeeded(t, e.result())
	if !bytes.Contains(e.readStack("headscale/config.yaml"), []byte("100.100.0.0/16")) {
		t.Error("config.yaml was not rendered again")
	}

	// Remove and add again, with the config left on disk.
	e2 := newStackEnv(t)
	e2.docker.fail["up"] = errors.New("no oidc")
	e2.apply(idA, stack.Headscale)
	e2.publish(StackRequest{Version: 1, RequestID: idB, Op: OpStackRemove, BaseRev: e2.rev(), Component: stack.Headscale})
	e2.run()
	succeeded(t, e2.result())
	e2.docker.fail = map[string]error{}
	succeeded(t, e2.apply(idC, stack.Headscale))

	// A verified config stays protected.
	req = e2.applyReq("99999999-9999-4999-8999-999999999999", stack.Headscale)
	req.Settings.PrefixV4 = "100.101.0.0/16"
	e2.publish(req)
	e2.run()
	if r := e2.result(); r.ErrorCode != StackSettings {
		t.Errorf("verified config not protected: %+v", r)
	}
}

// A failed restart after the restore is reported, not hidden behind changed=false.
func TestStackApply_RestoreRestartFailureReported(t *testing.T) {
	e := newStackEnv(t)
	succeeded(t, e.apply(idA, stack.Headscale))
	rev := e.rev()
	e.cfg.Manifest = testStackManifest(stackDigUp)
	e.docker.fail["up"] = errors.New("down") // fails for the upgrade and for the restart
	e.publish(StackRequest{Version: 1, RequestID: idB, Op: OpStackUpgrade, BaseRev: rev, Component: stack.Headscale})
	e.run()
	r := e.result()
	if r.ErrorCode != StackServiceDown || r.Changed != nil || r.Service != "down" {
		t.Fatalf("result = %+v", r)
	}
}

// A Failed Headscale that came back (restart) keeps its config.yaml.
func TestStackApply_RestartedFailedHeadscaleConfigProtected(t *testing.T) {
	e := newStackEnv(t)
	e.docker.fail["up"] = errors.New("slow")
	if r := e.apply(idA, stack.Headscale); r.ErrorCode != StackStartFailed {
		t.Fatalf("first install: %+v", r)
	}
	e.docker.fail = map[string]error{}
	e.publish(StackRequest{Version: 1, RequestID: idB, Op: OpServiceRestart, BaseRev: e.rev(), Component: stack.Headscale})
	e.run()
	succeeded(t, e.result())
	req := e.applyReq(idC, stack.Headscale)
	req.Settings.IssuerURL = "https://idp.example.net"
	e.publish(req)
	e.run()
	if r := e.result(); r.ErrorCode != StackSettings {
		t.Errorf("config.yaml rewritten after restart: %+v", r)
	}
	if bytes.Contains(e.readStack("headscale/config.yaml"), []byte("idp.example.net")) {
		t.Error("issuer changed on disk")
	}
}

// Another component's apply while Headscale is Failed must not record settings config.yaml never got.
func TestStackApply_OtherApplyWhileHeadscaleFailedRefused(t *testing.T) {
	e := newStackEnv(t)
	e.docker.fail["up"] = errors.New("no oidc")
	e.apply(idA, stack.Headscale)
	e.docker.fail = map[string]error{}
	req := e.applyReq(idB, stack.OAuth2Proxy)
	req.Settings.PrefixV4 = "100.100.0.0/16"
	e.publish(req)
	e.run()
	if r := e.result(); r.ErrorCode != StackSettings {
		t.Errorf("settings recorded that config.yaml lacks: %+v", r)
	}
}
