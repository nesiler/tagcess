// Package hsstack is the shared fixture for F3 integration tests that write a policy or manage
// nodes and keys: a throwaway Headscale v0.29.4 in policy database mode, reachable over loopback
// gRPC through a socat relay to its unix socket (Headscale's TCP gRPC would demand an API key; the
// unix socket is the unauthenticated admin surface production uses too, stack-notes).
//
// The shared compose Headscale runs in policy file mode (SetPolicy is refused there), so every test
// that writes a policy gets its own fixture from Start. Ports are free ports and container/volume
// names are unique, so parallel fixtures and parallel worktree runs do not collide. There is no
// Zitadel here: OIDC users are created directly and their provider identifier is patched into the
// SQLite file on a host bind mount (Headscale has no CLI/gRPC for it; F1-005/F1-021 did the same).
//
// The fixture is modeled after F2's test/compose/f2: helpers take *testing.T and fail the test.
package hsstack

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tailscale/hujson"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"

	"github.com/nesiler/tagcess/internal/headscale"

	_ "modernc.org/sqlite" // the "sqlite" driver for the provider identifier patch
)

// The images the fixture pins (F1-021, .agents/skills/stack-notes). Image is the compose pin.
const (
	Image      = "headscale/headscale:0.29.4"
	RelayImage = "alpine/socat:1.8.0.3"
)

// BaselinePolicy is the policy Start applies so the fixture is never in the "no policy" state and
// every test can watch a concrete groups section change.
const BaselinePolicy = `{
  "tagOwners": {"tag:server": ["group:devops"]},
  "groups": {"group:devops": []},
  "acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
}`

var fixtureSeq atomic.Uint64

// Stack is one running disposable Headscale. Use Start.
type Stack struct {
	name     string
	relay    string
	volume   string
	dir      string
	grpcAddr string
	httpAddr string
	client   *headscale.Client
	conn     *grpc.ClientConn
	api      v1.HeadscaleServiceClient
}

// Start runs one disposable database-mode Headscale plus its unix-socket relay and waits until it
// is healthy and has accepted BaselinePolicy. Containers, the relay, the volume and the temp
// directory are removed when the test ends.
func Start(t *testing.T) *Stack {
	t.Helper()
	dir, err := os.MkdirTemp("", "tagcess-hsstack-")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.MkdirAll(filepath.Join(dir, "data"), 0o750); err != nil {
		t.Fatal(err)
	}
	seq := fixtureSeq.Add(1)
	name := fmt.Sprintf("tagcess-hsstack-%d-%d", time.Now().UnixNano(), seq%1000)
	// Free ports for everything the container binds on the host network and for the relay, so two
	// fixtures (or a parallel worktree run) never collide.
	httpPort, grpcPort, metricsPort, relayPort := freePort(t), freePort(t), freePort(t), freePort(t)
	h := &Stack{
		name:     name,
		relay:    name + "-relay",
		volume:   name + "-run",
		dir:      dir,
		grpcAddr: net.JoinHostPort("127.0.0.1", strconv.Itoa(relayPort)),
		httpAddr: net.JoinHostPort("127.0.0.1", strconv.Itoa(httpPort)),
	}
	// A leftover container/volume from an interrupted run would make `docker run` fail on the name.
	// The names are fixture-generated (tagcess-hsstack-<nanos>-<seq>), not user input.
	_ = exec.CommandContext(context.Background(), "docker", "rm", "-f", name).Run()                                                 //nolint:gosec // fixture-generated name
	_ = exec.CommandContext(context.Background(), "docker", "rm", "-f", h.relay).Run()                                              //nolint:gosec // fixture-generated name
	_ = exec.CommandContext(context.Background(), "docker", "volume", "rm", h.volume).Run()                                         //nolint:gosec // fixture-generated name
	if out, err := exec.CommandContext(context.Background(), "docker", "volume", "create", h.volume).CombinedOutput(); err != nil { //nolint:gosec // fixture-generated name
		t.Fatalf("docker volume create: %v: %s", err, out)
	}

	cfg := fmt.Sprintf(`server_url: http://localhost:%d
listen_addr: 127.0.0.1:%d
metrics_listen_addr: 127.0.0.1:%d
grpc_listen_addr: 127.0.0.1:%d
grpc_allow_insecure: true
noise:
  private_key_path: /var/lib/headscale/noise_private.key
prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
  allocation: sequential
derp:
  server:
    enabled: false
  urls:
    - https://controlplane.tailscale.com/derpmap/default
  paths: []
  auto_update_enabled: false
disable_check_updates: true
database:
  type: sqlite
  sqlite:
    path: /var/lib/headscale/db.sqlite
    write_ahead_log: true
policy:
  mode: database
dns:
  magic_dns: true
  base_domain: ts.tagcess.test
  override_local_dns: false
  nameservers:
    global:
      - 1.1.1.1
unix_socket: /var/run/headscale/headscale.sock
unix_socket_permission: "0770"
log:
  level: info
  format: text
`, httpPort, httpPort, metricsPort, grpcPort)
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_ = exec.CommandContext(context.Background(), "docker", "rm", "-f", name).Run()         //nolint:gosec // fixture-generated name
		_ = exec.CommandContext(context.Background(), "docker", "rm", "-f", h.relay).Run()      //nolint:gosec // fixture-generated name
		_ = exec.CommandContext(context.Background(), "docker", "volume", "rm", h.volume).Run() //nolint:gosec // fixture-generated name
	})
	h.run(t)

	relayArgs := []string{
		"run", "-d", "--name", h.relay,
		"-v", h.volume + ":/run/hs", "-p", "127.0.0.1:" + strconv.Itoa(relayPort) + ":50456",
		RelayImage, "TCP-LISTEN:50456,fork,reuseaddr", "UNIX-CONNECT:/run/hs/headscale.sock",
	}
	//nolint:gosec // fixture-generated name
	if out, err := exec.CommandContext(context.Background(), "docker", relayArgs...).CombinedOutput(); err != nil {
		t.Fatalf("docker run headscale relay: %v: %s", err, out)
	}

	client, err := headscale.New(headscale.Config{Target: h.grpcAddr, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("headscale client: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	h.client = client

	conn, err := grpc.NewClient(h.grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial headscale: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	h.conn = conn
	h.api = v1.NewHeadscaleServiceClient(conn)

	ctx := context.Background()
	if err := poll(t, 15*time.Second, func() (bool, error) {
		_, err := client.SetPolicy(ctx, BaselinePolicy)
		return err == nil, err
	}); err != nil {
		logs, _ := exec.CommandContext(context.Background(), "docker", "logs", h.relay).CombinedOutput() //nolint:gosec // fixture-generated name
		t.Fatalf("headscale relay not usable: %v: %s", err, logs)
	}
	return h
}

// GRPCAddr is the loopback "host:port" of the socat relay; it is what the narrow client, the raw
// client and a tagcess binary under test dial.
func (h *Stack) GRPCAddr() string { return h.grpcAddr }

// Client is the narrow F1 Headscale client (the one tagcess itself uses).
func (h *Stack) Client() *headscale.Client { return h.client }

// Raw is the unauthenticated admin gRPC client, for verifying RPCs that must stay out of the
// narrow client (device, key and route operations, F3-004).
func (h *Stack) Raw() v1.HeadscaleServiceClient { return h.api }

func (h *Stack) run(t *testing.T) {
	t.Helper()
	// A stopped container still holds its name; remove it so a restart after a DB patch can reuse it.
	_ = exec.CommandContext(context.Background(), "docker", "rm", "-f", h.name).Run() //nolint:gosec // fixture-generated name
	args := []string{
		"run", "-d", "--name", h.name, "--network", "host",
		"-v", filepath.Join(h.dir, "config.yaml") + ":/etc/headscale/config.yaml:ro",
		"-v", filepath.Join(h.dir, "data") + ":/var/lib/headscale",
		"-v", h.volume + ":/var/run/headscale",
		Image, "serve",
	}
	if out, err := exec.CommandContext(context.Background(), "docker", args...).CombinedOutput(); err != nil { //nolint:gosec // fixture-generated name and temp paths, no user input
		t.Fatalf("docker run headscale: %v: %s", err, out)
	}
	h.waitHealthy(t)
}

// Stop stops the Headscale container; its data stays, so Restart brings the same state back. The relay
// keeps running, so calls fail with a connection error while Headscale is down.
func (h *Stack) Stop(t *testing.T) {
	t.Helper()
	if out, err := exec.CommandContext(context.Background(), "docker", "stop", h.name).CombinedOutput(); err != nil { //nolint:gosec // fixture-generated name
		t.Fatalf("docker stop headscale: %v: %s", err, out)
	}
}

// Restart starts a container stopped by Stop and waits until it is healthy.
func (h *Stack) Restart(t *testing.T) {
	t.Helper()
	if out, err := exec.CommandContext(context.Background(), "docker", "start", h.name).CombinedOutput(); err != nil { //nolint:gosec // fixture-generated name
		t.Fatalf("docker start headscale: %v: %s", err, out)
	}
	h.waitHealthy(t)
	// The unix socket behind the relay comes up a moment after /health: wait until gRPC answers.
	if err := poll(t, 15*time.Second, func() (bool, error) {
		_, err := h.client.GetPolicy(context.Background())
		return err == nil, err
	}); err != nil {
		t.Fatalf("headscale gRPC not usable after the restart: %v", err)
	}
}

// waitHealthy polls /health until Headscale answers 200 or fails the test.
func (h *Stack) waitHealthy(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+h.httpAddr+"/health", nil)
		if err == nil {
			resp, err := (&http.Client{Timeout: 2 * time.Second}).Do(req)
			if err == nil {
				_ = resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					return
				}
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	logs, _ := exec.CommandContext(context.Background(), "docker", "logs", h.name).CombinedOutput() //nolint:gosec // fixture-generated name
	t.Fatalf("headscale did not become healthy: %s", logs)
}

// CreateUser creates a Headscale user and returns its id.
func (h *Stack) CreateUser(t *testing.T, name string) uint64 {
	t.Helper()
	resp, err := h.api.CreateUser(context.Background(), &v1.CreateUserRequest{Name: name})
	if err != nil {
		t.Fatalf("CreateUser %s: %v", name, err)
	}
	return resp.GetUser().GetId()
}

// SetProviderID stops Headscale, writes the user's provider identifier directly into its SQLite
// file (there is no CLI/gRPC for it) and starts it again.
func (h *Stack) SetProviderID(t *testing.T, name, providerID string) {
	t.Helper()
	if out, err := exec.CommandContext(context.Background(), "docker", "stop", h.name).CombinedOutput(); err != nil { //nolint:gosec // fixture-generated name
		t.Fatalf("docker stop: %v: %s", err, out)
	}
	db, err := sql.Open("sqlite", filepath.Join(h.dir, "data", "db.sqlite"))
	if err != nil {
		t.Fatalf("open headscale db: %v", err)
	}
	if _, err := db.ExecContext(context.Background(), `UPDATE users SET provider = 'oidc', provider_identifier = ? WHERE name = ?`, providerID, name); err != nil {
		_ = db.Close()
		t.Fatalf("patch provider id: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close headscale db: %v", err)
	}
	h.run(t)
}

// SetNodeRoutableIPs stops Headscale, patches the node's hostinfo RoutableIPs directly in its
// SQLite file (a DebugCreateNode node announces no routes; the RPC's routes field only fills the
// echo response) and starts it again — the same stop-patch-start method as SetProviderID
// (F1-005). Headscale derives available_routes from hostinfo at read time.
func (h *Stack) SetNodeRoutableIPs(t *testing.T, nodeName string, prefixes []string) {
	t.Helper()
	if out, err := exec.CommandContext(context.Background(), "docker", "stop", h.name).CombinedOutput(); err != nil { //nolint:gosec // fixture-generated name
		t.Fatalf("docker stop: %v: %s", err, out)
	}
	db, err := sql.Open("sqlite", filepath.Join(h.dir, "data", "db.sqlite"))
	if err != nil {
		t.Fatalf("open headscale db: %v", err)
	}
	defer func() { _ = db.Close() }()
	var info sql.NullString
	err = db.QueryRowContext(context.Background(), `SELECT host_info FROM nodes WHERE hostname = ? OR given_name = ?`, nodeName, nodeName).Scan(&info)
	if err != nil {
		t.Fatalf("read host_info of %s: %v", nodeName, err)
	}
	hostinfo := map[string]any{}
	if info.Valid && strings.TrimSpace(info.String) != "" {
		if err := json.Unmarshal([]byte(info.String), &hostinfo); err != nil {
			t.Fatalf("parse host_info: %v", err)
		}
	}
	hostinfo["RoutableIPs"] = prefixes
	patched, err := json.Marshal(hostinfo)
	if err != nil {
		t.Fatalf("marshal host_info: %v", err)
	}
	if _, err := db.ExecContext(context.Background(), `UPDATE nodes SET host_info = ? WHERE hostname = ? OR given_name = ?`, string(patched), nodeName, nodeName); err != nil {
		t.Fatalf("patch host_info: %v", err)
	}
	h.run(t)
}

// NewNode registers a throwaway node under a Headscale user, optionally tagged.
func (h *Stack) NewNode(t *testing.T, userName, name, tag string) uint64 {
	t.Helper()
	ctx := context.Background()
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	key := "hskey-authreq-" + fmt.Sprintf("%x", buf)
	if _, err := h.api.DebugCreateNode(ctx, &v1.DebugCreateNodeRequest{User: userName, Key: key, Name: name}); err != nil {
		t.Fatalf("DebugCreateNode: %v", err)
	}
	resp, err := h.api.RegisterNode(ctx, &v1.RegisterNodeRequest{User: userName, Key: key})
	if err != nil {
		t.Fatalf("RegisterNode: %v", err)
	}
	id := resp.GetNode().GetId()
	if tag != "" {
		if _, err := h.api.SetTags(ctx, &v1.SetTagsRequest{NodeId: id, Tags: []string{tag}}); err != nil {
			t.Fatalf("SetTags: %v", err)
		}
	}
	t.Cleanup(func() { _, _ = h.api.DeleteNode(context.Background(), &v1.DeleteNodeRequest{NodeId: id}) })
	return id
}

// PreAuthKeyOptions varies PreAuthKey.
type PreAuthKeyOptions struct {
	Reusable   bool
	Ephemeral  bool
	Expiration time.Duration // 0 means the key never expires
	// Tags are the ACL tags assigned to nodes registered with the key (the shared-device flow).
	Tags []string
}

// PreAuthKey creates a pre-auth key for a Headscale user and returns its one-time plaintext value
// (Headscale masks it in every later listing).
func (h *Stack) PreAuthKey(t *testing.T, userName string, opts PreAuthKeyOptions) string {
	t.Helper()
	users, err := h.client.ListUsers(context.Background())
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	var id uint64
	for _, u := range users {
		if u.Name == userName {
			id = u.ID
			break
		}
	}
	if id == 0 {
		t.Fatalf("PreAuthKey: user %q not found", userName)
	}
	req := &v1.CreatePreAuthKeyRequest{User: id, Reusable: opts.Reusable, Ephemeral: opts.Ephemeral, AclTags: opts.Tags}
	if opts.Expiration > 0 {
		req.Expiration = timestamppb.New(time.Now().Add(opts.Expiration))
	}
	resp, err := h.api.CreatePreAuthKey(context.Background(), req)
	if err != nil {
		t.Fatalf("CreatePreAuthKey %s: %v", userName, err)
	}
	return resp.GetPreAuthKey().GetKey()
}

// PolicyGroups returns the current groups section of the disposable Headscale policy.
func (h *Stack) PolicyGroups(t *testing.T) map[string][]string {
	t.Helper()
	p, err := h.client.GetPolicy(context.Background())
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	return ParsePolicyGroups(t, p.Text)
}

// NodeExpiry returns the node's expiry, nil when it has none.
func (h *Stack) NodeExpiry(t *testing.T, id uint64) *time.Time {
	t.Helper()
	nodes, err := h.client.ListNodes(context.Background())
	if err != nil {
		t.Fatalf("ListNodes: %v", err)
	}
	for _, n := range nodes {
		if n.ID == id {
			return n.Expiry
		}
	}
	t.Fatalf("node %d not found", id)
	return nil
}

// ParsePolicyGroups returns the groups section of a policy text.
func ParsePolicyGroups(t *testing.T, text string) map[string][]string {
	t.Helper()
	root, err := hujson.Parse([]byte(text))
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

func freePort(t *testing.T) int {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().(*net.TCPAddr).Port
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
