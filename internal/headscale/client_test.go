package headscale

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
)

// fakeServer records which RPCs were called and answers from canned values.
type fakeServer struct {
	v1.UnimplementedHeadscaleServiceServer
	mu    sync.Mutex
	calls []string

	checkErr   error
	expiryResp func(req *v1.ExpireNodeRequest) *v1.Node
}

func (f *fakeServer) record(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, name)
}

func (f *fakeServer) called() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *fakeServer) GetPolicy(context.Context, *v1.GetPolicyRequest) (*v1.GetPolicyResponse, error) {
	f.record("GetPolicy")
	return &v1.GetPolicyResponse{Policy: `{"acls":[]}`, UpdatedAt: timestamppb.New(time.Unix(1700000000, 0))}, nil
}

func (f *fakeServer) CheckPolicy(context.Context, *v1.CheckPolicyRequest) (*v1.CheckPolicyResponse, error) {
	f.record("CheckPolicy")
	if f.checkErr != nil {
		return nil, f.checkErr
	}
	return &v1.CheckPolicyResponse{}, nil
}

func (f *fakeServer) SetPolicy(_ context.Context, r *v1.SetPolicyRequest) (*v1.SetPolicyResponse, error) {
	f.record("SetPolicy")
	return &v1.SetPolicyResponse{Policy: r.GetPolicy(), UpdatedAt: timestamppb.New(time.Unix(1700000001, 0))}, nil
}

func (f *fakeServer) ListUsers(context.Context, *v1.ListUsersRequest) (*v1.ListUsersResponse, error) {
	f.record("ListUsers")
	return &v1.ListUsersResponse{Users: []*v1.User{
		{Id: 1, Name: "alice", DisplayName: "Alice", Email: "alice@example.com", ProviderId: "https://idp/1", Provider: "oidc"},
	}}, nil
}

func (f *fakeServer) ListNodes(context.Context, *v1.ListNodesRequest) (*v1.ListNodesResponse, error) {
	f.record("ListNodes")
	return &v1.ListNodesResponse{Nodes: []*v1.Node{
		{Id: 7, Name: "laptop", GivenName: "laptop", User: &v1.User{Id: 1, Name: "alice"}, IpAddresses: []string{"100.64.0.1"}, Online: true},
		{Id: 8, Name: "srv", Tags: []string{"tag:vpn-server"}, Expiry: timestamppb.New(time.Unix(1700000000, 0))},
	}}, nil
}

func (f *fakeServer) ExpireNode(_ context.Context, r *v1.ExpireNodeRequest) (*v1.ExpireNodeResponse, error) {
	f.record("ExpireNode")
	if f.expiryResp != nil {
		return &v1.ExpireNodeResponse{Node: f.expiryResp(r)}, nil
	}
	return &v1.ExpireNodeResponse{Node: &v1.Node{Id: r.GetNodeId(), Expiry: r.GetExpiry()}}, nil
}

// serve starts srv on a fresh unix socket and returns the client target. The path is kept short:
// macOS limits unix socket paths to about 100 bytes.
func serve(t *testing.T, srv v1.HeadscaleServiceServer) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "hs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s.sock")
	lis, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer()
	v1.RegisterHeadscaleServiceServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	return "unix://" + sock
}

func newClient(t *testing.T, target string, timeout time.Duration) *Client {
	t.Helper()
	c, err := New(Config{Target: target, Timeout: timeout})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// TestHeadscale_ReadUnit covers the read mapping of AC1 against a fake server on a real unix socket.
func TestHeadscale_ReadUnit(t *testing.T) {
	c := newClient(t, serve(t, &fakeServer{}), time.Second)
	ctx := context.Background()

	p, err := c.GetPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if p.Text != `{"acls":[]}` || !p.UpdatedAt.Equal(time.Unix(1700000000, 0)) {
		t.Errorf("policy = %+v", p)
	}
	users, err := c.ListUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 || users[0].ID != 1 || users[0].Email != "alice@example.com" || users[0].ProviderID != "https://idp/1" {
		t.Errorf("users = %+v", users)
	}
	nodes, err := c.ListNodes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 || nodes[0].UserName != "alice" || !nodes[0].Online || nodes[0].Expiry != nil {
		t.Errorf("nodes[0] = %+v", nodes[0])
	}
	if nodes[1].UserID != 0 || len(nodes[1].Tags) != 1 || nodes[1].Expiry == nil {
		t.Errorf("nodes[1] = %+v", nodes[1])
	}
}

// TestHeadscale_SetPolicyChecksFirst is the unit half of AC2: a rejected policy never reaches
// SetPolicy, and the rejection carries Headscale's message.
func TestHeadscale_SetPolicyChecksFirst(t *testing.T) {
	f := &fakeServer{checkErr: status.Error(codes.InvalidArgument, `unknown field "aclz"`)}
	c := newClient(t, serve(t, f), time.Second)

	_, err := c.SetPolicy(context.Background(), `{"aclz":[]}`)
	var pe *PolicyError
	if !errors.As(err, &pe) {
		t.Fatalf("err = %v, want *PolicyError", err)
	}
	if !strings.Contains(pe.Message, `unknown field "aclz"`) {
		t.Errorf("message = %q", pe.Message)
	}
	for _, name := range f.called() {
		if name == "SetPolicy" {
			t.Fatalf("SetPolicy was called after a failed check: %v", f.called())
		}
	}

	// A valid policy goes through check, then set, in that order.
	f.checkErr = nil
	if _, err := c.SetPolicy(context.Background(), `{"acls":[]}`); err != nil {
		t.Fatal(err)
	}
	got := f.called()
	if len(got) < 2 || got[len(got)-2] != "CheckPolicy" || got[len(got)-1] != "SetPolicy" {
		t.Errorf("call order = %v", got)
	}
}

// TestHeadscale_CheckPolicyTransportErrorIsNotRejection: an unreachable server is not "policy
// invalid"; callers must be able to tell the two apart (both keep the last good state, but only
// one is the developer's mistake).
func TestHeadscale_CheckPolicyTransportErrorIsNotRejection(t *testing.T) {
	f := &fakeServer{checkErr: status.Error(codes.Internal, "database is locked")}
	c := newClient(t, serve(t, f), time.Second)
	err := c.CheckPolicy(context.Background(), `{}`)
	if err == nil {
		t.Fatal("want an error")
	}
	var pe *PolicyError
	if errors.As(err, &pe) {
		t.Errorf("Internal error reported as a policy rejection: %v", err)
	}
}

// TestHeadscale_ExpireNodeUnit is the unit half of AC3.
func TestHeadscale_ExpireNodeUnit(t *testing.T) {
	ctx := context.Background()
	t.Run("expiry in the past is confirmed", func(t *testing.T) {
		c := newClient(t, serve(t, &fakeServer{}), time.Second)
		n, err := c.ExpireNode(ctx, 7)
		if err != nil {
			t.Fatal(err)
		}
		if n.Expiry == nil || n.Expiry.After(time.Now()) {
			t.Errorf("expiry = %v", n.Expiry)
		}
	})
	t.Run("server that leaves the expiry in the future is an error", func(t *testing.T) {
		f := &fakeServer{expiryResp: func(r *v1.ExpireNodeRequest) *v1.Node {
			return &v1.Node{Id: r.GetNodeId(), Expiry: timestamppb.New(time.Now().Add(time.Hour))}
		}}
		c := newClient(t, serve(t, f), time.Second)
		if _, err := c.ExpireNode(ctx, 7); err == nil {
			t.Fatal("want an error")
		}
	})
	t.Run("server that returns no expiry is an error", func(t *testing.T) {
		f := &fakeServer{expiryResp: func(r *v1.ExpireNodeRequest) *v1.Node { return &v1.Node{Id: r.GetNodeId()} }}
		c := newClient(t, serve(t, f), time.Second)
		if _, err := c.ExpireNode(ctx, 7); err == nil {
			t.Fatal("want an error")
		}
	})
	t.Run("server that answers for another node is an error", func(t *testing.T) {
		f := &fakeServer{expiryResp: func(*v1.ExpireNodeRequest) *v1.Node {
			return &v1.Node{Id: 99, Expiry: timestamppb.New(time.Unix(1, 0))}
		}}
		c := newClient(t, serve(t, f), time.Second)
		if _, err := c.ExpireNode(ctx, 7); err == nil {
			t.Fatal("want an error")
		}
	})
	t.Run("node id 0 is refused before any call", func(t *testing.T) {
		f := &fakeServer{}
		c := newClient(t, serve(t, f), time.Second)
		if _, err := c.ExpireNode(ctx, 0); err == nil {
			t.Fatal("want an error")
		}
		if len(f.called()) != 0 {
			t.Errorf("calls = %v", f.called())
		}
	})
}

// TestHeadscale_ExportedSurface is AC4: the package exposes exactly the listed operations. The
// method set is pinned, so adding any RPC (delete, user create, keys, routes) fails this test and
// has to be a conscious change; the source never names a forbidden RPC.
func TestHeadscale_ExportedSurface(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var methods, funcs []string
	forbidden := []string{
		"DeleteNode", "CreateUser", "DeleteUser", "RenameUser", "RenameNode", "SetTags", "SetApprovedRoutes",
		"CreatePreAuthKey", "ExpirePreAuthKey", "DeletePreAuthKey", "CreateApiKey", "ExpireApiKey", "DeleteApiKey",
		"RegisterNode", "DebugCreateNode", "BackfillNodeIPs", "AuthApprove", "AuthReject", "AuthRegister",
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, rpc := range forbidden {
			if strings.Contains(string(src), rpc) {
				t.Errorf("%s names forbidden RPC %s", name, rpc)
			}
		}
		f, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || !fd.Name.IsExported() {
				continue
			}
			if fd.Recv == nil {
				funcs = append(funcs, fd.Name.Name)
				continue
			}
			// Any receiver counts, pointer or value, on any type of the package.
			typ := fd.Recv.List[0].Type
			if star, ok := typ.(*ast.StarExpr); ok {
				typ = star.X
			}
			if id, ok := typ.(*ast.Ident); ok {
				methods = append(methods, id.Name+"."+fd.Name.Name)
			}
		}
	}
	sort.Strings(methods)
	wantMethods := []string{"Client.CheckPolicy", "Client.Close", "Client.ExpireNode", "Client.GetPolicy", "Client.ListNodes", "Client.ListUsers", "Client.SetPolicy", "PolicyError.Error"}
	if strings.Join(methods, ",") != strings.Join(wantMethods, ",") {
		t.Errorf("exported methods = %v, want %v", methods, wantMethods)
	}
	sort.Strings(funcs)
	if strings.Join(funcs, ",") != "New" {
		t.Errorf("exported functions = %v, want [New]", funcs)
	}
}

// TestHeadscale_Timeout is AC5: an unreachable socket, and a socket whose server never answers,
// both return an error quickly instead of hanging.
func TestHeadscale_Timeout(t *testing.T) {
	t.Run("nothing listens", func(t *testing.T) {
		dir, _ := os.MkdirTemp("", "hs")
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		c := newClient(t, "unix://"+filepath.Join(dir, "missing.sock"), 300*time.Millisecond)
		start := time.Now()
		if _, err := c.ListUsers(context.Background()); err == nil {
			t.Fatal("want an error")
		}
		if d := time.Since(start); d > 3*time.Second {
			t.Errorf("took %v", d)
		}
	})
	t.Run("server accepts and never answers", func(t *testing.T) {
		dir, _ := os.MkdirTemp("", "hs")
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		sock := filepath.Join(dir, "s.sock")
		lis, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		t.Cleanup(func() { close(done); _ = lis.Close() })
		go func() {
			for {
				conn, err := lis.Accept()
				if err != nil {
					return
				}
				go func() { <-done; _ = conn.Close() }()
			}
		}()
		c := newClient(t, "unix://"+sock, 300*time.Millisecond)
		start := time.Now()
		_, err = c.GetPolicy(context.Background())
		if err == nil {
			t.Fatal("want an error")
		}
		if d := time.Since(start); d > 3*time.Second {
			t.Errorf("took %v", d)
		}
		if code := status.Code(errors.Unwrap(err)); code != codes.DeadlineExceeded {
			t.Errorf("error = %v, code %v, want DeadlineExceeded", err, code)
		}
	})
	t.Run("caller deadline shorter than the default wins", func(t *testing.T) {
		c := newClient(t, "unix:///nonexistent/s.sock", 30*time.Second)
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		start := time.Now()
		if _, err := c.ListNodes(ctx); err == nil {
			t.Fatal("want an error")
		}
		if d := time.Since(start); d > 3*time.Second {
			t.Errorf("took %v", d)
		}
	})
}

func TestHeadscale_ConfigValidation(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("empty target accepted")
	}
	for _, bad := range []string{"headscale.example.com:50443", "10.0.0.5:50443", "dns:///hs.example.com:443", "hs:50443", "127.0.0.1"} {
		if _, err := New(Config{Target: bad}); err == nil {
			t.Errorf("target %q accepted; only unix sockets and loopback are allowed", bad)
		}
	}
	for _, good := range []string{"/run/headscale/headscale.sock", "unix:///run/x.sock", "127.0.0.1:50444", "[::1]:50444", "localhost:50444"} {
		c, err := New(Config{Target: good})
		if err != nil {
			t.Errorf("target %q rejected: %v", good, err)
			continue
		}
		_ = c.Close()
	}
	c, err := New(Config{Target: "unix:///x.sock"})
	if err != nil {
		t.Fatal(err)
	}
	if c.timeout <= 0 {
		t.Errorf("default timeout = %v", c.timeout)
	}
	_ = c.Close()
}

// E1: after Headscale restarts (the socket file is recreated), the same client recovers on its own.
func TestHeadscale_RedialsAfterServerRestart(t *testing.T) {
	dir, err := os.MkdirTemp("", "hs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s.sock")
	start := func() *grpc.Server {
		lis, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		gs := grpc.NewServer()
		v1.RegisterHeadscaleServiceServer(gs, &fakeServer{})
		go func() { _ = gs.Serve(lis) }()
		return gs
	}
	gs := start()
	t.Cleanup(func() { gs.Stop() })
	c := newClient(t, "unix://"+sock, time.Second)
	if _, err := c.GetPolicy(context.Background()); err != nil {
		t.Fatalf("first call: %v", err)
	}

	gs.Stop()
	_ = os.Remove(sock)
	if _, err := c.GetPolicy(context.Background()); err == nil {
		t.Fatal("call succeeded while the server was down")
	}
	gs = start()
	deadline := time.Now().Add(15 * time.Second)
	for {
		_, err := c.GetPolicy(context.Background())
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("client did not recover after the restart: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
