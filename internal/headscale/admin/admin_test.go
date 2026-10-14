package admin

import (
	"context"
	"encoding/json"
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

	"github.com/nesiler/tagcess/internal/headscale"
)

// fakeServer records every RPC (name and raw request) and answers from canned values.
type fakeServer struct {
	v1.UnimplementedHeadscaleServiceServer

	mu      sync.Mutex
	calls   []string
	request []any

	err    error            // when set, every recorded RPC fails with it
	failOn map[string]bool  // which RPC names fail
	nodes  []*v1.Node       // ListNodes answer
	keys   []*v1.PreAuthKey // ListPreAuthKeys answer
	api    []*v1.ApiKey     // ListApiKeys answer
}

func (f *fakeServer) record(name string, req any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, name)
	f.request = append(f.request, req)
	if f.failOn[name] || f.err != nil {
		if f.err != nil {
			return f.err
		}
		return status.Error(codes.Internal, "injected failure")
	}
	return nil
}

func (f *fakeServer) called() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *fakeServer) requests() []any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]any(nil), f.request...)
}

func (f *fakeServer) RenameNode(_ context.Context, r *v1.RenameNodeRequest) (*v1.RenameNodeResponse, error) {
	if err := f.record("RenameNode", r); err != nil {
		return nil, err
	}
	return &v1.RenameNodeResponse{Node: &v1.Node{Id: r.GetNodeId(), Name: r.GetNewName(), GivenName: r.GetNewName()}}, nil
}

func (f *fakeServer) DeleteNode(_ context.Context, r *v1.DeleteNodeRequest) (*v1.DeleteNodeResponse, error) {
	if err := f.record("DeleteNode", r); err != nil {
		return nil, err
	}
	return &v1.DeleteNodeResponse{}, nil
}

func (f *fakeServer) ExpireNode(_ context.Context, r *v1.ExpireNodeRequest) (*v1.ExpireNodeResponse, error) {
	if err := f.record("ExpireNode", r); err != nil {
		return nil, err
	}
	n := &v1.Node{Id: r.GetNodeId()}
	if r.GetDisableExpiry() {
		n.Expiry = nil
	} else {
		n.Expiry = r.GetExpiry()
	}
	return &v1.ExpireNodeResponse{Node: n}, nil
}

func (f *fakeServer) SetTags(_ context.Context, r *v1.SetTagsRequest) (*v1.SetTagsResponse, error) {
	if err := f.record("SetTags", r); err != nil {
		return nil, err
	}
	return &v1.SetTagsResponse{Node: &v1.Node{Id: r.GetNodeId(), Tags: r.GetTags()}}, nil
}

func (f *fakeServer) SetApprovedRoutes(_ context.Context, r *v1.SetApprovedRoutesRequest) (*v1.SetApprovedRoutesResponse, error) {
	if err := f.record("SetApprovedRoutes", r); err != nil {
		return nil, err
	}
	return &v1.SetApprovedRoutesResponse{Node: &v1.Node{Id: r.GetNodeId(), ApprovedRoutes: r.GetRoutes()}}, nil
}

func (f *fakeServer) ListNodes(_ context.Context, r *v1.ListNodesRequest) (*v1.ListNodesResponse, error) {
	if err := f.record("ListNodes", r); err != nil {
		return nil, err
	}
	return &v1.ListNodesResponse{Nodes: f.nodes}, nil
}

func (f *fakeServer) CreatePreAuthKey(_ context.Context, r *v1.CreatePreAuthKeyRequest) (*v1.CreatePreAuthKeyResponse, error) {
	if err := f.record("CreatePreAuthKey", r); err != nil {
		return nil, err
	}
	return &v1.CreatePreAuthKeyResponse{PreAuthKey: &v1.PreAuthKey{
		Id: 11, User: &v1.User{Id: r.GetUser()}, Key: "hskey-auth-created0123456789ab",
		Reusable: r.GetReusable(), Ephemeral: r.GetEphemeral(), Expiration: r.GetExpiration(), AclTags: r.GetAclTags(),
	}}, nil
}

func (f *fakeServer) ListPreAuthKeys(_ context.Context, r *v1.ListPreAuthKeysRequest) (*v1.ListPreAuthKeysResponse, error) {
	if err := f.record("ListPreAuthKeys", r); err != nil {
		return nil, err
	}
	return &v1.ListPreAuthKeysResponse{PreAuthKeys: f.keys}, nil
}

func (f *fakeServer) ExpirePreAuthKey(_ context.Context, r *v1.ExpirePreAuthKeyRequest) (*v1.ExpirePreAuthKeyResponse, error) {
	if err := f.record("ExpirePreAuthKey", r); err != nil {
		return nil, err
	}
	return &v1.ExpirePreAuthKeyResponse{}, nil
}

func (f *fakeServer) DeletePreAuthKey(_ context.Context, r *v1.DeletePreAuthKeyRequest) (*v1.DeletePreAuthKeyResponse, error) {
	if err := f.record("DeletePreAuthKey", r); err != nil {
		return nil, err
	}
	return &v1.DeletePreAuthKeyResponse{}, nil
}

func (f *fakeServer) ListApiKeys(_ context.Context, r *v1.ListApiKeysRequest) (*v1.ListApiKeysResponse, error) {
	if err := f.record("ListApiKeys", r); err != nil {
		return nil, err
	}
	return &v1.ListApiKeysResponse{ApiKeys: f.api}, nil
}

func (f *fakeServer) ExpireApiKey(_ context.Context, r *v1.ExpireApiKeyRequest) (*v1.ExpireApiKeyResponse, error) {
	if err := f.record("ExpireApiKey", r); err != nil {
		return nil, err
	}
	return &v1.ExpireApiKeyResponse{}, nil
}

func (f *fakeServer) DeleteApiKey(_ context.Context, r *v1.DeleteApiKeyRequest) (*v1.DeleteApiKeyResponse, error) {
	if err := f.record("DeleteApiKey", r); err != nil {
		return nil, err
	}
	return &v1.DeleteApiKeyResponse{}, nil
}

// serve starts srv on a fresh unix socket and returns the client target. The path is kept short:
// macOS limits unix socket paths to about 100 bytes.
func serve(t *testing.T, srv v1.HeadscaleServiceServer) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "hsadmin")
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

func newAdmin(t *testing.T, target string, timeout time.Duration) *AdminClient {
	t.Helper()
	c, err := NewAdmin(headscale.Config{Target: target, Timeout: timeout})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// TestAdminClient_ExportedSurface is AC2: the admin client exposes exactly the allowed set. The
// method set is pinned, and the source never names a forbidden RPC (API key creation, user
// create/rename/delete, registration).
func TestAdminClient_ExportedSurface(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var methods, funcs []string
	forbidden := []string{
		"CreateApiKey", "CreateUser", "DeleteUser", "RenameUser",
		"RegisterNode", "DebugCreateNode", "BackfillNodeIPs", "AuthRegister", "AuthApprove", "AuthReject",
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
	wantMethods := []string{
		"AdminClient.Close",
		"AdminClient.CreatePreAuthKey",
		"AdminClient.DeleteApiKey",
		"AdminClient.DeleteNode",
		"AdminClient.DeletePreAuthKey",
		"AdminClient.EnableNode",
		"AdminClient.ExpireApiKey",
		"AdminClient.ExpireNode",
		"AdminClient.ExpirePreAuthKey",
		"AdminClient.ListApiKeys",
		"AdminClient.ListNodes",
		"AdminClient.ListPreAuthKeys",
		"AdminClient.RenameNode",
		"AdminClient.SetApprovedRoutes",
		"AdminClient.SetTags",
	}
	if strings.Join(methods, ",") != strings.Join(wantMethods, ",") {
		t.Errorf("exported methods = %v, want %v", methods, wantMethods)
	}
	sort.Strings(funcs)
	if strings.Join(funcs, ",") != "NewAdmin" {
		t.Errorf("exported functions = %v, want [NewAdmin]", funcs)
	}
}

// TestAdminClient_ConfigValidation is the config half of AC3: the same target rule as the F1
// client — unix socket or loopback only — and the default timeout when none is set.
func TestAdminClient_ConfigValidation(t *testing.T) {
	if _, err := NewAdmin(headscale.Config{}); err == nil {
		t.Error("empty target accepted")
	}
	for _, bad := range []string{"headscale.example.com:50443", "10.0.0.5:50443", "dns:///hs.example.com:443", "hs:50443", "127.0.0.1"} {
		if _, err := NewAdmin(headscale.Config{Target: bad}); err == nil {
			t.Errorf("target %q accepted; only unix sockets and loopback are allowed", bad)
		}
	}
	for _, good := range []string{"/run/headscale/headscale.sock", "unix:///run/x.sock", "127.0.0.1:50444", "[::1]:50444", "localhost:50444"} {
		c, err := NewAdmin(headscale.Config{Target: good})
		if err != nil {
			t.Errorf("target %q rejected: %v", good, err)
			continue
		}
		_ = c.Close()
	}
	c, err := NewAdmin(headscale.Config{Target: "unix:///x.sock"})
	if err != nil {
		t.Fatal(err)
	}
	if c.timeout != headscale.DefaultTimeout {
		t.Errorf("default timeout = %v, want %v", c.timeout, headscale.DefaultTimeout)
	}
	_ = c.Close()
}

// TestAdminClient_Timeout is the timeout half of AC3: an unreachable socket, and a socket whose
// server never answers, both return an error quickly instead of hanging.
func TestAdminClient_Timeout(t *testing.T) {
	t.Run("nothing listens", func(t *testing.T) {
		dir, _ := os.MkdirTemp("", "hsadmin")
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		c := newAdmin(t, "unix://"+filepath.Join(dir, "missing.sock"), 300*time.Millisecond)
		start := time.Now()
		if _, err := c.ListApiKeys(context.Background()); err == nil {
			t.Fatal("want an error")
		}
		if d := time.Since(start); d > 3*time.Second {
			t.Errorf("took %v", d)
		}
	})
	t.Run("server accepts and never answers", func(t *testing.T) {
		dir, _ := os.MkdirTemp("", "hsadmin")
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
		c := newAdmin(t, "unix://"+sock, 300*time.Millisecond)
		start := time.Now()
		_, err = c.ListNodes(context.Background())
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
		c := newAdmin(t, "unix:///nonexistent/s.sock", 30*time.Second)
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

// TestAdminClient_PreAuthListDropsSecret is AC4: even when the server answers with a legacy
// plaintext secret, no key material reaches the DTO. The proof is black box: the marshalled DTO
// list carries neither the legacy secret nor the masked form.
func TestAdminClient_PreAuthListDropsSecret(t *testing.T) {
	legacy := "hskey-auth-legacy0123456789ab" // what old Headscale versions still return verbatim
	masked := "{hskey-auth-masked}"
	f := &fakeServer{keys: []*v1.PreAuthKey{
		{Id: 1, User: &v1.User{Id: 3, Name: "alice"}, Key: legacy, Reusable: true, AclTags: []string{"tag:server"}},
		{Id: 2, User: &v1.User{Id: 3, Name: "alice"}, Key: masked, Used: true},
	}}
	c := newAdmin(t, serve(t, f), time.Second)

	keys, err := c.ListPreAuthKeys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("keys = %+v", keys)
	}
	if keys[0].ID != 1 || !keys[0].Reusable || keys[0].UserID != 3 || keys[0].UserName != "alice" || len(keys[0].Tags) != 1 {
		t.Errorf("keys[0] = %+v", keys[0])
	}
	if !keys[1].Used || keys[1].ID != 2 {
		t.Errorf("keys[1] = %+v", keys[1])
	}
	blob, err := json.Marshal(keys)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{legacy, masked, "hskey-auth"} {
		if strings.Contains(string(blob), s) {
			t.Errorf("marshalled DTO list contains key material %q: %s", s, blob)
		}
	}
}

// TestAdminClient_CreatePreAuthReturnsSecretOnce is the second half of AC4: the created key's
// secret comes back exactly once, as the separate return value, and never inside the DTO.
func TestAdminClient_CreatePreAuthReturnsSecretOnce(t *testing.T) {
	f := &fakeServer{}
	c := newAdmin(t, serve(t, f), time.Second)
	ctx := context.Background()
	expiry := time.Now().Add(30 * 24 * time.Hour)

	k, secret, err := c.CreatePreAuthKey(ctx, 3, PreAuthKeyOptions{Reusable: true, Expiration: expiry, Tags: []string{"tag:server"}})
	if err != nil {
		t.Fatal(err)
	}
	if secret != "hskey-auth-created0123456789ab" {
		t.Errorf("secret return = %q", secret)
	}
	blob, err := json.Marshal(k)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), "hskey-auth") {
		t.Errorf("created-key DTO carries key material: %s", blob)
	}
	if k.ID != 11 || !k.Reusable || len(k.Tags) != 1 || k.UserID != 3 {
		t.Errorf("created-key DTO = %+v", k)
	}
	reqs := f.requests()
	if len(reqs) != 1 {
		t.Fatalf("requests = %d", len(reqs))
	}
	req := reqs[0].(*v1.CreatePreAuthKeyRequest)
	if req.GetUser() != 3 || !req.GetReusable() || len(req.GetAclTags()) != 1 {
		t.Errorf("request = %+v", req)
	}
	if req.GetExpiration() == nil || !req.GetExpiration().AsTime().Equal(expiry) {
		t.Errorf("expiration = %v, want %v", req.GetExpiration(), expiry)
	}

	t.Run("user id 0 is refused before any call", func(t *testing.T) {
		if _, _, err := c.CreatePreAuthKey(ctx, 0, PreAuthKeyOptions{}); err == nil {
			t.Fatal("want an error")
		}
		if len(f.called()) != 1 {
			t.Errorf("calls = %v", f.called())
		}
	})

	t.Run("user id 0 is allowed for a tagged key", func(t *testing.T) {
		before := len(f.called())
		if _, _, err := c.CreatePreAuthKey(ctx, 0, PreAuthKeyOptions{Tags: []string{"tag:server"}}); err != nil {
			t.Fatalf("tagged key without user: %v", err)
		}
		if len(f.called()) != before+1 {
			t.Errorf("calls = %v", f.called())
		}
	})
}

// TestAdminClient_SetTagsRejectsEmpty is the first half of AC5: an empty tag list is refused
// before any RPC (the server would reject it too; failing here keeps the mistake local).
func TestAdminClient_SetTagsRejectsEmpty(t *testing.T) {
	f := &fakeServer{}
	c := newAdmin(t, serve(t, f), time.Second)
	for _, tags := range [][]string{nil, {}} {
		if _, err := c.SetTags(context.Background(), 7, tags); err == nil {
			t.Errorf("SetTags(%v) accepted", tags)
		}
	}
	if _, err := c.SetTags(context.Background(), 0, []string{"tag:server"}); err == nil {
		t.Error("node id 0 accepted")
	}
	if n := len(f.called()); n != 0 {
		t.Errorf("calls = %d, want 0", n)
	}
}

// TestAdminClient_SetApprovedRoutesValidates is the second half of AC5: every route must parse as
// a CIDR before the RPC; a bad one fails without a call.
func TestAdminClient_SetApprovedRoutesValidates(t *testing.T) {
	f := &fakeServer{}
	c := newAdmin(t, serve(t, f), time.Second)
	for _, bad := range []string{"10.0.0.0", "not-a-cidr", "10.0.0.0/33", "10.0.0.0/24/8"} {
		if _, err := c.SetApprovedRoutes(context.Background(), 7, []string{"10.0.0.0/24", bad}); err == nil {
			t.Errorf("route %q accepted", bad)
		}
	}
	if _, err := c.SetApprovedRoutes(context.Background(), 0, []string{"10.0.0.0/24"}); err == nil {
		t.Error("node id 0 accepted")
	}
	if n := len(f.called()); n != 0 {
		t.Fatalf("calls = %d, want 0", n)
	}

	// A valid full list goes through; an empty list (withdraw all) is valid too.
	if _, err := c.SetApprovedRoutes(context.Background(), 7, []string{"10.0.0.0/24", "fd7a:115c:a1e0::/48"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SetApprovedRoutes(context.Background(), 7, nil); err != nil {
		t.Fatal(err)
	}
	reqs := f.requests()
	last := reqs[len(reqs)-1].(*v1.SetApprovedRoutesRequest)
	if len(last.GetRoutes()) != 0 {
		t.Errorf("empty withdrawal sent %+v", last.GetRoutes())
	}
	prev := reqs[len(reqs)-2].(*v1.SetApprovedRoutesRequest)
	if strings.Join(prev.GetRoutes(), ",") != "10.0.0.0/24,fd7a:115c:a1e0::/48" {
		t.Errorf("routes sent = %v", prev.GetRoutes())
	}
}

// TestAdminClient_APIKeyByIDOnly is AC6: expire and delete address the key by ID only; the
// request's prefix field stays unset no matter what.
func TestAdminClient_APIKeyByIDOnly(t *testing.T) {
	f := &fakeServer{}
	c := newAdmin(t, serve(t, f), time.Second)

	if err := c.ExpireApiKey(context.Background(), 5); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteApiKey(context.Background(), 5); err != nil {
		t.Fatal(err)
	}
	reqs := f.requests()
	if len(reqs) != 2 {
		t.Fatalf("requests = %d", len(reqs))
	}
	for i, want := range []string{"ExpireApiKey", "DeleteApiKey"} {
		req := reqs[i]
		if got, ok := req.(*v1.ExpireApiKeyRequest); ok && want == "ExpireApiKey" {
			if got.GetPrefix() != "" || got.GetId() != 5 {
				t.Errorf("%s request = %+v, want id 5, empty prefix", want, got)
			}
			continue
		}
		if got, ok := req.(*v1.DeleteApiKeyRequest); ok && want == "DeleteApiKey" {
			if got.GetPrefix() != "" || got.GetId() != 5 {
				t.Errorf("%s request = %+v, want id 5, empty prefix", want, got)
			}
			continue
		}
		t.Errorf("request %d is %T, want %s", i, req, want)
	}

	if err := c.ExpireApiKey(context.Background(), 0); err == nil {
		t.Error("api key id 0 accepted")
	}
	if err := c.DeleteApiKey(context.Background(), 0); err == nil {
		t.Error("api key id 0 accepted")
	}
	if n := len(f.called()); n != 2 {
		t.Errorf("calls = %d, want 2", n)
	}
}

// TestAdminClient_ListNodesDetailed is the unit half of AC7: the admin node DTO carries the route
// fields, expiry, tags, owner and registration time.
func TestAdminClient_ListNodesDetailed(t *testing.T) {
	created := time.Unix(1700000000, 0)
	expiry := time.Unix(1800000000, 0)
	f := &fakeServer{nodes: []*v1.Node{
		{
			Id: 7, Name: "laptop", GivenName: "laptop", User: &v1.User{Id: 3, Name: "alice"},
			Tags: []string{"tag:server"}, IpAddresses: []string{"100.64.0.1"}, Online: true,
			Expiry: timestamppb.New(expiry), CreatedAt: timestamppb.New(created),
			ApprovedRoutes: []string{"10.0.0.0/24"}, AvailableRoutes: []string{"10.0.0.0/24", "192.168.1.0/24"},
			SubnetRoutes: []string{"192.168.1.0/24"},
		},
		{Id: 8, Name: "phone", User: &v1.User{Id: 4, Name: "bob"}, CreatedAt: timestamppb.New(created)},
	}}
	c := newAdmin(t, serve(t, f), time.Second)

	nodes, err := c.ListNodes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 {
		t.Fatalf("nodes = %+v", nodes)
	}
	n := nodes[0]
	if n.ID != 7 || n.Name != "laptop" || n.GivenName != "laptop" || n.UserID != 3 || n.UserName != "alice" {
		t.Errorf("nodes[0] identity = %+v", n)
	}
	if !n.Online || len(n.IPs) != 1 || !n.CreatedAt.Equal(created) {
		t.Errorf("nodes[0] base = %+v", n)
	}
	if n.Expiry == nil || !n.Expiry.Equal(expiry) {
		t.Errorf("nodes[0] expiry = %v, want %v", n.Expiry, expiry)
	}
	if strings.Join(n.Tags, ",") != "tag:server" {
		t.Errorf("nodes[0] tags = %v", n.Tags)
	}
	if strings.Join(n.ApprovedRoutes, ",") != "10.0.0.0/24" ||
		strings.Join(n.AvailableRoutes, ",") != "10.0.0.0/24,192.168.1.0/24" ||
		strings.Join(n.SubnetRoutes, ",") != "192.168.1.0/24" {
		t.Errorf("nodes[0] routes = %+v", n)
	}
	if nodes[1].Expiry != nil || len(nodes[1].ApprovedRoutes) != 0 {
		t.Errorf("nodes[1] = %+v", nodes[1])
	}
}

// TestAdminClient_NodeWriteMethods covers the remaining node operations' happy path: the response
// node is mapped and must be for the requested node.
func TestAdminClient_NodeWriteMethods(t *testing.T) {
	ctx := context.Background()
	t.Run("rename", func(t *testing.T) {
		f := &fakeServer{}
		c := newAdmin(t, serve(t, f), time.Second)
		n, err := c.RenameNode(ctx, 7, "laptop-2")
		if err != nil {
			t.Fatal(err)
		}
		if n.ID != 7 || n.Name != "laptop-2" {
			t.Errorf("node = %+v", n)
		}
		req := f.requests()[0].(*v1.RenameNodeRequest)
		if req.GetNodeId() != 7 || req.GetNewName() != "laptop-2" {
			t.Errorf("request = %+v", req)
		}
		if _, err := c.RenameNode(ctx, 0, "x"); err == nil {
			t.Error("node id 0 accepted")
		}
	})
	t.Run("expire in the future", func(t *testing.T) {
		f := &fakeServer{}
		c := newAdmin(t, serve(t, f), time.Second)
		at := time.Now().Add(24 * time.Hour)
		n, err := c.ExpireNode(ctx, 7, at)
		if err != nil {
			t.Fatal(err)
		}
		if n.Expiry == nil || !n.Expiry.Equal(at) {
			t.Errorf("expiry = %v, want %v", n.Expiry, at)
		}
		req := f.requests()[0].(*v1.ExpireNodeRequest)
		if req.GetDisableExpiry() {
			t.Errorf("request = %+v", req)
		}
	})
	t.Run("enable clears the expiry", func(t *testing.T) {
		f := &fakeServer{}
		c := newAdmin(t, serve(t, f), time.Second)
		n, err := c.EnableNode(ctx, 7)
		if err != nil {
			t.Fatal(err)
		}
		if n.Expiry != nil {
			t.Errorf("expiry = %v, want nil", n.Expiry)
		}
		req := f.requests()[0].(*v1.ExpireNodeRequest)
		if !req.GetDisableExpiry() {
			t.Errorf("request = %+v, want disable_expiry", req)
		}
	})
	t.Run("set tags sends the full list", func(t *testing.T) {
		f := &fakeServer{}
		c := newAdmin(t, serve(t, f), time.Second)
		n, err := c.SetTags(ctx, 7, []string{"tag:server"})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(n.Tags, ",") != "tag:server" {
			t.Errorf("tags = %v", n.Tags)
		}
	})
	t.Run("delete", func(t *testing.T) {
		f := &fakeServer{}
		c := newAdmin(t, serve(t, f), time.Second)
		if err := c.DeleteNode(ctx, 7); err != nil {
			t.Fatal(err)
		}
		req := f.requests()[0].(*v1.DeleteNodeRequest)
		if req.GetNodeId() != 7 {
			t.Errorf("request = %+v", req)
		}
		if err := c.DeleteNode(ctx, 0); err == nil {
			t.Error("node id 0 accepted")
		}
	})
	t.Run("pre-auth key id 0 is refused before any call", func(t *testing.T) {
		f := &fakeServer{}
		c := newAdmin(t, serve(t, f), time.Second)
		if err := c.ExpirePreAuthKey(ctx, 0); err == nil {
			t.Error("pre-auth key id 0 accepted")
		}
		if err := c.DeletePreAuthKey(ctx, 0); err == nil {
			t.Error("pre-auth key id 0 accepted")
		}
		if n := len(f.called()); n != 0 {
			t.Errorf("calls = %d, want 0", n)
		}
	})
}

// TestAdminClient_NoRetryOnError is AC9: a failing RPC returns its error wrapped and is never
// retried — exactly one RPC per call.
func TestAdminClient_NoRetryOnError(t *testing.T) {
	t.Run("SetTags", func(t *testing.T) {
		f := &fakeServer{failOn: map[string]bool{"SetTags": true}}
		c := newAdmin(t, serve(t, f), time.Second)
		_, err := c.SetTags(context.Background(), 7, []string{"tag:server"})
		if err == nil {
			t.Fatal("want an error")
		}
		if !strings.Contains(err.Error(), "SetTags") {
			t.Errorf("error is not wrapped with the RPC name: %v", err)
		}
		if got := f.called(); len(got) != 1 {
			t.Errorf("calls = %v, want exactly one SetTags", got)
		}
	})
	t.Run("ListApiKeys", func(t *testing.T) {
		f := &fakeServer{err: status.Error(codes.Internal, "database is locked")}
		c := newAdmin(t, serve(t, f), time.Second)
		if _, err := c.ListApiKeys(context.Background()); err == nil {
			t.Fatal("want an error")
		}
		if got := f.called(); len(got) != 1 {
			t.Errorf("calls = %v, want exactly one ListApiKeys", got)
		}
	})
	t.Run("DeleteNode", func(t *testing.T) {
		f := &fakeServer{failOn: map[string]bool{"DeleteNode": true}}
		c := newAdmin(t, serve(t, f), time.Second)
		if err := c.DeleteNode(context.Background(), 7); err == nil {
			t.Fatal("want an error")
		}
		if got := f.called(); len(got) != 1 {
			t.Errorf("calls = %v, want exactly one DeleteNode", got)
		}
	})
}
