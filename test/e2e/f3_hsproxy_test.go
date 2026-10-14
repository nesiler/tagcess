//go:build integration

// A pass-through gRPC proxy between the tagcess binary and the disposable Headscale (F3-030). It
// forwards every unary call untouched, and when armed it makes one policy write end the way a
// crash mid-apply does: Headscale commits the policy, then goes down before tagcess hears
// about it. Nothing short of that can leave the live policy different from every applied revision
// while the write's own outcome is unknown, which is what the recovery flow exists for.
package e2e_test

import (
	"net"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/mem"
	"google.golang.org/grpc/status"
)

// rawCodec passes the serialized messages through without looking at them.
type rawCodec struct{}

func (rawCodec) Marshal(v any) (mem.BufferSlice, error) {
	return mem.BufferSlice{mem.SliceBuffer(*v.(*[]byte))}, nil
}

func (rawCodec) Unmarshal(data mem.BufferSlice, v any) error {
	*v.(*[]byte) = data.Materialize()
	return nil
}

func (rawCodec) Name() string { return "proto" }

// hsProxy is the proxy: tagcess dials addr, the proxy dials target.
type hsProxy struct {
	addr   string
	target string
	srv    *grpc.Server

	mu    sync.Mutex
	armed func() // runs after the next SetPolicy was forwarded and committed
}

// startHSProxy listens on a free loopback port and forwards to target until the test ends.
func startHSProxy(t *testing.T, target string) *hsProxy {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("headscale proxy listen: %v", err)
	}
	p := &hsProxy{addr: lis.Addr().String(), target: target}
	p.srv = grpc.NewServer(grpc.ForceServerCodecV2(rawCodec{}), grpc.UnknownServiceHandler(p.handle))
	go func() { _ = p.srv.Serve(lis) }()
	t.Cleanup(p.srv.Stop)
	return p
}

// dieAfterNextSetPolicy arms the proxy: the next SetPolicy reaches Headscale and commits, then
// stop runs (the test takes Headscale down) and tagcess gets an error instead of the response.
func (p *hsProxy) dieAfterNextSetPolicy(stop func()) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.armed = stop
}

func (p *hsProxy) takeArmed() func() {
	p.mu.Lock()
	defer p.mu.Unlock()
	stop := p.armed
	p.armed = nil
	return stop
}

// handle forwards one unary call. A fresh connection per call keeps the proxy free of reconnect
// backoff: while Headscale is down the call fails at once, and the first call after its restart works.
func (p *hsProxy) handle(_ any, stream grpc.ServerStream) error {
	method, _ := grpc.MethodFromServerStream(stream)
	var in []byte
	if err := stream.RecvMsg(&in); err != nil {
		return err
	}
	conn, err := grpc.NewClient(p.target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return status.Error(codes.Unavailable, err.Error())
	}
	defer func() { _ = conn.Close() }()
	var out []byte
	err = conn.Invoke(stream.Context(), method, &in, &out, grpc.ForceCodecV2(rawCodec{}))
	if err == nil && strings.HasSuffix(method, "/SetPolicy") {
		if stop := p.takeArmed(); stop != nil {
			stop()
			return status.Error(codes.Unavailable, "proxy: Headscale went down before the response")
		}
	}
	if err != nil {
		return err
	}
	return stream.SendMsg(&out)
}
