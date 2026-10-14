package health

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nesiler/tagcess/test/k8s"
)

func httpTarget(statuses ...int) TargetRequest {
	return TargetRequest{Request: okRequest(), Statuses: statuses}
}

// AC1: the probe dials the allowlisted address, sends the chosen Host/SNI and path, and judges the
// answer only by the selected expected statuses (default: 200 on "/").
func TestHTTPProbeHostAndPath(t *testing.T) {
	ctx := context.Background()
	const other = "admin.internal.example"

	t.Run("Host and SNI reach the fixture", func(t *testing.T) {
		e := newEnv(t, nil)
		if err := e.targets.Set(ctx, []string{testHost, other}); err != nil {
			t.Fatalf("Set targets: %v", err)
		}
		fx := k8s.NewTLS(t, other)
		e.dialer.backend = fx.Addr()
		e.tr.rootCAs = fx.CAPool()
		req := TargetRequest{Request: Request{Host: testHost, Port: testPort, TLS: true, ServerName: other}}
		res, err := e.tr.ProbeTarget(ctx, req)
		if err != nil {
			t.Fatalf("ProbeTarget: %v", err)
		}
		if res.Kind != KindHealthy || res.Protocol != ProtocolHTTP || res.StatusCode != http.StatusOK {
			t.Fatalf("result = %+v, want a healthy HTTP 200", res)
		}
		obs := fx.Observations()
		if len(obs) != 1 || obs[0].Host != other || obs[0].SNI != other {
			t.Fatalf("fixture observed %+v, want one request with Host and SNI %q", obs, other)
		}
		if got := e.dialer.Addrs(); len(got) != 1 || got[0] != testIP+":8080" {
			t.Errorf("dialled %v, want the approved address %s:8080", got, testIP)
		}
		if res.Endpoint != testHost+":8080" {
			t.Errorf("endpoint = %q, want %q", res.Endpoint, testHost+":8080")
		}
	})

	t.Run("default path and expectation", func(t *testing.T) {
		var mu sync.Mutex
		var paths []string
		e := newEnv(t, func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			paths = append(paths, r.URL.RequestURI())
			mu.Unlock()
		})
		res, err := e.tr.ProbeTarget(ctx, httpTarget())
		if err != nil || res.Kind != KindHealthy {
			t.Fatalf("ProbeTarget = %+v, %v; want healthy", res, err)
		}
		mu.Lock()
		defer mu.Unlock()
		if len(paths) != 1 || paths[0] != "/" {
			t.Errorf("backend saw %v, want one request for /", paths)
		}
	})

	t.Run("chosen path and statuses", func(t *testing.T) {
		var mu sync.Mutex
		var paths []string
		e := newEnv(t, func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			paths = append(paths, r.URL.RequestURI())
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		})
		req := TargetRequest{Request: Request{Host: testHost, Port: testPort, Path: "/healthz"}, Statuses: []int{200, 204}}
		res, err := e.tr.ProbeTarget(ctx, req)
		if err != nil || res.Kind != KindHealthy || res.StatusCode != http.StatusNoContent {
			t.Fatalf("ProbeTarget = %+v, %v; want healthy 204", res, err)
		}
		// The same 204 is not enough when only 200 is expected.
		res, err = e.tr.ProbeTarget(ctx, TargetRequest{Request: req.Request, Statuses: []int{200}})
		if err != nil || res.Kind != KindUnexpectedStatus || res.StatusCode != http.StatusNoContent {
			t.Fatalf("ProbeTarget = %+v, %v; want an unexpected-status result", res, err)
		}
		mu.Lock()
		defer mu.Unlock()
		if len(paths) != 2 || paths[0] != "/healthz" || paths[1] != "/healthz" {
			t.Errorf("backend saw %v, want /healthz twice", paths)
		}
	})
}

// AC2: with the default expectation no access-layer or error answer is a success, and no redirect
// is followed. An explicitly selected status is the only way a non-200 is healthy.
func TestHTTPProbeRejectsAccessResponses(t *testing.T) {
	ctx := context.Background()
	for _, status := range []int{302, 401, 403, 404, 418, 500, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			e := newEnv(t, func(w http.ResponseWriter, r *http.Request) {
				if status == 302 {
					http.Redirect(w, r, "/login", status)
					return
				}
				w.WriteHeader(status)
			})
			res, err := e.tr.ProbeTarget(ctx, httpTarget())
			if err != nil {
				t.Fatalf("ProbeTarget: %v", err)
			}
			if res.Kind == KindHealthy || res.Kind != KindUnexpectedStatus || res.StatusCode != status {
				t.Fatalf("result = %+v, want unexpected status %d", res, status)
			}
			if n := e.hits.Load(); n != 1 {
				t.Errorf("backend got %d requests, want 1 (redirect not followed)", n)
			}

			// The same answer is healthy only when the developer selected it.
			res, err = e.tr.ProbeTarget(ctx, httpTarget(status))
			if err != nil || res.Kind != KindHealthy {
				t.Fatalf("selected expectation: result = %+v, %v; want healthy", res, err)
			}
		})
	}
}

// AC3: the Caddy gate has its own result type and kinds. A login redirect, 401 or 403 is the gate
// answering; the same fixture is never a healthy target under the default expectation.
func TestCaddyGateResponseIsNotTargetSuccess(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		status int
		want   GateKind
	}{
		{http.StatusFound, GateLoginRedirect},
		{http.StatusSeeOther, GateLoginRedirect},
		{http.StatusUnauthorized, GateUnauthorized},
		{http.StatusForbidden, GateForbidden},
		{http.StatusOK, GateAnswered},
		{http.StatusBadGateway, GateAnswered},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprint(tc.status), func(t *testing.T) {
			e := newEnv(t, func(w http.ResponseWriter, r *http.Request) {
				if tc.status/100 == 3 {
					http.Redirect(w, r, "https://login.internal.example/auth", tc.status)
					return
				}
				w.WriteHeader(tc.status)
			})
			gate, err := e.tr.ProbeGate(ctx, okRequest())
			if err != nil {
				t.Fatalf("ProbeGate: %v", err)
			}
			if gate.Kind != tc.want || gate.StatusCode != tc.status || gate.Endpoint != testHost+":8080" {
				t.Fatalf("gate = %+v, want kind %q status %d", gate, tc.want, tc.status)
			}
			target, err := e.tr.ProbeTarget(ctx, httpTarget())
			if err != nil {
				t.Fatalf("ProbeTarget: %v", err)
			}
			if tc.status != http.StatusOK && target.Kind == KindHealthy {
				t.Fatalf("gate answer %d counted as a healthy target: %+v", tc.status, target)
			}
			if n := e.hits.Load(); n != 2 {
				t.Errorf("backend got %d requests, want 2 (no redirect followed)", n)
			}
		})
	}

	t.Run("unreachable gate is not a gate answer", func(t *testing.T) {
		e := newEnv(t, nil)
		e.dialer.block = true
		e.tr.timeout = 50 * time.Millisecond
		gate, err := e.tr.ProbeGate(ctx, okRequest())
		if err != nil || gate.Kind != GateTimeout || gate.StatusCode != 0 {
			t.Fatalf("gate = %+v, %v; want a timeout with no status", gate, err)
		}
	})

	t.Run("template is unknown", func(t *testing.T) {
		e := newEnv(t, nil)
		gate, err := e.tr.ProbeGate(ctx, Request{Template: "zitadel", Host: testHost, Port: testPort})
		if err != nil || gate.Kind != GateUnknown {
			t.Fatalf("gate = %+v, %v; want unknown", gate, err)
		}
		e.noNetwork(t)
	})
}

// AC4: TCP connect, timeout and failure each produce a protocol + endpoint + bounded kind. Nothing
// is sent on a TCP probe and no body, header or cookie reaches the result.
func TestTargetProbeTCPAndTimeoutEvidence(t *testing.T) {
	ctx := context.Background()
	const wantEndpoint = testHost + ":8080"

	t.Run("tcp connects and sends nothing", func(t *testing.T) {
		ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		t.Cleanup(func() { _ = ln.Close() })

		// observe accepts one connection and reports how many bytes arrived before the
		// peer closed it (io.EOF) or the read failed.
		type seen struct {
			n   int
			err error
		}
		observe := func() <-chan seen {
			out := make(chan seen, 1)
			go func() {
				c, err := ln.Accept()
				if err != nil {
					out <- seen{err: err}
					return
				}
				defer func() { _ = c.Close() }()
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 64)
				n, err := c.Read(buf)
				out <- seen{n: n, err: err}
			}()
			return out
		}

		// Positive control: the same listener and observer must see a harmless payload.
		control := observe()
		cc, err := (&net.Dialer{}).DialContext(ctx, "tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("control dial: %v", err)
		}
		if _, err := cc.Write([]byte("x")); err != nil {
			t.Fatalf("control write: %v", err)
		}
		if got := <-control; got.n <= 0 {
			t.Fatalf("observer missed a control payload: %+v", got)
		}
		_ = cc.Close()

		got := observe()
		e := newEnv(t, nil)
		e.dialer.backend = ln.Addr().String()
		res, err := e.tr.ProbeTarget(ctx, TargetRequest{Request: okRequest(), Protocol: ProtocolTCP})
		if err != nil {
			t.Fatalf("ProbeTarget: %v", err)
		}
		if res.Protocol != ProtocolTCP || res.Endpoint != wantEndpoint || res.Kind != KindTCPConnected || res.StatusCode != 0 {
			t.Fatalf("result = %+v, want a tcp connect to %s", res, wantEndpoint)
		}
		if s := <-got; s.n != 0 || !errors.Is(s.err, io.EOF) {
			t.Errorf("server read %d bytes, err %v; want 0 bytes and io.EOF (probe closes without sending)", s.n, s.err)
		}
	})

	t.Run("tcp refused", func(t *testing.T) {
		ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		addr := ln.Addr().String()
		_ = ln.Close()
		e := newEnv(t, nil)
		e.dialer.backend = addr
		res, err := e.tr.ProbeTarget(ctx, TargetRequest{Request: okRequest(), Protocol: ProtocolTCP})
		if err != nil || res.Kind != KindUnreachable || res.Protocol != ProtocolTCP || res.Endpoint != wantEndpoint {
			t.Fatalf("result = %+v, %v; want unreachable tcp", res, err)
		}
	})

	t.Run("tcp timeout", func(t *testing.T) {
		e := newEnv(t, nil)
		e.dialer.block = true
		e.tr.timeout = 50 * time.Millisecond
		start := time.Now()
		res, err := e.tr.ProbeTarget(ctx, TargetRequest{Request: okRequest(), Protocol: ProtocolTCP})
		if err != nil || res.Kind != KindTimeout || res.Protocol != ProtocolTCP || res.Endpoint != wantEndpoint {
			t.Fatalf("result = %+v, %v; want a tcp timeout", res, err)
		}
		if d := time.Since(start); d > time.Second {
			t.Errorf("probe took %v, want it bounded by the time limit", d)
		}
	})

	t.Run("http timeout", func(t *testing.T) {
		e := newEnv(t, func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
		e.tr.timeout = 100 * time.Millisecond
		res, err := e.tr.ProbeTarget(ctx, httpTarget())
		if err != nil || res.Kind != KindTimeout || res.Protocol != ProtocolHTTP || res.Endpoint != wantEndpoint {
			t.Fatalf("result = %+v, %v; want an http timeout", res, err)
		}
	})

	t.Run("caller cancellation is an error, not a measurement", func(t *testing.T) {
		e := newEnv(t, nil)
		e.dialer.block = true
		cctx, cancel := context.WithCancel(ctx)
		time.AfterFunc(30*time.Millisecond, cancel)
		res, err := e.tr.ProbeTarget(cctx, httpTarget())
		if !errors.Is(err, context.Canceled) || res != (TargetResult{}) {
			t.Fatalf("result = %+v, %v; want context.Canceled and no result", res, err)
		}
	})

	t.Run("result holds no body or header", func(t *testing.T) {
		const secret = "s3cr3t-body-and-cookie"
		e := newEnv(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Set-Cookie", "sid="+secret)
			w.Header().Set("Location", "https://x.example/"+secret)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(secret))
		})
		res, err := e.tr.ProbeTarget(ctx, httpTarget())
		if err != nil || res.Kind != KindHealthy {
			t.Fatalf("ProbeTarget = %+v, %v", res, err)
		}
		gate, err := e.tr.ProbeGate(ctx, okRequest())
		if err != nil {
			t.Fatalf("ProbeGate: %v", err)
		}
		if s := fmt.Sprintf("%+v %#v %+v %#v", res, res, gate, gate); strings.Contains(s, secret) {
			t.Errorf("result leaks response content: %s", s)
		}
	})

	t.Run("policy refusal is an error, not a measurement", func(t *testing.T) {
		e := newEnv(t, nil)
		e.resolver.answers = nil
		for _, p := range []Protocol{ProtocolHTTP, ProtocolTCP} {
			res, err := e.tr.ProbeTarget(ctx, TargetRequest{Request: okRequest(), Protocol: p})
			if err == nil || res != (TargetResult{}) {
				t.Errorf("%s: result = %+v, %v; want an error and no result", p, res, err)
			}
		}
		if n := e.hits.Load(); n != 0 {
			t.Errorf("backend got %d requests, want 0", n)
		}
	})

	t.Run("template is unknown", func(t *testing.T) {
		e := newEnv(t, nil)
		for _, p := range []Protocol{ProtocolHTTP, ProtocolTCP} {
			res, err := e.tr.ProbeTarget(ctx, TargetRequest{Request: Request{Template: "kubernetes-api"}, Protocol: p})
			if err != nil || res.Kind != KindUnknown || res.StatusCode != 0 {
				t.Errorf("%s: result = %+v, %v; want unknown", p, res, err)
			}
		}
		e.noNetwork(t)
	})
}

// AC5: an unsafe path, Host/SNI, status expectation or protocol mix is refused before any lookup,
// dial or request; credentials and custom headers are never sent.
func TestHTTPProbeRejectsUnsafeExpectation(t *testing.T) {
	ctx := context.Background()
	const secret = "s3cr3t-token-value"
	base := func() Request { return okRequest() }
	with := func(f func(*Request)) Request { r := base(); f(&r); return r }

	cases := []struct {
		name string
		req  TargetRequest
	}{
		{"path with query", TargetRequest{Request: with(func(r *Request) { r.Path = "/x?token=" + secret })}},
		{"path with fragment", TargetRequest{Request: with(func(r *Request) { r.Path = "/x#" + secret })}},
		{"path without slash", TargetRequest{Request: with(func(r *Request) { r.Path = "x" })}},
		{"path with control character", TargetRequest{Request: with(func(r *Request) { r.Path = "/x\r\nX: " + secret })}},
		{"server name off the allowlist", TargetRequest{Request: with(func(r *Request) { r.ServerName = "evil.example" })}},
		{"server name with CRLF", TargetRequest{Request: with(func(r *Request) { r.ServerName = testHost + "\r\nX: y" })}},
		{"server name with port", TargetRequest{Request: with(func(r *Request) { r.ServerName = testHost + ":8080" })}},
		{"authorization header", TargetRequest{Request: with(func(r *Request) { r.Header = http.Header{"Authorization": {"Bearer " + secret}} })}},
		{"credential", TargetRequest{Request: with(func(r *Request) { r.Credential = secret })}},
		{"status zero", httpTarget(0)},
		{"status below 200", httpTarget(100)},
		{"status above 599", httpTarget(600)},
		{"negative status", httpTarget(-200)},
		{"good and bad status", httpTarget(200, 999)},
		{"too many statuses", httpTarget(200, 201, 202, 203, 204, 205, 206, 207, 208)},
		{"unknown protocol", TargetRequest{Request: base(), Protocol: "udp"}},
		{"tcp with statuses", TargetRequest{Request: base(), Protocol: ProtocolTCP, Statuses: []int{200}}},
		{"tcp with path", TargetRequest{Request: with(func(r *Request) { r.Path = "/x" }), Protocol: ProtocolTCP}},
		{"tcp with tls", TargetRequest{Request: with(func(r *Request) { r.TLS = true }), Protocol: ProtocolTCP}},
		{"tcp with server name", TargetRequest{Request: with(func(r *Request) { r.ServerName = testHost }), Protocol: ProtocolTCP}},
		{"tcp with header", TargetRequest{Request: with(func(r *Request) { r.Header = http.Header{"Cookie": {"sid=" + secret}} }), Protocol: ProtocolTCP}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, nil)
			res, err := e.tr.ProbeTarget(ctx, tc.req)
			if !errors.Is(err, ErrRejected) || res != (TargetResult{}) {
				t.Fatalf("ProbeTarget = %+v, %v; want ErrRejected and no result", res, err)
			}
			if err != nil && strings.Contains(err.Error(), secret) {
				t.Errorf("error leaks the secret: %v", err)
			}
			e.noNetwork(t)
		})
	}

	// The gate takes the same request checks.
	t.Run("gate refuses a header", func(t *testing.T) {
		e := newEnv(t, nil)
		gate, err := e.tr.ProbeGate(ctx, with(func(r *Request) { r.Header = http.Header{"Authorization": {"x"}} }))
		if !errors.Is(err, ErrRejected) || gate != (GateResult{}) {
			t.Fatalf("ProbeGate = %+v, %v; want ErrRejected and no result", gate, err)
		}
		e.noNetwork(t)
	})

	// Positive control: the same base request with valid input does measure.
	t.Run("control", func(t *testing.T) {
		e := newEnv(t, nil)
		res, err := e.tr.ProbeTarget(ctx, TargetRequest{Request: base(), Statuses: []int{200, 599}})
		if err != nil || res.Kind != KindHealthy {
			t.Fatalf("control = %+v, %v; want healthy", res, err)
		}
	})
}
