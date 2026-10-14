package health

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/netpolicy"
	"github.com/nesiler/tagcess/internal/site"
	"github.com/nesiler/tagcess/internal/store"
	"github.com/nesiler/tagcess/test/k8s"
)

const (
	testHost = "app.internal.example"
	testIP   = "10.20.0.5"
	testPort = 8080
)

// fakeResolver answers each lookup from a queue of answers (the last one repeats) and counts calls.
type fakeResolver struct {
	mu      sync.Mutex
	answers [][]netip.Addr
	calls   int
}

func (r *fakeResolver) LookupNetIP(_ context.Context, _, _ string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	i := r.calls
	r.calls++
	if len(r.answers) == 0 {
		return nil, errors.New("no answer")
	}
	if i >= len(r.answers) {
		i = len(r.answers) - 1
	}
	return r.answers[i], nil
}

func (r *fakeResolver) Calls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

// shiftedConn reports a chosen remote address while talking to the local backend, so the guard's
// "connection reached the checked address" test can be satisfied (or violated) without a real network.
type shiftedConn struct {
	net.Conn
	remote net.Addr
}

func (c shiftedConn) RemoteAddr() net.Addr { return c.remote }

// fakeDialer records every dial and connects to the local backend instead. mode "block" waits for
// the context; remoteOverride makes the connection claim another remote address.
type fakeDialer struct {
	backend        string
	block          bool
	remoteOverride string

	mu    sync.Mutex
	addrs []string
}

func (d *fakeDialer) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.addrs = append(d.addrs, address)
	d.mu.Unlock()
	if d.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	c, err := (&net.Dialer{}).DialContext(ctx, network, d.backend)
	if err != nil {
		return nil, err
	}
	remote := address
	if d.remoteOverride != "" {
		remote = d.remoteOverride
	}
	return shiftedConn{Conn: c, remote: net.TCPAddrFromAddrPort(netip.MustParseAddrPort(remote))}, nil
}

func (d *fakeDialer) Addrs() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.addrs...)
}

type env struct {
	st       *store.Store
	targets  *site.AllowedTargets
	policy   *netpolicy.Store
	resolver *fakeResolver
	dialer   *fakeDialer
	hits     atomic.Int32
	tr       *Transport
}

// newEnv wires the transport over a real settings database, a fake resolver/dialer and a local
// backend handler. Allowed target host: testHost; probe policy: 10.20.0.0/24 on port testPort.
func newEnv(t *testing.T, handler http.HandlerFunc) *env {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "tagcess.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	e := &env{st: st}
	e.targets = site.NewAllowedTargets(st.DB(), st.Queries())
	if err := e.targets.SeedIfMissing(ctx, []string{testHost, "169.254.169.254", "127.0.0.1", "10.99.0.1"}); err != nil {
		t.Fatalf("seed targets: %v", err)
	}
	e.policy = netpolicy.New(st.DB(), st.Queries())
	if err := e.policy.Set(ctx, netpolicy.ScopeProbe, netpolicy.Input{Addresses: []string{"10.20.0.0/24"}, Ports: []int{testPort}}); err != nil {
		t.Fatalf("set probe policy: %v", err)
	}
	if handler == nil {
		handler = func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.hits.Add(1)
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	e.resolver = &fakeResolver{answers: [][]netip.Addr{{netip.MustParseAddr(testIP)}}}
	e.dialer = &fakeDialer{backend: srv.Listener.Addr().String()}
	guard := netpolicy.NewGuard(e.policy, e.resolver, e.dialer.Dial)
	e.tr = newTransport(e.targets, guard.DialContext(netpolicy.ScopeProbe), 2*time.Second)
	return e
}

func (e *env) noNetwork(t *testing.T) {
	t.Helper()
	if n := e.resolver.Calls(); n != 0 {
		t.Errorf("resolver called %d times, want 0", n)
	}
	if a := e.dialer.Addrs(); len(a) != 0 {
		t.Errorf("dialled %v, want no dial", a)
	}
	if n := e.hits.Load(); n != 0 {
		t.Errorf("backend got %d requests, want 0", n)
	}
}

func okRequest() Request { return Request{Host: testHost, Port: testPort} }

// AC1: a target outside the approved host list or port scope is refused before any network call;
// an unreadable allowlist stops the same way.
func TestProbeTransportRequiresApprovedTargetAndPort(t *testing.T) {
	ctx := context.Background()

	// A control request goes through, so the refusals below are not an artefact of the setup.
	e := newEnv(t, nil)
	res, err := e.tr.Get(ctx, okRequest())
	if err != nil || res.Outcome != OutcomeResponded || res.StatusCode != http.StatusOK {
		t.Fatalf("approved Get = %+v, %v; want a 200 response", res, err)
	}

	cases := []struct {
		name string
		req  Request
		prep func(t *testing.T, e *env)
	}{
		{name: "host not on the allowlist", req: Request{Host: "other.example", Port: testPort}},
		{name: "port outside the approved scope", req: Request{Host: testHost, Port: 9999}},
		{name: "port zero", req: Request{Host: testHost, Port: 0}},
		{name: "empty host", req: Request{Host: "", Port: testPort}},
		{
			name: "allowlist unreadable",
			req:  okRequest(),
			prep: func(t *testing.T, e *env) {
				t.Helper()
				if _, err := e.st.DB().ExecContext(ctx, `DELETE FROM settings WHERE key = 'site.allowed_targets'`); err != nil {
					t.Fatalf("drop allowlist: %v", err)
				}
			},
		},
		{
			name: "probe policy not set",
			req:  okRequest(),
			prep: func(t *testing.T, e *env) {
				t.Helper()
				if _, err := e.st.DB().ExecContext(ctx, `DELETE FROM settings WHERE key = 'netpolicy.probe'`); err != nil {
					t.Fatalf("drop policy: %v", err)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, nil)
			if tc.prep != nil {
				tc.prep(t, e)
			}
			res, err := e.tr.Get(ctx, tc.req)
			if err == nil {
				t.Fatalf("Get = %+v, want an error", res)
			}
			if res != (Result{}) {
				t.Errorf("result on refusal = %+v, want zero", res)
			}
			e.noNetwork(t)
		})
	}
}

// A Host/SNI override is held to the same allowlist as the host: an approved address cannot be
// used to reach an unapproved virtual host. The refusal comes before any lookup or dial; an
// approved override reaches the fixture as both Host header and SNI.
func TestProbeTransportServerNameRequiresApprovedTarget(t *testing.T) {
	ctx := context.Background()
	const other = "admin.internal.example"

	t.Run("approved override is observed as Host and SNI", func(t *testing.T) {
		e := newEnv(t, nil)
		if err := e.targets.Set(ctx, []string{testHost, other}); err != nil {
			t.Fatalf("Set targets: %v", err)
		}
		fx := k8s.NewTLS(t, other)
		e.dialer.backend = fx.Addr()
		e.tr.rootCAs = fx.CAPool()
		res, err := e.tr.Get(ctx, Request{Host: testHost, Port: testPort, TLS: true, ServerName: other})
		if err != nil || res.Outcome != OutcomeResponded {
			t.Fatalf("Get = %+v, %v; want a response", res, err)
		}
		obs := fx.Observations()
		if len(obs) != 1 || obs[0].Host != other || obs[0].SNI != other {
			t.Fatalf("fixture observed %+v, want one request with Host and SNI %q", obs, other)
		}
		if got, want := e.dialer.Addrs(), []string{testIP + ":8080"}; len(got) != 1 || got[0] != want[0] {
			t.Errorf("dialled %v, want %v (the approved host's address)", got, want)
		}
	})

	cases := []struct {
		name       string
		serverName string
	}{
		{"name not on the allowlist", other},
		{"name with a port", testHost + ":8080"},
		{"bracketed literal", "[::1]"},
		{"control character", testHost + "\r\nX: y"},
	}
	for _, tc := range cases {
		for _, useTLS := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/tls=%v", tc.name, useTLS), func(t *testing.T) {
				e := newEnv(t, nil)
				res, err := e.tr.Get(ctx, Request{Host: testHost, Port: testPort, TLS: useTLS, ServerName: tc.serverName})
				if err == nil || res != (Result{}) {
					t.Fatalf("Get = %+v, %v; want a refusal", res, err)
				}
				if !errors.Is(err, ErrRejected) {
					t.Errorf("error = %v, want ErrRejected", err)
				}
				e.noNetwork(t)
			})
		}
	}
}

// The allowlist match is ASCII-only: a Unicode case-fold look-alike (U+017F long s, U+212A Kelvin
// sign) or IDN input must be refused before any lookup or dial, because the HTTP stack would send
// it as a different (punycode) name. ASCII case differences still match and are sent canonically.
func TestProbeTransportHostMatchIsASCIIOnly(t *testing.T) {
	ctx := context.Background()
	const (
		siteName = "site.internal.example"
		kubeName = "kube.internal.example"
	)
	setup := func(t *testing.T) *env {
		t.Helper()
		e := newEnv(t, nil)
		if err := e.targets.Set(ctx, []string{testHost, siteName, kubeName, "::1", "10.20.0.5"}); err != nil {
			t.Fatalf("Set targets: %v", err)
		}
		return e
	}

	t.Run("ASCII case differences reach the fixture with the canonical name", func(t *testing.T) {
		e := setup(t)
		for _, tc := range []struct {
			name string
			req  Request
			want string
		}{
			{"host", Request{Host: "Site.Internal.Example"}, siteName},
			{"server name", Request{Host: testHost, ServerName: "KUBE.internal.EXAMPLE"}, kubeName},
		} {
			fx := k8s.NewTLS(t, tc.want)
			e.dialer.backend = fx.Addr()
			e.tr.rootCAs = fx.CAPool()
			tc.req.Port, tc.req.TLS = testPort, true
			res, err := e.tr.Get(ctx, tc.req)
			if err != nil || res.Outcome != OutcomeResponded {
				t.Fatalf("%s: Get = %+v, %v; want a response", tc.name, res, err)
			}
			obs := fx.Observations()
			if len(obs) != 1 || obs[0].Host != tc.want || obs[0].SNI != tc.want {
				t.Fatalf("%s: fixture observed %+v, want one request with Host and SNI %q", tc.name, obs, tc.want)
			}
		}
	})

	cases := []struct {
		name string
		req  Request
	}{
		{"host long s", Request{Host: "\u017Fite.internal.example"}},
		{"host kelvin sign", Request{Host: "\u212Aube.internal.example"}},
		{"server name long s", Request{Host: testHost, ServerName: "\u017Fite.internal.example"}},
		{"server name kelvin sign", Request{Host: testHost, ServerName: "\u212Aube.internal.example"}},
		{"host idn", Request{Host: "s\u00EFte.internal.example"}},
		{"host trailing dot", Request{Host: siteName + "."}},
		{"server name trailing dot", Request{Host: testHost, ServerName: siteName + "."}},
		{"host with port", Request{Host: siteName + ":8080"}},
		{"server name with port", Request{Host: testHost, ServerName: siteName + ":8080"}},
		{"bracketed ipv6 host", Request{Host: "[::1]"}},
		{"bracketed ipv6 server name", Request{Host: testHost, ServerName: "[::1]"}},
		{"ipv6 zone host", Request{Host: "::1%25eth0"}},
	}
	for _, tc := range cases {
		for _, useTLS := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/tls=%v", tc.name, useTLS), func(t *testing.T) {
				e := setup(t)
				req := tc.req
				req.Port, req.TLS = testPort, useTLS
				res, err := e.tr.Get(ctx, req)
				if err == nil || res != (Result{}) || !errors.Is(err, ErrRejected) {
					t.Fatalf("Get = %+v, %v; want ErrRejected", res, err)
				}
				e.noNetwork(t)
			})
		}
	}
}

// AC2: every resolved address goes through the shared F4-043 policy; one refused address means no dial.
func TestProbeTransportUsesSharedEndpointPolicy(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name    string
		answers []netip.Addr
	}{
		{"second address outside the policy", []netip.Addr{netip.MustParseAddr(testIP), netip.MustParseAddr("10.30.0.9")}},
		{"loopback answer", []netip.Addr{netip.MustParseAddr(testIP), netip.MustParseAddr("127.0.0.1")}},
		{"metadata answer", []netip.Addr{netip.MustParseAddr("169.254.169.254")}},
		{"mapped loopback answer", []netip.Addr{netip.MustParseAddr("::ffff:127.0.0.1")}},
		{"empty answer", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, nil)
			e.resolver.answers = [][]netip.Addr{tc.answers}
			if _, err := e.tr.Get(ctx, okRequest()); err == nil {
				t.Fatal("Get succeeded, want a refusal")
			}
			if a := e.dialer.Addrs(); len(a) != 0 {
				t.Errorf("dialled %v, want no dial", a)
			}
			if n := e.hits.Load(); n != 0 {
				t.Errorf("backend got %d requests, want 0", n)
			}
		})
	}
}

// AC3: the connection goes to the IP that was checked; a second DNS answer cannot replace it.
func TestProbeTransportPinsValidatedDialIP(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, nil)
	// A rebinding resolver: the first answer is allowed, any later one would be an internal address.
	e.resolver.answers = [][]netip.Addr{{netip.MustParseAddr(testIP)}, {netip.MustParseAddr("169.254.169.254")}}

	res, err := e.tr.Get(ctx, okRequest())
	if err != nil || res.Outcome != OutcomeResponded {
		t.Fatalf("Get = %+v, %v", res, err)
	}
	if got, want := e.dialer.Addrs(), []string{testIP + ":8080"}; len(got) != 1 || got[0] != want[0] {
		t.Errorf("dialled %v, want exactly %v", got, want)
	}
	if n := e.resolver.Calls(); n != 1 {
		t.Errorf("resolver called %d times, want 1 (no second resolution)", n)
	}

	// A connection that ends up somewhere else than the checked address is dropped.
	e = newEnv(t, nil)
	e.dialer.remoteOverride = "10.20.0.77:8080"
	if res, err := e.tr.Get(ctx, okRequest()); err == nil {
		t.Fatalf("Get = %+v, want a refusal for a mismatching remote address", res)
	}
	if n := e.hits.Load(); n != 0 {
		t.Errorf("backend served %d requests over a mismatching connection", n)
	}
}

// AC4: a policy refusal or a credential/header request is turned away with no network call and
// nothing secret in the error or the result.
func TestProbeTransportRejectsPolicyOrCredentialInput(t *testing.T) {
	ctx := context.Background()
	const secret = "s3cr3t-token-value"
	cases := []struct {
		name string
		req  Request
	}{
		{"authorization header", Request{Host: testHost, Port: testPort, Header: http.Header{"Authorization": {"Bearer " + secret}}}},
		{"cookie header", Request{Host: testHost, Port: testPort, Header: http.Header{"Cookie": {"sid=" + secret}}}},
		{"credential field", Request{Host: testHost, Port: testPort, Credential: secret}},
		{"metadata literal", Request{Host: "169.254.169.254", Port: testPort}},
		{"loopback literal", Request{Host: "127.0.0.1", Port: testPort}},
		{"allowlisted literal outside the policy", Request{Host: "10.99.0.1", Port: testPort}},
		{"path with query", Request{Host: testHost, Port: testPort, Path: "/x?token=" + secret}},
		{"path without slash", Request{Host: testHost, Port: testPort, Path: "x"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, nil)
			res, err := e.tr.Get(ctx, tc.req)
			if err == nil {
				t.Fatalf("Get = %+v, want an error", res)
			}
			if res != (Result{}) {
				t.Errorf("result = %+v, want zero", res)
			}
			if strings.Contains(err.Error(), secret) {
				t.Errorf("error leaks the secret: %v", err)
			}
			if a := e.dialer.Addrs(); len(a) != 0 {
				t.Errorf("dialled %v, want no dial", a)
			}
			if n := e.hits.Load(); n != 0 {
				t.Errorf("backend got %d requests, want 0", n)
			}
		})
	}
}

// AC5: a redirect is reported as such and never followed; a disallowed IP surfaces as no result.
func TestProbeSSRFAndRedirectDenied(t *testing.T) {
	ctx := context.Background()
	var seen []string
	var mu sync.Mutex
	e := newEnv(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.Path+"|"+r.Header.Get("Authorization")+"|"+r.Header.Get("Cookie"))
		mu.Unlock()
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data", http.StatusFound)
	})
	res, err := e.tr.Get(ctx, Request{Host: testHost, Port: testPort, Path: "/healthz"})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if res.Outcome != OutcomeRedirect || res.StatusCode != http.StatusFound {
		t.Fatalf("result = %+v, want a redirect outcome with status 302", res)
	}
	if res.Outcome == OutcomeResponded {
		t.Fatal("a redirect must not count as a healthy response")
	}
	if got := e.hits.Load(); got != 1 {
		t.Errorf("backend got %d requests, want exactly the first one", got)
	}
	if a := e.dialer.Addrs(); len(a) != 1 {
		t.Errorf("dialled %v, want one dial (the redirect target is not looked up)", a)
	}
	if n := e.resolver.Calls(); n != 1 {
		t.Errorf("resolver called %d times, want 1", n)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 || seen[0] != "/healthz||" {
		t.Errorf("backend saw %v, want one credentialless /healthz request", seen)
	}

	// A disallowed address appearing at DNS time yields no result at all.
	e2 := newEnv(t, nil)
	e2.resolver.answers = [][]netip.Addr{{netip.MustParseAddr("169.254.169.254")}}
	res, err = e2.tr.Get(ctx, okRequest())
	if err == nil || res != (Result{}) {
		t.Fatalf("Get = %+v, %v; want an error and no result", res, err)
	}
	if !errors.Is(err, netpolicy.ErrDenied) {
		t.Errorf("error = %v, want netpolicy.ErrDenied", err)
	}
}

// AC6: the call ends at the time limit or on cancellation; a fixture loopback URL handed to the
// production constructor is refused without a single connection.
func TestProbeTransportTimeoutAndTestIsolation(t *testing.T) {
	t.Run("time limit", func(t *testing.T) {
		e := newEnv(t, nil)
		e.dialer.block = true
		e.tr.timeout = 50 * time.Millisecond
		start := time.Now()
		_, err := e.tr.Get(context.Background(), okRequest())
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v, want a deadline error", err)
		}
		if d := time.Since(start); d > time.Second {
			t.Errorf("Get took %v, want it bounded by the time limit", d)
		}
	})
	t.Run("hanging server", func(t *testing.T) {
		e := newEnv(t, func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
		e.tr.timeout = 100 * time.Millisecond
		start := time.Now()
		_, err := e.tr.Get(context.Background(), okRequest())
		if err == nil {
			t.Fatal("Get succeeded against a hanging server")
		}
		if d := time.Since(start); d > time.Second {
			t.Errorf("Get took %v, want it bounded by the time limit", d)
		}
	})
	t.Run("context cancelled", func(t *testing.T) {
		e := newEnv(t, nil)
		e.dialer.block = true
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(30*time.Millisecond, cancel)
		_, err := e.tr.Get(ctx, okRequest())
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	})
	t.Run("production constructor refuses the fixture", func(t *testing.T) {
		ctx := context.Background()
		e := newEnv(t, nil)
		fx := k8s.New(t)
		host, portStr, err := net.SplitHostPort(fx.Addr())
		if err != nil {
			t.Fatalf("fixture addr: %v", err)
		}
		port := mustPort(t, portStr)

		// The allowlist names the loopback host; the policy cannot even store a loopback entry.
		if err := e.targets.Set(ctx, []string{host}); err != nil {
			t.Fatalf("Set targets: %v", err)
		}
		// A listener that counts connections proves there was no dial at all.
		counter, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		var accepted atomic.Int32
		acceptedCh := make(chan struct{}, 16)
		go func() {
			for {
				c, err := counter.Accept()
				if err != nil {
					return
				}
				accepted.Add(1)
				acceptedCh <- struct{}{}
				_ = c.Close()
			}
		}()
		t.Cleanup(func() { _ = counter.Close() })
		_, cPortStr, _ := net.SplitHostPort(counter.Addr().String())
		if err := e.policy.Set(ctx, netpolicy.ScopeProbe, netpolicy.Input{Addresses: []string{"10.20.0.0/24"}, Ports: []int{port, mustPort(t, cPortStr)}}); err != nil {
			t.Fatalf("Set policy: %v", err)
		}

		// Positive control: a harmless direct connection moves both counters, so a zero below
		// means "production New never connected", not "the counters do not work".
		directReq, err := http.NewRequestWithContext(ctx, http.MethodGet, fx.URL()+"/", nil)
		if err != nil {
			t.Fatalf("build direct request: %v", err)
		}
		resp, err := fx.Client().Do(directReq)
		if err != nil {
			t.Fatalf("direct fixture request: %v", err)
		}
		_ = resp.Body.Close()
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", counter.Addr().String())
		if err != nil {
			t.Fatalf("direct listener dial: %v", err)
		}
		_ = conn.Close()
		select {
		case <-acceptedCh:
		case <-time.After(2 * time.Second):
			t.Fatal("listener did not report the direct connection")
		}
		baseRequests, baseAccepted := len(fx.Requests()), accepted.Load()
		if baseRequests < 1 || baseAccepted < 1 {
			t.Fatalf("positive control: fixture requests=%d, accepts=%d; want both > 0", baseRequests, baseAccepted)
		}

		prod := New(e.targets, e.policy)
		for _, p := range []int{port, mustPort(t, cPortStr)} {
			res, err := prod.Get(ctx, Request{Host: host, Port: p})
			if err == nil || res != (Result{}) {
				t.Fatalf("production Get(loopback:%d) = %+v, %v; want a refusal", p, res, err)
			}
			if !errors.Is(err, netpolicy.ErrDenied) {
				t.Errorf("error = %v, want netpolicy.ErrDenied", err)
			}
		}
		// Get returned only after the guarded dial refused, so nothing is still in flight here.
		if n := len(fx.Requests()); n != baseRequests {
			t.Errorf("fixture requests %d -> %d, want no production request", baseRequests, n)
		}
		if n := accepted.Load(); n != baseAccepted {
			t.Errorf("listener accepts %d -> %d, want no production connection", baseAccepted, n)
		}
	})
}

// AC7: a fixed system template without a trusted adapter is unmeasurable (unknown), and an
// arbitrary URL offered under a template name never gets a network call.
func TestProbeTransport_FixedTemplateWithoutAdapterIsUnknown(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		req  Request
	}{
		{"template only", Request{Template: "kubernetes-api"}},
		{"arbitrary host under a template name", Request{Template: "kubernetes-api", Host: testHost, Port: testPort}},
		{"loopback under a template name", Request{Template: "zitadel", Host: "127.0.0.1", Port: testPort}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, nil)
			res, err := e.tr.Get(ctx, tc.req)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if res.Outcome != OutcomeUnknown || res.StatusCode != 0 {
				t.Fatalf("result = %+v, want the unknown outcome", res)
			}
			e.noNetwork(t)
		})
	}
}

func mustPort(t *testing.T, s string) int {
	t.Helper()
	n := 0
	for _, r := range s {
		n = n*10 + int(r-'0')
	}
	if n <= 0 || n > 65535 {
		t.Fatalf("bad port %q", s)
	}
	return n
}

// L3: the probe never uses the environment proxy. A proxy in the environment would receive the
// request instead of the pinned, policy-checked dial.
func TestProbeTransportIgnoresEnvironmentProxy(t *testing.T) {
	proxyConns := make(chan struct{}, 8)
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			proxyConns <- struct{}{}
			_ = c.Close()
		}
	}()
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"} {
		t.Setenv(k, "http://"+ln.Addr().String())
	}
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")

	e := newEnv(t, nil)
	res, err := e.tr.Get(context.Background(), okRequest())
	if err != nil || res.Outcome != OutcomeResponded || res.StatusCode != http.StatusOK {
		t.Fatalf("Get with a proxy in the environment = %+v, %v; want a direct 200", res, err)
	}
	if got := e.dialer.Addrs(); len(got) != 1 || got[0] != fmt.Sprintf("%s:%d", testIP, testPort) {
		t.Fatalf("dialled %v, want the one checked address", got)
	}
	select {
	case <-proxyConns:
		t.Fatal("the probe connected to the environment proxy")
	default:
	}
}
