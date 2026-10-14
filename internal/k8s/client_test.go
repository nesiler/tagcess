package k8s

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/netpolicy"
	"github.com/nesiler/tagcess/internal/store"
	k8sfix "github.com/nesiler/tagcess/test/k8s"
)

const (
	apiHost = "k8s.example.test"
	apiIP   = "10.20.0.5"
	apiPort = 6443
)

// pki is a CA generated at test time and a leaf it signed.
type pki struct {
	caPEM string
	leaf  tls.Certificate
}

type leafOpts struct {
	dns       []string
	ips       []net.IP
	notBefore time.Time
	notAfter  time.Time
}

func newPKI(t *testing.T, o leafOpts) pki {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "tagcess client test CA"},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	if o.notBefore.IsZero() {
		o.notBefore = time.Now().Add(-time.Hour)
	}
	if o.notAfter.IsZero() {
		o.notAfter = time.Now().Add(time.Hour)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "k8s-api"},
		DNSNames:     o.dns,
		IPAddresses:  o.ips,
		NotBefore:    o.notBefore,
		NotAfter:     o.notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	return pki{
		caPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})),
		leaf:  tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey},
	}
}

// fakeResolver answers every lookup with a fixed list and counts calls.
type fakeResolver struct {
	mu    sync.Mutex
	addrs []netip.Addr
	calls int
}

func (r *fakeResolver) LookupNetIP(_ context.Context, _, _ string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	return r.addrs, nil
}

func (r *fakeResolver) Calls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

type shiftedConn struct {
	net.Conn
	remote net.Addr
}

func (c shiftedConn) RemoteAddr() net.Addr { return c.remote }

// fakeDialer records every dial and connects to the local TLS server instead, reporting the dialled
// address as the remote one so the guard's "reached the checked address" test passes.
type fakeDialer struct {
	backend string
	mu      sync.Mutex
	addrs   []string
}

func (d *fakeDialer) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.addrs = append(d.addrs, address)
	d.mu.Unlock()
	c, err := (&net.Dialer{}).DialContext(ctx, network, d.backend)
	if err != nil {
		return nil, err
	}
	return shiftedConn{Conn: c, remote: net.TCPAddrFromAddrPort(netip.MustParseAddrPort(address))}, nil
}

func (d *fakeDialer) Addrs() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.addrs...)
}

// seenRequest is one request that got through the TLS handshake to the API stand-in.
type seenRequest struct {
	Method, Path, Query, Authorization string
}

// apiEnv is a TLS API stand-in over the F4-001 fixture: the stand-in checks the bearer token,
// records every request and forwards to the fixture, which serves the pages and failures.
type apiEnv struct {
	t        *testing.T
	fx       *k8sfix.Fixture
	srv      *httptest.Server
	pki      pki
	token    string
	prefix   string // endpoint path prefix the stand-in strips
	policy   *netpolicy.Store
	resolver *fakeResolver
	dialer   *fakeDialer

	mu        sync.Mutex
	seen      []seenRequest
	intercept func(w http.ResponseWriter, r *http.Request) bool
}

type envOpts struct {
	leaf       leafOpts
	prefix     string
	policyAddr []string // default 10.20.0.0/24
	policyPort []int    // default apiPort
	noPolicy   bool
}

func newAPIEnv(t *testing.T, o envOpts) *apiEnv {
	t.Helper()
	if o.leaf.dns == nil && o.leaf.ips == nil {
		o.leaf.dns = []string{apiHost}
	}
	e := &apiEnv{t: t, fx: k8sfix.New(t), pki: newPKI(t, o.leaf), token: sentinel(t), prefix: o.prefix}

	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "tagcess.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	e.policy = netpolicy.New(st.DB(), st.Queries())
	if !o.noPolicy {
		addrs, ports := o.policyAddr, o.policyPort
		if addrs == nil {
			addrs = []string{"10.20.0.0/24"}
		}
		if ports == nil {
			ports = []int{apiPort}
		}
		if err := e.policy.Set(context.Background(), netpolicy.ScopeAPI, netpolicy.Input{Addresses: addrs, Ports: ports}); err != nil {
			t.Fatalf("set API policy: %v", err)
		}
	}

	upstream, err := url.Parse(e.fx.URL())
	if err != nil {
		t.Fatalf("parse fixture URL: %v", err)
	}
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	e.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		e.seen = append(e.seen, seenRequest{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Get("Authorization")})
		hook, token := e.intercept, e.token
		e.mu.Unlock()
		if hook != nil && hook(w, r) {
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, `{"kind":"Status","code":401}`, http.StatusUnauthorized)
			return
		}
		r.URL.Path = strings.TrimPrefix(r.URL.Path, e.prefix)
		proxy.ServeHTTP(w, r)
	}))
	e.srv.TLS = &tls.Config{Certificates: []tls.Certificate{e.pki.leaf}, MinVersion: tls.VersionTLS12}
	e.srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	e.srv.StartTLS()
	t.Cleanup(e.srv.Close)

	e.resolver = &fakeResolver{addrs: []netip.Addr{netip.MustParseAddr(apiIP)}}
	e.dialer = &fakeDialer{backend: e.srv.Listener.Addr().String()}
	return e
}

func (e *apiEnv) Seen() []seenRequest {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]seenRequest(nil), e.seen...)
}

func (e *apiEnv) setIntercept(f func(w http.ResponseWriter, r *http.Request) bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.intercept = f
}

func (e *apiEnv) cred() Credential {
	e.mu.Lock()
	defer e.mu.Unlock()
	return Credential{Endpoint: fmt.Sprintf("https://%s:%d%s", apiHost, apiPort, e.prefix), CAData: e.pki.caPEM, Token: e.token}
}

// setToken changes the only token the stand-in accepts, like an expired token being replaced.
func (e *apiEnv) setToken(token string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.token = token
}

func (e *apiEnv) client(t *testing.T, c Credential, timeout time.Duration) *Client {
	t.Helper()
	guard := netpolicy.NewGuard(e.policy, e.resolver, e.dialer.Dial)
	cl, err := newClient(c, guard.DialContext(netpolicy.ScopeAPI), timeout)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	return cl
}

// noNetwork asserts that nothing was looked up, dialled or received.
func (e *apiEnv) noNetwork(t *testing.T) {
	t.Helper()
	if a := e.dialer.Addrs(); len(a) != 0 {
		t.Errorf("dialled %v, want no dial", a)
	}
	if s := e.Seen(); len(s) != 0 {
		t.Errorf("API received %+v, want nothing", s)
	}
}

func item(name string) map[string]any {
	return map[string]any{"metadata": map[string]any{"name": name, "namespace": "web", "uid": "uid-" + name, "resourceVersion": "1"}}
}

func nameList[T any](items []T, name func(T) string) []string {
	var out []string
	for _, it := range items {
		out = append(out, name(it))
	}
	return out
}

func ingressName(i Ingress) string { return i.Metadata.Name }

// AC1: only GETs to the networking.k8s.io/v1 ingresses and ingressclasses and core/v1 services list
// endpoints are sent, per selected namespace; a namespace that is not a plain name sends nothing.
func TestK8sClient_OnlySelectedReadEndpoints(t *testing.T) {
	for _, prefix := range []string{"", "/k8s/clusters/c-1"} {
		t.Run("prefix="+prefix, func(t *testing.T) {
			e := newAPIEnv(t, envOpts{prefix: prefix})
			for _, ns := range []string{"web", "apps"} {
				e.fx.ServeList(k8sfix.Ingresses, ns, k8sfix.Page{Items: []any{item("i-" + ns)}})
				e.fx.ServeList(k8sfix.Services, ns, k8sfix.Page{Items: []any{item("s-" + ns)}})
			}
			e.fx.ServeList(k8sfix.IngressClasses, "", k8sfix.Page{Items: []any{item("traefik")}})
			cl := e.client(t, e.cred(), time.Second)
			ctx := context.Background()

			for _, ns := range []string{"web", "apps"} {
				ings, err := cl.ListIngresses(ctx, ns)
				if err != nil || len(ings) != 1 || ings[0].Metadata.Name != "i-"+ns {
					t.Fatalf("ListIngresses(%s) = %+v, %v", ns, ings, err)
				}
				svcs, err := cl.ListServices(ctx, ns)
				if err != nil || len(svcs) != 1 || svcs[0].Metadata.Name != "s-"+ns {
					t.Fatalf("ListServices(%s) = %+v, %v", ns, svcs, err)
				}
			}
			classes, err := cl.ListIngressClasses(ctx)
			if err != nil || len(classes) != 1 || classes[0].Metadata.Name != "traefik" {
				t.Fatalf("ListIngressClasses = %+v, %v", classes, err)
			}

			var got []string
			for _, r := range e.Seen() {
				if r.Method != http.MethodGet {
					t.Errorf("method %s on %s, want GET only", r.Method, r.Path)
				}
				if r.Authorization != "Bearer "+e.token {
					t.Errorf("request to %s lacks the bearer token", r.Path)
				}
				got = append(got, strings.TrimPrefix(r.Path, prefix))
			}
			want := []string{
				"/apis/networking.k8s.io/v1/namespaces/web/ingresses",
				"/api/v1/namespaces/web/services",
				"/apis/networking.k8s.io/v1/namespaces/apps/ingresses",
				"/api/v1/namespaces/apps/services",
				"/apis/networking.k8s.io/v1/ingressclasses",
			}
			if !slices.Equal(got, want) {
				t.Fatalf("paths = %v\nwant    %v", got, want)
			}
			for _, r := range e.Seen() {
				if !strings.HasPrefix(r.Path, prefix+"/api") {
					t.Errorf("path %q outside the endpoint prefix %q", r.Path, prefix)
				}
			}
		})
	}

	t.Run("namespace must be a plain name", func(t *testing.T) {
		e := newAPIEnv(t, envOpts{})
		cl := e.client(t, e.cred(), time.Second)
		for _, ns := range []string{"", "WEB", "a b", "web/../kube-system", "web?watch=1", "web%2Fx", "-web", strings.Repeat("a", 64)} {
			if _, err := cl.ListIngresses(context.Background(), ns); err == nil {
				t.Errorf("ListIngresses(%q) succeeded", ns)
			}
			if _, err := cl.ListServices(context.Background(), ns); err == nil {
				t.Errorf("ListServices(%q) succeeded", ns)
			}
		}
		e.noNetwork(t)
		if n := e.resolver.Calls(); n != 0 {
			t.Errorf("resolver called %d times, want 0", n)
		}
	})
}

// AC2: a list that continues is read to the last page and returned as one complete result.
func TestK8sClient_CompletesPagination(t *testing.T) {
	e := newAPIEnv(t, envOpts{})
	e.fx.ServeList(k8sfix.Ingresses, "web",
		k8sfix.Page{Items: []any{item("a"), item("b")}},
		k8sfix.Page{Items: []any{item("c")}},
		k8sfix.Page{Items: []any{item("d"), item("e")}},
	)
	cl := e.client(t, e.cred(), time.Second)

	got, err := cl.ListIngresses(context.Background(), "web")
	if err != nil {
		t.Fatalf("ListIngresses: %v", err)
	}
	if want := []string{"a", "b", "c", "d", "e"}; !slices.Equal(nameList(got, ingressName), want) {
		t.Fatalf("items = %v, want %v", nameList(got, ingressName), want)
	}
	var conts []string
	for _, r := range e.fx.Requests() {
		conts = append(conts, r.Continue)
	}
	if want := []string{"", "1-ingresses-web", "2-ingresses-web"}; !slices.Equal(conts, want) {
		t.Fatalf("continue tokens sent = %q, want %q", conts, want)
	}
	for _, r := range e.Seen() {
		if !strings.Contains(r.Query, "limit=") {
			t.Errorf("request %s?%s sets no page limit", r.Path, r.Query)
		}
	}

	t.Run("a repeated continue token ends the read", func(t *testing.T) {
		e := newAPIEnv(t, envOpts{})
		e.setIntercept(func(w http.ResponseWriter, r *http.Request) bool {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"kind":"IngressList","metadata":{"continue":"same"},"items":[]}`)
			return true
		})
		cl := e.client(t, e.cred(), time.Second)
		got, err := cl.ListIngresses(context.Background(), "web")
		if err == nil || got != nil {
			t.Fatalf("ListIngresses = %v, %v; want nil and an error", got, err)
		}
		if n := len(e.Seen()); n > 3 {
			t.Errorf("%d requests, want the loop cut after a repeated token", n)
		}
	})
}

// AC2: the page-count and page-size limits refuse a read instead of returning part of it. A chain
// of unique continue tokens is bounded too, and the limits themselves are accepted exactly.
func TestK8sClient_PageLimits(t *testing.T) {
	t.Run("empty and null items are valid empty pages", func(t *testing.T) {
		for _, body := range []string{
			`{"kind":"IngressList","metadata":{},"items":[]}`,
			`{"kind":"IngressList","items":null}`,
		} {
			e := newAPIEnv(t, envOpts{})
			e.setIntercept(func(w http.ResponseWriter, _ *http.Request) bool {
				_, _ = io.WriteString(w, body)
				return true
			})
			got, err := e.client(t, e.cred(), time.Second).ListIngresses(context.Background(), "web")
			if err != nil || got == nil || len(got) != 0 {
				t.Errorf("%s: ListIngresses = %#v, %v; want an empty non-nil list", body, got, err)
			}
		}
	})

	chain := func(t *testing.T, lastPage int) (*apiEnv, *Client) {
		t.Helper()
		e := newAPIEnv(t, envOpts{})
		var mu sync.Mutex
		n := 0
		e.setIntercept(func(w http.ResponseWriter, _ *http.Request) bool {
			mu.Lock()
			n++
			page := n
			mu.Unlock()
			cont := ""
			if page < lastPage {
				cont = fmt.Sprintf("unique-%d", page)
			}
			_, _ = io.WriteString(w, fmt.Sprintf(`{"kind":"IngressList","metadata":{"continue":%q},"items":[{"metadata":{"name":"i%d"}}]}`, cont, page))
			return true
		})
		return e, e.client(t, e.cred(), 5*time.Second)
	}

	t.Run("exactly the maximum number of pages succeeds", func(t *testing.T) {
		e, cl := chain(t, maxPages)
		got, err := cl.ListIngresses(context.Background(), "web")
		if err != nil || len(got) != maxPages {
			t.Fatalf("ListIngresses = %d items, %v; want %d items", len(got), err, maxPages)
		}
		if n := len(e.Seen()); n != maxPages {
			t.Errorf("%d requests, want %d", n, maxPages)
		}
	})

	t.Run("a page beyond the maximum is refused", func(t *testing.T) {
		e, cl := chain(t, maxPages+1)
		got, err := cl.ListIngresses(context.Background(), "web")
		if err == nil || got != nil {
			t.Fatalf("ListIngresses = %d items, %v; want nil and an error", len(got), err)
		}
		var re *ReadError
		if !errors.As(err, &re) || re.Page != maxPages+1 || !strings.Contains(re.Reason, "too many pages") {
			t.Errorf("error = %v (%+v), want a too-many-pages refusal at page %d", err, re, maxPages+1)
		}
		if n := len(e.Seen()); n != maxPages {
			t.Errorf("%d requests, want %d and none after the refusal", n, maxPages)
		}
	})

	// body is valid JSON of exactly size bytes: an empty list padded by an ignored field.
	body := func(size int) string {
		const head, tail = `{"kind":"IngressList","items":[],"pad":"`, `"}`
		return head + strings.Repeat("x", size-len(head)-len(tail)) + tail
	}
	size := func(t *testing.T, n int) (*apiEnv, *Client) {
		t.Helper()
		e := newAPIEnv(t, envOpts{})
		b := body(n)
		if len(b) != n {
			t.Fatalf("test body is %d bytes, want %d", len(b), n)
		}
		e.setIntercept(func(w http.ResponseWriter, _ *http.Request) bool {
			_, _ = io.WriteString(w, b)
			return true
		})
		return e, e.client(t, e.cred(), 10*time.Second)
	}

	t.Run("a page of exactly the byte limit succeeds", func(t *testing.T) {
		_, cl := size(t, maxPageBytes)
		got, err := cl.ListIngresses(context.Background(), "web")
		if err != nil || len(got) != 0 {
			t.Fatalf("ListIngresses = %v, %v; want an empty list", got, err)
		}
	})

	t.Run("a page one byte over the limit is refused", func(t *testing.T) {
		e, cl := size(t, maxPageBytes+1)
		got, err := cl.ListIngresses(context.Background(), "web")
		if err == nil || got != nil {
			t.Fatalf("ListIngresses = %v, %v; want nil and an error", got, err)
		}
		var re *ReadError
		if !errors.As(err, &re) || !strings.Contains(re.Reason, "too large") {
			t.Errorf("error = %v, want a page-too-large refusal", err)
		}
		if n := len(e.Seen()); n != 1 {
			t.Errorf("%d requests, want exactly 1", n)
		}
	})
}

// leaksToken reports whether the error, any error it unwraps to, or a ReadError's Reason or Err
// contains the token.
func leaksToken(err error, token string) bool {
	for ; err != nil; err = errors.Unwrap(err) {
		if strings.Contains(err.Error(), token) {
			return true
		}
		var re *ReadError
		if errors.As(err, &re) && (strings.Contains(re.Reason, token) || (re.Err != nil && strings.Contains(re.Err.Error(), token))) {
			return true
		}
	}
	return false
}

// AC3: any page that answers 401, 403, times out, does not decode or is otherwise not a clean list
// makes the whole read an error: no partial or empty result, the failing source and scope in the
// message, never the token.
func TestK8sClient_PartialReadIsError(t *testing.T) {
	type tc struct {
		name       string
		onPage     int // 1-based page that misbehaves
		hook       func(w http.ResponseWriter, r *http.Request)
		wantStatus int
		wantIs     error
		echoes     bool // the response carries the bearer value; checked as a positive control
	}
	var echoMu sync.Mutex
	var echoed string
	status := func(code int) func(http.ResponseWriter, *http.Request) {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			_, _ = io.WriteString(w, `{"kind":"Status","status":"Failure","code":`+fmt.Sprint(code)+`}`)
		}
	}
	cases := []tc{
		{name: "401 on page 2", onPage: 2, hook: status(401), wantStatus: 401},
		{name: "403 on page 2", onPage: 2, hook: status(403), wantStatus: 403},
		{name: "401 on page 1", onPage: 1, hook: status(401), wantStatus: 401},
		{name: "403 on page 1", onPage: 1, hook: status(403), wantStatus: 403},
		{name: "410 expired continue", onPage: 2, hook: status(410), wantStatus: 410},
		{name: "500 on page 3", onPage: 3, hook: status(500), wantStatus: 500},
		{name: "decode error", onPage: 2, hook: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"kind":"IngressList","items":[{"metadata":`)
		}},
		{name: "wrong list kind", onPage: 2, hook: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"kind":"ServiceList","items":[]}`)
		}},
		{name: "wrong list kind echoes the token", onPage: 2, echoes: true, hook: func(w http.ResponseWriter, r *http.Request) {
			tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			echoMu.Lock()
			echoed = tok
			echoMu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, fmt.Sprintf(`{"kind":%q,"items":[]}`, tok))
		}},
		{name: "missing items on page 1", onPage: 1, hook: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"kind":"IngressList"}`)
		}},
		{name: "missing items on page 2", onPage: 2, hook: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"kind":"IngressList","metadata":{"continue":""}}`)
		}},
		{name: "timeout", onPage: 2, wantIs: context.DeadlineExceeded, hook: func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newAPIEnv(t, envOpts{})
			e.fx.ServeList(k8sfix.Ingresses, "web",
				k8sfix.Page{Items: []any{item("a")}}, k8sfix.Page{Items: []any{item("b")}}, k8sfix.Page{Items: []any{item("c")}})
			var mu sync.Mutex
			page := 0
			e.setIntercept(func(w http.ResponseWriter, r *http.Request) bool {
				mu.Lock()
				page++
				n := page
				mu.Unlock()
				if n == c.onPage {
					c.hook(w, r)
					return true
				}
				return false
			})
			timeout := time.Second
			if c.wantIs != nil {
				timeout = 150 * time.Millisecond
			}
			cl := e.client(t, e.cred(), timeout)

			got, err := cl.ListIngresses(context.Background(), "web")
			if err == nil {
				t.Fatalf("ListIngresses succeeded with %v", got)
			}
			if got != nil {
				t.Errorf("result = %v with an error, want nil", got)
			}
			msg := err.Error()
			for _, want := range []string{"ingresses", `"web"`} {
				if !strings.Contains(msg, want) {
					t.Errorf("error %q does not name %s", msg, want)
				}
			}
			if leaksToken(err, e.token) {
				t.Errorf("error or one of its causes leaks the token: %q", msg)
			}
			if c.echoes {
				echoMu.Lock()
				got := echoed
				echoMu.Unlock()
				if got != e.token {
					t.Errorf("positive control: the API echoed %q, want the bearer value", got)
				}
			}
			var re *ReadError
			if !errors.As(err, &re) {
				t.Fatalf("error %T is not a *ReadError", err)
			}
			if c.wantStatus != 0 && re.Status != c.wantStatus {
				t.Errorf("Status = %d, want %d", re.Status, c.wantStatus)
			}
			if c.wantIs != nil && !errors.Is(err, c.wantIs) {
				t.Errorf("error %v is not %v", err, c.wantIs)
			}
		})
	}

	t.Run("IngressClass failure names the cluster scope", func(t *testing.T) {
		e := newAPIEnv(t, envOpts{})
		e.fx.Fail(k8sfix.IngressClasses, "", k8sfix.Failure{Status: 403})
		cl := e.client(t, e.cred(), time.Second)
		got, err := cl.ListIngressClasses(context.Background())
		if err == nil || got != nil {
			t.Fatalf("ListIngressClasses = %v, %v; want nil and an error", got, err)
		}
		if msg := err.Error(); !strings.Contains(msg, "ingressclasses") || !strings.Contains(msg, "cluster") || leaksToken(err, e.token) {
			t.Errorf("error %q", msg)
		}
	})
}

// AC4: the API certificate must chain to the given CA and match the endpoint host or the separate
// TLS server name; a wrong CA, a SAN mismatch or an expired certificate is refused before the token
// leaves.
func TestK8sClient_TLSVerification(t *testing.T) {
	const otherName = "other.example.test"
	ipEndpoint := func(e *apiEnv, serverName string) Credential {
		c := e.cred()
		c.Endpoint = fmt.Sprintf("https://%s:%d", apiIP, apiPort)
		c.TLSServerName = serverName
		return c
	}
	cases := []struct {
		name  string
		leaf  leafOpts
		cred  func(e *apiEnv) Credential
		wrong bool // use another CA on the client side
		ok    bool
	}{
		{name: "hostname matches", leaf: leafOpts{dns: []string{apiHost}}, cred: (*apiEnv).cred, ok: true},
		{name: "IP endpoint with separate server name", leaf: leafOpts{dns: []string{apiHost}}, ok: true,
			cred: func(e *apiEnv) Credential { return ipEndpoint(e, apiHost) }},
		{name: "IP endpoint matched by IP SAN", leaf: leafOpts{ips: []net.IP{net.ParseIP(apiIP)}}, ok: true,
			cred: func(e *apiEnv) Credential { return ipEndpoint(e, "") }},
		{name: "wrong CA", leaf: leafOpts{dns: []string{apiHost}}, cred: (*apiEnv).cred, wrong: true},
		{name: "SAN does not match the host", leaf: leafOpts{dns: []string{otherName}}, cred: (*apiEnv).cred},
		{name: "SAN does not match the server name", leaf: leafOpts{dns: []string{otherName}},
			cred: func(e *apiEnv) Credential { return ipEndpoint(e, apiHost) }},
		{name: "IP endpoint without server name and without IP SAN", leaf: leafOpts{dns: []string{apiHost}},
			cred: func(e *apiEnv) Credential { return ipEndpoint(e, "") }},
		{name: "expired certificate", leaf: leafOpts{dns: []string{apiHost}, notBefore: time.Now().Add(-48 * time.Hour), notAfter: time.Now().Add(-24 * time.Hour)}, cred: (*apiEnv).cred},
		{name: "not yet valid certificate", leaf: leafOpts{dns: []string{apiHost}, notBefore: time.Now().Add(24 * time.Hour), notAfter: time.Now().Add(48 * time.Hour)}, cred: (*apiEnv).cred},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newAPIEnv(t, envOpts{leaf: c.leaf})
			e.fx.ServeList(k8sfix.IngressClasses, "", k8sfix.Page{Items: []any{item("traefik")}})
			cred := c.cred(e)
			if c.wrong {
				cred.CAData = newPKI(t, leafOpts{dns: []string{apiHost}}).caPEM
			}
			cl := e.client(t, cred, time.Second)

			got, err := cl.ListIngressClasses(context.Background())
			if c.ok {
				if err != nil || len(got) != 1 {
					t.Fatalf("ListIngressClasses = %v, %v; want one class", got, err)
				}
				return
			}
			if err == nil || got != nil {
				t.Fatalf("ListIngressClasses = %v, %v; want nil and an error", got, err)
			}
			if strings.Contains(err.Error(), e.token) {
				t.Errorf("error leaks the token: %q", err)
			}
			if s := e.Seen(); len(s) != 0 {
				t.Errorf("API received %+v despite the failed handshake", s)
			}
		})
	}

	t.Run("an insecure credential is refused", func(t *testing.T) {
		e := newAPIEnv(t, envOpts{})
		for name, mutate := range map[string]func(c *Credential){
			"http endpoint": func(c *Credential) { c.Endpoint = "http://" + apiHost + ":6443" },
			"no CA":         func(c *Credential) { c.CAData = "" },
			"no token":      func(c *Credential) { c.Token = "" },
		} {
			c := e.cred()
			mutate(&c)
			if _, err := newClient(c, e.dialer.Dial, time.Second); err == nil {
				t.Errorf("%s: client built", name)
			}
		}
	})
}

// AC5: a redirect is never followed (no second dial, no token to the new target) and a finished
// context ends the call as a failure.
func TestK8sClient_RedirectAndTimeoutStopRead(t *testing.T) {
	for _, code := range []int{301, 302, 303, 307, 308} {
		t.Run(fmt.Sprintf("redirect %d", code), func(t *testing.T) {
			e := newAPIEnv(t, envOpts{})
			e.setIntercept(func(w http.ResponseWriter, r *http.Request) bool {
				http.Redirect(w, r, "https://10.20.0.99:6443/elsewhere", code)
				return true
			})
			cl := e.client(t, e.cred(), time.Second)
			got, err := cl.ListIngresses(context.Background(), "web")
			if err == nil || got != nil {
				t.Fatalf("ListIngresses = %v, %v; want nil and an error", got, err)
			}
			if a := e.dialer.Addrs(); !slices.Equal(a, []string{apiIP + ":6443"}) {
				t.Errorf("dialled %v, want only the API address", a)
			}
			if s := e.Seen(); len(s) != 1 {
				t.Errorf("API received %d requests, want 1", len(s))
			}
			if strings.Contains(err.Error(), e.token) {
				t.Errorf("error leaks the token: %q", err)
			}
		})
	}

	t.Run("context cancelled before the call", func(t *testing.T) {
		e := newAPIEnv(t, envOpts{})
		e.fx.ServeList(k8sfix.Ingresses, "web", k8sfix.Page{Items: []any{item("a")}})
		cl := e.client(t, e.cred(), time.Second)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		got, err := cl.ListIngresses(ctx, "web")
		if err == nil || got != nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("ListIngresses = %v, %v; want nil and context.Canceled", got, err)
		}
		e.noNetwork(t)
	})

	t.Run("context ends while the API hangs", func(t *testing.T) {
		e := newAPIEnv(t, envOpts{})
		e.fx.Fail(k8sfix.Ingresses, "web", k8sfix.Failure{Hang: true})
		cl := e.client(t, e.cred(), 10*time.Second)
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		defer cancel()
		start := time.Now()
		got, err := cl.ListIngresses(ctx, "web")
		if err == nil || got != nil || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("ListIngresses = %v, %v; want nil and context.DeadlineExceeded", got, err)
		}
		if d := time.Since(start); d > 3*time.Second {
			t.Errorf("took %v, the context deadline was not honoured", d)
		}
	})

	t.Run("the client timeout bounds one call", func(t *testing.T) {
		e := newAPIEnv(t, envOpts{})
		e.fx.Fail(k8sfix.Ingresses, "web", k8sfix.Failure{Hang: true})
		cl := e.client(t, e.cred(), 150*time.Millisecond)
		if _, err := cl.ListIngresses(context.Background(), "web"); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v, want context.DeadlineExceeded", err)
		}
	})
}

// AC7: the F4-043 API policy governs every connection (resolution and dial) and an environment HTTP
// proxy is never used; a refusal means no dial, no request and no token on the wire.
func TestK8sClient_UsesSharedPolicyAndNoProxy(t *testing.T) {
	denied := []struct {
		name         string
		opts         envOpts
		resolve      []netip.Addr
		wantResolves int
	}{
		{name: "no policy stored", opts: envOpts{noPolicy: true}, wantResolves: 0},
		{name: "address outside the allowed CIDR", opts: envOpts{policyAddr: []string{"10.30.0.0/24"}}, wantResolves: 1},
		{name: "port outside the allowed ports", opts: envOpts{policyPort: []int{443}}, wantResolves: 0},
		{name: "one forbidden answer refuses the name", opts: envOpts{},
			resolve: []netip.Addr{netip.MustParseAddr(apiIP), netip.MustParseAddr("169.254.169.254")}, wantResolves: 1},
		{name: "resolves to loopback", opts: envOpts{}, resolve: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, wantResolves: 1},
	}
	for _, c := range denied {
		t.Run(c.name, func(t *testing.T) {
			e := newAPIEnv(t, envOpts{policyAddr: c.opts.policyAddr, policyPort: c.opts.policyPort, noPolicy: c.opts.noPolicy})
			e.fx.ServeList(k8sfix.IngressClasses, "", k8sfix.Page{Items: []any{item("traefik")}})
			if c.resolve != nil {
				e.resolver.addrs = c.resolve
			}
			cl := e.client(t, e.cred(), time.Second)
			got, err := cl.ListIngressClasses(context.Background())
			if err == nil || got != nil {
				t.Fatalf("ListIngressClasses = %v, %v; want nil and an error", got, err)
			}
			if !errors.Is(err, netpolicy.ErrDenied) {
				t.Errorf("error %v is not netpolicy.ErrDenied", err)
			}
			if strings.Contains(err.Error(), e.token) {
				t.Errorf("error leaks the token: %q", err)
			}
			e.noNetwork(t)
			if n := e.resolver.Calls(); n != c.wantResolves {
				t.Errorf("resolver called %d times, want %d", n, c.wantResolves)
			}
		})
	}

	t.Run("environment proxy is not used", func(t *testing.T) {
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

		e := newAPIEnv(t, envOpts{})
		e.fx.ServeList(k8sfix.IngressClasses, "", k8sfix.Page{Items: []any{item("traefik")}})
		cl := e.client(t, e.cred(), time.Second)
		if tr, ok := cl.http.Transport.(*http.Transport); !ok || tr.Proxy != nil {
			t.Fatalf("transport %T has a proxy function, want none", cl.http.Transport)
		}
		got, err := cl.ListIngressClasses(context.Background())
		if err != nil || len(got) != 1 {
			t.Fatalf("ListIngressClasses = %v, %v", got, err)
		}
		if a := e.dialer.Addrs(); !reflect.DeepEqual(a, []string{apiIP + ":6443"}) {
			t.Errorf("dialled %v, want only the API address", a)
		}
		select {
		case <-proxyConns:
			t.Errorf("the environment proxy received a connection")
		case <-time.After(50 * time.Millisecond):
		}
	})
}

// Transport and protocol errors carry raw text (the request URL with the continue token, the bad
// status line the server sent). None of it may reach the error, its Reason, its Err or any cause.
func TestK8sClient_TransportErrorsCarryNoRawText(t *testing.T) {
	t.Run("continue echoes the bearer and page 2 times out", func(t *testing.T) {
		e := newAPIEnv(t, envOpts{})
		var mu sync.Mutex
		var echoedAuth, seenContinue string
		page := 0
		e.setIntercept(func(w http.ResponseWriter, r *http.Request) bool {
			mu.Lock()
			page++
			n := page
			if n == 2 {
				seenContinue = r.URL.Query().Get("continue")
			}
			mu.Unlock()
			tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if n == 1 {
				mu.Lock()
				echoedAuth = tok
				mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, fmt.Sprintf(`{"kind":"IngressList","metadata":{"continue":%q},"items":[]}`, tok))
				return true
			}
			<-r.Context().Done()
			return true
		})
		cl := e.client(t, e.cred(), 150*time.Millisecond)

		got, err := cl.ListIngresses(context.Background(), "web")
		if err == nil || got != nil {
			t.Fatalf("ListIngresses = %v, %v; want nil and an error", got, err)
		}
		mu.Lock()
		echo, cont := echoedAuth, seenContinue
		mu.Unlock()
		if echo != e.token || cont != e.token {
			t.Fatalf("positive control: API echoed %q and received continue %q, want the bearer value in both", echo, cont)
		}
		if leaksToken(err, e.token) || leaksToken(err, cont) {
			t.Errorf("error chain leaks the token: %q / %q", err, errors.Unwrap(err))
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("error %v is not context.DeadlineExceeded", err)
		}
	})

	t.Run("the status line echoes the bearer", func(t *testing.T) {
		e := newAPIEnv(t, envOpts{})
		var mu sync.Mutex
		var echoed string
		e.setIntercept(func(w http.ResponseWriter, r *http.Request) bool {
			tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			mu.Lock()
			echoed = tok
			mu.Unlock()
			conn, rw, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return true
			}
			defer func() { _ = conn.Close() }()
			_, _ = rw.WriteString("HTTP/1.1 " + tok + " Nope\r\nContent-Length: 0\r\n\r\n")
			_ = rw.Flush()
			return true
		})
		cl := e.client(t, e.cred(), time.Second)

		got, err := cl.ListIngresses(context.Background(), "web")
		if err == nil || got != nil {
			t.Fatalf("ListIngresses = %v, %v; want nil and an error", got, err)
		}
		mu.Lock()
		echo := echoed
		mu.Unlock()
		if echo != e.token {
			t.Fatalf("positive control: API echoed %q, want the bearer value", echo)
		}
		if leaksToken(err, e.token) {
			t.Errorf("error chain leaks the token: %q / %q", err, errors.Unwrap(err))
		}
	})

	t.Run("classified causes stay matchable", func(t *testing.T) {
		e := newAPIEnv(t, envOpts{noPolicy: true})
		cl := e.client(t, e.cred(), time.Second)
		if _, err := cl.ListIngresses(context.Background(), "web"); !errors.Is(err, netpolicy.ErrDenied) {
			t.Errorf("err = %v, want netpolicy.ErrDenied", err)
		}
	})
}

// The policy check runs in the guarded dial, so every page must dial: a kept-alive connection would
// carry the next request (and the token) past a policy that was narrowed in the meantime.
func TestK8sClient_PolicyNarrowedBetweenPagesIsEnforced(t *testing.T) {
	// serve answers page 1 with a continue token and page 2 with the last page; narrow runs while
	// page 1 is being served.
	run := func(t *testing.T, narrow bool) (*apiEnv, []Ingress, error) {
		e := newAPIEnv(t, envOpts{})
		e.setIntercept(func(w http.ResponseWriter, r *http.Request) bool {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Query().Get("continue") == "" {
				if narrow {
					in := netpolicy.Input{Addresses: []string{"10.30.0.0/24"}, Ports: []int{apiPort}}
					if err := e.policy.Set(context.Background(), netpolicy.ScopeAPI, in); err != nil {
						t.Errorf("narrow policy: %v", err)
					}
				}
				_, _ = io.WriteString(w, `{"kind":"IngressList","metadata":{"continue":"p2"},"items":[{"metadata":{"name":"a"}}]}`)
				return true
			}
			_, _ = io.WriteString(w, `{"kind":"IngressList","metadata":{},"items":[{"metadata":{"name":"b"}}]}`)
			return true
		})
		cl := e.client(t, e.cred(), 5*time.Second)
		got, err := cl.ListIngresses(context.Background(), "web")
		return e, got, err
	}

	t.Run("policy unchanged: two pages succeed, each on its own connection", func(t *testing.T) {
		e, got, err := run(t, false)
		if err != nil {
			t.Fatalf("ListIngresses: %v", err)
		}
		if names := nameList(got, ingressName); !reflect.DeepEqual(names, []string{"a", "b"}) {
			t.Errorf("items = %v, want [a b]", names)
		}
		if n := len(e.Seen()); n != 2 {
			t.Errorf("API saw %d requests, want 2", n)
		}
		if d := e.dialer.Addrs(); len(d) != 2 {
			t.Errorf("dialled %v, want one dial per page", d)
		}
	})

	t.Run("policy narrowed during page 1: page 2 is denied and never sent", func(t *testing.T) {
		e, got, err := run(t, true)
		if err == nil || got != nil {
			t.Fatalf("ListIngresses = %v, %v; want nil and an error", got, err)
		}
		if !errors.Is(err, netpolicy.ErrDenied) {
			t.Errorf("error %v is not netpolicy.ErrDenied", err)
		}
		var re *ReadError
		if !errors.As(err, &re) || re.Page != 2 {
			t.Errorf("error %v, want a ReadError for page 2", err)
		}
		if n := len(e.Seen()); n != 1 {
			t.Errorf("API saw %d requests, want only page 1", n)
		}
		if d := e.dialer.Addrs(); len(d) != 1 {
			t.Errorf("dialled %v, want only the page 1 dial", d)
		}
	})

	t.Run("a second read after narrowing is denied too", func(t *testing.T) {
		e := newAPIEnv(t, envOpts{})
		e.fx.ServeList(k8sfix.IngressClasses, "", k8sfix.Page{Items: []any{item("traefik")}})
		cl := e.client(t, e.cred(), 5*time.Second)
		if _, err := cl.ListIngressClasses(context.Background()); err != nil {
			t.Fatalf("first read: %v", err)
		}
		in := netpolicy.Input{Addresses: []string{"10.30.0.0/24"}, Ports: []int{apiPort}}
		if err := e.policy.Set(context.Background(), netpolicy.ScopeAPI, in); err != nil {
			t.Fatalf("narrow policy: %v", err)
		}
		got, err := cl.ListIngressClasses(context.Background())
		if got != nil || !errors.Is(err, netpolicy.ErrDenied) {
			t.Errorf("second read = %v, %v; want nil and netpolicy.ErrDenied", got, err)
		}
		if n := len(e.Seen()); n != 1 {
			t.Errorf("API saw %d requests, want only the first read", n)
		}
	})
}

// The client holds the same secret as Credential, so it prints without it too: by value or by
// pointer, with fmt and with slog.
func TestK8sClient_NoTokenInFormatting(t *testing.T) {
	e := newAPIEnv(t, envOpts{})
	cl := e.client(t, e.cred(), time.Second)
	token := e.token

	var textBuf, jsonBuf bytes.Buffer
	slog.New(slog.NewTextHandler(&textBuf, nil)).Info("client", "client", cl, "byvalue", *cl)
	slog.New(slog.NewJSONHandler(&jsonBuf, nil)).Info("client", "client", cl, "byvalue", *cl)
	outputs := []string{textBuf.String(), jsonBuf.String()}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		outputs = append(outputs, fmt.Sprintf(verb, cl), fmt.Sprintf(verb, *cl))
	}
	for _, out := range outputs {
		if strings.Contains(out, token) {
			t.Errorf("formatted client leaks the token: %q", out)
		}
		if !strings.Contains(out, "redacted") {
			t.Errorf("formatted client %q does not say it is redacted; the check may read the wrong output", out)
		}
	}

	// Positive control: a struct holding the same fields does print the token.
	type plain struct{ Token string }
	var plainLog bytes.Buffer
	slog.New(slog.NewTextHandler(&plainLog, nil)).Info("client", "client", plain{token})
	for name, out := range map[string]string{
		"%+v of a plain struct":  fmt.Sprintf("%+v", plain{token}),
		"slog of a plain struct": plainLog.String(),
	} {
		if !strings.Contains(out, token) {
			t.Errorf("control %s does not show the token: the leak check cannot fail", name)
		}
	}
}

// A-M2: ClientForProfile refuses a credential for another endpoint or TLS name before any resolve or
// dial; the error names no value.
func TestK8sClientForProfile_Mismatch(t *testing.T) {
	prof := validProfile()
	prof.TLSServerName = "kubernetes.example.test"
	cases := map[string]func(c *Credential){
		"endpoint":        func(c *Credential) { c.Endpoint = "https://10.9.9.9:6443" },
		"tls server name": func(c *Credential) { c.TLSServerName = "other.example.test" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			cred := validCredential(t)
			change(&cred)
			// A nil policy would panic on any dial: the check must come first.
			cl, err := ClientForProfile(prof, cred, nil)
			if cl != nil || !errors.Is(err, ErrCredentialMismatch) {
				t.Fatalf("ClientForProfile = %v, %v; want ErrCredentialMismatch", cl, err)
			}
			if strings.Contains(err.Error(), cred.Token) || strings.Contains(err.Error(), "other.example.test") || strings.Contains(err.Error(), "10.9.9.9") {
				t.Errorf("error echoes a value: %q", err)
			}
		})
	}
	t.Run("a matching credential builds a client", func(t *testing.T) {

		cl, err := ClientForProfile(prof, validCredential(t), newEnv(t).policy)
		if err != nil {
			t.Fatalf("ClientForProfile: %v", err)
		}
		cl.Close()
	})
}
