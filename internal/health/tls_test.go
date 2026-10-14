package health

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"go/parser"
	"go/token"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/netpolicy"
)

// testCA is a CA generated while the test runs; nothing is read from disk.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "tagcess health test CA"},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(2000 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert: cert, key: key, pool: pool}
}

// leaf issues a server certificate for dnsName valid until notAfter (and from an hour ago, or earlier).
func (ca *testCA) leaf(t *testing.T, dnsName string, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	notBefore := notAfter.Add(-48 * time.Hour)
	if now := time.Now().Add(-time.Hour); notBefore.After(now) {
		notBefore = now
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// sniServer is a TLS listener that presents a different leaf per SNI. It asks for a client
// certificate (and records what arrived) and counts HTTP requests, so a test can prove the probe
// only handshakes: no client credential, no request.
type sniServer struct {
	srv *httptest.Server

	mu          sync.Mutex
	certs       map[string]tls.Certificate
	fallback    tls.Certificate
	sni         []string
	clientCerts int
	httpHits    atomic.Int32
	hellos      atomic.Int32
	onHello     func(n int) // optional; called with the 1-based handshake count, may block
	done        chan struct{}
}

func newSNIServer(t *testing.T, fallback tls.Certificate) *sniServer {
	t.Helper()
	s := &sniServer{certs: map[string]tls.Certificate{}, fallback: fallback, done: make(chan struct{})}
	s.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		s.httpHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	s.srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.srv.TLS = &tls.Config{
		MinVersion: tls.VersionTLS12,
		ClientAuth: tls.RequestClientCert,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			n := int(s.hellos.Add(1))
			if s.onHello != nil {
				s.onHello(n)
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			s.sni = append(s.sni, hello.ServerName)
			if c, ok := s.certs[hello.ServerName]; ok {
				return &c, nil
			}
			return &s.fallback, nil
		},
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			s.mu.Lock()
			s.clientCerts += len(raw)
			s.mu.Unlock()
			return nil
		},
	}
	s.srv.StartTLS()
	t.Cleanup(s.srv.Close)
	t.Cleanup(func() { close(s.done) }) // runs first: releases any hello hook that is still blocked
	return s
}

// wait blocks until d passes or the server is shut down.
func (s *sniServer) wait(d time.Duration) {
	select {
	case <-time.After(d):
	case <-s.done:
	}
}

// control is the positive control for the "nothing was sent" proofs: with a test-generated client
// certificate it makes one harmless HTTP request to the same server and checks that the very
// counters the probe tests assert on really do rise and the request was handled. It then resets
// the counters, so a later zero reading means the probe sent nothing.
func (s *sniServer) control(t *testing.T, ca *testCA, host string) {
	t.Helper()
	client := ca.leaf(t, "client.internal.example", time.Now().Add(240*time.Hour))
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, s.srv.Listener.Addr().String())
		},
		TLSClientConfig: &tls.Config{
			ServerName:         host,
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true, //nolint:gosec // control client; the server leaf may be an expired test cert
			Certificates:       []tls.Certificate{client},
		},
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/", nil)
	if err != nil {
		t.Fatalf("control request: %v", err)
	}
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		t.Fatalf("control request: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("control status = %d, want 200", resp.StatusCode)
	}
	if n := s.httpHits.Load(); n != 1 {
		t.Fatalf("control: server counted %d HTTP requests, want 1: the observer is blind", n)
	}
	if n := s.clientCertCount(); n != 1 {
		t.Fatalf("control: server counted %d client certificates, want 1: the observer is blind", n)
	}
	s.httpHits.Store(0)
	s.mu.Lock()
	s.clientCerts = 0
	s.mu.Unlock()
}

func (s *sniServer) serve(name string, c tls.Certificate) {
	s.mu.Lock()
	s.certs[name] = c
	s.mu.Unlock()
}

func (s *sniServer) seenSNI() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.sni...)
}

func (s *sniServer) clientCertCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.clientCerts
}

func fingerprint(c tls.Certificate) string {
	sum := sha256.Sum256(c.Certificate[0])
	return hex.EncodeToString(sum[:])
}

// tlsEnv points the standard test env at a sniServer: every site host (plus the dial host) is an
// approved target, the connection is routed to the server and ca is the trust root.
func tlsEnv(t *testing.T, srv *sniServer, ca *testCA, hosts ...string) *env {
	t.Helper()
	e := newEnv(t, nil)
	if err := e.targets.Set(context.Background(), append([]string{testHost}, hosts...)); err != nil {
		t.Fatalf("Set targets: %v", err)
	}
	e.dialer.backend = srv.srv.Listener.Addr().String()
	e.tr.rootCAs = ca.pool
	return e
}

func TestTLSProbeChecksEverySNIHost(t *testing.T) {
	ctx := context.Background()
	ca := newCA(t)
	hosts := []string{"a.internal.example", "b.internal.example", "c.internal.example"}
	srv := newSNIServer(t, ca.leaf(t, "fallback.internal.example", time.Now().Add(240*time.Hour)))
	want := map[string]time.Time{}
	fp := map[string]string{}
	for i, h := range hosts {
		na := time.Now().Add(time.Duration(10*(i+1)) * 24 * time.Hour).UTC().Truncate(time.Second)
		c := ca.leaf(t, h, na)
		srv.serve(h, c)
		want[h], fp[h] = na, fingerprint(c)
	}
	e := tlsEnv(t, srv, ca, hosts...)

	obs := e.tr.ProbeTLSHosts(ctx, testHost, testPort, hosts)
	if len(obs) != len(hosts) {
		t.Fatalf("got %d observations, want %d", len(obs), len(hosts))
	}
	for i, h := range hosts {
		o := obs[i]
		if o.Host != h {
			t.Errorf("observation %d host = %q, want %q", i, o.Host, h)
		}
		if !o.Healthy() || o.Verification != TLSVerified {
			t.Errorf("%s: %+v, want a verified, healthy observation", h, o)
		}
		if o.Leaf == nil || !o.Leaf.NotAfter.Equal(want[h]) {
			t.Errorf("%s: leaf %+v, want NotAfter %v from the presented leaf", h, o.Leaf, want[h])
		} else if o.Leaf.Fingerprint != fp[h] {
			t.Errorf("%s: fingerprint %q, want %q", h, o.Leaf.Fingerprint, fp[h])
		}
	}
	// One handshake per host, each with its own SNI, all dialled to the approved address.
	if got := srv.seenSNI(); strings.Join(got, ",") != strings.Join(hosts, ",") {
		t.Errorf("server saw SNI %v, want %v", got, hosts)
	}
	for _, a := range e.dialer.Addrs() {
		if a != testIP+":8080" {
			t.Errorf("dialled %q, want the approved address", a)
		}
	}
	// The three NotAfter values are all different: a shared one would mean one leaf was reused.
	if obs[0].Leaf.NotAfter.Equal(obs[1].Leaf.NotAfter) || obs[1].Leaf.NotAfter.Equal(obs[2].Leaf.NotAfter) {
		t.Errorf("NotAfter values are not distinct: %+v", obs)
	}
}

func TestProbeSNIValidation(t *testing.T) {
	ctx := context.Background()
	ca := newCA(t)
	other := newCA(t)
	const host = "a.internal.example"
	na := time.Now().Add(240 * time.Hour)

	cases := []struct {
		name   string
		serve  tls.Certificate
		reason string
	}{
		{"wrong SAN", ca.leaf(t, "other.internal.example", na), TLSReasonHostname},
		{"chain from an untrusted CA", other.leaf(t, host, na), TLSReasonUnknownAuthority},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newSNIServer(t, tc.serve)
			e := tlsEnv(t, srv, ca, host)
			o, err := e.tr.ProbeTLS(ctx, TLSRequest{Host: testHost, Port: testPort, ServerName: host})
			if err != nil {
				t.Fatalf("ProbeTLS: %v", err)
			}
			if o.Healthy() || o.Verification != TLSFailed || o.Reason != tc.reason {
				t.Fatalf("observation %+v, want a failed verification (%s) that is not healthy", o, tc.reason)
			}
		})
	}

	t.Run("a verified certificate is healthy", func(t *testing.T) {
		srv := newSNIServer(t, ca.leaf(t, host, na))
		e := tlsEnv(t, srv, ca, host)
		o, err := e.tr.ProbeTLS(ctx, TLSRequest{Host: testHost, Port: testPort, ServerName: host})
		if err != nil || !o.Healthy() || o.Reason != "" {
			t.Fatalf("ProbeTLS = %+v, %v; want healthy", o, err)
		}
	})

	t.Run("the SNI must be an approved target", func(t *testing.T) {
		srv := newSNIServer(t, ca.leaf(t, host, na))
		e := tlsEnv(t, srv, ca, host)
		_, err := e.tr.ProbeTLS(ctx, TLSRequest{Host: testHost, Port: testPort, ServerName: "unapproved.internal.example"})
		if !errors.Is(err, ErrRejected) {
			t.Fatalf("err = %v, want ErrRejected", err)
		}
		if got := srv.seenSNI(); len(got) != 0 {
			t.Errorf("server saw %v, want no handshake", got)
		}
	})
}

func TestTLSProbeInvalidCertificateIsDiagnosticOnly(t *testing.T) {
	ctx := context.Background()
	ca := newCA(t)
	const host = "a.internal.example"
	expired := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	c := ca.leaf(t, host, expired)
	srv := newSNIServer(t, c)
	e := tlsEnv(t, srv, ca, host)
	srv.control(t, ca, host)
	srv.hellos.Store(0)

	o, err := e.tr.ProbeTLS(ctx, TLSRequest{Host: testHost, Port: testPort, ServerName: host})
	if err != nil {
		t.Fatalf("ProbeTLS: %v", err)
	}
	// Both the verified and the diagnostic handshake reached the server.
	if n := srv.hellos.Load(); n != 2 {
		t.Errorf("server saw %d handshakes, want 2 (verified, then diagnostic)", n)
	}
	// Reachability and verification are separate answers.
	if !o.Reachable {
		t.Errorf("Reachable = false, want true: the server answered the handshake")
	}
	if o.Verification != TLSFailed || o.Reason != TLSReasonExpired || o.Healthy() {
		t.Errorf("observation %+v, want failed/expired and not healthy", o)
	}
	// The leaf is readable, but only as a diagnostic: "TLS doğrulanmadı".
	if o.Leaf == nil || !o.Diagnostic || !o.Leaf.NotAfter.Equal(expired) || o.Leaf.Fingerprint != fingerprint(c) {
		t.Errorf("leaf %+v diagnostic=%v, want the expired leaf flagged diagnostic", o.Leaf, o.Diagnostic)
	}
	// The unverified measurement is a bare handshake: no HTTP request, no client certificate.
	if n := srv.httpHits.Load(); n != 0 {
		t.Errorf("server got %d HTTP requests, want 0", n)
	}
	if n := srv.clientCertCount(); n != 0 {
		t.Errorf("server received %d client certificates, want 0", n)
	}

	t.Run("a verified read is not diagnostic", func(t *testing.T) {
		srv := newSNIServer(t, ca.leaf(t, host, time.Now().Add(240*time.Hour)))
		e := tlsEnv(t, srv, ca, host)
		o, err := e.tr.ProbeTLS(ctx, TLSRequest{Host: testHost, Port: testPort, ServerName: host})
		if err != nil || o.Diagnostic || !o.Reachable {
			t.Fatalf("ProbeTLS = %+v, %v; want reachable and not diagnostic", o, err)
		}
	})

	t.Run("unreachable is not a verification verdict", func(t *testing.T) {
		e := newEnv(t, nil)
		e.dialer.block = false
		e.dialer.backend = "127.0.0.1:1" // nothing listens: connection refused
		if err := e.targets.Set(ctx, []string{testHost, host}); err != nil {
			t.Fatalf("Set targets: %v", err)
		}
		o, err := e.tr.ProbeTLS(ctx, TLSRequest{Host: testHost, Port: testPort, ServerName: host})
		if err != nil {
			t.Fatalf("ProbeTLS: %v", err)
		}
		if o.Reachable || o.Verification != TLSUnknown || o.Leaf != nil || o.Healthy() || o.Err == "" {
			t.Errorf("observation %+v, want unreachable, unknown and without a leaf", o)
		}
	})
}

func TestTLSProbeFailureDoesNotRefreshNotAfter(t *testing.T) {
	ctx := context.Background()
	ca := newCA(t)
	const host = "a.internal.example"
	na := time.Now().Add(240 * time.Hour).UTC().Truncate(time.Second)
	srv := newSNIServer(t, ca.leaf(t, host, na))
	e := tlsEnv(t, srv, ca, host)
	t0 := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	e.tr.now = func() time.Time { return t0 }

	first, err := e.tr.ProbeTLS(ctx, TLSRequest{Host: testHost, Port: testPort, ServerName: host})
	if err != nil || first.Leaf == nil || !first.Leaf.NotAfter.Equal(na) {
		t.Fatalf("first probe = %+v, %v; want the leaf", first, err)
	}
	if !first.ObservedAt.Equal(t0) {
		t.Errorf("ObservedAt = %v, want %v", first.ObservedAt, t0)
	}

	// The listener goes away; a later probe reads no leaf.
	srv.srv.Close()
	t1 := t0.Add(6 * time.Hour)
	e.tr.now = func() time.Time { return t1 }
	second, err := e.tr.ProbeTLS(ctx, TLSRequest{Host: testHost, Port: testPort, ServerName: host})
	if err != nil {
		t.Fatalf("second probe: %v", err)
	}
	if second.Leaf != nil || !second.Last.IsZero() {
		t.Fatalf("second probe %+v, want no leaf of its own", second)
	}
	merged := second.After(first)
	if merged.Leaf != nil {
		t.Errorf("merged Leaf = %+v, want nil: a failed read has no fresh NotAfter", merged.Leaf)
	}
	if merged.Healthy() || merged.Verification != TLSUnknown {
		t.Errorf("merged %+v, want unknown and not healthy", merged)
	}
	if !merged.Last.Leaf.NotAfter.Equal(na) || !merged.Last.ObservedAt.Equal(t0) {
		t.Errorf("Last = %+v, want the old NotAfter %v observed at %v", merged.Last, na, t0)
	}
	if !merged.ObservedAt.Equal(t1) {
		t.Errorf("ObservedAt = %v, want the failed attempt's time %v", merged.ObservedAt, t1)
	}

	// An unreadable run on top of another unreadable run keeps the original last leaf and time.
	third := second.After(merged)
	if third.Last.Leaf == nil || !third.Last.ObservedAt.Equal(t0) || !third.Last.Leaf.NotAfter.Equal(na) {
		t.Errorf("third.Last = %+v, want it to stay the t0 observation", third.Last)
	}

	// A fresh read replaces the old one and carries no Last.
	srv2 := newSNIServer(t, ca.leaf(t, host, na.Add(24*time.Hour)))
	e.dialer.backend = srv2.srv.Listener.Addr().String()
	fresh, err := e.tr.ProbeTLS(ctx, TLSRequest{Host: testHost, Port: testPort, ServerName: host})
	if err != nil {
		t.Fatalf("fresh probe: %v", err)
	}
	if got := fresh.After(merged); got.Leaf == nil || !got.Leaf.NotAfter.Equal(na.Add(24*time.Hour)) || !got.Last.IsZero() {
		t.Errorf("fresh merged %+v, want the new leaf and no Last", got)
	}
}

func TestTLSProbeNeedsNoPrivateKeysOrSecrets(t *testing.T) {
	ctx := context.Background()
	ca := newCA(t)
	const host = "a.internal.example"
	srv := newSNIServer(t, ca.leaf(t, host, time.Now().Add(240*time.Hour)))
	e := tlsEnv(t, srv, ca, host)
	srv.control(t, ca, host)

	// The checker must be able to see a forbidden import before its silence means anything.
	for _, bad := range []string{"os", "io/ioutil", "io/fs", "encoding/pem", "github.com/nesiler/tagcess/internal/k8s"} {
		src := "package x\n\nimport _ \"" + bad + "\"\n"
		if got := forbiddenImports(t, "synthetic.go", src); len(got) != 1 || got[0] != bad {
			t.Errorf("forbiddenImports(%q) = %v, want it flagged", bad, got)
		}
	}
	if got := forbiddenImports(t, "synthetic.go", "package x\n\nimport _ \"crypto/tls\"\n"); len(got) != 0 {
		t.Errorf("forbiddenImports flagged a harmless import: %v", got)
	}

	// The probe code does not import anything that reads files, keys or the cluster.
	for _, file := range []string{"tls.go", "transport.go"} {
		for _, p := range forbiddenImports(t, file, nil) {
			t.Errorf("%s imports %q: the TLS probe must not read files, keys or Secrets", file, p)
		}
	}

	// Run inside an empty directory with an empty environment: nothing to read, nothing sent.
	t.Chdir(t.TempDir())
	t.Setenv("HOME", t.TempDir())
	t.Setenv("KUBECONFIG", "")
	o, err := e.tr.ProbeTLS(ctx, TLSRequest{Host: testHost, Port: testPort, ServerName: host})
	if err != nil || !o.Healthy() {
		t.Fatalf("ProbeTLS = %+v, %v; want healthy", o, err)
	}
	if n := srv.httpHits.Load(); n != 0 {
		t.Errorf("server got %d HTTP requests, want none (no header, no body)", n)
	}
	if n := srv.clientCertCount(); n != 0 {
		t.Errorf("server received %d client certificates, want 0", n)
	}

	// A policy that does not allow the dial still refuses the probe: it never bypasses the guard.
	if err := e.policy.Set(ctx, netpolicy.ScopeProbe, netpolicy.Input{Addresses: []string{"10.30.0.0/24"}, Ports: []int{testPort}}); err != nil {
		t.Fatalf("Set policy: %v", err)
	}
	before := len(srv.seenSNI())
	_, err = e.tr.ProbeTLS(ctx, TLSRequest{Host: testHost, Port: testPort, ServerName: host})
	if !errors.Is(err, netpolicy.ErrDenied) {
		t.Errorf("err = %v, want netpolicy.ErrDenied", err)
	}
	if after := len(srv.seenSNI()); after != before {
		t.Errorf("a denied dial still reached the server")
	}
}

// forbiddenImports parses src (or the file itself when src is nil) and returns the imports a TLS
// probe must not have: anything that reads files, keys or the cluster.
func forbiddenImports(t *testing.T, name string, src any) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), filepath.Join(".", name), src, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	var out []string
	for _, imp := range f.Imports {
		switch p := strings.Trim(imp.Path.Value, `"`); p {
		case "os", "io/ioutil", "io/fs", "github.com/nesiler/tagcess/internal/k8s", "encoding/pem":
			out = append(out, p)
		}
	}
	return out
}

// TestTLSProbeSharesOneTimeBudget: the verified handshake, the diagnostic read and cancellation
// share ONE t.timeout; a stuck second attempt never doubles it, and no failure path is healthy or
// invents a leaf.
func TestTLSProbeSharesOneTimeBudget(t *testing.T) {
	const (
		budget = 600 * time.Millisecond
		slack  = 200 * time.Millisecond
		host   = "a.internal.example"
	)
	req := TLSRequest{Host: testHost, Port: testPort, ServerName: host}
	ca := newCA(t)
	other := newCA(t)
	na := time.Now().Add(240 * time.Hour)

	newRun := func(t *testing.T, serve tls.Certificate) (*sniServer, *env) {
		srv := newSNIServer(t, serve)
		e := tlsEnv(t, srv, ca, host)
		e.tr.timeout = budget
		return srv, e
	}
	noLeaf := func(t *testing.T, o TLSObservation) {
		t.Helper()
		if o.Healthy() || o.Leaf != nil || o.Diagnostic {
			t.Errorf("observation %+v, want not healthy, no leaf, not diagnostic", o)
		}
	}

	t.Run("positive control: a healthy server verifies within the budget", func(t *testing.T) {
		_, e := newRun(t, ca.leaf(t, host, na))
		start := time.Now()
		o, err := e.tr.ProbeTLS(context.Background(), req)
		if err != nil || !o.Healthy() || o.Leaf == nil {
			t.Fatalf("ProbeTLS = %+v, %v; want healthy", o, err)
		}
		if d := time.Since(start); d > budget {
			t.Errorf("took %v, want under the %v budget", d, budget)
		}
	})

	t.Run("slow verification then a hanging diagnostic stays inside one budget", func(t *testing.T) {
		srv, e := newRun(t, other.leaf(t, host, na)) // untrusted chain: verification fails
		srv.onHello = func(n int) {
			if n == 1 {
				srv.wait(budget * 2 / 3) // the first handshake fails late in the budget
				return
			}
			srv.wait(time.Minute) // the diagnostic handshake hangs
		}
		start := time.Now()
		o, err := e.tr.ProbeTLS(context.Background(), req)
		d := time.Since(start)
		if err != nil {
			t.Fatalf("ProbeTLS: %v", err)
		}
		if d > budget+slack {
			t.Errorf("took %v, want at most the %v budget (+%v slack): the second attempt got its own timer", d, budget, slack)
		}
		if o.Verification != TLSFailed || o.Reason != TLSReasonUnknownAuthority || !o.Reachable {
			t.Errorf("observation %+v, want failed/unknown_authority", o)
		}
		noLeaf(t, o)
		if n := srv.hellos.Load(); n != 2 {
			t.Errorf("server saw %d handshakes, want 2", n)
		}
	})

	t.Run("a first handshake that hangs times out without a second attempt", func(t *testing.T) {
		srv, e := newRun(t, ca.leaf(t, host, na))
		srv.onHello = func(int) { srv.wait(time.Minute) }
		start := time.Now()
		o, err := e.tr.ProbeTLS(context.Background(), req)
		if err != nil {
			t.Fatalf("ProbeTLS: %v", err)
		}
		if d := time.Since(start); d > budget+slack {
			t.Errorf("took %v, want at most %v (+%v slack)", d, budget, slack)
		}
		if o.Verification != TLSUnknown || o.Reachable || o.Err != "timeout" {
			t.Errorf("observation %+v, want unknown, unreachable, timeout", o)
		}
		noLeaf(t, o)
		if n := srv.hellos.Load(); n != 1 {
			t.Errorf("server saw %d handshakes, want 1", n)
		}
	})

	t.Run("a protocol error is unknown and never retried unverified", func(t *testing.T) {
		ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		var conns atomic.Int32
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				conns.Add(1)
				_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n")) // plain text where TLS is expected
				_ = c.Close()
			}
		}()
		_, e := newRun(t, ca.leaf(t, host, na))
		e.dialer.backend = ln.Addr().String()
		o, err := e.tr.ProbeTLS(context.Background(), req)
		if err != nil {
			t.Fatalf("ProbeTLS: %v", err)
		}
		if o.Verification != TLSUnknown || o.Reachable || o.Err != "handshake failed" {
			t.Errorf("observation %+v, want unknown, unreachable, handshake failed", o)
		}
		noLeaf(t, o)
		if n := conns.Load(); n != 1 {
			t.Errorf("listener saw %d connections, want 1", n)
		}
	})

	t.Run("cancelling during the first handshake returns at once", func(t *testing.T) {
		srv, e := newRun(t, ca.leaf(t, host, na))
		srv.onHello = func(int) { srv.wait(time.Minute) }
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(100*time.Millisecond, cancel)
		start := time.Now()
		o, err := e.tr.ProbeTLS(ctx, req)
		if err != nil {
			t.Fatalf("ProbeTLS: %v", err)
		}
		if d := time.Since(start); d > 100*time.Millisecond+slack {
			t.Errorf("took %v after a cancel at 100ms", d)
		}
		if o.Verification != TLSUnknown || o.Err != "canceled" {
			t.Errorf("observation %+v, want unknown, canceled", o)
		}
		noLeaf(t, o)
	})

	t.Run("cancelling during the diagnostic read keeps the failure and invents no leaf", func(t *testing.T) {
		srv, e := newRun(t, other.leaf(t, host, na))
		ctx, cancel := context.WithCancel(context.Background())
		srv.onHello = func(n int) {
			if n == 2 {
				time.AfterFunc(100*time.Millisecond, cancel)
				srv.wait(time.Minute)
			}
		}
		start := time.Now()
		o, err := e.tr.ProbeTLS(ctx, req)
		if err != nil {
			t.Fatalf("ProbeTLS: %v", err)
		}
		if d := time.Since(start); d > 100*time.Millisecond+slack {
			t.Errorf("took %v after a cancel at 100ms", d)
		}
		if o.Verification != TLSFailed || !o.Reachable || o.Reason != TLSReasonUnknownAuthority {
			t.Errorf("observation %+v, want failed/unknown_authority", o)
		}
		noLeaf(t, o)
	})
}
