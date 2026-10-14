package k8s

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// TLSFixture is a local HTTPS server whose leaf certificate is signed by a CA generated at test
// time (nothing is read from disk, no secret is stored). It records the Host header and the TLS
// SNI of every request the handshake let through, so a test can assert what the caller sent.
type TLSFixture struct {
	t       *testing.T
	dnsName string
	caPool  *x509.CertPool

	server *httptest.Server
	mu     sync.Mutex
	seen   []TLSObservation
	once   sync.Once
}

// TLSObservation is the Host header and TLS SNI the server observed on a request.
type TLSObservation struct {
	Host string
	SNI  string
}

// NewTLS starts a local TLS server with a fresh test CA and a leaf for dnsName, and registers Close
// with t.Cleanup.
func NewTLS(t *testing.T, dnsName string) *TLSFixture {
	t.Helper()
	ca, caKey, caPool := newTestCA(t)
	leaf := newLeafCert(t, ca, caKey, dnsName)

	f := &TLSFixture{t: t, dnsName: dnsName, caPool: caPool}
	f.server = httptest.NewUnstartedServer(http.HandlerFunc(f.handle))
	f.server.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}, MinVersion: tls.VersionTLS12}
	// A rejected handshake is an expected scenario, not a test failure; keep it out of the logs.
	f.server.Config.ErrorLog = log.New(io.Discard, "", 0)
	f.server.StartTLS()
	t.Cleanup(f.Close)
	return f
}

// URL is the HTTPS base URL of the fixture's local server.
func (f *TLSFixture) URL() string { return f.server.URL }

// Addr is the host:port the fixture's local server listens on.
func (f *TLSFixture) Addr() string { return f.server.Listener.Addr().String() }

// DNSName is the name the leaf certificate was issued for.
func (f *TLSFixture) DNSName() string { return f.dnsName }

// CAPool is the trust pool holding the fixture's test CA; pass it as RootCAs to validate the leaf.
func (f *TLSFixture) CAPool() *x509.CertPool { return f.caPool }

// Observations returns a copy of the Host/SNI pairs the server observed, in arrival order.
func (f *TLSFixture) Observations() []TLSObservation {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]TLSObservation, len(f.seen))
	copy(out, f.seen)
	return out
}

// Close closes the local server. It is idempotent.
func (f *TLSFixture) Close() {
	f.once.Do(func() {
		if f.server != nil {
			f.server.Close()
		}
	})
}

func (f *TLSFixture) handle(w http.ResponseWriter, r *http.Request) {
	observation := TLSObservation{Host: r.Host}
	if r.TLS != nil {
		observation.SNI = r.TLS.ServerName
	}
	f.mu.Lock()
	f.seen = append(f.seen, observation)
	f.mu.Unlock()

	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ok")
}

// newTestCA creates a self-signed CA valid for one day and returns it with its key and trust pool.
func newTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("k8s fixture: generate CA key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "tagcess k8s test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("k8s fixture: create CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("k8s fixture: parse CA certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return cert, key, pool
}

// newLeafCert signs a server certificate for dnsName with the test CA.
func newLeafCert(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, dnsName string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("k8s fixture: generate leaf key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: dnsName},
		DNSNames:              []string{dnsName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("k8s fixture: create leaf certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
