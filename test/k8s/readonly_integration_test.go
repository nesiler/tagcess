//go:build integration

package k8s

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The F4-034 acceptance run against the personal k3s: opt-in (`make k8s-lab`), the same scenarios as
// the local-API gate in contract_test.go, but with the real API, the real ServiceAccount token and
// real RBAC. Without the opt-in a test skips with a reason that says it is not a PASS (F4-033 AC4).

// dnsServerName is the TLS server name the profile may carry: a DNS name, never an IP literal.
func dnsServerName(name string) string {
	if _, err := netip.ParseAddr(name); err == nil {
		return ""
	}
	return name
}

// labTarget sets the lab up with the bootstrap identity and hands the scenario only the runtime
// identity: endpoint, CA and short-lived ServiceAccount tokens. The bootstrap kubeconfig never reaches
// the product code; Revoke and AddConflict are the lab tooling's own writes.
func labTarget(t *testing.T) *target {
	t.Helper()
	cfg := RequireLab(t, os.Getenv)
	lab := NewLab(t, cfg, nil)
	lab.Setup()
	rt := lab.Runtime()
	current := rt.Token

	tg := &target{
		Server: rt.Server, CAPEM: rt.CAPEM, ServerName: dnsServerName(lab.pre.TLSServerName),
		Namespace: rt.Namespace, Class: lab.pre.IngressClass, Controller: lab.pre.Controller, Token: rt.Token,
		AddConflict: lab.AddConflict,
		Record: func(name string, v any) {
			data := mustJSON(t, v)
			t.Logf("%s (nonsecret): %s", name, data)
			if cfg.RecordDir == "" {
				return
			}
			if err := os.MkdirAll(cfg.RecordDir, 0o750); err != nil {
				t.Fatalf("record dir: %v", err)
			}
			if err := os.WriteFile(filepath.Join(cfg.RecordDir, name), []byte(data+"\n"), 0o600); err != nil {
				t.Fatalf("write %s: %v", name, err)
			}
		},
	}
	tg.Revoke = func() {
		lab.Revoke()
		waitRejected(t, tg, current)
	}
	tg.NewToken = func() string {
		current = lab.Runtime().Token
		return current
	}
	return tg
}

// waitRejected polls (GET only) until the API answers 401 for token: the API server learns of the
// recreated ServiceAccount through its own cache, a moment after the delete returned.
func waitRejected(t *testing.T, tg *target, token string) {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(tg.CAPEM)) {
		t.Fatal("lab CA is not usable")
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: tg.ServerName, MinVersion: tls.VersionTLS12},
	}}
	deadline := time.Now().Add(60 * time.Second)
	for {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, tg.Server+"/apis/networking.k8s.io/v1/ingressclasses", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusUnauthorized {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the revoked token is still accepted after 60s (last status %v, err %v)", resp, err)
		}
		time.Sleep(time.Second)
	}
}

// TestK8sLab_ReadOnlyPermissionsAndForbiddenSnapshot is F4-034 AC1 on the real cluster.
func TestK8sLab_ReadOnlyPermissionsAndForbiddenSnapshot(t *testing.T) {
	scenarioReadOnly(t, labTarget(t))
}
