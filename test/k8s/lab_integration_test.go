//go:build integration

package k8s

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"
)

// TestK8sLabIntegration is the opt-in run against the personal k3s (`make k8s-lab`): it sets the lab up
// with the bootstrap identity, records the real profile, then talks to the API only with the runtime
// ServiceAccount token (GET only) and the cleanup removes everything. Without the opt-in it skips, and
// a skip is not a PASS in the phase acceptance evidence.
func TestK8sLabIntegration(t *testing.T) {
	cfg := RequireLab(t, os.Getenv)
	lab := NewLab(t, cfg, nil)
	lab.Setup()
	rt := lab.Runtime()

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(rt.CAPEM)) {
		t.Fatal("runtime CA is not usable")
	}
	client := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: lab.pre.TLSServerName, MinVersion: tls.VersionTLS12},
	}}
	get := func(path string) (status, items int) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, rt.Server+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+rt.Token)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer func() { _ = resp.Body.Close() }()
		var body struct {
			Items []json.RawMessage `json:"items"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		return resp.StatusCode, len(body.Items)
	}

	ns := "/namespaces/" + rt.Namespace
	for _, tc := range []struct {
		path      string
		want      int
		wantItems int
	}{
		{"/apis/networking.k8s.io/v1" + ns + "/ingresses", http.StatusOK, 1},
		{"/api/v1" + ns + "/services", http.StatusOK, 1},
		{"/apis/networking.k8s.io/v1/ingressclasses", http.StatusOK, -1},
		{"/api/v1" + ns + "/secrets", http.StatusForbidden, -1},
		{"/api/v1/namespaces/kube-system/services", http.StatusForbidden, -1},
	} {
		code, items := get(tc.path)
		if code != tc.want {
			t.Errorf("GET %s = %d, want %d", tc.path, code, tc.want)
		}
		if tc.wantItems >= 0 && items != tc.wantItems {
			t.Errorf("GET %s items = %d, want %d", tc.path, items, tc.wantItems)
		}
	}
}
