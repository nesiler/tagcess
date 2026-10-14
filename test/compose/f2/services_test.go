//go:build integration

// AC1 for F2-001: the F2 fixture runs on the local compose stack (Caddy v2.8.4, Headscale,
// oauth2-proxy) and the lab Zitadel (ADR 0014). `make lab-up` must have run; the test re-checks the
// running images and the health endpoints so a drifted or half-up stack fails clearly.
package f2

import (
	"fmt"
	"net/http"
	"testing"
	"time"
)

func TestF2Harness_Services(t *testing.T) {
	f := New(t)
	svc := f.Services()

	if svc.Caddy != CaddyImage {
		t.Errorf("running Caddy image = %q, want %q", svc.Caddy, CaddyImage)
	}
	if svc.Headscale != HeadscaleImage {
		t.Errorf("running Headscale image = %q, want %q", svc.Headscale, HeadscaleImage)
	}
	if svc.OAuth2Proxy != OAuth2ProxyImage {
		t.Errorf("running oauth2-proxy image = %q, want %q", svc.OAuth2Proxy, OAuth2ProxyImage)
	}
	// Zitadel is not part of the local compose stack (ADR 0014): it is the lab endpoint reached
	// over TLS. TestComposeStack_NoLocalZitadel pins the static side; this pins the resolved target.
	if svc.ZitadelHost != DefaultLabHost {
		t.Errorf("Zitadel host = %q, want the lab %q", svc.ZitadelHost, DefaultLabHost)
	}

	// Readiness: every service the F2 fixture depends on answers.
	zitadelScheme := "http"
	if f.HTTPS() {
		zitadelScheme = "https"
	}
	requireOK(t, "zitadel", zitadelScheme+"://"+svc.ZitadelHost+"/debug/healthz")
	requireOK(t, "headscale", "http://localhost:8090/health")
	requireOK(t, "oauth2-proxy", "http://127.0.0.1:4180/ping")
	// Caddy's admin API (2019) is not published to the host; an unauthenticated GET on the site
	// port proves the listener is up and the oauth2-proxy auth path is wired (F1-020).
	requireRedirect(t, "caddy", "http://localhost:8080/")
}

// requireOK polls url until it answers 200 or the deadline passes. The lab Zitadel is reached over
// the public internet and occasionally takes a few seconds, so a single short request is flaky.
func requireOK(t *testing.T, name, url string) {
	t.Helper()
	requireReady(t, name, url, func(code int) bool { return code == http.StatusOK })
}

// requireRedirect proves the listener is up by expecting a 3xx from an unauthenticated request.
func requireRedirect(t *testing.T, name, url string) {
	t.Helper()
	requireReady(t, name, url, func(code int) bool { return code >= 300 && code < 400 })
}

func requireReady(t *testing.T, name, url string, ok func(int) bool) {
	t.Helper()
	client := &http.Client{
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	deadline := time.Now().Add(90 * time.Second)
	var lastErr error
	for {
		resp, err := client.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if ok(resp.StatusCode) {
				return
			}
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
		} else {
			lastErr = err
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s %s: not ready within 90s: %v", name, url, lastErr)
		}
		time.Sleep(500 * time.Millisecond)
	}
}
