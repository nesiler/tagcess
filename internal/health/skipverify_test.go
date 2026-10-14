package health

import (
	"context"
	"net/http"
	"testing"

	"github.com/nesiler/tagcess/test/k8s"
)

// G-2: the k8s ingress Caddy proxies to presents a certificate Caddy itself does not verify
// (tls_insecure_skip_verify in the (k8s) snippet). A target check with SkipVerify reaches it the
// same way; without SkipVerify an untrusted certificate is still a failed handshake.
func TestProbeTargetSkipVerify(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		skip bool
		want Kind
	}{
		{"verified: untrusted certificate fails", false, KindUnreachable},
		{"skip verify: the backend answer counts", true, KindHealthy},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, nil)
			fx := k8s.NewTLS(t, testHost)
			e.dialer.backend = fx.Addr()
			// e.tr.rootCAs stays nil: the fixture's CA is not trusted.
			res, err := e.tr.ProbeTarget(ctx, TargetRequest{Request: Request{Host: testHost, Port: testPort, TLS: true, SkipVerify: tc.skip}})
			if err != nil {
				t.Fatalf("ProbeTarget: %v", err)
			}
			if res.Kind != tc.want {
				t.Errorf("kind = %q, want %q", res.Kind, tc.want)
			}
		})
	}
}

// K-02.7: behind Caddy's (k8s) upstream any app answer proves the backend is up; only 5xx and the
// ingress's own 404 are failures. Without SkipVerify the configured expected statuses still rule.
func TestProbeTargetK8sStatuses(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name   string
		status int
		skip   bool
		want   Kind
	}{
		{"ok", http.StatusOK, true, KindHealthy},
		{"login redirect", http.StatusFound, true, KindHealthy},
		{"unauthorized", http.StatusUnauthorized, true, KindHealthy},
		{"forbidden", http.StatusForbidden, true, KindHealthy},
		{"ingress 404", http.StatusNotFound, true, KindUnexpectedStatus},
		{"no pod 503", http.StatusServiceUnavailable, true, KindUnexpectedStatus},
		{"bad gateway", http.StatusBadGateway, true, KindUnexpectedStatus},
		{"url target keeps expected statuses", http.StatusFound, false, KindUnexpectedStatus},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(tc.status) })
			req := TargetRequest{Request: Request{Host: testHost, Port: testPort, SkipVerify: tc.skip}, Statuses: []int{http.StatusOK}}
			res, err := e.tr.ProbeTarget(ctx, req)
			if err != nil {
				t.Fatalf("ProbeTarget: %v", err)
			}
			if res.Kind != tc.want {
				t.Errorf("status %d: kind = %q, want %q", tc.status, res.Kind, tc.want)
			}
		})
	}
}
