//go:build integration

package e2e_test

import (
	"net/http"
	"net/url"
	"testing"
)

// f4Routes are the F4 dashboard, alert, connection and setup routes (every route F4 registers).
var f4Routes = []struct{ method, path string }{
	{http.MethodGet, "/"},
	{http.MethodGet, "/alerts"},
	{http.MethodPost, "/alerts/ack"},
	{http.MethodPost, "/alerts/maintenance"},
	{http.MethodGet, "/monitor/settings"},
	{http.MethodPost, "/monitor/settings"},
	{http.MethodGet, "/k8s/discovery"},
	{http.MethodGet, "/k8s/connection"},
	{http.MethodPost, "/k8s/connection/profile"},
	{http.MethodPost, "/k8s/connection/credential"},
	{http.MethodGet, "/k8s/setup"},
	{http.MethodGet, "/k8s/setup/manifest"},
	{http.MethodPost, "/k8s/setup/review"},
	{http.MethodPost, "/k8s/setup/policy"},
	{http.MethodGet, "/k8s/drafts/" + f4Host},
	{http.MethodPost, "/k8s/drafts/" + f4Host},
	{http.MethodPost, "/k8s/drafts/" + f4Host + "/refresh"},
	{http.MethodPost, "/k8s/drafts/" + f4Host + "/review"},
}

// TestF4_E2E_SpoofedHeaderRejected is F4-040 AC4: identities without devops, with or without forged
// X-Auth-Request-* headers, get 403 on every F4 route and nothing is written; through the compose
// Caddy/oauth2-proxy a session without devops is denied whatever the headers say.
func TestF4_E2E_SpoofedHeaderRejected(t *testing.T) {
	s := newF4Stack(t)
	audits := s.proc.queryInt(t, `SELECT count(*) FROM audit_events`)
	alerts := s.proc.queryInt(t, `SELECT count(*) FROM alerts`)
	csrf := s.ui.csrf()

	identities := map[string]map[string]string{
		"no identity":             nil,
		"developer":               {"X-Auth-Request-User": "dev", "X-Auth-Request-Email": "dev@tagcess.test", "X-Auth-Request-Groups": "developer"},
		"forged user, no groups":  {"X-Auth-Request-User": "devops", "X-Auth-Request-Email": "devops@tagcess.test"},
		"empty groups":            {"X-Auth-Request-User": "devops", "X-Auth-Request-Groups": ""},
		"look-alike group":        {"X-Auth-Request-User": "x", "X-Auth-Request-Groups": "devops-readonly,devopsx"},
		"other case":              {"X-Auth-Request-User": "x", "X-Auth-Request-Groups": "DevOps"},
		"foreign forwarded group": {"X-Auth-Request-User": "x", "X-Auth-Request-Groups": "developer", "X-Forwarded-Groups": "devops"},
	}
	for name, header := range identities {
		for _, r := range f4Routes {
			var form url.Values
			if r.method == http.MethodPost {
				form = url.Values{"csrf_token": {csrf}, "scope": {"api"}, "addresses": {"10.0.0.1"}, "ports": {"443"}}
			}
			if code, _ := uiRaw(t, s.proc.uiSock, r.method, r.path, header, form); code != http.StatusForbidden {
				t.Errorf("%s: %s %s: status %d, want 403", name, r.method, r.path, code)
			}
		}
	}
	if got := s.proc.queryInt(t, `SELECT count(*) FROM audit_events`); got != audits {
		t.Errorf("rejected requests wrote %d audit rows", got-audits)
	}
	if got := s.proc.queryInt(t, `SELECT count(*) FROM alerts`); got != alerts {
		t.Errorf("rejected requests changed the alerts (%d -> %d)", alerts, got)
	}
	// Control: the devops identity reaches the same pages.
	for _, path := range []string{"/", "/alerts", "/monitor/settings", "/k8s/connection", "/k8s/setup"} {
		if code, body := s.ui.get(path); code != http.StatusOK {
			t.Fatalf("devops control %s: status %d: %s", path, code, excerpt(body))
		}
	}

	// Through the compose Caddy: oauth2-proxy denies a developer session whatever the headers say.
	secret := s.l.envFileValue(t, "OAUTH2_PROXY_COOKIE_SECRET")
	devops := forgeSessionCookie(t, secret, []string{"devops"})
	developer := forgeSessionCookie(t, secret, []string{"developer"})
	for _, path := range []string{"/", "/alerts", "/monitor/settings", "/k8s/connection", "/k8s/setup", "/k8s/discovery"} {
		if code := getThroughCaddyPath(t, path, devops, ""); code != http.StatusOK {
			t.Errorf("devops session on %s through Caddy: status %d, want 200", path, code)
		}
		if code := getThroughCaddyPath(t, path, developer, "devops"); code != http.StatusForbidden {
			t.Errorf("developer session with a spoofed header on %s through Caddy: status %d, want 403", path, code)
		}
		if code := getThroughCaddyPath(t, path, "", "devops"); code == http.StatusOK {
			t.Errorf("a client without a session and with a spoofed header reached %s through Caddy", path)
		}
	}
}
