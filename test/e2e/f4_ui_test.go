//go:build integration

package e2e_test

import (
	"net/http"
	"net/url"
	"strings"
	"time"
)

// UI steps of the F4 scenarios. Each one goes through the real routes with the devops identity and
// CSRF token of uiClient; none of them touches Caddy, DNS, the URIs or the cluster directly.

// setAPIPolicy allows the lab endpoint for the API scope (F4-043).
func (s *f4Stack) setAPIPolicy() {
	s.t.Helper()
	addrs, port := s.apiPolicy()
	code, body := s.ui.post("/k8s/setup/policy", url.Values{"scope": {"api"}, "addresses": {addrs}, "ports": {port}})
	if code != http.StatusOK || !strings.Contains(body, "policy kaydedildi") {
		s.t.Fatalf("API policy: status %d: %s", code, excerpt(body))
	}
}

// saveProfile stores the connection profile with the given internal listener address.
func (s *f4Stack) saveProfile(internalAddr string) {
	s.t.Helper()
	code, body := s.ui.post("/k8s/connection/profile", url.Values{
		"endpoint":        {s.rt.Server},
		"tls_server_name": {s.tlsServerName()},
		"namespaces":      {s.rt.Namespace},
		"controller":      {s.pf.Controller},
		"ingress_classes": {s.pf.IngressClass},
		"internal":        {internalAddr + " 443 " + f4EntryPt},
	})
	if code != http.StatusOK {
		s.t.Fatalf("save the profile: status %d: %s", code, excerpt(body))
	}
}

// saveCredential uploads the CA and the short-lived token; tagcess makes the read-only connection
// attempt with them before accepting.
func (s *f4Stack) saveCredential() {
	s.t.Helper()
	code, body := s.ui.post("/k8s/connection/credential", url.Values{
		"endpoint":        {s.rt.Server},
		"tls_server_name": {s.tlsServerName()},
		"ca_data":         {s.rt.CAPEM},
		"token":           {s.rt.Token},
	})
	if code != http.StatusOK {
		s.t.Fatalf("save the credential: status %d: %s", code, excerpt(body))
	}
	if strings.Contains(body, s.rt.Token) {
		s.t.Fatal("the credential response echoes the token")
	}
}

// connect runs the whole connection setup through the UI.
func (s *f4Stack) connect(internalAddr string) {
	s.t.Helper()
	s.setAPIPolicy()
	s.saveProfile(internalAddr)
	s.saveCredential()
}

// waitPage polls a GET page until ok(body) holds (the inventory loop reads on its own interval).
func (s *f4Stack) waitPage(path, what string, ok func(body string) bool) string {
	s.t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	var code int
	var body string
	for {
		code, body = s.ui.get(path)
		if code == http.StatusOK && ok(body) {
			return body
		}
		if time.Now().After(deadline) {
			s.t.Fatalf("%s: not seen within 90s on %s (status %d): %s", what, path, code, excerpt(body))
		}
		time.Sleep(2 * time.Second)
	}
}

// draftPath is the draft screen of the lab host.
func draftPath(suffix string) string { return "/k8s/drafts/" + f4Host + suffix }

// saveDraft stores the private-access choice of the draft.
func (s *f4Stack) saveDraft(roles ...string) string {
	s.t.Helper()
	code, body := s.ui.post(draftPath(""), url.Values{
		"access_choice": {"role"}, "roles": {strings.Join(roles, "\n")}, "note": {"f4 e2e"},
	})
	if code != http.StatusOK {
		s.t.Fatalf("save the draft: status %d: %s", code, excerpt(body))
	}
	return body
}
