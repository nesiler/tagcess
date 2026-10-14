//go:build integration

// End-to-end scenarios for F3-026, part two: re-opening an expired device and the Y-04 priority,
// the manual MagicDNS records, the identity boundary of the F3 routes and the clean-up of a run.
// See f3_stack_test.go and `make e2e`.
package e2e_test

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	userv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"

	"github.com/nesiler/tagcess/test/compose/f2"
	"github.com/nesiler/tagcess/test/compose/seed"
)

// expireByRoleLoss takes the user's role away and waits for the reconcile to expire the node.
func (s *f3Stack) expireByRoleLoss(u f3User, role string, node uint64) {
	s.t.Helper()
	s.waitMember(role, u.zitadelID, true)
	s.l.removeGrant(s.t, u.zitadelID)
	if err := poll(s.t, 45*time.Second, func() (bool, error) {
		s.triggerSyncQuiet()
		return expired(s.mustNode(node)), nil
	}); err != nil {
		s.t.Fatalf("the device of %s was not expired after the role loss: %v", u.hsName, err)
	}
}

// AC6: a device expired by a role loss is not re-opened while its owner has no role; once the
// role is back it is re-opened only by an explicit approval (the reconcile does not do it); and an
// administrator who disabled the expiry cannot keep the device alive past the next role loss.
func TestE2E_F3_ReopenAndY04Priority(t *testing.T) {
	var carol f3User
	var laptop uint64
	s := newF3Stack(t, f3Options{prepare: func(s *f3Stack) {
		carol = s.user("carol", "standart")
		s.padHolders("standart", 3)
		laptop = s.hs.NewNode(s.t, carol.hsName, "carol-laptop", "")
	}})

	s.section(t, "role loss expires the device", func(t *testing.T) {
		s.expireByRoleLoss(carol, "standart", laptop)
	})

	s.section(t, "roleless owner", func(t *testing.T) {
		page := s.ui.getOK(devicePath(laptop, "/reopen"))
		mustContain(t, "reopen page", page, "yeniden açılamaz")
		mustNotContain(t, "reopen page", page, "/reopen/apply")
		// A hand-made POST is refused too: the guard reads the eligibility again.
		future := time.Now().UTC().Add(48 * time.Hour).Format("2006-01-02T15:04")
		code, body := s.deviceAction(laptop, "/reopen/apply", url.Values{"confirm": {"evet"}, "expiry": {future}})
		if code != http.StatusConflict {
			t.Fatalf("reopen of a roleless owner's device: status %d, want 409: %s", code, excerpt(body))
		}
		if n := s.mustNode(laptop); !expired(n) {
			t.Fatalf("the device was re-opened for a roleless owner: expiry %v", n.Expiry)
		}
	})

	s.section(t, "role back, explicit approval", func(t *testing.T) {
		s.l.grant(t, carol.zitadelID, "standart")
		s.waitMember("standart", carol.zitadelID, true)
		s.triggerSync()
		if n := s.mustNode(laptop); !expired(n) {
			t.Fatalf("the reconcile re-opened the device on its own: expiry %v", n.Expiry)
		}
		page := formOf{s.ui.getOK(devicePath(laptop, "/reopen"))}
		mustContain(t, "reopen page", page.body, "/reopen/apply", "standart")
		future := time.Now().UTC().Add(48 * time.Hour).Format("2006-01-02T15:04")
		code, body := s.ui.post(devicePath(laptop, "/reopen/apply"), url.Values{
			"expected":       {page.value("expected")},
			"current_name":   {page.value("current_name")},
			"current_expiry": {page.value("current_expiry")},
			"confirm":        {page.value("confirm")},
			"expiry":         {future},
		})
		wantApplied(t, "reopen", code, body)
		if n := s.mustNode(laptop); n.Expiry == nil || !n.Expiry.After(time.Now().Add(24*time.Hour)) {
			t.Fatalf("expiry after the reopen = %v, want about 48h ahead", n.Expiry)
		}
	})

	s.section(t, "Y-04 beats a disabled expiry", func(t *testing.T) {
		code, body := s.deviceAction(laptop, "/expiry/disable", nil)
		wantApplied(t, "disable expiry", code, body)
		if n := s.mustNode(laptop); n.Expiry != nil {
			t.Fatalf("expiry = %v, want none", n.Expiry)
		}
		s.expireByRoleLoss(carol, "standart", laptop)
	})
}

// AC8: a manual DNS record is added, edited and deleted through the interface; each time the DNS
// file and the resolver's answer follow. The site-derived records stay read-only and the other
// manual records are not touched.
func TestE2E_F3_ManualDNS(t *testing.T) {
	s := newF2Stack(t, f2Options{})
	const name = "f3-manual.example.com"

	lookup := func(host string) []string {
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "udp", s.resolver.addr)
		}}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		ips, err := r.LookupIP(ctx, "ip4", host)
		if err != nil {
			return nil
		}
		var out []string
		for _, ip := range ips {
			out = append(out, ip.String())
		}
		return out
	}
	// change previews and approves one DNS form; it fails the test unless the change applied.
	change := func(form url.Values) {
		t.Helper()
		code, body := s.ui.post("/headscale/dns/preview", form)
		if code != http.StatusOK {
			t.Fatalf("preview: status %d: %s", code, excerpt(body))
		}
		request, version := inputValue(body, "request"), inputValue(body, "plan_version")
		if request == "" || version == "" {
			t.Fatalf("the preview offers no approval: %s", excerpt(body))
		}
		code, body = s.ui.post("/headscale/dns/approve", url.Values{"request": {request}, "plan_version": {version}})
		if res := parseResult(code, body); !res.applied {
			t.Fatalf("the DNS change was not applied (status %d, change %q): %s", code, res.changeStatus, excerpt(body))
		}
	}
	dnsFileHas := func(host, value string) bool {
		raw, err := os.ReadFile(s.dnsFile)
		if err != nil {
			t.Fatal(err)
		}
		return strings.Contains(string(raw), `"`+host+`"`) && (value == "" || strings.Contains(string(raw), `"`+value+`"`))
	}
	waitResolver := func(host, want string) {
		t.Helper()
		if err := poll(t, 20*time.Second, func() (bool, error) {
			got := lookup(host)
			if want == "" {
				return len(got) == 0, nil
			}
			return len(got) == 1 && got[0] == want, nil
		}); err != nil {
			t.Fatalf("the resolver's answer for %s never became %q (got %v)", host, want, lookup(host))
		}
	}

	page := s.ui.getOK("/headscale/dns")
	mustContain(t, "DNS page", page, "read-only", "old-db.example.com", e2eTagcessHost)
	waitResolver("old-db.example.com", "100.64.0.9")

	t.Run("add, edit, delete", func(t *testing.T) {
		change(url.Values{"action": {"add"}, "name": {name}, "value": {"100.64.0.77"}})
		if !dnsFileHas(name, "100.64.0.77") {
			t.Fatal("the new record is not in the DNS file")
		}
		waitResolver(name, "100.64.0.77")
		s.assertManualDNS("after the add")

		change(url.Values{"action": {"edit"}, "old_name": {name}, "old_type": {"A"}, "name": {name}, "value": {"100.64.0.78"}})
		waitResolver(name, "100.64.0.78")

		change(url.Values{"action": {"delete"}, "name": {name}, "type": {"A"}})
		if dnsFileHas(name, "") {
			t.Fatal("the deleted record is still in the DNS file")
		}
		waitResolver(name, "")
		s.assertManualDNS("after the delete")
		if !dnsFileHas(e2eTagcessHost, "") {
			t.Error("the delete took a site record out of the DNS file")
		}
	})

	t.Run("site records are read-only", func(t *testing.T) {
		before, err := os.ReadFile(s.dnsFile)
		if err != nil {
			t.Fatal(err)
		}
		// No form of the page edits or deletes a site record.
		for _, m := range formRE.FindAllStringSubmatch(s.ui.getOK("/headscale/dns"), -1) {
			if inputValue(m[2], "name") == e2eTagcessHost || inputValue(m[2], "old_name") == e2eTagcessHost {
				t.Errorf("the DNS page has a form acting on the site record %s", e2eTagcessHost)
			}
		}
		// A hand-made request is refused: not editable, not deletable, not shadowable.
		for what, form := range map[string]url.Values{
			"delete": {"action": {"delete"}, "name": {e2eTagcessHost}, "type": {"A"}},
			"edit":   {"action": {"edit"}, "old_name": {e2eTagcessHost}, "old_type": {"A"}, "name": {e2eTagcessHost}, "value": {"100.64.0.99"}},
		} {
			if code, body := s.ui.post("/headscale/dns/preview", form); code != http.StatusBadRequest {
				t.Errorf("%s of a site record: status %d, want 400: %s", what, code, excerpt(body))
			}
		}
		code, body := s.ui.post("/headscale/dns/preview", url.Values{"action": {"add"}, "name": {e2eTagcessHost}, "value": {"100.64.0.99"}})
		if inputValue(body, "plan_version") != "" || code >= 500 {
			t.Errorf("a manual record that shadows a site record was offered for approval (status %d): %s", code, excerpt(body))
		}
		after, err := os.ReadFile(s.dnsFile)
		if err != nil {
			t.Fatal(err)
		}
		if string(after) != string(before) {
			t.Errorf("the DNS file changed while only refused requests were made:\n%s\n→\n%s", before, after)
		}
	})
}

// f3Routes are the routes of the F3 interface a request with a foreign identity must not reach.
var f3Routes = []struct{ method, path string }{
	{http.MethodGet, "/headscale"},
	{http.MethodGet, "/headscale/devices"},
	{http.MethodGet, "/headscale/devices/table"},
	{http.MethodGet, "/headscale/devices/1"},
	{http.MethodGet, "/headscale/devices/1/routes"},
	{http.MethodGet, "/headscale/devices/1/tags"},
	{http.MethodGet, "/headscale/devices/1/delete"},
	{http.MethodGet, "/headscale/devices/1/reopen"},
	{http.MethodGet, "/headscale/keys"},
	{http.MethodGet, "/headscale/keys/preauth"},
	{http.MethodGet, "/headscale/keys/personal"},
	{http.MethodGet, "/headscale/keys/api"},
	{http.MethodGet, "/headscale/keys/api/1/delete"},
	{http.MethodGet, "/headscale/keys/preauth/1/expire"},
	{http.MethodGet, "/headscale/users"},
	{http.MethodGet, "/headscale/dns"},
	{http.MethodGet, "/headscale/settings"},
	{http.MethodPost, "/headscale/devices/1/rename"},
	{http.MethodPost, "/headscale/devices/1/expire"},
	{http.MethodPost, "/headscale/devices/1/expiry"},
	{http.MethodPost, "/headscale/devices/1/expiry/disable"},
	{http.MethodPost, "/headscale/devices/1/delete"},
	{http.MethodPost, "/headscale/devices/1/routes"},
	{http.MethodPost, "/headscale/devices/1/tags"},
	{http.MethodPost, "/headscale/devices/1/reopen/apply"},
	{http.MethodPost, "/headscale/keys/preauth/create"},
	{http.MethodPost, "/headscale/keys/preauth/1/expire"},
	{http.MethodPost, "/headscale/keys/preauth/1/delete"},
	{http.MethodPost, "/headscale/keys/personal"},
	{http.MethodPost, "/headscale/keys/api/1/expire"},
	{http.MethodPost, "/headscale/keys/api/1/delete"},
	{http.MethodPost, "/headscale/dns/preview"},
	{http.MethodPost, "/headscale/dns/approve"},
	{http.MethodPost, "/headscale/settings/tags"},
	{http.MethodPost, "/headscale/settings/locked"},
	{http.MethodPost, "/headscale/settings/config-write"},
	{http.MethodGet, "/headscale/config"},
	{http.MethodGet, "/headscale/config/status"},
	{http.MethodPost, "/headscale/config/preview"},
	{http.MethodPost, "/headscale/config/apply"},
	{http.MethodPost, "/headscale/config/close"},
}

// getThroughCaddyPath is getThroughCaddy for any path.
func getThroughCaddyPath(t *testing.T, path, cookie, spoofedGroups string) int {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://localhost:8080"+path, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Cookie", oauth2ProxyCookieName+"="+cookie)
	if spoofedGroups != "" {
		req.Header.Set("X-Auth-Request-Groups", spoofedGroups)
		req.Header.Set("X-Auth-Request-User", "devops")
	}
	client := &http.Client{Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET Caddy %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

// AC9: an identity without devops, with or without forged X-Auth-Request-* headers, gets 403 on
// every F3 route (and nothing is written); through the compose Caddy a developer session with a
// spoofed groups header is denied before it reaches the upstream.
func TestE2E_F3_SpoofedHeaderRejected(t *testing.T) {
	s := newF3Stack(t, f3Options{})
	audits := s.proc.queryInt(t, `SELECT count(*) FROM audit_events`)
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
		for _, r := range f3Routes {
			var form url.Values
			if r.method == http.MethodPost {
				form = url.Values{"csrf_token": {csrf}, "version": {"x"}, "expected": {"x"}, "confirm": {"evet"}}
			}
			if code, _ := uiRaw(t, s.proc.uiSock, r.method, r.path, header, form); code != http.StatusForbidden {
				t.Errorf("%s: %s %s: status %d, want 403", name, r.method, r.path, code)
			}
		}
	}
	if got := s.proc.queryInt(t, `SELECT count(*) FROM audit_events`); got != audits {
		t.Errorf("rejected requests wrote %d audit rows", got-audits)
	}
	// Control: the devops identity reaches the same pages.
	if code, body := s.ui.get("/headscale/devices"); code != http.StatusOK {
		t.Fatalf("devops control: status %d: %s", code, excerpt(body))
	}

	// Through the compose Caddy: oauth2-proxy denies a developer session whatever the headers say.
	secret := s.l.envFileValue(t, "OAUTH2_PROXY_COOKIE_SECRET")
	devops := forgeSessionCookie(t, secret, []string{"devops"})
	developer := forgeSessionCookie(t, secret, []string{"developer"})
	for _, path := range []string{"/headscale/devices", "/headscale/keys/api", "/headscale/dns"} {
		if code := getThroughCaddyPath(t, path, devops, ""); code != http.StatusOK {
			t.Errorf("devops session on %s through Caddy: status %d, want 200", path, code)
		}
		if code := getThroughCaddyPath(t, path, developer, "devops"); code != http.StatusForbidden {
			t.Errorf("developer session with a spoofed header on %s through Caddy: status %d, want 403", path, code)
		}
	}
}

// AC10: after a run, the lab user and its grant, the compose DNS file, the oauth2-proxy app's
// redirect URIs, the throwaway Headscale, the Caddy box and the binary's data directory are back
// to what they were. The subtest never calls a clean-up itself; what t.Run's return leaves behind
// is what the fixtures' own t.Cleanup did not remove. Two runs prove it is repeatable.
func TestF3E2E_Cleanup(t *testing.T) {
	l := setupLab(t)
	dnsFile := filepath.Join(l.composeDir, "dns", "extra-records.json")
	baselineDNS, err := os.ReadFile(dnsFile)
	if err != nil {
		t.Fatalf("read the compose DNS file (is `make lab-up` done?): %v", err)
	}
	baselineURIs := f2.New(t).SharedAppURIs(seed.OAuth2ProxyAppName)
	if len(baselineURIs) == 0 {
		t.Fatal("the seeded oauth2-proxy app has no redirect URIs; cannot verify the lab was left alone")
	}

	for run := 1; run <= 2; run++ {
		var userID, dataDir, grpcAddr, caddyName string
		t.Run("run"+string(rune('0'+run)), func(t *testing.T) {
			s := newF2Stack(t, f2Options{})
			userID = s.l.createUserWithRole(t, "standart")
			dataDir, grpcAddr, caddyName = s.proc.dataDir, s.hs.GRPCAddr(), s.caddy.name
			// Touch every piece of state the clean-up must put back: a DNS record (the compose
			// file) and the Zitadel side of the first import (the redirect URIs).
			code, body := s.ui.post("/headscale/dns/preview", url.Values{"action": {"add"}, "name": {"f3-cleanup.example.com"}, "value": {"100.64.0.66"}})
			if code != http.StatusOK || inputValue(body, "plan_version") == "" {
				t.Fatalf("manual record preview: status %d: %s", code, excerpt(body))
			}
			res := parseResult(s.ui.post("/headscale/dns/approve", url.Values{
				"request": {inputValue(body, "request")}, "plan_version": {inputValue(body, "plan_version")}}))
			if !res.applied {
				t.Fatalf("manual record not applied: %s", excerpt(res.body))
			}
		})

		if userID == "" || dataDir == "" {
			t.Fatalf("run%d: the subtest failed before it created its state", run)
		}
		if _, err := os.Stat(dataDir); !os.IsNotExist(err) {
			t.Errorf("run%d: the binary's data directory %s is still there (%v)", run, dataDir, err)
		}
		if conn, err := net.DialTimeout("tcp", grpcAddr, time.Second); err == nil {
			_ = conn.Close()
			t.Errorf("run%d: the throwaway Headscale at %s still answers", run, grpcAddr)
		}
		if out, _ := exec.Command("docker", "ps", "-a", "-q", "--filter", "name="+caddyName).Output(); strings.TrimSpace(string(out)) != "" {
			t.Errorf("run%d: the Caddy box %s is still there", run, caddyName)
		}
		if err := poll(t, 30*time.Second, func() (bool, error) {
			_, err := userv2.NewUserServiceClient(l.conn).GetUserByID(l.adminCtx, &userv2.GetUserByIDRequest{UserId: userID})
			return status.Code(err) == codes.NotFound, err
		}); err != nil {
			t.Errorf("run%d: the lab user %s is still in Zitadel: %v", run, userID, err)
		}
		if l.hasGrant(t, userID, "standart") {
			t.Errorf("run%d: the lab user's grant is still in Zitadel", run)
		}
		after, err := os.ReadFile(dnsFile)
		if err != nil || string(after) != string(baselineDNS) {
			t.Errorf("run%d: the compose DNS file is not as it was (%v):\nbefore %s\nafter  %s", run, err, baselineDNS, after)
		}
		if got := f2.New(t).SharedAppURIs(seed.OAuth2ProxyAppName); !sameURIs(baselineURIs, got) {
			t.Errorf("run%d: the oauth2-proxy app's redirect URIs changed:\nbefore %v\nafter  %v", run, baselineURIs, got)
		}
	}
}
