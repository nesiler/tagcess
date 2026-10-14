//go:build integration

// End-to-end acceptance of F2 (F2-016): the real tagcess binary driven through its web interface
// against a disposable Caddy, the compose Headscale's DNS file, the lab Zitadel and a disposable
// Headscale. See f2_stack_test.go for the stack and what is restored afterwards. Run with
// `make e2e` (requires `make lab-up`).
package e2e_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/zitadel"
)

const e2eHost = "e2e-app.example.com"

// blockOf returns the Caddyfile block that starts with the host line, or "" when there is none.
func blockOf(caddyfile, host string) string {
	start := strings.Index(caddyfile, "\n"+host+" {\n")
	if start < 0 {
		return ""
	}
	rest := caddyfile[start+1:]
	end := strings.Index(rest, "\n}\n")
	if end < 0 {
		return rest
	}
	return rest[:end+3]
}

func callbackOf(host string) string { return fmt.Sprintf(e2eCallbackTemplate, host) }

// siteVersionIDs lists the stored source versions of a site, oldest first.
func (s *f2Stack) siteVersionIDs(id int64) []int64 {
	s.t.Helper()
	rows, err := s.proc.storeDB(s.t).Query(`SELECT id FROM site_versions WHERE site_id = ? ORDER BY id`, id)
	if err != nil {
		s.t.Fatalf("list site versions: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var ids []int64
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			s.t.Fatal(err)
		}
		ids = append(ids, v)
	}
	return ids
}

// assertSite checks that one site is present in, or absent from, every artifact together: the
// stored record, the live Caddy config, the Caddyfile on disk, the DNS file and the redirect URIs.
func (s *f2Stack) assertSite(host string, present bool) {
	s.t.Helper()
	snap := s.snapshot()
	inLive := strings.Contains(snap.live, `"`+host+`"`)
	inDisk := blockOf(snap.caddyfile, host) != ""
	inDNS := s.dnsHas(host)
	inURIs := hasURI(snap.uris, callbackOf(host))
	inStore := s.siteID(host) != 0
	for what, got := range map[string]bool{
		"the live Caddy config": inLive, "the Caddyfile on disk": inDisk, "the DNS file": inDNS,
		"the redirect URIs": inURIs, "the site store": inStore,
	} {
		if got != present {
			s.t.Errorf("%s present in %s = %v, want %v", host, what, got, present)
		}
	}
}

// AC1: adding, editing and deleting a site through the interface updates Caddy, DNS and the
// Zitadel redirect URI together, writes the audit trail and the artifact history, and the round
// trip returns to byte-identical artifacts.
func TestF2E2E_SiteLifecycle(t *testing.T) {
	s := newF2Stack(t, f2Options{})
	callback := callbackOf(e2eHost)

	// The first import (done by the stack) is the baseline of the whole scenario.
	base := s.snapshot()
	if base.sites != 22 {
		t.Fatalf("sites after the first import = %d, want the 21 seeded + tagcess", base.sites)
	}
	for _, host := range []string{"monitor.example.com", e2eTagcessHost, "auth.example.com"} {
		if !strings.Contains(base.live, `"`+host+`"`) || !s.dnsHas(host) {
			t.Errorf("first import: %s is not in both the live Caddy config and the DNS file", host)
		}
	}
	if !hasURI(base.uris, callbackOf("monitor.example.com")) || !hasURI(base.uris, callbackOf(e2eTagcessHost)) {
		t.Errorf("first import: the callbacks of the role sites and the tagcess site are not in the app's redirect URIs: %v", base.uris)
	}
	if n := s.auditCount("site.first_import", "applied"); n != 1 {
		t.Errorf("first-import audit events = %d, want 1", n)
	}
	if got := len(s.gitLog()); got != 1 {
		t.Errorf("artifact history commits after the first import = %d, want 1", got)
	}

	// --- add: preview first (writes nothing), then approve -------------------------------------
	review := s.ui.review("/sites", roleSiteForm(e2eHost, "devops"))
	if !review.approvable() {
		t.Fatalf("the add form did not reach an approvable review (status %d): %s", review.code, excerpt(review.body))
	}
	if !strings.Contains(review.body, "DNS → Caddy → Zitadel") {
		t.Errorf("the add review does not state the apply order: %s", excerpt(review.body))
	}
	if !strings.Contains(review.diffs["Caddy"], e2eHost) || !strings.Contains(review.diffs["DNS"], e2eHost) || !strings.Contains(review.diffs["Zitadel"], callback) {
		t.Errorf("the add review lacks one of the three artifact diffs: %v", review.diffs)
	}
	s.assertUnchanged(base, "after the add preview")
	if n := s.auditCount("site.preview", "requested"); n != 1 {
		t.Errorf("preview audit events = %d, want 1", n)
	}

	res := s.ui.approve(review)
	if !res.applied || res.changeStatus != "applied" {
		t.Fatalf("add was not applied (status %d, change %q): %s", res.code, res.changeStatus, excerpt(res.body))
	}
	s.assertSite(e2eHost, true)
	afterAdd := s.snapshot()
	s.assertManualDNS("after the add")
	for uri := range base.uris {
		if !hasURI(afterAdd.uris, base.uris[uri]) {
			t.Errorf("the add dropped the redirect URI %s that was already there", base.uris[uri])
		}
	}
	if !strings.Contains(blockOf(afterAdd.caddyfile, e2eHost), "import vpn_site example.com devops\n") {
		t.Errorf("the Caddyfile block of the new site is not the role snippet import:\n%s", blockOf(afterAdd.caddyfile, e2eHost))
	}
	// The site is really routed: the S-06 key is open, so a source outside the tailnet is proxied
	// to the k8s upstream (nothing answers in this stack: 502), not refused.
	if code, err := s.caddy.get(e2eHost, "/", nil); err != nil || code != http.StatusBadGateway {
		t.Errorf("the new site outside the tailnet: status %d, err %v; want 502 from the unreachable k8s upstream", code, err)
	}
	for _, want := range []struct{ event, result string }{
		{"site.approve", "applied"}, {"site.apply", "applied"}, {"site.apply_start", "started"}, {"git.commit", "applied"},
	} {
		if n := s.auditCount(want.event, want.result); n < 1 {
			t.Errorf("no %s/%s audit event after the add", want.event, want.result)
		}
	}
	if n := s.proc.queryInt(t, `SELECT count(*) FROM audit_events WHERE event = 'site.approve' AND actor = ?`, e2eOperator); n < 1 {
		t.Errorf("the add is not attributed to the signed-in operator")
	}
	if got := len(s.gitLog()); got != 2 {
		t.Errorf("artifact history commits after the add = %d, want 2", got)
	}
	if n := s.headscaleReadErrors(); n != 0 {
		t.Errorf("the compose Headscale could not read the DNS file %d time(s)", n)
	}
	id := s.siteID(e2eHost)

	// --- edit: only the Caddy artifact changes ---------------------------------------------------
	edit := roleSiteForm(e2eHost, "devops", "developer")
	edit.Set("note", "e2e edit")
	review = s.ui.review("/sites/"+strconv.FormatInt(id, 10), edit)
	if !review.approvable() {
		t.Fatalf("the edit form did not reach an approvable review (status %d): %s", review.code, excerpt(review.body))
	}
	if !strings.Contains(review.diffs["Caddy"], "developer") || review.diffs["DNS"] != "" || review.diffs["Zitadel"] != "" {
		t.Errorf("a role change must change only the Caddy artifact, got %v", review.diffs)
	}
	if res = s.ui.approve(review); !res.applied {
		t.Fatalf("edit was not applied (status %d, change %q): %s", res.code, res.changeStatus, excerpt(res.body))
	}
	afterEdit := s.snapshot()
	if !strings.Contains(blockOf(afterEdit.caddyfile, e2eHost), "devops,developer") {
		t.Errorf("the edited roles are not on disk:\n%s", blockOf(afterEdit.caddyfile, e2eHost))
	}
	if afterEdit.live == afterAdd.live {
		t.Error("the live Caddy config did not change with the edit")
	}
	if afterEdit.dns != afterAdd.dns || !sameURIs(afterEdit.uris, afterAdd.uris) {
		t.Error("a role edit touched the DNS file or the redirect URIs")
	}

	// --- history and rollback (A-02, A-03): the add version comes back ----------------------------
	versions := s.siteVersionIDs(id)
	if len(versions) != 2 {
		t.Fatalf("site versions = %v, want the add and the edit", versions)
	}
	code, body := s.ui.get(fmt.Sprintf("/sites/%d/history", id))
	if code != http.StatusOK || strings.Count(body, "/rollback\"") != 2 || strings.Contains(body, "revision bekliyor") {
		t.Errorf("history page: status %d, rows %d, pending revisions %v", code, strings.Count(body, "/rollback\""), strings.Contains(body, "revision bekliyor"))
	}
	rollbackPath := fmt.Sprintf("/sites/%d/history/%d/rollback", id, versions[0])
	code, body = s.ui.get(rollbackPath)
	baseHash := inputValue(body, "base_hash")
	if code != http.StatusOK || baseHash == "" {
		t.Fatalf("rollback preview: status %d, base hash %q: %s", code, baseHash, excerpt(body))
	}
	if strings.Contains(body, "ack_widen") {
		t.Errorf("a rollback that narrows the roles must not ask for a widening acknowledgement")
	}
	s.assertSiteSnapshotEquals(afterEdit, "the read-only rollback preview")
	code, body = s.ui.post(rollbackPath, url.Values{"base_hash": {baseHash}})
	if code != http.StatusOK || !strings.Contains(body, "Rollback yapıldı") {
		t.Fatalf("rollback was not applied (status %d): %s", code, excerpt(body))
	}
	afterRollback := s.snapshot()
	if afterRollback.live != afterAdd.live || afterRollback.caddyfile != afterAdd.caddyfile {
		t.Error("the rollback did not restore the add-time Caddy artifacts byte for byte")
	}
	if got := len(s.siteVersionIDs(id)); got != 3 {
		t.Errorf("site versions after the rollback = %d, want 3 (the rollback is a new version)", got)
	}
	if got := len(s.gitLog()); got != 4 {
		t.Errorf("artifact history commits after edit and rollback = %d, want 4", got)
	}

	// --- delete: Zitadel first, then Caddy, then DNS ------------------------------------------------
	review = s.ui.review(fmt.Sprintf("/sites/%d/delete", id), nil)
	if !review.approvable() {
		t.Fatalf("the delete did not reach an approvable review (status %d): %s", review.code, excerpt(review.body))
	}
	if !strings.Contains(review.body, "Zitadel → Caddy → DNS") {
		t.Errorf("the delete review does not state the reversed order: %s", excerpt(review.body))
	}
	if review.diffs["Caddy"] == "" || review.diffs["DNS"] == "" || review.diffs["Zitadel"] == "" {
		t.Errorf("the delete review lacks one of the three artifact diffs: %v", review.diffs)
	}
	if res = s.ui.approve(review); !res.applied {
		t.Fatalf("delete was not applied (status %d, change %q): %s", res.code, res.changeStatus, excerpt(res.body))
	}
	s.assertSite(e2eHost, false)
	s.assertManualDNS("after the delete")
	final := s.snapshot()
	if final.caddyfile != base.caddyfile || final.live != base.live || final.dns != base.dns || !sameURIs(final.uris, base.uris) {
		t.Error("add + edit + rollback + delete did not return to the baseline artifacts byte for byte")
	}
	if n := s.proc.queryInt(t, `SELECT count(*) FROM site_versions WHERE site_id = ? AND deleted = 1`, id); n != 1 {
		t.Errorf("tombstone versions of the deleted site = %d, want 1 (history survives the delete)", n)
	}
	if n := s.proc.queryInt(t, `SELECT count(*) FROM changes WHERE kind = 'site' AND status = 'applied'`); n != 5 {
		t.Errorf("applied site changes = %d, want 5 (import, add, edit, rollback, delete)", n)
	}
	if n := s.headscaleReadErrors(); n != 0 {
		t.Errorf("the compose Headscale could not read the DNS file %d time(s)", n)
	}
	if n := s.openAlerts("site_drift") + s.openAlerts("site_unverified") + s.openAlerts("site_partial") + s.openAlerts("site_dns_unverified"); n != 0 {
		t.Errorf("%d open site alert(s) after a clean lifecycle", n)
	}
}

// assertSiteSnapshotEquals is assertUnchanged for a snapshot taken by the caller.
func (s *f2Stack) assertSiteSnapshotEquals(before snapshot, what string) {
	s.t.Helper()
	s.assertUnchanged(before, what)
}

// withAPIRules adds API exemption rules (ADR 0011) to a site form: pairs of type and value.
func withAPIRules(form url.Values, rules ...[2]string) url.Values {
	for _, r := range rules {
		form.Add("api_rule_type", r[0])
		form.Add("api_rule_value", r[1])
	}
	return form
}

// withRedirect adds one redirect to a site form.
func withRedirect(form url.Values, source, target, code string) url.Values {
	form.Add("redirect_source", source)
	form.Add("redirect_target", target)
	form.Add("redirect_code", code)
	return form
}

// expectStatus sends requests from outside the tailnet in parallel (a proxied one waits for the
// 3 s dial timeout of the unreachable k8s upstream) and fails for each one whose status differs.
type probe struct {
	name   string
	host   string
	path   string
	header map[string]string
	want   int
}

func (s *f2Stack) expectStatuses(probes []probe) {
	s.t.Helper()
	type outcome struct {
		code int
		err  error
	}
	results := make([]chan outcome, len(probes))
	for i, p := range probes {
		results[i] = make(chan outcome, 1)
		go func(p probe, out chan<- outcome) {
			code, err := s.caddy.get(p.host, p.path, p.header)
			out <- outcome{code, err}
		}(p, results[i])
	}
	for i, p := range probes {
		got := <-results[i]
		if got.err != nil || got.code != p.want {
			s.t.Errorf("%s: GET https://%s%s from outside the tailnet = %d (err %v), want %d", p.name, p.host, p.path, got.code, got.err, p.want)
		}
	}
}

// setS06 flips the S-06 key through the settings screens (preview, then approval) and returns the
// result screen.
func (s *f2Stack) setS06(open bool) siteResult {
	s.t.Helper()
	value := "closed"
	if open {
		value = "open"
	}
	code, body := s.ui.post("/sites/s06/preview", url.Values{"s06": {value}})
	version := inputValue(body, "plan_version")
	if code != http.StatusOK || version == "" {
		s.t.Fatalf("the S-06 %s preview offers no approval (status %d): %s", value, code, excerpt(body))
	}
	code, body = s.ui.post("/sites/s06/approve", url.Values{"s06": {value}, "plan_version": {version}})
	return parseResult(code, body)
}

// AC2: the access matrix of ADR 0010/0011 holds end to end: system sites cannot be deleted or
// reopened through any form, nothing a user types reaches the Caddyfile as syntax, the API
// exemption passes while the S-06 key is closed, and the key itself closes every other path from
// outside the tailnet (including sites added while it is closed) without touching the system
// sites' own rules.
func TestF2E2E_AccessSafety(t *testing.T) {
	s := newF2Stack(t, f2Options{})
	base := s.snapshot()

	systemHosts := map[string]string{
		"auth.example.com": "zitadel",
		"hs.example.com":   "headscale",
		"vpn.example.com":  "wireguard_ui",
		e2eTagcessHost:     "tagcess",
	}

	s.section(t, "system sites are locked", func(t *testing.T) {
		for host, template := range systemHosts {
			id := s.siteID(host)
			if id == 0 {
				t.Fatalf("system site %s (%s) is not in the store", host, template)
			}
			// Deleting it is refused with the lock status, and no approval is offered.
			r := s.ui.review(fmt.Sprintf("/sites/%d/delete", id), nil)
			if r.code != http.StatusConflict || r.approvable() || !strings.Contains(r.body, "kilitli") {
				t.Errorf("deleting the %s system site: status %d, approvable %v: %s", template, r.code, r.approvable(), excerpt(r.body))
			}
			// Taking its host with a new open or role site (to dodge the role control) is refused.
			for _, kind := range []string{"role", "open"} {
				form := roleSiteForm(host, "devops")
				form.Set("kind", kind)
				if kind == "open" {
					form.Set("roles", "")
					form.Set("open_reason", "intentional")
				}
				if r := s.ui.review("/sites", form); r.code < 400 || r.approvable() {
					t.Errorf("a new %s site on the %s host: status %d, approvable %v", kind, template, r.code, r.approvable())
				}
			}
		}
		// A system site cannot be created through the form at all.
		form := roleSiteForm("another-system.example.com")
		form.Set("kind", "system")
		if r := s.ui.review("/sites", form); r.code < 400 || r.approvable() {
			t.Errorf("creating a system site through the form: status %d, approvable %v", r.code, r.approvable())
		}
		// Editing one only reaches the fields its template opens: forging kind, hosts, roles and
		// cert changes nothing about the block (the preview is empty or refused).
		tagcessID := s.siteID(e2eTagcessHost)
		forged := roleSiteForm("forged.example.com", "standart")
		forged.Set("kind", "open")
		forged.Set("note", "forged")
		if r := s.ui.review(fmt.Sprintf("/sites/%d", tagcessID), forged); r.approvable() {
			if res := s.ui.approve(r); res.applied {
				// Only the note may have changed; the block text must be byte-identical.
				if got := s.snapshot().caddyfile; got != base.caddyfile {
					t.Errorf("a forged edit of the tagcess system site changed the Caddyfile")
				}
			}
		}
		s.assertUnchanged(base, "after the system site attempts")
	})

	s.section(t, "nothing a user types reaches the Caddyfile as syntax", func(t *testing.T) {
		const okHost = "e2e-inject.example.com"
		cases := []struct {
			name string
			form url.Values
		}{
			{"host with a block", roleSiteForm("e2e-inject.example.com {\n\trespond 200\n}\nx.example.com", "devops")},
			{"host with an environment placeholder", roleSiteForm("e2e-inject.example.com{$HOME}", "devops")},
			{"host outside the allowed domains", roleSiteForm("evil.example.com", "devops")},
			{"role with a space", roleSiteForm(okHost, "devops respond 200")},
			{"role with a brace", roleSiteForm(okHost, "devops}")},
			{"role that does not exist in Zitadel", roleSiteForm(okHost, "root")},
			{"cert path traversal", func() url.Values { f := roleSiteForm(okHost, "devops"); f.Set("cert", "le:../../etc/passwd"); return f }()},
			{"cert with a space", func() url.Values { f := roleSiteForm(okHost, "devops"); f.Set("cert", "le:x y"); return f }()},
			{"cert with a newline", func() url.Values { f := roleSiteForm(okHost, "devops"); f.Set("cert", "auto\nrespond 200"); return f }()},
			{"api rule regex with a quote", withAPIRules(roleSiteForm(okHost, "devops"), [2]string{"path_regex", "^/x'+\"a\"+'"})},
			{"api rule regex with a backtick", withAPIRules(roleSiteForm(okHost, "devops"), [2]string{"path_regex", "^/x`"})},
			{"api rule regex that does not compile", withAPIRules(roleSiteForm(okHost, "devops"), [2]string{"path_regex", "*"})},
			{"api rule header name with a newline", withAPIRules(roleSiteForm(okHost, "devops"), [2]string{"header_present", "X-Api\nrespond 200"})},
			{"redirect source with a newline", withRedirect(roleSiteForm(okHost, "devops"), "/a\nrespond 200", "/b", "308")},
			{"redirect target with a block", withRedirect(roleSiteForm(okHost, "devops"), "/a", "https://evil.example.com {", "308")},
			{"redirect with a non-redirect code", withRedirect(roleSiteForm(okHost, "devops"), "/a", "/b", "200")},
			{"open site with a target outside the allowlist", func() url.Values {
				f := roleSiteForm(okHost)
				f.Set("kind", "open")
				f.Set("roles", "")
				f.Set("open_reason", "intentional")
				f.Set("target_kind", "url")
				f.Set("target_url", "http://evil.example.com")
				return f
			}()},
			{"open site with a loopback target", func() url.Values {
				f := roleSiteForm(okHost)
				f.Set("kind", "open")
				f.Set("roles", "")
				f.Set("open_reason", "intentional")
				f.Set("target_kind", "url")
				f.Set("target_url", "http://127.0.0.1:2019")
				return f
			}()},
			{"open site with a unix socket target", func() url.Values {
				f := roleSiteForm(okHost)
				f.Set("kind", "open")
				f.Set("roles", "")
				f.Set("open_reason", "intentional")
				f.Set("target_kind", "url")
				f.Set("target_url", "unix//run/tagcess/ui.sock")
				return f
			}()},
			{"open site with a header value that breaks the line", func() url.Values {
				f := roleSiteForm(okHost)
				f.Set("kind", "open")
				f.Set("roles", "")
				f.Set("open_reason", "intentional")
				f.Set("target_kind", "url")
				f.Set("target_url", "http://100.64.0.5")
				f.Add("header_name", "X-Test")
				f.Add("header_value", "a\nrespond 200")
				return f
			}()},
		}
		// The control: the same form without a poisoned field is accepted for review, so every
		// refusal below is down to the field it changes.
		if r := s.ui.review("/sites", roleSiteForm(okHost, "devops")); !r.approvable() {
			t.Fatalf("the clean control form is not accepted (status %d): %s", r.code, excerpt(r.body))
		}
		for _, tc := range cases {
			r := s.ui.review("/sites", tc.form)
			if r.code < 400 || r.approvable() {
				t.Errorf("%s: status %d, approvable %v; want a refusal: %s", tc.name, r.code, r.approvable(), excerpt(r.body))
			}
		}
		s.assertUnchanged(base, "after the injection attempts")
		if strings.Contains(s.caddy.config(), "evil") || strings.Contains(base.caddyfile, "e2e-inject") {
			t.Error("a refused value reached the Caddy config")
		}
	})

	// A role site with the two API exemption kinds and a redirect, added while the key is open.
	const apiHost = "e2e-api.example.com"
	apiForm := withRedirect(withAPIRules(roleSiteForm(apiHost, "devops", "developer"),
		[2]string{"header_present", "Authorization"},
		[2]string{"path_regex", "^/api/v[0-9]+/"}), "/old", "/new", "308")
	if _, res := s.ui.apply("/sites", apiForm); !res.applied {
		t.Fatalf("the API site was not applied (status %d, change %q): %s", res.code, res.changeStatus, excerpt(res.body))
	}
	apiBlock := blockOf(s.snapshot().caddyfile, apiHost)
	for _, want := range []string{"@api", "Authorization", "vpn_site_api"} {
		if !strings.Contains(apiBlock, want) {
			t.Errorf("the API site's Caddyfile block lacks %q:\n%s", want, apiBlock)
		}
	}

	openHost := "projects-auth.example.com" // seeded kind open (intentional), no role control
	const (
		zitadelHost = "auth.example.com"
		moh         = "monitor.example.com"
	)
	s.section(t, "key open: today's behaviour", func(t *testing.T) {
		s.expectStatuses([]probe{
			{"role site", moh, "/", nil, http.StatusBadGateway},
			{"open site", openHost, "/", nil, http.StatusBadGateway},
			{"api site without an exemption", apiHost, "/", nil, http.StatusBadGateway},
			{"zitadel login path", zitadelHost, "/oauth/v2/authorize", nil, http.StatusBadGateway},
			{"zitadel console", zitadelHost, "/ui/console", nil, http.StatusForbidden},
			{"tagcess", e2eTagcessHost, "/", nil, http.StatusForbidden},
		})
		if code, loc, err := s.caddy.location(apiHost, "/old"); err != nil || code != http.StatusPermanentRedirect || loc != "/new" {
			t.Errorf("the redirect with the key open: status %d, location %q, err %v; want 308 /new", code, loc, err)
		}
	})

	s.section(t, "key closed: outside the tailnet only the exemption and the system rules pass", func(t *testing.T) {
		before := s.snapshot()
		code, body := s.ui.get("/sites/settings")
		if code != http.StatusOK || !strings.Contains(body, "açık") {
			t.Fatalf("settings page: status %d: %s", code, excerpt(body))
		}
		// The preview of the flip writes nothing.
		pcode, pbody := s.ui.post("/sites/s06/preview", url.Values{"s06": {"closed"}})
		review := parseReview(pcode, pbody)
		// A key flip changes the Caddyfile only. (The Zitadel block of a resync preview lists the
		// whole desired URI set, because a resync has no stored baseline to diff against; the step
		// itself writes nothing when the live list already matches, asserted below.)
		if pcode != http.StatusOK || !strings.Contains(review.diffs["Caddy"], "respond 403") || review.diffs["DNS"] != "" {
			t.Fatalf("the S-06 close preview: status %d, diffs %v", pcode, review.diffs)
		}
		s.assertUnchanged(before, "after the S-06 preview")
		if res := s.setS06(false); !res.applied {
			t.Fatalf("the key was not closed (status %d, change %q): %s", res.code, res.changeStatus, excerpt(res.body))
		}
		if closed := s.snapshot(); closed.dns != before.dns || !sameURIs(closed.uris, before.uris) || closed.caddyfile == before.caddyfile {
			t.Error("closing the key must change the Caddyfile and nothing else")
		}
		s.expectStatuses([]probe{
			{"role site", moh, "/", nil, http.StatusForbidden},
			{"open site", openHost, "/", nil, http.StatusForbidden},
			{"api site without an exemption", apiHost, "/", nil, http.StatusForbidden},
			{"api header exemption", apiHost, "/", map[string]string{"Authorization": "Bearer x"}, http.StatusBadGateway},
			{"api path exemption", apiHost, "/api/v1/things", nil, http.StatusBadGateway},
			{"api path outside the exemption", apiHost, "/api/things", nil, http.StatusForbidden},
			{"zitadel login path keeps its own rule", zitadelHost, "/oauth/v2/authorize", nil, http.StatusBadGateway},
			{"zitadel console keeps its own rule", zitadelHost, "/ui/console", nil, http.StatusForbidden},
			{"tagcess keeps its own rule", e2eTagcessHost, "/", nil, http.StatusForbidden},
		})
		// A redirect must not answer a source the key closed: it applies to the tailnet only.
		if code, loc, err := s.caddy.location(apiHost, "/old"); err != nil || code != http.StatusForbidden {
			t.Errorf("the redirect with the key closed: status %d, location %q, err %v; want 403", code, loc, err)
		}
		// The S-06 state is the stored setting, shown on the settings page.
		if _, body := s.ui.get("/sites/settings"); !strings.Contains(body, "kapalı") {
			t.Errorf("the settings page does not show the closed key: %s", excerpt(body))
		}
	})

	s.section(t, "a site added while the key is closed is born closed", func(t *testing.T) {
		const lateRole, lateOpen = "e2e-late.example.com", "e2e-late-open.example.com"
		if _, res := s.ui.apply("/sites", roleSiteForm(lateRole, "devops")); !res.applied {
			t.Fatalf("the late role site was not applied (status %d): %s", res.code, excerpt(res.body))
		}
		open := roleSiteForm(lateOpen)
		open.Set("kind", "open")
		open.Set("roles", "")
		open.Set("open_reason", "intentional")
		if _, res := s.ui.apply("/sites", open); !res.applied {
			t.Fatalf("the late open site was not applied (status %d): %s", res.code, excerpt(res.body))
		}
		s.expectStatuses([]probe{
			{"late role site", lateRole, "/", nil, http.StatusForbidden},
			{"late open site", lateOpen, "/", nil, http.StatusForbidden},
			{"older role site is still closed", moh, "/", nil, http.StatusForbidden},
		})
	})

	s.section(t, "a rollback that widens needs the acknowledgement and never reopens the key", func(t *testing.T) {
		id := s.siteID(apiHost)
		versions := s.siteVersionIDs(id)
		narrow := withRedirect(withAPIRules(roleSiteForm(apiHost, "devops"),
			[2]string{"header_present", "Authorization"},
			[2]string{"path_regex", "^/api/v[0-9]+/"}), "/old", "/new", "308")
		if _, res := s.ui.apply("/sites/"+strconv.FormatInt(id, 10), narrow); !res.applied {
			t.Fatalf("narrowing the roles was not applied (status %d): %s", res.code, excerpt(res.body))
		}
		narrowed := s.snapshot()
		path := fmt.Sprintf("/sites/%d/history/%d/rollback", id, versions[0])
		code, body := s.ui.get(path)
		hash := inputValue(body, "base_hash")
		if code != http.StatusOK || hash == "" || !strings.Contains(body, "Bu rollback erişimi genişletiyor") || !strings.Contains(body, "ack_widen") {
			t.Fatalf("the widening rollback preview: status %d, hash %q: %s", code, hash, excerpt(body))
		}
		// Without the acknowledgement nothing is applied.
		if code, body := s.ui.post(path, url.Values{"base_hash": {hash}}); code != http.StatusConflict || !strings.Contains(body, "onaylanmadı") {
			t.Errorf("a widening rollback without the acknowledgement: status %d: %s", code, excerpt(body))
		}
		s.assertUnchanged(narrowed, "after the refused widening rollback")
		// With it the roles come back, but the key stays closed.
		if code, body := s.ui.post(path, url.Values{"base_hash": {hash}, "ack_widen": {"1"}}); code != http.StatusOK || !strings.Contains(body, "Rollback yapıldı") {
			t.Fatalf("the acknowledged widening rollback: status %d: %s", code, excerpt(body))
		}
		if !strings.Contains(blockOf(s.snapshot().caddyfile, apiHost), "devops,developer") {
			t.Error("the acknowledged rollback did not restore the wider roles")
		}
		s.expectStatuses([]probe{
			{"rolled-back site stays closed", apiHost, "/", nil, http.StatusForbidden},
			{"other role site stays closed", moh, "/", nil, http.StatusForbidden},
		})
	})

	s.section(t, "reopening the key restores today's behaviour", func(t *testing.T) {
		if res := s.setS06(true); !res.applied {
			t.Fatalf("the key was not reopened (status %d, change %q): %s", res.code, res.changeStatus, excerpt(res.body))
		}
		s.expectStatuses([]probe{
			{"role site", moh, "/", nil, http.StatusBadGateway},
			{"open site", openHost, "/", nil, http.StatusBadGateway},
			{"late role site", "e2e-late.example.com", "/", nil, http.StatusBadGateway},
			{"zitadel console", zitadelHost, "/ui/console", nil, http.StatusForbidden},
			{"tagcess", e2eTagcessHost, "/", nil, http.StatusForbidden},
		})
	})
}

// waitServiceRole waits until the service user's project role is in effect. Zitadel evaluates it
// per request from a projection, so the switch is not instant: probe with a write of the list that
// is already live (a no-op when allowed) until it is denied (viewer) or accepted (owner).
func (s *f2Stack) waitServiceRole(viewer bool) {
	s.t.Helper()
	if err := poll(s.t, 60*time.Second, func() (bool, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		current := s.redirectURIsNoFatal(ctx)
		if len(current) == 0 {
			return false, errors.New("the app's redirect URIs are unreadable")
		}
		// Zitadel checks permission before it checks for changes: "No changes" means the write
		// was allowed.
		err := s.zit.UpdateAppRedirectURIs(ctx, s.appID, current)
		if viewer {
			return errors.Is(err, zitadel.ErrPermissionDenied), err
		}
		return err == nil || strings.Contains(err.Error(), "No changes"), err
	}); err != nil {
		s.t.Fatalf("the service user's role did not take effect (viewer=%v): %v", viewer, err)
	}
}

// siteAlertText is the sync page's alert area: open alerts are what the operator sees (P-02).
func (s *f2Stack) syncPage() string {
	s.t.Helper()
	code, body := s.ui.get("/sync")
	if code != http.StatusOK {
		s.t.Fatalf("GET /sync: status %d", code)
	}
	return body
}

// failureOf asserts the shape every refused or failed apply shares: the result screen says the
// change did not happen and that the last good state was kept, and the change row, the audit trail
// and the history agree.
func (s *f2Stack) failureOf(res siteResult, status string, commitsBefore int) {
	s.t.Helper()
	if res.applied || res.changeStatus != status {
		s.t.Fatalf("change status = %q (applied %v), want %q: %s", res.changeStatus, res.applied, status, excerpt(res.body))
	}
	if !strings.Contains(res.body, "Site kayıtları değişmedi: son iyi durum korundu") {
		s.t.Errorf("the result screen does not say the last good state was kept: %s", excerpt(res.body))
	}
	if res.reason == "" {
		s.t.Errorf("the result screen shows no reason for the failure: %s", excerpt(res.body))
	}
	if got := len(s.gitLog()); got != commitsBefore {
		s.t.Errorf("artifact history commits = %d, want %d: a failed change commits nothing", got, commitsBefore)
	}
}

// AC3: when the Caddy load or the Zitadel write breaks, the pipeline keeps the last good state,
// warns, and rolls back only what is provably safe to roll back; the screens say which.
func TestF2E2E_FailSafe(t *testing.T) {
	s := newF2Stack(t, f2Options{interval: 8 * time.Second})
	base := s.snapshot()
	commits := len(s.gitLog())

	s.section(t, "caddy refuses the load: the earlier DNS step is rolled back", func(t *testing.T) {
		// The record is valid and adapts; /load fails at provisioning because the certificate
		// file does not exist.
		form := roleSiteForm("e2e-nocert.example.com", "devops")
		form.Set("cert", "le:missing-cert.example.com")
		review, res := s.ui.apply("/sites", form)
		if !review.approvable() {
			t.Fatalf("the form did not reach an approvable review: %s", excerpt(review.body))
		}
		s.failureOf(res, "rolled_back", commits)
		if !strings.Contains(res.reason, "caddy adımı başarısız") || !strings.Contains(res.reason, "geri alındı") {
			t.Errorf("the reason does not name the failed step and the rollback: %q", res.reason)
		}
		s.assertUnchanged(base, "after the refused Caddy load")
		if n := s.auditCount("site.rolled_back", "rolled_back"); n != 1 {
			t.Errorf("rolled-back audit events = %d, want 1", n)
		}
		if n := s.headscaleReadErrors(); n != 0 {
			t.Errorf("the compose Headscale could not read the DNS file %d time(s) across the apply and its rollback", n)
		}
	})

	s.section(t, "the Caddyfile cannot be written: the live config is restored and the key goes back", func(t *testing.T) {
		if err := os.Chmod(s.work, 0o555); err != nil {
			t.Fatal(err)
		}
		restored := false
		restore := func() {
			if !restored {
				restored = true
				_ = os.Chmod(s.work, 0o755)
			}
		}
		t.Cleanup(restore)

		_, res := s.ui.apply("/sites", roleSiteForm("e2e-ro.example.com", "devops"))
		s.failureOf(res, "rolled_back", commits)
		if !strings.Contains(res.reason, "caddy adımı başarısız") {
			t.Errorf("the reason does not name the Caddy step: %q", res.reason)
		}
		s.assertUnchanged(base, "after the Caddyfile write failure of an add")
		if n := s.openAlerts("site_caddy_file"); n != 1 || !strings.Contains(s.syncPage(), "site_caddy_file") {
			t.Errorf("open site_caddy_file alerts = %d (on the sync page: %v), want one the operator can see", n, strings.Contains(s.syncPage(), "site_caddy_file"))
		}

		// Closing the key must not leave the stored key ahead of the live Caddy: the same write
		// failure restores the key to open, and the live config still lets the open sources in.
		res = s.setS06(false)
		if res.applied || !strings.Contains(res.body, "switch eski değerine (açık) geri alındı") {
			t.Errorf("a failed S-06 close: applied %v, restore note missing: %s", res.applied, excerpt(res.body))
		}
		s.assertUnchanged(base, "after the failed S-06 close")
		if _, body := s.ui.get("/sites/settings"); !strings.Contains(body, `role="switch" aria-checked="true"`) {
			t.Errorf("the settings page does not show the key as still open: %s", excerpt(body))
		}
		s.expectStatuses([]probe{{"role site after the failed close", "monitor.example.com", "/", nil, http.StatusBadGateway}})

		// Once the disk is writable again the next clean apply proves the warning gone.
		restore()
		if _, res := s.ui.apply("/sites", roleSiteForm("e2e-ro.example.com", "devops")); !res.applied {
			t.Fatalf("the retry after the disk was fixed was not applied: %s", excerpt(res.body))
		}
		if n := s.openAlerts("site_caddy_file"); n != 0 {
			t.Errorf("site_caddy_file stays open after a clean apply (%d)", n)
		}
		// Put the stack back on the baseline for the next scenarios.
		id := s.siteID("e2e-ro.example.com")
		if _, res := s.ui.apply(fmt.Sprintf("/sites/%d/delete", id), nil); !res.applied {
			t.Fatalf("cleaning up the retry site: %s", excerpt(res.body))
		}
		s.assertUnchanged(snapshot{caddyfile: base.caddyfile, live: base.live, dns: base.dns, uris: base.uris, sites: base.sites}, "after the retry round trip")
		commits = len(s.gitLog())
	})

	s.section(t, "Caddy is unreachable at approval: nothing is written", func(t *testing.T) {
		review := s.ui.review("/sites", roleSiteForm("e2e-down.example.com", "devops"))
		if !review.approvable() {
			t.Fatalf("no approvable review: %s", excerpt(review.body))
		}
		s.caddy.pause(t)
		unpaused := false
		unpause := func() {
			if !unpaused {
				unpaused = true
				s.caddy.unpause(t)
			}
		}
		t.Cleanup(unpause)
		code, body := s.ui.post("/sites/review/approve", url.Values{"request": {review.request}, "plan_version": {review.version}})
		unpause()
		res := parseResult(code, body)
		if res.changeStatus != "failed" || res.applied || !strings.Contains(res.reason, "Caddy admin API okunamadı") {
			t.Errorf("approving while Caddy is unreachable: status %d, change %q: %s", code, res.changeStatus, excerpt(body))
		}
		if !strings.Contains(body, "Site kayıtları değişmedi: son iyi durum korundu") {
			t.Errorf("the result screen does not say the last good state was kept: %s", excerpt(body))
		}
		if n := s.auditCount("site.blocked", "blocked"); n != 1 {
			t.Errorf("blocked audit events = %d, want 1 (the gate stopped the change before the first write)", n)
		}
		if n := s.openAlerts("site_drift"); n != 1 {
			t.Errorf("open site_drift alerts = %d, want 1", n)
		}
		s.assertUnchanged(base, "after the approval with Caddy unreachable")
		// Back up, the very same change goes through the review again.
		if r := s.ui.review("/sites", roleSiteForm("e2e-down.example.com", "devops")); !r.approvable() {
			t.Errorf("the review stays blocked after Caddy came back: %s", excerpt(r.body))
		}
	})

	s.section(t, "a hand-edited Caddyfile blocks every change instead of being overwritten", func(t *testing.T) {
		edited := base.caddyfile + "# edited by hand\n"
		if err := os.WriteFile(s.caddyfile, []byte(edited), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.WriteFile(s.caddyfile, []byte(base.caddyfile), 0o644) })
		// The preview shows the hand edit among the lines the change would replace, and the
		// approval is stopped by the drift gate before anything is written.
		review := s.ui.review("/sites", roleSiteForm("e2e-drift.example.com", "devops"))
		if !review.approvable() || !strings.Contains(review.diffs["Caddy"], "-# edited by hand") {
			t.Fatalf("the preview over a hand-edited Caddyfile: approvable %v, diffs %v", review.approvable(), review.diffs)
		}
		// Every blocked change opens its own alert (the source is the change id).
		alertsBefore := s.openAlerts("site_drift")
		res := s.ui.approve(review)
		if res.applied || res.changeStatus != "failed" || !strings.Contains(res.reason, "Caddyfile kayıtlardan farklı") {
			t.Errorf("the approval over a hand-edited Caddyfile: change %q, reason %q", res.changeStatus, res.reason)
		}
		if got, _ := os.ReadFile(s.caddyfile); string(got) != edited {
			t.Error("tagcess overwrote the hand-edited Caddyfile")
		}
		if n := s.openAlerts("site_drift"); n != alertsBefore+1 {
			t.Errorf("open site_drift alerts = %d, want %d", n, alertsBefore+1)
		}
		if err := os.WriteFile(s.caddyfile, []byte(base.caddyfile), 0o644); err != nil {
			t.Fatal(err)
		}
		s.assertUnchanged(base, "after the hand-edit round trip")
	})

	s.section(t, "the resolver does not confirm a name: applied with a warning, cleared by the next clean apply", func(t *testing.T) {
		s.resolver.silent.Store(true)
		res := func() siteResult {
			_, r := s.ui.apply("/sites", roleSiteForm("e2e-dns.example.com", "devops"))
			return r
		}()
		s.resolver.silent.Store(false)
		if !res.applied {
			t.Fatalf("an unconfirmed DNS name must not undo the apply (status %q): %s", res.changeStatus, excerpt(res.body))
		}
		if n := s.openAlerts("site_dns_unverified"); n != 1 || !strings.Contains(s.syncPage(), "site_dns_unverified") {
			t.Errorf("open site_dns_unverified alerts = %d, want one on the sync page", n)
		}
		if n := s.auditCount("site.dns_unverified", "unverified"); n < 1 && s.proc.queryInt(t, `SELECT count(*) FROM audit_events WHERE event = 'site.dns_unverified'`) < 1 {
			t.Error("the unconfirmed name is not in the audit trail")
		}
		if !s.dnsHas("e2e-dns.example.com") {
			t.Error("the DNS record was removed although only its verification failed")
		}
		id := s.siteID("e2e-dns.example.com")
		if _, res := s.ui.apply(fmt.Sprintf("/sites/%d/delete", id), nil); !res.applied {
			t.Fatalf("deleting the DNS test site: %s", excerpt(res.body))
		}
		if n := s.openAlerts("site_dns_unverified"); n != 0 {
			t.Errorf("site_dns_unverified stays open after a clean apply (%d)", n)
		}
		commits = len(s.gitLog())
	})

	s.section(t, "Zitadel refuses the write: no blind rollback, a warning, and a way back", func(t *testing.T) {
		// One live site to delete first, added while Zitadel still accepts writes.
		const kept = "e2e-keep.example.com"
		if _, res := s.ui.apply("/sites", roleSiteForm(kept, "devops")); !res.applied {
			t.Fatalf("setting up the site to delete: %s", excerpt(res.body))
		}
		withKept := s.snapshot()
		commits = len(s.gitLog())

		if err := s.setServiceRole("PROJECT_OWNER_VIEWER"); err != nil {
			t.Fatalf("switch the service user to the read-only project role: %v", err)
		}
		t.Cleanup(s.restoreServiceRole)
		s.waitServiceRole(true)

		// A delete starts with Zitadel: the refused write leaves Caddy and DNS exactly as they were.
		_, res := s.ui.apply(fmt.Sprintf("/sites/%d/delete", s.siteID(kept)), nil)
		s.failureOf(res, "failed", commits)
		s.assertUnchanged(withKept, "after the refused Zitadel write of a delete")
		if n := s.openAlerts("site_unverified"); n != 1 {
			t.Errorf("open site_unverified alerts after the refused delete = %d, want 1", n)
		}

		// An add reaches Zitadel last: DNS and Caddy were applied and are kept (the write's outcome
		// is not proven, so nothing is rolled back blindly), the record is not stored and the
		// operator is warned.
		const orphan = "e2e-orphan.example.com"
		_, res = s.ui.apply("/sites", roleSiteForm(orphan, "devops"))
		s.failureOf(res, "failed", commits)
		if !strings.Contains(res.reason, "zitadel adımı başarısız") {
			t.Errorf("the reason does not name the Zitadel step: %q", res.reason)
		}
		if s.siteID(orphan) != 0 {
			t.Error("a site whose Zitadel write failed was stored")
		}
		if hasURI(s.redirectURIs(), callbackOf(orphan)) {
			t.Error("the redirect URI of the failed add is in Zitadel")
		}
		page := s.syncPage()
		if !strings.Contains(page, "site_unverified") {
			t.Errorf("the sync page does not warn about the unverified write: %s", excerpt(page))
		}

		// The role comes back. The unrecorded artifacts are a drift the pipeline will not
		// overwrite by itself: the next ordinary change is blocked and says why ...
		s.restoreServiceRole()
		s.waitServiceRole(false)
		if _, res := s.ui.apply("/sites", roleSiteForm("e2e-after.example.com", "devops")); res.applied || !strings.Contains(res.reason, "kayıtlardan farklı") {
			t.Errorf("a change over unrecorded artifacts must be stopped by the drift gate: change %q, reason %q", res.changeStatus, res.reason)
		}
		// ... and the explicit resync (the S-06 flip re-applies the stored records over the live
		// artifacts) is the way back: the orphan leaves Caddy and DNS and the warnings clear.
		if res := s.setS06(false); !res.applied {
			t.Fatalf("the resync after the Zitadel failure was not applied: %s", excerpt(res.body))
		}
		if res := s.setS06(true); !res.applied {
			t.Fatalf("reopening the key after the resync: %s", excerpt(res.body))
		}
		after := s.snapshot()
		if strings.Contains(after.live, orphan) || s.dnsHas(orphan) {
			t.Error("the resync left the unrecorded site in Caddy or DNS")
		}
		if n := s.openAlerts("site_unverified"); n != 0 {
			t.Errorf("site_unverified stays open after the resync (%d)", n)
		}
		if _, res := s.ui.apply(fmt.Sprintf("/sites/%d/delete", s.siteID(kept)), nil); !res.applied {
			t.Fatalf("deleting the kept site after the role came back: %s", excerpt(res.body))
		}
		s.assertUnchanged(base, "back on the baseline after the Zitadel failure round trip")
		commits = len(s.gitLog())
	})

	s.section(t, "the periodic run reports a redirect URI somebody removed", func(t *testing.T) {
		victim := callbackOf("monitor.example.com")
		current := s.redirectURIs()
		var cut []string
		for _, u := range current {
			if u != victim {
				cut = append(cut, u)
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := s.zit.UpdateAppRedirectURIs(ctx, s.appID, cut); err != nil {
			t.Fatalf("remove a URI behind tagcess's back: %v", err)
		}
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			if sameURIs(s.redirectURIsNoFatal(ctx), current) {
				return
			}
			if err := s.zit.UpdateAppRedirectURIs(ctx, s.appID, current); err != nil {
				t.Errorf("put the removed URI back: %v", err)
			}
		})
		// The sync interval is 8 s: the drift shows up within a few periods.
		if err := poll(t, 90*time.Second, func() (bool, error) { return s.openAlerts("zitadel_uri_drift") == 1, nil }); err != nil {
			t.Fatalf("the periodic run never raised the redirect URI drift alert: %v", err)
		}
		if !strings.Contains(s.syncPage(), "zitadel_uri_drift") {
			t.Error("the drift alert is not on the sync page")
		}
		// A change over a drifted list is stopped by the gate, not written over it.
		if _, res := s.ui.apply("/sites", roleSiteForm("e2e-uridrift.example.com", "devops")); res.applied || !strings.Contains(res.reason, "redirect URI listesi kayıtlardan farklı") {
			t.Errorf("a change over a drifted URI list: change %q, reason %q", res.changeStatus, res.reason)
		}
		// Put the URI back: the next periodic run clears the alert by itself.
		if err := s.zit.UpdateAppRedirectURIs(ctx, s.appID, current); err != nil {
			t.Fatalf("put the removed URI back: %v", err)
		}
		if err := poll(t, 90*time.Second, func() (bool, error) { return s.openAlerts("zitadel_uri_drift") == 0, nil }); err != nil {
			t.Fatalf("the drift alert did not clear after the URI came back: %v", err)
		}
	})
}
