//go:build integration

package e2e_test

import (
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/test/compose/f2"
	"github.com/nesiler/tagcess/test/compose/seed"
	"github.com/nesiler/tagcess/test/k8s"
)

// F4-036 scenarios: failure, dry run and the phase-closing secret scan (run with `make f4-e2e`, same
// opt-in as F4-035/F4-040). The role-source outage and the second inventory page are not reproducible
// against the real lab (the lab Zitadel and API are not ours to cut); they are covered by the unit
// tests named in the task evidence, so this file only claims the credential failure.

var observedRE = regexp.MustCompile(`(?s)Son tarama.*?<span class="stt-at">([^<]+)</span>`)
var freshnessAttrRE = regexp.MustCompile(`data-freshness="([a-z]+)"`)

// TestF4_E2E_LastGoodAndStaleSources is F4-036 AC1: when the cluster credential stops working, the
// last good snapshot and its original time stay, the state is labelled stale, no site is removed and
// the role matrix is still presented as the expected (not effective) access.
func TestF4_E2E_LastGoodAndStaleSources(t *testing.T) {
	s := newF4Stack(t)
	s.connect(f4Upstream)
	good := s.waitPage("/k8s/discovery", "a current snapshot with the lab host", func(b string) bool {
		m := freshnessAttrRE.FindStringSubmatch(b)
		return m != nil && m[1] == "current" && strings.Contains(b, f4Host)
	})
	goodAt := observedRE.FindStringSubmatch(good)
	if goodAt == nil {
		t.Fatalf("the discovery shows no last-good time: %s", excerpt(good))
	}
	base := s.snapshot()

	// The token stops working (an expired short-lived token answers 401).
	s.lab.Revoke()
	stale := s.waitPage("/k8s/discovery", "the stale label after the credential failed", func(b string) bool {
		m := freshnessAttrRE.FindStringSubmatch(b)
		return m != nil && m[1] == "stale"
	})
	if !strings.Contains(stale, f4Host) || !strings.Contains(stale, s.rt.Namespace) {
		t.Errorf("the stale discovery lost the last good inventory: %s", excerpt(stale))
	}
	if got := observedRE.FindStringSubmatch(stale); got == nil || got[1] != goodAt[1] {
		t.Errorf("the last-good time changed or vanished: %q -> %v", goodAt[1], got)
	}
	if !strings.Contains(stale, "Güncel değil: son tarama başarısız oldu") {
		t.Errorf("the stale discovery does not say it is not current: %s", excerpt(stale))
	}

	_, dash := s.ui.get("/")
	snap := cardOf(dash, "k8s_snapshot")
	if !strings.Contains(snap, `data-freshness="stale"`) || !strings.Contains(snap, "Taranan namespace'ler:") || !strings.Contains(snap, "son başarılı tarama gösteriliyor") {
		t.Errorf("the dashboard snapshot card is not the stale last-good view: %s", excerpt(snap))
	}
	matrix := cardOf(dash, "matrix")
	if !strings.Contains(matrix, "beklenen erişim") || !strings.Contains(matrix, "etkili uçtan uca erişim garantisi değildir") {
		t.Errorf("the matrix is not presented as expected access only: %s", excerpt(matrix))
	}

	// A missing read removes nothing.
	s.assertUnchanged(base, "after the credential failure")
	for _, page := range []string{dash, stale} {
		if strings.Contains(page, s.rt.Token) {
			t.Error("a page echoes the cluster token")
		}
	}
}

// TestF4_E2E_ApplyAndRollbackFailures is F4-036 AC2: a draft apply that fails keeps the last good
// state (S-04 conditional rollback result), is never reported as applied and leaves the critical
// alarm open.
func TestF4_E2E_ApplyAndRollbackFailures(t *testing.T) {
	s := newF4Stack(t)
	review := s.reviewableDraft()
	base := s.snapshot()
	commits := len(s.gitLog())

	// Caddy cannot be read at approval: the gate stops the change before the first write.
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
	s.failureOf(res, "failed", commits)
	if !strings.Contains(res.reason, "Caddy admin API okunamadı") {
		t.Errorf("the reason does not name the unreadable Caddy: %q", res.reason)
	}
	s.assertUnchanged(base, "after the approval with Caddy unreachable")
	if s.siteID(f4Host) != 0 {
		t.Error("the draft host became a site although the apply failed")
	}
	if n := s.openAlerts("site_drift"); n != 1 {
		t.Errorf("open site_drift alerts = %d, want the one critical alarm", n)
	}

	// Zitadel refuses the redirect URI write (read-only project role): DNS and Caddy are not rolled
	// back blindly, the result is "failed" (never "applied", never a masked old state) and the
	// unverified-write alarm is raised.
	if err := s.setServiceRole("PROJECT_OWNER_VIEWER"); err != nil {
		t.Fatalf("switch the service user to the read-only project role: %v", err)
	}
	t.Cleanup(s.restoreServiceRole)
	s.waitServiceRole(true)
	res = s.ui.approve(s.draftReview())
	s.failureOf(res, "failed", commits)
	if !strings.Contains(res.reason, "zitadel adımı başarısız") {
		t.Errorf("the reason does not name the Zitadel step: %q", res.reason)
	}
	if s.siteID(f4Host) != 0 {
		t.Error("a draft whose Zitadel write failed was stored as a site")
	}
	if hasURI(s.redirectURIs(), callbackOf(f4Host)) {
		t.Error("the redirect URI of the failed draft is in Zitadel")
	}
	if n := s.openAlerts("site_unverified"); n != 1 {
		t.Errorf("open site_unverified alerts = %d, want 1", n)
	}
	if page := s.syncPage(); !strings.Contains(page, "site_unverified") {
		t.Errorf("the sync page does not show the unverified write: %s", excerpt(page))
	}
	if n := s.openAlerts("site_drift"); n < 1 {
		t.Errorf("the critical drift alarm was dropped (%d open)", n)
	}
	// The draft itself survives and can be reopened.
	if code, _ := s.ui.get(draftPath("")); code != http.StatusOK {
		t.Errorf("the draft cannot be reopened after the failure: status %d", code)
	}
}

// TestF4_E2E_DryRunHasNoWrites is F4-036 AC3: with dry run on, the draft preview works and the apply
// request changes nothing (Caddy, DNS, URIs, history); the cluster identity cannot write at all.
// Control: the same draft applies once dry run is off.
func TestF4_E2E_DryRunHasNoWrites(t *testing.T) {
	s := newF4Stack(t)
	review := s.reviewableDraft()
	base := s.snapshot()
	commits := len(s.gitLog())

	if code, body := s.ui.post("/sync/dry-run", url.Values{"confirm": {"1"}, "dry_run": {"true"}}); code != http.StatusOK && code != http.StatusSeeOther {
		t.Fatalf("turn dry run on: status %d: %s", code, excerpt(body))
	}
	review = s.draftReview() // the preview is still available
	s.assertUnchanged(base, "after the dry-run preview")
	res := s.ui.approve(review)
	if res.applied || res.changeStatus != "dry_run" {
		t.Fatalf("a dry-run apply: applied %v, change %q: %s", res.applied, res.changeStatus, excerpt(res.body))
	}
	s.assertUnchanged(base, "after the dry-run apply")
	if s.siteID(f4Host) != 0 {
		t.Error("the dry run created a site")
	}
	if got := len(s.gitLog()); got != commits {
		t.Errorf("artifact history commits = %d, want %d", got, commits)
	}

	// Kubernetes: the lab identity is read-only by construction, so no apply path can write there.
	rbac, err := os.ReadFile(filepath.Join(repoRoot(), "test/k8s/rbac.yaml"))
	if err != nil {
		t.Fatalf("read the lab RBAC: %v", err)
	}
	for _, verb := range []string{`"create"`, `"update"`, `"patch"`, `"delete"`, `"*"`} {
		if strings.Contains(string(rbac), verb) {
			t.Errorf("the lab ServiceAccount has the %s verb", verb)
		}
	}

	// Control: dry run off, the same draft applies.
	if code, body := s.ui.post("/sync/dry-run", url.Values{"confirm": {"1"}, "dry_run": {"false"}}); code != http.StatusOK && code != http.StatusSeeOther {
		t.Fatalf("turn dry run off: status %d: %s", code, excerpt(body))
	}
	if res := s.ui.approve(s.draftReview()); !res.applied {
		t.Fatalf("the control apply with dry run off failed (change %q): %s", res.changeStatus, excerpt(res.body))
	}
}

// secretHits returns "<where>: <label>" for every secret found in the corpus.
func secretHits(corpus, secrets map[string]string) []string {
	var hits []string
	for where, text := range corpus {
		for label, secret := range secrets {
			if secret != "" && strings.Contains(text, secret) {
				hits = append(hits, where+": "+label)
			}
		}
	}
	return hits
}

// storeText dumps every cell of every table as text.
func storeText(t *testing.T, db *sql.DB) string {
	t.Helper()
	tables, err := db.Query(`SELECT name FROM sqlite_master WHERE type = 'table'`)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	var names []string
	for tables.Next() {
		var n string
		if err := tables.Scan(&n); err != nil {
			t.Fatal(err)
		}
		names = append(names, n)
	}
	_ = tables.Close()
	var b strings.Builder
	for _, n := range names {
		rows, err := db.Query(fmt.Sprintf(`SELECT * FROM %q`, n))
		if err != nil {
			t.Fatalf("read table %s: %v", n, err)
		}
		cols, _ := rows.Columns()
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			for _, v := range vals {
				switch x := v.(type) {
				case []byte:
					b.Write(x)
				default:
					fmt.Fprint(&b, x)
				}
				b.WriteByte('|')
			}
			b.WriteByte('\n')
		}
		_ = rows.Close()
	}
	return b.String()
}

// TestF4_E2E_NoSecretsAndCleanup is F4-036 AC5: after discovery, a rejected credential and a draft
// apply, no runtime token or private key is in the logs, the audit/SQLite store, the artifact git
// history or any response, and every fixture of the run is gone. The scanner proves it can find a
// secret first (positive control with a canary generated at run time).
func TestF4_E2E_NoSecretsAndCleanup(t *testing.T) {
	// Positive control: the scanner flags a runtime canary and stays quiet without it.
	canary := fmt.Sprintf("canary-%x", randomBytes(t, 16))
	if got := secretHits(map[string]string{"control": "log line " + canary}, map[string]string{"canary": canary}); len(got) != 1 {
		t.Fatalf("the scanner missed a planted canary: %v", got)
	}
	if got := secretHits(map[string]string{"control": "clean"}, map[string]string{"canary": canary}); len(got) != 0 {
		t.Fatalf("the scanner flagged a clean text: %v", got)
	}

	k8s.RequireLab(t, os.Getenv) // no opt-in: SKIP before anything is touched
	baseline := f2.New(t).SharedAppURIs(seed.OAuth2ProxyAppName)
	var (
		ran            bool
		work, dataDir  string
		caddyName      string
		scanned        int
		hits           []string
		scenarioFailed bool
	)
	ok := t.Run("stack", func(t *testing.T) {
		s := newF4Stack(t)
		ran = true
		work, dataDir, caddyName = s.work, s.proc.dataDir, s.caddy.name

		var responses []string
		get := func(path string) {
			code, body := s.ui.get(path)
			if code != http.StatusOK {
				t.Errorf("GET %s: status %d", path, code)
			}
			responses = append(responses, body)
		}

		// A credential with a made-up token is refused by the read-only attempt; its response must not
		// echo it, and it must not reach the store or the logs.
		s.setAPIPolicy()
		s.saveProfile(f4Upstream)
		code, body := s.ui.post("/k8s/connection/credential", url.Values{
			"endpoint": {s.rt.Server}, "tls_server_name": {s.tlsServerName()}, "ca_data": {s.rt.CAPEM}, "token": {canary},
		})
		if code == http.StatusOK && strings.Contains(body, "kaydedildi") {
			t.Error("a made-up token was accepted as the cluster credential")
		}
		responses = append(responses, body)

		review := s.reviewableDraft() // saves the real credential and discovers
		res := s.ui.approve(review)
		responses = append(responses, res.body)
		if !res.applied {
			t.Fatalf("the draft was not applied (change %q): %s", res.changeStatus, excerpt(res.body))
		}
		for _, p := range []string{"/", "/alerts", "/sync", "/sites", "/monitor/settings", "/k8s/connection", "/k8s/setup", "/k8s/discovery", draftPath("")} {
			get(p)
		}

		secrets := map[string]string{"cluster token": s.rt.Token, "canary token": canary}
		if raw, err := os.ReadFile(s.cfg.keyFile); err == nil {
			var key struct {
				Key string `json:"key"`
			}
			if json.Unmarshal(raw, &key) == nil && key.Key != "" {
				secrets["zitadel private key"] = key.Key
			}
		}
		corpus := map[string]string{
			"tagcess log": s.proc.stderr.String(),
			"sqlite":      storeText(t, s.proc.storeDB(t)),
		}
		if out, err := exec.Command("git", "-C", filepath.Join(s.proc.dataDir, "artifact-git"), "log", "-p", "--all").CombinedOutput(); err == nil {
			corpus["artifact git"] = string(out)
		} else {
			t.Errorf("read the artifact git history: %v", err)
		}
		for i, r := range responses {
			corpus[fmt.Sprintf("response %d", i)] = r
		}
		scanned = len(corpus)
		hits = secretHits(corpus, secrets)
		for _, h := range hits {
			t.Errorf("secret found: %s", h)
		}
		scenarioFailed = t.Failed()
	})
	if !ran {
		t.Skip("the real-lab stack did not start (skipped, not a PASS)")
	}
	if !ok {
		t.Fatalf("the scenario or the fixture cleanup failed (scanned %d sources, hits %v, failed %v)", scanned, hits, scenarioFailed)
	}

	// The subtest returned, so every cleanup has run (the lab's own cleanup fails the subtest when
	// objects are left in the cluster).
	for _, p := range []string{work, dataDir} {
		if p == "" {
			t.Fatal("the scenario did not record its directories")
		}
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s still exists after the scenario (stat err = %v)", p, err)
		}
	}
	if out, err := exec.Command("docker", "ps", "-a", "-q", "--filter", "name="+caddyName).Output(); err != nil || strings.TrimSpace(string(out)) != "" {
		t.Errorf("the Caddy fixture container %s is left (err %v, %q)", caddyName, err, out)
	}
	if after := f2.New(t).SharedAppURIs(seed.OAuth2ProxyAppName); !sameURIs(baseline, after) {
		t.Errorf("the shared lab redirect URIs changed:\nbefore %v\nafter  %v", baseline, after)
	}
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}
