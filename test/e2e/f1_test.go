//go:build integration

// End-to-end scenarios for F1-021 (the F1 exit criteria) against the lab Zitadel and a disposable
// database-mode Headscale. See harness_test.go and `make e2e`.
package e2e_test

import (
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/nesiler/tagcess/test/compose/hsstack"
)

// AC1: a grant added in the lab Zitadel updates the Headscale policy group within 5 seconds through
// the webhook -> trigger -> reconcile -> change pipeline chain.
func TestE2E_GrantAddedViaWebhook(t *testing.T) {
	l := setupLab(t)
	hs := hsstack.Start(t)
	// The Headscale user exists before tagcess starts (making it restarts the Headscale); the role
	// is granted last, so the webhook event is what applies it.
	userID := l.createHeadscaleUser(t, hs)
	startTagcess(t, l, tagcessConfig{
		headscaleAddr: hs.GRPCAddr(),
		issuer:        l.issuer,
		keyFile:       filepath.Join(l.secrets(), "zitadel-key.json"),
		interval:      5 * time.Minute, // long: only the webhook can apply within the budget
	})

	l.grant(t, userID, "standart")
	want := l.providerID(userID)
	start := time.Now()
	if err := poll(t, 10*time.Second, func() (bool, error) {
		return containsMember(hs.PolicyGroups(t)["group:standart"], want), nil
	}); err != nil {
		t.Fatalf("group:standart never got %s: %v", want, err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("webhook reconcile took %s, want <= 5s", elapsed)
	}
}

// AC2: when a user loses their last role, their untagged nodes are expired and tagged nodes are left
// alone.
func TestE2E_LastRoleRemovedExpires(t *testing.T) {
	l := setupLab(t)
	hs := hsstack.Start(t)
	// Only role holders with a Headscale user are in the group (F3-031), so the base that makes one
	// removal a fraction (not 100%, which the protection threshold would hold) is made here.
	for range 3 {
		l.createUserWithHeadscaleUser(t, hs, "standart")
	}
	userID := l.createUserWithRole(t, "standart")

	name := "f1021-expire"
	hs.CreateUser(t, name)
	hs.SetProviderID(t, name, l.zitadelProviderID(userID))
	untagged := hs.NewNode(t, name, "untagged", "")
	tagged := hs.NewNode(t, name, "tagged", "tag:server")

	startTagcess(t, l, tagcessConfig{
		headscaleAddr: hs.GRPCAddr(),
		issuer:        l.issuer,
		keyFile:       filepath.Join(l.secrets(), "zitadel-key.json"),
		interval:      3 * time.Second,
	})

	// Let an initial reconcile put the user and the padding holders into the policy, so removing one
	// user is a fraction of the base rather than 100% (which the protection threshold would hold).
	want := l.providerID(userID)
	if err := poll(t, 20*time.Second, func() (bool, error) {
		return containsMember(hs.PolicyGroups(t)["group:standart"], want), nil
	}); err != nil {
		t.Fatalf("policy never contained %s before the role removal: %v", want, err)
	}

	l.removeGrant(t, userID)
	if err := poll(t, 15*time.Second, func() (bool, error) {
		exp := hs.NodeExpiry(t, untagged)
		return exp != nil && exp.Before(time.Now()), nil
	}); err != nil {
		t.Fatalf("untagged node was not expired: %v", err)
	}
	if exp := hs.NodeExpiry(t, tagged); exp != nil && exp.Before(time.Now()) {
		t.Errorf("tagged node was expired (%v); tagged nodes must be left alone", exp)
	}
}

// AC3: with the webhook delivery broken (target re-pointed at a closed port), the periodic reconcile
// still applies the change.
func TestE2E_PeriodicCatchesMissedWebhook(t *testing.T) {
	l := setupLab(t)
	hs := hsstack.Start(t)
	userID := l.createHeadscaleUser(t, hs)
	proc := startTagcess(t, l, tagcessConfig{
		headscaleAddr: hs.GRPCAddr(),
		issuer:        l.issuer,
		keyFile:       filepath.Join(l.secrets(), "zitadel-key.json"),
		interval:      3 * time.Second,
	})

	restore := l.setWebhookEndpoint(t, "http://"+l.tailnetIP+":1/hook")
	t.Cleanup(restore)

	l.grant(t, userID, "standart")
	want := l.providerID(userID)
	if err := poll(t, 25*time.Second, func() (bool, error) {
		return containsMember(hs.PolicyGroups(t)["group:standart"], want), nil
	}); err != nil {
		t.Fatalf("periodic reconcile never applied the missed webhook change: %v", err)
	}
	// The webhook was dead, so the applying run must carry the periodic trigger.
	if err := poll(t, 10*time.Second, func() (bool, error) {
		return proc.queryInt(t, `SELECT count(*) FROM sync_runs WHERE trigger = 'periodic' AND result = 'applied'`) > 0, nil
	}); err != nil {
		t.Errorf("change was applied without a periodic run; the webhook may not have been blocked: %v", err)
	}
}

// AC4: when Zitadel cannot be read, the previously applied groups are kept and a read-failure alert
// is raised. A healthy tagcess first applies a non-empty policy, then a grant is added; when the
// reads break, that applied policy must survive and the new grant must not be applied. The issuer
// stays reachable (discovery succeeds at startup) but tagcess's service key is invalid, so every API
// read fails; taking the shared lab Zitadel down is avoided (it is shared and quota-constrained).
func TestE2E_ZitadelDownNoChange(t *testing.T) {
	l := setupLab(t)
	hs := hsstack.Start(t)

	// Phase 1: a healthy tagcess applies a non-empty policy, so "unchanged" is asserted against a
	// state the system built itself rather than the empty baseline.
	applied := l.createHeadscaleUser(t, hs)
	healthy := startTagcess(t, l, tagcessConfig{
		headscaleAddr: hs.GRPCAddr(),
		issuer:        l.issuer,
		keyFile:       filepath.Join(l.secrets(), "zitadel-key.json"),
		interval:      5 * time.Minute, // long: only the webhook can apply within the budget
	})
	l.grant(t, applied, "standart")
	appliedWant := l.providerID(applied)
	if err := poll(t, 25*time.Second, func() (bool, error) {
		return containsMember(hs.PolicyGroups(t)["group:standart"], appliedWant), nil
	}); err != nil {
		t.Fatalf("healthy tagcess never applied a non-empty policy: %v", err)
	}
	// Stop it so the phase-2 process owns the webhook listener and the pending delta is never applied.
	healthy.stop(t)

	// A grant added now would be applied on the next read: the pending delta the outage must not apply.
	delta := l.createUserWithHeadscaleUser(t, hs, "standart")
	deltaWant := l.providerID(delta)

	before, err := hs.Client().GetPolicy(t.Context())
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if len(hsstack.ParsePolicyGroups(t, before.Text)["group:standart"]) == 0 {
		t.Fatal("policy baseline is empty; the assertion would be vacuous")
	}

	// Phase 2: tagcess starts with an unregistered service key, so every Zitadel read fails while the
	// applied Headscale policy stays in place.
	proc := startTagcess(t, l, tagcessConfig{
		headscaleAddr: hs.GRPCAddr(),
		issuer:        l.issuer,
		keyFile:       l.tamperedKeyFile(t),
		interval:      3 * time.Second,
	})

	if err := poll(t, 25*time.Second, func() (bool, error) {
		return proc.queryInt(t, `SELECT count(*) FROM alerts WHERE kind = 'reconcile_read_failed' AND source = 'zitadel' AND resolved_at IS NULL`) > 0, nil
	}); err != nil {
		t.Fatalf("no read-failure alert was raised: %v", err)
	}
	if proc.queryInt(t, `SELECT count(*) FROM sync_runs WHERE result = 'read_failed'`) == 0 {
		t.Error("no read_failed sync run was recorded")
	}
	after, err := hs.Client().GetPolicy(t.Context())
	if err != nil {
		t.Fatalf("GetPolicy after: %v", err)
	}
	if after.Text != before.Text {
		t.Errorf("policy changed while Zitadel was unreadable:\nbefore %s\nafter  %s", before.Text, after.Text)
	}
	groups := hsstack.ParsePolicyGroups(t, after.Text)["group:standart"]
	if !containsMember(groups, appliedWant) {
		t.Errorf("the applied member %s disappeared while Zitadel was unreadable", appliedWant)
	}
	if containsMember(groups, deltaWant) {
		t.Errorf("the pending grant delta %s was applied while Zitadel was unreadable", deltaWant)
	}
}

// AC5: a client that only holds `developer` cannot turn itself into `devops` with a forged
// X-Auth-Request-Groups header; Caddy strips it and denies with 403.
func TestE2E_SpoofedHeaderRejected(t *testing.T) {
	l := setupLab(t)
	secret := l.envFileValue(t, "OAUTH2_PROXY_COOKIE_SECRET")

	// Control: a real devops session reaches the upstream (the stack is healthy).
	devops := forgeSessionCookie(t, secret, []string{"devops"})
	if code := getThroughCaddy(t, devops, ""); code != http.StatusOK {
		t.Fatalf("devops session: status = %d, want 200", code)
	}
	// A developer session with a spoofed header must still be denied.
	developer := forgeSessionCookie(t, secret, []string{"developer"})
	if code := getThroughCaddy(t, developer, "devops"); code != http.StatusForbidden {
		t.Fatalf("spoofed groups header: status = %d, want 403", code)
	}
}

// AC6: removing more roles than the protection threshold allows is held for approval and nothing is
// applied.
func TestE2E_ThresholdPending(t *testing.T) {
	l := setupLab(t)
	hs := hsstack.Start(t)
	// Five users with a role and a Headscale user, made before tagcess starts: every Headscale user
	// restarts the Headscale, which would break a running tagcess's reads for a moment.
	var ids []string
	for i := 0; i < 5; i++ {
		ids = append(ids, l.createHeadscaleUser(t, hs))
	}
	// Long interval: no periodic run can apply a partial removal between the deletes.
	proc := startTagcess(t, l, tagcessConfig{
		headscaleAddr: hs.GRPCAddr(),
		issuer:        l.issuer,
		keyFile:       filepath.Join(l.secrets(), "zitadel-key.json"),
		interval:      5 * time.Minute,
	})

	// The roles are granted now, so the webhook-driven reconciles put all five into the policy.
	for _, id := range ids {
		l.grant(t, id, "standart")
	}
	for _, id := range ids {
		want := l.providerID(id)
		if err := poll(t, 25*time.Second, func() (bool, error) {
			return containsMember(hs.PolicyGroups(t)["group:standart"], want), nil
		}); err != nil {
			t.Fatalf("policy never contained %s: %v", want, err)
		}
	}

	// Block the webhook so the five removals do not trigger partial reconciles, remove them all,
	// then restore the webhook and fire one event: the single reconcile sees the whole removal.
	restore := l.setWebhookEndpoint(t, "http://"+l.tailnetIP+":1/hook")
	t.Cleanup(restore)
	for _, id := range ids {
		l.removeGrant(t, id)
	}
	// Wait until every removal is visible in Zitadel, so the single reconcile sees the whole change.
	for _, id := range ids {
		if err := poll(t, 15*time.Second, func() (bool, error) { return !l.hasGrant(t, id, "standart"), nil }); err != nil {
			t.Fatalf("grant of %s still visible in Zitadel: %v", id, err)
		}
	}
	// Record where the change log stands now: the pending change must be newer than this, so an
	// earlier applied or pending change cannot satisfy the assertion.
	beforeMax := int64(proc.queryInt(t, `SELECT COALESCE(MAX(id), 0) FROM changes`))
	restore()
	l.createUserWithRole(t, "standart")

	// The bulk removal is a new pending change whose proposed policy drops the five removed members.
	proposed := proc.pendingGroupsAfter(t, beforeMax)["group:standart"]
	for _, id := range ids {
		if containsMember(proposed, l.providerID(id)) {
			t.Errorf("pending change still lists removed user %s; the pending diff omits a removal", id)
		}
	}
	// Nothing was applied: every removed user is still in the live policy.
	live := hs.PolicyGroups(t)["group:standart"]
	for _, id := range ids {
		if !containsMember(live, l.providerID(id)) {
			t.Errorf("user %s disappeared from the live policy without approval", id)
		}
	}
}

// AC7: a real login through the lab Zitadel completes the oauth2-proxy session (the `groups` claim
// from the F1-026 Action) and the request reaches the upstream; a session without `devops` is denied.
func TestE2E_LoginThroughOAuth2Proxy(t *testing.T) {
	l := setupLab(t)

	devops := loginThroughOAuth2Proxy(t, l, "devops@tagcess.test")
	resp, err := devops.Get("http://localhost:8080/")
	if err != nil {
		t.Fatalf("GET / with the devops session: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("completed devops login: status = %d, want 200", resp.StatusCode)
	}

	developer := loginThroughOAuth2Proxy(t, l, "developer@tagcess.test")
	resp, err = developer.Get("http://localhost:8080/")
	if err != nil {
		t.Fatalf("GET / with the developer session: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("completed developer login: status = %d, want 403 (allowed_groups=devops)", resp.StatusCode)
	}
}

func containsMember(members []string, want string) bool {
	for _, m := range members {
		if m == want {
			return true
		}
	}
	return false
}

// getThroughCaddy sends a GET through the local compose Caddy with the forged session cookie and an
// optional spoofed X-Auth-Request-Groups header, without following redirects.
func getThroughCaddy(t *testing.T, cookie, spoofedGroups string) int {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://localhost:8080/", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Cookie", oauth2ProxyCookieName+"="+cookie)
	if spoofedGroups != "" {
		req.Header.Set("X-Auth-Request-Groups", spoofedGroups)
	}
	client := &http.Client{Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET Caddy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}
