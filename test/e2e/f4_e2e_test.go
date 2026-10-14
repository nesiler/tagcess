//go:build integration

package e2e_test

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// F4-035 scenarios against the personal k3s lab (run with `make f4-e2e`).

// roleSitesOf returns the Caddyfile blocks of the seeded multi-host sites and their host grouping.
func (s *f4Stack) multiHostState() map[string]string {
	s.t.Helper()
	disk := s.snapshot().caddyfile
	out := map[string]string{}
	for _, h := range []string{"projects-auth.example.com", "store-staging.internal.example.org"} {
		out[h] = blockOf(disk, h)
		if out[h] == "" {
			// A multi-host block starts with the first host followed by ",\n<second host> {".
			if i := strings.Index(disk, h+",\n"); i >= 0 {
				rest := disk[i:]
				if end := strings.Index(rest, "\n}\n"); end >= 0 {
					out[h] = rest[:end+3]
				}
			}
		}
		if out[h] == "" {
			s.t.Fatalf("the seeded multi-host site of %s is not in the Caddyfile", h)
		}
	}
	return out
}

// TestF4_E2E_DiscoverAndResumeDraft is F4-035 AC1: connect through the UI, discover the real Ingress,
// save an incomplete draft, reopen it, and see that nothing but the draft store changed.
func TestF4_E2E_DiscoverAndResumeDraft(t *testing.T) {
	s := newF4Stack(t)
	base := s.snapshot()
	s.connect(f4Upstream)

	body := s.waitPage("/k8s/discovery", "the lab host in the discovery", func(b string) bool { return strings.Contains(b, f4Host) })
	if !strings.Contains(body, s.rt.Namespace) {
		t.Errorf("the discovery does not show the lab namespace %s: %s", s.rt.Namespace, excerpt(body))
	}
	s.assertUnchanged(base, "after the discovery")

	// An incomplete draft: roles are still missing. Saving stores only the draft.
	code, body := s.ui.post(draftPath(""), map[string][]string{"access_choice": {""}, "note": {"half done"}})
	if code != http.StatusOK {
		t.Fatalf("save the incomplete draft: status %d: %s", code, excerpt(body))
	}
	s.assertUnchanged(base, "after saving the incomplete draft")

	// Reopen with a fresh client: the draft is still there, incomplete, with its note.
	fresh := newUIClient(t, s.proc.uiSock)
	code, body = fresh.get(draftPath(""))
	if code != http.StatusOK || !strings.Contains(body, "half done") {
		t.Fatalf("the reopened draft lost its note (status %d): %s", code, excerpt(body))
	}
	if n := s.proc.queryInt(t, `SELECT count(*) FROM audit_events WHERE event = 'k8s.draft.save' AND result = 'applied'`); n < 1 {
		t.Errorf("the draft save is not in the audit log")
	}

	// Review is refused for an incomplete draft and writes nothing.
	if code, body = s.ui.post(draftPath("/review"), nil); code == http.StatusOK {
		t.Fatalf("an incomplete draft reached the review: %s", excerpt(body))
	}
	s.assertUnchanged(base, "after the refused review")
}

// TestF4_E2E_DraftApplyUsesExistingWorkflow is F4-035 AC2: a role draft on the k8s upstream passes the
// S-04 preview and is applied (Caddy, DNS, owned redirect URI), the seeded multi-host sites are not
// split, and a draft whose listener is not the k8s upstream is refused instead of rewritten.
func TestF4_E2E_DraftApplyUsesExistingWorkflow(t *testing.T) {
	s := newF4Stack(t)
	base := s.snapshot()
	multi := s.multiHostState()

	// Negative control: another listener. A role site renders only with the fixed k8s upstream, so the
	// draft is "not ready" with the reason shown; nothing is rewritten and nothing is written.
	s.connect("100.64.0.7")
	s.waitPage(draftPath(""), "the draft on the other listener", func(b string) bool { return strings.Contains(b, "100.64.0.7") })
	s.saveDraft("devops")
	code, body := s.ui.post(draftPath("/review"), nil)
	if code != http.StatusConflict || !strings.Contains(body, "yalnız") {
		t.Fatalf("a role draft on another listener: status %d, want 409 with the reason: %s", code, excerpt(body))
	}
	s.assertUnchanged(base, "after the refused review")

	// The declared listener is the k8s upstream: refresh the source and review again.
	s.saveProfile(f4Upstream)
	var review siteReview
	deadline := time.Now().Add(90 * time.Second)
	for {
		if code, _ := s.ui.post(draftPath("/refresh"), nil); code == http.StatusOK || code == http.StatusSeeOther {
			review = s.ui.review(draftPath("/review"), nil)
			if review.approvable() {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the draft never reached an approvable review (status %d): %s", review.code, excerpt(review.body))
		}
		time.Sleep(3 * time.Second)
	}
	if !strings.Contains(review.diffs["Caddy"], f4Host) || !strings.Contains(review.diffs["DNS"], f4Host) ||
		!strings.Contains(review.diffs["Zitadel"], callbackOf(f4Host)) {
		t.Errorf("the review lacks one of the three artifact diffs: %v", review.diffs)
	}
	s.assertUnchanged(base, "after the preview")

	res := s.ui.approve(review)
	if !res.applied || res.changeStatus != "applied" {
		t.Fatalf("the draft was not applied (status %d, change %q): %s", res.code, res.changeStatus, excerpt(res.body))
	}
	s.assertSite(f4Host, true)
	if !strings.Contains(blockOf(s.snapshot().caddyfile, f4Host), "import vpn_site") {
		t.Errorf("the new site is not a role site:\n%s", blockOf(s.snapshot().caddyfile, f4Host))
	}
	if got := s.multiHostState(); !sameMap(got, multi) {
		t.Errorf("a seeded multi-host site changed:\nbefore %v\nafter  %v", multi, got)
	}
	var split int
	for _, h := range []string{"projects-auth.example.com", "storage-api.example.com"} {
		if s.siteID(h) == 0 {
			t.Errorf("host %s lost its site", h)
		}
	}
	if a, b := s.siteID("projects-auth.example.com"), s.siteID("storage-api.example.com"); a != b {
		split++
	}
	if split != 0 {
		t.Error("the seeded multi-host site projects-auth/storage-api was split")
	}
	if got := s.siteCount(); got != base.sites+1 {
		t.Errorf("site count = %d, want %d (one new site)", got, base.sites+1)
	}
	if n := s.auditCount("site.approve", "applied"); n < 1 {
		t.Error("no site.approve audit event: the apply did not go through the S-04 pipeline")
	}
}

func sameMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
