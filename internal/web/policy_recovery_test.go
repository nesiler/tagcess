package web

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/internal/policydoc"
	"github.com/nesiler/tagcess/internal/policyrev"
	"github.com/nesiler/tagcess/internal/policywriter"
)

// Harness of the recovery page (F3-029, H-04, R2 karar 20/163): while an earlier write is unresolved,
// the page shows the candidate (the last applied revision's text with today's groups) and the fresh
// diff, and applies it only on an explicit approval through the policy writer (here a fake). The
// writer's own behaviour is tested in internal/policywriter (TestRecovery_*).

const recoveryUncertain = "revision #5 (unknown): yazılan policy doğrulanamadı"

type recoveryHarness struct {
	t     *testing.T
	ed    *fakeEditor
	csrf  *CSRF
	chain http.Handler
}

func newRecoveryHarness(t *testing.T) *recoveryHarness {
	t.Helper()
	h := &recoveryHarness{
		t: t,
		ed: &fakeEditor{live: policywriter.Live{
			Text: policyLive, BaseHash: policyrev.HashRaw(policyLive), Uncertain: recoveryUncertain,
		}},
		csrf: testCSRF(t),
	}
	handler, err := NewPolicyRecoveryHandler(PolicyRecoveryConfig{Editor: h.ed, DryRun: &fakeDryRunReader{}, CSRF: h.csrf})
	if err != nil {
		t.Fatalf("NewPolicyRecoveryHandler: %v", err)
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	h.chain = WithShell(nil, RequireDevops(h.csrf.Protect(mux)))
	return h
}

func (h *recoveryHarness) request(method, target string, form url.Values, groups string, token bool) *httptest.ResponseRecorder {
	h.t.Helper()
	body := ""
	if form != nil {
		if token {
			form.Set(CSRFParam, h.csrf.Token())
		}
		body = form.Encode()
	}
	req := httptest.NewRequestWithContext(context.Background(), method, target, strings.NewReader(body))
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set(headerUser, "devops-user")
	req.Header.Set(headerEmail, policyActor)
	req.Header.Set(headerGroups, groups)
	rec := httptest.NewRecorder()
	h.chain.ServeHTTP(rec, req)
	return rec
}

func (h *recoveryHarness) get() *httptest.ResponseRecorder {
	h.t.Helper()
	return h.request(http.MethodGet, "/headscale/policy/recovery", nil, "devops", true)
}

func (h *recoveryHarness) apply() *httptest.ResponseRecorder {
	h.t.Helper()
	return h.request(http.MethodPost, "/headscale/policy/recovery", url.Values{"base_hash": {policyrev.HashRaw(policyLive)}}, "devops", true)
}

// recoveryCandidate is the writer's answer: target #4, the candidate text and a passing report.
func recoveryCandidate() policywriter.SaveResult {
	text := "// recovered candidate\n" + policyLive
	target := histRev(4, policyrev.SourceUI, policyrev.StatusApplied, policyLive)
	return policywriter.SaveResult{
		Target: target, Current: policyLive, Text: text, Report: passingReport(text), GroupsRebuilt: true,
		Locked:   []policydoc.Change{{Kind: policydoc.ChangeAdded, Rule: "ui"}},
		RawDiff:  "-  \"live-only line\"\n+  \"candidate line\"",
		Semantic: []policywriter.SectionChange{{Section: "acls", Added: []string{`{"dst":["tag:web:443"]}`}}},
	}
}

// AC1: the page shows the target and the candidate and writes nothing: the writer is asked to preview
// a recovery, never to save.
func TestRecoveryPage_CandidateReadOnly(t *testing.T) {
	h := newRecoveryHarness(t)
	h.ed.previewRes = recoveryCandidate()
	rec := h.get()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	if len(h.ed.saves) != 0 {
		t.Fatalf("the page saved: %+v", h.ed.saves)
	}
	if len(h.ed.previews) != 1 {
		t.Fatalf("previews = %d, want 1", len(h.ed.previews))
	}
	if p := h.ed.previews[0]; p.Source != policyrev.SourceRecovery || p.Actor != policyActor || p.BaseHash != policyrev.HashRaw(policyLive) || p.Text != "" {
		t.Errorf("preview request = %+v, want a recovery by the actor on the live base, with no text of its own", p)
	}
	mustContain(t, body,
		html.EscapeString(recoveryUncertain),
		"revision #4", "<textarea", "readonly", html.EscapeString("// recovered candidate"),
		"Gruplar tagcess tarafından Zitadel'den yeniden oluşturuldu", "Kilitli testler eklendi",
		`href="/headscale/policy" aria-current="page"`,
	)
	// The approval carries only the base hash of what was shown.
	mustContain(t, body, `action="/headscale/policy/recovery"`, confirmApplyLabel)
	if got := hiddenValue(t, body, "base_hash"); got != policyrev.HashRaw(policyLive) {
		t.Errorf("base_hash = %q, want the live hash", got)
	}
	mustNotContain(t, body, `name="text"`)

	t.Run("not devops", func(t *testing.T) {
		if rec := h.request(http.MethodGet, "/headscale/policy/recovery", nil, "vpn", true); rec.Code != http.StatusForbidden {
			t.Errorf("status = %d, want 403", rec.Code)
		}
	})
}

// The page is active only while the state is uncertain: otherwise it explains that and asks the
// writer for nothing; an approval is refused.
func TestRecoveryPage_OnlyWhileUncertain(t *testing.T) {
	h := newRecoveryHarness(t)
	h.ed.live.Uncertain = ""
	rec := h.get()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}
	mustContain(t, rec.Body.String(), "belirsiz durum yok")
	mustNotContain(t, rec.Body.String(), "Onayla ve kurtar", `action="/headscale/policy/recovery"`)
	if len(h.ed.previews) != 0 || len(h.ed.saves) != 0 {
		t.Errorf("the writer was asked: previews %d, saves %d", len(h.ed.previews), len(h.ed.saves))
	}

	h.ed.saveErr = policywriter.ErrNotUncertain
	rec = h.apply()
	if rec.Code != http.StatusConflict {
		t.Errorf("approval status = %d, want 409", rec.Code)
	}
	mustContain(t, rec.Body.String(), "belirsiz durum yok")
	mustNotContain(t, rec.Body.String(), "Policy apply edildi")
}

// AC2: a candidate that does not validate is not offered for approval; the error panel shows why.
func TestRecoveryPage_RevalidatesCandidate(t *testing.T) {
	h := newRecoveryHarness(t)
	res := recoveryCandidate()
	res.Report = policydoc.Report{Stages: []policydoc.StageResult{
		{Stage: policydoc.StageInput, State: policydoc.StatePass},
		{Stage: policydoc.StageCheck, State: policydoc.StateFail, Message: "group:ghost is not defined"},
	}}
	h.ed.previewRes = res
	body := h.get().Body.String()
	mustContain(t, body, "Doğrulama raporu", "group:ghost is not defined", "apply sunulmuyor")
	mustNotContain(t, body, "Onayla ve kurtar", `action="/headscale/policy/recovery"`)

	// Headscale could not be asked: unverified is not good enough either.
	h = newRecoveryHarness(t)
	res = recoveryCandidate()
	res.Report.Stages[len(res.Report.Stages)-1] = policydoc.StageResult{Stage: policydoc.StageCheck, State: policydoc.StateUnverified, Message: "dial: refused"}
	h.ed.previewRes = res
	mustNotContain(t, h.get().Body.String(), confirmApplyLabel)
}

// AC3: the diff shown is the writer's, taken from a fresh read on every load of the page.
func TestRecoveryPage_ShowsDiffAgainstFreshLive(t *testing.T) {
	h := newRecoveryHarness(t)
	h.ed.previewRes = recoveryCandidate()
	body := h.get().Body.String()
	mustContain(t, body,
		"Fark (ham metin)", html.EscapeString(`-   "live-only line"`), html.EscapeString(`+   "candidate line"`),
		"Fark (anlam)", "ACL kuralı",
	)
	h.get()
	if len(h.ed.previews) != 2 {
		t.Errorf("previews = %d after two loads, want a fresh preview each time", len(h.ed.previews))
	}
}

// AC4: the approval applies through the writer as a recovery with the shown base hash; the page
// reports the new revision. The text is the writer's, not the form's.
func TestRecoveryPage_ApplyConfirmed(t *testing.T) {
	h := newRecoveryHarness(t)
	rev := histRev(8, policyrev.SourceRecovery, policyrev.StatusApplied, policyLive)
	rev.RollbackOf = 4
	h.ed.saveRes = policywriter.SaveResult{Revision: rev}
	h.ed.saveRes.Change.Applied = true
	h.ed.saveRes.Change.Revision = "gitrev9"

	form := url.Values{"base_hash": {policyrev.HashRaw(policyLive)}, "text": {"smuggled"}}
	rec := h.request(http.MethodPost, "/headscale/policy/recovery", form, "devops", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}
	if len(h.ed.saves) != 1 {
		t.Fatalf("saves = %d, want 1", len(h.ed.saves))
	}
	if s := h.ed.saves[0]; s.Source != policyrev.SourceRecovery || s.Actor != policyActor || s.BaseHash != policyrev.HashRaw(policyLive) || s.Text != "" {
		t.Errorf("save request = %+v, want a recovery by the actor on the shown base, with no text", s)
	}
	mustContain(t, rec.Body.String(), "Policy apply edildi", "#8", "gitrev9")

	t.Run("no CSRF token", func(t *testing.T) {
		h := newRecoveryHarness(t)
		rec := h.request(http.MethodPost, "/headscale/policy/recovery", url.Values{"base_hash": {"x"}}, "devops", false)
		if rec.Code != http.StatusForbidden || len(h.ed.saves) != 0 {
			t.Errorf("status = %d, saves = %d; want 403 and no save", rec.Code, len(h.ed.saves))
		}
	})
}

// AC6: whatever the writer cannot read blocks the recovery: the page says so, offers no approval, and
// an approval that the writer refuses writes nothing and never says success.
func TestRecoveryPage_Blocked(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status int
		want   string
	}{
		{"zitadel", fmt.Errorf("%w: boom", policywriter.ErrZitadelUnavailable), http.StatusServiceUnavailable, "Zitadel okunamıyor"},
		{"headscale", fmt.Errorf("%w: down", policywriter.ErrHeadscaleUnavailable), http.StatusBadGateway, "Headscale okunamıyor"},
		{"stale", policywriter.ErrStale, http.StatusConflict, "canlı policy değişti"},
		{"sync pending", fmt.Errorf("%w: eşik", policywriter.ErrSyncPending), http.StatusConflict, "Sync sayfası"},
		{"no target", policywriter.ErrNoRecoveryTarget, http.StatusConflict, "recovery hedefi yok"},
	}
	for _, tt := range tests {
		t.Run(tt.name+"/page", func(t *testing.T) {
			h := newRecoveryHarness(t)
			h.ed.previewErr = tt.err
			rec := h.get()
			if rec.Code != tt.status {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tt.status, rec.Body)
			}
			mustContain(t, rec.Body.String(), "Recovery bloke", tt.want)
			mustNotContain(t, rec.Body.String(), confirmApplyLabel)
		})
		t.Run(tt.name+"/approval", func(t *testing.T) {
			h := newRecoveryHarness(t)
			h.ed.saveErr = tt.err
			rec := h.apply()
			if rec.Code != tt.status {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tt.status, rec.Body)
			}
			mustContain(t, rec.Body.String(), tt.want)
			mustNotContain(t, rec.Body.String(), "Policy apply edildi")
		})
	}
	t.Run("live policy unreadable before the preview", func(t *testing.T) {
		h := newRecoveryHarness(t)
		h.ed.live = policywriter.Live{HeadscaleErr: fmt.Errorf("%w: down", policywriter.ErrHeadscaleUnavailable)}
		rec := h.get()
		if rec.Code != http.StatusBadGateway || len(h.ed.previews) != 0 {
			t.Errorf("status = %d, previews = %d; want 502 and no preview", rec.Code, len(h.ed.previews))
		}
		mustContain(t, rec.Body.String(), "Recovery bloke", "Headscale okunamıyor")
	})
}

// AC7: a recovery that fails or cannot be verified is never reported as success and is not retried by
// the page; the state stays uncertain, so the page offers a new attempt.
func TestRecoveryPage_FailureKeepsUnknown(t *testing.T) {
	for _, status := range []policyrev.Status{policyrev.StatusUnknown, policyrev.StatusFailed} {
		t.Run(string(status), func(t *testing.T) {
			h := newRecoveryHarness(t)
			h.ed.saveRes = policywriter.SaveResult{Revision: histRev(9, policyrev.SourceRecovery, status, policyLive)}
			h.ed.saveErr = fmt.Errorf("%w: yazılamadı", policywriter.ErrNotApplied)
			rec := h.apply()
			if rec.Code != http.StatusBadGateway {
				t.Errorf("status = %d, want 502", rec.Code)
			}
			mustNotContain(t, rec.Body.String(), "Policy apply edildi")
			if len(h.ed.saves) != 1 {
				t.Errorf("saves = %d, want exactly one attempt and no automatic retry", len(h.ed.saves))
			}
			// The state is still uncertain: the recovery page offers the candidate again.
			h.ed.previewRes = recoveryCandidate()
			mustContain(t, h.get().Body.String(), confirmApplyLabel, `action="/headscale/policy/recovery"`)
		})
	}
}
