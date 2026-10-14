package web

import (
	"context"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/policydoc"
	"github.com/nesiler/tagcess/internal/policyrev"
	"github.com/nesiler/tagcess/internal/policywriter"
)

// Harness of the policy history and rollback pages (F3-025, A-03, ADR 0020): the list and detail read
// the revision store; "Bu sürüme dön" loads the revision's raw text as a candidate and runs the normal
// preview and approval through the policy writer (here a fake), never a direct write.

// histRaw is the raw text of the rollback target: CRLF, a tab and a trailing comma, so a copy that
// is not byte for byte shows.
const histRaw = "// old policy\r\n{\r\n\t\"groups\": {\"group:devops\": [\"https://issuer.example/old@\"]},\r\n\t\"acls\": [{\"action\": \"accept\", \"src\": [\"group:devops\"], \"dst\": [\"tag:web:443\"],}],\r\n}\r\n"

// fakeRevisions is the revision store's read side.
type fakeRevisions struct {
	revs   []policyrev.Revision // newest first
	getErr error
	limits []int
}

func (f *fakeRevisions) List(_ context.Context, limit int) ([]policyrev.Revision, error) {
	f.limits = append(f.limits, limit)
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.revs, nil
}

func (f *fakeRevisions) Get(_ context.Context, id int64) (policyrev.Revision, error) {
	if f.getErr != nil {
		return policyrev.Revision{}, f.getErr
	}
	for _, r := range f.revs {
		if r.ID == id {
			return r, nil
		}
	}
	return policyrev.Revision{}, policyrev.ErrNotFound
}

func histRev(id int64, src policyrev.Source, status policyrev.Status, raw string) policyrev.Revision {
	return policyrev.Revision{
		ID: id, Raw: raw, RawHash: policyrev.HashRaw(raw), Source: src, Actor: fmt.Sprintf("actor%d@example.com", id),
		CreatedAt: time.Date(2026, 10, 1, 8, int(id), 0, 0, time.UTC), Reason: fmt.Sprintf("reason-%d", id),
		ApplyStatus: status, ApplyDetail: fmt.Sprintf("detail-%d", id),
	}
}

type policyHistoryHarness struct {
	t     *testing.T
	ed    *fakeEditor
	revs  *fakeRevisions
	dry   *fakeDryRunReader
	csrf  *CSRF
	chain http.Handler
}

func newPolicyHistoryHarness(t *testing.T) *policyHistoryHarness {
	t.Helper()
	h := &policyHistoryHarness{
		t:   t,
		ed:  &fakeEditor{live: policywriter.Live{Text: policyLive, BaseHash: policyrev.HashRaw(policyLive)}},
		dry: &fakeDryRunReader{},
		revs: &fakeRevisions{revs: []policyrev.Revision{
			func() policyrev.Revision {
				r := histRev(7, policyrev.SourceRollback, policyrev.StatusApplied, policyLive)
				r.RollbackOf = 2
				return r
			}(),
			histRev(6, policyrev.SourceUI, policyrev.StatusPending, policyLive),
			histRev(5, policyrev.SourceUI, policyrev.StatusUnknown, policyLive),
			histRev(4, policyrev.SourceUI, policyrev.StatusFailed, policyLive),
			histRev(3, policyrev.SourceUI, policyrev.StatusDryRun, policyLive),
			histRev(2, policyrev.SourceSync, policyrev.StatusApplied, histRaw),
			histRev(1, policyrev.SourceExternal, policyrev.StatusApplied, policyLive),
		}},
		csrf: testCSRF(t),
	}
	handler, err := NewPolicyHistoryHandler(PolicyHistoryConfig{Editor: h.ed, Revisions: h.revs, DryRun: h.dry, CSRF: h.csrf})
	if err != nil {
		t.Fatalf("NewPolicyHistoryHandler: %v", err)
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	h.chain = WithShell(nil, RequireDevops(h.csrf.Protect(mux)))
	return h
}

func (h *policyHistoryHarness) request(method, target string, form url.Values, groups string) *httptest.ResponseRecorder {
	h.t.Helper()
	body := ""
	if form != nil {
		form.Set(CSRFParam, h.csrf.Token())
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

func (h *policyHistoryHarness) get(target string) *httptest.ResponseRecorder {
	h.t.Helper()
	return h.request(http.MethodGet, target, nil, "devops")
}

func (h *policyHistoryHarness) post(target string, form url.Values) *httptest.ResponseRecorder {
	h.t.Helper()
	return h.request(http.MethodPost, target, form, "devops")
}

func rollbackForm() url.Values {
	return url.Values{"base_hash": {policyrev.HashRaw(policyLive)}}
}

// candidate is the writer's answer for a passing rollback preview.
func candidate() policywriter.SaveResult {
	text := strings.Replace(histRaw, "old@", "current@", 1)
	return policywriter.SaveResult{
		Current: policyLive, Text: text, Report: passingReport(text), GroupsRebuilt: true,
		Locked:   []policydoc.Change{{Kind: policydoc.ChangeAdded, Rule: "ui"}},
		RawDiff:  "-  \"acls\": [old]\n+  \"acls\": [new]",
		Semantic: []policywriter.SectionChange{{Section: "acls", Added: []string{`{"dst":["tag:web:443"]}`}}},
	}
}

// AC1: the list shows the revisions newest first with time, actor, source, status, reason and
// rollback_of; only applied revisions offer the rollback.
func TestPolicyHistory_List(t *testing.T) {
	h := newPolicyHistoryHarness(t)
	rec := h.get("/headscale/policy/history")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	mustContain(t, body,
		"2026-10-01 08:07:00", "actor7@example.com", "reason-7", "<code>rollback</code>", "applied",
		"<code>external</code>", "<code>sync</code>", "pending", "unknown", "failed", "dry_run",
		"revision #2 geri yüklendi",
		`href="/headscale/policy" aria-current="page"`,
	)
	// Each status is shown in the status cell of its own revision row.
	for _, rev := range h.revs.revs {
		assertPolicyHistoryStatus(t, body, rev.ID, string(rev.ApplyStatus))
	}
	// Newest first: #7 before #6 ... before #1.
	last := -1
	for id := 7; id >= 1; id-- {
		i := strings.Index(body, fmt.Sprintf(`href="/headscale/policy/history/%d"`, id))
		if i < 0 || i < last {
			t.Fatalf("revision %d is missing or out of order (at %d, previous at %d):\n%s", id, i, last, body)
		}
		last = i
	}
	// The rollback link is offered for applied revisions only.
	for id, want := range map[int]bool{7: true, 6: false, 5: false, 4: false, 3: false, 2: true, 1: true} {
		got := strings.Contains(body, fmt.Sprintf(`href="/headscale/policy/history/%d/rollback"`, id))
		if got != want {
			t.Errorf("rollback link for #%d = %v, want %v", id, got, want)
		}
	}
	if len(h.ed.saves) != 0 || len(h.ed.previews) != 0 {
		t.Error("the list wrote or previewed something")
	}

	t.Run("store unreadable", func(t *testing.T) {
		h := newPolicyHistoryHarness(t)
		h.revs.getErr = errors.New("db down")
		if rec := h.get("/headscale/policy/history"); rec.Code != http.StatusInternalServerError {
			t.Errorf("status = %d, want 500", rec.Code)
		}
	})
	t.Run("not devops", func(t *testing.T) {
		h := newPolicyHistoryHarness(t)
		if rec := h.request(http.MethodGet, "/headscale/policy/history", nil, "vpn"); rec.Code != http.StatusForbidden {
			t.Errorf("status = %d, want 403", rec.Code)
		}
	})
}

// AC2: the detail shows the raw text and the raw and semantic difference against the live policy.
func TestPolicyHistory_Detail(t *testing.T) {
	h := newPolicyHistoryHarness(t)
	rec := h.get("/headscale/policy/history/2")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	mustContain(t, body,
		// the raw text of the revision
		html.EscapeString(`"acls": [{"action": "accept", "src": ["group:devops"], "dst": ["tag:web:443"],}]`),
		// raw diff from the live policy to the revision: the live line is removed, the revision's added
		"Fark (ham metin)", html.EscapeString("+ \t\"acls\": [{\"action\": \"accept\", \"src\": [\"group:devops\"], \"dst\": [\"tag:web:443\"],}],\r"), html.EscapeString(`-   "acls": [{"action": "accept", "src": ["group:devops"], "dst": ["*:*"]}],`),
		// semantic diff
		"Fark (anlam)", "ACL kuralı",
		// the way back, with the scope note
		`href="/headscale/policy/history/2/rollback"`, "Bu sürüme dön",
		"cihaz/key/expiry/ownership dönüşümünü kapsamaz",
		"actor2@example.com", "reason-2",
	)
	if len(h.ed.saves) != 0 || len(h.ed.previews) != 0 {
		t.Error("the detail wrote or previewed something")
	}

	t.Run("a revision equal to the live policy has no difference", func(t *testing.T) {
		body := h.get("/headscale/policy/history/1").Body.String()
		mustContain(t, body, "Canlı policy ile aynı", "Anlamca değişiklik yok")
	})
	t.Run("a revision that cannot be rolled back has no link", func(t *testing.T) {
		body := h.get("/headscale/policy/history/4").Body.String()
		mustNotContain(t, body, `/headscale/policy/history/4/rollback`)
		mustContain(t, body, "yalnız apply edilmiş")
	})
	t.Run("live policy unreadable", func(t *testing.T) {
		h := newPolicyHistoryHarness(t)
		h.ed.live = policywriter.Live{HeadscaleErr: fmt.Errorf("%w: down", policywriter.ErrHeadscaleUnavailable)}
		rec := h.get("/headscale/policy/history/2")
		body := rec.Body.String()
		mustContain(t, body, "Headscale okunamıyor", html.EscapeString(`"acls": [{"action": "accept", "src": ["group:devops"], "dst": ["tag:web:443"],}]`))
		mustNotContain(t, body, "Fark (ham metin)", "Fark (anlam)")
	})
	t.Run("unknown or malformed id", func(t *testing.T) {
		for _, p := range []string{"/headscale/policy/history/99", "/headscale/policy/history/x", "/headscale/policy/history/0"} {
			if rec := h.get(p); rec.Code != http.StatusNotFound {
				t.Errorf("GET %s = %d, want 404", p, rec.Code)
			}
		}
	})
}

// AC3: "Bu sürüme dön" loads the revision's raw text, byte for byte, as the candidate and writes
// nothing: the writer is only asked to preview.
func TestPolicyRollback_CandidateNoWrite(t *testing.T) {
	h := newPolicyHistoryHarness(t)
	h.ed.previewRes = candidate()
	rec := h.get("/headscale/policy/history/2/rollback")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	if len(h.ed.saves) != 0 {
		t.Fatalf("the candidate page saved: %+v", h.ed.saves)
	}
	if len(h.ed.previews) != 1 {
		t.Fatalf("previews = %d, want 1", len(h.ed.previews))
	}
	p := h.ed.previews[0]
	if p.Text != histRaw || p.Source != policyrev.SourceRollback || p.RollbackOf != 2 || p.Actor != policyActor || p.BaseHash != policyrev.HashRaw(policyLive) {
		t.Errorf("preview request = %+v, want the revision's exact raw text, source rollback of 2, the actor and the live base hash", p)
	}
	// The candidate text is shown as it is stored (read only) next to the preview.
	mustContain(t, body, "<textarea", "readonly", html.EscapeString(`"group:devops": ["https://issuer.example/old@"]`), "revision #2")
	// The confirm form carries only the base hash: the text comes from the store on save.
	mustContain(t, body, `action="/headscale/policy/history/2/rollback"`)
	if got := hiddenValue(t, body, "base_hash"); got != policyrev.HashRaw(policyLive) {
		t.Errorf("base_hash = %q, want the live hash", got)
	}
	mustNotContain(t, body, `name="text" value=`, `name="report_hash"`)
}

// The preview call carries what the writer needs to rebuild the candidate from today's state: the
// page reports the rebuilt groups and locked tests, and shows the refusal of a failing validation
// without an approve button.
func TestPolicyRollback_PreviewShowsRebuild(t *testing.T) {
	h := newPolicyHistoryHarness(t)
	h.ed.previewRes = candidate()
	body := h.get("/headscale/policy/history/2/rollback").Body.String()
	mustContain(t, body,
		"Gruplar tagcess tarafından Zitadel'den yeniden oluşturuldu", "Kilitli testler eklendi",
		"Fark (ham metin)", "Fark (anlam)", confirmApplyLabel, `action="/headscale/policy/history/2/rollback"`,
	)

	h = newPolicyHistoryHarness(t)
	bad := candidate()
	bad.Report = policydoc.Report{Stages: []policydoc.StageResult{
		{Stage: policydoc.StageInput, State: policydoc.StatePass},
		{Stage: policydoc.StageCheck, State: policydoc.StateFail, Message: "group:ghost is not defined"},
	}}
	h.ed.previewRes = bad
	body = h.get("/headscale/policy/history/2/rollback").Body.String()
	mustContain(t, body, "Doğrulama raporu", "group:ghost is not defined")
	mustNotContain(t, body, "Onayla ve geri dön")
}

// AC5: the approval saves through the writer as a rollback of the revision: the stored raw text, the
// revision id, the actor and the base hash of the preview. The page reports the new revision.
func TestPolicyRollback_AppliesAsNewRevision(t *testing.T) {
	h := newPolicyHistoryHarness(t)
	applied := histRev(8, policyrev.SourceRollback, policyrev.StatusApplied, histRaw)
	applied.RollbackOf = 2
	h.ed.saveRes = policywriter.SaveResult{Revision: applied}
	h.ed.saveRes.Change.Applied = true
	h.ed.saveRes.Change.Revision = "gitrev1"

	rec := h.post("/headscale/policy/history/2/rollback", rollbackForm())
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}
	if len(h.ed.saves) != 1 {
		t.Fatalf("saves = %d, want 1", len(h.ed.saves))
	}
	s := h.ed.saves[0]
	if s.Text != histRaw || s.Source != policyrev.SourceRollback || s.RollbackOf != 2 || s.Actor != policyActor || s.BaseHash != policyrev.HashRaw(policyLive) {
		t.Errorf("save request = %+v, want the exact stored text as a rollback of 2 with the actor and base hash", s)
	}
	if s.Reason == "" {
		t.Error("the save carries no reason; the revision should say what it restores")
	}
	mustContain(t, rec.Body.String(), "Policy apply edildi", "#8", "gitrev1")

	t.Run("a failed outcome never says success", func(t *testing.T) {
		h := newPolicyHistoryHarness(t)
		failed := histRev(8, policyrev.SourceRollback, policyrev.StatusUnknown, histRaw)
		h.ed.saveRes = policywriter.SaveResult{Revision: failed}
		h.ed.saveErr = fmt.Errorf("%w: apply belirsiz", policywriter.ErrNotApplied)
		rec := h.post("/headscale/policy/history/2/rollback", rollbackForm())
		if rec.Code != http.StatusBadGateway {
			t.Errorf("status = %d, want 502", rec.Code)
		}
		mustNotContain(t, rec.Body.String(), "Policy apply edildi")
		mustContain(t, rec.Body.String(), "Apply belirsiz")
	})
	t.Run("no CSRF token", func(t *testing.T) {
		h := newPolicyHistoryHarness(t)
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/headscale/policy/history/2/rollback", strings.NewReader(rollbackForm().Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set(headerUser, "u")
		req.Header.Set(headerEmail, policyActor)
		req.Header.Set(headerGroups, "devops")
		rec := httptest.NewRecorder()
		h.chain.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden || len(h.ed.saves) != 0 {
			t.Errorf("status = %d, saves = %d; want 403 and no save", rec.Code, len(h.ed.saves))
		}
	})
}

// AC6: a failed, unknown, pending or dry-run revision is never a target: neither the candidate page
// nor the approval reaches the writer; an unknown id is a 404.
func TestPolicyRollback_OnlyAppliedTargets(t *testing.T) {
	for _, id := range []int{6, 5, 4, 3} {
		t.Run(fmt.Sprintf("revision %d", id), func(t *testing.T) {
			h := newPolicyHistoryHarness(t)
			path := fmt.Sprintf("/headscale/policy/history/%d/rollback", id)
			if rec := h.get(path); rec.Code != http.StatusConflict {
				t.Errorf("GET status = %d, want 409", rec.Code)
			} else {
				mustContain(t, rec.Body.String(), "yalnız apply edilmiş")
				mustNotContain(t, rec.Body.String(), "Onayla ve geri dön")
			}
			if rec := h.post(path, rollbackForm()); rec.Code != http.StatusConflict {
				t.Errorf("POST status = %d, want 409", rec.Code)
			}
			if len(h.ed.previews) != 0 || len(h.ed.saves) != 0 {
				t.Errorf("the writer was reached: previews %d, saves %d", len(h.ed.previews), len(h.ed.saves))
			}
		})
	}
	t.Run("unknown id", func(t *testing.T) {
		h := newPolicyHistoryHarness(t)
		for _, rec := range []*httptest.ResponseRecorder{
			h.get("/headscale/policy/history/99/rollback"), h.post("/headscale/policy/history/99/rollback", rollbackForm()),
		} {
			if rec.Code != http.StatusNotFound {
				t.Errorf("status = %d, want 404", rec.Code)
			}
		}
	})
	t.Run("the external baseline is a target", func(t *testing.T) {
		h := newPolicyHistoryHarness(t)
		h.ed.previewRes = candidate()
		if rec := h.get("/headscale/policy/history/1/rollback"); rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}
	})
}

// AC7: whatever stops the editor stops the rollback: Zitadel unreadable, a stale base, an uncertain
// earlier write, a sync that holds a group change, Headscale unreadable. The page says why and offers
// no approval; a refused approval writes nothing and never says success.
func TestPolicyRollback_BlockedLikeEditor(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status int
		want   string
	}{
		{"zitadel", fmt.Errorf("%w: boom", policywriter.ErrZitadelUnavailable), http.StatusServiceUnavailable, "Zitadel okunamıyor"},
		{"stale", policywriter.ErrStale, http.StatusConflict, "Policy dışarıdan değişti"},
		{"uncertain", fmt.Errorf("%w (revision #5)", policywriter.ErrUncertain), http.StatusConflict, "Önceki apply belirsiz"},
		{"sync pending", fmt.Errorf("%w: eşik", policywriter.ErrSyncPending), http.StatusConflict, "Sync sayfası"},
		{"headscale", fmt.Errorf("%w: down", policywriter.ErrHeadscaleUnavailable), http.StatusBadGateway, "Headscale okunamıyor"},
	}
	for _, tt := range tests {
		t.Run(tt.name+"/candidate", func(t *testing.T) {
			h := newPolicyHistoryHarness(t)
			h.ed.previewErr = tt.err
			rec := h.get("/headscale/policy/history/2/rollback")
			if rec.Code != tt.status {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tt.status, rec.Body)
			}
			mustContain(t, rec.Body.String(), tt.want)
			mustNotContain(t, rec.Body.String(), "Onayla ve geri dön")
		})
		t.Run(tt.name+"/approval", func(t *testing.T) {
			h := newPolicyHistoryHarness(t)
			h.ed.saveErr = tt.err
			rec := h.post("/headscale/policy/history/2/rollback", rollbackForm())
			if rec.Code != tt.status {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tt.status, rec.Body)
			}
			mustContain(t, rec.Body.String(), tt.want)
			mustNotContain(t, rec.Body.String(), "Policy apply edildi")
		})
	}
	t.Run("live policy unreadable before the preview", func(t *testing.T) {
		h := newPolicyHistoryHarness(t)
		h.ed.live = policywriter.Live{HeadscaleErr: fmt.Errorf("%w: down", policywriter.ErrHeadscaleUnavailable)}
		rec := h.get("/headscale/policy/history/2/rollback")
		if rec.Code != http.StatusBadGateway || len(h.ed.previews) != 0 {
			t.Errorf("status = %d, previews = %d; want 502 and no preview", rec.Code, len(h.ed.previews))
		}
		mustContain(t, rec.Body.String(), "Headscale okunamıyor")
	})
}

// AC8: the candidate page always carries the scope note, and shows the autoApprovers difference of
// the candidate when there is one.
func TestPolicyRollback_ShowsScopeAndAutoApprovers(t *testing.T) {
	const scope = "cihaz/key/expiry/ownership dönüşümünü kapsamaz; autoApprovers farkı varsa route onayları yeniden değerlendirilebilir"

	h := newPolicyHistoryHarness(t)
	res := candidate()
	res.Semantic = append(res.Semantic, policywriter.SectionChange{Section: "autoApprovers", Added: []string{`routes: {"10.0.0.0/24":["tag:web"]}`}})
	h.ed.previewRes = res
	body := h.get("/headscale/policy/history/2/rollback").Body.String()
	mustContain(t, body, scope, "autoApprovers değişti", "otomatik onay")

	h = newPolicyHistoryHarness(t)
	h.ed.previewRes = candidate()
	body = h.get("/headscale/policy/history/2/rollback").Body.String()
	mustContain(t, body, scope)
	mustNotContain(t, body, "autoApprovers değişti")
}
