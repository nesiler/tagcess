package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/site"
)

// Tests of the F2-020 screens: the version list of a site, the read-only rollback preview, and the
// approval that hands the preview's live base hash back to the pipeline (A-03, ADR 0017).

type fakeVersionReader struct {
	byID map[int64][]site.Version // newest first, like the store
	err  error
}

func (f fakeVersionReader) ListVersions(_ context.Context, id int64) ([]site.Version, error) {
	return f.byID[id], f.err
}

type fakeRollbacker struct {
	previewCalls []int64
	preview      change.RollbackPreview
	previewErr   error

	applied  []change.RollbackApproval
	applyRes change.SiteResult
	applyErr error
}

func (f *fakeRollbacker) PreviewRollback(_ context.Context, _ string, versionID int64) (change.RollbackPreview, error) {
	f.previewCalls = append(f.previewCalls, versionID)
	return f.preview, f.previewErr
}

func (f *fakeRollbacker) ApplyRollback(_ context.Context, a change.RollbackApproval) (change.SiteResult, error) {
	f.applied = append(f.applied, a)
	return f.applyRes, f.applyErr
}

type historyHarness struct {
	rb    *fakeRollbacker
	csrf  *CSRF
	chain http.Handler
}

var historyAt = time.Date(2026, 10, 1, 9, 30, 0, 0, time.UTC)

func historyVersions() map[int64][]site.Version {
	return map[int64][]site.Version{
		7: {
			{ID: 12, SiteID: 7, ChangeID: 40, Op: "update", Hosts: []string{"wiki.example.com"},
				Actor: "dev@example.com", Revision: "", CreatedAt: historyAt.Add(time.Hour)},
			{ID: 11, SiteID: 7, ChangeID: 30, Op: "add", Hosts: []string{"wiki.example.com"},
				Actor: "<script>alert(1)</script>", Revision: "0123456789abcdef0123456789abcdef01234567", CreatedAt: historyAt},
		},
	}
}

func newHistoryHarness(t *testing.T) *historyHarness {
	t.Helper()
	h := &historyHarness{rb: &fakeRollbacker{}, csrf: testCSRF(t)}
	handler, err := NewSiteHistoryHandler(SiteHistoryConfig{
		Versions: fakeVersionReader{byID: historyVersions()}, Rollback: h.rb, CSRF: h.csrf,
	})
	if err != nil {
		t.Fatalf("NewSiteHistoryHandler: %v", err)
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	h.chain = RequireDevops(h.csrf.Protect(mux))
	return h
}

func (h *historyHarness) do(t *testing.T, method, target string, form url.Values, withToken bool) *httptest.ResponseRecorder {
	t.Helper()
	if form == nil {
		form = url.Values{}
	}
	if withToken {
		form.Set(CSRFParam, h.csrf.Token())
	}
	var body *strings.Reader
	if method == http.MethodPost {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	req := httptest.NewRequestWithContext(context.Background(), method, target, body)
	req.Header.Set(headerUser, "devops-user")
	req.Header.Set(headerEmail, "devops@example.com")
	req.Header.Set(headerGroups, "devops")
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	rec := httptest.NewRecorder()
	h.chain.ServeHTTP(rec, req)
	return rec
}

func (h *historyHarness) get(t *testing.T, target string) *httptest.ResponseRecorder {
	return h.do(t, http.MethodGet, target, nil, false)
}

func (h *historyHarness) post(t *testing.T, target string, form url.Values) *httptest.ResponseRecorder {
	return h.do(t, http.MethodPost, target, form, true)
}

// AC2: every recorded version is listed and selectable, newest first; a revision that has not been
// committed yet says so; values are escaped.
func TestArtifactRollback_HistoryPage(t *testing.T) {
	h := newHistoryHarness(t)
	rec := h.get(t, "/sites/7/history")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"wiki.example.com", "dev@example.com", "2026-10-01 09:30:00", "2026-10-01 10:30:00",
		"0123456789ab", "/sites/7/history/11/rollback", "/sites/7/history/12/rollback",
		"revision bekliyor",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if strings.Contains(body, "<script>alert(1)") {
		t.Error("an actor value was not escaped")
	}
	if strings.Index(body, "/history/12/rollback") > strings.Index(body, "/history/11/rollback") {
		t.Error("versions are not listed newest first")
	}
}

func TestArtifactRollback_HistoryUnknownSite(t *testing.T) {
	h := newHistoryHarness(t)
	if rec := h.get(t, "/sites/99/history"); rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for a site without versions", rec.Code)
	}
	if rec := h.get(t, "/sites/abc/history"); rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for a bad id", rec.Code)
	}
}

// AC6: site history offers no policy Apply; the separate policy history screen
// handles policy rollback without a manual config step.
func TestArtifactRollback_PolicyDisabled(t *testing.T) {
	h := newHistoryHarness(t)
	body := h.get(t, "/sites/7/history").Body.String()
	if !strings.Contains(body, `href="/headscale/policy/history"`) || !strings.Contains(strings.ToLower(body), "policy") {
		t.Errorf("page does not link to the separate policy rollback flow")
	}
	for _, action := range formActions(body) {
		if strings.Contains(strings.ToLower(action), "policy") {
			t.Errorf("the page offers a policy action: %s", action)
		}
	}
	for _, bad := range []string{"elle ", "manuel", "kopyala", "ssh "} {
		if strings.Contains(strings.ToLower(body), bad) {
			t.Errorf("the page suggests a manual step (%q)", bad)
		}
	}
	// No policy route exists on the history handler.
	for _, target := range []string{"/policy/apply", "/headscale/policy/apply", "/sites/7/history/policy"} {
		if rec := h.post(t, target, nil); rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("POST %s = %d, want no such route", target, rec.Code)
		}
	}
}

func formActions(body string) []string {
	var out []string
	for _, part := range strings.Split(body, "<form")[1:] {
		if i := strings.Index(part, `action="`); i >= 0 {
			rest := part[i+len(`action="`):]
			out = append(out, rest[:strings.Index(rest, `"`)])
		}
	}
	return out
}

func previewFixture() change.RollbackPreview {
	return change.RollbackPreview{
		Version: site.Version{ID: 11, SiteID: 7, Op: "add", Hosts: []string{"wiki.example.com"}, Actor: "dev@example.com", CreatedAt: historyAt},
		Op:      change.SiteUpdate,
		Plan: change.SitePlan{Op: change.SiteUpdate, Hosts: []string{"wiki.example.com"},
			Diff: change.SiteDiff{Caddy: "-old <b>line</b>\n+new line"}},
		BaseHash: strings.Repeat("ab", 32),
	}
}

// AC1: the preview is read-only: GET renders the diff, the live base hash for the approval and the
// widening warning, and never applies.
func TestArtifactRollback_PreviewPage(t *testing.T) {
	h := newHistoryHarness(t)
	h.rb.preview = previewFixture()
	rec := h.get(t, "/sites/7/history/11/rollback")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if len(h.rb.previewCalls) != 1 || h.rb.previewCalls[0] != 11 {
		t.Errorf("preview calls = %v", h.rb.previewCalls)
	}
	if len(h.rb.applied) != 0 {
		t.Error("a GET applied the rollback")
	}
	for _, want := range []string{
		"+new line", "&lt;b&gt;line&lt;/b&gt;", `name="base_hash" value="` + strings.Repeat("ab", 32) + `"`,
		`method="post"`, `action="/sites/7/history/11/rollback"`, `name="csrf_token"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("preview lacks %q", want)
		}
	}
	if strings.Contains(body, "<b>line</b>") {
		t.Error("a diff line was not escaped")
	}
	if strings.Contains(body, "ack_widen") {
		t.Error("the acknowledgement is asked for although the rollback does not widen access")
	}
}

func TestArtifactRollback_PreviewWidenAndNoChange(t *testing.T) {
	h := newHistoryHarness(t)
	p := previewFixture()
	p.Widens = []string{"yeni roller erişebilecek: developer"}
	h.rb.preview = p
	body := h.get(t, "/sites/7/history/11/rollback").Body.String()
	if !strings.Contains(body, "yeni roller erişebilecek: developer") || !strings.Contains(body, `name="ack_widen"`) {
		t.Errorf("a widening rollback must show its reasons and ask for the acknowledgement")
	}

	p.Widens = nil
	p.NoChange = true
	h.rb.preview = p
	body = h.get(t, "/sites/7/history/11/rollback").Body.String()
	if strings.Contains(body, `method="post"`) {
		t.Error("a no-change rollback offers an approval form")
	}
}

func TestArtifactRollback_PreviewErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"locked system site", site.ErrSystemLocked, http.StatusConflict},
		{"no such version", site.ErrNotFound, http.StatusNotFound},
		{"already in the version", change.ErrRollbackNoChange, http.StatusConflict},
		{"anything else", errors.New("validation: role x unknown"), http.StatusUnprocessableEntity},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHistoryHarness(t)
			h.rb.previewErr = tt.err
			rec := h.get(t, "/sites/7/history/11/rollback")
			if rec.Code != tt.want {
				t.Errorf("status = %d, want %d", rec.Code, tt.want)
			}
			if len(h.rb.applied) != 0 {
				t.Error("a failed preview applied something")
			}
		})
	}
	// A version of another site is not this site's.
	h := newHistoryHarness(t)
	if rec := h.get(t, "/sites/8/history/11/rollback"); rec.Code != http.StatusNotFound {
		t.Errorf("status for another site's version = %d, want 404", rec.Code)
	}
}

// AC3 (handler side): the approval needs the CSRF token, carries the actor, the version, the live
// base hash of the preview and the acknowledgement to the pipeline, and shows the revision.
func TestArtifactRollback_ApproveHandler(t *testing.T) {
	h := newHistoryHarness(t)
	h.rb.applyRes = change.SiteResult{Result: change.Result{ChangeID: 41, Status: change.StatusApplied, Applied: true, Revision: "0123456789abcdef0123456789abcdef01234567"}}

	form := url.Values{"base_hash": {strings.Repeat("cd", 32)}, "ack_widen": {"1"}}
	if rec := h.do(t, http.MethodPost, "/sites/7/history/11/rollback", form, false); rec.Code != http.StatusForbidden {
		t.Fatalf("POST without a CSRF token = %d, want 403", rec.Code)
	}
	if len(h.rb.applied) != 0 {
		t.Fatal("a request without a token reached the pipeline")
	}

	rec := h.post(t, "/sites/7/history/11/rollback", form)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if len(h.rb.applied) != 1 {
		t.Fatalf("approvals = %d, want 1", len(h.rb.applied))
	}
	got := h.rb.applied[0]
	if got.Actor != "devops@example.com" || got.VersionID != 11 || got.BaseHash != strings.Repeat("cd", 32) || !got.AcknowledgeWiden {
		t.Errorf("approval = %+v", got)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "0123456789ab") || !strings.Contains(body, "apply edildi") {
		t.Errorf("result page lacks the outcome and the revision")
	}

	// Without the acknowledgement field it is false.
	h.post(t, "/sites/7/history/11/rollback", url.Values{"base_hash": {"x"}})
	if h.rb.applied[1].AcknowledgeWiden {
		t.Error("the acknowledgement was assumed")
	}
}

func TestArtifactRollback_ApproveOutcomes(t *testing.T) {
	tests := []struct {
		name string
		res  change.SiteResult
		err  error
		want int
		text string
	}{
		{"stale", change.SiteResult{}, change.ErrRollbackStale, http.StatusConflict, "değişti"},
		{"widens", change.SiteResult{}, change.ErrRollbackWidens, http.StatusConflict, "genişlet"},
		{"no change", change.SiteResult{}, change.ErrRollbackNoChange, http.StatusConflict, "zaten"},
		{"system lock", change.SiteResult{}, site.ErrSystemLocked, http.StatusConflict, "kilitli"},
		{"blocked", change.SiteResult{Result: change.Result{Status: change.StatusBlocked}}, nil, http.StatusConflict, "apply edilmedi"},
		{"failed", change.SiteResult{Result: change.Result{ChangeID: 3, Status: change.StatusFailed}}, nil, http.StatusBadGateway, "başarısız"},
		{"dry run", change.SiteResult{Result: change.Result{Status: change.StatusDryRun}}, nil, http.StatusOK, "Kuru çalışma"},
		{"git failed", change.SiteResult{Result: change.Result{ChangeID: 4, Status: change.StatusApplied, Applied: true, GitFailed: true}}, nil, http.StatusOK, "revision bekliyor"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHistoryHarness(t)
			h.rb.applyRes, h.rb.applyErr = tt.res, tt.err
			rec := h.post(t, "/sites/7/history/11/rollback", url.Values{"base_hash": {"h"}})
			if rec.Code != tt.want {
				t.Errorf("status = %d, want %d", rec.Code, tt.want)
			}
			if !strings.Contains(rec.Body.String(), tt.text) {
				t.Errorf("page lacks %q:\n%s", tt.text, rec.Body.String())
			}
		})
	}
	// A version of another site never reaches the pipeline.
	h := newHistoryHarness(t)
	if rec := h.post(t, "/sites/8/history/11/rollback", url.Values{"base_hash": {"h"}}); rec.Code != http.StatusNotFound {
		t.Errorf("status for another site's version = %d, want 404", rec.Code)
	}
	if len(h.rb.applied) != 0 {
		t.Error("another site's version reached the pipeline")
	}
}

// AC2 (entry point): every row of the site list links to the site's history.
func TestSitesPage_LinksToHistory(t *testing.T) {
	sites := []site.Site{{ID: 7, Hosts: []string{"wiki.example.com"}, Kind: site.KindRole, TargetKind: site.TargetK8s}}
	body := getSites(t, newSitesHarness(t, fakeSiteLister{sites: sites}, nil), "/sites")
	if !strings.Contains(rowContaining(t, body, "wiki.example.com"), `href="/sites/7/history"`) {
		t.Error("the site row has no link to its history")
	}
}
