package web

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/policydoc"
	"github.com/nesiler/tagcess/internal/policyrev"
	"github.com/nesiler/tagcess/internal/policywriter"
)

// Harness of the policy editor page (F3-019, H-04): a plain textarea, the server-side validation
// report, the raw and semantic diff and the confirm step. The handler is driven over a fake editor
// (the policywriter surface), so every refusal the writer can give is reachable.

const (
	policyActor = "devops@example.com"
	policyLive  = "// everyone reaches the gate\n{\n  \"groups\": {\"group:devops\": [\"https://issuer.example/u1@\"]},\n  \"acls\": [{\"action\": \"accept\", \"src\": [\"group:devops\"], \"dst\": [\"*:*\"]}],\n}\n"
)

// fakeEditor records what the handler sends and answers with the configured results.
type fakeEditor struct {
	mu   sync.Mutex
	live policywriter.Live

	liveErr    error
	previewRes policywriter.SaveResult
	previewErr error
	saveRes    policywriter.SaveResult
	saveErr    error

	previews []policywriter.SaveRequest
	saves    []policywriter.SaveRequest
}

func (f *fakeEditor) Live(context.Context) (policywriter.Live, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.live, f.liveErr
}

func (f *fakeEditor) Preview(_ context.Context, req policywriter.SaveRequest) (policywriter.SaveResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.previews = append(f.previews, req)
	return f.previewRes, f.previewErr
}

func (f *fakeEditor) Save(_ context.Context, req policywriter.SaveRequest) (policywriter.SaveResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.saves = append(f.saves, req)
	return f.saveRes, f.saveErr
}

type policyHarness struct {
	t     *testing.T
	ed    *fakeEditor
	dry   *fakeDryRunReader
	csrf  *CSRF
	chain http.Handler
	nodes *fakeAdminNodes    // tag-form collaborator (F3-024); nil keeps the tag card hidden
	prot  *fakeProtectedTags // tag-form collaborator (F3-024)
}

func newPolicyHarness(t *testing.T) *policyHarness {
	t.Helper()
	h := &policyHarness{
		t:    t,
		ed:   &fakeEditor{live: policywriter.Live{Text: policyLive, BaseHash: policyrev.HashRaw(policyLive)}},
		dry:  &fakeDryRunReader{},
		csrf: testCSRF(t),
	}
	handler, err := NewPolicyHandler(PolicyHandlerConfig{Editor: h.ed, DryRun: h.dry, CSRF: h.csrf})
	if err != nil {
		t.Fatalf("NewPolicyHandler: %v", err)
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	h.chain = WithShell(nil, RequireDevops(h.csrf.Protect(mux)))
	return h
}

// request sends one request as a devops identity; token false leaves the CSRF token out.
func (h *policyHarness) request(method, target string, form url.Values, groups string, token bool) *httptest.ResponseRecorder {
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

func (h *policyHarness) get(target string) *httptest.ResponseRecorder {
	h.t.Helper()
	return h.request(http.MethodGet, target, nil, "devops", true)
}

func (h *policyHarness) post(target string, form url.Values) *httptest.ResponseRecorder {
	h.t.Helper()
	return h.request(http.MethodPost, target, form, "devops", true)
}

// editForm is the editor form as the browser sends it: the text and the base hash it was loaded with.
func editForm(text string) url.Values {
	return url.Values{"text": {text}, "base_hash": {policyrev.HashRaw(policyLive)}}
}

// saveForm is the confirm form of a preview: the previewed text and the hash that binds the report to it.
func saveForm(text string) url.Values {
	f := editForm(text)
	f.Set("report_hash", policyrev.HashRaw(text))
	return f
}

func passingReport(text string) policydoc.Report {
	rep := policydoc.Report{Hash: policyrev.HashRaw(text)}
	for _, s := range []policydoc.Stage{policydoc.StageInput, policydoc.StageSyntax, policydoc.StageStructure, policydoc.StageLocked, policydoc.StageCheck} {
		rep.Stages = append(rep.Stages, policydoc.StageResult{Stage: s, State: policydoc.StatePass})
	}
	return rep
}

func mustContain(t *testing.T, body string, wants ...string) {
	t.Helper()
	// Text may be given escaped or as the reader sees it: the apostrophe of "tag'ler" renders as &#39;.
	text := html.UnescapeString(body)
	for _, w := range wants {
		if !strings.Contains(body, w) && !strings.Contains(text, w) {
			t.Errorf("body misses %q:\n%s", w, body)
		}
	}
}

func mustNotContain(t *testing.T, body string, nots ...string) {
	t.Helper()
	for _, n := range nots {
		if strings.Contains(body, n) {
			t.Errorf("body has %q:\n%s", n, body)
		}
	}
}

// AC1: the live policy is the textarea's content as raw text, the base hash rides in a form field and
// the groups section is shown read-only with the note that Zitadel owns it.
func TestPolicyPage_ShowsRawAndBase(t *testing.T) {
	h := newPolicyHarness(t)
	rec := h.get("/headscale/policy")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	mustContain(t, body,
		"<textarea",
		html.EscapeString("// everyone reaches the gate"),
		html.EscapeString(`"acls": [{"action": "accept"`),
		html.EscapeString("Zitadel rollerinden gelir ve kayıtta yeniden oluşturulur"),
		html.EscapeString(`"group:devops": ["https://issuer.example/u1@"]`),
	)
	if got := hiddenValue(t, body, "base_hash"); got != policyrev.HashRaw(policyLive) {
		t.Errorf("base_hash = %q, want the live text's hash", got)
	}
	mustContain(t, body, `action="/headscale/policy/preview"`)
	mustNotContain(t, body, "düzenleme kapalı", "readonly")
}

// AC11: the page shows the section's screens with ACL marked (the sidebar).
func TestPolicyPage_ShowsTabs(t *testing.T) {
	h := newPolicyHarness(t)
	body := h.get("/headscale/policy").Body.String()
	mustContain(t, body, `href="/headscale/policy" aria-current="page"`)
	for _, tab := range headscaleTabs {
		mustContain(t, body, `href="`+tab.Href+`"`)
	}

	h.dry.on = true
	mustContain(t, h.get("/headscale/policy").Body.String(), dryRunNote)
}

// AC2: the preview shows each validation stage with its own state; a Headscale rejection is shown
// verbatim and a line number only when the parser gave one.
func TestPolicyPage_PreviewErrorPanel(t *testing.T) {
	text := "{ \"acls\": [ }"
	tests := []struct {
		name    string
		stages  []policydoc.StageResult
		want    []string
		notWant []string
	}{
		{
			name: "syntax error with a parser position",
			stages: []policydoc.StageResult{
				{Stage: policydoc.StageInput, State: policydoc.StatePass},
				{Stage: policydoc.StageSyntax, State: policydoc.StateFail, Message: "unexpected token '}'", Line: 3, Column: 7},
				{Stage: policydoc.StageStructure, State: policydoc.StateSkipped},
				{Stage: policydoc.StageLocked, State: policydoc.StateSkipped},
				{Stage: policydoc.StageCheck, State: policydoc.StateSkipped},
			},
			want:    []string{"Sözdizimi", "hata", "unexpected token &#39;}&#39;", "satır 3, sütun 7", "geçti"},
			notWant: []string{"satır 0"},
		},
		{
			name: "Headscale rejects: its message verbatim, no invented line",
			stages: []policydoc.StageResult{
				{Stage: policydoc.StageInput, State: policydoc.StatePass},
				{Stage: policydoc.StageSyntax, State: policydoc.StatePass},
				{Stage: policydoc.StageStructure, State: policydoc.StatePass},
				{Stage: policydoc.StageLocked, State: policydoc.StatePass},
				{Stage: policydoc.StageCheck, State: policydoc.StateFail, Message: `policy: group "group:ghost" is not defined`},
			},
			want:    []string{"Headscale", html.EscapeString(`policy: group "group:ghost" is not defined`), "hata"},
			notWant: []string{"satır", "sütun"},
		},
		{
			name: "Headscale could not be asked: unverified, not an error",
			stages: []policydoc.StageResult{
				{Stage: policydoc.StageInput, State: policydoc.StatePass},
				{Stage: policydoc.StageSyntax, State: policydoc.StatePass},
				{Stage: policydoc.StageStructure, State: policydoc.StatePass},
				{Stage: policydoc.StageLocked, State: policydoc.StatePass},
				{Stage: policydoc.StageCheck, State: policydoc.StateUnverified, Message: "dial unix: connection refused"},
			},
			want:    []string{"doğrulanamadı", "connection refused"},
			notWant: []string{"satır"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newPolicyHarness(t)
			h.ed.previewRes = policywriter.SaveResult{
				Current: policyLive, Text: text,
				Report: policydoc.Report{Hash: policyrev.HashRaw(text), Stages: tt.stages},
			}
			rec := h.post("/headscale/policy/preview", editForm(text))
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d: %s", rec.Code, rec.Body)
			}
			body := rec.Body.String()
			mustContain(t, body, tt.want...)
			mustNotContain(t, body, tt.notWant...)
			// An invalid or unverified text cannot be saved: no confirm form.
			mustNotContain(t, body, `action="/headscale/policy/save"`)
			// The editor keeps the user's text.
			mustContain(t, body, html.EscapeString(text))
		})
	}
}

// AC3: a passing preview shows both diffs, the groups-rebuilt and locked-tests notices, and the confirm
// form that carries the text and the report hash.
func TestPolicyPage_PreviewDiffs(t *testing.T) {
	h := newPolicyHarness(t)
	text := strings.Replace(policyLive, `"dst": ["*:*"]`, `"dst": ["tag:web:443"]`, 1)
	h.ed.previewRes = policywriter.SaveResult{
		Current: policyLive, Text: text, Report: passingReport(text),
		GroupsRebuilt: true,
		Locked:        []policydoc.Change{{Kind: policydoc.ChangeAdded, Rule: "ui"}},
		RawDiff:       "-  \"acls\": [{\"dst\": [\"*:*\"]}]\n+  \"acls\": [{\"dst\": [\"tag:web:443\"]}]",
		Semantic: []policywriter.SectionChange{
			{Section: "acls", Added: []string{`{"dst":["tag:web:443"]}`}, Removed: []string{`{"dst":["*:*"]}`}},
			{Section: "autoApprovers", Added: []string{`routes: {"10.0.0.0/24":["tag:web"]}`}},
			{Section: "tagOwners", Added: []string{`tag:web: ["group:devops"]`}, Removed: []string{`tag:web: ["group:old"]`}},
		},
	}
	// The browser submits the textarea with CRLF line ends; the writer must get LF.
	form := editForm(strings.ReplaceAll(text, "\n", "\r\n"))
	rec := h.post("/headscale/policy/preview", form)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}
	body := rec.Body.String()

	if len(h.ed.previews) != 1 || h.ed.previews[0].Text != text || h.ed.previews[0].BaseHash != policyrev.HashRaw(policyLive) || h.ed.previews[0].Actor != policyActor {
		t.Fatalf("previews = %+v, want the LF text, the base hash and the actor", h.ed.previews)
	}
	if len(h.ed.saves) != 0 {
		t.Error("a preview saved")
	}
	mustContain(t, body,
		// raw diff, added and removed lines apart
		html.EscapeString(`+   "acls": [{"dst": ["tag:web:443"]}]`), html.EscapeString(`-   "acls": [{"dst": ["*:*"]}]`),
		// semantic diff: added, removed and changed entries
		"ACL kuralı", html.EscapeString(`{"dst":["tag:web:443"]}`), "eklenen", "silinen",
		"tag owner'ları", "değişen", html.EscapeString(`["group:old"]`), html.EscapeString(`["group:devops"]`),
		// notices
		"Gruplar tagcess tarafından Zitadel'den yeniden oluşturuldu", "Kilitli testler eklendi",
		// autoApprovers side effect is noted separately
		"autoApprovers", "otomatik onay",
		// the diff is not an access proof
		"erişim etkisinin kanıtı değildir",
	)
	// The confirm form binds the report to the previewed text.
	mustContain(t, body, `action="/headscale/policy/save"`)
	if got := hiddenValue(t, body, "report_hash"); got != policyrev.HashRaw(text) {
		t.Errorf("report_hash = %q, want the previewed text's hash", got)
	}
	if got := hiddenValue(t, body, "base_hash"); got != policyrev.HashRaw(policyLive) {
		t.Errorf("base_hash = %q, want the loaded base", got)
	}
}

// AC4: a save whose report hash is not the posted text's hash (an old preview, an edited text) never
// reaches the writer.
func TestPolicyPage_SaveRequiresMatchingPreview(t *testing.T) {
	text := strings.Replace(policyLive, "everyone reaches the gate", "edited", 1)

	t.Run("hash of an earlier text", func(t *testing.T) {
		h := newPolicyHarness(t)
		form := saveForm(text)
		form.Set("report_hash", policyrev.HashRaw(policyLive))
		rec := h.post("/headscale/policy/save", form)
		if rec.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409: %s", rec.Code, rec.Body)
		}
		mustContain(t, rec.Body.String(), "Preview bu metne ait değil")
		if len(h.ed.saves) != 0 {
			t.Errorf("saves = %d, want none", len(h.ed.saves))
		}
	})
	t.Run("no hash", func(t *testing.T) {
		h := newPolicyHarness(t)
		rec := h.post("/headscale/policy/save", editForm(text))
		if rec.Code != http.StatusConflict || len(h.ed.saves) != 0 {
			t.Errorf("status = %d, saves = %d, want 409 and none", rec.Code, len(h.ed.saves))
		}
	})
	t.Run("text edited after the preview", func(t *testing.T) {
		h := newPolicyHarness(t)
		form := saveForm(text)
		form.Set("text", text+"// sneaked in\n")
		rec := h.post("/headscale/policy/save", form)
		if rec.Code != http.StatusConflict || len(h.ed.saves) != 0 {
			t.Errorf("status = %d, saves = %d, want 409 and none", rec.Code, len(h.ed.saves))
		}
	})
	t.Run("matching hash saves exactly the previewed text", func(t *testing.T) {
		h := newPolicyHarness(t)
		h.ed.saveRes = policywriter.SaveResult{
			Revision: policyrev.Revision{ID: 4, ApplyStatus: policyrev.StatusApplied},
			Change:   change.Result{Applied: true, Status: change.StatusApplied},
		}
		// The browser re-posts the hidden text with CRLF; the hash was made over the LF text.
		form := saveForm(text)
		form.Set("text", strings.ReplaceAll(text, "\n", "\r\n"))
		rec := h.post("/headscale/policy/save", form)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", rec.Code, rec.Body)
		}
		if len(h.ed.saves) != 1 || h.ed.saves[0].Text != text || h.ed.saves[0].BaseHash != policyrev.HashRaw(policyLive) || h.ed.saves[0].Actor != policyActor {
			t.Errorf("saves = %+v, want one save of the LF text with the base hash and the actor", h.ed.saves)
		}
	})
}

// AC5: while Zitadel cannot be read the page opens read-only with the closed-editing banner, and a
// save POST is refused whatever the form says.
func TestPolicyPage_ZitadelDownBlocksSave(t *testing.T) {
	h := newPolicyHarness(t)
	h.ed.live.ZitadelErr = fmt.Errorf("%w: connection refused", policywriter.ErrZitadelUnavailable)

	rec := h.get("/headscale/policy")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	mustContain(t, body, "Zitadel okunamıyor: düzenleme kapalı", "readonly", html.EscapeString("// everyone reaches the gate"))
	mustNotContain(t, body, `action="/headscale/policy/preview"`, `action="/headscale/policy/save"`)

	h.ed.saveErr = fmt.Errorf("%w: connection refused", policywriter.ErrZitadelUnavailable)
	for _, target := range []string{"/headscale/policy/save", "/headscale/policy/preview"} {
		h.ed.previewErr = h.ed.saveErr
		rec = h.post(target, saveForm(policyLive))
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s: status = %d, want 503: %s", target, rec.Code, rec.Body)
		}
		mustContain(t, rec.Body.String(), "düzenleme kapalı")
		mustNotContain(t, rec.Body.String(), "Policy apply edildi")
	}
}

// Headscale unreadable: no text, no editor, an error.
func TestPolicyPage_HeadscaleDown(t *testing.T) {
	h := newPolicyHarness(t)
	h.ed.live = policywriter.Live{HeadscaleErr: fmt.Errorf("%w: socket closed", policywriter.ErrHeadscaleUnavailable)}
	rec := h.get("/headscale/policy")
	body := rec.Body.String()
	mustContain(t, body, "Headscale okunamıyor", "socket closed")
	mustNotContain(t, body, "<textarea", `action="/headscale/policy/preview"`)
}

// A preview or save refused because Headscale cannot be read keeps the typed text in a read-only
// textarea, so nothing the operator typed is lost; the editable form stays hidden.
func TestPolicyPage_HeadscaleDownKeepsTypedText(t *testing.T) {
	text := strings.Replace(policyLive, "everyone reaches the gate", "my typed edit", 1)
	hsErr := fmt.Errorf("%w: socket closed", policywriter.ErrHeadscaleUnavailable)
	for _, path := range []string{"/headscale/policy/preview", "/headscale/policy/save"} {
		t.Run(path, func(t *testing.T) {
			h := newPolicyHarness(t)
			h.ed.previewErr, h.ed.saveErr = hsErr, hsErr
			form := saveForm(text)
			rec := h.post(path, form)
			if rec.Code != http.StatusBadGateway {
				t.Fatalf("status = %d, want 502: %s", rec.Code, rec.Body)
			}
			body := rec.Body.String()
			mustContain(t, body, "Headscale okunamıyor", "my typed edit", "<textarea", "readonly")
			mustNotContain(t, body, `action="/headscale/policy/preview"`)
		})
	}
}

// AC6: a base hash that is no longer the live policy's is a 409 with the "changed outside" band and a
// reload link; the user's text stays visible and nothing is saved.
func TestPolicyPage_StaleBase(t *testing.T) {
	text := strings.Replace(policyLive, "everyone reaches the gate", "my edit", 1)
	for _, target := range []string{"/headscale/policy/preview", "/headscale/policy/save"} {
		t.Run(target, func(t *testing.T) {
			h := newPolicyHarness(t)
			h.ed.previewErr = policywriter.ErrStale
			h.ed.saveErr = policywriter.ErrStale
			h.ed.previewRes.Current = "changed elsewhere"
			rec := h.post(target, saveForm(text))
			if rec.Code != http.StatusConflict {
				t.Fatalf("status = %d, want 409: %s", rec.Code, rec.Body)
			}
			body := rec.Body.String()
			mustContain(t, body, "Policy dışarıdan değişti", `href="/headscale/policy"`, "yeniden yükle", html.EscapeString("my edit"))
			mustNotContain(t, body, `action="/headscale/policy/save"`, "Policy apply edildi")
		})
	}
}

// AC7: an unresolved earlier write shows a persistent banner with the detail, a re-validation link and
// the link to the recovery page; saving is closed. The re-validation reports a fresh read's result.
func TestPolicyPage_UnknownStateBanner(t *testing.T) {
	h := newPolicyHarness(t)
	h.ed.live.Uncertain = "revision #7 (unknown): geri okuma uyuşmadı"

	body := h.get("/headscale/policy").Body.String()
	mustContain(t, body,
		"Önceki apply belirsiz", "revision #7 (unknown): geri okuma uyuşmadı",
		`href="/headscale/policy/revalidate"`, "yeniden doğrula",
		`href="/headscale/policy/recovery"`, "Kontrollü recovery",
	)
	mustNotContain(t, body, `action="/headscale/policy/preview"`, `action="/headscale/policy/save"`)

	// Re-validation reads fresh: still unresolved.
	body = h.get("/headscale/policy/revalidate").Body.String()
	mustContain(t, body, "Taze okuma", "belirsizlik sürüyor", "Önceki apply belirsiz")

	// A refused save carries the banner too.
	h.ed.saveErr = fmt.Errorf("%w (revision #7 (unknown))", policywriter.ErrUncertain)
	rec := h.post("/headscale/policy/save", saveForm(policyLive))
	if rec.Code != http.StatusConflict {
		t.Fatalf("save status = %d, want 409: %s", rec.Code, rec.Body)
	}
	mustContain(t, rec.Body.String(), "Önceki apply belirsiz", `href="/headscale/policy/recovery"`)
	mustNotContain(t, rec.Body.String(), "Policy apply edildi")

	// Once the live policy matches the last applied revision again, the fresh read says so.
	h.ed.live.Uncertain = ""
	body = h.get("/headscale/policy/revalidate").Body.String()
	mustContain(t, body, "Taze okuma", "belirsizlik kalktı")
	mustNotContain(t, body, "Önceki apply belirsiz")
	mustContain(t, body, `action="/headscale/policy/preview"`)
}

// AC8: the result page shows the revision id, the status and the git revision; a failed or unknown
// outcome never says success.
func TestPolicyPage_SaveResult(t *testing.T) {
	text := strings.Replace(policyLive, "everyone reaches the gate", "edited", 1)
	tests := []struct {
		name    string
		res     policywriter.SaveResult
		err     error
		code    int
		want    []string
		notWant []string
	}{
		{
			name: "applied",
			res: policywriter.SaveResult{
				Revision: policyrev.Revision{ID: 12, ApplyStatus: policyrev.StatusApplied},
				Change:   change.Result{Applied: true, Status: change.StatusApplied, Revision: "9f3c2ab", RevisionID: 12},
			},
			code:    http.StatusOK,
			want:    []string{"Policy apply edildi", "#12", "applied", "9f3c2ab"},
			notWant: []string{"belirsiz", "başarısız"},
		},
		{
			name: "applied but the git commit failed",
			res: policywriter.SaveResult{
				Revision: policyrev.Revision{ID: 13, ApplyStatus: policyrev.StatusApplied},
				Change:   change.Result{Applied: true, Status: change.StatusApplied, GitFailed: true, RevisionID: 13},
			},
			code: http.StatusOK,
			want: []string{"Policy apply edildi", "#13", "git kaydı yazılamadı"},
		},
		{
			// The policy is live; only the bookkeeping after the apply failed. The page must not claim
			// that nothing was written.
			name: "applied but the bookkeeping failed",
			res: policywriter.SaveResult{
				Revision: policyrev.Revision{ID: 17, ApplyStatus: policyrev.StatusApplied},
				Change:   change.Result{Applied: true, Status: change.StatusApplied, Revision: "1a2b3c4", RevisionID: 17},
			},
			err:     fmt.Errorf("audit write failed"),
			code:    http.StatusOK,
			want:    []string{"Policy apply edildi", "#17", "kayıt hatası: audit write failed"},
			notWant: []string{"hiçbir şey yazılmadı", "işlenemedi", "Policy apply edilemedi"},
		},
		{
			name: "failed",
			res: policywriter.SaveResult{
				Revision: policyrev.Revision{ID: 14, ApplyStatus: policyrev.StatusFailed, ApplyDetail: "SetPolicy: boom"},
				Change:   change.Result{Status: change.StatusFailed, RevisionID: 14},
			},
			err:     fmt.Errorf("%w: SetPolicy: boom", policywriter.ErrNotApplied),
			code:    http.StatusBadGateway,
			want:    []string{"Policy apply edilemedi", "#14", "failed", "SetPolicy: boom"},
			notWant: []string{"Policy apply edildi"},
		},
		{
			name: "unknown",
			res: policywriter.SaveResult{
				Revision: policyrev.Revision{ID: 15, ApplyStatus: policyrev.StatusUnknown, ApplyDetail: "geri okuma uyuşmadı"},
				Change:   change.Result{Status: change.StatusFailed, RevisionID: 15},
			},
			err:     fmt.Errorf("%w: apply belirsiz: geri okuma uyuşmadı", policywriter.ErrNotApplied),
			code:    http.StatusBadGateway,
			want:    []string{"Apply belirsiz", "#15", "unknown", "geri okuma uyuşmadı", `href="/headscale/policy/recovery"`},
			notWant: []string{"Policy apply edildi"},
		},
		{
			name: "dry run writes nothing",
			res: policywriter.SaveResult{
				Revision: policyrev.Revision{ID: 16, ApplyStatus: policyrev.StatusDryRun},
				Change:   change.Result{Status: change.StatusDryRun, RevisionID: 16},
			},
			code:    http.StatusOK,
			want:    []string{"Dry-run", "yazılmadı", "#16", "dry_run"},
			notWant: []string{"Policy apply edildi"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newPolicyHarness(t)
			h.ed.saveRes, h.ed.saveErr = tt.res, tt.err
			rec := h.post("/headscale/policy/save", saveForm(text))
			if rec.Code != tt.code {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tt.code, rec.Body)
			}
			mustContain(t, rec.Body.String(), tt.want...)
			mustNotContain(t, rec.Body.String(), tt.notWant...)
		})
	}

	t.Run("validation failed at save shows the report", func(t *testing.T) {
		h := newPolicyHarness(t)
		h.ed.saveRes = policywriter.SaveResult{Report: policydoc.Report{Hash: "x", Stages: []policydoc.StageResult{
			{Stage: policydoc.StageInput, State: policydoc.StatePass},
			{Stage: policydoc.StageSyntax, State: policydoc.StateFail, Message: "bad token"},
		}}}
		h.ed.saveErr = fmt.Errorf("%w: syntax: bad token", policywriter.ErrInvalid)
		rec := h.post("/headscale/policy/save", saveForm(text))
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want 422: %s", rec.Code, rec.Body)
		}
		mustContain(t, rec.Body.String(), "bad token", "Sözdizimi")
		mustNotContain(t, rec.Body.String(), "Policy apply edildi")
	})
	t.Run("a pending sync points to /sync", func(t *testing.T) {
		h := newPolicyHarness(t)
		h.ed.saveErr = fmt.Errorf("%w: eşik aşıldı", policywriter.ErrSyncPending)
		rec := h.post("/headscale/policy/save", saveForm(text))
		if rec.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409: %s", rec.Code, rec.Body)
		}
		mustContain(t, rec.Body.String(), `href="/sync"`)
	})
}

// AC9: a non-devops identity gets 403 on every route, a POST without the CSRF token is 403, and the
// write actions answer GET with 405.
func TestPolicyPage_CSRFAndDevops(t *testing.T) {
	h := newPolicyHarness(t)

	for _, tc := range []struct{ method, target string }{
		{http.MethodGet, "/headscale/policy"},
		{http.MethodGet, "/headscale/policy/revalidate"},
		{http.MethodPost, "/headscale/policy/preview"},
		{http.MethodPost, "/headscale/policy/save"},
	} {
		var form url.Values
		if tc.method == http.MethodPost {
			form = saveForm(policyLive)
		}
		for _, groups := range []string{"", "viewer"} {
			if rec := h.request(tc.method, tc.target, form, groups, true); rec.Code != http.StatusForbidden {
				t.Errorf("%s %s as %q = %d, want 403", tc.method, tc.target, groups, rec.Code)
			}
		}
	}

	for _, target := range []string{"/headscale/policy/preview", "/headscale/policy/save"} {
		if rec := h.request(http.MethodPost, target, saveForm(policyLive), "devops", false); rec.Code != http.StatusForbidden {
			t.Errorf("POST %s without the CSRF token = %d, want 403", target, rec.Code)
		}
		if rec := h.get(target); rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET %s = %d, want 405", target, rec.Code)
		}
	}
	if len(h.ed.saves) != 0 || len(h.ed.previews) != 0 {
		t.Errorf("a refused request reached the editor: %d previews, %d saves", len(h.ed.previews), len(h.ed.saves))
	}
}

// AC10 (raw): the raw diff rows mark exactly the added and the removed lines.
func TestPolicyDiff_Raw(t *testing.T) {
	before := "{\n  \"acls\": [],\n  \"tests\": []\n}\n"
	after := "{\n  \"acls\": [{\"a\": 1}],\n  \"tests\": []\n}\n"
	rows := rawDiffRows(change.LineDiff(before, after))
	want := []diffRow{
		{Kind: diffDel, Text: `  "acls": [],`},
		{Kind: diffAdd, Text: `  "acls": [{"a": 1}],`},
	}
	if len(rows) != len(want) {
		t.Fatalf("rows = %+v, want %+v", rows, want)
	}
	for i := range want {
		if rows[i] != want[i] {
			t.Errorf("row %d = %+v, want %+v", i, rows[i], want[i])
		}
	}
	if rows := rawDiffRows(change.LineDiff(before, before)); len(rows) != 0 {
		t.Errorf("identical texts gave rows %+v", rows)
	}
	// The writer's own marker for a trailing-newline-only change is kept as a note, not a line change.
	if rows := rawDiffRows(change.LineDiff("{}", "{}\n")); len(rows) != 1 || rows[0].Kind != diffNote {
		t.Errorf("trailing newline rows = %+v, want one note", rows)
	}
}

// AC10 (semantic): a reordered array is no change; an edited rule is one removal and one addition; an
// edited object member is one changed entry.
func TestPolicyDiff_Semantic(t *testing.T) {
	a := `{"acls": [{"action":"accept","src":["a"],"dst":["x:1"]}, {"action":"accept","src":["b"],"dst":["y:2"]}], "tagOwners": {"tag:web": ["group:old"]}}`
	reordered := `{"tagOwners": {"tag:web": ["group:old"]}, "acls": [{"action":"accept","src":["b"],"dst":["y:2"]}, {"action":"accept","src":["a"],"dst":["x:1"]}]}`
	if rows := semanticRows(policywriter.SemanticDiff(a, reordered)); len(rows) != 0 {
		t.Errorf("a reordered array gave %+v, want no change", rows)
	}

	edited := `{"acls": [{"action":"accept","src":["a"],"dst":["x:1"]}, {"action":"accept","src":["b"],"dst":["z:3"]}], "tagOwners": {"tag:web": ["group:new"]}}`
	rows := semanticRows(policywriter.SemanticDiff(a, edited))
	if len(rows) != 2 {
		t.Fatalf("rows = %+v, want acls and tagOwners", rows)
	}
	acls, owners := rows[0], rows[1]
	if acls.Label != "ACL kuralı" || len(acls.Added) != 1 || len(acls.Removed) != 1 || len(acls.Changed) != 0 {
		t.Errorf("acls row = %+v, want one added and one removed rule", acls)
	}
	if owners.Label != "tag owner'ları" || len(owners.Added) != 0 || len(owners.Removed) != 0 || len(owners.Changed) != 1 {
		t.Fatalf("tagOwners row = %+v, want one changed entry", owners)
	}
	if c := owners.Changed[0]; c.Key != "tag:web" || c.Before != `["group:old"]` || c.After != `["group:new"]` {
		t.Errorf("changed = %+v", c)
	}

	// A brand-new tag is an addition, not a change.
	added := semanticRows(policywriter.SemanticDiff(`{"tagOwners": {}}`, `{"tagOwners": {"tag:x": ["group:devops"]}}`))
	if len(added) != 1 || len(added[0].Added) != 1 || len(added[0].Changed) != 0 {
		t.Errorf("new tag rows = %+v", added)
	}
}

func TestPolicyHandler_NeedsWiring(t *testing.T) {
	csrf := testCSRF(t)
	for name, cfg := range map[string]PolicyHandlerConfig{
		"no editor": {DryRun: &fakeDryRunReader{}, CSRF: csrf},
		"no dryrun": {Editor: &fakeEditor{}, CSRF: csrf},
		"no csrf":   {Editor: &fakeEditor{}, DryRun: &fakeDryRunReader{}},
	} {
		if _, err := NewPolicyHandler(cfg); err == nil {
			t.Errorf("%s: NewPolicyHandler accepted the config", name)
		}
	}
}
