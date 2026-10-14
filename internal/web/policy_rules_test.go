package web

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/internal/policydoc"
	"github.com/nesiler/tagcess/internal/policyrev"
	"github.com/nesiler/tagcess/internal/policywriter"
)

// Harness extensions for the policy form view (F3-023/F3-024): the rules, tagOwners and
// autoApprovers forms of the /headscale/policy page. The draft is stateless: a form action POSTs
// the current textarea text plus the operation, the server answers with the new raw text in the
// textarea and the saving itself stays F3-019's preview/approve flow.

// fakeProtectedTags is a fixed protected-tag list source.
type fakeProtectedTags struct {
	tags []string
	err  error
}

func (f *fakeProtectedTags) ProtectedTags(context.Context) ([]string, error) { return f.tags, f.err }

const policyRichFile = "testdata/policy-rich.hujson"

func policyRich(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(policyRichFile)
	if err != nil {
		t.Fatalf("read %s: %v", policyRichFile, err)
	}
	return string(b)
}

// newPolicyFormsHarness is the policy harness with the tag-form collaborators wired.
func newPolicyFormsHarness(t *testing.T, live string, nodes *fakeAdminNodes, prot *fakeProtectedTags) *policyHarness {
	t.Helper()
	h := &policyHarness{
		t:     t,
		ed:    &fakeEditor{live: policywriter.Live{Text: live, BaseHash: policyrev.HashRaw(live)}},
		dry:   &fakeDryRunReader{},
		csrf:  testCSRF(t),
		nodes: nodes,
		prot:  prot,
	}
	handler, err := NewPolicyHandler(PolicyHandlerConfig{Editor: h.ed, DryRun: h.dry, CSRF: h.csrf, Nodes: h.nodes, Protected: h.prot})
	if err != nil {
		t.Fatalf("NewPolicyHandler: %v", err)
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	h.chain = RequireDevops(h.csrf.Protect(mux))
	return h
}

// edited applies fn to a fresh Doc of text and returns the expected result text.
func edited(t *testing.T, text string, fn func(d *policydoc.Doc) error) string {
	t.Helper()
	d, err := policydoc.Parse(text)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	if err := fn(d); err != nil {
		t.Fatalf("apply edit: %v", err)
	}
	return d.Text()
}

// textareaValue reads the editor textarea the way a browser would submit it back.
func textareaValue(t *testing.T, body string) string {
	t.Helper()
	// Component attributes may change order; locate the same editable control by its identity.
	var rest string
	for _, part := range strings.Split(body, "<textarea")[1:] {
		open := strings.Index(part, ">")
		if open >= 0 && strings.Contains(part[:open], `id="policy-text"`) && strings.Contains(part[:open], `name="text"`) && !strings.Contains(part[:open], "readonly") {
			rest = "<textarea" + part
			break
		}
	}
	if rest == "" {
		t.Fatalf("no editable textarea in %s", body)
	}
	open := strings.Index(rest, ">")
	end := strings.Index(rest, "</textarea>")
	if open < 0 || end < 0 || open > end {
		t.Fatalf("malformed textarea in %s", body)
	}
	v := html.UnescapeString(rest[open+1 : end])
	return strings.TrimPrefix(v, "\n")
}

// ruleForm is a rules form action: the editor text plus the operation's fields.
func ruleForm(text string, fields url.Values) url.Values {
	f := url.Values{"text": {text}, "base_hash": {policyrev.HashRaw(policyLive)}}
	for k, vs := range fields {
		f[k] = vs
	}
	return f
}

func idxForm(text, button string, i int, fields url.Values) url.Values {
	f := ruleForm(text, fields)
	f.Set(button, fmt.Sprint(i))
	return f
}

// AC1: the page lists the acls rules in order with action, src, dst and proto, and notes the
// form-external grants and ssh sections.
func TestRulesForm_ListsRules(t *testing.T) {
	t.Run("single rule of the prod fixture", func(t *testing.T) {
		h := newPolicyFormsHarness(t, policyLive, &fakeAdminNodes{}, &fakeProtectedTags{})
		body := h.get("/headscale/policy").Body.String()
		mustContain(t, body, "ACL kuralları",
			html.EscapeString("autogroup:member"), html.EscapeString("*:*"), "accept",
			"grants: yok", "ssh: yok", "ham editörden düzenlenir",
		)
	})
	t.Run("three rules of the rich fixture with proto and info line", func(t *testing.T) {
		rich := policyRich(t)
		h := newPolicyFormsHarness(t, rich, &fakeAdminNodes{}, &fakeProtectedTags{})
		body := h.get("/headscale/policy").Body.String()
		mustContain(t, body,
			html.EscapeString("tag:vpn-server:80,443"), html.EscapeString("tag:k8s:8443"),
			html.EscapeString("tag:vpn-server:22"), html.EscapeString("tag:k8s:22"),
			"tcp",
			"grants: var", "ssh: var",
		)
		// The rows carry their index, in order.
		first := strings.Index(body, html.EscapeString("tag:vpn-server:80,443"))
		second := strings.Index(body, html.EscapeString("tag:k8s:8443"))
		third := strings.Index(body, html.EscapeString("tag:vpn-server:22"))
		if first < 0 || second < first || third < second {
			t.Errorf("rule rows out of order: %d, %d, %d", first, second, third)
		}
	})
}

// AC2: adding a rule returns the new raw text with only that rule added, updates the textarea and
// never saves.
func TestRulesForm_AddRule(t *testing.T) {
	h := newPolicyFormsHarness(t, policyLive, &fakeAdminNodes{}, &fakeProtectedTags{})
	form := ruleForm(policyLive, url.Values{
		"add_src":   {"group:devops"},
		"add_dst":   {"tag:web:443"},
		"add_proto": {"tcp"},
	})
	rec := h.post("/headscale/policy/rules/add", form)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	want := edited(t, policyLive, func(d *policydoc.Doc) error {
		return d.AddACLRule(policydoc.Rule{Proto: "tcp", Src: []string{"group:devops"}, Dst: []string{"tag:web:443"}})
	})
	if got := textareaValue(t, body); got != want {
		t.Errorf("textarea = %q, want %q", got, want)
	}
	mustContain(t, body, html.EscapeString("tag:web:443"), "Kural draft'a eklendi", "kaydedilmedi")
	if len(h.ed.previews) != 0 || len(h.ed.saves) != 0 {
		t.Errorf("an add reached the writer: %d previews, %d saves", len(h.ed.previews), len(h.ed.saves))
	}
	// The base hash is unchanged, so the following preview stays bound to the live read.
	if got := hiddenValue(t, body, "base_hash"); got != policyrev.HashRaw(policyLive) {
		t.Errorf("base_hash = %q, want the loaded base", got)
	}
}

// AC3: edit and delete work with the expected rule content and answer 409 when the live rule moved.
func TestRulesForm_EditDeleteStale(t *testing.T) {
	expected := url.Values{
		"exp_0_src": {"group:devops"},
		"exp_0_dst": {"*:*"},
	}
	t.Run("edit applies when the expected rule matches", func(t *testing.T) {
		h := newPolicyFormsHarness(t, policyLive, &fakeAdminNodes{}, &fakeProtectedTags{})
		form := idxForm(policyLive, "edit", 0, url.Values{
			"edit_0_src": {"group:devops"},
			"edit_0_dst": {"tag:web:443"},
			"exp_0_src":  {"group:devops"},
			"exp_0_dst":  {"*:*"},
		})
		rec := h.post("/headscale/policy/rules/update", form)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", rec.Code, rec.Body)
		}
		want := edited(t, policyLive, func(d *policydoc.Doc) error {
			return d.UpdateACLRule(0, policydoc.Rule{Src: []string{"group:devops"}, Dst: []string{"*:*"}},
				policydoc.Rule{Src: []string{"group:devops"}, Dst: []string{"tag:web:443"}})
		})
		if got := textareaValue(t, rec.Body.String()); got != want {
			t.Errorf("textarea = %q, want %q", got, want)
		}
		mustContain(t, rec.Body.String(), "Kural draft'ta güncellendi")
	})
	t.Run("delete removes the rule", func(t *testing.T) {
		h := newPolicyFormsHarness(t, policyLive, &fakeAdminNodes{}, &fakeProtectedTags{})
		rec := h.post("/headscale/policy/rules/delete", idxForm(policyLive, "del", 0, expected))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", rec.Code, rec.Body)
		}
		want := edited(t, policyLive, func(d *policydoc.Doc) error {
			return d.DeleteACLRule(0, policydoc.Rule{Src: []string{"group:devops"}, Dst: []string{"*:*"}})
		})
		if got := textareaValue(t, rec.Body.String()); got != want {
			t.Errorf("textarea = %q, want %q", got, want)
		}
		mustContain(t, rec.Body.String(), "Kural draft'tan silindi")
	})
	t.Run("a moved rule gives 409 and keeps the text", func(t *testing.T) {
		staleExp := url.Values{"exp_0_src": {"group:ghost"}, "exp_0_dst": {"*:*"}}
		for _, tc := range []struct {
			target, button string
			fields         url.Values
		}{
			{"/headscale/policy/rules/update", "edit", url.Values{"edit_0_src": {"group:devops"}, "edit_0_dst": {"tag:web:443"}, "exp_0_src": {"group:ghost"}, "exp_0_dst": {"*:*"}}},
			{"/headscale/policy/rules/delete", "del", staleExp},
		} {
			h := newPolicyFormsHarness(t, policyLive, &fakeAdminNodes{}, &fakeProtectedTags{})
			rec := h.post(tc.target, idxForm(policyLive, tc.button, 0, tc.fields))
			if rec.Code != http.StatusConflict {
				t.Errorf("%s status = %d, want 409: %s", tc.target, rec.Code, rec.Body)
			}
			mustContain(t, rec.Body.String(), "Kural bu arada değişti")
			if got := textareaValue(t, rec.Body.String()); got != policyLive {
				t.Errorf("%s changed the text", tc.target)
			}
			if len(h.ed.saves) != 0 {
				t.Errorf("%s reached the writer", tc.target)
			}
		}
	})
	t.Run("an unknown index gives 409", func(t *testing.T) {
		h := newPolicyFormsHarness(t, policyLive, &fakeAdminNodes{}, &fakeProtectedTags{})
		rec := h.post("/headscale/policy/rules/delete", idxForm(policyLive, "del", 7, expected))
		if rec.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409: %s", rec.Code, rec.Body)
		}
		mustContain(t, rec.Body.String(), "bulunamadı")
	})
}

// AC4: an out-of-allow-list value is refused with the error next to its field and the raw text
// untouched.
func TestRulesForm_FieldErrors(t *testing.T) {
	tests := []struct {
		name   string
		fields url.Values
		field  string
		msg    string
	}{
		{"bad proto", url.Values{"add_src": {"group:devops"}, "add_dst": {"tag:web:443"}, "add_proto": {"tcp2"}}, "add_proto", `proto &#34;tcp2&#34;`},
		{"bad src", url.Values{"add_src": {"group:bad name!"}, "add_dst": {"tag:web:443"}}, "add_src", `src &#34;group:bad name!&#34;`},
		{"dst without ports", url.Values{"add_src": {"group:devops"}, "add_dst": {"tag:web"}}, "add_dst", `dst &#34;tag:web&#34;: not an allowed alias`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newPolicyFormsHarness(t, policyLive, &fakeAdminNodes{}, &fakeProtectedTags{})
			rec := h.post("/headscale/policy/rules/add", ruleForm(policyLive, tt.fields))
			if rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d, want 422: %s", rec.Code, rec.Body)
			}
			body := rec.Body.String()
			mustContain(t, body, `aria-invalid="true"`, tt.msg)
			// The error sits next to its field: within the same form section as the input.
			fi := strings.Index(body, `name="`+tt.field+`"`)
			mi := strings.Index(body, tt.msg)
			if fi < 0 || mi < fi {
				t.Errorf("error %q not shown after field %s (field at %d, message at %d)", tt.msg, tt.field, fi, mi)
			}
			if got := textareaValue(t, body); got != policyLive {
				t.Error("a refused add changed the text")
			}
		})
	}
}

// AC5: grants, ssh, tests, nodeAttrs, comments and unknown fields survive form actions byte for
// byte.
func TestRulesForm_PreservesComplexSections(t *testing.T) {
	rich := policyRich(t)
	keep := []string{
		`"#note": "kept as is"`,
		"// Zitadel owns this section",
		`"grants": [`,
		`{ "src": ["group:devops"], "dst": ["tag:k8s"], "ip": ["*"] },`,
		`"ssh": [`,
		`"nodeAttrs": [`,
		`{ "src": "100.64.9.9", "deny": ["lab-host:443"] },`,
		`"sshTests": [],`,
		`"randomizeClientPort": true,`,
		"// access rules",
		"// gate",
	}
	ops := []struct {
		name   string
		target string
		form   url.Values
		edit   func(d *policydoc.Doc) error
	}{
		{
			"add", "/headscale/policy/rules/add",
			ruleForm(rich, url.Values{"add_src": {"group:developer"}, "add_dst": {"tag:k8s:8080"}}),
			func(d *policydoc.Doc) error {
				return d.AddACLRule(policydoc.Rule{Src: []string{"group:developer"}, Dst: []string{"tag:k8s:8080"}})
			},
		},
		{
			"update", "/headscale/policy/rules/update",
			idxForm(rich, "edit", 1, url.Values{
				"edit_1_src": {"tag:vpn-server"},
				"edit_1_dst": {"tag:k8s:9443"},
				"exp_1_src":  {"tag:vpn-server"},
				"exp_1_dst":  {"tag:k8s:8443"},
			}),
			func(d *policydoc.Doc) error {
				return d.UpdateACLRule(1, policydoc.Rule{Src: []string{"tag:vpn-server"}, Dst: []string{"tag:k8s:8443"}},
					policydoc.Rule{Src: []string{"tag:vpn-server"}, Dst: []string{"tag:k8s:9443"}})
			},
		},
		{
			"delete", "/headscale/policy/rules/delete",
			idxForm(rich, "del", 2, url.Values{
				"exp_2_proto": {"tcp"},
				"exp_2_src":   {"group:devops"},
				"exp_2_dst":   {"tag:vpn-server:22", "tag:k8s:22"},
			}),
			func(d *policydoc.Doc) error {
				return d.DeleteACLRule(2, policydoc.Rule{Proto: "tcp", Src: []string{"group:devops"}, Dst: []string{"tag:vpn-server:22", "tag:k8s:22"}})
			},
		},
	}
	for _, op := range ops {
		t.Run(op.name, func(t *testing.T) {
			h := newPolicyFormsHarness(t, rich, &fakeAdminNodes{}, &fakeProtectedTags{})
			rec := h.post(op.target, op.form)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d: %s", rec.Code, rec.Body)
			}
			got := textareaValue(t, rec.Body.String())
			if want := edited(t, rich, op.edit); got != want {
				t.Errorf("result differs from the policydoc edit:\n got: %q\nwant: %q", got, want)
			}
			for _, k := range keep {
				if !strings.Contains(got, k) {
					t.Errorf("result lost %q", k)
				}
			}
		})
	}
}

// AC6: deleting a rule that breaks a locked test surfaces at the preview as a failed locked-test
// stage and the save is blocked; the form itself does not judge.
func TestRulesForm_LockedRuleDeletionBlockedAtPreview(t *testing.T) {
	h := newPolicyFormsHarness(t, policyLive, &fakeAdminNodes{}, &fakeProtectedTags{})
	rec := h.post("/headscale/policy/rules/delete", idxForm(policyLive, "del", 0, url.Values{
		"exp_0_src": {"group:devops"},
		"exp_0_dst": {"*:*"},
	}))
	if rec.Code != http.StatusOK {
		t.Fatalf("delete status = %d: %s", rec.Code, rec.Body)
	}
	text := textareaValue(t, rec.Body.String())

	h.ed.previewRes = policywriter.SaveResult{
		Current: policyLive, Text: text,
		Report: policydoc.Report{Hash: policyrev.HashRaw(text), Stages: []policydoc.StageResult{
			{Stage: policydoc.StageInput, State: policydoc.StatePass},
			{Stage: policydoc.StageSyntax, State: policydoc.StatePass},
			{Stage: policydoc.StageStructure, State: policydoc.StatePass},
			{Stage: policydoc.StageLocked, State: policydoc.StateFail, Message: "locked test 1 failed: src 100.64.9.9 → tag:vpn-server:443"},
			{Stage: policydoc.StageCheck, State: policydoc.StateSkipped},
		}},
	}
	rec = h.post("/headscale/policy/preview", editForm(text))
	if rec.Code != http.StatusOK {
		t.Fatalf("preview status = %d: %s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	mustContain(t, body, "Kilitli testler", "hata", "locked test 1 failed")
	mustNotContain(t, body, `action="/headscale/policy/save"`)
	if len(h.ed.saves) != 0 {
		t.Error("a save went through with a failing locked test")
	}
}

// AC7: the src/dst suggestions offer the role groups (read-only), the tags and the fixed
// autogroup; the groups section never gets an edit action.
func TestRulesForm_GroupsNotEditable(t *testing.T) {
	rich := policyRich(t)
	h := newPolicyFormsHarness(t, rich, &fakeAdminNodes{}, &fakeProtectedTags{})
	body := h.get("/headscale/policy").Body.String()
	for _, sug := range []string{"group:devops", "group:developer", "tag:vpn-server", "tag:k8s", "autogroup:member", `"*"`} {
		if !strings.Contains(body, html.EscapeString(sug)) && !strings.Contains(body, sug) {
			t.Errorf("suggestion %q missing", sug)
		}
	}
	mustNotContain(t, body, "/headscale/policy/groups")
	mustContain(t, body, "read-only")
}

// AC8: a non-devops identity or a POST without the CSRF token gets 403; the actions are POST-only.
func TestRulesForm_CSRFAndDevops(t *testing.T) {
	h := newPolicyFormsHarness(t, policyLive, &fakeAdminNodes{}, &fakeProtectedTags{})
	targets := []string{
		"/headscale/policy/rules/add",
		"/headscale/policy/rules/update",
		"/headscale/policy/rules/delete",
	}
	for _, target := range targets {
		for _, groups := range []string{"", "viewer"} {
			if rec := h.request(http.MethodPost, target, ruleForm(policyLive, nil), groups, true); rec.Code != http.StatusForbidden {
				t.Errorf("POST %s as %q = %d, want 403", target, groups, rec.Code)
			}
		}
		if rec := h.request(http.MethodPost, target, ruleForm(policyLive, nil), "devops", false); rec.Code != http.StatusForbidden {
			t.Errorf("POST %s without CSRF = %d, want 403", target, rec.Code)
		}
		if rec := h.get(target); rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET %s = %d, want 405", target, rec.Code)
		}
	}
	if len(h.ed.saves) != 0 || len(h.ed.previews) != 0 {
		t.Error("a refused request reached the editor")
	}
}

// A draft the page cannot parse (hand-edited) is refused without touching anything.
func TestRulesForm_UnparseableText(t *testing.T) {
	h := newPolicyFormsHarness(t, policyLive, &fakeAdminNodes{}, &fakeProtectedTags{})
	bad := "{ not hujson"
	rec := h.post("/headscale/policy/rules/add", ruleForm(bad, url.Values{"add_src": {"a@b.c"}, "add_dst": {"x:1"}}))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body)
	}
	mustContain(t, rec.Body.String(), "ayrıştırılamadı")
	if len(h.ed.saves) != 0 {
		t.Error("reached the writer")
	}
}
