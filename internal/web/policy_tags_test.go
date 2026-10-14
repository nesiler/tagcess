package web

import (
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/internal/headscale/admin"
	"github.com/nesiler/tagcess/internal/policydoc"
	"github.com/nesiler/tagcess/internal/policyrev"
	"github.com/nesiler/tagcess/internal/policywriter"
)

// The tagOwners and route autoApprovers forms (F3-024, H-05) on the policy page. Same stateless
// draft flow as the rules forms (F3-023): the action POSTs the current text, the server answers
// with the new raw text, saving stays the preview/approve flow.

// tagNodes is the fixed node list for the tag form tests: two nodes carry tag:vpn-server, one of
// them also tag:k8s.
func tagNodes() []admin.AdminNode {
	return []admin.AdminNode{
		{ID: 1, Name: "gate", Tags: []string{"tag:vpn-server"}},
		{ID: 2, Name: "k8s-1", Tags: []string{"tag:vpn-server", "tag:k8s"}},
		{ID: 3, Name: "laptop", Tags: nil},
	}
}

// formAction is a tag/route form action: the editor text plus the operation's fields.
func formAction(text string, fields url.Values) url.Values {
	f := url.Values{"text": {text}, "base_hash": {policyrev.HashRaw(policyLive)}}
	for k, vs := range fields {
		f[k] = vs
	}
	return f
}

// inputValue reads an input's value attribute the way a browser would submit it back.
func inputValue(t *testing.T, body, name string) string {
	t.Helper()
	marker := `name="` + name + `"`
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatalf("no input %q in %s", name, body)
	}
	tag := body[i : i+400]
	vi := strings.Index(tag, `value="`)
	if vi < 0 {
		t.Fatalf("input %q has no value in %s", name, tag)
	}
	rest := tag[vi+len(`value="`):]
	return strings.ReplaceAll(rest[:strings.Index(rest, `"`)], "&#34;", `"`)
}

// AC1: the page lists the tagOwners entries (tag, owners, node count) and the autoApprovers
// entries (routes and exitNode with their approvers).
func TestTagsForm_Lists(t *testing.T) {
	h := newPolicyFormsHarness(t, policyRich(t), &fakeAdminNodes{nodes: tagNodes()}, &fakeProtectedTags{tags: []string{"tag:vpn-server"}})
	body := h.get("/headscale/policy").Body.String()
	mustContain(t, body,
		"Tag owner'ları",
		html.EscapeString("tag:vpn-server"), html.EscapeString("tag:k8s"),
		"2 node", "1 node",
		html.EscapeString(`["group:devops"]`),
		"korumalı",
		"Route autoApprovers",
		html.EscapeString("10.20.0.0/16"), html.EscapeString("192.168.1.0/24"),
		"exitNode",
	)
}

// AC2: a new tag arrives with group:devops prefilled, an empty owner list is refused, and the
// accepted add changes only that entry in the raw text.
func TestTagsForm_AddTagDefaultOwner(t *testing.T) {
	rich := policyRich(t)
	h := newPolicyFormsHarness(t, rich, &fakeAdminNodes{nodes: tagNodes()}, &fakeProtectedTags{tags: []string{"tag:vpn-server"}})

	body := h.get("/headscale/policy").Body.String()
	if got := inputValue(t, body, "tag_new_owners"); got != "group:devops" {
		t.Errorf("add form owners = %q, want the group:devops prefill", got)
	}

	t.Run("empty owners refused", func(t *testing.T) {
		rec := h.post("/headscale/policy/tags/set", formAction(rich, url.Values{
			"tag_new_name":   {"tag:printer"},
			"tag_new_owners": {""},
		}))
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want 422: %s", rec.Code, rec.Body)
		}
		mustContain(t, rec.Body.String(), "boş olamaz")
		if got := textareaValue(t, rec.Body.String()); got != rich {
			t.Error("a refused add changed the text")
		}
	})
	t.Run("add applies to the draft only", func(t *testing.T) {
		rec := h.post("/headscale/policy/tags/set", formAction(rich, url.Values{
			"tag_new_name":   {"tag:printer"},
			"tag_new_owners": {"group:devops"},
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", rec.Code, rec.Body)
		}
		want := edited(t, rich, func(d *policydoc.Doc) error { return d.SetTagOwners("tag:printer", []string{"group:devops"}) })
		if got := textareaValue(t, rec.Body.String()); got != want {
			t.Errorf("textarea = %q, want %q", got, want)
		}
		mustContain(t, rec.Body.String(), "Tag draft'a eklendi")
		if len(h.ed.saves) != 0 || len(h.ed.previews) != 0 {
			t.Error("a tag add reached the writer")
		}
	})
}

// AC3: owner edits and deletions protect everything outside the target byte for byte, a protected
// server tag cannot be deleted, and changing its owners without group:devops warns.
func TestTagsForm_EditDeleteAndProtected(t *testing.T) {
	rich := policyRich(t)
	prot := []string{"tag:vpn-server"}
	t.Run("edit owners of tag:k8s", func(t *testing.T) {
		h := newPolicyFormsHarness(t, rich, &fakeAdminNodes{nodes: tagNodes()}, &fakeProtectedTags{tags: prot})
		rec := h.post("/headscale/policy/tags/set", formAction(rich, url.Values{
			"tagset":       {"1"},
			"tag_1_name":   {"tag:k8s"},
			"tag_1_owners": {"group:devops"},
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", rec.Code, rec.Body)
		}
		want := edited(t, rich, func(d *policydoc.Doc) error { return d.SetTagOwners("tag:k8s", []string{"group:devops"}) })
		if got := textareaValue(t, rec.Body.String()); got != want {
			t.Errorf("textarea = %q, want %q", got, want)
		}
		mustContain(t, rec.Body.String(), "Tag owner'ları draft'ta güncellendi")
	})
	t.Run("a protected tag cannot be deleted", func(t *testing.T) {
		h := newPolicyFormsHarness(t, rich, &fakeAdminNodes{nodes: tagNodes()}, &fakeProtectedTags{tags: prot})
		rec := h.post("/headscale/policy/tags/delete", formAction(rich, url.Values{
			"tagdel":     {"0"},
			"tag_0_name": {"tag:vpn-server"},
		}))
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want 422: %s", rec.Code, rec.Body)
		}
		mustContain(t, rec.Body.String(), "Korumalı sunucu tag&#39;i silinemez", html.EscapeString("tag:vpn-server"))
		if got := textareaValue(t, rec.Body.String()); got != rich {
			t.Error("a protected deletion changed the text")
		}
	})
	t.Run("weakening a protected tag warns", func(t *testing.T) {
		h := newPolicyFormsHarness(t, rich, &fakeAdminNodes{nodes: tagNodes()}, &fakeProtectedTags{tags: prot})
		rec := h.post("/headscale/policy/tags/set", formAction(rich, url.Values{
			"tagset":       {"0"},
			"tag_0_name":   {"tag:vpn-server"},
			"tag_0_owners": {"group:sre"},
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", rec.Code, rec.Body)
		}
		want := edited(t, rich, func(d *policydoc.Doc) error { return d.SetTagOwners("tag:vpn-server", []string{"group:sre"}) })
		if got := textareaValue(t, rec.Body.String()); got != want {
			t.Errorf("textarea = %q, want %q", got, want)
		}
		mustContain(t, rec.Body.String(), "zayıflatma", "group:devops")
	})
}

// AC4: deleting a tag that is in use (nodes or rules) warns on the response; the preview then
// reports the validation outcome and blocks the save.
func TestTagsForm_DeleteInUseWarns(t *testing.T) {
	rich := policyRich(t)
	h := newPolicyFormsHarness(t, rich, &fakeAdminNodes{nodes: tagNodes()}, &fakeProtectedTags{tags: []string{"tag:vpn-server"}})
	rec := h.post("/headscale/policy/tags/delete", formAction(rich, url.Values{
		"tagdel":     {"1"},
		"tag_1_name": {"tag:k8s"},
	}))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	mustContain(t, body, html.EscapeString("1 node bu tag'i taşıyor"), "başka bölümlerde geçiyor", "kaydedilmedi")
	want := edited(t, rich, func(d *policydoc.Doc) error { return d.DeleteTag("tag:k8s") })
	if got := textareaValue(t, body); got != want {
		t.Errorf("textarea = %q, want %q", got, want)
	}

	// The preview is the gate: with the tag gone, validation fails and no save form appears.
	h.ed.previewRes = policywriter.SaveResult{
		Current: rich, Text: want,
		Report: policydoc.Report{Hash: policyrev.HashRaw(want), Stages: []policydoc.StageResult{
			{Stage: policydoc.StageInput, State: policydoc.StatePass},
			{Stage: policydoc.StageSyntax, State: policydoc.StatePass},
			{Stage: policydoc.StageStructure, State: policydoc.StatePass},
			{Stage: policydoc.StageLocked, State: policydoc.StatePass},
			{Stage: policydoc.StageCheck, State: policydoc.StateFail, Message: `node "k8s-1" has invalid tag "tag:k8s"`},
		}},
	}
	rec = h.post("/headscale/policy/preview", editForm(want))
	if rec.Code != http.StatusOK {
		t.Fatalf("preview status = %d: %s", rec.Code, rec.Body)
	}
	mustContain(t, rec.Body.String(), "Headscale", "hata", `invalid tag &#34;tag:k8s&#34;`)
	mustNotContain(t, rec.Body.String(), `action="/headscale/policy/save"`)
	if len(h.ed.saves) != 0 {
		t.Error("a save went through")
	}
}

// AC5: route approver add/change/delete and the exitNode approvers validate CIDR and approver
// shape, change only the target entry and carry the re-approval side-effect note.
func TestAutoApproversForm_Edits(t *testing.T) {
	rich := policyRich(t)
	note := "yeniden onaylayabilir"
	t.Run("add a route", func(t *testing.T) {
		h := newPolicyFormsHarness(t, rich, &fakeAdminNodes{nodes: tagNodes()}, &fakeProtectedTags{tags: nil})
		rec := h.post("/headscale/policy/routes/set", formAction(rich, url.Values{
			"route_new_cidr":      {"10.30.0.0/16"},
			"route_new_approvers": {"group:devops"},
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", rec.Code, rec.Body)
		}
		want := edited(t, rich, func(d *policydoc.Doc) error { return d.SetRouteApprovers("10.30.0.0/16", []string{"group:devops"}) })
		if got := textareaValue(t, rec.Body.String()); got != want {
			t.Errorf("textarea = %q, want %q", got, want)
		}
		mustContain(t, rec.Body.String(), note)
	})
	t.Run("change one route's approvers", func(t *testing.T) {
		h := newPolicyFormsHarness(t, rich, &fakeAdminNodes{nodes: tagNodes()}, &fakeProtectedTags{tags: nil})
		rec := h.post("/headscale/policy/routes/set", formAction(rich, url.Values{
			"routeset":          {"0"},
			"route_0_cidr":      {"10.20.0.0/16"},
			"route_0_approvers": {"group:devops, tag:vpn-server"},
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", rec.Code, rec.Body)
		}
		want := edited(t, rich, func(d *policydoc.Doc) error {
			return d.SetRouteApprovers("10.20.0.0/16", []string{"group:devops", "tag:vpn-server"})
		})
		if got := textareaValue(t, rec.Body.String()); got != want {
			t.Errorf("textarea = %q, want %q", got, want)
		}
	})
	t.Run("delete a route", func(t *testing.T) {
		h := newPolicyFormsHarness(t, rich, &fakeAdminNodes{nodes: tagNodes()}, &fakeProtectedTags{tags: nil})
		rec := h.post("/headscale/policy/routes/delete", formAction(rich, url.Values{
			"routedel":     {"1"},
			"route_1_cidr": {"192.168.1.0/24"},
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", rec.Code, rec.Body)
		}
		want := edited(t, rich, func(d *policydoc.Doc) error { return d.DeleteRoute("192.168.1.0/24") })
		if got := textareaValue(t, rec.Body.String()); got != want {
			t.Errorf("textarea = %q, want %q", got, want)
		}
		mustContain(t, rec.Body.String(), "Route draft'tan silindi")
	})
	t.Run("set the exitNode approvers", func(t *testing.T) {
		h := newPolicyFormsHarness(t, rich, &fakeAdminNodes{nodes: tagNodes()}, &fakeProtectedTags{tags: nil})
		rec := h.post("/headscale/policy/routes/exitnode", formAction(rich, url.Values{
			"exit_approvers": {"group:devops"},
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", rec.Code, rec.Body)
		}
		want := edited(t, rich, func(d *policydoc.Doc) error { return d.SetExitNodeApprovers([]string{"group:devops"}) })
		if got := textareaValue(t, rec.Body.String()); got != want {
			t.Errorf("textarea = %q, want %q", got, want)
		}
	})
	t.Run("empty approvers refused", func(t *testing.T) {
		h := newPolicyFormsHarness(t, rich, &fakeAdminNodes{nodes: tagNodes()}, &fakeProtectedTags{tags: nil})
		rec := h.post("/headscale/policy/routes/set", formAction(rich, url.Values{
			"route_new_cidr":      {"10.30.0.0/16"},
			"route_new_approvers": {""},
		}))
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want 422: %s", rec.Code, rec.Body)
		}
		mustContain(t, rec.Body.String(), "boş olamaz")
	})
}

// AC6: out-of-allow-list input (bad tag name, bad approver, non-canonical CIDR) is refused with a
// field error and the raw text untouched.
func TestTagsForm_FieldErrors(t *testing.T) {
	rich := policyRich(t)
	tests := []struct {
		name   string
		target string
		fields url.Values
		field  string
		msg    string
	}{
		{"bad tag name", "/headscale/policy/tags/set", url.Values{
			"tag_new_name": {"Tag:Bad!"}, "tag_new_owners": {"group:devops"},
		}, "tag_new_name", `tag name &#34;Tag:Bad!&#34;`},
		{"bad approver", "/headscale/policy/tags/set", url.Values{
			"tag_new_name": {"tag:printer"}, "tag_new_owners": {"ghost"},
		}, "tag_new_owners", `owner &#34;ghost&#34;`},
		{"bad route approver", "/headscale/policy/routes/set", url.Values{
			"route_new_cidr": {"10.30.0.0/16"}, "route_new_approvers": {"ghost"},
		}, "route_new_approvers", `owner &#34;ghost&#34;`},
		{"non-canonical CIDR", "/headscale/policy/routes/set", url.Values{
			"route_new_cidr": {"10.20.0.9/16"}, "route_new_approvers": {"group:devops"},
		}, "route_new_cidr", "canonical CIDR"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newPolicyFormsHarness(t, rich, &fakeAdminNodes{nodes: tagNodes()}, &fakeProtectedTags{tags: nil})
			rec := h.post(tt.target, formAction(rich, tt.fields))
			if rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d, want 422: %s", rec.Code, rec.Body)
			}
			body := rec.Body.String()
			mustContain(t, body, `aria-invalid="true"`, tt.msg)
			fi := strings.Index(body, `name="`+tt.field+`"`)
			mi := strings.Index(body, tt.msg)
			if fi < 0 || mi < fi {
				t.Errorf("error %q not shown after field %s", tt.msg, tt.field)
			}
			if got := textareaValue(t, body); got != rich {
				t.Error("a refused action changed the text")
			}
		})
	}
}

// AC7: after tag and route form actions, groups, acls, grants, ssh, tests and the comments are
// byte for byte the same.
func TestTagsForm_PreservesOtherSections(t *testing.T) {
	rich := policyRich(t)
	h := newPolicyFormsHarness(t, rich, &fakeAdminNodes{nodes: tagNodes()}, &fakeProtectedTags{tags: []string{"tag:vpn-server"}})
	rec := h.post("/headscale/policy/tags/set", formAction(rich, url.Values{
		"tag_new_name":   {"tag:printer"},
		"tag_new_owners": {"group:devops"},
	}))
	if rec.Code != http.StatusOK {
		t.Fatalf("tags/set status = %d: %s", rec.Code, rec.Body)
	}
	text := textareaValue(t, rec.Body.String())
	rec = h.post("/headscale/policy/routes/set", formAction(text, url.Values{
		"route_new_cidr":      {"10.30.0.0/16"},
		"route_new_approvers": {"group:devops"},
	}))
	if rec.Code != http.StatusOK {
		t.Fatalf("routes/set status = %d: %s", rec.Code, rec.Body)
	}
	text = textareaValue(t, rec.Body.String())
	want := edited(t, rich, func(d *policydoc.Doc) error {
		if err := d.SetTagOwners("tag:printer", []string{"group:devops"}); err != nil {
			return err
		}
		return d.SetRouteApprovers("10.30.0.0/16", []string{"group:devops"})
	})
	if text != want {
		t.Errorf("combined result differs:\n got: %q\nwant: %q", text, want)
	}
	for _, k := range []string{
		`"#note": "kept as is"`, "// Zitadel owns this section",
		`{ "action": "accept", "src": ["autogroup:member"], "dst": ["tag:vpn-server:80,443"] }, // gate`,
		`{ "src": ["group:devops"], "dst": ["tag:k8s"], "ip": ["*"] },`,
		`{ "src": "100.64.9.9", "deny": ["lab-host:443"] },`,
		`"sshTests": [],`,
	} {
		if !strings.Contains(text, k) {
			t.Errorf("result lost %q", k)
		}
	}
}

// AC8: a non-devops identity or a POST without the CSRF token gets 403; the actions are POST-only.
func TestTagsForm_CSRFAndDevops(t *testing.T) {
	h := newPolicyFormsHarness(t, policyLive, &fakeAdminNodes{nodes: tagNodes()}, &fakeProtectedTags{tags: nil})
	for _, target := range []string{
		"/headscale/policy/tags/set",
		"/headscale/policy/tags/delete",
		"/headscale/policy/routes/set",
		"/headscale/policy/routes/delete",
		"/headscale/policy/routes/exitnode",
	} {
		for _, groups := range []string{"", "viewer"} {
			if rec := h.request(http.MethodPost, target, formAction(policyLive, nil), groups, true); rec.Code != http.StatusForbidden {
				t.Errorf("POST %s as %q = %d, want 403", target, groups, rec.Code)
			}
		}
		if rec := h.request(http.MethodPost, target, formAction(policyLive, nil), "devops", false); rec.Code != http.StatusForbidden {
			t.Errorf("POST %s without CSRF = %d, want 403", target, rec.Code)
		}
		if rec := h.get(target); rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET %s = %d, want 405", target, rec.Code)
		}
	}
}

// The tag card closes when the nodes or the protected list cannot be read (fail safe), while the
// rules card stays up.
func TestTagsForm_UnreadableDepsCloseCard(t *testing.T) {
	rich := policyRich(t)
	h := newPolicyFormsHarness(t, rich, &fakeAdminNodes{err: fmt.Errorf("dial: refused")}, &fakeProtectedTags{tags: nil})
	rec := h.get("/headscale/policy")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}
	mustContain(t, rec.Body.String(), "Tag formları kapalı", "ACL kuralları")
	mustNotContain(t, rec.Body.String(), `name="tag_new_name"`)
}

// M3 (F5 live findings): after a tag/route form action, and after any refused form action, the
// draft page still lists the ACL rules of the draft text (and the tag table of a refused rule
// action) instead of "Kural yok.".
func TestPolicyForms_DraftPageKeepsOtherTables(t *testing.T) {
	rich := policyRich(t)
	rule := html.EscapeString("tag:vpn-server:80,443")
	cases := []struct {
		name   string
		target string
		fields url.Values
		want   []string
	}{
		{"tag add", "/headscale/policy/tags/set", url.Values{
			"tag_new_name": {"tag:printer"}, "tag_new_owners": {"group:devops"},
		}, []string{rule}},
		{"tag refusal", "/headscale/policy/tags/set", url.Values{
			"tag_new_name": {"tag:printer"}, "tag_new_owners": {""},
		}, []string{rule, "2 node"}},
		{"route add", "/headscale/policy/routes/set", url.Values{
			"route_new_cidr": {"10.30.0.0/16"}, "route_new_approvers": {"group:devops"},
		}, []string{rule}},
		{"rule refusal", "/headscale/policy/rules/add", url.Values{
			"add_src": {"group:devops"}, "add_dst": {"tag:web:443"}, "add_proto": {"tcp2"},
		}, []string{rule, "2 node"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newPolicyFormsHarness(t, rich, &fakeAdminNodes{nodes: tagNodes()}, &fakeProtectedTags{tags: []string{"tag:vpn-server"}})
			body := h.post(tc.target, formAction(rich, tc.fields)).Body.String()
			if strings.Contains(body, "Kural yok.") {
				t.Errorf("rules table empty after %s", tc.name)
			}
			mustContain(t, body, tc.want...)
		})
	}
}
