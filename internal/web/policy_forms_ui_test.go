package web

import (
	"regexp"
	"strings"
	"testing"
)

// 2026-10-06 item 7 (policy forms): rule src/dst, tag owners and route/exit approvers are multi-value
// fields over the same plain field the server parses (newline lists for src/dst, comma lists for
// owners/approvers) with the policy's aliases suggested; protocol and CIDR are typed inputs; the
// protected tag is plain text, not a chip.
func TestPolicyFormsUseMultiSelect(t *testing.T) {
	rich := policyRich(t)
	h := newPolicyFormsHarness(t, rich, &fakeAdminNodes{nodes: tagNodes()}, &fakeProtectedTags{})
	body := h.get("/headscale/policy").Body.String()

	field := func(name string) string {
		m := regexp.MustCompile(`<div class="multi" data-multi>\s*<(?:textarea|input)[^>]*name="` + name + `"[^>]*>`).FindString(body)
		if m == "" {
			t.Errorf("%s is not a multi-value field", name)
		}
		return m
	}
	for _, name := range []string{"add_src", "add_dst", "edit_0_src", "edit_0_dst"} {
		if f := field(name); f != "" && !strings.Contains(f, `<textarea`) {
			t.Errorf("%s must post a newline list: %s", name, f)
		}
	}
	for _, name := range []string{"tag_new_owners", "tag_0_owners", "route_new_approvers", "exit_approvers"} {
		if f := field(name); f != "" && (!strings.Contains(f, `data-multi-sep=", "`) || !strings.Contains(f, `form="policy-editor"`)) {
			t.Errorf("%s must post a comma list through the editor form: %s", name, f)
		}
	}
	for _, want := range []string{
		`<datalist id="add_src-opts"><option value="group:devops">`,
		`<option value="autogroup:member">`,
		`<datalist id="tag_new_owners-opts">`,
		`list="add_proto-opts"`, `<option value="udp">`,
		`name="route_new_cidr"`, `pattern="[0-9A-Fa-f:.]+/[0-9]{1,3}"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("policy page lacks %s", want)
		}
	}
	if strings.Contains(body, `<datalist id="tag_new_owners-opts"><option value="*">`) {
		t.Error(`"*" is suggested as a tag owner`)
	}
	if strings.Contains(body, `class="pill pill-info">korumalı`) {
		t.Error("the protected tag is still a chip")
	}
}
