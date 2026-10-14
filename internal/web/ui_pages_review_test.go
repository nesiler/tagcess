package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/html"

	"github.com/nesiler/tagcess/internal/site"
	"github.com/nesiler/tagcess/internal/web/ui"
)

// UI-11: validation preserves the rejected input and reopens only that dialog;
// the draft and writer must remain untouched.
func TestPolicyFormValidationPreservesInput(t *testing.T) {
	rich := policyRich(t)
	cases := []struct {
		name, path, dialog string
		fields             url.Values
	}{
		{"rule add", "/headscale/policy/rules/add", "rule-add", url.Values{"add_src": {"group:devops\ngroup:developer"}, "add_dst": {"tag:web:443"}, "add_proto": {"tcp2"}}},
		{"rule edit", "/headscale/policy/rules/update", "rule-edit-0", url.Values{"edit": {"0"}, "exp_0_action": {"accept"}, "exp_0_src": {"autogroup:member"}, "exp_0_dst": {"tag:vpn-server:80,443"}, "edit_0_src": {"group:devops"}, "edit_0_dst": {"tag:web:443"}, "edit_0_proto": {"tcp2"}}},
		{"tag add", "/headscale/policy/tags/set", "tag-add", url.Values{"tag_new_name": {"tag:printer"}, "tag_new_owners": {"ghost"}}},
		{"tag edit empty", "/headscale/policy/tags/set", "tag-edit-0", url.Values{"tagset": {"0"}, "tag_0_name": {"tag:k8s"}, "tag_0_owners": {""}}},
		{"route add", "/headscale/policy/routes/set", "route-add", url.Values{"route_new_cidr": {"10.20.0.9/16"}, "route_new_approvers": {"group:devops"}}},
		{"route edit", "/headscale/policy/routes/set", "route-edit-0", url.Values{"routeset": {"0"}, "route_0_cidr": {"10.20.0.0/16"}, "route_0_approvers": {"ghost"}}},
		{"exit node", "/headscale/policy/routes/exitnode", "exit-edit", url.Values{"exit_approvers": {"ghost"}}},
		{"escaping", "/headscale/policy/tags/set", "tag-add", url.Values{"tag_new_name": {"tag:<script>alert(1)</script>"}, "tag_new_owners": {"group:devops"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newPolicyFormsHarness(t, rich, &fakeAdminNodes{nodes: tagNodes()}, &fakeProtectedTags{})
			rec := h.post(tc.path, formAction(rich, tc.fields))
			if rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status %d", rec.Code)
			}
			body := rec.Body.String()
			doc, err := html.Parse(strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			dialog := reviewElement(doc, "dialog", "id", tc.dialog)
			if dialog == nil || !reviewHasAttr(dialog, "data-dialog-auto-open") {
				t.Errorf("rejected dialog %s is not reopened", tc.dialog)
			}
			for name, values := range tc.fields {
				if strings.HasPrefix(name, "exp_") || name == "edit" || name == "tagset" || name == "routeset" {
					continue
				}
				c := reviewControl(dialog, name)
				if c == nil {
					t.Errorf("missing control %s", name)
					continue
				}
				got := reviewAttr(c, "value")
				if c.Data == "textarea" {
					got = reviewNodeText(c)
				}
				if got != values[0] {
					t.Errorf("%s=%q, want %q", name, got, values[0])
				}
			}
			if textareaValue(t, body) != rich || len(h.ed.saves) != 0 {
				t.Error("rejected form changed or saved policy")
			}
			if reviewElement(dialog, "script", "", "") != nil {
				t.Error("submitted markup became executable")
			}
		})
	}
}

func TestUIReviewHealthTones(t *testing.T) {
	for _, tc := range []struct {
		state string
		want  ui.Tone
	}{{"sağlıklı", ui.OK}, {healthUnknown, ui.Off}, {"", ui.Off}, {"başarısız", ui.Err}, {"sorunlu", ui.Err}, {"güncel değil", ui.Stale}, {"kontrol edilmiyor", ui.Off}, {"unexpected", ui.Off}} {
		if got := healthTone(tc.state); got != tc.want {
			t.Errorf("%q: tone=%s want %s", tc.state, got, tc.want)
		}
	}
	// Item 6 (2026-10-06): the health cell is a plain state with the latest check time; the per-row
	// "Pano" link is gone, and an unknown state is never coloured as healthy.
	at := time.Date(2026, 10, 5, 14, 2, 0, 0, time.UTC)
	body := render(t, SitesPage([]SiteView{
		{ID: 1, Hosts: []string{"example.test"}, Health: healthUnknown},
		{ID: 2, Hosts: []string{"ok.test"}, Health: "sağlıklı", CheckedAt: at},
	}, "tok"))
	if strings.Contains(body, `href="/#health-checks"`) || strings.Contains(body, "· Pano") {
		t.Error("the health cell still links every row to the dashboard")
	}
	unknown := body[strings.Index(body, "example.test"):strings.Index(body, "ok.test")]
	if !strings.Contains(unknown, `data-health="bilinmiyor"`) || strings.Contains(unknown, "stt-ok") {
		t.Errorf("unknown health row: %s", unknown)
	}
	if ok := body[strings.Index(body, "ok.test"):]; !strings.Contains(ok, "stt-ok") || !strings.Contains(ok, "2026-10-05 14:02") {
		t.Errorf("known health lacks its state colour or check time: %s", ok)
	}
}

func TestUIReviewCurrentPolicyHistory(t *testing.T) {
	body := render(t, SiteHistoryPage(SiteHistoryView{SiteID: 7, Hosts: "example.test"}))
	if !strings.Contains(body, `href="/headscale/policy/history"`) || strings.Contains(body, "F3'te") {
		t.Error("site history does not point to existing policy history")
	}
}

func TestUIReviewSystemFormScope(t *testing.T) {
	f := previewSiteForm(site.Site{ID: 2, Kind: site.KindSystem, SystemTemplate: site.TemplateZitadel}, false, "")
	if body := render(t, SiteFormPage(f, "tok")); strings.Contains(body, `action="/sites/targets"`) {
		t.Error("system form offers unrelated URL target management")
	}
}

func reviewElement(n *html.Node, tag, key, value string) *html.Node {
	if n == nil {
		return nil
	}
	if n.Type == html.ElementNode && n.Data == tag && (key == "" || reviewAttr(n, key) == value) {
		return n
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if found := reviewElement(c, tag, key, value); found != nil {
			return found
		}
	}
	return nil
}
func reviewControl(n *html.Node, name string) *html.Node {
	if n == nil {
		return nil
	}
	if n.Type == html.ElementNode && (n.Data == "input" || n.Data == "textarea") && reviewAttr(n, "name") == name {
		return n
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if found := reviewControl(c, name); found != nil {
			return found
		}
	}
	return nil
}
func reviewAttr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}
func reviewHasAttr(n *html.Node, key string) bool {
	for _, a := range n.Attr {
		if a.Key == key {
			return true
		}
	}
	return false
}
func reviewNodeText(n *html.Node) string {
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(x *html.Node) {
		if x.Type == html.TextNode {
			b.WriteString(x.Data)
		}
		for c := x.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return b.String()
}

// Early source/parse refusals keep submitted fields available as read-only
// recovery text while all policy form actions remain blocked.
func TestPolicyFormRefusalRecovery(t *testing.T) {
	for _, tc := range []struct {
		name, path, text string
		status           int
		readFail         bool
		fields           url.Values
	}{
		{"bad rule document", "/headscale/policy/rules/add", "{broken", http.StatusBadRequest, false, url.Values{"add_src": {"group:devops"}, "add_dst": {"tag:web:443"}, "add_proto": {"tcp"}}},
		{"bad tag document", "/headscale/policy/tags/set", "{broken", http.StatusBadRequest, false, url.Values{"tag_new_name": {"tag:printer"}, "tag_new_owners": {"group:devops"}}},
		{"protected tags unreadable", "/headscale/policy/tags/set", policyLive, http.StatusServiceUnavailable, true, url.Values{"tag_new_name": {"tag:printer"}, "tag_new_owners": {"group:devops"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prot := &fakeProtectedTags{}
			if tc.readFail {
				prot.err = errPreviewStatus
			}
			h := newPolicyFormsHarness(t, tc.text, &fakeAdminNodes{}, prot)
			rec := h.post(tc.path, formAction(tc.text, tc.fields))
			if rec.Code != tc.status {
				t.Fatalf("status=%d want %d", rec.Code, tc.status)
			}
			doc, err := html.Parse(strings.NewReader(rec.Body.String()))
			if err != nil {
				t.Fatal(err)
			}
			recovery := reviewElement(doc, "section", "aria-label", "Korunan form girdileri")
			if recovery == nil {
				t.Fatal("no read-only recovery content")
			}
			text := reviewNodeText(recovery)
			for _, v := range tc.fields {
				if !strings.Contains(text, v[0]) {
					t.Errorf("lost %q", v[0])
				}
			}
			if textareaValue(t, rec.Body.String()) != tc.text || len(h.ed.saves) != 0 {
				t.Error("refusal changed/saved policy")
			}
			if reviewElement(recovery, "button", "", "") != nil || reviewElement(recovery, "form", "", "") != nil {
				t.Error("recovery text exposes a form action")
			}
		})
	}
}
