package web

import (
	"context"
	"io"
	"net/http"

	"github.com/a-h/templ"

	"github.com/nesiler/tagcess/internal/web/ui"
)

// Preview samples of the ACL rules card and the tag/route cards (the cards sit under the policy
// editor on /headscale/policy; here they are shown alone). Query states of every sample:
//
//	?empty=1    no rows
//	?field=1    a field error (rejected add or edit)
//	?general=1  a refusal that is not one field
//	?read=1     the sections cannot be read out of the text
//	?readonly=1 the editor is closed (Zitadel unreadable): rows without actions
//	?load=1     tags only: protected list or nodes unreadable
func init() {
	previewPages = append(previewPages,
		previewPage{"/headscale/policy/rules", "headscale", "ACL kuralları", func(r *http.Request) templ.Component {
			return policyCardsPreview("ACL kuralları", "Kurallar formu, ham editörün altındaki kart.", PolicyRulesCard(*previewRulesView(r), !previewReadOnly(r)))
		}},
		previewPage{"/headscale/policy/tags", "headscale", "Tag owner'ları ve route'lar", func(r *http.Request) templ.Component {
			return policyCardsPreview("Tag owner'ları ve route'lar", "Tag ve autoApprovers formları, ham editörün altındaki kartlar.", PolicyTagsCards(*previewTagsView(r), !previewReadOnly(r)))
		}},
	)
}

func previewReadOnly(r *http.Request) bool { return r.URL.Query().Get("readonly") == "1" }

// policyCardsPreview puts the cards under a page head, as the policy page does.
func policyCardsPreview(title, sub string, cards templ.Component) templ.Component {
	return templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
		crumbs := []ui.Crumb{{Label: "ACL", Href: "/headscale/policy"}, {Label: title}}
		if err := ui.PageHead(ui.H{Title: title, Sub: sub, Crumbs: crumbs}).Render(ctx, w); err != nil {
			return err
		}
		return cards.Render(ctx, w)
	})
}

func previewRulesView(r *http.Request) *policyRulesView {
	q := r.URL.Query()
	v := &policyRulesView{
		Rows: []ruleRow{
			{Index: 0, Action: "accept", Src: []string{"autogroup:member"}, Dst: []string{"*:*"}},
			{Index: 1, Action: "accept", Proto: "tcp", Src: []string{"group:devops"}, Dst: []string{"tag:vpn-server:80,443", "tag:k8s:8443"}},
			{Index: 2, Action: "accept", Src: []string{"group:devops", "group:yazilim"}, Dst: []string{"tag:vpn-server:22", "tag:k8s:22"}},
		},
		HasGrants: true,
		Sug:       []string{"group:devops", "group:yazilim", "tag:vpn-server", "tag:k8s", "autogroup:member", "*"},
		Applied:   "Kural draft'a eklendi; henüz kaydedilmedi.",
	}
	switch {
	case q.Get("empty") == "1":
		v.Rows, v.Applied = nil, ""
	case q.Get("read") == "1":
		*v = policyRulesView{ReadErr: "policy: invalid character '}' looking for beginning of object key string"}
	case q.Get("field") == "1":
		v.Applied = ""
		v.FieldErr, v.FieldMsg = "add_proto", `proto "tcp2": not an allowed protocol`
		v.Feedback = draftFormFeedback{Dialog: "rule-add", Values: map[string]string{"add_src": "group:devops", "add_dst": "tag:web:443", "add_proto": "tcp2"}}
	case q.Get("general") == "1":
		v.Applied = ""
		v.General = "Kural bu arada değişti; sayfayı yeniden yükleyin."
	}
	return v
}

func previewTagsView(r *http.Request) *policyTagsView {
	q := r.URL.Query()
	v := &policyTagsView{
		Tags: []tagRow{
			{Tag: "tag:vpn-server", Owners: []string{"group:devops"}, Nodes: 2, Protected: true},
			{Tag: "tag:k8s", Owners: []string{"group:devops", "group:yazilim"}, Nodes: 1, InText: true},
			{Tag: "tag:printer", Owners: []string{"group:devops"}},
		},
		Routes: []routeRow{
			{CIDR: "10.20.0.0/16", Approvers: []string{"group:devops"}},
			{CIDR: "192.168.1.0/24", Approvers: []string{"group:devops", "tag:vpn-server"}},
		},
		Exit:    []string{"group:devops"},
		Applied: "Tag draft'a eklendi; henüz kaydedilmedi.",
		Warn:    []string{"Korumalı tag tag:vpn-server: yeni owner'larda group:devops yok (zayıflatma)."},
	}
	switch {
	case q.Get("empty") == "1":
		*v = policyTagsView{}
	case q.Get("read") == "1":
		*v = policyTagsView{ReadErr: "policy: invalid character '}' looking for beginning of object key string"}
	case q.Get("load") == "1":
		*v = policyTagsView{LoadErr: "Tag formları kapalı: node'lar okunamadı: dial tcp: connection refused"}
	case q.Get("field") == "1":
		v.Applied, v.Warn = "", nil
		v.FieldErr, v.FieldMsg = "tag_new_owners", `owner "ghost": not a known group, tag or user`
		v.Feedback = draftFormFeedback{Dialog: "tag-add", Values: map[string]string{"tag_new_name": "tag:printer", "tag_new_owners": "ghost"}}
	case q.Get("general") == "1":
		v.Applied, v.Warn = "", nil
		v.General = "Tag bulunamadı: tag:old (sayfa eski bir metne dayanıyor)."
	}
	return v
}
