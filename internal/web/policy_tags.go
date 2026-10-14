package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"

	"github.com/nesiler/tagcess/internal/headscale/admin"
	"github.com/nesiler/tagcess/internal/policydoc"
)

// The tagOwners and route autoApprovers forms (F3-024, H-05) of the policy page. Same stateless
// draft flow as the rules forms (F3-023): the action POSTs the current editor text, the server
// applies one targeted policydoc edit and answers with the new raw text. A protected server tag
// (headscale.protected_tags, F3-009) cannot be deleted and its owner changes warn when they drop
// group:devops. The real gate for in-use tags is the preview's validation (F3-006); the form only
// warns.

// protectedLister reads the protected server tags.
type protectedLister interface {
	ProtectedTags(ctx context.Context) ([]string, error)
}

// tagRow is one tagOwners entry as the table shows it.
type tagRow struct {
	Tag       string
	Owners    []string
	Nodes     int
	Protected bool
	InText    bool // the tag appears outside its own tagOwners entry
}

// routeRow is one autoApprovers.routes entry.
type routeRow struct {
	CIDR      string
	Approvers []string
}

// policyTagsView is the tagOwners/autoApprovers form section plus the feedback of the last action.
type policyTagsView struct {
	Feedback draftFormFeedback
	Tags     []tagRow
	Routes   []routeRow
	Exit     []string
	ReadErr  string // the sections cannot be read out of this text
	LoadErr  string // the protected list or the nodes cannot be read: the forms stay closed
	FieldErr string // input name the error belongs to
	FieldMsg string
	General  string // a refusal that is not one field
	Warn     []string
	Applied  string
	// Sug are the owner/approver suggestions from the policy text: groups, tags, autogroup:member.
	Sug []string
}

// The default owner of a shared device tag (H-05.1). Dropping it from a protected tag's owners
// weakens the protection and warns.
const defaultTagOwner = "group:devops"

func (h *PolicyHandler) tagsView(ctx context.Context, text string) *policyTagsView {
	v := &policyTagsView{Sug: ownerSuggestions(text)}
	prot, err := h.cfg.Protected.ProtectedTags(ctx)
	if err != nil {
		v.LoadErr = "Tag formları kapalı: korumalı tag listesi okunamadı: " + err.Error()
		return v
	}
	nodes, err := h.cfg.Nodes.ListNodes(ctx)
	if err != nil {
		v.LoadErr = "Tag formları kapalı: node'lar okunamadı: " + err.Error()
		return v
	}
	owners, err := policydoc.TagOwners(text)
	if err != nil {
		v.ReadErr = err.Error()
		return v
	}
	aa, err := policydoc.ReadAutoApprovers(text)
	if err != nil {
		v.ReadErr = err.Error()
		return v
	}
	for tag, o := range owners {
		v.Tags = append(v.Tags, tagRow{
			Tag: tag, Owners: o,
			Nodes:     nodeTagCount(nodes, tag),
			Protected: slices.Contains(prot, tag),
			InText:    tagUsedInText(text, tag),
		})
	}
	sort.Slice(v.Tags, func(i, j int) bool { return v.Tags[i].Tag < v.Tags[j].Tag })
	for cidr, ap := range aa.Routes {
		v.Routes = append(v.Routes, routeRow{CIDR: cidr, Approvers: ap})
	}
	sort.Slice(v.Routes, func(i, j int) bool { return v.Routes[i].CIDR < v.Routes[j].CIDR })
	v.Exit = aa.ExitNode
	return v
}

// withTagsTable returns the tags view of text carrying the action feedback of fb. A view that
// already holds the tables (or a read/load error) is kept as it is.
func (h *PolicyHandler) withTagsTable(ctx context.Context, fb *policyTagsView, text string) *policyTagsView {
	if fb != nil && (fb.Tags != nil || fb.Routes != nil || fb.Exit != nil || fb.ReadErr != "" || fb.LoadErr != "") {
		return fb
	}
	v := h.tagsView(ctx, text)
	if fb != nil {
		v.FieldErr, v.FieldMsg, v.General, v.Warn, v.Applied = fb.FieldErr, fb.FieldMsg, fb.General, fb.Warn, fb.Applied
		v.Feedback = fb.Feedback
	}
	return v
}

// nodeTagCount counts the nodes carrying the tag.
func nodeTagCount(nodes []admin.AdminNode, tag string) int {
	n := 0
	for _, nd := range nodes {
		if slices.Contains(nd.Tags, tag) {
			n++
		}
	}
	return n
}

// tagUsedInText reports whether the tag appears outside its own tagOwners key (a rule, grant,
// test, nodeAttr or another owner list).
func tagUsedInText(text, tag string) bool {
	n := strings.Count(text, `"`+tag+`"`) + strings.Count(text, `"`+tag+`:`)
	return n > 1 // the tagOwners key itself is the one occurrence
}

// tagRefusal renders a failed tag/route operation; the text is never touched by a refusal.
func (h *PolicyHandler) tagRefusal(w http.ResponseWriter, r *http.Request, v policyPageView, field, msg string, err error) {
	v.Tags.Feedback = tagFeedback(r, field)
	switch {
	case err != nil && errors.Is(err, policydoc.ErrInvalidInput):
		v.Tags.FieldErr, v.Tags.FieldMsg = field, err.Error()
		h.render(w, r, http.StatusUnprocessableEntity, v)
	case err != nil:
		v.Tags.General = "İşlem yapılamadı; hiçbir şey değişmedi: " + err.Error()
		h.render(w, r, http.StatusUnprocessableEntity, v)
	default:
		v.Tags.FieldErr, v.Tags.FieldMsg = field, msg
		h.render(w, r, http.StatusUnprocessableEntity, v)
	}
}

// tagDraft parses the posted text for a tag/route operation and loads the fresh protected list;
// any failure renders and returns nil.
func (h *PolicyHandler) tagDraft(w http.ResponseWriter, r *http.Request) (*policydoc.Doc, []string, policyPageView, bool) {
	if _, ok := operatorActor(r); !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return nil, nil, policyPageView{}, false
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "geçersiz form", http.StatusBadRequest)
		return nil, nil, policyPageView{}, false
	}
	prot, err := h.cfg.Protected.ProtectedTags(r.Context())
	if err != nil {
		v := h.draftView(formText(r), r.PostFormValue("base_hash"))
		v.Tags = &policyTagsView{Feedback: postedTagFeedback(r), LoadErr: "Tag formları kapalı: korumalı tag listesi okunamadı: " + err.Error()}
		h.render(w, r, http.StatusServiceUnavailable, v)
		return nil, nil, policyPageView{}, false
	}
	text := formText(r)
	v := h.draftView(text, r.PostFormValue("base_hash"))
	v.Tags = &policyTagsView{Feedback: postedTagFeedback(r)}
	doc, err := policydoc.Parse(text)
	if err != nil {
		v.Tags.General = "Metin HuJSON olarak ayrıştırılamadı; hiçbir şey değişmedi: " + err.Error()
		h.render(w, r, http.StatusBadRequest, v)
		return nil, nil, policyPageView{}, false
	}
	return doc, prot, v, true
}

func (h *PolicyHandler) tagSet(w http.ResponseWriter, r *http.Request) {
	doc, prot, v, ok := h.tagDraft(w, r)
	if !ok {
		return
	}
	tagField, ownersField := "tag_new_name", "tag_new_owners"
	tag := strings.TrimSpace(r.PostFormValue(tagField))
	owners := formList(r, ownersField)
	edit := false
	if i, isEdit := formIndex(r, "tagset"); isEdit {
		edit = true
		tagField = fmt.Sprintf("tag_%d_name", i)
		ownersField = fmt.Sprintf("tag_%d_owners", i)
		tag = strings.TrimSpace(r.PostFormValue(tagField))
		owners = formList(r, ownersField)
	}
	if len(owners) == 0 {
		h.tagRefusal(w, r, v, ownersField, "Owner/approver listesi boş olamaz.", nil)
		return
	}
	if err := doc.SetTagOwners(tag, owners); err != nil {
		field := ownersField
		if strings.Contains(err.Error(), "tag name") {
			field = tagField
		}
		h.tagRefusal(w, r, v, field, "", err)
		return
	}
	v.Text = doc.Text()
	v.Tags = h.tagsView(r.Context(), v.Text)
	if slices.Contains(prot, tag) && !slices.Contains(owners, defaultTagOwner) {
		v.Tags.Warn = append(v.Tags.Warn,
			fmt.Sprintf("Korumalı tag %s: yeni owner'larda %s yok (zayıflatma).", tag, defaultTagOwner))
	}
	if edit {
		v.Tags.Applied = "Tag owner'ları draft'ta güncellendi; kaydedilmedi. Preview edip onaylayın."
	} else {
		v.Tags.Applied = "Tag draft'a eklendi; kaydedilmedi. Preview edip onaylayın."
	}
	h.render(w, r, http.StatusOK, v)
}

func (h *PolicyHandler) tagDelete(w http.ResponseWriter, r *http.Request) {
	doc, prot, v, ok := h.tagDraft(w, r)
	if !ok {
		return
	}
	tagField := "tag_new_name"
	tag := strings.TrimSpace(r.PostFormValue(tagField))
	if i, ok := formIndex(r, "tagdel"); ok {
		tagField = fmt.Sprintf("tag_%d_name", i)
		tag = strings.TrimSpace(r.PostFormValue(tagField))
	}
	if slices.Contains(prot, tag) {
		v.Tags.General = "Korumalı sunucu tag'i silinemez: " + tag + ". Ayarı Headscale ayarları sayfasından yapılır."
		h.render(w, r, http.StatusUnprocessableEntity, v)
		return
	}
	nodes, err := h.cfg.Nodes.ListNodes(r.Context())
	if err != nil {
		v.Tags.General = "Node'lar okunamadı; silme yapılmadı: " + err.Error()
		h.render(w, r, http.StatusServiceUnavailable, v)
		return
	}
	var warn []string
	if n := nodeTagCount(nodes, tag); n > 0 {
		warn = append(warn, fmt.Sprintf("%d node bu tag'i taşıyor.", n))
	}
	if tagUsedInText(formText(r), tag) {
		warn = append(warn, "Tag policy metninde başka bölümlerde geçiyor; silmek doğrulamayı bozabilir.")
	}
	if err := doc.DeleteTag(tag); err != nil {
		h.tagRefusal(w, r, v, tagField, "", err)
		return
	}
	v.Text = doc.Text()
	v.Tags = h.tagsView(r.Context(), v.Text)
	v.Tags.Warn = warn
	v.Tags.Applied = "Tag draft'tan silindi; kaydedilmedi. Preview doğrulayacak."
	h.render(w, r, http.StatusOK, v)
}

// routeTarget reads the CIDR and approvers of a route form action and the input names for errors.
func routeTarget(r *http.Request, edit bool, i int) (cidr, cidrField, approversField string, approvers []string) {
	if edit {
		cidrField = fmt.Sprintf("route_%d_cidr", i)
		approversField = fmt.Sprintf("route_%d_approvers", i)
	} else {
		cidrField, approversField = "route_new_cidr", "route_new_approvers"
	}
	return strings.TrimSpace(r.PostFormValue(cidrField)), cidrField, approversField, formList(r, approversField)
}

func (h *PolicyHandler) routeSet(w http.ResponseWriter, r *http.Request) {
	doc, _, v, ok := h.tagDraft(w, r)
	if !ok {
		return
	}
	edit := false
	i := 0
	if n, isEdit := formIndex(r, "routeset"); isEdit {
		edit, i = true, n
	}
	cidr, cidrField, approversField, approvers := routeTarget(r, edit, i)
	if len(approvers) == 0 {
		h.tagRefusal(w, r, v, approversField, "Owner/approver listesi boş olamaz.", nil)
		return
	}
	if err := doc.SetRouteApprovers(cidr, approvers); err != nil {
		field := approversField
		if strings.Contains(err.Error(), "route") {
			field = cidrField
		}
		h.tagRefusal(w, r, v, field, "", err)
		return
	}
	v.Text = doc.Text()
	v.Tags = h.tagsView(r.Context(), v.Text)
	if edit {
		v.Tags.Applied = "Route approver'ları draft'ta güncellendi; kaydedilmedi."
	} else {
		v.Tags.Applied = "Route draft'a eklendi; kaydedilmedi."
	}
	h.render(w, r, http.StatusOK, v)
}

func (h *PolicyHandler) routeDelete(w http.ResponseWriter, r *http.Request) {
	doc, _, v, ok := h.tagDraft(w, r)
	if !ok {
		return
	}
	cidrField := "route_new_cidr"
	cidr := strings.TrimSpace(r.PostFormValue(cidrField))
	if i, ok := formIndex(r, "routedel"); ok {
		cidrField = fmt.Sprintf("route_%d_cidr", i)
		cidr = strings.TrimSpace(r.PostFormValue(cidrField))
	}
	if err := doc.DeleteRoute(cidr); err != nil {
		h.tagRefusal(w, r, v, cidrField, "", err)
		return
	}
	v.Text = doc.Text()
	v.Tags = h.tagsView(r.Context(), v.Text)
	v.Tags.Applied = "Route draft'tan silindi; kaydedilmedi."
	h.render(w, r, http.StatusOK, v)
}

func (h *PolicyHandler) exitNodeSet(w http.ResponseWriter, r *http.Request) {
	doc, _, v, ok := h.tagDraft(w, r)
	if !ok {
		return
	}
	approvers := formList(r, "exit_approvers")
	if len(approvers) == 0 {
		h.tagRefusal(w, r, v, "exit_approvers", "Owner/approver listesi boş olamaz.", nil)
		return
	}
	if err := doc.SetExitNodeApprovers(approvers); err != nil {
		h.tagRefusal(w, r, v, "exit_approvers", "", err)
		return
	}
	v.Text = doc.Text()
	v.Tags = h.tagsView(r.Context(), v.Text)
	v.Tags.Applied = "exitNode approver'ları draft'ta güncellendi; kaydedilmedi."
	h.render(w, r, http.StatusOK, v)
}

// ownerSuggestions are the aliases a tag owner or route approver usually is: the policy's groups and
// tags and autogroup:member ("*" is not an owner). Free text stays allowed in the field.
func ownerSuggestions(text string) []string {
	var out []string
	for _, s := range aliasSuggestions(text) {
		if s != "*" {
			out = append(out, s)
		}
	}
	return out
}
