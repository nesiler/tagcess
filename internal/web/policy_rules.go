package web

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/tailscale/hujson"

	"github.com/nesiler/tagcess/internal/policydoc"
)

// The ACL rules form (F3-023, H-04) of the policy page. The draft is stateless (ADR 0020): a form
// action POSTs the editor text plus the operation's fields, the server applies one targeted
// policydoc edit and answers with the new raw text in the textarea. Saving stays F3-019's
// preview/approve flow; the form never writes anything.

// ruleRow is one acls entry as the table shows it.
type ruleRow struct {
	Index    int
	Action   string // always "accept" for display; "" arrives as accept
	Proto    string
	Src, Dst []string
}

// policyRulesView is the form section of the acls rules plus the feedback of the last action.
type policyRulesView struct {
	Feedback  draftFormFeedback
	Rows      []ruleRow
	HasGrants bool
	HasSSH    bool
	Sug       []string // src/dst suggestions: role groups (read-only), tags, autogroup:member, *
	ReadErr   string   // the rules cannot be read out of this text
	FieldErr  string   // input name the error belongs to
	FieldMsg  string
	General   string // a refusal that is not one field: stale, unknown index, unparseable text
	Applied   string // the action changed the draft (never saved)
}

// rulesView reads the form data out of a draft text.
func rulesView(text string) *policyRulesView {
	v := &policyRulesView{}
	doc, err := policydoc.Parse(text)
	if err != nil {
		v.ReadErr = err.Error()
		return v
	}
	rules, err := doc.ACLRules()
	if err != nil {
		v.ReadErr = err.Error()
		return v
	}
	for i, r := range rules {
		action := r.Action
		if action == "" {
			action = "accept"
		}
		v.Rows = append(v.Rows, ruleRow{Index: i, Action: action, Proto: r.Proto, Src: r.Src, Dst: r.Dst})
	}
	v.HasGrants = hasTopMember(text, "grants")
	v.HasSSH = hasTopMember(text, "ssh")
	v.Sug = aliasSuggestions(text)
	return v
}

// withRulesTable returns the rules view of text carrying the action feedback of fb. A view that
// already holds the table (or its read error) is kept as it is.
func withRulesTable(fb *policyRulesView, text string) *policyRulesView {
	if fb != nil && (fb.Rows != nil || fb.ReadErr != "") {
		return fb
	}
	v := rulesView(text)
	if fb != nil {
		v.FieldErr, v.FieldMsg, v.General, v.Applied = fb.FieldErr, fb.FieldMsg, fb.General, fb.Applied
		v.Feedback = fb.Feedback
	}
	return v
}

// hasTopMember reports whether the text has a top-level member called name.
func hasTopMember(text, name string) bool {
	obj, ok := topObject(text)
	if !ok {
		return false
	}
	return len(memberIndexesByName(obj, name)) > 0
}

// topObject parses the text and returns its root object.
func topObject(text string) (*hujson.Object, bool) {
	root, err := hujson.Parse([]byte(text))
	if err != nil {
		return nil, false
	}
	obj, ok := root.Value.(*hujson.Object)
	return obj, ok
}

// memberIndexesByName returns the indexes of the members whose name equals name, case-insensitive
// like Headscale matches section names.
func memberIndexesByName(obj *hujson.Object, name string) []int {
	var idx []int
	for i, m := range obj.Members {
		if lit, ok := m.Name.Value.(hujson.Literal); ok && lit.Kind() == '"' && strings.EqualFold(lit.String(), name) {
			idx = append(idx, i)
		}
	}
	return idx
}

// groupKeys returns the keys of the groups section in document order; the section belongs to
// Zitadel and is offered as a read-only suggestion source only.
func groupKeys(text string) []string {
	obj, ok := topObject(text)
	if !ok {
		return nil
	}
	idx := memberIndexesByName(obj, "groups")
	if len(idx) != 1 {
		return nil
	}
	g, ok := obj.Members[idx[0]].Value.Value.(*hujson.Object)
	if !ok {
		return nil
	}
	var out []string
	for _, m := range g.Members {
		if lit, ok := m.Name.Value.(hujson.Literal); ok && lit.Kind() == '"' && !strings.HasPrefix(lit.String(), "#") {
			out = append(out, lit.String())
		}
	}
	return out
}

// aliasSuggestions is the shared src/dst/owner suggestion list: the policy's role groups (from the
// Zitadel-owned groups section, read-only), the tagOwners tags, and the fixed aliases.
func aliasSuggestions(text string) []string {
	var out []string
	out = append(out, groupKeys(text)...)
	if owners, err := policydoc.TagOwners(text); err == nil {
		tags := make([]string, 0, len(owners))
		for tag := range owners {
			tags = append(tags, tag)
		}
		slices.Sort(tags)
		out = append(out, tags...)
	}
	return append(out, "autogroup:member", "*")
}

// ---- form helpers ----

// formLines reads a textarea value as one entry per line; blank lines go.
func formLines(r *http.Request, name string) []string {
	var out []string
	for _, l := range strings.Split(r.PostFormValue(name), "\n") {
		if s := strings.TrimSpace(l); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// formList reads a comma-separated input value.
func formList(r *http.Request, name string) []string {
	var out []string
	for _, p := range strings.Split(r.PostFormValue(name), ",") {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// formIndex reads the clicked row button's value.
func formIndex(r *http.Request, button string) (int, bool) {
	s := r.PostFormValue(button)
	if s == "" {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// expectedRule reads the hidden expected-* fields of a rule row's forms.
func expectedRule(r *http.Request, i int) policydoc.Rule {
	return policydoc.Rule{
		Action: r.PostFormValue(fmt.Sprintf("exp_%d_action", i)),
		Proto:  r.PostFormValue(fmt.Sprintf("exp_%d_proto", i)),
		Src:    r.PostForm[fmt.Sprintf("exp_%d_src", i)],
		Dst:    r.PostForm[fmt.Sprintf("exp_%d_dst", i)],
	}
}

// draftView opens the page view for a form action: the posted text stays, editing stays open and
// the rules feedback section is ready.
func (h *PolicyHandler) draftView(text, base string) policyPageView {
	return policyPageView{Text: text, BaseHash: base, Editable: true, Rules: &policyRulesView{}}
}

// ruleRefusal renders a failed rule operation: a field error, or a 409 band for a moved or missing
// rule. The text is never touched by a refused operation.
func (h *PolicyHandler) ruleRefusal(w http.ResponseWriter, r *http.Request, v policyPageView, prefix string, err error) {
	v.Rules.Feedback = ruleFeedback(r, prefix)
	switch {
	case errors.Is(err, policydoc.ErrStaleRule):
		v.Rules.General = "Kural bu arada değişti: güncel kural farklı. Yeniden yükleyip tekrar deneyin."
		h.render(w, r, http.StatusConflict, v)
	case errors.Is(err, policydoc.ErrNotFound):
		v.Rules.General = "Kural bulunamadı: liste değişmiş olabilir. Yeniden yükleyin."
		h.render(w, r, http.StatusConflict, v)
	default:
		v.Rules.FieldErr, v.Rules.FieldMsg = ruleFieldErr(prefix, err)
		h.render(w, r, http.StatusUnprocessableEntity, v)
	}
}

// ruleFieldErr maps a policydoc input error to the input it belongs to.
func ruleFieldErr(prefix string, err error) (field, msg string) {
	msg = err.Error()
	switch {
	case strings.Contains(msg, "proto"):
		return prefix + "proto", msg
	case strings.Contains(msg, "dst"):
		return prefix + "dst", msg
	case strings.Contains(msg, "src"):
		return prefix + "src", msg
	}
	return "", msg
}

// ruleDraft parses the posted text for a rule operation; a parse failure renders 400 and returns
// nil.
func (h *PolicyHandler) ruleDraft(w http.ResponseWriter, r *http.Request, base string) (*policydoc.Doc, policyPageView, bool) {
	text := formText(r)
	v := h.draftView(text, base)
	v.Rules.Feedback = postedRuleFeedback(r)
	doc, err := policydoc.Parse(text)
	if err != nil {
		v.Rules.General = "Metin HuJSON olarak ayrıştırılamadı; hiçbir şey değişmedi: " + err.Error()
		h.render(w, r, http.StatusBadRequest, v)
		return nil, v, false
	}
	return doc, v, true
}

func (h *PolicyHandler) ruleAdd(w http.ResponseWriter, r *http.Request) {
	if _, ok := operatorActor(r); !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "geçersiz form", http.StatusBadRequest)
		return
	}
	doc, v, ok := h.ruleDraft(w, r, r.PostFormValue("base_hash"))
	if !ok {
		return
	}
	rule := policydoc.Rule{
		Action: "accept",
		Proto:  r.PostFormValue("add_proto"),
		Src:    formLines(r, "add_src"),
		Dst:    formLines(r, "add_dst"),
	}
	if err := doc.AddACLRule(rule); err != nil {
		h.ruleRefusal(w, r, v, "add_", err)
		return
	}
	v.Text = doc.Text()
	v.Rules = rulesView(v.Text)
	v.Rules.Applied = "Kural draft'a eklendi; kaydedilmedi. Preview edip onaylayın."
	h.render(w, r, http.StatusOK, v)
}

func (h *PolicyHandler) ruleUpdate(w http.ResponseWriter, r *http.Request) {
	if _, ok := operatorActor(r); !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "geçersiz form", http.StatusBadRequest)
		return
	}
	i, ok := formIndex(r, "edit")
	if !ok {
		http.Error(w, "kural seçilmedi", http.StatusBadRequest)
		return
	}
	doc, v, ok := h.ruleDraft(w, r, r.PostFormValue("base_hash"))
	if !ok {
		return
	}
	prefix := fmt.Sprintf("edit_%d_", i)
	rule := policydoc.Rule{
		Proto: r.PostFormValue(prefix + "proto"),
		Src:   formLines(r, prefix+"src"),
		Dst:   formLines(r, prefix+"dst"),
	}
	if err := doc.UpdateACLRule(i, expectedRule(r, i), rule); err != nil {
		h.ruleRefusal(w, r, v, prefix, err)
		return
	}
	v.Text = doc.Text()
	v.Rules = rulesView(v.Text)
	v.Rules.Applied = "Kural draft'ta güncellendi; kaydedilmedi. Preview edip onaylayın."
	h.render(w, r, http.StatusOK, v)
}

func (h *PolicyHandler) ruleDelete(w http.ResponseWriter, r *http.Request) {
	if _, ok := operatorActor(r); !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "geçersiz form", http.StatusBadRequest)
		return
	}
	i, ok := formIndex(r, "del")
	if !ok {
		http.Error(w, "kural seçilmedi", http.StatusBadRequest)
		return
	}
	doc, v, ok := h.ruleDraft(w, r, r.PostFormValue("base_hash"))
	if !ok {
		return
	}
	if err := doc.DeleteACLRule(i, expectedRule(r, i)); err != nil {
		h.ruleRefusal(w, r, v, fmt.Sprintf("edit_%d_", i), err)
		return
	}
	v.Text = doc.Text()
	v.Rules = rulesView(v.Text)
	v.Rules.Applied = "Kural draft'tan silindi; kaydedilmedi. Preview edip onaylayın."
	h.render(w, r, http.StatusOK, v)
}
