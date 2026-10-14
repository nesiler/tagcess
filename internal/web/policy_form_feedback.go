package web

import (
	"net/http"
	"slices"
	"strconv"
	"strings"
)

// draftFormFeedback retains only the rejected dialog's fields in the response.
// It never changes the policy text or its optimistic-concurrency fields.
type draftFormFeedback struct {
	Dialog string
	Values map[string]string
}

func rejectedDraftForm(r *http.Request, dialog, prefix string) draftFormFeedback {
	f := draftFormFeedback{Dialog: dialog, Values: make(map[string]string)}
	for name := range r.PostForm {
		if strings.HasPrefix(name, prefix) {
			f.Values[name] = r.PostFormValue(name)
		}
	}
	return f
}

func (f draftFormFeedback) value(name, fallback string) string {
	if value, ok := f.Values[name]; ok {
		return value
	}
	return fallback
}

func ruleFeedback(r *http.Request, prefix string) draftFormFeedback {
	dialog := "rule-add"
	if prefix != "add_" {
		i, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(prefix, "edit_"), "_"))
		if err != nil {
			return draftFormFeedback{}
		}
		dialog = ruleEditID(i)
	}
	return rejectedDraftForm(r, dialog, prefix)
}

func tagFeedback(r *http.Request, field string) draftFormFeedback {
	if field == "exit_approvers" {
		return rejectedDraftForm(r, "exit-edit", "exit_")
	}
	parts := strings.Split(field, "_")
	if len(parts) < 3 {
		return draftFormFeedback{}
	}
	prefix := parts[0] + "_" + parts[1] + "_"
	dialog := ""
	if parts[1] == "new" {
		switch parts[0] {
		case "tag":
			dialog = "tag-add"
		case "route":
			dialog = "route-add"
		}
	} else if i, err := strconv.Atoi(parts[1]); err == nil && i >= 0 {
		switch parts[0] {
		case "tag":
			dialog = tagEditID(i)
		case "route":
			dialog = routeEditID(i)
		}
	}
	if dialog == "" {
		return draftFormFeedback{}
	}
	return rejectedDraftForm(r, dialog, prefix)
}

// postedRuleFeedback identifies the one dialog that submitted the draft.
func postedRuleFeedback(r *http.Request) draftFormFeedback {
	if strings.HasSuffix(r.URL.Path, "/add") {
		return ruleFeedback(r, "add_")
	}
	for _, button := range []string{"edit", "del"} {
		if i, ok := formIndex(r, button); ok {
			return ruleFeedback(r, "edit_"+strconv.Itoa(i)+"_")
		}
	}
	return draftFormFeedback{}
}

func postedTagFeedback(r *http.Request) draftFormFeedback {
	if strings.HasSuffix(r.URL.Path, "/exitnode") {
		return tagFeedback(r, "exit_approvers")
	}
	kind := "route"
	if strings.Contains(r.URL.Path, "/tags/") {
		kind = "tag"
	}
	buttons := []string{"routeset", "routedel"}
	if kind == "tag" {
		buttons = []string{"tagset", "tagdel"}
	}
	for _, button := range buttons {
		if i, ok := formIndex(r, button); ok {
			return tagFeedback(r, kind+"_"+strconv.Itoa(i)+"_name")
		}
	}
	return tagFeedback(r, kind+"_new_name")
}

// summary offers non-interactive recovery when the source cannot be parsed/read.
// Unknown posted fields and the concurrency/CSRF metadata are never displayed.
func (f draftFormFeedback) summary() string {
	keys := make([]string, 0, len(f.Values))
	for k := range f.Values {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var b strings.Builder
	labels := map[string]string{"src": "src", "dst": "dst", "proto": "proto", "name": "Tag", "owners": "Owner'lar", "cidr": "Route (CIDR)", "approvers": "Approver'lar"}
	for _, k := range keys {
		field := k[strings.LastIndex(k, "_")+1:]
		if label, ok := labels[field]; ok {
			b.WriteString(label + ": " + f.Values[k] + "\n")
		}
	}
	return b.String()
}
