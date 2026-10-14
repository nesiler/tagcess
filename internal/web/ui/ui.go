// Package ui holds the presentational components of the tagcess interface: buttons, pills, cards,
// tables, form controls, dialogs, diffs. They know nothing about tagcess itself; pages in
// internal/web compose them. Every class a component writes is defined in static/components.css,
// so pages never write CSS classes of their own (docs/ui-guide.md).
package ui

import (
	"context"
	"fmt"
	"hash/fnv"
	"strconv"
	"strings"

	"github.com/a-h/templ"
)

// Tone is the semantic colour of a pill, status dot or callout.
type Tone string

// The tones. Neutral has no colour of its own.
const (
	Neutral Tone = ""
	OK      Tone = "ok"
	Warn    Tone = "warn"
	Err     Tone = "err"
	Stale   Tone = "stale"
	Info    Tone = "info"
	Off     Tone = "off"
)

// Kind is the look of a button.
type Kind string

// The button kinds. Primary is the one main action of a screen; Danger is a destructive submit
// (usually inside a confirm dialog); the outline kinds mark an action's effect without shouting.
const (
	Default       Kind = ""
	Primary       Kind = "primary"
	Danger        Kind = "danger"
	WarnOutline   Kind = "warn"
	DangerOutline Kind = "danger-o"
	OKOutline     Kind = "ok-o"
	Ghost         Kind = "ghost"
)

// B describes a button. With Href it renders a link, otherwise a <button>.
type B struct {
	Kind  Kind
	Small bool
	Icon  string
	// Href makes the button a link. A disabled link renders as an inert span.
	Href string
	// Type is the button type; empty means "submit", the HTML default.
	Type     string
	Name     string
	Value    string
	Disabled bool
	// Title is the tooltip; use it to say why a disabled button is disabled.
	Title string
	Attrs templ.Attributes
}

func (b B) class() string {
	c := []string{"btn"}
	if b.Kind != Default {
		c = append(c, "btn-"+string(b.Kind))
	}
	if b.Small {
		c = append(c, "btn-sm")
	}
	return strings.Join(c, " ")
}

func (b B) buttonType() string {
	if b.Type == "" {
		return "submit"
	}
	return b.Type
}

// Crumb is one step of the breadcrumb above a page title. The last crumb has no Href.
type Crumb struct {
	Label string
	Href  string
}

// H is a page header. Sub is at most one short line; a longer explanation goes into Tip, which is
// shown as an info tooltip next to the title.
type H struct {
	Title  string
	Sub    string
	Tip    string
	Crumbs []Crumb
}

// C is a card. Desc is the card's explanation: with a Title it is shown as an info tooltip next to
// the title (hover and keyboard focus), so the card body stays short; without a Title it is a
// muted line at the top of the card.
type C struct {
	ID    string
	Title string
	Desc  string
	// Right is shown at the right end of the title row (a link, a pill).
	Right templ.Component
	// Flush removes the padding; tables and lists that touch the card edge use it.
	Flush bool
	// Wide spans every column of the enclosing Grid.
	Wide bool
}

func (c C) class() string {
	out := "card"
	if c.Flush {
		out += " card-flush"
	}
	if c.Wide {
		out += " span-all"
	}
	return out
}

// N is a callout: a toned box with a title and a body.
type N struct {
	Tone  Tone
	Title string
	// Icon overrides the tone's icon.
	Icon string
}

func (n N) icon() string {
	if n.Icon != "" {
		return n.Icon
	}
	switch n.Tone {
	case OK:
		return "ok"
	case Warn:
		return "warn"
	case Err:
		return "error"
	case Stale:
		return "clock"
	default:
		return "info"
	}
}

func (n N) role() string {
	if n.Tone == Err || n.Tone == Warn {
		return "alert"
	}
	return "status"
}

// Tab is one tab of a Tabs bar.
type Tab struct {
	Key   string
	Label string
	Href  string
	// Count is shown as a small counter after the label when not empty.
	Count string
}

// Tile is one number on a dashboard tile.
type Tile struct {
	Icon  string
	Label string
	Value string
	Sub   string
	// Href makes Sub a link.
	Href string
}

// F is a form field row: label and help on the left, the control (children) on the right.
type F struct {
	Label string
	// For is the id of the control the label names.
	For  string
	Help string
	// Err is the server's validation message for this field: shown under the control, which is
	// marked aria-invalid and described by it.
	Err string
}

// In is a text input. Options turns it into a combobox: the browser suggests the known values
// (a <datalist>), and the person can still type any other value. Without options it is a plain input.
type In struct {
	ID   string
	Name string
	// Label is the accessible name (aria-label) of an input that has no visible <label>, such as
	// the inputs of a repeated row or a table cell.
	Label       string
	Value       string
	Type        string
	Placeholder string
	Required    bool
	Disabled    bool
	ReadOnly    bool
	Options     []string
	// Pattern is the HTML pattern the browser checks; Msg is the plain message shown when the
	// value does not fit (live, ui.js). The server still validates every value.
	Pattern string
	Msg     string
	// Autocomplete overrides the default "off" (e.g. "new-password" keeps a secret field out of the
	// browser's password manager).
	Autocomplete string
	Attrs        templ.Attributes
}

func (i In) autocomplete() string {
	if i.Autocomplete == "" {
		return "off"
	}
	return i.Autocomplete
}

// listID is the id of the input's <datalist>; empty when the input has no options.
func (i In) listID() string {
	if len(i.Options) == 0 {
		return ""
	}
	base := i.ID
	if base == "" {
		base = i.Name
	}
	return base + "-opts"
}

func (i In) inputType() string {
	if i.Type == "" {
		return "text"
	}
	return i.Type
}

// TA is a textarea. Code switches to the monospace style for config and policy text.
type TA struct {
	ID   string
	Name string
	// Label is the accessible name (aria-label) when no visible <label> names the textarea.
	Label       string
	Value       string
	Rows        int
	Placeholder string
	Code        bool
	// Editor turns the textarea into a code editor in the browser (CodeMirror 6, static/editor.js,
	// loaded by ui.js): line numbers and highlighting for the named language ("hujson"). The
	// textarea stays the form field, so the form posts the same value with or without script.
	Editor string
	// ErrorLine marks the line (1-based) a validation reported, in the editor; 0 marks none.
	ErrorLine int
	// LinePattern is a regular expression every non-empty line must match (checked live by ui.js);
	// Msg is the message shown when a line does not. The server still validates every value.
	LinePattern string
	Msg         string
	Required    bool
	Disabled    bool
	ReadOnly    bool
	Attrs       templ.Attributes
}

func (t TA) class() string {
	if t.Code {
		return "input input-code"
	}
	return "input"
}

func (t TA) rows() int {
	if t.Rows <= 0 {
		return 3
	}
	return t.Rows
}

// Opt is one option of a Select.
type Opt struct {
	Value string
	Label string
}

// Sel is a select box; the option whose Value equals Selected is selected.
type Sel struct {
	ID   string
	Name string
	// Label is the accessible name (aria-label) when no visible <label> names the select.
	Label    string
	Options  []Opt
	Selected string
	Disabled bool
	Attrs    templ.Attributes
}

// Chk is a checkbox with its label and an optional hint under it.
type Chk struct {
	ID       string
	Name     string
	Value    string
	Label    string
	Hint     string
	Checked  bool
	Disabled bool
	Attrs    templ.Attributes
}

func (c Chk) value() string {
	if c.Value == "" {
		return "1"
	}
	return c.Value
}

// RG is a group of radio buttons that share Name; the option whose Value equals Selected is checked.
// Legend names the group for screen readers and is shown above the options when set.
type RG struct {
	Name     string
	Legend   string
	Selected string
	Options  []Radio
	Disabled bool
}

// Radio is one option of an RG, with an optional hint under its label.
type Radio struct {
	ID    string
	Value string
	Label string
	Hint  string
}

// Link is one row of a LinkList: an icon, a title, a description and the target.
type Link struct {
	Href  string
	Icon  string
	Title string
	Desc  string
}

// Hidden is a hidden form field.
type Hidden struct {
	Name  string
	Value string
}

// D is a modal dialog, opened by a control with data-dialog-open set to its ID (ui.js).
type D struct {
	// Open requests a modal after rendering, for example after validation fails.
	Open  bool
	ID    string
	Title string
	Desc  string
	Wide  bool
}

func (d D) class() string {
	if d.Wide {
		return "dlg dlg-wide"
	}
	return "dlg"
}

// L is a ListTable: a table sorted and searched in the browser.
type L struct {
	// Label names the table for screen readers and the search box ("Siteler").
	Label string
	// Search adds a box above the rows that filters them by their text.
	Search bool
	// In places the table inside a padded card, running edge to edge like TableIn; otherwise it
	// sits in its own flush card like Table.
	In bool
	// Foot is an optional line under the rows, inside the same card (a Pager).
	Foot templ.Component
}

func (l L) class() string {
	if l.In {
		return "tlist-in"
	}
	return "card card-flush"
}

func (l L) scrollClass() string {
	if l.In {
		return "table-in tscroll"
	}
	return "tscroll"
}

// searchID is a stable id for the search input so htmx can restore its focus after a refresh swap.
func (l L) searchID() string {
	var b strings.Builder
	for _, r := range strings.ToLower(l.Label) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case b.Len() > 0 && !strings.HasSuffix(b.String(), "-"):
			b.WriteByte('-')
		}
	}
	return "tsearch-" + strings.Trim(b.String(), "-")
}

func (l L) searchLabel() string {
	if l.Label == "" {
		return "Tabloda ara"
	}
	return l.Label + " içinde ara"
}

// P is a pager line under a table. An empty Prev or Next renders that step disabled.
type P struct {
	Info string
	Prev string
	Next string
	// Label names the navigation landmark; "Sayfalama" when empty.
	Label string
}

func (p P) label() string {
	if p.Label == "" {
		return "Sayfalama"
	}
	return p.Label
}

func toneClass(prefix string, t Tone) string {
	if t == Neutral {
		return prefix
	}
	return prefix + " " + prefix + "-" + string(t)
}

func pillClass(t Tone, flat bool) string {
	c := toneClass("pill", t)
	if flat {
		c += " pill-flat"
	}
	return c
}

func gridClass(cols int) string {
	if cols < 2 || cols > 5 {
		cols = 2
	}
	return "grid g" + string(rune('0'+cols))
}

// optAttrs returns the attributes whose value is not empty, merged over extra. HTML forbids an empty
// id, and an empty title or placeholder is noise, so optional attributes are written only when set.
func optAttrs(extra templ.Attributes, kv ...string) templ.Attributes {
	out := templ.Attributes{}
	for k, v := range extra {
		out[k] = v
	}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] != "" {
			out[kv[i]] = kv[i+1]
		}
	}
	return out
}

func (b B) attrs() templ.Attributes {
	return optAttrs(b.Attrs, "title", b.Title, "name", b.Name, "value", b.Value)
}

func (i In) attrs(ctx context.Context) templ.Attributes {
	return optAttrs(describeControl(ctx, i.ID, i.Attrs), "id", i.ID, "placeholder", i.Placeholder, "aria-label", i.Label, "list", i.listID(),
		"pattern", i.Pattern, "data-msg", i.Msg)
}

func (t TA) attrs(ctx context.Context) templ.Attributes {
	errLine := ""
	if t.Editor != "" && t.ErrorLine > 0 {
		errLine = strconv.Itoa(t.ErrorLine)
	}
	return optAttrs(describeControl(ctx, t.ID, t.Attrs), "id", t.ID, "placeholder", t.Placeholder, "aria-label", t.Label,
		"data-code-editor", t.Editor, "data-error-line", errLine, "data-line-pattern", t.LinePattern, "data-msg", t.Msg)
}

func (s Sel) attrs(ctx context.Context) templ.Attributes {
	return optAttrs(describeControl(ctx, s.ID, s.Attrs), "id", s.ID, "aria-label", s.Label)
}

func (c Chk) attrs() templ.Attributes {
	return optAttrs(c.Attrs, "id", c.ID)
}

func (c C) attrs() templ.Attributes {
	return optAttrs(nil, "id", c.ID)
}

// Field descriptions are scoped to the children render; only the labelled control inherits them.
type fieldDescriptionKey struct{}

func (f F) helpID() string {
	if f.For == "" || f.Help == "" {
		return ""
	}
	return f.For + "-help"
}

func (f F) errID() string {
	if f.For == "" || f.Err == "" {
		return ""
	}
	return f.For + "-err"
}
func withFieldDescription(ctx context.Context, f F) context.Context {
	return context.WithValue(ctx, fieldDescriptionKey{}, f)
}
func describeControl(ctx context.Context, id string, attrs templ.Attributes) templ.Attributes {
	out := optAttrs(attrs)
	f, ok := ctx.Value(fieldDescriptionKey{}).(F)
	if !ok || id == "" || id != f.For {
		return out
	}
	for _, ref := range []string{f.helpID(), f.errID()} {
		if ref == "" {
			continue
		}
		before := ""
		if v, ok := out["aria-describedby"]; ok {
			before = fmt.Sprint(v)
		}
		out["aria-describedby"] = strings.TrimSpace(before + " " + ref)
	}
	if f.errID() != "" {
		out["aria-invalid"] = "true"
	}
	return out
}
func (d D) attrs() templ.Attributes {
	attrs := templ.Attributes{}
	if d.Desc != "" {
		attrs["aria-describedby"] = d.ID + "-desc"
	}
	if d.Open {
		attrs["data-dialog-auto-open"] = true
	}
	return attrs
}

// MS is a multi-value input: a list of values such as roles, tags or owners. In the browser
// (ui.js) the values become removable chips and an input that suggests the known Options while
// still accepting any typed value. The form field itself is the plain control underneath (a
// textarea with one value per line, or an input with Sep between values), so the form posts the
// same value with or without script, and with no Options it simply has no suggestions.
type MS struct {
	ID   string
	Name string
	// Label is the accessible name when no visible <label> names the field.
	Label       string
	Values      []string
	Options     []string
	Placeholder string
	// Sep joins the values in a single-line input (", "); empty means a textarea, one per line.
	Sep      string
	Rows     int
	Required bool
	Disabled bool
	Attrs    templ.Attributes
}

func (m MS) listID() string {
	if len(m.Options) == 0 {
		return ""
	}
	return m.ID + "-opts"
}

func (m MS) value() string {
	if m.Sep == "" {
		return strings.Join(m.Values, "\n")
	}
	return strings.Join(m.Values, m.Sep)
}

func (m MS) rows() int {
	if m.Rows <= 0 {
		return 3
	}
	return m.Rows
}

func (m MS) attrs(ctx context.Context) templ.Attributes {
	sep := m.Sep
	if sep == "" {
		sep = "\n"
	}
	return optAttrs(describeControl(ctx, m.ID, m.Attrs), "id", m.ID, "aria-label", m.Label, "placeholder", m.Placeholder,
		"data-multi-sep", sep, "data-multi-list", m.listID())
}

// tipID derives the tooltip id from its text, so the markup is deterministic (golden files) and
// two tooltips with the same text simply describe their buttons with the same words.
func tipID(text string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(text))
	return fmt.Sprintf("tip-%08x", h.Sum32())
}

func statusTextClass(t Tone) string {
	return toneClass("stt", t)
}

// SW is an on/off switch that submits its form: pressing it posts Name=Value (the state it moves
// to), so a change can go through a preview first. On is the current state. Disabled with Title
// says why it cannot be used. The visible text says the current state; Label names the switch for
// screen readers.
type SW struct {
	Name     string
	Value    string
	On       bool
	Label    string
	OnText   string
	OffText  string
	Disabled bool
	Title    string
}

func (s SW) checked() string {
	if s.On {
		return "true"
	}
	return "false"
}

func (s SW) stateText() string {
	if s.On {
		if s.OnText != "" {
			return s.OnText
		}
		return "Açık"
	}
	if s.OffText != "" {
		return s.OffText
	}
	return "Kapalı"
}

func (s SW) attrs() templ.Attributes {
	return optAttrs(nil, "title", s.Title, "aria-description", s.Title)
}
