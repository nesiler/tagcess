package ui

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/a-h/templ"
)

func render(t *testing.T, c templ.Component) string {
	t.Helper()
	var b bytes.Buffer
	if err := c.Render(context.Background(), &b); err != nil {
		t.Fatalf("render: %v", err)
	}
	return b.String()
}

// Every icon name written as a literal in the interface exists, so a typo cannot draw an empty
// icon unnoticed. It scans the hand-written .templ and .go files of internal/web.
func TestIconNamesExist(t *testing.T) {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`Icon(?:Sm)?\("([^"]+)"\)`),
		regexp.MustCompile(`Icon:\s*"([^"]+)"`),
		regexp.MustCompile(`ui\.Empty\("([^"]+)"`),
		regexp.MustCompile(`\bEmpty\("([^"]+)"`),
	}
	var files []string
	for _, glob := range []string{"../*.templ", "../*.go", "*.templ"} {
		m, err := filepath.Glob(glob)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, m...)
	}
	seen := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_templ.go") || strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, re := range patterns {
			for _, m := range re.FindAllStringSubmatch(string(src), -1) {
				seen++
				if _, ok := iconBodies[m[1]]; !ok {
					t.Errorf("%s: unknown icon %q (add it to icons.go)", f, m[1])
				}
			}
		}
	}
	if seen == 0 {
		t.Fatal("no icon names found; the scan is broken")
	}
}

func TestParseDiff(t *testing.T) {
	d := parseDiff("--- a\n+++ b\n@@ -1,2 +1,2 @@\n keep\n-old\n+new\n--- removed dashes\n")
	if d.adds != 1 || d.dels != 2 {
		t.Errorf("adds/dels = %d/%d, want 1/2", d.adds, d.dels)
	}
	want := []diffLine{
		{"ln ln-hunk", "@@ -1,2 +1,2 @@"},
		{"ln", " keep"},
		{"ln ln-del", "-old"},
		{"ln ln-add", "+new"},
		{"ln ln-del", "--- removed dashes"},
	}
	if len(d.lines) != len(want) {
		t.Fatalf("lines = %+v, want %+v", d.lines, want)
	}
	for i := range want {
		if d.lines[i] != want[i] {
			t.Errorf("line %d = %+v, want %+v", i, d.lines[i], want[i])
		}
	}
}

// The site diffs (change.lineDiff) have no headers: a removed "-- note" line and an added "++x"
// line start like file headers and must still be shown and counted.
func TestParseDiff_HeaderlessKeepsDashLines(t *testing.T) {
	d := parseDiff("--- note\n+++x\n-a\n+b\n")
	if d.adds != 2 || d.dels != 2 || len(d.lines) != 4 {
		t.Fatalf("adds/dels/lines = %d/%d/%+v, want 2/2/4 lines", d.adds, d.dels, d.lines)
	}
	if d.lines[0] != (diffLine{"ln ln-del", "--- note"}) || d.lines[1] != (diffLine{"ln ln-add", "+++x"}) {
		t.Errorf("lines = %+v", d.lines)
	}
}

// The pager is a labelled nav; a missing step is a disabled link, not a (submit) button.
func TestPagerIsLabelledNavWithoutButtons(t *testing.T) {
	out := render(t, Pager(P{Info: "Sayfa 1", Next: "/audit?page=2"}))
	for _, w := range []string{`<nav class="pager" aria-label="Sayfalama">`, `<span class="btn btn-sm" aria-disabled="true">Önceki</span>`, `href="/audit?page=2" rel="next"`} {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q in %s", w, out)
		}
	}
	if strings.Contains(out, "<button") {
		t.Errorf("pager renders a button: %s", out)
	}
	if out := render(t, Pager(P{Label: "Kayıt sayfaları"})); !strings.Contains(out, `aria-label="Kayıt sayfaları"`) {
		t.Errorf("custom label missing: %s", out)
	}
}

func TestDiff_EmptySaysUnchanged(t *testing.T) {
	out := render(t, Diff("Caddy", ""))
	if !strings.Contains(out, "değişmiyor") || strings.Contains(out, "ln-add") {
		t.Errorf("empty diff = %s", out)
	}
}

func TestBtn(t *testing.T) {
	tests := []struct {
		name string
		b    B
		want []string
		not  []string
	}{
		{"submit", B{Kind: Primary}, []string{`<button class="btn btn-primary" type="submit"`}, []string{"href", `title=""`, `name=""`}},
		{"link", B{Href: "/sites/new", Small: true}, []string{`<a class="btn btn-sm" href="/sites/new"`}, []string{"<button"}},
		{"disabled link", B{Href: "/x", Disabled: true, Title: "neden"}, []string{`<span class="btn"`, `role="link"`, `aria-disabled="true"`, `title="neden"`, `aria-description="neden"`}, []string{"href"}},
		{"disabled button", B{Type: "button", Disabled: true}, []string{`type="button" disabled`}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := render(t, Btn(tc.b))
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Errorf("missing %q in %s", w, out)
				}
			}
			for _, w := range tc.not {
				if strings.Contains(out, w) {
					t.Errorf("unexpected %q in %s", w, out)
				}
			}
		})
	}
}

// Optional attributes are written only when set: no empty id, which HTML forbids.
func TestNoEmptyIDs(t *testing.T) {
	for name, c := range map[string]templ.Component{
		"input":    Input(In{Name: "n"}),
		"textarea": Textarea(TA{Name: "n"}),
		"select":   Select(Sel{Name: "n"}),
		"check":    Check(Chk{Name: "n"}),
		"card":     Card(C{Title: "t"}),
	} {
		if out := render(t, c); strings.Contains(out, `id=""`) || strings.Contains(out, `placeholder=""`) {
			t.Errorf("%s writes an empty attribute: %s", name, out)
		}
	}
}

func TestTabsMarkActive(t *testing.T) {
	out := render(t, Tabs([]Tab{{Key: "a", Label: "A", Href: "/a"}, {Key: "b", Label: "B", Href: "/b", Count: "3"}}, "b"))
	if !strings.Contains(out, `href="/b" aria-current="page"`) || strings.Contains(out, `href="/a" aria-current`) {
		t.Errorf("tabs = %s", out)
	}
	if !strings.Contains(out, `<span class="cnt">3</span>`) {
		t.Errorf("tab count missing: %s", out)
	}
}

func TestSelectMarksSelected(t *testing.T) {
	out := render(t, Select(Sel{Name: "k", Selected: "b", Options: []Opt{{"a", "A"}, {"b", "B"}}}))
	if !strings.Contains(out, `<option value="b" selected>`) || strings.Contains(out, `<option value="a" selected>`) {
		t.Errorf("select = %s", out)
	}
}

// A radio group checks exactly the selected option, an empty value included, and keeps one name.
func TestRadioGroupChecksSelected(t *testing.T) {
	g := RG{Name: "k", Options: []Radio{{ID: "k-none", Value: "", Label: "yok"}, {ID: "k-a", Value: "a", Label: "A"}}}
	out := render(t, RadioGroup(g))
	if !strings.Contains(out, `name="k" value="" checked`) || strings.Contains(out, `value="a" checked`) {
		t.Errorf("empty selection: %s", out)
	}
	g.Selected = "a"
	out = render(t, RadioGroup(g))
	if !strings.Contains(out, `id="k-a" name="k" value="a" checked`) || strings.Contains(out, `value="" checked`) {
		t.Errorf("selected a: %s", out)
	}
	if strings.Count(out, `type="radio"`) != 2 {
		t.Errorf("want 2 radios: %s", out)
	}
}

// A fold is closed by default and passes its attributes; a link list links every row.
func TestFoldAndLinkList(t *testing.T) {
	out := render(t, Fold("eski", templ.Attributes{"data-x": "1"}))
	if !strings.Contains(out, `<details class="fold" data-x="1">`) || strings.Contains(out, " open") {
		t.Errorf("fold = %s", out)
	}
	out = render(t, LinkList([]Link{{Href: "/a", Title: "A", Desc: "d"}, {Href: "/b", Title: "B"}}))
	if !strings.Contains(out, `href="/a"`) || !strings.Contains(out, `href="/b"`) || !strings.Contains(out, "<small>d</small>") {
		t.Errorf("links = %s", out)
	}
}

// Every class a component writes is defined in static/components.css.
func TestComponentClassesAreDefined(t *testing.T) {
	css, err := os.ReadFile("../static/components.css")
	if err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob("*.templ")
	if err != nil {
		t.Fatal(err)
	}
	classAttr := regexp.MustCompile(`class="([^"]+)"`)
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range classAttr.FindAllStringSubmatch(string(src), -1) {
			for _, c := range strings.Fields(m[1]) {
				if !strings.Contains(string(css), "."+c) {
					t.Errorf("%s: class %q is not defined in components.css", f, c)
				}
			}
		}
	}
}

// U-1 (K-3): ListTable marks the table for the browser's sort and search and keeps the search box
// hidden until ui.js shows it, so without script the page is the plain table.
func TestListTable(t *testing.T) {
	rows := templ.Raw(`<thead><tr><th>Ad</th></tr></thead><tbody><tr><td>a</td></tr></tbody>`)
	cases := []struct {
		name    string
		l       L
		want    []string
		notWant []string
	}{
		{"search", L{Label: "Siteler", Search: true}, []string{
			`class="card card-flush" data-table`, `<table data-sortable aria-label="Siteler"`,
			`data-table-tools hidden`, `<span class="sr-only">Siteler içinde ara</span>`, `data-table-search`,
			`role="status" aria-live="polite" data-table-count`, `data-table-none hidden`,
		}, nil},
		{"sort only", L{Label: "Sürümler"}, []string{`<table data-sortable aria-label="Sürümler"`, `class="tscroll"`},
			[]string{`data-table-search`, `data-table-none`}},
		{"inside a card with a pager", L{Label: "Çözülmüş", In: true, Foot: Pager(P{Info: "Sayfa 1 / 2", Next: "/x?p=2"})},
			[]string{`class="tlist-in" data-table`, `class="table-in tscroll"`, `class="pager"`}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := renderWith(t, ListTable(tc.l), rows)
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Errorf("missing %q in\n%s", w, out)
				}
			}
			for _, w := range tc.notWant {
				if strings.Contains(out, w) {
					t.Errorf("unexpected %q in\n%s", w, out)
				}
			}
		})
	}
}

// U-9: inputs without a visible label get an accessible name; an editor textarea carries the
// language and the error line for editor.js, and nothing without Editor.
func TestControlLabelsAndEditorAttrs(t *testing.T) {
	cases := []struct {
		name    string
		c       templ.Component
		want    []string
		notWant []string
	}{
		{"input", Input(In{Name: "value", Label: "Kayıt değeri"}), []string{`aria-label="Kayıt değeri"`}, nil},
		{"select", Select(Sel{Name: "code", Label: "HTTP kodu"}), []string{`aria-label="HTTP kodu"`}, nil},
		{"textarea", Textarea(TA{Name: "t", Label: "Not"}), []string{`aria-label="Not"`}, []string{"data-code-editor"}},
		{"editor", Textarea(TA{Name: "text", Editor: "hujson", ErrorLine: 4}), []string{`data-code-editor="hujson"`, `data-error-line="4"`}, nil},
		{"editor without error", Textarea(TA{Name: "text", Editor: "hujson"}), []string{`data-code-editor="hujson"`}, []string{"data-error-line"}},
		{"error line needs an editor", Textarea(TA{Name: "text", ErrorLine: 4}), nil, []string{"data-error-line", "data-code-editor"}},
		{"no label, no attribute", Input(In{Name: "x"}), nil, []string{"aria-label"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := render(t, tc.c)
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Errorf("missing %q in %s", w, out)
				}
			}
			for _, w := range tc.notWant {
				if strings.Contains(out, w) {
					t.Errorf("unexpected %q in %s", w, out)
				}
			}
		})
	}
}

// U-5: the inline editor is closed by default (details/summary, no script) and holds its form.
func TestInlineEdit(t *testing.T) {
	out := renderWith(t, InlineEdit("Düzenle"), templ.Raw(`<form id="f"></form>`))
	for _, w := range []string{`<details class="iedit">`, `Düzenle</summary>`, `<div class="iedit-body"><form id="f"></form></div>`} {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q in %s", w, out)
		}
	}
	if strings.Contains(out, "<details class=\"iedit\" open") {
		t.Error("the inline editor must start closed")
	}
}

func renderWith(t *testing.T, c templ.Component, children templ.Component) string {
	t.Helper()
	var b bytes.Buffer
	if err := c.Render(templ.WithChildren(context.Background(), children), &b); err != nil {
		t.Fatalf("render: %v", err)
	}
	return b.String()
}

func TestAccessibleComponentDescriptions(t *testing.T) {
	for _, control := range []templ.Component{
		Input(In{ID: "host", Attrs: templ.Attributes{"aria-describedby": "existing"}}),
		Textarea(TA{ID: "host", Attrs: templ.Attributes{"aria-describedby": "existing"}}),
		Select(Sel{ID: "host", Attrs: templ.Attributes{"aria-describedby": "existing"}}),
	} {
		var b bytes.Buffer
		ctx := templ.WithChildren(context.Background(), control)
		if err := Field(F{For: "host", Label: "Host", Help: "DNS adı"}).Render(ctx, &b); err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{`id="host-help"`, `aria-describedby="existing host-help"`} {
			if !strings.Contains(b.String(), want) {
				t.Errorf("missing %s in %s", want, b.String())
			}
		}
	}
	out := render(t, Dialog(D{ID: "confirm", Title: "Onay", Desc: "İşlemi doğrulayın"}))
	for _, want := range []string{`aria-describedby="confirm-desc"`, `id="confirm-desc"`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s in %s", want, out)
		}
	}
	if out := render(t, Dialog(D{ID: "plain", Title: "Onay"})); strings.Contains(out, "aria-describedby") {
		t.Error("dialog without description has a dangling reference")
	}
	if out := render(t, Tabs([]Tab{{Key: "a", Label: "A", Href: "/a"}}, "a")); !strings.Contains(out, `aria-label="Alt menü"`) {
		t.Error("secondary navigation is unnamed")
	}
	out = render(t, Btn(B{Href: "/apply", Disabled: true, Title: "Bakım sürüyor"}))
	if !strings.Contains(out, `aria-description="Bakım sürüyor"`) || strings.Contains(out, `href=`) {
		t.Errorf("disabled action must describe its reason without navigating: %s", out)
	}
	out = render(t, Secret("example"))
	if !strings.Contains(out, `data-copy-status`) || !strings.Contains(out, `aria-live="polite"`) {
		t.Error("copy feedback lacks an announcement region")
	}
}

func TestDialogReopensAfterValidation(t *testing.T) {
	out := render(t, Dialog(D{ID: "retry", Title: "Tekrar dene", Open: true}))
	if !strings.Contains(out, "data-dialog-auto-open") {
		t.Errorf("modal reopen marker missing: %s", out)
	}
	if out := render(t, Dialog(D{ID: "closed"})); strings.Contains(out, "data-dialog-auto-open") {
		t.Error("normal dialogs must stay closed")
	}
}

// A card's description is a tooltip next to its title: a described info button, the text in a
// role=tooltip element, and no paragraph under the title.
func TestCardDescIsTooltip(t *testing.T) {
	out := render(t, Card(C{Title: "Cihazlar", Desc: "Headscale'den okunur."}))
	for _, want := range []string{`class="tip"`, `aria-label="Bilgi"`, `role="tooltip"`, "Headscale&#39;den okunur."} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s in %s", want, out)
		}
	}
	id := regexp.MustCompile(`aria-describedby="(tip-[0-9a-f]+)"`).FindStringSubmatch(out)
	if id == nil || !strings.Contains(out, `id="`+id[1]+`"`) {
		t.Errorf("tooltip button is not described by its text: %s", out)
	}
	if strings.Contains(out, "card-desc") {
		t.Error("a titled card still prints its description as a paragraph")
	}
	if out := render(t, Card(C{Desc: "Yalnız açıklama"})); !strings.Contains(out, "card-desc") || strings.Contains(out, "tip-btn") {
		t.Errorf("an untitled card keeps its description visible: %s", out)
	}
	if out := render(t, Tip("")); strings.TrimSpace(out) != "" {
		t.Errorf("empty tip renders %q", out)
	}
	if out := render(t, PageHead(H{Title: "Pano", Tip: "Kaynaklar"})); !strings.Contains(out, `role="tooltip"`) {
		t.Error("page head tip missing")
	}
}

// A simple state is coloured text with its time, never a chip.
func TestStatusTextIsPlainText(t *testing.T) {
	out := render(t, StatusText(OK, "güncel", "2026-10-05 14:02"))
	if strings.Contains(out, "pill") || !strings.Contains(out, "stt-ok") || !strings.Contains(out, ">güncel<") || !strings.Contains(out, ">2026-10-05 14:02<") {
		t.Errorf("status text: %s", out)
	}
	if out := render(t, StatusText(Off, "bilinmiyor", "")); strings.Contains(out, "stt-at") {
		t.Errorf("empty time renders: %s", out)
	}
}

// The multi-value field posts through a plain control (textarea by default, input with Sep), with
// the known options as a datalist; without options it is just the plain control.
func TestMultiSelectFallsBackToPlainControl(t *testing.T) {
	out := render(t, MultiSelect(MS{ID: "roles", Name: "roles", Values: []string{"devops", "yazilim"}, Options: []string{"devops", "muhasebe"}}))
	for _, want := range []string{`data-multi`, `<textarea`, `name="roles"`, "devops\nyazilim</textarea>", `data-multi-list="roles-opts"`, `<datalist id="roles-opts"><option value="devops"></option><option value="muhasebe"></option></datalist>`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in %s", want, out)
		}
	}
	out = render(t, MultiSelect(MS{ID: "owners", Name: "owners", Values: []string{"group:devops", "carol@"}, Sep: ", "}))
	for _, want := range []string{`<input`, `value="group:devops, carol@"`, `data-multi-sep=", "`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in %s", want, out)
		}
	}
	if strings.Contains(out, "datalist") || strings.Contains(out, "data-multi-list") {
		t.Errorf("no options must mean no suggestion list: %s", out)
	}
	out = render(t, Input(In{ID: "cert", Name: "cert", Options: []string{"auto"}}))
	if !strings.Contains(out, `list="cert-opts"`) || !strings.Contains(out, `<datalist id="cert-opts">`) {
		t.Errorf("combobox input: %s", out)
	}
	if out := render(t, Input(In{ID: "cert", Name: "cert"})); strings.Contains(out, "list=") {
		t.Errorf("plain input has a list: %s", out)
	}
}
