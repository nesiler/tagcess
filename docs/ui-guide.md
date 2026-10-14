# UI guide (internal/web)

The UI uses a single Pangolin-style design language: a dark graphite background, an orange primary colour, a left sidebar and
cards. The look lives in one place. Pages only compose components.

## Layers

| Location | Contents | Who changes it |
|---|---|---|
| `internal/web/static/tokens.css` | Colour, radius, shadow and font tokens (dark by default, `data-theme="light"`) | Design work only |
| `internal/web/static/components.css` | The classes of each component; the component name is in the heading | Only with a `ui` change |
| `internal/web/static/ui.js` | Theme, dialog, copy, menu closing, narrow-screen menu, table sorting/search, loading the editor, tooltip, chip input, instant field check, reading text from a file (data- attributes). Behaviour tests: `testdata/ui_behavior.test.cjs`, `testdata/ui_forms.test.cjs` | Only with a `ui` change |
| `internal/web/static/editor.js` | The CodeMirror 6 policy editor (compiled, embedded); its source is `tools/editor/` | Only with `tools/editor/build.sh` |
| `internal/web/ui/` | Pure components (`ui.Btn`, `ui.Card`, `ui.Table` …); they know nothing about tagcess | Only with a `ui` change |
| `internal/web/layout.*` | The shell: sidebar (`Nav`), top bar, `WithShell` | Shell work |
| `internal/web/flow.templ` | Shared flow: `CSRFField`, `ApplyForm`, `ConfirmDialog`, `dryRunWarning` | Shell work |
| `internal/web/<area>.templ` | Pages: they only compose components | The area owner |

## Rules

1. **A page does not write its own style.** A `.templ` page has no `class=`, `style=` or `<script`.
   `TestPagesUseUIComponents` checks this. The only exception is the shell files (`shellTemplates`).
2. **A missing component is not invented in a page.** It is added to the `ui` package: component + `components.css` block + gallery
   example + a test if needed. In parallel work, one person makes the `ui` change and the others request it.
3. **Colour comes only from `ui.Tone`.** `OK` healthy/applied, `Warn` attention/dry run, `Err`
   error/unreachable, `Stale` old data, `Info` information/operation kind, `Off` unknown. `OK` is never shown
   when there is no data (fail safe).
4. **Icons come only from `ui/icons.go`** (mdi-light, or mdi `-outline` if missing). A new icon
   is added to that file. `TestIconNamesExist` catches a wrong name.
5. **Every state-changing form carries `@CSRFField(token)`.** A preview ends with `@ApplyForm(...)`
   (a single label: `confirmApplyLabel`). Deletion and irreversible operations are asked with `@ConfirmDialog`.
6. **UI text is translated; technical terms follow the glossary.** The UI is available in English and Turkish.
   Technical terms are written as in the [glossary](ui-glossary.md) (tag, node, route, policy, dry-run, preview, apply …);
   `TestUITextUsesGlossaryTerms` checks this. The texts that existing tests look for are kept.
   To change a test text, the behaviour must change. Code is English.
7. **Markup tests are written on meaning.** The active item is found by `aria-current="page"`, a disabled
   link by `aria-disabled="true"`. Tests are not written on class names.
8. **Generic language.** The UI is a generic VPN portal: project-internal identifiers (`S-06`, `H-07`, `G-03` …)
   and internal jargon (`freshness`, `scope`, `snapshot`, `observation`, `check point`, `diff/approval pipeline`)
   do not enter visible text, tooltips, or `title`/`aria-label`/`placeholder` values; code identifiers stay only in `data-*`
   attributes. `TestUIWordingIsGeneric` scans all preview pages and their states.
9. **Plain text.** The page subtitle (`H.Sub`) is at most one short line; a long explanation becomes `H.Tip` or the card's `C.Desc`
   and appears as an info icon (tooltip) next to the title. No explanation paragraph/info callout is written on the page.
10. **State is not a chip.** Simple states such as "on/off", "current", "default" are written with `ui.StatusText` (coloured text +
    a date-time next to it) or with `ui.Status` in a table row; a setting that turns on and off becomes `ui.Switch`. `ui.Pill`
    is only for counters/badges, `ui.Tag` is for identifiers (role, tag).
11. **Controlled inputs.** Known values are selectable: `In.Options` (combobox) for a single value, `ui.MultiSelect` (chip)
    for a list. The user can still type their own value; if the option list cannot be read the field works as plain text.
    Fields with a known format use `Type` (url, number, datetime-local, password), `Pattern` + `Msg` (instant check) and `F.Err`
    for a server error. Server validation always stays; the browser check is only early feedback.
12. **Tables.** One piece of information per column, no multi-line cells; secondary detail (where the check is, target, raw code explanation)
    becomes a `ui.Tip` in the cell.

## Page skeleton

```templ
templ ThingsPage(v ThingsView, csrfToken string) {
	@ui.PageHead(ui.H{Title: "Things", Sub: "Short description.", Crumbs: []ui.Crumb{{Label: "Parent", Href: "/parent"}, {Label: "Things"}}}) {
		@ui.Btn(ui.B{Kind: ui.Primary, Href: "/things/new", Icon: "plus"}) {
			New
		}
	}
	if v.Err != "" {
		@ui.Callout(ui.N{Tone: ui.Err, Title: "Could not be read"}) {
			{ v.Err }
		}
	}
	@ui.Table() {
		<thead><tr><th>Name</th><th>Status</th><th aria-label="Actions"></th></tr></thead>
		<tbody>
			for _, t := range v.Rows {
				<tr>
					<td><a href={ templ.SafeURL(t.Href) }><strong>{ t.Name }</strong></a></td>
					<td>@ui.Status(t.Tone, t.State)</td>
					@ui.Actions() {
						@ui.Menu("actions") {
							@ui.MenuLink(t.Href, false) {
								Edit
							}
						}
					}
				</tr>
			}
		</tbody>
	}
}
```

Ready examples: `sites.templ` (list), `site_form.templ` (long form + SaveBar), `sites_review.templ`
(preview → confirm → result). Headscale pages call `@HeadscaleTabs(...)` at the top. This call only draws the
dry-run note and the maintenance banner; the tabs are in the sidebar. The sub-tabs of keys and the ACL
are made with `ui.Tabs`.

## Components (summary)

| Component | Use |
|---|---|
| `PageHead(H){acts}` | Title, one-line subtitle (`Sub`), explanation next to the title (`Tip`), breadcrumb, page actions on the right |
| `Card(C){…}` | Section. `Desc` becomes a tooltip next to the title (a plain line on a card without a title). `Flush` for a list flush to the edge, `Wide` a full row in a `Grid`, `Right` right of the title (for example `StatusText`) |
| `Tip(text)` | Info icon + tooltip: opens on hover, keyboard focus and touch, Escape closes; the button is described by the text with `aria-describedby`. With script it is pinned to the viewport (a table/card does not clip it) |
| `StatusText(Tone,text,at)` | Simple state: coloured plain text with a faint date-time next to it. Not a chip |
| `Switch(SW)` | On/off switch: a `role="switch"` button that submits its form; `Value` is the state to go to, so the change can first pass preview/confirmation |
| `MultiSelect(MS)` | Multiple values (role, tag, owner, namespace): chip + suggestion list (`datalist`) in the browser; the real form field is the textarea below (one value per line) or an input separated by `Sep`; without script that one is visible and the POST does not change |
| `FileInto(id,target,label)` | Reads a small text file (kubeconfig, PEM) into a textarea in the browser; the file is not sent separately, hidden without script |
| `Grid(n){cards}`, `TileCard(Tile)` | Dashboard cards and numbers |
| `Table(){thead,tbody}`, `TableFoot(foot)`, `TableIn()`, `Actions()` | Tables. The right cell is `Actions` |
| `ListTable(L){thead,tbody}` | List screen: sorting and (`Search`) search in the browser. `In` inside a card, `Foot` pagination. A cell gives a sort key with `data-sort`, a header is not sortable with `data-nosort` |
| `Btn(B){label}`, `BtnRow()` | A single button. `Href` makes it a link, `Disabled`+`Title` says why it is disabled |
| `Pill(Tone)`, `Tag(text)`, `Status(Tone,text)` | Labels and the status dot |
| `Callout(N){body}` | Error/warning/result/note box |
| `Tabs([]Tab, active)` | Sub-tabs |
| `Field(F){control}`, `Input`, `Textarea`, `Select`, `Check`, `Checks`, `RadioGroup(RG)`, `Row`, `Row3`, `Group`, `SaveBar` | Forms. `RadioGroup` if the description of each option must be visible, `Select` for a short plain list. A field without a visible label (a `Row` line, a table cell) gets an accessible name with `Label`. `In.Options` combobox, `In.Pattern`/`TA.LinePattern` + `Msg` instant check, `F.Err` a server error under the field (the field becomes `aria-invalid` and is described by the error) |
| `Inline(){control, btn}` | Keeps a field and its button on one line (for example name + "Rename" inside a `Field`) |
| `InlineEdit(label){form}` | Inline editing: the value stays as text, the form appears when the button is opened (no script) |
| `Textarea(TA{Editor: "hujson", ErrorLine})` | Code editor (below). `ErrorLine` marks the line reported by validation |
| `Fold(summary, attrs){…}` | A secondary section closed by default (for example expired keys) |
| `LinkList([]Link)` | Rows leading to other screens (icon, title, description) |
| `Diff(title, unified)`, `Code(title, text)`, `Secret(value)` | A diff, a code block, a key shown once |
| `KV(){dt,dd}`, `Empty(icon,title,text){act}`, `Pager(P)` | Detail list, empty state, pagination |
| `Menu(label){MenuLink/MenuDialog}`, `Dialog(D){…}`, `DialogFoot(){action}` | Menu and modal |

## Tables, narrow screens and the code editor

- **Sorting and search:** list screens use `ui.ListTable`; sorting and search are in the browser (`ui.js`).
  Headers become `<button>`, carry `aria-sort`; the search box and result count are hidden without script (the table stays as it is).
  A list refreshed with htmx (devices) keeps the last sort and search. Audit is server-filtered and paged, and does not use `ListTable`.
- **Narrow screen:** tables scroll horizontally; the first column stays fixed, a shadow on the right edge shows continuing columns. There is no card
  view. Under 800 px the menu becomes a drawer behind the "Menu" button in the top bar (Escape and clicking outside close it);
  without script the menu stays at the top of the page as before.
- **Keyboard and menus:** the shell has a "Skip to main content" link. While the mobile drawer is open the background content is `inert`,
  page scrolling is locked and focus is in the drawer; Escape or the close button returns focus to the opener. Switching to desktop removes the lock.
  Status indicators sit on mobile below the brand/theme/account row of the top bar.
  If script and the Popover API are available, action menus open in the browser's top layer; they are not clipped by a table/card,
  are positioned at the screen edge and close with Escape. Without script the `details` disclosure is kept.
- **Instant field check:** when a field carrying `data-msg` loses focus, the browser check (type, pattern, required) and
  `data-line-pattern` (every filled line of a textarea) run; the message is written under the field and describes it, and is
  cleared when fixed. The line check stops submission with `setCustomValidity` and says the line number.
- **Form help and rejection:** `ui.Field` help is linked with `aria-describedby` to the `Input`, `Textarea` or `Select` control it names with `For`.
  A `ui.Dialog` description is also associated with the dialog. `D.Open` is only for opening the relevant dialog in an error response;
  it does not submit automatically. On a policy field error the entered values and empty inputs are kept;
  if the raw policy or a protected source cannot be read the operations stay closed and the inputs are shown as a read-only recovery text.
- **Periodic list refresh:** on an htmx refresh, search, selection range, sorting, horizontal position and the current keyboard focus
  are kept. A row link is re-focused only if the same `href` still exists; focus is not moved to a deleted/hidden row.
- **Copy:** `ui.Secret` announces copy success and failure in a visible live region; on failure it can be retried
  or the text selected by hand. The key or a technical error object is not logged.
- **Code editor:** `ui.js` turns a textarea with `TA.Editor` into CodeMirror 6 with `/static/editor.js` only when needed:
  line numbers, HuJSON highlighting, a `data-error-line` line marker. The textarea stays hidden in the form and is
  updated on every change; without script the same POST goes as from a plain textarea. Validation is on the server (policydoc).
  `editor.js` is a compiled file: `tools/editor/build.sh` installs the pinned-version packages (`package.json` + `package-lock.json`)
  into a temporary directory and produces a single IIFE file with esbuild; the output is deterministic. When the file changes, the SHA-256 in
  `TestStatic_AssetChecksums` and `static/README.md` are updated. There is no npm or CDN at runtime.

## Preview and screenshots

```
go run ./cmd/tagcess-ui            # http://127.0.0.1:8770/_ui
```

The preview server draws the pages with fixed example data. No Zitadel, Headscale or database is needed.
There is no authentication and it listens only on loopback. The examples are in the `previewPages` list in
`internal/web/preview.go`. Each page family adds its own examples (including error and empty states). Top bar flags:
`?dry=1`, `?pending=2`, `?err=1`.

Screenshot (1440 wide):

```
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --headless=new --disable-gpu \
  --hide-scrollbars --window-size=1440,1400 --screenshot=out.png "http://127.0.0.1:8770/sites"
```

When the shell changes, the golden file is refreshed with: `go test ./internal/web -run TestLayout_Render -update`.
