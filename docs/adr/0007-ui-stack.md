# 0007: UI stack: templ + htmx + own component package

- Status: Accepted; the visual layer (item 4) changed on 2026-10-06, see [Note (2026-10-06)](#note-2026-10-06)
- Date: 2026-09-28
- Decided by: the developer, who delegated with "/onasor... admin experience matters, pick the best and most sensible option".
  The decisions were made through two independent model consultations.
- Related: all UI functions (S, H, Y-05, P, A)

## Context
- The UI will be used by 2-3 devops people; admin experience comes first. The UI replaces Headplane.
- Screens needed:
  - Forms
  - Diff preview
  - Changes awaiting approval
  - Filterable device tables
  - ACL editor (form and HuJSON)
  - Audit
  - Dashboard
- No CDN; all assets are embedded in the binary. No Node toolchain.
- Most of the development will be done by AI agents.

## Decision
1. **Templates: `templ`.** Type checking at compile time and a component model.
   Generated with `go tool templ generate`; no Node needed. Both models chose this in the first round.
2. **Interaction: htmx.** Embedded in the repository with a pinned version. A small amount of vanilla JS is used where needed.
   - The server returns HTML fragments; no separate JSON API is written.
   - Every state-changing request carries a CSRF token (NFR-03).
3. **Rich editor: CodeMirror 6.** Used in the HuJSON/ACL editor.
   - Embedded in the repository as a single pre-built bundle.
   - Runs on the page as an "island" independent of htmx.
4. **Visual layer: Bootstrap 5.3.** (Replaced by our own `ui` package on 2026-10-06; see the note below.)
   Embedded as one CSS and one JS file.
   - Table, form, modal, toast, tab and dark mode (`data-bs-theme`) come ready-made, with ARIA support.
   - It binds events through data-api delegation, so it needs no re-initialisation after htmx swaps a page fragment.
   - In the first round Codex chose Bootstrap and Fable chose Tailwind. In the second round Fable switched to Bootstrap; the
     two models decided jointly. Tailwind's flexibility is not worth an extra build step and keeping generated CSS up to date.

## Consequences
- Pro:
  - A single `go build` is enough (generated templ code is committed).
  - One language.
  - Automatic escaping.
  - Handlers can be tested with `httptest`.
  - Ready-made components speed up the admin screens.
- Con: the Bootstrap look can be ordinary; our own theme is added as a small CSS file.
  Client interactivity is not as rich as in an SPA. This use case does not need it.
- Follow-up: the htmx version (2.x or 4.x) is chosen and pinned in the first UI task, and checked with `researcher`.

## Note (2026-10-01)
**[Decided]** (developer, 2026-10-01) Relaxation: the policy editor first ships as a plain textarea + server-side error panel; CodeMirror 6 is a later step. The stack decision (templ + htmx + Bootstrap) does not change. See ADR 0020.

## Note (2026-10-06)
**[Decided]** (developer, 2026-10-06) The visual layer changed: Bootstrap was removed and the UI moved to our own design
in the style of Pangolin. The templ, htmx and CodeMirror decisions (items 1-3) still apply as they are.
- Components live in the `internal/web/ui` package (`ui.Btn`, `ui.Card`, `ui.Table` ...). Pages only compose
  components; they do not write `class=`, `style=` or `<script` (`TestPagesUseUIComponents`).
- The look lives in the project's own embedded files: `static/tokens.css`, `static/components.css`, `static/ui.js`.
  No new external dependency or build step was added; icons are embedded in `ui/icons.go` (mdi-light, mdi,
  svg-spinners).
- Reason: the Bootstrap look was ordinary (the "Con" above) and pages carried styling in class names. A single component
  package keeps the look in one place and stops agents from inventing per-page styles.
- Rules and component list: [docs/ui-guide.md](../ui-guide.md).

## Alternatives considered
- `html/template` + htmx: no compile-time checks, weak component reuse.
- SPA (React or Svelte): needs a Node toolchain; brings two languages and a wider API/CSRF surface.
- Ready-made admin kit (GoAdmin etc.): maintenance risk (Fable: no release since 2024).
- Tailwind v4: flexible but adds an extra build step.
- Pico: not enough for table, dialog and toast needs.
- Web Awesome/Shoelace: shadow DOM causes problems with htmx swaps.
