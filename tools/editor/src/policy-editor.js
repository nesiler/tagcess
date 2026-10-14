// tagcess code editor: CodeMirror 6 over a <textarea data-code-editor="hujson"> (ui.CodeEditor).
// The textarea stays in the form, hidden, and is kept in sync on every change, so the form posts
// the same field it posts without script. data-error-line marks the line the server's validation
// reported. ui.js loads this file only on pages that have such a textarea.
import { EditorState, RangeSetBuilder, StateField } from "@codemirror/state";
import {
  EditorView, Decoration, lineNumbers, highlightActiveLine, highlightActiveLineGutter,
  drawSelection, keymap, GutterMarker, gutter,
} from "@codemirror/view";
import { defaultKeymap, history, historyKeymap } from "@codemirror/commands";
import {
  StreamLanguage, HighlightStyle, syntaxHighlighting, bracketMatching, indentOnInput,
} from "@codemirror/language";
import { tags as t } from "@lezer/highlight";

// HuJSON is JSON with comments and trailing commas. A small stream tokenizer is enough to colour
// it; validation stays on the server (policydoc), which reports the line.
const hujson = StreamLanguage.define({
  name: "hujson",
  startState: () => ({ inComment: false }),
  token(stream, state) {
    if (state.inComment) {
      if (stream.skipTo("*/")) { stream.match("*/"); state.inComment = false; } else stream.skipToEnd();
      return "comment";
    }
    if (stream.eatSpace()) return null;
    if (stream.match("//")) { stream.skipToEnd(); return "comment"; }
    if (stream.match("/*")) { state.inComment = true; return "comment"; }
    const ch = stream.peek();
    if (ch === '"') {
      stream.next();
      let escaped = false, c;
      while ((c = stream.next()) != null) {
        if (c === '"' && !escaped) break;
        escaped = !escaped && c === "\\";
      }
      // A string followed by ':' is an object key.
      return /^\s*:/.test(stream.string.slice(stream.pos)) ? "propertyName" : "string";
    }
    if (stream.match(/^-?\d+(\.\d+)?([eE][+-]?\d+)?/)) return "number";
    if (stream.match(/^(true|false|null)\b/)) return "atom";
    if (/[{}[\],:]/.test(ch)) { stream.next(); return "punctuation"; }
    stream.next();
    return "invalid";
  },
  languageData: { commentTokens: { line: "//", block: { open: "/*", close: "*/" } } },
});

// Colours come from the page's design tokens, so dark and light themes follow automatically.
const style = HighlightStyle.define([
  { tag: t.comment, color: "var(--muted-fg)", fontStyle: "italic" },
  { tag: t.propertyName, color: "var(--info)" },
  { tag: t.string, color: "var(--ok)" },
  { tag: t.number, color: "var(--warn)" },
  { tag: t.atom, color: "var(--primary)" },
  { tag: t.punctuation, color: "var(--muted-fg)" },
  { tag: t.invalid, color: "var(--err)" },
]);

const theme = EditorView.theme({
  "&": { fontSize: "12.5px", border: "1px solid var(--border)", borderRadius: "var(--r-sm)", background: "transparent", color: "var(--fg)" },
  "&.cm-focused": { outline: "none", borderColor: "var(--primary)", boxShadow: "0 0 0 3px color-mix(in oklch, var(--primary) 22%, transparent)" },
  ".cm-scroller": { fontFamily: "var(--mono)", lineHeight: "1.6", maxHeight: "70vh", minHeight: "440px" },
  ".cm-content": { caretColor: "var(--fg)" },
  ".cm-cursor": { borderLeftColor: "var(--fg)" },
  ".cm-gutters": { background: "color-mix(in oklch, var(--muted) 30%, transparent)", color: "var(--muted-fg)", border: "0", borderRight: "1px solid var(--border)" },
  ".cm-activeLine": { background: "color-mix(in oklch, var(--muted) 30%, transparent)" },
  ".cm-activeLineGutter": { background: "color-mix(in oklch, var(--muted) 50%, transparent)", color: "var(--fg)" },
  "&.cm-focused .cm-selectionBackground, .cm-selectionBackground, ::selection": { background: "color-mix(in oklch, var(--primary) 30%, transparent) !important" },
  ".cm-matchingBracket": { background: "color-mix(in oklch, var(--primary) 25%, transparent)", outline: "none" },
  ".cm-errline": { background: "var(--del-bg)" },
  ".cm-errmark": { color: "var(--err)", fontWeight: "700", padding: "0 2px" },
});

class ErrorMarker extends GutterMarker {
  toDOM() {
    const s = document.createElement("span");
    s.className = "cm-errmark";
    s.textContent = "!";
    s.title = "Doğrulama bu satırda hata buldu";
    return s;
  }
}

// errorLine highlights the server-reported line until the text changes; an edit clears the mark,
// because the report no longer describes the text.
function errorLine(line) {
  const deco = (doc) => {
    const b = new RangeSetBuilder();
    if (line >= 1 && line <= doc.lines) b.add(doc.line(line).from, doc.line(line).from, Decoration.line({ class: "cm-errline" }));
    return b.finish();
  };
  const field = StateField.define({
    create: (st) => deco(st.doc),
    update: (value, tr) => (tr.docChanged ? Decoration.none : value),
    provide: (f) => EditorView.decorations.from(f),
  });
  const marks = gutter({
    class: "cm-errgutter",
    markers: (view) => {
      const b = new RangeSetBuilder();
      const d = view.state.field(field);
      d.between(0, view.state.doc.length, (from) => { b.add(from, from, new ErrorMarker()); });
      return b.finish();
    },
  });
  return [field, marks];
}

function enhance(ta) {
  if (ta.dataset.enhanced) return;
  ta.dataset.enhanced = "1";
  const readOnly = ta.readOnly || ta.disabled;
  const line = parseInt(ta.dataset.errorLine || "0", 10);
  const label = ta.getAttribute("aria-label") || "Kod";
  const state = EditorState.create({
    doc: ta.value,
    extensions: [
      lineNumbers(), highlightActiveLineGutter(), highlightActiveLine(), drawSelection(), history(),
      indentOnInput(), bracketMatching(), hujson, syntaxHighlighting(style), theme,
      keymap.of([...defaultKeymap, ...historyKeymap]),
      EditorState.readOnly.of(readOnly), EditorView.editable.of(!readOnly),
      EditorView.contentAttributes.of({ "aria-label": label }),
      EditorView.updateListener.of((u) => { if (u.docChanged) ta.value = u.state.doc.toString(); }),
      line > 0 ? errorLine(line) : [],
    ],
  });
  const view = new EditorView({ state });
  ta.insertAdjacentElement("afterend", view.dom);
  ta.hidden = true;
  if (line > 0 && line <= view.state.doc.lines) {
    view.dispatch({ effects: EditorView.scrollIntoView(view.state.doc.line(line).from, { y: "center" }) });
  }
}

function enhanceAll() {
  document.querySelectorAll("textarea[data-code-editor]").forEach(enhance);
}
if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", enhanceAll);
else enhanceAll();
