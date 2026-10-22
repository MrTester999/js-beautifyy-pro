import { EditorView, basicSetup } from "codemirror";
import { Compartment, EditorState } from "@codemirror/state";
import { indentWithTab } from "@codemirror/commands";
import { keymap } from "@codemirror/view";
import { javascript } from "@codemirror/lang-javascript";
import { HighlightStyle, syntaxHighlighting } from "@codemirror/language";
import { tags } from "@lezer/highlight";

const javascriptHighlight = HighlightStyle.define([
  { tag: [tags.keyword, tags.controlKeyword, tags.moduleKeyword], color: "#ff7ab2", fontWeight: "700" },
  { tag: [tags.definitionKeyword, tags.operatorKeyword], color: "#c099ff", fontWeight: "650" },
  { tag: [tags.name, tags.variableName], color: "#d7e2f1" },
  { tag: [tags.definition(tags.variableName), tags.function(tags.variableName)], color: "#82d2ff", fontWeight: "650" },
  { tag: [tags.propertyName, tags.special(tags.propertyName)], color: "#73e0c5" },
  { tag: [tags.string, tags.special(tags.string)], color: "#f6c177" },
  { tag: [tags.number, tags.bool, tags.null], color: "#b8a1ff", fontWeight: "650" },
  { tag: [tags.comment, tags.lineComment, tags.blockComment], color: "#74869d", fontStyle: "italic" },
  { tag: [tags.operator, tags.punctuation, tags.separator], color: "#9fb0c6" },
  { tag: [tags.regexp, tags.escape], color: "#ff9f7a" },
  { tag: [tags.className, tags.typeName], color: "#6ee7b7", fontWeight: "700" },
  { tag: tags.meta, color: "#5eead4" },
  { tag: tags.invalid, color: "#fff", backgroundColor: "#e5484d" }
]);

const editorTheme = EditorView.theme({
  "&": { height: "100%", backgroundColor: "transparent", color: "#dbe7f5" },
  "&.cm-focused": { outline: "none" },
  ".cm-scroller": {
    overflow: "auto", fontFamily: '"Cascadia Code", "JetBrains Mono", "Fira Code", Consolas, monospace',
    fontSize: "12.5px", lineHeight: "1.72"
  },
  ".cm-content": { minHeight: "100%", padding: "14px 0 80px", caretColor: "#49f1dc" },
  ".cm-line": { padding: "0 18px" },
  ".cm-cursor, .cm-dropCursor": { borderLeftColor: "#49f1dc", borderLeftWidth: "2px" },
  "&.cm-focused .cm-selectionBackground, .cm-selectionBackground, .cm-content ::selection": { backgroundColor: "#244d725f" },
  ".cm-activeLine": { backgroundColor: "#17243772" },
  ".cm-gutters": {
    backgroundColor: "#080d15", color: "#52647d", borderRight: "1px solid #172335",
    minWidth: "48px", fontWeight: "650"
  },
  ".cm-lineNumbers .cm-gutterElement": { minWidth: "47px", padding: "0 11px 0 5px" },
  ".cm-activeLineGutter": { backgroundColor: "#172437", color: "#55e6d3" },
  ".cm-matchingBracket": { color: "#6ee7b7", backgroundColor: "#34d39928", outline: "1px solid #34d39955" },
  ".cm-nonmatchingBracket": { color: "#fff", backgroundColor: "#fb718566" },
  ".cm-foldPlaceholder": { border: "1px solid #2e415b", color: "#8da0b8", backgroundColor: "#152033" },
  ".cm-panels": { backgroundColor: "#101827", color: "#d7e2ef" },
  ".cm-search": { borderTop: "1px solid #26354a", padding: "7px" },
  ".cm-search input": { border: "1px solid #314159", borderRadius: "6px", background: "#08101a", color: "#e7eef8", padding: "4px 7px" },
  ".cm-search button": { border: "1px solid #314159", borderRadius: "6px", background: "#172235", color: "#bdc9d9", padding: "4px 8px" },
  ".cm-tooltip": { border: "1px solid #293a51", backgroundColor: "#101827", color: "#d8e2ef" },
  ".cm-tooltip-autocomplete ul li[aria-selected]": { backgroundColor: "#1b5060", color: "#fff" },
  ".cm-placeholder": { color: "#64758d", fontStyle: "normal" },
  "&.cm-editor.cm-readonly .cm-content": { opacity: ".92" }
}, { dark: true });

export function createCodeEditor({ textarea, parent }) {
  const editable = new Compartment();
  let suppressInput = false;
  let disabled = false;

  const view = new EditorView({
    state: EditorState.create({
      doc: textarea.defaultValue || textarea.value || "",
      extensions: [
        basicSetup,
        javascript({ jsx: true, typescript: true }),
        syntaxHighlighting(javascriptHighlight),
        editorTheme,
        keymap.of([indentWithTab]),
        editable.of(EditorView.editable.of(true)),
        EditorView.updateListener.of((update) => {
          if (update.docChanged && !suppressInput) textarea.dispatchEvent(new Event("input"));
          if (update.selectionSet) textarea.dispatchEvent(new Event("select"));
        })
      ]
    }),
    parent
  });

  view.contentDOM.setAttribute("aria-label", textarea.getAttribute("aria-label") || "JavaScript editor");
  textarea.hidden = true;

  Object.defineProperties(textarea, {
    value: {
      configurable: true,
      get: () => view.state.doc.toString(),
      set: (value) => {
        const next = String(value ?? "");
        if (next === view.state.doc.toString()) return;
        suppressInput = true;
        view.dispatch({ changes: { from: 0, to: view.state.doc.length, insert: next }, selection: { anchor: 0 } });
        suppressInput = false;
      }
    },
    disabled: {
      configurable: true,
      get: () => disabled,
      set: (value) => {
        disabled = Boolean(value);
        view.dispatch({ effects: editable.reconfigure(EditorView.editable.of(!disabled)) });
        view.dom.classList.toggle("cm-readonly", disabled);
      }
    },
    selectionStart: { configurable: true, get: () => view.state.selection.main.from },
    selectionEnd: { configurable: true, get: () => view.state.selection.main.to },
    scrollTop: {
      configurable: true,
      get: () => view.scrollDOM.scrollTop,
      set: (value) => { view.scrollDOM.scrollTop = Number(value) || 0; }
    }
  });

  textarea.focus = () => view.focus();
  textarea.select = () => view.dispatch({ selection: { anchor: 0, head: view.state.doc.length } });
  textarea.setSelectionRange = (start, end = start) => {
    const anchor = Math.max(0, Math.min(Number(start) || 0, view.state.doc.length));
    const head = Math.max(0, Math.min(Number(end) || anchor, view.state.doc.length));
    view.dispatch({ selection: { anchor, head }, effects: EditorView.scrollIntoView(anchor, { y: "center" }) });
  };
  textarea.setRangeText = (replacement, start, end) => {
    const from = Math.max(0, Math.min(start, view.state.doc.length));
    const to = Math.max(from, Math.min(end, view.state.doc.length));
    view.dispatch({ changes: { from, to, insert: replacement }, selection: { anchor: from + replacement.length } });
  };
  view.scrollDOM.addEventListener("scroll", () => textarea.dispatchEvent(new Event("scroll")), { passive: true });

  return { view, destroy: () => view.destroy() };
}
