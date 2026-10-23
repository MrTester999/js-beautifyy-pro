import { createCodeEditor } from "../vendor/editor.bundle.js";

const $ = (id) => document.getElementById(id);

const elements = Object.fromEntries([
  "activeMeta", "activeName", "analysisState", "analysisTime", "analyzeAll", "braceStyle",
  "busy", "busyDetail", "busyTitle", "categoryTabs", "clearAll", "codeEditor", "codeEditorMount", "collapseIntel", "copyCode",
  "downloadCode", "dropZone", "editorPosition", "editorStats", "emptyPaste", "emptyState",
  "emptyUpload", "exportJson", "exportText", "fileInput", "findingSearch", "findingTotal",
  "findings", "formattedTab", "indentSize", "lineNumbers", "metricEndpoints", "metricParameters",
  "metricSecrets", "metricVulnerabilities", "newSource", "pasteSource", "preserveNewlines",
  "resultScope", "revealSecrets", "runAnalysis", "scanPage", "severityCritical", "severityHigh",
  "severityMedium", "severityInfo", "sourceCount", "sourceKind",
  "sourceList", "sourceScope", "sourceTab", "toast", "uploadTrigger", "urlForm", "urlInput"
].map((id) => [id, $(id)]));

const MAX_FILE_BYTES = 8 * 1024 * 1024;
const CATEGORIES = [
  ["all", "All"], ["endpoints", "Endpoints"], ["urls", "URLs"],
  ["parameters", "Parameters"], ["scripts", "Scripts"], ["sensitive", "Sensitive"],
  ["secrets", "Secrets"], ["vulnerabilities", "Vulnerabilities"], ["signals", "Signals"]
];

const state = {
  sources: [], activeId: null, view: "source", category: "all", toastTimer: null, running: false,
  enabled: true, options: { indentSize: "2", braceStyle: "collapse", preserveNewlines: true }
};

function setWorkspaceEnabled(enabled) {
  state.enabled = enabled;
  document.body.classList.toggle("tool-disabled-workspace", !enabled);
}

function uid() {
  return crypto.randomUUID();
}

function byteSize(text) {
  return new Blob([String(text || "")]).size;
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
}

function activeSource() {
  return state.sources.find((source) => source.id === state.activeId) || null;
}

function sourceCode(source = activeSource()) {
  if (!source) return "";
  return state.view === "formatted" && source.formatted ? source.formatted : source.code;
}

function toast(message, error = false) {
  clearTimeout(state.toastTimer);
  elements.toast.textContent = message;
  elements.toast.classList.toggle("error", error);
  elements.toast.classList.add("show");
  state.toastTimer = setTimeout(() => elements.toast.classList.remove("show"), 2600);
}

function busy(show, title = "Analyzing JavaScript…", detail = "Running locally") {
  state.running = show;
  elements.busy.classList.toggle("show", show);
  elements.busy.setAttribute("aria-hidden", String(!show));
  elements.busyTitle.textContent = title;
  elements.busyDetail.textContent = detail;
}

async function runtime(type, payload = {}) {
  const response = await chrome.runtime.sendMessage({ type, ...payload });
  if (!response?.ok) throw new Error(response?.error || "Extension request failed");
  return response.data;
}

function cleanName(name = "untitled.js") {
  return name.replace(/[\\/:*?"<>|]+/g, "-").slice(0, 150) || "untitled.js";
}

function sourceNameFromUrl(url) {
  try {
    return new URL(url).pathname.split("/").filter(Boolean).pop() || "remote-script.js";
  } catch {
    return "remote-script.js";
  }
}

function addSource(input, select = true) {
  const code = String(input.code || "");
  if (!code.trim()) return null;
  if (byteSize(code) > MAX_FILE_BYTES) throw new Error(`${input.name || "Source"} exceeds 8 MB`);
  const source = {
    id: uid(), name: cleanName(input.name || sourceNameFromUrl(input.url)), url: input.url || "",
    kind: input.kind || "local", code, formatted: "", findings: null, stats: null
  };
  state.sources.push(source);
  if (select) state.activeId = source.id;
  render();
  return source;
}

function updateActiveSourceFromEditor() {
  const source = activeSource();
  if (!source || state.view !== "source") return;
  if (source.code !== elements.codeEditor.value) {
    source.code = elements.codeEditor.value;
    source.formatted = "";
    source.findings = null;
    source.stats = null;
  }
}

function renderSources() {
  elements.sourceList.replaceChildren();
  elements.sourceCount.textContent = state.sources.length;
  for (const source of state.sources) {
    const row = document.createElement("button");
    row.type = "button";
    row.className = `source-item${source.id === state.activeId ? " active" : ""}`;
    row.dataset.id = source.id;
    const type = document.createElement("span");
    type.className = "source-type";
    type.textContent = source.kind === "inline" ? "IN" : source.kind === "external" ? "URL" : "JS";
    const info = document.createElement("span");
    info.className = "source-info";
    const title = document.createElement("strong");
    title.textContent = source.name;
    const meta = document.createElement("small");
    meta.textContent = `${formatBytes(byteSize(source.code))}${source.findings ? ` · ${source.stats.findings} findings` : ""}`;
    info.append(title, meta);
    const remove = document.createElement("span");
    remove.className = "source-remove";
    remove.title = "Remove source";
    remove.textContent = "×";
    const stateDot = document.createElement("span");
    stateDot.className = `source-state${source.findings ? " ready" : ""}`;
    stateDot.title = source.findings ? "Analysis complete" : "Not analyzed";
    row.append(type, info, remove, stateDot);
    elements.sourceList.append(row);
  }
}

function updateLineNumbers() {
  const count = Math.max(1, elements.codeEditor.value.split("\n").length);
  elements.lineNumbers.textContent = Array.from({ length: count }, (_, index) => index + 1).join("\n");
  elements.lineNumbers.scrollTop = elements.codeEditor.scrollTop;
}

function updateEditorPosition() {
  const before = elements.codeEditor.value.slice(0, elements.codeEditor.selectionStart);
  const lines = before.split("\n");
  elements.editorPosition.textContent = `Ln ${lines.length}, Col ${lines.at(-1).length + 1}`;
}

function renderEditor() {
  const source = activeSource();
  const hasSource = Boolean(source);
  elements.emptyState.classList.toggle("hidden", hasSource);
  elements.codeEditor.disabled = !hasSource || state.view === "formatted";
  elements.codeEditor.value = sourceCode(source);
  elements.activeName.textContent = source?.name || "Untitled.js";
  elements.activeMeta.textContent = source
    ? source.url || `${source.kind === "inline" ? "Inline script" : "Local source"} · ${formatBytes(byteSize(source.code))}`
    : "Ready for JavaScript";
  elements.sourceKind.className = `kind-dot ${source?.kind || "empty"}`;
  elements.sourceTab.classList.toggle("active", state.view === "source");
  elements.formattedTab.classList.toggle("active", state.view === "formatted");
  const code = elements.codeEditor.value;
  elements.editorStats.textContent = `${code ? code.split("\n").length : 0} lines · ${formatBytes(byteSize(code))}`;
  updateLineNumbers();
  updateEditorPosition();
}

function scopedSources() {
  if (elements.resultScope.value === "all") return state.sources.filter((source) => source.findings);
  const source = activeSource();
  return source?.findings ? [source] : [];
}

function flattenedFindings() {
  const output = [];
  for (const source of scopedSources()) {
    for (const [group, findings] of Object.entries(source.findings || {})) {
      for (const finding of findings) output.push({ ...finding, group, sourceId: source.id, sourceName: source.name });
    }
  }
  return output;
}

function findingCounts(findings) {
  const counts = Object.fromEntries(CATEGORIES.map(([key]) => [key, 0]));
  for (const finding of findings) {
    counts.all += 1;
    counts[finding.group] += 1;
  }
  return counts;
}

function renderCategoryTabs(counts) {
  elements.categoryTabs.replaceChildren();
  for (const [key, label] of CATEGORIES) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `category-tab${state.category === key ? " active" : ""}`;
    button.dataset.category = key;
    const name = document.createElement("span");
    name.textContent = label;
    const count = document.createElement("b");
    count.textContent = counts[key];
    button.append(name, count);
    elements.categoryTabs.append(button);
  }
}

function renderFindings() {
  const all = flattenedFindings();
  const counts = findingCounts(all);
  renderCategoryTabs(counts);
  elements.findingTotal.textContent = counts.all;
  elements.metricEndpoints.textContent = counts.endpoints;
  elements.metricParameters.textContent = counts.parameters;
  elements.metricSecrets.textContent = counts.secrets;
  elements.metricVulnerabilities.textContent = counts.vulnerabilities;
  const severity = { critical: 0, high: 0, medium: 0, info: 0 };
  for (const finding of all) severity[finding.severity in severity ? finding.severity : "info"] += 1;
  elements.severityCritical.textContent = severity.critical;
  elements.severityHigh.textContent = severity.high;
  elements.severityMedium.textContent = severity.medium;
  elements.severityInfo.textContent = severity.info;
  elements.revealSecrets.closest("label").classList.toggle("show", counts.secrets > 0);

  const search = elements.findingSearch.value.trim().toLowerCase();
  const filtered = all.filter((finding) => {
    if (state.category !== "all" && finding.group !== state.category) return false;
    if (!search) return true;
    return `${finding.label} ${finding.value} ${finding.context} ${finding.sourceName} ${finding.ruleId || ""} ${finding.cwe || ""} ${finding.recommendation || ""}`.toLowerCase().includes(search);
  });

  elements.findings.replaceChildren();
  if (!filtered.length) {
    const empty = document.createElement("div");
    empty.className = "no-findings";
    empty.innerHTML = all.length
      ? "<span>⌕</span><strong>No matching findings</strong><p>Change the category or search filter.</p>"
      : "<span>⌁</span><strong>No analysis results yet</strong><p>Run Beautify & Analyze to map this JavaScript file.</p>";
    elements.findings.append(empty);
  } else {
    for (const finding of filtered.slice(0, 3000)) {
      const card = document.createElement("article");
      card.className = `finding ${finding.severity || "info"} group-${finding.group}`;
      card.dataset.sourceId = finding.sourceId;
      card.dataset.line = finding.line;
      const head = document.createElement("div");
      head.className = "finding-head";
      const label = document.createElement("strong");
      label.textContent = finding.label;
      const group = document.createElement("em");
      group.className = "finding-group";
      group.textContent = finding.group;
      const severityBadge = document.createElement("i");
      severityBadge.className = "severity-badge";
      severityBadge.textContent = finding.severity || "info";
      const location = document.createElement("span");
      location.textContent = `${finding.sourceName} : ${finding.line}`;
      head.append(group, label, severityBadge, location);
      const value = document.createElement("div");
      value.className = "finding-value";
      value.textContent = finding.group === "secrets" && !elements.revealSecrets.checked ? finding.masked : finding.value;
      value.title = value.textContent;
      const context = document.createElement("div");
      context.className = "finding-context";
      context.textContent = finding.context;
      card.append(head, value, context);
      if (finding.ruleId || finding.cwe || finding.recommendation) {
        const details = document.createElement("div");
        details.className = "finding-details";
        const metadata = [finding.ruleId, finding.cwe, finding.confidence ? `${finding.confidence} confidence` : ""].filter(Boolean);
        const meta = document.createElement("span");
        meta.textContent = metadata.join(" · ");
        details.append(meta);
        if (finding.recommendation) {
          const recommendation = document.createElement("p");
          recommendation.textContent = finding.recommendation;
          details.append(recommendation);
        }
        card.append(details);
      }
      elements.findings.append(card);
    }
  }

  const analyzed = scopedSources();
  const duration = analyzed.reduce((sum, source) => sum + (source.stats?.durationMs || 0), 0);
  elements.analysisState.textContent = analyzed.length ? `${analyzed.length} source${analyzed.length === 1 ? "" : "s"} analyzed` : "Not analyzed";
  elements.analysisTime.textContent = analyzed.length ? `${counts.all} findings · ${duration} ms local scan` : "Run local analysis to begin";
  elements.sourceScope.textContent = elements.resultScope.value === "all" ? "All analyzed sources" : "Current source";
}

function render() {
  renderSources();
  renderEditor();
  renderFindings();
}

function workerOptions() {
  return {
    indentSize: elements.indentSize.value === "tab" ? 1 : Number(elements.indentSize.value),
    indentWithTabs: elements.indentSize.value === "tab",
    braceStyle: elements.braceStyle.value,
    preserveNewlines: elements.preserveNewlines.checked
  };
}

function analyzeInWorker(source) {
  return new Promise((resolve, reject) => {
    const worker = new Worker("../workers/analyzer.js");
    worker.onmessage = ({ data }) => {
      worker.terminate();
      if (data.ok) resolve(data);
      else reject(new Error(data.error || "Analysis failed"));
    };
    worker.onerror = (event) => {
      worker.terminate();
      reject(new Error(event.message || "Analysis worker failed"));
    };
    worker.postMessage({ source: source.code, options: workerOptions() });
  });
}

async function analyzeOne(source, position = "") {
  busy(true, "Beautifying & analyzing…", position || source.name);
  const result = await analyzeInWorker(source);
  source.formatted = result.formatted;
  source.findings = result.findings;
  source.stats = result.stats;
  return result;
}

async function runCurrent() {
  if (state.running) return;
  updateActiveSourceFromEditor();
  const source = activeSource();
  if (!source?.code.trim()) return toast("Add JavaScript first", true);
  try {
    await analyzeOne(source);
    state.view = "formatted";
    render();
    toast(`Done — ${source.stats.findings} findings in ${source.stats.durationMs} ms`);
  } catch (error) {
    toast(error.message, true);
  } finally {
    busy(false);
  }
}

async function runAll() {
  if (state.running || !state.sources.length) return;
  updateActiveSourceFromEditor();
  try {
    for (let index = 0; index < state.sources.length; index += 1) {
      await analyzeOne(state.sources[index], `${index + 1} of ${state.sources.length} · ${state.sources[index].name}`);
    }
    elements.resultScope.value = "all";
    render();
    toast(`Analyzed ${state.sources.length} sources locally`);
  } catch (error) {
    toast(error.message, true);
  } finally {
    busy(false);
  }
}

async function loadFiles(files) {
  const accepted = [...files].filter((file) => /(?:javascript|ecmascript|text\/plain)/i.test(file.type) || /\.(?:js|mjs|cjs|txt)$/i.test(file.name));
  if (!accepted.length) return toast("Choose JavaScript or TXT files", true);
  busy(true, "Importing JavaScript…", `${accepted.length} file${accepted.length === 1 ? "" : "s"}`);
  try {
    let imported = 0;
    for (const file of accepted) {
      if (file.size > MAX_FILE_BYTES) {
        toast(`${file.name} exceeds 8 MB`, true);
        continue;
      }
      addSource({ name: file.name, code: await file.text(), kind: "local" }, false);
      imported += 1;
    }
    if (imported) state.activeId = state.sources.at(-1).id;
    render();
    toast(`Imported ${imported} JavaScript file${imported === 1 ? "" : "s"}`);
  } finally {
    busy(false);
    elements.fileInput.value = "";
  }
}

async function pasteSource() {
  try {
    const code = await navigator.clipboard.readText();
    if (!code.trim()) throw new Error("Clipboard is empty");
    addSource({ name: `pasted-${state.sources.length + 1}.js`, code, kind: "clipboard" });
    toast("Clipboard imported locally");
  } catch (error) {
    toast(error.message || "Clipboard permission was denied", true);
  }
}

async function scanPage() {
  if (state.running) return;
  busy(true, "Collecting page JavaScript…", "External scripts are fetched without cookies");
  try {
    const page = await runtime("analyzeTab");
    for (const source of page.sources) addSource(source, false);
    if (page.sources.length) state.activeId = state.sources.at(-page.sources.length).id;
    render();
    toast(`Imported ${page.sources.length} scripts${page.errors.length ? ` · ${page.errors.length} skipped` : ""}`,
      !page.sources.length);
  } catch (error) {
    toast(error.message, true);
  } finally {
    busy(false);
  }
}

async function fetchUrl(event) {
  event.preventDefault();
  const url = elements.urlInput.value.trim();
  if (!url) return;
  busy(true, "Fetching JavaScript…", "Credentials and browser cache are not used");
  try {
    addSource(await runtime("fetchUrl", { url }));
    elements.urlInput.value = "";
    toast("Remote script imported safely");
  } catch (error) {
    toast(error.message, true);
  } finally {
    busy(false);
  }
}

function downloadText(filename, text, mime = "text/plain") {
  const url = URL.createObjectURL(new Blob([text], { type: mime }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = cleanName(filename);
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function exportData(format) {
  const findings = flattenedFindings().map((finding) => ({
    source: finding.sourceName, category: finding.group, label: finding.label,
    value: finding.group === "secrets" && !elements.revealSecrets.checked ? finding.masked : finding.value,
    line: finding.line, severity: finding.severity, confidence: finding.confidence, ruleId: finding.ruleId,
    cwe: finding.cwe, recommendation: finding.recommendation, context: finding.context
  }));
  if (!findings.length) return toast("No findings to export", true);
  const stamp = new Date().toISOString();
  if (format === "json") {
    downloadText("js-beautifyy-findings.json", JSON.stringify({ generatedAt: stamp, localAnalysis: true, findings }, null, 2), "application/json");
  } else {
    const text = ["JS Beautifyy Pro — Local Static Analysis", `Generated: ${stamp}`, "", ...findings.map((finding) =>
      `[${finding.category.toUpperCase()}] ${finding.label}\nSource: ${finding.source}:${finding.line}\nValue: ${finding.value}\nSeverity: ${finding.severity} · Confidence: ${finding.confidence}${finding.ruleId ? `\nRule: ${finding.ruleId}${finding.cwe ? ` · ${finding.cwe}` : ""}` : ""}${finding.recommendation ? `\nRecommendation: ${finding.recommendation}` : ""}\n`
    )].join("\n");
    downloadText("js-beautifyy-findings.txt", text);
  }
  toast(`Exported ${findings.length} findings`);
}

function jumpToFinding(card) {
  const source = state.sources.find((item) => item.id === card.dataset.sourceId);
  if (!source) return;
  state.activeId = source.id;
  state.view = source.formatted ? "formatted" : "source";
  render();
  const targetLine = Number(card.dataset.line || 1);
  const lines = elements.codeEditor.value.split("\n");
  const index = lines.slice(0, Math.max(0, targetLine - 1)).reduce((sum, line) => sum + line.length + 1, 0);
  elements.codeEditor.focus();
  elements.codeEditor.setSelectionRange(index, index);
  elements.codeEditor.scrollTop = Math.max(0, (targetLine - 4) * 19);
  updateLineNumbers();
  updateEditorPosition();
}

async function consumePendingImport() {
  const token = new URL(location.href).searchParams.get("import");
  if (!token) return;
  try {
    const pending = await runtime("consumeImport", { token });
    if (!pending) return;
    if (pending.error) toast(pending.error, true);
    const sources = pending.page?.sources || pending.sources || [];
    for (const source of sources) addSource(source, false);
    if (sources.length) state.activeId = state.sources.at(-sources.length).id;
    render();
    if (sources.length) toast(`Imported ${sources.length} scripts from ${pending.page?.title || "browser"}`);
    if (sources.length && pending.autoAnalyze) setTimeout(() => void runAll(), 60);
  } catch (error) {
    toast(error.message, true);
  }
}

function bindEvents() {
  elements.newSource.addEventListener("click", () => addSource({ name: `untitled-${state.sources.length + 1}.js`, code: "// Paste or write JavaScript here\n", kind: "local" }));
  elements.uploadTrigger.addEventListener("click", () => elements.fileInput.click());
  elements.emptyUpload.addEventListener("click", () => elements.fileInput.click());
  elements.fileInput.addEventListener("change", () => loadFiles(elements.fileInput.files));
  elements.pasteSource.addEventListener("click", pasteSource);
  elements.emptyPaste.addEventListener("click", pasteSource);
  elements.scanPage.addEventListener("click", scanPage);
  elements.urlForm.addEventListener("submit", fetchUrl);
  elements.runAnalysis.addEventListener("click", runCurrent);
  elements.analyzeAll.addEventListener("click", runAll);
  elements.copyCode.addEventListener("click", async () => {
    const code = sourceCode();
    if (!code) return toast("Nothing to copy", true);
    await navigator.clipboard.writeText(code);
    toast("Code copied");
  });
  elements.downloadCode.addEventListener("click", () => {
    const source = activeSource();
    if (!source) return toast("Nothing to download", true);
    downloadText(state.view === "formatted" ? source.name.replace(/\.m?js$/i, ".beautified.js") : source.name, sourceCode(), "text/javascript");
  });
  elements.sourceList.addEventListener("click", (event) => {
    const row = event.target.closest(".source-item");
    if (!row) return;
    updateActiveSourceFromEditor();
    if (event.target.closest(".source-remove")) {
      state.sources = state.sources.filter((source) => source.id !== row.dataset.id);
      if (state.activeId === row.dataset.id) state.activeId = state.sources[0]?.id || null;
    } else {
      state.activeId = row.dataset.id;
      if (state.view === "formatted" && !activeSource()?.formatted) state.view = "source";
    }
    render();
  });
  elements.sourceTab.addEventListener("click", () => { updateActiveSourceFromEditor(); state.view = "source"; renderEditor(); });
  elements.formattedTab.addEventListener("click", () => {
    updateActiveSourceFromEditor();
    if (!activeSource()?.formatted) return toast("Run Beautify & Analyze first", true);
    state.view = "formatted";
    renderEditor();
  });
  elements.codeEditor.addEventListener("input", () => {
    updateActiveSourceFromEditor();
    const code = elements.codeEditor.value;
    elements.editorStats.textContent = `${code ? code.split("\n").length : 0} lines · ${formatBytes(byteSize(code))}`;
    updateLineNumbers();
    updateEditorPosition();
    renderSources();
    renderFindings();
  });
  elements.codeEditor.addEventListener("scroll", updateLineNumbers);
  ["click", "keyup", "select"].forEach((event) => elements.codeEditor.addEventListener(event, updateEditorPosition));
  elements.codeEditor.addEventListener("keydown", (event) => {
    if (event.key === "Tab") {
      event.preventDefault();
      const indent = elements.indentSize.value === "tab" ? "\t" : " ".repeat(Number(elements.indentSize.value));
      elements.codeEditor.setRangeText(indent, elements.codeEditor.selectionStart, elements.codeEditor.selectionEnd, "end");
      elements.codeEditor.dispatchEvent(new Event("input"));
    }
  });
  elements.categoryTabs.addEventListener("click", (event) => {
    const tab = event.target.closest(".category-tab");
    if (!tab) return;
    state.category = tab.dataset.category;
    renderFindings();
  });
  elements.findingSearch.addEventListener("input", renderFindings);
  elements.resultScope.addEventListener("change", renderFindings);
  elements.revealSecrets.addEventListener("change", renderFindings);
  elements.findings.addEventListener("click", (event) => {
    const card = event.target.closest(".finding");
    if (card) jumpToFinding(card);
  });
  elements.exportJson.addEventListener("click", () => exportData("json"));
  elements.exportText.addEventListener("click", () => exportData("text"));
  elements.collapseIntel.addEventListener("click", async () => {
    const collapsed = document.body.classList.toggle("intel-collapsed");
    elements.collapseIntel.textContent = collapsed ? "‹" : "›";
    elements.collapseIntel.title = collapsed ? "Expand intelligence panel" : "Collapse intelligence panel";
    await chrome.storage.local.set({ intelCollapsed: collapsed });
  });
  elements.clearAll.addEventListener("click", () => {
    if (state.sources.length && !confirm("Clear all imported sources and local findings?")) return;
    state.sources = []; state.activeId = null; state.view = "source"; render();
  });
  [elements.indentSize, elements.braceStyle, elements.preserveNewlines].forEach((control) => control.addEventListener("change", async () => {
    state.options = { indentSize: elements.indentSize.value, braceStyle: elements.braceStyle.value, preserveNewlines: elements.preserveNewlines.checked };
    await chrome.storage.local.set({ beautifyOptions: state.options });
  }));
  ["dragenter", "dragover"].forEach((eventName) => elements.dropZone.addEventListener(eventName, (event) => { event.preventDefault(); elements.dropZone.classList.add("dragging"); }));
  ["dragleave", "drop"].forEach((eventName) => elements.dropZone.addEventListener(eventName, (event) => { event.preventDefault(); elements.dropZone.classList.remove("dragging"); }));
  elements.dropZone.addEventListener("drop", (event) => loadFiles(event.dataTransfer.files));
  document.addEventListener("dragenter", (event) => { event.preventDefault(); elements.dropZone.classList.add("show"); });
  document.addEventListener("dragover", (event) => event.preventDefault());
  document.addEventListener("drop", (event) => {
    elements.dropZone.classList.remove("show", "dragging");
    if (!elements.dropZone.contains(event.target)) {
      event.preventDefault();
      loadFiles(event.dataTransfer.files);
    }
  });
  document.addEventListener("keydown", (event) => {
    const modifier = event.ctrlKey || event.metaKey;
    if (modifier && event.key === "Enter") {
      event.preventDefault();
      if (event.shiftKey) void runAll();
      else void runCurrent();
    }
    if (modifier && event.key.toLowerCase() === "k") {
      event.preventDefault();
      elements.findingSearch.focus();
      elements.findingSearch.select();
    }
    if (modifier && event.key.toLowerCase() === "o") {
      event.preventDefault();
      elements.fileInput.click();
    }
    if (event.key === "Escape" && document.activeElement === elements.findingSearch) {
      elements.findingSearch.value = "";
      elements.findingSearch.blur();
      renderFindings();
    }
  });
}

async function init() {
  createCodeEditor({ textarea: elements.codeEditor, parent: elements.codeEditorMount });
  bindEvents();
  const extensionStatus = await runtime("getStatus");
  setWorkspaceEnabled(extensionStatus.enabled);
  const stored = await chrome.storage.local.get(["beautifyOptions", "intelCollapsed"]);
  if (stored.beautifyOptions) state.options = { ...state.options, ...stored.beautifyOptions };
  elements.indentSize.value = state.options.indentSize;
  elements.braceStyle.value = state.options.braceStyle;
  elements.preserveNewlines.checked = state.options.preserveNewlines;
  document.body.classList.toggle("intel-collapsed", Boolean(stored.intelCollapsed));
  elements.collapseIntel.textContent = stored.intelCollapsed ? "‹" : "›";
  render();
  await consumePendingImport();
}

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.extensionEnabled) setWorkspaceEnabled(changes.extensionEnabled.newValue !== false);
});

void init();
