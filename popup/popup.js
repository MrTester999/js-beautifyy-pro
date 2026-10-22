const pageTitle = document.getElementById("pageTitle");
const pageUrl = document.getElementById("pageUrl");
const analyzePage = document.getElementById("analyzePage");
const openWorkspace = document.getElementById("openWorkspace");
const status = document.getElementById("status");
const enableTool = document.getElementById("enableTool");
const toolState = document.getElementById("toolState");
let activeTab = null;
let statusTimer = null;
let pageAvailable = false;

function notify(message, error = false) {
  clearTimeout(statusTimer);
  status.textContent = message;
  status.classList.toggle("error", error);
  status.classList.add("show");
  statusTimer = setTimeout(() => status.classList.remove("show"), 2300);
}

async function call(type, payload = {}) {
  const response = await chrome.runtime.sendMessage({ type, ...payload });
  if (!response?.ok) throw new Error(response?.error || "Extension request failed");
  return response.data;
}

async function init() {
  try {
    const extensionStatus = await call("getStatus");
    setEnabledUi(extensionStatus.enabled);
    activeTab = await call("getActiveTab");
    if (!activeTab) throw new Error("Open a normal website first");
    pageAvailable = true;
    setEnabledUi(extensionStatus.enabled);
    pageTitle.textContent = activeTab.title || new URL(activeTab.url).hostname;
    pageUrl.textContent = activeTab.url;
    if (activeTab.isScript) {
      pageTitle.textContent = activeTab.title || activeTab.url.split("/").pop() || "JavaScript file";
      analyzePage.querySelector("strong").textContent = "Beautify this JavaScript file";
      analyzePage.querySelector("small").textContent = "Import, format, and analyze automatically";
    }
  } catch (error) {
    pageTitle.textContent = "Page analysis unavailable";
    pageUrl.textContent = error.message;
    analyzePage.disabled = true;
  }
}

function setEnabledUi(enabled) {
  enableTool.checked = enabled;
  document.body.classList.toggle("tool-disabled", !enabled);
  toolState.textContent = enabled ? "◆ Tool enabled · Local-only analysis" : "◇ Tool disabled";
  analyzePage.disabled = !enabled || !pageAvailable;
  openWorkspace.disabled = !enabled;
}

enableTool.addEventListener("change", async () => {
  enableTool.disabled = true;
  try {
    const result = await call("setEnabled", { enabled: enableTool.checked });
    setEnabledUi(result.enabled);
    notify(result.enabled ? "JS Beautifyy Pro enabled" : "JS Beautifyy Pro disabled");
  } catch (error) {
    enableTool.checked = !enableTool.checked;
    notify(error.message, true);
  } finally {
    enableTool.disabled = false;
  }
});

analyzePage.addEventListener("click", async () => {
  analyzePage.disabled = true;
  try {
    const result = await call("analyzeTab", { tabId: activeTab?.id, openWorkspace: true });
    notify(`Collected ${result.count} scripts${result.errors ? ` · ${result.errors} skipped` : ""}`);
    setTimeout(() => window.close(), 500);
  } catch (error) {
    notify(error.message, true);
    analyzePage.disabled = false;
  }
});

openWorkspace.addEventListener("click", async () => {
  try {
    await call("openWorkspace");
    window.close();
  } catch (error) {
    notify(error.message, true);
  }
});

void init();
