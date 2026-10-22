const WORKSPACE_URL = "workspace/index.html";
const PENDING_KEY = "pendingImport";
const MAX_FILE_BYTES = 8 * 1024 * 1024;
const MAX_TOTAL_BYTES = 24 * 1024 * 1024;
const FETCH_CONCURRENCY = 4;

let lastWebTabId = null;

async function isToolEnabled() {
  const stored = await chrome.storage.local.get("extensionEnabled");
  return stored.extensionEnabled !== false;
}

async function setToolEnabled(enabled) {
  await chrome.storage.local.set({ extensionEnabled: Boolean(enabled) });
  await setupMenus(Boolean(enabled));
  const tabs = await chrome.tabs.query({});
  await Promise.all(tabs.map((tab) => updateActionBadge(tab.id, tab.url || "", Boolean(enabled))));
}

function isWebUrl(url = "") {
  return /^https?:\/\//i.test(url);
}

function isSupportedUrl(url = "") {
  return isWebUrl(url) || /^file:\/\//i.test(url);
}

function isJavaScriptUrl(url = "") {
  return /(?:\.m?js(?:[?#]|$)|[?&](?:file|format|type)=js(?:&|$))/i.test(url);
}

async function activeWebTab() {
  if (Number.isInteger(lastWebTabId)) {
    const remembered = await chrome.tabs.get(lastWebTabId).catch(() => null);
    if (remembered && isSupportedUrl(remembered.url)) return remembered;
  }
  const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  return tab && isSupportedUrl(tab.url) ? tab : null;
}

async function fetchJavaScript(url) {
  if (!isSupportedUrl(url)) throw new Error("Only HTTP(S) and local file script URLs are supported");
  const response = await fetch(url, {
    credentials: "omit",
    cache: "no-store",
    redirect: "follow"
  });
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
  const declaredSize = Number(response.headers.get("content-length") || 0);
  if (declaredSize > MAX_FILE_BYTES) throw new Error("Script exceeds the 8 MB safety limit");
  const text = await response.text();
  if (new Blob([text]).size > MAX_FILE_BYTES) throw new Error("Script exceeds the 8 MB safety limit");
  return {
    name: new URL(response.url || url).pathname.split("/").pop() || "remote-script.js",
    url: response.url || url,
    code: text,
    kind: "external"
  };
}

async function detectScriptDocument(tab) {
  if (isJavaScriptUrl(tab.url)) return true;
  try {
    const [{ result }] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: () => /(?:javascript|ecmascript)/i.test(document.contentType || "")
    });
    return Boolean(result);
  } catch {
    return false;
  }
}

async function readDirectScript(tab) {
  try {
    return await fetchJavaScript(tab.url);
  } catch (fetchError) {
    try {
      const [{ result }] = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: () => ({
          contentType: document.contentType || "",
          code: document.body?.innerText || document.documentElement?.textContent || ""
        })
      });
      if (!result?.code?.trim()) throw new Error("The opened JavaScript file is empty");
      if (new Blob([result.code]).size > MAX_FILE_BYTES) throw new Error("Script exceeds the 8 MB safety limit");
      return {
        name: (() => {
          try { return new URL(tab.url).pathname.split("/").filter(Boolean).pop() || "opened-script.js"; }
          catch { return "opened-script.js"; }
        })(),
        url: tab.url,
        code: result.code,
        kind: /^file:/i.test(tab.url) ? "local" : "external"
      };
    } catch (readError) {
      if (/^file:/i.test(tab.url)) {
        throw new Error("Enable ‘Allow access to file URLs’ for JS Beautifyy Pro, then reload the file");
      }
      throw new Error(`Could not read this JavaScript file: ${readError.message || fetchError.message}`);
    }
  }
}

async function directScriptPage(tab) {
  const source = await readDirectScript(tab);
  return {
    title: source.name,
    pageUrl: tab.url,
    sources: [source],
    errors: [],
    totalBytes: new Blob([source.code]).size,
    directScript: true
  };
}

async function updateActionBadge(tabId, tabUrl = "", enabled = null) {
  const active = enabled ?? await isToolEnabled();
  const isScript = active && isJavaScriptUrl(tabUrl);
  await chrome.action.setBadgeBackgroundColor({ tabId, color: "#18afaa" }).catch(() => {});
  await chrome.action.setBadgeText({ tabId, text: isScript ? "JS" : "" }).catch(() => {});
  await chrome.action.setTitle({
    tabId,
    title: !active ? "JS Beautifyy Pro is disabled" : isScript ? "Beautify and analyze this JavaScript file" : "JS Beautifyy Pro"
  }).catch(() => {});
}

async function mapLimit(items, limit, mapper) {
  const output = new Array(items.length);
  let cursor = 0;
  async function worker() {
    while (cursor < items.length) {
      const index = cursor;
      cursor += 1;
      output[index] = await mapper(items[index], index);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return output;
}

async function inspectPage(tabId) {
  const tab = await chrome.tabs.get(tabId).catch(() => null);
  if (!tab || !isSupportedUrl(tab.url)) throw new Error("Open an HTTP(S) page or JavaScript file first");

  const [{ result }] = await chrome.scripting.executeScript({
    target: { tabId },
    func: () => ({
      title: document.title,
      url: location.href,
      external: [...new Set([...document.scripts].map((script) => script.src).filter(Boolean))],
      inline: [...document.scripts]
        .filter((script) => !script.src && script.textContent.trim())
        .map((script, index) => ({ name: `inline-${index + 1}.js`, code: script.textContent }))
    })
  });

  const sources = [];
  const errors = [];
  let totalBytes = 0;

  for (const item of result.inline) {
    const size = new Blob([item.code]).size;
    if (size > MAX_FILE_BYTES || totalBytes + size > MAX_TOTAL_BYTES) {
      errors.push({ source: item.name, error: "Skipped because the local analysis limit was reached" });
      continue;
    }
    totalBytes += size;
    sources.push({ ...item, url: result.url, kind: "inline" });
  }

  const fetched = await mapLimit(result.external, FETCH_CONCURRENCY, async (url) => {
    if (totalBytes >= MAX_TOTAL_BYTES) return { error: "Total 24 MB analysis limit reached", source: url };
    try {
      const source = await fetchJavaScript(url);
      const size = new Blob([source.code]).size;
      if (totalBytes + size > MAX_TOTAL_BYTES) return { error: "Total 24 MB analysis limit reached", source: url };
      totalBytes += size;
      return { source };
    } catch (error) {
      return { error: error?.message || String(error), source: url };
    }
  });

  for (const item of fetched) {
    if (item.source) sources.push(item.source);
    else errors.push(item);
  }
  return {
    title: result.title || new URL(result.url).hostname,
    pageUrl: result.url,
    sources,
    errors,
    totalBytes
  };
}

async function queueImport(payload) {
  const token = crypto.randomUUID();
  await chrome.storage.session.set({
    [PENDING_KEY]: { token, createdAt: Date.now(), ...payload }
  });
  return token;
}

async function openWorkspace(payload = null) {
  let url = chrome.runtime.getURL(WORKSPACE_URL);
  if (payload) {
    const token = await queueImport(payload);
    url += `?import=${encodeURIComponent(token)}`;
  }
  return chrome.tabs.create({ url });
}

async function setupMenus(enabled = null) {
  const active = enabled ?? await isToolEnabled();
  await chrome.contextMenus.removeAll();
  chrome.contextMenus.create({
    id: "jsb-analyze-page",
    title: "Analyze page JavaScript with JS Beautifyy Pro",
    contexts: ["page"],
    enabled: active
  });
  chrome.contextMenus.create({
    id: "jsb-analyze-link",
    title: "Beautify and analyze this JavaScript link",
    contexts: ["link"],
    targetUrlPatterns: ["http://*/*", "https://*/*", "file:///*"],
    enabled: active
  });
}

chrome.runtime.onInstalled.addListener(() => void (async () => {
  const stored = await chrome.storage.local.get("extensionEnabled");
  if (typeof stored.extensionEnabled !== "boolean") await chrome.storage.local.set({ extensionEnabled: true });
  await setupMenus();
})());
chrome.runtime.onStartup.addListener(() => void setupMenus());

chrome.tabs.onActivated.addListener(({ tabId }) => {
  void chrome.tabs.get(tabId).then((tab) => {
    if (isSupportedUrl(tab.url)) lastWebTabId = tabId;
    return updateActionBadge(tabId, tab.url);
  }).catch(() => {});
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if ((changeInfo.url || changeInfo.status === "complete") && tab.active && isSupportedUrl(tab.url)) lastWebTabId = tabId;
  if (changeInfo.url || changeInfo.status === "complete") void updateActionBadge(tabId, tab.url);
});

chrome.commands.onCommand.addListener((command) => {
  if (command === "open-workspace") void isToolEnabled().then((enabled) => enabled && openWorkspace());
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  void isToolEnabled().then((enabled) => {
    if (!enabled) return;
  if (info.menuItemId === "jsb-analyze-page" && tab?.id) {
    void inspectPage(tab.id)
      .then((page) => openWorkspace({ type: "page", page }))
      .catch((error) => openWorkspace({ type: "error", error: error.message }));
  }
  if (info.menuItemId === "jsb-analyze-link" && info.linkUrl) {
    void fetchJavaScript(info.linkUrl)
      .then((source) => openWorkspace({ type: "sources", sources: [source] }))
      .catch((error) => openWorkspace({ type: "error", error: error.message }));
  }
  });
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  void (async () => {
    if (message?.type === "getStatus") return { enabled: await isToolEnabled() };
    if (message?.type === "setEnabled") {
      await setToolEnabled(Boolean(message.enabled));
      return { enabled: Boolean(message.enabled) };
    }
    if (message?.type === "getActiveTab") {
      const tab = await activeWebTab();
      if (!tab) return null;
      return { id: tab.id, title: tab.title, url: tab.url, isScript: await detectScriptDocument(tab), isLocal: /^file:/i.test(tab.url) };
    }
    if (!await isToolEnabled()) throw new Error("JS Beautifyy Pro is disabled — enable it from the extension popup");
    if (message?.type === "openWorkspace") {
      const tab = await openWorkspace();
      return { tabId: tab.id };
    }
    if (message?.type === "analyzeTab") {
      const tab = Number.isInteger(message.tabId) ? await chrome.tabs.get(message.tabId) : await activeWebTab();
      if (!tab?.id) throw new Error("No analyzable page is active");
      const directScript = await detectScriptDocument(tab);
      const page = directScript ? await directScriptPage(tab) : await inspectPage(tab.id);
      if (message.openWorkspace) {
        const workspace = await openWorkspace({ type: "page", page, autoAnalyze: directScript });
        return { tabId: workspace.id, count: page.sources.length, errors: page.errors.length };
      }
      return page;
    }
    if (message?.type === "fetchUrl") return fetchJavaScript(message.url);
    if (message?.type === "consumeImport") {
      const data = await chrome.storage.session.get(PENDING_KEY);
      const pending = data[PENDING_KEY];
      if (!pending || pending.token !== message.token) return null;
      await chrome.storage.session.remove(PENDING_KEY);
      return pending;
    }
    throw new Error("Unknown action");
  })().then(
    (data) => sendResponse({ ok: true, data }),
    (error) => sendResponse({ ok: false, error: error?.message || String(error) })
  );
  return true;
});
