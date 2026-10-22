import assert from "node:assert/strict";
import { readFile, stat } from "node:fs/promises";
import vm from "node:vm";
import { performance } from "node:perf_hooks";
import { execFileSync } from "node:child_process";

const root = new URL("../", import.meta.url);
const json = async (path) => JSON.parse(await readFile(new URL(path, root), "utf8"));

const manifest = await json("manifest.json");
assert.equal(manifest.manifest_version, 3);
assert.equal(manifest.action.default_popup, "popup/popup.html");

const required = [
  manifest.background.service_worker,
  manifest.action.default_popup,
  ...Object.values(manifest.icons),
  "workspace/index.html", "workspace/workspace.css", "workspace/workspace.js",
  "workers/analyzer.js", "vendor/beautifier.min.js", "vendor/editor.bundle.js",
  "vendor/js-beautify.LICENSE", "vendor/codemirror.LICENSE", "DOCUMENTATION.md", "DOCUMENTATION.txt"
];
for (const path of new Set(required)) {
  const info = await stat(new URL(path, root));
  assert.ok(info.size > 0, `${path} is empty`);
}

for (const path of ["background/service-worker.js", "popup/popup.js", "workspace/workspace.js", "workers/analyzer.js", "vendor/editor.bundle.js"]) {
  execFileSync(process.execPath, ["--check", new URL(path, root).pathname], { stdio: "pipe" });
}

const vendor = await readFile(new URL("vendor/beautifier.min.js", root), "utf8");
const analyzer = await readFile(new URL("workers/analyzer.js", root), "utf8");
let response = null;
const context = vm.createContext({
  Blob, URL, performance, console,
  postMessage: (value) => { response = value; }
});
context.self = context;
context.importScripts = () => vm.runInContext(vendor, context, { filename: "beautifier.min.js" });
vm.runInContext(analyzer, context, { filename: "analyzer.js" });
context.onmessage({ data: {
  source: `
    const api = '/api/v1/users?id=7';
    fetch('/account/profile?expand=roles');
    axios.post('v2/session/login', { body: { email: 'demo@example.test' } });
    xhr.open('POST', '/oauth/token?grant_type=code');
    router.get('/admin/users/:userId', handler);
    const socket = new WebSocket('wss://socket.example.test/events?channel=audit');
    const q = new URLSearchParams(location.search);
    q.get('next');
    const form = new FormData();
    form.append('csrf_token', 'demo');
    const userId = req.params.userId;
    const payload = JSON.stringify({ username: 'demo', rememberMe: true });
    const aws = 'AKIAABCDEFGHIJKLMNOP';
    const openai = 'sk-proj-abcdefghijklmnopqrstuvwxyz123456';
    const database = 'postgres://demo_user:demo_password@db.example.test/app';
    eval('1+1');
  `,
  options: { indentSize: 2, braceStyle: "collapse", preserveNewlines: true }
} });
assert.equal(response?.ok, true, response?.error);
assert.ok(response.formatted.includes("\n"), "beautifier did not produce readable output");
assert.ok(response.findings.endpoints.some((item) => item.value.includes("/api/v1/users")));
assert.ok(response.findings.endpoints.some((item) => item.value === "v2/session/login"), "axios endpoint missing");
assert.ok(response.findings.endpoints.some((item) => item.value.includes("/oauth/token")), "XHR endpoint missing");
assert.ok(response.findings.endpoints.some((item) => item.value.includes("/admin/users")), "route endpoint missing");
assert.ok(response.findings.urls.some((item) => item.value.startsWith("wss://")), "WebSocket URL missing");
assert.ok(response.findings.parameters.some((item) => item.value === "id"));
assert.ok(response.findings.parameters.some((item) => item.value === "next"));
assert.ok(response.findings.parameters.some((item) => item.value === "csrf_token"), "FormData parameter missing");
assert.ok(response.findings.parameters.some((item) => item.value === "userId"), "request parameter missing");
assert.ok(response.findings.parameters.some((item) => item.value === "username"), "JSON body parameter missing");
assert.ok(response.findings.secrets.some((item) => item.label === "AWS access key"));
assert.ok(response.findings.secrets.some((item) => item.label === "OpenAI API key"));
assert.ok(response.findings.secrets.some((item) => item.label === "Database connection string"));
assert.ok(response.findings.secrets.every((item) => item.masked !== item.value), "secret masking failed");
assert.ok(response.findings.signals.some((item) => item.label === "Dynamic code execution"));

console.log(`✓ Manifest v${manifest.version}`);
console.log(`✓ ${new Set(required).size} required assets`);
console.log(`✓ JavaScript syntax checks`);
console.log(`✓ Analyzer coverage test (${response.findings.endpoints.length} endpoints, ${response.findings.parameters.length} parameters, ${response.findings.secrets.length} secrets)`);
