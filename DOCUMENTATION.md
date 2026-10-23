# JS Beautifyy Pro

**JS Beautifyy Pro** is a privacy-focused Chrome extension for formatting and statically reviewing JavaScript. It turns minified or difficult-to-read JavaScript into clean, highlighted code and maps useful information without executing the imported code.

## Main features

- Beautifies minified JavaScript using `js-beautify`.
- Provides a CodeMirror 6 editor with JavaScript, TypeScript, and JSX syntax highlighting.
- Extracts potential API endpoints, absolute URLs, WebSocket URLs, application routes, and JavaScript assets.
- Extracts query parameters, runtime parameters, `URLSearchParams`, `FormData`, request fields, GraphQL variables, headers, and JSON body fields.
- Detects provider-specific and generic secret candidates, including API keys, tokens, JWTs, private keys, database connection strings, webhooks, and high-entropy assigned credentials.
- Masks sensitive values by default.
- Identifies potential vulnerable code with rule IDs, CWE mappings, confidence, severity, and remediation guidance.
- Maps interesting paths and security-relevant JavaScript sources for manual data-flow review.
- Imports files, clipboard content, URLs, scripts from the current page, and directly opened JavaScript tabs.
- Exports analysis results as JSON or TXT.
- Runs formatting and analysis locally. Imported JavaScript is not executed.

> [!IMPORTANT]
> Findings are static indicators for manual review. They are not proof of a vulnerability, and secret detection may produce false positives.

## Install the unpacked extension

1. Extract the ZIP file if necessary.
2. Open Chrome.
3. Navigate to:

   ```text
   chrome://extensions
   ```

4. Enable **Developer mode**.
5. Select **Load unpacked**.
6. Choose this folder:

   ```text
   js-beautifyy-pro
   ```

7. Pin **JS Beautifyy Pro** from Chrome's Extensions menu.

When source files change, return to `chrome://extensions` and press **Reload** on the extension card.

## Install from the ZIP package

The ZIP package is intended for distribution or Chrome Web Store submission. Chrome's **Load unpacked** option requires an extracted folder, so extract the ZIP before loading it locally.

Current package:

```text
dist/js-beautifyy-pro-1.5.0.zip
```

## Analyze the current website

1. Open an authorized website.
2. Select the extension icon.
3. Press **Analyze page JavaScript**.
4. The workspace imports available inline and external scripts.
5. Press **Beautify & analyze**, or use **Analyze all** for every imported source.

Some authenticated or restricted scripts may not be available because of browser security policies.

## Analyze an opened JavaScript file

1. Open a `.js`, `.mjs`, or `.cjs` URL in Chrome.
2. Select the extension icon.
3. Press **Beautify this JavaScript file**.
4. The extension imports, formats, and analyzes the opened file automatically.

## Analyze a local file

1. Open `chrome://extensions`.
2. Open **Details** for JS Beautifyy Pro.
3. Enable **Allow access to file URLs**.
4. Open the local JavaScript file in Chrome.
5. Select the extension and analyze it.

Alternatively, open the workspace and use **Upload**.

## Analyze JavaScript stored in a TXT file

The extension accepts `.txt` files when their contents are JavaScript:

1. Open the extension workspace.
2. Select **Upload**.
3. Choose the `.txt` file containing JavaScript.
4. Select the imported source.
5. Press **Beautify & analyze**.

You can also drag the TXT file into the workspace or copy its contents and use **Paste**.

Example TXT content:

```javascript
const api = "/api/v1/users?id=42";
fetch(api).then(response => response.json());
```

## Load a JavaScript URL

1. Open the full workspace.
2. Paste an HTTP(S) JavaScript URL into **Load JavaScript URL**.
3. Press the arrow button.
4. Run **Beautify & analyze**.

Remote fetching omits cookies and bypasses the browser cache. For an authenticated script already open in a tab, analyze the opened tab instead.

## Understanding the results

- **Endpoints:** API paths, routes, request targets, and network destinations.
- **URLs:** HTTP(S), WebSocket, and other absolute network URLs.
- **Parameters:** Query keys, form fields, request fields, and JSON body keys.
- **Scripts:** Referenced JavaScript assets.
- **Sensitive:** Interesting administrative, internal, configuration, upload, debug, or authentication paths.
- **Secrets:** Potential credentials and tokens. Values are masked unless explicitly revealed.
- **Vulnerabilities:** Potentially unsafe sinks and configurations with severity, confidence, rule IDs, CWE references, and remediation guidance.
- **Signals:** Security-relevant sources and browser APIs requiring manual data-flow review.

Select a finding to jump to its source line.

## Export results

Use the bottom-right buttons:

- **Export JSON** for structured results.
- **Export TXT** for a readable text report.
- **Download** to save the currently visible source or beautified code.

## Keyboard shortcuts

| Shortcut | Action |
|---|---|
| `Alt+Shift+J` | Open the workspace |
| `Ctrl+Enter` | Analyze the current source |
| `Ctrl+Shift+Enter` | Analyze all sources |
| `Ctrl+K` | Focus finding search |
| `Ctrl+O` | Upload a file |
| `Ctrl+F` | Search inside the code editor |

## Enable or disable the extension

Open the extension popup and use the switch in the top-right corner. Disabling the extension blocks page analysis, URL imports, context-menu actions, badges, and workspace actions until it is enabled again.

## Limits and privacy

- Maximum size: 8 MB per source and 24 MB per page scan.
- No telemetry or remote analysis service is used.
- Direct URL and page imports require network access only to retrieve selected scripts.
- Imported code is analyzed as text and is never executed by the extension.
- Only analyze systems for which you have authorization.
