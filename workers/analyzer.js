importScripts("../vendor/beautifier.min.js");

const MAX_FINDINGS_PER_GROUP = 3000;

function decodeLiteral(value) {
  return value
    .replace(/\\x([\da-f]{2})/gi, (_, hex) => String.fromCharCode(Number.parseInt(hex, 16)))
    .replace(/\\u([\da-f]{4})/gi, (_, hex) => String.fromCharCode(Number.parseInt(hex, 16)))
    .replace(/\\([\\/"'`])/g, "$1")
    .replace(/\\n/g, "\n")
    .replace(/\\r/g, "\r")
    .replace(/\\t/g, "\t");
}

function maskSecret(value) {
  if (value.includes("PRIVATE KEY")) return "-----BEGIN … PRIVATE KEY-----";
  if (value.length <= 8) return "•".repeat(value.length);
  return `${value.slice(0, 4)}${"•".repeat(Math.min(12, value.length - 8))}${value.slice(-4)}`;
}

function lineIndex(source) {
  const starts = [0];
  for (let index = 0; index < source.length; index += 1) {
    if (source.charCodeAt(index) === 10) starts.push(index + 1);
  }
  return starts;
}

function lineFor(starts, index) {
  let low = 0;
  let high = starts.length - 1;
  while (low <= high) {
    const middle = (low + high) >> 1;
    if (starts[middle] <= index) low = middle + 1;
    else high = middle - 1;
  }
  return high + 1;
}

function contextFor(source, index, secret = false) {
  const start = Math.max(0, source.lastIndexOf("\n", index) + 1);
  const endPosition = source.indexOf("\n", index);
  const end = endPosition === -1 ? Math.min(source.length, start + 220) : Math.min(endPosition, start + 220);
  const text = source.slice(start, end).trim();
  return secret ? "Sensitive value hidden — reveal to inspect locally" : text;
}

function createCollector(source) {
  const starts = lineIndex(source);
  const groups = {
    endpoints: [], urls: [], parameters: [], scripts: [], sensitive: [], secrets: [], signals: []
  };
  const seen = Object.fromEntries(Object.keys(groups).map((key) => [key, new Set()]));

  function add(group, value, index, extra = {}) {
    const clean = String(value || "").trim();
    if (!clean || groups[group].length >= MAX_FINDINGS_PER_GROUP) return;
    const key = `${extra.label || ""}\0${clean}`.toLowerCase();
    if (seen[group].has(key)) return;
    seen[group].add(key);
    const secret = group === "secrets";
    groups[group].push({
      value: clean,
      masked: secret ? maskSecret(clean) : clean,
      line: lineFor(starts, Math.max(0, index)),
      index: Math.max(0, index),
      context: contextFor(source, Math.max(0, index), secret),
      severity: extra.severity || "info",
      confidence: extra.confidence || "medium",
      label: extra.label || group
    });
  }
  return { groups, add };
}

function normalizeCandidate(value) {
  return decodeLiteral(value).trim().replace(/[),;]+$/, "");
}

function addParametersFromUrl(value, index, add) {
  const queryIndex = value.indexOf("?");
  if (queryIndex === -1) return;
  for (const part of value.slice(queryIndex + 1).split(/[&#]/)) {
    const key = part.split("=", 1)[0].trim();
    if (!key || key.length > 100 || /[{}$\s]/.test(key)) continue;
    try { add("parameters", decodeURIComponent(key), index, { label: "Query parameter", confidence: "high" }); }
    catch { add("parameters", key, index, { label: "Query parameter" }); }
  }
}

function addEndpointCandidate(rawValue, index, add, label = "Network endpoint") {
  const value = normalizeCandidate(rawValue);
  if (!value || value.length > 4096 || /[\s<>]/.test(value)) return;
  if (/^(?:https?|wss?):\/\//i.test(value) || /^\/\//.test(value)) {
    add("urls", value, index, { label, confidence: "high" });
  } else if (!/^(?:data|blob|javascript):/i.test(value)) {
    add("endpoints", value, index, { label, confidence: "high" });
  }
  addParametersFromUrl(value, index, add);
}

function scanNetworkEndpoints(source, add) {
  const callPattern = /\b(fetch|axios(?:\.(?:get|post|put|patch|delete|head|options))?|request|got(?:\.(?:get|post|put|patch|delete|head))?|WebSocket|EventSource)\s*\(\s*(["'`])((?:\\[\s\S]|(?!\2)[^\\])*?)\2/gi;
  let match;
  while ((match = callPattern.exec(source))) {
    addEndpointCandidate(match[3], match.index + match[0].indexOf(match[3]), add, `${match[1]} target`);
  }

  const xhrPattern = /\.open\s*\(\s*(["'`])(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\1\s*,\s*(["'`])((?:\\[\s\S]|(?!\2)[^\\])*?)\2/gi;
  while ((match = xhrPattern.exec(source))) {
    addEndpointCandidate(match[3], match.index + match[0].indexOf(match[3]), add, "XMLHttpRequest endpoint");
  }

  const configUrlPattern = /\b(?:url|uri|endpoint|baseURL)\s*:\s*(["'`])((?:\\[\s\S]|(?!\1)[^\\])*?)\1/gi;
  while ((match = configUrlPattern.exec(source))) {
    addEndpointCandidate(match[2], match.index + match[0].indexOf(match[2]), add, "Request configuration");
  }

  const routePattern = /\b(?:app|router|server|routes?)\s*\.\s*(?:get|post|put|patch|delete|head|options|use|all)\s*\(\s*(["'`])((?:\\[\s\S]|(?!\1)[^\\])*?)\1/gi;
  while ((match = routePattern.exec(source))) {
    addEndpointCandidate(match[2], match.index + match[0].indexOf(match[2]), add, "Application route");
  }
}

function scanStrings(source, add) {
  const literal = /(["'`])((?:\\[\s\S]|(?!\1)[^\\])*?)\1/g;
  let match;
  while ((match = literal.exec(source))) {
    const value = normalizeCandidate(match[2]);
    if (value.length < 2 || value.length > 4096) continue;
    const index = match.index + 1;
    if (/^(?:https?|wss?):\/\//i.test(value) || /^\/\//.test(value)) {
      add("urls", value, index, { label: "Absolute URL", confidence: "high" });
      addParametersFromUrl(value, index, add);
    }
    const pathLike = /^(?:\.{0,2}\/)[^\s<>]+/.test(value) || /\/(?:api|rest|graphql|oauth|auth|v\d+)(?:\/|\?|$)/i.test(value);
    if (pathLike && !/^\/\//.test(value)) {
      add("endpoints", value, index, { label: "Endpoint", confidence: "high" });
      addParametersFromUrl(value, index, add);
    }
    if (/\.m?js(?:[?#].*)?$/i.test(value)) {
      add("scripts", value, index, { label: "JavaScript asset", confidence: "high" });
    }
    if (/(?:admin|internal|private|debug|swagger|openapi|graphql|actuator|metrics|health|config|backup|upload|download|reset|password|oauth|token|secret|\.env|\.git|server-status)(?:\/|\?|\.|$)/i.test(value) && /\//.test(value)) {
      add("sensitive", value, index, { label: "Interesting path", severity: "medium", confidence: "medium" });
    }
  }
}

function scanParameters(source, add) {
  const patterns = [
    /(?:searchParams|params|query)\s*\.\s*(?:get|set|append|has|delete)\s*\(\s*["'`]([^"'`]{1,100})["'`]/gi,
    /new\s+URLSearchParams\s*\([^)]{0,300}\)/gi
  ];
  let match;
  while ((match = patterns[0].exec(source))) {
    add("parameters", match[1], match.index, { label: "Runtime parameter", confidence: "high" });
  }
  while ((match = patterns[1].exec(source))) {
    const block = match[0];
    const keyPattern = /[?&]?([\w.-]{1,100})\s*=/g;
    let key;
    while ((key = keyPattern.exec(block))) {
      add("parameters", key[1], match.index + key.index, { label: "URLSearchParams key", confidence: "medium" });
    }
  }

  const searchParamVariables = new Set(["searchParams", "params", "query"]);
  const declarationPattern = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*new\s+URLSearchParams\b/g;
  while ((match = declarationPattern.exec(source))) searchParamVariables.add(match[1]);
  for (const variable of searchParamVariables) {
    const escaped = variable.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const accessorPattern = new RegExp(`\\b${escaped}\\s*\\.\\s*(?:get|set|append|has|delete)\\s*\\(\\s*[\"'\`]([^\"'\`]{1,100})[\"'\`]`, "gi");
    while ((match = accessorPattern.exec(source))) {
      add("parameters", match[1], match.index, { label: "URLSearchParams key", confidence: "high" });
    }
  }

  const formVariables = new Set(["formData", "form", "payload"]);
  const formDeclaration = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*new\s+FormData\b/g;
  while ((match = formDeclaration.exec(source))) formVariables.add(match[1]);
  for (const variable of formVariables) {
    const escaped = variable.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const fieldPattern = new RegExp(`\\b${escaped}\\s*\\.\\s*(?:append|set|get|has|delete)\\s*\\(\\s*[\"'\`]([^\"'\`]{1,100})[\"'\`]`, "gi");
    while ((match = fieldPattern.exec(source))) {
      add("parameters", match[1], match.index, { label: "FormData field", confidence: "high" });
    }
  }

  const requestAccessPattern = /\b(?:req|request|ctx)?\s*\.?\s*(query|params|body|payload)\s*(?:\.\s*([A-Za-z_$][\w$-]{0,99})|\[\s*["'`]([^"'`]{1,100})["'`]\s*\])/gi;
  while ((match = requestAccessPattern.exec(source))) {
    const name = match[2] || match[3];
    if (name) add("parameters", name, match.index, { label: `${match[1]} field`, confidence: "high" });
  }

  const destructuringPattern = /\{([^{}]{1,500})\}\s*=\s*(?:req|request|ctx)\s*\.\s*(?:query|params|body|payload)\b/gi;
  while ((match = destructuringPattern.exec(source))) {
    for (const item of match[1].split(",")) {
      const name = item.trim().match(/^([A-Za-z_$][\w$-]{0,99})/)?.[1];
      if (name) add("parameters", name, match.index, { label: "Destructured request field", confidence: "high" });
    }
  }

  const objectPattern = /\b(?:params|query|data|body|payload|form)\s*:\s*\{([^{}]{1,1800})\}/gi;
  while ((match = objectPattern.exec(source))) {
    const keyPattern = /(?:^|,)\s*([A-Za-z_$][\w$.-]{0,99})\s*:/g;
    let key;
    while ((key = keyPattern.exec(match[1]))) {
      add("parameters", key[1], match.index + key.index, { label: "Request object key", confidence: "medium" });
    }
  }


  const jsonBodyPattern = /JSON\.stringify\s*\(\s*\{([^{}]{1,1800})\}\s*\)/gi;
  while ((match = jsonBodyPattern.exec(source))) {
    const keyPattern = /(?:^|,)\s*([A-Za-z_$][\w$.-]{0,99})\s*:/g;
    let key;
    while ((key = keyPattern.exec(match[1]))) {
      add("parameters", key[1], match.index + key.index, { label: "JSON request field", confidence: "high" });
    }
  }
}

function scanSecrets(source, add) {
  const patterns = [
    { label: "AWS access key", regex: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, severity: "high" },
    { label: "Google API key", regex: /\bAIza[0-9A-Za-z_-]{35}\b/g, severity: "high" },
    { label: "GitHub token", regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b/g, severity: "high" },
    { label: "GitHub fine-grained token", regex: /\bgithub_pat_[A-Za-z0-9_]{70,255}\b/g, severity: "high" },
    { label: "Stripe secret key", regex: /\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b/g, severity: "high" },
    { label: "Slack token", regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, severity: "high" },
    { label: "OpenAI API key", regex: /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b/g, severity: "high" },
    { label: "GitLab token", regex: /\bglpat-[A-Za-z0-9_-]{20,}\b/g, severity: "high" },
    { label: "Hugging Face token", regex: /\bhf_[A-Za-z0-9]{30,}\b/g, severity: "high" },
    { label: "npm access token", regex: /\bnpm_[A-Za-z0-9]{30,}\b/g, severity: "high" },
    { label: "SendGrid API key", regex: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{32,}\b/g, severity: "high" },
    { label: "Twilio API key", regex: /\bSK[0-9a-f]{32}\b/gi, severity: "high" },
    { label: "Discord webhook", regex: /https:\/\/(?:canary\.|ptb\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+/gi, severity: "high" },
    { label: "Database connection string", regex: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s"'`:@/]+:[^\s"'`@/]+@[^\s"'`]+/gi, severity: "high" },
    { label: "Azure storage connection", regex: /DefaultEndpointsProtocol=https?;AccountName=[^;\s]+;AccountKey=[^;\s]+;/gi, severity: "high" },
    { label: "JWT", regex: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, severity: "high" },
    { label: "Private key", regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]{20,}?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g, severity: "critical" },
    { label: "Bearer token", regex: /\bBearer\s+([A-Za-z0-9._~+\/-]{16,}=*)/gi, severity: "high", group: 1 },
    {
      label: "Hardcoded credential candidate",
      regex: /\b(?:api[_-]?key|secret|access[_-]?token|auth[_-]?token|password|passwd|client[_-]?secret)\b\s*[:=]\s*["'`]([^"'`\s]{8,})["'`]/gi,
      severity: "medium",
      group: 1
    }
  ];
  for (const pattern of patterns) {
    let match;
    while ((match = pattern.regex.exec(source))) {
      const value = match[pattern.group || 0];
      const offset = match.index + match[0].indexOf(value);
      add("secrets", value, offset, {
        label: pattern.label,
        severity: pattern.severity,
        confidence: pattern.label === "Hardcoded credential candidate" ? "medium" : "high"
      });
    }
  }
}

function scanSecuritySignals(source, add) {
  const patterns = [
    { label: "Dynamic code execution", regex: /\b(?:eval|Function)\s*\(/g, severity: "high" },
    { label: "HTML injection sink", regex: /\.(?:innerHTML|outerHTML)\s*=|\bdocument\.write\s*\(/g, severity: "medium" },
    { label: "Command-like timer", regex: /\bset(?:Timeout|Interval)\s*\(\s*["'`]/g, severity: "medium" },
    { label: "Cross-window messaging", regex: /\bpostMessage\s*\(/g, severity: "info" },
    { label: "Location source/sink", regex: /\b(?:window\.)?location\.(?:href|search|hash|assign|replace)\b/g, severity: "info" },
    { label: "DOM URL source", regex: /\bdocument\.(?:URL|documentURI|referrer)\b/g, severity: "info" }
  ];
  for (const pattern of patterns) {
    let match;
    while ((match = pattern.regex.exec(source))) {
      add("signals", match[0], match.index, {
        label: pattern.label,
        severity: pattern.severity,
        confidence: "medium"
      });
    }
  }
}

function analyze(source) {
  const { groups, add } = createCollector(source);
  scanStrings(source, add);
  scanNetworkEndpoints(source, add);
  scanParameters(source, add);
  scanSecrets(source, add);
  scanSecuritySignals(source, add);
  for (const group of Object.values(groups)) group.sort((a, b) => a.line - b.line || a.value.localeCompare(b.value));
  return groups;
}

self.onmessage = ({ data }) => {
  const startedAt = performance.now();
  try {
    const source = String(data.source || "");
    const formatted = self.beautifier.js(source, {
      indent_size: Number(data.options?.indentSize) || 2,
      indent_char: data.options?.indentWithTabs ? "\t" : " ",
      brace_style: data.options?.braceStyle || "collapse",
      preserve_newlines: data.options?.preserveNewlines !== false,
      max_preserve_newlines: 2,
      space_in_empty_paren: false,
      end_with_newline: true,
      unescape_strings: false,
      e4x: true
    });
    const findings = analyze(formatted);
    self.postMessage({
      ok: true,
      formatted,
      findings,
      stats: {
        sourceBytes: new Blob([source]).size,
        formattedBytes: new Blob([formatted]).size,
        sourceLines: source ? source.split("\n").length : 0,
        formattedLines: formatted ? formatted.split("\n").length : 0,
        findings: Object.values(findings).reduce((sum, group) => sum + group.length, 0),
        durationMs: Math.round(performance.now() - startedAt)
      }
    });
  } catch (error) {
    self.postMessage({ ok: false, error: error?.message || String(error) });
  }
};
