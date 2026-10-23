# Changelog

## 1.5.0

### Added

- Dedicated **Vulnerabilities** results category with severity, confidence,
  rule IDs, CWE mappings, source locations, and remediation guidance.
- Detection for dynamic code execution, DOM injection sinks, wildcard
  `postMessage`, disabled TLS verification, command execution, weak hashes,
  insecure random security values, dynamic SQL templates, prototype mutation,
  insecure HTTP requests, and sensitive Web Storage usage.
- Provider-specific patterns for Anthropic, Google OAuth, DigitalOcean,
  HashiCorp Vault, Shopify, Mailgun, Telegram, and Slack credentials.
- Context-aware high-entropy credential detection with common placeholder
  suppression to reduce noise.
- Parameter discovery for bracket access, GraphQL variables, request headers,
  and template query strings.
- Vulnerability metadata in JSON and TXT exports.

### Changed

- Updated the workspace summary to highlight potential vulnerable code.
- Expanded regression coverage for secrets, parameters, and vulnerability rules.
- Clarified that all findings require manual validation and are not proof of an
  exploitable issue.

## 1.4.2

- Added the CodeMirror editor workspace and local static-analysis workflow.
