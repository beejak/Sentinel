# Architecture

Goals
- Scanner that prioritizes MCP protocol compliance and runtime safety, with production-grade reporting and policy gating.
- Deterministic, scriptable, fast; safe-by-default (no secrets echoed, no destructive actions).

Language and packaging
- Short term: keep a Python CLI for rapid iteration (Milestones 1–2).
- Medium term: implement high-performance core in Go for cross-platform single-binary delivery and robust OAuth/TLS (Milestones 3–9).
- Optional: Rust accelerator(s) for SAST/SCA if needed.

High-level components
- cli: argument parsing, config merge, progress UI, exit codes
- discovery:
  - HTTP probe; parse WWW-Authenticate on 401; RFC9728/8414 metadata discovery; enumerate capabilities (tools/resources/prompts)
- auth_tester:
  - OAuth 2.1 Authorization Code + PKCE; resource (RFC8707) and audience checks; redirect/TLS hygiene; token passthrough negative tests; confused-deputy consent validation
- runtime_probe:
  - Invoke MCP tools in a controlled harness; SSRF checks for URL fetchers; sandbox/allowlist checks for file/process/network tools; prompt-injection probes; session-hijack tests
- sast_sca:
  - Optional repo/filesystem scanning; Semgrep integration; supply-chain patterns (node/python/go)
- threat_intel:
  - Optional enrichment: NVD CVEs and MITRE ATT&CK technique mapping; local caching
- reporting:
  - Findings normalization; JSON, SARIF 2.1.0 writers; HTML dashboard generator (static assets)
- policy:
  - YAML policy loader; rule evaluation; CI gating
- common:
  - HTTP/TLS client; OAuth helpers; JSON schema; logging/tracing

Data model (stable)
- Target: name, uri, metadata
- ServerMetadata: well-known endpoints, OAuth metadata (AS URIs, JWKS), server version, advertised scopes, authorization_servers
- Capability: kind (tool/resource/prompt), name, description, schema, side_effects
- Finding: id (rule), title, severity, description, references, evidence, remediation, category, affected (capability/file/endpoint), fingerprint
- Evidence: request/response excerpts (redacted), headers, body hashes, timestamps
- Severity: info/low/medium/high/critical
- Output: { version, scanned_at, target, findings[], summary }

Configuration (YAML)
- Global: timeouts, parallelism, user agent, cache dir
- Auth: client_id, redirect_uri (localhost), scopes, consent_mode (strict|permissive)
- Tests enablement: discovery/auth/runtime/sast/sca/threat_intel
- Policy: path
- Reporting: formats [json, sarif, html], output dir, fail-on (severity)

Concurrency model
- Discovery → Auth tests → Runtime probes can be pipelined per target; within each stage, run parallel subtests with bounded worker pool.
- SAST/SCA can run in parallel to runtime probes (if filesystem available).

Extensibility
- Rule packs: add new tests without changing core (config-driven).
- Output adapters: writer interface for JSON/SARIF/HTML.
- Inspector artifacts: export sessions/calls to replay in modelcontextprotocol/inspector.

Security and privacy
- Never print secret values; support env var references; redact tokens in logs.
- HTTPS required for remote endpoints; allow localhost exceptions per spec.
- Strict dependency verification for releases; checksums/signatures.
