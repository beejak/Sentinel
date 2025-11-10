# Security Test Plan

Runtime Probes (Milestone 3)
- PROBE-005 Tool Guardrails
  - Goal: Server must deny dangerous tool invocations (path traversal, privileged paths) with structured error {error, message} and 401/403.
  - Method: Dynamic registration -> non-interactive PKCE -> call /tools and POST /tool/run with malicious args.
  - Pass: 401/403 with JSON error + message; Fail (high): 2xx success; Fail (medium): 4xx without structured error.
- PROBE-006 State Replay
  - Goal: Prevent reuse of authorization codes (invalid_grant on replay).
  - Method: Exchange code once (200), replay same code (expect 400 + invalid_grant).
  - Fail (high): second exchange 200 or wrong/absent error.
- PROBE-007 Rate Limiting
  - Goal: Detect absence of burst protection on sensitive endpoints.
  - Method: 5 quick POSTs to /tool/run with safe payload.
  - Pass: At least one 429 with Retry-After header; Info (low): no 429 observed.
- PROBE-003 Oversize Payload (intrusive)
  - Goal: Graceful handling (no 5xx) for large POST bodies; reject or backpressure.
  - Method: POST ~512KB payload to origin.
  - Fail (medium): 5xx crash; Info: robust 4xx or absorption without crash.
- PROBE-008 Method Matrix
  - Goal: Ensure sensitive endpoints enforce correct HTTP methods.
  - Method: GET/PUT /tool/run should be rejected (401/403/405), not 2xx.
  - Fail (high): 2xx on GET/PUT /tool/run; Fail (medium): unexpected status outside 401/403/405.
- PROBE-009 Content-Type Matrix
  - Goal: Robust content-type and body parsing handling.
  - Method: POST /tool/run with text/plain + JSON body, and application/json + invalid JSON.
  - Fail (high): 2xx; Fail (medium): 5xx; Pass: 4xx with structured error.
- PROBE-010 Invalid Auth
  - Goal: Sensitive endpoints require auth.
  - Method: POST /tool/run without Authorization.
  - Fail (high): 2xx; Fail (medium): unexpected status outside 401/403/405/429.
- PROBE-011 TRACE Method
  - Goal: Ensure TRACE is disabled on sensitive endpoints.
  - Method: TRACE /tool/run.
  - Fail (high): 2xx; Fail (medium): unexpected status outside 401/403/405.
- PROBE-012 Missing Content-Type
  - Goal: Reject requests without Content-Type when a JSON body is expected.
  - Method: POST /tool/run with JSON body but no Content-Type.
  - Fail (high): 2xx; Fail (medium): 5xx; Info (low): 4xx without structured error.
- PROBE-013 Large Header (intrusive)
  - Goal: Ensure large headers don’t crash the server.
  - Method: POST /tool/run with ~8KB custom header.
  - Fail (medium): 5xx; Pass/Info: non-5xx.
- PROBE-014 SSRF/Egress
  - Goal: Server must block requests to loopback and private address ranges.
  - Method: Invoke fetch_url tool with http://127.0.0.1:8085/ and similar; expect 403 with structured error.
  - Fail (high): 2xx success; Fail (medium): 5xx.

Scope
- MCP protocol compliance (Authorization, Security Best Practices) and MCP-specific runtime risks.
- References: MCP Spec 2025-06-18 Authorization & Security Best Practices; RFC 8414, 8707, 9728; academic papers (AgentBound; When MCP Servers Attack; MCP Safety Audit; Beyond the Protocol; MPMA).

Legend
- Rule ID: stable identifier for SARIF/JSON
- Evidence: redacted request/response excerpts, headers, hashes
- Severity: info/low/medium/high/critical

Protocol & Auth
- AUTH-001 OAuth metadata discovery
  - Expect: RFC9728/RFC8414 metadata present or discoverable; advertised authorization_servers
  - Fail: metadata missing or malformed
- AUTH-002 HTTPS and redirect URI hygiene
  - Expect: HTTPS endpoints; exact redirect URI match; localhost exceptions allowed
  - Fail: open redirect or insecure schemes
- AUTH-003 Authorization Code + PKCE
  - Expect: PKCE required; state used; code flow succeeds with valid inputs
  - Fail: code flow without PKCE; missing state validation
- AUTH-004 resource parameter (RFC8707) and audience
  - Expect: resource included; access token audience matches server; invalid audience rejected (401)
  - Fail: server accepts token for other audience
- AUTH-005 Token passthrough
  - Negative test: pass arbitrary bearer token from other AS
  - Expect: rejected (401); no passthrough
  - Fail: token accepted or forwarded downstream
- AUTH-006 Confused deputy / consent bypass
  - Scenario: proxy dynamic registration; ensure per-client consent prompts
  - Expect: consent per client ID; no cookie reuse to skip consent
  - Fail: consent skipped or shared across clients

Session & Runtime
- SESS-001 No session-for-auth
  - Expect: sessions not used to authenticate; all requests verified
  - Fail: session alone authorizes sensitive operations
- SESS-002 Session ID robustness
  - Expect: non-deterministic, securely generated, bound to user context
  - Fail: predictable or unbound session IDs

Dangerous Surface & Sandbox
- RUNT-001 File system tools
  - Expect: path allowlist/denylist; no traversal; limited scope
  - Fail: broad FS read/write/exec without controls
- RUNT-002 Process execution tools
  - Expect: explicit opt-in, constraints, audit trail
  - Fail: arbitrary exec with unconstrained args/env
- RUNT-003 Network/URL fetch
  - Expect: SSRF protections (allowlist, IP block, protocol filtering, size limits)
  - Fail: internal IPs, file://, gopher:// allowed; no size/content-type checks

Prompt Injection Resilience
- INJ-001 Harmful tool invocation
  - Probes attempt to coerce unsafe actions via crafted inputs
  - Expect: server validates/guards; refuses dangerous operations
  - Fail: executes unsafe tasks without checks

Tool Poisoning & Preference Manipulation (MPMA)
- POIS-001 Manipulative naming/description
  - Heuristics: superlatives/calls-to-action/advertising in tool names/descriptions; ranking bias hints
  - Expect: neutral, descriptive metadata
  - Fail: manipulative phrasing designed to bias LLM selection

Marketplace Hygiene
- MKT-001 Typosquatting/obfuscation
  - Expect: transparent naming, no obfuscation
  - Fail: name squatting; heavy/minified bundles without sources
- MKT-002 Release integrity
  - Expect: signed releases, checksums, SBOM
  - Fail: missing integrity artifacts; suspicious maintainer churn

Supply Chain & SAST (optional)
- SCA-001 Install script risks (Node/Python)
- SCA-002 Insecure deps (http, wildcards)
- SCA-003 Package confusion indicators
- SAST-001 Curated Semgrep rules relevant to MCP servers

Reporting
- Each rule emits: ruleId, title, severity, description, references (spec/RFC/paper links), evidence, remediation, fingerprint
- Outputs: JSON, SARIF 2.1.0; HTML dashboard aggregates by category and severity
