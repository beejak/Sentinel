# Probe Catalog

<a id="probe-017"></a>
### PROBE-017 — NoneAlgTokenProbe (high)
  Sends unsigned JWT (alg=none). Accepting it is a critical flaw.
  Fix: Reject alg=none; enforce signature verification.

<a id="probe-018"></a>
### PROBE-018 — JWKSKeyStrengthProbe (high/medium)
  Flags RSA keys < 2048 bits, unsupported EC curves, and alg/kty/crv mismatches.
  Fix: Use RSA >= 2048; EC curves P-256/384/521; align alg with kty/crv.

<a id="probe-019"></a>
### PROBE-019 — HSTSAndTLSProbe (low/medium)
  Checks for HSTS header on HTTPS origins and outdated TLS.
  Fix: Enable HSTS and disable TLS 1.0/1.1.
This document lists available probes, their rule IDs, purpose, and typical outcomes.

<a id="probe-001"></a>
### PROBE-001 — BogusTokenProbe (high)
  Ensures resource rejects requests with bogus bearer tokens (expects 401/403).
  Fix: Always validate bearer tokens server-side and return 401/403 for invalid or expired tokens.

<a id="probe-002"></a>
### PROBE-002 — MalformedRequestProbe (medium/low)
  Sends invalid Content-Type and JSON body on GET; flags 5xx responses.
  Fix: Validate methods and Content-Type; fail fast with 4xx and structured errors.

<a id="probe-003"></a>
### PROBE-003 — OversizePayloadProbe (intrusive, medium/low)
  Sends large POST payloads; flags 5xx responses.
  Fix: Enforce reasonable request body limits; return 413 or structured 4xx.

<a id="probe-004"></a>
### PROBE-004 — CORSPreflightProbe (low)
  Checks for permissive CORS preflight responses; informational.
  Fix: Restrict allowed origins/headers/methods to the minimum required.

<a id="probe-005"></a>
### PROBE-005 — ToolGuardrailsProbe (high/medium/low)
  Attempts dangerous tool invocations (path traversal, sensitive files). Expects deny with structured error.
  Fix: Enforce tool policy (allowlisted roots for read_file, blocked CIDRs for fetch_url) and structured 403.

<a id="probe-006"></a>
### PROBE-006 — StateReplayProbe (high)
  Confirms authorization codes are single-use (replay should fail with invalid_grant).
  Fix: Mark codes one-time-use and expire quickly; enforce PKCE.

<a id="probe-007"></a>
### PROBE-007 — RateLimitProbe (low)
  Bursts /tool/run calls; expects 429s and Retry-After.
  Fix: Add per-user/tool rate limits and include Retry-After.

<a id="probe-008"></a>
### PROBE-008 — MethodMatrixProbe (high/medium/low)
  Ensures /tool/run disallows GET/PUT; /tools GET should not 5xx.
  Fix: Restrict /tool/run to POST and return 405 for others.

<a id="probe-009"></a>
### PROBE-009 — ContentTypeMatrixProbe (high/medium/low)
  Tests mismatched Content-Type and bodies; expects 4xx structured errors.
  Fix: Require application/json for JSON bodies; reject mismatches with structured 4xx.

<a id="probe-010"></a>
### PROBE-010 — InvalidAuthProbe (high/medium/low)
  Ensures /tool/run requires Authorization header and returns structured errors.
  Fix: Enforce auth on sensitive endpoints; return 401/403 with a JSON error schema.

<a id="probe-011"></a>
### PROBE-011 — TraceMethodProbe (high/medium/low)
  TRACE should not be allowed on /tool/run.
  Fix: Disable TRACE globally or per-route.

<a id="probe-012"></a>
### PROBE-012 — MissingContentTypeProbe (high/medium/low)
  POST without Content-Type should be rejected with structured error.
  Fix: Require Content-Type and reject requests without it.

<a id="probe-013"></a>
### PROBE-013 — LargeHeaderProbe (intrusive, medium/low)
  Large header should not cause 5xx.
  Fix: Limit header sizes and return 4xx or drop requests instead of 5xx.

<a id="probe-014"></a>
### PROBE-014 — SSRFProbe (high/medium/low)
  Attempts to coerce server to fetch private/loopback URLs; expects deny.
  Fix: Block link-local, loopback and RFC1918 ranges for outbound fetch tools.

<a id="probe-015"></a>
### PROBE-015 — SecurityHeadersProbe (low)
  Checks root response for common security headers (X-Content-Type-Options, X-Frame-Options, CSP, Referrer-Policy).
  Fix: Add the headers with secure values; adopt a basic CSP and SAMEORIGIN/deny framing.

<a id="probe-016"></a>
### PROBE-016 — ToolSchemaValidationProbe (high/medium/low)
  Validates /tools JSON structure and policy. Flags dangerous tool names (exec/shell/system etc.), missing read_file roots, and missing fetch_url blocked list.
  Fix: Document a safe tool schema; avoid dangerous names; include read_file roots and fetch_url blocked list.
