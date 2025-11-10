# Probe Catalog

This document lists available probes, their rule IDs, purpose, and typical outcomes.

<a id="probe-001"></a>
### PROBE-001 — BogusTokenProbe (high)
  Ensures resource rejects requests with bogus bearer tokens (expects 401/403).

<a id="probe-002"></a>
### PROBE-002 — MalformedRequestProbe (medium/low)
  Sends invalid Content-Type and JSON body on GET; flags 5xx responses.

<a id="probe-003"></a>
### PROBE-003 — OversizePayloadProbe (intrusive, medium/low)
  Sends large POST payloads; flags 5xx responses.

<a id="probe-004"></a>
### PROBE-004 — CORSPreflightProbe (low)
  Checks for permissive CORS preflight responses; informational.

<a id="probe-005"></a>
### PROBE-005 — ToolGuardrailsProbe (high/medium/low)
  Attempts dangerous tool invocations (path traversal, sensitive files). Expects deny with structured error.

<a id="probe-006"></a>
### PROBE-006 — StateReplayProbe (high)
  Confirms authorization codes are single-use (replay should fail with invalid_grant).

<a id="probe-007"></a>
### PROBE-007 — RateLimitProbe (low)
  Bursts /tool/run calls; expects 429s and Retry-After.

<a id="probe-008"></a>
### PROBE-008 — MethodMatrixProbe (high/medium/low)
  Ensures /tool/run disallows GET/PUT; /tools GET should not 5xx.

<a id="probe-009"></a>
### PROBE-009 — ContentTypeMatrixProbe (high/medium/low)
  Tests mismatched Content-Type and bodies; expects 4xx structured errors.

<a id="probe-010"></a>
### PROBE-010 — InvalidAuthProbe (high/medium/low)
  Ensures /tool/run requires Authorization header and returns structured errors.

<a id="probe-011"></a>
### PROBE-011 — TraceMethodProbe (high/medium/low)
  TRACE should not be allowed on /tool/run.

<a id="probe-012"></a>
### PROBE-012 — MissingContentTypeProbe (high/medium/low)
  POST without Content-Type should be rejected with structured error.

<a id="probe-013"></a>
### PROBE-013 — LargeHeaderProbe (intrusive, medium/low)
  Large header should not cause 5xx.

<a id="probe-014"></a>
### PROBE-014 — SSRFProbe (high/medium/low)
  Attempts to coerce server to fetch private/loopback URLs; expects deny.

<a id="probe-015"></a>
### PROBE-015 — SecurityHeadersProbe (low)
  Checks root response for common security headers (X-Content-Type-Options, X-Frame-Options, CSP, Referrer-Policy).

<a id="probe-016"></a>
### PROBE-016 — ToolSchemaValidationProbe (high/medium/low)
  Validates /tools JSON structure and policy. Flags dangerous tool names (exec/shell/system etc.), missing read_file roots, and missing fetch_url blocked list.
