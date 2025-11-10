# Probe Catalog

This document lists available probes, their rule IDs, purpose, and typical outcomes.

- PROBE-001 — BogusTokenProbe (high)
  Ensures resource rejects requests with bogus bearer tokens (expects 401/403).

- PROBE-002 — MalformedRequestProbe (medium/low)
  Sends invalid Content-Type and JSON body on GET; flags 5xx responses.

- PROBE-003 — OversizePayloadProbe (intrusive, medium/low)
  Sends large POST payloads; flags 5xx responses.

- PROBE-004 — CORSPreflightProbe (low)
  Checks for permissive CORS preflight responses; informational.

- PROBE-005 — ToolGuardrailsProbe (high/medium/low)
  Attempts dangerous tool invocations (path traversal, sensitive files). Expects deny with structured error.

- PROBE-006 — StateReplayProbe (high)
  Confirms authorization codes are single-use (replay should fail with invalid_grant).

- PROBE-007 — RateLimitProbe (low)
  Bursts /tool/run calls; expects 429s and Retry-After.

- PROBE-008 — MethodMatrixProbe (high/medium/low)
  Ensures /tool/run disallows GET/PUT; /tools GET should not 5xx.

- PROBE-009 — ContentTypeMatrixProbe (high/medium/low)
  Tests mismatched Content-Type and bodies; expects 4xx structured errors.

- PROBE-010 — InvalidAuthProbe (high/medium/low)
  Ensures /tool/run requires Authorization header and returns structured errors.

- PROBE-011 — TraceMethodProbe (high/medium/low)
  TRACE should not be allowed on /tool/run.

- PROBE-012 — MissingContentTypeProbe (high/medium/low)
  POST without Content-Type should be rejected with structured error.

- PROBE-013 — LargeHeaderProbe (intrusive, medium/low)
  Large header should not cause 5xx.

- PROBE-014 — SSRFProbe (high/medium/low)
  Attempts to coerce server to fetch private/loopback URLs; expects deny.

- PROBE-015 — SecurityHeadersProbe (low)
  Checks root response for common security headers (X-Content-Type-Options, X-Frame-Options, CSP, Referrer-Policy).
