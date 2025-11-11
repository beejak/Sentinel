# Testing

Overview
- This project includes a local test harness providing a mock OIDC Authorization Server and a protected MCP-like resource.
- Purpose: exercise discovery, dynamic client registration, and OAuth 2.1 + PKCE flows without a live MCP endpoint.

Contents
- testharness/ (Go)
  - /.well-known/openid-configuration and /.well-known/oauth-authorization-server
  - /register (dynamic client registration)
  - /authorize, /token, /jwks.json
  - / (protected resource returns 200 only with valid Bearer JWT)

Build and run (local)
- Prerequisites: Go 1.21+
- Build:
  - `go build -o testharness.exe ./testharness`
- Run:
  - `./testharness.exe`
  - Server listens on http://127.0.0.1:8085

Vulnerable MCP server (vuln-mcp/)
- Purpose: exercise scanner probes against intentionally insecure behaviors.
- Default port: 8090
- Build:
  - `go build -o vuln-mcp.exe ./vuln-mcp`
- Run (defaults to vulnerable):
  - `./vuln-mcp.exe`
- Quick start (fully-insecure, cmd.exe):
  - `scripts\run_vuln_mcp_insecure.cmd`
- Quick start (fully-insecure, macOS/Linux):
  - `bash scripts/run_vuln_mcp_insecure.sh`
- Quick start (safer, cmd.exe):
  - `scripts\run_vuln_mcp_safe.cmd`
- Quick start (safer, macOS/Linux):
  - `bash scripts/run_vuln_mcp_safe.sh`
- Run normally (macOS/Linux):
  - `bash scripts/run_vuln_mcp.sh`
- Toggle vulnerabilities via env vars (true by default):
  - `VULN_ALLOW_GET_PUT` (allow GET/PUT on /tool/run)
  - `VULN_ALLOW_TRACE` (allow TRACE on /tool/run)
  - `VULN_ACCEPT_MISSING_CT` (accept POST without Content-Type)
  - `VULN_ALLOW_TRAVERSAL` (allow path traversal/privileged paths)
  - `VULN_PERMISSIVE_TOOL_RUN` (accept invalid JSON/tool/args)
  - `VULN_REPLAY_CODE` (allow authorization code reuse)
  - `VULN_ACCEPT_BOGUS_TOKEN` (accept any bearer token at /)
  - `VULN_SSRF_BLOCK` (set true to enable basic SSRF blocking; defaults to false for vulnerability)
  - `VULN_ACCEPT_ALG_NONE` (accept unsigned JWTs alg=none)
  - `VULN_WEAK_RSA_KEY` (use 1024-bit RSA key in JWKS)
  - `VULN_NO_HSTS` (omit HSTS header)
  - `VULN_DANGEROUS_TOOL` (expose a dangerous `exec` tool in /tools)

Scanner usage with harness
- Dynamic registration + PKCE (Python API):
  ```python
  from scanner.auth import run_auth_flow_dynamic
  res = run_auth_flow_dynamic(target="http://127.0.0.1:8085", scopes="openid profile", redirect_port=8765, resource=None, open_browser=False)
  ```
- Expected results:
  - Dynamic registration returns a client_id.
  - Authorization auto-approves and redirects to local callback with code/state.
  - Token endpoint issues an RS256 JWT with aud set to the requested resource (if provided).
  - Root resource responds 401 to bogus tokens (negative test passes).

Notes
- The harness is intentionally permissive and auto-approving to simplify local testing.
- Keys are ephemeral per run; JWKS is published at /jwks.json.
- Not for production use.
