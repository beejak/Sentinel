# Usage

Commands
- Discover OAuth/OIDC metadata and auth hints
  - python main.py discover <base-url> [-o out.json]
- Run OAuth 2.1 + PKCE compliance checks (Milestone 2)
  - python main.py auth <base-url> --client-id <id> [--scopes "scope1 scope2"] [--resource <uri>] [--redirect-port 8765] [--open-browser] [-o out.json]
- Dynamic registration + PKCE (no client pre-setup)
  - python main.py auth-dynamic <issuer-base-url> [--scopes "openid profile"] [--resource <uri>] [--redirect-port 8765] [--open-browser] [-o out.json]
- Runtime probes (Milestone 3)
  - python main.py probe <base-url> [--profile baseline|intrusive] [--timeout 10] [--out findings.json] [--sarif findings.sarif] [--no-fail]
    - Baseline probes: PROBE-001 (Bogus token), PROBE-002 (Malformed GET), PROBE-004 (CORS preflight), PROBE-005 (Tool guardrails + structured error), PROBE-006 (Auth code replay), PROBE-007 (Rate limiting), PROBE-008 (Method matrix), PROBE-009 (Content-Type matrix), PROBE-010 (Invalid auth), PROBE-011 (TRACE method), PROBE-012 (Missing Content-Type), PROBE-014 (SSRF/egress)
    - Intrusive adds: PROBE-003 (Oversize payload), PROBE-013 (Large header)
- Legacy stub scan
  - python main.py scan <base-url> [--json]

Defaults
- Redirect callback port: 8765 (auth --redirect-port)
- Local test harness port: 8085 (testharness)

Auth flow notes
- The auth command will:
  - Discover authorization/token endpoints via well-known docs or WWW-Authenticate.
  - Generate PKCE code challenge and a random state.
  - Provide an authorization URL; with --open-browser it attempts to launch your browser.
  - Start a temporary localhost HTTP server to capture the redirect with code/state.
  - Exchange code for tokens and attempt to validate token audience (if JWT) against the resource parameter.
  - Perform a negative test by sending a bogus bearer token to the resource and expect 401/403.

Tips
- Client must be registered with redirect URI http://127.0.0.1:<port>/callback.
- If the access_token is an opaque token, audience_ok may be null (unknown from client-side).
- For non-interactive CI, you can run auth with a pre-authorized code via manual paste by opening the auth_url yourself and letting the local callback receive the code.

Dynamic Client Registration (optional)
- If the authorization server exposes a `registration_endpoint` in discovery, you can request a public client dynamically.
- Programmatic use (Python API):
  ```python
  from scanner.auth import run_auth_flow_dynamic
  result = run_auth_flow_dynamic(target="http://localhost:8085", scopes="openid profile", redirect_port=8765, resource=None, open_browser=False)
  ```
- This will register a client with redirect URI `http://127.0.0.1:8765/callback` and run the PKCE flow.

Local Test Harness (mock MCP + OIDC)
- A lightweight local server is provided under `testharness/` to exercise discovery and auth flows without a live MCP URL.
- Start it (build required): see `docs/TESTING.md` for instructions.
- Default issuer: `http://127.0.0.1:8085`
- Endpoints exposed:
  - `/.well-known/openid-configuration`, `/.well-known/oauth-authorization-server`
  - `/register` (dynamic client registration)
  - `/authorize`, `/token`, `/jwks.json`
  - `/` (protected resource; rejects bogus tokens with 401)
