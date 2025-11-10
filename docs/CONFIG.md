# Sentinel Configuration (sentinel.yml)

This file defines default behavior for the scanner. CLI flags override config values; environment variables override the file as well.

Precedence:
1. CLI flags
2. Environment variables (SENTINEL_*)
3. sentinel.yml
4. Built-in defaults

Keys
- offline (bool)
  - Disable live network calls (discovery/probes). Repo-mode unaffected.

- policy.enable_private_egress_checks (bool)
  - Opt-in to private-network SSRF tests and CIDR checks.

- http
  - verify: true|false|path
    - TLS verification. Path points to CA bundle.
  - cert: path
  - key: path
  - proxy: url
    - Applies to http and https.
  - timeout: seconds (default: 10)
- headers: map of additional headers
  - Safe defaults: User-Agent, Accept
  - Commented templates provided in sentinel.yml for Authorization, X-API-Key, Proxy-Authorization, X-Request-ID

Per-domain headers
- Configure host-specific headers without sending credentials to every host:
```
domains:
  api.example.com:
    headers:
      Authorization: "Bearer <TOKEN>"
  .internal.example.com:
    headers:
      X-Org: "security-scan"
```
- A leading dot matches subdomains (e.g., .example.com)
- Domain headers are merged after global headers and CLI/env headers.

Environment variables

Common header templates (enable one of these in sentinel.yml or via CLI/env)
- Authorization: Bearer <TOKEN>
- X-API-Key: <KEY>
- Proxy-Authorization: Basic <BASE64_USER_PASS>
- X-Request-ID: <RUN_ID>

Hints
- Prefer CLI: --header "Authorization: Bearer <TOKEN>"
- Or env: SENTINEL_HTTP_HEADER_AUTHORIZATION="Bearer <TOKEN>"
- Keep sensitive headers commented in sentinel.yml to avoid accidental commits/leaks.

Environment variables
- SENTINEL_OFFLINE=true|false
- SENTINEL_ENABLE_PRIVATE_EGRESS_CHECKS=true|false
- SENTINEL_HTTP_VERIFY=true|false|/path/to/ca.pem
- SENTINEL_HTTP_CERT=/path/to/cert.pem
- SENTINEL_HTTP_KEY=/path/to/key.pem
- SENTINEL_HTTP_PROXY=http://127.0.0.1:8080
- SENTINEL_HTTP_TIMEOUT=15
- SENTINEL_HTTP_HEADER_AUTHORIZATION="Bearer X..." (any header as SENTINEL_HTTP_HEADER_*)
