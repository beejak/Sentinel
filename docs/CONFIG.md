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

Per-domain headers and overrides
- Configure host-specific overrides without sending credentials to every host:
```
domains:
  api.example.com:
    headers:
      Authorization: "Bearer <TOKEN>"
    verify: true        # or false, or path to CA bundle
    cert: /path/to/cert.pem
    key: /path/to/key.pem
    proxy: http://127.0.0.1:8080
    allow_auth: true    # explicitly allow Authorization to this host under strict policy
  .internal.example.com:
    headers:
      X-Org: "security-scan"
```
- A leading dot matches subdomains (e.g., .example.com)
- Domain headers merge after global headers and CLI/env headers.

Strict Authorization policy
- Set `policy.strict_auth_domains: true` to strip Authorization unless the target host matches a configured domain entry with `headers.Authorization` or `allow_auth: true`.

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
