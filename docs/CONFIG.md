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

Environment variables
- SENTINEL_OFFLINE=true|false
- SENTINEL_ENABLE_PRIVATE_EGRESS_CHECKS=true|false
- SENTINEL_HTTP_VERIFY=true|false|/path/to/ca.pem
- SENTINEL_HTTP_CERT=/path/to/cert.pem
- SENTINEL_HTTP_KEY=/path/to/key.pem
- SENTINEL_HTTP_PROXY=http://127.0.0.1:8080
- SENTINEL_HTTP_TIMEOUT=15
- SENTINEL_HTTP_HEADER_AUTHORIZATION="Bearer X..." (any header as SENTINEL_HTTP_HEADER_*)
