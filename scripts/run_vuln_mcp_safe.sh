#!/usr/bin/env bash
set -euo pipefail
# Launch vuln-mcp with safer behaviors (close known vulnerabilities)
export VULN_ACCEPT_ALG_NONE=false
export VULN_WEAK_RSA_KEY=false
export VULN_NO_HSTS=false
export VULN_DANGEROUS_TOOL=false
export VULN_ALLOW_GET_PUT=false
export VULN_ALLOW_TRACE=false
export VULN_ACCEPT_MISSING_CT=false
export VULN_ALLOW_TRAVERSAL=false
export VULN_PERMISSIVE_TOOL_RUN=false
export VULN_REPLAY_CODE=false
export VULN_ACCEPT_BOGUS_TOKEN=false
export VULN_SSRF_BLOCK=true

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec "${script_dir}/run_vuln_mcp.sh"
