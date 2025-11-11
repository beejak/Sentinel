#!/usr/bin/env bash
set -euo pipefail
# Launch vuln-mcp with all insecure behaviors enabled
export VULN_ACCEPT_ALG_NONE=true
export VULN_WEAK_RSA_KEY=true
export VULN_NO_HSTS=true
export VULN_DANGEROUS_TOOL=true
export VULN_ALLOW_GET_PUT=true
export VULN_ALLOW_TRACE=true
export VULN_ACCEPT_MISSING_CT=true
export VULN_ALLOW_TRAVERSAL=true
export VULN_PERMISSIVE_TOOL_RUN=true
export VULN_REPLAY_CODE=true
export VULN_ACCEPT_BOGUS_TOKEN=true
export VULN_SSRF_BLOCK=false

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec "${script_dir}/run_vuln_mcp.sh"
