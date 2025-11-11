#!/usr/bin/env bash
set -euo pipefail
# Run vuln-mcp with current environment
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
cd "${repo_root}/vuln-mcp"
exec go run .
