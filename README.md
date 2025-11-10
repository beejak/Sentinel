# MCP Scanner

[![CI](https://github.com/beejak/Sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/beejak/Sentinel/actions/workflows/ci.yml)
[![CodeQL](https://github.com/beejak/Sentinel/actions/workflows/codeql.yml/badge.svg)](https://github.com/beejak/Sentinel/actions/workflows/codeql.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A lightweight command-line tool to scan and report on MCP endpoints, schemas, and capabilities.

## Goals
- Discover and enumerate MCP servers/endpoints
- Probe and validate capabilities
- Output structured results (JSON) and human-readable summaries

## Quick start
- Python 3.10+
- Run: `python main.py --help`

### Windows one-liners (cmd)
- Setup venv + deps: `scripts\setup.cmd`
- Run CLI: `scripts\run_scanner.cmd --help`
- Start local harness (secure): `scripts\run_harness.cmd`
- Start vulnerable MCP server: `scripts\run_vuln_mcp.cmd`

### Make targets (macOS/Linux or with make on Windows)
- `make install` – create venv and install deps
- `make py-check` – Python syntax check
- `make run ARGS="discover http://127.0.0.1:8085"`
- `make harness` / `make vuln` – run Go servers
- `make build-harness` – build Go binaries into `bin/`

## CLI usage
```
python main.py discover <target> [-o out.json]
python main.py auth <target> --client-id <id> [--scopes "openid profile"] [--redirect-port 8765] [--resource <origin>] [--open-browser] [-o out.json]
python main.py auth-dynamic <issuer> [--scopes "openid profile"] [--redirect-port 8765] [--resource <origin>] [--open-browser] [-o out.json]
python main.py probe <target> [--profile baseline|intrusive] [--timeout 10] [--out findings.json] [--sarif report.sarif] [--no-fail]
python main.py scan <target> [--json]
```

Examples:
- Discover against harness: `python main.py discover http://127.0.0.1:8085`
- Probe vulnerable server: `python main.py probe http://127.0.0.1:8090 --profile baseline`

## Dev notes
- Go test harness lives in `testharness/`; vulnerable server in `vuln-mcp/`.
- CI runs Python smoke and Go builds on each push/PR (see `.github/workflows/ci.yml`).
- Release workflow builds Go binaries for Windows/Linux/macOS on tag push `v*` and publishes a GitHub Release.

To cut a release:
1. Tag: `git tag v0.1.0 && git push origin v0.1.0`
2. GitHub Actions will attach the built harness binaries to the release.
