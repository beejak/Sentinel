`
# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.
``

## Overview

- Purpose: command-line tool to scan and report on MCP endpoints, schemas, and capabilities.
- Entry point: `main.py` exposes a small argparse-based CLI.
- Core flow:
  - `main.py` parses args (`target`, optional `--json`).
  - Calls `scan(target)` which currently returns a stubbed result dict.
  - Outputs human-readable text or JSON (when `--json` is provided).
- Dependencies: currently stdlib-only; `requirements.txt` has no active third-party libs.

Relevant docs pulled from `README.md`:
- Goals: discover MCP servers/endpoints, probe/validate capabilities, output JSON and summaries.
- Quick start: Python 3.10+, run `python main.py --help`.

## Commands

Environment setup (choose your OS):
- macOS/Linux
  - Create venv: `python3 -m venv .venv`
  - Activate: `source .venv/bin/activate`
- Windows (PowerShell)
  - Create venv: `py -3 -m venv .venv`
  - Activate: `.\.venv\Scripts\Activate.ps1`

Install dependencies:
- `pip install -r requirements.txt`

Run the CLI:
- Help: `python main.py --help`
- Scan target (text output): `python main.py <target>`
- Scan target (JSON output): `python main.py <target> --json`

Testing and linting:
- No test suite or linters are configured in this repo at present.

## Architecture notes

- `main.py`
  - `scan(target)` is a placeholder; replace with real MCP discovery/probing logic.
  - CLI prints either a formatted summary or `json.dumps(result, indent=2)` when `--json` is set.
- As the project grows, consider extracting modules (e.g., `scanner/`, `cli/`) and adding tests under `tests/`.

## Tooling and rules

- There are no project-specific AI assistant rules files (Claude, Cursor, Copilot) in this repository.
- No additional build, lint, or type-check commands are defined beyond the basics above.
