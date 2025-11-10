# Contributing

Thanks for your interest in contributing!

## Development setup
- Python 3.10+
- Go 1.21+
- Install dev tools: `pip install -r requirements-dev.txt`
- Optional: `pre-commit install`

## Running
- CLI help: `python main.py --help` or `scripts\run_scanner.cmd --help`
- Local secure harness: `scripts\run_harness.cmd`
- Local vulnerable server: `scripts\run_vuln_mcp.cmd`

## Style & quality
- Python: ruff + black; type checking with mypy
- Tests: pytest (`pytest -q`)
- CI runs formatting, lint, mypy and tests on PRs

## Pull requests
- Create a feature branch from `main`
- Add tests when adding behavior
- Update docs/README as needed
- Ensure `make py-check` and tests pass

## Reporting issues
- Use the issue templates; include repro steps and environment details
