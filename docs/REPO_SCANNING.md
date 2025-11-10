# Repo scanning with Semgrep

Sentinel can scan repositories using Semgrep to catch secrets, supply-chain risks, and unsafe patterns.

Usage
- Local path: `python main.py repo-scan --path <dir> --out repo.json --html repo.html`
- Remote repo: `python main.py repo-scan --repo https://github.com/org/repo.git --out repo.json`
- Docker fallback for Semgrep: `--semgrep-docker`

Rule packs
We invoke Semgrep with recommended packs and fall back to `auto` if unavailable:
- p/secrets — secret detection
- p/ci — common CI misconfigurations
- p/r2c-security-audit — general security checks
- p/owasp-top-ten — web-centric checks

Outputs
- JSON (default)
- HTML (summary table with severity counts)
- SARIF via our converter (`--sarif out.sarif`)

Notes
- Ensure Semgrep is installed or use `--semgrep-docker` with Docker installed.
- In offline/air-gapped environments, rule packs may not resolve; we automatically fall back to `--config auto`.
