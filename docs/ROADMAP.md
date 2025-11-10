# Roadmap

This roadmap prioritizes an MCP-focused security scanner with protocol compliance, runtime probes, and production-grade outputs. Each phase lists deliverables and acceptance criteria.

Milestone 0 — Project scaffolding (Week 0)
- Deliverables
  - docs/: ROADMAP, ARCHITECTURE, SECURITY_TEST_PLAN, RESEARCH_COMPARISON, LESSONS_LEARNED, TODO
  - Baseline config format (YAML) draft and exit code convention
- Acceptance
  - Docs reviewed; contributors can align on goals and scope

Milestone 1 — Discovery & Inventory (Week 1)
- Deliverables
  - MCP server discovery: RFC9728/8414 OAuth metadata; parse WWW-Authenticate on 401
  - Capabilities inventory: tools/resources/prompts schema snapshot
  - Output: JSON report with versioning
- Acceptance
  - Against known servers, discovery returns AS metadata and capability lists deterministically

Milestone 2 — Auth & Transport Compliance (Weeks 2–3)
- Deliverables
  - OAuth 2.1 Authorization Code + PKCE tests as public client
  - resource (RFC8707) and audience validation checks
  - Token passthrough negative tests; HTTPS and redirect URI validation; open-redirect detection
- Acceptance
  - Servers that violate spec are flagged with evidence; compliant servers pass

Milestone 3 — Runtime Security Probes (Weeks 4–5)
- Deliverables
  - Dangerous-surface detection (file/process/network tools) with sandbox/allowlist guidance
  - SSRF tests for URL-fetch tools
  - Prompt-injection harness; session-hijack tests (no session for auth, strong session IDs)
- Acceptance
  - High-signal findings on common OSS servers without excessive false positives

Milestone 4 — SAST & Supply Chain (Weeks 6–7)
- Deliverables
  - Semgrep integration (curated ruleset)
  - Supply-chain checks (malicious scripts, http deps, wildcards, package confusion) for Node/Python/Go
- Acceptance
  - Reproducible SAST/SCA results; low-noise profiles validated on sample repos

Milestone 5 — Threat Intelligence (Week 8)
- Deliverables
  - Optional enrichment (NVD API, MITRE ATT&CK mapping); cache layer
- Acceptance
  - Findings show CVEs/ATT&CK techniques where relevant; disabled by default in CI

Milestone 6 — Reporting & CI (Weeks 9–10)
- Deliverables
  - JSON, SARIF 2.1.0 outputs; standardized exit codes; progress UI
  - HTML dashboard (Phase 2.5) with risk scoring and evidence links
- Acceptance
  - CI integration in GitHub/GitLab succeeds; SARIF ingested; HTML usable locally

Milestone 7 — Policy Engine & Gating (Week 11)
- Deliverables
  - Policy-as-code (YAML): allowed tool classes, HTTPS required, audience checks, etc.
  - CI gate: fail on policy violations with actionable messages
- Acceptance
  - Policy toggles produce deterministic pass/fail; devs can suppress with justifications

Milestone 8 — Marketplace Hygiene (Week 12)
- Deliverables
  - Heuristics: tool poisoning/MPMA, typosquatting, obfuscation, signed releases/SBOM presence, maintainer reputation
- Acceptance
  - Detects known bad patterns with clear rationales; low false positives

Milestone 9 — Performance & Packaging (Weeks 13–14)
- Deliverables
  - Engine optimization (Go or Rust) for parallel probes; single-binary distribution; Docker image
- Acceptance
  - <2s small-server scan target; memory bounded; cross-platform binaries

Milestone 10 — Hardening & Release (Week 15)
- Deliverables
  - Versioned rule IDs; semantic versioning; CONTRIBUTING; release notes; telemetry toggle
- Acceptance
  - Tagged release; changelog; docs up to date
Add a research assistance to gather info everyday from different reources from across the internet to seek what new 
and what security researches are talking about. new MCP vulnerabilities, zero day, current attack vectores and new 
and upcoming issues that were reported through the week. Update this somewhere and set a reminder to look into it 
and figure if this is something to be worried about or could this be incorporated into our product. 