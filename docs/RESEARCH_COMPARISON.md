# Research Comparison (MCP scanners)

Reference project: beejak/MCP_Scanner (mcp-sentinel)
- Strengths we should emulate
  - Packaging & CI: SARIF 2.1.0 output, standardized exit codes, Docker/binaries, YAML config, progress UI
  - Reporting: interactive HTML dashboards with risk scoring (Phase 2.5)
  - SAST/SCA: Semgrep integration; supply-chain patterns (install scripts, http deps, wildcards, confusion)
  - Threat intel: optional NVD/MITRE enrichment; real-world context
  - Performance: Rust + concurrent scanning
- Gaps relative to MCP protocol/security research
  - Protocol/auth MUSTs: PKCE enforcement, resource/audience checks, token passthrough rejection, HTTPS/redirect validation, RFC9728/8414 discovery
  - Confused deputy: per-client consent flows; cookie/consent reuse detection
  - Runtime probes: invoke MCP tools safely; sandbox/allowlist checks; SSRF protections
  - Session hygiene: no session-for-auth; robust session IDs
  - Ecosystem abuse: tool poisoning/MPMA detection; marketplace vetting (typosquatting, obfuscation, signatures, SBOM, maintainer reputation)
  - Inspector artifacts: reproducible sessions for modelcontextprotocol/inspector
- Conclusion
  - Combine mcp-sentinel’s packaging/reporting/SAST-SCA strengths with deep protocol compliance and runtime probe focus from MCP spec and academia.
