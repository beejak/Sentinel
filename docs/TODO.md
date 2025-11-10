# TODO (Project)

Now
- [ ] Milestone 1: Discovery & Inventory
  - [ ] Implement RFC9728/8414 metadata discovery and 401 WWW-Authenticate parsing
  - [ ] Enumerate tools/resources/prompts; JSON report v0.1
- [ ] Milestone 2: Auth & Transport
  - [ ] PKCE code flow (public client), state; resource (RFC8707); audience check
  - [ ] Token passthrough negative test; HTTPS/redirect URI validation; open-redirect detector
- [ ] Configuration & Outputs
  - [ ] YAML config schema draft; exit codes; progress UI draft
  - [ ] JSON writer with stable schema and versioning

Next
- [ ] Milestone 3: Runtime probes
  - [ ] Dangerous-surface detector; SSRF tests; prompt-injection harness; session-hijack checks
- [ ] Milestone 4: SAST/SCA
  - [ ] Semgrep curated rules; Node/Python/Go supply-chain patterns
- [ ] Milestone 5: Threat intel
  - [ ] Optional NVD/MITRE enrichment (disabled by default); local cache
- [ ] Milestone 6: Reporting & CI
  - [ ] SARIF 2.1.0 writer; HTML dashboard; GitHub/GitLab CI examples
- [ ] Milestone 7: Policy engine & gating
  - [ ] YAML policy; CI fail-on policy violations with actionable remediation
- [ ] Milestone 8: Marketplace hygiene
  - [ ] MPMA/tool-poisoning heuristics; typosquatting/obfuscation/signature/SBOM checks

Operational
- [ ] Release engineering (checksums/signatures; changelog)
- [ ] Telemetry opt-in design (anonymous usage counts), privacy policy draft
- [ ] Weekly research sweep: track new MCP vulns/zero-days/attack vectors; triage into rules
