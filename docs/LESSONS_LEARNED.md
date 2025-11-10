# Lessons Learned

From official MCP docs
- The spec mandates OAuth 2.1 behaviors (PKCE, HTTPS, exact redirect URIs) and resource/audience validation; rejecting tokens not issued to the server is non-negotiable.
- Security Best Practices identify Confused Deputy, Token Passthrough, and Session Hijacking as common pitfalls with concrete mitigations.

From academic work
- Malicious MCP servers are feasible, cheap to create, and hard to detect with generic scanners; MCP-specific tests are required.
- Tool poisoning/preference manipulation can bias LLM routing; scanners must assess metadata, not only code.
- Marketplaces/aggregators may have weak vetting; users are likely to install malicious servers unintentionally.

From industry/community
- Vendors with strong OAuth/infra (GitHub, Google, Cloudflare) tend to be more compliant and auditable; hobby servers vary widely.
- Ephemeral, isolated execution contexts (browsers/sessions) reduce blast radius.

Implications for our scanner
- Prioritize protocol compliance and runtime probes; SAST/SCA enhance coverage but don’t replace MCP-specific checks.
- Provide policy-as-code and CI gating to shift-left and make results actionable.
- Offer SARIF/HTML outputs; keep JSON stable; include evidence snippets and spec references for each finding.

Design guardrails
- No token passthrough; always validate audience.
- Never treat sessions as authentication; ensure strong, bound session IDs.
- Default-deny dangerous surfaces; require allowlists and explicit opt-in.
