import argparse
import json
import logging
from typing import Any, Dict

from scanner.discovery import discover
from scanner.auth import run_auth_flow, run_auth_flow_dynamic
from scanner.probes import run_probes

logger = logging.getLogger(__name__)

class JSONLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:  # type: ignore[override]
        payload = {
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        return json.dumps(payload)

def scan(target: str) -> Dict[str, Any]:
    """Placeholder scanner implementation.

    Replace with real MCP probing logic beyond discovery.
    """
    return {
        "target": target,
        "reachable": False,
        "capabilities": [],
        "notes": "Scanner stub — implement real checks."
    }



def main() -> None:
    parser = argparse.ArgumentParser(description="MCP Scanner CLI")
    subparsers = parser.add_subparsers(dest="command")

    # Common parent for shared flags
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--log-level", default="INFO", help="Logging level (DEBUG, INFO, WARNING, ERROR)")
    common.add_argument("--log-format", choices=["text", "json"], default="text", help="Log output format")
    common.add_argument("--offline", action="store_true", help="Disable all network activity (skip live endpoint checks)")
    common.add_argument("--enable-private-egress-checks", action="store_true", help="Opt-in to private-network SSRF/egress tests")
    common.add_argument("--config", help="Path to sentinel.yml (config-as-code)")
    common.add_argument("--verify", help="TLS verify: true/false or path to CA bundle")
    common.add_argument("--cert", help="Client certificate path (PEM or PFX if supported)")
    common.add_argument("--key", help="Client private key path (PEM)")
    common.add_argument("--proxy", help="HTTP/HTTPS proxy URL")
    common.add_argument("--header", action="append", help="Additional header, e.g., 'Name: Value' (can be repeated)")

    # discover subcommand
    p_discover = subparsers.add_parser("discover", parents=[common], help="Discover OAuth metadata and capabilities for an MCP server")
    p_discover.add_argument("target", help="MCP server base URL (e.g., https://example.com)")
    p_discover.add_argument("--output", "-o", help="Write JSON results to file instead of stdout")

    # auth subcommand
    p_auth = subparsers.add_parser("auth", parents=[common], help="Run OAuth 2.1 + PKCE compliance checks against an MCP server")
    p_auth.add_argument("target", help="MCP server base URL (e.g., https://example.com)")
    p_auth.add_argument("--client-id", required=True, help="OAuth client_id (public client)")
    p_auth.add_argument("--scopes", default="", help="Space-separated scopes to request")
    p_auth.add_argument("--redirect-port", type=int, default=8765, help="Local redirect port (default: 8765)")
    p_auth.add_argument("--resource", help="Override resource parameter (defaults to target origin)")
    p_auth.add_argument("--open-browser", action="store_true", help="Open the system browser automatically for authorization")
    p_auth.add_argument("--output", "-o", help="Write JSON results to file instead of stdout")

    # auth-dynamic subcommand
    p_auth_dyn = subparsers.add_parser("auth-dynamic", parents=[common], help="Dynamic client registration then PKCE auth")
    p_auth_dyn.add_argument("target", help="Authorization server base URL")
    p_auth_dyn.add_argument("--scopes", default="openid profile", help="Space-separated scopes (default: 'openid profile')")
    p_auth_dyn.add_argument("--redirect-port", type=int, default=8765, help="Local redirect port (default: 8765)")
    p_auth_dyn.add_argument("--resource", help="Override resource parameter (defaults to target origin)")
    p_auth_dyn.add_argument("--open-browser", action="store_true", help="Open the system browser automatically for authorization")
    p_auth_dyn.add_argument("--output", "-o", help="Write JSON results to file instead of stdout")

    # probe subcommand
    p_probe = subparsers.add_parser("probe", parents=[common], help="Run runtime probes against target")

    # repo-scan subcommand (static analysis placeholder)
    p_repo = subparsers.add_parser("repo-scan", parents=[common], help="Scan a repository path or URL (static analysis)")
    p_repo.add_argument("--path", help="Local path to scan (repository root)")
    p_repo.add_argument("--repo", help="Git URL to scan (shallow clone)")
    p_repo.add_argument("--semgrep-docker", action="store_true", help="Run Semgrep via Docker image (requires Docker)")
    p_repo.add_argument("--out", help="Write findings JSON to file")
    p_repo.add_argument("--sarif", help="Write SARIF 2.1.0 to file")
    p_probe.add_argument("target", help="Target base URL")
    p_probe.add_argument("--profile", choices=["baseline", "intrusive"], default="baseline", help="Probe profile (default: baseline)")
    p_probe.add_argument("--timeout", type=int, default=10, help="Per-request timeout seconds (default: 10)")
    p_probe.add_argument("--out", help="Write findings JSON to file")
    p_probe.add_argument("--sarif", help="Write SARIF 2.1.0 to file")
    p_probe.add_argument("--no-fail", action="store_true", help="Do not exit non-zero on high severity findings")

    # scan subcommand (aggregated discover + probes)
    p_scan = subparsers.add_parser("scan", parents=[common], help="Run full scan (discover + probes)")
    p_scan.add_argument("target", help="MCP endpoint or server to scan (e.g., URL or host)")
    p_scan.add_argument("--profile", choices=["baseline", "intrusive"], default="baseline", help="Probe profile (default: baseline)")
    p_scan.add_argument("--timeout", type=int, default=10, help="Per-request timeout seconds (default: 10)")
    p_scan.add_argument("--out", help="Write combined JSON to file")
    p_scan.add_argument("--sarif", help="Write SARIF 2.1.0 to file (probes only)")
    p_scan.add_argument("--md", help="Write Markdown report to file")
    p_scan.add_argument("--html", help="Write HTML report to file")
    p_scan.add_argument("--json", action="store_true", help="Print JSON to stdout (default view)")
    p_scan.add_argument("--no-fail", action="store_true", help="Do not exit non-zero on high severity findings")

    # Backward-compatible mode: if no subcommand provided, treat as scan stub
    parser.add_argument("fallback_target", nargs="?", help=argparse.SUPPRESS)
    parser.add_argument("--json", action="store_true", help=argparse.SUPPRESS)

    args = parser.parse_args()

    # Load config and apply CLI overrides
    from scanner.config import load_config, get_config, set_config
    cfg = load_config(getattr(args, "config", None))
    # CLI overrides
    http_cfg = dict(cfg.get("http", {}))
    if getattr(args, "verify", None) is not None:
        val = str(getattr(args, "verify")).strip()
        if val.lower() in ("true", "1", "yes", "on"):
            http_cfg["verify"] = True
        elif val.lower() in ("false", "0", "no", "off"):
            http_cfg["verify"] = False
        else:
            http_cfg["verify"] = val
    if getattr(args, "cert", None):
        http_cfg["cert"] = args.cert
    if getattr(args, "key", None):
        http_cfg["key"] = args.key
    if getattr(args, "proxy", None):
        http_cfg["proxy"] = args.proxy
    if getattr(args, "header", None):
        headers = dict(http_cfg.get("headers", {}))
        for h in (args.header or []):
            if ":" in h:
                name, val = h.split(":", 1)
                headers[name.strip()] = val.strip()
        http_cfg["headers"] = headers
    # Policy/flags
    policy = dict(cfg.get("policy", {}))
    if getattr(args, "enable_private_egress_checks", False):
        policy["enable_private_egress_checks"] = True
    offline = getattr(args, "offline", None)
    if offline is not None:
        cfg["offline"] = bool(offline)
    cfg["http"] = http_cfg
    cfg["policy"] = policy
    set_config(cfg)

    # Configure logging
    log_level = getattr(args, "log_level", None) or "INFO"
    level = getattr(logging, str(log_level).upper(), logging.INFO)
    if getattr(args, "log_format", "text") == "json":
        handler = logging.StreamHandler()
        handler.setFormatter(JSONLogFormatter())
        root = logging.getLogger()
        root.handlers = []
        root.addHandler(handler)
        root.setLevel(level)
    else:
        logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")
    logger.debug("parsed args: %s", vars(args))

    if args.command == "discover":
        if getattr(args, "offline", False):
            print(json.dumps({"error": "offline_mode", "message": "Discovery skipped due to --offline"}, indent=2))
            return
        result = discover(args.target)
        out = json.dumps(result, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(out)
        else:
            print(out)
        return

    if args.command == "auth":
        result = run_auth_flow(
            target=args.target,
            client_id=args.client_id,
            scopes=args.scopes,
            redirect_port=args.redirect_port,
            resource=args.resource,
            open_browser=args.open_browser,
        )
        out = json.dumps(result, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(out)
        else:
            print(out)
        return

    if args.command == "repo-scan":
        from scanner.repo_scan import repo_scan as _repo_scan
        result = _repo_scan(path=getattr(args, "path", None), repo=getattr(args, "repo", None), semgrep_docker=getattr(args, "semgrep_docker", False))
        out_path = getattr(args, "out", None)
        if out_path:
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(json.dumps(result, indent=2))
        else:
            print(json.dumps(result, indent=2))
        return

    if args.command == "auth-dynamic":
        result = run_auth_flow_dynamic(
            target=args.target,
            scopes=args.scopes,
            redirect_port=args.redirect_port,
            resource=args.resource,
            open_browser=args.open_browser,
        )
        out = json.dumps(result, indent=2)
        out_path = getattr(args, "output", None)
        if out_path:
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(out)
        else:
            print(out)
        return

    if args.command == "probe":
        if getattr(args, "offline", False):
            print(json.dumps({"error": "offline_mode", "message": "Probes skipped due to --offline"}, indent=2))
            return
        result = run_probes(
            target=args.target,
            profile=args.profile,
            request_timeout=args.timeout,
            out_json=args.out,
            out_sarif=args.sarif,
            enable_private_egress_checks=getattr(args, "enable_private_egress_checks", False),
        )
        # Print summary if no out
        if not getattr(args, "out", None):
            print(json.dumps(result, indent=2))
        # Exit non-zero on high severity unless --no-fail
        has_high = any((f.get("severity") == "high") for f in result.get("findings", []))
        if has_high and not getattr(args, "no_fail", False):
            raise SystemExit(1)
        return

    # scan stub or fallback
    target = getattr(args, "target", None) or getattr(args, "fallback_target", None)
    if not target:
        parser.print_help()
        return

    # Full scan: discovery + probes
    if getattr(args, "offline", False):
        disc = {"error": "offline_mode", "message": "Discovery skipped due to --offline"}
        probes = {"error": "offline_mode", "findings": []}
    else:
        disc = discover(target)
        probes = run_probes(
            target=target,
            profile=getattr(args, "profile", "baseline"),
            request_timeout=getattr(args, "timeout", 10),
            out_json=None,
            out_sarif=getattr(args, "sarif", None),
            enable_private_egress_checks=getattr(args, "enable_private_egress_checks", False),
        )
    sc = _scorecard((disc or {}).get("oauth_summary", {})) if isinstance(disc, dict) else {"score": 0, "checks": []}
    result = {
        "target": target,
        "discovery": disc,
        "probes": probes,
        "scorecard": sc,
    }
    if getattr(args, "out", None):
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(json.dumps(result, indent=2))
    if getattr(args, "md", None):
        with open(args.md, "w", encoding="utf-8") as f:
            f.write(_render_markdown_scan(result))
    if getattr(args, "html", None):
        with open(args.html, "w", encoding="utf-8") as f:
            f.write(_render_html_scan(result))
    # Print JSON unless suppressed
    if getattr(args, "json", True):
        print(json.dumps(result, indent=2))
    # Exit on high findings unless --no-fail
    has_high = any((f.get("severity") == "high") for f in probes.get("findings", []))
    if has_high and not getattr(args, "no_fail", False):
        raise SystemExit(1)


def _scorecard(oa: Dict[str, Any]) -> Dict[str, Any]:
    items = []
    score = 0
    total = 0
    def add(name: str, ok: bool, weight: int, note: str) -> None:
        nonlocal score, total
        total += weight
        if ok:
            score += weight
        items.append({"check": name, "ok": ok, "weight": weight, "note": note})
    # Basic checks
    add("issuer_present", bool(oa.get("issuer")), 5, "OIDC issuer present")
    add("authz_endpoint_present", bool(oa.get("authorization_endpoint")), 10, "Authorization endpoint present")
    add("token_endpoint_present", bool(oa.get("token_endpoint")), 10, "Token endpoint present")
    # HTTPS for endpoints
    def _https(u: str) -> bool:
        from urllib.parse import urlparse
        try:
            return (urlparse(u or "").scheme or "").lower() == "https"
        except Exception:
            return False
    add("authz_https", _https(oa.get("authorization_endpoint", "")), 10, "Authorization endpoint uses HTTPS")
    add("token_https", _https(oa.get("token_endpoint", "")), 10, "Token endpoint uses HTTPS")
    # PKCE S256 support
    ccms = oa.get("code_challenge_methods_supported") or []
    add("pkce_s256", ("S256" in ccms) if isinstance(ccms, list) else False, 15, "PKCE S256 supported")
    # Response/grant types
    rts = oa.get("response_types_supported") or []
    gts = oa.get("grant_types_supported") or []
    add("code_flow_supported", ("code" in rts) or ("authorization_code" in gts), 10, "Authorization Code flow supported")
    # JWKS present
    add("jwks_uri_present", bool(oa.get("jwks_uri")), 10, "JWKS URI present")
    # Registration endpoint exposure (informational)
    add("dynamic_registration", bool(oa.get("registration_endpoint")), 5, "Dynamic client registration available")
    pct = int(round(100 * (score / max(total, 1))))
    return {"score": pct, "checks": items}


def _render_markdown_scan(result: Dict[str, Any]) -> str:
    target = result.get("target")
    disc = result.get("discovery", {})
    probes = result.get("probes", {})
    findings = probes.get("findings", [])
    lines = [
        f"# Scan Report",
        "",
        f"Target: {target}",
        "",
        "## OAuth Summary",
    ]
    oa = (disc.get("oauth_summary") or {})
    for k in ["issuer", "authorization_endpoint", "token_endpoint", "jwks_uri", "registration_endpoint"]:
        if k in oa and oa[k]:
            lines.append(f"- {k}: {oa[k]}")
    # Scorecard
    sc = result.get("scorecard", {})
    lines += [
        "",
        f"## Standards Scorecard: {sc.get('score', 0)}%",
        "",
        "## Findings",
    ]
    if not findings:
        lines.append("No findings.")
    else:
        for f in findings:
            lines.append(f"- [{f.get('severity','')}] {f.get('ruleId','')}: {f.get('title','')} ")
    return "\n".join(lines)


def _render_html_scan(result: Dict[str, Any]) -> str:
    import html
    target = html.escape(str(result.get("target", "")))
    oa = (result.get("discovery", {}).get("oauth_summary") or {})
    sc = result.get("scorecard", {})
    findings = result.get("probes", {}).get("findings", [])
    sev_color = {"high": "#e74c3c", "medium": "#f39c12", "low": "#3498db"}
    # Counts
    hi = sum(1 for f in findings if (f.get('severity') == 'high'))
    me = sum(1 for f in findings if (f.get('severity') == 'medium'))
    lo = sum(1 for f in findings if (f.get('severity') == 'low'))
    def _sev_cls(s: str) -> str:
        return {'high':'sev-high','medium':'sev-medium','low':'sev-low'}.get(s,'')
    rows = "\n".join(
        f"<tr><td><a href='docs/PROBES.md' target='_blank'>{html.escape(f.get('ruleId',''))}</a></td><td class='{_sev_cls(str(f.get('severity','')))}'>{html.escape(f.get('severity',''))}</td><td>{html.escape(f.get('title',''))}</td></tr>"
        for f in findings
    )
    return f"""
<!doctype html>
<html><head><meta charset='utf-8'>
<title>Sentinel Scan Report</title>
<style>body{{font-family:system-ui,Arial,sans-serif;margin:2rem}} table{{border-collapse:collapse;width:100%}} td,th{{border:1px solid #ddd;padding:.5rem}} th{{background:#f8f8f8}} .sev-high{{color:#e74c3c}} .sev-medium{{color:#f39c12}} .sev-low{{color:#3498db}} .badge{{display:inline-block;padding:.1rem .4rem;border-radius:.25rem;background:#f0f0f0;margin-right:.5rem}}</style>
</head>
<body>
<h1>Sentinel Scan Report</h1>
<p><strong>Target:</strong> {target}</p>
<p>
  <span class='badge sev-high'>High: {hi}</span>
  <span class='badge sev-medium'>Medium: {me}</span>
  <span class='badge sev-low'>Low: {lo}</span>
</p>
<h2>OAuth Summary</h2>
<ul>
<li>issuer: {html.escape(str(oa.get('issuer','')))}</li>
<li>authorization_endpoint: {html.escape(str(oa.get('authorization_endpoint','')))}</li>
<li>token_endpoint: {html.escape(str(oa.get('token_endpoint','')))}</li>
<li>jwks_uri: {html.escape(str(oa.get('jwks_uri','')))}</li>
</ul>
<h2>Standards Scorecard</h2>
<p><span class='badge'>Score: {sc.get('score',0)}%</span></p>
<ul>
{''.join(f"<li>{html.escape(str(c.get('check')))} — {'OK' if c.get('ok') else 'MISS'} ({c.get('note')})</li>" for c in (sc.get('checks') or []))}
</ul>
<h2>Findings</h2>
<table><thead><tr><th>Rule</th><th>Severity</th><th>Title</th></tr></thead>
<tbody>
{rows if rows else '<tr><td colspan=\"3\">No findings</td></tr>'}
</tbody></table>
<p style='margin-top:1rem;color:#666'>Legend: <span class='sev-high'>High</span>, <span class='sev-medium'>Medium</span>, <span class='sev-low'>Low</span>. See <a href='docs/PROBES.md' target='_blank'>Probe Catalog</a> for details.</p>
</body></html>
"""


if __name__ == "__main__":
    main()
