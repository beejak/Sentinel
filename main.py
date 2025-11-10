import argparse
import json
from typing import Any, Dict

from scanner.discovery import discover
from scanner.auth import run_auth_flow, run_auth_flow_dynamic
from scanner.probes import run_probes


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

    # discover subcommand
    p_discover = subparsers.add_parser("discover", help="Discover OAuth metadata and capabilities for an MCP server")
    p_discover.add_argument("target", help="MCP server base URL (e.g., https://example.com)")
    p_discover.add_argument("--output", "-o", help="Write JSON results to file instead of stdout")

    # auth subcommand
    p_auth = subparsers.add_parser("auth", help="Run OAuth 2.1 + PKCE compliance checks against an MCP server")
    p_auth.add_argument("target", help="MCP server base URL (e.g., https://example.com)")
    p_auth.add_argument("--client-id", required=True, help="OAuth client_id (public client)")
    p_auth.add_argument("--scopes", default="", help="Space-separated scopes to request")
    p_auth.add_argument("--redirect-port", type=int, default=8765, help="Local redirect port (default: 8765)")
    p_auth.add_argument("--resource", help="Override resource parameter (defaults to target origin)")
    p_auth.add_argument("--open-browser", action="store_true", help="Open the system browser automatically for authorization")
    p_auth.add_argument("--output", "-o", help="Write JSON results to file instead of stdout")

    # auth-dynamic subcommand
    p_auth_dyn = subparsers.add_parser("auth-dynamic", help="Dynamic client registration then PKCE auth")
    p_auth_dyn.add_argument("target", help="Authorization server base URL")
    p_auth_dyn.add_argument("--scopes", default="openid profile", help="Space-separated scopes (default: 'openid profile')")
    p_auth_dyn.add_argument("--redirect-port", type=int, default=8765, help="Local redirect port (default: 8765)")
    p_auth_dyn.add_argument("--resource", help="Override resource parameter (defaults to target origin)")
    p_auth_dyn.add_argument("--open-browser", action="store_true", help="Open the system browser automatically for authorization")
    p_auth_dyn.add_argument("--output", "-o", help="Write JSON results to file instead of stdout")

    # probe subcommand
    p_probe = subparsers.add_parser("probe", help="Run runtime probes against target")
    p_probe.add_argument("target", help="Target base URL")
    p_probe.add_argument("--profile", choices=["baseline", "intrusive"], default="baseline", help="Probe profile (default: baseline)")
    p_probe.add_argument("--timeout", type=int, default=10, help="Per-request timeout seconds (default: 10)")
    p_probe.add_argument("--out", help="Write findings JSON to file")
    p_probe.add_argument("--sarif", help="Write SARIF 2.1.0 to file")
    p_probe.add_argument("--no-fail", action="store_true", help="Do not exit non-zero on high severity findings")

    # scan subcommand (stub)
    p_scan = subparsers.add_parser("scan", help="Run full scan (placeholder)")
    p_scan.add_argument("target", help="MCP endpoint or server to scan (e.g., URL or host)")
    p_scan.add_argument("--json", action="store_true", help="Output JSON only")

    # Backward-compatible mode: if no subcommand provided, treat as scan stub
    parser.add_argument("fallback_target", nargs="?", help=argparse.SUPPRESS)
    parser.add_argument("--json", action="store_true", help=argparse.SUPPRESS)

    args = parser.parse_args()

    if args.command == "discover":
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
        result = run_probes(
            target=args.target,
            profile=args.profile,
            request_timeout=args.timeout,
            out_json=args.out,
            out_sarif=args.sarif,
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

    result = scan(target)
    if getattr(args, "json", False):
        print(json.dumps(result, indent=2))
    else:
        print(f"Target: {result['target']}")
        print(f"Reachable: {result['reachable']}")
        print(f"Capabilities: {', '.join(result['capabilities']) if result['capabilities'] else 'None'}")
        print(f"Notes: {result['notes']}")


if __name__ == "__main__":
    main()
