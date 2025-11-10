import datetime as _dt
import json
import logging
import socket
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse, urlunparse

import requests

USER_AGENT = "mcp-scanner/0.1 (+https://example.invalid)"
TIMEOUT = 10

_logger = logging.getLogger(__name__)


def _origin(url: str) -> str:
    p = urlparse(url)
    netloc = p.netloc or p.path  # allow scheme-less inputs
    scheme = p.scheme or "https"
    return urlunparse((scheme, netloc, "", "", "", ""))


def _get(url: str) -> Tuple[int, Dict[str, str], Optional[Any], Optional[str]]:
    try:
        _logger.debug("GET %s", url)
        resp = requests.get(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json, */*"}, timeout=TIMEOUT, allow_redirects=True)
        status = resp.status_code
        headers = {k: v for k, v in resp.headers.items()}
        data: Optional[Any] = None
        if resp.headers.get("Content-Type", "").lower().startswith("application/json"):
            try:
                data = resp.json()
            except Exception:
                data = None
        return status, headers, data, None
    except requests.RequestException as e:
        _logger.error("HTTP error for %s: %s", url, e)
        return 0, {}, None, str(e)


def _parse_www_authenticate(headers: Dict[str, str]) -> Dict[str, Any]:
    # Return raw headers and naive parsed challenges
    values = []
    for k, v in headers.items():
        if k.lower() == "www-authenticate":
            values.append(v)
    parsed = []
    for v in values:
        # Minimal parse: split first token as scheme, then parse key="value" pairs
        part = v.strip()
        if not part:
            continue
        scheme, _, params = part.partition(" ")
        params_dict: Dict[str, str] = {}
        for kv in [p.strip() for p in params.split(",") if p.strip()]:
            if "=" in kv:
                k, val = kv.split("=", 1)
                val = val.strip().strip('"')
                params_dict[k.strip()] = val
        parsed.append({"scheme": scheme, "params": params_dict, "raw": v})
    return {"raw": values, "parsed": parsed}


def discover(target: str) -> Dict[str, Any]:
    now = _dt.datetime.utcnow().isoformat() + "Z"
    origin = _origin(target)

    _logger.info("Discovery start: %s -> %s", target, origin)
    probe_status, probe_headers, probe_json, probe_error = _get(target)
    www_auth = _parse_www_authenticate(probe_headers) if probe_headers else {"raw": [], "parsed": []}

    well_known_paths = [
        "/.well-known/oauth-authorization-server",
        "/.well-known/openid-configuration",
        "/.well-known/oauth-protected-resource",
    ]
    well_known: Dict[str, Any] = {}
    for path in well_known_paths:
        url = origin.rstrip("/") + path
        status, headers, data, error = _get(url)
        well_known[path] = {
            "url": url,
            "status": status,
            "error": error,
            "headers": headers,
            "json": data,
        }

    # Summarize OAuth endpoints if present
    oauth_summary: Dict[str, Any] = {}
    oa = well_known.get("/.well-known/oauth-authorization-server", {})
    oidc = well_known.get("/.well-known/openid-configuration", {})
    pr = well_known.get("/.well-known/oauth-protected-resource", {})

    def pick(d: Any, key: str) -> Optional[Any]:
        try:
            return (d or {}).get("json", {}).get(key)
        except Exception:
            return None

    oauth_summary = {
        "authorization_endpoint": pick(oa, "authorization_endpoint") or pick(oidc, "authorization_endpoint"),
        "token_endpoint": pick(oa, "token_endpoint") or pick(oidc, "token_endpoint"),
        "issuer": pick(oa, "issuer") or pick(oidc, "issuer"),
        "jwks_uri": pick(oa, "jwks_uri") or pick(oidc, "jwks_uri"),
        "registration_endpoint": pick(oa, "registration_endpoint") or pick(oidc, "registration_endpoint"),
        "scopes_supported": pick(oa, "scopes_supported") or pick(oidc, "scopes_supported"),
        "authorization_servers": pick(pr, "authorization_servers"),
    }

    result: Dict[str, Any] = {
        "version": "0.1",
        "scanned_at": now,
        "target": target,
        "origin": origin,
        "http_probe": {
            "status": probe_status,
            "error": probe_error,
            "headers": probe_headers,
            "www_authenticate": www_auth,
            "json": probe_json,
        },
        "well_known": well_known,
        "oauth_summary": oauth_summary,
    }

    return result