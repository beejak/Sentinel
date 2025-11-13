import base64
import os
import secrets
import socket
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs

import requests
from . import http

from .discovery import _origin, _get


def _b64url_nopad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _b64url_decode_nopad(s: str) -> bytes:
    pad = '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _code_verifier() -> str:
    return _b64url_nopad(os.urandom(32))


def _code_challenge(verifier: str) -> str:
    import hashlib
    return _b64url_nopad(hashlib.sha256(verifier.encode()).digest())


class _CallbackHandler(BaseHTTPRequestHandler):
    params: Dict[str, Any] = {}

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        # store minimal params
        _CallbackHandler.params = {k: v[0] for k, v in qs.items()}
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"<html><body>You may close this window.</body></html>")

    def log_message(self, format: str, *args: Any) -> None:  # silence
        return


def _serve_once(port: int, timeout: int = 300) -> Dict[str, Any]:
    server = HTTPServer(("127.0.0.1", port), _CallbackHandler)
    t = threading.Thread(target=server.handle_request)
    t.daemon = True
    t.start()
    start = time.time()
    while t.is_alive() and (time.time() - start) < timeout:
        time.sleep(0.05)
    server.server_close()
    return _CallbackHandler.params.copy()


def _open_browser(url: str) -> None:
    try:
        import webbrowser
        webbrowser.open(url)
    except Exception:
        pass


# Minimum JWT parts required (header + payload)
MIN_JWT_PARTS = 2

def _decode_jwt_aud(token: str) -> Optional[Any]:
    try:
        parts = token.split(".")
        if len(parts) < MIN_JWT_PARTS:
            return None
        payload = _b64url_decode_nopad(parts[1])
        import json
        data = json.loads(payload.decode())
        return data.get("aud")
    except Exception:
        return None


def run_auth_flow(*, target: str, client_id: str, scopes: str, redirect_port: int, resource: Optional[str], open_browser: bool) -> Dict[str, Any]:
    origin = _origin(target)
    resource = resource or origin

    # fetch metadata via discovery
    from .discovery import discover
    meta = discover(origin)
    oa = meta.get("oauth_summary", {})

    authz = oa.get("authorization_endpoint")
    token = oa.get("token_endpoint")

    findings = []

    # HTTPS & redirect checks (basic)
    def _scheme(u: Optional[str]) -> str:
        try:
            return (urlparse(u or "").scheme or "").lower()
        except Exception:
            return ""

    if _scheme(authz) not in ("https", "http"):
        findings.append({"ruleId": "AUTH-002", "severity": "high", "title": "Missing or invalid authorization_endpoint", "evidence": {"authorization_endpoint": authz}})
    if _scheme(token) not in ("https", "http"):
        findings.append({"ruleId": "AUTH-002", "severity": "high", "title": "Missing or invalid token_endpoint", "evidence": {"token_endpoint": token}})

    # Build auth URL (Authorization Code + PKCE)
    verifier = _code_verifier()
    challenge = _code_challenge(verifier)
    state = secrets.token_urlsafe(16)

    redirect_uri = f"http://127.0.0.1:{redirect_port}/callback"

    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scopes,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "resource": resource,
    }

    auth_url = (authz or "") + ("?" + urlencode(params)) if authz else None

    # If open_browser requested, try to open; otherwise return URL for user
    if auth_url and open_browser:
        _open_browser(auth_url)

    # Start callback listener and wait for authorization
    callback_params: Dict[str, Any] = {}
    if auth_url:
        callback_params = _serve_once(redirect_port, timeout=300)

    code = callback_params.get("code")
    recv_state = callback_params.get("state")

    state_ok = (state == recv_state)
    if not state_ok:
        findings.append({"ruleId": "AUTH-003", "severity": "high", "title": "State mismatch on redirect", "evidence": {"expected_state": state, "received_state": recv_state}})

    token_resp: Dict[str, Any] = {}
    audience_ok: Optional[bool] = None

    if code and token:
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "code_verifier": verifier,
            "resource": resource,
        }
        try:
            r = http.post(token, data=data, headers={"Accept": "application/json"}, timeout=20)
            token_resp = {
                "status": r.status_code,
                "headers": dict(r.headers),
            }
            try:
                token_json = r.json()
            except Exception:
                token_json = None
            token_resp["json"] = token_json
            HTTP_OK = 200
            if r.status_code == HTTP_OK and token_json and token_json.get("access_token"):
                aud = _decode_jwt_aud(token_json["access_token"]) or []
                if isinstance(aud, str):
                    aud = [aud]
                audience_ok = (resource in aud) if aud else None
                if audience_ok is False:
                    findings.append({"ruleId": "AUTH-004", "severity": "high", "title": "Access token audience does not include resource", "evidence": {"aud": aud, "resource": resource}})
        except requests.RequestException as e:
            token_resp = {"error": str(e)}

    # Token passthrough negative test: send bogus token to resource
    bogus = secrets.token_urlsafe(24)
    status, headers, _, _ = _get(origin)
    _ = headers  # keep for potential future use
    try:
        r2 = http.get(origin, headers={"Authorization": f"Bearer {bogus}"}, timeout=10, allow_redirects=False)
        if r2.status_code not in (401, 403):
            findings.append({"ruleId": "AUTH-005", "severity": "high", "title": "Resource accepted or redirected with bogus token", "evidence": {"status": r2.status_code}})
    except requests.RequestException as e:
        findings.append({"ruleId": "AUTH-005", "severity": "low", "title": "Unable to perform token passthrough test", "evidence": {"error": str(e)}})

    result: Dict[str, Any] = {
        "target": target,
        "origin": origin,
        "authorization_endpoint": authz,
        "token_endpoint": token,
        "auth_url": auth_url,
        "redirect_port": redirect_port,
        "state_ok": state_ok,
        "token_response": token_resp,
        "audience_ok": audience_ok,
        "findings": findings,
    }

    return result


# --- Dynamic Client Registration helpers ---
def dynamic_register(target: str, redirect_port: int) -> Dict[str, Any]:
    """
    Perform OAuth 2.0 Dynamic Client Registration (RFC 7591) if the AS exposes
    a registration_endpoint in discovery metadata. Registers a public client
    (token_endpoint_auth_method = none) with the local redirect URI.
    """
    origin = _origin(target)
    redirect_uri = f"http://127.0.0.1:{redirect_port}/callback"

    from .discovery import discover
    meta = discover(origin)
    oa = meta.get("oauth_summary", {})
    reg = oa.get("registration_endpoint")

    if not reg:
        return {
            "error": "registration_endpoint not found in discovery",
            "discovery": meta,
        }

    body = {
        "application_type": "native",
        "token_endpoint_auth_method": "none",
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "client_name": "mcp-scanner"
    }

    try:
        r = requests.post(reg, json=body, headers={"Accept": "application/json"}, timeout=20)
        try:
            j = r.json()
        except Exception:
            j = None
        return {
            "status": r.status_code,
            "headers": dict(r.headers),
            "json": j,
            "registration_endpoint": reg,
            "redirect_uri": redirect_uri,
        }
    except requests.RequestException as e:
        return {"error": str(e), "registration_endpoint": reg}


def run_auth_flow_dynamic(*, target: str, scopes: str, redirect_port: int, resource: Optional[str], open_browser: bool) -> Dict[str, Any]:
    """
    Convenience wrapper that performs dynamic registration first, then runs the
    Authorization Code + PKCE flow with the issued client_id.
    """
    reg = dynamic_register(target, redirect_port)
    client_id = (reg.get("json") or {}).get("client_id") if isinstance(reg, dict) else None

    result: Dict[str, Any] = {"registration": reg}

    if not client_id:
        result["error"] = "dynamic registration did not return client_id"
        return result

    flow = run_auth_flow(
        target=target,
        client_id=client_id,
        scopes=scopes,
        redirect_port=redirect_port,
        resource=resource,
        open_browser=open_browser,
    )
    result["auth_flow"] = flow
    return result
