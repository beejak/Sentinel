import time
from typing import Any, Dict, List, Optional, Tuple

import requests
from . import http

import base64
import hashlib
import secrets
from urllib.parse import urlencode, urlparse, parse_qs

from .discovery import _origin
from .discovery import discover


Severity = str  # "low" | "medium" | "high"

# Minimal rule metadata for SARIF enrichment
RULE_META: Dict[str, Dict[str, Any]] = {
    "PROBE-001": {"cwe": "CWE-287", "help": "https://github.com/beejak/Sentinel/blob/main/docs/PROBES.md#probe-001", "remediation": "Ensure protected resources validate bearer tokens server-side; reject invalid/expired tokens with 401/403."},  # Improper Authentication
    "PROBE-002": {"cwe": "CWE-20",  "help": "https://github.com/beejak/Sentinel/blob/main/docs/PROBES.md#probe-002", "remediation": "Validate Content-Type and input; avoid processing JSON on GET; handle errors without 5xx."},  # Improper Input Validation
    "PROBE-003": {"cwe": "CWE-770", "help": "https://github.com/beejak/Sentinel/blob/main/docs/PROBES.md#probe-003", "remediation": "Limit payload sizes and request body limits; return 413 or structured 4xx instead of 5xx."},  # Uncontrolled Resource Consumption
    "PROBE-004": {"cwe": "CWE-942","help": "https://github.com/beejak/Sentinel/blob/main/docs/PROBES.md#probe-004", "remediation": "Avoid permissive CORS; restrict origins, methods and headers to minimal necessity."},  # Permissive CORS Policy
    "PROBE-005": {"cwe": "CWE-22",  "help": "https://github.com/beejak/Sentinel/blob/main/docs/PROBES.md#probe-005", "remediation": "Enforce tool policies: sanitize file paths, allowlist roots, and return structured 403 on violations."},  # Path Traversal (policy)
    "PROBE-006": {"cwe": "CWE-294", "help": "https://github.com/beejak/Sentinel/blob/main/docs/PROBES.md#probe-006", "remediation": "Make authorization codes single-use and time-limited; reject replays with invalid_grant."},  # Authentication Bypass by Replay
    "PROBE-007": {"cwe": "CWE-307", "help": "https://github.com/beejak/Sentinel/blob/main/docs/PROBES.md#probe-007", "remediation": "Introduce request throttling for sensitive endpoints; return 429 with Retry-After."},  # Excessive Attempts / Rate Limit
    "PROBE-008": {"cwe": "CWE-749","help": "https://github.com/beejak/Sentinel/blob/main/docs/PROBES.md#probe-008", "remediation": "Ensure /tool/run allows POST only; return 405 for disallowed methods; validate /tools behavior."},  # Exposed Dangerous Method
    "PROBE-009": {"cwe": "CWE-436","help": "https://github.com/beejak/Sentinel/blob/main/docs/PROBES.md#probe-009", "remediation": "Validate Content-Type/body alignment; reject invalid JSON and mismatched types with structured 4xx."},  # Interpretation Conflict
    "PROBE-010": {"cwe": "CWE-306","help": "https://github.com/beejak/Sentinel/blob/main/docs/PROBES.md#probe-010", "remediation": "Require Authorization header for /tool/run; return structured 401/403 for unauthenticated calls."},  # Missing Authentication
    "PROBE-011": {"cwe": "CWE-200","help": "https://github.com/beejak/Sentinel/blob/main/docs/PROBES.md#probe-011", "remediation": "Disable HTTP TRACE on sensitive endpoints."},  # Information Exposure via TRACE
    "PROBE-012": {"cwe": "CWE-345","help": "https://github.com/beejak/Sentinel/blob/main/docs/PROBES.md#probe-012", "remediation": "Reject POST without Content-Type; require application/json for JSON bodies."},  # Insufficient Verification of Data Authenticity
    "PROBE-013": {"cwe": "CWE-770","help": "https://github.com/beejak/Sentinel/blob/main/docs/PROBES.md#probe-013", "remediation": "Cap header sizes; drop or reject oversized headers instead of 5xx."},  # Uncontrolled Resource Consumption
    "PROBE-014": {"cwe": "CWE-918","help": "https://github.com/beejak/Sentinel/blob/main/docs/PROBES.md#probe-014", "remediation": "Block access to private addresses and metadata services; allowlist egress destinations."},  # SSRF
    "PROBE-015": {"cwe": "CWE-693","help": "https://github.com/beejak/Sentinel/blob/main/docs/PROBES.md#probe-015", "remediation": "Set security headers (X-Content-Type-Options: nosniff, X-Frame-Options: DENY/SAMEORIGIN, CSP, Referrer-Policy)."},  # Protection Mechanism Failure (headers)
    "PROBE-016": {"cwe": "CWE-1220","help": "https://github.com/beejak/Sentinel/blob/main/docs/PROBES.md#probe-016", "remediation": "Restrict tool surface; add read_file roots and fetch_url blocked CIDRs; avoid dangerous tool names (exec/shell)."}, # Insufficient Granularity of Access Control (policy)
    "PROBE-017": {"cwe": "CWE-347","help": "https://github.com/beejak/Sentinel/blob/main/docs/PROBES.md#probe-017", "remediation": "Do not accept unsigned JWTs; reject alg=none; require signature verification for all tokens."}, # Improper Verification of Cryptographic Signature
    "PROBE-018": {"cwe": "CWE-326","help": "https://github.com/beejak/Sentinel/blob/main/docs/PROBES.md#probe-018", "remediation": "Use RSA >= 2048 bits and approved EC curves (P-256/384/521). Ensure alg/kty/crv are consistent."}, # Inadequate Encryption Strength
    "PROBE-019": {"cwe": "CWE-523","help": "https://github.com/beejak/Sentinel/blob/main/docs/PROBES.md#probe-019", "remediation": "Enable HSTS on HTTPS origins and disable legacy TLS versions (TLS 1.0/1.1)."}, # Unprotected Transport of Credentials
}


def _result(rule: str, severity: Severity, title: str, evidence: Dict[str, Any]) -> Dict[str, Any]:
    return {"ruleId": rule, "severity": severity, "title": title, "evidence": evidence}


def _sarif(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    from datetime import datetime, timezone
    rules: Dict[str, Dict[str, Any]] = {}
    cwes: List[str] = []
    for f in findings:
        rid = f.get("ruleId")
        if rid and rid not in rules:
            meta = RULE_META.get(rid, {})
            level = {"low": "note", "medium": "warning", "high": "error"}.get(f.get("severity"), "warning")
            rem = meta.get("remediation")
            rules[rid] = {
                "id": rid,
                "name": rid,
                "shortDescription": {"text": f.get("title", rid)},
                "fullDescription": {"text": f.get("title", rid)},
                "helpUri": meta.get("help"),
                "help": ({"text": rem, "markdown": rem} if rem else None),
                "properties": {"cwe": meta.get("cwe")},
                "defaultConfiguration": {"level": level},
            }
            if meta.get("cwe") and meta.get("cwe") not in cwes:
                cwes.append(meta.get("cwe"))
    results = []
    import hashlib
    for f in findings:
        level = {"low": "note", "medium": "warning", "high": "error"}.get(f.get("severity"), "warning")
        ev = (f.get("evidence") or {})
        path = str(ev.get("path") or "")
        origin = str(ev.get("origin") or "")
        fp = hashlib.sha256(f"{f.get('ruleId')}|{origin}|{path}".encode()).hexdigest()
        results.append({
            "ruleId": f.get("ruleId"),
            "level": level,
            "message": {"text": f.get("title")},
            "locations": ([{"physicalLocation": {"artifactLocation": {"uri": path or origin}}}] if (path or origin) else None),
            "partialFingerprints": {"ruleOriginPath": fp},
            "properties": {"evidence": f.get("evidence")},
        })
    now = datetime.now(timezone.utc).isoformat()
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": "mcp-scanner", "version": "0.1.0", "rules": list(rules.values())}},
                "taxonomies": [
                    {"name": "CWE", "taxa": [{"id": c} for c in cwes]}
                ] if cwes else [],
                "invocations": [
                    {"executionSuccessful": True, "startTimeUtc": now, "endTimeUtc": now}
                ],
                "results": results,
            }
        ],
    }


class Probe:
    id: str = "PROBE"
    intrusive: bool = False

    def run(self, target: str, timeout: int, options: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        raise NotImplementedError


class BogusTokenProbe(Probe):
    id = "PROBE-001"
    intrusive = False

    def run(self, target: str, timeout: int, options: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        origin = _origin(target)
        try:
            r = http.get(origin, headers={"Authorization": "Bearer X_BOGUS_"}, timeout=timeout, allow_redirects=False)
            if r.status_code not in (401, 403):
                return [_result(self.id, "high", "Resource accepted or redirected with bogus token", {"status": r.status_code})]
            return []
        except requests.RequestException as e:
            return [_result(self.id, "low", "Unable to perform bogus token probe", {"error": str(e)})]


class MalformedRequestProbe(Probe):
    id = "PROBE-002"
    intrusive = False

    def run(self, target: str, timeout: int, options: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        origin = _origin(target)
        findings: List[Dict[str, Any]] = []
        # Send invalid Content-Type and JSON body to GET
        try:
            r = http.get(origin, headers={"Content-Type": "application/json"}, data="{not json}", timeout=timeout)
            if r.status_code >= 500:
                findings.append(_result(self.id, "medium", "Server 5xx on malformed GET", {"status": r.status_code}))
        except requests.RequestException as e:
            findings.append(_result(self.id, "low", "Error during malformed GET", {"error": str(e)}))
        return findings


class OversizePayloadProbe(Probe):
    id = "PROBE-003"
    intrusive = True

    def __init__(self, size_kb: int = 512):
        self.size_kb = size_kb

    def run(self, target: str, timeout: int, options: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        origin = _origin(target)
        findings: List[Dict[str, Any]] = []
        data = b"x" * (self.size_kb * 1024)
        try:
            r = http.post(origin, data=data, headers={"Content-Type": "text/plain"}, timeout=timeout)
            if r.status_code >= 500:
                findings.append(_result(self.id, "medium", "Server 5xx on oversize POST", {"status": r.status_code, "size_kb": self.size_kb}))
        except requests.RequestException as e:
            findings.append(_result(self.id, "low", "Error during oversize POST", {"error": str(e)}))
        return findings


class CORSPreflightProbe(Probe):
    id = "PROBE-004"
    intrusive = False

    def run(self, target: str, timeout: int, options: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        origin = _origin(target)
        try:
            r = http.options(
                origin,
                headers={
                    "Origin": "http://example.com",
                    "Access-Control-Request-Method": "GET",
                    "Access-Control-Request-Headers": "Authorization",
                },
                timeout=timeout,
            )
            # Not strictly a failure if CORS is absent; record info-level only
            allow_origin = r.headers.get("Access-Control-Allow-Origin")
            allow_headers = r.headers.get("Access-Control-Allow-Headers")
            if allow_origin or allow_headers:
                return [_result(self.id, "low", "CORS preflight responded with allowances", {"status": r.status_code, "allow_origin": allow_origin, "allow_headers": allow_headers})]
            return []
        except requests.RequestException as e:
            return [_result(self.id, "low", "Error during CORS preflight", {"error": str(e)})]


# --- OAuth helpers for probes (non-interactive, harness-friendly) ---

def _b64url_nopad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _code_verifier() -> str:
    return _b64url_nopad(secrets.token_bytes(32))


def _code_challenge(verifier: str) -> str:
    return _b64url_nopad(hashlib.sha256(verifier.encode()).digest())


def _oauth_discover(target: str) -> Dict[str, Any]:
    meta = discover(target)
    return meta.get("oauth_summary", {})


def _oauth_dynamic_register(issuer: str, redirect_uri: str, timeout: int) -> Optional[str]:
    oa = _oauth_discover(issuer)
    reg = oa.get("registration_endpoint")
    if not reg:
        return None
    body = {
        "application_type": "native",
        "token_endpoint_auth_method": "none",
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "client_name": "mcp-scanner-probes",
    }
    r = http.post(reg, json=body, headers={"Accept": "application/json"}, timeout=timeout)
    j = None
    try:
        j = r.json()
    except Exception:
        pass
    return (j or {}).get("client_id") if r.status_code in (200, 201) else None


def _oauth_authorize_get_code(issuer: str, client_id: str, redirect_uri: str, scopes: str, resource: str, timeout: int) -> Tuple[Optional[str], bool, str, str]:
    oa = _oauth_discover(issuer)
    authz = oa.get("authorization_endpoint")
    if not authz:
        return None, False, "", ""
    verifier = _code_verifier()
    challenge = _code_challenge(verifier)
    state = secrets.token_urlsafe(16)
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
    r = http.get(authz, params=params, timeout=timeout, allow_redirects=False)
    if r.status_code not in (302, 303):
        return None, False, "", ""
    loc = r.headers.get("Location", "")
    parsed = urlparse(loc)
    qs = parse_qs(parsed.RawQuery if hasattr(parsed, 'RawQuery') else parsed.query)
    code = (qs.get("code") or [None])[0]
    recv_state = (qs.get("state") or [None])[0]
    return code, (recv_state == state), verifier, state


def _oauth_exchange_token(issuer: str, code: str, client_id: str, verifier: str, redirect_uri: str, resource: str, timeout: int) -> requests.Response:
    oa = _oauth_discover(issuer)
    token = oa.get("token_endpoint")
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "code_verifier": verifier,
        "resource": resource,
    }
    return http.post(token, data=data, headers={"Accept": "application/json"}, timeout=timeout)


class ToolGuardrailsProbe(Probe):
    id = "PROBE-005"
    intrusive = False

    def run(self, target: str, timeout: int, options: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        origin = _origin(target)
        redirect_uri = "http://127.0.0.1:8765/callback"
        client_id = _oauth_dynamic_register(origin, redirect_uri, timeout)
        if not client_id:
            return [_result(self.id, "low", "No dynamic registration endpoint; skipping tool guardrails probe", {})]
        code, state_ok, verifier, _ = _oauth_authorize_get_code(origin, client_id, redirect_uri, "openid profile", origin, timeout)
        if not code:
            return [_result(self.id, "low", "Unable to obtain authorization code", {})]
        if not state_ok:
            return [_result(self.id, "high", "State mismatch on authorization redirect", {})]
        rtok = _oauth_exchange_token(origin, code, client_id, verifier, redirect_uri, origin, timeout)
        tok_json = None
        try:
            tok_json = rtok.json()
        except Exception:
            pass
        access = (tok_json or {}).get("access_token") if rtok.status_code == 200 else None
        if not access:
            return [_result(self.id, "low", "Unable to acquire access token", {"status": rtok.status_code})]

        # Query tools
        try:
            r_tools = http.get(origin + "/tools", timeout=timeout)
            if r_tools.status_code >= 500:
                return [_result(self.id, "medium", "Server 5xx on /tools", {"status": r_tools.status_code})]
        except requests.RequestException as e:
            return [_result(self.id, "low", "Error querying /tools", {"error": str(e)})]

        # Attempt dangerous invocation
        bad_args = [
            {"tool": "read_file", "args": {"path": "../../etc/passwd"}},
            {"tool": "read_file", "args": {"path": "C\\\\Windows\\\\System32\\\\config\\\\SAM"}},
        ]
        findings: List[Dict[str, Any]] = []
        for payload in bad_args:
            try:
                r = http.post(
                    origin + "/tool/run",
                    json=payload,
                    headers={"Authorization": f"Bearer {access}", "Content-Type": "application/json"},
                    timeout=timeout,
                )
                if 200 <= r.status_code < 300:
                    findings.append(_result(self.id, "high", "Tool invocation accepted dangerous parameters", {"payload": payload, "status": r.status_code}))
                elif r.status_code in (401, 403):
                    # Expected deny; assert structured error shape
                    try:
                        j = r.json()
                    except Exception:
                        j = {}
                    if not (isinstance(j, dict) and j.get("error") and j.get("message")):
                        findings.append(_result(self.id, "medium", "Unstructured policy violation response", {"status": r.status_code, "body": getattr(r, 'text', '')[:200]}))
                elif r.status_code >= 500:
                    findings.append(_result(self.id, "medium", "Server 5xx on tool deny", {"payload": payload, "status": r.status_code}))
            except requests.RequestException as e:
                findings.append(_result(self.id, "low", "Error calling /tool/run", {"error": str(e), "payload": payload}))
        return findings


class StateReplayProbe(Probe):
    id = "PROBE-006"
    intrusive = False

    def run(self, target: str, timeout: int, options: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        origin = _origin(target)
        redirect_uri = "http://127.0.0.1:8765/callback"
        client_id = _oauth_dynamic_register(origin, redirect_uri, timeout)
        if not client_id:
            return [_result(self.id, "low", "No dynamic registration endpoint; skipping replay probe", {})]
        code, state_ok, verifier, _ = _oauth_authorize_get_code(origin, client_id, redirect_uri, "openid profile", origin, timeout)
        findings: List[Dict[str, Any]] = []
        if not code:
            return [_result(self.id, "low", "Unable to obtain authorization code", {})]
        if not state_ok:
            findings.append(_result(self.id, "high", "State mismatch on authorization redirect", {}))
        # First exchange should succeed
        r1 = _oauth_exchange_token(origin, code, client_id, verifier, redirect_uri, origin, timeout)
        # Replay the same code should fail with 400/invalid_grant
        r2 = _oauth_exchange_token(origin, code, client_id, verifier, redirect_uri, origin, timeout)
        try:
            j2 = r2.json()
        except Exception:
            j2 = {}
        if r1.status_code == 200 and (r2.status_code == 200 or (j2.get("error") != "invalid_grant")):
            findings.append(_result(self.id, "high", "Authorization code could be replayed or wrong error", {"r1_status": r1.status_code, "r2_status": r2.status_code, "error": j2.get("error")}))
        return findings


class RateLimitProbe(Probe):
    id = "PROBE-007"
    intrusive = False

    def run(self, target: str, timeout: int, options: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        origin = _origin(target)
        redirect_uri = "http://127.0.0.1:8765/callback"
        client_id = _oauth_dynamic_register(origin, redirect_uri, timeout)
        if not client_id:
            return [_result(self.id, "low", "No dynamic registration endpoint; skipping rate limit probe", {})]
        code, state_ok, verifier, _ = _oauth_authorize_get_code(origin, client_id, redirect_uri, "openid profile", origin, timeout)
        if not code or not state_ok:
            return [_result(self.id, "low", "Unable to complete auth for rate limit probe", {})]
        rtok = _oauth_exchange_token(origin, code, client_id, verifier, redirect_uri, origin, timeout)
        try:
            tok_json = rtok.json()
        except Exception:
            tok_json = {}
        access = tok_json.get("access_token") if rtok.status_code == 200 else None
        if not access:
            return [_result(self.id, "low", "Unable to acquire access token", {"status": rtok.status_code})]

        # Fire a quick burst of safe tool calls
        got_429 = False
        retry_after_vals = []
        payload = {"tool": "read_file", "args": {"path": "/tmp/test.txt"}}
        for _ in range(5):
            try:
                r = requests.post(
                    origin + "/tool/run",
                    json=payload,
                    headers={"Authorization": f"Bearer {access}", "Content-Type": "application/json"},
                    timeout=timeout,
                )
                if r.status_code == 429:
                    got_429 = True
                    ra = r.headers.get("Retry-After")
                    if ra:
                        retry_after_vals.append(ra)
                time.sleep(0.05)
            except requests.RequestException:
                pass
        if not got_429:
            return [_result(self.id, "low", "No rate limiting observed on burst tool calls", {})]
        else:
            return []


class MethodMatrixProbe(Probe):
    id = "PROBE-008"
    intrusive = False

    def run(self, target: str, timeout: int, options: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        origin = _origin(target)
        findings: List[Dict[str, Any]] = []
        # Endpoints to test: /tool/run should reject GET; /tools should accept GET; root may accept GET
        try:
            r_get_tool = requests.get(origin + "/tool/run", timeout=timeout)
            if 200 <= r_get_tool.status_code < 300:
                findings.append(_result(self.id, "high", "GET allowed on /tool/run (should be POST only)", {"status": r_get_tool.status_code}))
            elif r_get_tool.status_code not in (401, 403, 405):
                findings.append(_result(self.id, "medium", "Unexpected status for GET /tool/run", {"status": r_get_tool.status_code}))
        except requests.RequestException as e:
            findings.append(_result(self.id, "low", "Error on GET /tool/run", {"error": str(e)}))
        try:
            r_put_tool = http.request("PUT", origin + "/tool/run", timeout=timeout)
            if 200 <= r_put_tool.status_code < 300:
                findings.append(_result(self.id, "high", "PUT allowed on /tool/run (should be POST only)", {"status": r_put_tool.status_code}))
            elif r_put_tool.status_code not in (401, 403, 405):
                findings.append(_result(self.id, "medium", "Unexpected status for PUT /tool/run", {"status": r_put_tool.status_code}))
        except requests.RequestException as e:
            findings.append(_result(self.id, "low", "Error on PUT /tool/run", {"error": str(e)}))
        try:
            r_get_tools = http.get(origin + "/tools", timeout=timeout)
            if r_get_tools.status_code >= 500:
                findings.append(_result(self.id, "medium", "/tools GET caused 5xx", {"status": r_get_tools.status_code}))
        except requests.RequestException as e:
            findings.append(_result(self.id, "low", "Error on GET /tools", {"error": str(e)}))
        return findings


class ContentTypeMatrixProbe(Probe):
    id = "PROBE-009"
    intrusive = False

    def run(self, target: str, timeout: int, options: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        origin = _origin(target)
        findings: List[Dict[str, Any]] = []
        # POST with wrong Content-Type but valid JSON body, and invalid JSON body
        bad_ct_cases = [
            ({"Content-Type": "text/plain"}, {"tool": "read_file", "args": {"path": "/tmp/test.txt"}}),
            ({"Content-Type": "application/json"}, "{not json}"),
        ]
        for headers, body in bad_ct_cases:
            try:
                r = http.post(
                    origin + "/tool/run",
                    headers=headers,
                    json=(body if isinstance(body, dict) else None),
                    data=(body if isinstance(body, str) else None),
                    timeout=timeout,
                )
                if 200 <= r.status_code < 300:
                    findings.append(_result(self.id, "high", "Accepted invalid/mismatched Content-Type or body", {"headers": headers, "body": str(body)[:120]}))
                elif r.status_code >= 500:
                    findings.append(_result(self.id, "medium", "5xx on Content-Type/body mismatch", {"headers": headers, "status": r.status_code}))
                else:
                    # For 4xx, prefer structured JSON error {error, message}
                    try:
                        j = r.json()
                    except Exception:
                        j = {}
                    if not (isinstance(j, dict) and j.get("error")):
                        findings.append(_result(self.id, "low", "Unstructured error on Content-Type/body mismatch", {"status": r.status_code, "body": getattr(r, 'text', '')[:200]}))
            except requests.RequestException as e:
                findings.append(_result(self.id, "low", "Error during Content-Type mismatch POST", {"error": str(e), "headers": headers}))
        return findings


class TraceMethodProbe(Probe):
    id = "PROBE-011"
    intrusive = False

    def run(self, target: str, timeout: int, options: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        origin = _origin(target)
        try:
            r = http.request("TRACE", origin + "/tool/run", timeout=timeout)
            if 200 <= r.status_code < 300:
                return [_result(self.id, "high", "TRACE allowed on /tool/run", {"status": r.status_code})]
            if r.status_code not in (401, 403, 405):
                return [_result(self.id, "medium", "Unexpected status for TRACE /tool/run", {"status": r.status_code})]
            return []
        except requests.RequestException as e:
            return [_result(self.id, "low", "Error on TRACE /tool/run", {"error": str(e)})]


class MissingContentTypeProbe(Probe):
    id = "PROBE-012"
    intrusive = False

    def run(self, target: str, timeout: int, options: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        origin = _origin(target)
        payload = {"tool": "read_file", "args": {"path": "/tmp/test.txt"}}
        try:
            r = http.post(origin + "/tool/run", data=__import__("json").dumps(payload), timeout=timeout)
            if 200 <= r.status_code < 300:
                return [_result(self.id, "high", "Accepted POST without Content-Type", {"status": r.status_code})]
            elif r.status_code >= 500:
                return [_result(self.id, "medium", "5xx on missing Content-Type", {"status": r.status_code})]
            else:
                try:
                    j = r.json()
                except Exception:
                    j = {}
                if not (isinstance(j, dict) and j.get("error")):
                    return [_result(self.id, "low", "Unstructured error for missing Content-Type", {"status": r.status_code, "body": getattr(r, 'text', '')[:200]})]
                return []
        except requests.RequestException as e:
            return [_result(self.id, "low", "Error on POST without Content-Type", {"error": str(e)})]


class LargeHeaderProbe(Probe):
    id = "PROBE-013"
    intrusive = True

    def run(self, target: str, timeout: int, options: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        origin = _origin(target)
        headers = {"Content-Type": "application/json", "X-Long": "a" * 8192}
        payload = {"tool": "read_file", "args": {"path": "/tmp/test.txt"}}
        try:
            r = http.post(origin + "/tool/run", json=payload, headers=headers, timeout=timeout)
            if r.status_code >= 500:
                return [_result(self.id, "medium", "5xx on large header", {"status": r.status_code})]
            return []
        except requests.RequestException as e:
            return [_result(self.id, "low", "Error on large header request", {"error": str(e)})]


class SSRFProbe(Probe):
    id = "PROBE-014"
    intrusive = False

    def run(self, target: str, timeout: int, options: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        origin = _origin(target)
        if not (options or {}).get("enable_private_egress_checks", False):
            return [_result(self.id, "low", "Private egress checks disabled (opt-in)", {})]
        redirect_uri = "http://127.0.0.1:8765/callback"
        client_id = _oauth_dynamic_register(origin, redirect_uri, timeout)
        if not client_id:
            return [_result(self.id, "low", "No dynamic registration endpoint; skipping SSRF probe", {})]
        code, state_ok, verifier, _ = _oauth_authorize_get_code(origin, client_id, redirect_uri, "openid profile", origin, timeout)
        if not code or not state_ok:
            return [_result(self.id, "low", "Unable to complete auth for SSRF probe", {})]
        rtok = _oauth_exchange_token(origin, code, client_id, verifier, redirect_uri, origin, timeout)
        try:
            tok_json = rtok.json()
        except Exception:
            tok_json = {}
        access = tok_json.get("access_token") if rtok.status_code == 200 else None
        if not access:
            return [_result(self.id, "low", "Unable to acquire access token", {"status": rtok.status_code})]

        findings: List[Dict[str, Any]] = []
        # Attempt loopback SSRF to harness
        ssrf_targets = [
            "http://127.0.0.1:8085/",
            "http://169.254.169.254/",
        ]
        for url in ssrf_targets:
            payload = {"tool": "fetch_url", "args": {"url": url}}
            try:
                r = http.post(
                    origin + "/tool/run",
                    json=payload,
                    headers={"Authorization": f"Bearer {access}", "Content-Type": "application/json"},
                    timeout=timeout,
                )
                if 200 <= r.status_code < 300:
                    findings.append(_result(self.id, "high", "SSRF: server fetched a private/loopback URL", {"target": url, "status": r.status_code}))
                elif r.status_code in (401, 403):
                    # Expected block; prefer structured error
                    try:
                        j = r.json()
                    except Exception:
                        j = {}
                    if not (isinstance(j, dict) and j.get("error")):
                        findings.append(_result(self.id, "low", "Unstructured SSRF block response", {"status": r.status_code}))
                elif r.status_code >= 500:
                    findings.append(_result(self.id, "medium", "5xx on SSRF block", {"status": r.status_code}))
            except requests.RequestException as e:
                findings.append(_result(self.id, "low", "Error during SSRF probe", {"error": str(e), "target": url}))
        return findings


class NoneAlgTokenProbe(Probe):
    id = "PROBE-017"
    intrusive = False

    def run(self, target: str, timeout: int, options: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        origin = _origin(target)
        # Build unsigned JWT (alg=none)
        try:
            header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip('=')
            payload = base64.urlsafe_b64encode(b'{"sub":"test"}').decode().rstrip('=')
            token = f"{header}.{payload}."
            r = http.get(origin, headers={"Authorization": f"Bearer {token}"}, timeout=timeout, allow_redirects=False)
            if r.status_code in (200, 302, 303):
                return [_result(self.id, "high", "Resource accepted unsigned JWT (alg=none)", {"status": r.status_code})]
            return []
        except requests.RequestException as e:
            return [_result(self.id, "low", "Error sending unsigned JWT", {"error": str(e)})]


class JWKSKeyStrengthProbe(Probe):
    id = "PROBE-018"
    intrusive = False

    def run(self, target: str, timeout: int, options: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        # Fetch jwks_uri from discovery and validate key sizes
        meta = discover(target)
        oa = meta.get("oauth_summary", {}) if isinstance(meta, dict) else {}
        jwks = oa.get("jwks_uri")
        if not jwks:
            return [_result(self.id, "low", "No jwks_uri in discovery", {})]
        findings: List[Dict[str, Any]] = []
        try:
            r = http.get(jwks, timeout=timeout)
            j = r.json()
        except Exception as e:
            return [_result(self.id, "low", "Unable to fetch/parse JWKS", {"error": str(e)})]
        keys = (j or {}).get("keys") or []
        for k in keys:
            kty = k.get("kty")
            alg = (k.get("alg") or "").upper()
            if kty == "RSA":
                n_b64 = k.get("n")
                if not n_b64:
                    continue
                try:
                    import base64
                    nb = base64.urlsafe_b64decode(n_b64 + "==")
                    bits = len(nb) * 8
                    if bits < 2048:
                        findings.append(_result(self.id, "high", "RSA key size too small", {"kid": k.get("kid"), "bits": bits}))
                    if alg.startswith("ES"):
                        findings.append(_result(self.id, "medium", "alg/kty mismatch: RSA key with ES* algorithm", {"kid": k.get("kid"), "alg": alg, "kty": kty}))
                except Exception:
                    pass
            elif kty == "EC":
                crv = (k.get("crv") or "").upper()
                allowed = {"P-256", "P-384", "P-521"}
                if crv not in allowed:
                    findings.append(_result(self.id, "high", "Unsupported or weak EC curve", {"kid": k.get("kid"), "crv": k.get("crv")}))
                # alg alignment
                expected = {"P-256": "ES256", "P-384": "ES384", "P-521": "ES512"}.get(crv)
                if alg and expected and alg != expected:
                    findings.append(_result(self.id, "medium", "alg/crv mismatch for EC key", {"kid": k.get("kid"), "alg": alg, "crv": k.get("crv")}))
                if alg.startswith("RS"):
                    findings.append(_result(self.id, "medium", "alg/kty mismatch: EC key with RS* algorithm", {"kid": k.get("kid"), "alg": alg, "kty": kty}))
                if alg == "NONE":
                    findings.append(_result(self.id, "high", "JWKS advertises alg=none (invalid)", {"kid": k.get("kid")}))
        return findings


class HSTSAndTLSProbe(Probe):
    id = "PROBE-019"
    intrusive = False

    def run(self, target: str, timeout: int, options: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        origin = _origin(target)
        findings: List[Dict[str, Any]] = []
        # HSTS check
        try:
            r = http.get(origin, timeout=timeout)
            if origin.lower().startswith("https"):
                hsts = r.headers.get("Strict-Transport-Security")
                if not hsts:
                    findings.append(_result(self.id, "low", "Missing HSTS header on HTTPS origin", {}))
        except requests.RequestException as e:
            findings.append(_result(self.id, "low", "Error probing HSTS", {"error": str(e)}))
        # TLS version check (best effort)
        try:
            from urllib.parse import urlparse
            import socket, ssl
            u = urlparse(origin)
            host = u.hostname
            port = u.port or 443
            if u.scheme == "https" and host:
                ctx = ssl.create_default_context()
                with socket.create_connection((host, port), timeout=timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        ver = getattr(ssock, "version", lambda: "unknown")()
                        if ver in ("TLSv1", "TLSv1.1"):
                            findings.append(_result(self.id, "medium", "TLS version is outdated", {"version": ver}))
        except Exception:
            pass
        return findings


class SecurityHeadersProbe(Probe):
    id = "PROBE-015"
    intrusive = False

    def run(self, target: str, timeout: int, options: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        origin = _origin(target)
        try:
            r = http.get(origin, timeout=timeout)
            headers = {k.lower(): v for k, v in r.headers.items()}
            missing = []
            expected = [
                "x-content-type-options",
                "x-frame-options",
                "content-security-policy",
                "referrer-policy",
            ]
            for h in expected:
                if h not in headers:
                    missing.append(h)
            if missing:
                return [_result(self.id, "low", "Missing common security headers", {"missing": missing})]
            return []
        except requests.RequestException as e:
            return [_result(self.id, "low", "Error checking security headers", {"error": str(e)})]


class ToolSchemaValidationProbe(Probe):
    id = "PROBE-016"
    intrusive = False

    def run(self, target: str, timeout: int, options: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        origin = _origin(target)
        findings: List[Dict[str, Any]] = []
        try:
            r_tools = http.get(origin + "/tools", timeout=timeout)
        except requests.RequestException as e:
            return [_result(self.id, "low", "Error fetching /tools for schema validation", {"error": str(e)})]
        try:
            data = r_tools.json()
        except Exception:
            return [_result(self.id, "medium", "/tools is not JSON", {"status": r_tools.status_code})]
        tools = (data or {}).get("tools")
        policy = (data or {}).get("policy", {})
        if not isinstance(tools, list):
            findings.append(_result(self.id, "medium", "Missing or invalid 'tools' array", {}))
            return findings
        # Check for dangerous tool names and missing policies
        dangerous = {"exec", "shell", "spawn", "system", "eval", "download_and_execute"}
        for t in tools:
            name = (t or {}).get("name")
            if name and any(name.lower() == d for d in dangerous):
                findings.append(_result(self.id, "high", "Dangerous tool exposed", {"tool": name}))
        # read_file policy roots
        rf_pol = (policy.get("read_file") or {}) if isinstance(policy, dict) else {}
        roots = rf_pol.get("roots") if isinstance(rf_pol, dict) else None
        if roots is None:
            findings.append(_result(self.id, "medium", "Missing policy.roots for read_file", {}))
        elif not any(isinstance(x, str) for x in roots):
            findings.append(_result(self.id, "medium", "Invalid roots format for read_file", {"roots": roots}))
        # fetch_url policy (blocked private ranges)
        fu_pol = (policy.get("fetch_url") or {}) if isinstance(policy, dict) else {}
        blocked = (fu_pol.get("blocked") or []) if isinstance(fu_pol, dict) else []
        if not blocked:
            findings.append(_result(self.id, "low", "No blocked list for fetch_url (SSRF)", {}))
        return findings


class InvalidAuthProbe(Probe):
    id = "PROBE-010"
    intrusive = False

    def run(self, target: str, timeout: int, options: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        origin = _origin(target)
        payload = {"tool": "read_file", "args": {"path": "/tmp/test.txt"}}
        try:
            r = http.post(origin + "/tool/run", json=payload, headers={"Content-Type": "application/json"}, timeout=timeout)
            if 200 <= r.status_code < 300:
                return [_result(self.id, "high", "/tool/run succeeded without Authorization header", {"status": r.status_code})]
            if r.status_code not in (401, 403, 405, 429):
                return [_result(self.id, "medium", "Unexpected status for unauthenticated /tool/run", {"status": r.status_code})]
            # For 401/403, prefer structured JSON error
            try:
                j = r.json()
            except Exception:
                j = {}
            if not (isinstance(j, dict) and j.get("error")):
                return [_result(self.id, "low", "Unstructured auth error on /tool/run", {"status": r.status_code, "body": getattr(r, 'text', '')[:200]})]
            return []
        except requests.RequestException as e:
            return [_result(self.id, "low", "Error calling /tool/run without auth", {"error": str(e)})]


def run_probes(*, target: str, profile: str = "baseline", request_timeout: int = 10, out_json: Optional[str] = None, out_sarif: Optional[str] = None, enable_private_egress_checks: bool = False) -> Dict[str, Any]:
    start = time.time()
    probes: List[Probe] = [
        BogusTokenProbe(),
        MalformedRequestProbe(),
        CORSPreflightProbe(),
        ToolGuardrailsProbe(),
        StateReplayProbe(),
        RateLimitProbe(),
        MethodMatrixProbe(),
        ContentTypeMatrixProbe(),
        InvalidAuthProbe(),
        TraceMethodProbe(),
        MissingContentTypeProbe(),
        SSRFProbe(),
        SecurityHeadersProbe(),
        ToolSchemaValidationProbe(),
        NoneAlgTokenProbe(),
        JWKSKeyStrengthProbe(),
        HSTSAndTLSProbe(),
    ]
    if profile == "intrusive":
        probes.append(OversizePayloadProbe(size_kb=512))
        probes.append(LargeHeaderProbe())

    findings: List[Dict[str, Any]] = []
    for p in probes:
        if p.intrusive and profile != "intrusive":
            continue
        findings.extend(p.run(target, timeout=request_timeout, options={"enable_private_egress_checks": enable_private_egress_checks}))

    # Annotate findings with origin for better fingerprints
    for f in findings:
        ev = f.get("evidence") or {}
        if "origin" not in ev:
            ev["origin"] = _origin(target)
            f["evidence"] = ev

    out: Dict[str, Any] = {
        "target": target,
        "profile": profile,
        "duration_ms": int((time.time() - start) * 1000),
        "findings": findings,
    }

    if out_json:
        with open(out_json, "w", encoding="utf-8") as f:
            json_dump = __import__("json").dumps(out, indent=2)
            f.write(json_dump)
    if out_sarif:
        sarif = _sarif(findings)
        with open(out_sarif, "w", encoding="utf-8") as f:
            f.write(__import__("json").dumps(sarif, indent=2))

    return out
