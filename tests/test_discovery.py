import json
from typing import Dict
from unittest.mock import patch

from scanner.discovery import _origin, _parse_www_authenticate, discover


def test_origin_normalizes_scheme_and_host():
    assert _origin("example.com") == "https://example.com"
    assert _origin("http://example.com/path") == "http://example.com"
    assert _origin("https://api.example.com") == "https://api.example.com"


def test_parse_www_authenticate_basic():
    headers = {"WWW-Authenticate": 'Bearer realm="x", error="invalid_token"'}
    parsed = _parse_www_authenticate(headers)
    assert parsed["raw"]
    assert parsed["parsed"][0]["scheme"].lower() == "bearer"
    params: Dict[str, str] = parsed["parsed"][0]["params"]
    assert params.get("realm") == "x"
    assert params.get("error") == "invalid_token"


@patch("scanner.discovery._get")
def test_discover_oauth_summary_aggregates(mock_get):
    def _fake_get(url: str):
        if url.endswith("/.well-known/oauth-authorization-server"):
            return 200, {}, {"authorization_endpoint": "https://as/authorize", "issuer": "https://as"}, None
        if url.endswith("/.well-known/openid-configuration"):
            return 200, {}, {"token_endpoint": "https://as/token", "jwks_uri": "https://as/jwks.json"}, None
        if url.endswith("/.well-known/oauth-protected-resource"):
            return 200, {}, {"authorization_servers": ["https://as"]}, None
        # probe to target
        return 200, {}, None, None

    mock_get.side_effect = _fake_get
    res = discover("https://resource")
    oa = res["oauth_summary"]
    assert oa["authorization_endpoint"] == "https://as/authorize"
    assert oa["token_endpoint"] == "https://as/token"
    assert oa["jwks_uri"] == "https://as/jwks.json"
    assert oa["authorization_servers"] == ["https://as"]
