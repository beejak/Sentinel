import json
from types import SimpleNamespace
from scanner.probes import JWKSKeyStrengthProbe


class FakeResp:
    def __init__(self, data):
        self._data = data
        self.status_code = 200
    def json(self):
        return self._data


def test_jwks_ec_curve_and_mismatch(monkeypatch):
    # Patch discover to return jwks uri
    monkeypatch.setattr("scanner.probes.discover", lambda target: {"oauth_summary": {"jwks_uri": "https://as/jwks.json"}})

    # Prepare JWKS with EC P-256 but wrong alg ES384 and RSA with ES alg
    jwks = {
        "keys": [
            {"kty": "EC", "kid": "ec1", "crv": "P-256", "alg": "ES384", "x": "00", "y": "00"},
            {"kty": "RSA", "kid": "rsa1", "n": "AQAB", "e": "AQAB", "alg": "ES256"},
        ]
    }
    monkeypatch.setattr("scanner.probes.http", "get", lambda url, timeout=None: FakeResp(jwks))

    p = JWKSKeyStrengthProbe()
    findings = p.run("https://resource", timeout=5)
    texts = [f["title"] for f in findings]
    assert any("alg/crv mismatch" in t for t in texts)
    assert any("alg/kty mismatch" in t for t in texts)