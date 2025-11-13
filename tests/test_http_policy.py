import pytest
from scanner.config import set_config
from scanner.http import _apply_http_options

# Default HTTP timeout in seconds
DEFAULT_HTTP_TIMEOUT = 7


def test_headers_merge_replace_and_strict_auth():
    set_config({
        "policy": {"strict_auth_domains": True},
        "http": {"headers": {"Authorization": "Bearer GLOBAL", "X-Base": "A"}, "headers_merge": "merge_prefer_domain", "timeout": 9},
        "domains": {
            "api.example.com": {
                "headers": {"X-D": "B"},
                # do NOT allow auth and do NOT redeclare Authorization -> should be stripped
                "headers_merge": "replace",
                "timeouts": {"connect": 2, "read": 3},
            }
        },
    })
    kwargs = _apply_http_options("https://api.example.com/x", {"headers": {"X-Req": "C"}})
    # Authorization should be stripped due to strict policy and no allow_auth/Authorization in domain headers
    assert "Authorization" not in kwargs["headers"]
    # replace -> only domain headers remain, then merged with request headers per strategy
    assert kwargs["headers"].get("X-D") == "B"
    assert kwargs["headers"].get("X-Req") == "C"
    # timeout tuple applied from domain
    assert kwargs["timeout"] == (2, 3)


def test_headers_merge_append_and_allow_auth():
    set_config({
        "policy": {"strict_auth_domains": True},
        "http": {"headers": {"Authorization": "Bearer GLOBAL", "List": "a"}, "headers_merge": "append", "timeout": DEFAULT_HTTP_TIMEOUT},
        "domains": {
            "svc.internal": {
                "headers": {"Authorization": "Bearer DOM", "List": "b"},
                "allow_auth": True,
            }
        },
    })
    kwargs = _apply_http_options("https://svc.internal/", {})
    # Authorization preserved due to allow_auth and domain header provides Authorization
    assert kwargs["headers"].get("Authorization").endswith("DOM")
    # append strategy -> base then domain
    assert kwargs["headers"].get("List") == "a, b"
    # default timeout
    assert kwargs["timeout"] == DEFAULT_HTTP_TIMEOUT
