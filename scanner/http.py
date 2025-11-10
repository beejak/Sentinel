from __future__ import annotations
from typing import Any, Dict, Optional
import requests
from .config import get_config


def _merge_headers(h1: Optional[Dict[str, str]], h2: Optional[Dict[str, str]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if h1:
        out.update(h1)
    if h2:
        out.update(h2)
    return out


def _apply_http_options(kwargs: Dict[str, Any]) -> Dict[str, Any]:
    cfg = get_config().get("http", {})
    # verify may be bool or path
    if cfg.get("verify") is not None:
        kwargs.setdefault("verify", cfg.get("verify"))
    # cert can be str or (cert,key)
    cert = cfg.get("cert")
    key = cfg.get("key")
    if cert and key:
        kwargs.setdefault("cert", (cert, key))
    elif cert:
        kwargs.setdefault("cert", cert)
    # proxies: one URL for both http/https
    proxy = cfg.get("proxy")
    if proxy:
        kwargs.setdefault("proxies", {"http": proxy, "https": proxy})
    # headers
    headers = _merge_headers(cfg.get("headers"), kwargs.get("headers"))
    if headers:
        kwargs["headers"] = headers
    # timeout default
    kwargs.setdefault("timeout", cfg.get("timeout", 10))
    return kwargs


def request(method: str, url: str, **kwargs: Any) -> requests.Response:
    return requests.request(method, url, **_apply_http_options(kwargs))


def get(url: str, **kwargs: Any) -> requests.Response:
    return request("GET", url, **kwargs)


def post(url: str, **kwargs: Any) -> requests.Response:
    return request("POST", url, **kwargs)


def options(url: str, **kwargs: Any) -> requests.Response:
    return request("OPTIONS", url, **kwargs)
