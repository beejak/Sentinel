from __future__ import annotations
from typing import Any, Dict, Optional
from urllib.parse import urlparse
import requests
from .config import get_config


def _merge_headers(h1: Optional[Dict[str, str]], h2: Optional[Dict[str, str]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if h1:
        out.update(h1)
    if h2:
        out.update(h2)
    return out


def _apply_http_options(url: str, kwargs: Dict[str, Any]) -> Dict[str, Any]:
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
    # headers (global)
    headers = _merge_headers(cfg.get("headers"), kwargs.get("headers"))
    # domain-specific headers
    try:
        host = urlparse(url).hostname or ""
    except Exception:
        host = ""
    domains = get_config().get("domains", {})
    dom_headers: Dict[str, str] = {}
    if isinstance(domains, dict) and host:
        # Exact host match or suffix keys like ".example.com"
        for k, v in domains.items():
            if not isinstance(v, dict):
                continue
            if k == host or (k.startswith(".") and host.endswith(k)):
                dh = v.get("headers")
                if isinstance(dh, dict):
                    dom_headers.update({str(n): str(val) for n, val in dh.items()})
    headers = _merge_headers(headers, dom_headers)
    if headers:
        kwargs["headers"] = headers
    # timeout default
    kwargs.setdefault("timeout", cfg.get("timeout", 10))
    return kwargs


def request(method: str, url: str, **kwargs: Any) -> requests.Response:
    return requests.request(method, url, **_apply_http_options(url, kwargs))


def get(url: str, **kwargs: Any) -> requests.Response:
    return request("GET", url, **kwargs)


def post(url: str, **kwargs: Any) -> requests.Response:
    return request("POST", url, **kwargs)


def options(url: str, **kwargs: Any) -> requests.Response:
    return request("OPTIONS", url, **kwargs)
