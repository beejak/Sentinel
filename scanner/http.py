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


def _merge_with_strategy(base: Dict[str, str], dom: Dict[str, str], strategy: str) -> Dict[str, str]:
    strategy = (strategy or "merge_prefer_domain").lower()
    if strategy == "replace":
        return dict(dom)
    if strategy == "merge_prefer_global":
        out = dict(dom)
        out.update(base)
        return out
    if strategy in ("append", "prepend"):
        out = dict(base)
        for k, v in dom.items():
            if k in out:
                if strategy == "append":
                    out[k] = f"{out[k]}, {v}"
                else:
                    out[k] = f"{v}, {out[k]}"
            else:
                out[k] = v
        return out
    # default merge_prefer_domain
    out = dict(base)
    out.update(dom)
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

    # domain-specific overrides (verify/cert/key/proxy)
    try:
        host = urlparse(url).hostname or ""
    except Exception:
        host = ""
    domains = get_config().get("domains", {})
    dom_cfg: Dict[str, Any] = {}
    if isinstance(domains, dict) and host:
        for k, v in domains.items():
            if not isinstance(v, dict):
                continue
            if k == host or (k.startswith(".") and host.endswith(k)):
                dom_cfg = v
                break
    # Apply domain overrides if present
    if isinstance(dom_cfg, dict) and dom_cfg:
        if dom_cfg.get("verify") is not None:
            kwargs["verify"] = dom_cfg.get("verify")
        dc = dom_cfg.get("cert")
        dk = dom_cfg.get("key")
        if dc and dk:
            kwargs["cert"] = (dc, dk)
        elif dc:
            kwargs["cert"] = dc
        dproxy = dom_cfg.get("proxy")
        if dproxy:
            kwargs["proxies"] = {"http": dproxy, "https": dproxy}

    # headers (global)
    headers = _merge_headers(cfg.get("headers"), kwargs.get("headers"))
    # domain-specific headers and policy
    # host already parsed above; domains already loaded
    dom_headers: Dict[str, str] = {}
    headers_merge_strategy = str(cfg.get("headers_merge", "merge_prefer_domain"))
    allow_auth = False
    dom_timeouts: Optional[Dict[str, int]] = None
    if isinstance(domains, dict) and host:
        # Exact host match or suffix keys like ".example.com"
        for k, v in domains.items():
            if not isinstance(v, dict):
                continue
            if k == host or (k.startswith(".") and host.endswith(k)):
                dh = v.get("headers")
                if isinstance(dh, dict):
                    dom_headers.update({str(n): str(val) for n, val in dh.items()})
                allow_auth = bool(v.get("allow_auth"))
                headers_merge_strategy = str(v.get("headers_merge", headers_merge_strategy))
                if isinstance(v.get("timeouts"), dict):
                    dom_timeouts = {"connect": int(v["timeouts"].get("connect", 0) or 0), "read": int(v["timeouts"].get("read", 0) or 0)}
                break
    # Strict auth policy: remove Authorization header unless allowed by domain or explicitly set in domain headers
    strict = bool(get_config().get("policy", {}).get("strict_auth_domains", False))
    if strict and "Authorization" in headers and not (allow_auth or ("Authorization" in dom_headers)):
        headers.pop("Authorization", None)

    # Apply merge strategy between global/request headers and domain headers
    headers = _merge_with_strategy(headers, dom_headers, headers_merge_strategy)
    if headers:
        kwargs["headers"] = headers

    # timeout default (support per-domain connect/read overrides)
    if dom_timeouts and (dom_timeouts.get("connect") or dom_timeouts.get("read")):
        conn = dom_timeouts.get("connect") or cfg.get("timeout", 10)
        rd = dom_timeouts.get("read") or cfg.get("timeout", 10)
        kwargs.setdefault("timeout", (conn, rd))
    else:
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
