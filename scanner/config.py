from __future__ import annotations
import os
import re
from typing import Any, Dict, Optional

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover - PyYAML provided in requirements
    yaml = None  # type: ignore

_CFG: Dict[str, Any] = {}


def _str_to_bool_or_path(val: str) -> Any:
    v = str(val).strip().lower()
    if v in ("true", "1", "yes", "on"):  # bool true
        return True
    if v in ("false", "0", "no", "off"):  # bool false
        return False
    return val  # treat as path/string


def set_config(cfg: Dict[str, Any]) -> None:
    global _CFG
    _CFG = cfg


def get_config() -> Dict[str, Any]:
    return _CFG


essential_keys = {
    "offline": False,
    "policy": {
        "enable_private_egress_checks": False,
    },
    "http": {
        "verify": True,
        "cert": None,
        "key": None,
        "proxy": None,
        "headers": {},
        "timeout": 10,
    },
    # Per-domain overrides: { "api.example.com": { "headers": {"Authorization": "Bearer ..."} } }
    "domains": {},
}


def _merge(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(a)
    for k, v in (b or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config(path: Optional[str]) -> Dict[str, Any]:
    cfg: Dict[str, Any] = essential_keys
    # Load from file if provided or default sentinel.yml
    file_path = path or (os.path.exists("sentinel.yml") and "sentinel.yml") or (os.path.exists("sentinel.yaml") and "sentinel.yaml") or None
    if file_path and yaml is not None:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                file_cfg = yaml.safe_load(f) or {}
            cfg = _merge(cfg, file_cfg)
        except Exception:
            pass
    # Environment overrides (SENTINEL_*)
    env_http_headers: Dict[str, str] = {}
    for k, v in os.environ.items():
        if k.startswith("SENTINEL_HTTP_HEADER_"):
            name = k[len("SENTINEL_HTTP_HEADER_"):].replace("_", "-")
            env_http_headers[name] = v
    env_cfg: Dict[str, Any] = {
        "offline": _str_to_bool_or_path(os.environ.get("SENTINEL_OFFLINE", str(cfg["offline"]))),
        "policy": {
            "enable_private_egress_checks": _str_to_bool_or_path(os.environ.get("SENTINEL_ENABLE_PRIVATE_EGRESS_CHECKS", str(cfg["policy"]["enable_private_egress_checks"]))),
        },
        "http": {
            "verify": _str_to_bool_or_path(os.environ.get("SENTINEL_HTTP_VERIFY", str(cfg["http"]["verify"]))),
            "cert": os.environ.get("SENTINEL_HTTP_CERT", cfg["http"]["cert"] or "") or None,
            "key": os.environ.get("SENTINEL_HTTP_KEY", cfg["http"]["key"] or "") or None,
            "proxy": os.environ.get("SENTINEL_HTTP_PROXY", cfg["http"]["proxy"] or "") or None,
            "timeout": int(os.environ.get("SENTINEL_HTTP_TIMEOUT", cfg["http"]["timeout"])),
            "headers": _merge(cfg["http"].get("headers", {}), env_http_headers),
        },
    }
    cfg = _merge(cfg, env_cfg)
    set_config(cfg)
    return cfg
