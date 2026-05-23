#!/usr/bin/env python3
"""Shared config.toml helpers for vuln-monitor and web dashboard."""

from __future__ import annotations

import copy
import hashlib
import os
import tomllib
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_FILE = PROJECT_ROOT / "config.toml"
CONFIG_EXAMPLE_FILE = PROJECT_ROOT / "config.example.toml"


DEFAULT_CONFIG = {
    "app": {
        "host": "0.0.0.0",
        "port": 8001,
        "data_dir": ".",
        "fetch_interval": 300,
        "login_required": True,
    },
    "network": {
        "https_proxy": "",
        "proxy_required_for_external": True,
        "request_timeout": 20,
    },
    "auth": {
        "admin_username": "admin",
        "admin_password": "",
        "session_secret": "",
    },
    "notify": {
        "default_channel": "wecom",
        "enabled": ["wecom"],
        "include_github_context": True,
    },
    "notify_wecom": {
        "webhook_url": "",
        "mentioned_list": [],
        "mentioned_mobile_list": [],
    },
    "notify_telegram": {
        "enabled": False,
        "bot_token": "",
        "chat_ids": [],
    },
    "github": {
        "tokens": [],
        "request_interval_sec": 2,
        "max_repo_results": 5,
        "fetch_readme_excerpt": True,
        "fetch_poc_metadata": True,
    },
    "nvd": {
        "api_key": "",
    },
    "llm": {
        "provider": "",
        "api_key": "",
        "base_url": "",
        "model": "",
        "temperature": 0.1,
        "max_tokens": 4096,
        "timeout": 60,
        "max_context": 1048576,
        "reasoning_effort": "high",
        "top_p": 0.9,
    },
}


SECTION_KEY_MAP = {
    ("notify", "wecom"): "notify_wecom",
    ("notify", "telegram"): "notify_telegram",
}


SECRET_KEYS = {
    ("auth", "admin_password"),
    ("auth", "session_secret"),
    ("notify_wecom", "webhook_url"),
    ("notify_telegram", "bot_token"),
    ("nvd", "api_key"),
    ("llm", "api_key"),
}


def _deep_merge(dst: dict, src: dict) -> dict:
    for key, value in src.items():
        if isinstance(value, dict) and isinstance(dst.get(key), dict):
            _deep_merge(dst[key], value)
        else:
            dst[key] = value
    return dst


def _toml_to_internal(raw: dict) -> dict:
    converted = {}
    for key, value in raw.items():
        if isinstance(value, dict):
            for alias, target in SECTION_KEY_MAP.items():
                if key == alias[0]:
                    nested = converted.setdefault(key, {})
                    nested.update(value)
                    for sub_key, sub_val in value.items():
                        if (key, sub_key) in SECTION_KEY_MAP:
                            converted[SECTION_KEY_MAP[(key, sub_key)]] = sub_val
                    break
            else:
                converted[key] = value
        else:
            converted[key] = value
    if "notify" in converted:
        notify = converted["notify"]
        if isinstance(notify.get("wecom"), dict):
            converted["notify_wecom"] = notify.pop("wecom")
        if isinstance(notify.get("telegram"), dict):
            converted["notify_telegram"] = notify.pop("telegram")
    return converted


def normalize_config(data: dict | None) -> dict:
    merged = copy.deepcopy(DEFAULT_CONFIG)
    if data:
        _deep_merge(merged, _toml_to_internal(data))
    merged["app"]["port"] = int(merged["app"].get("port") or 8001)
    merged["app"]["fetch_interval"] = int(merged["app"].get("fetch_interval") or 300)
    merged["network"]["request_timeout"] = int(merged["network"].get("request_timeout") or 20)
    merged["github"]["request_interval_sec"] = max(
        0, int(merged["github"].get("request_interval_sec") or 0)
    )
    merged["github"]["max_repo_results"] = max(
        1, int(merged["github"].get("max_repo_results") or 5)
    )
    merged["llm"]["temperature"] = float(merged["llm"].get("temperature") or 0.1)
    merged["llm"]["top_p"] = float(merged["llm"].get("top_p") or 0.9)
    merged["llm"]["max_tokens"] = int(merged["llm"].get("max_tokens") or 4096)
    merged["llm"]["timeout"] = int(merged["llm"].get("timeout") or 60)
    merged["llm"]["max_context"] = int(merged["llm"].get("max_context") or 1048576)
    merged["notify"]["enabled"] = list(merged["notify"].get("enabled") or [])
    merged["notify_telegram"]["chat_ids"] = list(merged["notify_telegram"].get("chat_ids") or [])
    merged["notify_wecom"]["mentioned_list"] = list(merged["notify_wecom"].get("mentioned_list") or [])
    merged["notify_wecom"]["mentioned_mobile_list"] = list(
        merged["notify_wecom"].get("mentioned_mobile_list") or []
    )
    merged["github"]["tokens"] = [t.strip() for t in merged["github"].get("tokens") or [] if str(t).strip()]
    return merged


def load_config(path: Path | None = None) -> dict:
    cfg_path = path or CONFIG_FILE
    if not cfg_path.exists():
        return copy.deepcopy(DEFAULT_CONFIG)
    raw = tomllib.loads(cfg_path.read_text(encoding="utf-8"))
    return normalize_config(raw)


def config_exists(path: Path | None = None) -> bool:
    return (path or CONFIG_FILE).exists()


def data_dir_from_config(cfg: dict) -> Path:
    raw = cfg.get("app", {}).get("data_dir", ".") or "."
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = PROJECT_ROOT / candidate
    candidate.mkdir(parents=True, exist_ok=True)
    return candidate.resolve()


def ensure_session_secret(cfg: dict) -> dict:
    auth = cfg.setdefault("auth", {})
    if auth.get("session_secret"):
        return cfg
    seed = "|".join([
        str(CONFIG_FILE),
        auth.get("admin_username", ""),
        auth.get("admin_password", ""),
        cfg.get("notify_wecom", {}).get("webhook_url", ""),
    ])
    auth["session_secret"] = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    return cfg


def _quote(val) -> str:
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, int):
        return str(val)
    if isinstance(val, float):
        return repr(val)
    return '"' + str(val).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _list(values) -> str:
    return "[" + ", ".join(_quote(v) for v in values) + "]"


def _serialize(cfg: dict) -> str:
    c = normalize_config(cfg)
    lines = [
        "[app]",
        f'host = {_quote(c["app"]["host"])}',
        f'port = {c["app"]["port"]}',
        f'data_dir = {_quote(c["app"]["data_dir"])}',
        f'fetch_interval = {c["app"]["fetch_interval"]}',
        f'login_required = {_quote(c["app"]["login_required"])}',
        "",
        "[network]",
        f'https_proxy = {_quote(c["network"]["https_proxy"])}',
        f'proxy_required_for_external = {_quote(c["network"]["proxy_required_for_external"])}',
        f'request_timeout = {c["network"]["request_timeout"]}',
        "",
        "[auth]",
        f'admin_username = {_quote(c["auth"]["admin_username"])}',
        f'admin_password = {_quote(c["auth"]["admin_password"])}',
        f'session_secret = {_quote(c["auth"]["session_secret"])}',
        "",
        "[notify]",
        f'default_channel = {_quote(c["notify"]["default_channel"])}',
        f'enabled = {_list(c["notify"]["enabled"])}',
        f'include_github_context = {_quote(c["notify"]["include_github_context"])}',
        "",
        "[notify.wecom]",
        f'webhook_url = {_quote(c["notify_wecom"]["webhook_url"])}',
        f'mentioned_list = {_list(c["notify_wecom"]["mentioned_list"])}',
        f'mentioned_mobile_list = {_list(c["notify_wecom"]["mentioned_mobile_list"])}',
        "",
        "[notify.telegram]",
        f'enabled = {_quote(c["notify_telegram"]["enabled"])}',
        f'bot_token = {_quote(c["notify_telegram"]["bot_token"])}',
        f'chat_ids = {_list(c["notify_telegram"]["chat_ids"])}',
        "",
        "[github]",
        f'tokens = {_list(c["github"]["tokens"])}',
        f'request_interval_sec = {c["github"]["request_interval_sec"]}',
        f'max_repo_results = {c["github"]["max_repo_results"]}',
        f'fetch_readme_excerpt = {_quote(c["github"]["fetch_readme_excerpt"])}',
        f'fetch_poc_metadata = {_quote(c["github"]["fetch_poc_metadata"])}',
        "",
        "[nvd]",
        f'api_key = {_quote(c["nvd"]["api_key"])}',
        "",
        "[llm]",
        f'provider = {_quote(c["llm"]["provider"])}',
        f'api_key = {_quote(c["llm"]["api_key"])}',
        f'base_url = {_quote(c["llm"]["base_url"])}',
        f'model = {_quote(c["llm"]["model"])}',
        f'temperature = {c["llm"]["temperature"]}',
        f'max_tokens = {c["llm"]["max_tokens"]}',
        f'timeout = {c["llm"]["timeout"]}',
        f'max_context = {c["llm"]["max_context"]}',
        f'reasoning_effort = {_quote(c["llm"]["reasoning_effort"])}',
        f'top_p = {c["llm"]["top_p"]}',
        "",
    ]
    return "\n".join(lines)


def save_config(cfg: dict, path: Path | None = None) -> Path:
    cfg_path = path or CONFIG_FILE
    normalized = ensure_session_secret(normalize_config(cfg))
    text = _serialize(normalized)
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = cfg_path.with_suffix(".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, cfg_path)
    return cfg_path


def ensure_config_file(path: Path | None = None) -> Path:
    cfg_path = path or CONFIG_FILE
    if not cfg_path.exists():
        save_config(copy.deepcopy(DEFAULT_CONFIG), cfg_path)
    return cfg_path


def _mask_secret(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"


def masked_config(cfg: dict) -> dict:
    out = copy.deepcopy(normalize_config(cfg))
    for section, key in SECRET_KEYS:
        section_map = out.get(section, {})
        if key in section_map:
            section_map[key] = _mask_secret(str(section_map.get(key, "")))
    if out.get("github", {}).get("tokens") is not None:
        out["github"]["tokens"] = [_mask_secret(str(t)) for t in out["github"]["tokens"]]
    return out


def config_status(cfg: dict) -> dict:
    normalized = normalize_config(cfg)
    missing = []
    if normalized["notify"]["default_channel"] == "wecom" and not normalized["notify_wecom"]["webhook_url"]:
        missing.append("notify.wecom.webhook_url")
    if normalized["notify_telegram"]["enabled"]:
        if not normalized["notify_telegram"]["bot_token"]:
            missing.append("notify.telegram.bot_token")
        if not normalized["notify_telegram"]["chat_ids"]:
            missing.append("notify.telegram.chat_ids")
    if normalized["app"]["login_required"]:
        if not normalized["auth"]["admin_username"]:
            missing.append("auth.admin_username")
        if not normalized["auth"]["admin_password"]:
            missing.append("auth.admin_password")
    return {
        "config_path": str(CONFIG_FILE),
        "exists": config_exists(),
        "missing": missing,
        "proxy_enabled": bool(normalized["network"]["https_proxy"]),
        "github_token_count": len(normalized["github"]["tokens"]),
        "wecom_enabled": "wecom" in normalized["notify"]["enabled"],
        "telegram_enabled": normalized["notify_telegram"]["enabled"],
        "llm_enabled": bool(normalized["llm"]["api_key"]),
    }
