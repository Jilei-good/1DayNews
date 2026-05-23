#!/usr/bin/env python3
"""Interactive setup for vuln-monitor's project-local config.toml."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
SRC_DIR = SCRIPT_DIR.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from config_utils import CONFIG_FILE, ensure_config_file, load_config, save_config


def _prompt(label: str, current: str, required: bool = False) -> str:
    suffix = f" [current: {current}]" if current else ""
    while True:
        try:
            raw = input(f"{label}{suffix}: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\ncancelled")
            raise SystemExit(1)
        if raw:
            return raw
        if current or not required:
            return current
        print("value required")


def _prompt_list(label: str, current: list[str]) -> list[str]:
    joined = ",".join(current)
    raw = _prompt(label + " (comma-separated)", joined)
    return [item.strip() for item in raw.split(",") if item.strip()]


def do_show() -> None:
    cfg = load_config()
    print(f"path: {CONFIG_FILE}\n")
    print(f"host                 = {cfg['app']['host']}")
    print(f"port                 = {cfg['app']['port']}")
    print(f"fetch_interval       = {cfg['app']['fetch_interval']}")
    print(f"https_proxy          = {cfg['network']['https_proxy'] or '(empty)'}")
    print(f"notify.default       = {cfg['notify']['default_channel']}")
    print(f"wecom.enabled        = {'wecom' in cfg['notify']['enabled']}")
    print(f"telegram.enabled     = {cfg['notify_telegram']['enabled']}")
    print(f"github.tokens        = {len(cfg['github']['tokens'])}")
    print(f"llm.provider         = {cfg['llm']['provider'] or '(empty)'}")


def do_interactive() -> None:
    ensure_config_file()
    cfg = load_config()
    print(f"editing {CONFIG_FILE}\n")
    cfg["app"]["host"] = _prompt("Web host", str(cfg["app"]["host"])) or "0.0.0.0"
    cfg["app"]["port"] = int(_prompt("Web port", str(cfg["app"]["port"])))
    cfg["app"]["fetch_interval"] = int(_prompt("Fetch interval (sec)", str(cfg["app"]["fetch_interval"])))
    cfg["network"]["https_proxy"] = _prompt("HTTPS proxy", cfg["network"]["https_proxy"])
    cfg["auth"]["admin_username"] = _prompt("Admin username", cfg["auth"]["admin_username"], required=True)
    cfg["auth"]["admin_password"] = _prompt("Admin password", cfg["auth"]["admin_password"], required=True)
    cfg["notify"]["default_channel"] = _prompt("Default notify channel", cfg["notify"]["default_channel"] or "wecom")
    cfg["notify_wecom"]["webhook_url"] = _prompt("WeCom webhook URL", cfg["notify_wecom"]["webhook_url"])
    cfg["notify_telegram"]["enabled"] = (
        _prompt("Enable Telegram (true/false)", "true" if cfg["notify_telegram"]["enabled"] else "false").lower() == "true"
    )
    cfg["notify_telegram"]["bot_token"] = _prompt("Telegram bot token", cfg["notify_telegram"]["bot_token"])
    cfg["notify_telegram"]["chat_ids"] = _prompt_list("Telegram chat IDs", cfg["notify_telegram"]["chat_ids"])
    cfg["github"]["tokens"] = _prompt_list("GitHub tokens", cfg["github"]["tokens"])
    cfg["nvd"]["api_key"] = _prompt("NVD API key", cfg["nvd"]["api_key"])
    cfg["llm"]["provider"] = _prompt("LLM provider", cfg["llm"]["provider"])
    cfg["llm"]["api_key"] = _prompt("LLM API key", cfg["llm"]["api_key"])
    cfg["llm"]["base_url"] = _prompt("LLM base URL", cfg["llm"]["base_url"])
    cfg["llm"]["model"] = _prompt("LLM model", cfg["llm"]["model"])
    save_config(cfg)
    print(f"\nsaved to {CONFIG_FILE}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--show", action="store_true", help="print config summary")
    parser.add_argument("--path", action="store_true", help="print config path")
    args = parser.parse_args()
    if args.path:
        print(CONFIG_FILE)
        return
    if args.show:
        do_show()
        return
    do_interactive()


if __name__ == "__main__":
    main()
