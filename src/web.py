#!/usr/bin/env python3
"""Shared-access vuln-monitor dashboard with auth and config management."""

from __future__ import annotations

import argparse
import contextlib
import json
import sqlite3
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
from flask import Flask, abort, jsonify, request, session
from waitress import serve

try:
    from config_utils import (
        CONFIG_FILE,
        config_exists,
        config_status,
        data_dir_from_config,
        ensure_config_file,
        ensure_session_secret,
        load_config,
        masked_config,
        normalize_config,
        save_config,
    )
except ModuleNotFoundError:
    from .config_utils import (
        CONFIG_FILE,
        config_exists,
        config_status,
        data_dir_from_config,
        ensure_config_file,
        ensure_session_secret,
        load_config,
        masked_config,
        normalize_config,
        save_config,
    )


LIMIT_MAX = 500
app = Flask(__name__)
app.secret_key = ensure_session_secret(load_config())["auth"]["session_secret"]


def current_config():
    cfg = ensure_session_secret(load_config())
    app.secret_key = cfg["auth"]["session_secret"]
    return cfg


def db_file():
    return data_dir_from_config(current_config()) / "vuln_cache.db"


def _session_ok():
    cfg = current_config()
    if not cfg["app"]["login_required"]:
        return True
    return bool(session.get("auth_ok"))


def require_auth():
    if not _session_ok():
        abort(401)


@app.after_request
def no_cache(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return response


@contextlib.contextmanager
def get_db():
    db = db_file()
    if not db.exists():
        yield None
        return
    db_uri = f"file:{urllib.parse.quote(str(db), safe='/:')}?mode=ro"
    try:
        conn = sqlite3.connect(db_uri, uri=True, timeout=5)
    except sqlite3.OperationalError:
        conn = sqlite3.connect(str(db), timeout=5)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def _vulns_columns(conn):
    return {row[1] for row in conn.execute("PRAGMA table_info(vulns)")}


def _int_arg(name, default, lo, hi):
    try:
        return max(lo, min(hi, int(request.args.get(name, default))))
    except (ValueError, TypeError):
        return default


def _to_bool(val):
    if isinstance(val, bool):
        return val
    return str(val).strip().lower() in {"1", "true", "yes", "on"}


def _clean_list(value):
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    if isinstance(value, str):
        return [line.strip() for line in value.splitlines() if line.strip()]
    return []


def _apply_config_update(payload):
    cfg = current_config()
    app_section = payload.get("app", {})
    network = payload.get("network", {})
    auth = payload.get("auth", {})
    notify = payload.get("notify", {})
    wecom = payload.get("notify_wecom", {})
    telegram = payload.get("notify_telegram", {})
    github = payload.get("github", {})
    nvd = payload.get("nvd", {})
    llm = payload.get("llm", {})

    cfg["app"]["host"] = app_section.get("host", cfg["app"]["host"]) or cfg["app"]["host"]
    cfg["app"]["port"] = int(app_section.get("port", cfg["app"]["port"]) or cfg["app"]["port"])
    cfg["app"]["fetch_interval"] = int(app_section.get("fetch_interval", cfg["app"]["fetch_interval"]) or cfg["app"]["fetch_interval"])
    cfg["app"]["data_dir"] = app_section.get("data_dir", cfg["app"]["data_dir"]) or cfg["app"]["data_dir"]
    cfg["app"]["login_required"] = _to_bool(app_section.get("login_required", cfg["app"]["login_required"]))
    cfg["network"]["https_proxy"] = network.get("https_proxy", cfg["network"]["https_proxy"])
    cfg["network"]["request_timeout"] = int(network.get("request_timeout", cfg["network"]["request_timeout"]) or cfg["network"]["request_timeout"])
    cfg["notify"]["default_channel"] = notify.get("default_channel", cfg["notify"]["default_channel"]) or cfg["notify"]["default_channel"]
    cfg["notify"]["include_github_context"] = _to_bool(notify.get("include_github_context", cfg["notify"]["include_github_context"]))
    cfg["notify"]["enabled"] = _clean_list(notify.get("enabled", cfg["notify"]["enabled"]))
    cfg["notify_telegram"]["enabled"] = _to_bool(telegram.get("enabled", cfg["notify_telegram"]["enabled"]))
    cfg["notify_telegram"]["chat_ids"] = _clean_list(telegram.get("chat_ids", cfg["notify_telegram"]["chat_ids"]))
    cfg["notify_wecom"]["mentioned_list"] = _clean_list(wecom.get("mentioned_list", cfg["notify_wecom"]["mentioned_list"]))
    cfg["notify_wecom"]["mentioned_mobile_list"] = _clean_list(wecom.get("mentioned_mobile_list", cfg["notify_wecom"]["mentioned_mobile_list"]))
    cfg["github"]["request_interval_sec"] = int(github.get("request_interval_sec", cfg["github"]["request_interval_sec"]) or cfg["github"]["request_interval_sec"])
    cfg["github"]["max_repo_results"] = int(github.get("max_repo_results", cfg["github"]["max_repo_results"]) or cfg["github"]["max_repo_results"])
    cfg["github"]["fetch_readme_excerpt"] = _to_bool(github.get("fetch_readme_excerpt", cfg["github"]["fetch_readme_excerpt"]))
    cfg["github"]["fetch_poc_metadata"] = _to_bool(github.get("fetch_poc_metadata", cfg["github"]["fetch_poc_metadata"]))
    cfg["llm"]["provider"] = llm.get("provider", cfg["llm"]["provider"])
    cfg["llm"]["base_url"] = llm.get("base_url", cfg["llm"]["base_url"])
    cfg["llm"]["model"] = llm.get("model", cfg["llm"]["model"])
    cfg["llm"]["temperature"] = float(llm.get("temperature", cfg["llm"]["temperature"]) or cfg["llm"]["temperature"])
    cfg["llm"]["max_tokens"] = int(llm.get("max_tokens", cfg["llm"]["max_tokens"]) or cfg["llm"]["max_tokens"])
    cfg["llm"]["timeout"] = int(llm.get("timeout", cfg["llm"]["timeout"]) or cfg["llm"]["timeout"])
    cfg["llm"]["max_context"] = int(llm.get("max_context", cfg["llm"]["max_context"]) or cfg["llm"]["max_context"])
    cfg["llm"]["reasoning_effort"] = llm.get("reasoning_effort", cfg["llm"]["reasoning_effort"])
    cfg["llm"]["top_p"] = float(llm.get("top_p", cfg["llm"]["top_p"]) or cfg["llm"]["top_p"])

    for section, key in [
        ("auth", "admin_username"),
        ("auth", "admin_password"),
        ("notify_wecom", "webhook_url"),
        ("notify_telegram", "bot_token"),
        ("nvd", "api_key"),
        ("llm", "api_key"),
    ]:
        source = {
            "auth": auth,
            "notify_wecom": wecom,
            "notify_telegram": telegram,
            "nvd": nvd,
            "llm": llm,
        }[section]
        value = source.get(key)
        if value not in (None, ""):
            cfg[section][key] = value

    token_lines = github.get("tokens")
    if token_lines not in (None, ""):
        cfg["github"]["tokens"] = _clean_list(token_lines)

    save_config(normalize_config(cfg))
    return current_config()


def _test_wecom(cfg):
    webhook = cfg["notify_wecom"]["webhook_url"]
    if not webhook:
        return {"ok": False, "detail": "wecom webhook not configured"}
    session_obj = requests.Session()
    if cfg["network"]["https_proxy"]:
        session_obj.proxies = {"http": cfg["network"]["https_proxy"], "https": cfg["network"]["https_proxy"]}
    try:
        resp = session_obj.post(
            webhook,
            json={"msgtype": "markdown", "markdown": {"content": "**vuln-monitor test**\n\n配置测试成功。"}},
            timeout=cfg["network"]["request_timeout"],
        )
        data = resp.json()
        return {"ok": resp.status_code == 200 and data.get("errcode") == 0, "detail": data}
    except Exception as ex:
        return {"ok": False, "detail": str(ex)}


def _test_telegram(cfg):
    bot = cfg["notify_telegram"]["bot_token"]
    chat_ids = cfg["notify_telegram"]["chat_ids"]
    if not bot or not chat_ids:
        return {"ok": False, "detail": "telegram bot_token/chat_ids not configured"}
    session_obj = requests.Session()
    if cfg["network"]["https_proxy"]:
        session_obj.proxies = {"http": cfg["network"]["https_proxy"], "https": cfg["network"]["https_proxy"]}
    try:
        resp = session_obj.post(
            f"https://api.telegram.org/bot{bot}/sendMessage",
            json={"chat_id": chat_ids[0], "text": "vuln-monitor test\n\n配置测试成功。"},
            timeout=cfg["network"]["request_timeout"],
        )
        return {"ok": resp.status_code == 200, "detail": resp.text[:200]}
    except Exception as ex:
        return {"ok": False, "detail": str(ex)}


def _network_check(cfg):
    endpoints = {
        "github": "https://api.github.com/rate_limit",
        "nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-3400",
        "cisco": "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml",
        "wecom": cfg["notify_wecom"]["webhook_url"] or "https://qyapi.weixin.qq.com/cgi-bin/webhook/send",
    }
    session_obj = requests.Session()
    if cfg["network"]["https_proxy"]:
        session_obj.proxies = {"http": cfg["network"]["https_proxy"], "https": cfg["network"]["https_proxy"]}
    results = {}
    for name, url in endpoints.items():
        try:
            resp = session_obj.get(url, timeout=cfg["network"]["request_timeout"])
            results[name] = {"ok": resp.status_code < 500, "status": resp.status_code}
        except Exception as ex:
            results[name] = {"ok": False, "error": str(ex)}
    return results


@app.route("/api/auth/session")
def api_session():
    cfg = current_config()
    return jsonify({
        "authenticated": _session_ok(),
        "login_required": cfg["app"]["login_required"],
        "config_exists": config_exists(),
    })


@app.route("/api/auth/login", methods=["POST"])
def api_login():
    cfg = current_config()
    data = request.get_json(force=True, silent=True) or {}
    if data.get("username") == cfg["auth"]["admin_username"] and data.get("password") == cfg["auth"]["admin_password"]:
        session["auth_ok"] = True
        session.permanent = True
        return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "invalid credentials"}), 401


@app.route("/api/auth/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"ok": True})


@app.route("/api/config/status")
def api_config_status():
    require_auth()
    return jsonify(config_status(current_config()))


@app.route("/api/config", methods=["GET", "POST"])
def api_config():
    require_auth()
    if request.method == "POST":
        cfg = _apply_config_update(request.get_json(force=True, silent=True) or {})
        return jsonify({"ok": True, "status": config_status(cfg)})
    return jsonify(masked_config(current_config()))


@app.route("/api/test-notify", methods=["POST"])
def api_test_notify():
    require_auth()
    cfg = current_config()
    return jsonify({
        "wecom": _test_wecom(cfg),
        "telegram": _test_telegram(cfg) if cfg["notify_telegram"]["enabled"] else {"ok": False, "detail": "telegram disabled"},
    })


@app.route("/api/network/check")
def api_network_check():
    require_auth()
    return jsonify(_network_check(current_config()))


@app.route("/api/vulns")
def api_vulns():
    require_auth()
    with get_db() as conn:
        if conn is None:
            return jsonify([])
        cols_avail = _vulns_columns(conn)
        where, params = [], []
        q = request.args.get("q", "").strip()
        if q:
            where.append("(cve_id LIKE ? OR title LIKE ? OR summary LIKE ? OR github_repo_name LIKE ? OR github_poc_summary LIKE ?)")
            params.extend([f"%{q}%"] * 5)
        source = request.args.get("source", "").strip()
        if source:
            where.append("source = ?")
            params.append(source)
        vuln_type = request.args.get("vuln_type", "").strip()
        if vuln_type and "vuln_type" in cols_avail:
            where.append("vuln_type = ?")
            params.append(vuln_type)
        severity = request.args.get("severity", "").strip().lower()
        if severity in ("critical", "high", "medium", "low"):
            where.append("LOWER(severity) = ?")
            params.append(severity)
        pushed = request.args.get("pushed", "").strip()
        if pushed == "1":
            where.append("pushed = 1")
        days = _int_arg("days", 0, 0, 3650)
        if days > 0:
            cutoff_date = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
            cutoff_ts = (datetime.now(timezone.utc) - timedelta(days=days)).timestamp()
            where.append("(cve_published >= ? OR (cve_published IS NULL AND created_at > ?))")
            params.extend([cutoff_date, cutoff_ts])
        cols = [
            "cve_id", "source", "title", "link", "summary", "reason", "pushed", "created_at",
            "cve_published", "severity", "cvss", "llm_verdict", "llm_notes", "tg_sent",
            "vuln_type", "freshness", "github_repo_url", "github_repo_name", "github_repo_desc",
            "github_repo_stars", "github_primary_poc_url", "github_poc_index_url", "github_related_poc_urls", "github_poc_summary", "github_poc_readme_excerpt",
            "github_poc_found", "github_poc_count",
        ]
        sql = f"SELECT {','.join(c for c in cols if c in cols_avail or c in ('cve_id','source','title','link','summary','reason','pushed','created_at','cve_published','severity','cvss','llm_verdict','llm_notes','tg_sent'))} FROM vulns"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY COALESCE(cve_published, strftime('%Y-%m-%d', created_at, 'unixepoch')) DESC, created_at DESC LIMIT ?"
        params.append(_int_arg("limit", 100, 1, LIMIT_MAX))
        rows = conn.execute(sql, params).fetchall()
    return jsonify([{
        "id": r["cve_id"],
        "source": r["source"],
        "title": r["title"],
        "url": r["link"],
        "summary": r["summary"],
        "reason": r["reason"],
        "vuln_type": r["vuln_type"] if "vuln_type" in r.keys() else None,
        "freshness": r["freshness"] if "freshness" in r.keys() else None,
        "pushed": bool(r["pushed"]),
        "tg_sent": bool(r["tg_sent"]) if r["tg_sent"] is not None else None,
        "cve_published": r["cve_published"],
        "severity": r["severity"],
        "cvss": r["cvss"],
        "llm_verdict": r["llm_verdict"],
        "llm_notes": r["llm_notes"],
        "github_repo_url": r["github_repo_url"] if "github_repo_url" in r.keys() else "",
        "github_repo_name": r["github_repo_name"] if "github_repo_name" in r.keys() else "",
        "github_repo_desc": r["github_repo_desc"] if "github_repo_desc" in r.keys() else "",
        "github_repo_stars": r["github_repo_stars"] if "github_repo_stars" in r.keys() else 0,
        "github_primary_poc_url": r["github_primary_poc_url"] if "github_primary_poc_url" in r.keys() else "",
        "github_poc_index_url": r["github_poc_index_url"] if "github_poc_index_url" in r.keys() else "",
        "github_related_poc_urls": r["github_related_poc_urls"] if "github_related_poc_urls" in r.keys() else "[]",
        "github_poc_summary": r["github_poc_summary"] if "github_poc_summary" in r.keys() else "",
        "github_poc_readme_excerpt": r["github_poc_readme_excerpt"] if "github_poc_readme_excerpt" in r.keys() else "",
        "github_poc_found": r["github_poc_found"] if "github_poc_found" in r.keys() else 0,
        "github_poc_count": r["github_poc_count"] if "github_poc_count" in r.keys() else 0,
        "date": r["cve_published"] or (datetime.fromtimestamp(r["created_at"], tz=timezone.utc).strftime("%Y-%m-%d") if r["created_at"] else None),
    } for r in rows])


@app.route("/api/stats")
def api_stats():
    require_auth()
    with get_db() as conn:
        if conn is None:
            return jsonify({"total": 0, "pushed": 0, "sources": {}})
        total = conn.execute("SELECT COUNT(*) FROM vulns").fetchone()[0]
        pushed = conn.execute("SELECT COUNT(*) FROM vulns WHERE pushed=1").fetchone()[0]
        sources = conn.execute("SELECT source, COUNT(*) as n FROM vulns WHERE source IS NOT NULL GROUP BY source ORDER BY n DESC").fetchall()
    return jsonify({"total": total, "pushed": pushed, "sources": {r["source"]: r["n"] for r in sources}})


@app.route("/api/sources")
def api_sources():
    require_auth()
    with get_db() as conn:
        if conn is None:
            return jsonify([])
        rows = conn.execute("SELECT DISTINCT source FROM vulns WHERE source IS NOT NULL ORDER BY source").fetchall()
    return jsonify([r["source"] for r in rows])


@app.route("/")
def index():
    return HTML


HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>1DayNews Console</title>
  <style>
    :root { --bg:#f6eddc; --ink:#131313; --card:#fffdf7; --line:#1a1a1a; --accent:#de5b31; --soft:#efd6a2; --ok:#2d8f6f; }
    * { box-sizing:border-box; }
    body { margin:0; font-family:ui-sans-serif,system-ui,-apple-system,sans-serif; background:radial-gradient(circle at top left, #ffe5b2, transparent 30%), var(--bg); color:var(--ink); }
    .wrap { max-width:1380px; margin:0 auto; padding:24px; }
    .shell { display:grid; grid-template-columns:320px 1fr; gap:18px; }
    .card { background:var(--card); border:1px solid var(--line); border-radius:18px; padding:18px; box-shadow:4px 4px 0 var(--line); }
    .hidden { display:none !important; }
    h1,h2,h3 { margin:0 0 12px; }
    h1 { font-size:28px; }
    h2 { font-size:18px; }
    input, textarea, select, button { width:100%; padding:10px 12px; border:1px solid var(--line); border-radius:12px; background:#fff; font:inherit; }
    textarea { min-height:88px; resize:vertical; }
    button { cursor:pointer; background:var(--accent); color:#fff; font-weight:700; }
    button.secondary { background:#fff; color:var(--ink); }
    .grid { display:grid; gap:12px; }
    .grid.two { grid-template-columns:repeat(2,minmax(0,1fr)); }
    .pillrow { display:flex; gap:8px; flex-wrap:wrap; }
    .pill { border:1px solid var(--line); border-radius:999px; padding:6px 12px; background:#fff; cursor:pointer; }
    .pill.active { background:var(--ink); color:#fff3b5; }
    .navbtn { text-align:left; background:#fff; color:var(--ink); }
    .navbtn.active { background:var(--ink); color:#fff3b5; }
    .stats { display:flex; gap:12px; flex-wrap:wrap; margin-bottom:10px; }
    .stat { padding:10px 14px; border:1px solid var(--line); border-radius:14px; background:#fff; min-width:140px; }
    .vlist { display:grid; grid-template-columns:repeat(auto-fit,minmax(330px,1fr)); gap:16px; }
    .vcard { border:1px solid var(--line); border-radius:16px; background:#fff; padding:16px; display:grid; gap:8px; }
    .meta { display:flex; gap:8px; flex-wrap:wrap; align-items:center; }
    .badge { border:1px solid var(--line); border-radius:999px; padding:3px 10px; font-size:12px; background:#fff3b5; }
    .muted { color:#5e5e5e; }
    .small { font-size:12px; }
    .status { white-space:pre-wrap; font-family:ui-monospace,SFMono-Regular,monospace; font-size:12px; background:#fff; border:1px dashed var(--line); border-radius:12px; padding:12px; }
    .label { font-size:12px; font-weight:700; margin-bottom:6px; display:block; }
    .right { display:grid; gap:18px; }
    .github-box { border:1px dashed var(--line); border-radius:12px; padding:10px; background:#fff8e8; }
    @media (max-width: 980px) { .shell, .grid.two { grid-template-columns:1fr; } }
  </style>
</head>
<body>
  <div class="wrap">
    <h1>1DayNews Console</h1>
    <div id="loginCard" class="card">
      <h2>Login</h2>
      <div class="grid">
        <input id="username" placeholder="Username">
        <input id="password" type="password" placeholder="Password">
        <button id="loginBtn">Sign in</button>
        <div id="loginMsg" class="muted small"></div>
      </div>
    </div>

    <div id="appShell" class="shell hidden">
      <div class="card grid">
        <button class="navbtn active" data-view="dataView">Data</button>
        <button class="navbtn" data-view="configView">Config</button>
        <button class="navbtn" data-view="networkView">Network</button>
        <button id="logoutBtn" class="secondary">Logout</button>
        <div id="statusBox" class="status"></div>
      </div>

      <div class="right">
        <section id="dataView" class="card">
          <div class="stats" id="statsBar"></div>
          <div class="grid two">
            <input id="searchInput" placeholder="Search CVE, title, GitHub repo, PoC summary">
            <select id="sourceSelect"><option value="">All sources</option></select>
          </div>
          <div class="pillrow" id="dayPills">
            <button class="pill active" data-days="7">7 days</button>
            <button class="pill" data-days="1">24h</button>
            <button class="pill" data-days="30">30 days</button>
            <button class="pill" data-days="60">60 days</button>
            <button class="pill" data-days="">All</button>
          </div>
          <div style="margin:12px 0;">
            <label><input id="pushedOnly" type="checkbox" checked style="width:auto;"> pushed only</label>
          </div>
          <div id="vulnList" class="vlist"></div>
        </section>

        <section id="configView" class="card hidden">
          <h2>Config</h2>
          <div class="grid two">
            <div><span class="label">Host</span><input id="cfgHost"></div>
            <div><span class="label">Port</span><input id="cfgPort" type="number"></div>
            <div><span class="label">Fetch interval (sec)</span><input id="cfgInterval" type="number"></div>
            <div><span class="label">Data dir</span><input id="cfgDataDir"></div>
            <div><span class="label">HTTPS proxy</span><input id="cfgProxy" placeholder="http://127.0.0.1:7890"></div>
            <div><span class="label">Request timeout</span><input id="cfgTimeout" type="number"></div>
            <div><span class="label">Admin username</span><input id="cfgUser"></div>
            <div><span class="label">Admin password</span><input id="cfgPass" type="password" placeholder="Leave blank to keep current"></div>
            <div><span class="label">Default notify channel</span><select id="cfgDefaultChannel"><option value="wecom">wecom</option><option value="telegram">telegram</option></select></div>
            <div><span class="label">Enabled channels</span><textarea id="cfgEnabledChannels" placeholder="wecom&#10;telegram"></textarea></div>
            <div><span class="label">WeCom webhook</span><input id="cfgWecomWebhook" type="password" placeholder="Leave blank to keep current"></div>
            <div><span class="label">Telegram bot token</span><input id="cfgTelegramToken" type="password" placeholder="Leave blank to keep current"></div>
            <div><span class="label">Telegram enabled</span><select id="cfgTelegramEnabled"><option value="false">false</option><option value="true">true</option></select></div>
            <div><span class="label">Telegram chat IDs</span><textarea id="cfgTelegramChats"></textarea></div>
            <div><span class="label">GitHub tokens</span><textarea id="cfgGithubTokens" placeholder="One token per line. Leave blank to keep current."></textarea></div>
            <div><span class="label">GitHub token summary</span><div id="cfgGithubSummary" class="status"></div></div>
            <div><span class="label">GitHub request interval</span><input id="cfgGhInterval" type="number"></div>
            <div><span class="label">GitHub max repo results</span><input id="cfgGhMax" type="number"></div>
            <div><span class="label">NVD API key</span><input id="cfgNvdKey" type="password" placeholder="Leave blank to keep current"></div>
            <div><span class="label">LLM provider</span><input id="cfgLlmProvider" placeholder="openai / deepseek"></div>
            <div><span class="label">LLM API key</span><input id="cfgLlmKey" type="password" placeholder="Leave blank to keep current"></div>
            <div><span class="label">LLM base URL</span><input id="cfgLlmBase"></div>
            <div><span class="label">LLM model</span><input id="cfgLlmModel"></div>
          </div>
          <div class="grid two" style="margin-top:12px;">
            <button id="saveConfigBtn">Save config</button>
            <button id="testNotifyBtn" class="secondary">Test notification</button>
          </div>
          <div id="configMsg" class="status" style="margin-top:12px;"></div>
        </section>

        <section id="networkView" class="card hidden">
          <h2>Network checks</h2>
          <button id="networkCheckBtn">Run checks</button>
          <div id="networkMsg" class="status" style="margin-top:12px;"></div>
        </section>
      </div>
    </div>
  </div>
  <script>
    let activeDays = '7';
    async function jsonFetch(url, opts) {
      const resp = await fetch(url, Object.assign({headers:{'Content-Type':'application/json'}}, opts||{}));
      if (resp.status === 401) throw new Error('AUTH');
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || JSON.stringify(data));
      return data;
    }
    function setView(id) {
      document.querySelectorAll('[data-view]').forEach(btn => btn.classList.toggle('active', btn.dataset.view === id));
      ['dataView','configView','networkView'].forEach(v => document.getElementById(v).classList.toggle('hidden', v !== id));
    }
    function showLogin(msg='') {
      document.getElementById('loginCard').classList.remove('hidden');
      document.getElementById('appShell').classList.add('hidden');
      document.getElementById('loginMsg').textContent = msg;
    }
    function showApp() {
      document.getElementById('loginCard').classList.add('hidden');
      document.getElementById('appShell').classList.remove('hidden');
    }
    async function bootstrap() {
      const sess = await jsonFetch('/api/auth/session');
      if (!sess.login_required || sess.authenticated) {
        showApp();
        await Promise.all([loadStatus(), loadSources(), loadStats(), loadVulns(), loadConfig()]);
      } else {
        showLogin();
      }
    }
    async function login() {
      try {
        await jsonFetch('/api/auth/login', {method:'POST', body:JSON.stringify({
          username: document.getElementById('username').value.trim(),
          password: document.getElementById('password').value
        })});
        showApp();
        await Promise.all([loadStatus(), loadSources(), loadStats(), loadVulns(), loadConfig()]);
      } catch (e) {
        document.getElementById('loginMsg').textContent = e.message === 'AUTH' ? 'Unauthorized' : e.message;
      }
    }
    async function logout() {
      await jsonFetch('/api/auth/logout', {method:'POST'});
      showLogin('Logged out');
    }
    async function loadStatus() {
      try {
        const data = await jsonFetch('/api/config/status');
        document.getElementById('statusBox').textContent = JSON.stringify(data, null, 2);
      } catch (e) {
        if (e.message === 'AUTH') return showLogin();
      }
    }
    async function loadStats() {
      try {
        const stats = await jsonFetch('/api/stats');
        document.getElementById('statsBar').innerHTML = `
          <div class="stat"><div class="small muted">Total</div><div>${stats.total}</div></div>
          <div class="stat"><div class="small muted">Pushed</div><div>${stats.pushed}</div></div>
          <div class="stat"><div class="small muted">Sources</div><div>${Object.keys(stats.sources).length}</div></div>`;
      } catch (e) { if (e.message === 'AUTH') showLogin(); }
    }
    async function loadSources() {
      try {
        const sources = await jsonFetch('/api/sources');
        const select = document.getElementById('sourceSelect');
        select.innerHTML = '<option value="">All sources</option>' + sources.map(s => `<option value="${s}">${s}</option>`).join('');
      } catch (e) { if (e.message === 'AUTH') showLogin(); }
    }
    async function loadVulns() {
      const params = new URLSearchParams();
      const q = document.getElementById('searchInput').value.trim();
      const source = document.getElementById('sourceSelect').value;
      if (q) params.set('q', q);
      if (source) params.set('source', source);
      if (activeDays) params.set('days', activeDays);
      if (document.getElementById('pushedOnly').checked) params.set('pushed', '1');
      params.set('limit', '100');
      try {
        const vulns = await jsonFetch('/api/vulns?' + params.toString());
        const root = document.getElementById('vulnList');
        if (!vulns.length) {
          root.innerHTML = '<div class="card">No data under current filters.</div>';
          return;
        }
        root.innerHTML = vulns.map(v => {
          const relatedUrls = parseUrlList(v.github_related_poc_urls).slice(0, 2);
          return `
          <div class="vcard">
            <div class="meta">
              <span class="badge">${v.source || '-'}</span>
              <span class="badge">${v.id || 'N/A'}</span>
              <span class="badge">${v.reason || '-'}</span>
              <span class="badge">${v.date || '-'}</span>
            </div>
            <h3>${escapeHtml(v.title || '')}</h3>
            <div class="muted">${escapeHtml((v.summary || '').slice(0, 280))}</div>
            ${v.url ? `<a href="${safeUrl(v.url)}" target="_blank" rel="noreferrer">${escapeHtml(v.url)}</a>` : ''}
            ${(v.github_repo_name || v.github_repo_url || v.github_primary_poc_url || v.github_poc_index_url || v.github_poc_summary) ? `
              <div class="github-box">
                <div><strong>GitHub</strong>: ${escapeHtml(v.github_repo_name || 'N/A')}</div>
                ${v.github_primary_poc_url ? `<div><strong>Primary PoC</strong>: <a href="${safeUrl(v.github_primary_poc_url)}" target="_blank" rel="noreferrer">${escapeHtml(v.github_primary_poc_url)}</a></div>` : ''}
                ${v.github_poc_index_url ? `<div><strong>PoC Index</strong>: <a href="${safeUrl(v.github_poc_index_url)}" target="_blank" rel="noreferrer">${escapeHtml(v.github_poc_index_url)}</a></div>` : ''}
                ${v.github_repo_url && v.github_repo_url !== v.github_primary_poc_url ? `<div><strong>Repo</strong>: <a href="${safeUrl(v.github_repo_url)}" target="_blank" rel="noreferrer">${escapeHtml(v.github_repo_url)}</a></div>` : ''}
                ${relatedUrls.length ? `<div class="small"><strong>Related</strong>: ${relatedUrls.map(url => `<a href="${safeUrl(url)}" target="_blank" rel="noreferrer">${escapeHtml(url)}</a>`).join(' | ')}</div>` : ''}
                <div>PoC found: ${v.github_poc_found ? 'yes' : 'no'} | repos: ${v.github_poc_count || 0} | stars: ${v.github_repo_stars || 0}</div>
                ${v.github_poc_summary ? `<div class="small">${escapeHtml(v.github_poc_summary)}</div>` : ''}
              </div>` : ''}
            ${(v.llm_verdict || v.llm_notes) ? `
              <div class="github-box">
                <div><strong>LLM 研判</strong>: ${escapeHtml(llmVerdictLabel(v.llm_verdict))}</div>
                ${v.llm_notes ? `<div class="small">${escapeHtml(v.llm_notes)}</div>` : ''}
              </div>` : ''}
          </div>`;
        }).join('');
      } catch (e) {
        if (e.message === 'AUTH') return showLogin();
        document.getElementById('vulnList').innerHTML = '<div class="card">Failed to load vulnerabilities.</div>';
      }
    }
    async function loadConfig() {
      try {
        const cfg = await jsonFetch('/api/config');
        document.getElementById('cfgHost').value = cfg.app.host;
        document.getElementById('cfgPort').value = cfg.app.port;
        document.getElementById('cfgInterval').value = cfg.app.fetch_interval;
        document.getElementById('cfgDataDir').value = cfg.app.data_dir;
        document.getElementById('cfgProxy').value = cfg.network.https_proxy;
        document.getElementById('cfgTimeout').value = cfg.network.request_timeout;
        document.getElementById('cfgUser').value = cfg.auth.admin_username;
        document.getElementById('cfgDefaultChannel').value = cfg.notify.default_channel;
        document.getElementById('cfgEnabledChannels').value = (cfg.notify.enabled || []).join('\n');
        document.getElementById('cfgTelegramEnabled').value = String(cfg.notify_telegram.enabled);
        document.getElementById('cfgTelegramChats').value = (cfg.notify_telegram.chat_ids || []).join('\n');
        document.getElementById('cfgGithubSummary').textContent = JSON.stringify({token_count:(cfg.github.tokens || []).length, masked_tokens:cfg.github.tokens}, null, 2);
        document.getElementById('cfgGhInterval').value = cfg.github.request_interval_sec;
        document.getElementById('cfgGhMax').value = cfg.github.max_repo_results;
        document.getElementById('cfgLlmProvider').value = cfg.llm.provider;
        document.getElementById('cfgLlmBase').value = cfg.llm.base_url;
        document.getElementById('cfgLlmModel').value = cfg.llm.model;
      } catch (e) { if (e.message === 'AUTH') showLogin(); }
    }
    async function saveConfig() {
      try {
        const payload = {
          app: {
            host: document.getElementById('cfgHost').value.trim(),
            port: document.getElementById('cfgPort').value,
            fetch_interval: document.getElementById('cfgInterval').value,
            data_dir: document.getElementById('cfgDataDir').value.trim(),
            login_required: true
          },
          network: {
            https_proxy: document.getElementById('cfgProxy').value.trim(),
            request_timeout: document.getElementById('cfgTimeout').value
          },
          auth: {
            admin_username: document.getElementById('cfgUser').value.trim(),
            admin_password: document.getElementById('cfgPass').value
          },
          notify: {
            default_channel: document.getElementById('cfgDefaultChannel').value,
            enabled: document.getElementById('cfgEnabledChannels').value,
            include_github_context: true
          },
          notify_wecom: {
            webhook_url: document.getElementById('cfgWecomWebhook').value
          },
          notify_telegram: {
            enabled: document.getElementById('cfgTelegramEnabled').value === 'true',
            bot_token: document.getElementById('cfgTelegramToken').value,
            chat_ids: document.getElementById('cfgTelegramChats').value
          },
          github: {
            tokens: document.getElementById('cfgGithubTokens').value,
            request_interval_sec: document.getElementById('cfgGhInterval').value,
            max_repo_results: document.getElementById('cfgGhMax').value,
            fetch_readme_excerpt: true,
            fetch_poc_metadata: true
          },
          nvd: {
            api_key: document.getElementById('cfgNvdKey').value
          },
          llm: {
            provider: document.getElementById('cfgLlmProvider').value.trim(),
            api_key: document.getElementById('cfgLlmKey').value,
            base_url: document.getElementById('cfgLlmBase').value.trim(),
            model: document.getElementById('cfgLlmModel').value.trim()
          }
        };
        const data = await jsonFetch('/api/config', {method:'POST', body:JSON.stringify(payload)});
        document.getElementById('configMsg').textContent = JSON.stringify(data, null, 2);
        document.getElementById('cfgPass').value = '';
        document.getElementById('cfgWecomWebhook').value = '';
        document.getElementById('cfgTelegramToken').value = '';
        document.getElementById('cfgGithubTokens').value = '';
        document.getElementById('cfgNvdKey').value = '';
        document.getElementById('cfgLlmKey').value = '';
        await Promise.all([loadConfig(), loadStatus()]);
      } catch (e) {
        if (e.message === 'AUTH') return showLogin();
        document.getElementById('configMsg').textContent = e.message;
      }
    }
    async function testNotify() {
      try {
        const data = await jsonFetch('/api/test-notify', {method:'POST', body:'{}'});
        document.getElementById('configMsg').textContent = JSON.stringify(data, null, 2);
      } catch (e) {
        if (e.message === 'AUTH') return showLogin();
        document.getElementById('configMsg').textContent = e.message;
      }
    }
    async function runNetworkCheck() {
      try {
        const data = await jsonFetch('/api/network/check');
        document.getElementById('networkMsg').textContent = JSON.stringify(data, null, 2);
      } catch (e) {
        if (e.message === 'AUTH') return showLogin();
        document.getElementById('networkMsg').textContent = e.message;
      }
    }
    function escapeHtml(s) {
      return (s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
    }
    function parseUrlList(value) {
      if (!value) return [];
      if (Array.isArray(value)) return value.filter(Boolean);
      try {
        const parsed = JSON.parse(value);
        return Array.isArray(parsed) ? parsed.filter(Boolean) : [];
      } catch {
        return [];
      }
    }
    function llmVerdictLabel(value) {
      const mapping = {
        confirmed: '确认值得关注',
        not_relevant: '相关性较低',
        noise: '噪声/不建议关注'
      };
      return mapping[value] || (value || 'N/A');
    }
    function safeUrl(u) {
      try {
        const url = new URL(u);
        return ['http:','https:'].includes(url.protocol) ? u : '#';
      } catch {
        return '#';
      }
    }
    document.getElementById('loginBtn').addEventListener('click', login);
    document.getElementById('logoutBtn').addEventListener('click', logout);
    document.getElementById('saveConfigBtn').addEventListener('click', saveConfig);
    document.getElementById('testNotifyBtn').addEventListener('click', testNotify);
    document.getElementById('networkCheckBtn').addEventListener('click', runNetworkCheck);
    document.getElementById('searchInput').addEventListener('input', () => setTimeout(loadVulns, 100));
    document.getElementById('sourceSelect').addEventListener('change', loadVulns);
    document.getElementById('pushedOnly').addEventListener('change', loadVulns);
    document.querySelectorAll('#dayPills .pill').forEach(btn => btn.addEventListener('click', () => {
      document.querySelectorAll('#dayPills .pill').forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      activeDays = btn.dataset.days;
      loadVulns();
    }));
    document.querySelectorAll('[data-view]').forEach(btn => btn.addEventListener('click', () => setView(btn.dataset.view)));
    bootstrap();
  </script>
</body>
</html>"""


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="vuln-monitor shared dashboard")
    parser.add_argument("--host", default=None, help="Override bind host")
    parser.add_argument("--port", type=int, default=None, help="Override bind port")
    args = parser.parse_args()

    if not config_exists():
        ensure_config_file()
        print(f"NOTICE: created default config at {CONFIG_FILE}")

    cfg = current_config()
    host = args.host or cfg["app"]["host"]
    port = args.port or int(cfg["app"]["port"])
    print(f"vuln-monitor dashboard: http://{host}:{port}")
    print(f"config: {CONFIG_FILE}")
    print(f"database: {db_file()}")
    serve(app, host=host, port=port)
