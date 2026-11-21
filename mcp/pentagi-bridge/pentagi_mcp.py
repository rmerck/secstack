#!/usr/bin/env python3
"""
pentagi-bridge: a local stdio MCP server that lets 5ire (or any MCP client)
drive PentAGI autonomous pentest flows over PentAGI's REST API.

Security posture (matches the rest of the sec-ops stack):
  - Talks only to a loopback PentAGI (self-signed TLS on 127.0.0.1:8443); any other
    PENTAGI_URL is refused, and no HTTP proxy is ever used for it.
  - Bearer token read from a 0600 file, never passed on argv or printed.
  - Read-mostly: the only state-changing tools are create_flow, send_input,
    stop_flow and generate_report. No host shell, no file access.

The default provider for new flows is read at call time: PENTAGI_PROVIDER if set, otherwise
PENTAGI_DEFAULT_PROVIDER from $SECOPS/configs/stack.conf (written by scripts/plan.py), so a
re-plan takes effect without touching the MCP client's config.
"""
import json
import os
import pathlib
import re
from urllib.parse import urlsplit

import requests
import urllib3
from mcp.server.fastmcp import FastMCP

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SECOPS = pathlib.Path(os.environ.get("SECOPS") or (pathlib.Path.home() / "GitHub/.sec-ops"))
STACK_CONF = SECOPS / "configs" / "stack.conf"
BASE = os.environ.get("PENTAGI_URL", "https://127.0.0.1:8443/api/v1").rstrip("/")
TOKEN_FILE = os.environ.get("PENTAGI_TOKEN_FILE", str(SECOPS / "env/pentagi-api-token"))
TIMEOUT = float(os.environ.get("PENTAGI_HTTP_TIMEOUT", "30"))
PROVIDER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")

LOOPBACK = ("localhost", "127.0.0.1", "::1")


def _loopback_url(url: str) -> bool:
    """True for a plain http(s) URL to loopback that every URL parser reads the same way (no userinfo,
    backslashes, whitespace or non-ASCII, which parsers disagree on)."""
    if not url.isascii() or any(c in url for c in "\\@ \t\r\n"):
        return False
    try:
        parts = urlsplit(url)
        host = parts.hostname
    except ValueError:              # e.g. "[127.0.0.1]": refused with the clear message, not a traceback
        return False
    if parts.scheme not in ("http", "https") or host not in LOOPBACK:
        return False
    try:
        return urllib3.util.parse_url(url).host.strip("[]").lower() in LOOPBACK
    except Exception:
        return False


if not _loopback_url(BASE):
    raise SystemExit(f"pentagi-bridge: PENTAGI_URL must be a plain loopback URL, not {BASE!r}")

# Loopback only: self-signed certificate (no CA to check against) and never an HTTP proxy.
_HTTP = requests.Session()
_HTTP.trust_env = False
_HTTP.verify = False

mcp = FastMCP("pentagi-bridge")


def _token() -> str:
    try:
        t = pathlib.Path(TOKEN_FILE).read_text().strip()
    except FileNotFoundError:
        raise RuntimeError(
            f"PentAGI API token not found at {TOKEN_FILE}. Create one in the "
            f"PentAGI UI (Settings -> API Tokens) and save it to that file (chmod 600)."
        )
    if not t:
        raise RuntimeError(f"PentAGI API token file {TOKEN_FILE} is empty.")
    if not re.fullmatch(r"[\x21-\x7e]{8,4096}", t):
        # Never echo it: a token with spaces or line breaks would end up in error messages.
        raise RuntimeError(f"{TOKEN_FILE} doesn't hold a single-line API token; save the token again.")
    return t


def _conf_value(key: str) -> str:
    """Same rules as scripts/plan.py read_conf(): last line wins, CR stripped, unsafe = absent."""
    try:
        lines = STACK_CONF.read_text(encoding="utf-8", errors="replace").split("\n")
    except OSError:
        return ""
    val = ""
    for line in lines:
        if line.endswith("\r"):
            line = line[:-1]
        if line.startswith(key + "="):
            val = line[len(key) + 1:]
    return val if PROVIDER_RE.fullmatch(val) else ""


def _default_provider_or_none():
    env = os.environ.get("PENTAGI_PROVIDER", "")
    if env:
        return env if PROVIDER_RE.fullmatch(env) else None
    return _conf_value("PENTAGI_DEFAULT_PROVIDER") or None


def _default_provider() -> str:
    env = os.environ.get("PENTAGI_PROVIDER", "")
    if env:
        if not PROVIDER_RE.fullmatch(env):
            raise RuntimeError("PENTAGI_PROVIDER is not a valid provider name.")
        return env
    p = _conf_value("PENTAGI_DEFAULT_PROVIDER")
    if not p:
        raise RuntimeError(f"No default provider: pass `provider` (see pentagi_list_providers), "
                           f"or re-run the secstack plan so {STACK_CONF} has PENTAGI_DEFAULT_PROVIDER.")
    return p


def _req(method: str, path: str, **kw):
    url = f"{BASE}{path}"
    headers = kw.pop("headers", {})
    headers["Authorization"] = f"Bearer {_token()}"
    headers.setdefault("Content-Type", "application/json")
    r = _HTTP.request(method, url, headers=headers, timeout=TIMEOUT, **kw)
    body = None
    try:
        body = r.json()
    except Exception:
        body = {"raw": r.text[:2000]}
    if r.status_code >= 400:
        raise RuntimeError(f"PentAGI {method} {path} -> HTTP {r.status_code}: "
                           f"{json.dumps(body)[:500]}")
    # unwrap {status:success, data:...}
    if isinstance(body, dict) and "data" in body:
        return body["data"]
    return body


def _flow_brief(f: dict) -> dict:
    return {k: f.get(k) for k in
            ("id", "status", "title", "model", "model_provider_name",
             "created_at", "updated_at")}


def _limit(n) -> int:
    try:
        return max(1, min(int(n), 200))
    except (TypeError, ValueError):
        return 20


@mcp.tool()
def pentagi_list_providers() -> str:
    """List the model providers configured in PentAGI (use one as `provider`)."""
    data = _req("GET", "/providers/")
    names = []
    items = data.get("providers", data) if isinstance(data, dict) else data
    for p in (items or []):
        if isinstance(p, dict):
            names.append({"name": p.get("name"), "type": p.get("type")})
    return json.dumps({"default": _default_provider_or_none(), "providers": names or data},
                      indent=2)


@mcp.tool()
def pentagi_create_flow(objective: str, provider: str = "") -> str:
    """Start a new autonomous pentest flow.

    objective: the full scoped task for the agent (target, scope, goals,
      constraints, and desired output). Be specific; PentAGI plans from this.
    provider: PentAGI provider name. Leave empty for this machine's default
      (the planned primary model's provider).
    Returns the new flow id and status. Poll with pentagi_flow_status.
    """
    provider = (provider or "").strip() or _default_provider()
    if not PROVIDER_RE.fullmatch(provider):
        raise RuntimeError("provider must be a PentAGI provider name (see pentagi_list_providers).")
    data = _req("POST", "/flows/", json={"input": objective, "provider": provider})
    return json.dumps(_flow_brief(data), indent=2)


@mcp.tool()
def pentagi_list_flows() -> str:
    """List all flows (id, status, title, model)."""
    data = _req("GET", "/flows/", params={"type": "init", "page": 1, "pageSize": 100})
    items = data.get("flows", data) if isinstance(data, dict) else data
    return json.dumps([_flow_brief(f) for f in (items or [])], indent=2)


@mcp.tool()
def pentagi_flow_status(flow_id: int) -> str:
    """Get a flow's status plus a summary of its tasks (status per task)."""
    flow = _req("GET", f"/flows/{int(flow_id)}")
    out = _flow_brief(flow)
    try:
        td = _req("GET", f"/flows/{int(flow_id)}/tasks/", params={"type": "init", "page": 1, "pageSize": 100})
        tasks = td.get("tasks", td) if isinstance(td, dict) else td
        out["tasks"] = [{"id": t.get("id"), "status": t.get("status"),
                         "title": (t.get("title") or "")[:80]} for t in (tasks or [])]
    except Exception as e:
        out["tasks_error"] = str(e)
    return json.dumps(out, indent=2)


def _logs(flow_id: int, kind: str, limit: int):
    """The latest `limit` rows of a flow log, oldest of them first. pentagi lists the newest first (ORDER BY
    id DESC), so page 1 of size `limit` is exactly those rows; rows can be large (whole command outputs)."""
    n = _limit(limit)
    d = _req("GET", f"/flows/{int(flow_id)}/{kind}/",
             params={"type": "init", "page": 1, "pageSize": n})
    rows = d.get(kind, d) if isinstance(d, dict) else d
    rows = rows if isinstance(rows, list) else []
    return rows[:n][::-1]


@mcp.tool()
def pentagi_flow_messages(flow_id: int, limit: int = 20) -> str:
    """Latest agent messages for a flow (reasoning, findings, report text). limit: 1-200."""
    rows = _logs(flow_id, "msglogs", limit)
    out = [{"type": m.get("type"), "task_id": m.get("task_id"),
            "message": (m.get("message") or "")[:4000],
            "result": (m.get("result") or "")[:2000],
            "created_at": m.get("created_at")} for m in rows]
    return json.dumps(out, indent=2)


@mcp.tool()
def pentagi_flow_terminal(flow_id: int, limit: int = 20) -> str:
    """Latest terminal (shell) output lines from the flow's Kali container. limit: 1-200."""
    rows = _logs(flow_id, "termlogs", limit)
    out = [{"type": t.get("type"), "text": (t.get("text") or t.get("message") or "")[:3000],
            "created_at": t.get("created_at")} for t in rows]
    return json.dumps(out, indent=2)


@mcp.tool()
def pentagi_send_input(flow_id: int, text: str) -> str:
    """Send a steering message / answer to a running or waiting flow."""
    data = _req("PUT", f"/flows/{int(flow_id)}", json={"action": "input", "input": text})
    return json.dumps(data if isinstance(data, dict) else {"result": data}, indent=2)


@mcp.tool()
def pentagi_generate_report(flow_id: int) -> str:
    """Ask PentAGI to generate the final report for a flow."""
    data = _req("PUT", f"/flows/{int(flow_id)}", json={"action": "report"})
    return json.dumps(data if isinstance(data, dict) else {"result": data}, indent=2)


@mcp.tool()
def pentagi_stop_flow(flow_id: int) -> str:
    """Stop a running flow."""
    data = _req("PUT", f"/flows/{int(flow_id)}", json={"action": "stop"})
    return json.dumps(data if isinstance(data, dict) else {"result": data}, indent=2)


if __name__ == "__main__":
    mcp.run()
