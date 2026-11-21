#!/usr/bin/env python3
"""hexstrike-client: run the upstream HexStrike MCP client (hexstrike_mcp.py, unchanged) with the
secstack API token on its requests to the HexStrike server.

  hexstrike_client.py /path/to/hexstrike-ai/hexstrike_mcp.py [--server URL] [other hexstrike_mcp.py options]

The HexStrike API (hexstrike_entry.py in the Kali container) refuses every request except
GET /health that lacks the header X-Secstack-Token. The token is in $HEXSTRIKE_TOKEN_FILE, else
$SECOPS/env/hexstrike-token (SECOPS defaults to ~/GitHub/.sec-ops), and `secstack mcp on` (or
`secstack prep`) writes a new one for every new HexStrike container. So the file is checked on every
request and read again whenever it changed. While it is missing or malformed, requests go without the
header and HexStrike answers 401; this server keeps running and picks the token up once it is there
(5ire and Claude Desktop give up on an MCP server that exits at start). The token is added only to requests
for the --server origin (scheme, host and port; the host must be 127.0.0.1), those requests never go through an
HTTP proxy, and the token is never printed or put on a command line. Messages go to stderr: stdout is
the MCP channel.
"""
import os
import pathlib
import re
import runpy
import sys
import threading
from urllib.parse import urlsplit

HEADER = "X-Secstack-Token"
DEFAULT_SERVER = "http://127.0.0.1:8888"   # hexstrike_mcp.py's own default for --server
# Only where secstack publishes HexStrike (127.0.0.1:8888): on macOS localhost resolves to ::1 first, and
# Docker publishes nothing there, so any local process listening on [::1] would get the token.
LOOPBACK = ("127.0.0.1",)
VALID = re.compile(r"[0-9a-f]{64}")


def say(msg):
    print(f"hexstrike-client: {msg}", file=sys.stderr, flush=True)


def fail(msg):
    say(msg)
    sys.exit(2)


def token_file():
    override = os.environ.get("HEXSTRIKE_TOKEN_FILE")
    if override:
        return pathlib.Path(override)
    secops = os.environ.get("SECOPS") or str(pathlib.Path.home() / "GitHub" / ".sec-ops")
    return pathlib.Path(secops) / "env" / "hexstrike-token"


class TokenFile:
    """The token in PATH, or None while the file is missing or doesn't hold one. The file is read again
    only when it changed (device, inode, size or modification time): secstack replaces it with a new
    file for every new HexStrike container. Each problem is reported on stderr once, never with the
    file's content."""

    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()   # hexstrike_mcp.py may send requests from several threads
        self._stamp = None
        self._token = None
        self._reported = None

    def _report(self, problem, msg=""):
        if problem != self._reported:
            self._reported = problem
            if msg:
                say(msg)

    def _read(self):
        try:
            with open(self.path, "rb") as f:
                first = f.readline(256).strip().decode("ascii", "replace")
        except OSError:
            return None
        return first if VALID.fullmatch(first) else None

    def get(self):
        with self._lock:
            try:
                st = os.stat(self.path)
            except OSError:
                self._stamp = self._token = None
                self._report("missing", f"no HexStrike API token at {self.path} yet: requests go without it "
                                        "(HTTP 401) until `secstack mcp on` (or `secstack prep`) writes one")
                return None
            stamp = (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)
            if stamp != self._stamp:
                self._stamp, self._token = stamp, self._read()
                if self._token is None:
                    self._report("malformed", f"{self.path} doesn't hold a readable 64-hex HexStrike API token: "
                                              "requests go without it (HTTP 401) until `secstack mcp on` writes a new one")
                else:
                    self._report("ok")
            return self._token


def origin(url):
    """(scheme, host, port) of a URL, or None if it can't be read."""
    try:
        p = urlsplit(url)
        port = p.port
    except ValueError:
        return None
    scheme = p.scheme.lower()
    return scheme, (p.hostname or "").lower(), port or {"http": 80, "https": 443}.get(scheme)


def server_url(args):
    """The --server value hexstrike_mcp.py will use (argparse: the last one wins)."""
    url = DEFAULT_SERVER
    for i, a in enumerate(args):
        if a == "--server" and i + 1 < len(args):
            url = args[i + 1]
        elif a.startswith("--server="):
            url = a.split("=", 1)[1]
    return url


def install(tokens, allowed):
    """Add the token header to requests for the allowed origin; strip it from any other (a redirect)."""
    import requests

    original_send = requests.Session.send

    def send(self, request, **kwargs):
        request.headers.pop(HEADER, None)
        if origin(request.url) == allowed:
            token = tokens.get()
            if token:
                request.headers[HEADER] = token
            kwargs["proxies"] = {}    # loopback API: a proxy would see the token
        return original_send(self, request, **kwargs)

    requests.Session.send = send


def main():
    if len(sys.argv) < 2 or sys.argv[1].startswith("-"):
        fail("usage: hexstrike_client.py /path/to/hexstrike_mcp.py [hexstrike_mcp.py options]")
    script = os.path.abspath(sys.argv[1])
    if not os.path.isfile(script):
        fail(f"{script} not found (the hexstrike-ai clone: ./setup.sh --only upstream)")
    args = sys.argv[2:]
    allowed = origin(server_url(args))
    if allowed is None or allowed[0] not in ("http", "https") or allowed[1] not in LOOPBACK:
        fail("--server must be an http(s) URL on 127.0.0.1, where secstack publishes HexStrike (not localhost or [::1])")
    tokens = TokenFile(token_file())
    tokens.get()                              # reports a missing or malformed token now, without stopping
    install(tokens, allowed)
    sys.argv = [script] + args
    sys.path[0] = os.path.dirname(script)    # as if hexstrike_mcp.py had been run directly
    runpy.run_path(script, run_name="__main__")


if __name__ == "__main__":
    main()
