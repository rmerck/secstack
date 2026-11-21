"""Start hexstrike_server's Flask app behind two checks that run before any route:

  1. Host header allowlist on every request (blocks DNS rebinding from a browser on the Mac).
  2. The API token on every request except GET/HEAD /health: header X-Secstack-Token, compared in
     constant time. The Host header alone proves nothing: anything that reaches port 8888 (a container
     on HexStrike's network, or one that reaches the Mac's 127.0.0.1:8888 through host.docker.internal)
     can send "Host: 127.0.0.1:8888".

The token arrives in HEXSTRIKE_TOKEN: secstack writes a new one to $SECOPS/env/hexstrike-token for every
new container and passes it with docker run --env-file. Without a valid one (64 lowercase hex) the server
refuses to start. os.environ.pop keeps it from the commands HexStrike runs, but the kernel keeps the
environment a process started with in /proc/<pid>/environ for the life of the process, and every command
HexStrike runs (root, same PID namespace) could read /proc/1/environ. So the first run hands the token on a
pipe to a fresh image of this script, exec'd with the same PID and an environment that never held it:
neither the server's /proc environ nor its command line holds the token, and the pipe is closed once read.
This only raises the bar: root in the container can still read the token from the server's memory
(/proc/1/mem, or gdb, which the image has). A captured token dies with the container: the next start
makes a new one.
The container listens on 0.0.0.0:8888 internally; the host publishes it on 127.0.0.1 only."""
import hmac
import os
import re
import sys

TOKEN_HEADER = "X-Secstack-Token"
TOKEN_FD_FLAG = "--secstack-token-fd"   # the second run reads the token from this inherited pipe
VALID = re.compile(r"[0-9a-f]{64}")


def _refuse():
    sys.exit("hexstrike_entry: no valid API token (HEXSTRIKE_TOKEN, 64 lowercase hex); refusing to start. "
             "Start HexStrike with `secstack mcp on`, which passes a new token in an --env-file.")


def _hand_off(token):
    """Exec this script again (same PID) with the token on a pipe and an environment without it."""
    env = {k: v for k, v in os.environ.items() if k != "HEXSTRIKE_TOKEN"}
    r, w = os.pipe()
    try:
        os.write(w, token.encode("ascii"))   # 64 bytes: far below a pipe's capacity, so this never blocks
    finally:
        os.close(w)
    os.set_inheritable(r, True)
    try:
        os.execve(sys.executable, [sys.executable, os.path.abspath(__file__), TOKEN_FD_FLAG, str(r)], env)
    except OSError as e:
        sys.exit("hexstrike_entry: couldn't restart without the token in its environment (%s); "
                 "refusing to start" % e.strerror)


def _token_from_fd(arg):
    try:
        with os.fdopen(int(arg), "rb") as f:   # closed here, so no command HexStrike runs inherits it
            return f.read(65).decode("ascii", "replace").strip()
    except (ValueError, OSError):
        return ""


if "HEXSTRIKE_TOKEN" in os.environ:            # first run, as docker started it (PID 1)
    _token = os.environ.pop("HEXSTRIKE_TOKEN").strip()
    if not VALID.fullmatch(_token):
        _refuse()
    _hand_off(_token)                           # does not return
    _refuse()                                   # (not reached: execve replaces this process or fails)
elif len(sys.argv) == 3 and sys.argv[1] == TOKEN_FD_FLAG:
    _token = _token_from_fd(sys.argv[2])
else:
    _token = ""
if not VALID.fullmatch(_token):
    _refuse()
_TOKEN = _token.encode("ascii")
del _token

sys.argv = [sys.argv[0]]
sys.path.insert(0, "/opt/hexstrike")
import hexstrike_server as hs  # noqa: E402
from flask import abort, request  # noqa: E402

ALLOWED = {h.strip() for h in os.environ.get(
    "HEXSTRIKE_ALLOWED_HOSTS", "127.0.0.1:8888,localhost:8888").split(",") if h.strip()}
OPEN = {("GET", "/health"), ("HEAD", "/health")}   # health answers without the token (liveness only)


def _guard():
    if request.host not in ALLOWED:
        abort(403)
    if (request.method, request.path) in OPEN:
        return None
    given = request.headers.get(TOKEN_HEADER, "")
    if not hmac.compare_digest(given.encode("utf-8", "replace"), _TOKEN):
        abort(401)
    return None


# First in line, so no hook upstream registers can answer a request before these checks run.
hs.app.before_request_funcs.setdefault(None, []).insert(0, _guard)

if __name__ == "__main__":
    hs.app.run(host="0.0.0.0", port=8888, debug=False, threaded=True)
