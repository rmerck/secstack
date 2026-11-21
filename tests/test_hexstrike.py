"""Tests for HexStrike's API token: the entry guard in the Kali image
(configs/hexstrike-kali/hexstrike_entry.py), the MCP client wrapper (mcp/hexstrike-client/), secstack's
token helpers and hexstrike_start/hexstrike_stop, bin/hexstrike-ctl, setup.sh's 5ire check and the
MCP config templates.

Run from the repo root:  python3 -m unittest discover -s tests -v
The entry runs against stub flask/hexstrike_server modules (and a real Flask app when flask is
installed); the wrapper tests need `requests` (the host venv has it). docker and curl are stubs.
No network, no Docker.
"""
import errno
import hashlib
import hmac
import importlib.util
import io
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parent.parent
sys.dont_write_bytecode = True   # don't leave __pycache__ in configs/, mcp/, scripts/
ENTRY = REPO / "configs" / "hexstrike-kali" / "hexstrike_entry.py"
CLIENT = REPO / "mcp" / "hexstrike-client" / "hexstrike_client.py"
SECSTACK = REPO / "bin" / "secstack"
CTL = REPO / "bin" / "hexstrike-ctl"
LAUNCHER = REPO / "bin" / "secstack-mcp"
TOKEN = "0123456789abcdef" * 4          # a well-formed token (64 hex)
OTHER = "f" * 64                         # well-formed, but not this install's token
HEADER = "X-Secstack-Token"
FD_FLAG = "--secstack-token-fd"
HAVE_BASH = bool(shutil.which("bash"))
HAVE_PROC = sys.platform.startswith("linux") and os.path.exists("/proc/self/environ")
try:
    import requests  # noqa: F401
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False
try:
    import flask  # noqa: F401
    HAVE_FLASK = True
except ImportError:
    HAVE_FLASK = False


def fingerprint(token):
    return hashlib.sha256(token.encode()).hexdigest()[:16]


# --------------------------------------------------------------------------- entry guard
class Abort(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class Exec(BaseException):
    """Raised by the os.execve stand-in: like a real exec, the run that calls it goes no further."""


class StubApp:
    """Just what hexstrike_entry.py touches on hexstrike_server.app."""
    def __init__(self, upstream_hook=None):
        self.before_request_funcs = {None: [upstream_hook]} if upstream_hook else {}
        self.run_kwargs = None

    def run(self, **kw):
        self.run_kwargs = kw


def stub_flask():
    fl = types.ModuleType("flask")
    fl.request = types.SimpleNamespace(host="127.0.0.1:8888", method="GET", path="/health", headers={})

    def abort(code):
        raise Abort(code)
    fl.abort = abort
    return fl


def entry_env(token):
    env = {k: v for k, v in os.environ.items() if k not in ("HEXSTRIKE_TOKEN", "HEXSTRIKE_ALLOWED_HOSTS")}
    if token is not None:
        env["HEXSTRIKE_TOKEN"] = token
    return env


def run_entry(argv, env, app=None, flask_module=None, name="hexstrike_entry_under_test", execve=Exec):
    """Execute the real hexstrike_entry.py once, in-process, with this argv and environment, a stub
    hexstrike_server (and a stub flask unless one is given), and os.execve replaced by a mock whose side
    effect is `execve` (by default Exec: the run stops there). SystemExit propagates.
    Returns (outcome "exec" or "ran", app, flask module, os.environ as the run left it, the execve mock)."""
    app = app if app is not None else StubApp()
    fl = flask_module or stub_flask()
    hs = types.ModuleType("hexstrike_server")
    hs.app = app
    ex = mock.Mock(side_effect=execve)
    with mock.patch.dict(sys.modules, {"flask": fl, "hexstrike_server": hs}), \
            mock.patch.dict(os.environ, env, clear=True), \
            mock.patch.object(sys, "argv", list(argv)), \
            mock.patch.object(sys, "path", list(sys.path)), \
            mock.patch.object(os, "execve", ex):
        spec = importlib.util.spec_from_file_location(name, ENTRY)
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)
            outcome = "ran"
        except Exec:
            outcome = "exec"
        left = dict(os.environ)
    return outcome, app, fl, left, ex


def load_entry(token, app=None, flask_module=None, name="hexstrike_entry_under_test"):
    """Start the entry the way the container does: the first run, with HEXSTRIKE_TOKEN in its
    environment, must exec a fresh image of itself (recorded, not done) that gets the token on a pipe;
    the second run is that image. Returns (app, flask module, os.environ as the second run left it)."""
    app = app if app is not None else StubApp()
    hooks = dict(app.before_request_funcs)
    outcome, _, _, _, ex = run_entry(["hexstrike_entry.py", "--port", "1"], entry_env(token), app=app, name=name)
    assert outcome == "exec", "the first run must hand the token to a fresh image of itself"
    assert app.before_request_funcs == hooks and getattr(app, "run_kwargs", None) is None, "the first run served"
    path, argv, env = ex.call_args[0]
    outcome, app, fl, left, _ = run_entry(argv[1:], env, app=app, flask_module=flask_module, name=name)
    assert outcome == "ran"
    return app, fl, left


class TestEntryGuard(unittest.TestCase):
    def setUp(self):
        self.app, self.flask, self.env_after = load_entry(TOKEN)
        self.guard = self.app.before_request_funcs[None][0]

    def call(self, method, path, token=None, host="127.0.0.1:8888"):
        req = self.flask.request
        req.method, req.path, req.host = method, path, host
        req.headers = {} if token is None else {HEADER: token}
        try:
            return self.guard() or 200
        except Abort as e:
            return e.code

    def test_refuses_to_start_without_a_valid_token(self):
        for bad in (None, "", "   ", "abc", TOKEN[:-1], TOKEN + "0", TOKEN.upper(), TOKEN[:-1] + "g"):
            app = StubApp()
            with self.subTest(token=bad), self.assertRaises(SystemExit) as cm:
                run_entry(["hexstrike_entry.py"], entry_env(bad), app=app)
            self.assertEqual(app.before_request_funcs, {})          # stopped before touching the app
            self.assertIsNone(app.run_kwargs)
            if bad and bad.strip():
                self.assertNotIn(bad.strip(), str(cm.exception.code))  # never echoed

    def test_token_required_on_every_endpoint_but_health(self):
        for method, path in (("POST", "/api/command"), ("GET", "/api/command"), ("POST", "/api/files/create"),
                             ("GET", "/"), ("POST", "/health"), ("GET", "/health/"), ("GET", "//health"),
                             ("OPTIONS", "/health"), ("GET", "/api/secstack-auth-check")):
            with self.subTest(method=method, path=path):
                self.assertEqual(self.call(method, path), 401)
                self.assertEqual(self.call(method, path, OTHER), 401)
                self.assertEqual(self.call(method, path, TOKEN[:-1]), 401)
                self.assertEqual(self.call(method, path, TOKEN + "0"), 401)
                self.assertEqual(self.call(method, path, "caf" + chr(0xE9)), 401)
                self.assertEqual(self.call(method, path, TOKEN), 200)

    def test_health_is_open(self):
        self.assertEqual(self.call("GET", "/health"), 200)
        self.assertEqual(self.call("HEAD", "/health"), 200)

    def test_host_allowlist_is_kept(self):
        for host in ("172.30.1.5:8888", "172.30.0.5:8888", "evil.example", "127.0.0.1", "127.0.0.1:8889", ""):
            with self.subTest(host=host):
                self.assertEqual(self.call("POST", "/api/command", TOKEN, host=host), 403)
                self.assertEqual(self.call("GET", "/health", host=host), 403)
        self.assertEqual(self.call("POST", "/api/command", TOKEN, host="localhost:8888"), 200)

    def test_compares_in_constant_time(self):
        with mock.patch("hmac.compare_digest", wraps=hmac.compare_digest) as spy:
            self.assertEqual(self.call("POST", "/api/command", OTHER), 401)
            self.assertEqual(self.call("POST", "/api/command", TOKEN), 200)
        self.assertEqual(spy.call_count, 2)

    def test_guard_runs_before_upstream_hooks(self):
        def upstream_hook():
            return "answered without auth"
        app, _, _ = load_entry(TOKEN, app=StubApp(upstream_hook))
        self.assertEqual(app.before_request_funcs[None][1], upstream_hook)
        self.assertIn("_guard", app.before_request_funcs[None][0].__name__)

    def test_token_leaves_the_environment(self):
        self.assertNotIn("HEXSTRIKE_TOKEN", self.env_after)       # commands HexStrike runs don't inherit it

    def test_main_serves_on_8888(self):
        app, _, _ = load_entry(TOKEN, name="__main__")
        self.assertEqual(app.run_kwargs, {"host": "0.0.0.0", "port": 8888, "debug": False, "threaded": True})


class TestEntryHandOff(unittest.TestCase):
    """/proc/1/environ keeps the environment PID 1 started with, so the entry must not serve from the
    process that got HEXSTRIKE_TOKEN in its environment: it execs a fresh image with the token on a pipe."""

    def test_first_run_execs_a_fresh_image_with_the_token_on_a_pipe(self):
        app = StubApp()
        outcome, _, _, left, ex = run_entry(["hexstrike_entry.py"], entry_env(TOKEN), app=app)
        self.assertEqual(outcome, "exec")
        ex.assert_called_once()
        path, argv, env = ex.call_args[0]
        self.assertEqual(path, sys.executable)
        self.assertEqual(argv[:3], [sys.executable, str(ENTRY), FD_FLAG])
        self.assertEqual(len(argv), 4)
        self.assertEqual(env, entry_env(None))                    # everything but the token, which it never holds
        self.assertNotIn(TOKEN, json.dumps([argv, env]))          # nor its command line
        self.assertNotIn("HEXSTRIKE_TOKEN", left)
        fd = int(argv[3])
        self.assertTrue(os.get_inheritable(fd))                   # survives the exec
        with os.fdopen(fd, "rb") as f:
            self.assertEqual(f.read(), TOKEN.encode())            # write end closed: the reader gets EOF
        self.assertEqual(app.before_request_funcs, {})            # the first run serves nothing
        self.assertIsNone(app.run_kwargs)

    def test_refuses_to_serve_if_the_exec_fails(self):
        app = StubApp()
        with self.assertRaises(SystemExit) as cm:
            run_entry(["hexstrike_entry.py"], entry_env(TOKEN), app=app,
                      execve=OSError(errno.ENOEXEC, "Exec format error"))
        self.assertIn("refusing to start", str(cm.exception.code))
        self.assertNotIn(TOKEN, str(cm.exception.code))
        self.assertEqual(app.before_request_funcs, {})
        self.assertIsNone(app.run_kwargs)

    def test_second_run_refuses_a_bad_token_on_its_pipe(self):
        for data in (b"", TOKEN[:-1].encode(), (TOKEN + "0").encode(), TOKEN.upper().encode(), b"x" * 5000):
            r, w = os.pipe()
            os.write(w, data)
            os.close(w)
            app = StubApp()
            with self.subTest(n=len(data)), self.assertRaises(SystemExit):
                run_entry([str(ENTRY), FD_FLAG, str(r)], entry_env(None), app=app)
            self.assertEqual(app.before_request_funcs, {})
        app = StubApp()
        with self.assertRaises(SystemExit):
            run_entry([str(ENTRY), FD_FLAG, "not-a-number"], entry_env(None), app=app)
        self.assertEqual(app.before_request_funcs, {})

    def test_second_run_reads_and_closes_the_pipe(self):
        r, w = os.pipe()
        os.write(w, TOKEN.encode())
        os.close(w)
        outcome, app, _, left, ex = run_entry([str(ENTRY), FD_FLAG, str(r)], entry_env(None))
        self.assertEqual(outcome, "ran")
        ex.assert_not_called()
        self.assertEqual(len(app.before_request_funcs[None]), 1)
        self.assertNotIn("HEXSTRIKE_TOKEN", left)
        with self.assertRaises(OSError):
            os.fstat(r)                                           # closed: no command HexStrike runs inherits it


STUB_FLASK_MODULE = r'''
import types
class Abort(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code
def abort(code):
    raise Abort(code)
request = types.SimpleNamespace(host="127.0.0.1:8888", method="POST", path="/api/command", headers={})
'''

# app.run() records what a command HexStrike runs could see: the server's /proc environ and command line,
# read by a child process too, and its open pipes; and how the guard answers the tokens in $STUB_PROBE.
STUB_SERVER_MODULE = r'''
import json, os, subprocess
class App:
    def __init__(self):
        self.before_request_funcs = {}
    def run(self, **kw):
        import flask
        pipes = []
        for n in os.listdir("/proc/self/fd"):
            try:
                if int(n) > 2 and os.readlink("/proc/self/fd/" + n).startswith("pipe:"):
                    pipes.append(int(n))
            except OSError:
                pass
        guard, codes = self.before_request_funcs[None][0], []
        with open(os.environ["STUB_PROBE"]) as f:
            probe = json.load(f)
        for token in probe:
            flask.request.headers = {} if token is None else {"X-Secstack-Token": token}
            try:
                codes.append(guard() or 200)
            except flask.Abort as e:
                codes.append(e.code)
        child = subprocess.run(["cat", "/proc/%d/environ" % os.getpid()], stdout=subprocess.PIPE).stdout
        with open("/proc/self/environ", "rb") as f:
            environ = f.read()
        with open("/proc/self/cmdline", "rb") as f:
            cmdline = f.read()
        with open(os.environ["STUB_OUT"], "w") as f:
            json.dump({"pid": os.getpid(), "run": kw, "codes": codes, "pipes": pipes, "environ": environ.hex(),
                       "cmdline": cmdline.hex(), "child_saw": child.hex()}, f)
app = App()
'''


@unittest.skipUnless(HAVE_PROC, "needs Linux /proc, like the container")
class TestEntryProcess(unittest.TestCase):
    """The real two-step start, as a process: what a root command in the container could read."""

    def start(self, token):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / "flask.py").write_text(STUB_FLASK_MODULE)
            (d / "hexstrike_server.py").write_text(STUB_SERVER_MODULE)
            (d / "probe.json").write_text(json.dumps([TOKEN, None, OTHER]))
            env = dict(entry_env(token), PYTHONPATH=str(d), STUB_PROBE=str(d / "probe.json"), STUB_OUT=str(d / "out.json"))
            p = subprocess.Popen([sys.executable, str(ENTRY)], env=env, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = p.communicate(timeout=120)
            got = json.loads((d / "out.json").read_text()) if (d / "out.json").exists() else None
        return p, (out + err).decode(errors="replace"), got

    def test_server_process_holds_the_token_only_in_memory(self):
        p, output, got = self.start(TOKEN)
        self.assertEqual(p.returncode, 0, output)
        self.assertEqual(got["pid"], p.pid)              # the same process: in the container it stays PID 1
        self.assertEqual(got["run"], {"host": "0.0.0.0", "port": 8888, "debug": False, "threaded": True})
        self.assertEqual(got["codes"], [200, 401, 401])  # the guard has the token
        environ, cmdline, child = (bytes.fromhex(got[k]) for k in ("environ", "cmdline", "child_saw"))
        self.assertIn(b"STUB_PROBE=", environ)          # the reads worked...
        self.assertIn(b"STUB_PROBE=", child)
        self.assertIn(FD_FLAG.encode(), cmdline)
        for name, blob in (("environ", environ), ("cmdline", cmdline), ("a child's read of it", child)):
            self.assertNotIn(TOKEN.encode(), blob, name)   # ...and found no token
            self.assertNotIn(b"HEXSTRIKE_TOKEN", blob, name)
        self.assertEqual(got["pipes"], [])               # the token's pipe is closed
        self.assertNotIn(TOKEN, output)

    def test_bad_token_stops_before_serving(self):
        p, output, got = self.start(TOKEN[:-1])
        self.assertNotEqual(p.returncode, 0)
        self.assertIsNone(got)
        self.assertIn("refusing to start", output)
        self.assertNotIn(TOKEN[:-1], output)


@unittest.skipUnless(HAVE_FLASK, "flask not installed (the hexstrike-kali image has it)")
class TestEntryWithFlask(unittest.TestCase):
    def test_real_flask_app(self):
        import flask
        app = flask.Flask("stub_hexstrike_server")

        @app.route("/health")
        def health():
            return {"status": "healthy"}

        @app.route("/api/command", methods=["POST"])
        def command():
            return {"ran": True}
        load_entry(TOKEN, app=app, flask_module=flask)
        c = app.test_client()
        local = {"Host": "127.0.0.1:8888"}
        self.assertEqual(c.get("/health", headers=local).status_code, 200)
        self.assertEqual(c.post("/api/command", headers=local).status_code, 401)
        self.assertEqual(c.post("/api/command", headers=dict(local, **{HEADER: OTHER})).status_code, 401)
        self.assertEqual(c.post("/api/command", headers=dict(local, **{HEADER.lower(): TOKEN})).status_code, 200)
        self.assertEqual(c.post("/api/command", headers={"Host": "172.30.1.5:8888", HEADER: TOKEN}).status_code, 403)
        self.assertEqual(c.get("/api/secstack-auth-check", headers=local).status_code, 401)   # before routing
        self.assertEqual(c.get("/api/secstack-auth-check", headers=dict(local, **{HEADER: TOKEN})).status_code, 404)


# --------------------------------------------------------------------------- MCP client wrapper
# Requests like hexstrike_mcp.py's. Between the first and the second, FAKE_ROTATE_SRC (a file holding a new
# token) replaces FAKE_ROTATE_DST, as `secstack mcp on` does for a new container; an empty SRC deletes DST.
FAKE_MCP = '''
import argparse, json, os, sys
import requests
ap = argparse.ArgumentParser()
ap.add_argument("--server", default="http://127.0.0.1:8888")
ap.add_argument("--other")
a = ap.parse_args()
s = requests.Session()                       # trusts the environment: HTTP_PROXY points at a dead port
s.get(a.server + "/health", timeout=5)
if os.environ.get("FAKE_ROTATE_DST"):
    if os.environ["FAKE_ROTATE_SRC"]:
        os.replace(os.environ["FAKE_ROTATE_SRC"], os.environ["FAKE_ROTATE_DST"])
    else:
        os.unlink(os.environ["FAKE_ROTATE_DST"])
s.post(a.server + "/api/command", json={"command": "id"}, timeout=5)
direct = requests.Session()
direct.trust_env = False
direct.get(a.other + "/elsewhere", timeout=5)
direct.get(a.server + "/redirect", timeout=5)   # answered with a redirect to the other server
out = {"argv": sys.argv, "name": __name__, "path0": sys.path[0], "env": dict(os.environ)}
with open(os.environ["FAKE_MCP_OUT"], "w") as f:
    json.dump(out, f)
'''


def recording_server(seen, redirect_to=None):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def handle_any(self):
            seen.append((self.command, self.path, self.headers.get(HEADER)))
            n = int(self.headers.get("Content-Length") or 0)
            if n:
                self.rfile.read(n)
            if self.path == "/redirect" and redirect_to:
                self.send_response(302)
                self.send_header("Location", redirect_to() + "/landed")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = b"{}"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        do_GET = do_POST = handle_any
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def dead_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@unittest.skipUnless(HAVE_REQUESTS, "requests not installed (the host venv has it)")
class TestClientWrapper(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = Path(self.tmp.name)
        self.secops = t / "sec-ops"
        (self.secops / "env").mkdir(parents=True)
        self.token_file = self.secops / "env" / "hexstrike-token"
        self.token_file.write_text(TOKEN + "\n")
        self.next_token = t / "next-token"          # what a new container's start writes
        self.next_token.write_text(OTHER + "\n")
        self.fake = t / "hexstrike-ai" / "hexstrike_mcp.py"
        self.fake.parent.mkdir()
        self.fake.write_text(FAKE_MCP)
        self.out = t / "fake-out.json"
        self.hex_seen, self.other_seen = [], []
        self.other = recording_server(self.other_seen)
        self.hex = recording_server(self.hex_seen, redirect_to=lambda: self.other_url)
        self.hex_url = f"http://127.0.0.1:{self.hex.server_address[1]}"
        self.other_url = f"http://127.0.0.1:{self.other.server_address[1]}"

    def tearDown(self):
        for srv in (self.hex, self.other):
            srv.shutdown()
            srv.server_close()
        self.tmp.cleanup()

    def run_client(self, *args, **env_extra):
        env = {k: v for k, v in os.environ.items() if "proxy" not in k.lower() and not k.startswith("HEXSTRIKE")}
        dead = f"http://127.0.0.1:{dead_port()}"
        env.update(SECOPS=str(self.secops), FAKE_MCP_OUT=str(self.out), HTTP_PROXY=dead, http_proxy=dead)
        env.update(env_extra)
        cmd = [sys.executable, str(CLIENT)] + [str(a) for a in args]
        return subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=60)

    def run_fake(self, *server_args, **env_extra):
        return self.run_client(self.fake, *(server_args or ("--server", self.hex_url)), "--other", self.other_url,
                               **env_extra)

    def tokens_seen(self):
        return [h for _, _, h in self.hex_seen]

    def test_adds_the_token_to_hexstrike_requests_only(self):
        r = self.run_fake()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.hex_seen, [("GET", "/health", TOKEN), ("POST", "/api/command", TOKEN),
                                         ("GET", "/redirect", TOKEN)])      # direct, past HTTP_PROXY
        self.assertEqual(self.other_seen, [("GET", "/elsewhere", None), ("GET", "/landed", None)])
        out = json.loads(self.out.read_text())
        self.assertEqual(out["argv"], [str(self.fake), "--server", self.hex_url, "--other", self.other_url])
        self.assertEqual(out["name"], "__main__")
        self.assertEqual(out["path0"], str(self.fake.parent))
        self.assertNotIn(TOKEN, json.dumps(out))                  # not in argv, not in the environment
        self.assertNotIn(TOKEN, r.stdout + r.stderr)

    def test_server_equals_form(self):
        r = self.run_fake("--server=" + self.hex_url)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.tokens_seen(), [TOKEN, TOKEN, TOKEN])

    def test_token_file_override(self):
        other_file = Path(self.tmp.name) / "tok"
        other_file.write_text(OTHER)
        r = self.run_fake(HEXSTRIKE_TOKEN_FILE=str(other_file))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.hex_seen[0], ("GET", "/health", OTHER))

    def test_new_token_is_picked_up_mid_session(self):
        r = self.run_fake(FAKE_ROTATE_SRC=str(self.next_token), FAKE_ROTATE_DST=str(self.token_file))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.tokens_seen(), [TOKEN, OTHER, OTHER])
        self.assertNotIn(OTHER, r.stdout + r.stderr)

    def test_missing_token_file_sends_no_header_and_keeps_running(self):
        # A fresh install: 5ire starts the server before `secstack prep` wrote the token; then it appears.
        self.token_file.unlink()
        r = self.run_fake(FAKE_ROTATE_SRC=str(self.next_token), FAKE_ROTATE_DST=str(self.token_file))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.tokens_seen(), [None, OTHER, OTHER])
        self.assertEqual(r.stderr.count("no HexStrike API token at"), 1, r.stderr)
        self.assertTrue(self.out.exists())
        # and the token file goes away mid-session (HexStrike stopped and its token removed by hand)
        self.hex_seen.clear()
        self.next_token.write_text(OTHER + "\n")
        r = self.run_fake(FAKE_ROTATE_SRC="", FAKE_ROTATE_DST=str(self.next_token),
                          HEXSTRIKE_TOKEN_FILE=str(self.next_token))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.tokens_seen(), [OTHER, None, None])

    def test_malformed_token_file_sends_no_header_and_keeps_running(self):
        for content in ("", "not-a-token\n", TOKEN.upper(), TOKEN[:-1], TOKEN + "0\n"):
            self.token_file.write_text(content)
            self.hex_seen.clear()
            if self.out.exists():
                self.out.unlink()
            with self.subTest(content=content):
                r = self.run_fake()
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual(self.tokens_seen(), [None, None, None])
                self.assertIn("hexstrike-client:", r.stderr)
                self.assertNotIn("Traceback", r.stderr)
                if content.strip():
                    self.assertNotIn(content.strip(), r.stdout + r.stderr)   # never echoed
                self.assertTrue(self.out.exists())

    def test_server_must_be_loopback(self):
        # localhost and [::1] too: on macOS localhost resolves to ::1 first, where Docker publishes nothing, so
        # any local process listening there would get the token.
        for url in ("http://10.0.0.5:8888", "http://172.30.1.5:8888", "ftp://127.0.0.1:8888", "http://127.0.0.1:x",
                    "http://localhost:8888", "http://LocalHost:8888", "http://[::1]:8888"):
            for form in (["--server", url], ["--server=" + url], ["--server", self.hex_url, "--server=" + url]):
                with self.subTest(form=form):
                    r = self.run_fake(*form)
                    self.assertEqual(r.returncode, 2, r.stderr)
                    self.assertIn("127.0.0.1", r.stderr)
                    self.assertFalse(self.out.exists())
                    self.assertEqual(self.hex_seen, [])

    def test_upstream_script_required(self):
        r = self.run_client(Path(self.tmp.name) / "missing.py")
        self.assertEqual(r.returncode, 2)
        self.assertIn("not found", r.stderr)


class TestClientServerCheck(unittest.TestCase):
    """The --server check runs before requests is imported: tested here without requests too (the Mac's python3)."""

    def test_token_goes_to_127_0_0_1_only(self):
        with tempfile.TemporaryDirectory() as d:
            fake = Path(d) / "hexstrike_mcp.py"
            fake.write_text("raise SystemExit('started')\n")
            for url in ("http://localhost:8888", "http://[::1]:8888", "http://10.0.0.5:8888"):
                with self.subTest(url=url):
                    r = subprocess.run([sys.executable, str(CLIENT), str(fake), "--server", url],
                                       env=dict(os.environ, SECOPS=d), capture_output=True, text=True, timeout=60)
                    self.assertEqual(r.returncode, 2, r.stderr)
                    self.assertIn("--server must be an http(s) URL on 127.0.0.1", r.stderr)
                    self.assertNotIn("started", r.stderr)


def load_client():
    spec = importlib.util.spec_from_file_location("hexstrike_client_under_test", CLIENT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestTokenFile(unittest.TestCase):
    """The wrapper's view of the token file: read again only when a stat shows it changed."""

    def setUp(self):
        self.mod = load_client()
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "hexstrike-token"
        self.stderr = io.StringIO()
        p = mock.patch.object(sys, "stderr", self.stderr)
        p.start()
        self.addCleanup(p.stop)

    def tearDown(self):
        self.tmp.cleanup()

    def replace(self, text):
        """As secstack writes it: a new file renamed over the old one."""
        new = self.path.with_name(".new")
        new.write_text(text)
        os.replace(new, self.path)

    def test_unchanged_file_is_not_read_again(self):
        self.replace(TOKEN + "\n")
        tf = self.mod.TokenFile(self.path)
        self.assertEqual(tf.get(), TOKEN)
        st = os.stat(self.path)
        with open(self.path, "r+") as f:          # same file, same size, old modification time
            f.write(OTHER + "\n")
        os.utime(self.path, ns=(st.st_atime_ns, st.st_mtime_ns))
        self.assertEqual(tf.get(), TOKEN)
        os.utime(self.path, ns=(st.st_atime_ns, st.st_mtime_ns + 10 ** 9))
        self.assertEqual(tf.get(), OTHER)          # a newer modification time: read again

    def test_replaced_file_is_read_again_even_with_the_same_size_and_time(self):
        self.replace(TOKEN + "\n")
        tf = self.mod.TokenFile(self.path)
        self.assertEqual(tf.get(), TOKEN)
        st = os.stat(self.path)
        self.replace(OTHER + "\n")
        os.utime(self.path, ns=(st.st_atime_ns, st.st_mtime_ns))   # e.g. within one second on HFS+
        self.assertEqual(tf.get(), OTHER)

    def test_missing_then_malformed_then_valid(self):
        tf = self.mod.TokenFile(self.path)
        self.assertIsNone(tf.get())
        self.assertIsNone(tf.get())
        self.replace("not-a-token\n")
        self.assertIsNone(tf.get())
        self.replace(TOKEN + "\n")
        self.assertEqual(tf.get(), TOKEN)
        self.path.unlink()
        self.assertIsNone(tf.get())
        said = self.stderr.getvalue()
        self.assertEqual(said.count("no HexStrike API token at"), 2, said)   # once per spell, not per request
        self.assertEqual(said.count("doesn't hold a readable 64-hex"), 1, said)
        self.assertNotIn("not-a-token", said)
        self.assertNotIn(TOKEN, said)


# --------------------------------------------------------------------------- secstack + hexstrike-ctl
DOCKER_STUB = r'''
import json, os, sys
args = sys.argv[1:]
with open(os.environ["FAKE_DOCKER_LOG"], "a") as f:
    f.write(json.dumps(args) + "\n")
path = os.environ["FAKE_DOCKER_STATE"]
st = json.load(open(path)) if os.path.exists(path) else {"running": False, "label": "", "net": "hexstrike-net"}
def save():
    with open(path, "w") as f:
        json.dump(st, f)
if args[:1] == ["ps"]:
    if st["running"] and "--filter" not in args:
        print("hexstrike")
elif args[:1] == ["inspect"]:
    fmt = args[args.index("--format") + 1]
    print(st["net"] + " " if "Networks" in fmt else st["label"] if "secstack.token-id" in fmt else "")
elif args[:2] == ["rm", "-f"] or args[:1] == ["stop"]:
    st.update(running=False, label="")
    save()
elif args[:1] == ["run"]:
    envf = args[args.index("--env-file") + 1]
    with open(os.environ["FAKE_DOCKER_ENVCOPY"], "w") as f:
        json.dump({"content": open(envf).read(), "mode": os.stat(envf).st_mode & 0o777,
                   "link": os.path.islink(envf)}, f)
    labels = [a.split("=", 1)[1] for a in args if a.startswith("secstack.token-id=")]
    st.update(running=True, label=labels[0] if labels else "", net=args[args.index("--network") + 1])
    save()
'''

CURL_STUB = r'''
import json, os, sys
args = sys.argv[1:]
stdin = sys.stdin.read() if "@-" in args else ""
with open(os.environ["FAKE_CURL_LOG"], "a") as f:
    f.write(json.dumps({"argv": args, "stdin": stdin}) + "\n")
url = args[-1]
if url.endswith("/health"):
    # FAKE_HEALTH_SECONDS: how long /health takes; a shorter curl -m times out (exit 28), without waiting here
    took = float(os.environ.get("FAKE_HEALTH_SECONDS", "0"))
    if took and "-m" in args and float(args[args.index("-m") + 1]) < took:
        sys.exit(28)
    sys.exit(0 if os.environ.get("FAKE_HEALTH", "up") == "up" else 7)
if "-w" in args:
    with_token = os.environ["FAKE_TOKEN"] in stdin
    sys.stdout.write(os.environ.get("FAKE_TOKEN_CODE" if with_token else "FAKE_AUTH_CODE", "404" if with_token else "401"))
'''


def write_stub(directory, name, code):
    py = directory / f"{name}.py"
    py.write_text(code)
    sh = directory / name
    sh.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{py}" "$@"\n')
    sh.chmod(0o755)


@unittest.skipUnless(HAVE_BASH, "needs bash")
class TestSecstackHexstrike(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = self.t = Path(self.tmp.name).resolve()
        self.stubs = t / "stubs"
        self.stubs.mkdir()
        write_stub(self.stubs, "docker", DOCKER_STUB)
        write_stub(self.stubs, "curl", CURL_STUB)
        self.home = t / "home"
        self.secops = t / "GH" / ".sec-ops"
        (self.secops / "configs").mkdir(parents=True)
        self.home.mkdir()
        self.token_file = self.secops / "env" / "hexstrike-token"
        self.envf = self.secops / "run" / "hexstrike.env"
        self.state = t / "docker-state.json"
        self.claude_cfg = self.home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
        self.fiveire = self.home / "Library" / "Application Support" / "5ire"
        self.env = {k: v for k, v in os.environ.items() if k not in ("SECOPS", "SECSTACK_GH")}
        self.env.update(PATH=f"{self.stubs}{os.pathsep}{os.environ['PATH']}", HOME=str(self.home),
                        SECSTACK_GH=str(t / "GH"), SECOPS=str(self.secops), S=str(SECSTACK),
                        FAKE_DOCKER_LOG=str(t / "docker.log"), FAKE_DOCKER_STATE=str(self.state),
                        FAKE_DOCKER_ENVCOPY=str(t / "envcopy.json"), FAKE_CURL_LOG=str(t / "curl.log"),
                        FAKE_TOKEN=TOKEN)

    def tearDown(self):
        self.tmp.cleanup()

    def secstack(self, calls, **env_extra):
        script = ('source "$S" version >/dev/null; docker_up(){ return 0; }; scope_apply(){ return 0; }; '
                  'sleep(){ :; }; ' + calls)
        env = dict(self.env, **env_extra)
        r = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True, timeout=120)
        return r.returncode, r.stdout + r.stderr

    def docker_calls(self):
        p = self.t / "docker.log"
        return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []

    def curl_calls(self):
        p = self.t / "curl.log"
        return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []

    def runs(self):
        return [c for c in self.docker_calls() if c[:1] == ["run"]]

    def token(self):
        return self.token_file.read_text().strip()

    def envcopy(self):
        return json.loads((self.t / "envcopy.json").read_text())

    def test_first_start_creates_the_token_and_passes_it_in_an_env_file(self):
        rc, out = self.secstack("hexstrike_start")
        self.assertEqual(rc, 0, out)
        self.assertIn("API token required", out)
        tok = self.token()
        self.assertRegex(tok, r"^[0-9a-f]{64}$")
        self.assertEqual(self.token_file.read_text(), tok + "\n")
        self.assertEqual(stat.S_IMODE(self.token_file.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.token_file.parent.stat().st_mode), 0o700)
        self.assertEqual(sorted(p.name for p in self.token_file.parent.iterdir()), ["hexstrike-token"])  # no temp file left
        (run,) = self.runs()
        self.assertIn("--env-file", run)
        self.assertEqual(run[run.index("--label") + 1], "secstack.token-id=" + fingerprint(tok))
        self.assertFalse([a for a in run if "hexstrike-data" in a or a in ("-v", "--volume", "--mount")])
        self.assertEqual(self.envcopy(), {"content": f"HEXSTRIKE_TOKEN={tok}\n", "mode": 0o600, "link": False})
        self.assertFalse(self.envf.exists())                                   # removed after docker read it
        for call in self.docker_calls():
            self.assertFalse([a for a in call if tok in a], call)               # never on a command line
        for call in self.curl_calls():
            self.assertNotIn(tok, json.dumps(call))
            self.assertEqual(call["argv"][call["argv"].index("--noproxy") + 1], "*")

    def test_every_new_container_gets_a_new_token(self):
        seen = []
        for calls in ("hexstrike_start", "hexstrike_stop; hexstrike_start", "hexstrike_stop; hexstrike_start"):
            rc, out = self.secstack(calls)
            self.assertEqual(rc, 0, out)
            tok = self.token()
            self.assertNotIn(tok, seen)
            seen.append(tok)
            run = self.runs()[-1]
            self.assertEqual(run[run.index("--label") + 1], "secstack.token-id=" + fingerprint(tok))
            self.assertEqual(self.envcopy()["content"], f"HEXSTRIKE_TOKEN={tok}\n")
        self.assertEqual(len(self.runs()), 3)
        # A container replaced because the file no longer matches it gets a new token too.
        self.token_file.write_text(OTHER + "\n")
        rc, out = self.secstack("hexstrike_start")
        self.assertEqual(rc, 0, out)
        self.assertIn("without the current API token", out)
        self.assertNotIn(self.token(), seen + [OTHER])
        self.assertEqual(stat.S_IMODE(self.token_file.stat().st_mode), 0o600)

    def test_running_container_with_this_token_is_kept(self):
        self.assertEqual(self.secstack("hexstrike_start")[0], 0)
        tok = self.token()
        self.token_file.chmod(0o644)
        rc, out = self.secstack("hexstrike_start")
        self.assertEqual(rc, 0, out)
        self.assertIn("already running", out)
        self.assertEqual(len(self.runs()), 1)
        self.assertEqual(self.token(), tok)                                     # not rotated: same container
        self.assertEqual(stat.S_IMODE(self.token_file.stat().st_mode), 0o600)   # an existing file is re-locked

    def test_runs_alone_on_its_own_network_at_its_fixed_address(self):
        # A Kali terminal with NET_RAW on a shared bridge could take over HexStrike's address.
        rc, out = self.secstack("hexstrike_start")
        self.assertEqual(rc, 0, out)
        (run,) = self.runs()
        self.assertEqual(run[run.index("--network") + 1], "hexstrike-net")
        self.assertEqual(run[run.index("--ip") + 1], "172.30.1.5")
        self.assertEqual(run.count("--network"), 1)
        # one still on pentest-net (from before hexstrike-net) is replaced, even with the current token
        self.state.write_text(json.dumps(dict(json.loads(self.state.read_text()), net="pentest-net")))
        rc, out = self.secstack("hexstrike_start")
        self.assertEqual(rc, 0, out)
        self.assertIn("restarting it on hexstrike-net", out)
        self.assertEqual(len(self.runs()), 2)

    def test_container_started_without_the_token_is_replaced(self):
        for token_file in (True, False):
            self.state.write_text(json.dumps({"running": True, "label": "", "net": "hexstrike-net"}))
            if token_file:
                self.token_file.parent.mkdir(mode=0o700, exist_ok=True)
                self.token_file.write_text(TOKEN + "\n")
            elif self.token_file.exists():
                self.token_file.unlink()        # no token to compare: an empty label must not count as a match
            with self.subTest(token_file=token_file):
                before = len(self.runs())
                rc, out = self.secstack("hexstrike_start")
                self.assertEqual(rc, 0, out)
                self.assertIn("without the current API token", out)
                calls = self.docker_calls()
                self.assertEqual(len(self.runs()), before + 1)
                self.assertLess(calls.index(["rm", "-f", "hexstrike"], len(calls) - 3), calls.index(self.runs()[-1]))
                run = self.runs()[-1]
                self.assertEqual(run[run.index("--label") + 1], "secstack.token-id=" + fingerprint(self.token()))

    def test_image_without_the_token_check_is_stopped(self):
        rc, out = self.secstack("hexstrike_start", FAKE_AUTH_CODE="404")
        self.assertEqual(rc, 1, out)
        self.assertIn("predates the token check", out)
        self.assertEqual(self.docker_calls()[-1], ["rm", "-f", "hexstrike"])
        self.assertFalse(json.loads(self.state.read_text())["running"])

    def test_slow_or_silent_health_still_gets_the_token_check(self):
        # Upstream /health takes 3-3.5 s; each try may take 10 s. An image without the token check is stopped
        # whether /health answered or not, and so is one that never answers at all (fail closed).
        for env, rc, want in (({"FAKE_HEALTH_SECONDS": "3.5", "FAKE_AUTH_CODE": "404"}, 1, "predates the token check"),
                              ({"FAKE_HEALTH": "down", "FAKE_AUTH_CODE": "404"}, 1, "predates the token check"),
                              ({"FAKE_HEALTH": "down", "FAKE_AUTH_CODE": "000"}, 1, "didn't answer within a minute"),
                              ({"FAKE_HEALTH": "down"}, 0, "/health isn't answering yet"),
                              ({"FAKE_HEALTH_SECONDS": "3.5"}, 0, "hexstrike up on 127.0.0.1:8888")):
            self.state.write_text(json.dumps({"running": False, "label": "", "net": ""}))
            with self.subTest(env=env):
                got, out = self.secstack("hexstrike_start", **env)
                self.assertEqual(got, rc, out)
                self.assertIn(want, out)
                self.assertEqual(json.loads(self.state.read_text())["running"], rc == 0)
                health = [c["argv"] for c in self.curl_calls() if c["argv"][-1].endswith("/health")]
                self.assertTrue(health and all(float(a[a.index("-m") + 1]) >= 10 for a in health), health)

    def test_refuses_to_start_unless_the_scope_firewall_is_applied_first(self):
        # scope_apply runs before anything starts; when it fails, nothing starts.
        log = self.t / "docker.log"
        rc, out = self.secstack('scope_apply(){ echo \'["scope_apply"]\' >> "$FAKE_DOCKER_LOG"; return 1; }; hexstrike_start')
        self.assertEqual(rc, 1, out)
        self.assertEqual(self.runs(), [])
        self.assertEqual(self.docker_calls(), [["scope_apply"]])
        log.unlink()
        rc, out = self.secstack('scope_apply(){ echo \'["scope_apply"]\' >> "$FAKE_DOCKER_LOG"; return 0; }; hexstrike_start')
        self.assertEqual(rc, 0, out)
        calls = self.docker_calls()
        self.assertLess(calls.index(["scope_apply"]), calls.index(self.runs()[0]))

    def test_malformed_token_file_is_replaced_and_a_symlink_refused(self):
        self.token_file.parent.mkdir(mode=0o700)
        self.token_file.write_text("not-a-token\n")
        rc, out = self.secstack("hexstrike_start")
        self.assertEqual(rc, 0, out)
        self.assertRegex(self.token(), r"^[0-9a-f]{64}$")
        self.token_file.unlink()
        target = self.t / "elsewhere"
        target.write_text(TOKEN + "\n")
        self.token_file.symlink_to(target)
        self.state.unlink()
        before = len(self.runs())
        rc, out = self.secstack("hexstrike_start")
        self.assertEqual(rc, 1, out)
        self.assertIn("symlink", out)
        self.assertEqual(len(self.runs()), before)
        self.assertTrue(self.token_file.is_symlink())
        self.assertEqual(target.read_text(), TOKEN + "\n")

    def test_token_helpers(self):
        rc, out = self.secstack('hexstrike_token_id; echo "[$?]"')
        self.assertEqual(out, "[0]\n")                                           # no file: nothing
        self.token_file.parent.mkdir(mode=0o700)
        for content, want in ((TOKEN + "\n", fingerprint(TOKEN) + "\n"), (TOKEN, fingerprint(TOKEN) + "\n"),
                              (TOKEN.upper() + "\n", ""), ("x\n", ""), ("", "")):
            self.token_file.write_text(content)
            with self.subTest(content=content):
                self.assertEqual(self.secstack("hexstrike_token_id")[1], want)
        self.token_file.unlink()
        (self.t / "x").write_text(TOKEN + "\n")
        self.token_file.symlink_to(self.t / "x")
        self.assertEqual(self.secstack("hexstrike_token_id")[1], "")
        self.token_file.unlink()
        envf = self.t / "some.env"
        rc, out = self.secstack(f'hexstrike_token "{envf}"')
        self.assertEqual(rc, 0, out)
        self.assertEqual(out, fingerprint(self.token()) + "\n")                 # only the fingerprint is printed
        self.assertEqual(envf.read_text(), f"HEXSTRIKE_TOKEN={self.token()}\n")
        self.assertEqual(stat.S_IMODE(envf.stat().st_mode), 0o600)

    def test_token_stays_out_of_a_shell_trace(self):
        tokens = []
        for calls, want in (("hexstrike_start", "+ hexstrike_token"), ("hexstrike_start", "already running"),
                            ("hexstrike_stop; hexstrike_start", "+ hexstrike_token")):
            rc, out = self.secstack("set -x; " + calls)
            self.assertEqual(rc, 0, out)
            tokens.append(self.token())
            self.assertIn(want, out)                                            # the trace is there...
            self.assertIn(fingerprint(tokens[-1]), out)
            for tok in tokens:
                self.assertNotIn(tok, out)                                      # ...without the old or new token

    def test_leftover_env_file_is_replaced(self):
        self.envf.parent.mkdir(parents=True, exist_ok=True)
        self.envf.write_text("HEXSTRIKE_TOKEN=" + OTHER + "\n")                 # an interrupted start's
        rc, out = self.secstack("hexstrike_start")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.envcopy()["content"], f"HEXSTRIKE_TOKEN={self.token()}\n")
        self.assertFalse(self.envf.exists())

    def test_env_file_is_never_written_through_a_planted_symlink(self):
        self.envf.parent.mkdir(parents=True, exist_ok=True)
        victim, absent = self.t / "victim", self.t / "absent"
        victim.write_text("original\n")
        for target in (victim, absent):
            # Planted before the start: removed, and the token goes to a new file.
            self.envf.symlink_to(target)
            self.state.write_text(json.dumps({"running": False, "label": "", "net": ""}))
            rc, out = self.secstack("hexstrike_start")
            with self.subTest(target=target.name, planted="before"):
                self.assertEqual(rc, 0, out)
                self.assertEqual(self.envcopy()["link"], False)
                self.assertEqual(victim.read_text(), "original\n")
                self.assertFalse(absent.exists())
                self.assertFalse(os.path.lexists(self.envf))
            # Planted after the cleanup (simulated: rm leaves it): the start fails without writing through it.
            self.envf.symlink_to(target)
            tok, before = self.token(), len(self.runs())
            rc, out = self.secstack('rm(){ case "$*" in *hexstrike.env*) return 0 ;; esac; command rm "$@"; }; '
                                    'hexstrike_stop; hexstrike_start')
            with self.subTest(target=target.name, planted="after"):
                self.assertEqual(rc, 1, out)
                self.assertIn("couldn't write a new HexStrike API token", out)
                self.assertEqual(victim.read_text(), "original\n")
                self.assertFalse(absent.exists())
                self.assertEqual(len(self.runs()), before)
                self.assertEqual(self.token(), tok)
            self.envf.unlink()

    def test_stop_removes_a_leftover_env_file(self):
        self.envf.parent.mkdir(parents=True)
        self.envf.write_text("HEXSTRIKE_TOKEN=x\n")
        self.state.write_text(json.dumps({"running": True, "label": "x", "net": "hexstrike-net"}))
        rc, out = self.secstack("hexstrike_stop")
        self.assertEqual(rc, 0, out)
        self.assertFalse(self.envf.exists())
        self.assertIn(["stop", "hexstrike"], self.docker_calls())

    # ---- MCP entries that run hexstrike_mcp.py without the wrapper
    OLD = {"command": "/x/venv/bin/python3", "args": ["/x/hexstrike-ai/hexstrike_mcp.py", "--server", "http://127.0.0.1:8888"]}
    STALE = "without the token wrapper"

    def test_stale_claude_entry_is_reported_with_the_fix(self):
        self.claude_cfg.parent.mkdir(parents=True)
        self.claude_cfg.write_text(json.dumps({"mcpServers": {"hexstrike-ai": self.OLD}}))
        rc, out = self.secstack("hexstrike_start")
        self.assertEqual(rc, 0, out)
        self.assertIn(self.STALE, out)
        self.assertIn("Claude Desktop", out)
        self.assertIn("secstack claude off && secstack claude on", out)
        self.assertNotIn("__SECOPS__", out)
        rc, out = self.secstack("claude_toggle off && claude_toggle on && hexstrike_stop && hexstrike_start")
        self.assertEqual(rc, 0, out)
        self.assertNotIn(self.STALE, out)                    # the fix it names works

    def test_stale_stash_entry_is_not_reported(self):
        # `claude on` and `claude off` (and install.sh) replace it before it can be used: no warning.
        (self.secops / "configs" / "mcp-servers.stash.json").write_text(json.dumps({"hexstrike-ai": self.OLD}))
        rc, out = self.secstack("hexstrike_start")
        self.assertEqual(rc, 0, out)
        self.assertNotIn(self.STALE, out)

    def test_5ire_mcp_json_counts_only_until_5ire_imports_it(self):
        self.fiveire.mkdir(parents=True)
        mcp = self.fiveire / "mcp.json"
        for old in (self.OLD, {"command": "/x/hexstrike-ai/hexstrike-env/bin/python3", "args": ["/x/hexstrike_mcp.py"]}):
            mcp.write_text(json.dumps({"mcpServers": {"hexstrike-ai": old}}))
            rc, out = self.secstack("hexstrike_stop; hexstrike_start")
            with self.subTest(old=old):
                self.assertEqual(rc, 0, out)
                self.assertIn(self.STALE, out)
                self.assertIn("before opening 5ire", out)
                self.assertIn(str(self.secops / "configs" / "generated" / "5ire-mcp.json"), out)
        current = json.loads((REPO / "configs" / "5ire" / "mcp.json").read_text())
        mcp.write_text(json.dumps(current))
        rc, out = self.secstack("hexstrike_stop; hexstrike_start")
        self.assertNotIn(self.STALE, out)
        # Once 5ire has imported it (its first launch), the file is never read again: not checked.
        mcp.write_text(json.dumps({"mcpServers": {"hexstrike-ai": self.OLD}}))
        (self.fiveire / "Stories").mkdir()
        (self.fiveire / "Stories" / "legacy-data-migrator.store").write_text("83a86d696772617465")
        rc, out = self.secstack("hexstrike_stop; hexstrike_start")
        self.assertEqual(rc, 0, out)
        self.assertNotIn(self.STALE, out)

    # ---- bin/hexstrike-ctl
    def ctl(self, *bash_opts, **env_extra):
        r = subprocess.run(["bash", *bash_opts, str(CTL), "status"], env=dict(self.env, **env_extra),
                           capture_output=True, text=True, timeout=60)
        return r.returncode, r.stdout + r.stderr

    def test_ctl_status_sends_the_token_on_stdin_never_through_a_proxy(self):
        self.token_file.parent.mkdir(mode=0o700)
        self.token_file.write_text(TOKEN + "\n")
        rc, out = self.ctl()
        self.assertEqual(rc, 0, out)
        self.assertIn("health: OK", out)
        self.assertIn("ours accepted", out)
        calls = self.curl_calls()
        self.assertEqual(len(calls), 3)
        for c in calls:
            self.assertEqual(c["argv"][c["argv"].index("--noproxy") + 1], "*")
            self.assertNotIn(TOKEN, " ".join(c["argv"]))
        health, anon, ours = calls
        self.assertTrue(health["argv"][-1].endswith("/health"))
        self.assertNotIn("-H", health["argv"])
        self.assertNotIn("-H", anon["argv"])
        self.assertEqual(ours["argv"][ours["argv"].index("-H") + 1], "@-")
        self.assertEqual(ours["stdin"], f"{HEADER}: {TOKEN}\n")

    def test_ctl_status_keeps_the_token_out_of_a_shell_trace(self):
        self.token_file.parent.mkdir(mode=0o700)
        self.token_file.write_text(TOKEN + "\n")
        rc, out = self.ctl("-x")
        self.assertEqual(rc, 0, out)
        self.assertIn("ours accepted", out)
        self.assertIn("+ ", out)
        self.assertNotIn(TOKEN, out)

    def test_ctl_status_failures(self):
        self.token_file.parent.mkdir(mode=0o700)
        self.token_file.write_text(TOKEN + "\n")
        for env, want in (({"FAKE_AUTH_CODE": "200"}, "NOT protected"),
                          ({"FAKE_AUTH_CODE": "404"}, "NOT protected"),     # an image without the token check
                          ({"FAKE_TOKEN_CODE": "401"}, "ours refused"),
                          ({"FAKE_HEALTH": "down"}, "health: no response"), ({"FAKE_AUTH_CODE": "000"}, "api: no response")):
            with self.subTest(env=env):
                rc, out = self.ctl(**env)
                self.assertEqual(rc, 1, out)
                self.assertIn(want, out)
        for content in (None, "", TOKEN[:-1] + "\n", TOKEN.upper() + "\n", "x" + TOKEN + "\n"):
            if content is None:
                self.token_file.unlink()
            else:
                self.token_file.write_text(content)
            with self.subTest(content=content):
                rc, out = self.ctl()
                self.assertEqual(rc, 1, out)
                self.assertIn("no valid token", out)


# --------------------------------------------------------------------------- MCP config templates, setup.sh
class TestClientConfigs(unittest.TestCase):
    WRAPPER = "__SECOPS__/mcp/hexstrike-client/hexstrike_client.py"
    FIVEIRE = REPO / "configs" / "5ire" / "mcp.json"

    def test_templates_run_hexstrike_through_the_wrapper(self):
        # Claude Desktop runs the wrapper itself; 5ire runs bin/secstack-mcp, which runs the same wrapper
        # (TestMcpLauncher), because 5ire's Command field can't hold the full line.
        e = json.loads((REPO / "configs" / "claude-desktop" / "mcp-servers.json").read_text())["hexstrike-ai"]
        self.assertEqual(e["command"], "__SECOPS__/venv/bin/python3")
        self.assertEqual(e["args"][:2], [self.WRAPPER, "__GH__/hexstrike-ai/hexstrike_mcp.py"])
        self.assertEqual(e["env"], {"SECOPS": "__SECOPS__"})
        e = json.loads(self.FIVEIRE.read_text())["mcpServers"]["hexstrike-ai"]
        self.assertEqual((e["command"], e["args"]), ("__SECOPS__/bin/secstack-mcp", ["hexstrike"]))
        self.assertEqual(e["env"], {"SECOPS": "__SECOPS__", "SECSTACK_GH": "__GH__"})
        self.assertTrue(CLIENT.is_file())

    def test_5ire_entries_fit_its_fields(self):
        # 5ire (pinned 12c6a08, src/renderer/pages/tool/ServerEditDialog.tsx) keeps the first 64 characters of a
        # name and 128 of a description or command line, and drops the rest without a word: an entry typed in
        # 5ire > Tools from the generated file must fit, even under a long home folder.
        home = "/Users/" + "u" * 32
        servers = json.loads(self.FIVEIRE.read_text())["mcpServers"]
        self.assertEqual(sorted(servers), ["hexstrike-ai", "kali-tools", "pentagi-bridge"])
        for key, e in servers.items():
            line = " ".join([e["command"]] + e["args"]).replace("__SECOPS__", home + "/GitHub/.sec-ops")
            with self.subTest(server=key):
                self.assertNotIn("__", line)
                self.assertLessEqual(len(line), 128, line)
                self.assertLessEqual(len(e["name"]), 64)
                self.assertLessEqual(len(e["description"]), 128)
                self.assertEqual(e["command"], "__SECOPS__/bin/secstack-mcp")

    def test_generated_5ire_config_points_at_the_launcher(self):
        with tempfile.TemporaryDirectory() as d:
            secops = Path(d) / "sec-ops"
            with mock.patch.dict(os.environ, {"SECOPS": str(secops), "SECSTACK_GH": str(Path(d) / "GH")}):
                spec = importlib.util.spec_from_file_location("plan_for_hexstrike", REPO / "scripts" / "plan.py")
                plan = importlib.util.module_from_spec(spec)
                sys.modules["plan_for_hexstrike"] = plan
                try:
                    spec.loader.exec_module(plan)
                    e = json.loads(plan.fiveire_config())["mcpServers"]["hexstrike-ai"]
                finally:
                    sys.modules.pop("plan_for_hexstrike", None)
        self.assertEqual((e["command"], e["args"]), (f"{secops}/bin/secstack-mcp", ["hexstrike"]))
        self.assertEqual(e["env"], {"SECOPS": str(secops), "SECSTACK_GH": str(Path(d) / "GH")})
        for placeholder in ("__SECOPS__", "__GH__", "__HOME__"):
            self.assertNotIn(placeholder, json.dumps(e))

    def test_no_em_dashes(self):
        for p in (ENTRY, CLIENT, CTL, LAUNCHER, Path(__file__), REPO / "configs" / "5ire" / "mcp.json",
                  REPO / "configs" / "claude-desktop" / "mcp-servers.json"):
            self.assertNotIn(chr(0x2014), p.read_text(encoding="utf-8"), p)   # em dash


@unittest.skipUnless(os.path.exists("/bin/sh"), "needs /bin/sh")
class TestMcpLauncher(unittest.TestCase):
    """bin/secstack-mcp NAME runs one MCP server with the same roots as bin/secstack, as a command short
    enough for 5ire's Command field. Stubs stand in for the venv's python3 and for docker: each prints its
    arguments and the roots it got, one per line."""

    STUB = '#!/bin/sh\nfor a in "$@"; do echo "$a"; done\necho "SECOPS=$SECOPS"; echo "GH=$SECSTACK_GH"\n'

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.t = Path(self._tmp.name)
        self.home = self.t / "home"
        self.bin = self.t / "bin"                 # what PATH has first: the docker stub
        self.bin.mkdir()
        docker = self.bin / "docker"
        docker.write_text(self.STUB)
        docker.chmod(0o755)

    def tearDown(self):
        self._tmp.cleanup()

    def venv(self, secops):
        py = secops / "venv" / "bin" / "python3"
        py.parent.mkdir(parents=True)
        py.write_text(self.STUB)
        py.chmod(0o755)

    def run_launcher(self, *args, **env):
        # The environment an app started from Finder gives the servers it spawns: HOME and a short PATH.
        base = {"HOME": str(self.home), "PATH": f"{self.bin}:/usr/bin:/bin"}
        r = subprocess.run([str(LAUNCHER), *args], env=dict(base, **env), capture_output=True, text=True,
                           timeout=30)
        return r.returncode, r.stdout.splitlines(), r.stderr

    def test_hexstrike_runs_the_wrapper_against_secstacks_server(self):
        secops = self.home / "GitHub" / ".sec-ops"   # the defaults: ~/GitHub and its .sec-ops
        self.venv(secops)
        rc, out, err = self.run_launcher("hexstrike")
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, [f"{secops}/mcp/hexstrike-client/hexstrike_client.py",
                               f"{self.home}/GitHub/hexstrike-ai/hexstrike_mcp.py",
                               "--server", "http://127.0.0.1:8888",
                               f"SECOPS={secops}", f"GH={self.home}/GitHub"])
        # Options go on to hexstrike_mcp.py after the default --server, so a second one wins there.
        rc, out, err = self.run_launcher("hexstrike", "--server", "http://127.0.0.1:9999")
        self.assertEqual(rc, 0, err)
        self.assertEqual(out[2:6], ["--server", "http://127.0.0.1:8888", "--server", "http://127.0.0.1:9999"])

    def test_roots_from_the_environment(self):
        gh, secops = self.t / "clones", self.t / "runtime"
        self.venv(secops)
        rc, out, err = self.run_launcher("hexstrike", SECOPS=str(secops), SECSTACK_GH=str(gh))
        self.assertEqual(rc, 0, err)
        self.assertEqual(out[:2], [f"{secops}/mcp/hexstrike-client/hexstrike_client.py",
                                   f"{gh}/hexstrike-ai/hexstrike_mcp.py"])
        self.assertEqual(out[-2:], [f"SECOPS={secops}", f"GH={gh}"])
        rc, out, err = self.run_launcher("pentagi-bridge", SECOPS=str(secops), SECSTACK_GH=str(gh))
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, [f"{secops}/mcp/pentagi-bridge/pentagi_mcp.py", f"SECOPS={secops}", f"GH={gh}"])

    def test_kali_docs_runs_the_offline_container(self):
        rc, out, err = self.run_launcher("kali-docs")
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, ["run", "-i", "--rm", "--network=none", "--cpus=2", "--memory=512m", "--read-only",
                               "--tmpfs", "/tmp", "kali-tools-mcp-server",
                               f"SECOPS={self.home}/GitHub/.sec-ops", f"GH={self.home}/GitHub"])
        # More arguments would become the container's command: refused, nothing on the MCP channel.
        rc, out, err = self.run_launcher("kali-docs", "sh")
        self.assertEqual((rc, out), (2, []))
        self.assertIn("usage: secstack-mcp", err)

    def test_entry_names_work_too(self):
        # 5ire throws a server's stderr away, so a usage error there would look like any failed connection.
        secops = self.home / "GitHub" / ".sec-ops"
        self.venv(secops)
        for name, alias in (("hexstrike", "hexstrike-ai"), ("kali-docs", "kali-tools")):
            with self.subTest(alias=alias):
                self.assertEqual(self.run_launcher(alias), self.run_launcher(name))
                self.assertEqual(self.run_launcher(alias)[0], 0)

    def test_missing_venv_leaves_the_mcp_channel_empty(self):
        rc, out, err = self.run_launcher("hexstrike")      # no venv under the default root
        self.assertIn(rc, (126, 127))                      # 126 from macOS /bin/sh (bash 3.2), 127 from dash
        self.assertEqual(out, [])
        self.assertIn("venv/bin/python3", err)

    def test_unknown_or_missing_server(self):
        for args in ((), ("nope",), ("",)):
            with self.subTest(args=args):
                rc, out, err = self.run_launcher(*args)
                self.assertEqual((rc, out), (2, []))
                self.assertIn("usage: secstack-mcp hexstrike", err)

    def test_is_an_executable_sh_script(self):
        self.assertTrue(os.access(LAUNCHER, os.X_OK))
        self.assertTrue(LAUNCHER.read_text().startswith("#!/bin/sh\n"))


@unittest.skipUnless(HAVE_BASH, "needs bash")
class TestSetup5ire(unittest.TestCase):
    """setup.sh's 5ire step flags an mcp.json that runs HexStrike without the wrapper. 5ire (pinned 12c6a08)
    imports the file once, on its first launch, and records that in Stories/legacy-data-migrator.store: before
    that the file is to be fixed, after it the server in 5ire > Tools."""

    def run_step(self, mcp_json, imported=False, other_files=False, default_roots=False):
        text = (REPO / "setup.sh").read_text()
        m = re.search(r"^step_5ire\(\)\{\n.*?^\}\n", text, re.S | re.M)
        self.assertIsNotNone(m, "step_5ire not found in setup.sh")
        with tempfile.TemporaryDirectory() as d:
            t = Path(d)
            # The defaults are ~/GitHub and ~/GitHub/.sec-ops; otherwise both are elsewhere.
            gh = t / "home" / "GitHub" if default_roots else t / "GH"
            secops = gh / ".sec-ops" if default_roots else t / "sec-ops"
            cfg = secops / "configs"
            (cfg / "generated").mkdir(parents=True)
            (cfg / "generated" / "5ire-mcp.json").write_text("{}\n")
            fivedir = t / "home" / "Library" / "Application Support" / "5ire"
            fivedir.mkdir(parents=True)
            if mcp_json is not None:
                (fivedir / "mcp.json").write_text(json.dumps(mcp_json))
            if imported:
                (fivedir / "Stories").mkdir()
                (fivedir / "Stories" / "legacy-data-migrator.store").write_text("83a86d696772617465")
            if other_files:
                (fivedir / "Preferences").write_text("{}")
            harness = ('hdr(){ :; }; ok(){ echo "ok: $*"; }; warn(){ echo "warn: $*"; }; die(){ echo "die: $*"; exit 1; }\n'
                       'PENDING=""; pend(){ PENDING="$PENDING - $*\n"; }; q(){ printf "%q" "$1"; }\n'
                       'ask_yn(){ return 1; }; conf_get(){ :; }; INTERACTIVE=0\n'
                       + m.group(0) + 'step_5ire\nprintf "%s" "$PENDING"\n')
            env = dict(os.environ, HOME=str(t / "home"), CFG=str(cfg), SECOPS=str(secops), GH=str(gh))
            r = subprocess.run(["bash", "-c", harness], env=env, capture_output=True, text=True, timeout=60)
            wrote = mcp_json is None and (fivedir / "mcp.json").exists()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return r.stdout, wrote

    OLD = {"mcpServers": {"hexstrike-ai": {"command": "/x/venv/bin/python3", "args": ["/x/hexstrike_mcp.py"]},
                          "pentagi-bridge": {"command": "/x/venv/bin/python3", "args": []}}}

    def test_old_entry_is_flagged_before_5ire_imports_it(self):
        for other_files in (False, True):     # an older 5ire kept reading mcp.json: flagged there too
            with self.subTest(other_files=other_files):
                out, _ = self.run_step(self.OLD, other_files=other_files)
                self.assertIn("warn: 5ire's mcp.json runs hexstrike_mcp.py without the API token wrapper", out)
                self.assertIn("Before opening 5ire", out)
                self.assertIn("secstack-mcp", out)

    def test_current_entry_passes(self):
        cur = json.loads((REPO / "configs" / "5ire" / "mcp.json").read_text())
        out, _ = self.run_step(cur)
        self.assertNotIn("without the API token wrapper", out)
        self.assertIn("already lists the secstack servers", out)

    def test_imported_mcp_json_is_not_checked_again(self):
        # Imported with an old entry: 5ire's database most likely holds it too, so the fix is in 5ire > Tools.
        out, _ = self.run_step(self.OLD, imported=True)
        self.assertIn("warn: 5ire imported a HexStrike entry without the API token wrapper on its first launch", out)
        self.assertNotIn("ok: 5ire imported mcp.json", out)
        todo = [l for l in out.splitlines() if l.startswith(" - ") and "hexstrike" in l.lower()]
        self.assertEqual(len(todo), 1, out)
        self.assertIn("In 5ire > Tools, set the hexstrike-ai server's command to: ", todo[0])
        self.assertIn("/bin/secstack-mcp hexstrike" + self.ROOTS, todo[0])         # roots other than the defaults
        self.assertIn("5ire-mcp.json", todo[0])                                 # where the full entries are
        self.assertNotIn("Before opening 5ire", out)                           # the file itself is never read again
        # Imported with a current entry: nothing to fix.
        cur = json.loads((REPO / "configs" / "5ire" / "mcp.json").read_text())
        out, _ = self.run_step(cur, imported=True)
        self.assertNotIn("without the API token wrapper", out)
        self.assertIn("ok: 5ire imported mcp.json on its first launch", out)
        self.assertIn("if you edit it there, use: ", out)
        self.assertIn("/bin/secstack-mcp hexstrike", out)
        self.assertEqual([l for l in out.splitlines() if l.startswith(" - ") and "hexstrike" in l.lower()], [])   # no to-do

    ADD = " - Add or fix HexStrike / Kali docs / pentagi-bridge in 5ire > Tools, one command each: "
    LAUNCH = "/bin/secstack-mcp hexstrike, kali-docs or pentagi-bridge"
    ROOTS = ", with environment variables SECOPS="

    def test_opened_without_mcp_json_lists_what_to_add(self):
        # The roots are not the defaults here, so the entries need them as environment variables.
        out, wrote = self.run_step(None, imported=True)
        self.assertFalse(wrote)
        self.assertIn("opened before", out)
        todo = [l for l in out.splitlines() if l.startswith(self.ADD)]
        self.assertEqual(len(todo), 1, out)
        self.assertIn(self.LAUNCH + self.ROOTS, todo[0])
        self.assertIn(" and SECSTACK_GH=", todo[0])
        # With the default roots, the command alone does.
        out, _ = self.run_step(None, imported=True, default_roots=True)
        todo = [l for l in out.splitlines() if l.startswith(self.ADD)]
        self.assertEqual(len(todo), 1, out)
        self.assertIn(self.LAUNCH + " (names and approval policies: ", todo[0])
        self.assertNotIn("environment variables", out)

    def test_own_mcp_json_without_secstacks_servers(self):
        # Not imported yet, no old HexStrike entry, none of secstack's servers: left as it is, with a to-do.
        out, wrote = self.run_step({"mcpServers": {"mine": {"command": "/x/mine"}}}, default_roots=True)
        self.assertFalse(wrote)
        self.assertIn("ok: 5ire mcp.json exists; left untouched", out)
        self.assertEqual(len([l for l in out.splitlines() if l.startswith(self.ADD) and self.LAUNCH in l]), 1, out)

    def test_fresh_5ire_gets_the_generated_file(self):
        out, wrote = self.run_step(None)
        self.assertTrue(wrote)
        self.assertIn("ok: wrote", out)


class TestClaudeToggleMigration(unittest.TestCase):
    """`secstack claude off/on` never leaves a hexstrike-ai entry that runs hexstrike_mcp.py directly
    (the API refuses it without the token the wrapper adds), whichever side held the old entry."""
    OLD = {"command": "/x/venv/bin/python3", "args": ["/x/hexstrike-ai/hexstrike_mcp.py", "--server", "http://127.0.0.1:8888"]}

    tearDown = TestSecstackHexstrike.tearDown       # same stubs and environment, without its tests
    secstack = TestSecstackHexstrike.secstack

    def setUp(self):
        TestSecstackHexstrike.setUp(self)
        self.cfg = self.home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
        self.cfg.parent.mkdir(parents=True)
        self.stash = self.secops / "configs" / "mcp-servers.stash.json"

    def entry(self, path, name="hexstrike-ai"):
        d = json.loads(path.read_text())
        return (d.get("mcpServers", d)).get(name)

    def check_wrapper(self, e):
        self.assertIsNotNone(e)
        self.assertEqual(e["args"][0], f"{self.secops}/mcp/hexstrike-client/hexstrike_client.py")
        self.assertEqual(e["args"][1], f"{self.t}/GH/hexstrike-ai/hexstrike_mcp.py")

    def test_off_then_on_with_an_old_live_entry(self):
        self.cfg.write_text(json.dumps({"mcpServers": {"hexstrike-ai": self.OLD, "other": {"command": "keep"}}}))
        self.stash.write_text(json.dumps({"kali-tools": {"command": "k"}}))
        rc, out = self.secstack("claude_toggle off")
        self.assertEqual(rc, 0, out)
        self.check_wrapper(self.entry(self.stash))
        self.assertIsNone(self.entry(self.cfg))
        rc, out = self.secstack("claude_toggle on")
        self.assertEqual(rc, 0, out)
        self.check_wrapper(self.entry(self.cfg))
        self.assertEqual(self.entry(self.cfg, "other"), {"command": "keep"})
        self.assertEqual(self.entry(self.cfg, "kali-tools"), {"command": "k"})
        self.assertEqual(stat.S_IMODE(self.cfg.stat().st_mode), 0o600)

    def test_on_with_an_old_stashed_entry(self):
        self.cfg.write_text(json.dumps({"mcpServers": {}}))
        self.stash.write_text(json.dumps({"hexstrike-ai": self.OLD}))
        rc, out = self.secstack("claude_toggle on")
        self.assertEqual(rc, 0, out)
        self.check_wrapper(self.entry(self.cfg))

    def test_current_entries_are_left_alone(self):
        for mine in ({"command": "/x/py", "args": ["/x/hexstrike_client.py", "/x/hexstrike_mcp.py", "--custom"]},
                     {"command": "/x/.sec-ops/bin/secstack-mcp", "args": ["hexstrike"]}):
            with self.subTest(mine=mine):
                self.cfg.write_text(json.dumps({"mcpServers": {}}))
                self.stash.write_text(json.dumps({"hexstrike-ai": mine}))
                rc, out = self.secstack("claude_toggle on")
                self.assertEqual(rc, 0, out)
                self.assertEqual(self.entry(self.cfg), mine)


if __name__ == "__main__":
    unittest.main()
