"""Functional tests for setup.sh, plus the executable bits of the repo's scripts.

Run from the repo root:  python3 -m unittest discover -s tests -v

setup.sh runs from a copy of the repo against a throwaway HOME, with stub docker, curl, pbcopy/pbpaste,
sudo, sysctl, uname, id, sw_vers, ifconfig, launchctl and install and a stub bin/secstack. In the copy,
the absolute macOS paths (/usr/sbin/sysctl, /Applications/, /etc/hosts, /Library/LaunchDaemons/,
/sbin/ifconfig, /bin/launchctl, /usr/bin/install) point into the sandbox or at the stubs, and the stub
sudo refuses the real ones, so nothing outside the sandbox is written. The sandbox path has a space in
it. Interactive steps run on a pseudo-terminal. No network, no Docker, no real sudo.

setup.sh is tested with every distinct bash among: $SECSTACK_TEST_BASH, `bash` on PATH and /bin/bash
(on macOS that is bash 3.2, the shell `#!/usr/bin/env bash` gets on a stock Mac).
"""
import fcntl
import os
import plistlib
import re
import select
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import termios
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.dont_write_bytecode = True
FAKE_CLAIM = "0123456789abcdef" * 2     # stands in for ARTEX's one-time setup value (32 hex)
CTRL_C, CTRL_D = b"\x03", b"\x04"
TIOCSCTTY = getattr(termios, "TIOCSCTTY", 0x20007461 if sys.platform == "darwin" else 0x540E)

STUBS = {
    "uname": 'case "$1" in -m) echo arm64 ;; *) echo Darwin ;; esac\n',
    "sysctl": 'case "$2" in hw.optional.arm64) echo 1 ;; sysctl.proc_translated) echo 0 ;;\n'
              '  hw.memsize) echo 34359738368 ;; machdep.cpu.brand_string) echo "Apple M2 Pro" ;; *) exit 1 ;; esac\n',
    "id": '[ "$1" = -u ] && { echo 501; exit 0; }; echo "uid=501(someone)"\n',
    "sw_vers": "echo 14.5\n",
    "docker": 'echo "docker $*" >> "$SANDBOX/log"\n'
              'case "$1" in\n'
              '  ps) cat "$SANDBOX/ps" 2>/dev/null ;;\n'
              '  compose) [ "$2" = logs ] && echo "artex-1  | Setup token: $FAKE_CLAIM" ;;\n'
              'esac\nexit 0\n',
    "curl": 'for a; do case "$a" in */api/auth/status)\n'
            '  if [ -n "$FAKE_ARTEX_STATUS" ]; then echo "$FAKE_ARTEX_STATUS"; else echo \'{"initialized": false}\'; fi\n'
            '  exit 0 ;; esac; done\n'
            'for a; do case "$a" in *http_code*) printf 200; exit 0 ;; esac; done\nexit 0\n',
    "pbcopy": 'cat > "$SANDBOX/clip"\n',
    "pbpaste": 'cat "$SANDBOX/clip" 2>/dev/null; exit 0\n',
    # Runs the command as "root" (STUB_ROOT), but never on a real system path: the rewrite in setUpClass
    # should have pointed every one of them into the sandbox or at a stub.
    "sudo": 'echo "sudo $*" >> "$SANDBOX/log"\n[ "$1" = -k ] && exit 0\n'
            'for a; do case "$a" in /etc/hosts|/Library/*|/sbin/*|/bin/launchctl|/usr/bin/install)\n'
            '  echo "REFUSED the real $a" >> "$SANDBOX/log"; exit 1 ;; esac; done\n'
            'export STUB_ROOT=1\nexec "$@"\n',
    # lo0 has 127.0.0.2 once $SANDBOX/lo0_alias exists; adding it needs root.
    "ifconfig": 'echo "ifconfig $*" >> "$SANDBOX/log"\n'
                'case "$*" in\n'
                '  lo0) printf "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384\\n\\tinet 127.0.0.1 netmask 0xff000000\\n"\n'
                '       [ -f "$SANDBOX/lo0_alias" ] && printf "\\tinet 127.0.0.2 netmask 0xff000000\\n"; exit 0 ;;\n'
                '  "lo0 alias 127.0.0.2 up") [ -n "$STUB_ROOT" ] || { echo "ifconfig: Permission denied" >&2; exit 1; }\n'
                '       : > "$SANDBOX/lo0_alias"; exit 0 ;;\n'
                'esac\nexit 1\n',
    # Like macOS: bootout of a service that isn't loaded exits 113, bootstrap of a loaded one exits 5.
    "launchctl": 'echo "launchctl $*" >> "$SANDBOX/log"\n'
                 'case "$1 $2" in "bootstrap system"|"bootout system/"*)\n'
                 '  [ -n "$STUB_ROOT" ] || { echo "launchctl: Operation not permitted" >&2; exit 1; } ;; esac\n'
                 'case "$1" in\n'
                 '  bootout) [ -f "$SANDBOX/launchd_loaded" ] || { echo "Boot-out failed: 113: Could not find service" >&2; exit 113; }\n'
                 '           rm -f "$SANDBOX/launchd_loaded" ;;\n'
                 '  bootstrap) [ -f "$SANDBOX/launchd_loaded" ] && { echo "Bootstrap failed: 5: Input/output error" >&2; exit 5; }\n'
                 '             : > "$SANDBOX/launchd_loaded" ;;\n'
                 'esac\nexit 0\n',
    # install [-m MODE] [-o OWNER] [-g GROUP] SRC DST: copies and sets the mode (the owner needs real root).
    "install": 'echo "install $*" >> "$SANDBOX/log"\n'
               '[ -n "$STUB_ROOT" ] || { echo "install: Operation not permitted" >&2; exit 1; }\n'
               'mode=755\n'
               'while [ $# -gt 2 ]; do case "$1" in -m) mode=$2; shift ;; -o|-g) shift ;; esac; shift; done\n'
               'cp "$1" "$2" && chmod "$mode" "$2"\n',
    "open": "exit 0\n", "uv": "exit 0\n", "ollama": "exit 0\n", "hf": "exit 0\n",
}
LO0_DAEMON = {"Label": "com.secstack.lo0-alias", "RunAtLoad": True,
              "ProgramArguments": ["/sbin/ifconfig", "lo0", "alias", "127.0.0.2", "up"]}


def shells():
    seen, found = set(), []
    for b in (os.environ.get("SECSTACK_TEST_BASH"), shutil.which("bash"), "/bin/bash"):
        if b and os.path.isfile(b) and os.access(b, os.X_OK) and os.path.realpath(b) not in seen:
            seen.add(os.path.realpath(b))
            found.append(b)
    return found


def run_pty(argv, env, script, timeout=30):
    """Run argv on a new pseudo-terminal (its controlling terminal). script: list of (text, action);
    once `text` has been printed, action (bytes to type, a signal number, or a function returning one
    of those) is applied. Returns (output, exit code, whether the terminal echoes input after the run)."""
    master, slave = os.openpty()
    # Signals start at their defaults, as in Terminal: a runner started with SIGINT or SIGHUP ignored (nohup,
    # a background job) would pass that on, and bash can't trap a signal that was ignored when it started.
    # Python itself ignores SIGPIPE and SIGXFSZ.
    sigs = [getattr(signal, n) for n in ("SIGINT", "SIGHUP", "SIGTERM", "SIGQUIT", "SIGPIPE", "SIGXFSZ")
            if hasattr(signal, n)]
    pid = os.fork()
    if pid == 0:   # child: only async-signal-safe work before exec
        try:
            os.setsid()
            fcntl.ioctl(slave, TIOCSCTTY, 0)
            for fd in (0, 1, 2):
                os.dup2(slave, fd)
            for s in sigs:
                signal.signal(s, signal.SIG_DFL)
            os.execve(argv[0], argv, env)
        finally:
            os._exit(127)
    out, status = bytearray(), None
    deadline = time.time() + timeout

    def pump(seconds):
        end = min(time.time() + seconds, deadline)
        while time.time() < end:
            r, _, _ = select.select([master], [], [], 0.05)
            if r:
                try:
                    data = os.read(master, 65536)
                except OSError:
                    return
                out.extend(data)
    try:
        for text, action in script:
            while text.encode() not in out and time.time() < deadline:
                pump(0.1)
                if os.waitpid(pid, os.WNOHANG)[0]:
                    raise AssertionError(f"exited before {text!r}:\n{out.decode(errors='replace')}")
            if text.encode() not in out:
                raise AssertionError(f"never saw {text!r}:\n{out.decode(errors='replace')}")
            pump(0.3)       # let the shell reach the blocking read
            if callable(action):
                action = action()
            if isinstance(action, bytes):
                os.write(master, action)
            else:
                os.kill(pid, action)
        while time.time() < deadline:
            p, st = os.waitpid(pid, os.WNOHANG)
            if p:
                status = st
                break
            pump(0.1)
        if status is None:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
            raise AssertionError(f"timed out:\n{out.decode(errors='replace')}")
        pump(0.2)
        # The modes come from the master. On macOS the child's exit revoked the terminal (the child led its
        # session), so every ioctl on our slave fd fails with EBADF; closing that fd first makes every system
        # behave alike. The master reports the terminal's modes on macOS and Linux.
        os.close(slave)
        slave = None
        echo_on = bool(termios.tcgetattr(master)[3] & termios.ECHO)
    finally:
        try:
            os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            pass
        os.close(master)
        if slave is not None:
            os.close(slave)
    code = os.WEXITSTATUS(status) if os.WIFEXITED(status) else 128 + os.WTERMSIG(status)
    return out.decode(errors="replace").replace("\r", ""), code, echo_on


@unittest.skipUnless(os.name == "posix" and shells(), "needs bash and a pseudo-terminal")
class TestSetup(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        # A space in the sandbox path (as in a TMPDIR or HOME with one): the rewritten paths below are quoted.
        sb = cls.sb = Path(os.path.realpath(cls.tmp.name)) / "sand box"
        sb.mkdir()
        cls.q = q = shlex.quote(str(sb))
        cls.repo = sb / "repo"
        shutil.copytree(REPO, cls.repo, ignore=shutil.ignore_patterns(".git", "__pycache__"))
        text = (REPO / "setup.sh").read_text()
        for old, new in (("/usr/sbin/sysctl", "sysctl"), ("/Applications/", f"{q}/Applications/"),
                         ("/etc/hosts", f"{q}/hosts"), ("/Library/LaunchDaemons/", f"{q}/LaunchDaemons/"),
                         ("/sbin/ifconfig lo0", "ifconfig lo0"), ("/bin/launchctl ", "launchctl "),
                         ("/usr/bin/install ", "install ")):
            assert old in text, f"setup.sh has no {old!r} any more: update the sandbox rewrite"
            text = text.replace(old, new)
        for old in ("/etc/hosts", "/usr/sbin/", "/Library/LaunchDaemons", "/sbin/ifconfig lo0", "/bin/launchctl",
                    "/usr/bin/install"):
            assert old not in text, f"sandbox rewrite missed {old!r}"
        assert "<string>/sbin/ifconfig</string>" in text, "the LaunchDaemon must run the real /sbin/ifconfig"
        (cls.repo / "setup.sh").write_text(text)
        (cls.repo / "bin" / "secstack").unlink()
        (cls.repo / "bin" / "secstack").write_text(
            '#!/bin/sh\necho "secstack $*" >> "$SANDBOX/log"\n'
            'case "$1" in audit) exit "${FAKE_AUDIT_RC:-0}" ;; pentagi) exit "${FAKE_PENTAGI_RC:-0}" ;; esac\nexit 0\n')
        os.chmod(cls.repo / "bin" / "secstack", 0o755)
        cls.stubs = sb / "stubs"
        cls.stubs.mkdir()
        for name, body in STUBS.items():
            (cls.stubs / name).write_text("#!/bin/sh\n" + body)
            os.chmod(cls.stubs / name, 0o755)
        for app in ("Ollama.app", "5ire.app"):
            (sb / "Applications" / app).mkdir(parents=True)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        sb = self.sb
        for p in ("home", "clip", "log", "ps", "hosts", "LaunchDaemons", "lo0_alias", "launchd_loaded", "tmp"):
            if (sb / p).is_dir():
                shutil.rmtree(sb / p)
            elif (sb / p).exists():
                (sb / p).unlink()
        self.gh = sb / "home" / "GitHub"
        self.secops = self.gh / ".sec-ops"
        for d in ("env", "configs/generated"):
            (self.secops / d).mkdir(parents=True)
        (self.secops / "bin").symlink_to(self.repo / "bin")
        (self.secops / "configs" / "stack.conf").write_text("CHAT_MODEL=qwen3-4b-abliterated\nOLLAMA_NUM_PARALLEL=2\n")
        (self.secops / "configs" / "generated" / "5ire-mcp.json").write_text("{}\n")
        for d in ("ARTEX", "pentagi"):
            (self.gh / d).mkdir()
        (sb / "hosts").write_text("127.0.0.1 localhost\n")
        (sb / "LaunchDaemons").mkdir()
        (sb / "tmp").mkdir()
        self.env = {"HOME": str(sb / "home"), "SECSTACK_GH": str(self.gh), "SANDBOX": str(sb),
                    "FAKE_CLAIM": FAKE_CLAIM, "TERM": "dumb", "TMPDIR": str(sb / "tmp"),
                    "PATH": f"{self.stubs}:{os.path.dirname(sys.executable)}:/usr/bin:/bin"}

    def tearDown(self):
        self.assertNotIn("REFUSED", self.log(), "setup.sh tried to write a real system file")

    def clip(self):
        p = self.sb / "clip"
        return p.read_text() if p.exists() else ""

    def log(self):
        p = self.sb / "log"
        return p.read_text() if p.exists() else ""

    def sudo_log(self):
        return [line for line in self.log().splitlines() if line.startswith("sudo ")]

    @staticmethod
    def todo(out):
        """The "Still to do by hand" items, one per line, without their "  - "."""
        _, _, rest = out.partition("Still to do by hand:\n")
        return [line[4:] for line in rest.splitlines() if line.startswith("  - ")]

    def setup_pty(self, bash, args, script, timeout=30):
        return run_pty([bash, str(self.repo / "setup.sh")] + args, self.env, script, timeout)

    def setup_plain(self, bash, args, wrap=lambda argv: argv):
        r = subprocess.run(wrap([bash, str(self.repo / "setup.sh")] + args), env=self.env,
                           stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60)
        return r.stdout + r.stderr, r.returncode

    def other_path_to(self, real):
        """(path, wrap): a second path to the folder `real`, spelled differently and not through a symlink,
        valid in a command run as wrap(argv). On a case-insensitive file system (macOS's default APFS) it is
        `real` in other case; elsewhere a bind mount in a private mount namespace. Skips the test if neither
        is possible."""
        real = Path(real)
        other = real.parent / real.name.swapcase()
        if other != real and other.exists() and os.path.samefile(other, real):
            return other, (lambda argv: argv)
        unshare = shutil.which("unshare")
        if unshare:
            alias = self.sb.parent / ("bind of " + real.name)
            alias.mkdir(exist_ok=True)

            def wrap(argv):
                return [unshare, "-rm", "sh", "-c", 'mount --bind "$1" "$2" && shift 2 && exec "$@"', "sh",
                        str(real), str(alias)] + list(argv)
            if subprocess.run(wrap(["true"]), capture_output=True).returncode == 0:
                return alias, wrap
        self.skipTest("needs a case-insensitive file system, or unshare and bind mounts")

    # ---------------------------------------------------------------- ARTEX setup value on the clipboard
    def test_artex_claim_cleared_from_clipboard_on_every_exit(self):
        for bash in shells():
            for how, action, want_rc in (("Enter", b"\r", 0), ("Ctrl-C", CTRL_C, 130),
                                         ("Ctrl-D", CTRL_D, 1), ("hangup", signal.SIGHUP, 130)):
                with self.subTest(bash=bash, how=how):
                    self.setUp()
                    out, rc, _ = self.setup_pty(bash, ["--only", "artex"], [("Press Enter when done.", action)])
                    self.assertIn("copied to the clipboard", out)
                    self.assertEqual(rc, want_rc, out)
                    self.assertEqual(self.clip(), "", f"setup value left on the clipboard after {how}:\n{out}")

    def test_artex_exit_keeps_what_the_user_copied_since(self):
        for bash in shells():
            with self.subTest(bash=bash):
                self.setUp()

                def user_copies_then_ctrl_c():
                    (self.sb / "clip").write_text("the admin password from my vault")
                    return CTRL_C
                out, rc, _ = self.setup_pty(bash, ["--only", "artex"],
                                            [("Press Enter when done.", user_copies_then_ctrl_c)])
                self.assertEqual(rc, 130, out)
                self.assertEqual(self.clip(), "the admin password from my vault")

    # ---------------------------------------------------------------- hidden prompt
    def test_ctrl_c_at_hidden_prompt_restores_echo(self):
        for bash in shells():
            with self.subTest(bash=bash):
                self.setUp()
                (self.sb / "lo0_alias").touch()
                out, rc, echo_on = self.setup_pty(bash, ["--only", "pentagi"], [("Enter to skip): ", CTRL_C)])
                self.assertEqual(rc, 130, out)
                self.assertTrue(echo_on, f"terminal left without echo by {bash}:\n{out}")
                self.assertFalse((self.secops / "env" / "pentagi-api-token").exists())

    # ---------------------------------------------------------------- /etc/hosts lines for api.axiom.co
    def hosts_run(self, bash, before, answer=b"y\r"):
        (self.sb / "hosts").write_text(before)
        script = [("[y/N] ", answer)] if answer else []
        out, rc, _ = self.setup_pty(bash, ["--only", "5ire"], script)
        self.assertEqual(rc, 0, out)
        return out, (self.sb / "hosts").read_text()

    def test_hosts_adds_only_the_missing_ipv6_line(self):
        for bash in shells():
            with self.subTest(bash=bash):
                self.setUp()
                out, after = self.hosts_run(bash, "127.0.0.1 localhost\n0.0.0.0 api.axiom.co\n")
                self.assertEqual(after, "127.0.0.1 localhost\n0.0.0.0 api.axiom.co\n:: api.axiom.co\n", out)

    def test_hosts_adds_only_the_missing_ipv4_line(self):
        for bash in shells():
            with self.subTest(bash=bash):
                self.setUp()
                out, after = self.hosts_run(bash, "127.0.0.1 localhost\n::1   api.axiom.co   # 5ire\n")
                self.assertEqual(after, "127.0.0.1 localhost\n::1   api.axiom.co   # 5ire\n0.0.0.0 api.axiom.co\n", out)

    def test_hosts_adds_both_lines_after_a_missing_final_newline(self):
        for bash in shells():
            with self.subTest(bash=bash):
                self.setUp()
                out, after = self.hosts_run(bash, "127.0.0.1 localhost\n# 0.0.0.0 api.axiom.co\n::1 localhost")
                self.assertEqual(after, "127.0.0.1 localhost\n# 0.0.0.0 api.axiom.co\n::1 localhost\n"
                                        "0.0.0.0 api.axiom.co\n:: api.axiom.co\n", out)

    def test_hosts_with_both_lines_asks_nothing(self):
        for bash in shells():
            with self.subTest(bash=bash):
                self.setUp()
                before = "127.0.0.1 localhost\n0.0.0.0 api.axiom.co\n:: api.axiom.co\n"
                out, after = self.hosts_run(bash, before, answer=None)
                self.assertEqual(after, before)
                self.assertIn("already blocked", out)
                self.assertNotIn("sudo", (self.sb / "log").read_text() if (self.sb / "log").exists() else "")

    def test_hosts_unattended_lists_only_the_missing_line(self):
        for bash in shells():
            with self.subTest(bash=bash):
                self.setUp()
                (self.sb / "hosts").write_text("0.0.0.0 api.axiom.co\n")
                out, rc = self.setup_plain(bash, ["--only", "5ire", "--yes"])
                self.assertEqual(rc, 0, out)
                self.assertIn(f"printf '\\n:: api.axiom.co\\n' | sudo tee -a {self.q}/hosts", out)
                self.assertNotIn("printf '\\n0.0.0.0", out)
                self.assertEqual((self.sb / "hosts").read_text(), "0.0.0.0 api.axiom.co\n")

    # ---------------------------------------------------------------- runtime root vs repo
    def test_preflight_refuses_runtime_folders_inside_the_repo(self):
        bash = shells()[0]
        out, rc = self.setup_plain(bash, ["--only", "preflight"])
        self.assertEqual(rc, 0, out)
        # a runtime folder symlinked into a repo folder, onto the repo itself, or into another repo folder
        for sub, target in (("configs", self.repo / "configs"), ("env", self.repo),
                            ("hexstrike-data", self.repo / "docs")):
            with self.subTest(sub=sub):
                self.setUp()
                p = self.secops / sub
                if p.exists():
                    shutil.rmtree(p)
                p.symlink_to(target)
                out, rc = self.setup_plain(bash, ["--only", "preflight"])
                self.assertEqual(rc, 1, out)
                self.assertIn("overlap", out)
                self.assertIn(str(p), out)
        with self.subTest(case="runtime root symlinked into the repo"):
            self.setUp()
            shutil.rmtree(self.secops)
            self.secops.symlink_to(self.repo / "rt")
            out, rc = self.setup_plain(bash, ["--only", "preflight"])
            self.assertEqual(rc, 1, out)
            self.assertIn("overlap", out)
            self.assertFalse((self.repo / "rt").exists())
        with self.subTest(case="SECOPS is the repo"):
            self.setUp()
            self.env["SECOPS"] = str(self.repo)
            out, rc = self.setup_plain(bash, ["--only", "preflight"])
            self.assertEqual(rc, 1, out)
            self.assertIn("overlap", out)
        with self.subTest(case="SECOPS contains the repo"):
            self.setUp()
            self.env["SECOPS"] = str(self.sb)
            out, rc = self.setup_plain(bash, ["--only", "preflight"])
            self.assertEqual(rc, 1, out)
            self.assertIn("overlap", out)

    def test_runtime_root_and_bin_link_are_compared_by_identity(self):
        # APFS ignores case, so ~/github/x is ~/GitHub/x: the same folder under another spelling (here, the
        # sandbox through a case change or a bind mount) must count as the same folder.
        bash = shells()[0]
        alias, wrap = self.other_path_to(self.sb)
        with self.subTest(case="runtime root holding the repo, spelled differently"):
            self.setUp()
            self.env["SECOPS"] = str(alias)
            out, rc = self.setup_plain(bash, ["--only", "preflight"], wrap)
            self.assertEqual(rc, 1, out)
            self.assertIn("overlap", out)
        with self.subTest(case="runtime configs/ in the repo, spelled differently"):
            self.setUp()
            shutil.rmtree(self.secops / "configs")
            (self.secops / "configs").symlink_to(alias / "repo" / "configs")
            out, rc = self.setup_plain(bash, ["--only", "preflight"], wrap)
            self.assertEqual(rc, 1, out)
            self.assertIn("overlap", out)
            self.assertIn(str(self.secops / "configs"), out)
        with self.subTest(case="runtime bin/ linked to the repo's bin, spelled differently"):
            self.setUp()
            (self.secops / "bin").unlink()
            (self.secops / "bin").symlink_to(alias / "repo" / "bin")
            out, rc = self.setup_plain(bash, ["--only", "audit"], wrap)
            self.assertEqual(rc, 0, out)
            self.assertIn("secstack audit", self.log())

    # ---------------------------------------------------------------- the test harness itself
    def test_pty_child_starts_with_default_signals(self):
        # A runner started with SIGINT or SIGHUP ignored (nohup, a background job) must not pass that on to
        # setup.sh, or its traps (and the Ctrl-C and hangup tests above) can't work.
        script = "trap 'exit 7' INT; trap 'exit 8' HUP; echo ready; while :; do sleep 0.1; done"
        saved = {s: signal.signal(s, signal.SIG_IGN) for s in (signal.SIGINT, signal.SIGHUP)}
        try:
            for bash in shells():
                for sig, want in ((signal.SIGINT, 7), (signal.SIGHUP, 8)):
                    with self.subTest(bash=bash, sig=sig):
                        out, rc, _ = run_pty([bash, "-c", script], self.env, [("ready", sig)], timeout=10)
                        self.assertEqual(rc, want, out)
        finally:
            for s, h in saved.items():
                signal.signal(s, h)

    def test_help_lists_the_steps_setup_runs(self):
        out, rc = self.setup_plain(shells()[0], ["--help"])
        self.assertEqual(rc, 0, out)
        steps = re.search(r'^STEPS="([^"]+)"$', (self.repo / "setup.sh").read_text(), re.M).group(1)
        self.assertIn(f"\nSteps: {steps}\n", out)
        self.assertIn("(both run preflight first)", out)
        self.assertIn("Exit status: 0 = ", out)

    # ---------------------------------------------------------------- items left for later
    def test_framework_items_start_their_framework(self):
        # The artex step stops pentagi, and `secstack pentagi` stops ARTEX: an item left for later starts its
        # framework itself, so the list works when followed in order.
        sync = "secstack providers --create-only && secstack templates --create-only"
        for bash in shells():
            for case, args, script in (
                    ("pentagi, unattended", ["--only", "pentagi", "--yes"], None),
                    ("pentagi, token skipped", ["--only", "pentagi"], [("Enter to skip): ", b"\r")]),
                    ("pentagi, not a token", ["--only", "pentagi"], [("Enter to skip): ", b"not a token!\r")])):
                with self.subTest(bash=bash, case=case):
                    self.setUp()
                    (self.sb / "lo0_alias").touch()
                    if script:
                        out, rc, _ = self.setup_pty(bash, args, script)
                    else:
                        out, rc = self.setup_plain(bash, args)
                    self.assertEqual(rc, 0, out)
                    items = [t for t in self.todo(out) if t.startswith("pentagi")]
                    self.assertEqual(len(items), 1, out)
                    self.assertRegex(items[0], r"^pentagi[^:]*: secstack pentagi; ")
                    self.assertTrue(items[0].endswith(sync), items[0])
            for case, status, conf, workers in (
                    ("unattended", None, "OLLAMA_NUM_PARALLEL=2\n", "concurrent workers to 2;"),
                    ("status unreadable", "not json", "OLLAMA_NUM_PARALLEL=2\n", "concurrent workers to 2"),
                    ("no plan value", None, "CHAT_MODEL=x\n", "concurrent workers to the plan's OLLAMA_NUM_PARALLEL")):
                with self.subTest(bash=bash, case="ARTEX, " + case):
                    self.setUp()
                    (self.secops / "configs" / "stack.conf").write_text(conf)
                    if status:
                        self.env["FAKE_ARTEX_STATUS"] = status
                    out, rc = self.setup_plain(bash, ["--only", "artex", "--yes"])
                    self.assertEqual(rc, 0, out)
                    items = [t for t in self.todo(out) if t.startswith("ARTEX")]
                    self.assertEqual(len(items), 1, out)
                    self.assertTrue(items[0].startswith("ARTEX: secstack artex; "), items[0])
                    self.assertIn("System > Settings > " + workers, items[0])

    def test_install_notes_reach_the_list(self):
        # install.sh's "note" and "keep    existing" lines ask for work by hand; with --yes they would scroll away.
        if not shutil.which("git"):
            self.skipTest("needs git")
        bash = shells()[0]
        # git looks no higher than the sandbox (a TMPDIR inside some checkout must not get hooks).
        self.env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=str(self.sb / "home" / ".gitconfig"),
                        GIT_CEILING_DIRECTORIES=str(self.sb))
        with open(self.sb / "home" / ".zshrc", "w") as f:
            f.write("export SECOPS=/old/place/.sec-ops\n")
        out, rc = self.setup_plain(bash, ["--only", "install", "--yes"])
        self.assertEqual(rc, 0, out)
        self.assertTrue(any(t.startswith("install.sh: ~/.zshrc sets SECSTACK_GH or SECOPS") for t in self.todo(out)),
                        out)
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True, env=self.env)
        try:
            hook = self.repo / ".git" / "hooks" / "pre-commit"
            hook.write_text("#!/bin/sh\necho mine\n")
            out, rc = self.setup_plain(bash, ["--only", "install", "--yes"])
            self.assertEqual(rc, 0, out)
            self.assertEqual(hook.read_text(), "#!/bin/sh\necho mine\n")
            self.assertTrue(any(t.startswith("install.sh kept your pre-commit hook") for t in self.todo(out)), out)
        finally:
            shutil.rmtree(self.repo / ".git")

    # ---------------------------------------------------------------- audit result and exit status
    def test_audit_result_reaches_the_exit_status(self):
        for bash in shells():
            for audit_rc, want_rc, says in ((0, 0, None), (1, 3, "the audit found issues"),
                                              (2, 2, "the audit could not check everything"),
                                              (9, 3, "the audit failed (exit 9")):
                with self.subTest(bash=bash, audit=audit_rc):
                    self.setUp()
                    self.env["FAKE_AUDIT_RC"] = str(audit_rc)
                    out, rc = self.setup_plain(bash, ["--only", "audit"])
                    self.assertEqual(rc, want_rc, out)
                    if says is None:
                        self.assertNotIn("setup finished, but", out)
                        self.assertEqual([t for t in self.todo(out) if "secstack audit" in t], [])
                        continue
                    self.assertIn(says, out)
                    self.assertIn(f"setup finished, but the audit", out.rsplit("Still to do by hand:", 1)[-1])
                    self.assertTrue([t for t in self.todo(out) if t.endswith("then: secstack audit")], out)

    def test_a_step_ending_with_2_or_3_exits_1(self):
        # 2 and 3 mean only "the steps ran, the audit didn't pass".
        for bash in shells():
            for step_rc in (2, 3):
                with self.subTest(bash=bash, rc=step_rc):
                    self.setUp()
                    (self.sb / "lo0_alias").touch()
                    self.env["FAKE_PENTAGI_RC"] = str(step_rc)
                    out, rc = self.setup_plain(bash, ["--only", "pentagi", "--yes"])
                    self.assertEqual(rc, 1, out)
                    self.assertIn(f'setup stopped in step "pentagi" (exit {step_rc})', out)
                    self.assertNotIn("setup finished", out)

    # ---------------------------------------------------------------- live work is not interrupted unasked
    def test_pentagi_step_asks_before_interrupting_a_flow(self):
        for bash in shells():
            for case in ("unattended", "asked, no"):
                with self.subTest(bash=bash, case=case):
                    self.setUp()
                    (self.sb / "ps").write_text("pentagi\npentagi-terminal-1a2b3c\n")
                    if case == "unattended":
                        out, rc = self.setup_plain(bash, ["--only", "pentagi", "--yes"])
                    else:
                        out, rc, _ = self.setup_pty(bash, ["--only", "pentagi"], [("[y/N] ", b"n\r")])
                        self.assertIn("pentagi flow", out)
                    self.assertEqual(rc, 0, out)
                    self.assertNotIn("secstack pentagi", self.log())
                    self.assertIn("Finish the pentagi step later: ./setup.sh --only pentagi", self.todo(out))

    def test_pentagi_step_waits_for_the_loopback_alias(self):
        # `secstack pentagi` refuses without 127.0.0.2 on lo0, so a fresh Mac that declined the loopback step
        # gets an item for later instead of a stopped run.
        for bash in shells():
            with self.subTest(bash=bash):
                self.setUp()
                out, rc = self.setup_plain(bash, ["--only", "pentagi", "--yes"])
                self.assertEqual(rc, 0, out)
                self.assertNotIn("secstack pentagi", self.log())
                items = [t for t in self.todo(out) if "127.0.0.2" in t]
                self.assertEqual(len(items), 1, out)
                self.assertIn("./setup.sh --only loopback", items[0])
                self.assertIn("./setup.sh --only pentagi", items[0])

    # ---------------------------------------------------------------- 127.0.0.2 on lo0 (loopback step)
    def daemon(self):
        return self.sb / "LaunchDaemons" / "com.secstack.lo0-alias.plist"

    def assert_daemon(self):
        p = self.daemon()
        self.assertEqual(plistlib.loads(p.read_bytes()), LO0_DAEMON)
        self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o644)

    def test_loopback_asks_then_adds_the_alias_now_and_at_boot(self):
        for bash in shells():
            with self.subTest(bash=bash):
                self.setUp()
                out, rc, _ = self.setup_pty(bash, ["--only", "loopback"], [("[y/N] ", b"y\r")])
                self.assertEqual(rc, 0, out)
                self.assert_daemon()
                self.assertTrue((self.sb / "lo0_alias").exists(), out)
                plist, sudo = str(self.daemon()), self.sudo_log()
                self.assertRegex(sudo[0], r"^sudo install -m 644 -o root -g wheel \S.*/secstack-lo0\.\w+ "
                                 + re.escape(plist) + "$")
                self.assertLess(sudo.index("sudo launchctl bootout system/com.secstack.lo0-alias"),
                                sudo.index(f"sudo launchctl bootstrap system {plist}"))
                self.assertIn("sudo ifconfig lo0 alias 127.0.0.2 up", sudo)
                self.assertEqual(sudo[-1], "sudo -k")
                self.assertEqual(list((self.sb / "tmp").iterdir()), [], "temporary plist left behind")
                self.assertEqual([t for t in self.todo(out) if "127.0.0.2" in t], [])
                # Again: nothing missing, so no question and no sudo.
                (self.sb / "log").unlink()
                out, rc, _ = self.setup_pty(bash, ["--only", "loopback"], [], timeout=15)
                self.assertEqual(rc, 0, out)
                self.assertIn("adds it at every boot", out)
                self.assertNotIn("[y/N]", out)
                self.assertEqual(self.sudo_log(), [])

    def test_loopback_declined_or_unattended_is_left_for_later(self):
        for bash in shells():
            for case in ("declined", "unattended"):
                with self.subTest(bash=bash, case=case):
                    self.setUp()
                    if case == "declined":
                        out, rc, _ = self.setup_pty(bash, ["--only", "loopback"], [("[y/N] ", b"n\r")])
                    else:
                        out, rc = self.setup_plain(bash, ["--only", "loopback", "--yes"])
                    self.assertEqual(rc, 0, out)
                    self.assertFalse(self.daemon().exists())
                    self.assertFalse((self.sb / "lo0_alias").exists())
                    self.assertEqual(self.sudo_log(), [])
                    items = [t for t in self.todo(out) if "127.0.0.2" in t]
                    self.assertEqual(len(items), 1, out)
                    self.assertIn("./setup.sh --only loopback", items[0])
                    self.assertIn("sudo ifconfig lo0 alias 127.0.0.2 up", items[0])

    def test_loopback_does_only_what_is_missing(self):
        other = dict(LO0_DAEMON, ProgramArguments=["/sbin/ifconfig", "lo0", "alias", "127.0.0.3", "up"])
        for bash in shells():
            with self.subTest(bash=bash, case="alias there, no daemon"):
                self.setUp()
                (self.sb / "lo0_alias").touch()
                out, rc, _ = self.setup_pty(bash, ["--only", "loopback"], [("[y/N] ", b"y\r")])
                self.assertEqual(rc, 0, out)
                self.assert_daemon()
                self.assertNotIn("ifconfig lo0 alias", self.log())
            with self.subTest(bash=bash, case="daemon there, alias gone"):
                (self.sb / "lo0_alias").unlink()
                (self.sb / "log").unlink()
                out, rc, _ = self.setup_pty(bash, ["--only", "loopback"], [("[y/N] ", b"y\r")])
                self.assertEqual(rc, 0, out)
                self.assertTrue((self.sb / "lo0_alias").exists(), out)
                self.assertEqual(self.sudo_log(), ["sudo ifconfig lo0 alias 127.0.0.2 up", "sudo -k"])
            with self.subTest(bash=bash, case="a different daemon file"):
                self.setUp()
                (self.sb / "lo0_alias").touch()
                self.daemon().write_bytes(plistlib.dumps(other))
                out, rc, _ = self.setup_pty(bash, ["--only", "loopback"], [("[y/N] ", b"y\r")])
                self.assertEqual(rc, 0, out)
                self.assertIn("(in place of the different one there)? Needs your sudo password.", out)
                self.assert_daemon()
                self.assertIn("sudo launchctl bootout system/com.secstack.lo0-alias", self.sudo_log())


class TestScriptModes(unittest.TestCase):
    def test_scripts_are_executable(self):
        files = [REPO / "setup.sh", REPO / "install.sh"]
        files += [p for p in sorted((REPO / "bin").iterdir()) if p.is_file() and p.read_bytes()[:2] == b"#!"]
        for pattern in ("scripts/*.sh", "scripts/*.py", "tests/func/*.sh"):
            files += sorted(REPO.glob(pattern))
        not_exec = [str(p.relative_to(REPO)) for p in files if not os.stat(p).st_mode & stat.S_IXUSR]
        self.assertEqual(not_exec, [], "run `chmod +x` on these (git keeps the bit)")


if __name__ == "__main__":
    unittest.main()
