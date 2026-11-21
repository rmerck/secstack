#!/usr/bin/env python3
"""check_secrets.py: the guard behind scripts/check-secrets.sh (run it through that script).

Blocks commits and pushes that would put secrets, engagement data (client names, past targets) or
live scope addresses into this repo. Modes:
  staged             what is staged: the pre-commit, pre-merge-commit and pre-applypatch hooks, and
                     the default when run by hand
  --all              every tracked and untracked (not ignored) file as it is on disk
  --push REMOTE URL  every commit, tag, message and file a push would add (the pre-push hook, ref
                     lines on stdin), so commits made with --no-verify, git am, cherry-pick or rebase
                     are checked before they leave
  --commit-msg FILE  a commit message (the commit-msg and applypatch-msg hooks)

Live scope is configs/scope.cidrs and the deny-list configs/never-commit.txt (client names, domains,
usernames, past targets: one per line, # comments) in the runtime root. A deny-list entry matches
as whole words, ignoring case, accents and punctuation, and also with its words run together
("ExampleCorp") or joined to another word at a capital or a digit ("ExampleCorpQ3.docx"); an
address or CIDR entry matches every address in it. In staged and push mode scope and the deny-list
are checked on the lines a change adds (for a merge, lines in no parent), so an old line that
happens to fall in today's scope doesn't block an unrelated edit; --all checks whole files. The
runtime root is $SECOPS, else `git config secstack.secops` (recorded by install.sh for git apps that
don't inherit SECOPS), else ~/GitHub/.sec-ops. If it can't be read, or a list exists but can't be
read, the check refuses (SECSTACK_NO_RUNTIME=1 runs everything except those two lists).

Git objects are read by id, never through pathspecs, and text is decoded the same way whatever the
locale. Output names paths (deny-list and scope matches masked), line numbers and key names, never a
matched value. Anything that can't be read or checked blocks.
"""
import base64
import fnmatch
import html
import ipaddress
import os
import re
import stat
import subprocess
import sys
import traceback
import unicodedata
import urllib.parse

if sys.version_info < (3, 9):
    sys.stderr.write("check-secrets: needs Python 3.9 or newer; refusing.\n")
    sys.exit(1)

A = re.ASCII
AI = re.ASCII | re.IGNORECASE
# pentest-net (172.30.0.0/24) and hexstrike-net (172.30.1.0/24), the lab on both: reserved, never a target
LAB_NETS = (ipaddress.ip_network("172.30.0.0/24"), ipaddress.ip_network("172.30.1.0/24"))
HOOK_MODES = {"pre-commit": "staged", "pre-merge-commit": "staged", "pre-applypatch": "staged",
              "commit-msg": "commit-msg", "applypatch-msg": "commit-msg", "pre-push": "push"}
ZERO = re.compile(r"0+\Z")
GITLINK = "160000"   # the git mode of a submodule pointer (a commit in another repo)
SHOW = 3      # line numbers shown per finding
DENY_LIST = "$SECOPS/configs/never-commit.txt"   # printed instead of the real path, which names the user

R_NEVER = "this path is never committed"
R_IGNORED = "path is in .gitignore (force-added?)"
R_BINARY = "binary file (reports, captures and archives don't belong in the repo; check it, then --no-verify)"
R_FILTER = ("stored through a filter (git-lfs or a clean filter), so the real content can't be "
            "checked; keep it out of the repo")
R_UNREADABLE = "couldn't read its content, so it can't be checked"
R_LINK = "symlink pointing outside the repo"
R_SCOPE = "live scope address"
R_PATH_SCOPE = "path holds a live scope address"
R_DENY = "matches " + DENY_LIST
R_PATH_DENY = "path matches " + DENY_LIST
R_FORMAT = "credential pattern"
R_ASSIGN = "secret-looking assignment (use @generators in env.overrides)"
R_KV = "secret-looking key/value"
R_CLI = "password on a command line"
R_URL = "credentials in a URL"
R_HEX = "bare hex token (setup tokens, generated secrets and hashes look like this)"
R_USERS = "a /Users/<name>/ path (use $HOME or ~)"


class Refuse(Exception):
    """Something couldn't be read or checked: refuse, with this reason."""


# ---------- text and git ----------

def decode(data):
    """Bytes to text the same way in every locale: invalid UTF-8 becomes U+FFFD, ASCII stays."""
    return data.decode("utf-8", "replace")


def other_decodings(data):
    """Text that isn't UTF-8 read as cp1252 and MacRoman too, so accented names still match."""
    try:
        data.decode("utf-8")
        return []
    except UnicodeDecodeError:
        return [data.decode("cp1252", "replace"), data.decode("mac_roman", "replace")]


def split_lines(text):
    return re.split(r"\r\n|\n|\r", text)


# ASCII words: an acronym before a capitalized word (HTTP|Server), a capitalized or lowercase word, digits
WORD_ASCII = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|[0-9]+")


def words(s):
    """Deny-list form: case, accents and width ignored; each run of other characters is one break,
    and so is each camelCase (aB, ABc) and letter/digit edge (ExampleCorpReport, examplecorp01, Q3)."""
    if s.isascii():   # fast path, the same split as the loop below
        return [w.lower() for w in WORD_ASCII.findall(s)]
    t = "".join(c for c in unicodedata.normalize("NFKD", s) if not unicodedata.combining(c))
    out, cur = [], []
    for k, c in enumerate(t):
        if not c.isalnum():
            if cur:
                out.append(cur)
                cur = []
            continue
        if cur:
            p = cur[-1]
            if (p.isdigit() != c.isdigit() or (p.islower() and c.isupper())
                    or (p.isupper() and c.isupper() and t[k + 1:k + 2].islower())):
                out.append(cur)
                cur = []
        cur.append(c)
    if cur:
        out.append(cur)
    folded = (unicodedata.normalize("NFKD", "".join(w).casefold()) for w in out)
    return ["".join(c for c in w if not unicodedata.combining(c)) for w in folded]


def norm_text(s):
    """Lowercase, accents dropped, runs of white space as one space: for entries like X&Y."""
    s = unicodedata.normalize("NFKD", unicodedata.normalize("NFKD", s).casefold())
    return " ".join("".join(c for c in s if not unicodedata.combining(c)).split())


def unescaped(line):
    """The line with %-escapes and HTML entities decoded (Example%20Corp, Example&amp;Co)."""
    return html.unescape(urllib.parse.unquote(line, errors="replace"))


def tilde(path):
    home = os.path.expanduser("~").rstrip("/")
    if home and (path == home or path.startswith(home + "/")):
        return "~" + path[len(home):]
    return path


def git(*args, stdin=None, ok=(0,)):
    """Run git. Its stderr is never shown: it can quote a path that names a client."""
    try:
        # GIT_NO_REPLACE_OBJECTS: read the real objects, the ones a push sends, never a `git replace` stand-in
        p = subprocess.run(("git",) + args, input=stdin, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, env=dict(os.environ, GIT_NO_REPLACE_OBJECTS="1"))
    except OSError as e:
        raise Refuse("can't run git (%s)" % (e.strerror or e))
    if p.returncode not in ok:
        raise Refuse("git %s failed (exit %d)" % (args[0], p.returncode))
    return p


def show_path(path):
    """A path for output: one line, control characters and undecodable bytes escaped."""
    s = os.fsencode(path).decode("utf-8", "backslashreplace")
    return "".join(c if c.isprintable() else "\\x%02x" % ord(c) if ord(c) < 256 else "\\u%04x" % ord(c)
                   for c in s)


# ---------- runtime root: live scope and the deny-list ----------

def norm_v4(tok):
    """'010.001.002.003/24' -> '10.1.2.3/24' (Python 3.9.5+ rejects leading zeros); else unchanged."""
    m = re.fullmatch(r"([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})(/[0-9]{1,2})?", tok)
    if not m:
        return tok
    return ".".join(str(int(o)) for o in m.groups()[:4]) + (m.group(5) or "")


def parse_net(s):
    s = s.strip()
    for tok in (s, (s.split() or [""])[0]):
        if tok:
            try:
                return ipaddress.ip_network(norm_v4(tok), strict=False)
            except ValueError:
                pass
    return None


class Runtime:
    def __init__(self):
        self.off = False
        self.nets = []        # (line in scope.cidrs, IPv4Network)
        self.deny_text = []   # (line in never-commit.txt, its words run together, exact text or None,
                              #  a pattern for its spacing variants or None)
        self.deny_nets = []   # (line in never-commit.txt, IPv4Network)


def runtime_root():
    env = os.environ.get("SECOPS", "")
    if env:
        return env, "from SECOPS"
    p = git("config", "--get", "secstack.secops", ok=(0, 1))
    rec = decode(p.stdout).strip()
    if p.returncode == 0 and rec:
        return os.path.expanduser(rec), "recorded in git config secstack.secops"
    gh = os.environ.get("SECSTACK_GH", "") or os.path.join(os.path.expanduser("~"), "GitHub")
    return os.path.join(gh, ".sec-ops"), "the default"


def read_list(path):
    """A list's bytes, or None when it doesn't exist. One that exists but can't be read refuses."""
    if not os.path.lexists(path):
        return None
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError as e:
        raise Refuse("can't read %s (%s), so nothing can be checked against it"
                     % (tilde(path), e.strerror or e))


def load_runtime():
    rt = Runtime()
    if os.environ.get("SECSTACK_NO_RUNTIME") == "1":
        rt.off = True
        return rt
    root, source = runtime_root()
    cfg = os.path.join(root, "configs")
    if not (os.path.isdir(cfg) and os.access(cfg, os.R_OK | os.X_OK)):
        raise Refuse("the runtime root %s (%s) has no readable configs/ folder, so live scope and "
                     "the deny-list can't be checked. Set SECOPS or run install.sh (or set "
                     "SECSTACK_NO_RUNTIME=1 to check everything else)" % (tilde(root), source))
    data = read_list(os.path.join(cfg, "scope.cidrs"))
    for n, line in enumerate(split_lines(decode(data or b"")), 1):
        net = parse_net(line.split("#")[0])
        if net is not None and net.version == 4:
            rt.nets.append((n, net))
    data = read_list(os.path.join(cfg, "never-commit.txt"))
    for n, line in enumerate(split_lines(decode(data or b"")), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        net = parse_net(s)
        if net is not None and net.version == 4:
            rt.deny_nets.append((n, net))
        elif words(s):
            # With a one-letter word (X&Y) the words alone would match "created_x": y, so such an
            # entry has to appear as written, or run together as one word.
            parts = re.findall(r"[^\W_]+", norm_text(s))   # its words between punctuation (X2 is one)
            exact = norm_text(s) if any(len(w) == 1 for w in parts) else None
            # ... or spaced differently: those words in order with only spaces, & and . between them
            # (X & Y, x y, x.y. example for X&Y Example), and no letter or digit on either side. Not
            # - or +: shell flags (-x -y) and code (x+y) aren't X&Y.
            flex = exact and re.compile(r"(?<![^\W_])%s(?![^\W_])" % r"[\s&.]*".join(map(re.escape, parts)))
            rt.deny_text.append((n, "".join(words(s)), exact, flex))
    return rt


# ---------- addresses (live scope, deny-list networks) and names ----------

DEFANG = re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.IGNORECASE)
V4_DOTS = re.compile(r"(?<![0-9])(?<![0-9]\.)([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})"
                     r"(?![0-9])(?!\.[0-9])")
V4_DASHES = re.compile(r"(?<![0-9])(?<![0-9]-)([0-9]{1,3})-([0-9]{1,3})-([0-9]{1,3})-([0-9]{1,3})"
                       r"(?![0-9])(?!-[0-9])")   # ip-10-1-2-3.ec2.internal


def addresses(text):
    t = DEFANG.sub(".", text)
    for rx in (V4_DOTS, V4_DASHES):
        for m in rx.finditer(t):
            octets = [int(o) for o in m.groups()]
            if max(octets) <= 255:
                yield ipaddress.IPv4Address(".".join(str(o) for o in octets))


def scope_entry(rt, addr):
    if any(addr in n for n in LAB_NETS):
        return None
    for n, net in rt.nets:
        if addr in net:
            return n
    return None


def deny_net_entry(rt, addr):
    for n, net in rt.deny_nets:
        if addr in net:
            return n
    return None


def deny_entry(rt, toks, text=None):
    """The never-commit.txt line of an entry found in these words (of text): as whole words, alone or
    run together (ExampleCorp), never inside a longer word (XYZ isn't in GitHub/xyzzy/secstack) but
    maybe joined to one at a capital or a digit (ExampleCorpReport, examplecorp01)."""
    if not toks or not rt.deny_text:
        return None
    joined = "".join(toks)
    bounds, pos = {0}, 0
    for t in toks:
        pos += len(t)
        bounds.add(pos)
    nt = runs = coarse = None
    for n, e, exact, flex in rt.deny_text:
        if exact is not None:
            if text is None:
                if e in toks:
                    return n
                continue
            if nt is None:
                nt = norm_text(text)
                runs = set(re.findall(r"[^\W_]+", nt))
            # run together only as a word between punctuation: xy, but not xy1 or getXy, for X&Y
            if e in runs or exact in nt or flex.search(nt):
                return n
            continue
        k = joined.find(e)
        while k != -1:
            if k in bounds and k + len(e) in bounds:
                if text is None or not (e[0].isdigit() or e[-1].isdigit()):
                    return n
                # digits at either end of the entry are a whole number in the text: 3X isn't in
                # "python3 -x" (a letter there may still meet a digit: examplecorp01)
                coarse = coarse_bounds(text) if coarse is None else coarse
                if (k in coarse or not e[0].isdigit()) and (k + len(e) in coarse or not e[-1].isdigit()):
                    return n
            k = joined.find(e, k + 1)
    return None


def coarse_bounds(s):
    """Offsets in "".join(words(s)) where a run of letters and digits between other characters starts
    or ends (camelCase and letter/digit edges inside a run aren't among them)."""
    if not s.isascii():
        s = "".join(c for c in unicodedata.normalize("NFKD", s) if not unicodedata.combining(c))
    out, pos = {0}, 0
    for run in re.findall(r"[^\W_]+", s):
        pos += sum(len(w) for w in words(run))
        out.add(pos)
    return out


def variants(line):
    v = unescaped(line)
    return [line] if v == line else [line, v]


def sensitive(s, rt):
    """True if s names a deny-listed thing or holds a live scope or deny-listed address."""
    if any(deny_entry(rt, words(v), v) for v in variants(s)):
        return True
    return any(scope_entry(rt, a) or deny_net_entry(rt, a) for a in addresses(s))


def mask_path(path, rt):
    """The path for output, with any component that names a deny-listed thing or address masked;
    all of it when only the whole path matches (example/corp.md for Example Corp)."""
    parts = path.split("/")
    out = ["****" if sensitive(p, rt) else p for p in parts]
    if out == parts and sensitive(path, rt):
        return "****"
    return show_path("/".join(out))


# ---------- what counts as a secret ----------

FORMATS = [(name, re.compile(rx, A)) for name, rx in (
    ("JWT", r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}"),
    ("private key block", r"-----BEGIN[A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----"
                          r"|---- BEGIN SSH2 ENCRYPTED PRIVATE KE[Y] ----"),
    ("PuTTY private key", r"PuTTY-User-Key-Fil[e]-"),
    ("AWS access key ID", r"(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])"),
    ("API key (sk-, xai-, gsk_)", r"(?<![A-Za-z0-9])(?:(?:sk|xai)-[A-Za-z0-9_-]{20,}|gsk_[A-Za-z0-9]{20,})"),
    ("GitHub token", r"(?<![A-Za-z0-9])(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})"),
    ("Hugging Face token", r"(?<![A-Za-z0-9])hf_[A-Za-z0-9]{30,}"),
    ("GitLab token", r"glpat-[A-Za-z0-9_-]{20,}"),
    ("Slack token", r"(?<![A-Za-z0-9])(?:xox[abposre]-[A-Za-z0-9-]{10,}|xapp-[0-9]-[A-Za-z0-9-]{10,})"),
    ("Google API key", r"AIza[0-9A-Za-z_-]{35}"),
    ("Google OAuth client secret", r"GOCSPX-[A-Za-z0-9_-]{20,}"),
    ("Slack webhook", r"hooks\.slack\.com/services/[A-Za-z0-9/]{8,}"),
    ("Discord webhook", r"discord(?:app)?\.com/api/webhooks/[0-9]{8,}"),
    ("Stripe key", r"(?<![A-Za-z0-9])[rs]k_(?:live|test)_[0-9A-Za-z]{16,}"),
    ("SendGrid key", r"(?<![A-Za-z0-9])SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}"),
    ("npm token", r"(?<![A-Za-z0-9])npm_[A-Za-z0-9]{36}"),
    ("PyPI token", r"pypi-AgE[A-Za-z0-9_-]{20,}"),
    ("Docker Hub token", r"dckr_pat_[A-Za-z0-9_-]{20,}"),
    ("Azure storage key", r"(?:AccountKey|SharedAccessKey)\s*=\s*[A-Za-z0-9+/]{20,}"),
    ("Azure SAS signature", r"[?&]sig=[A-Za-z0-9%+/=]{16,}"),
    ("password hash", r"\$(?:1|5|6|md5|apr1|sha1)\$[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{20,}"
                      r"|\$2[abxy]?\$[0-9]{2}\$[./0-9A-Za-z]{53}"
                      r"|\$(?:y|gy|7)\$[./0-9A-Za-z]+\$[./0-9A-Za-z]+\$[./0-9A-Za-z]{20,}"),
)]
BEARER = re.compile(r"\bbearer\s+([A-Za-z0-9._~+/=-]{16,})", AI)
BASIC = re.compile(r"authorization[\"']?\s*[:=]\s*[\"']?basic\s+([A-Za-z0-9+/]{8,}=*)", AI)
B64_PEM = re.compile(r"LS0tLS1CRUdJTi[A-Za-z0-9+/=]{20,}", A)   # base64 of a PEM block (kubeconfig)

KEY = r"[A-Za-z_][A-Za-z0-9_.-]{0,63}"
KV_QUOTED = re.compile(r"""(?<![A-Za-z0-9_.-])\\*["'`]?(?P<key>%s)\\*["'`]?\s*(?:=>|:=|=|:)\s*"""
                       r"""\\*(?P<q>["'`])(?P<val>[^"'`\\\s]{8,})\\*(?P=q)""" % KEY, A)
KV_START = re.compile(r"""^\s*(?:(?:[-*+>]|[0-9]+[.)])\s+)*"""
                      r"""(?:(?:export|env|arg|set|setenv|local|declare|typeset|readonly)\s+(?:-[A-Za-z]+\s+)*)?"""
                      r"""[*_]{0,2}["'`]?(?P<key>%s)["'`]?[*_]{0,2}[ \t]*(?P<sep>=|:)[*_]{0,2}[ \t]*"""
                      r"""(?P<val>[^\s"'`]\S*)""" % KEY, AI)
KV_EQ = re.compile(r"""(?<![A-Za-z0-9_.-])(?P<key>%s)[ \t]*=[ \t]*(?P<val>[^\s"'`=&;,)\]}|]+)""" % KEY, A)
KV_COLON = re.compile(r"""(?<![A-Za-z0-9_.-])(?P<key>%s)[*_]{0,2}:[*_]{0,2}[ \t]+(?P<val>[^\s"'`,]+)""" % KEY, A)
DOCKER_ENV = re.compile(r"^\s*(?:ENV|ARG)\s+(?P<key>[A-Za-z_][A-Za-z0-9_]*)\s+(?P<val>[^\s=\"'`]\S*)\s*$", AI)
BLOCK_KEY = re.compile(r"""^(?P<ind>[ \t]*)(?:-[ \t]+)?["']?(?P<key>%s)["']?[ \t]*:[ \t]*"""
                       r"""(?:[|>][-+0-9]*)?[ \t]*(?:#.*)?$""" % KEY, A)
LIST_KEY = re.compile(r"""^(?P<ind>[ \t]*)(?:-[ \t]+)?["']?(?P<key>%s)["']?[ \t]*:[ \t]*"""
                      r"""(?:\[(?P<inline>[^\]]*)\])?[ \t]*(?:#.*)?$""" % KEY, A)
LIST_ITEM = re.compile(r"""^(?P<ind>[ \t]*)-[ \t]+["']?(?P<val>[^\s"'#]+)["']?[ \t]*(?:#.*)?$""", A)
GETENV = re.compile(r"""\b(?:getenv|get|fetch|env)\(\s*["'](?P<key>[A-Za-z_][A-Za-z0-9_.-]{0,63})["']\s*,\s*"""
                    r"""["'](?P<val>[^"'\\\s]{8,})["']""", A)
XML_ELEM = re.compile(r"""<(?P<key>[A-Za-z_][A-Za-z0-9_.:-]{0,63})(?:\s[^<>]*)?>(?P<val>[^<>\s]{8,})</(?P=key)>""", A)

CLI_TOOL = re.compile(
    r"(?<![A-Za-z0-9_.-])(?:impacket-)?"   # the Kali names of the impacket scripts: impacket-psexec
    r"(?:sshpass|nxc|netexec|crackmapexec|cme|hydra|medusa|ncrack|patator|evil-winrm"
    r"|smbclient|smbmap|rpcclient|mysql|mysqldump|mysqladmin|mariadb|mssqlclient|sqlcmd|xfreerdp|wlfreerdp"
    r"|rdesktop|kerbrute|ldapsearch|winexe|enum4linux|enum4linux-ng|bloodhound-python|certipy|psexec"
    r"|wmiexec|smbexec|atexec|dcomexec|secretsdump|getuserspns|getnpusers|gettgt|getst|lookupsid)"
    r"(?:\.py)?(?![A-Za-z0-9_-])", AI)
CLI_SHORT = re.compile(r"""(?<!\S)(?:-[pw](?:[ \t]+|(?=[^\s-]))|/p:)\\?["']?(?P<val>[^\s"'\\]+)""", A)
CLI_SMB = re.compile(r"""(?<!\S)-U[ \t]*["']?[^\s"'%]+%(?P<val>[^\s"']+)""", A)
CLI_LONG = re.compile(r"""(?<!\S)--[A-Za-z0-9-]{0,40}?(?:password|passwd|pass|pwd|token|secret|api-?key)"""
                      r"""(?:=|[ \t]+)\\?["']?(?P<val>[^\s"'\\]+)""", AI)
CURL = re.compile(r"\bcurl\b", AI)
CURL_USER = re.compile(r"""(?<!\S)(?:-u|--user)(?:[ \t]+|=)?\\?["']?[^\s:"'\\]+:(?P<val>[^\s"'@\\]+)""", A)
IMPACKET = re.compile(r"""(?<![\w/.-])[\w.-]+/[\w.$-]+:(?P<val>[^\s@:'"/]{6,})@(?!sha256:|sha512:)[\w.-]+""", A)
# user:pass@host with no domain (impacket-psexec admin:X@10.0.0.5): only on a line with a CLI tool
IMPACKET_BARE = re.compile(r"""(?<![\w/.:@$-])[\w.$-]+:(?P<val>[^\s@:'"/]{6,})@(?!sha256:|sha512:)[\w.-]+""",
                           A)
# docker/podman login: -p is the registry password there (in docker run, -p is a port)
REG_LOGIN = re.compile(r"(?<![\w.-])(?:docker|podman|nerdctl|buildah|skopeo|oras|helm[ \t]+registry)"
                       r"[ \t]+login(?![\w-])", AI)
REDIS_CLI = re.compile(r"(?<![\w.-])redis-cli(?![\w-])", A)
REDIS_A = re.compile(r"""(?<!\S)-a[ \t]+\\?["']?(?P<val>[^\s"'`\\]+)""", A)   # redis-cli -a PASSWORD
# openssl -pass, -passin, -passout pass:X (env:VAR and file:PATH are fine)
OPENSSL_PASS = re.compile(r"""(?<!\S)-pass(?:in|out)?[ \t]+\\?["']?pass:(?P<val>[^\s"'`\\]+)""", A)
MSF_SET = re.compile(   # Metasploit: set PASSWORD X, setg SMBPass X, after a "msf6 ... >" prompt, in `code`,
    # or in msfconsole -x "...; set ...; run"
    r"""(?:^|[;"'`>])[ \t]*setg?[ \t]+(?P<key>[A-Za-z_][A-Za-z0-9_]*)[ \t]+(?P<val>[^\s;"'`]+)[ \t]*"""
    r"""(?=$|[;"'`])""", AI)
MSF_PASS = re.compile(r"pass\Z", re.IGNORECASE)   # SMBPass, FTPPASS, DBPASS: Metasploit's password options
NETRC = re.compile(   # a .netrc line in a heredoc, echo or any file: machine H [login U] [account A] password X
    r"""(?<![\w.-])machine[ \t]+\S+(?:[ \t]+(?:login|account)[ \t]+\S+){0,2}[ \t]+password[ \t]+\\?["']?"""
    r"""(?P<val>[^\s"'`\\]+)""", A)
# Docker's config.json "auth": "<base64 of user:pass>" and npm's _auth=<base64>
AUTH_B64 = re.compile(r"""(?<![A-Za-z0-9_.-])["']?(?P<key>_?auth)["']?[ \t]*[:=][ \t]*["']?"""
                      r"""(?P<val>[A-Za-z0-9+/]{8,}={0,2})(?![A-Za-z0-9+/=])""", AI)
URL_CREDS = re.compile(r"""(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]{0,31}://(?P<user>[^/\s:@"'<>]{1,256}):"""
                       r"""(?P<val>[^/\s@"'<>]{3,256})@""", A)
USERS = re.compile(r"/Users/(?P<name>[A-Za-z0-9._-]+)/", A)
USERS_OK = {"example", "someone", "shared", "you", "me", "user", "username", "name", "yourname"}
HEX = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{64}|[0-9A-Fa-f]{48}|[0-9A-Fa-f]{32})(?![0-9A-Fa-f])", A)
HEX_OK_BEFORE = re.compile(  # a digest or commit id, judged from just before the match on its line
    r"(?:sha-?(?:1|224|256|384|512)|md5|digest|checksum|--hash|commit|revision|weights|zh:)"   # not "hash": NTLM
    r"[^A-Za-z0-9]{0,4}(?:[A-Za-z0-9_-]{1,16}[^A-Za-z0-9]{1,4})?\Z", AI)
WELL_KNOWN_HEX = {   # hashes of nothing: not secrets
    "31d6cfe0d16ae931b73c59d7e0c089c0",    # NT hash of the empty password
    "aad3b435b51404eeaad3b435b51404ee",    # LM hash of the empty password
    "d41d8cd98f00b204e9800998ecf8427e",    # MD5 of nothing
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",   # SHA-256 of nothing
}

SECRET_WORDS = re.compile(r"password(?!s)|passwd|passphrase|secret(?!s)|credential|api[_-]?key|private[_-]?key"
                          r"|access[_-]?key|client[_-]?secret|accountkey|sharedaccesskey|signing[_-]?key"
                          r"|encryption[_-]?key|master[_-]?key", re.IGNORECASE)
SECRET_PARTS = {"pass", "pwd", "pw", "token", "salt", "sig", "signature"}
NOT_SECRET_TAIL = {"file", "path", "dir", "url", "uri", "env", "name", "type", "mode", "id", "field",
                   "header", "prompt", "hint", "label", "length", "len", "policy", "version", "count",
                   "size", "ttl", "timeout", "expiry", "expires", "format", "prefix", "suffix", "regex",
                   "pattern", "endpoint", "command", "cmd", "enabled", "required", "var", "variable",
                   "ref", "source", "location", "help", "description", "example", "min", "max",
                   "flag", "option", "arg", "opt"}
PROVIDERS = {"shodan", "censys", "virustotal", "securitytrails", "binaryedge", "chaos", "github", "gitlab",
             "hunter", "intelx", "passivetotal", "fofa", "zoomeye", "zoomeyeapi", "quake", "hunterhow",
             "fullhunt", "netlas", "leakix", "bevigil", "builtwith", "c99", "certspotter", "dnsdb",
             "dnsrepo", "facebook", "redhuntlabs", "threatbook", "whoisxmlapi", "urlscan", "bufferover",
             "alienvault", "robtex", "digitalyama", "dnsdumpster", "trickest", "rsecloud", "spyse"}
PLACEHOLDER = re.compile(
    r"(?:x{3,}|\*{3,}|\.{3,}|-{3,}|_{3,}|0+|changeme|change[_-]me|placeholder|redacted|example|dummy"
    r"|sample|notset|unset|none|null|nil|empty|tbd|todo|fixme|secret|password|passwd|pass|pwd|token"
    r"|apikey|api[_-]key|(?:your|insert|paste|put|enter|replace)[_-]?[a-z_-]*|[a-z_-]*[_-]here)\Z", AI)
PLACEHOLDER_START = re.compile(
    r"(?:redacted|changeme|change[_-]me|placeholder|example|dummy|sample|fake|test|xxx+)(?:[^A-Za-z0-9]|\Z)", AI)
SEQUENCE = "0123456789abcdefghijklmnopqrstuvwxyz0123456789"
CODE_EXT = {".py", ".pyw", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go", ".rb", ".java", ".kt",
            ".kts", ".scala", ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".rs", ".swift", ".m",
            ".mm", ".cs", ".php", ".pl", ".pm", ".lua", ".dart", ".groovy"}


def key_parts(key):
    return [p.lower() for p in re.split(r"[_.\-]+|(?<=[a-z0-9])(?=[A-Z])", key) if p]


def secret_kind(key):
    """'strong' for password/secret/token-like names, 'weak' for *_KEY names and recon providers
    (only random-looking values count), None otherwise."""
    parts = key_parts(key)
    if not parts or parts[-1] in NOT_SECRET_TAIL:
        return None
    if SECRET_WORDS.search(key) or any(p in SECRET_PARTS for p in parts):
        return "strong"
    if (len(parts) > 1 and parts[-1] == "key") or key.lower() in PROVIDERS:
        return "weak"
    return None


def clean(val):
    """An unquoted value without trailing punctuation: ',' ';' and closers it didn't open.
    Linear in the length of val: it walks back from the end once (a long value used to take minutes)."""
    end = len(val)
    while end >= 2 and val[end - 2] == "\\" and val[end - 1] in "nrt0":   # PASSWORD=x\n inside a string literal
        end -= 2
    v = val[:end].rstrip(",;")
    opener = {")": "(", "]": "[", "}": "{"}
    count = {c: v.count(c) for c in "()[]{}"}   # only closers are dropped, so only their counts change
    end = len(v)
    while end and v[end - 1] in opener and count[v[end - 1]] > count[opener[v[end - 1]]]:
        count[v[end - 1]] -= 1
        end -= 1
        while end and v[end - 1] in ",;":
            end -= 1
    return v[:end]


def plausible(v, minlen=8, quoted=False, code=False):
    """True if v could be a real secret, not a placeholder, reference or code expression."""
    if len(v) < minlen or v[0] in "$@%<-" or v.startswith(("/", "./", "../", "~/")):
        return False   # a variable, generator, format, placeholder, option or path
    if not quoted and v[0] in "([{&*!|>#~\\":
        return False   # code or structure, a YAML anchor, tag or block, a comment
    if re.fullmatch(r"[(\[{<].*[)\]}>]", v):
        return False   # [REDACTED], <your key>
    if PLACEHOLDER.match(v) or PLACEHOLDER_START.match(v) or "://" in v or placeholder_token(v):
        return False   # changeme, <set me>, sk-xxxxxxxx..., ...EXAMPLE...
    if re.fullmatch(r"(.{1,8}?)\1+", v) or v.lower() in SEQUENCE:
        return False   # aaaa..., abcabc..., 0123456789abcdef: test values, not secrets
    if any(t in v for t in ("${", "{{", "$(", "%(", ".*", ".+")):
        return False   # templates and regular expressions
    if not quoted:
        if any(c in v for c in "\"'`\\"):
            return False   # part of a quoted or escaped expression; real literals are checked quoted
        if re.match(r"[A-Za-z_][\w.]*[(\[]", v):
            return False   # a call or an index (get_password(), os.environ[...]): code, not a literal
        if re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+", v) or re.fullmatch(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+", v):
            return False   # an attribute or the name of another variable
        if re.fullmatch(r"[\w.-]+(?:/[\w.-]+)*\.[A-Za-z][A-Za-z0-9]{0,4}", v) and ("/" in v or not has_digit(v)):
            return False   # a file name (scripts/check-secrets.sh, config.yaml), not a secret
    return True


def has_digit(s):
    return any(c.isdigit() for c in s)


def made_up(v):
    """Mixes letters with digits or symbols, or is long: a password, not a word or a name."""
    symbols = re.search(r"[^A-Za-z0-9._/-]", v) is not None
    return len(v) >= 20 or (any(c.isalpha() for c in v) and (has_digit(v) or symbols))


def randomish(v):
    """At least 16 characters of letters and digits that aren't words: a generated key."""
    if len(v) < 16 or not has_digit(v) or not any(c.isalpha() for c in v) or re.search(r"\s", v):
        return False
    return not any(len(p) >= 4 and p.isalpha() and p.islower() for p in re.split(r"[-_.:/+=]", v))


def placeholder_token(s):
    """sk-xxxxxxxx..., AKIAIOSFODNN7EXAMPLE: documentation, not a credential."""
    tail = re.sub(r"[^A-Za-z0-9]", "", s)[-16:]
    return "EXAMPLE" in s.upper() or len(set(tail.lower())) <= 2


def b64_userpass(v):
    """True if v is base64 of user:password with a real-looking password (Docker's and npm's auth)."""
    try:
        s = base64.b64decode(v + "=" * (-len(v) % 4), validate=True).decode("utf-8")
    except ValueError:   # not base64, or not text (binascii.Error and UnicodeDecodeError are ValueErrors)
        return False
    user, sep, pw = s.partition(":")
    return bool(sep and user and s.isprintable() and plausible(pw, minlen=6, quoted=True))


def b64_private_key(line):
    for m in B64_PEM.finditer(line):
        chunk = m.group(0)[:200]
        try:
            if b"PRIVATE KEY" in base64.b64decode(chunk[:len(chunk) // 4 * 4]):
                return True
        except ValueError:
            pass
    return False


def is_code(path, data):
    if os.path.splitext(path)[1].lower() in CODE_EXT:
        return True
    first = data[:200].split(b"\n", 1)[0]
    return first.startswith(b"#!") and re.search(rb"python|node|ruby|perl|php", first) is not None


# ---------- findings ----------

class Findings:
    def __init__(self):
        self.hits = {}    # reason -> [(line, label)]

    def add(self, reason, line=None, label=None):
        lst = self.hits.setdefault(reason, [])
        if line is None or all(ln != line for ln, _ in lst):
            lst.append((line, label))


def key_label(key, rt):
    if (re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,39}", key) and not sensitive(key, rt)
            and not re.search(r"[A-Za-z0-9]{16,}|[0-9A-Fa-f]{12,}", key)):
        return key + " = ****"
    return "(key hidden)"


def kv_hit(key, val, code=False, quoted=False, prose=False, kind=None):
    """Is `key <sep> val` a secret? Strong names take any plausible value (made-up ones in code and
    prose); *_KEY names and recon providers only random-looking ones. kind: the caller's own judgment
    of the name, when secret_kind doesn't know it (SMBPass)."""
    kind = kind or secret_kind(key)
    v = val if quoted else clean(val)
    if not kind or not plausible(v, quoted=quoted, code=code):
        return False
    if kind == "weak":
        return randomish(v)
    return made_up(v) if (prose or (code and not quoted)) else True


def scan_text(text, rt, f, code=False, identity=False, check=None, others=()):
    """Check text line by line; record findings in f. Labels never hold a matched value.
    check: the line numbers to check against live scope and the deny-list (None: every line).
    others: other decodings of the same bytes (same lines), for the deny-list."""
    lines = split_lines(text)
    alts = [split_lines(t) for t in others]
    toks = None
    if rt.deny_text:
        toks = []
        for k, line in enumerate(lines):
            vs = variants(line) + [a[k] for a in alts if k < len(a) and a[k] != line]
            toks.append([(words(v), v) for v in vs])
    kv_lines, list_key, list_ind = set(), None, -1
    for i, line in enumerate(lines, 1):
        if check is None or i in check:
            for a in addresses(line):
                n = scope_entry(rt, a)
                if n:
                    f.add(R_SCOPE, i, "an address in live scope entry #%d" % n)
                n = deny_net_entry(rt, a)
                if n:
                    f.add(R_DENY, i, "deny-list entry on line %d" % n)
        if toks is not None:
            n = None
            if check is None or i in check:
                n = next((m for m in (deny_entry(rt, w, v) for w, v in toks[i - 1]) if m), None)
            if n is None and i < len(lines) and (check is None or i in check or i + 1 in check):
                # a name wrapped onto the next line: found only when the two lines are read together
                if not deny_entry(rt, *toks[i - 1][0]) and not deny_entry(rt, *toks[i][0]):
                    n = deny_entry(rt, toks[i - 1][0][0] + toks[i][0][0],
                                   toks[i - 1][0][1] + "\n" + toks[i][0][1])
            if n:
                f.add(R_DENY, i, "deny-list entry on line %d" % n)
        if identity:
            continue
        for name, rx in FORMATS:
            if any(not placeholder_token(m.group(0)) for m in rx.finditer(line)):
                f.add(R_FORMAT, i, name)
        if any(has_digit(m.group(1)) and not placeholder_token(m.group(1)) for m in BEARER.finditer(line)):
            f.add(R_FORMAT, i, "bearer token")
        if any((has_digit(m.group(1)) or len(m.group(1)) >= 16) and not placeholder_token(m.group(1))
               for m in BASIC.finditer(line)):
            f.add(R_FORMAT, i, "basic auth header")
        if b64_private_key(line):
            f.add(R_FORMAT, i, "base64 private key")

        def kv(reason, key, at=None):
            kv_lines.add(at or i)
            f.add(reason, at or i, key_label(key, rt))
        for rx in (KV_QUOTED, GETENV, XML_ELEM):
            m = next((m for m in rx.finditer(line) if kv_hit(m.group("key"), m.group("val"), code, True)), None)
            if m and i not in kv_lines:
                kv(R_KV, m.group("key"))
        if i not in kv_lines:
            m = KV_START.match(line)
            if m and kv_hit(m.group("key"), m.group("val"), code):
                kv(R_ASSIGN if m.group("sep") == "=" else R_KV, m.group("key"))
            else:
                m = DOCKER_ENV.match(line)
                if m and kv_hit(m.group("key"), m.group("val"), code):
                    kv(R_ASSIGN, m.group("key"))
        if i not in kv_lines:
            m = next((m for m in KV_EQ.finditer(line) if kv_hit(m.group("key"), m.group("val"), code)), None)
            if m:
                kv(R_ASSIGN, m.group("key"))
        if i not in kv_lines:   # "... password: X" inside prose or a flow map: only made-up values
            m = next((m for m in KV_COLON.finditer(line)
                      if kv_hit(m.group("key"), m.group("val").rstrip(".:"), code, prose=True)), None)
            if m:
                kv(R_KV, m.group("key"))
        if i not in kv_lines:   # Metasploit set/setg NAME VALUE: made-up values only, as in prose
            m = next((m for m in MSF_SET.finditer(line)
                      if kv_hit(m.group("key"), m.group("val"), code, prose=True,
                                kind="strong" if MSF_PASS.search(m.group("key")) else None)), None)
            if m:
                kv(R_ASSIGN, m.group("key"))
        if i not in kv_lines:   # machine H login U password X (.netrc written by a script or shown in docs)
            m = next((m for m in NETRC.finditer(line) if kv_hit("password", m.group("val"), code)), None)
            if m:
                kv(R_KV, "password")
        if i not in kv_lines:   # "auth": "<base64 of user:pass>" (Docker config.json), _auth= (.npmrc)
            m = next((m for m in AUTH_B64.finditer(line) if b64_userpass(m.group("val"))), None)
            if m:
                kv(R_KV, m.group("key"))
        if not code:
            m = BLOCK_KEY.match(line)
            if m and secret_kind(m.group("key")) == "strong":   # key: |  or  key:  with the value below
                j = next((k for k in range(i, len(lines)) if lines[k].strip()), None)
                if j is not None:
                    nxt = lines[j]
                    tok = nxt.strip()
                    if (len(nxt) - len(nxt.lstrip(" \t")) > len(m.group("ind"))
                            and not re.search(r"\s|:\s|:$|=", tok) and plausible(tok)):
                        kv(R_KV, m.group("key"), j + 1)
            # recon tool key lists (subfinder): shodan: [KEY] or shodan: then "- KEY" lines
            m = LIST_KEY.match(line)
            item = LIST_ITEM.match(line)
            if m and (secret_kind(m.group("key")) or m.group("key").lower() in PROVIDERS):
                list_key, list_ind = m.group("key"), len(m.group("ind"))
                inline = [p.strip(" \t\"'") for p in (m.group("inline") or "").split(",")]
                if any(randomish(q) for p in inline for q in p.split(":")):
                    kv(R_KV, list_key)
            elif item and list_key and len(item.group("ind")) >= list_ind:
                if any(randomish(q) for q in item.group("val").split(":")):
                    kv(R_KV, list_key)
            elif line.strip() and len(line) - len(line.lstrip(" \t")) <= list_ind:
                list_key = None
        cli = []
        if CLI_TOOL.search(line):
            cli += [m.group("val") for m in CLI_SHORT.finditer(line)]
            cli += [m.group("val") for m in CLI_SMB.finditer(line)]
            cli += [m.group("val") for m in IMPACKET_BARE.finditer(line)]
        elif REG_LOGIN.search(line):   # docker login -p X
            cli += [m.group("val") for m in CLI_SHORT.finditer(line)]
        if REDIS_CLI.search(line):   # redis-cli -a X
            cli += [m.group("val") for m in REDIS_A.finditer(line)]
        cli += [m.group("val") for m in OPENSSL_PASS.finditer(line)]
        if CURL.search(line):
            cli += [m.group("val") for m in CURL_USER.finditer(line)]
        cli += [m.group("val") for m in CLI_LONG.finditer(line)]
        cli += [m.group("val") for m in IMPACKET.finditer(line)]
        if any(not v.startswith("-") and plausible(clean(v), minlen=6) for v in cli):
            f.add(R_CLI, i, "(value hidden)")
        for m in URL_CREDS.finditer(line):
            v = m.group("val")
            if not (any(c in v for c in "${<") or v == m.group("user") or PLACEHOLDER.match(v)
                    or PLACEHOLDER_START.match(v)):
                f.add(R_URL, i, "(value hidden)")
                break
        for m in HEX.finditer(line):
            if (m.group(0).lower() not in WELL_KNOWN_HEX
                    and not HEX_OK_BEFORE.search(line[max(0, m.start() - 48):m.start()])):
                f.add(R_HEX, i, "(value hidden)")
                break
        if any(m.group("name").lower() not in USERS_OK for m in USERS.finditer(line)):
            f.add(R_USERS, i, "(name hidden)")


def added_lines(data, olds):
    """Line numbers of data whose text is in none of the old versions (all of them without one)."""
    old = set()
    for d in olds:
        if d is not None:
            old.update(split_lines(decode(d)))
    return {i for i, line in enumerate(split_lines(decode(data)), 1) if line not in old}


# ---------- paths ----------

ENV_OK_EXT = {"py", "sh", "bash", "zsh", "js", "mjs", "cjs", "ts", "go", "rb", "md", "example",
              "overrides", "sample", "template", "d.ts"}
NEVER = [
    ".env", "*/.env", "*.env", ".env.*", "*/.env.*", ".env-*", "*/.env-*", ".env_*", "*/.env_*",
    "*.env.*", ".envrc", "*/.envrc", "env/*", "*/env/*", "logs/*", "reports/*", "run/*", "cache/*",
    "hexstrike-data/*", "operations.md", "*/operations.md",
    "configs/scope.cidrs", "*/configs/scope.cidrs", "configs/scope.mode", "*/configs/scope.mode",
    "configs/mcp-servers.stash.json", "*/configs/mcp-servers.stash.json", "configs/stack.conf",
    "*/configs/stack.conf", "configs/models.selected.json", "*/configs/models.selected.json",
    "configs/generated/*", "*/configs/generated/*", "configs/pentagi-providers/*",
    "*/configs/pentagi-providers/*",
    "*.bak", "*.pre-repo-*", "*-api-token", "*-secret", "*-setup-token", "nvd-api-key", "*/nvd-api-key",
    "*.pem", "*.key", "*.p12", "*.pfx", "*.kdbx", "*.ovpn", "*.pcap", "*.pcapng", "*.pot", "*.ppk",
    "*.har", "id_rsa*", "*/id_rsa*", "id_ed25519*", "*/id_ed25519*", "id_ecdsa*", "*/id_ecdsa*",
    "id_dsa*", "*/id_dsa*", ".netrc", "*/.netrc", "_netrc", "*/_netrc", ".git-credentials",
    "*/.git-credentials", ".pgpass", "*/.pgpass",
    "models/exported/*.raw", "models/exported/ollama-list.txt",
]
NEVER_OK = ["*.env.example", "env.overrides", "*/env.overrides"]


def never_path(path):
    """Never-commit path rules: case-insensitive, trailing spaces and dots ignored ('.env ' is .env)."""
    p = "/".join(re.sub(r"[ .\t]+$", "", c) or c for c in path.split("/"))
    p = unicodedata.normalize("NFC", p).lower()
    if any(fnmatch.fnmatchcase(p, pat) for pat in NEVER_OK):
        return False
    if any(fnmatch.fnmatchcase(p, pat) for pat in NEVER):
        return True
    base = p.rsplit("/", 1)[-1]
    return base.startswith("env.") and base[4:] not in ENV_OK_EXT


def link_escapes(path, target):
    if target.startswith("/"):
        return True
    p = os.path.normpath(os.path.join(os.path.dirname(path), target))
    return p == ".." or p.startswith("../")


# ---------- checking one file ----------

class Item:
    """One file version to check. olds: the blob ids it replaces (lines found there aren't checked
    against scope and the deny-list), None to check every line. new_path: the path itself is new."""
    def __init__(self, path, mode, oid=None, commit=None, olds=None, new_path=True):
        self.path, self.mode, self.oid, self.commit = path, mode, oid, commit
        self.olds, self.new_path = olds, new_path


def check_item(it, data, olds, rt, ignored, filtered, report):
    f = Findings()
    where = mask_path(it.path, rt) + (" (commit %s)" % it.commit[:10] if it.commit else "")
    if never_path(it.path):
        f.add(R_NEVER)
        return report.add(where, f)
    if it.path in ignored:
        f.add(R_IGNORED)
    if it.new_path and sensitive(it.path, rt):
        if any(deny_entry(rt, words(v), v) for v in variants(it.path)) \
                or any(deny_net_entry(rt, a) for a in addresses(it.path)):
            f.add(R_PATH_DENY)
        if any(scope_entry(rt, a) for a in addresses(it.path)):
            f.add(R_PATH_SCOPE)
    if it.mode == GITLINK:   # only the path: the content is another repo's commit
        return report.add(where, f)
    if data is None:
        f.add(R_UNREADABLE)
        return report.add(where, f)
    check = None if olds is None else added_lines(data, olds)
    if it.mode == "120000":   # git stores the target; the file it points to is never read
        if link_escapes(it.path, os.fsdecode(data)):
            f.add(R_LINK)
        scan_text(decode(data), rt, f, check=check, others=other_decodings(data))
        return report.add(where, f)
    if it.path in filtered or data.startswith(b"version https://git-lfs.github.com/spec/"):
        f.add(R_FILTER)
        return report.add(where, f)
    if b"\0" in data:
        f.add(R_BINARY)
        return report.add(where, f)
    scan_text(decode(data), rt, f, code=is_code(it.path, data), check=check, others=other_decodings(data))
    return report.add(where, f)


class Report:
    def __init__(self):
        self.blocked = False
        color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
        self.tag = "\033[31mBLOCKED\033[0m" if color else "BLOCKED"

    def say(self, s):
        sys.stdout.buffer.write((s + "\n").encode("utf-8", "backslashreplace"))

    def add(self, where, f):
        for reason, hits in f.hits.items():
            self.blocked = True
            self.say("%s %s: %s" % (self.tag, where, reason))
            for line, label in [h for h in hits if h[0] is not None][:SHOW]:
                self.say("    line %d: %s" % (line, label))


# ---------- reading from git and disk ----------

def parse_raw(out):
    """`git diff --raw -z` output -> [(status, src mode, dst mode, src id, dst id, path)]."""
    toks = out.split(b"\0")
    res, i = [], 0
    while i < len(toks) - 1:
        head = toks[i].decode("ascii", "replace")
        if not head.startswith(":"):
            raise Refuse("unexpected git diff output")
        smode, dmode, soid, doid, status = head[1:].split(" ")
        npaths = 2 if status[:1] in ("R", "C") else 1
        res.append((status[:1], smode, dmode, soid, doid, os.fsdecode(toks[i + npaths])))
        i += 1 + npaths
    return res


def read_blobs(oids):
    uniq = list(dict.fromkeys(o for o in oids if o and not ZERO.match(o)))
    res = {}
    if not uniq:
        return res
    out = git("cat-file", "--batch", stdin=("\n".join(uniq) + "\n").encode()).stdout
    pos = 0
    for oid in uniq:
        nl = out.index(b"\n", pos)
        head = out[pos:nl].split()
        pos = nl + 1
        if len(head) == 3 and head[2].isdigit():
            size = int(head[2])
            res[oid] = out[pos:pos + size] if head[1] == b"blob" else None
            pos += size + 1
        else:
            res[oid] = None   # missing
    return res


def ignored_paths(paths):
    """Paths .gitignore (or the user's excludes) would ignore. check-ignore reads pathspecs, so each
    path goes in as ./path: a leading ':' is then a plain character, not pathspec magic."""
    if not paths:
        return set()
    p = git("check-ignore", "-z", "--stdin", "--no-index", ok=(0, 1),
            stdin=b"".join(b"./" + os.fsencode(x) + b"\0" for x in paths))
    return {os.fsdecode(x[2:] if x.startswith(b"./") else x) for x in p.stdout.split(b"\0") if x}


def filtered_paths(paths):
    """Paths with a filter attribute (git-lfs, clean filters), from the work tree's .gitattributes
    and the staged ones. check-attr takes plain path names."""
    found = set()
    if not paths:
        return found
    data = b"".join(os.fsencode(x) + b"\0" for x in paths)
    for extra in ((), ("--cached",)):
        out = git("check-attr", "-z", "--stdin", *extra, "filter", stdin=data).stdout
        toks = out.split(b"\0")
        for k in range(0, len(toks) - 2, 3):
            if toks[k + 2] not in (b"unspecified", b"unset", b"set"):
                found.add(os.fsdecode(toks[k]))
    return found


def toplevel():
    try:
        top = decode(git("rev-parse", "--show-toplevel").stdout).strip()
    except Refuse:
        top = ""
    if not top:
        raise Refuse("not inside a git work tree")
    os.chdir(top)


def check_items(items, rt, report, datas=None):
    paths = [it.path for it in items]
    ignored = ignored_paths(paths)
    filtered, olds = set(), [None] * len(items)
    if datas is None:
        filtered = filtered_paths(paths)
        files = [it for it in items if it.mode != GITLINK]   # a gitlink's id names no blob here
        blobs = read_blobs([it.oid for it in files] + [o for it in files for o in (it.olds or [])])
        datas = [blobs.get(it.oid) for it in items]
        olds = [None if it.olds is None else [blobs.get(o) for o in it.olds] for it in items]
    for it, data, old in zip(items, datas, olds):
        check_item(it, data, old, rt, ignored, filtered, report)


RAW = ("--no-color", "-z", "--raw", "--no-abbrev")


def raw_items(out, commit=None):
    items = []
    for status, smode, mode, soid, oid, path in parse_raw(out):
        if status in ("D", "U") or mode == "000000":
            continue   # deleted, or unmerged (git refuses those first)
        # a gitlink (a submodule, or a nested clone caught by `git add -A`) keeps its path checks;
        # what it points to is another repo's commit, never read
        before = [] if status == "A" or smode in ("000000", GITLINK) or mode == GITLINK else [soid]
        items.append(Item(path, mode, oid, commit, olds=before, new_path=status in ("A", "R", "C")))
    return items


def merge_heads():
    """The other side(s) of a merge being committed: GITHEAD_<id> in the environment of the
    pre-merge-commit hook (MERGE_HEAD isn't written yet then), MERGE_HEAD for `git commit` after a
    conflict."""
    heads = [k[8:] for k in os.environ if re.fullmatch(r"GITHEAD_[0-9a-f]{40,64}", k)]
    path = decode(git("rev-parse", "--git-path", "MERGE_HEAD").stdout).strip()
    try:
        with open(path, "rb") as fh:
            heads += [x for x in decode(fh.read()).split() if re.fullmatch(r"[0-9a-f]{40,64}", x)]
    except FileNotFoundError:
        pass
    except OSError as e:
        raise Refuse("can't read MERGE_HEAD (%s)" % (e.strerror or e))
    return list(dict.fromkeys(heads))


def run_staged(rt, report):
    toplevel()
    items = raw_items(git("diff", "--cached", "-M", "-C", *RAW).stdout)
    for mh in merge_heads():   # finishing a merge: lines either side already had aren't new
        other = {e[5]: e for e in parse_raw(git("diff", "--cached", "--no-renames", *RAW, mh).stdout)}
        for it in items:
            e = other.get(it.path)
            if e is None:   # the same as on the other side
                it.olds.append(it.oid)
                it.new_path = False
            elif e[1] != "000000":   # the other side has this path (a gitlink there: no lines to reuse)
                if e[1] != GITLINK:
                    it.olds.append(e[3])
                it.new_path = False
    check_items(items, rt, report)


def run_all(rt, report):
    toplevel()
    out = git("ls-files", "-z", "--cached", "--others", "--exclude-standard").stdout
    items, datas = [], []
    for path in dict.fromkeys(os.fsdecode(x) for x in out.split(b"\0") if x):
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            continue   # tracked but deleted on disk
        except OSError:
            items.append(Item(path, "100644"))
            datas.append(None)
            continue
        if stat.S_ISLNK(st.st_mode):   # never followed: git stores only the target
            items.append(Item(path, "120000"))
            datas.append(os.fsencode(os.readlink(path)))
        elif stat.S_ISREG(st.st_mode):
            try:
                with open(path, "rb") as fh:
                    data = fh.read()
            except OSError:
                data = None
            items.append(Item(path, "100644"))
            datas.append(data)
    check_items(items, rt, report, datas=datas)
    return len(items)


# ---------- messages and pushes ----------

def message_findings(raw, rt, where, report, identity=False):
    f = Findings()
    scan_text(decode(raw), rt, f, identity=identity, others=other_decodings(raw))
    report.add(where, f)


def run_commit_msg(rt, report, path):
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as e:
        raise Refuse("can't read the commit message (%s)" % (e.strerror or e))
    cc = decode(git("config", "--get", "core.commentChar", ok=(0, 1)).stdout).strip()
    cc = cc if cc and cc != "auto" else "#"
    lines = re.split(rb"\r\n|\n|\r", raw)
    ccb = cc.encode()
    # git drops comment lines (and anything below the scissors) only when its editor template says
    # so; a message from -m, -F or git am keeps them.
    template = any(ln.startswith(ccb) and b"will be ignored" in ln for ln in lines)
    keep = []
    for ln in lines:
        if template and re.fullmatch(re.escape(ccb) + rb" -{8,} >8 -{8,}", ln):
            break
        keep.append(b"" if template and ln.startswith(ccb) else ln)
    message_findings(b"\n".join(keep), rt, "commit message", report)


def object_exists(oid):
    return git("cat-file", "-e", oid, ok=(0, 1, 128)).returncode == 0


def commit_items(c):
    raw = git("cat-file", "commit", c).stdout
    head, _, msg = raw.partition(b"\n\n")
    parents = [ln.split()[1].decode() for ln in head.split(b"\n") if ln.startswith(b"parent ")]
    ident = b"\n".join(ln for ln in head.split(b"\n") if ln.startswith((b"author ", b"committer ")))
    if not parents:
        items = raw_items(git("diff-tree", "-r", "--root", "--no-commit-id", *RAW, c).stdout, c)
    elif len(parents) == 1:
        items = raw_items(git("diff-tree", "-r", "-M", "-C", *RAW, parents[0], c).stdout, c)
    else:   # a merge: only what differs from every parent is new in it, and only lines in none
        per = [{it.path: it for it in raw_items(git("diff-tree", "-r", "--no-renames", *RAW, p, c).stdout, c)}
               for p in parents]
        items = [it for path, it in per[0].items() if all(path in d for d in per[1:])]
        for it in items:
            it.olds = [o for d in per for o in d[it.path].olds]
            it.new_path = all(d[it.path].new_path for d in per)
    return items, msg, ident


def tag_chain(oid, ref, rt, report):
    """Check every tag message down a (possibly nested) tag; return the object it ends at, or None
    when that isn't a commit (a tag of a tree or a blob can't be checked)."""
    for _ in range(20):
        typ = decode(git("cat-file", "-t", oid).stdout).strip()
        if typ == "commit":
            return oid
        if typ != "tag":
            f = Findings()
            f.add("points at a %s rather than a commit, so it can't be checked" % typ)
            report.add("ref " + mask_path(ref, rt), f)
            return None
        raw = git("cat-file", "tag", oid).stdout
        head, _, body = raw.partition(b"\n\n")
        message_findings(body, rt, "tag %s message" % mask_path(ref, rt), report)
        message_findings(b"\n".join(ln for ln in head.split(b"\n") if ln.startswith(b"tagger ")),
                         rt, "tag %s tagger" % mask_path(ref, rt), report, identity=True)
        oid = next(ln.split()[1].decode() for ln in head.split(b"\n") if ln.startswith(b"object "))
    f = Findings()
    f.add("is a chain of more than 20 tags, so it can't be checked")
    report.add("ref " + mask_path(ref, rt), f)
    return None


def run_push(rt, report, remote, stdin):
    toplevel()
    known = remote and re.fullmatch(r"[A-Za-z0-9._-]+", remote) and git(
        "config", "--get", "remote.%s.url" % remote, ok=(0, 1)).returncode == 0
    commits, seen = [], set()
    for line in decode(stdin).splitlines():
        parts = line.split()
        if not parts:
            continue
        if len(parts) != 4:
            raise Refuse("unexpected pre-push input")
        lref, loid, rref, roid = parts
        if ZERO.match(loid):
            continue   # deleting a remote ref adds nothing
        f = Findings()
        if sensitive(rref, rt):   # a branch or tag named after a client or a target
            f.add("ref name matches the deny-list or live scope")
        report.add("ref " + mask_path(rref, rt), f)
        tip = tag_chain(loid, rref, rt, report)
        if tip is None:
            continue
        args = ["rev-list", "--reverse", tip, "--not"]
        if known:
            args.append("--remotes=" + remote)
        if not ZERO.match(roid) and object_exists(roid):
            args.append(roid)
        for c in decode(git(*args).stdout).split():
            if c not in seen:
                seen.add(c)
                commits.append(c)
    items, done = [], set()
    for c in commits:
        its, msg, ident = commit_items(c)
        message_findings(msg, rt, "commit %s message" % c[:10], report)
        message_findings(ident, rt, "commit %s author/committer" % c[:10], report, identity=True)
        for it in its:
            k = (it.path, it.oid, tuple(sorted(it.olds or ())))
            if k not in done:
                done.add(k)
                items.append(it)
    check_items(items, rt, report)


# ---------- main ----------

USAGE = ("usage: check-secrets.sh [staged | --all | --push REMOTE URL | --commit-msg FILE\n"
         "                        | --hook NAME [hook args]]")


def main(argv):
    args = list(argv)
    if args[:1] == ["--hook"]:
        if len(args) < 2 or args[1] not in HOOK_MODES:
            sys.stderr.write("check-secrets: unknown hook %r; refusing\n" % (args[1:2] or [""])[0])
            return 1
        mode, args = HOOK_MODES[args[1]], args[2:]
    elif not args or args[0] in ("staged", "--staged"):
        mode, args = "staged", args[1:]
    elif args[0] in ("--all", "--push", "--commit-msg"):
        mode, args = args[0][2:], args[1:]
    else:
        sys.stderr.write(USAGE + "\n")
        return 2
    if (mode in ("staged", "all") and args) or (mode == "commit-msg" and len(args) != 1) \
            or (mode == "push" and len(args) > 2):
        sys.stderr.write(USAGE + "\n")
        return 2
    report = Report()
    try:
        rt = load_runtime()
        if rt.off:
            sys.stderr.write("check-secrets: live scope and the deny-list are not checked "
                             "(SECSTACK_NO_RUNTIME=1)\n")
        n = None
        if mode == "staged":
            run_staged(rt, report)
        elif mode == "all":
            n = run_all(rt, report)
        elif mode == "commit-msg":
            run_commit_msg(rt, report, args[0])
        else:
            run_push(rt, report, args[0] if args else "", sys.stdin.buffer.read())
    except Refuse as e:
        sys.stderr.write("check-secrets: %s; refusing.\n" % e)
        return 1
    except Exception as e:   # never echo data from an unexpected error, but never pass either
        where = traceback.extract_tb(e.__traceback__)[-1].lineno
        sys.stderr.write("check-secrets: internal error (%s at line %d); refusing.\n"
                         % (type(e).__name__, where))
        return 1
    if report.blocked:
        verb = "push" if mode == "push" else "commit"
        what = "the message" if mode == "commit-msg" else "the above"
        report.say("Fix %s, or if it's a false positive, check it carefully and %s with --no-verify."
                   % (what, verb))
        return 1
    if n is not None:
        report.say("check-secrets: %d files clean" % n)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
