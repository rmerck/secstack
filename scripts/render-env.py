#!/usr/bin/env python3
"""render-env.py: build an upstream .env from its .env.example plus a secstack overrides file.

Overrides are KEY=VALUE lines (blank lines and # comments allowed; anything else is an error, so a
typo can't silently leave an upstream default secret in place). Special values are generated fresh:
  @hex16 @hex24 @hex32   random hex (that many bytes)
  @alnum12               random letters+digits, 12 chars
  @b64_32                base64 of 32 random bytes (ARTEX_SECRET_KEY format)
  @GEN renewable         (e.g. "@hex24 renewable") nothing stores data under this secret, so a weak
                         existing value is replaced instead of stopping the run
  ${KEY}                 substituted from the overrides first, then from the --vars files (the plan's
                         stack.conf, upstream/images.lock). Vars values must be plain identifiers,
                         paths or image references; anything else counts as missing. An unresolved
                         ${KEY} is an error.

Files are read the way Docker Compose reads a .env file (a port of compose-go's dotenv parser):
lines end at \\n only; `export KEY=v`, leading whitespace, `KEY: v` and `KEY = v` all assign; a quoted
value can span lines and another assignment can follow it on the same line; the last assignment
wins. Every assignment of an override key is dropped from the upstream text and the overrides are
written as one block at the end, so nothing upstream wrote can override them. The result is parsed
again before it is written: if any override wouldn't come out exactly as rendered, nothing is written.

The output is written 0600 and never regenerated unless --force is given, because some secrets
(ARTEX_SECRET_KEY, database passwords) must match data that already exists.

--update-keys K1,K2 rewrites only those keys in an existing output (model names after re-planning,
image pins); every other line, secrets included, stays byte for byte. Keys whose value is a
generated secret are refused there: rotating them would lock you out of existing data.
--refresh rewrites every override key in an existing output: settings get their current values,
generated secrets keep the values the file has, values built from them are rebuilt, and a generated
key the file doesn't have yet is generated and added. An existing secret is kept when it looks like
its generator's output (48 hex characters for @hex24, ...) or is strong: at least 16 characters with
at least 8 different ones (so installers' own passwords and keys survive). The upstream example's
value never counts. Any other secret stops the run, unless its key is renewable: then it is replaced.
--get KEY --file PATH prints the value Compose would read for KEY from PATH (an empty line when it
isn't set) and exits 0; it exits 2 when PATH can't be read or Compose couldn't parse it.
The output is never written through a symlink.
"""
import argparse
import base64
import os
import re
import secrets
import string
import sys
import tempfile
import unicodedata

KV = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)=(.*)")
VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
SAFE_VAR = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/,@-]*")
GENERATORS = {
    "@hex16": lambda: secrets.token_hex(16),
    "@hex24": lambda: secrets.token_hex(24),
    "@hex32": lambda: secrets.token_hex(32),
    "@alnum12": lambda: "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12)),
    "@b64_32": lambda: base64.b64encode(secrets.token_bytes(32)).decode(),
}
# What a value made by each generator looks like; an existing secret must match its generator.
FORMATS = {
    "@hex16": (re.compile(r"[0-9a-f]{32}"), "32 lowercase hex characters"),
    "@hex24": (re.compile(r"[0-9a-f]{48}"), "48 lowercase hex characters"),
    "@hex32": (re.compile(r"[0-9a-f]{64}"), "64 lowercase hex characters"),
    "@alnum12": (re.compile(r"[A-Za-z0-9]{12}"), "12 letters and digits"),
    "@b64_32": (re.compile(r"[A-Za-z0-9+/]{43}="), "base64 of 32 bytes"),
}
MIN_DISTINCT = 6   # a generated value with fewer distinct characters is astronomically unlikely
STRONG_LENGTH, STRONG_DISTINCT = 16, 8   # what an existing secret made some other way must reach
RENEWABLE = "renewable"
PLAIN_VALUE = re.compile(r"[A-Za-z0-9+/=_.:@,%~^-]*")   # written as is: Compose reads it back unchanged
HEADER ="# ---- secstack overrides (scripts/render-env.py rewrites everything below on every run) ----"
OLD_HEADER = "# ---- secstack overrides"

# ---------- Compose's .env parser (compose-go dotenv/parser.go, template/template.go) ----------
# Go's unicode.IsSpace, and compose-go's isSpace (the same without line breaks).
GO_SPACE = ("\t\n\v\f\r \x85\xa0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008"
            "\u2009\u200a\u2028\u2029\u202f\u205f\u3000")
INLINE_SPACE = "\t\v\f\r \x85\xa0"
EXPORT = re.compile(r"export[\t\n\f\r ]+")                       # RE2's \s
ESCAPES = re.compile(r'\\(?:[abcfnrtv$"\\]|0[0-9]{0,3})')
SIMPLE_ESCAPES = {"a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v",
                  "\\": "\\", '"': '"'}
TEMPLATE = re.compile(r"\$(?:(?P<escaped>\$)|(?P<named>[_a-z][_a-z0-9]*)|"
                      r"\{(?:(?P<braced>[_a-z][_a-z0-9]*(?::?[-+?](.*))?)\}|(?P<invalid>)))",
                      re.IGNORECASE)
OPERATORS = (":?", "?", ":-", "-", ":+", "+")


class DotenvError(Exception):
    pass


def _line_of(src, pos):
    return src.count("\n", 0, pos) + 1


def _is_key_char(c):
    return c in "_.-[]" or unicodedata.category(c)[0] in "LN"


def _statement_start(src, pos):
    """Skip whitespace and comment lines (getStatementStart)."""
    n = len(src)
    while True:
        while pos < n and src[pos] in GO_SPACE:
            pos += 1
        if pos >= n or src[pos] != "#":
            return pos
        nl = src.find("\n", pos)
        if nl < 0:
            return n
        pos = nl


def _locate_key(src, pos):
    """locateKeyName: returns (key, end of the key text, where the value starts, inherited)."""
    n = len(src)
    if EXPORT.match(src, pos):
        pos += len("export")
        while pos < n and src[pos] in INLINE_SPACE:
            pos += 1
    i = pos
    while i < n:
        c = src[i]
        if c in INLINE_SPACE:
            i += 1
            continue
        if c in "=:\n":
            key, end, nxt, inherited = src[pos:i], i, i + 1, c == "\n"
            break
        if _is_key_char(c):
            i += 1
            continue
        raise DotenvError(f"line {_line_of(src, i)}: unexpected character {c!r} in variable name "
                          f"{src[pos:].split(chr(10))[0]!r}")
    else:
        if pos >= n:
            raise DotenvError("zero length string")
        key, end, nxt, inherited = src[pos:], n, n, True
    key = key.rstrip(GO_SPACE)
    while nxt < n and src[nxt] in INLINE_SPACE:
        nxt += 1
    return key, end, nxt, inherited


def _expand_escapes(value):
    def one(m):
        t = m.group(0)
        if t == "\\$":
            return "$$"
        if t.startswith("\\0"):
            t = "\\" + t[2:]            # Go wants \ooo, not \0ooo
        c = t[1:2]
        if c in SIMPLE_ESCAPES and len(t) == 2:
            return SIMPLE_ESCAPES[c]
        if len(t) == 4 and all(x in "01234567" for x in t[1:]) and int(t[1:], 8) <= 255:
            return chr(int(t[1:], 8))
        return t                        # strconv.UnquoteChar failed: Go keeps the rewritten text
    return ESCAPES.sub(one, value)


def _first_brace_closing_index(s):
    depth, i = 0, 0
    while i < len(s):
        if s[i] == "}":
            depth -= 1
            if depth == 0:
                return i
        if s[i] == "{":
            depth += 1
            i += 1
        i += 1
    return -1


def _operator(template):
    """getSubstitutionFunctionForTemplate: the operator that appears first (":?" when none)."""
    found = [(template.find(op), k, op) for k, op in enumerate(OPERATORS) if template.find(op) >= 0]
    return min(found)[2] if found else OPERATORS[0]


def _apply_operator(op, substitution, mapping):
    if op not in substitution:
        return "", False
    name, arg = substitution.split(op, 1)
    value, ok = mapping(name)
    if op in (":-", "-"):
        if not ok or (op == ":-" and value == ""):
            return _substitute(arg, mapping), True
        return value, True
    if op in (":+", "+"):
        if ok and (op == "+" or value != ""):
            return _substitute(arg, mapping), True
        return value, True
    if not ok or (op == ":?" and value == ""):
        reason = _substitute(arg, mapping)
        raise DotenvError(f"required variable {name} is missing a value" + (f": {reason}" if reason else ""))
    return value, True


def _substitute(template, mapping):
    """template.Substitute: $$, $NAME, ${NAME}, ${NAME:-x} ${NAME-x} ${NAME:+x} ${NAME+x} ${NAME:?x} ${NAME?x}."""
    def one(m):
        substring = m.group(0)
        op = _operator(substring)
        close = _first_brace_closing_index(substring)
        rest = ""
        if close > -1:
            substring, rest = substring[:close + 1], substring[close + 1:]
        g = TEMPLATE.search(substring)
        if g is None:
            raise DotenvError(f"Invalid template: {template!r}")
        if g.group("escaped"):
            return "$"
        substitution, braced = g.group("named"), False
        if not substitution:
            substitution, braced = g.group("braced"), True
        if not substitution:
            raise DotenvError(f"Invalid template: {template!r}")
        if braced:
            value, applied = _apply_operator(op, substitution, mapping)
            if applied:
                return value + _substitute(rest, mapping)
        return mapping(substitution)[0]
    return TEMPLATE.sub(one, template)


def _extract_value(src, pos, mapping):
    """extractVarValue: returns (value, end of the value text, where parsing continues)."""
    n = len(src)
    if pos < n and src[pos] in "'\"":
        quote, escaped, chars = src[pos], False, []
        i = pos + 1
        while i < n:
            c = src[i]
            if c != quote:
                if not escaped and c == "\\":
                    escaped = True
                elif escaped:
                    escaped = False
                    chars += ["\\", c]
                else:
                    chars.append(c)
                i += 1
                continue
            if escaped:
                escaped = False
                chars.append(c)
                i += 1
                continue
            value = "".join(chars)
            if quote == '"':
                value = _substitute(_expand_escapes(value), mapping)
            return value, i + 1, i + 1
        raise DotenvError(f"line {_line_of(src, pos)}: unterminated quoted value {src[pos:].split(chr(10))[0]}")
    nl = src.find("\n", pos)
    end = n if nl < 0 else nl
    value = src[pos:end]
    cut = value.find(" #")
    if cut >= 0:
        value = value[:cut]
    return _substitute(value.rstrip(GO_SPACE), mapping), end, (n if nl < 0 else nl + 1)


def parse_env(src, lookup=None):
    """Parse .env text as Docker Compose does. lookup(name) -> str or None stands for the process
    environment (Compose consults it first, then the file's earlier values).
    Returns (values, statements); each statement is (key, start, end): the span of one assignment
    from its first character (`export` included) to the end of its value."""
    out, stmts, pos, n = {}, [], 0, len(src)

    def mapping(name):
        if lookup is not None:
            v = lookup(name)
            if v is not None:
                return v, True
        if name in out:
            return out[name], True
        return "", False

    while True:
        pos = _statement_start(src, pos)
        if pos >= n:
            return out, stmts
        start = pos
        key, end, pos, inherited = _locate_key(src, pos)
        if " " in key:
            raise DotenvError(f"line {_line_of(src, start)}: key cannot contain a space")
        if inherited:
            value, ok = mapping(key) if key else ("", False)
        else:
            value, end, pos = _extract_value(src, pos, mapping)
            ok = True
        # An empty key (a line like "=x") sets nothing; newer Compose versions reject the file instead.
        if key and ok:
            out[key] = value
        if key:
            stmts.append((key, start, end))


def env_lookup(name):
    return os.environ.get(name)


# ---------- rendering ----------
def fail(msg):
    print(f"render-env: {msg}", file=sys.stderr)
    sys.exit(2)


def read_text(path):
    with open(path, encoding="utf-8-sig", errors="strict", newline="") as f:
        return f.read()


def lines_of(text):
    """Lines split at \\n only (one trailing \\r dropped), like everything else that reads these files."""
    return [line[:-1] if line.endswith("\r") else line for line in text.split("\n")]


def read_overrides(path):
    out = {}
    for n, line in enumerate(lines_of(read_text(path)), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = KV.fullmatch(line.rstrip())
        if not m:
            fail(f"{path}:{n}: not KEY=VALUE: {line[:60]!r}")
        out[m.group(1)] = m.group(2).strip()
    return out


def read_vars(paths):
    out = {}
    for path in paths or []:
        for line in lines_of(read_text(path)):
            m = KV.fullmatch(line)
            if not m or line.lstrip().startswith("#"):
                continue
            if SAFE_VAR.fullmatch(m.group(2)):
                out[m.group(1)] = m.group(2)
            else:
                out.pop(m.group(1), None)   # unsafe or empty: treat as missing (fails closed below)
    return out


def _bad_char(c):
    # Controls, format (bidi, zero-width), surrogates, private use, line/paragraph separators, spaces other
    # than U+0020, and the 66 noncharacters. A code point this Python's Unicode tables don't know (Cn) is
    # allowed: the Mac's Python 3.9 knows Unicode 13 only, and the answer mustn't depend on which Python runs.
    o = ord(c)
    if 0xFDD0 <= o <= 0xFDEF or o & 0xFFFE == 0xFFFE:
        return True
    return (c != " " and c in GO_SPACE) or unicodedata.category(c) in ("Cc", "Cf", "Cs", "Co", "Zl", "Zp")


def resolve(raw, variables, preset=None):
    """Values for every override key; preset holds generated secrets to keep (instead of new ones)."""
    for k, v in raw.items():
        if v.startswith("@") and v not in GENERATORS:
            fail(f"unknown generator {v!r} for {k}")
    preset = preset or {}
    vals = {k: preset[k] if k in preset else GENERATORS[v]() if v in GENERATORS else v for k, v in raw.items()}
    done = {}

    def value(k, stack):
        if k in vals and k not in stack:
            if k not in done:
                done[k] = VAR.sub(lambda mm: value(mm.group(1), stack | {k}), vals[k])
            return done[k]
        if k in variables:
            return variables[k]
        fail(f"unresolved ${{{k}}} (missing from the overrides and from --vars, or not a safe value)")

    out = {k: value(k, frozenset()) for k in vals}
    for k, v in out.items():
        if any(_bad_char(c) for c in v):
            fail(f"value for {k} contains a control or line-break character")
    return out


def generated_keys(raw):
    """Keys holding a generated secret, directly or through ${...} references."""
    gen = {k for k, v in raw.items() if v in GENERATORS}
    changed = True
    while changed:
        changed = False
        for k, v in raw.items():
            if k not in gen and gen & set(VAR.findall(v)):
                gen.add(k)
                changed = True
    return gen


def write_atomic(path, text):
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".env-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def eol_of(text):
    nl = text.find("\n")
    return "\r\n" if nl > 0 and text[nl - 1] == "\r" else "\n"


def _drop_if_blank(text, pos):
    """Remove the line holding pos if nothing but whitespace is left on it."""
    start = text.rfind("\n", 0, pos) + 1
    nl = text.find("\n", pos)
    end = len(text) if nl < 0 else nl
    if text[start:end].strip(INLINE_SPACE + "\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008"
                                            "\u2009\u200a\u2028\u2029\u202f\u205f\u3000") == "":
        return text[:start] + text[end + 1:] if nl >= 0 else text[:start]
    return text


def dotenv_value(value):
    """A value as Compose must read it back: plain when that's safe, else double-quoted with \\, " and $ escaped."""
    if PLAIN_VALUE.fullmatch(value):
        return value
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$") + '"'


def compose_text(text, stmts, keys, vals, eol, quote=()):
    """Drop every assignment of keys (and our old block headers) from text, then append the block.
    Values of keys in quote (secrets, which may be kept from an earlier file) are quoted when needed."""
    drop = set(keys)
    cuts = [(s, e, True) for k, s, e in stmts if k in drop]
    inside = [(s, e) for _, s, e in stmts]
    pos = 0
    for line in text.split("\n"):
        if line.lstrip(INLINE_SPACE).startswith(OLD_HEADER) and not any(s <= pos < e for s, e in inside):
            cuts.append((pos, min(pos + len(line) + 1, len(text)), False))
        pos += len(line) + 1
    for s, e, statement in sorted(cuts, reverse=True):
        text = text[:s] + text[e:]
        if statement:
            text = _drop_if_blank(text, s)
    text = text.rstrip(GO_SPACE)
    block = HEADER + eol + "".join(f"{k}={dotenv_value(vals[k]) if k in quote else vals[k]}{eol}" for k in keys)
    return text + eol + eol + block if text else block


def verify(text, keys, vals, what):
    """The written file must give every override exactly the rendered value when Compose reads it."""
    try:
        got, _ = parse_env(text, env_lookup)
    except DotenvError as e:
        fail(f"{what}: Compose couldn't read the result ({e}); nothing written")
    wrong = [k for k in keys if got.get(k) != vals[k]]
    if wrong:
        fail(f"{what}: {', '.join(wrong)} wouldn't read back as rendered; nothing written")


def secret_problem(cur, gen, example_value, renewable=False):
    """Why an existing secret can't be kept, or None. Kept: its generator's format, or strong (at
    least STRONG_LENGTH characters, STRONG_DISTINCT different ones); never the example's value. A
    renewable secret is kept only in its generator's format: nothing depends on its old value, and other
    values are built from it (a scraper password inside SCRAPER_PRIVATE_URL), so "x@evil.example/" mustn't pass."""
    pattern, form = FORMATS[gen]
    if cur == "":
        return "is empty"
    if example_value and cur == example_value:
        return "is still the upstream example value"
    if any(_bad_char(c) for c in cur):
        return "contains a control or line-break character"
    if pattern.fullmatch(cur) and len(set(cur)) >= MIN_DISTINCT:
        return None
    if renewable:
        return f"isn't {form} ({gen})"
    if len(cur) < STRONG_LENGTH:
        return f"is shorter than {STRONG_LENGTH} characters and isn't {form} ({gen})"
    if len(set(cur)) < STRONG_DISTINCT:
        return f"has fewer than {STRONG_DISTINCT} different characters"
    return None


def check_secrets(out_path, raw, have, example, renewable=()):
    """Existing generated secrets. Returns (secrets to keep, keys the file doesn't have, renewable keys
    whose value is weak); both of the latter get fresh values. Any other weak secret stops the run."""
    keep, missing, renewed, weak = {}, [], [], []
    for k, gen in raw.items():
        if gen not in GENERATORS:
            continue
        if k not in have:
            missing.append(k)
            continue
        why = secret_problem(have[k], gen, example.get(k), renewable=k in renewable)
        if why is None:
            keep[k] = have[k]
        elif k in renewable:
            renewed.append(k)
        else:
            weak.append(f"{k} {why}")
    if weak:
        fail(f"{out_path} has weak secrets ({'; '.join(weak)}). An existing secret is kept when it looks like "
             f"secstack's generated value or is strong: at least {STRONG_LENGTH} characters with at least "
             f"{STRONG_DISTINCT} different ones, and not the upstream example. Put a strong value in {out_path} "
             f"and in whatever stores data under it (for a database, change the user's password there too), "
             f"or move {out_path} aside and re-run to render fresh secrets (an existing database then needs "
             f"its data reset).")
    return keep, missing, renewed


def split_renewable(raw):
    """Strip the " renewable" mark from generator values; returns the keys that had it."""
    renewable = set()
    for k, v in raw.items():
        parts = v.split()
        if len(parts) == 2 and parts[0] in GENERATORS and parts[1] == RENEWABLE:
            raw[k] = parts[0]
            renewable.add(k)
    return renewable


def cmd_get(key, path):
    try:
        values, _ = parse_env(read_text(path), env_lookup)
    except (OSError, UnicodeDecodeError, DotenvError) as e:
        fail(f"{path}: {e}")
    sys.stdout.buffer.write((values.get(key, "") + "\n").encode("utf-8", "surrogateescape"))
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--example")
    ap.add_argument("--overrides")
    ap.add_argument("--out")
    ap.add_argument("--vars", action="append", help="KEY=VALUE file for ${KEY} substitution (repeatable)")
    ap.add_argument("--update-keys", default="", help="comma-separated keys to refresh in an existing --out")
    ap.add_argument("--refresh", action="store_true",
                    help="refresh every override key in an existing --out, keeping (and checking) its secrets")
    ap.add_argument("--force", action="store_true", help="regenerate an existing --out (rotates every secret)")
    ap.add_argument("--get", metavar="KEY", help="print the value Compose would read for KEY from --file")
    ap.add_argument("--file", help="the .env file for --get")
    a = ap.parse_args()
    if a.get is not None:
        if not a.file:
            ap.error("--get needs --file")
        return cmd_get(a.get, a.file)
    for name in ("example", "overrides", "out"):
        if not getattr(a, name):
            ap.error(f"--{name} is required")

    try:
        raw = read_overrides(a.overrides)
        variables = read_vars(a.vars)
    except (OSError, UnicodeDecodeError) as e:
        fail(str(e))
    renewable = split_renewable(raw)
    quote = generated_keys(raw)                     # secrets and values built from them
    keys = [k.strip() for k in a.update_keys.split(",") if k.strip()]
    unknown = [k for k in keys if k not in raw]
    if unknown:
        fail(f"--update-keys not in overrides: {', '.join(unknown)}")
    secret = sorted(set(keys) & generated_keys(raw))
    if secret:
        fail(f"--update-keys would rotate generated secrets: {', '.join(secret)}")
    resolve(raw, variables)                         # fail early on a bad override or a missing variable
    if os.path.islink(a.out):
        fail(f"{a.out} is a symlink; refusing to write through it")
    if os.path.lexists(a.out) and not os.path.isfile(a.out):
        fail(f"{a.out} isn't a regular file; move it aside and re-run")

    if os.path.lexists(a.out) and not a.force:
        if not a.refresh and not keys:
            print(f"  keep    {a.out} (exists; --force regenerates it and rotates every secret)")
            return 0
        try:
            text = read_text(a.out)
            have, stmts = parse_env(text, env_lookup)
        except (OSError, UnicodeDecodeError) as e:
            fail(str(e))
        except DotenvError as e:
            fail(f"{a.out} isn't a .env file Compose can read ({e}); fix it or move it aside")
        added, renewed = [], []
        if a.refresh:
            try:
                example, _ = parse_env(read_text(a.example), env_lookup)
            except (OSError, UnicodeDecodeError, DotenvError):
                example = {}
            keep, added, renewed = check_secrets(a.out, raw, have, example, renewable)
            vals = resolve(raw, variables, keep)
            keys = list(raw)
        else:
            vals = resolve(raw, variables)
        new = compose_text(text, stmts, keys, vals, eol_of(text), quote)
        verify(new, keys, vals, a.out)
        if new == text:
            print(f"  ok      {a.out} (overrides current)")
            return 0
        write_atomic(a.out, new)
        changed = [k for k in keys if have.get(k) != vals[k]]
        print(f"  updated {a.out}: {', '.join(changed) if changed else 'overrides moved to the end'}")
        if added:
            print(f"  added   new secret{'s' if len(added) > 1 else ''} {', '.join(added)}; if a service already "
                  f"stored data under an older value, put that value back in {a.out}")
        if renewed:
            print(f"  renewed {', '.join(renewed)}: too weak to keep, and nothing stores data under "
                  f"{'them' if len(renewed) > 1 else 'it'}")
        return 0

    try:
        example_text = read_text(a.example)
        _, stmts = parse_env(example_text, env_lookup)
    except (OSError, UnicodeDecodeError) as e:
        fail(str(e))
    except DotenvError as e:
        fail(f"{a.example} isn't a .env file Compose can read ({e})")
    vals = resolve(raw, variables)
    keys = list(raw)
    new = compose_text(example_text, stmts, keys, vals, "\n", quote)
    verify(new, keys, vals, a.out)
    old = os.umask(0o077)
    try:
        write_atomic(a.out, new)
    finally:
        os.umask(old)
    print(f"  wrote   {a.out} ({len(vals)} overrides, 600)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
