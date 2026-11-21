#!/usr/bin/env python3
"""Tool-calling smoke test for local Ollama models (OpenAI-compatible endpoint, like ARTEX/pentagi use)."""
import itertools, json, os, pathlib, re, sys, time, urllib.request

BASE = "http://127.0.0.1:11434"
# Loopback only: never through an HTTP proxy (urllib would otherwise honour http_proxy / system settings).
LOCAL = urllib.request.build_opener(urllib.request.ProxyHandler({}))
# What the model (or the server) sends is printed escaped, as secops-flow.py's _esc does: every character Python
# doesn't call printable (ESC and other controls, bidi and zero-width characters, separators, unassigned), plus
# fillers and variation selectors that draw nothing. A tool name ending in ESC ]52;c;...BEL writes the clipboard.
_INVISIBLE = frozenset(chr(c) for c in itertools.chain(
    (0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x3164, 0xFFA0), range(0x180B, 0x180E), (0x180F,),
    range(0xFE00, 0xFE10), range(0xE0100, 0xE01F0)))


def esc(s):
    return "".join(c if c.isprintable() and c not in _INVISIBLE else f"\\x{ord(c):02x}" if ord(c) < 0x100
                   else f"\\u{ord(c):04x}" if ord(c) < 0x10000 else f"\\U{ord(c):08x}" for c in str(s))


def planned_models():
    """Models from the plan (configs/stack.conf MODELS=a,b,c), else the 48 GB reference set."""
    secops = pathlib.Path(os.environ.get("SECOPS") or pathlib.Path.home() / "GitHub/.sec-ops")
    found = None
    try:
        for line in (secops / "configs/stack.conf").read_text().split("\n"):   # last MODELS= line wins
            m = re.fullmatch(r"MODELS=([A-Za-z0-9._:/,][A-Za-z0-9._:/,-]*)\r?", line)
            if m:
                found = [x for x in m.group(1).split(",") if x and x != "none"]
            elif line.startswith("MODELS="):
                found = None
    except OSError:
        pass
    if found:
        return found
    return ["qwen3.6-35b-a3b-abliterated", "qwen3.8-27b-abliterated", "gemma4-26b-abliterated"]


MODELS = sys.argv[1:] or planned_models()
TOOLS = [{"type": "function", "function": {
    "name": "nmap_scan",
    "description": "Run an nmap scan against a target host.",
    "parameters": {"type": "object", "properties": {
        "target": {"type": "string", "description": "IP or hostname"},
        "ports": {"type": "string", "description": "Port spec, e.g. 1-1000"}},
        "required": ["target"]}}}]


def post(path, body, timeout=600):
    req = urllib.request.Request(BASE + path, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    return json.load(LOCAL.open(req, timeout=timeout))


for m in MODELS:
    t0 = time.time()
    try:
        r = post("/v1/chat/completions", {
            "model": m, "temperature": 0, "max_tokens": 2048, "tools": TOOLS,
            "messages": [{"role": "user",
                          "content": "Scan ports 1-1000 on 10.0.0.1 using the nmap_scan tool."}]})
        msg = r["choices"][0]["message"]
        calls = msg.get("tool_calls") or []
        ok = False
        if calls:
            fn = calls[0]["function"]
            args = json.loads(fn["arguments"]) if isinstance(fn["arguments"], str) else fn["arguments"]
            ok = fn["name"] == "nmap_scan" and args.get("target") == "10.0.0.1"
            detail = f'{esc(fn["name"])}({json.dumps(args)})'       # json.dumps writes ASCII escapes itself
        else:
            detail = "no tool_calls; text: " + esc((msg.get("content") or "")[:80].replace("\n", " "))
        ps = post("/api/ps", {}, 10) if False else json.load(LOCAL.open(BASE + "/api/ps", timeout=10))
        vram = sum(x.get("size_vram", 0) for x in ps.get("models", [])) / 1e9
        u = r.get("usage", {})
        print(f'{"PASS" if ok else "FAIL"}  {m:26s} {time.time()-t0:5.1f}s  mem={vram:4.1f} GB  '
              f'out_tok={esc(u.get("completion_tokens"))}  {detail}')
    except Exception as e:
        print(f"ERROR {m}: {esc(e)}")      # an HTTP error's reason phrase is the server's text
    # unload before the next model so peak memory stays inside the plan's fence
    try:
        post("/api/generate", {"model": m, "keep_alive": 0}, 60)
    except Exception:
        pass
