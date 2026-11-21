#!/usr/bin/env python3
"""A model of the Docker VM's netfilter for tests/func/scope_test.sh (no root, no kernel).

  fake_iptables.py iptables|ip6tables ARGS...            act like the tool; state in $FAKE_IPT_STATE
  fake_iptables.py conntrack|sysctl|modprobe|ip ARGS...  the other VM tools the firewall script uses
  fake_iptables.py --verdict SRC DST PORT [new|est|reply] [tcp|udp] [INIF]
                                                          ALLOW or BLOCK for a packet from a container
  fake_iptables.py --verdicts SRC:DST:PORT[:STATE[:PROTO]] ...   several, one per line
  fake_iptables.py --serve PORTFILE   answer tool calls on 127.0.0.1 (faster; see serve())
  fake_iptables.py --env-keys         the environment variables a tool call depends on, in serve()'s order

iptables forms: [-w [N]] -N/-F/-X CHAIN, -A CHAIN RULE, -I CHAIN [POS] RULE, -D CHAIN RULE|NUM,
-R CHAIN NUM RULE, -C CHAIN RULE, -S CHAIN. Rules are kept as the exact argument strings and -S prints
them back as written: secstack writes them in the form real iptables prints (scope_test.sh checks that
against real iptables when it can). Built-in chains print "-P CHAIN ACCEPT" first, like iptables.

Packets: the source address says which bridge a packet enters from (172.30.0.0/24 br-pentest, 172.30.1.0/24
br-hexstrike) unless INIF names it (a forged source address) and the destination where it leaves. One addressed to the VM itself (a bridge gateway or
broadcast, docker0's gateway, the uplink address) goes through INPUT; any other goes through FORWARD,
whose first rule jumps to DOCKER-USER. A packet that stays on its bridge reaches iptables only while
net.bridge.bridge-nf-call-iptables is 1. States: new (NEW, original direction), est (ESTABLISHED, original
direction: the container opened the connection), reply (ESTABLISHED, reply direction: the container
answers a connection made to it).

Environment: FAKE_IPT_FAIL_AT=N makes the Nth iptables/ip6tables call fail (exit 4, like a held xtables
lock). FAKE_UPLINK=ADDR/LEN is the VM's uplink address (default 192.168.65.3/24; empty means no default
route). FAKE_BRNF_LOCKED=1 makes bridge-nf-call-iptables impossible to set; FAKE_SYSCTL_STUCK=KEY makes writes to
sysctl KEY "succeed" while its value stays as it was. FAKE_NO_IPV6=1 is a kernel without IPv6 (no net.ipv6 keys).
FAKE_CONNTRACK_RC is conntrack's exit code. FAKE_DOCKER_USER_EMPTY=1 starts DOCKER-USER empty (Docker
28.2.2 and later) instead of with Docker's old "-j RETURN". FAKE_IPT_FAIL_FLUSH=CHAIN also empties CHAIN when the
FAKE_IPT_FAIL_AT call fails (another program changing the firewall at that moment).
"""
import json
import os
import sys

STATE = os.environ["FAKE_IPT_STATE"]
BRIDGES = {"172.30.0.0/24": "br-pentest", "172.30.1.0/24": "br-hexstrike"}
BRNF = "net.bridge.bridge-nf-call-iptables"
V6ALL = "net.ipv6.conf.all.disable_ipv6"
BUILTIN = ("INPUT", "FORWARD", "OUTPUT")
TARGETS = ("ACCEPT", "DROP", "REJECT", "RETURN", "LOG")


def uplink():
    import ipaddress                         # imported only where needed: every tool call starts a process
    v = os.environ.get("FAKE_UPLINK", "192.168.65.3/24")
    return ipaddress.ip_interface(v) if v else None


def load():
    try:
        with open(STATE) as f:
            return json.load(f)
    except (OSError, ValueError):
        user = [] if os.environ.get("FAKE_DOCKER_USER_EMPTY") else ["-j RETURN"]
        sysctls = {BRNF: "0", V6ALL: "0"}
        sysctls.update(("net.ipv6.conf.%s.disable_ipv6" % b, "0") for b in BRIDGES.values())
        return {"v4": {"INPUT": [], "FORWARD": ["-j DOCKER-USER"], "OUTPUT": [], "DOCKER-USER": user},
                "v6": {"INPUT": [], "FORWARD": [], "OUTPUT": []},
                "sysctl": sysctls, "calls": 0, "log": []}


def save(st):
    with open(STATE, "w") as f:
        json.dump(st, f)


def err(msg, rc):
    sys.stderr.write(msg + "\n")
    return rc


def target(rule):
    t = rule.split()
    return t[t.index("-j") + 1] if "-j" in t[:-1] else None


def xtables(tool, args):
    st = load()
    st["calls"] += 1
    st["log"].append(" ".join([tool] + args))
    fail_at = os.environ.get("FAKE_IPT_FAIL_AT")
    if fail_at and st["calls"] == int(fail_at):
        if os.environ.get("FAKE_IPT_FAIL_FLUSH") in st["v4"]:
            st["v4"][os.environ["FAKE_IPT_FAIL_FLUSH"]] = []
        save(st)
        return err("Another app is currently holding the xtables lock. Stopped waiting after 10s.", 4)
    if args[:1] == ["-w"]:
        args = args[2:] if len(args) > 1 and args[1].isdigit() else args[1:]
    if len(args) < 2:
        save(st)
        return err("%s: bad arguments" % tool, 2)
    chains = st["v4" if tool == "iptables" else "v6"]
    op, chain, rest = args[0], args[1], args[2:]
    rc = 0
    if op in ("-A", "-I", "-R", "-C") and "-j" in rest:
        tgt = rest[rest.index("-j") + 1]
        if tgt not in TARGETS and tgt not in chains:
            save(st)
            return err("%s: Couldn't load target `%s'" % (tool, tgt), 2)
    if op == "-N":
        if chain in chains:
            rc = err("%s: Chain already exists." % tool, 1)
        else:
            chains[chain] = []
    elif chain not in chains:
        rc = err("%s: No chain/target/match by that name." % tool, 1)
    elif op == "-S":
        print("-P %s ACCEPT" % chain if chain in BUILTIN else "-N %s" % chain)
        for r in chains[chain]:
            print("-A %s %s" % (chain, r))
    elif op == "-F":
        chains[chain] = []
    elif op == "-X":
        if chain in BUILTIN or any(target(r) == chain for rules in chains.values() for r in rules):
            rc = err("%s: Too many links." % tool, 1)
        else:
            del chains[chain]
    elif op == "-A":
        chains[chain].append(" ".join(rest))
    elif op == "-I":
        pos = 1
        if rest and rest[0].isdigit():
            pos, rest = int(rest[0]), rest[1:]
        if pos < 1 or pos > len(chains[chain]) + 1:
            rc = err("%s: Index of insertion too big." % tool, 1)
        else:
            chains[chain].insert(pos - 1, " ".join(rest))
    elif op == "-R":
        num = int(rest[0]) if rest and rest[0].isdigit() else 0
        if 1 <= num <= len(chains[chain]):
            chains[chain][num - 1] = " ".join(rest[1:])
        else:
            rc = err("%s: Index of replacement too big." % tool, 1)
    elif op == "-D":
        if len(rest) == 1 and rest[0].isdigit():
            num = int(rest[0])
            if 1 <= num <= len(chains[chain]):
                del chains[chain][num - 1]
            else:
                rc = err("%s: Index of deletion too big." % tool, 1)
        elif " ".join(rest) in chains[chain]:
            chains[chain].remove(" ".join(rest))
        else:
            rc = err("%s: Bad rule (does a matching rule exist in that chain?)." % tool, 1)
    elif op == "-C":
        rc = 0 if " ".join(rest) in chains[chain] else 1
    else:
        rc = err("%s: unsupported operation %s" % (tool, op), 2)
    save(st)
    return rc


def sysctl(args):
    st = load()
    known = dict(st["sysctl"])
    if os.environ.get("FAKE_NO_IPV6"):
        known = {k: v for k, v in known.items() if not k.startswith("net.ipv6.")}
    if args[:1] == ["-w"] and len(args) == 2:
        key, _, val = args[1].partition("=")
        if key not in known or (key == BRNF and os.environ.get("FAKE_BRNF_LOCKED")):
            return err("sysctl: error: '%s' is an unknown key" % key, 1)
        if key != os.environ.get("FAKE_SYSCTL_STUCK"):
            st["sysctl"][key] = val
            save(st)
        print("%s = %s" % (key, val))
        return 0
    if args[:1] == ["-n"] and len(args) == 2 and args[1] in known:
        print(known[args[1]])
        return 0
    return err("sysctl: error: '%s' is an unknown key" % " ".join(args[1:]), 1)


def ip(args):
    up = uplink()
    a = [x for x in args if x != "-4"]
    if a[:3] == ["route", "show", "default"]:
        if up:
            print("default via %s dev eth0 " % (up.network.network_address + 1))
        return 0
    if a[:2] == ["addr", "show"] and "dev" in a:
        if up and a[a.index("dev") + 1] == "eth0":
            print("2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 65535 qdisc pfifo_fast state UP qlen 1000")
            print("    inet %s brd %s scope global eth0" % (up, up.network.broadcast_address))
            print("       valid_lft forever preferred_lft forever")
            return 0
        return err("Device does not exist", 1)
    return err("ip: unsupported: %s" % " ".join(args), 1)


def conntrack(args):
    st = load()
    st["log"].append(" ".join(["conntrack"] + args))
    save(st)
    return int(os.environ.get("FAKE_CONNTRACK_RC", "0"))


def modprobe(args):
    return 0


class Packet:
    def __init__(self, src, dst, port, state, proto, inif, out):
        self.src, self.dst, self.port, self.proto, self.inif, self.out = src, dst, port, proto, inif, out
        self.ctstate = "NEW" if state == "new" else "ESTABLISHED"
        self.ctdir = "REPLY" if state == "reply" else "ORIGINAL"


def iface(pattern, name):
    if name is None:
        return False
    return name.startswith(pattern[:-1]) if pattern.endswith("+") else name == pattern


def matches(rule, pkt):
    import ipaddress
    t = rule.split()
    i, neg = 0, False
    while i < len(t):
        k = t[i]
        if k == "!":
            neg, i = True, i + 1
            continue
        if k == "-j":
            return True
        if k == "-m":
            i += 2
            continue
        if i + 1 >= len(t):
            break
        v = t[i + 1]
        if k == "-i":
            ok = iface(v, pkt.inif)
        elif k == "-o":
            ok = iface(v, pkt.out)
        elif k == "-s":
            ok = pkt.src in ipaddress.ip_network(v, strict=False)
        elif k == "-d":
            ok = pkt.dst in ipaddress.ip_network(v, strict=False)
        elif k == "-p":
            ok = pkt.proto == v
        elif k == "--ctstate":
            ok = pkt.ctstate in v.split(",")
        elif k == "--ctdir":
            ok = pkt.ctdir == v
        elif k in ("--dports", "--dport"):
            ok = str(pkt.port) in v.split(",")
        else:
            raise SystemExit("fake_iptables: can't model %r in rule: %s" % (k, rule))
        if ok == neg:
            return False
        neg, i = False, i + 2
    return True


def walk(chains, name, pkt, depth=0):
    for rule in chains.get(name, []):
        if not matches(rule, pkt):
            continue
        tgt = target(rule)
        if tgt == "RETURN":
            return "RETURN"
        if tgt in ("ACCEPT", "REJECT", "DROP"):
            return tgt
        if tgt in chains and depth < 8:
            res = walk(chains, tgt, pkt, depth + 1)
            if res != "RETURN":
                return res
    return "RETURN"                         # built-in chains: policy ACCEPT


def bridge_of(addr):
    import ipaddress
    return next((b for n, b in BRIDGES.items() if addr in ipaddress.ip_network(n)), None)


def vm_addresses():
    import ipaddress
    addrs = {ipaddress.ip_address(a) for a in ("172.30.0.1", "172.30.0.255", "172.30.1.1", "172.30.1.255", "172.17.0.1")}
    up = uplink()
    if up:
        addrs.add(up.ip)
    return addrs


def verdict(src, dst, port, state="new", proto="tcp", inif=None, st=None):
    import ipaddress
    st = st or load()
    s, d = ipaddress.ip_address(src), ipaddress.ip_address(dst)
    inif = inif or bridge_of(s)             # INIF given: a container forging another source address
    if inif is None:
        raise SystemExit("fake_iptables: %s is on neither bridge" % src)
    if d in vm_addresses():
        chain, out = "INPUT", None
    else:
        out = bridge_of(d) or "eth0"
        if out == inif and st["sysctl"].get(BRNF) != "1":
            return "ALLOW"                  # bridged traffic never reaches iptables
        chain = "FORWARD"
    res = walk(st["v4"], chain, Packet(s, d, int(port), state, proto, inif, out))
    return "BLOCK" if res in ("REJECT", "DROP") else "ALLOW"


HANDLERS = {"conntrack": conntrack, "sysctl": sysctl, "ip": ip, "modprobe": modprobe,
            "iptables": lambda a: xtables("iptables", a), "ip6tables": lambda a: xtables("ip6tables", a)}
ENV_KEYS = ("FAKE_IPT_STATE", "FAKE_IPT_FAIL_AT", "FAKE_UPLINK", "FAKE_BRNF_LOCKED", "FAKE_SYSCTL_STUCK",
            "FAKE_NO_IPV6", "FAKE_CONNTRACK_RC", "FAKE_DOCKER_USER_EMPTY", "FAKE_IPT_FAIL_FLUSH")


def serve(portfile):
    """--serve PORTFILE: answer tool calls over 127.0.0.1 so each call costs a bash, not a python, start.
    Request: NUL-terminated fields TOOL, the ENV_KEYS values (\\x01 = unset), ARGC, ARGS...
    Reply: the exit code on one line, stdout, a \\x1f line, stderr. State stays in $FAKE_IPT_STATE."""
    import contextlib
    import io
    import socket
    global STATE
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(16)
    with open(portfile + ".tmp", "w") as f:
        f.write(str(srv.getsockname()[1]))
    os.replace(portfile + ".tmp", portfile)
    while True:
        conn, _ = srv.accept()
        with conn:
            buf, fields = b"", None
            while fields is None:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                buf += chunk
                parts = buf.split(b"\0")
                n = len(ENV_KEYS) + 2
                if len(parts) > n and len(parts) - 1 >= n + int(parts[n - 1]):
                    fields = [p.decode() for p in parts[:n + int(parts[n - 1])]]
            if fields is None:
                continue
            for k, v in zip(ENV_KEYS, fields[1:]):
                if v == "\x01":
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
            STATE = os.environ["FAKE_IPT_STATE"]
            out, errs = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(errs):
                try:
                    rc = HANDLERS[fields[0]](fields[len(ENV_KEYS) + 2:])
                except SystemExit as e:
                    rc = e.code if isinstance(e.code, int) else 1
                except Exception as e:      # report, don't kill the server
                    sys.stderr.write("fake_iptables: %r\n" % e)
                    rc = 3
            e = errs.getvalue()
            conn.sendall(("%d\n%s\x1f\n%s" % (rc, out.getvalue(), e if not e or e.endswith("\n") else e + "\n")).encode())


if __name__ == "__main__":
    tool, args = sys.argv[1], sys.argv[2:]
    if tool == "--serve":
        serve(args[0])
    if tool == "--env-keys":
        print(" ".join(ENV_KEYS))
        sys.exit(0)
    if tool == "--verdict":
        print(verdict(*args))
        sys.exit(0)
    if tool == "--verdicts":                  # SRC:DST:PORT[:STATE[:PROTO]] ...: one verdict per line
        st = load()
        for a in args:
            print(verdict(*a.split(":"), st=st))
        sys.exit(0)
    sys.exit(HANDLERS[tool](args))
