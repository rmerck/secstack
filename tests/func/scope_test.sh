#!/usr/bin/env bash
# Functional test for the scope firewall and the lab. A stub docker runs the firewall scripts secstack
# sends into the Docker VM against a model of the VM's netfilter (tests/func/fake_iptables.py), then the
# test checks what packets from pentest-net (Kali terminals, the lab) and hexstrike-net (HexStrike, the lab)
# would do. No Docker, no root. When run as root on Linux with unshare, it also loads every rule secstack
# wrote into real iptables in a throwaway network namespace: the read-back compares rule text, so each rule
# must be exactly what iptables prints.
#   bash tests/func/scope_test.sh        (from the repo root; needs python3)
# Greps on pipes read all their input (no grep -q): with pipefail, an early exit could fail the writer.
set -uo pipefail
SRC_REPO="$(cd "${1:-$(dirname "$0")/../..}" && pwd -P)"
T="$(cd "$(mktemp -d "${TMPDIR:-/tmp}/sc.XXXXXX")" && pwd -P)"
SERVER=""
trap '[ -n "$SERVER" ] && { kill "$SERVER"; wait "$SERVER"; } 2>/dev/null; rm -rf "$T"' EXIT   # wait: no job notice (bash 3.2)
PY="$(command -v python3)"; BASH_BIN="$(command -v bash)"
FAKE="$SRC_REPO/tests/func/fake_iptables.py"
export FAKE_IPT_STATE="$T/ipt.json"
mkdir -p "$T/bin" "$T/fake" "$T/vmbin" "$T/probe" "$T/GH/.sec-ops/configs" "$T/home"
# The VM side: fake netfilter tools plus only the plain utilities the scripts need. Each tool asks the
# fake's server (one python for the whole test, much faster); without it, it runs the fake directly.
"$PY" "$FAKE" --serve "$T/fake.port" & SERVER=$!
for _ in $(seq 1 50); do [ -s "$T/fake.port" ] && break; sleep 0.1; done
[ -s "$T/fake.port" ] && export FAKE_PORT="$(cat "$T/fake.port")"
envargs=""; for k in $("$PY" "$FAKE" --env-keys); do envargs="$envargs \"\${$k-\$u}\""; done
for tool in iptables ip6tables conntrack sysctl modprobe ip; do
  cat > "$T/fake/$tool" <<EOF
#!$BASH_BIN
if [ -n "\${FAKE_PORT:-}" ] && { exec 3<>"/dev/tcp/127.0.0.1/\$FAKE_PORT"; } 2>/dev/null; then
  u=\$'\\001'
  printf '%s\\0' $tool $envargs "\$#" "\$@" >&3
  IFS= read -r rc <&3
  while IFS= read -r l <&3; do [ "\$l" = \$'\\037' ] && break; printf '%s\\n' "\$l"; done
  while IFS= read -r l <&3; do printf '%s\\n' "\$l" >&2; done
  exit "\$rc"
fi
exec "$PY" "$FAKE" $tool "\$@"
EOF
  chmod +x "$T/fake/$tool"
done
for tool in sh sed grep head tail cat cut tr; do ln -s "$(command -v "$tool")" "$T/vmbin/$tool"; done
# Probe containers: nc asks the model whether the probe's address (on its network) gets through; getent
# answers host.docker.internal with $FAKE_HDI (no answer when it's empty, as when DNS is blocked).
cat > "$T/probe/nc" <<EOF
#!/bin/sh
h=; p=
for a; do case "\$a" in -*) ;; *) h=\$p; p=\$a ;; esac; done
[ "\$("$PY" "$FAKE" --verdict "\$PROBE_SRC" "\$h" "\$p")" = ALLOW ]
EOF
cat > "$T/probe/getent" <<'EOF'
#!/bin/sh
[ "$1 $2" = "hosts host.docker.internal" ] && [ -n "${FAKE_HDI-192.168.65.254}" ] || exit 2
echo "${FAKE_HDI-192.168.65.254}      host.docker.internal"
EOF
printf '#!/bin/sh\nexit 0\n' > "$T/probe/nslookup"; chmod +x "$T/probe/nc" "$T/probe/getent" "$T/probe/nslookup"
cat > "$T/bin/ifconfig" <<EOF
#!/bin/sh
printf 'lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384\n\tinet 127.0.0.1 netmask 0xff000000\n'
[ -f "$T/lo0_alias" ] && printf '\tinet 127.0.0.2 netmask 0xff000000\n'
exit 0
EOF
chmod +x "$T/bin/ifconfig"
cat > "$T/bin/curl" <<'EOF'
#!/bin/sh
for a; do u=$a; done
case "$u" in */health) exit 0 ;; */api/secstack-auth-check) printf 401; exit 0 ;; esac
exit 7
EOF
chmod +x "$T/bin/curl"
cat > "$T/bin/docker" <<EOF
#!$PY
import json, os, subprocess, sys
TD = "$T"
EOF
cat >> "$T/bin/docker" <<'EOF'
DB = os.path.join(TD, "docker.json")
args = sys.argv[1:]
def log(name, line):
    with open(os.path.join(TD, name), "a") as f:
        f.write(line + "\n")
log("docker_log", "docker " + " ".join(args))
try:
    d = json.load(open(DB))
except (OSError, ValueError):
    d = {"nets": {}, "containers": {}, "next": 1}
C = d["containers"]
def save():
    json.dump(d, open(DB, "w"))
def find(ref):
    return next((n for n, c in C.items() if ref in (n, c["id"])), None)
def refs():
    return [a for a in args[1:] if not a.startswith("-")]
def vm():  # the modelled VM's firewall, as the next packet would meet it
    try:
        return json.load(open(os.environ["FAKE_IPT_STATE"]))["v4"]
    except (OSError, ValueError):
        return {}
def firewall_on():
    du = vm().get("DOCKER-USER", [])
    return "SECOPS-SCOPE" in vm() and all("-i %s -j SECOPS-SCOPE" % b in du for b in ("br-pentest", "br-hexstrike"))
def guards_in():
    du = vm().get("DOCKER-USER", [])
    return all("-i %s -j REJECT --reject-with icmp-net-prohibited" % b in du for b in ("br-pentest", "br-hexstrike"))
def render(fmt, parts):
    # Render the --format templates secstack uses from the model, fragment by fragment (longest first);
    # anything else is an error, so a changed template can't pass by accident.
    for frag in sorted(parts, key=len, reverse=True):
        fmt = fmt.replace(frag, parts[frag])
    if "{{" in fmt:
        sys.exit("template: unknown fragment in " + fmt)
    return fmt
def net_parts(n):
    return {'{{.Driver}}': n["driver"], '{{index .Options "com.docker.network.bridge.name"}}': n["bridge"],
            '{{range .IPAM.Config}}{{.Subnet}} {{.IPRange}}{{end}}': "%s %s" % (n["subnet"], n["range"]),
            '{{.EnableIPv6}}': n["ipv6"]}
def container_parts(name, c):
    return {'{{range $k, $v := .NetworkSettings.Networks}}{{$k}}={{if $v.IPAMConfig}}{{$v.IPAMConfig.IPv4Address}}{{end}} {{end}}':
                "".join("%s=%s " % kv for kv in sorted(c["nets"].items())),
            '{{range $p, $b := .HostConfig.PortBindings}}{{range $b}}{{.HostIp}}:{{.HostPort}} {{end}}{{end}}': c["ports"],
            '{{.HostConfig.CapDrop}}': c["capdrop"], '{{.Name}}': "/" + name, '{{.Config.Image}}': c.get("image", ""),
            '{{.HostConfig.RestartPolicy.Name}}': c["policy"], '{{.HostConfig.AutoRemove}}': "true" if c["autoremove"] else "false",
            '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}': "".join("%s " % k for k in sorted(c["nets"]))}
opt = lambda k, dflt="": args[args.index(k) + 1] if k in args else dflt
cmd = args[0] if args else ""
if cmd == "info":
    sys.exit(1 if os.path.exists(os.path.join(TD, "docker_down")) else 0)
if cmd == "network":
    if args[1] == "inspect":
        n = d["nets"].get(args[2])
        if not n:
            sys.exit(1)
        if "--format" in args:
            print(render(opt("--format"), net_parts(n)))
    elif args[1] == "create":
        bridge = next((a.split("=", 1)[1] for a in args if a.startswith("com.docker.network.bridge.name=")), "br-0123456789ab")
        d["nets"][args[-1]] = {"driver": opt("--driver", "bridge"), "bridge": bridge, "subnet": opt("--subnet", "172.18.0.0/16"),
                               "range": opt("--ip-range"), "ipv6": "true" if ("--ipv6" in args or "--ipv6=true" in args) else "false"}
        log("net_create", " ".join(args))
    elif args[1] == "rm":
        d["nets"].pop(args[2], None)
    elif args[1] == "connect":
        pos = [a for a in args[2:] if a not in ("--ip", opt("--ip"))]
        n = find(pos[1])
        if not n or pos[0] not in d["nets"]:
            sys.exit("Error: No such container or network")
        C[n]["nets"][pos[0]] = opt("--ip")
    save()
    sys.exit(0)
if cmd == "run":
    if "nsenter" in args:                            # vm_sh: the script runs "in the VM"
        open(os.path.join(TD, "vm_args"), "w").write(" ".join(args) + "\n")
        if os.path.exists(os.path.join(TD, "docker_run_fail")):
            sys.exit("docker: Error response from daemon: pull access denied")
        script = sys.stdin.read()
        n = len([f for f in os.listdir(TD) if f.startswith("vm_script.")])
        open(os.path.join(TD, "vm_script.%d" % n), "w").write(script)
        env = dict(os.environ, PATH=os.path.join(TD, "fake") + ":" + os.path.join(TD, "vmbin"))
        sys.exit(subprocess.run([os.path.join(TD, "vmbin", "sh"), "-s"], input=script, text=True, env=env).returncode)
    net = opt("--network")
    if opt("--name") == "hexstrike":                 # mcp on: was the firewall in when HexStrike started?
        log("start_log", "run hexstrike firewall=%s guards=%s" % ("yes" if firewall_on() else "no", "yes" if guards_in() else "no"))
        sys.exit(0)
    if net in ("pentest-net", "hexstrike-net") and "-c" in args and "--entrypoint" not in args:   # scope test probe
        log("probe_log", net)
        env = dict(os.environ, PATH=os.path.join(TD, "probe") + ":" + os.environ["PATH"],
                   PROBE_SRC="172.30.0.200" if net == "pentest-net" else "172.30.1.200")
        sys.exit(subprocess.run(["sh", "-c", args[args.index("-c") + 1]], env=env).returncode)
    sys.exit(0)
if cmd == "ps":
    flags, nets, i = set(), [], 1
    while i < len(args):
        if args[i] in ("--filter", "--format"):
            if args[i] == "--filter" and args[i + 1].startswith("network="):
                nets.append(args[i + 1].split("=", 1)[1])
            i += 2
            continue
        if args[i].startswith("-") and not args[i].startswith("--"):
            flags.update(args[i][1:])
        i += 1
    lines = [c["id"] if "q" in flags else n for n, c in sorted(C.items())
             if ("a" in flags or c["running"]) and (not nets or any(x in c["nets"] for x in nets))]
    try:                                 # like docker: a reader that quits early (grep -q) kills the writer
        for i, line in enumerate(lines):
            print(line, flush=True)
            if i == 0 and len(lines) > 1:
                import time; time.sleep(0.05)
    except BrokenPipeError:
        os._exit(141)
    sys.exit(0)
if cmd == "inspect":
    fmt = opt("--format")
    n = find(next((a for a in args[1:] if a not in ("--format", fmt)), ""))
    if not n:
        sys.exit(1)
    print(render(fmt, container_parts(n, C[n])))
    sys.exit(0)
if cmd == "create":
    c = {"nets": {}, "ports": "", "capdrop": "[]", "policy": "no", "autoremove": False, "running": False}
    name, net, ip, i = None, None, "", 1
    while i < len(args):
        a = args[i]
        if a.startswith("--") and "=" in a:
            if a.startswith("--restart="):
                c["policy"] = a.split("=", 1)[1]
            i += 1
        elif a in ("--name", "--network", "--ip", "-p", "--cap-drop", "--platform", "--memory", "--cpus", "--restart"):
            v = args[i + 1]
            if a == "--name": name = v
            elif a == "--network": net = v
            elif a == "--ip": ip = v
            elif a == "-p": c["ports"] += "%s:%s " % tuple(v.split(":")[:2])
            elif a == "--cap-drop": c["capdrop"] = "[CAP_%s]" % v
            elif a == "--restart": c["policy"] = v
            i += 2
        elif a == "--rm":
            c["autoremove"] = True
            i += 1
        else:
            c["image"] = a
            break
    if name in C:
        sys.exit("docker: Conflict. The container name is already in use")
    c["nets"] = {net: ip} if net else {"bridge": ""}
    c["id"] = "c%04d" % d["next"]
    d["next"] += 1
    C[name] = c
    save()
    log("create_log", " ".join(args))
    sys.exit(0)
if cmd in ("rm", "start", "stop", "kill"):
    names = refs()
    if cmd == "start" and any(find(r) is None for r in names):
        sys.exit("Error: No such container")
    for r in names:
        n = find(r)
        if n and cmd == "rm":
            del C[n]
        elif n:
            C[n]["running"] = cmd == "start"
            log("start_log" if cmd == "start" else "stop_log", "%s %s firewall=%s guards=%s" % (
                cmd, n, "yes" if firewall_on() else "no", "yes" if guards_in() else "no"))
    save()
    sys.exit(0)
if cmd == "update":
    n = find(args[-1])
    if not n or C[n].get("update_fail"):
        sys.exit("Error response from daemon: cannot update container")
    C[n]["policy"] = next(a.split("=", 1)[1] for a in args if a.startswith("--restart="))
    save()
    sys.exit(0)
if cmd == "image":    # no hexstrike-kali image (dvwa_init only warns) unless a test made one
    sys.exit(0 if os.path.exists(os.path.join(TD, "hexstrike_image")) else 1)
sys.exit(0)
EOF
chmod +x "$T/bin/docker"
export HOME="$T/home" SECSTACK_GH="$T/GH" SECOPS="$T/GH/.sec-ops" PATH="$T/bin:$PATH"
SC="$SECOPS/configs/scope.cidrs"; MODE="$SECOPS/configs/scope.mode"
S="$SRC_REPO/bin/secstack"
HOOK="-i br-pentest -j SECOPS-SCOPE"; HOOKH="-i br-hexstrike -j SECOPS-SCOPE"
GUARD="-i br-pentest -j REJECT --reject-with icmp-net-prohibited"; GUARDH="-i br-hexstrike -j REJECT --reject-with icmp-net-prohibited"
INPUT_RULE="-i br-pentest -m conntrack ! --ctstate RELATED,ESTABLISHED -j REJECT --reject-with icmp-port-unreachable"
INPUT_RULEH="-i br-hexstrike -m conntrack ! --ctstate RELATED,ESTABLISHED -j REJECT --reject-with icmp-port-unreachable"
TERM_IP=172.30.0.200; HEX=172.30.1.5    # a Kali terminal (dynamic pentest-net address) and HexStrike
DVWA_IMAGE=$(sed -n 's/^DVWA_IMAGE=//p' "$SRC_REPO/upstream/images.lock" | tail -n 1)
pass=0; fail=0
ok(){ echo "PASS $*"; pass=$((pass+1)); }
bad(){ echo "FAIL $*"; fail=$((fail+1)); [ -z "${SCOPE_TEST_FAIL_FAST:-}" ] || exit 1; }   # fail fast: for mutation runs
v(){ "$PY" "$FAKE" --verdict "$@"; }   # v SRC DST PORT [new|est|reply] [tcp|udp]
expect(){ # expect ALLOW|BLOCK SRC DST PORT [state] [proto]
  local want="$1" got; shift; got=$(v "$@")
  [ "$got" = "$want" ] && ok "$want $2:$3 from $1 (${4:-new} ${5:-tcp})" || bad "expected $want for $2:$3 from $1 (${4:-new} ${5:-tcp}), got $got"
}
run(){ bash "$S" "$@" >"$T/out" 2>&1; }
must(){ run "$@" && return 0; bad "secstack $* failed:"; sed 's/^/    /' "$T/out"; return 1; }
mustnot(){ run "$@" || return 0; bad "secstack $* succeeded but must fail:"; sed 's/^/    /' "$T/out"; return 1; }
has(){ grep -F -- "$1" "$T/out" >/dev/null && ok "$2" || { bad "$2 (no \"$1\" in the output):"; sed 's/^/    /' "$T/out"; }; }
hasnot(){ grep -F -- "$1" "$T/out" >/dev/null && { bad "$2 (\"$1\" in the output):"; sed 's/^/    /' "$T/out"; } || ok "$2"; }
st(){ "$PY" - "$FAKE_IPT_STATE" "$1" <<'PY'   # st EXPR: evaluate on the modelled VM (v4, v6, s)
import json, sys
s = json.load(open(sys.argv[1])); v4, v6 = s["v4"], s["v6"]
r = eval(sys.argv[2])
print(("yes" if r else "no") if isinstance(r, bool) else r)
PY
}
tamper(){ "$PY" - "$FAKE_IPT_STATE" "$1" <<'PY'   # tamper STMT: change the modelled VM
import json, sys
p = sys.argv[1]; s = json.load(open(p)); v4, v6 = s["v4"], s["v6"]
exec(sys.argv[2]); json.dump(s, open(p, "w"))
PY
}
dk(){ "$PY" - "$T/docker.json" "$1" <<'PY'   # dk STMT: change the stub's containers/networks (d, C)
import json, sys
p = sys.argv[1]; d = json.load(open(p)); C = d["containers"]
exec(sys.argv[2]); json.dump(d, open(p, "w"))
PY
}
dq(){ "$PY" - "$T/docker.json" "$1" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); C = d["containers"]; print(eval(sys.argv[2]))
PY
}
same_vm(){ "$PY" - "$FAKE_IPT_STATE" "$1" <<'PY'   # same_vm FILE: firewall identical to a saved state
import json, sys
a, b = (json.load(open(f)) for f in sys.argv[1:3])
sys.exit(0 if all(a[k] == b[k] for k in ("v4", "v6", "sysctl")) else 1)
PY
}
same_scope(){ "$PY" - "$FAKE_IPT_STATE" "$1" <<'PY'   # same_scope FILE: DOCKER-USER, the chain and sysctls as saved
import json, sys
a, b = (json.load(open(f)) for f in sys.argv[1:3])
sys.exit(0 if all(a["v4"].get(c) == b["v4"].get(c) for c in ("DOCKER-USER", "SECOPS-SCOPE")) and a["sysctl"] == b["sysctl"] else 1)
PY
}
as_written(){ "$PY" - "$FAKE_IPT_STATE" "$1" "$HOOK" "$HOOKH" <<'PY'   # as_written FILE: the rules that matter are FILE's
import json, sys
a, b = (json.load(open(f)) for f in sys.argv[1:3])
head = lambda s, c, k: (s["v4"].get(c) or [])[:k]
sys.exit(0 if a["v4"]["SECOPS-SCOPE"] == b["v4"]["SECOPS-SCOPE"] and head(a, "DOCKER-USER", 2) == sys.argv[3:5]
         and head(a, "INPUT", 2) == head(b, "INPUT", 2) and head(a, "FORWARD", 1) == ["-j DOCKER-USER"]
         and a["sysctl"] == b["sysctl"] else 1)
PY
}
calls(){ st 's["calls"]'; }
nth_call(){ # nth_call C0 SUFFIX: the position, counted from call C0, of the first iptables call ending in SUFFIX
  "$PY" - "$FAKE_IPT_STATE" "$1" "$2" <<'PY'
import json, sys
s = json.load(open(sys.argv[1])); calls = [l for l in s["log"] if l.split()[0] in ("iptables", "ip6tables")]
print(next(i for i, l in enumerate(calls[int(sys.argv[2]):], 1) if l.endswith(sys.argv[3])))
PY
}
flushes(){ st 'min(sum(l == "conntrack -D -s %s" % n for l in s["log"]) for n in ("172.30.0.0/24", "172.30.1.0/24"))'; }   # both bridges
any_flush(){ st 'sum(l.startswith("conntrack -D") for l in s["log"])'; }
vm_scripts(){ ls "$T" | grep -c '^vm_script'; }
dlog_since(){ tail -n +"$(( $1 + 1 ))" "$T/docker_log"; }
dlog_len(){ [ -f "$T/docker_log" ] && wc -l < "$T/docker_log" | tr -d ' ' || echo 0; }
snap(){ cp "$FAKE_IPT_STATE" "$T/canon.$1.json"; }   # rule sets for the real-iptables check

# ---- the seeded example applies on a fresh install; both networks are made as secstack needs them
cp "$SRC_REPO/configs/scope.cidrs.example" "$SC"; chmod 600 "$SC"
must scope apply && ok "the seeded scope.cidrs.example applies (fresh install)"
for spec in "pentest-net br-pentest 172.30.0.0/24 172.30.0.128/25 172.30.0.1" "hexstrike-net br-hexstrike 172.30.1.0/24 172.30.1.128/25 172.30.1.1"; do
  set -- $spec
  grep -e "--driver bridge --ipv6=false --subnet $3 --ip-range $4 --gateway $5 -o com.docker.network.bridge.name=$2 $1\$" "$T/net_create" >/dev/null \
    && ok "$1 created as a bridge without IPv6, with a dynamic range" || { bad "$1 create flags"; cat "$T/net_create"; }
done
grep 'alpine@sha256:' "$T/vm_args" >/dev/null && ok "firewall runs from the digest-pinned alpine" || bad "alpine not pinned: $(cat "$T/vm_args")"
printf '172.30.0.8/29   # lab\n' > "$SC"
mustnot scope apply && has "secstack scope rm 172.30.0.8/29" "a reserved line is refused, with the scope rm that fixes it"
: > "$SC"
must scope apply

# ---- strict, empty scope: each bridge reaches only the lab; nothing reaches the VM or beyond
expect BLOCK $TERM_IP 1.1.1.1 443
expect BLOCK $TERM_IP 10.1.2.3 80
expect ALLOW $TERM_IP 172.30.0.10 80                     # terminals reach the lab
expect ALLOW $TERM_IP 172.30.0.11 3000
expect BLOCK $TERM_IP $HEX 8888                          # never HexStrike (another bridge)
expect BLOCK $TERM_IP 172.30.1.10 80                     # nor the lab's address on HexStrike's bridge
expect BLOCK $TERM_IP 172.30.0.201 22                    # nor each other
expect ALLOW $HEX 172.30.1.10 80                         # HexStrike reaches the lab
expect ALLOW $HEX 172.30.1.11 3000
expect BLOCK $HEX 172.30.0.10 80                         # only on its own bridge
expect BLOCK $HEX $TERM_IP 22
expect BLOCK 172.30.1.200 $HEX 8888                      # anything else on hexstrike-net can't reach it
expect BLOCK 172.30.1.10 $HEX 8888                       # the lab never opens a connection
expect ALLOW 172.30.1.10 $HEX 40000 reply                # but answers
for src in $TERM_IP $HEX; do
  for dst in 192.168.65.254:11434 192.168.65.1:2375 172.30.0.1:2375 172.30.1.1:2375 172.17.0.1:2375 192.168.65.3:22; do
    expect BLOCK $src "${dst%:*}" "${dst#*:}"            # host.docker.internal, the VM's own addresses
  done
done
expect BLOCK 172.30.0.10 172.30.0.1 80
expect BLOCK $TERM_IP 1.1.1.1 443 est                    # a connection the container opened, out of scope
expect ALLOW $HEX 192.168.65.1 50000 reply               # replies on HexStrike's published port
expect ALLOW $HEX 172.30.1.1 50000 reply                 # replies to the VM's own connections
expect ALLOW 172.30.0.10 $TERM_IP 40000 reply            # the lab answers
# Forged sources (NET_RAW): "replies" injected into the other bridge's connections are dropped (last field: the bridge)
expect BLOCK 10.1.2.3 $HEX 40000 reply udp br-pentest   # an in-scope server's reply to HexStrike, sent by a terminal
expect BLOCK 172.30.1.10 $HEX 40001 reply udp br-pentest # the lab's hexstrike-net address, forged by a terminal
expect BLOCK 1.1.1.1 $TERM_IP 40000 reply tcp br-hexstrike
expect BLOCK 172.30.1.200 $HEX 8888 reply tcp br-pentest
[ "$(st 's["sysctl"]["net.bridge.bridge-nf-call-iptables"]')" = 1 ] && ok "apply turns bridge netfilter on" || bad "bridge netfilter not on"
[ "$(st '[s["sysctl"]["net.ipv6.conf.%s.disable_ipv6" % b] for b in ("br-pentest", "br-hexstrike")]')" = "['1', '1']" ] \
  && ok "IPv6 off on both bridges" || bad "IPv6 sysctls: $(st 's["sysctl"]')"
[ "$(st 'v4["INPUT"][:2]')" = "['$INPUT_RULE', '$INPUT_RULEH']" ] && ok "INPUT rules first, both bridges" || bad "INPUT: $(st 'v4["INPUT"]')"
[ "$(st 'v4["DOCKER-USER"][:2]')" = "['$HOOK', '$HOOKH']" ] && ok "hooks first in DOCKER-USER, both bridges" || bad "DOCKER-USER: $(st 'v4["DOCKER-USER"]')"
[ "$(st 'v6["FORWARD"]')" = "[]" ] && ok "no ip6tables needed" || bad "ip6tables used: $(st 'v6')"

# ---- add a target
must scope add 10.1.2.3/32 "web $(printf '\033')[31m café" && ok "scope add"
expect ALLOW $TERM_IP 10.1.2.3 80
expect ALLOW $TERM_IP 10.1.2.3 80 est
expect ALLOW $HEX 10.1.2.3 443                           # same scope from HexStrike's bridge
expect BLOCK $TERM_IP 10.1.2.4 80
LC_ALL=C grep "$(printf '\033')" "$SC" >/dev/null || LC_ALL=C grep "$(printf '\303')" "$SC" >/dev/null \
  && bad "control/non-ASCII characters in scope.cidrs" || ok "note reduced to printable ASCII"
[ "$(python3 -c 'import os,sys; print(oct(os.stat(sys.argv[1]).st_mode & 0o777)[2:])' "$SC")" = 600 ] && ok "scope.cidrs stays 600" || bad "scope.cidrs mode"
expect BLOCK 172.30.0.10 10.1.2.3 80                     # the lab never starts a connection
expect BLOCK 172.30.1.11 10.1.2.3 80
expect BLOCK 172.30.0.10 $TERM_IP 22
snap strict

# ---- refused additions never reach the VM (each reserved range, too wide, not IPv4, injection)
cp "$FAKE_IPT_STATE" "$T/before.json"; cp "$SC" "$T/sc.before"
for cidr in 10.0.0.0/8 10.0.0.0/15 192.168.0.0/16 127.0.0.1/32 "1.2.3.4/32; reboot" 169.254.169.254/32 0.0.0.0/16 \
            224.0.0.0/16 240.0.0.0/16 192.168.65.0/24 172.30.0.0/24 172.30.1.0/24 172.30.1.5/32 ::ffff:10.1.2.9/128; do
  mustnot scope add "$cidr" && ok "scope add $cidr refused"
done
same_vm "$T/before.json" && cmp -s "$SC" "$T/sc.before" && ok "refused additions changed nothing" || bad "a refused addition changed something"
for line in "10.0.0.0/15" "2001:db8::/64" "not-a-cidr" "10.1.0.0/16 10.2.0.0/16"; do  # hand-edited lines
  { cat "$T/sc.before"; echo "$line"; } > "$SC"
  mustnot scope apply && ok "hand-edited line refused: $line"
done
cp "$T/sc.before" "$SC"; same_vm "$T/before.json" && ok "refused files changed nothing" || bad "a refused file changed the firewall"

# ---- install mode opens public 80/443 only; reserved and private ranges stay closed
must scope install && ok "scope install"
has "install mode" "install mode warns"
expect ALLOW $TERM_IP 1.1.1.1 443
expect ALLOW $HEX 1.1.1.1 80
expect BLOCK $TERM_IP 1.1.1.1 22
expect BLOCK $TERM_IP 1.1.1.1 443 new udp
for dst in 10.9.9.9 172.16.0.1 192.168.1.1 100.64.0.1 169.254.169.254 192.168.65.254 224.0.0.1 240.0.0.1 0.0.0.1 $HEX 172.30.1.10; do
  expect BLOCK $TERM_IP "$dst" 80
done
expect BLOCK $HEX 172.30.0.10 443
snap install
before=$(flushes)
must scope strict && ok "scope strict"
expect BLOCK $TERM_IP 1.1.1.1 443
[ "$(flushes)" -gt "$before" ] && ok "strict after install flushes connections" || bad "no conntrack flush"
[ "$(cat "$MODE")" = strict ] && ok "mode strict" || bad "mode $(cat "$MODE")"

# ---- the read-back compares every rule: each tamper is reported, and an apply repairs it
run scope show; has "match scope.cidrs" "scope show: rules match"
check_tamper(){ # check_tamper "what" STMT "expected message"
  tamper "$2"; run scope show
  grep "doesn't match" "$T/out" >/dev/null && grep -F -- "$3" "$T/out" >/dev/null && ok "detects: $1" \
    || { bad "not detected: $1"; sed 's/^/    /' "$T/out"; }
  must scope apply && ok "re-apply repairs (its read-back passes): $1"
}
tamper 'v4["SECOPS-SCOPE"].insert(0, "-p udp -j RETURN")'
expect ALLOW $TERM_IP 8.8.8.8 53 new udp                 # (what that tamper would let out)
check_tamper "UDP returned early" 'pass' "unexpected rule: -p udp -j RETURN"
check_tamper "final REJECT qualified" 'v4["SECOPS-SCOPE"][-1] = "-o eth9 -j REJECT --reject-with icmp-net-prohibited"' "missing rule: -j REJECT"
check_tamper "final REJECT deleted" 'v4["SECOPS-SCOPE"].pop()' "missing rule: -j REJECT --reject-with icmp-net-prohibited"
check_tamper "rules reordered" 'c = v4["SECOPS-SCOPE"]; c[1], c[3] = c[3], c[1]' "out of order"
check_tamper "80/443 open in strict mode" 'v4["SECOPS-SCOPE"].insert(3, "-p tcp -m multiport --dports 80,443 -j RETURN")' "public 80/443 is open although the mode is strict"
check_tamper "an extra allowed network" 'c = v4["SECOPS-SCOPE"]; c.remove("-d 10.1.2.3/32 -j RETURN"); c.insert(0, "-d 8.8.8.8/32 -j RETURN")' "unexpected rule: -d 8.8.8.8/32 -j RETURN"
expect BLOCK $TERM_IP 8.8.8.8 53
tamper 'v4["DOCKER-USER"].insert(0, "-s 172.30.0.0/24 -j ACCEPT")'
expect ALLOW $TERM_IP 1.1.1.1 443                        # (ACCEPT ends the walk, as in iptables)
check_tamper "ACCEPT above the hooks" 'pass' "another DOCKER-USER rule before SECOPS-SCOPE"
expect BLOCK $TERM_IP 1.1.1.1 443                        # (the repair puts the hooks above it)
check_tamper "ACCEPT between the hooks" 'v4["DOCKER-USER"].insert(1, "-i br-hexstrike -j ACCEPT")' "another DOCKER-USER rule before SECOPS-SCOPE: -i br-hexstrike -j ACCEPT"
tamper 'v4["DOCKER-USER"].remove("-i br-hexstrike -j ACCEPT"); v4["DOCKER-USER"][1:1] = ["'"$HOOK"'", "-i br-hexstrike -j ACCEPT"]'
expect ALLOW $HEX 1.1.1.1 443                            # (the pentest-net hook twice pushed HexStrike's below an ACCEPT)
check_tamper "pentest-net hook twice, an ACCEPT above the hexstrike-net hook" 'pass' "another DOCKER-USER rule before SECOPS-SCOPE: -i br-hexstrike -j ACCEPT"
tamper 'v4["DOCKER-USER"].remove("-i br-hexstrike -j ACCEPT")'
check_tamper "pentest-net hook twice" 'v4["DOCKER-USER"].insert(0, "'"$HOOK"'")' "does not start with one jump into SECOPS-SCOPE per bridge, in order"
check_tamper "hooks swapped" 'u = v4["DOCKER-USER"]; u[0], u[1] = u[1], u[0]' "does not start with one jump into SECOPS-SCOPE per bridge, in order"
tamper 'v4["FORWARD"].insert(0, "-i br-hexstrike -j ACCEPT")'
expect ALLOW $HEX 1.1.1.1 443                            # (FORWARD accepted it before DOCKER-USER)
check_tamper "ACCEPT above FORWARD's jump" 'pass' "FORWARD does not start with the jump to DOCKER-USER"
expect BLOCK $HEX 1.1.1.1 443
tamper 'v4["FORWARD"] = [r for r in v4["FORWARD"] if r != "-j DOCKER-USER"]'
expect ALLOW $TERM_IP 1.1.1.1 443
check_tamper "FORWARD's jump missing" 'pass' "FORWARD does not start with the jump to DOCKER-USER"
expect BLOCK $TERM_IP 1.1.1.1 443
tamper 'v4["DOCKER-USER"].remove("-s 172.30.0.0/24 -j ACCEPT"); v4["FORWARD"].remove("-i br-hexstrike -j ACCEPT")'
check_tamper "pentest-net hook missing" 'v4["DOCKER-USER"].remove("'"$HOOK"'")' "no jump from DOCKER-USER into SECOPS-SCOPE for br-pentest"
tamper 'v4["DOCKER-USER"].remove("'"$HOOKH"'")'
expect ALLOW $HEX 1.1.1.1 443
check_tamper "hexstrike-net hook missing" 'pass' "no jump from DOCKER-USER into SECOPS-SCOPE for br-hexstrike"
tamper 'v4["DOCKER-USER"].insert(2, "'"$GUARD"'")'
expect BLOCK $TERM_IP 10.1.2.3 80                        # (a guard after the hooks still blocks the scope)
check_tamper "pentest-net guard left" 'pass' "a guard rule left by a failed apply blocks all of br-pentest"
check_tamper "hexstrike-net guard left" 'v4["DOCKER-USER"].append("'"$GUARDH"'")' "a guard rule left by a failed apply blocks all of br-hexstrike"
tamper 'v4["INPUT"].pop(1)'
expect ALLOW $HEX 172.30.1.1 2375
check_tamper "hexstrike-net INPUT rule missing" 'pass' "can reach the Docker VM itself"
check_tamper "INPUT rules not first" 'v4["INPUT"].insert(0, "-i br-pentest -j ACCEPT")' "can reach the Docker VM itself"
check_tamper "IPv6 on for br-hexstrike" 's["sysctl"]["net.ipv6.conf.br-hexstrike.disable_ipv6"] = "0"' "IPv6 is on for br-hexstrike"
tamper 's["sysctl"]["net.bridge.bridge-nf-call-iptables"] = "0"'
expect ALLOW 172.30.1.10 $HEX 8888                       # (bridged traffic then skips iptables)
check_tamper "bridge netfilter off" 'pass' "bridge netfilter is off"
check_tamper "chain missing" 'v4["DOCKER-USER"].remove("'"$HOOK"'"); v4["DOCKER-USER"].remove("'"$HOOKH"'"); del v4["SECOPS-SCOPE"]' "the SECOPS-SCOPE chain is missing"
expect BLOCK 172.30.1.10 $HEX 8888

# ---- fail closed: whichever call fails during a re-apply, nothing out of scope opens, success is never
# claimed for a broken firewall, and the message says what really happened
must scope apply; cp "$FAKE_IPT_STATE" "$T/good.json"; c0=$(calls)
must scope apply; per_apply=$(( $(calls) - c0 ))
[ "$per_apply" -gt 30 ] && ok "apply makes $per_apply iptables calls (read-back included)" || bad "apply made only $per_apply calls"
probes="$TERM_IP:1.1.1.1:443 $TERM_IP:10.1.2.4:80 $TERM_IP:192.168.65.254:11434 $TERM_IP:8.8.8.8:53 $TERM_IP:$HEX:8888
        $TERM_IP:172.30.0.1:2375 $TERM_IP:172.30.1.1:2375 $TERM_IP:192.168.65.3:22 $TERM_IP:172.30.0.201:22
        $HEX:1.1.1.1:443 $HEX:192.168.65.254:11434 $HEX:172.30.1.1:2375 $HEX:$TERM_IP:22
        172.30.0.10:10.1.2.3:80 172.30.1.10:$HEX:8888"
leaks(){ "$PY" "$FAKE" --verdicts $probes | paste -d' ' - <(printf '%s\n' $probes) | grep '^ALLOW' | cut -d' ' -f2; }
must scope off; [ "$(leaks | wc -l | tr -d ' ')" -ge 10 ] && ok "the leak probes see an open firewall" || bad "leak probes with the hooks removed: $(leaks | tr '\n' ' ')"
must scope apply; [ -z "$(leaks)" ] && ok "and nothing with it on" || bad "leaks with the firewall on: $(leaks | tr '\n' ' ')"
opened=0; lied=0; reported=0; dishonest=0
for k in $(seq 1 "$per_apply"); do
  cp "$T/good.json" "$FAKE_IPT_STATE"; c0=$(calls)
  if FAKE_IPT_FAIL_AT=$((c0 + k)) run scope apply; then
    { [ "$(v $TERM_IP 10.1.2.3 80)" = ALLOW ] && as_written "$T/good.json"; } || { lied=$((lied+1)); echo "  call $k failing: success reported, firewall not as written"; }
  else
    reported=$((reported+1))
    grep "no scope firewall yet" "$T/out" >/dev/null && { dishonest=$((dishonest+1)); echo "  call $k failing: a re-apply called a fresh VM"; }
    if grep "pentest-net and hexstrike-net traffic stays blocked" "$T/out" >/dev/null; then
      [ "$(v $TERM_IP 10.1.2.3 80)$(v $HEX 10.1.2.3 80)" = BLOCKBLOCK ] || { dishonest=$((dishonest+1)); echo "  call $k failing: says blocked, isn't"; }
    elif grep "pentest-net traffic stays blocked" "$T/out" >/dev/null; then
      [ "$(v $TERM_IP 10.1.2.3 80)$(v $HEX 10.1.2.3 80)" = BLOCKALLOW ] || { dishonest=$((dishonest+1)); echo "  call $k failing: says pentest-net blocked, hexstrike-net as before; isn't"; }
    elif grep "before the scope rules changed" "$T/out" >/dev/null; then
      same_scope "$T/good.json" || { dishonest=$((dishonest+1)); echo "  call $k failing: says the scope rules are unchanged, aren't"; }
    elif grep "before anything was changed" "$T/out" >/dev/null; then
      same_vm "$T/good.json" || { dishonest=$((dishonest+1)); echo "  call $k failing: says unchanged, isn't"; }
    elif ! grep "isn't the one just written" "$T/out" >/dev/null; then
      dishonest=$((dishonest+1)); echo "  call $k failing: unexplained failure"; sed 's/^/    /' "$T/out"
    fi
  fi
  for probe in $(leaks); do opened=$((opened+1)); echo "  call $k failing let through $probe"; done
done
[ $opened -eq 0 ] && ok "no single failed call opens anything" || bad "$opened probes got through after a failed call"
[ $lied -eq 0 ] && ok "no failed call is reported as success" || bad "$lied failures reported as success"
[ $dishonest -eq 0 ] && ok "every failure message matches the firewall's real state" || bad "$dishonest misleading failure messages"
[ $reported -ge $((per_apply - 12)) ] && ok "failed calls reported ($reported of $per_apply)" || bad "only $reported of $per_apply failures reported"
# Failed applies pile up guard rules; the next good apply removes all of them.
cp "$T/good.json" "$FAKE_IPT_STATE"; c0=$(calls)
must scope apply; k_chain=$(nth_call "$c0" "-A SECOPS-SCOPE -j REJECT --reject-with icmp-net-prohibited")
c0=$(calls); FAKE_IPT_FAIL_AT=$((c0 + k_chain)) run scope apply
c0=$(calls); FAKE_IPT_FAIL_AT=$((c0 + k_chain)) run scope apply
[ "$(st 'v4["DOCKER-USER"].count("'"$GUARD"'") + v4["DOCKER-USER"].count("'"$GUARDH"'")')" = 4 ] && ok "two failed applies left four guards" \
  || bad "guards after failures: $(st 'v4["DOCKER-USER"]')"
expect BLOCK $TERM_IP 10.1.2.3 80
must scope apply && ok "a good apply after failed ones succeeds"
[ "$(st 'v4["DOCKER-USER"][:2]')" = "['$HOOK', '$HOOKH']" ] && [ "$(st 'sum("REJECT" in r for r in v4["DOCKER-USER"])')" = 0 ] \
  && [ "$(st 'v4["DOCKER-USER"].count("'"$HOOK"'") + v4["DOCKER-USER"].count("'"$HOOKH"'")')" = 2 ] && ok "every guard removed, one hook per bridge, first" \
  || bad "DOCKER-USER: $(st 'v4["DOCKER-USER"]')"
expect ALLOW $TERM_IP 10.1.2.3 80
# Another program empties DOCKER-USER just as an apply fails with its guards in: no "stays blocked" claim
c0=$(calls); FAKE_IPT_FAIL_AT=$((c0 + k_chain)) FAKE_IPT_FAIL_FLUSH=DOCKER-USER run scope apply
hasnot "stays blocked" "a failed apply whose guards were removed meanwhile doesn't claim traffic is blocked"
has "egress may be open until an apply succeeds" "...it says egress may be open"
expect ALLOW $TERM_IP 1.1.1.1 443                        # (which it is)
must scope apply && expect BLOCK $TERM_IP 1.1.1.1 443

# ---- one firewall change at a time (scope lock): an apply waits while another runs, and concurrent ones
# (two terminal tabs) never leave the bridges open
mkdir -p "$T/owner"; printf '#!/bin/sh\nwhile :; do sleep 1; done\n' > "$T/owner/secstack"; chmod +x "$T/owner/secstack"
"$T/owner/secstack" & owner=$!
mkdir "$SECOPS/run/scope.lock"; echo "$owner" > "$SECOPS/run/scope.lock/pid"     # another secstack is applying
n0=$(vm_scripts); run scope apply & applier=$!
sleep 2; [ "$(vm_scripts)" = "$n0" ] && kill -0 "$applier" 2>/dev/null && ok "an apply waits while another holds the scope lock" \
  || bad "an apply went ahead while another held the scope lock"
rm -rf "$SECOPS/run/scope.lock"                           # the other one is done
wait "$applier" && ok "...and goes ahead once the lock is released" || { bad "the waiting apply failed:"; sed 's/^/    /' "$T/out"; }
kill "$owner"; wait "$owner" 2>/dev/null
mkdir "$SECOPS/run/scope.lock"; echo 99999999 > "$SECOPS/run/scope.lock/pid"     # its owner died mid-apply
must scope apply && ok "a lock whose owner is gone is taken over"
[ ! -e "$SECOPS/run/scope.lock" ] && ok "the scope lock is released after an apply" || bad "scope lock left behind"
must scope apply; cp "$FAKE_IPT_STATE" "$T/conc.json"; raced=0
for round in 1 2 3 4; do
  bash "$S" scope apply >"$T/c1.out" 2>&1 & a=$!
  bash "$S" scope apply >"$T/c2.out" 2>&1 & b=$!
  wait "$a"; ra=$?; wait "$b"; rb=$?
  if [ $ra$rb != 00 ] || ! as_written "$T/conc.json" || [ "$(st 'sum("REJECT" in r for r in v4["DOCKER-USER"])')" != 0 ]; then
    raced=$((raced + 1)); echo "  round $round: exit $ra/$rb, DOCKER-USER: $(st 'v4["DOCKER-USER"]')"; cat "$T/c1.out" "$T/c2.out" | sed 's/^/    /'
  fi
done
[ $raced -eq 0 ] && ok "two applies at once both succeed and leave the firewall as written (4 rounds)" || bad "$raced of 4 concurrent rounds went wrong"
expect BLOCK $TERM_IP 1.1.1.1 443

# ---- narrowing: open connections die, a failure before any change says so, strict sticks
must scope off && expect ALLOW $TERM_IP 203.0.113.9 443
expect ALLOW $TERM_IP 203.0.113.9 443 est               # an agent opens a channel while it's off
expect ALLOW 172.30.0.10 10.1.2.3 80 est                # ...and so does the lab
must scope apply
expect BLOCK $TERM_IP 203.0.113.9 443 est               # both are cut when the scope returns
expect BLOCK 172.30.0.10 10.1.2.3 80 est
expect BLOCK 172.30.1.10 10.1.2.3 80 est
printf '10.9.9.9/32 # other\n' >> "$SC"; must scope apply; expect ALLOW $TERM_IP 10.9.9.9 22 est
grep -v '^10.9.9.9/32' "$SC" > "$T/sc.tmp"; cat "$T/sc.tmp" > "$SC"; must scope apply   # hand-edited narrowing
expect BLOCK $TERM_IP 10.9.9.9 22 est
printf '10.9.9.9/32 # other\n' >> "$SC"; must scope apply
cp "$FAKE_IPT_STATE" "$T/wide.json"; c0=$(calls); must scope apply
k_guard=$(nth_call "$c0" "-I DOCKER-USER 1 $GUARD")       # the first change when INPUT and FORWARD are right
cp "$T/wide.json" "$FAKE_IPT_STATE"; c0=$(calls)
FAKE_IPT_FAIL_AT=$((c0 + k_guard)) run scope rm 10.9.9.9; rc=$?
[ $rc -ne 0 ] && ok "scope rm with a failed first change fails" || bad "scope rm reported success"
has "before the scope rules changed: the previous ones are still in force" "says the scope rules didn't change"
hasnot "stays blocked" "doesn't claim traffic is blocked"
has "unexpected rule: -d 10.9.9.9/32 -j RETURN" "shows the rule still in force"
same_vm "$T/wide.json" && expect ALLOW $TERM_IP 10.9.9.9 22
must scope apply && expect BLOCK $TERM_IP 10.9.9.9 22
# INPUT rules missing (as after `iptables -F INPUT`): the apply puts them back first; if that fails, the scope
# rules are untouched and the message says so
tamper 'v4["INPUT"] = []'; cp "$FAKE_IPT_STATE" "$T/noinput.json"; c0=$(calls)
FAKE_IPT_FAIL_AT=$((c0 + 3)) run scope apply                # probe, INPUT read, first INPUT insert
has "before the scope rules changed: the previous ones are still in force" "a failed INPUT repair says the scope rules didn't change"
has "can reach the Docker VM itself" "...and shows the INPUT problem"
same_vm "$T/noinput.json" && ok "a failed INPUT repair changed nothing" || bad "a failed INPUT repair changed the firewall"
must scope apply && [ "$(st 'v4["INPUT"]')" = "['$INPUT_RULE', '$INPUT_RULEH']" ] && ok "apply restores the INPUT rules" || bad "INPUT: $(st 'v4["INPUT"]')"
# A held xtables lock when the apply first looks at the VM is a failed read, not a fresh VM
c0=$(calls); cp "$FAKE_IPT_STATE" "$T/before.json"
FAKE_IPT_FAIL_AT=$((c0 + 1)) run scope apply && bad "apply succeeded with its first look failing" \
  || has "couldn't read the firewall in the Docker VM: scope apply failed before anything was changed" "a failed first look is reported"
same_vm "$T/before.json" && ok "...and changes nothing" || bad "a failed first look changed the firewall"
printf '10.9.9.9/32 # other\n' >> "$SC"; must scope apply; touch "$T/docker_run_fail"
run scope rm 10.9.9.9; has "before anything was changed" "a docker failure says nothing was changed"
rm -f "$T/docker_run_fail"; must scope apply
before=$(flushes); b_any=$(any_flush); printf '10.9.9.9/32 # other\n' >> "$SC"; must scope apply
[ "$(any_flush)" = "$b_any" ] && ok "a plain apply doesn't flush" || bad "plain apply flushed"
must scope rm 10.9.9.9/32 && [ "$(flushes)" -gt "$before" ] && ok "scope rm flushes tracked connections on both bridges" || bad "scope rm didn't flush both bridges"
grep '^10.1.2.3/32' "$SC" >/dev/null && ! grep '^10.9.9.9/32' "$SC" >/dev/null && ok "rm is exact" || bad "rm removed the wrong lines"
mv "$T/fake/conntrack" "$T/conntrack.off"; printf '10.9.9.9/32 # other\n' >> "$SC"; must scope apply
must scope rm 10.9.9.9 && has "no conntrack in the Docker VM" "a missing conntrack is reported, not silent"
mv "$T/conntrack.off" "$T/fake/conntrack"
must scope install; c0=$(calls)
FAKE_IPT_FAIL_AT=$((c0 + 10)) run scope strict
has "pentest-net and hexstrike-net traffic stays blocked" "a failed strict (guards in) says traffic is blocked"
[ "$(cat "$MODE")" = strict ] && ok "a failed strict still records strict" || bad "mode is $(cat "$MODE") after a failed strict"
must scope apply && expect BLOCK $TERM_IP 1.1.1.1 443 && [ "$(st '"-p tcp -m multiport --dports 80,443 -j RETURN" in v4["SECOPS-SCOPE"]')" = no ] \
  && ok "the next apply stays strict"
run scope rm 10.9.9.9/32 && bad "rm of an absent entry succeeded" || ok "rm of an absent entry fails"

# ---- the VM's own uplink network is reserved, wherever Docker Desktop puts it
export FAKE_UPLINK=198.18.0.5/24
cp "$SC" "$T/sc.before"
mustnot scope add 198.18.0.0/16 && has "198.18.0.0/24" "scope add refuses the VM's uplink network" && cmp -s "$SC" "$T/sc.before" && ok "scope.cidrs unchanged"
must scope apply
[ "$(st '"-d 198.18.0.0/24 -j REJECT --reject-with icmp-net-prohibited" in v4["SECOPS-SCOPE"]')" = yes ] && ok "uplink network rejected in the chain" || bad "no REJECT for 198.18.0.0/24"
must scope install; snap uplink
expect BLOCK $TERM_IP 198.18.0.254 443                  # host.docker.internal on a custom subnet
expect BLOCK $HEX 198.18.0.5 22                         # the VM itself
expect ALLOW $TERM_IP 1.1.1.1 443
must scope strict
FAKE_HDI="" run scope test; has "host.docker.internal 198.18.0.254:11434 blocked" "scope test falls back to the uplink's .254"
FAKE_HDI=198.18.0.77 run scope test; has "host.docker.internal 198.18.0.77:11434 blocked" "scope test probes the address host.docker.internal resolves to"
tamper 'v4["SECOPS-SCOPE"].insert(0, "-d 198.18.0.77/32 -j RETURN")'
FAKE_HDI=198.18.0.77 run scope test && bad "scope test missed a leak to host.docker.internal" \
  || has "host.docker.internal 198.18.0.77:11434 REACHABLE (leak)" "scope test catches a leak to the resolved host.docker.internal"
export FAKE_UPLINK=""
cp "$FAKE_IPT_STATE" "$T/before.json"; n0=$(vm_scripts)
mustnot scope apply && has "couldn't read the Docker VM's own network" "no uplink: refuses to apply"
same_vm "$T/before.json" && [ "$(vm_scripts)" = $((n0 + 1)) ] && ok "no uplink: nothing after the probe ran" || bad "no uplink: $(( $(vm_scripts) - n0 )) VM scripts ran"
unset FAKE_UPLINK; must scope apply

# ---- bridge netfilter that can't be turned on, or stays off, fails closed; so does IPv6 that stays on
tamper 's["sysctl"]["net.bridge.bridge-nf-call-iptables"] = "0"'
FAKE_BRNF_LOCKED=1 run scope apply && bad "apply succeeded without bridge netfilter" || has "stays blocked" "bridge netfilter refused: apply fails, blocked"
expect BLOCK $TERM_IP 10.1.2.3 80
expect BLOCK $HEX 1.1.1.1 443
FAKE_SYSCTL_STUCK=net.bridge.bridge-nf-call-iptables run scope apply && bad "apply succeeded with bridge netfilter stuck off" \
  || has "stays blocked" "bridge netfilter stuck off (the write 'succeeds'): apply fails, blocked"
expect BLOCK $TERM_IP 10.1.2.3 80
must scope apply && expect ALLOW $TERM_IP 10.1.2.3 80
tamper 's["sysctl"]["net.ipv6.conf.br-hexstrike.disable_ipv6"] = "0"'
FAKE_SYSCTL_STUCK=net.ipv6.conf.br-hexstrike.disable_ipv6 run scope apply && bad "apply succeeded with IPv6 stuck on" \
  || has "stays blocked" "IPv6 stuck on for br-hexstrike: apply fails, blocked"
expect BLOCK $HEX 10.1.2.3 80
must scope apply && expect ALLOW $HEX 10.1.2.3 80
# ...and a VM without IPv6 has nothing to switch off
FAKE_NO_IPV6=1 must scope apply && FAKE_NO_IPV6=1 run scope show && has "match scope.cidrs" "no IPv6 in the VM: applies, reads back"

# ---- scope test runs its probes through the firewall, from both bridges
must scope test && ok "scope test passes with the firewall on"
[ "$(sort -u "$T/probe_log" | tr '\n' ' ')" = "hexstrike-net pentest-net " ] && ok "scope test probes from both bridges" || bad "probes from: $(cat "$T/probe_log")"
has "pentest-net  IN-SCOPE   10.1.2.3 reachable" "scope test reaches the in-scope host"
has "pentest-net  BRIDGE     hexstrike $HEX:8888 blocked" "scope test probes HexStrike from the terminals' bridge"
has "hexstrike-net  BRIDGE     hexstrike $HEX:8888 blocked" "and from its own"
tamper 'v4["SECOPS-SCOPE"].insert(0, "-d 172.30.1.5/32 -o br-hexstrike -j RETURN")'
run scope test && bad "scope test missed a bridge leak" || has "hexstrike-net  BRIDGE     hexstrike $HEX:8888 REACHABLE (leak)" "scope test catches a bridge leak"
must scope apply; must scope off
run scope test && bad "scope test passed with the hooks removed" || has "1.1.1.1:443 REACHABLE (leak)" "scope test fails on a leak"
must scope apply

# ---- containers on either bridge never restart with Docker (they'd beat the firewall)
dk 'C.update({
 "pentagi-terminal-1": {"id": "t1", "nets": {"pentest-net": ""}, "ports": "", "capdrop": "[]", "policy": "on-failure", "autoremove": False, "running": True},
 "pentagi-terminal-2": {"id": "t2", "nets": {"pentest-net": ""}, "ports": "", "capdrop": "[]", "policy": "no", "autoremove": False, "running": False},
 "pentagi-terminal-3": {"id": "t3", "nets": {"pentest-net": ""}, "ports": "", "capdrop": "[]", "policy": "unless-stopped", "autoremove": False, "running": False, "update_fail": True},
 "hexstrike": {"id": "h1", "nets": {"hexstrike-net": "172.30.1.5"}, "ports": "", "capdrop": "[]", "policy": "always", "autoremove": True, "running": True},
 "hex-sidecar": {"id": "h2", "nets": {"hexstrike-net": ""}, "ports": "", "capdrop": "[]", "policy": "always", "autoremove": False, "running": False},
 "elsewhere": {"id": "e1", "nets": {"bridge": ""}, "ports": "", "capdrop": "[]", "policy": "always", "autoremove": False, "running": True}})'
n0=$(dlog_len)
must scope apply && ok "apply succeeds although one restart policy can't be changed"
[ "$(dq 'C["pentagi-terminal-1"]["policy"] + C["hex-sidecar"]["policy"]')" = nono ] && ok "restart=no on both bridges" \
  || bad "policies: $(dq '[(n, c["policy"]) for n, c in C.items()]')"
has "couldn't set restart=no on pentagi-terminal-3" "a failed update warns"
dlog_since "$n0" | grep -e 'update.* t2$' -e 'update.* h1$' -e 'update.* e1$' >/dev/null && bad "updated a container it must leave alone" \
  || ok "restart=no left alone: policy no, --rm, other networks"
[ "$(dq 'C["elsewhere"]["policy"]')" = always ] && ok "containers off both bridges untouched" || bad "elsewhere changed"
dk 'for n in ("pentagi-terminal-1", "pentagi-terminal-2", "pentagi-terminal-3", "hexstrike", "hex-sidecar", "elsewhere"): del C[n]'

# ---- a fresh VM (Docker restarted): what came back by itself is stopped while the guards block it
dk 'C["pentagi-terminal-7"] = {"id": "t7", "nets": {"pentest-net": ""}, "ports": "", "capdrop": "[]", "policy": "on-failure", "autoremove": False, "running": True}'
dk 'C["hex-came-back"] = {"id": "h7", "nets": {"hexstrike-net": ""}, "ports": "", "capdrop": "[]", "policy": "always", "autoremove": False, "running": True}'
rm -f "$FAKE_IPT_STATE"; : > "$T/stop_log"
must scope apply && ok "apply on a fresh VM"
[ "$(dq 'C["pentagi-terminal-7"]["running"]')" = False ] && ok "a terminal that came back with Docker is stopped" || bad "terminal still running"
grep -E '^kill pentagi-terminal-7 firewall=no guards=yes' "$T/stop_log" >/dev/null && ok "...killed (not docker stop) while the guards blocked it" \
  || bad "stopped without the guards in: $(cat "$T/stop_log")"
[ "$(dq 'C["hex-came-back"]["running"]')" = False ] && grep -E '^kill hex-came-back firewall=no guards=yes' "$T/stop_log" >/dev/null \
  && ok "a hexstrike-net container that came back with Docker is stopped too, while the guards blocked it" \
  || bad "hexstrike-net container: running=$(dq 'C["hex-came-back"]["running"]'), stops: $(cat "$T/stop_log")"
dk 'del C["hex-came-back"]'
[ "$(st 'v4["DOCKER-USER"][:2]')" = "['$HOOK', '$HOOKH']" ] && ok "the firewall is complete afterwards" || bad "DOCKER-USER: $(st 'v4["DOCKER-USER"]')"
dk 'C["pentagi-terminal-7"]["running"] = True'; must scope off; : > "$T/stop_log"
must scope apply; [ "$(dq 'C["pentagi-terminal-7"]["running"]')" = True ] && [ ! -s "$T/stop_log" ] && ok "after scope off (not a fresh VM) nothing is stopped" \
  || bad "a running terminal was stopped on a plain re-apply"
c0=$(calls); FAKE_IPT_FAIL_AT=$((c0 + 1)) run scope apply
[ "$(dq 'C["pentagi-terminal-7"]["running"]')" = True ] && [ ! -s "$T/stop_log" ] && ok "a held xtables lock at the first look stops nothing" \
  || bad "a failed first look was taken for a fresh VM"
rm -f "$FAKE_IPT_STATE"; FAKE_IPT_FAIL_AT=1 run scope apply   # the same on a restarted VM: it has no rules at all
hasnot "the previous firewall rules are still in force" "a failed first look doesn't promise previous rules (the VM may have restarted)"
has "or none if Docker restarted since the last apply" "...and says what a restart leaves"
# Whichever call fails during the apply on a fresh VM: what came back with Docker is stopped all the same,
# success is never claimed for a firewall that isn't as written, and the message says what is really in force.
rm -f "$FAKE_IPT_STATE"; must scope apply; cp "$FAKE_IPT_STATE" "$T/fresh_good.json"; per_fresh=$(calls)
lied=0; dishonest=0; kept=0
for k in $(seq 1 "$per_fresh"); do
  rm -f "$FAKE_IPT_STATE"; dk 'C["pentagi-terminal-7"]["running"] = True'
  if FAKE_IPT_FAIL_AT=$k run scope apply; then
    as_written "$T/fresh_good.json" || { lied=$((lied+1)); echo "  fresh, call $k failing: success reported, firewall not as written"; }
  elif grep "pentest-net and hexstrike-net traffic stays blocked" "$T/out" >/dev/null; then
    [ "$(v $TERM_IP 10.1.2.3 80)$(v $HEX 10.1.2.3 80)" = BLOCKBLOCK ] || { dishonest=$((dishonest+1)); echo "  fresh, call $k failing: says blocked, isn't"; }
  elif grep "pentest-net traffic stays blocked until an apply succeeds, and hexstrike-net has no scope firewall yet" "$T/out" >/dev/null; then
    [ "$(v $TERM_IP 10.1.2.3 80)" = BLOCK ] || { dishonest=$((dishonest+1)); echo "  fresh, call $k failing: says pentest-net blocked, isn't"; }
  elif ! grep -e "has no scope firewall yet, so pentest-net and hexstrike-net are not scope-limited" -e "isn't the one just written" "$T/out" >/dev/null \
       && ! { [ $k = 1 ] && grep "couldn't read the firewall" "$T/out" >/dev/null; }; then
    dishonest=$((dishonest+1)); echo "  fresh, call $k failing: misleading message"; sed 's/^/    /' "$T/out"
  fi
  [ $k = 1 ] || [ "$(dq 'C["pentagi-terminal-7"]["running"]')" = False ] || { kept=$((kept+1)); echo "  fresh, call $k failing: the terminal kept running"; }
done
[ $lied -eq 0 ] && ok "fresh VM: no failed call is reported as success ($per_fresh calls)" || bad "fresh VM: $lied failures reported as success"
[ $dishonest -eq 0 ] && ok "fresh VM: every failure message matches the firewall's real state" || bad "fresh VM: $dishonest misleading failure messages"
[ $kept -eq 0 ] && ok "fresh VM: whichever call fails, what came back with Docker is stopped" || bad "fresh VM: $kept failures left the terminal running"
dk 'del C["pentagi-terminal-7"]'; rm -f "$FAKE_IPT_STATE"; must scope apply

# ---- the lab: arguments and the 127.0.0.2 alias are checked before anything happens
cp "$FAKE_IPT_STATE" "$T/before.json"; n0=$(dlog_len)
mustnot lab up --ui && has "sudo ifconfig lo0 alias 127.0.0.2 up" "lab up --ui without the alias says how to add it"
dlog_since "$n0" | grep -E '^docker (run|create|rm|start)' >/dev/null && bad "lab up --ui acted before checking the alias" || ok "lab up --ui changed nothing without the alias"
same_vm "$T/before.json" && ok "no firewall change either" || bad "firewall changed"
touch "$T/lo0_alias"
rm -f "$FAKE_IPT_STATE"; : > "$T/start_log"                # a fresh VM: the firewall goes in before the lab starts
must lab up --ui && has "http://127.0.0.2:8081" "lab --ui lives on 127.0.0.2"
[ "$(grep -c 'firewall=yes' "$T/start_log")" = 2 ] && ok "lab starts only once the firewall is in (fresh VM)" || bad "lab start: $(cat "$T/start_log")"
grep -e '-p 127.0.0.2:8081:80' "$T/create_log" >/dev/null && grep -e '-p 127.0.0.2:8082:3000' "$T/create_log" >/dev/null \
  && ! grep '127.0.0.1:808' "$T/create_log" >/dev/null && ok "lab ports published on 127.0.0.2 only" || { bad "lab ports:"; cat "$T/create_log"; }
[ "$(grep -c -e '--cap-drop NET_RAW' "$T/create_log")" = 2 ] && [ "$(grep -c -e '--restart=no' "$T/create_log")" = 2 ] && ok "lab: NET_RAW dropped, no restart" || bad "lab create flags"
lab_nets='sorted(C["lab-dvwa"]["nets"].items()) + sorted(C["lab-juice"]["nets"].items())'
LAB_NETS="[('hexstrike-net', '172.30.1.10'), ('pentest-net', '172.30.0.10'), ('hexstrike-net', '172.30.1.11'), ('pentest-net', '172.30.0.11')]"
[ "$(dq "$lab_nets")" = "$LAB_NETS" ] && [ "$(dq 'C["lab-juice"]["running"]')" = True ] && ok "lab on both bridges at its addresses, running" || bad "lab: $(dq 'C')"
[ "$(dq 'C["lab-dvwa"]["image"]')" = "$DVWA_IMAGE" ] && ok "lab from the pinned image" || bad "lab image $(dq 'C["lab-dvwa"]["image"]')"
creates(){ wc -l < "$T/create_log" | tr -d ' '; }
n=$(creates); must lab up --ui; [ "$(creates)" = "$n" ] && ok "a correct lab is kept" || bad "a correct lab was recreated"
must lab up; [ "$(dq 'C["lab-dvwa"]["ports"]')" = "" ] && ok "lab up without --ui drops the published ports" || bad "ports kept"
for change in 'del C["lab-dvwa"]["nets"]["hexstrike-net"]' 'C["lab-juice"]["nets"]["pentest-net"] = "172.30.0.12"' \
              'C["lab-juice"]["nets"]["hexstrike-net"] = "172.30.1.12"' 'C["lab-dvwa"]["nets"]["bridge"] = ""' \
              'C["lab-juice"]["capdrop"] = "[]"' 'C["lab-dvwa"]["ports"] = "127.0.0.1:8081 "' 'C["lab-dvwa"]["image"] = "vulnerables/web-dvwa:latest"'; do
  dk "$change"; n=$(creates); must lab up
  [ "$(creates)" -gt "$n" ] && [ "$(dq "$lab_nets")" = "$LAB_NETS" ] && [ "$(dq 'C["lab-dvwa"]["image"]')" = "$DVWA_IMAGE" ] \
    && [ "$(dq 'C["lab-juice"]["capdrop"] + C["lab-dvwa"]["ports"]')" = "[CAP_NET_RAW]" ] && ok "recreated a lab that wasn't ours: $change" || bad "kept a wrong lab: $change -> $(dq 'C')"
done
mustnot lab up --ui --ui && ok "lab up refuses extra arguments (alias present)"
mustnot lab up "" && ok "lab up refuses an empty argument"
n0=$(dlog_len); mustnot lab reset --bogus && ok "lab reset refuses an unknown argument"
dlog_since "$n0" | grep '^docker rm' >/dev/null && bad "lab reset removed the lab before checking its arguments" || ok "lab reset removed nothing"
rm -f "$T/lo0_alias"; n0=$(dlog_len)
if mustnot lab reset --ui; then
  dlog_since "$n0" | grep '^docker rm' >/dev/null && bad "lab reset --ui removed the lab without the alias" || ok "lab reset --ui checks the alias first"
fi
mustnot lab down now && ok "lab down refuses extra arguments"
must lab down && [ "$(dq 'C["lab-dvwa"]["running"]')" = False ] && ok "lab down stops the lab"

# ---- mcp on: HexStrike starts only once the scope firewall is in, and not at all when it can't be applied
touch "$T/hexstrike_image"; rm -f "$FAKE_IPT_STATE"; : > "$T/start_log"     # a fresh VM
must mcp on && has "hexstrike up on 127.0.0.1:8888" "mcp on starts HexStrike"
grep -x 'run hexstrike firewall=yes guards=no' "$T/start_log" >/dev/null && ok "...only once the scope firewall is in (fresh VM)" \
  || bad "HexStrike started without the firewall: $(cat "$T/start_log")"
touch "$T/docker_run_fail"; : > "$T/start_log"            # the firewall can't be applied
mustnot mcp on && has "couldn't read the Docker VM's own network" "mcp on fails when the firewall can't be applied"
[ ! -s "$T/start_log" ] && ok "...and starts nothing" || bad "HexStrike started although the firewall couldn't be applied"
rm -f "$T/docker_run_fail" "$T/hexstrike_image"

# ---- a network made some other way is refused, field by field, and nothing reaches the VM
must scope apply; cp "$FAKE_IPT_STATE" "$T/before.json"; n0=$(vm_scripts)
for net in pentest-net hexstrike-net; do
  dk 'd["good"] = dict(d["nets"]["'"$net"'"])'
  for change in '"driver": "macvlan"' '"bridge": "br-0123456789ab"' '"subnet": "172.31.0.0/24"' '"range": "172.30.0.0/25"' '"ipv6": "true"'; do
    dk 'd["nets"]["'"$net"'"] = dict(d["good"], **{'"$change"'})'
    mustnot scope apply && has "$net isn't the network secstack creates" "refused a $net with $change"
  done
  dk 'd["nets"]["'"$net"'"] = d.pop("good")'
done
same_vm "$T/before.json" && [ "$(vm_scripts)" = "$n0" ] && ok "nothing ran in the VM for foreign networks" || bad "the VM was touched for a foreign network"
dk 'd["nets"]["pentest-net"]["bridge"] = "br-0123456789ab"'   # a plain pentest-net (pentagi makes one when it's missing)
run scope show; has "pentest-net isn't the network secstack creates" "scope show checks the networks too"
hasnot "match scope.cidrs" "...and reports no match for a network the rules don't cover"
dk 'd["nets"]["pentest-net"]["bridge"] = "br-pentest"'
must scope apply && ok "secstack's own networks still pass"
dk 'del d["nets"]["hexstrike-net"]'                       # an install from before hexstrike-net
mustnot scope test && has "hexstrike-net doesn't exist yet: secstack scope apply creates it" "a missing hexstrike-net is named, with the fix"
must scope apply && [ "$(dq 'd["nets"]["hexstrike-net"]["bridge"]')" = br-hexstrike ] && ok "scope apply creates the missing hexstrike-net"

# ---- the firewall image must be pinned by digest, for every command that enters the VM
mkdir -p "$T/repo"; cp -R "$SRC_REPO/bin" "$SRC_REPO/scripts" "$SRC_REPO/upstream" "$SRC_REPO/configs" "$SRC_REPO/models" "$T/repo/" 2>/dev/null
chmod -R u+w "$T/repo"; sed 's/^ALPINE_IMAGE=.*/ALPINE_IMAGE=alpine:3/' "$SRC_REPO/upstream/images.lock" > "$T/repo/upstream/images.lock"
cp "$FAKE_IPT_STATE" "$T/before.json"
for cmd in apply off show; do
  n0=$(vm_scripts)
  bash "$T/repo/bin/secstack" scope "$cmd" >"$T/out" 2>&1
  [ "$cmd" = show ] && has "doesn't match" "scope show with a tagged alpine reports instead of reading"
  has "pinned by digest" "scope $cmd with a tagged alpine says why"
  [ "$(vm_scripts)" = "$n0" ] && same_vm "$T/before.json" && ok "scope $cmd ran nothing in the VM with a tag" || bad "scope $cmd ran a script with an unpinned image"
done

# ---- every rule secstack writes is exactly what real iptables prints back
if [ "$(id -u)" = 0 ] && command -v unshare >/dev/null 2>&1 && unshare -n true 2>/dev/null; then
  for f in strict install uplink; do
    out=$(unshare -n "$PY" -I - "$T/canon.$f.json" <<'PY'
import json, shutil, subprocess, sys
s = json.load(open(sys.argv[1]))
chains = {"SECOPS-SCOPE": s["v4"]["SECOPS-SCOPE"], "DOCKER-USER": s["v4"]["DOCKER-USER"][:2],
          "INPUT": s["v4"]["INPUT"][:2], "FORWARD": s["v4"]["FORWARD"][:1]}
tested, bad = [], []
for b in ("legacy", "nft"):
    exe = shutil.which("iptables-" + b)
    if not exe or subprocess.run([exe, "-S"], capture_output=True).returncode:
        continue
    for c in ("SECOPS-SCOPE", "DOCKER-USER"):
        subprocess.run([exe, "-N", c], capture_output=True)
    for c, rules in chains.items():
        for r in rules:
            p = subprocess.run([exe, "-A", c] + r.split(), capture_output=True, text=True)
            if p.returncode:
                bad.append("iptables-%s refused -A %s %s: %s" % (b, c, r, p.stderr.strip()))
        got = [l for l in subprocess.run([exe, "-S", c], capture_output=True, text=True).stdout.splitlines() if l.startswith("-A ")]
        if got != ["-A %s %s" % (c, r) for r in rules]:
            bad.append("iptables-%s prints %s differently: %s" % (b, c, got))
    tested.append("iptables-" + b)
print("tested " + " ".join(tested))
for x in bad:
    print("BAD " + x)
PY
)
    case "$out" in
      *BAD*) bad "rules secstack writes ($f) differ from what real iptables prints:"; printf '%s\n' "$out" | sed 's/^/    /' ;;
      "tested ") echo "SKIP real-iptables check ($f): no usable iptables here" ;;
      *) ok "real iptables prints every $f rule back verbatim (${out#tested })" ;;
    esac
  done
else
  echo "SKIP real-iptables check (needs root, unshare and a network namespace)"
fi

echo "scope: $pass passed, $fail failed"
[ $fail -eq 0 ]
