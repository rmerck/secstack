#!/usr/bin/env bash
# Functional test for `secstack audit` and the control commands around it (pentagi, artex, stop, down,
# llm start|stop, models, bench, the restart guard). Stubs: docker (a small simulator: containers as
# `docker inspect` JSON, networks, `docker events`, and the Docker VM's firewall through
# tests/func/fake_iptables.py, as in scope_test.sh), netstat, lsof, ifconfig, launchctl, sysctl, curl (the two
# Ollama instances), ollama, open (Docker Desktop, Ollama.app and the server log it writes), osascript,
# pkill/pgrep and du. No Docker, no Ollama, no root; nothing outside the temp folder is touched or killed.
#   bash tests/func/audit_test.sh        (from the repo root; needs python3)
# Greps read files, or all of a pipe (no grep -q on a pipe: with pipefail an early exit could fail the writer).
set -uo pipefail
SRC_REPO="$(cd "${1:-$(dirname "$0")/../..}" && pwd -P)"
T="$(cd "$(mktemp -d "${TMPDIR:-/tmp}/au.XXXXXX")" && pwd -P)"
VICTIMS=""
cleanup(){
  local p
  for p in $VICTIMS $(cat "$T/GH/.sec-ops/run/restart-guard.pid" 2>/dev/null) \
           $(ps ax -o pid=,command= 2>/dev/null | awk -v t="$T/" 'index($0, t) {print $1}'); do
    kill "$p" 2>/dev/null
  done
  rm -rf "$T"
}
trap cleanup EXIT
SIM="$T/sim"; export SIM
mkdir -p "$T/bin" "$T/fake" "$T/vmbin" "$T/fakeguard" "$SIM"
export HOME="$T/home" SECSTACK_GH="$T/GH" SECOPS="$T/GH/.sec-ops" PATH="$T/bin:$PATH" SECSTACK_HOSTS_FILE="$T/hosts"
export FAKE_IPT_STATE="$T/ipt.json"
unset OLLAMA_MODELS OLLAMA_HOST OLLAMA_ORIGINS SECSTACK_MODELS_DIR COMPOSE_FILE DOCKER_INSIDE DOCKER_NETWORK DOCKER_PUBLIC_IP
: > "$T/hosts"
S="$SRC_REPO/bin/secstack"
PD="$SECSTACK_GH/pentagi"; AD="$SECSTACK_GH/ARTEX"

# ---------------------------------------------------------------- stubs
cat > "$T/simlib.py" <<'PY'
import hashlib, json, os
S = os.environ["SIM"]
ST = os.path.join(S, "containers.json")
def load(path=ST, default=None):
    try:
        return json.load(open(path))
    except (OSError, ValueError):
        return [] if default is None else default
def save(data, path=ST):
    json.dump(data, open(path, "w"), indent=1)
def container(n, kv):
    dflt = "hexstrike-net" if n == "hexstrike" else "hexstrike-net,pentest-net" if n in ("lab-dvwa", "lab-juice") else "pentest-net"
    nets = [x for x in kv.get("nets", dflt).split(",") if x]   # where secstack puts each one
    mounts = []
    for m in filter(None, kv.get("mounts", "").split(";")):
        src, dst, typ = (m.split("|") + ["bind"])[:3]
        mounts.append({"Type": typ, "Source": src, "Destination": dst})
    ports = {}
    for d in filter(None, kv.get("ports", "").split(";")):
        ip, hp, cp = d.split("|")
        ports.setdefault(cp, []).append({"HostIp": ip, "HostPort": hp})
    run = kv.get("running", "1") == "1"
    lst = lambda k: [x for x in kv.get(k, "").split(",") if x] or None
    return {"Id": hashlib.sha256(n.encode()).hexdigest(), "Name": "/" + n,
            "State": {"Running": run, "Status": "running" if run else "exited"},
            "HostConfig": {"Privileged": kv.get("priv") == "1", "NetworkMode": kv.get("netmode", nets[0] if nets else "none"),
                           "PidMode": kv.get("pid", ""), "IpcMode": kv.get("ipc", "private"), "CapAdd": lst("capadd"),
                           "SecurityOpt": lst("secopt"), "Devices": [{"PathOnHost": "/dev/kmsg"}] if kv.get("devices") else [],
                           "DeviceCgroupRules": lst("devcg"),
                           "RestartPolicy": {"Name": kv.get("restart", "no")}, "AutoRemove": kv.get("rm") == "1"},
            "NetworkSettings": {"Networks": {x: {} for x in nets}, "Ports": ports},
            "Config": {"Env": [x for x in kv.get("env", "").split(";") if x]},
            "Mounts": mounts}
def add(n, kv):
    save([c for c in load() if c["Name"] != "/" + n] + [container(n, kv)])
PY
printf 'import sys, simlib\nsimlib.add(sys.argv[1], dict(x.split("=", 1) for x in sys.argv[2:]))\n' > "$T/cset.py"
cat > "$T/dockersim.py" <<'PY'
import json, os, re, subprocess, sys, time
import simlib
S = simlib.S
T = os.path.dirname(S)
NT = os.path.join(S, "nets.json")
def log(*a):
    with open(os.path.join(S, "docker.log"), "a") as f:
        f.write(" ".join(a) + "\n")
def name(c):
    return c["Name"].lstrip("/")
def find(cs, ref):
    return next((c for c in cs if c["Id"].startswith(ref) or name(c) == ref), None)
def tmpl(fmt, c):
    def rep(m):
        v = c
        for k in m.group(1).split("."):
            v = v.get(k) if isinstance(v, dict) else None
        return ("true" if v else "false") if isinstance(v, bool) else ("" if v is None else str(v))
    return re.sub(r"\{\{\s*\.([A-Za-z0-9_.]+)\s*\}\}", rep, fmt)
def net_fmt(fmt, n):   # the network templates secstack uses; anything else fails, so a change can't pass unseen
    for frag, val in (('{{range .IPAM.Config}}{{.Subnet}} {{.IPRange}}{{end}}', n["subnet"] + " " + n["range"]),
                      ('{{index .Options "com.docker.network.bridge.name"}}', n["bridge"]),
                      ("{{.Driver}}", n["driver"]), ("{{.EnableIPv6}}", n["ipv6"])):
        fmt = fmt.replace(frag, val)
    if "{{" in fmt:
        sys.exit("template: unknown fragment in " + fmt)
    return fmt
a = sys.argv[1:]
cmd = a[0] if a else ""
log(*([cmd, os.getcwd()] + a[1:] if cmd == "compose" else a))
if not os.path.exists(os.path.join(S, "docker_up")):
    sys.exit(1)
cs = simlib.load()
fmt = a[a.index("--format") + 1] if "--format" in a else None
flt = [a[i + 1].partition("=") for i, x in enumerate(a) if x == "--filter"]
if cmd == "info":
    if fmt:
        print("8 CPUs, 17179869184 bytes")
elif cmd == "ps":
    allc, quiet = any(x in a for x in ("-a", "-aq", "-qa")), any(x in a for x in ("-q", "-aq", "-qa"))
    nets = [v for k, _, v in flt if k == "network"]          # several network filters: any of them
    out = [c["Id"][:12] if quiet else (fmt or "{{.Names}}").replace("{{.Names}}", name(c)).replace("{{.Status}}", "Up")
           .replace("{{.Ports}}", "") for c in cs
           if (allc or c["State"]["Running"]) and (not nets or any(n in c["NetworkSettings"]["Networks"] for n in nets))
           and all(re.search(v, name(c)) for k, _, v in flt if k == "name")]
    if out:
        print("\n".join(out))
elif cmd == "inspect":
    refs = [x for x in a[1:] if not x.startswith("--") and x != fmt]
    found = [find(cs, r) for r in refs]
    if fmt:
        for c in found:
            if c:
                print(tmpl(fmt, c))
    else:
        print(json.dumps([c for c in found if c], indent=1))
    sys.exit(0 if all(found) else 1)
elif cmd in ("stop", "kill", "update"):
    pol = [x.split("=", 1)[1] for x in a if x.startswith("--restart=")]
    for r in a[1:]:
        c = find(cs, r)
        if c and cmd != "update":
            c["State"].update(Running=False, Status="exited")
        elif c and pol:
            c["HostConfig"]["RestartPolicy"]["Name"] = pol[0]
    simlib.save(cs)
elif cmd == "network":
    nets = simlib.load(NT, {})
    sub = a[1] if len(a) > 1 else ""
    opt = lambda k, d="": a[a.index(k) + 1] if k in a else d
    if sub == "inspect":
        n = nets.get(a[2])
        if not n:
            sys.exit(1)
        if fmt:
            print(net_fmt(fmt, n))
    elif sub == "create":
        br = next((x.split("=", 1)[1] for x in a if x.startswith("com.docker.network.bridge.name=")), "br-0123456789ab")
        nets[a[-1]] = {"driver": opt("--driver", "bridge"), "bridge": br, "subnet": opt("--subnet"),
                       "range": opt("--ip-range"), "ipv6": "false"}
        simlib.save(nets, NT)
    elif sub == "rm":
        nets.pop(a[2], None)
        simlib.save(nets, NT)
elif cmd == "run" and "nsenter" in a:                  # vm_sh: the script runs "in the VM"
    env = dict(os.environ, PATH=os.path.join(T, "fake") + ":" + os.path.join(T, "vmbin"))
    sys.exit(subprocess.run([os.path.join(T, "vmbin", "sh"), "-s"], input=sys.stdin.read(), text=True, env=env).returncode)
elif cmd == "events":                                  # one line per container created from now on
    seen = {c["Id"] for c in cs}
    open(os.path.join(S, "events_subscribed"), "w").close()
    try:
        while os.path.exists(os.path.join(S, "docker_up")):
            time.sleep(0.2)
            for c in simlib.load():
                if c["Id"] not in seen:
                    seen.add(c["Id"])
                    print("container create", flush=True)
    except BrokenPipeError:
        pass
    sys.exit(1)
elif cmd == "compose":
    # pentagi creating one more terminal while `compose stop` runs (the race pentagi_down must close)
    if os.path.exists(os.path.join(S, "compose_stop_spawns")) and "stop" in a and os.getcwd().endswith("/pentagi"):
        simlib.add("pentagi-terminal-8", {"restart": "on-failure:5"})
    # `compose up` failing (a recreate that fails, an image pull offline) while the old pentagi keeps running
    if os.path.exists(os.path.join(S, "compose_up_fails")) and "up" in a and os.getcwd().endswith("/pentagi"):
        sys.exit(1)
PY
printf '#!/bin/sh\nexec python3 "%s/dockersim.py" "$@"\n' "$T" > "$T/bin/docker"
FAKE="$SRC_REPO/tests/func/fake_iptables.py"
for tool in iptables ip6tables conntrack sysctl modprobe ip; do   # the VM's PATH has no python3: name it in full
  printf '#!/bin/sh\nexec "%s" "%s" %s "$@"\n' "$(command -v python3)" "$FAKE" "$tool" > "$T/fake/$tool"
done
for tool in sh sed grep head tail cat cut tr; do ln -s "$(command -v "$tool")" "$T/vmbin/$tool"; done
cat > "$T/bin/curl" <<'SH'
#!/bin/sh
url=""; origin=0; code=0; fail=0
for a in "$@"; do
  case "$a" in http://*) url="$a" ;; Origin:*) origin=1 ;; *http_code*) code=1 ;; -f*) fail=1 ;; esac
done
case "$url" in *:11434/*) port=11434 ;; *:11435/*) port=11435 ;; *) exit 7 ;; esac
up="$SIM/ollama_up"; [ $port = 11435 ] && up="$SIM/embed_up"
if [ ! -f "$up" ]; then [ $code = 1 ] && printf 000; exit 7; fi
if [ $origin = 1 ]; then
  if [ -f "$SIM/cors_open_$port" ]; then [ $code = 1 ] && printf 200; exit 0; fi
  [ $code = 1 ] && printf 403; [ $fail = 1 ] && exit 22; exit 0
fi
case "$url" in
  */api/version) echo '{"version":"0.12.0"}' ;;
  */api/tags) cat "$SIM/tags.json" ;;
  */api/ps) cat "$SIM/ps.json" ;;
esac
SH
cat > "$T/bin/ollama" <<'SH'
#!/bin/sh
echo "ollama $* OLLAMA_HOST=${OLLAMA_HOST:-}" >> "$SIM/ollama.log"
if [ "${1:-}" = serve ]; then
  env | grep '^OLLAMA_' | sort > "$SIM/embed_env"; touch "$SIM/embed_up"
  trap 'rm -f "$SIM/embed_up"; exit 0' TERM
  while :; do sleep 1; done
fi
SH
cat > "$T/bin/launchctl" <<'SH'
#!/bin/sh
echo "launchctl $*" >> "$SIM/launchctl.log"
case "$1" in getenv) [ -f "$SIM/launchd_$2" ] && cat "$SIM/launchd_$2" ;; print) exit 1 ;; esac
exit 0
SH
# Ollama.app writes its server's settings to server.log as it starts: $SIM/app_log is that line.
cat > "$T/bin/open" <<'SH'
#!/bin/sh
echo "open $*" >> "$SIM/open.log"
case "$*" in
  *Docker*) touch "$SIM/docker_up" ;;
  *Ollama*) mkdir -p "$HOME/.ollama/logs"; [ -f "$SIM/app_log" ] && cp "$SIM/app_log" "$HOME/.ollama/logs/server.log"
            touch "$SIM/ollama_up" ;;
esac
SH
cat > "$T/bin/osascript" <<'SH'
#!/bin/sh
echo "osascript $*" >> "$SIM/pkill.log"
case "$*" in *'quit app "Ollama"'*) [ -f "$SIM/foreign_ollama" ] || rm -f "$SIM/ollama_up" ;; esac   # foreign: not the app's
exit 0
SH
for t in pkill pgrep; do printf '#!/bin/sh\necho "%s $*" >> "$SIM/pkill.log"\nexit 1\n' "$t" > "$T/bin/$t"; done
cat > "$T/bin/netstat" <<'SH'
#!/bin/sh
[ -f "$SIM/netstat_fail" ] && exit 1
cat "$SIM/netstat"
SH
cat > "$T/bin/ifconfig" <<'SH'
#!/bin/sh
printf 'lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384\n\tinet 127.0.0.1 netmask 0xff000000\n'
[ -f "$SIM/lo0_alias" ] && printf '\tinet 127.0.0.2 netmask 0xff000000\n'
exit 0
SH
printf '#!/bin/sh\ncat "$SIM/lsof" 2>/dev/null\nexit 0\n' > "$T/bin/lsof"
printf '#!/bin/sh\necho "total = 2048.00M  used = 100.00M  free = 1948.00M  (encrypted)"\n' > "$T/bin/sysctl"
cat > "$T/bin/du" <<'SH'
#!/bin/sh
echo "du $*" >> "$SIM/du.log"
case "$1" in -sk*) [ -f "$SIM/du_kb" ] && { printf '%s\t%s\n' "$(cat "$SIM/du_kb")" "$2"; exit 0; } ;; esac
exec /usr/bin/du "$@"
SH
# Stands in for a running restart guard (its command line is what secstack checks).
printf '#!/bin/sh\nwhile :; do sleep 1; done\n' > "$T/fakeguard/secstack"
chmod +x "$T"/bin/* "$T"/fake/* "$T/fakeguard/secstack"

# ---------------------------------------------------------------- helpers
pass=0; fail=0; rc=0
ok(){ echo "PASS $*"; pass=$((pass+1)); }
bad(){ echo "FAIL $*"; fail=$((fail+1)); }
run(){ bash "$S" "$@" >"$T/out" 2>&1; rc=$?; }
cadd(){ python3 "$T/cset.py" "$@"; }
cid(){ python3 -c 'import hashlib,sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest()[:12])' "$1"; }
pol(){ python3 -c 'import json,sys; print(next((c["HostConfig"]["RestartPolicy"]["Name"] for c in json.load(open(sys.argv[1]))
if c["Name"] == "/" + sys.argv[2]), "none"))' "$SIM/containers.json" "$1"; }
# expect WANT_RC DESCRIPTION [TEXT that must appear in the output]
expect(){
  if [ "$rc" = "$1" ] && { [ -z "${3:-}" ] || grep -qF -- "$3" "$T/out"; }; then ok "$2"
  else bad "$2 (exit $rc, want $1${3:+, with: $3})"; sed 's/^/    | /' "$T/out" | tail -30; fi
}
absent(){ # absent FILE TEXT DESCRIPTION
  if grep -qF -- "$2" "$1" 2>/dev/null; then bad "$3"; grep -F -- "$2" "$1" | sed 's/^/    | /'; else ok "$3"; fi
}
present(){ # present FILE TEXT DESCRIPTION
  if grep -qF -- "$2" "$1" 2>/dev/null; then ok "$3"; else bad "$3"; sed 's/^/    | /' "$1" 2>/dev/null | tail -20; fi
}
line_of(){ grep -n -m1 -E -- "$2" "$1" 2>/dev/null | cut -d: -f1; }   # line_of FILE REGEX: first matching line number
before(){ # before FILE REGEX1 REGEX2 DESCRIPTION: both appear, the first one earlier
  local x y; x=$(line_of "$1" "$2"); y=$(line_of "$1" "$3")
  if [ -n "$x" ] && [ -n "$y" ] && [ "$x" -lt "$y" ]; then ok "$4"; else bad "$4 (lines ${x:-none} and ${y:-none})"; sed 's/^/    | /' "$1" | tail -25; fi
}
fake_guard(){ "$T/fakeguard/secstack" _restart-guard & VICTIMS="$VICTIMS $!"; echo $! > "$SECOPS/run/restart-guard.pid"; }
fake_watcher(){ bash -c 'exec -a "python3 secops-flow.py watch 5 --down" sleep 300' & VICTIMS="$VICTIMS $!"; echo $! > "$SECOPS/run/watch-5.pid"; }
D=$(printf '%064d' 1)
ORIGINS_OK='[http://localhost https://localhost http://localhost:* https://localhost:* http://127.0.0.1 https://127.0.0.1 http://127.0.0.1:* https://127.0.0.1:* http://0.0.0.0 https://0.0.0.0 http://0.0.0.0:* https://0.0.0.0:* app://* file://* tauri://* vscode-webview://* vscode-file://*]'
server_log(){ # server_log FILE "KEY:VALUE ..." ORIGINS [" KEY:VALUE ..." after OLLAMA_ORIGINS]
  mkdir -p "$(dirname "$1")"
  printf 'time=2026-11-20T10:00:00 level=INFO source=routes.go:1 msg="server config" env="map[%s OLLAMA_ORIGINS:%s%s]"\n' "$2" "$3" "${4:-}" > "$1"
}
AFTER=' OLLAMA_REMOTES:[ollama.com] OLLAMA_SCHED_SPREAD:false http_proxy: https_proxy: no_proxy:'   # what Ollama prints after it
DFLT=$(echo "$ORIGINS_OK" | tr -d '[]')
chat_cfg(){ echo "OLLAMA_CONTEXT_LENGTH:${2:-32768} OLLAMA_HOST:${3:-http://127.0.0.1:11434} OLLAMA_KV_CACHE_TYPE:q8_0 OLLAMA_MODELS:${1:-$HOME/.ollama/models} OLLAMA_NUM_PARALLEL:2"; }
baseline(){ # a stack that passes: Docker and both Ollama instances up, hexstrike running, settings right
  rm -rf "$SIM" "$HOME" "$SECSTACK_GH" "$FAKE_IPT_STATE"; mkdir -p "$SIM" "$HOME"
  mkdir -p "$SECOPS/env" "$SECOPS/configs" "$SECOPS/run" "$SECOPS/logs" "$PD" "$AD"
  touch "$SIM/docker_up" "$SIM/ollama_up" "$SIM/embed_up" "$SIM/lo0_alias"
  cat > "$SIM/netstat" <<'EOF'
Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)       rxbytes      txbytes  rhiwat  shiwat    pid   epid state  options
tcp4       0      0  127.0.0.1.11434        *.*                    LISTEN              0            0  131072  131072   4321      0 0x0100 0x00000006
tcp4       0      0  127.0.0.1.11435        *.*                    LISTEN              0            0  131072  131072   4322      0 0x0100 0x00000006
tcp4       0      0  127.0.0.1.8888         *.*                    LISTEN              0            0  131072  131072   1234      0 0x0100 0x00000006
tcp46      0      0  *.5000                 *.*                    LISTEN              0            0  131072  131072    999      0 0x0100 0x00000006
tcp4       0      0  192.168.1.20.52344     17.57.146.10.443       ESTABLISHED      1200          800  131072  131072    777      0 0x0102 0x00000000
EOF
  printf '%s\n' 'COMMAND     PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME' \
    'ollama     4321 me    3u  IPv4 0x1      0t0  TCP 127.0.0.1:11434 (LISTEN)' \
    'com.docke  1234 me   50u  IPv4 0x2      0t0  TCP 127.0.0.1:8888 (LISTEN)' > "$SIM/lsof"
  printf '{"models":[{"name":"qwen-a:latest","digest":"%s","size":1000000000}]}\n' "$D" > "$SIM/tags.json"
  echo '{"models":[]}' > "$SIM/ps.json"
  printf '{"installed":{"qwen-a":{"digest":"%s"}}}\n' "$D" > "$SECOPS/configs/models.selected.json"
  echo strict > "$SECOPS/configs/scope.mode"
  printf '%s\n' DOCKER_NETWORK=pentest-net DOCKER_INSIDE=false DOCKER_NET_ADMIN=false \
    DOCKER_IMAGE_SELECTION_MODE=fixed PENTAGI_LISTEN_IP=127.0.0.1 DOCKER_PUBLIC_IP=127.0.0.2 > "$PD/.env"
  cp "$SRC_REPO/upstream/pentagi/docker-compose.override.yml" "$PD/docker-compose.override.yml"
  echo 'POSTGRES_PASSWORD=x' > "$AD/.env"; echo 'SEARXNG_SECRET=ab' > "$SECOPS/env/searxng.env"
  chmod 600 "$PD/.env" "$AD/.env" "$SECOPS/env/searxng.env"; chmod 700 "$SECOPS" "$SECOPS/env" "$PD" "$AD"
  server_log "$SIM/app_log" "$(chat_cfg)" "$ORIGINS_OK"; mkdir -p "$HOME/.ollama/logs"; cp "$SIM/app_log" "$HOME/.ollama/logs/server.log"
  server_log "$SECOPS/logs/ollama-embed.log" "OLLAMA_HOST:http://127.0.0.1:11435 OLLAMA_MODELS:$HOME/.ollama/models" "$ORIGINS_OK"
  cadd hexstrike "ports=127.0.0.1|8888|8888/tcp" rm=1
  cadd pentagi-terminal-1 running=0
  cadd pentagi running=0 nets=pentagi-network "mounts=/var/run/docker.sock|/var/run/docker.sock|bind"   # by design
}

# ---------------------------------------------------------------- audit: containers
baseline; run audit; expect 0 "a safe stack passes" "AUDIT PASSED"
grep -qF "hexstrike on hexstrike-net only" "$T/out" && ok "pentest-net and hexstrike-net containers listed" || bad "hexstrike not listed"
# HexStrike alone on hexstrike-net (a terminal with NET_RAW could take over its address on a shared bridge),
# the lab on both bridges, everything else on pentest-net only
baseline; cadd hexstrike nets=pentest-net rm=1; run audit; expect 1 "hexstrike on the terminals' bridge fails" "hexstrike (running): on networks: pentest-net"
baseline; cadd hexstrike nets=hexstrike-net,pentest-net rm=1; run audit; expect 1 "hexstrike on both bridges fails" "on networks: hexstrike-net pentest-net"
baseline; cadd lab-dvwa running=0; cadd lab-juice running=0; run audit; expect 0 "the lab on both bridges passes" "lab-juice on hexstrike-net and pentest-net only"
baseline; cadd lab-juice running=0 nets=pentest-net; run audit; expect 1 "the lab on one bridge fails" "lab-juice (exited): on networks: pentest-net"
baseline; cadd pentagi-terminal-2 nets=hexstrike-net,pentest-net; run audit; expect 1 "a terminal on HexStrike's bridge fails" "pentagi-terminal-2 (running): on networks: hexstrike-net pentest-net"
baseline; cadd kali-x nets=hexstrike-net; run audit; expect 1 "any other container on HexStrike's bridge fails" "kali-x (running): on networks: hexstrike-net"

baseline; cadd hexstrike priv=1 rm=1; run audit; expect 1 "privileged HexStrike fails" "privileged"
baseline; cadd kali-scratch "mounts=/var/run/docker.sock|/var/run/docker.sock|bind"; run audit
expect 1 "container picked by network, not name (socket holder named kali-scratch)" "kali-scratch (running)"
baseline; cadd kali-old running=0 priv=1; run audit; expect 1 "a stopped privileged pentest-net container fails" "kali-old (exited)"
baseline; cadd pentagi-terminal-1 running=0 "mounts=/var/run|/hostrun|bind"; run audit; expect 1 "socket parent folder mount fails" "/var/run at /hostrun"
baseline; cadd pentagi-terminal-1 running=0 "mounts=/var/lib/docker/overlay2|/x|bind"; run audit; expect 1 "VM Docker data mount fails" "/var/lib/docker/overlay2"
baseline; cadd pentagi-terminal-1 running=0 "mounts=/var/lib/docker/volumes/v/_data|/data|volume"; run audit; expect 0 "a named volume is fine"
baseline; cadd pentagi-terminal-1 running=0 capadd=NET_ADMIN; run audit; expect 1 "added NET_ADMIN fails" "added capabilities NET_ADMIN"
baseline; cadd pentagi-terminal-1 running=0 capadd=CAP_SYS_ADMIN; run audit; expect 1 "added CAP_SYS_ADMIN fails" "SYS_ADMIN"
baseline; cadd pentagi-terminal-1 running=0 capadd=NET_RAW; run audit; expect 0 "a capability in Docker's default set is fine"
caps="CAP_CHOWN,CAP_DAC_OVERRIDE,CAP_FSETID,CAP_FOWNER,CAP_NET_RAW,CAP_SETGID,CAP_SETUID,CAP_SETFCAP,CAP_SETPCAP,CAP_NET_BIND_SERVICE,CAP_SYS_CHROOT,CAP_KILL,CAP_AUDIT_WRITE,CAP_SYS_PTRACE"
baseline; cadd pentagi-terminal-1 running=0 "capadd=$caps"; run audit; expect 0 "pentagi's own terminal capabilities (with SYS_PTRACE) pass"
baseline; cadd hexstrike "ports=127.0.0.1|8888|8888/tcp" capadd=SYS_PTRACE rm=1; run audit
expect 1 "SYS_PTRACE outside pentagi's terminals fails" "added capabilities SYS_PTRACE"
baseline; cadd pentagi-terminal-1 running=0 pid=host; run audit; expect 1 "PidMode host fails" "PidMode host"
baseline; cadd pentagi-terminal-1 running=0 ipc=host; run audit; expect 1 "IpcMode host fails" "IpcMode host"
baseline; cadd hexstrike nets= netmode=host rm=1; run audit; expect 1 "NetworkMode host fails" "NetworkMode host"
baseline; cadd pentagi-terminal-1 running=0 secopt=seccomp=unconfined; run audit; expect 1 "seccomp=unconfined fails" "seccomp=unconfined"
baseline; cadd pentagi-terminal-1 running=0 secopt=apparmor:unconfined; run audit; expect 1 "apparmor:unconfined fails" "apparmor:unconfined"
baseline; cadd pentagi-terminal-1 running=0 devices=1; run audit; expect 1 "host devices fail" "host devices"
baseline; cadd pentagi-terminal-1 running=0 "devcg=b *:* rwm"; run audit; expect 1 "a device cgroup rule fails" "device cgroup rules b *:* rwm"
baseline; cadd sidecar nets= netmode=container:hexstrike; run audit; expect 1 "a container in hexstrike's network namespace fails" "shares the network namespace of hexstrike"
baseline; cadd hexstrike nets=bridge rm=1; run audit; expect 1 "HexStrike on another network fails" "on networks: bridge"
baseline; cadd pentagi-terminal-2 running=0 nets=pentest-net,bridge; run audit
expect 1 "a container on pentest-net and another network fails" "on networks: bridge pentest-net"
baseline; cadd artex-web "ports=0.0.0.0|8787|8787/tcp;0.0.0.0|8788|8788/tcp;::|8787|8787/tcp" nets=artex_default
run audit; expect 1 "consecutive published ports on all interfaces fail" "artex-web 0.0.0.0:8788->8788/tcp"
baseline; cadd svc "ports=::|9000|9000/tcp" nets=bridge; run audit; expect 1 "a port published only on :: fails" "svc :::9000->9000/tcp"
baseline; cadd pentagi-terminal-3 "ports=127.0.0.1|28006|28006/tcp"; run audit
expect 1 "a terminal port on 127.0.0.1 (an origin Ollama trusts) fails" "publishing on an origin Ollama trusts (only 127.0.0.2 is allowed): pentagi-terminal-3"
baseline; cadd pentagi-terminal-3 "ports=127.0.0.2|28006|28006/tcp"; run audit; expect 0 "a terminal port on 127.0.0.2 is fine"
baseline; cadd pentagi-terminal-1 running=0 restart=on-failure; run audit
expect 1 "restart policy on pentest-net fails while pentagi is stopped" "restart policy on-failure: it would start with Docker"
baseline; cadd pentagi-terminal-1 running=0 restart=on-failure; cadd pentagi nets=pentagi-network; fake_guard; run audit
expect 0 "restart policy only warns while pentagi runs with its guard" "while pentagi runs"
baseline; cadd pentagi nets=pentagi-network; run audit; expect 1 "pentagi running without the restart guard fails" "runs without secstack's restart guard"
baseline; cadd pentagi running=0 nets=pentagi-network restart=unless-stopped; run audit; expect 1 "pentagi's own restart policy fails" "pentagi restarts with Docker"
TOK=$(printf '%064d' 7)    # stands in for HexStrike's API token, which docker inspect shows in Config.Env
baseline; cadd hexstrike "ports=127.0.0.1|8888|8888/tcp" rm=1 "env=HEXSTRIKE_TOKEN=$TOK"
bash -x "$S" audit > "$T/out" 2>&1; rc=$?; expect 0 "the audit under bash -x" "AUDIT PASSED"
absent "$T/out" "$TOK" "docker inspect's output (HexStrike's token) stays out of a bash -x trace of the audit"

# ---------------------------------------------------------------- audit: pentagi .env, Docker or Ollama down
baseline; echo 'export DOCKER_INSIDE=true' >> "$PD/.env"; run audit
expect 1 ".env: an export line Compose honours is read" "DOCKER_INSIDE is not false"
baseline; printf '  DOCKER_NETWORK: bridge\n' >> "$PD/.env"; run audit; expect 1 ".env: KEY: value with leading spaces is read" "DOCKER_NETWORK is not pentest-net"
baseline; grep -v NET_ADMIN "$PD/.env" > "$T/e" && cat "$T/e" > "$PD/.env"; run audit; expect 1 ".env: DOCKER_NET_ADMIN must be false" "DOCKER_NET_ADMIN is not false"
baseline; echo 'DOCKER_IMAGE_SELECTION_MODE=any' >> "$PD/.env"; run audit; expect 1 ".env: any image mode but fixed fails" "DOCKER_IMAGE_SELECTION_MODE is not fixed"
baseline; echo 'PENTAGI_LISTEN_IP=' >> "$PD/.env"; run audit; expect 1 ".env: an empty PENTAGI_LISTEN_IP fails" "PENTAGI_LISTEN_IP is not 127.0.0.1"
baseline; echo 'DOCKER_PUBLIC_IP=127.0.0.1' >> "$PD/.env"; run audit; expect 1 ".env: terminal ports on 127.0.0.1 fail" "DOCKER_PUBLIC_IP is not 127.0.0.2"
baseline; grep -v PUBLIC_IP "$PD/.env" > "$T/e" && cat "$T/e" > "$PD/.env"; run audit; expect 1 ".env: DOCKER_PUBLIC_IP must be set" "DOCKER_PUBLIC_IP is not 127.0.0.2"
baseline; echo 'DOCKER_INSIDE="false' >> "$PD/.env"; run audit; expect 1 ".env: one Compose can't parse fails" "couldn't read DOCKER_INSIDE"
baseline; rm "$PD/.env"; run audit; expect 1 "a missing pentagi .env fails" "is missing"
baseline; rm "$SIM/docker_up"; run audit; expect 2 "Docker stopped: incomplete, never passed" "AUDIT INCOMPLETE"
absent "$T/out" "AUDIT PASSED" "no PASSED with Docker stopped"
baseline; rm "$SIM/docker_up"; echo 'DOCKER_INSIDE=true' >> "$PD/.env"; run audit
expect 1 "Docker stopped: the .env is still checked" "DOCKER_INSIDE is not false"

# ---------------------------------------------------------------- audit: scope enforcement (the simulated VM)
baseline; run scope apply; expect 0 "scope apply in the simulated VM"
run audit; expect 0 "the audit checks the firewall in the VM" "firewall in the Docker VM matches scope.cidrs"
run scope install; run audit; expect 1 "install mode fails the audit" "scope is in install mode"
run scope strict; python3 -c 'import json,sys; s=json.load(open(sys.argv[1])); s["v4"]["SECOPS-SCOPE"].insert(0, "-d 8.8.8.8/32 -j RETURN"); json.dump(s, open(sys.argv[1], "w"))' "$FAKE_IPT_STATE"
run audit; expect 1 "a tampered SECOPS-SCOPE chain fails the audit" "firewall in the Docker VM doesn't match"
baseline; run scope apply; python3 -c 'import json,sys; n=json.load(open(sys.argv[1])); n["pentest-net"]["bridge"]="br-other"; json.dump(n, open(sys.argv[1], "w"))' "$SIM/nets.json"
run audit; expect 1 "a pentest-net secstack didn't create fails the audit" "isn't the network secstack creates"
baseline; run scope apply; python3 -c 'import json,sys; n=json.load(open(sys.argv[1])); del n["pentest-net"]; json.dump(n, open(sys.argv[1], "w"))' "$SIM/nets.json"
rm -f "$FAKE_IPT_STATE"; run audit     # a restarted VM, HexStrike still on hexstrike-net
expect 1 "pentest-net gone but hexstrike-net there: the firewall is still checked" "pentest-net doesn't exist yet"
present "$T/out" "the SECOPS-SCOPE chain is missing" "...and the missing firewall reported"

# ---------------------------------------------------------------- audit: listeners, Ollama, models, files
baseline; rm "$SIM/ollama_up"; run audit; expect 2 "Ollama stopped: model digests unchecked, incomplete" "model digests: Ollama is not running"
baseline; rm "$SECOPS/configs/models.selected.json"; run audit; expect 2 "no recorded digests: incomplete" "no recorded digests"
baseline; printf '{"models":[{"name":"qwen-a:latest","digest":"%064d","size":1}]}\n' 2 > "$SIM/tags.json"; run audit
expect 1 "model drift fails" "models changed since install-models recorded them: qwen-a"
baseline; echo '{"models":[]}' > "$SIM/tags.json"; run audit; expect 1 "a recorded model missing from Ollama fails" "recorded models missing from Ollama: qwen-a"
baseline; printf '{"models":[{"name":"Qwen-A:latest","digest":"%s","size":1}]}\n' "$D" > "$SIM/tags.json"; run audit
expect 0 "a model Ollama lists in another letter case is found (as plan.py finds it)" "installed models match the digests"
baseline; printf '{"models":[{"name":"Qwen-A:latest","digest":"%s","size":1},{"name":"QWEN-A:latest","digest":"%s","size":1}]}\n' "$D" "$D" > "$SIM/tags.json"
run audit; expect 1 "two entries equal up to case are no match (as plan.py)" "recorded models missing from Ollama: qwen-a"
baseline; sed 's/127.0.0.1.8888 /*.8888         /' "$SIM/netstat" > "$T/n" && mv "$T/n" "$SIM/netstat"; head -2 "$SIM/lsof" > "$T/l" && mv "$T/l" "$SIM/lsof"
run audit; expect 1 "a listener lsof can't see (another user) on all interfaces fails" "(another user) *:8888"
baseline; touch "$SIM/netstat_fail"; run audit; expect 2 "netstat unreadable: incomplete" "not checked: listeners"
baseline; touch "$SIM/cors_open_11435"; run audit; expect 1 "an Ollama that serves any website fails" "127.0.0.1:11435 accepts requests from other websites"
baseline; server_log "$HOME/.ollama/logs/server.log" "$(chat_cfg)" "[chrome-extension://* $(echo "$ORIGINS_OK" | tr -d '[]')]"; run audit
expect 1 "audit: an extension origin in Ollama's server config fails" "127.0.0.1:11434 accepts requests from other websites or extensions"
baseline; server_log "$HOME/.ollama/logs/server.log" "$(chat_cfg)" "[https://evil.example $(echo "$ORIGINS_OK" | tr -d '[]')]"; run audit
expect 1 "audit: a listed website origin fails (the probe alone would pass)" "127.0.0.1:11434 accepts requests"
baseline; server_log "$HOME/.ollama/logs/server.log" "$(chat_cfg)" "[http://[::1]:3000 https://evil.example $DFLT]" "$AFTER"; run audit
expect 1 "audit: an IPv6 origin doesn't hide a website listed after it" "127.0.0.1:11434 accepts requests"
baseline; server_log "$HOME/.ollama/logs/server.log" "$(chat_cfg)" "[http://[::1] https://evil.example $DFLT]"; run audit
expect 1 "audit: ...nor without a port, with OLLAMA_ORIGINS last in the map" "127.0.0.1:11434 accepts requests"
baseline; server_log "$HOME/.ollama/logs/server.log" "$(chat_cfg)" "[http://[::1]:3000 $DFLT]" "$AFTER"; run audit
expect 0 "audit: a loopback IPv6 origin, with Ollama's own keys after the list, passes" "refuses requests from other websites and extensions"
baseline; rm "$HOME/.ollama/logs/server.log"; run audit; expect 2 "audit: running Ollama without a server config: incomplete" "no server config"
baseline; echo 90000000 > "$SIM/du_kb"; run audit; expect 1 "model storage over the budget fails" "exceeds 75 GB"
baseline; echo x > "$SECOPS/env/.hidden"; chmod 644 "$SECOPS/env/.hidden"; run audit; expect 1 "hidden env file with 644 fails" ".hidden (chmod 600)"
baseline; mv "$PD/.env" "$T/real.env"; ln -s "$T/real.env" "$PD/.env"; run audit; expect 1 "a symlinked .env fails" "a symlink"
baseline; mkdir -p "$HOME/Applications/5ire.app"; printf '0.0.0.0 api.axiom.co\n' > "$T/hosts"; run audit
expect 0 "hosts: IPv4 entry only warns" "not blocked for both IPv4 and IPv6"
printf '0.0.0.0 api.axiom.co\n:: api.axiom.co\n' > "$T/hosts"; run audit; expect 0 "hosts: IPv4 and IPv6 entries" "blocked for IPv4 and IPv6"
: > "$T/hosts"

# ---------------------------------------------------------------- pentagi, artex, stop, down
baseline; rm "$SIM/docker_up" "$SIM/ollama_up"; run pentagi
expect 0 "pentagi starts" "pentagi on https://127.0.0.1:8443"
before "$SIM/docker.log" "nsenter" "^compose $PD .* up -d" "the scope firewall is applied before pentagi starts"
before "$SIM/open.log" "Docker" "Ollama" "pentagi starts Docker before Ollama"
[ -f "$SECOPS/run/restart-guard.pid" ] && kill -0 "$(cat "$SECOPS/run/restart-guard.pid")" 2>/dev/null \
  && ok "the restart guard runs" || bad "no restart guard after secstack pentagi"
for _ in $(seq 1 50); do [ -f "$SIM/events_subscribed" ] && break; sleep 0.1; done   # the guard listens
# pentagi creates a terminal, then another: each event gets its own sweep (not only the first one)
for n in 5 6; do
  cadd pentagi-terminal-$n restart=on-failure:5
  for _ in 1 2 3 4 5 6 7 8 9 10; do [ "$(pol pentagi-terminal-$n)" = no ] && break; sleep 0.5; done
  [ "$(pol pentagi-terminal-$n)" = no ] && ok "the guard clears new terminal $n's restart policy" || bad "new terminal $n kept $(pol pentagi-terminal-$n)"
done
cadd pentagi nets=pentagi-network; run audit; expect 0 "audit passes with pentagi, its guard and the firewall" "the restart guard clears"
guard=$(cat "$SECOPS/run/restart-guard.pid"); touch "$SIM/compose_up_fails"; run pentagi
expect 1 "a pentagi re-run whose compose up fails fails" "pentagi failed"
kill -0 "$guard" 2>/dev/null && [ "$(cat "$SECOPS/run/restart-guard.pid" 2>/dev/null)" = "$guard" ] \
  && ok "...and keeps the restart guard of the pentagi that still runs" || bad "a failed re-run stopped the guard of the running pentagi"
rm -f "$SIM/compose_up_fails"
guard=$(cat "$SECOPS/run/restart-guard.pid"); run stop; expect 0 "stop"
sleep 1; kill -0 "$guard" 2>/dev/null && bad "the restart guard survived stop" || ok "stop ends the restart guard"
[ ! -f "$SECOPS/run/restart-guard.pid" ] && ok "guard pid file removed" || bad "guard pid file kept"
baseline; touch "$SIM/compose_up_fails"; run pentagi; expect 1 "a first pentagi start whose compose up fails fails" "pentagi failed"
[ ! -f "$SECOPS/run/restart-guard.pid" ] && ok "...and stops its restart guard (no pentagi runs)" || bad "a failed start left its guard with no pentagi running"
baseline; cadd pentagi nets=pentagi-network; cadd pentagi-terminal-1 restart=on-failure; touch "$SIM/compose_stop_spawns"; run stop
expect 0 "stop while pentagi makes one more terminal"
before "$SIM/docker.log" "^compose $PD .* stop" "^stop pentagi-terminal-" "pentagi stops before its terminals"
[ "$(pol pentagi-terminal-8)" = no ] && ok "a terminal pentagi created during stop has no restart policy" || bad "terminal created during stop kept $(pol pentagi-terminal-8)"
before "$SIM/docker.log" "update --restart=no" "^stop " "stop clears restart policies before stopping anything"
present "$SIM/docker.log" "compose $PD -f docker-compose.yml -f docker-compose.override.yml stop" "pentagi compose files named explicitly"
present "$SIM/docker.log" "compose $AD -f docker-compose.yml stop" "ARTEX compose file named explicitly"
baseline; cadd pentagi-terminal-1 restart=on-failure; run down; expect 0 "down"
before "$SIM/docker.log" "update --restart=no" "^stop " "down clears restart policies before stopping anything"
baseline; fake_watcher; w=$(cat "$SECOPS/run/watch-5.pid"); sleep 0.3; rm "$SIM/docker_up"; run stop
expect 0 "stop with Docker down" "flow watchers stopped"
sleep 0.3; kill -0 "$w" 2>/dev/null && bad "stop left a flow watcher running with Docker down" || ok "stop ends flow watchers even with Docker down"
baseline; for args in "down --help" "pentagi stop" "stop now"; do
  # shellcheck disable=SC2086
  run $args; expect 1 "secstack $args is refused" "usage: secstack ${args%% *}"
done
absent "$SIM/docker.log" "stop" "...and nothing was stopped"
absent "$SIM/docker.log" "desktop" "...and Docker kept running"
baseline; echo 'export DOCKER_INSIDE=true' >> "$PD/.env"; run pentagi
expect 1 "pentagi refuses an unsafe .env" "refusing to start pentagi"
absent "$SIM/docker.log" "compose" "...before stopping ARTEX or starting anything"
baseline; rm "$PD/docker-compose.override.yml"; run pentagi; expect 1 "pentagi refuses without its restart override" "docker-compose.override.yml (restart: no) is missing"
baseline; echo 'services: {}' > "$PD/docker-compose.override.yml"; run pentagi
expect 1 "pentagi refuses an override that isn't the one secstack ships" "isn't the one secstack ships (./setup.sh --only upstream"
absent "$SIM/docker.log" "compose" "...before stopping ARTEX or starting anything"
baseline; rm "$SIM/lo0_alias"; run pentagi; expect 1 "pentagi refuses without the 127.0.0.2 alias" "sudo ifconfig lo0 alias 127.0.0.2 up"
absent "$SIM/docker.log" "compose" "...before stopping ARTEX"
baseline; cadd pentagi-terminal-7 restart=on-failure; run artex --bild
expect 1 "artex rejects a bad argument" "usage: secstack artex [--build]"
absent "$SIM/docker.log" "stop" "artex typo stops nothing"
[ ! -f "$SIM/launchctl.log" ] && ok "artex typo doesn't touch Ollama" || bad "artex typo touched Ollama"
baseline; rm "$SIM/docker_up" "$SIM/ollama_up"; cadd pentagi-terminal-9 restart=on-failure; fake_watcher; w=$(cat "$SECOPS/run/watch-5.pid"); sleep 0.3
run artex; expect 0 "artex starts" "ARTEX on http://127.0.0.1:8787"
grep -E "^kill .*$(cid pentagi-terminal-9)" "$SIM/docker.log" >/dev/null && ok "Docker started by secstack: a container back on pentest-net is killed (not docker stop)" \
  || { bad "container back on pentest-net not stopped"; sed 's/^/    | /' "$SIM/docker.log"; }
present "$SIM/docker.log" "update --restart=no $(cid pentagi-terminal-9)" "...and its restart policy cleared"
present "$SIM/docker.log" "compose $AD -f docker-compose.yml up -d" "ARTEX compose runs its pinned file explicitly"
before "$SIM/open.log" "Docker" "Ollama" "artex starts Docker before Ollama"
kill -0 "$w" 2>/dev/null && bad "artex left a flow watcher running" || ok "artex ends flow watchers"

# ---------------------------------------------------------------- inference
baseline; rm "$SIM/ollama_up" "$SIM/embed_up"; server_log "$SIM/app_log" "$(chat_cfg /x/models)" "$ORIGINS_OK"
OLLAMA_ORIGINS='*' OLLAMA_MODELS=/x/models bash "$S" llm start > "$T/out" 2>&1; rc=$?
expect 0 "llm start" "embeddings on 127.0.0.1:11435"
present "$SIM/launchctl.log" "launchctl unsetenv OLLAMA_ORIGINS" "llm start clears OLLAMA_ORIGINS for Ollama.app"
present "$SIM/launchctl.log" "launchctl setenv OLLAMA_MODELS /x/models" "the shell's OLLAMA_MODELS goes to launchd"
absent "$SIM/embed_env" "OLLAMA_ORIGINS" ":11435 starts without OLLAMA_ORIGINS"
present "$SIM/embed_env" "OLLAMA_MODELS=/x/models" ":11435 uses the same models folder"
present "$SIM/embed_env" "OLLAMA_HOST=127.0.0.1:11435" ":11435 on loopback"
run llm stop; expect 0 "llm stop"
[ ! -f "$SIM/embed_up" ] && ok "llm stop ends secstack's embedding server" || bad "embedding server still up"
baseline; rm "$SIM/ollama_up"; echo /y/models > "$SIM/launchd_OLLAMA_MODELS"; server_log "$SIM/app_log" "$(chat_cfg /y/models)" "$ORIGINS_OK"
server_log "$SECOPS/logs/ollama-embed.log" "OLLAMA_HOST:http://127.0.0.1:11435 OLLAMA_MODELS:/y/models" "$ORIGINS_OK"
run llm start; expect 0 "llm start with OLLAMA_MODELS set in launchd only"
present "$SIM/launchctl.log" "launchctl setenv OLLAMA_MODELS /y/models" "launchd's folder is kept"
run models; expect 0 "models measures launchd's folder" "(/y/models)"
present "$SIM/du.log" "du -skH /y/models" "models follows a symlinked models folder (du -H)"
baseline; server_log "$HOME/.ollama/logs/server.log" "$(chat_cfg)" "[* http://localhost https://localhost]"; run llm start
expect 0 "running Ollama with OLLAMA_ORIGINS=* is restarted" "restarting it"
baseline; server_log "$HOME/.ollama/logs/server.log" "$(chat_cfg)" "[https://example.com $(echo "$ORIGINS_OK" | tr -d '[]')]"; run llm start
expect 0 "running Ollama allowing a website origin is restarted" "restarting it"
baseline; server_log "$HOME/.ollama/logs/server.log" "$(chat_cfg)" "[chrome-extension://* $(echo "$ORIGINS_OK" | tr -d '[]')]"; run llm start
expect 0 "running Ollama allowing an extension origin is restarted" "restarting it"
baseline; run llm start; expect 0 "running Ollama with the planned settings is kept"
absent "$T/out" "restarting it" "no restart when the settings match"
absent "$SIM/pkill.log" "quit app" "...and nothing was stopped"
baseline; rm "$SIM/ollama_up"; server_log "$SIM/app_log" "$(chat_cfg "" 32768 http://0.0.0.0:11434)" "$ORIGINS_OK"; run llm start
expect 1 "Ollama.app exposing Ollama fails llm start, naming the setting" "Expose Ollama to the network"
[ "$(grep -c 'Ollama' "$SIM/open.log")" = 1 ] && ok "...started once, no restart loop" || bad "Ollama started $(grep -c 'Ollama' "$SIM/open.log") times"
[ ! -f "$SIM/ollama_up" ] && ok "...and stopped again" || bad "the exposed Ollama kept running"
baseline; server_log "$HOME/.ollama/logs/server.log" "$(chat_cfg "" 4096)" "$ORIGINS_OK"; server_log "$SIM/app_log" "$(chat_cfg "" 4096)" "$ORIGINS_OK"
run llm start; expect 1 "Ollama.app's context length fails llm start after one restart" "Context length is set"
[ "$(grep -c 'Ollama' "$SIM/open.log")" = 1 ] && ok "...restarted once, not in a loop" || bad "Ollama started $(grep -c 'Ollama' "$SIM/open.log") times"
baseline; touch "$SIM/cors_open_11434"; run llm start     # restarted, and still open: Ollama.app's browser setting
expect 1 "an Ollama that keeps serving any website fails llm start, naming the setting" "browser requests from other origins are allowed"
[ ! -f "$SIM/ollama_up" ] && ok "...and it is stopped, not left running" || bad "the Ollama serving any website kept running"
baseline; rm "$SIM/ollama_up"; touch "$SIM/cors_open_11434"; run llm start   # started here
expect 1 "an Ollama started open to any website fails llm start, naming the setting" "browser requests from other origins are allowed"
[ ! -f "$SIM/ollama_up" ] && ok "...and is stopped again" || bad "the Ollama started open to any website kept running"
baseline; touch "$SIM/cors_open_11434" "$SIM/foreign_ollama"; run llm start  # an ollama serve that isn't the app's
expect 1 "a foreign Ollama serving any website is reported" "stop that server"
absent "$T/out" "so it was stopped" "...without claiming it was stopped"
baseline; rm "$SIM/ollama_up"; server_log "$SIM/app_log" "$(chat_cfg)" "[http://[::1]:3000 https://evil.example $DFLT]" "$AFTER"; run llm start
expect 1 "llm start: an IPv6 origin doesn't hide a website listed after it" "browser requests from other origins are allowed"
baseline; server_log "$SECOPS/logs/ollama-embed.log" "OLLAMA_HOST:http://127.0.0.1:11435 OLLAMA_MODELS:$HOME/.ollama/models" "[*]"
run llm start; expect 1 "a foreign :11435 with other settings is reported, not killed" "something other than secstack's embedding server"
baseline; echo '{"models":[{"name":"m1:latest"}]}' > "$SIM/ps.json"
sleep 300 & VICTIMS="$VICTIMS $!"; echo $! > "$SECOPS/run/ollama-embed.pid"; victim=$!
OLLAMA_HOST=http://192.0.2.1:11434 bash "$S" llm stop > "$T/out" 2>&1; rc=$?; expect 0 "llm stop (stale pid file)"
kill -0 "$victim" 2>/dev/null && ok "stale embed pid naming another process: not killed" || bad "llm stop killed an unrelated process"
[ ! -f "$SECOPS/run/ollama-embed.pid" ] && ok "stale pid file removed" || bad "stale pid file kept"
present "$SIM/ollama.log" "ollama stop m1:latest OLLAMA_HOST=127.0.0.1:11434" "ollama CLI pinned to 127.0.0.1:11434"
absent "$SIM/pkill.log" "llama-server" "no pkill of llama.cpp servers"
grep -x 'pkill -f ollama serve' "$SIM/pkill.log" >/dev/null && bad "pkill of every 'ollama serve'" || ok "no pkill of every ollama serve"
baseline; rm -f "$SIM/embed_up"; "$T/bin/ollama" serve & echo $! > "$SECOPS/run/ollama-embed.pid"; ours=$!; sleep 1
run llm stop; expect 0 "llm stop (our embedding server)"
sleep 1; kill -0 "$ours" 2>/dev/null && bad "our embedding server survived llm stop" || ok "our embedding server stopped by its verified pid"

# ---------------------------------------------------------------- models, bench
baseline; echo 90000000 > "$SIM/du_kb"; run models; expect 1 "models fails over the budget" "exceeds 75 GB"
mkdir -p "$SECOPS/bin"; printf '#!/bin/sh\necho "bench OLLAMA_HOST=$OLLAMA_HOST"\n' > "$SECOPS/bin/bench-run.sh"; chmod +x "$SECOPS/bin/bench-run.sh"
OLLAMA_HOST=http://192.0.2.1:11434 bash "$S" bench > "$T/out" 2>&1; rc=$?; expect 0 "bench targets this Mac's Ollama" "bench OLLAMA_HOST=127.0.0.1:11434"

echo "audit: $pass passed, $fail failed"
[ $fail -eq 0 ]
