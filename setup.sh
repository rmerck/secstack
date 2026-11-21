#!/usr/bin/env bash
# setup.sh: hardware-aware, one-command install of the secstack offensive-security workstation.
#
#   ./setup.sh                 full install, interactive: you pick models from the recommendation
#   ./setup.sh --plan          show this Mac's hardware, resource plan and recommended models;
#                              change nothing
#   ./setup.sh --yes           unattended: the recommended models on a first install, the current
#                              plan's models on a re-run; runtime dirs that differ from the repo are
#                              replaced (kept as *.pre-repo-<time>). Browser steps are listed at the
#                              end instead.
#   ./setup.sh --models a,b    use these catalog models (ids or aliases) instead of the recommendation
#   ./setup.sh --from STEP     resume at STEP
#   ./setup.sh --only STEP     run one step
#                              (both run preflight first)
#
# Steps: preflight plan upstream install docker loopback images models pentagi artex 5ire audit
#
# Safe to re-run: it never regenerates existing .env secrets, never overwrites the live scope, the
# pentagi API token, an existing 5ire config or providers/templates you edited in pentagi's UI, never
# upgrades images that are already present, and asks before stopping ARTEX, a pentagi flow or the tool
# containers (starting ARTEX still stops an idle pentagi, and Ollama restarts if its settings differ).
# It uses sudo only after asking, never with --yes: for the missing /etc/hosts lines, and to put
# 127.0.0.2 on lo0 now and at every boot (a LaunchDaemon), where pentagi's terminal ports and
# the lab UI publish.
#
# Exit status: 0 = the steps ran (and the audit, when it ran, passed); 2 = they ran, but the audit
# couldn't check everything; 3 = they ran, but the audit found issues; anything else = setup stopped
# (it says where and how to resume).
#
# For authorized testing only: scope is enforced at the network layer, authorization is yours.
set -euo pipefail

REPO="$(cd "$(dirname "$0")" && pwd -P)"
GH="${SECSTACK_GH:-$HOME/GitHub}"
SECOPS="${SECOPS:-$GH/.sec-ops}"
CFG="$SECOPS/configs"
PLANPY="$REPO/scripts/plan.py"
SECSTACK="$SECOPS/bin/secstack"
export SECSTACK_GH="$GH" SECOPS
for _d in /Applications/Docker.app/Contents/Resources/bin /Applications/Ollama.app/Contents/Resources \
          /opt/homebrew/bin /usr/local/bin "$HOME/.local/bin"; do
  case ":$PATH:" in *":$_d:"*) ;; *) PATH="$PATH:$_d" ;; esac
done
export PATH
STEPS="preflight plan upstream install docker loopback images models pentagi artex 5ire audit"

YES=0; MODELS=""; FROM=""; ONLY=""; PLAN_ONLY=0
usage(){ awk 'NR == 1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0"; }
while [ $# -gt 0 ]; do
  case "$1" in
    --plan) PLAN_ONLY=1 ;;
    --yes|-y) YES=1 ;;
    --models) MODELS="${2:?--models needs a list}"; shift ;;
    --from) FROM="${2:?--from needs a step}"; shift ;;
    --only) ONLY="${2:?--only needs a step}"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1"; usage; exit 1 ;;
  esac
  shift
done
for s in "$FROM" "$ONLY"; do
  [ -z "$s" ] && continue
  case " $STEPS " in *" $s "*) ;; *) echo "unknown step '$s' (steps: $STEPS)"; exit 1 ;; esac
done
case "$MODELS" in -*|*[!A-Za-z0-9._,-]*) echo "--models: use catalog ids/aliases separated by commas"; exit 1 ;; esac
INTERACTIVE=0; [ -t 0 ] && [ $YES -eq 0 ] && INTERACTIVE=1

PENDING=""; CURRENT=""; AUDIT_EXIT=0
hdr(){ printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
ok(){ printf '  \033[32m✔\033[0m %s\n' "$*"; }
warn(){ printf '  \033[33m!\033[0m %s\n' "$*"; }
die(){ printf '  \033[31m✘\033[0m %s\n' "$*"; exit 1; }
pend(){ PENDING="${PENDING}  - $*
"; }
q(){ printf '%q' "$1"; }   # a path made safe to paste into a shell command
ask_yn(){ local a; [ $INTERACTIVE -eq 1 ] || return 1; read -r -p "  $1 [y/N] " a; case "$a" in y|Y|yes) return 0 ;; *) return 1 ;; esac; }
pause(){ [ $INTERACTIVE -eq 1 ] || { pend "$1"; return 0; }; read -r -p "  $1 Press Enter when done. " _; }
# Same rules as plan.py read_conf(): last occurrence wins, trailing CR stripped, unsafe = empty.
conf_get(){ grep -E "^$1=" "$CFG/stack.conf" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d '\r' | grep -E '^[A-Za-z0-9._:/,][A-Za-z0-9._:/,-]*$' || true; }
wait_http(){ # url seconds
  local i=0
  while [ $i -lt "$2" ]; do
    [ "$(curl -ks --noproxy '*' -o /dev/null -m 3 -w '%{http_code}' "$1" 2>/dev/null || true)" != "000" ] && return 0
    sleep 3; i=$((i + 3))
  done
  return 1
}
wait_docker(){ # seconds
  local i=0
  while [ $i -lt "$1" ]; do docker info >/dev/null 2>&1 && return 0; sleep 3; i=$((i + 3)); done
  return 1
}
xtrace_off(){ XT="$-"; set +x; }          # keep tokens out of `bash -x` traces
xtrace_restore(){ case "${XT:-}" in *x*) set -x ;; esac; }
running(){ docker ps --format '{{.Names}}' 2>/dev/null | grep -E "$1" >/dev/null 2>&1; }
clear_clipboard_if(){ [ -n "$1" ] && [ "$(pbpaste 2>/dev/null || true)" = "$1" ] && pbcopy </dev/null; return 0; }
# Ctrl-C, a closed terminal or Ctrl-D can end the run in the middle of a step. on_exit then takes back
# a token setup.sh put on the clipboard (CLIP_TOK) and the no-echo mode of a hidden read (TTY_SAVED:
# bash 3.2 leaves the terminal silent when Ctrl-C interrupts `read -s`).
CLIP_TOK=""; TTY_SAVED=""; LO0_TMP=""
on_exit(){
  local rc=$? hint
  set +x                                   # never trace the token below
  [ -z "$TTY_SAVED" ] || stty "$TTY_SAVED" 2>/dev/null || true
  clear_clipboard_if "$CLIP_TOK"; CLIP_TOK=""
  [ -z "$LO0_TMP" ] || rm -f "$LO0_TMP"
  if [ -n "$PENDING" ]; then printf '\n  Still to do by hand:\n%s' "$PENDING"; fi
  if [ $rc -ne 0 ] && [ -n "$CURRENT" ]; then
    if [ -n "$ONLY" ]; then hint="--only $ONLY"
    elif [ "$CURRENT" = preflight ] && [ -n "$FROM" ]; then hint="--from $FROM"
    else hint="--from $CURRENT"; fi
    printf '\n\033[31msetup stopped in step "%s" (exit %s).\033[0m Fix the problem above, then: ./setup.sh %s\n' \
      "$CURRENT" "$rc" "$hint"
  fi
  # Exit 2 and 3 say only "the steps ran, the audit didn't pass" (header); anything else that ends with
  # one of them (a step, --plan) exits 1.
  if [ $rc -ne 0 ] && [ $rc -eq $AUDIT_EXIT ] && [ -z "$CURRENT" ]; then
    case $rc in
      2) printf '\n\033[33msetup finished, but the audit could not check everything (exit 2).\033[0m See its "not checked" lines, then: secstack audit\n' ;;
      *) printf '\n\033[31msetup finished, but the audit found issues (exit 3).\033[0m Fix them (above), then: secstack audit\n' ;;
    esac
  elif [ $rc -eq 2 ] || [ $rc -eq 3 ]; then
    exit 1
  fi
}
trap on_exit EXIT
trap 'exit 130' INT TERM HUP

# ------------------------------------------------------------------------------------ steps
step_preflight(){
  hdr "preflight"
  [ "$(uname -s)" = Darwin ] || die "secstack runs on macOS on Apple Silicon only."
  [ "$(/usr/sbin/sysctl -n hw.optional.arm64 2>/dev/null || echo 0)" = 1 ] || die "Apple Silicon (arm64) Mac required."
  [ "$(/usr/sbin/sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" != 1 ] \
    || die "this terminal runs under Rosetta (Intel mode). Open a native arm64 terminal and re-run."
  [ "$(id -u)" -ne 0 ] || die "don't run setup.sh as root or with sudo."
  local ram missing=""
  ram=$(( $(/usr/sbin/sysctl -n hw.memsize) / 1073741824 ))
  [ "$ram" -ge 16 ] || die "$ram GB of memory: 16 GB is the minimum."
  command -v python3 >/dev/null 2>&1 && python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))' 2>/dev/null \
    || missing="${missing}    python3 3.9+:  xcode-select --install
"
  command -v git >/dev/null 2>&1 || missing="${missing}    git:           xcode-select --install
"
  command -v uv >/dev/null 2>&1 || missing="${missing}    uv:            brew install uv   (or https://docs.astral.sh/uv/)
"
  command -v docker >/dev/null 2>&1 || missing="${missing}    Docker Desktop: https://www.docker.com/products/docker-desktop/   (or brew install --cask docker)
"
  [ -d /Applications/Ollama.app ] || missing="${missing}    Ollama.app:    https://ollama.com/download   (or brew install --cask ollama-app)
"
  command -v ollama >/dev/null 2>&1 || missing="${missing}    ollama CLI:    open Ollama.app once (it ships the CLI in Ollama.app/Contents/Resources)
"
  if [ -n "$missing" ]; then
    printf '  Missing prerequisites:\n%s' "$missing"
    die "install them, then re-run ./setup.sh"
  fi
  # The runtime root holds secrets, the live scope and generated files. Neither it nor a folder in it
  # (a configs/ or env/ symlinked into the repo, say) may resolve into the repo, and it must not
  # contain the repo. Folders are compared by identity as well as by path: APFS ignores case, so
  # ~/github/x and ~/GitHub/x are one folder (so are the two ends of a bind mount). Same check as install.sh.
  local overlap
  if ! overlap=$(python3 -c 'import os, sys
def ident(p):
    try:
        s = os.stat(p)
    except OSError:
        return None
    return s.st_dev, s.st_ino
def lineage(p):  # the identities of p and of every ancestor of it that exists
    ids = set()
    while True:
        ids.add(ident(p))
        up = os.path.dirname(p)
        if up == p:
            return ids - {None}
        p = up
root, repo = sys.argv[1], os.path.realpath(sys.argv[2])
repo_id, repo_up = ident(repo), lineage(repo)
bad = []
for p in [root] + [os.path.join(root, d) for d in sys.argv[3:]]:
    r = os.path.realpath(p)
    if (r == repo or r.startswith(repo + os.sep) or repo.startswith(r + os.sep)
            or repo_id in lineage(r) or ident(r) in repo_up):
        bad.append(p if r == p else p + " -> " + r)
print("\n".join("    " + b for b in bad))
sys.exit(1 if bad else 0)' "$SECOPS" "$REPO" configs env logs reports run cache hexstrike-data venv); then
    printf '%s\n' "$overlap"
    die "the runtime root $SECOPS and the repo $REPO overlap (above). Clone the repo somewhere else (e.g. ~/GitHub/secstack) and keep the runtime folders out of it (no symlinks into the repo)."
  fi
  command -v hf >/dev/null 2>&1 \
    || warn "Hugging Face CLI (hf) not found; needed only for GGUF-sourced models: brew install hf   (or: uv tool install huggingface_hub)"
  ok "macOS $(sw_vers -productVersion), $(/usr/sbin/sysctl -n machdep.cpu.brand_string), ${ram} GB, tools present"
}

step_plan(){
  hdr "plan: hardware and model selection"
  local cur
  cur="$(conf_get MODELS)"
  if [ -n "$MODELS" ]; then
    python3 "$PLANPY" select --write --models "$MODELS"
  elif [ $YES -eq 1 ] && [ -n "$cur" ]; then
    ok "keeping the current plan's models ($cur); regenerating its files"
    python3 "$PLANPY" select --write --models "$cur" --primary "$(conf_get CHAT_MODEL)" \
      || die "couldn't keep the current models (see above). Fix that and re-run, or choose again: ./setup.sh --only plan"
  elif [ $YES -eq 1 ]; then
    python3 "$PLANPY" select --write --yes
  else
    python3 "$PLANPY" select --write
  fi
  # Fail now, not after the 30-minute image build, if a chosen model needs the Hugging Face CLI.
  if python3 -c 'import json, sys; d = json.load(open(sys.argv[1])); sys.exit(0 if any((m.get("source") or {}).get("type") == "hf" for m in d.get("models", [])) else 1)' \
       "$CFG/models.selected.json" 2>/dev/null && ! command -v hf >/dev/null 2>&1; then
    die "a chosen model downloads from Hugging Face and the hf CLI is missing: brew install hf   (or: uv tool install huggingface_hub)"
  fi
}

step_upstream(){ hdr "upstream: clone pinned projects, patches, .env files, host venv"; "$REPO/scripts/bootstrap-upstream.sh"; }

# install.sh [--force], shown as it ran. Its "note" and "keep    existing" lines ask for something done by
# hand (git hooks it couldn't install, a stale ~/.zshrc line), so they go to the list at the end too.
run_install(){
  local out rc=0 line
  out=$("$REPO/install.sh" "$@" 2>&1) || rc=$?
  printf '%s\n' "$out"
  while IFS= read -r line; do
    case "$line" in
      "  note    "*) pend "install.sh: ${line#  note    }" ;;
      "  keep    existing "*) pend "install.sh kept your ${line#  keep    existing }" ;;
    esac
  done <<EOF
$out
EOF
  return $rc
}

step_install(){
  hdr "install: link the repo into $SECOPS"
  local rc=0
  run_install || rc=$?
  [ $rc -eq 0 ] && return 0
  [ $rc -eq 3 ] || die "install.sh failed"
  if [ $INTERACTIVE -eq 1 ] && ask_yn "Replace those directories with links to the repo? (they're kept as *.pre-repo-<time>)"; then
    run_install --force
  elif [ $YES -eq 1 ]; then
    warn "replacing them (kept as *.pre-repo-<time>; review the differences above)"
    run_install --force
  else
    die "not replaced; re-run when ready: ./setup.sh --from install"
  fi
}

need_secstack(){
  # The runtime bin dir must be this repo's bin (an older real secstack would ignore the plan). Compared
  # by identity: on APFS, ~/github/... and ~/GitHub/... are the same folder.
  [ "$SECOPS/bin" -ef "$REPO/bin" ] && [ -x "$SECSTACK" ] \
    || die "$SECOPS/bin isn't linked to this repo yet: ./setup.sh --from install"
}

step_docker(){
  hdr "docker: Docker Desktop VM sized to the plan"
  need_secstack
  if ! docker info >/dev/null 2>&1; then
    open -a Docker
    wait_docker 180 || die "Docker Desktop did not start within 3 minutes"
  fi
  local rc msg a
  while :; do
    set +e; python3 "$PLANPY" docker-check; rc=$?; set -e
    [ $rc -eq 0 ] && { ok "Docker VM matches the plan"; break; }
    [ $rc -eq 1 ] || die "couldn't compare the Docker VM with the plan"
    msg="Docker Desktop > Settings > Resources: CPUs $(conf_get DOCKER_VM_CPUS), Memory $(conf_get DOCKER_VM_GB) GB, Swap $(conf_get DOCKER_SWAP_GB) GB, then Apply & restart."
    if [ $INTERACTIVE -eq 0 ]; then
      warn "Docker VM differs from the plan"
      pend "Resize Docker: secstack stop; $msg Then: secstack scope apply"
      break
    fi
    # Applying new resources restarts Docker: running tool containers stop and the VM's scope
    # firewall is wiped (it's re-applied below). Ask before stopping anything.
    if running '^(pentagi|pentagi-terminal-.*|artex.*|hexstrike|lab-.*)$'; then
      if ask_yn "Resizing restarts Docker. Stop pentagi/ARTEX/hexstrike/lab (and any running flow) now?"; then
        "$SECSTACK" stop || true
      else
        warn "Docker VM left as is"; pend "Resize Docker when nothing is running: secstack stop; $msg Then: secstack scope apply"; break
      fi
    fi
    read -r -p "  $msg Press Enter to re-check, or type 'skip': " a
    if [ "$a" = skip ]; then warn "Docker VM left as is"; pend "$msg Then: secstack scope apply"; break; fi
    wait_docker 180 || die "Docker Desktop is not running"
  done
  "$SECSTACK" scope strict || die "couldn't apply the scope firewall"
}

# pentagi's Kali terminals publish their per-flow ports, and `secstack lab up --ui` the lab, on 127.0.0.2:
# Ollama trusts every web page on 127.0.0.1 and localhost, and what those ports serve can be hostile (the
# lab serves XSS). macOS has no 127.0.0.2 until it's added to lo0, and a reboot drops it, so a LaunchDaemon
# adds it at every boot.
LO0_IP=127.0.0.2
LO0_LABEL=com.secstack.lo0-alias
LO0_PLIST=/Library/LaunchDaemons/com.secstack.lo0-alias.plist
lo0_has_ip(){ /sbin/ifconfig lo0 2>/dev/null | grep -F "inet $LO0_IP " >/dev/null; }
lo0_plist(){
  cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$LO0_LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>/sbin/ifconfig</string>
    <string>lo0</string>
    <string>alias</string>
    <string>$LO0_IP</string>
    <string>up</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
</dict>
</plist>
EOF
}

step_loopback(){
  hdr "loopback: $LO0_IP on lo0 (pentagi's terminal ports, secstack lab up --ui)"
  local want ip=0 boot=0 other=0 what todo failed=0
  want=$(lo0_plist)
  lo0_has_ip && ip=1
  if [ -f "$LO0_PLIST" ]; then
    if [ "$(cat "$LO0_PLIST" 2>/dev/null)" = "$want" ]; then boot=1; else other=1; fi
  fi
  if [ $ip -eq 1 ] && [ $boot -eq 1 ]; then ok "$LO0_IP is on lo0, and $LO0_PLIST adds it at every boot"; return 0; fi
  if [ $ip -eq 0 ]; then
    todo="Add $LO0_IP to lo0 (pentagi's terminal ports and secstack lab up --ui publish there): ./setup.sh --only loopback (asks before sudo; also adds it at every boot), or until the next reboot: sudo ifconfig lo0 alias $LO0_IP up"
  else
    todo="Keep $LO0_IP on lo0 after a reboot: ./setup.sh --only loopback (asks before sudo), or after each reboot: sudo ifconfig lo0 alias $LO0_IP up"
  fi
  if [ $boot -eq 1 ]; then what="add $LO0_IP to lo0 now ($LO0_PLIST adds it at boot)"
  elif [ $ip -eq 1 ]; then what="install $LO0_PLIST to add $LO0_IP at every boot (it's on lo0 until the next reboot)"
  else what="add $LO0_IP to lo0 now, and install $LO0_PLIST to add it at every boot"; fi
  [ $other -eq 0 ] || what="$what (in place of the different one there)"
  if ! ask_yn "pentagi's terminal ports and the lab UI need $LO0_IP: $what? Needs your sudo password."; then
    if [ $ip -eq 1 ]; then warn "$LO0_IP stays on lo0 only until the next reboot"; else warn "$LO0_IP is not on lo0"; fi
    pend "$todo"
    return 0
  fi
  if [ $boot -eq 0 ]; then
    # launchd loads it only if it's root:wheel and not writable by others. A copy already loaded under the
    # label is booted out first, or bootstrap would refuse the new one.
    if LO0_TMP=$(mktemp "${TMPDIR:-/tmp}/secstack-lo0.XXXXXX") && printf '%s\n' "$want" > "$LO0_TMP" \
       && sudo /usr/bin/install -m 644 -o root -g wheel "$LO0_TMP" "$LO0_PLIST"; then
      sudo /bin/launchctl bootout "system/$LO0_LABEL" >/dev/null 2>&1 || true
      if sudo /bin/launchctl bootstrap system "$LO0_PLIST"; then ok "installed $LO0_PLIST: it adds $LO0_IP at every boot"
      else warn "installed $LO0_PLIST, but launchctl couldn't load it now; launchd loads it at the next boot"; fi
    else
      warn "couldn't install $LO0_PLIST"; failed=1
    fi
    rm -f "$LO0_TMP"; LO0_TMP=""
  fi
  if [ $failed -eq 0 ] && ! lo0_has_ip; then
    sudo /sbin/ifconfig lo0 alias "$LO0_IP" up || true
    lo0_has_ip || { warn "couldn't add $LO0_IP to lo0"; failed=1; }
  fi
  sudo -k
  if [ $failed -eq 0 ]; then ok "$LO0_IP is on lo0"; else pend "$todo"; fi
}

step_images(){ hdr "images: hexstrike-kali + kali-tools-mcp (20-40 min the first time)"; "$REPO/scripts/build-images.sh"; }

step_models(){
  hdr "models: install the planned models into Ollama"
  need_secstack
  [ -s "$CFG/models.selected.json" ] || die "no model selection yet: ./setup.sh --from plan"
  "$SECSTACK" llm start || die "Ollama didn't start"
  python3 "$PLANPY" install-models
  "$SECSTACK" models || true
}

# Ask before interrupting live work: starting pentagi stops ARTEX and vice versa.
may_interrupt(){ # may_interrupt <container-regex> <what> <step>
  running "$1" || return 0
  if ask_yn "$2 is running. Restart the frameworks now (this interrupts it)?"; then return 0; fi
  warn "left $2 running; skipped the $3 step"
  pend "Finish the $3 step later: ./setup.sh --only $3"
  return 1
}

step_pentagi(){
  hdr "pentagi: first login, API token, providers, templates"
  need_secstack
  # A running flow is interrupted too: Ollama restarts if its settings changed, and so does pentagi's
  # container if the upstream step rewrote its .env.
  may_interrupt '^(artex|pentagi-terminal-)' "ARTEX or a pentagi flow (Kali terminal)" pentagi || return 0
  if ! lo0_has_ip; then   # `secstack pentagi` refuses without it (its terminals publish on it)
    warn "pentagi needs $LO0_IP on lo0; skipped the pentagi step"
    pend "Add $LO0_IP to lo0 (./setup.sh --only loopback, asks before sudo), then: ./setup.sh --only pentagi"
    return 0
  fi
  "$SECSTACK" pentagi
  wait_http https://127.0.0.1:8443/ 240 || die "pentagi did not answer on https://127.0.0.1:8443 (see $SECOPS/logs/pentagi-up.log)"
  # The items left for later start pentagi themselves: the artex step stops it, and so does `secstack artex`.
  local tokf="$SECOPS/env/pentagi-api-token" tok="" save sync="secstack providers --create-only && secstack templates --create-only"
  save="(umask 077; pbpaste > $(q "$tokf")) && pbcopy </dev/null"
  if [ -s "$tokf" ]; then
    ok "API token already saved"
  else
    cat <<EOF
  Open https://127.0.0.1:8443 (self-signed certificate: accept the browser warning for localhost only).
    1. Log in with pentagi's default admin@pentagi.com / admin and CHANGE THE PASSWORD now.
    2. Settings > API Tokens > create a token (e.g. "5ire-bridge", 1 year). Copy it.
EOF
    if [ $INTERACTIVE -eq 1 ]; then
      xtrace_off
      TTY_SAVED=$(stty -g 2>/dev/null || true)       # on_exit restores echo if Ctrl-C ends the read
      read -r -s -p "  Paste the API token (hidden; Enter to skip): " tok; echo
      TTY_SAVED=""
      case "$tok" in
        "") pend "pentagi API token: secstack pentagi; then at https://127.0.0.1:8443 (once it loads) create a token in Settings > API Tokens, copy it and save it: $save; then: $sync" ;;
        *[!A-Za-z0-9._-]*) warn "that doesn't look like a token; not saved"
           pend "pentagi API token: secstack pentagi; then at https://127.0.0.1:8443 (once it loads) copy the token from Settings > API Tokens and save it: $save; then: $sync" ;;
        *) ( umask 077; printf '%s\n' "$tok" > "$tokf" ); chmod 600 "$tokf"; ok "token saved to $tokf (600)"
           clear_clipboard_if "$tok" ;;
      esac
      tok=""
      xtrace_restore
    else
      pend "pentagi: secstack pentagi; then log in at https://127.0.0.1:8443 (once it loads) as admin@pentagi.com / admin, change the password, create an API token in Settings > API Tokens, copy it and save it: $save; then: $sync"
    fi
  fi
  if [ -s "$tokf" ]; then
    # Create what's missing; never overwrite providers/templates you tuned in the UI (`secstack providers` updates).
    local synced=1 rc
    "$SECSTACK" providers --create-only || { synced=0; warn "provider sync failed"; }
    rc=0; "$SECSTACK" templates --create-only || rc=$?   # (|| keeps set -e from ending setup here)
    case $rc in
      0) ;;
      3) pend "Add the flow templates in pentagi's UI (Templates): pentagi lets only a browser login manage them. The texts are in $(q "$SECOPS/configs/flow-templates") (first line = title)" ;;
      *) synced=0; warn "template sync failed" ;;
    esac
    [ $synced -eq 1 ] || pend "pentagi sync failed. If the token is wrong or expired: rm $(q "$tokf"), then ./setup.sh --only pentagi"
  fi
}

step_artex(){
  hdr "artex: first-run claim"
  need_secstack
  may_interrupt '^pentagi-terminal-' "A pentagi flow (Kali terminal)" artex || return 0
  "$SECSTACK" artex || die "ARTEX failed to start (see $SECOPS/logs/artex-up.log)"
  wait_http http://127.0.0.1:8787/ 240 || die "ARTEX did not answer on http://127.0.0.1:8787 (see $SECOPS/logs/artex-up.log)"
  local status tok logs workers
  logs="cd $(q "$GH/ARTEX") && docker compose logs artex | grep 'Setup token'"
  workers=$(conf_get OLLAMA_NUM_PARALLEL)
  [ -n "$workers" ] || workers="the plan's OLLAMA_NUM_PARALLEL ($(q "$CFG/stack.conf"))"
  status=$(curl -s --noproxy '*' -m 5 http://127.0.0.1:8787/api/auth/status 2>/dev/null \
    | python3 -c 'import json, sys
try:
    v = json.load(sys.stdin).get("initialized")
except Exception:
    v = None
print({True: "claimed", False: "unclaimed"}.get(v, "unknown"))' 2>/dev/null || echo unknown)
  case "$status" in
    claimed) ok "ARTEX already claimed"; return 0 ;;
    unclaimed) ;;
    *) warn "couldn't read ARTEX's setup status"
       pend "ARTEX: secstack artex; if http://127.0.0.1:8787/setup asks for a token: $logs; then set the admin password, and System > Settings > concurrent workers to $workers"
       return 0 ;;
  esac
  if [ $INTERACTIVE -eq 1 ]; then
    xtrace_off
    tok=$(cd "$GH/ARTEX" && docker compose logs artex 2>/dev/null | grep -i 'setup token' | tail -1 | grep -oE '[0-9a-f]{32}' | tail -1 || true)
    # CLIP_TOK is set before the copy, so on_exit clears it however the run ends (Ctrl-C, Ctrl-D or a
    # closed terminal at the pause below).
    if [ -n "$tok" ]; then CLIP_TOK="$tok"; printf '%s' "$tok" | pbcopy; ok "ARTEX one-time setup token copied to the clipboard"
    else warn "no setup token in ARTEX's logs yet; get it with: $logs"; fi
    pause "Open http://127.0.0.1:8787/setup, paste the token, set the admin password, then set System > Settings > concurrent workers to $workers. Back up $(q "$GH/ARTEX/.env") (ARTEX_SECRET_KEY) to your password manager."
    clear_clipboard_if "$tok"
    tok=""; CLIP_TOK=""
    xtrace_restore
  else
    pend "ARTEX: secstack artex; get the setup token with: $logs; open http://127.0.0.1:8787/setup (once it loads), paste it, set the admin password, then System > Settings > concurrent workers to $workers; back up $(q "$GH/ARTEX/.env") (ARTEX_SECRET_KEY)"
  fi
}

step_5ire(){
  hdr "5ire: local chat client with the MCP tools"
  local dir="$HOME/Library/Application Support/5ire" src="$CFG/generated/5ire-mcp.json"
  [ -d /Applications/5ire.app ] || { warn "5ire is not installed"; pend "Install 5ire from the official notarized DMG: https://github.com/nanbingxyz/5ire/releases"; }
  [ -s "$src" ] || die "missing $src (re-run: ./setup.sh --only plan)"
  # 5ire (pinned 12c6a08, legacy-data-migrator.ts) imports mcp.json into its own database once, on its first
  # launch, records that in Stories/legacy-data-migrator.store and never reads or rewrites the file again. So
  # the file's HexStrike entry is checked only until then; after that, 5ire's servers live in 5ire > Tools.
  local old_entry=0   # mcp.json's HexStrike entry predates the token wrapper (HexStrike answers it 401)
  if [ -e "$dir/mcp.json" ] && { grep -q 'hexstrike-env/bin/python3' "$dir/mcp.json" 2>/dev/null \
       || { grep -q 'hexstrike_mcp\.py' "$dir/mcp.json" 2>/dev/null && ! grep -q 'hexstrike_client\.py' "$dir/mcp.json" 2>/dev/null; }; }; then
    old_entry=1
  fi
  if [ -e "$dir/mcp.json" ] && [ -e "$dir/Stories/legacy-data-migrator.store" ]; then
    if [ $old_entry -eq 1 ]; then
      # What 5ire imported came from this file, so its database most likely holds the old entry too.
      warn "5ire imported a HexStrike entry without the API token wrapper on its first launch (HexStrike answers it 401)"
      pend "In 5ire > Tools, change the hexstrike-ai server to run through $(q "$SECOPS/mcp/hexstrike-client/hexstrike_client.py") (the command is in $(q "$src"))"
    else
      ok "5ire imported mcp.json on its first launch and keeps its MCP servers in its own database: change them in 5ire > Tools (the HexStrike entry must run through $(q "$SECOPS/mcp/hexstrike-client/hexstrike_client.py"); without it HexStrike answers 401)"
    fi
  elif [ -e "$dir/mcp.json" ]; then
    if [ $old_entry -eq 1 ]; then
      warn "5ire's mcp.json runs hexstrike_mcp.py without the API token wrapper (HexStrike refuses it), and 5ire imports it on its first launch"
      pend "Before opening 5ire, replace the hexstrike-ai entry in $(q "$dir/mcp.json") with the one in $(q "$src"): HexStrike runs through $(q "$SECOPS/mcp/hexstrike-client/hexstrike_client.py"), which adds its API token"
    elif grep -q 'pentagi-bridge' "$dir/mcp.json" 2>/dev/null; then ok "5ire mcp.json already lists the secstack servers (5ire imports it on its first launch)"
    else ok "5ire mcp.json exists; left untouched"; pend "Add HexStrike / Kali docs / pentagi-bridge in 5ire > Tools from $(q "$src")"; fi
  elif [ -d "$dir" ] && [ -n "$(ls -A "$dir" 2>/dev/null)" ]; then
    # 5ire reads mcp.json only on its very first launch; after that, servers are added in the app.
    ok "5ire has been opened before; not writing mcp.json"
    pend "Add HexStrike / Kali docs / pentagi-bridge in 5ire > Tools, using the commands in $(q "$src")"
  else
    mkdir -p "$dir"; ( umask 077; cp "$src" "$dir/mcp.json" ); ok "wrote $dir/mcp.json (5ire imports it on first launch)"
  fi
  # Two lines, checked one at a time: with only the IPv4 sinkhole, macOS still asks DNS for the IPv6
  # address (and the reverse). Only the missing ones are added.
  local v4_rx='^[[:space:]]*(0\.0\.0\.0|127\.0\.0\.1)[[:space:]]+([^#]*[[:space:]])?api\.axiom\.co([[:space:]]|$)'
  local v6_rx='^[[:space:]]*(::|::1)[[:space:]]+([^#]*[[:space:]])?api\.axiom\.co([[:space:]]|$)'
  local add="" what="" hosts_fix
  if ! grep -iqE "$v4_rx" /etc/hosts; then add='0.0.0.0 api.axiom.co\n'; what="IPv4"; fi
  if ! grep -iqE "$v6_rx" /etc/hosts; then add="$add"':: api.axiom.co\n'; what="${what:+$what and }IPv6"; fi
  hosts_fix="printf '\\n$add' | sudo tee -a /etc/hosts"
  if [ -z "$add" ]; then
    ok "api.axiom.co already blocked in /etc/hosts (IPv4 and IPv6)"
  elif ask_yn "Block 5ire's log shipping (api.axiom.co, $what) in /etc/hosts? Needs your sudo password."; then
    if { [ -z "$(tail -c1 /etc/hosts)" ] || echo; printf '%b' "$add"; } | sudo tee -a /etc/hosts >/dev/null; then
      ok "api.axiom.co blocked ($what added to /etc/hosts)"
    else
      warn "couldn't update /etc/hosts"; pend "Block 5ire's log shipping: $hosts_fix"
    fi
    sudo -k
  else
    pend "Block 5ire's log shipping: $hosts_fix"
  fi
  pend "In 5ire: add the Ollama provider http://127.0.0.1:11434 and pick model $(conf_get CHAT_MODEL)"
}

step_audit(){
  hdr "audit"
  need_secstack
  local rc=0
  "$SECSTACK" audit || rc=$?
  case $rc in                             # secstack audit: 0 passed, 1 issues, 2 incomplete
    0) ;;
    2) AUDIT_EXIT=2; warn "the audit could not check everything (its \"not checked\" lines above)"
       pend "Make what the audit could not check available (its \"not checked\" lines), then: secstack audit" ;;
    *) AUDIT_EXIT=3
       if [ $rc -eq 1 ]; then warn "the audit found issues (above)"; else warn "the audit failed (exit $rc, above)"; fi
       pend "Fix what the audit flagged (above), then: secstack audit" ;;
  esac
}

# ------------------------------------------------------------------------------------ main
if [ $PLAN_ONLY -eq 1 ]; then
  [ "$(uname -s)" = Darwin ] || { echo "macOS on Apple Silicon only."; exit 1; }
  python3 "$PLANPY" recommend
  exit $?
fi

plan_runs=0
if [ -n "$ONLY" ]; then [ "$ONLY" = plan ] && plan_runs=1
else case "$FROM" in ""|preflight|plan) plan_runs=1 ;; esac; fi
if [ $plan_runs -eq 1 ] && [ $INTERACTIVE -eq 0 ] && [ $YES -eq 0 ] && [ -z "$MODELS" ]; then
  echo "stdin is not a terminal: pass --yes (recommended models) or --models ID,ID"; exit 1
fi
echo "secstack setup: repo $REPO, runtime $SECOPS"
started=0
for s in $STEPS; do
  if [ -n "$ONLY" ]; then
    [ "$s" = "$ONLY" ] || [ "$s" = preflight ] || continue
  elif [ -n "$FROM" ] && [ $started -eq 0 ]; then
    if [ "$s" = "$FROM" ]; then started=1; elif [ "$s" != preflight ]; then continue; fi
  fi
  CURRENT="$s"
  "step_$s"
done
CURRENT=""

hdr "done"
pend "Keep nothing at login: Docker Desktop > Settings > General: turn off 'Start Docker Desktop when you sign in'; Ollama.app > Settings: turn off launch at login"
pend "When you're finished for the day: secstack down"
cat <<EOF

  Daily use (new shell):  secstack prep | secstack pentagi | secstack artex | secstack lab up | secstack down
  Re-plan models later:   ./setup.sh --only plan, then --only upstream, --only models (see docs/REBUILD.md)
  Add real targets:       secstack scope add <CIDR> "note"   (authorized hosts only)
EOF
exit $AUDIT_EXIT
