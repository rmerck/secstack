#!/usr/bin/env bash
# install.sh: wire this repo into the runtime root (~/GitHub/.sec-ops by default).
#
# The repo holds code and config. The runtime root holds secrets, logs, reports, live scope and the
# generated per-machine plan. Code dirs in the runtime root become symlinks into the repo, so
# `git pull` updates the stack and nothing secret ever lands in the working tree.
#
#   ./install.sh            link repo into runtime root, create private dirs, seed scope
#   ./install.sh --check    show what would change (including how existing dirs differ), change nothing
#   ./install.sh --force    also replace existing real dirs whose contents differ from the repo
#
# Existing real directories are renamed to <name>.pre-repo-<stamp>, never deleted. If one differs
# from the repo (local edits, extra scripts), install stops and lists the differences unless --force.
set -euo pipefail

REPO="$(cd "$(dirname "$0")" && pwd -P)"
GH="${SECSTACK_GH:-$HOME/GitHub}"
SECOPS="${SECOPS:-$GH/.sec-ops}"
STAMP="$(date +%Y%m%d-%H%M%S)"
CHECK=0; FORCE=0
# One option at most: an ignored extra word (`--force --check`) would change things the caller meant to check.
case "$#:${1:-}" in
  0:) ;;
  1:--check) CHECK=1 ;;
  1:--force) FORCE=1 ;;
  *) echo "usage: $0 [--check|--force]   (one option at most)"; exit 1 ;;
esac

# Everything below needs python3 (the guard, the stash, the hooks). Without the Command Line Tools,
# /usr/bin/python3 is a stub that fails, which the guard would report as an overlap.
if ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))' >/dev/null 2>&1; then
  echo "install.sh needs a working python3, 3.9 or later, and python3 here isn't one: xcode-select --install"
  exit 1
fi

# The runtime root holds secrets, the live scope and generated files. Neither it nor a folder in it
# (a configs/ or env/ symlinked into the repo, say) may resolve into the repo (git would see them, and
# link() below would move the repo's own folders), and it must not contain the repo. Folders are compared
# by identity as well as by path: APFS ignores case, so ~/github/x and ~/GitHub/x are one folder (so are
# the two ends of a bind mount). Same check as setup.sh's preflight.
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
  echo "The runtime root $SECOPS and the repo $REPO overlap (above). Clone the repo somewhere else (e.g. ~/GitHub/secstack) and keep the runtime folders out of it (no symlinks into the repo)."
  exit 1
fi

say(){ printf '  %s\n' "$*"; }
would(){ [ $CHECK -eq 1 ] && { say "would: $*"; return 0; }; return 1; }
BLOCKED=0

# Compare an existing real dir with the repo copy; print the differences (ignoring .bak/.DS_Store/pycache).
# The two roots are shortened by plain string replacement: no sed, so '#', '[' or '&' in a path is fine.
differs(){ # differs <runtime-dir> <repo-dir>
  local out line n=0
  out=$(diff -rq -x '*.bak' -x '*.pre-repo-*' -x '.DS_Store' -x '__pycache__' "$1" "$2" 2>&1 || true)
  [ -z "$out" ] && return 1
  while IFS= read -r line; do
    n=$((n + 1))
    if [ $n -gt 20 ]; then say "    ... (more differences not shown)"; break; fi
    line=${line//"$1"/<runtime>}; line=${line//"$2"/<repo>}
    printf '      %s\n' "$line"
  done <<EOF
$out
EOF
  return 0
}

link(){ # link <repo-path> <runtime-path>
  local src="$1" dst="$2"
  if [ -L "$dst" ]; then
    if [ "$(readlink "$dst")" = "$src" ]; then say "ok      $dst -> $src"; return; fi
    would "relink $dst -> $src" || { ln -sfn "$src" "$dst"; say "relink  $dst -> $src"; }
  elif [ -e "$dst" ]; then
    # Already the repo's own folder, reached another way (a symlink the repo holds, a bind mount):
    # moving it would move the repo's copy and leave a link pointing at itself.
    if [ "$dst" -ef "$src" ]; then say "ok      $dst is the repo copy itself"; return; fi
    if differs "$dst" "$src"; then
      say "differs $dst (above) from the repo copy"
      if [ $CHECK -eq 1 ]; then say "would: back it up and link it (needs --force)"; return; fi
      if [ $FORCE -ne 1 ]; then BLOCKED=1; return; fi
    fi
    would "move $dst to $dst.pre-repo-$STAMP, then link it" || {
      mv "$dst" "$dst.pre-repo-$STAMP"; say "backup  $dst -> $dst.pre-repo-$STAMP"
      ln -s "$src" "$dst"; say "link    $dst -> $src"; }
  else
    would "link $dst -> $src" || { ln -s "$src" "$dst"; say "link    $dst -> $src"; }
  fi
}

echo "repo:    $REPO"
echo "runtime: $SECOPS"
umask 077
would "create $SECOPS/{env,logs,reports,run,cache,configs} (700)" || {
  mkdir -p "$SECOPS"/env "$SECOPS"/logs "$SECOPS"/reports "$SECOPS"/run "$SECOPS"/cache "$SECOPS"/configs
  chmod 700 "$SECOPS"; }

echo "code"
link "$REPO/bin" "$SECOPS/bin"
link "$REPO/mcp" "$SECOPS/mcp"
for d in hexstrike-kali searxng flow-templates; do
  link "$REPO/configs/$d" "$SECOPS/configs/$d"
done
if [ $BLOCKED -eq 1 ]; then
  echo
  echo "Some existing directories differ from the repo (listed above). Nothing was replaced."
  echo "Keep anything you need from them, then re-run with --force (they are backed up as *.pre-repo-<stamp>)."
  exit 3
fi
# configs/pentagi-providers is generated per machine by scripts/plan.py (no longer a repo link).
if [ -L "$SECOPS/configs/pentagi-providers" ]; then
  would "remove the old pentagi-providers link (plan.py regenerates it)" || {
    rm "$SECOPS/configs/pentagi-providers"; say "unlink  configs/pentagi-providers (now generated by plan.py)"; }
fi

echo "state"
if [ -f "$SECOPS/configs/scope.cidrs" ]; then say "keep    configs/scope.cidrs"
else
  would "seed configs/scope.cidrs from the example" || {
    cp "$REPO/configs/scope.cidrs.example" "$SECOPS/configs/scope.cidrs"; chmod 600 "$SECOPS/configs/scope.cidrs"
    say "seed    configs/scope.cidrs (empty: the lab needs no entry; add targets with: secstack scope add CIDR)"; }
fi
[ -f "$SECOPS/configs/scope.mode" ] || would "write scope.mode=strict" || echo strict > "$SECOPS/configs/scope.mode"
if [ ! -f "$SECOPS/configs/mcp-servers.stash.json" ]; then
  would "seed configs/mcp-servers.stash.json" || {
    python3 - "$REPO/configs/claude-desktop/mcp-servers.json" "$SECOPS/configs/mcp-servers.stash.json" "$GH" "$SECOPS" "$HOME" <<'PY'
import json, os, sys
src, dst, gh, secops, home = sys.argv[1:6]
def walk(x):
    if isinstance(x, str):
        return x.replace("__SECOPS__", secops).replace("__GH__", gh).replace("__HOME__", home)
    if isinstance(x, list):
        return [walk(i) for i in x]
    if isinstance(x, dict):
        return {k: walk(v) for k, v in x.items()}
    return x
data = walk(json.load(open(src)))
fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w") as f:
    json.dump(data, f, indent=2)
PY
    say "seed    configs/mcp-servers.stash.json"; }
elif ! grep -F 'hexstrike_client.py' "$SECOPS/configs/mcp-servers.stash.json" >/dev/null 2>&1 \
     && grep -F '"hexstrike-ai"' "$SECOPS/configs/mcp-servers.stash.json" >/dev/null 2>&1; then
  # Earlier versions ran hexstrike_mcp.py directly; the API now needs the token the wrapper adds.
  would "update the hexstrike-ai entry in configs/mcp-servers.stash.json (HexStrike API token)" || {
    if python3 - "$REPO/configs/claude-desktop/mcp-servers.json" "$SECOPS/configs/mcp-servers.stash.json" "$GH" "$SECOPS" "$HOME" <<'PY'
import json, os, sys, tempfile
src, dst, gh, secops, home = sys.argv[1:6]
def walk(x):
    if isinstance(x, str):
        return x.replace("__SECOPS__", secops).replace("__GH__", gh).replace("__HOME__", home)
    if isinstance(x, list):
        return [walk(i) for i in x]
    if isinstance(x, dict):
        return {k: walk(v) for k, v in x.items()}
    return x
stash = json.load(open(dst))
if not isinstance(stash, dict):
    sys.exit("the stash is not a JSON object; left as it is")
stash["hexstrike-ai"] = walk(json.load(open(src)))["hexstrike-ai"]
fd, tmp = tempfile.mkstemp(dir=os.path.dirname(dst), prefix=".stash-")
with os.fdopen(fd, "w") as f:
    json.dump(stash, f, indent=2)
os.chmod(tmp, 0o600)
os.replace(tmp, dst)
PY
    then
      say "update  configs/mcp-servers.stash.json: hexstrike-ai now runs through mcp/hexstrike-client"
      say "        (Claude Desktop users: secstack claude off && secstack claude on, then restart Claude)"
    else
      say "note    couldn't update the hexstrike-ai entry in configs/mcp-servers.stash.json; replace it with the one in configs/claude-desktop/mcp-servers.json"
    fi; }
fi
would "chmod +x bin/* scripts/*.sh scripts/*.py install.sh setup.sh" || \
  chmod +x "$REPO"/bin/* "$REPO"/scripts/*.sh "$REPO"/scripts/*.py "$REPO"/install.sh "$REPO"/setup.sh

echo "shell"
ESC_BIN="$(printf '%q' "$SECOPS/bin")"
LINE="export PATH=$ESC_BIN:\"\$PATH\""
# Only an exact, uncommented line counts (a commented-out or similar-looking entry doesn't).
if grep -qsxF "$LINE" "$HOME/.zshrc" || grep -qsxF "export PATH=\"$SECOPS/bin:\$PATH\"" "$HOME/.zshrc" \
   || { [ "$SECOPS" = "$HOME/GitHub/.sec-ops" ] && grep -qsxF 'export PATH="$HOME/GitHub/.sec-ops/bin:$PATH"' "$HOME/.zshrc"; }; then
  say "ok      PATH entry in ~/.zshrc"
else
  would "append the PATH entry to ~/.zshrc" || { printf '\n# secstack\n%s\n' "$LINE" >> "$HOME/.zshrc"; say "add     PATH entry to ~/.zshrc"; }
fi
# secstack, plan.py and the MCP clients find the runtime root through SECSTACK_GH and SECOPS, which
# default to ~/GitHub and ~/GitHub/.sec-ops. A different root has to reach new shells too, or `secstack`
# there would quietly use (and create) ~/GitHub/.sec-ops. The last such line in ~/.zshrc wins.
ENV_LINE="export SECSTACK_GH=$(printf '%q' "$GH") SECOPS=$(printf '%q' "$SECOPS")"
if [ "$GH" != "$HOME/GitHub" ] || [ "$SECOPS" != "$GH/.sec-ops" ]; then
  if grep -qsxF "$ENV_LINE" "$HOME/.zshrc"; then say "ok      runtime root in ~/.zshrc"
  else
    would "append the runtime root to ~/.zshrc: $ENV_LINE" || {
      printf '\n# secstack runtime root\n%s\n' "$ENV_LINE" >> "$HOME/.zshrc"; say "add     runtime root to ~/.zshrc: $ENV_LINE"; }
  fi
elif grep -qsE '^[[:space:]]*export[[:space:]]+(SECSTACK_GH|SECOPS)=' "$HOME/.zshrc"; then
  say "note    ~/.zshrc sets SECSTACK_GH or SECOPS (an earlier install?): new shells use that runtime root, not $SECOPS. Remove that line."
fi

echo "hooks"
# scripts/check-secrets.sh runs as every hook it supports: pre-commit, pre-merge-commit and
# pre-applypatch (what is staged), commit-msg and applypatch-msg (the message) and pre-push
# (everything a push sends, --no-verify commits included). Each hook is a small wrapper, not a link:
# when the script is missing (a sparse checkout, an old branch) it refuses, where git skips a
# dangling link without a word. A hook of your own is kept; only our wrappers, links to our script
# and dangling links are replaced.
SECRET_HOOKS="pre-commit pre-merge-commit pre-applypatch commit-msg applypatch-msg pre-push"
HOOK_MARK="# secstack check-secrets hook"
hook_body(){ # hook_body <script>: the wrapper, with the path single-quoted for sh
  local q
  q=$(printf '%s' "$1" | sed "s/'/'\\\\''/g")
  printf '%s\n' '#!/bin/sh' "$HOOK_MARK (written by install.sh; re-run it to update this file)." \
    "# Runs scripts/check-secrets.sh and refuses when it can't be found, instead of being skipped." \
    "s='$q'" \
    '[ -f "$s" ] || s="$(git rev-parse --show-toplevel 2>/dev/null)/scripts/check-secrets.sh"' \
    'if [ ! -f "$s" ]; then' \
    '  echo "check-secrets: scripts/check-secrets.sh not found, so the ${0##*/} hook refuses. Re-run install.sh, or use --no-verify after checking by hand." >&2' \
    '  exit 1' \
    'fi' \
    'exec bash "$s" --hook "${0##*/}" "$@"'
}
realp(){ python3 -c 'import os, sys; print(os.path.realpath(sys.argv[1]))' "$1"; }
if git -C "$REPO" rev-parse --git-dir >/dev/null 2>&1; then
  hooks_path="$(git -C "$REPO" config --get core.hooksPath || true)"
  # In a linked worktree the hooks are the main checkout's and run for every worktree: point them
  # at the main checkout's script.
  common="$(cd "$REPO" && cd "$(git rev-parse --git-common-dir)" && pwd -P)"
  main="$REPO"
  if [ "$(basename "$common")" = .git ] && [ -f "$(dirname "$common")/scripts/check-secrets.sh" ]; then
    main="$(dirname "$common")"
  fi
  script="$main/scripts/check-secrets.sh"
  own="$common/hooks"
  local_hp="$(git -C "$REPO" config --local --get core.hooksPath || true)"
  # The value written for a repo-local override: relative in a main checkout (git resolves it from the
  # top of the working tree), so it still works after the clone is moved; absolute in a linked worktree.
  own_hp="$own"; [ "$common" = "$(cd "$REPO" && pwd -P)/.git" ] && own_hp=.git/hooks
  if [ -n "$local_hp" ] && [ ! -e "$(cd "$REPO" && realp "$local_hp")" ] \
     && case "$local_hp" in */.git/hooks) true ;; *) false ;; esac; then
    # An absolute .git/hooks path that no longer exists: an earlier install's, left behind when the clone
    # moved (git then runs no hooks at all). Ours to reset.
    would "reset the repo-local core.hooksPath $local_hp (a moved clone's) to $own_hp" || {
      git -C "$REPO" config --local core.hooksPath "$own_hp"
      say "set     repo-local core.hooksPath $own_hp (was $local_hp, from before the clone moved)"; }
    hooks_path=""
  elif [ -n "$hooks_path" ] && [ -z "$local_hp" ]; then
    # Set in the global or system config (a hooks manager shared by every repo): git would never run
    # this repo's hooks. A repo-local setting pointing at its own hooks folder takes precedence, so the
    # global hooks no longer run here: a note, which setup lists at the end.
    say "note    core.hooksPath is set globally ($hooks_path): this repo now uses its own hooks folder, so your global hooks don't run here"
    would "set a repo-local core.hooksPath to $own_hp" || {
      git -C "$REPO" config --local core.hooksPath "$own_hp"
      say "set     repo-local core.hooksPath $own_hp (undo: git config --local --unset core.hooksPath)"; }
    hooks_path=""
  elif [ -n "$local_hp" ] && [ "$(cd "$REPO" && realp "$local_hp")" = "$(realp "$own")" ]; then
    hooks_path=""   # already this repo's own hooks folder (set by an earlier run)
  fi
  if [ -n "$hooks_path" ]; then
    # A hooksPath set for this repo is your choice; don't write there. git ignores .git/hooks then.
    say "note    core.hooksPath is set ($hooks_path), so git won't run .git/hooks: make its hooks ($SECRET_HOOKS) run: bash $script --hook <name> \"\$@\""
  else
    hooks_dir="$own"
    [ "$main" = "$REPO" ] || say "info    linked worktree: the hooks in $hooks_dir are shared and run $script"
    want="$(hook_body "$script")"
    for name in $SECRET_HOOKS; do
      h="$hooks_dir/$name"
      if [ -L "$h" ] && [ ! -e "$h" ]; then
        action="replace the dangling $name hook link"
      elif [ -L "$h" ] && { [ "$(realp "$h")" = "$(realp "$script")" ] || [ "$(realp "$h")" = "$(realp "$REPO/scripts/check-secrets.sh")" ]; }; then
        action="replace the $name hook link with a wrapper"
      elif [ -L "$h" ]; then
        say "keep    existing $name hook (a link to $(readlink "$h")): make it run bash $script --hook $name \"\$@\""; continue
      elif [ -f "$h" ] && grep -qF "$HOOK_MARK" "$h"; then
        if [ "$(cat "$h")" = "$want" ]; then say "ok      $name hook"; continue; fi
        action="update the $name hook"
      elif [ -e "$h" ]; then
        say "keep    existing $name hook (add: bash $script --hook $name \"\$@\")"; continue
      else
        action="add the $name hook"
      fi
      would "$action" || {
        mkdir -p "$hooks_dir"; rm -f "$h"; printf '%s\n' "$want" > "$h"; chmod 755 "$h"; say "hook    $action"; }
    done
  fi
  # GUI git apps don't inherit SECOPS: record the runtime root where the hooks look for it. A recorded
  # root that can't be read makes them refuse.
  if [ "$(git -C "$REPO" config --get secstack.secops || true)" = "$SECOPS" ]; then
    say "ok      git config secstack.secops"
  else
    would "record git config secstack.secops $SECOPS" || {
      git -C "$REPO" config secstack.secops "$SECOPS"; say "record  git config secstack.secops $SECOPS"; }
  fi
fi

if [ $CHECK -eq 1 ]; then echo "(check only, nothing changed)"; else echo "done. Open a new shell (or: export PATH=\"$SECOPS/bin:\$PATH\"), then: secstack audit"; fi
