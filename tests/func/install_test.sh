#!/usr/bin/env bash
# Functional test for install.sh in a throwaway HOME (with a space in its path).
#   bash tests/func/install_test.sh        (from the repo root; needs git, python3)
set -uo pipefail
SRC_REPO="$(cd "${1:-$(dirname "$0")/../..}" && pwd -P)"
T="$(cd "$(mktemp -d "${TMPDIR:-/tmp}/it.XXXXXX")" && pwd -P)"     # macOS: /var is /private/var
trap 'rm -rf "$T"' EXIT
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
# git looks no higher than $T: a TMPDIR inside some checkout must not lend the tests its repo.
export GIT_CEILING_DIRECTORIES="$T"
mode(){ python3 -c 'import os,sys; print(oct(os.stat(sys.argv[1]).st_mode & 0o777)[2:])' "$1"; }
mkdir -p "$T/home dir/GitHub/secstack"
(cd "$SRC_REPO" && tar cf - --exclude .git --exclude __pycache__ .) | (cd "$T/home dir/GitHub/secstack" && tar xf -)
R="$T/home dir/GitHub/secstack"
(cd "$R" && git init -q)
export HOME="$T/home dir" SECSTACK_GH="$T/home dir/GitHub"
unset SECOPS
S="$HOME/GitHub/.sec-ops"
pass=0; fail=0
ok(){ echo "PASS $*"; pass=$((pass+1)); }
bad(){ echo "FAIL $*"; fail=$((fail+1)); }

# --check on a fresh machine changes nothing
"$R/install.sh" --check > "$T/o1" 2>&1; rc=$?
[ $rc -eq 0 ] && [ ! -e "$S" ] && ok "--check changes nothing" || { bad "--check rc=$rc"; cat "$T/o1"; }

# fresh install
"$R/install.sh" > "$T/o2" 2>&1; rc=$?
[ $rc -eq 0 ] && ok "fresh install" || { bad "fresh install rc=$rc"; cat "$T/o2"; }
[ "$(readlink "$S/bin")" = "$R/bin" ] && ok "bin linked" || bad "bin link: $(readlink "$S/bin")"
[ "$(mode "$S")" = 700 ] && ok "runtime root 700" || bad "runtime perms"
[ "$(mode "$S/configs/scope.cidrs")" = 600 ] && ok "scope 600" || bad "scope perms"
python3 -c "import json,sys; d=json.load(open(sys.argv[1])); s=json.dumps(d); sys.exit(0 if '__' not in s and sys.argv[2] in s else 1)" \
  "$S/configs/mcp-servers.stash.json" "$SECSTACK_GH/hexstrike-ai" && ok "stash placeholders substituted" || bad "stash placeholders"
[ "$(grep -c 'secstack' "$HOME/.zshrc")" = 1 ] && ok "zshrc line added once" || bad "zshrc"
( export PATH=/usr/bin:/bin; . "$HOME/.zshrc" 2>/dev/null; case ":$PATH:" in *":$S/bin:"*) exit 0 ;; *) exit 1 ;; esac ) \
  && ok "zshrc PATH line works with a space in HOME" || bad "zshrc PATH line: $(tail -1 "$HOME/.zshrc")"
grep -qF '# secstack check-secrets hook' "$R/.git/hooks/pre-commit" && [ -x "$R/.git/hooks/pre-commit" ] && ok "hook installed" || bad "hook"

# re-run is idempotent
"$R/install.sh" > "$T/o3" 2>&1; rc=$?
[ $rc -eq 0 ] && ! grep -qE '^  (link|relink|backup|seed|add) ' "$T/o3" && ok "re-run changes nothing" || { bad "re-run rc=$rc"; cat "$T/o3"; }
[ "$(grep -c 'secstack' "$HOME/.zshrc")" = 1 ] && ok "zshrc still one line" || bad "zshrc duplicated"

# a real dir identical to the repo is swapped without --force
rm "$S/mcp" && cp -a "$R/mcp" "$S/mcp"
"$R/install.sh" > "$T/o4" 2>&1; rc=$?
[ $rc -eq 0 ] && [ -L "$S/mcp" ] && ls -d "$S"/mcp.pre-repo-* >/dev/null 2>&1 && ok "identical dir swapped, backup kept" || { bad "identical swap rc=$rc"; cat "$T/o4"; }

# a real dir that differs blocks (exit 3) and lists the difference
rm "$S/bin" && cp -a "$R/bin" "$S/bin" && echo "my local script" > "$S/bin/my-tool"
"$R/install.sh" > "$T/o5" 2>&1; rc=$?
[ $rc -eq 3 ] && [ ! -L "$S/bin" ] && grep -q 'my-tool' "$T/o5" && ok "differing dir blocks with exit 3 and lists it" || { bad "differ rc=$rc"; cat "$T/o5"; }
"$R/install.sh" --check > "$T/o6" 2>&1; rc=$?
[ $rc -eq 0 ] && [ ! -L "$S/bin" ] && grep -q 'needs --force' "$T/o6" && ok "--check reports it, changes nothing" || { bad "check differ rc=$rc"; cat "$T/o6"; }
"$R/install.sh" --force > "$T/o7" 2>&1; rc=$?
[ $rc -eq 0 ] && [ -L "$S/bin" ] && ls "$S"/bin.pre-repo-*/my-tool >/dev/null 2>&1 && ok "--force backs up and links" || { bad "force rc=$rc"; cat "$T/o7"; }

# an existing non-symlink pre-commit hook is kept
rm "$R/.git/hooks/pre-commit" && printf '#!/bin/sh\necho mine\n' > "$R/.git/hooks/pre-commit"
"$R/install.sh" > "$T/o8" 2>&1
grep -q 'echo mine' "$R/.git/hooks/pre-commit" && grep -q 'keep    existing pre-commit' "$T/o8" && ok "own hook kept" || { bad "hook overwritten"; cat "$T/o8"; }

# a dangling hook link is replaced; with core.hooksPath set the hook is left alone, with a note
rm "$R/.git/hooks/pre-commit" && ln -s ../../scripts/gone.sh "$R/.git/hooks/pre-commit"
"$R/install.sh" > "$T/o10" 2>&1
[ ! -L "$R/.git/hooks/pre-commit" ] && grep -qF '# secstack check-secrets hook' "$R/.git/hooks/pre-commit" && ok "dangling hook link replaced" || { bad "dangling hook"; cat "$T/o10"; }
git -C "$R" config core.hooksPath "$T/shared-hooks"
"$R/install.sh" > "$T/o11" 2>&1
[ ! -e "$T/shared-hooks" ] && grep -q 'core.hooksPath is set' "$T/o11" && ok "core.hooksPath: nothing written, note shown" || { bad "hooksPath"; cat "$T/o11"; }
git -C "$R" config --unset core.hooksPath

# a runtime root inside the repo (or containing it) is refused before anything is written
SECOPS="$R/runtime" "$R/install.sh" > "$T/o12" 2>&1; rc=$?
[ $rc -ne 0 ] && [ ! -e "$R/runtime" ] && grep -q 'overlap' "$T/o12" && ok "runtime root inside the repo refused" || { bad "overlap rc=$rc"; cat "$T/o12"; }
SECOPS="$HOME/GitHub" "$R/install.sh" > "$T/o13" 2>&1; rc=$?
[ $rc -ne 0 ] && grep -q 'overlap' "$T/o13" && ok "runtime root containing the repo refused" || { bad "overlap (parent) rc=$rc"; cat "$T/o13"; }

# old pentagi-providers link is removed
ln -s "$R/configs" "$S/configs/pentagi-providers"
"$R/install.sh" > "$T/o9" 2>&1
[ ! -e "$S/configs/pentagi-providers" ] && ok "old providers link removed" || bad "providers link kept"

# ======================================================================================================
# Section: arguments, runtime-root guard, link() on the repo's own folder, difference listing, and a
# non-default runtime root in ~/.zshrc. Every case below uses its own HOME and repo copy (no .git, so
# the hooks block stays out of it) and depends on nothing above.
# ======================================================================================================
fresh(){ mkdir -p "$1" && (cd "$SRC_REPO" && tar cf - --exclude .git --exclude __pycache__ .) | (cd "$1" && tar xf -); }
P="$T/paths/repo"; fresh "$P"

# Unknown, empty or extra arguments are refused before anything changes.
H="$T/paths/args home"
for args in "--force --check" "--check --force" "--check --check" "--bogus"; do
  rm -rf "$H"; mkdir -p "$H"
  # shellcheck disable=SC2086
  HOME="$H" SECSTACK_GH="$H/GitHub" "$P/install.sh" $args > "$T/pa" 2>&1; rc=$?
  [ $rc -eq 1 ] && grep -q '^usage:' "$T/pa" && [ ! -e "$H/GitHub" ] && [ ! -e "$H/.zshrc" ] \
    && ok "install.sh $args: refused, nothing changed" || { bad "install.sh $args rc=$rc"; cat "$T/pa"; }
done
rm -rf "$H"; mkdir -p "$H"
HOME="$H" SECSTACK_GH="$H/GitHub" "$P/install.sh" "" > "$T/pa" 2>&1; rc=$?
[ $rc -eq 1 ] && [ ! -e "$H/GitHub" ] && ok "install.sh '': refused, nothing changed" || { bad "empty argument rc=$rc"; cat "$T/pa"; }

# The guard resolves symlinks and also catches the runtime root being the repo itself.
H="$T/paths/guard home"; mkdir -p "$H/GitHub"
HOME="$H" SECSTACK_GH="$H/GitHub" SECOPS="$P" "$P/install.sh" > "$T/pg1" 2>&1; rc=$?
[ $rc -eq 1 ] && grep -q 'overlap' "$T/pg1" && [ ! -e "$P/env" ] && [ ! -e "$H/.zshrc" ] \
  && ok "runtime root equal to the repo refused" || { bad "SECOPS=repo rc=$rc"; cat "$T/pg1"; }
ln -s "$P/rt" "$H/GitHub/.sec-ops"            # the default runtime root, symlinked into the repo
HOME="$H" SECSTACK_GH="$H/GitHub" "$P/install.sh" > "$T/pg2" 2>&1; rc=$?
[ $rc -eq 1 ] && grep -q 'overlap' "$T/pg2" && [ ! -e "$P/rt" ] && [ ! -e "$H/.zshrc" ] \
  && ok "runtime root symlinked into the repo refused" || { bad "symlinked root rc=$rc"; cat "$T/pg2"; }
rm "$H/GitHub/.sec-ops"; S2="$H/GitHub/.sec-ops"
for sub in configs env hexstrike-data; do
  rm -rf "$S2"; mkdir -p "$S2"
  case $sub in                                 # into a repo folder, the repo itself, another repo folder
    configs) ln -s "$P/configs" "$S2/configs" ;;
    env) ln -s "$P" "$S2/env" ;;
    *) ln -s "$P/docs" "$S2/$sub" ;;
  esac
  HOME="$H" SECSTACK_GH="$H/GitHub" "$P/install.sh" > "$T/pg3" 2>&1; rc=$?
  [ $rc -eq 1 ] && grep -q 'overlap' "$T/pg3" && grep -qF "$S2/$sub" "$T/pg3" && [ ! -e "$S2/bin" ] \
    && [ -d "$P/configs/hexstrike-kali" ] && [ ! -L "$P/configs/hexstrike-kali" ] \
    && ! ls -d "$P"/configs/*.pre-repo-* >/dev/null 2>&1 && [ ! -e "$P/configs/scope.cidrs" ] && [ ! -e "$P/docs/scope.cidrs" ] \
    && ok "runtime $sub/ symlinked into the repo refused, repo untouched" || { bad "symlinked $sub rc=$rc"; cat "$T/pg3"; }
done

# A runtime folder that already is the repo's folder (here through a symlink the repo itself holds) is
# left alone: moving it would move the repo's copy and leave a link to itself.
Q="$T/paths/q"; fresh "$Q"; SH="$T/paths/shared"; mkdir -p "$SH"
mv "$Q/configs/hexstrike-kali" "$SH/hexstrike-kali"; ln -s "$SH/hexstrike-kali" "$Q/configs/hexstrike-kali"
H="$T/paths/same home"; mkdir -p "$H/GitHub/.sec-ops"; ln -s "$SH" "$H/GitHub/.sec-ops/configs"
HOME="$H" SECSTACK_GH="$H/GitHub" "$Q/install.sh" > "$T/ps" 2>&1; rc=$?
[ $rc -eq 0 ] && [ -d "$SH/hexstrike-kali" ] && [ ! -L "$SH/hexstrike-kali" ] && [ -f "$SH/hexstrike-kali/Dockerfile" ] \
  && ! ls -d "$SH"/hexstrike-kali.pre-repo-* >/dev/null 2>&1 && grep -q 'is the repo copy itself' "$T/ps" \
  && ok "the repo's own folder is not moved or relinked" || { bad "same-folder link rc=$rc"; cat "$T/ps"; ls -la "$SH"; }

# The difference listing works with '#', '[', '&' and '*' in the paths (no sed on user paths).
H="$T/paths/h#o[m]e & *"; mkdir -p "$H"
HOME="$H" SECSTACK_GH="$H/GitHub" "$P/install.sh" > "$T/pd1" 2>&1 || { bad "special-character HOME install"; cat "$T/pd1"; }
S3="$H/GitHub/.sec-ops"; rm "$S3/bin" && cp -a "$P/bin" "$S3/bin" && echo "my local script" > "$S3/bin/my-tool"
HOME="$H" SECSTACK_GH="$H/GitHub" "$P/install.sh" > "$T/pd2" 2>&1; rc=$?
[ $rc -eq 3 ] && grep -q 'Only in <runtime>: my-tool' "$T/pd2" && ! grep -qi 'sed' "$T/pd2" && [ ! -L "$S3/bin" ] \
  && ok "difference listing with special characters in HOME" || { bad "listing rc=$rc"; cat "$T/pd2"; }

# A non-default runtime root reaches new shells through ~/.zshrc (once), and the default adds nothing.
H="$T/paths/custom home"; G="$T/paths/vol GH"; mkdir -p "$H"
HOME="$H" SECSTACK_GH="$G" "$P/install.sh" --check > "$T/pz0" 2>&1
grep -q 'would: append the runtime root' "$T/pz0" && [ ! -e "$H/.zshrc" ] && ok "--check lists the runtime-root line" \
  || { bad "check runtime root"; cat "$T/pz0"; }
HOME="$H" SECSTACK_GH="$G" "$P/install.sh" > "$T/pz1" 2>&1 && HOME="$H" SECSTACK_GH="$G" "$P/install.sh" > "$T/pz2" 2>&1
# --norc and stdin from /dev/null: a bash that thinks it was started by sshd reads the system bashrc.
got=$(env -i HOME="$H" PATH=/usr/bin:/bin bash --norc -c '. "$HOME/.zshrc" 2>/dev/null; printf "%s|%s|%s" "$SECSTACK_GH" "$SECOPS" "$PATH"' </dev/null)
[ "$got" = "$G|$G/.sec-ops|$G/.sec-ops/bin:/usr/bin:/bin" ] && [ "$(grep -c '^export SECSTACK_GH=' "$H/.zshrc")" = 1 ] \
  && ok "non-default SECSTACK_GH kept in ~/.zshrc, once" || { bad "custom GH: $got"; cat "$H/.zshrc"; }
H="$T/paths/custom2 home"; R2="$T/paths/rt elsewhere"; mkdir -p "$H"
HOME="$H" SECSTACK_GH="$H/GitHub" SECOPS="$R2" "$P/install.sh" > "$T/pz3" 2>&1
got=$(env -i HOME="$H" PATH=/usr/bin:/bin bash --norc -c '. "$HOME/.zshrc" 2>/dev/null; printf "%s|%s" "$SECSTACK_GH" "$SECOPS"' </dev/null)
[ "$got" = "$H/GitHub|$R2" ] && ok "non-default SECOPS kept in ~/.zshrc" || { bad "custom SECOPS: $got"; cat "$H/.zshrc"; }
H="$T/paths/default home"; mkdir -p "$H"
HOME="$H" SECSTACK_GH="$H/GitHub" "$P/install.sh" > "$T/pz4" 2>&1
! grep -qE 'SECSTACK_GH|SECOPS=' "$H/.zshrc" && ! grep -q 'note.*SECSTACK_GH' "$T/pz4" \
  && ok "default runtime root adds no export line" || { bad "default root exports"; cat "$H/.zshrc"; }
printf 'export SECSTACK_GH=/old/place SECOPS=/old/place/.sec-ops\n' >> "$H/.zshrc"
HOME="$H" SECSTACK_GH="$H/GitHub" "$P/install.sh" > "$T/pz5" 2>&1
grep -q 'note.*SECSTACK_GH' "$T/pz5" && ok "a leftover runtime-root line in ~/.zshrc is pointed out" || { bad "stale export"; cat "$T/pz5"; }
grep -qF 'seed    configs/scope.cidrs (empty: the lab needs no entry;' "$T/pz4" && [ -z "$(grep -v '^#' "$H/GitHub/.sec-ops/configs/scope.cidrs")" ] \
  && ok "the seeded scope is empty, and install says so" || { bad "scope seed message"; cat "$T/pz4"; }

# A python3 that doesn't run (no Command Line Tools: /usr/bin/python3 is a stub that fails) is named as
# such before anything changes, not reported as an overlap of the runtime root and the repo.
SB="$T/paths/stub bin"; mkdir -p "$SB"
printf '#!/bin/sh\necho "xcrun: error: invalid active developer path" >&2\nexit 1\n' > "$SB/python3"; chmod +x "$SB/python3"
H="$T/paths/nopy home"; mkdir -p "$H"
HOME="$H" SECSTACK_GH="$H/GitHub" PATH="$SB:$PATH" "$P/install.sh" > "$T/pp" 2>&1; rc=$?
[ $rc -eq 1 ] && grep -q 'needs a working python3' "$T/pp" && ! grep -q 'overlap' "$T/pp" && [ ! -e "$H/GitHub" ] && [ ! -e "$H/.zshrc" ] \
  && ok "a python3 that doesn't run is named, nothing changed" || { bad "broken python3 rc=$rc"; cat "$T/pp"; }

# The runtime root and the repo are compared by identity: APFS ignores case (~/github is ~/GitHub), and a
# bind mount is the same folder under another path. AL is $T/paths (holding the repo copy P) spelled
# another way: in other case where the file system ignores it, else a bind mount in its own namespace.
AL=""; AL_BIND=""
if [ -d "$T/PATHS" ] && [ "$T/PATHS" -ef "$T/paths" ]; then AL="$T/PATHS"
elif command -v unshare >/dev/null 2>&1 && mkdir -p "$T/paths bind" \
     && unshare -rm sh -c 'mount --bind "$1" "$2"' sh "$T/paths" "$T/paths bind" >/dev/null 2>&1; then
  AL="$T/paths bind"; AL_BIND=1
fi
in_al(){ # command...: run it where $AL names $T/paths
  if [ -n "$AL_BIND" ]; then unshare -rm sh -c 'mount --bind "$1" "$2" && shift 2 && exec "$@"' sh "$T/paths" "$AL" "$@"
  else "$@"; fi
}
if [ -z "$AL" ]; then
  echo "SKIP identity checks (need a case-insensitive file system, or unshare with bind mounts)"
else
  H="$T/alias home"; mkdir -p "$H"
  in_al env HOME="$H" SECSTACK_GH="$H/GitHub" SECOPS="$AL" "$P/install.sh" > "$T/pi1" 2>&1; rc=$?
  [ $rc -eq 1 ] && grep -q 'overlap' "$T/pi1" && [ ! -e "$T/paths/env" ] && [ ! -e "$H/.zshrc" ] \
    && ok "a runtime root holding the repo, spelled another way, is refused" || { bad "root by identity rc=$rc"; cat "$T/pi1"; }
  S4="$H/GitHub/.sec-ops"; mkdir -p "$S4"; ln -s "$AL/repo/configs" "$S4/configs"
  in_al env HOME="$H" SECSTACK_GH="$H/GitHub" "$P/install.sh" > "$T/pi2" 2>&1; rc=$?
  [ $rc -eq 1 ] && grep -q 'overlap' "$T/pi2" && grep -qF "$S4/configs" "$T/pi2" && [ ! -e "$S4/bin" ] \
    && [ ! -e "$P/configs/scope.cidrs" ] && [ ! -e "$H/.zshrc" ] \
    && ok "a runtime configs/ in the repo, spelled another way, is refused" || { bad "configs by identity rc=$rc"; cat "$T/pi2"; }
fi
# ======================================================================================================

# ======================================================================================================
# Section: git hooks (scripts/check-secrets.sh). Its own HOME and repo copy, with a quote and a space in
# the repo's path (the wrapper single-quotes it); depends on nothing above.
# ======================================================================================================
HM='# secstack check-secrets hook'; HOOKS="pre-commit pre-merge-commit pre-applypatch commit-msg applypatch-msg pre-push"
HH="$T/hooks home"; HR="$T/hooks/it's repo"; HS="$HH/GitHub/.sec-ops"
mkdir -p "$HH" "$HR" && (cd "$SRC_REPO" && tar cf - --exclude .git --exclude __pycache__ .) | (cd "$HR" && tar xf -)
(cd "$HR" && git init -q && git symbolic-ref HEAD refs/heads/main)
hi(){ HOME="$HH" SECSTACK_GH="$HH/GitHub" "$@"; }                      # install.sh in this section's HOME
hg(){ GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@t GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@t git "$@"; }
wrappers(){ local n; for n in $HOOKS; do [ -x "$1/$n" ] && [ ! -L "$1/$n" ] && grep -qF "$HM" "$1/$n" || return 1; done; }
tok(){ python3 -c 'import secrets,string; print("ghp_" + "".join(secrets.choice(string.ascii_letters+string.digits) for _ in range(36)))'; }

hi "$HR/install.sh" --check > "$T/h0" 2>&1
n=0; for x in $HOOKS; do [ -e "$HR/.git/hooks/$x" ] && n=$((n + 1)); done
[ $n -eq 0 ] && [ -z "$(git -C "$HR" config --get secstack.secops)" ] && grep -q 'would: add the pre-push hook' "$T/h0" \
  && ok "hooks: --check writes no hook and records nothing" || { bad "hooks --check ($n hooks)"; cat "$T/h0"; }
ln -s ../../scripts/check-secrets.sh "$HR/.git/hooks/pre-commit"     # the old install's link: ours, replaced
ln -s /usr/bin/true "$HR/.git/hooks/pre-push"                         # someone else's link: kept
hi "$HR/install.sh" > "$T/h1" 2>&1; rc=$?
[ $rc -eq 0 ] && [ "$(readlink "$HR/.git/hooks/pre-push")" = /usr/bin/true ] && grep -q 'keep    existing pre-push hook' "$T/h1" \
  && ok "hooks: a link to another script is kept" || { bad "hooks: foreign link rc=$rc"; cat "$T/h1"; }
rm "$HR/.git/hooks/pre-push"; hi "$HR/install.sh" > "$T/h2" 2>&1
wrappers "$HR/.git/hooks" && ok "hooks: all six installed as wrappers, the old link replaced" || { bad "hooks: wrappers"; ls -la "$HR/.git/hooks"; cat "$T/h2"; }
[ "$(git -C "$HR" config --get secstack.secops)" = "$HS" ] && ok "hooks: runtime root recorded in git config" || bad "hooks: secstack.secops"
hi "$HR/install.sh" > "$T/h3" 2>&1; grep -q 'ok      pre-push hook' "$T/h3" && ! grep -q '^  hook ' "$T/h3" \
  && ok "hooks: re-run changes nothing" || { bad "hooks: re-run"; cat "$T/h3"; }

# The installed hooks work without SECOPS in the environment (a GUI git app), and refuse when they can't.
printf 'clean\n' > "$HR/h-clean.txt"; hg -C "$HR" add h-clean.txt
(unset SECOPS; hg -C "$HR" commit -qm clean) > "$T/h4" 2>&1 && ok "hooks: a clean commit goes through" || { bad "hooks: clean commit"; cat "$T/h4"; }
printf 'token %s\n' "$(tok)" > "$HR/h-tok.txt"; hg -C "$HR" add h-tok.txt
(unset SECOPS; hg -C "$HR" commit -qm tok) > "$T/h5" 2>&1 && bad "hooks: a token was committed" \
  || { grep -q 'credential pattern' "$T/h5" && ok "hooks: pre-commit blocks a token" || { bad "hooks: no reason shown"; cat "$T/h5"; }; }
hg -C "$HR" rm -q --cached h-tok.txt; rm "$HR/h-tok.txt"
printf 'x\n' > "$HR/h-x.txt"; hg -C "$HR" add h-x.txt
git -C "$HR" config secstack.secops "$T/hooks/gone"
(unset SECOPS; hg -C "$HR" commit -qm x) > "$T/h6" 2>&1 && bad "hooks: committed with an unreadable recorded root" \
  || { grep -q 'runtime root' "$T/h6" && ok "hooks: an unreadable recorded root refuses" || { bad "hooks: no reason"; cat "$T/h6"; }; }
git -C "$HR" config secstack.secops "$HS"
mv "$HR/scripts/check-secrets.sh" "$T/hooks/cs.sh"
(unset SECOPS; hg -C "$HR" commit -qm x) > "$T/h7" 2>&1 && bad "hooks: committed with the script missing" \
  || { grep -q 'not found' "$T/h7" && ok "hooks: a missing script refuses (not skipped)" || { bad "hooks: no reason"; cat "$T/h7"; }; }
mv "$T/hooks/cs.sh" "$HR/scripts/check-secrets.sh"; hg -C "$HR" rm -q --cached h-x.txt; rm "$HR/h-x.txt"

# From a linked worktree: the hooks go to the shared hooks dir and run the main checkout's script.
hg -C "$HR" add -A >/dev/null 2>&1; hg -C "$HR" commit -qm all --no-verify
hg -C "$HR" worktree add -q "$T/hooks/wt" 2>/dev/null
for x in $HOOKS; do rm -f "$HR/.git/hooks/$x"; done
hi "$T/hooks/wt/install.sh" > "$T/h8" 2>&1
wrappers "$HR/.git/hooks" && grep -qF "s='$T/hooks/it'\\''s repo/scripts/check-secrets.sh'" "$HR/.git/hooks/pre-commit" \
  && [ ! -e "$HR/.git/worktrees/wt/hooks" ] && grep -q 'linked worktree' "$T/h8" \
  && ok "hooks: from a worktree, shared hooks run the main checkout's script" || { bad "hooks: worktree"; cat "$T/h8"; ls -la "$HR/.git/hooks"; }
printf 'token %s\n' "$(tok)" > "$T/hooks/wt/w.txt"; hg -C "$T/hooks/wt" add w.txt
(unset SECOPS; hg -C "$T/hooks/wt" commit -qm w) > "$T/h9" 2>&1 && bad "hooks: a token was committed in a worktree" \
  || { grep -q 'credential pattern' "$T/h9" && ok "hooks: they run in a worktree" || { bad "hooks: worktree commit"; cat "$T/h9"; }; }

# A core.hooksPath from the global config would skip this repo's hooks: install sets a repo-local one
# pointing at them (and --check only says so).
GH2="$T/hooks/global-hooks"; mkdir -p "$GH2"; printf '[core]\n\thooksPath = %s\n' "$GH2" > "$T/hooks/gcfg"
for x in $HOOKS; do rm -f "$HR/.git/hooks/$x"; done
GIT_CONFIG_GLOBAL="$T/hooks/gcfg" hi "$HR/install.sh" --check > "$T/h10" 2>&1
[ -z "$(git -C "$HR" config --local --get core.hooksPath)" ] && grep -q 'would: set a repo-local core.hooksPath' "$T/h10" \
  && [ ! -e "$HR/.git/hooks/pre-commit" ] && ok "hooks: --check reports a global core.hooksPath and sets nothing" || { bad "hooks: global hooksPath --check"; cat "$T/h10"; }
GIT_CONFIG_GLOBAL="$T/hooks/gcfg" hi "$HR/install.sh" > "$T/h11" 2>&1
[ "$(git -C "$HR" config --local --get core.hooksPath)" = .git/hooks ] && wrappers "$HR/.git/hooks" && [ -z "$(ls -A "$GH2")" ] \
  && grep -q 'note    core.hooksPath is set globally' "$T/h11" && ok "hooks: a global core.hooksPath gets a repo-local (relative) override, hooks installed" \
  || { bad "hooks: global hooksPath"; cat "$T/h11"; }
printf 'token %s\n' "$(tok)" > "$HR/h-g.txt"; hg -C "$HR" add h-g.txt
(unset SECOPS; GIT_CONFIG_GLOBAL="$T/hooks/gcfg" hg -C "$HR" commit -qm g) > "$T/h12" 2>&1 && bad "hooks: a global core.hooksPath let a token through" \
  || { grep -q 'credential pattern' "$T/h12" && ok "hooks: they run despite a global core.hooksPath" || { bad "hooks: global hooksPath commit"; cat "$T/h12"; }; }
GIT_CONFIG_GLOBAL="$T/hooks/gcfg" hi "$HR/install.sh" > "$T/h13" 2>&1
grep -q 'ok      pre-push hook' "$T/h13" && ! grep -q 'core.hooksPath is set' "$T/h13" && ok "hooks: the override is kept on re-run" || { bad "hooks: hooksPath re-run"; cat "$T/h13"; }
hg -C "$HR" rm -q --cached h-g.txt; rm "$HR/h-g.txt"
# An absolute override left by an older install, from before the clone moved: git would run no hooks at
# all. Re-running install resets it to the relative one.
git -C "$HR" config --local core.hooksPath "$T/moved-away/secstack/.git/hooks"
GIT_CONFIG_GLOBAL="$T/hooks/gcfg" hi "$HR/install.sh" > "$T/h14" 2>&1
[ "$(git -C "$HR" config --local --get core.hooksPath)" = .git/hooks ] && grep -q 'from before the clone moved' "$T/h14" \
  && ! grep -q 'note    core.hooksPath is set (' "$T/h14" && ok "hooks: a moved clone's stale override is reset" || { bad "hooks: stale override"; cat "$T/h14"; }
git -C "$HR" config --local --unset core.hooksPath
# ======================================================================================================

# ---- MCP stash migration: an old hexstrike-ai entry (no token wrapper) is replaced, the rest kept ----
MH="$T/stash home"; MS="$MH/GitHub/.sec-ops"; mkdir -p "$MS/configs"; chmod 700 "$MS"
printf '%s\n' '{"hexstrike-ai": {"command": "/x/venv/bin/python3", "args": ["/x/hexstrike-ai/hexstrike_mcp.py", "--server", "http://127.0.0.1:8888"]}, "kali-tools": {"command": "keep-me"}}' \
  > "$MS/configs/mcp-servers.stash.json"; chmod 600 "$MS/configs/mcp-servers.stash.json"
before=$(cat "$MS/configs/mcp-servers.stash.json")
(export HOME="$MH" SECSTACK_GH="$MH/GitHub"; unset SECOPS; "$R/install.sh" --check) > "$T/m1" 2>&1
[ "$(cat "$MS/configs/mcp-servers.stash.json")" = "$before" ] && grep -q 'update the hexstrike-ai entry' "$T/m1" \
  && ok "stash: --check reports the migration and changes nothing" || { bad "stash: --check"; cat "$T/m1"; }
(export HOME="$MH" SECSTACK_GH="$MH/GitHub"; unset SECOPS; "$R/install.sh") > "$T/m2" 2>&1
python3 - "$MS/configs/mcp-servers.stash.json" "$MS" <<'PY' && ok "stash: hexstrike-ai runs through the token wrapper, other entries kept" || { bad "stash: migration"; cat "$T/m2"; }
import json, sys
d = json.load(open(sys.argv[1]))
args = d["hexstrike-ai"]["args"]
sys.exit(0 if args[0] == sys.argv[2] + "/mcp/hexstrike-client/hexstrike_client.py" and d["kali-tools"] == {"command": "keep-me"} else 1)
PY
[ "$(mode "$MS/configs/mcp-servers.stash.json")" = 600 ] && ok "stash: still 600" || bad "stash: mode $(mode "$MS/configs/mcp-servers.stash.json")"
(export HOME="$MH" SECSTACK_GH="$MH/GitHub"; unset SECOPS; "$R/install.sh") > "$T/m3" 2>&1
! grep -q 'hexstrike-ai' "$T/m3" && ok "stash: migrated once" || { bad "stash: migrated again"; cat "$T/m3"; }
# An entry that runs bin/secstack-mcp goes through the same token wrapper: left as it is.
printf '%s\n' '{"hexstrike-ai": {"command": "/x/.sec-ops/bin/secstack-mcp", "args": ["hexstrike"]}}' \
  > "$MS/configs/mcp-servers.stash.json"
before=$(cat "$MS/configs/mcp-servers.stash.json")
(export HOME="$MH" SECSTACK_GH="$MH/GitHub"; unset SECOPS; "$R/install.sh") > "$T/m4" 2>&1
[ "$(cat "$MS/configs/mcp-servers.stash.json")" = "$before" ] && ! grep -q 'hexstrike-ai' "$T/m4" \
  && ok "stash: an entry that runs secstack-mcp is kept" || { bad "stash: secstack-mcp entry replaced"; cat "$T/m4"; }

echo "install: $pass passed, $fail failed"
[ $fail -eq 0 ]
