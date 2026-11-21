#!/usr/bin/env bash
# bootstrap-upstream.sh: clone the upstream projects at the pinned commits, apply local patches,
# drop in provider files, render .env files, build the host MCP venv.
#
#   scripts/bootstrap-upstream.sh            pinned commits from upstream/repos.lock (reproducible)
#   scripts/bootstrap-upstream.sh --latest   report what each default branch has past its pin: fetches
#                                            the lock URL's HEAD and prints, changes nothing. To adopt
#                                            a commit, review it, put its full hash in
#                                            upstream/repos.lock, re-run, re-test.
#
# Needs the hardware plan first ($SECOPS/configs/stack.conf, written by ./setup.sh or
# scripts/plan.py select --write): model names in the .env files come from it, image references
# from upstream/images.lock.
# Safe to re-run: clones are fetched, never re-cloned. A clone is vetted before it is used: origin is
# exactly the lock's URL; its .git has no replace refs, grafts, alternates, commondir, config.worktree
# or info/attributes, and no local config key outside a short allowlist; git fsck passes (no planted
# or damaged objects); no index entry hides edits (assume-unchanged, skip-worktree); tracked files
# match HEAD's tree through a fresh index (plus our patches). Every git command on a clone runs with
# hooks, fsmonitor and the commit-graph off and replace refs ignored, so a tampered .git can neither
# run code nor swap the pinned tree. pentagi and ARTEX must not hold a compose file their commits
# don't track, ARTEX no untracked file outside .env, data/, keys/ and backups/, and the pinned commit
# must not track .env or secstack.* (nor pentagi's docker-compose.override.yml), in any letter case.
# pentagi's override must be exactly the one secstack ships. A patch that doesn't apply stops the run.
# Existing .env secrets are kept (weak ones stop the run, see scripts/render-env.py).
set -euo pipefail
# Each clone's own .git is what gets vetted and used, whatever the caller's environment names.
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES \
  GIT_COMMON_DIR GIT_NAMESPACE GIT_REPLACE_REF_BASE

REPO="$(cd "$(dirname "$0")/.." && pwd -P)"
GH="${SECSTACK_GH:-$HOME/GitHub}"
SECOPS="${SECOPS:-$GH/.sec-ops}"
STACK_CONF="$SECOPS/configs/stack.conf"
GEN="$SECOPS/configs/generated"
LOCK="$REPO/upstream/repos.lock"
LATEST=0
case "${1:-}" in
  --latest) LATEST=1 ;;
  "") ;;
  *) echo "usage: $0 [--latest]"; exit 1 ;;
esac
if [ $LATEST -eq 0 ]; then
  [ -s "$STACK_CONF" ] || { echo "No hardware plan at $STACK_CONF. Run ./setup.sh (or scripts/plan.py select --write) first."; exit 1; }
  [ -s "$GEN/ollama.provider.yml" ] || { echo "Missing $GEN/ollama.provider.yml. Re-run: scripts/plan.py select --write"; exit 1; }
fi
mkdir -p "$GH"

entries(){ grep -vE '^[[:space:]]*(#|$)' "$LOCK" || true; }
patches_for(){ local p; for p in "$REPO"/upstream/patches/"$1"-[0-9][0-9][0-9][0-9]-*.patch; do [ -e "$p" ] && printf '%s\n' "$p"; done; return 0; }
q(){ printf '%q' "$1"; }
# Upstream text shown on the terminal (commit subjects): tab, newline and printable ASCII only, so no
# escape sequences (C0, C1 or UTF-8 encoded) and no bidi overrides.
printable(){ LC_ALL=C tr -cd '\11\12\40-\176'; }
# hgit ARGS...: git with hooks, fsmonitor and the commit-graph cache off and replace refs ignored.
# cg DIR ARGS...: the same in a clone.
hgit(){ GIT_NO_REPLACE_OBJECTS=1 git -c core.hooksPath=/dev/null -c core.fsmonitor=false -c core.commitGraph=false \
  -c diff.ignoreSubmodules=all -c submodule.recurse=false -c fetch.recurseSubmodules=false "$@"; }
cg(){ local d="$1"; shift; hgit -C "$d" "$@"; }
# cgi INDEX DIR ARGS...: cg with another index file (a fresh one of HEAD's tree).
cgi(){ local i="$1" d="$2"; shift 2; GIT_INDEX_FILE="$i" GIT_NO_REPLACE_OBJECTS=1 git -c core.hooksPath=/dev/null \
  -c core.fsmonitor=false -c core.commitGraph=false -c diff.ignoreSubmodules=all -c submodule.recurse=false -C "$d" "$@"; }

# Local config a clone may carry: what git clone writes, branch tracking, identity, maintenance, the
# ref store git picks (files or reftable). Anything else (include*, url.*, core.worktree,
# core.hooksPath, core.fsmonitor, core.attributesFile, filter.*, diff.*, http.*, other extensions,
# other remotes or refspecs ...) can change what git fetches, runs or reports.
config_ok(){ # config_ok KEY VALUE
  case "$1" in
    core.repositoryformatversion|core.filemode|core.bare|core.logallrefupdates|core.ignorecase|\
    core.precomposeunicode|core.symlinks|remote.origin.url|remote.origin.followremotehead|branch.*|\
    user.name|user.email|maintenance.auto|maintenance.strategy|lfs.repositoryformatversion) return 0 ;;
    remote.origin.fetch) [ "$2" = '+refs/heads/*:refs/remotes/origin/*' ] ;;
    extensions.refstorage) case "$2" in files|reftable) return 0 ;; *) return 1 ;; esac ;;
    *) return 1 ;;
  esac
}
# reclone_only KEY: keys a clone can't simply drop (its repository format or object store depend on them).
reclone_only(){ case "$1" in extensions.*|remote.origin.promisor|remote.origin.partialclonefilter) return 0 ;; esac; return 1; }
# reclone_cmd NAME DIR URL: how to replace a clone that can't be repaired in place, keeping its .env.
reclone_cmd(){
  echo "      mv $(q "$2") $(q "$2.old") && git clone --no-checkout $(q "$3") $(q "$2") &&"
  echo "        { [ ! -e $(q "$2.old/.env") ] || cp -p $(q "$2.old/.env") $(q "$2/"); }"
  echo "    then re-run, and remove $(q "$2.old") once everything works."
}

# vet_clone NAME DIR URL: refuse a clone that fetches from anywhere but the lock's URL, or whose .git
# could change what git checks out, runs or reports. Prints every problem with its fix.
vet_clone(){
  local name="$1" dir="$2" url="$3" gd="$2/.git" bad=0 urls f ref entry key val
  urls="$(cg "$dir" config --get-all remote.origin.url 2>/dev/null || true)"
  if [ "$urls" != "$url" ]; then
    echo "  $name: origin is '$urls', repos.lock says '$url'. Fix the remote first."; bad=1
  fi
  for f in commondir config.worktree info/grafts info/attributes objects/info/alternates; do
    if [ -e "$gd/$f" ] || [ -L "$gd/$f" ]; then
      echo "  $name: $gd/$f changes which objects, config or attributes git uses; remove it: rm $(q "$gd/$f")"; bad=1
    fi
  done
  for ref in $(cg "$dir" for-each-ref --format='%(refname)' refs/replace/); do
    echo "  $name: $ref makes git show another commit in place of $(basename "$ref"); remove it: git -C $(q "$dir") update-ref -d $ref"; bad=1
  done
  if ! cg "$dir" config --local --list >/dev/null 2>&1; then
    echo "  $name: git can't read $gd/config; fix or re-clone it"; return 1
  fi
  while IFS= read -r -d '' entry; do
    key="${entry%%$'\n'*}"
    if [ "$key" = "$entry" ]; then val=""; else val="${entry#*$'\n'}"; fi
    config_ok "$key" "$val" && continue
    bad=1
    if [ "$key" = remote.origin.fetch ]; then
      echo "  $name: $gd/config fetches '$val' as origin; restore the default:"
      echo "      git -C $(q "$dir") config --replace-all remote.origin.fetch '+refs/heads/*:refs/remotes/origin/*'"
    elif reclone_only "$key"; then
      echo "  $name: $gd/config sets $key='$val'; removing it would break the clone, so clone it again:"
      reclone_cmd "$name" "$dir" "$url"
    else
      echo "  $name: $gd/config sets $key, which can change what git fetches, runs or reports; remove it:"
      echo "      git -C $(q "$dir") config --unset-all $(q "$key")"
    fi
  done < <(cg "$dir" config --local --null --list 2>/dev/null)
  [ "$bad" -eq 0 ]
}

# vet_index NAME DIR: no index entry may hide local edits from git diff.
vet_index(){
  local flagged
  flagged="$(cg "$2" ls-files -v | grep -v '^H ' || true)"
  [ -z "$flagged" ] && return 0
  echo "  $1: these index entries hide local edits from git (assume-unchanged, skip-worktree):"
  printf '%s\n' "$flagged" | head -10 | sed 's/^/      /'
  echo "    clear the flags (git -C $(q "$2") update-index --no-assume-unchanged --no-skip-worktree -- PATH,"
  echo "    or git -C $(q "$2") sparse-checkout disable), then check what changed with git -C $(q "$2") status"
  return 1
}

# stray_compose NAME DIR COMMIT: docker compose also reads these names (some in preference to the
# tracked docker-compose.yml); one in neither HEAD's nor the pinned commit's tree (a commit's tree, not
# the index, which a tampered .git can fake), ignored or not, would change what runs.
stray_compose(){
  local f bad=0 tracked
  tracked="$(cg "$2" ls-tree --name-only HEAD 2>/dev/null || true)
$(cg "$2" ls-tree --name-only "$3")"
  for f in compose.yaml compose.yml compose.override.yaml compose.override.yml docker-compose.yaml \
           docker-compose.override.yaml; do
    # grep reads a here-doc, not a pipe: under pipefail, grep -q quitting early could fail printf's write.
    if { [ -e "$2/$f" ] || [ -L "$2/$f" ]; } && ! grep -Fx -- "$f" >/dev/null <<EOF
$tracked
EOF
    then
      echo "  $1: $2/$f isn't part of the pinned commit and docker compose would read it; move it aside: mv $(q "$2/$f") $(q "$2/$f.off")"
      bad=1
    fi
  done
  [ "$bad" -eq 0 ]
}

# artex_untracked DIR INDEX: ARTEX builds its image from the clone (COPY . .) and mounts ./skills, so a
# file HEAD's tree doesn't have would end up in what runs. Only .env and its data folders may hold
# such files (and Finder's .DS_Store). INDEX is a fresh index of HEAD's tree.
artex_untracked(){
  local extra
  extra="$(cgi "$2" "$1" ls-files -z --others | tr '\0' '\n' \
    | grep -vE '^(\.env|data/.*|keys/.*|backups/.*)$' | grep -vE '(^|/)\.DS_Store$' || true)"
  [ -z "$extra" ] && return 0
  echo "  ARTEX: files that aren't part of the pinned commit (its image build copies them, ./skills is mounted):"
  printf '%s\n' "$extra" | head -10 | printable | sed 's/^/      /'
  echo "    move them out of $(q "$1"); only .env, data/, keys/ and backups/ may hold files of yours. Then re-run."
  return 1
}

# fsck_ok NAME DIR URL: every object must hash to its id and every reachable one must be there, so a
# planted pack or loose object can't stand in for a pinned file (about 1.5 s for pentagi).
fsck_ok(){
  local out
  if out="$(cg "$2" fsck --no-dangling --no-progress 2>&1)"; then return 0; fi
  echo "  $1: git fsck found damaged or forged objects in $(q "$2/.git"):"
  printf '%s\n' "$out" | head -5 | printable | sed 's/^/      /'
  echo "    clone it again:"
  reclone_cmd "$1" "$2" "$3"
  return 1
}

echo "== check repos.lock"
entries | while read -r name url commit _; do
  case "$name" in *[!A-Za-z0-9._-]*|""|-*|.*) echo "  bad repo name in repos.lock: $name"; exit 1 ;; esac
  case "$url" in https://github.com/*.git) ;; *) echo "  $name: only https://github.com/...git URLs are allowed"; exit 1 ;; esac
  case "$commit" in ""|*[!0-9a-f]*) echo "  $name: commit must be hex"; exit 1 ;; esac
  [ "${#commit}" -eq 40 ] || { echo "  $name: commit must be the full 40-character hash"; exit 1; }
done

if [ $LATEST -eq 1 ]; then
  echo "== what each default branch has past its pin (nothing is changed)"
  entries | while read -r name url commit _; do
    dir="$GH/$name"
    [ -d "$dir/.git" ] || { echo "  $name: not cloned yet"; continue; }
    vet_clone "$name" "$dir" "$url" | printable || exit 1   # its messages quote .git/config: printable only
    # The lock URL's HEAD, into FETCH_HEAD only: the clone's remote config and refs play no part.
    cg "$dir" fetch --quiet --no-tags "$url" HEAD
    fsck_ok "$name" "$dir" "$url" || exit 1
    target="$(cg "$dir" rev-parse --verify -q 'FETCH_HEAD^{commit}' || true)"
    [ -n "$target" ] || { echo "  $name: $url has no HEAD commit"; continue; }
    if cg "$dir" merge-base --is-ancestor "$commit" "$target" 2>/dev/null; then
      echo "  $name: $(cg "$dir" rev-list --count "$commit..$target") commits past the pin, default branch at $target"
      cg "$dir" log --no-decorate --format='%h %s' -10 "$commit..$target" | printable | sed 's/^/      /'
      cg "$dir" diff --stat "$commit" "$target" | tail -1 | printable | sed 's/^/     /'
    else
      echo "  $name: the default branch ($target) no longer contains the pin; review before moving"
    fi
  done
  echo "To adopt a commit: review it, put its full hash in upstream/repos.lock, re-run without --latest, re-test."
  exit 0
fi

echo "== fetch (all repos first, so a network failure changes nothing)"
entries | while read -r name url commit _; do
  dir="$GH/$name"
  if [ -d "$dir/.git" ]; then
    vet_clone "$name" "$dir" "$url" | printable || exit 1   # its messages quote .git/config: printable only
    cg "$dir" fetch --quiet origin
  elif [ -e "$dir" ]; then
    echo "  $dir exists but isn't a git clone; move it aside and re-run"; exit 1
  else
    hgit clone --quiet --no-checkout -- "$url" "$dir"   # no files until the pin is checked out below
  fi
  cg "$dir" cat-file -e "$commit^{commit}" 2>/dev/null || { echo "  $name: pinned commit $commit not found"; exit 1; }
  fsck_ok "$name" "$dir" "$url" || exit 1
  echo "  $name ok"
done

echo "== checkout + patches"
# Fresh indexes of HEAD's tree: tracked files are compared through these, not the clone's own index.
IDX_TMP="$(mktemp -d "${TMPDIR:-/tmp}/secstack-index.XXXXXX")"
trap 'rm -rf "$IDX_TMP"' EXIT
entries | while read -r name url commit _; do
  dir="$GH/$name"
  case "$name" in
    pentagi|ARTEX)
      # secstack writes these; a pinned commit that tracks one (in any letter case: APFS ignores case)
      # would have it checked out, and render-env would keep its public secrets.
      if [ "$name" = pentagi ]; then pat='^(\.env|secstack\..*|docker-compose\.override\.yml)$'
      else pat='^(\.env|secstack\..*)$'; fi
      tracked="$(cg "$dir" ls-tree --name-only "$commit" | grep -iE "$pat" | tr '\n' ' ' || true)"
      if [ -n "$tracked" ]; then
        echo "  $name: the pinned commit tracks ${tracked% }; secstack writes those itself (secrets in git are public). Pin another commit."
        exit 1
      fi
      stray_compose "$name" "$dir" "$commit" || exit 1 ;;
  esac
  # Take our patches off (newest first) so tracked files can be compared with the commit.
  patches_for "$name" | sort -r | while IFS= read -r p; do
    if cg "$dir" apply --reverse --check "$p" 2>/dev/null; then cg "$dir" apply --reverse "$p"; fi
  done
  index="$dir/.git/index"   # a fresh --no-checkout clone has none yet
  if [ -f "$index" ]; then
    vet_index "$name" "$dir" || exit 1
    # The clone's own index can carry forged stat data that hides an edit; a fresh one of HEAD's tree
    # makes git hash every file.
    ti="$IDX_TMP/$name"
    cgi "$ti" "$dir" read-tree HEAD
    if ! cgi "$ti" "$dir" diff --quiet; then
      echo "  $name: tracked files differ from $(cg "$dir" rev-parse --short HEAD) (local edits?); commit, stash or discard them first:"
      cgi "$ti" "$dir" diff --name-only | head -10 | printable | sed 's/^/      /'
      if [ "$name" = pentagi ] && cgi "$ti" "$dir" diff --name-only \
           | grep -E '^example\.(custom|ollama|bedrock)\.provider\.yml$' >/dev/null; then
        echo "    An earlier secstack wrote its provider files over pentagi's example.*.provider.yml; it now writes"
        echo "    secstack.*.provider.yml. Keep anything you added to them, then restore them:"
        echo "      git -C $(q "$dir") checkout -- example.custom.provider.yml example.ollama.provider.yml example.bedrock.provider.yml"
      fi
      exit 1
    fi
    if [ "$name" = ARTEX ]; then artex_untracked "$dir" "$ti" || exit 1; fi
  fi
  if [ "$(cg "$dir" rev-parse HEAD)" != "$commit" ] || [ ! -f "$index" ]; then
    cg "$dir" checkout --quiet --detach "$commit^{commit}"
    if [ "$name" = ARTEX ]; then echo "  ARTEX is at a new commit: rebuild its images with: secstack artex --build"; fi
  fi
  # What checkout left must be the pinned tree itself: checkout keeps an edit the clone's own index
  # already matches, and leaves files the old HEAD tracked but the index didn't (if ignored).
  tp="$IDX_TMP/$name.pin"
  cgi "$tp" "$dir" read-tree "$commit^{tree}"
  if ! cgi "$tp" "$dir" diff --quiet; then
    echo "  $name: after checkout, tracked files differ from the pinned commit:"
    cgi "$tp" "$dir" diff --name-only | head -10 | printable | sed 's/^/      /'
    exit 1
  fi
  if [ "$name" = ARTEX ]; then artex_untracked "$dir" "$tp" || exit 1; fi
  case "$name" in pentagi|ARTEX) stray_compose "$name" "$dir" "$commit" || exit 1 ;; esac
  patches_for "$name" | while IFS= read -r p; do
    cg "$dir" apply "$p" || { echo "  $name: $(basename "$p") doesn't apply at $commit; update the patch or the pin"; exit 1; }
    echo "  $name: applied $(basename "$p")"
  done
  printf '  %-13s %s\n' "$name" "$(cg "$dir" rev-parse --short HEAD)"
done
# These clones hold .env secrets and provider files.
chmod 700 "$GH/pentagi" "$GH/ARTEX"

echo "== pentagi provider files"
umask 077
put(){ # put <src> <dst>: copy to a regular file, never through a symlink or into a directory
  local tmp
  if [ -L "$2" ] || { [ -e "$2" ] && [ ! -f "$2" ]; }; then
    echo "  $2 is a symlink or not a regular file; refusing to write it (move it aside and re-run)"; exit 1
  fi
  tmp="$(mktemp "$(dirname "$2")/.secstack-tmp.XXXXXX")"
  cp "$1" "$tmp"; chmod 600 "$tmp"; mv -f "$tmp" "$2"
  echo "  $(basename "$2")"
}
put "$REPO/upstream/pentagi/example.custom.provider.yml" "$GH/pentagi/secstack.custom.provider.yml"
put "$REPO/upstream/pentagi/example.bedrock.provider.yml" "$GH/pentagi/secstack.bedrock.provider.yml"
put "$GEN/ollama.provider.yml" "$GH/pentagi/secstack.ollama.provider.yml"

echo "== pentagi compose override (no restart on its own)"
# Only the exact file secstack ships (upstream/pentagi/docker-compose.override.yml) is accepted:
# anything else in it would be applied to pentagi by docker compose.
OV="$GH/pentagi/docker-compose.override.yml"
OV_SRC="$REPO/upstream/pentagi/docker-compose.override.yml"
if [ -L "$OV" ] || { [ -e "$OV" ] && [ ! -f "$OV" ]; }; then
  echo "  $OV is a symlink or not a regular file; refusing to touch it (move it aside and re-run)"; exit 1
elif [ -e "$OV" ] && ! cmp -s "$OV_SRC" "$OV"; then
  echo "  $OV isn't the file secstack writes, and docker compose would apply whatever it adds; move it aside:"
  echo "      mv $(q "$OV") $(q "$OV.off")"
  exit 1
else
  put "$OV_SRC" "$OV"
fi

echo "== .env files (fresh secrets on first render; other override keys refreshed after)"
python3 "$REPO/scripts/render-env.py" --example "$GH/pentagi/.env.example" \
  --vars "$STACK_CONF" --vars "$REPO/upstream/images.lock" \
  --overrides "$REPO/upstream/pentagi/env.overrides" --out "$GH/pentagi/.env" --refresh
python3 "$REPO/scripts/render-env.py" --example "$GH/ARTEX/.env.example" --vars "$STACK_CONF" \
  --overrides "$REPO/upstream/artex/env.overrides" --out "$GH/ARTEX/.env" --refresh

echo "== host MCP venv ($SECOPS/venv: pentagi bridge, hexstrike MCP client, secops-flow)"
# uv is required: the Python 3.9 in Apple's Command Line Tools is too old for mcp. The venv lives in
# the runtime root (not inside an upstream clone) and is synced to the hash-locked list on every run.
command -v uv >/dev/null || { echo "  uv not found: brew install uv"; exit 1; }
VENV="$SECOPS/venv"
mkdir -p "$SECOPS"; chmod 700 "$SECOPS"
if ! "$VENV/bin/python3" -c 'import sys; sys.exit(sys.version_info[:2] != (3, 12))' 2>/dev/null; then
  rm -rf "$VENV"
  uv venv -q -p 3.12 "$VENV"
fi
uv pip sync -q --require-hashes --no-build -p "$VENV/bin/python3" "$REPO/configs/host-venv.lock.txt"
echo "  ready   $VENV (hash-locked)"

echo "done. Next: ./install.sh"
