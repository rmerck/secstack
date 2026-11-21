#!/usr/bin/env bash
# pin-images.sh: pin every unpinned entry of upstream/images.lock to the image this Mac actually has.
# Run it on a Mac where the stack works (Docker running, images pulled), review the diff, commit.
#   scripts/pin-images.sh            pin tag entries that have a local image with a registry digest
#   scripts/pin-images.sh --check    list what would change, change nothing
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
LOCK="$REPO/upstream/images.lock"
export PATH="$PATH:/Applications/Docker.app/Contents/Resources/bin"
CHECK=0
case "${1:-}" in
  --check) CHECK=1 ;;
  "") ;;
  *) echo "usage: $0 [--check]"; exit 1 ;;
esac
docker info >/dev/null 2>&1 || { echo "Docker is not running"; exit 1; }

# repo_of REF: the repository part of a tag reference (registry ports and paths kept; only the
# last segment's :tag is dropped), with Docker Hub's docker.io/ and library/ prefixes removed.
repo_of(){
  local ref="$1" last head
  last="${ref##*/}"; head="${ref%"$last"}"
  case "$last" in *:*) last="${last%%:*}" ;; esac
  ref="$head$last"
  ref="${ref#docker.io/}"; ref="${ref#library/}"
  printf '%s\n' "$ref"
}

tmp="$(mktemp "$LOCK.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
changed=0
while IFS= read -r line || [ -n "$line" ]; do
  case "$line" in
    [A-Z]*=*) key="${line%%=*}"; ref="${line#*=}" ;;
    *) printf '%s\n' "$line" >> "$tmp"; continue ;;
  esac
  case "$ref" in
    *@sha256:*) printf '%s\n' "$line" >> "$tmp"; continue ;;
    ""|-*|*[!A-Za-z0-9._/:@-]*) echo "  skip $key: bad reference"; printf '%s\n' "$line" >> "$tmp"; continue ;;
  esac
  repo="$(repo_of "$ref")"
  digests=$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$ref" 2>/dev/null \
    | while IFS= read -r d; do
        [ -n "$d" ] || continue
        r="${d%@*}"; r="${r#docker.io/}"; r="${r#library/}"
        [ "$r" = "$repo" ] && printf '%s\n' "${d##*@}"
      done | grep -E '^sha256:[0-9a-f]{64}$' | sort -u || true)
  n=$(printf '%s' "$digests" | grep -c . || true)
  if [ "$n" -eq 1 ]; then
    echo "  pin  $key=$repo@$digests"
    printf '%s=%s@%s\n' "$key" "$repo" "$digests" >> "$tmp"; changed=1
  elif [ "$n" -gt 1 ]; then
    echo "  keep $key=$ref (the local image has $n digests for $repo; pull the one you want by digest)"
    printf '%s\n' "$line" >> "$tmp"
  else
    echo "  keep $key=$ref (no local image with a registry digest)"
    printf '%s\n' "$line" >> "$tmp"
  fi
done < "$LOCK"
if [ $CHECK -eq 1 ]; then echo "(check only, nothing written)"; exit 0; fi
if [ $changed -eq 1 ]; then
  chmod 644 "$tmp"; mv "$tmp" "$LOCK"; trap - EXIT
  echo "Updated $LOCK. Review with git diff, then commit."
else echo "Nothing to pin."; fi
