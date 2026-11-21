#!/usr/bin/env bash
# build-images.sh: build the two local images and make sure the runtime images are present.
#   hexstrike-kali          HexStrike API + ~45 tools in Kali arm64 (used by `secstack mcp on|prep`)
#   kali-tools-mcp-server   offline Kali tool-docs MCP (stdio, --network=none)
# Runtime images come from upstream/images.lock and are pulled only when missing, so an existing
# install is never silently upgraded (a newer pentagi/pgvector image can migrate or break its DB).
#   scripts/build-images.sh            build + pull missing images
#   scripts/build-images.sh --pull     also re-pull every image in the lock (deliberate upgrade)
# Needs Docker running. Takes 20-40 min the first time (Kali packages, angr, pwntools).
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
GH="${SECSTACK_GH:-$HOME/GitHub}"
LOCK="$REPO/upstream/images.lock"
export PATH="/Applications/Docker.app/Contents/Resources/bin:$PATH"
PULL=0
case "${1:-}" in --pull) PULL=1 ;; "") ;; *) echo "usage: $0 [--pull]"; exit 1 ;; esac
docker info >/dev/null 2>&1 || { echo "start Docker Desktop first (or: open -a Docker)"; exit 1; }

echo "== hexstrike-kali"
docker build --platform linux/arm64 \
  -f "$REPO/configs/hexstrike-kali/Dockerfile" \
  --build-context entry="$REPO/configs/hexstrike-kali" \
  -t hexstrike-kali "$GH/hexstrike-ai"
docker run --rm --entrypoint cat hexstrike-kali /opt/tools.txt | sort | awk '{print "  "$0}'

echo "== kali-tools-mcp-server"
docker build --platform linux/arm64 -t kali-tools-mcp-server "$GH/kali-mcp"

echo "== runtime images (upstream/images.lock)"
failed=0
while IFS='=' read -r key ref; do
  ref="${ref%$'\r'}"
  case "$ref" in ""|-*|*[!A-Za-z0-9._/:@-]*) echo "  bad reference for $key"; failed=1; continue ;; esac
  plat=""; [ "$key" = DVWA_IMAGE ] && plat="--platform linux/amd64"   # DVWA has no arm64 build
  if [ $PULL -eq 0 ] && docker image inspect "$ref" >/dev/null 2>&1; then
    echo "  present  $ref"
  else
    # shellcheck disable=SC2086
    if docker pull -q $plat "$ref" >/dev/null; then echo "  pulled   $ref"; else echo "  FAILED   $ref"; failed=1; fi
  fi
  case "$ref" in *@sha256:*) ;; *) echo "           (not pinned: scripts/pin-images.sh pins it to this image)" ;; esac
done < <(grep -E '^[A-Z_]+_IMAGE=' "$LOCK")
[ $failed -eq 0 ] || { echo "some images could not be pulled (above); check the network and re-run"; exit 1; }
echo "done. Next: scripts/models.sh"
