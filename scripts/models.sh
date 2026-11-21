#!/usr/bin/env bash
# models.sh: install the models chosen in the hardware plan ($SECOPS/configs/models.selected.json).
# Thin wrapper; the work (pull, pinned+verified GGUF import, alias creation) is in scripts/plan.py.
#   scripts/models.sh [--keep-gguf] [--force] [--allow-unpinned]
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
exec python3 "$REPO/scripts/plan.py" install-models "$@"
