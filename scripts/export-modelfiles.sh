#!/usr/bin/env bash
# export-modelfiles.sh: capture the exact Modelfiles (template, stop tokens, parameters) and metadata
# of installed aliases into models/exported/, so a rebuild on another Mac reproduces them.
# Run it on a machine where the models already work, with Ollama running.
#
#   scripts/export-modelfiles.sh [ALIAS ...]     default: the models in the plan (stack.conf MODELS)
#
# Only the commands that describe how to talk to the model are kept (scripts/plan.py modelfile-filter),
# read the way Ollama's parser reads them and written out again, never copied: FROM lines (local blob
# paths that include your username) and CAPABILITY lines (the rebuild inherits them from the catalog
# source) are dropped, plan.py install-models supplies FROM from the catalog, and num_ctx/num_predict are
# dropped because the plan sets them per machine.
# Check SYSTEM and MESSAGE lines for anything personal before committing.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
GH="${SECSTACK_GH:-$HOME/GitHub}"; SECOPS="${SECOPS:-$GH/.sec-ops}"
O="$(command -v ollama 2>/dev/null || ls /Applications/Ollama.app/Contents/Resources/ollama 2>/dev/null || echo /usr/local/bin/ollama)"
OUT="$REPO/models/exported"; mkdir -p "$OUT"
curl -fsS -m 2 http://127.0.0.1:11434/api/version >/dev/null || { echo "start Ollama first: secstack llm start"; exit 1; }
if [ $# -eq 0 ]; then
  csv=$(grep -E '^MODELS=' "$SECOPS/configs/stack.conf" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d '\r' || true)
  case "$csv" in ""|-*|*[!A-Za-z0-9._:/,-]*) echo "no plan: pass aliases, e.g. $0 qwen3.6-35b-a3b-abliterated"; exit 1 ;; esac
  set -- $(printf '%s' "$csv" | tr ',' ' ')
fi
for n in "$@"; do
  case "$n" in ""|[!a-z0-9]*|*[!a-z0-9._-]*) echo "  skip bad alias: $n"; continue ;; esac
  "$O" show "$n" --modelfile > "$OUT/$n.raw" 2>/dev/null || { echo "  missing $n"; rm -f "$OUT/$n.raw"; continue; }
  "$O" show "$n" > "$OUT/$n.info.txt"
  # Keep only the allowed commands (TEMPLATE, SYSTEM, PARAMETER, MESSAGE, LICENSE, RENDERER, PARSER);
  # anything else (ADAPTER, DRAFT, REQUIRES, a PARAMETER named like one of them, invisible characters,
  # a bare CR, a value with """ in it) stops the export of that model instead of being copied.
  if python3 "$REPO/scripts/plan.py" modelfile-filter "$OUT/$n.raw" "$OUT/$n.Modelfile"; then
    echo "  exported $n"
  else
    echo "  not exported: $n (see above)"; rm -f "$OUT/$n.Modelfile"
  fi
done
"$O" list > "$OUT/ollama-list.txt"
echo "Review models/exported/*.Modelfile and *.info.txt, then commit them (.raw and ollama-list.txt are gitignored)."
