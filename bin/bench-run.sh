#!/usr/bin/env bash
# Sequential model benchmark (Ollama). One model resident at a time; results in logs/bench-*.json.
# usage: secstack bench [MODEL ...]   (default: the models in the plan, configs/stack.conf)
set -u
GH="${SECSTACK_GH:-$HOME/GitHub}"; SECOPS="${SECOPS:-$GH/.sec-ops}"
PY="$SECOPS/venv/bin/python3"; F="$SECOPS/bin/secops-flow.py"
O="$(command -v ollama 2>/dev/null || ls /Applications/Ollama.app/Contents/Resources/ollama 2>/dev/null || echo /usr/local/bin/ollama)"
if [ $# -eq 0 ]; then
  csv=$(grep -E '^MODELS=' "$SECOPS/configs/stack.conf" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d '\r' || true)
  case "$csv" in ""|-*|*[!A-Za-z0-9._:/,-]*) csv="qwen3.6-35b-a3b-abliterated,qwen3.8-27b-abliterated,gemma4-26b-abliterated" ;; esac
  set -- $(printf '%s' "$csv" | tr ',' ' ')
fi
unload(){ for m in $(curl -s --noproxy '*' localhost:11434/api/ps | python3 -c 'import json,sys;[print(m["name"]) for m in json.load(sys.stdin)["models"]]'); do "$O" stop "$m"; done; }
for m in "$@"; do
  unload
  "$PY" "$F" bench --backend ollama --url http://127.0.0.1:11434 --model "$m" --label "ollama-${m//[:\/]/_}"
done
unload
python3 - <<'PY'
import glob, json, os
for f in sorted(glob.glob(os.path.join(os.environ.get("SECOPS") or os.path.expanduser("~/GitHub/.sec-ops"), "logs/bench-ollama-*.json"))):
    d = json.load(open(f))
    print(f"{d['model']:34s} decode {d['decode_tps']:6.1f} t/s | prefill {d['prefill_tps']:7.1f} t/s | "
          f"first token @{d['long_prompt_tokens']} tok {d['ttft_long_s']:5.1f}s | tools {d['tool_calls']} | "
          f"json {d['json_ok']} | refusals {d['refusals']}")
PY
echo BENCH-DONE
