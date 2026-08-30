#!/usr/bin/env bash
# Count findings in SentinelFlow reports (json, sarif, text, markdown, html).
# Safe under `set -e` / `pipefail`: zero matches exits 0 with count 0.
set -euo pipefail

usage() {
  echo "usage: count-findings.sh <json|sarif|text|markdown|html> <report-file>" >&2
  exit 2
}

[[ $# -eq 2 ]] || usage
format="$1"
file="$2"

if [[ ! -f "$file" ]]; then
  echo "0"
  exit 0
fi

count_json() {
  python3 - "$1" <<'PY'
import json, sys
path = sys.argv[1]
with open(path, encoding="utf-8") as f:
    data = json.load(f)
findings = data.get("findings")
if isinstance(findings, list):
    print(len(findings))
else:
    print(0)
PY
}

count_sarif() {
  python3 - "$1" <<'PY'
import json, sys
path = sys.argv[1]
with open(path, encoding="utf-8") as f:
    data = json.load(f)
total = 0
for run in data.get("runs") or []:
    total += len(run.get("results") or [])
print(total)
PY
}

count_textish() {
  # Prefer explicit "Total Findings: N" (text) or table "| **Total Findings** | **N** |" (markdown).
  local n
  n=$(grep -oE 'Total Findings[:[:space:]*|]*\*?\*?[0-9]+' "$1" 2>/dev/null | grep -oE '[0-9]+' | tail -n1 || true)
  echo "${n:-0}"
}

case "$format" in
  json)
    count_json "$file" 2>/dev/null || echo 0
    ;;
  sarif)
    count_sarif "$file" 2>/dev/null || echo 0
    ;;
  text|markdown|html)
    count_textish "$file"
    ;;
  *)
    usage
    ;;
esac
