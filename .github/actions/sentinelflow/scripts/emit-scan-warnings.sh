#!/usr/bin/env bash
# Emit GitHub Actions ::warning:: annotations for scanner_runs[].warnings in a JSON report.
# Usage: emit-scan-warnings.sh <report.json>
# Safe under set -e: parse failures exit 0 (no annotations).
set -euo pipefail

file="${1:-}"
if [[ -z "$file" || ! -f "$file" ]]; then
  exit 0
fi

python3 - "$file" <<'PY'
import json, sys
path = sys.argv[1]
try:
    data = json.load(open(path, encoding="utf-8"))
except Exception:
    sys.exit(0)
for run in data.get("scanner_runs") or []:
    scanner = run.get("scanner") or "scanner"
    for w in run.get("warnings") or []:
        print(f"::warning::sentinelflow {scanner}: {w}")
PY
