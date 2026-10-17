#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <package> <test-regexp>" >&2
  exit 2
fi

package=$1
selector=$2
tmp_root=${TMPDIR:-/tmp}
result=$(mktemp "${tmp_root%/}/sentinelflow-test-selector.XXXXXX")
trap 'rm -f "$result"' EXIT

if ! go test -json -count=1 -run "^${selector}$" "$package" >"$result"; then
  cat "$result"
  exit 1
fi

python3 - "$result" "$selector" <<'PY'
import json
import sys

path = sys.argv[1]
executed = []
with open(path, encoding="utf-8") as stream:
    for line in stream:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("Action") == "pass" and event.get("Test"):
            executed.append(event["Test"])

if not executed:
    print(f"no tests matched selector {sys.argv[2]!r}", file=sys.stderr)
    raise SystemExit(1)

for name in executed:
    print(f"PASS {name}")
PY
