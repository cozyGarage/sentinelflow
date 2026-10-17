#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
cache_root=${SENTINELFLOW_CACHE_ROOT:-"${HOME}/.cache"}
tmp_root=${TMPDIR:-"${cache_root}/tmp-sentinelflow"}
mkdir -p "$tmp_root" "${cache_root}/go-build-sentinelflow" "${cache_root}/go-mod-sentinelflow"
work_dir=$(mktemp -d "${tmp_root%/}/govulncheck-qualification.XXXXXX")
trap 'rm -rf "$work_dir"' EXIT

export GOCACHE=${GOCACHE:-"${cache_root}/go-build-sentinelflow"}
export GOMODCACHE=${GOMODCACHE:-"${cache_root}/go-mod-sentinelflow"}
export GOTMPDIR=${GOTMPDIR:-"${tmp_root}"}
export TMPDIR="$tmp_root"
export GOBIN="$work_dir/bin"
mkdir -p "$GOBIN"

go install golang.org/x/vuln/cmd/govulncheck@v1.9.0
cd "$repo_root"
SENTINELFLOW_REAL_GOVULNCHECK="$GOBIN/govulncheck" \
  go test ./internal/scanner/dependencies -run '^TestSC043_RealGovulncheckContract$' -count=1 -v
