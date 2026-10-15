#!/usr/bin/env bash
# Unit test for pr-comment.sh with a fake gh on PATH.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

mkdir -p "${TMP}/bin"
cat > "${TMP}/bin/gh" <<'GH'
#!/usr/bin/env bash
echo "$*" >> "${GH_LOG}"
case "$*" in
  *"--paginate"*) [ -n "${GH_EXISTING:-}" ] && echo "${GH_EXISTING}" ;;
esac
exit 0
GH
chmod +x "${TMP}/bin/gh"

run() {
  printf '# report\n' > "${TMP}/report.md"
  PATH="${TMP}/bin:${PATH}" GH_LOG="${TMP}/log" SF_REPO=o/r SF_PR=7 SF_REPORT="${TMP}/report.md" \
    bash "${ROOT}/scripts/pr-comment.sh"
}

: > "${TMP}/log"; GH_EXISTING="" run
grep -q '^api repos/o/r/issues/7/comments -f body=<!-- sentinelflow-pr-comment -->' "${TMP}/log" || { echo "FAIL: expected create"; cat "${TMP}/log"; exit 1; }

: > "${TMP}/log"; GH_EXISTING=42 run
grep -q '^api -X PATCH repos/o/r/issues/comments/42 ' "${TMP}/log" || { echo "FAIL: expected update"; cat "${TMP}/log"; exit 1; }
[ ! -e "${TMP}/report.md" ] || { echo "FAIL: report not cleaned up"; exit 1; }

: > "${TMP}/log"; rm -f "${TMP}/report.md"
PATH="${TMP}/bin:${PATH}" GH_LOG="${TMP}/log" SF_REPO=o/r SF_PR=7 SF_REPORT="${TMP}/report.md" bash "${ROOT}/scripts/pr-comment.sh" >/dev/null
[ ! -s "${TMP}/log" ] || { echo "FAIL: missing report must not call gh"; exit 1; }

echo "pr-comment tests passed"
