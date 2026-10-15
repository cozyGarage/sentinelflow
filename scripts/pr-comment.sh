#!/usr/bin/env bash
# Post or update one sticky SentinelFlow comment on a pull request.
# Env: GH_TOKEN, SF_REPO (owner/repo), SF_PR (number), SF_REPORT (markdown file).
# Never fails the job: fork PRs get a read-only token, which is expected.
set -uo pipefail

MARKER='<!-- sentinelflow-pr-comment -->'
LIMIT=60000 # GitHub caps comment bodies at 65536 characters

if [ ! -s "${SF_REPORT}" ]; then
  echo "::notice::no SentinelFlow markdown report; skipping PR comment"
  exit 0
fi

report=$(cat "${SF_REPORT}")
rm -f "${SF_REPORT}"
if [ "${#report}" -gt "$LIMIT" ]; then
  report="${report:0:$LIMIT}"$'\n\n'"_Report truncated. See the workflow run for the full output._"
fi
body="${MARKER}"$'\n'"${report}"

id=$(gh api --paginate "repos/${SF_REPO}/issues/${SF_PR}/comments" \
  --jq ".[] | select(.body | startswith(\"${MARKER}\")) | .id" 2>/dev/null | head -n1)

if [ -n "$id" ]; then
  gh api -X PATCH "repos/${SF_REPO}/issues/comments/${id}" -f body="$body" >/dev/null
else
  gh api "repos/${SF_REPO}/issues/${SF_PR}/comments" -f body="$body" >/dev/null
fi || echo "::warning::could not post the SentinelFlow PR comment (needs pull-requests: write; fork PRs are read-only)"
