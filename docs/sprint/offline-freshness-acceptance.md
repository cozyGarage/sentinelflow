# Offline freshness acceptance

Scope: SC-082 required offline OSV freshness policy. This is a follow-up to the SC-081 provenance work on `codex/vulnerability-data-quality`.

## Local evidence

- `go test ./...` and `go test -race -count=1 ./...` pass on the combined SC-081/SC-082 branch worktree.
- `go vet ./...`, `actionlint .github/workflows/ci.yml`, `scripts/check-scan-sprint-docs.py`, its four positive/negative control tests and `git diff --check` pass.
- Named SC-082 selectors pass for freshness states, cache-hit revalidation, configuration defaults/validation and strict-policy failure precedence over `fail_on_error: false`.
- Fresh-at-limit passes; stale, unknown-age, missing and corrupt states fail with the expected status/diagnostic. A future file mtime does not change the acquisition-age decision.

## Hosted evidence

Pending PR creation and exact-head GitHub Actions / Security Scan results.

## Limits

Freshness is opt-in. The acquisition timestamp is local download time, not a cryptographically verified upstream publication time. This policy does not qualify ecosystem version semantics or online/offline matching parity.
