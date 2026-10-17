# GIT range acceptance

Scope: SC-084 safe handling of OSV GIT ranges in offline advisory matching.

## Local evidence

- `go test ./...` and `go test -race -count=1 ./...` pass on the cumulative branch.
- `go vet ./...`, `actionlint .github/workflows/ci.yml`, the sprint evidence checker, its four positive/negative control tests and `git diff --check` pass.
- The named SC-084 selector passes: an exact `versions` match remains positive, while an unlisted version with a GIT range returns an explicit unsupported-range error.

## Hosted evidence

Pending PR creation and exact-head GitHub Actions / Security Scan results.

## Limits

GIT commit intervals are not evaluated. Exact listed versions remain usable; otherwise a matching advisory with a GIT range fails as unassessed rather than producing a clean result.
