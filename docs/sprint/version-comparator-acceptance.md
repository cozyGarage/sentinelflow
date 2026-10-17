# Version comparator acceptance

Scope: SC-083 explicit local comparator capability and fail-closed behavior.

## Local evidence

- `go test ./...` and `go test -race -count=1 ./...` pass on the cumulative branch.
- `go vet ./...`, `actionlint .github/workflows/ci.yml`, the sprint evidence checker, its four negative/positive control tests and `git diff --check` pass.
- Both named SC-083 Actions selectors pass: the capability matrix covers every supported offline ecosystem, while the fail-closed fixture proves a PyPI post-release range returns uncertainty instead of a clean result.
- Valid SemVer prerelease ordering, numeric dotted ordering and arbitrarily large numeric components are covered. ECOSYSTEM prerelease/postrelease/qualifier forms and unknown range types fail explicitly.

## Hosted evidence

Pending PR creation and exact-head GitHub Actions / Security Scan results.

## Limits

Only numeric dotted `ECOSYSTEM` releases and valid `SEMVER` ranges are ordered. Qualifier-bearing ecosystem versions fail with uncertainty rather than being treated as clean. This does not establish full per-ecosystem native comparator compatibility.
