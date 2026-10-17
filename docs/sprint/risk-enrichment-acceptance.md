# Risk enrichment acceptance

Scope: SC-089 missing/invalid EPSS values, partial signal retention, optional enrichment degradation, and required KEV fail-closed behavior.

## Required local evidence

- [x] Named SC-089 Actions selectors pass for missing scores, invalid scores, required KEV policy, and no-CVE behavior.
- [x] `go test ./...` passes (455 tests across 33 packages); `go test -race -count=1 ./...` passes (455 tests across 33 packages).
- [x] `go vet ./...`, `actionlint .github/workflows/ci.yml`, sprint documentation checker and its four regression tests pass.
- [x] `git diff --check` passes.

## Hosted evidence

Pending PR creation and exact-head GitHub Actions / Security Scan results. Do not describe this slice as hosted-green until those checks run on the pushed commit.
