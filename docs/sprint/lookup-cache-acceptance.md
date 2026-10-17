# Lookup cache acceptance

Scope: SC-090 cache key identity across package tuples, configured sources and offline snapshots; complete-result-only caching; corrupt-entry recovery; and atomic disk entry replacement under concurrent access.

## Required local evidence

- [x] Named SC-090 Actions selectors pass for configured source isolation, offline snapshot isolation, corrupt-cache recovery, and concurrent disk readers/writers (`go test ./internal/vulndb -run '^TestSC090_' -count=1`).
- [x] `go test ./...` passes (459 tests across 33 packages); `go test -race -count=1 ./...` passes (459 tests across 33 packages).
- [x] `go vet ./...`, `actionlint .github/workflows/ci.yml`, sprint documentation checker and its four regression tests pass.
- [x] `git diff --check` passes.

## Hosted evidence

Pending PR creation and exact-head GitHub Actions / Security Scan results. Do not describe this slice as hosted-green until those checks run on the pushed commit.
