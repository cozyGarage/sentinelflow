# OSV interval acceptance

Scope: SC-085 range-event boundary, event ordering, limit decoding, and withdrawal-time correctness.

## Required local evidence

- [x] Named SC-085 Actions selectors pass for boundary matrix, withdrawal timestamp, and decoded limit evaluation (`go test ./internal/vulndb -run 'TestSC085_|TestAffects' -count=1`).
- [x] `go test ./...` passes (429 tests across 33 packages); `go test -race -count=1 ./...` passes (429 tests across 33 packages).
- [x] `go vet ./...`, `actionlint .github/workflows/ci.yml`, sprint documentation checker and its four regression tests pass.
- [x] `git diff --check` passes.

## Hosted evidence

Pending PR creation and exact-head GitHub Actions / Security Scan results. Do not describe this slice as hosted-green until those checks run on the pushed commit.

## Limits

The comparator still intentionally rejects unsupported ecosystem qualifiers. Online OSV responses are evaluated at query time; this slice does not add an immutable online snapshot identifier.
