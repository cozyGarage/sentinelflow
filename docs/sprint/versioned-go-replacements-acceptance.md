# Versioned Go replacement acceptance

Scope: SC-016 advisory lookups for versioned Go module replacements while preserving original `go.mod` attribution.

## Required local evidence

- [x] Named SC-016 Actions selector verifies both original and replacement coordinates, replacement version, finding retention, and original declaration attribution.
- [x] SC-015 local replacement rejection remains covered as the SC-017 boundary.
- [x] `go test ./...` passes: 467 tests across 33 packages.
- [x] `go test -race -count=1 ./...` passes: 467 tests across 33 packages.
- [x] `go vet ./...`, `actionlint .github/workflows/ci.yml`, sprint documentation checker and its four regression tests pass.
- [x] `git diff --check` passes.

## Hosted evidence

Pending push, PR creation, and exact-head GitHub Actions / Security Scan results. Do not describe this slice as hosted-green until those checks run on the pushed commit.
