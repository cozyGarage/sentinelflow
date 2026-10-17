# Batch query acceptance

Scope: SC-088 response alignment, retry/cancellation after completed chunks, detail-fetch partial success, finding retention, and cache correctness.

## Required local evidence

- [x] Named SC-088 selectors pass for aligned chunk cancellation, detail partial results/cache behavior, and dependency finding retention.
- [x] `go test ./...` passes (444 tests across 33 packages); `go test -race -count=1 ./...` passes (444 tests across 33 packages).
- [x] `go vet ./...`, `actionlint .github/workflows/ci.yml`, sprint documentation checker and its four regression tests pass.
- [x] `git diff --check` passes.

## Hosted evidence

Pending PR creation and exact-head GitHub Actions / Security Scan results. Do not describe this slice as hosted-green until those checks run on the pushed commit.
