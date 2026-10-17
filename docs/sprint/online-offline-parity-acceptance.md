# Online/offline parity acceptance

Scope: SC-086 compares online-query and offline-index outputs for identical package tuples and identical pinned OSV advisory records, without a live network dependency.

## Required local evidence

- [x] Named SC-086 Actions selector passes across all package/version cases (`go test ./internal/vulndb -run '^TestSC086_' -count=1`).
- [x] `go test ./...` passes (434 tests across 33 packages); `go test -race -count=1 ./...` passes (434 tests across 33 packages).
- [x] `go vet ./...`, `actionlint .github/workflows/ci.yml`, sprint documentation checker and its four regression tests pass.
- [x] `git diff --check` passes.

## Hosted evidence

Pending PR creation and exact-head GitHub Actions / Security Scan results. Do not describe this slice as hosted-green until those checks run on the pushed commit.

## Limits

The fixture API returns a pinned expected match set; the test validates API decoding/output parity against independently evaluated offline results, not OSV's remote service implementation. Coverage is limited to supported `SEMVER`, exact-version, and withdrawal behavior represented by the fixture.
