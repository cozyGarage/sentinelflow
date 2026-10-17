# Offline database update acceptance

Scope: SC-087 archive/index size bounds, failed-refresh preservation, temporary-file cleanup, serialized writers, and concurrent reader safety.

## Required local evidence

- [x] Named SC-087 Actions selectors pass for byte ceilings, failed update preservation, and concurrent update/read behavior (`go test ./internal/vulndb -run '^TestSC087_' -count=1`).
- [x] `go test ./...` passes (440 tests across 33 packages); `go test -race -count=1 ./...` passes (440 tests across 33 packages).
- [x] `go vet ./...`, `actionlint .github/workflows/ci.yml`, sprint documentation checker and its four regression tests pass.
- [x] `git diff --check` passes.

## Hosted evidence

Pending PR creation and exact-head GitHub Actions / Security Scan results. Do not describe this slice as hosted-green until those checks run on the pushed commit.

## Limits

The configured upper bounds should be checked against current largest official ecosystem exports before production rollout. Existing source instances retain their loaded snapshot after an atomic replacement; a new source instance reads the refreshed index.
