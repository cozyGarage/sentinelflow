# Local Go replacement acceptance

Scope: SC-017 fail-closed coverage for local and unversioned Go replacement targets without invented registry identities or source traversal.

## Required local evidence

- [x] Named SC-017 Actions selector covers nested, outside-root, and unversioned replacement targets and verifies graph resolution does not run or emit dependencies.
- [x] Versioned replacement dual-coordinate regression remains green.
- [x] `go test ./...` passes: 471 tests across 33 packages.
- [x] `go test -race -count=1 ./...` passes: 471 tests across 33 packages.
- [x] `go vet ./...`, `actionlint .github/workflows/ci.yml`, sprint documentation checker and its four regression tests pass.
- [x] `git diff --check` passes.

## Hosted evidence

Pending push, PR creation, and exact-head GitHub Actions / Security Scan results. Do not describe this slice as hosted-green until those checks run on the pushed commit.
