# Go module graph acceptance

Scope: SC-015 opt-in `go list -m` resolution, source attribution, network policy, tool failures and cancellation.

## Required local evidence

- [x] Named SC-015 selectors pass locally for selected versions, direct/transitive attribution, offline/config policy, command failure, timeout, missing tool, and the local-replacement boundary (7 tests across config, CLI, and dependencies packages).
- [x] `go test ./...` passes: 466 tests across 33 packages.
- [x] `go test -race -count=1 ./...` passes: 466 tests across 33 packages.
- [x] `go vet ./...`, `actionlint .github/workflows/ci.yml`, sprint documentation checker and its four regression tests pass.
- [x] `git diff --check` passes.

The real repository graph was not validated with the installed Go command: the system binary is Go 1.27.1 while `go.mod` requires 1.27.2. The matching cached Go 1.27.2 toolchain also could not resolve with `GOPROXY=off` because this checkout's dependencies are not cached. This confirms the intended visible failure when offline graph inputs are unavailable; deterministic behavior is covered with fake-command fixtures.

## Hosted evidence

Pending push, PR creation, and exact-head GitHub Actions / Security Scan results. Do not describe this slice as hosted-green until those checks run on the pushed commit.
