# Go module version selection acceptance

Scope: SC-019 fidelity for pseudo-versions, major-version module paths, excluded versions as resolved by Go, and toolchain directives.

## Required local evidence

- [x] Named SC-019 Actions selector verifies the version returned by the selected graph replaces the declared excluded version in inventory and preserves pseudo-version contents and `/vN` module paths in advisory tuples.
- [x] Toolchain directives do not create synthetic dependency queries.
- [x] `go test ./...` passes: 474 tests across 33 packages.
- [x] `go test -race -count=1 ./...` passes: 474 tests across 33 packages.
- [x] `go vet ./...`, `actionlint .github/workflows/ci.yml`, sprint documentation checker and its four regression tests pass.
- [x] `git diff --check` passes.

A local Go 1.27.2 two-module fixture with `toolchain go1.27.2` confirmed the exact read-only `go list -m -json -mod=readonly all` command emits the workspace main module(s) and no synthetic toolchain module. Pseudo-version, excluded-version handoff, and `/v2` query-coordinate tests use deterministic fake graph output; the Go command remains the authority for actual MVS/exclusion selection, which is not independently exercised here against a public module proxy.

## Hosted evidence

Pending push, PR creation, and exact-head GitHub Actions / Security Scan results. Do not describe this slice as hosted-green until those checks run on the pushed commit.
