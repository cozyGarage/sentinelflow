# Go workspace resolution acceptance

Scope: SC-018 selected Go workspace membership, module-root handling, workspace replacements, stable provenance, and one graph resolution per workspace scan.

## Required local evidence

- [x] Named SC-018 Actions selectors verify two module members, workspace-selected version precedence, versioned workspace replacement, stable direct/transitive attribution, one graph invocation, parent workspace discovery from a member-rooted scan, and fail-closed local workspace replacement handling.
- [x] Local and unversioned replacement rejection remains green.
- [x] `go test ./...` passes: 473 tests across 33 packages.
- [x] `go test -race -count=1 ./...` passes: 473 tests across 33 packages.
- [x] `go vet ./...`, `actionlint .github/workflows/ci.yml`, sprint documentation checker and its four regression tests pass.
- [x] `git diff --check` passes.

The exact Go 1.27.2 command was also run against a two-member workspace fixture with `GOPROXY=off`, `GOSUMDB=off`, and `GOTOOLCHAIN=local`; it returned both `use` modules as `Main: true` without network access. The selected-version and replacement cases use deterministic fake-command output so the tests do not depend on a public registry.

## Hosted evidence

Pending push, PR creation, and exact-head GitHub Actions / Security Scan results. Do not describe this slice as hosted-green until those checks run on the pushed commit.
