# Scan correctness work package

**Status: in progress.** The 32-item scan-correctness core has implementation and local regression evidence on branch `codex/scan-correctness-sprint`. Draft [PR #56](https://github.com/cozyGarage/sentinelflow/pull/56) is open. CI passed on the initial PR head; later security scans found the long synthetic API-key marker quoted in the test and acceptance report. The test marker is corrected, and the acceptance-report correction is queued for the next hosted run. This package is not an acceptance or release claim.

This package develops the readiness review into one developer's **14-working-day plan** and a **100-item assignment backlog**. The core is 32 dependency-ordered items; the other 68 are follow-up work, not extra scope for the same timebox.

- [14-day developer plan](scan-correctness-14-days.md): sequence, daily outcomes, PR boundaries and completion checklist.
- [100-item backlog](scan-correctness-backlog.md): stable IDs, dependencies, implementation direction and acceptance criteria.
- [Acceptance report](scan-correctness-acceptance.md): per-core-item evidence and outstanding local, hosted and real-tool gates.
- [Compatibility notes](compatibility.md): behavior changes, identity/baseline implications and supported boundaries.
- [Real-tool qualification](real-tool-qualification.md): exact command/version evidence and unavailable-tool limits.
- [Proposed next assignment](next-assignment.md): ordered work after the core.

The implementation source was validated at `3e128766b4e497136984bb0f9fbcafe9d91e7693`; local SC-001/SC-100 and matrix checks passed at `347dbeee6c3c3574e38933918e257056545aec03`. Subsequent commits update only the acceptance report and status index. Current repository state is authoritative; use `git status --short --branch` and `git rev-parse HEAD` before assigning or accepting work.

## Evidence and current limits

The workflow has a named regression row for every core ID. `SC-001` records the exact checkout and Go toolchain. The stable-ID matrix covers `SC-002`, `SC-003`, `SC-011`–`SC-014`, `SC-021`–`SC-024`, `SC-031`–`SC-034`, `SC-041`–`SC-044`, `SC-051`–`SC-054`, and `SC-091`–`SC-093`, `SC-097`, `SC-098`. Separate named jobs cover `SC-094` integration, `SC-095` govulncheck/tool inventory, `SC-099` exact-head gates, and `SC-100` backlog/acceptance/handoff reconciliation. Selector rows fail if no test executes. `scripts/check-scan-sprint-docs.py` checks all core IDs across backlog, acceptance and named Actions; its CI test suite includes missing-row and missing-job negative controls.

Locally, the full race suite, `go vet`, tagged integration tests, actionlint, all 37 selector rows, pinned govulncheck synthetic fixtures, and helper tests passed. The Go cache is under `/home/trung/.cache`; temporary files must remain outside the repository so Git metadata tests do not discover the checkout as their temp directory. See the acceptance report for exact commands, revisions and evidence qualifications.

`SC-095` is partial: pinned govulncheck behavior is qualified locally; Semgrep, Gitleaks, Grype, Syft, Trivy and YARA were unavailable locally and remain unqualified. The hosted inventory job reports what is available but does not install or qualify those scanners. Keep unavailable-tool evidence explicit.

The CI workflow runs on pull requests targeting `main` or `develop`, pushes to `main`, and manual dispatch. Hosted evidence is recorded per exact head in the acceptance report; runs on superseded heads do not close SC-099 or SC-100. The PR remains a draft while hosted checks and remaining real-tool acceptance are resolved.

For assignment, retain the backlog dependencies and attach the reproducer, positive control, failing-first result, named local/hosted evidence, compatibility impact, and unresolved boundaries. The backlog is the acceptance source of truth; this README is the compact status index.
