# Scan correctness work package

**Status: final exact-head validation in progress.** Previous code passed CI/security on `8c1dae578d4907724e33e56b9d48d68906b22b79`: [CI](https://github.com/cozyGarage/sentinelflow/actions/runs/39047811537) and [security](https://github.com/cozyGarage/sentinelflow/actions/runs/39047811527). This audit closes the missing SC-031 command/version assertions, SC-097 migration examples and updates the named CI selector; fresh Actions evidence on the resulting commit is still required. Draft [PR #56](https://github.com/cozyGarage/sentinelflow/pull/56) is open. SC-095 remains resolved only at its stated availability boundary: pinned govulncheck fixtures passed; six external tools remain unqualified. No organization-wide scanner-readiness claim is made.

This package develops the readiness review into one developer's **14-working-day plan** and a **100-item assignment backlog**. The core is 32 dependency-ordered items; the other 68 are follow-up work, not extra scope for the same timebox.

- [14-day developer plan](scan-correctness-14-days.md): sequence, daily outcomes, PR boundaries and completion checklist.
- [100-item backlog](scan-correctness-backlog.md): stable IDs, dependencies, implementation direction and acceptance criteria.
- [Acceptance report](scan-correctness-acceptance.md): per-core-item evidence and outstanding local, hosted and real-tool gates.
- [Compatibility notes](compatibility.md): behavior changes, identity/baseline implications and supported boundaries.
- [Real-tool qualification](real-tool-qualification.md): exact command/version evidence and unavailable-tool limits.
- [Proposed next assignment](next-assignment.md): ordered work after the core.

The base implementation and previous exact-head runs are recorded in the acceptance report. The current source/test/workflow/documentation changes passed local adapter, race, vet, integration, documentation and actionlint gates; the named hosted matrix has not yet rerun on this work. Current repository state is authoritative; use `git status --short --branch` and `git rev-parse HEAD` before assigning or accepting work.

## Evidence and current limits

The workflow has a named regression row for every core ID. `SC-001` records the exact checkout and Go toolchain. The stable-ID matrix covers `SC-002`, `SC-003`, `SC-011`–`SC-014`, `SC-021`–`SC-024`, `SC-031`–`SC-034`, `SC-041`–`SC-044`, `SC-051`–`SC-054`, and `SC-091`–`SC-093`, `SC-097`, `SC-098`. Separate named jobs cover `SC-094` integration, `SC-095` govulncheck/tool inventory, `SC-099` exact-head gates, and `SC-100` backlog/acceptance/handoff reconciliation. Selector rows fail if no test executes. `scripts/check-scan-sprint-docs.py` checks all core IDs across backlog, acceptance and named Actions; its CI test suite includes missing-row and missing-job negative controls.

Locally, the full race suite, `go vet`, tagged integration tests, actionlint, all 37 selector rows, pinned govulncheck synthetic fixtures, and helper tests passed. The Go cache is under `/home/trung/.cache`; temporary files must remain outside the repository so Git metadata tests do not discover the checkout as their temp directory. See the acceptance report for exact commands, revisions and evidence qualifications.

`SC-095` is resolved under its documented boundary: pinned govulncheck behavior is qualified against synthetic fixtures, and Semgrep, Gitleaks, Grype, Syft, Trivy and YARA are explicitly marked unavailable and unqualified in local and hosted inventories. This does not qualify those integrations or support an organization-wide readiness claim.

The CI workflow runs on pull requests targeting `main` or `develop`, pushes to `main`, and manual dispatch. Hosted evidence is recorded per exact head in the acceptance report; runs on superseded heads do not close SC-099 or SC-100. The PR remains a draft until the final acceptance-report change is verified and reviewed.

For assignment, retain the backlog dependencies and attach the reproducer, positive control, failing-first result, named local/hosted evidence, compatibility impact, and unresolved boundaries. The backlog is the acceptance source of truth; this README is the compact status index.
