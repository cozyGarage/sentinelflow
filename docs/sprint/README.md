# Scan correctness work package

**Status: in progress.** The 32-item scan-correctness core has implementation and local regression evidence on branch `codex/scan-correctness-sprint`. The current worktree has additional SC-001/SC-100 evidence checks in progress. No PR is open and no hosted Action result exists yet; this package is not an acceptance or release claim.

This package develops the readiness review into one developer's **14-working-day plan** and a **100-item assignment backlog**. The core is 32 dependency-ordered items; the other 68 are follow-up work, not extra scope for the same timebox.

- [14-day developer plan](scan-correctness-14-days.md): sequence, daily outcomes, PR boundaries and completion checklist.
- [100-item backlog](scan-correctness-backlog.md): stable IDs, dependencies, implementation direction and acceptance criteria.
- [Acceptance report](scan-correctness-acceptance.md): per-core-item evidence and outstanding local, hosted and real-tool gates.
- [Compatibility notes](compatibility.md): behavior changes, identity/baseline implications and supported boundaries.
- [Real-tool qualification](real-tool-qualification.md): exact command/version evidence and unavailable-tool limits.
- [Proposed next assignment](next-assignment.md): ordered work after the core.

The implementation source was validated at `3e128766b4e497136984bb0f9fbcafe9d91e7693`; the report-only commit that followed is `409db8e185de9e46de67eeee98daaf2cbe6c0832`. The branch was clean at that checkpoint. Current repository state is authoritative; use `git status --short --branch` and `git rev-parse HEAD` before assigning or accepting work.

## Evidence and current limits

The workflow has a named regression row for every core ID. `SC-001` records the exact checkout and Go toolchain. The stable-ID matrix covers `SC-002`, `SC-003`, `SC-011`–`SC-014`, `SC-021`–`SC-024`, `SC-031`–`SC-034`, `SC-041`–`SC-044`, `SC-051`–`SC-054`, and `SC-091`–`SC-093`, `SC-097`, `SC-098`. Separate named jobs cover `SC-094` integration, `SC-095` govulncheck/tool inventory, `SC-099` exact-head gates, and `SC-100` backlog/acceptance/handoff reconciliation. Selector rows fail if no test executes. `scripts/check-scan-sprint-docs.py` checks that all core IDs appear in the acceptance table and have a named Actions check.

Locally, the full race suite, `go vet`, tagged integration tests, actionlint, all 37 selector rows, pinned govulncheck synthetic fixtures, and helper tests passed. The Go cache is under `/home/trung/.cache`; temporary files must remain outside the repository so Git metadata tests do not discover the checkout as their temp directory. See the acceptance report for exact commands, revisions and evidence qualifications.

`SC-095` is partial: pinned govulncheck behavior is qualified locally; Semgrep, Gitleaks, Grype, Syft, Trivy and YARA were unavailable locally and remain unqualified. The hosted inventory job reports what is available but does not install or qualify those scanners. Keep unavailable-tool evidence explicit.

The CI workflow runs on pull requests targeting `main` or `develop`, pushes to `main`, and manual dispatch. The sprint branch has not been pushed and no PR exists. To obtain hosted evidence for the final branch, push it and open a PR; do not mark core items complete based on local checks alone. SC-099 and SC-100 remain open until exact-revision hosted results and the final reconciliation are recorded.

For assignment, retain the backlog dependencies and attach the reproducer, positive control, failing-first result, named local/hosted evidence, compatibility impact, and unresolved boundaries. The backlog is the acceptance source of truth; this README is the compact status index.
