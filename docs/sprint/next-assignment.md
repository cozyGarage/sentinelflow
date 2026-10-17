# Proposed follow-up assignment

Status: **SC-100 handoff prepared**. This orders the next work after the scan-correctness core. It does not imply organizational rollout readiness; confirm pilot scope and assign an owner when starting the follow-up.

## Completed follow-up: explicit scan outcome and coverage (SC-004–SC-006)

Add an additive, compatibility-aware representation for complete, partial, failed, timed-out, not-applicable and skipped analysis. Trace how collection, native scanners, optional/required adapters, dependencies and reachability move that state through the engine, API, CLI and reports. Define which profiles may accept degraded coverage and make required profiles fail closed. Keep a valid clean result distinguishable from a scanner that never ran.

This slice has been implemented and merged in [PR #57](https://github.com/cozyGarage/sentinelflow/pull/57), with named Actions checks and exact-head acceptance evidence.

## Completed follow-up: suppression identity and retained evidence (SC-071–SC-080)

SC-071–SC-075 are merged in [PR #58](https://github.com/cozyGarage/sentinelflow/pull/58), and SC-076–SC-080 are merged in [PR #59](https://github.com/cozyGarage/sentinelflow/pull/59). Repository-authored exception provenance remains explicitly self-attested rather than organizational approval.

## Active follow-up: vulnerability data quality (SC-081–SC-090)

The current branch implements and locally validates SC-081 through SC-090: vulnerability-data provenance, offline freshness, comparator support, unsupported GIT uncertainty, OSV boundaries/withdrawals, online/offline parity, bounded atomic updates, aligned partial batch results, KEV/EPSS completeness, and cache isolation. Full local gates pass for all ten slices; PR and hosted checks remain pending. SC-015 now adds opt-in selected Go module graph resolution and explicit provenance for direct versus transitive modules; full local gates pass, while exact-head hosted evidence awaits PR creation. See [Go module graph resolution](go-module-graph-resolution.md). Preserve the boundary that graph metadata does not establish build, platform, or artifact contents; SC-016–SC-018 cover replacement and workspace behavior.

## Subsequent batches

1. **Inventory depth and coverage (SC-016–SC-018, SC-025–SC-030, SC-065–SC-070).** Implement versioned and local Go replacements, qualify workspace/module-root behavior, qualify other ecosystem lockfiles, expose skipped file/package coverage and native SAST degradation. Make no whole-repository or artifact coverage claim without measured evidence.
2. **Staged/diff integrity (SC-055–SC-067).** Pin refs to commits, qualify monorepo paths and compatible rule/data snapshots, preserve staged index state, and make scanner timeouts and result filtering explicit.
3. **Resource and production tool qualification (SC-035–SC-050, SC-096).** Bound process output/resources and run pinned real-tool matrices on a permitted runner. Keep each unavailable version explicitly unqualified.

## Readiness boundary

The current sprint repairs selected false-pass paths and adds local evidence. Before a mandatory organization-wide gate, require final hosted checks on the exact sprint revision, real-tool qualification for advertised integrations, explicit outcome/coverage policy, reviewed suppression authority, data freshness behavior and consumer compatibility evidence. Preserve the distinction between a technically reliable local scanner and an organizationally governed CI control.
