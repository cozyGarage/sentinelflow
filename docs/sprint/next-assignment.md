# Proposed follow-up assignment

Status: **SC-100 handoff prepared**. This orders the next work after the scan-correctness core. It does not imply organizational rollout readiness; confirm pilot scope and assign an owner when starting the follow-up.

## Completed follow-up: explicit scan outcome and coverage (SC-004–SC-006)

Add an additive, compatibility-aware representation for complete, partial, failed, timed-out, not-applicable and skipped analysis. Trace how collection, native scanners, optional/required adapters, dependencies and reachability move that state through the engine, API, CLI and reports. Define which profiles may accept degraded coverage and make required profiles fail closed. Keep a valid clean result distinguishable from a scanner that never ran.

This slice has been implemented and merged in [PR #57](https://github.com/cozyGarage/sentinelflow/pull/57), with named Actions checks and exact-head acceptance evidence.

## Completed follow-up: suppression identity and retained evidence (SC-071–SC-080)

SC-071–SC-075 are merged in [PR #58](https://github.com/cozyGarage/sentinelflow/pull/58), and SC-076–SC-080 are merged in [PR #59](https://github.com/cozyGarage/sentinelflow/pull/59). Repository-authored exception provenance remains explicitly self-attested rather than organizational approval.

## Active follow-up: vulnerability data quality (SC-081–SC-090)

SC-081–SC-090 and SC-015–SC-018 are merged in [PR #60](https://github.com/cozyGarage/sentinelflow/pull/60), and SC-019 is merged in [PR #61](https://github.com/cozyGarage/sentinelflow/pull/61) after local and exact-head hosted checks passed. SC-015 adds opt-in selected Go module graph resolution with explicit direct/transitive provenance; SC-016 checks versioned replacement coordinates while retaining declaration attribution; SC-017 fails closed for local/unversioned replacements; SC-018 resolves workspace graphs once with stable member attribution; SC-019 preserves pseudo-version/path tuples and excludes toolchain metadata from package queries. Preserve the boundary that dependency graph metadata does not establish build, platform, or artifact contents.

## Subsequent batches

1. **Inventory depth and coverage.** SC-020 depends on SC-068, so validate SBOM schemas and identifiers first; then ensure Go source and compiled artifact inventories keep distinct evidence. Qualify other ecosystem lockfiles and expose skipped file/package coverage and native SAST degradation. Make no whole-repository or artifact coverage claim without measured evidence.
2. **Staged/diff integrity (SC-055–SC-067).** Pin refs to commits, qualify monorepo paths and compatible rule/data snapshots, preserve staged index state, and make scanner timeouts and result filtering explicit.
3. **Resource and production tool qualification (SC-035–SC-050, SC-096).** Bound process output/resources and run pinned real-tool matrices on a permitted runner. Keep each unavailable version explicitly unqualified.

## Readiness boundary

The current sprint repairs selected false-pass paths and adds local evidence. Before a mandatory organization-wide gate, require final hosted checks on the exact sprint revision, real-tool qualification for advertised integrations, explicit outcome/coverage policy, reviewed suppression authority, data freshness behavior and consumer compatibility evidence. Preserve the distinction between a technically reliable local scanner and an organizationally governed CI control.
